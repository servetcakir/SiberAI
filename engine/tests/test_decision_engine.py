import unittest
from datetime import datetime, timedelta, timezone

from engine.analysis.decision_engine import DECISION_ENGINE_VERSION, analyze_incident
from engine.models.analysis import (
    AnalysisEvidence, EvidenceType, IncidentAnalysis, ReasonCode, RecommendedAction, Verdict,
)
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent
from engine.models.incident import Incident, IncidentStatus


class DecisionEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc)
        self.incident = Incident(
            incident_id="INC:event-1", title="Detection", status=IncidentStatus.OPEN,
            severity=Severity.HIGH, risk_score=85, created_at=self.now,
            updated_at=self.now, host="ServoPC", process_guid="{GUID-X}",
            primary_event_id="event-1", event_ids=["event-1"], detection_ids=[],
        )
        self.process = SecurityEvent(
            event_id="event-1", timestamp=self.now, source_type="sysmon",
            category="process_creation", host="ServoPC", process="powershell.exe",
            process_guid="{GUID-X}", raw={"secret": "must-not-appear"},
        )

    def detection(
        self, rule: str = "DET-PS-001", severity: Severity = Severity.HIGH,
        risk: int = 85, event_id: str = "event-1", mitre: list[str] | None = None,
    ) -> Detection:
        return Detection(
            detection_id=f"{rule}:{event_id}", event_id=event_id, rule_id=rule,
            title=rule, severity=severity, risk_score=risk, description="Test",
            mitre_techniques=mitre or [],
        )

    def test_analysis_validation_bounds(self) -> None:
        values = dict(
            analysis_id="a", incident_id="i", verdict=Verdict.SUSPICIOUS,
            severity=Severity.HIGH, reason_codes=[], contributing_detection_ids=[],
            mitre_techniques=[], recommended_actions=[], evidence=[],
            requires_human_review=True, engine_version="v", created_at=self.now,
            updated_at=self.now,
        )
        with self.assertRaisesRegex(ValueError, "confidence"):
            IncidentAnalysis(confidence=1.01, risk_score=50, **values)
        with self.assertRaisesRegex(ValueError, "risk_score"):
            IncidentAnalysis(confidence=0.5, risk_score=101, **values)

    def test_one_high_detection_is_conservative_and_stable(self) -> None:
        detection = self.detection(mitre=["T1059.001"])
        first = analyze_incident(self.incident, [self.process], [detection], now=self.now)
        second = analyze_incident(self.incident, [self.process], [detection], now=self.now)
        self.assertEqual(first.analysis_id, f"ANALYSIS:{self.incident.incident_id}:{DECISION_ENGINE_VERSION}")
        self.assertEqual(first, second)
        self.assertEqual(first.verdict, Verdict.SUSPICIOUS)
        self.assertEqual(first.confidence, 0.74)
        self.assertEqual(first.severity, Severity.HIGH)
        self.assertEqual(first.risk_score, 85)
        self.assertTrue(first.requires_human_review)
        self.assertNotEqual(first.verdict, Verdict.BENIGN)

    def test_correlated_network_is_context_and_can_raise_confidence(self) -> None:
        detection = self.detection()
        network = SecurityEvent(
            event_id="network-1", timestamp=self.now + timedelta(seconds=10),
            source_type="sysmon", category="network_connection", host="ServoPC",
            process="powershell.exe", process_guid="{GUID-X}",
            destination_ip="203.0.113.8", destination_port=443,
            raw={"complete": "telemetry"},
        )
        analysis = analyze_incident(self.incident, [self.process, network], [detection], now=self.now)
        self.assertEqual(analysis.verdict, Verdict.LIKELY_MALICIOUS)
        self.assertEqual(analysis.confidence, 0.84)
        self.assertIn(ReasonCode.CORRELATED_NETWORK_ACTIVITY, analysis.reason_codes)
        network_evidence = next(item for item in analysis.evidence if item.type == EvidenceType.NETWORK_CONNECTION)
        self.assertEqual(network_evidence.event_id, network.event_id)
        self.assertEqual(network_evidence.destination_ip, "203.0.113.8")
        self.assertNotEqual(analysis.verdict, Verdict.MALICIOUS)
        self.assertEqual(analysis.risk_score, 85)

    def test_network_activity_alone_does_not_imply_maliciousness(self) -> None:
        network = SecurityEvent(
            event_id="network-1", timestamp=self.now, source_type="sysmon",
            category="network_connection", process_guid="{GUID-X}", destination_port=443,
        )
        analysis = analyze_incident(self.incident, [network], [], now=self.now)
        self.assertEqual(analysis.verdict, Verdict.SUSPICIOUS)
        self.assertEqual(analysis.confidence, 0.55)

    def test_independent_behaviors_outweigh_duplicate_same_family(self) -> None:
        powershell = [self.detection(), self.detection("DET-PS-002", Severity.MEDIUM, 70)]
        duplicate_family = analyze_incident(self.incident, [self.process], powershell, now=self.now)
        office = self.detection("DET-OFFICE-001", Severity.HIGH, 78)
        diverse = analyze_incident(self.incident, [self.process], powershell + [office], now=self.now)
        self.assertEqual(duplicate_family.verdict, Verdict.SUSPICIOUS)
        self.assertEqual(duplicate_family.confidence, 0.74)
        self.assertEqual(diverse.verdict, Verdict.LIKELY_MALICIOUS)
        self.assertEqual(diverse.confidence, 0.90)
        self.assertIn(ReasonCode.MULTIPLE_HIGH_CONFIDENCE_DETECTIONS, diverse.reason_codes)

    def test_duplicate_evidence_is_deduplicated_without_confidence_inflation(self) -> None:
        detection = self.detection()
        analysis = analyze_incident(
            self.incident, [self.process, self.process], [detection, detection], now=self.now
        )
        self.assertEqual(analysis.confidence, 0.74)
        self.assertEqual(analysis.contributing_detection_ids, [detection.detection_id])
        self.assertEqual(len(analysis.evidence), 1)

    def test_malicious_requires_critical_semantics_and_diversity(self) -> None:
        credential = self.detection("DET-CRED-001", Severity.CRITICAL, 96)
        alone = analyze_incident(self.incident, [self.process], [credential], now=self.now)
        persistence = self.detection("DET-PERSIST-002", Severity.HIGH, 80)
        combined = analyze_incident(self.incident, [self.process], [credential, persistence], now=self.now)
        self.assertEqual(alone.verdict, Verdict.SUSPICIOUS)
        self.assertEqual(alone.severity, Severity.CRITICAL)
        self.assertIn(ReasonCode.CRITICAL_DETECTION_PRESENT, alone.reason_codes)
        self.assertEqual(combined.verdict, Verdict.MALICIOUS)
        self.assertEqual(combined.confidence, 0.97)
        self.assertIn(RecommendedAction.ISOLATE_HOST, combined.recommended_actions)
        self.assertIn(RecommendedAction.RESET_CREDENTIALS, combined.recommended_actions)

    def test_reasons_actions_mitre_and_evidence_are_grounded(self) -> None:
        detections = [
            self.detection(mitre=["T1059.001"]),
            self.detection("DET-PERSIST-002", Severity.HIGH, 80, mitre=["T1547.001", "T1059.001"]),
        ]
        analysis = analyze_incident(self.incident, [self.process], detections, now=self.now)
        self.assertEqual(analysis.mitre_techniques, ["T1059.001", "T1547.001"])
        self.assertIn(ReasonCode.ENCODED_POWERSHELL, analysis.reason_codes)
        self.assertIn(ReasonCode.PERSISTENCE_BEHAVIOR, analysis.reason_codes)
        self.assertIn(RecommendedAction.REVIEW_PERSISTENCE, analysis.recommended_actions)
        self.assertNotIn(ReasonCode.CREDENTIAL_ACCESS_INDICATOR, analysis.reason_codes)
        self.assertNotIn(RecommendedAction.RESET_CREDENTIALS, analysis.recommended_actions)
        self.assertEqual(
            {item.detection_id for item in analysis.evidence if item.type == EvidenceType.DETECTION},
            {item.detection_id for item in detections},
        )
        self.assertTrue(all(not hasattr(item, "raw") for item in analysis.evidence))


if __name__ == "__main__":
    unittest.main()
