import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from engine.ml.examples import ExampleLabel, ExampleSource, IncidentFeatureExample
from engine.ml.features import (
    RULE_BEHAVIOR_FEATURE_MAP,
    RULE_FAMILY_MAP,
    extract_features,
    extract_incident_features,
    to_vector,
)
from engine.ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent
from engine.models.incident import Incident, IncidentStatus


EXPECTED_FEATURE_NAMES = (
    "has_encoded_powershell", "has_evasive_powershell",
    "has_office_spawned_interpreter", "has_credential_access",
    "has_security_control_impairment", "has_persistence",
    "has_suspicious_lolbin", "detection_count", "low_detection_count",
    "medium_detection_count", "high_detection_count", "critical_detection_count",
    "unique_detection_family_count", "max_detection_risk", "event_count",
    "process_event_count", "network_event_count", "events_after_first_detection",
    "detections_per_event", "network_connection_count", "unique_destination_count",
    "unique_destination_port_count", "outbound_connection_count",
    "has_network_after_detection", "incident_duration_seconds",
)


class MlFeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.start = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc)

    def event(
        self, event_id: str = "event-1", *, seconds: int = 0,
        category: str = "process_creation", destination_ip: str | None = None,
        destination_hostname: str | None = None, destination_port: int | None = None,
        initiated: bool | None = None,
    ) -> SecurityEvent:
        return SecurityEvent(
            event_id=event_id, timestamp=self.start + timedelta(seconds=seconds),
            source_type="sysmon", category=category, host="SensitiveHost",
            user="SensitiveUser", process_guid="{SENSITIVE-GUID}",
            destination_ip=destination_ip, destination_hostname=destination_hostname,
            destination_port=destination_port, initiated=initiated,
            raw={"secret": "raw telemetry"},
        )

    def detection(
        self, rule_id: str, *, detection_id: str | None = None,
        event_id: str = "event-1", severity: Severity = Severity.HIGH,
        risk: int = 80,
    ) -> Detection:
        return Detection(
            detection_id=detection_id or f"{rule_id}:{event_id}",
            event_id=event_id, rule_id=rule_id, title="Ignored title",
            severity=severity, risk_score=risk, description="Ignored description",
        )

    def incident(self, **overrides: object) -> Incident:
        values = dict(
            incident_id="INC:sensitive", title="Heuristic title", status=IncidentStatus.OPEN,
            severity=Severity.CRITICAL, risk_score=99, created_at=self.start,
            updated_at=self.start, host="SensitiveHost", process_guid="{SENSITIVE-GUID}",
            primary_event_id="event-1", event_ids=["event-1"], detection_ids=[],
        )
        values.update(overrides)
        return Incident(**values)

    def test_schema_version_names_and_order_are_stable(self) -> None:
        self.assertEqual(FEATURE_SCHEMA_VERSION, "incident-features-v1")
        self.assertEqual(FEATURE_NAMES, EXPECTED_FEATURE_NAMES)
        self.assertEqual(len(FEATURE_NAMES), 25)

    def test_same_evidence_produces_identical_vector(self) -> None:
        events = [self.event()]
        detections = [self.detection("DET-PS-001", risk=85)]
        first = to_vector(extract_features(events, detections))
        second = to_vector(extract_features(list(reversed(events)), list(reversed(detections))))
        self.assertEqual(first, second)
        self.assertEqual(len(first), len(FEATURE_NAMES))

    def test_empty_benign_window_is_all_neutral(self) -> None:
        features = extract_features([], [])
        self.assertEqual(features.schema_version, FEATURE_SCHEMA_VERSION)
        self.assertEqual(to_vector(features), [0] * len(FEATURE_NAMES))
        self.assertEqual(features.detections_per_event, 0.0)

    def test_current_rules_map_to_explicit_flags_and_families(self) -> None:
        expected = {
            "DET-PS-001": "has_encoded_powershell",
            "DET-PS-002": "has_evasive_powershell",
            "DET-OFFICE-001": "has_office_spawned_interpreter",
            "DET-CRED-001": "has_credential_access",
            "DET-DEFENSE-001": "has_security_control_impairment",
            "DET-PERSIST-001": "has_persistence",
            "DET-PERSIST-002": "has_persistence",
            "DET-LOL-001": "has_suspicious_lolbin",
            "DET-LOL-002": "has_suspicious_lolbin",
            "DET-LOL-003": "has_suspicious_lolbin",
        }
        self.assertEqual(RULE_BEHAVIOR_FEATURE_MAP, expected)
        self.assertEqual(set(RULE_FAMILY_MAP), set(expected))
        for rule_id, feature_name in expected.items():
            with self.subTest(rule_id=rule_id):
                features = extract_features([self.event()], [self.detection(rule_id)])
                self.assertEqual(getattr(features, feature_name), 1)

    def test_detection_statistics_and_family_count(self) -> None:
        detections = [
            self.detection("UNKNOWN-LOW", severity=Severity.LOW, risk=10),
            self.detection("DET-PS-001", detection_id="medium", severity=Severity.MEDIUM, risk=45),
            self.detection("DET-PS-002", detection_id="high-ps", severity=Severity.HIGH, risk=70),
            self.detection("DET-CRED-001", detection_id="critical", severity=Severity.CRITICAL, risk=96),
        ]
        features = extract_features([self.event()], detections)
        self.assertEqual(features.detection_count, 4)
        self.assertEqual(
            (features.low_detection_count, features.medium_detection_count,
             features.high_detection_count, features.critical_detection_count),
            (1, 1, 1, 1),
        )
        self.assertEqual(features.unique_detection_family_count, 2)
        self.assertEqual(features.max_detection_risk, 96)

    def test_unknown_rule_counts_but_activates_no_known_behavior(self) -> None:
        features = extract_features([self.event()], [self.detection("DET-FUTURE-999")])
        self.assertEqual(features.detection_count, 1)
        self.assertEqual(features.unique_detection_family_count, 0)
        self.assertEqual(sum(getattr(features, name) for name in FEATURE_NAMES[:7]), 0)

    def test_duplicates_do_not_double_count(self) -> None:
        event = self.event()
        detection = self.detection("DET-PS-001")
        features = extract_features([event, event], [detection, detection])
        self.assertEqual(features.event_count, 1)
        self.assertEqual(features.detection_count, 1)
        self.assertEqual(features.detections_per_event, 1.0)

    def test_conflicting_duplicate_ids_fail_clearly(self) -> None:
        event = self.event()
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate event ID"):
            extract_features([event, replace(event, category="network_connection")], [])
        detection = self.detection("DET-PS-001")
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate detection ID"):
            extract_features([event], [detection, replace(detection, risk_score=84)])

    def test_process_and_network_counts_and_ratio(self) -> None:
        events = [
            self.event(),
            self.event("network-1", seconds=5, category="network_connection"),
            self.event("other-1", seconds=10, category="other"),
        ]
        detections = [self.detection("DET-PS-001")]
        features = extract_features(events, detections)
        self.assertEqual(features.event_count, 3)
        self.assertEqual(features.process_event_count, 1)
        self.assertEqual(features.network_event_count, 1)
        self.assertEqual(features.network_connection_count, 1)
        self.assertAlmostEqual(features.detections_per_event, 1 / 3)

    def test_network_statistics_use_counts_not_identifiers(self) -> None:
        events = [
            self.event("n1", category="network_connection", destination_ip="203.0.113.1", destination_port=443, initiated=True),
            self.event("n2", seconds=1, category="network_connection", destination_ip="203.0.113.1", destination_port=443, initiated=False),
            self.event("n3", seconds=2, category="network_connection", destination_hostname="Example.NET", destination_port=53, initiated=True),
            self.event("n4", seconds=3, category="network_connection", destination_hostname="example.net", destination_port=None, initiated=None),
        ]
        features = extract_features(events, [])
        self.assertEqual(features.unique_destination_count, 2)
        self.assertEqual(features.unique_destination_port_count, 2)
        self.assertEqual(features.outbound_connection_count, 2)

    def test_detection_relative_event_and_network_semantics(self) -> None:
        events = [
            self.event("network-before", seconds=0, category="network_connection"),
            self.event("detected", seconds=10),
            self.event("same-time", seconds=10, category="network_connection"),
            self.event("network-after", seconds=20, category="network_connection"),
            self.event("process-after", seconds=30),
        ]
        detection = self.detection("DET-PS-001", event_id="detected")
        features = extract_features(events, [detection])
        self.assertEqual(features.events_after_first_detection, 2)
        self.assertEqual(features.has_network_after_detection, 1)

        without_after = extract_features(events[:3], [detection])
        self.assertEqual(without_after.has_network_after_detection, 0)
        self.assertEqual(without_after.events_after_first_detection, 0)

    def test_zero_detection_temporal_values_are_neutral(self) -> None:
        features = extract_features([
            self.event("n1", category="network_connection"),
            self.event("n2", seconds=10, category="network_connection"),
        ], [])
        self.assertEqual(features.events_after_first_detection, 0)
        self.assertEqual(features.has_network_after_detection, 0)

    def test_duration_semantics(self) -> None:
        one = extract_features([self.event()], [])
        many = extract_features([self.event("later", seconds=75), self.event("first")], [])
        self.assertEqual(one.incident_duration_seconds, 0.0)
        self.assertEqual(many.incident_duration_seconds, 75.0)

    def test_identifiers_and_sensitive_values_are_not_features(self) -> None:
        forbidden = {"hostname", "username", "source_ip", "destination_ip", "process_guid", "event_id", "incident_id", "timestamp", "command_line"}
        self.assertTrue(all(not any(token in name for token in forbidden) for name in FEATURE_NAMES))
        serialized_vector = json.dumps(to_vector(extract_features([
            self.event(destination_ip="203.0.113.99")
        ], [])))
        for sensitive in ("SensitiveHost", "SensitiveUser", "203.0.113.99", "SENSITIVE-GUID"):
            self.assertNotIn(sensitive, serialized_vector)

    def test_incident_helper_matches_generic_extraction_and_ignores_summary(self) -> None:
        events = [self.event()]
        detections = [self.detection("DET-PS-001")]
        generic = extract_features(events, detections)
        first = extract_incident_features(self.incident(risk_score=99), events, detections)
        second = extract_incident_features(self.incident(risk_score=1, title="Different"), events, detections)
        self.assertEqual(generic, first)
        self.assertEqual(first, second)

    def test_missing_detection_reference_and_naive_timestamp_fail_clearly(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing event IDs"):
            extract_features([self.event()], [self.detection("DET-PS-001", event_id="missing")])
        naive = replace(self.event(), timestamp=datetime(2026, 8, 13, 12, 0))
        with self.assertRaisesRegex(ValueError, "timezone-naive"):
            extract_features([naive], [])

    def test_examples_serialize_labels_and_support_unlabeled_inference(self) -> None:
        features = extract_features([self.event()], [])
        benign = IncidentFeatureExample(
            example_id="benign-1", features=features, source=ExampleSource.SYNTHETIC,
            label=ExampleLabel.BENIGN, group_id="session-a", metadata={"note": "test"},
        )
        malicious = replace(benign, example_id="malicious-1", label=ExampleLabel.MALICIOUS)
        inference = replace(benign, example_id="local-1", source=ExampleSource.LOCAL, label=None, group_id=None)
        self.assertEqual(benign.to_dict()["label"], 0)
        self.assertEqual(malicious.to_dict()["label"], 1)
        self.assertIsNone(inference.to_dict()["label"])
        json.dumps(benign.to_dict())
        self.assertEqual(benign.to_vector(), malicious.to_vector())
        self.assertNotIn("source", FEATURE_NAMES)
        self.assertNotIn("group_id", FEATURE_NAMES)
        self.assertNotIn("metadata", FEATURE_NAMES)


if __name__ == "__main__":
    unittest.main()
