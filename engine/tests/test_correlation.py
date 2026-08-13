import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from engine.correlation.engine import CORRELATION_WINDOW_SECONDS, correlate
from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_sysmon_event
from engine.ingestion.sysmon_xml import parse_sysmon_xml
from engine.models.detection import Detection, Severity
from engine.storage.sqlite import SQLiteStorage
from engine.tests.test_sysmon_network import network_xml
from engine.tests.test_sysmon_xml import sysmon_xml
from engine.analysis.decision_engine import DECISION_ENGINE_VERSION, analyze_incident
from engine.models.analysis import Verdict


class CorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.storage = SQLiteStorage(Path(self.directory.name) / "correlation.db")

    def tearDown(self) -> None:
        self.storage.close()
        self.directory.cleanup()

    def process_event(self, *, event_id: str = "process-1", host: str | None = "ServoPC", guid: str = "{GUID-X}"):
        event = normalize_sysmon_event(parse_sysmon_xml(sysmon_xml(record_id=100)))
        return replace(event, event_id=event_id, host=host, process_guid=guid)

    def network_event(self, *, event_id: str = "network-1", host: str | None = "ServoPC", guid: str = "{GUID-X}"):
        event = normalize_sysmon_event(parse_sysmon_xml(network_xml(record_id=101)))
        return replace(event, event_id=event_id, host=host, process_guid=guid)

    def detection(self, event_id: str, severity: Severity, risk: int, rule: str = "TEST-001") -> Detection:
        return Detection(
            detection_id=f"{rule}:{event_id}", event_id=event_id, rule_id=rule,
            title=f"{severity.value.title()} test detection", severity=severity,
            risk_score=risk, description="Correlation test", mitre_techniques=[],
        )

    def persist_and_correlate(self, event, detections):
        self.storage.store_event(event)
        for item in detections:
            self.storage.store_detection(item)
        return correlate(event, detections, self.storage)

    def test_high_and_critical_create_incidents_but_medium_does_not(self) -> None:
        for severity, creates in ((Severity.HIGH, True), (Severity.CRITICAL, True), (Severity.MEDIUM, False)):
            with self.subTest(severity=severity):
                event = self.process_event(event_id=f"event-{severity.value}", guid=f"{{{severity.value}}}")
                result = self.persist_and_correlate(event, [self.detection(event.event_id, severity, 80)])
                self.assertEqual(result.incident is not None, creates)

    def test_multiple_qualifying_detections_create_one_incident(self) -> None:
        event = self.process_event()
        detections = [
            self.detection(event.event_id, Severity.HIGH, 80, "HIGH-RULE"),
            self.detection(event.event_id, Severity.CRITICAL, 95, "CRIT-RULE"),
        ]
        result = self.persist_and_correlate(event, detections)
        self.assertTrue(result.created)
        self.assertEqual(len(self.storage.recent_incidents()), 1)
        self.assertEqual(result.incident.severity, Severity.CRITICAL)
        self.assertEqual(result.incident.risk_score, 95)
        self.assertEqual(result.incident.title, "Critical test detection")
        self.assertEqual(len(result.incident.detection_ids), 2)

    def test_exact_process_guid_attaches_network_event(self) -> None:
        process = self.process_event()
        incident = self.persist_and_correlate(
            process, [self.detection(process.event_id, Severity.HIGH, 85)]
        ).incident
        network = replace(self.network_event(), timestamp=process.timestamp + timedelta(seconds=20))
        result = self.persist_and_correlate(network, [])
        self.assertEqual(result.incident.incident_id, incident.incident_id)
        self.assertTrue(result.event_attached)
        self.assertEqual(set(result.incident.event_ids), {process.event_id, network.event_id})
        self.assertEqual(result.incident.risk_score, 85)

    def test_process_name_or_pid_without_guid_match_does_not_correlate(self) -> None:
        process = replace(self.process_event(), process="powershell.exe", process_id=500)
        self.persist_and_correlate(process, [self.detection(process.event_id, Severity.HIGH, 85)])
        network = replace(
            self.network_event(guid="{DIFFERENT}"), process="powershell.exe",
            process_id=500, timestamp=process.timestamp + timedelta(seconds=10),
        )
        self.assertIsNone(self.persist_and_correlate(network, []).incident)

    def test_host_mismatch_and_outside_window_do_not_correlate(self) -> None:
        process = self.process_event()
        self.persist_and_correlate(process, [self.detection(process.event_id, Severity.HIGH, 85)])
        wrong_host = replace(self.network_event(event_id="wrong-host", host="OtherPC"), timestamp=process.timestamp)
        too_late = replace(
            self.network_event(event_id="too-late"),
            timestamp=process.timestamp + timedelta(seconds=CORRELATION_WINDOW_SECONDS + 1),
        )
        self.assertIsNone(self.persist_and_correlate(wrong_host, []).incident)
        self.assertIsNone(self.persist_and_correlate(too_late, []).incident)

    def test_preexisting_network_event_attaches_when_incident_is_created(self) -> None:
        process = self.process_event()
        network = replace(self.network_event(), timestamp=process.timestamp - timedelta(seconds=15))
        self.storage.store_event(network)
        result = self.persist_and_correlate(
            process, [self.detection(process.event_id, Severity.HIGH, 85)]
        )
        self.assertEqual(set(result.incident.event_ids), {network.event_id, process.event_id})

    def test_duplicate_processing_is_idempotent(self) -> None:
        event = self.process_event()
        detections = [self.detection(event.event_id, Severity.HIGH, 85)]
        first = self.persist_and_correlate(event, detections)
        second = correlate(event, detections, self.storage)
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        detail = self.storage.get_incident_detail(first.incident.incident_id)
        self.assertEqual(len(self.storage.recent_incidents()), 1)
        self.assertEqual(len(detail.events), 1)
        self.assertEqual(len(detail.detections), 1)

    def test_storage_list_and_detail_retrieval(self) -> None:
        event = self.process_event()
        result = self.persist_and_correlate(
            event, [self.detection(event.event_id, Severity.HIGH, 85, "DET-PS-001")]
        )
        listed = self.storage.recent_incidents()
        detail = self.storage.get_incident_detail(result.incident.incident_id)
        self.assertEqual(listed[0].incident_id, result.incident.incident_id)
        self.assertEqual(detail.incident.primary_event_id, event.event_id)
        self.assertEqual(detail.events[0].event_id, event.event_id)
        self.assertEqual(detail.detections[0].event_id, event.event_id)

    def test_analysis_persistence_and_reanalysis_update_current_row(self) -> None:
        event = self.process_event()
        result = self.persist_and_correlate(
            event, [self.detection(event.event_id, Severity.HIGH, 85, "DET-PS-001")]
        )
        detail = self.storage.get_incident_detail(result.incident.incident_id)
        first_time = event.timestamp + timedelta(minutes=1)
        first = self.storage.store_analysis(
            analyze_incident(detail.incident, detail.events, detail.detections, now=first_time)
        )
        network = replace(self.network_event(), timestamp=event.timestamp + timedelta(seconds=30))
        self.persist_and_correlate(network, [])
        detail = self.storage.get_incident_detail(result.incident.incident_id)
        second_time = first_time + timedelta(minutes=1)
        second = self.storage.store_analysis(
            analyze_incident(detail.incident, detail.events, detail.detections, now=second_time)
        )
        self.assertEqual(first.analysis_id, second.analysis_id)
        self.assertEqual(second.engine_version, DECISION_ENGINE_VERSION)
        self.assertEqual(second.created_at, first_time)
        self.assertEqual(second.updated_at, second_time)
        self.assertEqual(second.verdict, Verdict.LIKELY_MALICIOUS)
        count = self.storage._connection.execute("SELECT count(*) FROM incident_analyses").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
