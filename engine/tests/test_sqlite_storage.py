import sqlite3
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
from pathlib import Path

from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_process_create
from engine.ingestion.sysmon_xml import parse_process_create_xml
from engine.models.detection import Detection, Severity
from engine.storage.sqlite import SQLiteStorage, StorageError
from engine.tests.test_sysmon_xml import sysmon_xml
from engine.ingestion.sysmon import normalize_sysmon_event
from engine.ingestion.sysmon_xml import parse_sysmon_xml
from engine.tests.test_sysmon_network import network_xml


class SQLiteStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "siberai.db"
        self.storage = SQLiteStorage(self.database)

    def tearDown(self) -> None:
        self.storage.close()
        self.temporary_directory.cleanup()

    def make_event(self, *, record_id: int = 8421, command_line: str = "powershell.exe -EncodedCommand SQBFAFgA"):
        return normalize_process_create(
            parse_process_create_xml(sysmon_xml(record_id=record_id, command_line=command_line))
        )

    def test_schema_initialization(self) -> None:
        connection = sqlite3.connect(self.database)
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            foreign_keys = list(connection.execute("PRAGMA foreign_key_list(detections)"))
        finally:
            connection.close()

        self.assertEqual({"events", "detections"} - tables, set())
        self.assertTrue(any(row[2] == "events" and row[3] == "event_id" for row in foreign_keys))

    def test_security_event_insertion_and_json_round_trip(self) -> None:
        event = self.make_event()

        self.assertTrue(self.storage.store_event(event))
        stored = self.storage.recent_events()[0]

        self.assertEqual(stored.event_id, event.event_id)
        self.assertEqual(stored.record_id, 8421)
        self.assertEqual(stored.timestamp.tzinfo, timezone.utc)
        self.assertEqual(stored.raw, event.raw)

    def test_detection_insertion_and_json_round_trip(self) -> None:
        event = self.make_event()
        detection = detect(event)[0]
        self.storage.store_event(event)

        self.assertTrue(self.storage.store_detection(detection))
        stored = self.storage.recent_detections()[0]

        self.assertEqual(stored.mitre_techniques, ["T1059.001"])
        self.assertEqual(stored.evidence, detection.evidence)
        self.assertEqual(stored.host, event.host)

    def test_foreign_key_is_enforced(self) -> None:
        orphan = Detection(
            detection_id="orphan", event_id="missing", rule_id="TEST-001",
            title="Orphan", severity=Severity.LOW, risk_score=10,
            description="Should fail",
        )

        with self.assertRaisesRegex(StorageError, "FOREIGN KEY constraint failed"):
            self.storage.store_detection(orphan)

    def test_duplicate_event_is_ignored_without_overwrite(self) -> None:
        event = self.make_event()
        self.assertTrue(self.storage.store_event(event))

        self.assertFalse(self.storage.store_event(replace(event, host="changed-host")))

        events = self.storage.recent_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].host, event.host)

    def test_duplicate_detection_is_ignored_without_overwrite(self) -> None:
        event = self.make_event()
        detection = detect(event)[0]
        self.storage.store_event(event)
        self.assertTrue(self.storage.store_detection(detection))

        self.assertFalse(self.storage.store_detection(replace(detection, title="Changed")))

        detections = self.storage.recent_detections()
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].title, detection.title)

    def test_none_raw_round_trips_cleanly(self) -> None:
        event = replace(self.make_event(), event_id="no-raw", raw=None)

        self.storage.store_event(event)

        self.assertIsNone(self.storage.recent_events()[0].raw)

    def test_recent_events_are_newest_first(self) -> None:
        older = replace(self.make_event(record_id=1), event_id="older", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
        newer = replace(self.make_event(record_id=2), event_id="newer", timestamp=datetime(2026, 2, 1, tzinfo=timezone.utc))
        self.storage.store_event(older, 1)
        self.storage.store_event(newer, 2)

        self.assertEqual([item.event_id for item in self.storage.recent_events()], ["newer", "older"])

    def test_recent_detections_are_newest_event_first(self) -> None:
        older = replace(self.make_event(record_id=1), event_id="older", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
        newer = replace(self.make_event(record_id=2), event_id="newer", timestamp=datetime(2026, 2, 1, tzinfo=timezone.utc))
        for event in (older, newer):
            self.storage.store_event(event)
            self.storage.store_detection(replace(detect(event)[0], detection_id=f"det-{event.event_id}"))

        self.assertEqual([item.event_id for item in self.storage.recent_detections()], ["newer", "older"])

    def test_detections_can_be_retrieved_by_event_id(self) -> None:
        event = self.make_event()
        detection = detect(event)[0]
        self.storage.store_event(event)
        self.storage.store_detection(detection)

        self.assertEqual(self.storage.detections_for_event(event.event_id)[0].detection_id, detection.detection_id)
        self.assertEqual(self.storage.detections_for_event("missing"), [])

    def test_single_event_and_detection_lookups(self) -> None:
        event = self.make_event()
        detection = detect(event)[0]
        self.storage.store_event(event)
        self.storage.store_detection(detection)

        self.assertEqual(self.storage.get_event(event.event_id).event_id, event.event_id)
        stored_detection = self.storage.get_detection(detection.detection_id)
        self.assertEqual(stored_detection.detection_id, detection.detection_id)
        self.assertEqual(stored_detection.process, "powershell.exe")
        self.assertIsNone(self.storage.get_event("missing"))
        self.assertIsNone(self.storage.get_detection("missing"))

    def test_network_event_round_trip(self) -> None:
        event = normalize_sysmon_event(parse_sysmon_xml(network_xml(record_id=9100)))
        self.assertTrue(self.storage.store_event(event))
        stored = self.storage.get_event(event.event_id)
        self.assertEqual(stored.process_guid, "{NET-PROCESS-GUID}")
        self.assertEqual(stored.process_id, 4120)
        self.assertEqual(stored.source_port, 54321)
        self.assertEqual(stored.destination_port, 443)
        self.assertEqual(stored.protocol, "tcp")
        self.assertIs(stored.initiated, True)
        self.assertEqual(stored.destination_hostname, "example.net")

    def test_existing_database_is_upgraded_without_deletion(self) -> None:
        legacy = Path(self.temporary_directory.name) / "legacy.db"
        connection = sqlite3.connect(legacy)
        connection.executescript("""
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY, record_id INTEGER, timestamp TEXT NOT NULL,
                source_type TEXT NOT NULL, category TEXT NOT NULL, host TEXT, user TEXT,
                process TEXT, parent_process TEXT, command_line TEXT, source_ip TEXT,
                destination_ip TEXT, raw_json TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE detections (
                detection_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, rule_id TEXT NOT NULL,
                title TEXT NOT NULL, severity TEXT NOT NULL, risk_score INTEGER NOT NULL,
                description TEXT NOT NULL, mitre_json TEXT NOT NULL, evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL, FOREIGN KEY (event_id) REFERENCES events(event_id)
            );
            INSERT INTO events VALUES ('legacy', 1, '2026-01-01T00:00:00Z', 'sysmon',
                'process_creation', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'null',
                '2026-01-01T00:00:00Z');
            INSERT INTO detections VALUES ('legacy-det', 'legacy', 'LEGACY-001', 'Legacy',
                'high', 80, 'Existing detection', '[]', '{}', '2026-01-01T00:00:00Z');
        """)
        connection.commit()
        connection.close()

        with SQLiteStorage(legacy) as upgraded:
            self.assertEqual(upgraded.get_event("legacy").event_id, "legacy")
            self.assertEqual(upgraded.get_detection("legacy-det").detection_id, "legacy-det")
            columns = {row[1] for row in upgraded._connection.execute("PRAGMA table_info(events)")}
            tables = {row[0] for row in upgraded._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )}
        self.assertTrue({"process_guid", "source_port", "destination_hostname"} <= columns)
        self.assertTrue({"incidents", "incident_events", "incident_detections"} <= tables)


if __name__ == "__main__":
    unittest.main()
