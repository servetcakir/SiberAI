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


if __name__ == "__main__":
    unittest.main()
