import unittest
import argparse
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch
from tempfile import TemporaryDirectory
from pathlib import Path

from engine.__main__ import _positive_interval, main, run_watch
from engine.tests.test_sysmon_xml import sysmon_xml
from engine.watch import SysmonWatch, event_record_id
from engine.ingestion.sysmon_xml import parse_process_create_xml
from engine.storage.sqlite import SQLiteStorage
from engine.tests.test_sysmon_network import network_xml


class SysmonWatchTests(unittest.TestCase):
    def test_event_record_id_is_numeric_checkpoint(self) -> None:
        data = parse_process_create_xml(sysmon_xml(record_id=9012))

        self.assertEqual(event_record_id(data), 9012)

    def test_startup_baselines_without_replaying_history(self) -> None:
        watch = SysmonWatch(
            recent_collector=lambda **kwargs: [sysmon_xml(record_id=100)],
            newer_collector=lambda *args, **kwargs: [],
        )

        self.assertEqual(watch.establish_baseline(), 100)
        self.assertEqual(watch.poll(), [])

    def test_new_records_are_processed_once_in_chronological_order(self) -> None:
        batches = [
            [sysmon_xml(record_id=103), sysmon_xml(record_id=101), sysmon_xml(record_id=102)],
            [sysmon_xml(record_id=102), sysmon_xml(record_id=104)],
            [],
        ]
        checkpoints: list[int] = []

        def collect_newer(checkpoint: int, **kwargs) -> list[str]:
            checkpoints.append(checkpoint)
            return batches.pop(0)

        watch = SysmonWatch(
            recent_collector=lambda **kwargs: [sysmon_xml(record_id=100)],
            newer_collector=collect_newer,
        )
        watch.establish_baseline()

        first = watch.poll()
        second = watch.poll()
        third = watch.poll()

        self.assertEqual([item.record_id for item in first], [101, 102, 103])
        self.assertEqual([item.record_id for item in second], [104])
        self.assertEqual(third, [])
        self.assertEqual(checkpoints, [100, 103, 104])
        self.assertEqual(watch.checkpoint, 104)

    def test_interleaved_supported_events_share_ordered_checkpoint(self) -> None:
        watch = SysmonWatch(
            recent_collector=lambda **kwargs: [network_xml(record_id=100)],
            newer_collector=lambda *args, **kwargs: [
                network_xml(record_id=103),
                sysmon_xml(record_id=101),
                network_xml(record_id=102),
            ],
        )
        watch.establish_baseline()
        results = watch.poll()
        self.assertEqual([item.record_id for item in results], [101, 102, 103])
        self.assertEqual([item.event.category for item in results], [
            "process_creation", "network_connection", "network_connection"
        ])
        self.assertEqual(watch.checkpoint, 103)

    def test_no_new_events_produce_no_results_or_detections(self) -> None:
        watch = SysmonWatch(
            recent_collector=lambda **kwargs: [sysmon_xml(record_id=100)],
            newer_collector=lambda *args, **kwargs: [],
        )
        watch.establish_baseline()

        self.assertEqual(watch.poll(), [])
        self.assertEqual(watch.poll(), [])

    def test_invalid_watch_intervals_are_rejected(self) -> None:
        for value in ("0", "-1", "not-a-number"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                _positive_interval(value)

    @patch("engine.__main__.collect_recent_sysmon_process_events")
    @patch("sys.argv", ["engine", "--count", "10"])
    def test_existing_one_shot_count_behavior_remains_valid(self, collector) -> None:
        collector.return_value = []

        with redirect_stdout(StringIO()) as output:
            result = main()

        self.assertEqual(result, 0)
        collector.assert_called_once_with(10)
        self.assertIn("No recent", output.getvalue())

    def test_ctrl_c_stops_cleanly_with_summary(self) -> None:
        monitor = SysmonWatch(
            recent_collector=lambda **kwargs: [sysmon_xml(record_id=100)],
            newer_collector=lambda *args, **kwargs: [],
        )
        with patch("engine.__main__.time.sleep", side_effect=KeyboardInterrupt), redirect_stdout(StringIO()) as output:
            counts = run_watch(1.0, monitor=monitor)

        self.assertEqual(counts, (0, 0))
        self.assertIn("Stopped. Processed 0 event(s); produced 0 detection(s).", output.getvalue())

    def test_watch_persists_event_and_generated_detection(self) -> None:
        with TemporaryDirectory() as directory, SQLiteStorage(Path(directory) / "watch.db") as storage:
            watch = SysmonWatch(
                recent_collector=lambda **kwargs: [sysmon_xml(record_id=100)],
                newer_collector=lambda *args, **kwargs: [sysmon_xml(record_id=101)],
                storage=storage,
            )
            watch.establish_baseline()

            results = watch.poll()

            self.assertEqual(len(results), 1)
            self.assertEqual(len(storage.recent_events()), 1)
            self.assertEqual(storage.recent_events()[0].record_id, 101)
            self.assertEqual(storage.recent_detections()[0].rule_id, "DET-PS-001")

    def test_watch_persists_ordinary_event_without_detection(self) -> None:
        ordinary = sysmon_xml(record_id=101, command_line="powershell.exe -NoProfile Get-Process")
        with TemporaryDirectory() as directory, SQLiteStorage(Path(directory) / "watch.db") as storage:
            watch = SysmonWatch(
                recent_collector=lambda **kwargs: [sysmon_xml(record_id=100)],
                newer_collector=lambda *args, **kwargs: [ordinary],
                storage=storage,
            )
            watch.establish_baseline()

            results = watch.poll()

            self.assertEqual(len(results), 1)
            self.assertEqual(len(storage.recent_events()), 1)
            self.assertEqual(storage.recent_detections(), [])


if __name__ == "__main__":
    unittest.main()
