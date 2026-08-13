import subprocess
import unittest
from unittest.mock import patch

from engine.ingestion.windows_event_log import (
    SYSMON_CHANNEL,
    WindowsEventLogError,
    collect_recent_sysmon_process_events,
    collect_sysmon_process_events_after,
    collect_recent_sysmon_events,
    collect_sysmon_events_after,
    split_event_xml,
)
from engine.tests.test_sysmon_xml import sysmon_xml


class WindowsEventLogTests(unittest.TestCase):
    def test_wrapped_multi_event_output_is_separated(self) -> None:
        first = sysmon_xml().replace('<?xml version="1.0" encoding="utf-8"?>', "")
        second = sysmon_xml(command_line="powershell.exe Get-Process").replace(
            '<?xml version="1.0" encoding="utf-8"?>', ""
        )
        output = f'<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">{first}{second}</Events>'

        events = split_event_xml(output)

        self.assertEqual(len(events), 2)
        self.assertTrue(all("<" in event and "Event" in event for event in events))

    def test_adjacent_top_level_events_are_separated(self) -> None:
        first = sysmon_xml().replace('<?xml version="1.0" encoding="utf-8"?>', "")
        second = sysmon_xml(command_line="powershell.exe Get-Process").replace(
            '<?xml version="1.0" encoding="utf-8"?>', ""
        )

        events = split_event_xml(f"{first}{second}")

        self.assertEqual(len(events), 2)

    def test_single_standalone_event_is_preserved(self) -> None:
        events = split_event_xml(sysmon_xml())

        self.assertEqual(len(events), 1)

    def test_malformed_output_fails_clearly(self) -> None:
        with self.assertRaisesRegex(WindowsEventLogError, "Malformed XML returned by wevtutil"):
            split_event_xml("<Event><System></Event>")

    @patch("engine.ingestion.windows_event_log.os.name", "nt")
    @patch("engine.ingestion.windows_event_log.subprocess.run")
    def test_collector_builds_bounded_safe_command(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")

        events = collect_recent_sysmon_process_events(limit=7)

        self.assertEqual(events, [])
        args, kwargs = run_mock.call_args
        command = args[0]
        self.assertEqual(command[:3], ["wevtutil", "qe", SYSMON_CHANNEL])
        self.assertIn("/q:*[System[(EventID=1)]]", command)
        self.assertIn("/c:7", command)
        self.assertIn("/rd:true", command)
        self.assertIn("/f:xml", command)
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], True)

    @patch("engine.ingestion.windows_event_log.os.name", "nt")
    @patch("engine.ingestion.windows_event_log.subprocess.run")
    def test_newer_collector_queries_checkpoint_oldest_first(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")

        collect_sysmon_process_events_after(8421, limit=50)

        command = run_mock.call_args.args[0]
        self.assertIn("/q:*[System[(EventID=1) and (EventRecordID>8421)]]", command)
        self.assertIn("/c:50", command)
        self.assertIn("/rd:false", command)
        self.assertIs(run_mock.call_args.kwargs["shell"], False)

    @patch("engine.ingestion.windows_event_log.os.name", "nt")
    @patch("engine.ingestion.windows_event_log.subprocess.run")
    def test_supported_collector_queries_event_ids_one_and_three(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        collect_recent_sysmon_events(limit=8)
        command = run_mock.call_args.args[0]
        self.assertIn("/q:*[System[(EventID=1 or EventID=3)]]", command)
        self.assertIn("/c:8", command)
        self.assertIs(run_mock.call_args.kwargs["shell"], False)

    @patch("engine.ingestion.windows_event_log.os.name", "nt")
    @patch("engine.ingestion.windows_event_log.subprocess.run")
    def test_supported_newer_query_uses_one_global_channel_checkpoint(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        collect_sysmon_events_after(9000, limit=50)
        command = run_mock.call_args.args[0]
        self.assertIn("EventID=1 or EventID=3", command[3])
        self.assertIn("EventRecordID>9000", command[3])
        self.assertIn("/rd:false", command)

    @patch("engine.ingestion.windows_event_log.os.name", "posix")
    def test_non_windows_collection_fails_clearly(self) -> None:
        with self.assertRaisesRegex(WindowsEventLogError, "only on Windows"):
            collect_recent_sysmon_process_events()

    def test_empty_collector_output_returns_empty_list(self) -> None:
        self.assertEqual(split_event_xml("  \n"), [])


if __name__ == "__main__":
    unittest.main()
