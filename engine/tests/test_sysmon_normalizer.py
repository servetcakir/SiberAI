import unittest
from datetime import timezone

from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_process_create


class SysmonNormalizerTests(unittest.TestCase):
    def make_sysmon_event(self, **overrides: object) -> dict[str, object]:
        event: dict[str, object] = {
            "UtcTime": "2026-08-12 19:32:18.456",
            "ProcessGuid": "{A23D7E91-7712-0001-8F10-000000001A00}",
            "ProcessId": "6420",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
            "CurrentDirectory": "C:\\Users\\analyst\\Documents\\",
            "User": r"SIBERAI\analyst",
            "ParentProcessGuid": "{A23D7E91-7701-0001-6C0F-000000001A00}",
            "ParentProcessId": "4912",
            "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "ParentCommandLine": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n',
            "Computer": "WS-FIN-042.siberai.local",
        }
        event.update(overrides)
        return event

    def test_realistic_process_create_normalizes_correctly(self) -> None:
        source = self.make_sysmon_event()

        event = normalize_process_create(source)

        self.assertEqual(event.event_id, source["ProcessGuid"])
        self.assertEqual(event.source_type, "sysmon")
        self.assertEqual(event.category, "process_creation")
        self.assertEqual(event.host, "WS-FIN-042.siberai.local")
        self.assertEqual(event.user, r"SIBERAI\analyst")
        self.assertEqual(event.command_line, source["CommandLine"])
        self.assertEqual(event.process_guid, source["ProcessGuid"])
        self.assertEqual(event.process_id, 6420)
        self.assertEqual(event.raw, source)
        self.assertIsNot(event.raw, source)

    def test_windows_executable_path_becomes_process_name(self) -> None:
        event = normalize_process_create(self.make_sysmon_event())

        self.assertEqual(event.process, "powershell.exe")

    def test_parent_windows_path_becomes_process_name(self) -> None:
        event = normalize_process_create(self.make_sysmon_event())

        self.assertEqual(event.parent_process, "WINWORD.EXE")

    def test_utc_timestamp_is_timezone_aware(self) -> None:
        event = normalize_process_create(self.make_sysmon_event())

        self.assertIsNotNone(event.timestamp.tzinfo)
        self.assertEqual(event.timestamp.utcoffset(), timezone.utc.utcoffset(None))
        self.assertEqual(event.timestamp.microsecond, 456000)

    def test_missing_optional_fields_do_not_crash(self) -> None:
        event = normalize_process_create(
            {
                "UtcTime": "2026-08-12T19:32:18Z",
                "ProcessGuid": "{A23D7E91-7712-0001-8F10-000000001A00}",
            }
        )

        self.assertIsNone(event.host)
        self.assertIsNone(event.user)
        self.assertIsNone(event.process)
        self.assertIsNone(event.parent_process)
        self.assertIsNone(event.command_line)

    def test_invalid_timestamp_fails_clearly(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid Sysmon UtcTime"):
            normalize_process_create(
                self.make_sysmon_event(UtcTime="not-a-timestamp")
            )

    def test_normalized_encoded_powershell_triggers_existing_rule(self) -> None:
        event = normalize_process_create(self.make_sysmon_event())

        detections = detect(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "DET-PS-001")
        self.assertEqual(detections[0].event_id, event.event_id)

    def test_normalized_ordinary_powershell_does_not_trigger(self) -> None:
        event = normalize_process_create(
            self.make_sysmon_event(
                CommandLine="powershell.exe -NoProfile Get-Process"
            )
        )

        self.assertEqual(detect(event), [])


if __name__ == "__main__":
    unittest.main()
