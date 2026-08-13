import unittest

from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_process_create
from engine.ingestion.sysmon_xml import SysmonXmlError, parse_process_create_xml


def sysmon_xml(*, event_id: str = "1", command_line: str = "powershell.exe -EncodedCommand SQBFAFgA") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}" />
    <EventID>{event_id}</EventID>
    <EventRecordID>8421</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WS-FIN-042.siberai.local</Computer>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-08-12 19:32:18.456</Data>
    <Data Name="ProcessGuid">{{A23D7E91-7712-0001-8F10-000000001A00}}</Data>
    <Data Name="ProcessId">6420</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">{command_line}</Data>
    <Data Name="CurrentDirectory">C:\\Users\\analyst\\Documents\\</Data>
    <Data Name="User">SIBERAI\\analyst</Data>
    <Data Name="ParentProcessGuid">{{A23D7E91-7701-0001-6C0F-000000001A00}}</Data>
    <Data Name="ParentProcessId">4912</Data>
    <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
    <Data Name="ParentCommandLine">WINWORD.EXE /n</Data>
  </EventData>
</Event>"""


class SysmonXmlTests(unittest.TestCase):
    def test_parses_namespaced_event_id_one(self) -> None:
        parsed = parse_process_create_xml(sysmon_xml())

        self.assertEqual(parsed["_System"]["EventID"], "1")
        self.assertEqual(parsed["_System"]["RecordID"], "8421")

    def test_extracts_computer(self) -> None:
        parsed = parse_process_create_xml(sysmon_xml())

        self.assertEqual(parsed["Computer"], "WS-FIN-042.siberai.local")

    def test_extracts_named_event_data(self) -> None:
        parsed = parse_process_create_xml(sysmon_xml())

        self.assertEqual(parsed["ProcessId"], "6420")
        self.assertEqual(parsed["User"], r"SIBERAI\analyst")
        self.assertTrue(parsed["Image"].endswith("powershell.exe"))

    def test_xml_normalizer_integration(self) -> None:
        event = normalize_process_create(parse_process_create_xml(sysmon_xml()))

        self.assertEqual(event.process, "powershell.exe")
        self.assertEqual(event.parent_process, "WINWORD.EXE")
        self.assertEqual(event.host, "WS-FIN-042.siberai.local")
        self.assertEqual(event.raw["_System"]["Channel"], "Microsoft-Windows-Sysmon/Operational")

    def test_encoded_powershell_xml_triggers_existing_rule(self) -> None:
        event = normalize_process_create(parse_process_create_xml(sysmon_xml()))

        detections = detect(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "DET-PS-001")

    def test_ordinary_powershell_xml_produces_no_detection(self) -> None:
        event = normalize_process_create(
            parse_process_create_xml(sysmon_xml(command_line="powershell.exe -NoProfile Get-Process"))
        )

        self.assertEqual(detect(event), [])

    def test_non_event_id_one_is_rejected(self) -> None:
        with self.assertRaisesRegex(SysmonXmlError, "Expected Sysmon Event ID 1"):
            parse_process_create_xml(sysmon_xml(event_id="3"))

    def test_malformed_xml_fails_clearly(self) -> None:
        with self.assertRaisesRegex(SysmonXmlError, "Malformed Sysmon event XML"):
            parse_process_create_xml("<Event><System>")


if __name__ == "__main__":
    unittest.main()
