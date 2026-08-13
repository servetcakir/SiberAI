import unittest
from datetime import timezone

from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_network_connection, normalize_sysmon_event
from engine.ingestion.sysmon_xml import parse_sysmon_xml


def network_xml(*, record_id: int = 9003, process: str = "chrome.exe", initiated: str = "true") -> str:
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>3</EventID>
    <EventRecordID>{record_id}</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>ServoPC</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-08-12 20:01:02.123</Data>
    <Data Name="ProcessGuid">{{NET-PROCESS-GUID}}</Data>
    <Data Name="ProcessId">4120</Data>
    <Data Name="Image">C:\\Program Files\\Browser\\{process}</Data>
    <Data Name="User">SIBERAI\\analyst</Data>
    <Data Name="Protocol">TCP</Data>
    <Data Name="Initiated">{initiated}</Data>
    <Data Name="SourceIsIpv6">false</Data>
    <Data Name="SourceIp">192.168.1.25</Data>
    <Data Name="SourceHostname">ServoPC</Data>
    <Data Name="SourcePort">54321</Data>
    <Data Name="SourcePortName">-</Data>
    <Data Name="DestinationIsIpv6">false</Data>
    <Data Name="DestinationIp">142.250.191.46</Data>
    <Data Name="DestinationHostname">example.net</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="DestinationPortName">https</Data>
  </EventData>
</Event>"""


class SysmonNetworkTests(unittest.TestCase):
    def test_event_id_three_xml_parsing_and_normalization(self) -> None:
        parsed = parse_sysmon_xml(network_xml())
        event = normalize_sysmon_event(parsed)

        self.assertEqual(parsed["_System"]["EventID"], "3")
        self.assertEqual(event.category, "network_connection")
        self.assertEqual(event.process_guid, "{NET-PROCESS-GUID}")
        self.assertEqual(event.process_id, 4120)
        self.assertEqual(event.process, "chrome.exe")
        self.assertEqual(event.source_ip, "192.168.1.25")
        self.assertEqual(event.destination_ip, "142.250.191.46")
        self.assertEqual(event.source_port, 54321)
        self.assertEqual(event.destination_port, 443)
        self.assertEqual(event.protocol, "tcp")
        self.assertIs(event.initiated, True)
        self.assertEqual(event.source_hostname, "ServoPC")
        self.assertEqual(event.destination_hostname, "example.net")
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)
        self.assertEqual(event.raw, parsed)

    def test_network_event_id_is_deterministic_from_channel_and_record(self) -> None:
        first = normalize_sysmon_event(parse_sysmon_xml(network_xml(record_id=9010)))
        second = normalize_sysmon_event(parse_sysmon_xml(network_xml(record_id=9010)))
        self.assertEqual(first.event_id, second.event_id)
        self.assertEqual(first.event_id, "sysmon:operational:9010")

    def test_missing_optional_network_fields_are_none(self) -> None:
        event = normalize_network_connection({
            "UtcTime": "2026-08-12T20:01:02Z",
            "_System": {"EventID": "3", "RecordID": "7", "Channel": "Microsoft-Windows-Sysmon/Operational"},
        })
        self.assertIsNone(event.process_guid)
        self.assertIsNone(event.source_port)
        self.assertIsNone(event.initiated)

    def test_malformed_typed_fields_fail_clearly(self) -> None:
        base = parse_sysmon_xml(network_xml())
        for field, value in (("ProcessId", "abc"), ("SourcePort", "-1"), ("DestinationPort", "70000"), ("Initiated", "maybe")):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, f"Invalid Sysmon {field}"):
                normalize_network_connection({**base, field: value})

    def test_process_rules_do_not_run_on_network_events(self) -> None:
        for process, command_line in (
            ("powershell.exe", "powershell -EncodedCommand AAAA"),
            ("certutil.exe", "certutil -decode in out"),
        ):
            with self.subTest(process=process):
                event = normalize_sysmon_event(parse_sysmon_xml(network_xml(process=process)))
                event.command_line = command_line
                self.assertEqual(detect(event), [])


if __name__ == "__main__":
    unittest.main()
