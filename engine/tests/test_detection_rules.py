import unittest
from datetime import datetime, timezone
from typing import Any
from unittest.mock import Mock, patch

from engine.detection import engine
from engine.detection.engine import RULES, detect
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


class DetectionRuleTests(unittest.TestCase):
    def make_event(self, **overrides: object) -> SecurityEvent:
        values: dict[str, Any] = {
            "event_id": "evt-rules-001",
            "timestamp": datetime(2026, 8, 12, tzinfo=timezone.utc),
            "source_type": "sysmon",
            "category": "process_creation",
        }
        values.update(overrides)
        return SecurityEvent(**values)

    def rule_ids(self, **overrides: object) -> list[str]:
        return [item.rule_id for item in detect(self.make_event(**overrides))]

    def test_registry_contains_expected_rules(self) -> None:
        self.assertEqual(len(RULES), 10)
        samples = [
            ("DET-PS-001", {"process": "powershell.exe", "command_line": "powershell -enc AAAA"}),
            ("DET-PS-002", {"process": "powershell.exe", "command_line": "powershell -ep bypass -w hidden"}),
            ("DET-OFFICE-001", {"parent_process": "winword.exe", "process": "cmd.exe", "command_line": "cmd /c whoami"}),
            ("DET-LOL-001", {"process": "certutil.exe", "command_line": "certutil -decode in out"}),
            ("DET-LOL-002", {"process": "mshta.exe", "command_line": "mshta https://example.invalid/a.hta"}),
            ("DET-LOL-003", {"process": "rundll32.exe", "command_line": "rundll32 javascript:alert(1)"}),
            ("DET-CRED-001", {"process": "procdump64.exe", "command_line": "procdump64 -ma lsass.exe dump.dmp"}),
            ("DET-PERSIST-001", {"process": "schtasks.exe", "command_line": "schtasks /create /tn Update /tr calc.exe"}),
            ("DET-PERSIST-002", {"process": "reg.exe", "command_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d calc.exe"}),
            ("DET-DEFENSE-001", {"process": "powershell.exe", "command_line": "powershell Set-MpPreference -DisableRealtimeMonitoring $true"}),
        ]
        for expected, event in samples:
            with self.subTest(rule=expected):
                self.assertIn(expected, self.rule_ids(**event))

    def test_powershell_suspicious_options_requires_combination(self) -> None:
        self.assertIn("DET-PS-002", self.rule_ids(
            process="PoWeRsHeLl.ExE", command_line="powershell -EXECUTIONPOLICY BYPASS -WINDOWSTYLE HIDDEN"
        ))
        self.assertNotIn("DET-PS-002", self.rule_ids(
            process="powershell.exe", command_line="powershell -ExecutionPolicy RemoteSigned"
        ))
        self.assertNotIn("DET-PS-002", self.rule_ids(
            process="powershell.exe", command_line="powershell -WindowStyle Hidden"
        ))

    def test_office_shell_requires_office_parent_and_interpreter_child(self) -> None:
        self.assertIn("DET-OFFICE-001", self.rule_ids(
            parent_process="EXCEL.EXE", process="PWSH.EXE", command_line="pwsh -File report.ps1"
        ))
        self.assertNotIn("DET-OFFICE-001", self.rule_ids(
            parent_process="winword.exe", process="powershell.exe", command_line="powershell -NoProfile Get-Process"
        ))
        self.assertNotIn("DET-OFFICE-001", self.rule_ids(
            parent_process="explorer.exe", process="cmd.exe", command_line="cmd /c dir"
        ))
        self.assertNotIn("DET-OFFICE-001", self.rule_ids(
            parent_process="winword.exe", process="acrobat.exe", command_line="acrobat document.pdf"
        ))

    def test_certutil_requires_transfer_or_decode_behavior(self) -> None:
        self.assertIn("DET-LOL-001", self.rule_ids(
            process="CERTUTIL.EXE", command_line="certutil -URLCACHE -split -f HTTPS://example.invalid/file.bin out.bin"
        ))
        self.assertIn("DET-LOL-001", self.rule_ids(
            process="certutil.exe", command_line="certutil -decode input.txt output.bin"
        ))
        self.assertNotIn("DET-LOL-001", self.rule_ids(
            process="certutil.exe", command_line="certutil -store My"
        ))
        self.assertNotIn("DET-LOL-001", self.rule_ids(
            process="certutil.exe", command_line="certutil -urlcache"
        ))

    def test_mshta_requires_remote_or_script_content(self) -> None:
        self.assertIn("DET-LOL-002", self.rule_ids(
            process="MSHTA.EXE", command_line="mshta.exe JAVASCRIPT:close()"
        ))
        self.assertNotIn("DET-LOL-002", self.rule_ids(
            process="mshta.exe", command_line=r"mshta.exe C:\Admin\approved.hta"
        ))

    def test_rundll32_requires_script_protocol(self) -> None:
        self.assertIn("DET-LOL-003", self.rule_ids(
            process="RUNDLL32.EXE", command_line='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"'
        ))
        self.assertNotIn("DET-LOL-003", self.rule_ids(
            process="rundll32.exe", command_line="rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl"
        ))

    def test_credential_rule_requires_full_memory_switch_and_lsass_target(self) -> None:
        self.assertIn("DET-CRED-001", self.rule_ids(
            process="PROCDUMP64.EXE", command_line="procdump64.exe -MA LSASS.EXE lsass.dmp"
        ))
        self.assertNotIn("DET-CRED-001", self.rule_ids(
            process="procdump.exe", command_line="procdump.exe -ma example.exe example.dmp"
        ))
        self.assertNotIn("DET-CRED-001", self.rule_ids(
            process="procdump.exe", command_line="procdump.exe lsass.exe lsass.dmp"
        ))

    def test_scheduled_task_requires_create_switch_boundary(self) -> None:
        self.assertIn("DET-PERSIST-001", self.rule_ids(
            process="SCHTASKS.EXE", command_line="schtasks.exe /CREATE /tn Update /tr calc.exe"
        ))
        self.assertNotIn("DET-PERSIST-001", self.rule_ids(
            process="schtasks.exe", command_line="schtasks.exe /query"
        ))
        self.assertNotIn("DET-PERSIST-001", self.rule_ids(
            process="schtasks.exe", command_line="schtasks.exe /creator administrator"
        ))

    def test_registry_run_key_requires_reg_add_and_run_key(self) -> None:
        self.assertIn("DET-PERSIST-002", self.rule_ids(
            process="REG.EXE", command_line="REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v Update /d calc.exe"
        ))
        self.assertNotIn("DET-PERSIST-002", self.rule_ids(
            process="reg.exe", command_line="reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ))
        self.assertNotIn("DET-PERSIST-002", self.rule_ids(
            process="reg.exe", command_line="reg add HKCU\\Software\\SiberAI /v Enabled /d 1"
        ))

    def test_defender_impairment_requires_explicit_disable_true(self) -> None:
        self.assertIn("DET-DEFENSE-001", self.rule_ids(
            process="PWSH.EXE", command_line="Set-MpPreference -DisableRealtimeMonitoring TRUE"
        ))
        self.assertNotIn("DET-DEFENSE-001", self.rule_ids(
            process="powershell.exe", command_line="Get-MpPreference"
        ))
        self.assertNotIn("DET-DEFENSE-001", self.rule_ids(
            process="powershell.exe", command_line="Set-MpPreference -DisableRealtimeMonitoring $false"
        ))

    def test_one_event_can_produce_multiple_detections(self) -> None:
        ids = self.rule_ids(
            process="powershell.exe",
            command_line="powershell -EncodedCommand AAAA -ExecutionPolicy Bypass -WindowStyle Hidden",
        )
        self.assertEqual(ids, ["DET-PS-001", "DET-PS-002"])

    def test_detection_ids_are_deterministic_and_unique_per_rule_event(self) -> None:
        event = self.make_event(
            process="powershell.exe",
            command_line="powershell -enc AAAA -ep bypass -w hidden",
        )
        first = [item.detection_id for item in detect(event)]
        second = [item.detection_id for item in detect(event)]
        self.assertEqual(first, second)
        self.assertEqual(len(first), len(set(first)))
        self.assertEqual(first, ["DET-PS-001:evt-rules-001", "DET-PS-002:evt-rules-001"])

    def test_registry_evaluates_every_registered_rule(self) -> None:
        first = Mock(return_value=None)
        second = Mock(return_value=None)
        event = self.make_event()
        with patch.object(engine, "RULES", (first, second)):
            self.assertEqual(engine.detect(event), [])
        first.assert_called_once_with(event)
        second.assert_called_once_with(event)

    def test_missing_optional_fields_are_safe_for_every_rule(self) -> None:
        self.assertEqual(detect(self.make_event()), [])

    def test_evidence_contains_only_selected_non_null_fields(self) -> None:
        detection = detect(self.make_event(
            process="schtasks.exe", command_line="schtasks /create /tn Demo /tr calc.exe"
        ))[0]
        self.assertEqual(set(detection.evidence), {"process", "command_line"})
        self.assertNotIn("raw", detection.evidence)

    def test_rule_severity_and_scores_are_deliberately_varied(self) -> None:
        event = self.make_event(
            process="powershell.exe",
            command_line="powershell -enc AAAA -ep bypass -w hidden Set-MpPreference -DisableRealtimeMonitoring $true",
        )
        detections = detect(event)
        self.assertEqual(
            {(item.rule_id, item.severity, item.risk_score) for item in detections},
            {
                ("DET-PS-001", Severity.HIGH, 85),
                ("DET-PS-002", Severity.MEDIUM, 70),
                ("DET-DEFENSE-001", Severity.CRITICAL, 94),
            },
        )


if __name__ == "__main__":
    unittest.main()
