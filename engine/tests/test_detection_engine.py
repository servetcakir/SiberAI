import unittest
from datetime import datetime, timezone
from typing import Any

from engine.detection.engine import detect
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


class DetectionEngineTests(unittest.TestCase):
    def make_event(self, **overrides: object) -> SecurityEvent:
        values: dict[str, Any] = {
            "event_id": "evt-001",
            "timestamp": datetime(2026, 8, 12, 19, 32, tzinfo=timezone.utc),
            "source_type": "endpoint",
            "category": "process_execution",
        }
        values.update(overrides)
        return SecurityEvent(**values)

    def test_encoded_powershell_is_detected(self) -> None:
        event = self.make_event(
            process="powershell.exe",
            command_line="powershell.exe -EncodedCommand SQBFAFgA",
        )

        detections = detect(event)

        self.assertEqual(len(detections), 1)
        detection = detections[0]
        self.assertEqual(detection.rule_id, "DET-PS-001")
        self.assertEqual(detection.severity, Severity.HIGH)
        self.assertEqual(detection.risk_score, 85)
        self.assertEqual(detection.mitre_techniques, ["T1059.001"])
        self.assertEqual(detection.evidence["process"], "powershell.exe")
        self.assertEqual(
            detection.evidence["command_line"],
            "powershell.exe -EncodedCommand SQBFAFgA",
        )

    def test_matching_is_case_insensitive(self) -> None:
        event = self.make_event(
            process="PWSH.EXE",
            command_line="pwsh.exe -EnC SQBFAFgA",
        )

        self.assertEqual(len(detect(event)), 1)

    def test_normal_powershell_does_not_trigger(self) -> None:
        event = self.make_event(
            process="powershell.exe",
            command_line="powershell.exe -NoProfile Get-Process",
        )

        self.assertEqual(detect(event), [])

    def test_non_powershell_with_encoded_switch_does_not_trigger(self) -> None:
        event = self.make_event(
            process="cmd.exe",
            command_line="cmd.exe /c tool.exe -enc payload",
        )

        self.assertEqual(detect(event), [])

    def test_missing_optional_fields_do_not_crash(self) -> None:
        event = self.make_event()

        self.assertEqual(detect(event), [])

    def test_risk_score_validation(self) -> None:
        detection_values = {
            "detection_id": "det-001",
            "event_id": "evt-001",
            "rule_id": "TEST-001",
            "title": "Test detection",
            "severity": Severity.LOW,
            "description": "Validation test",
        }

        with self.assertRaises(ValueError):
            Detection(risk_score=-1, **detection_values)
        with self.assertRaises(ValueError):
            Detection(risk_score=101, **detection_values)


if __name__ == "__main__":
    unittest.main()
