import re

from engine.detection.rules.common import detection, process_name
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


_DISABLE_DEFENDER = re.compile(
    r"\bset-mppreference\b(?=.*(?<!\w)-disablerealtimemonitoring(?:\s+|:)(?:\$?true|1)\b)",
    re.IGNORECASE,
)


def detect_defender_impairment(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if process_name(event.process) not in {"powershell.exe", "pwsh.exe"} or not _DISABLE_DEFENDER.search(command_line):
        return None
    return detection(
        event, "DET-DEFENSE-001", "Windows Defender real-time monitoring disable attempt", Severity.CRITICAL, 94,
        "PowerShell attempted to explicitly disable Windows Defender real-time monitoring.",
        ["T1562.001"], ("process", "parent_process", "command_line", "user"),
    )
