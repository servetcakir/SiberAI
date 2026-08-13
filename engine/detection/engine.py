import re

from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


_POWERSHELL_PROCESSES = {"powershell.exe", "pwsh.exe"}
_ENCODED_COMMAND_SWITCH = re.compile(
    r"(?<!\w)-(?:encodedcommand|enc)(?=$|\s|:)",
    re.IGNORECASE,
)


def detect(event: SecurityEvent) -> list[Detection]:
    """Run the current detection rules against one normalized event."""

    process = (event.process or "").casefold()
    command_line = event.command_line or ""

    if process not in _POWERSHELL_PROCESSES:
        return []
    if not _ENCODED_COMMAND_SWITCH.search(command_line):
        return []

    return [
        Detection(
            detection_id=f"DET-PS-001:{event.event_id}",
            event_id=event.event_id,
            rule_id="DET-PS-001",
            title="Suspicious encoded PowerShell execution",
            severity=Severity.HIGH,
            risk_score=85,
            description=(
                "PowerShell was executed with an encoded-command switch. "
                "The payload has not been decoded."
            ),
            mitre_techniques=["T1059.001"],
            evidence={
                "process": event.process,
                "command_line": event.command_line,
            },
        )
    ]
