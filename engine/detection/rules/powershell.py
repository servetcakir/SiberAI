import re

from engine.detection.rules.common import detection, has_switch, process_name
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


_POWERSHELL = {"powershell.exe", "pwsh.exe"}
_ENCODED_COMMAND_SWITCH = re.compile(r"(?<!\w)-(?:encodedcommand|enc)(?=$|\s|:)", re.IGNORECASE)


def detect_encoded_command(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if process_name(event.process) not in _POWERSHELL or not _ENCODED_COMMAND_SWITCH.search(command_line):
        return None
    return detection(
        event, "DET-PS-001", "Suspicious encoded PowerShell execution", Severity.HIGH, 85,
        "PowerShell was executed with an encoded-command switch. The payload has not been decoded.",
        ["T1059.001"], ("process", "command_line"),
    )


def detect_suspicious_options(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if process_name(event.process) not in _POWERSHELL:
        return None
    bypass = has_switch(command_line, "executionpolicy", "ep") and re.search(
        r"(?<!\w)(?:bypass|unrestricted)(?!\w)", command_line, re.IGNORECASE
    ) is not None
    concealed = has_switch(command_line, "windowstyle", "w") and re.search(
        r"(?<!\w)hidden(?!\w)", command_line, re.IGNORECASE
    ) is not None
    noninteractive = has_switch(command_line, "noninteractive", "noni")
    if sum((bypass, concealed, noninteractive)) < 2:
        return None
    return detection(
        event, "DET-PS-002", "PowerShell launched with evasive options", Severity.MEDIUM, 70,
        "PowerShell combined multiple options commonly used to reduce visibility or bypass execution policy.",
        ["T1059.001", "T1562.001"], ("process", "command_line"),
    )
