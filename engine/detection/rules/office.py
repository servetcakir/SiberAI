import re

from engine.detection.rules.common import detection, has_switch, process_name
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
_INTERPRETERS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
_SCRIPT_FILE = re.compile(r"\.(?:ps1|vbs|vbe|js|jse|wsf|hta)(?:[\s\"']|$)", re.IGNORECASE)


def _has_interpreter_execution(process: str, command_line: str) -> bool:
    if process in {"powershell.exe", "pwsh.exe"}:
        return has_switch(command_line, "file", "f") and _SCRIPT_FILE.search(command_line) is not None
    if process == "cmd.exe":
        return has_switch(command_line, "c", "k")
    if process in {"wscript.exe", "cscript.exe", "mshta.exe"}:
        return _SCRIPT_FILE.search(command_line) is not None
    return False


def detect_office_shell(event: SecurityEvent) -> Detection | None:
    process = process_name(event.process)
    command_line = event.command_line or ""
    if (
        process_name(event.parent_process) not in _OFFICE
        or process not in _INTERPRETERS
        or not _has_interpreter_execution(process, command_line)
    ):
        return None
    return detection(
        event, "DET-OFFICE-001", "Office application spawned a command interpreter", Severity.HIGH, 78,
        "An Office application created a shell or script interpreter with an explicit command or script target.",
        ["T1204.002", "T1059"], ("process", "parent_process", "command_line"),
    )
