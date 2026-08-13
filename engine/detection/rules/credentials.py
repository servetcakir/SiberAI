import re

from engine.detection.rules.common import detection, has_switch, process_name
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


_LSASS_TARGET = re.compile(r"(?<![\w.-])lsass(?:\.exe)?(?![\w.-])", re.IGNORECASE)


def detect_lsass_memory_dump(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if (
        process_name(event.process) not in {"procdump.exe", "procdump64.exe"}
        or not has_switch(command_line, "ma")
        or not _LSASS_TARGET.search(command_line)
    ):
        return None
    return detection(
        event, "DET-CRED-001", "Full-memory dump of LSASS requested", Severity.CRITICAL, 96,
        "ProcDump requested a full-memory dump with LSASS explicitly named as the target.",
        ["T1003.001"], ("process", "parent_process", "command_line", "user"),
    )
