import re

from engine.detection.rules.common import detection, has_switch, has_word, process_name
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


_RUN_KEY = re.compile(r"\\(?:software\\microsoft\\windows\\currentversion\\)?run(?:once)?(?:\\|\s|\"|$)", re.IGNORECASE)


def detect_scheduled_task(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if process_name(event.process) != "schtasks.exe" or not has_switch(command_line, "create"):
        return None
    return detection(
        event, "DET-PERSIST-001", "Scheduled task creation observed", Severity.MEDIUM, 65,
        "Schtasks was used to create a scheduled task; confirm that the task and creator are authorized.",
        ["T1053.005"], ("process", "parent_process", "command_line", "user"),
    )


def detect_registry_run_key(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if process_name(event.process) != "reg.exe" or not has_word(command_line, "add") or not _RUN_KEY.search(command_line):
        return None
    return detection(
        event, "DET-PERSIST-002", "Registry Run key modification observed", Severity.HIGH, 80,
        "Reg.exe added or modified a common Run or RunOnce autostart location.",
        ["T1547.001"], ("process", "parent_process", "command_line", "user"),
    )
