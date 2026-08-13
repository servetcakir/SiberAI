import re

from engine.detection.rules.common import detection, has_switch, process_name
from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


_REMOTE = re.compile(r"(?:https?|ftp)://", re.IGNORECASE)
_SCRIPT_PROTOCOL = re.compile(r"(?:javascript|vbscript)\s*:", re.IGNORECASE)


def detect_certutil(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if process_name(event.process) != "certutil.exe":
        return None
    remote = _REMOTE.search(command_line) is not None and has_switch(command_line, "urlcache", "verifyctl")
    decode = has_switch(command_line, "decode", "decodehex")
    if not remote and not decode:
        return None
    techniques = (["T1105"] if remote else []) + (["T1140"] if decode else [])
    return detection(
        event, "DET-LOL-001", "Suspicious certutil transfer or decode operation", Severity.MEDIUM, 68,
        "Certutil was used with command-line behavior capable of retrieving or decoding content.",
        techniques, ("process", "parent_process", "command_line"),
    )


def detect_mshta(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if process_name(event.process) != "mshta.exe" or not (_REMOTE.search(command_line) or _SCRIPT_PROTOCOL.search(command_line)):
        return None
    return detection(
        event, "DET-LOL-002", "MSHTA launched remote or inline script content", Severity.HIGH, 82,
        "MSHTA was invoked with a remote resource or script protocol rather than a local HTA file.",
        ["T1218.005"], ("process", "parent_process", "command_line"),
    )


def detect_rundll32(event: SecurityEvent) -> Detection | None:
    command_line = event.command_line or ""
    if process_name(event.process) != "rundll32.exe" or not _SCRIPT_PROTOCOL.search(command_line):
        return None
    return detection(
        event, "DET-LOL-003", "Rundll32 invoked script-protocol content", Severity.HIGH, 84,
        "Rundll32 was invoked with a JavaScript or VBScript protocol command line.",
        ["T1218.011"], ("process", "parent_process", "command_line"),
    )
