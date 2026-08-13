import os
import subprocess
from xml.etree import ElementTree

from engine.ingestion.sysmon_xml import EVENT_NAMESPACE


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_EVENT_TAG = f"{{{EVENT_NAMESPACE}}}Event"


class WindowsEventLogError(RuntimeError):
    """Raised when the local Windows Event Log query cannot be completed."""


def split_event_xml(output: str) -> list[str]:
    """Separate standalone or wrapped wevtutil XML into individual events."""

    content = output.lstrip("\ufeff\n\r\t ")
    if not content:
        return []

    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        # wevtutil /f:xml can emit adjacent <Event> documents with no root.
        # Add one synthetic root and let ElementTree parse the complete stream.
        if content.startswith("<?xml"):
            declaration_end = content.find("?>")
            if declaration_end == -1:
                raise WindowsEventLogError("Malformed XML returned by wevtutil: incomplete XML declaration")
            content = content[declaration_end + 2 :]
        try:
            root = ElementTree.fromstring(f"<SiberAIEvents>{content}</SiberAIEvents>")
        except ElementTree.ParseError as error:
            raise WindowsEventLogError(f"Malformed XML returned by wevtutil: {error}") from error

    events = [root] if root.tag == _EVENT_TAG else list(root.iter(_EVENT_TAG))
    return [ElementTree.tostring(event, encoding="unicode") for event in events]


def collect_recent_sysmon_process_events(limit: int = 10) -> list[str]:
    """Read a bounded set of recent Sysmon Event ID 1 records via wevtutil."""

    if os.name != "nt":
        raise WindowsEventLogError("Windows Event Log collection is supported only on Windows")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 100:
        raise ValueError("limit must be an integer between 1 and 100")

    command = [
        "wevtutil",
        "qe",
        SYSMON_CHANNEL,
        "/q:*[System[(EventID=1)]]",
        f"/c:{limit}",
        "/rd:true",
        "/f:xml",
    ]
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except FileNotFoundError as error:
        raise WindowsEventLogError("wevtutil was not found on this system") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "unknown error").strip()
        raise WindowsEventLogError(f"wevtutil query failed: {detail}") from error

    return split_event_xml(result.stdout)
