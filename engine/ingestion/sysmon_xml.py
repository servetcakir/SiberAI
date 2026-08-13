from typing import Any
from xml.etree import ElementTree


EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = {"event": EVENT_NAMESPACE}


class SysmonXmlError(ValueError):
    """Raised when Sysmon event XML cannot be parsed or validated."""


def parse_sysmon_xml(xml: str) -> dict[str, Any]:
    """Parse one supported Sysmon Event ID 1 or 3 XML document."""

    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as error:
        raise SysmonXmlError(f"Malformed Sysmon event XML: {error}") from error

    if root.tag != f"{{{EVENT_NAMESPACE}}}Event":
        raise SysmonXmlError("Expected one Microsoft Windows Event XML <Event>")

    system = root.find("event:System", _NS)
    if system is None:
        raise SysmonXmlError("Sysmon event XML is missing the System section")

    event_id_element = system.find("event:EventID", _NS)
    event_id = (event_id_element.text or "").strip() if event_id_element is not None else ""
    if event_id not in {"1", "3"}:
        raise SysmonXmlError(f"Expected Sysmon Event ID 1 or 3, received {event_id or 'missing'}")

    provider = system.find("event:Provider", _NS)
    provider_name = provider.get("Name") if provider is not None else None
    if provider_name and provider_name.casefold() != "microsoft-windows-sysmon":
        raise SysmonXmlError(f"Expected the Sysmon provider, received {provider_name!r}")

    result: dict[str, Any] = {}
    computer = system.find("event:Computer", _NS)
    if computer is not None and computer.text:
        result["Computer"] = computer.text.strip()

    event_data = root.find("event:EventData", _NS)
    if event_data is not None:
        for item in event_data.findall("event:Data", _NS):
            name = item.get("Name")
            if name:
                result[name] = item.text or ""

    # Keep compact System metadata in raw normalizer input without changing SecurityEvent.
    result["_System"] = {
        "Provider": provider_name,
        "EventID": event_id,
        "RecordID": _text(system.find("event:EventRecordID", _NS)),
        "Channel": _text(system.find("event:Channel", _NS)),
    }
    return result


def parse_process_create_xml(xml: str) -> dict[str, Any]:
    """Compatibility parser that accepts only Sysmon Event ID 1."""

    result = parse_sysmon_xml(xml)
    if result["_System"]["EventID"] != "1":
        raise SysmonXmlError(f"Expected Sysmon Event ID 1, received {result['_System']['EventID']}")
    return result


def _text(element: ElementTree.Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    return element.text.strip() or None
