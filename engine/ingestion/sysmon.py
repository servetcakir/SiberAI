from datetime import datetime, timezone
from pathlib import PureWindowsPath
from typing import Any

from engine.models.event import SecurityEvent


def _required_text(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Sysmon process-create field {field!r} is required")
    return value.strip()


def _optional_text(data: dict[str, Any], field: str) -> str | None:
    value = data.get(field)
    if value is None or value == "":
        return None
    return str(value)


def _optional_int(data: dict[str, Any], field: str) -> int | None:
    value = _optional_text(data, field)
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"Invalid Sysmon {field}: {value!r}") from error
    if parsed < 0:
        raise ValueError(f"Invalid Sysmon {field}: {value!r}")
    return parsed


def _optional_bool(data: dict[str, Any], field: str) -> bool | None:
    value = _optional_text(data, field)
    if value is None:
        return None
    normalized = value.casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError(f"Invalid Sysmon {field}: {value!r}")


def _optional_port(data: dict[str, Any], field: str) -> int | None:
    port = _optional_int(data, field)
    if port is not None and port > 65535:
        raise ValueError(f"Invalid Sysmon {field}: {port!r}")
    return port


def _parse_utc_timestamp(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith(("Z", "z")):
        normalized = f"{normalized[:-1]}+00:00"

    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"Invalid Sysmon UtcTime: {value!r}") from error

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)

    return timestamp


def _windows_process_name(path: str | None) -> str | None:
    if path is None:
        return None
    return PureWindowsPath(path).name or None


def normalize_process_create(data: dict[str, Any]) -> SecurityEvent:
    """Normalize parsed Sysmon Event ID 1 fields into a SecurityEvent."""

    utc_time = _required_text(data, "UtcTime")
    process_guid = _required_text(data, "ProcessGuid")
    image = _optional_text(data, "Image")
    parent_image = _optional_text(data, "ParentImage")

    return SecurityEvent(
        event_id=process_guid,
        timestamp=_parse_utc_timestamp(utc_time),
        source_type="sysmon",
        category="process_creation",
        host=_optional_text(data, "Computer"),
        user=_optional_text(data, "User"),
        process=_windows_process_name(image),
        parent_process=_windows_process_name(parent_image),
        command_line=_optional_text(data, "CommandLine"),
        process_guid=process_guid,
        process_id=_optional_int(data, "ProcessId"),
        raw=dict(data),
    )


def normalize_network_connection(data: dict[str, Any]) -> SecurityEvent:
    """Normalize parsed Sysmon Event ID 3 fields into a SecurityEvent."""

    utc_time = _required_text(data, "UtcTime")
    record_id = _system_value(data, "RecordID")
    channel = _system_value(data, "Channel")
    if record_id is None or channel is None:
        raise ValueError("Sysmon network connection requires System Channel and EventRecordID")
    _optional_int({"RecordID": record_id}, "RecordID")
    image = _optional_text(data, "Image")
    protocol = _optional_text(data, "Protocol")
    return SecurityEvent(
        # EventRecordID is unique and monotonic within this fixed Sysmon channel.
        event_id=f"sysmon:operational:{record_id}",
        timestamp=_parse_utc_timestamp(utc_time),
        source_type="sysmon",
        category="network_connection",
        host=_optional_text(data, "Computer"),
        user=_optional_text(data, "User"),
        process=_windows_process_name(image),
        source_ip=_optional_text(data, "SourceIp"),
        destination_ip=_optional_text(data, "DestinationIp"),
        process_guid=_optional_text(data, "ProcessGuid"),
        process_id=_optional_int(data, "ProcessId"),
        source_port=_optional_port(data, "SourcePort"),
        destination_port=_optional_port(data, "DestinationPort"),
        protocol=protocol.casefold() if protocol else None,
        initiated=_optional_bool(data, "Initiated"),
        source_hostname=_optional_text(data, "SourceHostname"),
        destination_hostname=_optional_text(data, "DestinationHostname"),
        raw=dict(data),
    )


def normalize_sysmon_event(data: dict[str, Any]) -> SecurityEvent:
    system = data.get("_System")
    event_id = system.get("EventID") if isinstance(system, dict) else None
    if event_id == "1":
        return normalize_process_create(data)
    if event_id == "3":
        return normalize_network_connection(data)
    raise ValueError(f"Unsupported Sysmon Event ID: {event_id!r}")


def _system_value(data: dict[str, Any], field: str) -> str | None:
    system = data.get("_System")
    value = system.get(field) if isinstance(system, dict) else None
    return str(value) if value is not None and str(value) else None
