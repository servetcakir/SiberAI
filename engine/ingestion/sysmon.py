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
        raw=dict(data),
    )
