from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class SecurityEvent:
    """A normalized security event accepted by the detection engine."""

    event_id: str
    timestamp: datetime
    source_type: str
    category: str
    host: str | None = None
    user: str | None = None
    process: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    raw: dict[str, Any] | None = None
