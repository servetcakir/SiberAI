from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from engine.models.detection import Severity


class IncidentStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


@dataclass(slots=True)
class Incident:
    """A deterministic investigation unit linking related events and detections."""

    incident_id: str
    title: str
    status: IncidentStatus
    severity: Severity
    risk_score: int
    created_at: datetime
    updated_at: datetime
    host: str | None
    process_guid: str | None
    primary_event_id: str
    event_ids: list[str] = field(default_factory=list)
    detection_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
