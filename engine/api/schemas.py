from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from engine.models.detection import Severity
from engine.models.incident import IncidentStatus


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class HealthResponse(ApiModel):
    status: str
    service: str
    database: str


class EventResponse(ApiModel):
    event_id: str
    record_id: int | None
    timestamp: datetime
    source_type: str
    category: str
    host: str | None
    user: str | None
    process: str | None
    parent_process: str | None
    command_line: str | None
    source_ip: str | None
    destination_ip: str | None
    process_guid: str | None
    process_id: int | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    initiated: bool | None
    source_hostname: str | None
    destination_hostname: str | None


class DetectionResponse(ApiModel):
    detection_id: str
    event_id: str
    rule_id: str
    title: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    description: str
    mitre_techniques: list[str]
    evidence: dict[str, Any]
    created_at: datetime
    event_timestamp: datetime | None
    host: str | None
    process: str | None


class EventDetailResponse(EventResponse):
    raw: dict[str, Any] | None
    detections: list[DetectionResponse]


class IncidentResponse(ApiModel):
    incident_id: str
    title: str
    status: IncidentStatus
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    host: str | None
    process_guid: str | None
    primary_event_id: str
    created_at: datetime
    updated_at: datetime
    event_count: int
    detection_count: int


class IncidentDetailResponse(IncidentResponse):
    events: list[EventResponse]
    detections: list[DetectionResponse]
