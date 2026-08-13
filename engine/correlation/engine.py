from dataclasses import dataclass
from datetime import datetime, timezone

from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent
from engine.models.incident import Incident, IncidentStatus
from engine.storage.sqlite import SQLiteStorage


CORRELATION_WINDOW_SECONDS = 15 * 60
INCIDENT_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}
_SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(slots=True)
class CorrelationResult:
    incident: Incident | None
    created: bool = False
    event_attached: bool = False


def correlate(
    event: SecurityEvent,
    detections: list[Detection],
    storage: SQLiteStorage,
) -> CorrelationResult:
    """Create or update one incident using exact ProcessGuid correlation."""

    incident = None
    if event.process_guid:
        incident = storage.find_open_incident(
            event.process_guid, event.host, event.timestamp, CORRELATION_WINDOW_SECONDS
        )

    qualifying = [item for item in detections if item.severity in INCIDENT_SEVERITIES]
    created = False
    if incident is None and qualifying:
        strongest = _strongest(qualifying)
        now = datetime.now(timezone.utc)
        incident = Incident(
            incident_id=f"INC:{event.event_id}",
            title=strongest.title,
            status=IncidentStatus.OPEN,
            severity=strongest.severity,
            risk_score=strongest.risk_score,
            created_at=now,
            updated_at=now,
            host=event.host,
            process_guid=event.process_guid,
            primary_event_id=event.event_id,
        )
        created = storage.store_incident(incident)
        incident = storage.get_incident(incident.incident_id)

    if incident is None:
        return CorrelationResult(None)

    event_attached = storage.attach_incident_event(incident.incident_id, event.event_id)
    for detection in detections:
        storage.attach_incident_detection(incident.incident_id, detection.detection_id)

    if created and event.process_guid:
        for related in storage.related_events(
            event.process_guid, event.host, event.timestamp, CORRELATION_WINDOW_SECONDS
        ):
            storage.attach_incident_event(incident.incident_id, related.event_id)
            for related_detection in storage.detections_for_event(related.event_id):
                storage.attach_incident_detection(incident.incident_id, related_detection.detection_id)

    detail = storage.get_incident_detail(incident.incident_id)
    if detail is None:
        return CorrelationResult(None)
    if detail.detections:
        strongest_stored = max(
            detail.detections,
            key=lambda item: (_SEVERITY_RANK[item.severity], item.risk_score, item.detection_id),
        )
        storage.update_incident(
            incident.incident_id,
            title=strongest_stored.title,
            severity=strongest_stored.severity,
            risk_score=max(item.risk_score for item in detail.detections),
            updated_at=datetime.now(timezone.utc),
        )
    return CorrelationResult(
        storage.get_incident(incident.incident_id), created=created, event_attached=event_attached
    )


def _strongest(detections: list[Detection]) -> Detection:
    return max(
        detections,
        key=lambda item: (_SEVERITY_RANK[item.severity], item.risk_score, item.detection_id),
    )
