from collections import Counter
from collections.abc import Sequence
from typing import Protocol, TypeVar

from engine.ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, IncidentFeatures
from engine.models.detection import Severity
from engine.models.incident import Incident


T = TypeVar("T")


class EventLike(Protocol):
    event_id: str
    timestamp: object
    category: str
    destination_ip: str | None
    destination_hostname: str | None
    destination_port: int | None
    initiated: bool | None


class DetectionLike(Protocol):
    detection_id: str
    event_id: str
    rule_id: str
    severity: Severity
    risk_score: int


RULE_FAMILY_MAP: dict[str, str] = {
    "DET-PS-001": "powershell",
    "DET-PS-002": "powershell",
    "DET-OFFICE-001": "office_execution",
    "DET-LOL-001": "lolbin",
    "DET-LOL-002": "lolbin",
    "DET-LOL-003": "lolbin",
    "DET-CRED-001": "credential_access",
    "DET-PERSIST-001": "persistence",
    "DET-PERSIST-002": "persistence",
    "DET-DEFENSE-001": "defense_evasion",
}

RULE_BEHAVIOR_FEATURE_MAP: dict[str, str] = {
    "DET-PS-001": "has_encoded_powershell",
    "DET-PS-002": "has_evasive_powershell",
    "DET-OFFICE-001": "has_office_spawned_interpreter",
    "DET-LOL-001": "has_suspicious_lolbin",
    "DET-LOL-002": "has_suspicious_lolbin",
    "DET-LOL-003": "has_suspicious_lolbin",
    "DET-CRED-001": "has_credential_access",
    "DET-PERSIST-001": "has_persistence",
    "DET-PERSIST-002": "has_persistence",
    "DET-DEFENSE-001": "has_security_control_impairment",
}


def extract_features(
    events: Sequence[EventLike],
    detections: Sequence[DetectionLike],
) -> IncidentFeatures:
    """Extract v1 evidence features from an arbitrary bounded event group."""

    unique_events = _deduplicate(events, "event_id", "event")
    unique_detections = _deduplicate(detections, "detection_id", "detection")
    for event in unique_events.values():
        timestamp = event.timestamp
        if getattr(timestamp, "tzinfo", None) is None or timestamp.utcoffset() is None:
            raise ValueError(f"Event {event.event_id!r} has a timezone-naive timestamp")
    missing = sorted({item.event_id for item in unique_detections.values()} - unique_events.keys())
    if missing:
        raise ValueError(f"Detections reference missing event IDs: {', '.join(missing)}")

    event_values = sorted(unique_events.values(), key=lambda item: (item.timestamp, item.event_id))
    detection_values = sorted(unique_detections.values(), key=lambda item: item.detection_id)
    severity_counts = Counter(item.severity for item in detection_values)
    behavior_values = {name: 0 for name in RULE_BEHAVIOR_FEATURE_MAP.values()}
    families: set[str] = set()
    for detection in detection_values:
        family = RULE_FAMILY_MAP.get(detection.rule_id)
        if family is not None:
            families.add(family)
        behavior_feature = RULE_BEHAVIOR_FEATURE_MAP.get(detection.rule_id)
        if behavior_feature is not None:
            behavior_values[behavior_feature] = 1

    process_events = [item for item in event_values if item.category in {"process_creation", "process_execution"}]
    network_events = [item for item in event_values if item.category == "network_connection"]
    destinations = {
        ("ip", item.destination_ip)
        if item.destination_ip
        else ("host", item.destination_hostname.casefold())
        for item in network_events
        if item.destination_ip or item.destination_hostname
    }
    destination_ports = {item.destination_port for item in network_events if item.destination_port is not None}

    first_detection_time = min(
        (unique_events[item.event_id].timestamp for item in detection_values),
        default=None,
    )
    events_after_detection = sum(
        item.timestamp > first_detection_time for item in event_values
    ) if first_detection_time is not None else 0
    has_network_after_detection = int(
        first_detection_time is not None
        and any(item.timestamp > first_detection_time for item in network_events)
    )
    duration = (
        (event_values[-1].timestamp - event_values[0].timestamp).total_seconds()
        if len(event_values) > 1 else 0.0
    )
    event_count = len(event_values)

    return IncidentFeatures(
        schema_version=FEATURE_SCHEMA_VERSION,
        **behavior_values,
        detection_count=len(detection_values),
        low_detection_count=severity_counts[Severity.LOW],
        medium_detection_count=severity_counts[Severity.MEDIUM],
        high_detection_count=severity_counts[Severity.HIGH],
        critical_detection_count=severity_counts[Severity.CRITICAL],
        unique_detection_family_count=len(families),
        max_detection_risk=max((item.risk_score for item in detection_values), default=0),
        event_count=event_count,
        process_event_count=len(process_events),
        network_event_count=len(network_events),
        events_after_first_detection=events_after_detection,
        detections_per_event=len(detection_values) / event_count if event_count else 0.0,
        network_connection_count=len(network_events),
        unique_destination_count=len(destinations),
        unique_destination_port_count=len(destination_ports),
        outbound_connection_count=sum(item.initiated is True for item in network_events),
        has_network_after_detection=has_network_after_detection,
        incident_duration_seconds=duration,
    )


def extract_incident_features(
    incident: Incident,
    events: Sequence[EventLike],
    detections: Sequence[DetectionLike],
) -> IncidentFeatures:
    """Extract features for a production incident without using incident summaries."""

    del incident  # Incident identity, risk, and decision output are intentionally excluded.
    return extract_features(events, detections)


def to_vector(features: IncidentFeatures) -> list[int | float]:
    """Return model inputs in the canonical schema order."""

    if features.schema_version != FEATURE_SCHEMA_VERSION:
        raise ValueError(f"Unsupported feature schema: {features.schema_version!r}")
    return [getattr(features, name) for name in FEATURE_NAMES]


def _deduplicate(items: Sequence[T], id_field: str, label: str) -> dict[str, T]:
    unique: dict[str, T] = {}
    for item in items:
        item_id = getattr(item, id_field)
        existing = unique.get(item_id)
        if existing is not None and existing != item:
            raise ValueError(f"Conflicting duplicate {label} ID: {item_id!r}")
        unique[item_id] = item
    return unique
