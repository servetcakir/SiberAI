from dataclasses import asdict, dataclass


FEATURE_SCHEMA_VERSION = "incident-features-v1"

# This tuple is the canonical model-input contract. Append-only schema changes
# still require a new schema version because position is significant.
FEATURE_NAMES: tuple[str, ...] = (
    "has_encoded_powershell",
    "has_evasive_powershell",
    "has_office_spawned_interpreter",
    "has_credential_access",
    "has_security_control_impairment",
    "has_persistence",
    "has_suspicious_lolbin",
    "detection_count",
    "low_detection_count",
    "medium_detection_count",
    "high_detection_count",
    "critical_detection_count",
    "unique_detection_family_count",
    "max_detection_risk",
    "event_count",
    "process_event_count",
    "network_event_count",
    "events_after_first_detection",
    "detections_per_event",
    "network_connection_count",
    "unique_destination_count",
    "unique_destination_port_count",
    "outbound_connection_count",
    "has_network_after_detection",
    "incident_duration_seconds",
)


@dataclass(frozen=True, slots=True)
class IncidentFeatures:
    schema_version: str
    has_encoded_powershell: int = 0
    has_evasive_powershell: int = 0
    has_office_spawned_interpreter: int = 0
    has_credential_access: int = 0
    has_security_control_impairment: int = 0
    has_persistence: int = 0
    has_suspicious_lolbin: int = 0
    detection_count: int = 0
    low_detection_count: int = 0
    medium_detection_count: int = 0
    high_detection_count: int = 0
    critical_detection_count: int = 0
    unique_detection_family_count: int = 0
    max_detection_risk: int = 0
    event_count: int = 0
    process_event_count: int = 0
    network_event_count: int = 0
    events_after_first_detection: int = 0
    detections_per_event: float = 0.0
    network_connection_count: int = 0
    unique_destination_count: int = 0
    unique_destination_port_count: int = 0
    outbound_connection_count: int = 0
    has_network_after_detection: int = 0
    incident_duration_seconds: float = 0.0

    def as_dict(self) -> dict[str, str | int | float]:
        return asdict(self)
