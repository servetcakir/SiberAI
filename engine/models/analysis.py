from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from engine.models.detection import Severity


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"


class ReasonCode(str, Enum):
    ENCODED_POWERSHELL = "encoded_powershell"
    EVASIVE_POWERSHELL_OPTIONS = "evasive_powershell_options"
    OFFICE_SPAWNED_INTERPRETER = "office_spawned_interpreter"
    CREDENTIAL_ACCESS_INDICATOR = "credential_access_indicator"
    SECURITY_CONTROL_IMPAIRMENT = "security_control_impairment"
    PERSISTENCE_BEHAVIOR = "persistence_behavior"
    SUSPICIOUS_LOLBIN = "suspicious_lolbin"
    CORRELATED_NETWORK_ACTIVITY = "correlated_network_activity"
    MULTIPLE_HIGH_CONFIDENCE_DETECTIONS = "multiple_high_confidence_detections"
    CRITICAL_DETECTION_PRESENT = "critical_detection_present"


class RecommendedAction(str, Enum):
    REVIEW_INCIDENT = "review_incident"
    REVIEW_PROCESS_TREE = "review_process_tree"
    INSPECT_COMMAND_LINE = "inspect_command_line"
    INSPECT_PARENT_PROCESS = "inspect_parent_process"
    REVIEW_NETWORK_ACTIVITY = "review_network_activity"
    INVESTIGATE_DESTINATION = "investigate_destination"
    INSPECT_RELATED_FILE = "inspect_related_file"
    REVIEW_USER_ACTIVITY = "review_user_activity"
    ISOLATE_HOST = "isolate_host"
    COLLECT_FORENSIC_EVIDENCE = "collect_forensic_evidence"
    RESET_CREDENTIALS = "reset_credentials"
    REVIEW_PERSISTENCE = "review_persistence"
    VERIFY_SECURITY_CONTROLS = "verify_security_controls"


class EvidenceType(str, Enum):
    DETECTION = "detection"
    NETWORK_CONNECTION = "network_connection"


@dataclass(slots=True)
class AnalysisEvidence:
    type: EvidenceType
    event_id: str
    detection_id: str | None = None
    rule_id: str | None = None
    process_guid: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None


@dataclass(slots=True)
class IncidentAnalysis:
    analysis_id: str
    incident_id: str
    verdict: Verdict
    confidence: float
    severity: Severity
    risk_score: int
    requires_human_review: bool
    engine_version: str
    created_at: datetime
    updated_at: datetime
    reason_codes: list[ReasonCode] = field(default_factory=list)
    contributing_detection_ids: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    recommended_actions: list[RecommendedAction] = field(default_factory=list)
    evidence: list[AnalysisEvidence] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be a number")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if isinstance(self.risk_score, bool) or not isinstance(self.risk_score, int):
            raise TypeError("risk_score must be an integer")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
