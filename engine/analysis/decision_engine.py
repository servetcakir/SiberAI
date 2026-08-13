from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Protocol

from engine.models.analysis import (
    AnalysisEvidence,
    EvidenceType,
    IncidentAnalysis,
    ReasonCode,
    RecommendedAction,
    Verdict,
)
from engine.models.detection import Severity
from engine.models.incident import Incident


DECISION_ENGINE_VERSION = "decision-v0"


class EventLike(Protocol):
    event_id: str
    category: str
    process_guid: str | None
    destination_ip: str | None
    destination_port: int | None


class DetectionLike(Protocol):
    detection_id: str
    event_id: str
    rule_id: str
    severity: Severity
    risk_score: int
    mitre_techniques: list[str]


_RULE_REASONS = {
    "DET-PS-001": ReasonCode.ENCODED_POWERSHELL,
    "DET-PS-002": ReasonCode.EVASIVE_POWERSHELL_OPTIONS,
    "DET-OFFICE-001": ReasonCode.OFFICE_SPAWNED_INTERPRETER,
    "DET-CRED-001": ReasonCode.CREDENTIAL_ACCESS_INDICATOR,
    "DET-DEFENSE-001": ReasonCode.SECURITY_CONTROL_IMPAIRMENT,
    "DET-PERSIST-001": ReasonCode.PERSISTENCE_BEHAVIOR,
    "DET-PERSIST-002": ReasonCode.PERSISTENCE_BEHAVIOR,
    "DET-LOL-001": ReasonCode.SUSPICIOUS_LOLBIN,
    "DET-LOL-002": ReasonCode.SUSPICIOUS_LOLBIN,
    "DET-LOL-003": ReasonCode.SUSPICIOUS_LOLBIN,
}
_BEHAVIOR_FAMILY = {
    ReasonCode.ENCODED_POWERSHELL: "powershell",
    ReasonCode.EVASIVE_POWERSHELL_OPTIONS: "powershell",
    ReasonCode.OFFICE_SPAWNED_INTERPRETER: "office",
    ReasonCode.CREDENTIAL_ACCESS_INDICATOR: "credential_access",
    ReasonCode.SECURITY_CONTROL_IMPAIRMENT: "defense_evasion",
    ReasonCode.PERSISTENCE_BEHAVIOR: "persistence",
    ReasonCode.SUSPICIOUS_LOLBIN: "lolbin",
}
_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def analyze_incident(
    incident: Incident,
    events: Sequence[EventLike],
    detections: Sequence[DetectionLike],
    *,
    now: datetime | None = None,
) -> IncidentAnalysis:
    """Produce a conservative deterministic analysis using heuristic confidence."""

    ordered_detections = sorted(
        {item.detection_id: item for item in detections}.values(),
        key=lambda item: item.detection_id,
    )
    reasons = {_RULE_REASONS[item.rule_id] for item in ordered_detections if item.rule_id in _RULE_REASONS}
    network_events = sorted(
        {item.event_id: item for item in events if item.category == "network_connection"}.values(),
        key=lambda item: item.event_id,
    )
    if network_events:
        reasons.add(ReasonCode.CORRELATED_NETWORK_ACTIVITY)
    if any(item.severity == Severity.CRITICAL for item in ordered_detections):
        reasons.add(ReasonCode.CRITICAL_DETECTION_PRESENT)

    families = {_BEHAVIOR_FAMILY[reason] for reason in reasons if reason in _BEHAVIOR_FAMILY}
    if len(families) >= 2:
        reasons.add(ReasonCode.MULTIPLE_HIGH_CONFIDENCE_DETECTIONS)

    critical_semantic = bool(
        reasons & {ReasonCode.CREDENTIAL_ACCESS_INDICATOR, ReasonCode.SECURITY_CONTROL_IMPAIRMENT}
    )
    if critical_semantic and len(families) >= 2:
        verdict, confidence = Verdict.MALICIOUS, 0.97
    elif len(families) >= 2:
        verdict, confidence = Verdict.LIKELY_MALICIOUS, 0.90
    elif families and network_events:
        verdict, confidence = Verdict.LIKELY_MALICIOUS, 0.84
    elif critical_semantic:
        verdict, confidence = Verdict.SUSPICIOUS, 0.82
    elif ordered_detections:
        verdict, confidence = Verdict.SUSPICIOUS, 0.74
    else:
        verdict, confidence = Verdict.SUSPICIOUS, 0.55

    severity = max(
        (item.severity for item in ordered_detections),
        key=lambda value: _SEVERITY_RANK[value],
        default=incident.severity,
    )
    risk_score = max((item.risk_score for item in ordered_detections), default=incident.risk_score)
    timestamp = now or datetime.now(timezone.utc)
    return IncidentAnalysis(
        analysis_id=f"ANALYSIS:{incident.incident_id}:{DECISION_ENGINE_VERSION}",
        incident_id=incident.incident_id,
        verdict=verdict,
        confidence=confidence,
        severity=severity,
        risk_score=risk_score,
        reason_codes=sorted(reasons, key=lambda item: item.value),
        contributing_detection_ids=[item.detection_id for item in ordered_detections],
        mitre_techniques=sorted({technique for item in ordered_detections for technique in item.mitre_techniques}),
        recommended_actions=_recommended_actions(reasons, verdict),
        evidence=_evidence(ordered_detections, network_events),
        requires_human_review=True,
        engine_version=DECISION_ENGINE_VERSION,
        created_at=timestamp,
        updated_at=timestamp,
    )


def _recommended_actions(
    reasons: set[ReasonCode], verdict: Verdict,
) -> list[RecommendedAction]:
    actions = {RecommendedAction.REVIEW_INCIDENT, RecommendedAction.REVIEW_PROCESS_TREE}
    if reasons & {
        ReasonCode.ENCODED_POWERSHELL, ReasonCode.EVASIVE_POWERSHELL_OPTIONS,
        ReasonCode.SUSPICIOUS_LOLBIN, ReasonCode.PERSISTENCE_BEHAVIOR,
        ReasonCode.SECURITY_CONTROL_IMPAIRMENT,
    }:
        actions.add(RecommendedAction.INSPECT_COMMAND_LINE)
    if ReasonCode.OFFICE_SPAWNED_INTERPRETER in reasons:
        actions.add(RecommendedAction.INSPECT_PARENT_PROCESS)
    if ReasonCode.CORRELATED_NETWORK_ACTIVITY in reasons:
        actions.update({RecommendedAction.REVIEW_NETWORK_ACTIVITY, RecommendedAction.INVESTIGATE_DESTINATION})
    if ReasonCode.PERSISTENCE_BEHAVIOR in reasons:
        actions.add(RecommendedAction.REVIEW_PERSISTENCE)
    if ReasonCode.CREDENTIAL_ACCESS_INDICATOR in reasons:
        actions.update({RecommendedAction.REVIEW_USER_ACTIVITY, RecommendedAction.COLLECT_FORENSIC_EVIDENCE, RecommendedAction.RESET_CREDENTIALS})
    if ReasonCode.SECURITY_CONTROL_IMPAIRMENT in reasons:
        actions.add(RecommendedAction.VERIFY_SECURITY_CONTROLS)
    if verdict == Verdict.MALICIOUS:
        actions.update({RecommendedAction.ISOLATE_HOST, RecommendedAction.COLLECT_FORENSIC_EVIDENCE})
    return sorted(actions, key=lambda item: item.value)


def _evidence(
    detections: Sequence[DetectionLike], network_events: Sequence[EventLike],
) -> list[AnalysisEvidence]:
    evidence = [
        AnalysisEvidence(
            type=EvidenceType.DETECTION,
            event_id=item.event_id,
            detection_id=item.detection_id,
            rule_id=item.rule_id,
        )
        for item in detections
    ]
    evidence.extend(
        AnalysisEvidence(
            type=EvidenceType.NETWORK_CONNECTION,
            event_id=item.event_id,
            process_guid=item.process_guid,
            destination_ip=item.destination_ip,
            destination_port=item.destination_port,
        )
        for item in network_events
    )
    return evidence
