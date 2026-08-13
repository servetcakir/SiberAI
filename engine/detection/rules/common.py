import re
from pathlib import PureWindowsPath
from typing import Any

from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent


def process_name(value: str | None) -> str:
    return PureWindowsPath(value or "").name.casefold()


def has_switch(command_line: str, *switches: str) -> bool:
    alternatives = "|".join(re.escape(switch) for switch in switches)
    return re.search(rf"(?<![\w-])[-/](?:{alternatives})(?=$|[\s:=])", command_line, re.IGNORECASE) is not None


def has_word(command_line: str, word: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(word)}(?![\w-])", command_line, re.IGNORECASE) is not None


def evidence(event: SecurityEvent, *fields: str) -> dict[str, Any]:
    return {field: value for field in fields if (value := getattr(event, field)) is not None}


def detection(
    event: SecurityEvent,
    rule_id: str,
    title: str,
    severity: Severity,
    risk_score: int,
    description: str,
    mitre_techniques: list[str],
    evidence_fields: tuple[str, ...],
) -> Detection:
    return Detection(
        detection_id=f"{rule_id}:{event.event_id}",
        event_id=event.event_id,
        rule_id=rule_id,
        title=title,
        severity=severity,
        risk_score=risk_score,
        description=description,
        mitre_techniques=mitre_techniques,
        evidence=evidence(event, *evidence_fields),
    )
