from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class Detection:
    """A structured result produced by a detection rule."""

    detection_id: str
    event_id: str
    rule_id: str
    title: str
    severity: Severity
    risk_score: int
    description: str
    mitre_techniques: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.risk_score, bool) or not isinstance(self.risk_score, int):
            raise TypeError("risk_score must be an integer")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
