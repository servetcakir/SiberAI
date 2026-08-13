from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any

from engine.ml.features import to_vector
from engine.ml.schema import FEATURE_NAMES, IncidentFeatures


class ExampleLabel(IntEnum):
    BENIGN = 0
    MALICIOUS = 1


class ExampleSource(str, Enum):
    LOCAL = "local"
    OTRF = "otrf"
    SPLUNK = "splunk"
    SYNTHETIC = "synthetic"


@dataclass(slots=True)
class IncidentFeatureExample:
    example_id: str
    features: IncidentFeatures
    source: ExampleSource
    label: ExampleLabel | None = None
    group_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def schema_version(self) -> str:
        return self.features.schema_version

    def to_vector(self) -> list[int | float]:
        return to_vector(self.features)

    def to_dict(self) -> dict[str, Any]:
        return {
            "example_id": self.example_id,
            "schema_version": self.schema_version,
            "label": int(self.label) if self.label is not None else None,
            "features": {name: getattr(self.features, name) for name in FEATURE_NAMES},
            "source": self.source.value,
            "group_id": self.group_id,
            "metadata": self.metadata,
        }
