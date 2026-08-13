from collections.abc import Callable

from engine.detection.rules.credentials import detect_lsass_memory_dump
from engine.detection.rules.defense_evasion import detect_defender_impairment
from engine.detection.rules.office import detect_office_shell
from engine.detection.rules.persistence import detect_registry_run_key, detect_scheduled_task
from engine.detection.rules.lolbins import detect_certutil, detect_mshta, detect_rundll32
from engine.detection.rules.powershell import detect_encoded_command, detect_suspicious_options
from engine.models.detection import Detection
from engine.models.event import SecurityEvent

Rule = Callable[[SecurityEvent], Detection | None]

# Explicit registration keeps rule order stable and reviewable.
RULES: tuple[Rule, ...] = (
    detect_encoded_command,
    detect_suspicious_options,
    detect_office_shell,
    detect_certutil,
    detect_mshta,
    detect_rundll32,
    detect_lsass_memory_dump,
    detect_scheduled_task,
    detect_registry_run_key,
    detect_defender_impairment,
)


def detect(event: SecurityEvent) -> list[Detection]:
    """Evaluate every registered rule against one normalized event."""

    return [detection for rule in RULES if (detection := rule(event)) is not None]
