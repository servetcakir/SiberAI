from collections.abc import Callable
from dataclasses import dataclass

from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_process_create
from engine.ingestion.sysmon_xml import parse_process_create_xml
from engine.ingestion.windows_event_log import (
    collect_recent_sysmon_process_events,
    collect_sysmon_process_events_after,
)
from engine.models.detection import Detection
from engine.models.event import SecurityEvent
from engine.storage.sqlite import SQLiteStorage


XmlCollector = Callable[..., list[str]]


@dataclass(slots=True)
class ProcessedEvent:
    record_id: int
    event: SecurityEvent
    detections: list[Detection]


def event_record_id(data: dict[str, object]) -> int:
    """Return the numeric EventRecordID preserved by the Sysmon XML parser."""

    system = data.get("_System")
    value = system.get("RecordID") if isinstance(system, dict) else None
    try:
        record_id = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid Sysmon EventRecordID: {value!r}") from error
    if record_id < 0:
        raise ValueError(f"Invalid Sysmon EventRecordID: {value!r}")
    return record_id


class SysmonWatch:
    """In-memory checkpoint monitor for new Sysmon process-create events."""

    def __init__(
        self,
        *,
        recent_collector: XmlCollector = collect_recent_sysmon_process_events,
        newer_collector: XmlCollector = collect_sysmon_process_events_after,
        batch_size: int = 50,
        storage: SQLiteStorage | None = None,
    ) -> None:
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 100:
            raise ValueError("batch_size must be an integer between 1 and 100")
        self._recent_collector = recent_collector
        self._newer_collector = newer_collector
        self.batch_size = batch_size
        self.storage = storage
        self.checkpoint: int | None = None

    def establish_baseline(self) -> int:
        xml_events = self._recent_collector(limit=1)
        self.checkpoint = max(
            (event_record_id(parse_process_create_xml(xml)) for xml in xml_events),
            default=0,
        )
        return self.checkpoint

    def poll(self) -> list[ProcessedEvent]:
        if self.checkpoint is None:
            raise RuntimeError("watch baseline has not been established")

        parsed = [parse_process_create_xml(xml) for xml in self._newer_collector(self.checkpoint, limit=self.batch_size)]
        ordered = sorted(
            ((event_record_id(data), data) for data in parsed),
            key=lambda item: item[0],
        )
        processed: list[ProcessedEvent] = []
        for record_id, data in ordered:
            if record_id <= self.checkpoint:
                continue
            event = normalize_process_create(data)
            if self.storage is not None:
                self.storage.store_event(event, record_id)
            detections = detect(event)
            if self.storage is not None:
                for detection in detections:
                    self.storage.store_detection(detection)
            processed.append(ProcessedEvent(record_id, event, detections))
            self.checkpoint = record_id
        return processed
