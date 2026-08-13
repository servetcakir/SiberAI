from collections.abc import Callable
from dataclasses import dataclass

from engine.detection.engine import detect
from engine.correlation.engine import CorrelationResult, correlate
from engine.analysis.decision_engine import analyze_incident
from engine.ingestion.sysmon import normalize_sysmon_event
from engine.ingestion.sysmon_xml import parse_sysmon_xml
from engine.ingestion.windows_event_log import (
    collect_recent_sysmon_events,
    collect_sysmon_events_after,
)
from engine.models.detection import Detection
from engine.models.event import SecurityEvent
from engine.models.analysis import IncidentAnalysis
from engine.storage.sqlite import SQLiteStorage


XmlCollector = Callable[..., list[str]]


@dataclass(slots=True)
class ProcessedEvent:
    record_id: int
    event: SecurityEvent
    detections: list[Detection]
    correlation: CorrelationResult | None = None
    analysis: IncidentAnalysis | None = None


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
    """In-memory channel checkpoint monitor for supported Sysmon events."""

    def __init__(
        self,
        *,
        recent_collector: XmlCollector = collect_recent_sysmon_events,
        newer_collector: XmlCollector = collect_sysmon_events_after,
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
            (event_record_id(parse_sysmon_xml(xml)) for xml in xml_events),
            default=0,
        )
        return self.checkpoint

    def poll(self) -> list[ProcessedEvent]:
        if self.checkpoint is None:
            raise RuntimeError("watch baseline has not been established")

        parsed = [parse_sysmon_xml(xml) for xml in self._newer_collector(self.checkpoint, limit=self.batch_size)]
        ordered = sorted(
            ((event_record_id(data), data) for data in parsed),
            key=lambda item: item[0],
        )
        processed: list[ProcessedEvent] = []
        for record_id, data in ordered:
            if record_id <= self.checkpoint:
                continue
            event = normalize_sysmon_event(data)
            if self.storage is not None:
                self.storage.store_event(event, record_id)
            detections = detect(event)
            if self.storage is not None:
                for detection in detections:
                    self.storage.store_detection(detection)
            correlation = correlate(event, detections, self.storage) if self.storage is not None else None
            analysis = None
            if self.storage is not None and correlation and correlation.incident:
                detail = self.storage.get_incident_detail(correlation.incident.incident_id)
                if detail is None:
                    raise RuntimeError("correlated incident detail could not be loaded")
                analysis = self.storage.store_analysis(
                    analyze_incident(detail.incident, detail.events, detail.detections)
                )
            processed.append(ProcessedEvent(record_id, event, detections, correlation, analysis))
            self.checkpoint = record_id
        return processed
