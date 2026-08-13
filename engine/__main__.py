import argparse
import time

from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_sysmon_event
from engine.ingestion.sysmon_xml import SysmonXmlError, parse_sysmon_xml
from engine.ingestion.windows_event_log import (
    SYSMON_CHANNEL,
    WindowsEventLogError,
    collect_recent_sysmon_events as collect_recent_sysmon_process_events,
)
from engine.models.detection import Detection
from engine.models.event import SecurityEvent
from engine.storage.sqlite import SQLiteStorage, StorageError
from engine.watch import SysmonWatch


def _positive_interval(value: str) -> float:
    try:
        interval = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("interval must be a number greater than zero") from error
    if interval <= 0:
        raise argparse.ArgumentTypeError("interval must be greater than zero")
    return interval


def _print_event(event: SecurityEvent, detections: list[Detection]) -> int:
    if not detections:
        if event.category == "network_connection":
            source = _network_endpoint(event.source_ip, event.source_port)
            destination = _network_endpoint(event.destination_ip, event.destination_port)
            print(f"[OK] {event.host or 'unknown host'} | NETWORK | {event.process or 'unknown process'} | {source} -> {destination}")
        else:
            print(f"[OK] {event.host or 'unknown host'} | PROCESS | {event.process or 'unknown process'}")
        return 0

    for detection in detections:
        print(f"[{detection.severity.value.upper()}] {detection.title}")
        print(f"Rule: {detection.rule_id}")
        print(f"Host: {event.host or 'unknown'}")
        print(f"Process: {event.process or 'unknown'}")
        print(f"Risk: {detection.risk_score}/100")
        print(f"MITRE: {', '.join(detection.mitre_techniques) or 'none'}")
        print()
    return len(detections)


def _network_endpoint(address: str | None, port: int | None) -> str:
    return f"{address or 'unknown'}:{port}" if port is not None else address or "unknown"


def run_watch(interval: float, *, monitor: SysmonWatch | None = None) -> tuple[int, int]:
    watch = monitor or SysmonWatch()
    watch.establish_baseline()
    processed_count = 0
    detection_count = 0
    print("SiberAI Engine")
    print(f"Monitoring: {SYSMON_CHANNEL}")
    print("Event types: Process Create (1), Network Connection (3)")
    print("Status: watching for new events...")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            try:
                for result in watch.poll():
                    processed_count += 1
                    detection_count += _print_event(result.event, result.detections)
            except (ValueError, SysmonXmlError, WindowsEventLogError, StorageError) as error:
                print(f"SiberAI watch error: {error}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\nStopped. Processed {processed_count} event(s); produced {detection_count} detection(s).")
    return processed_count, detection_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SiberAI against recent supported local Sysmon events.")
    parser.add_argument("--count", type=int, default=10, help="Recent events to inspect (1-100; default: 10)")
    parser.add_argument("--watch", action="store_true", help="Watch for new supported Sysmon events")
    parser.add_argument("--interval", type=_positive_interval, default=1.0, help="Watch polling interval in seconds (default: 1)")
    parser.add_argument("--recent", action="store_true", help="Show recent persisted detections")
    parser.add_argument("--database", default="data/siberai.db", help="SQLite database path (default: data/siberai.db)")
    args = parser.parse_args()

    if args.recent:
        try:
            with SQLiteStorage(args.database) as storage:
                detections = storage.recent_detections(args.count)
        except (ValueError, StorageError) as error:
            parser.exit(1, f"SiberAI storage error: {error}\n")
        if not detections:
            print("No persisted detections found.")
            return 0
        for detection in detections:
            timestamp = detection.event_timestamp.isoformat() if detection.event_timestamp else "unknown time"
            print(
                f"{timestamp} | [{detection.severity.value.upper()}] | "
                f"{detection.title} | {detection.host or 'unknown host'} | "
                f"{detection.risk_score}/100"
            )
        return 0

    if args.watch:
        try:
            with SQLiteStorage(args.database) as storage:
                run_watch(args.interval, monitor=SysmonWatch(storage=storage))
        except (ValueError, SysmonXmlError, WindowsEventLogError, StorageError) as error:
            parser.exit(1, f"SiberAI collector error: {error}\n")
        return 0

    try:
        xml_events = collect_recent_sysmon_process_events(args.count)
    except (ValueError, WindowsEventLogError) as error:
        parser.exit(1, f"SiberAI collector error: {error}\n")

    if not xml_events:
        print("No recent Sysmon Event ID 1 or 3 records found.")
        return 0

    detection_count = 0
    processed_count = 0
    for xml in xml_events:
        try:
            event = normalize_sysmon_event(parse_sysmon_xml(xml))
        except (ValueError, SysmonXmlError) as error:
            print(f"Skipped invalid Sysmon event: {error}")
            continue

        processed_count += 1
        detection_count += _print_event(event, detect(event))

    print(f"Processed {processed_count} event(s); produced {detection_count} detection(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
