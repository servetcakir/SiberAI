import argparse

from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_process_create
from engine.ingestion.sysmon_xml import SysmonXmlError, parse_process_create_xml
from engine.ingestion.windows_event_log import (
    WindowsEventLogError,
    collect_recent_sysmon_process_events,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SiberAI against recent local Sysmon process events.")
    parser.add_argument("--count", type=int, default=10, help="Recent events to inspect (1-100; default: 10)")
    args = parser.parse_args()

    try:
        xml_events = collect_recent_sysmon_process_events(args.count)
    except (ValueError, WindowsEventLogError) as error:
        parser.exit(1, f"SiberAI collector error: {error}\n")

    if not xml_events:
        print("No recent Sysmon Event ID 1 records found.")
        return 0

    detection_count = 0
    processed_count = 0
    for xml in xml_events:
        try:
            event = normalize_process_create(parse_process_create_xml(xml))
        except (ValueError, SysmonXmlError) as error:
            print(f"Skipped invalid Sysmon event: {error}")
            continue

        processed_count += 1
        detections = detect(event)
        if not detections:
            print(f"[OK] {event.host or 'unknown host'} | {event.process or 'unknown process'} | no detections")
            continue

        for detection in detections:
            detection_count += 1
            print(f"[{detection.severity.value.upper()}] {detection.title}")
            print(f"Rule: {detection.rule_id}")
            print(f"Host: {event.host or 'unknown'}")
            print(f"Process: {event.process or 'unknown'}")
            print(f"Risk: {detection.risk_score}/100")
            print(f"MITRE: {', '.join(detection.mitre_techniques) or 'none'}")
            print()

    print(f"Processed {processed_count} event(s); produced {detection_count} detection(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
