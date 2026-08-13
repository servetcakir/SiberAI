import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.models.detection import Detection, Severity
from engine.models.event import SecurityEvent
from engine.models.incident import Incident, IncidentStatus


class StorageError(RuntimeError):
    """Raised when persistent event or detection storage fails."""


@dataclass(slots=True)
class StoredEvent:
    event_id: str
    record_id: int | None
    timestamp: datetime
    source_type: str
    category: str
    host: str | None
    user: str | None
    process: str | None
    parent_process: str | None
    command_line: str | None
    source_ip: str | None
    destination_ip: str | None
    process_guid: str | None
    process_id: int | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    initiated: bool | None
    source_hostname: str | None
    destination_hostname: str | None
    raw: dict[str, Any] | None
    created_at: datetime


@dataclass(slots=True)
class StoredDetection:
    detection_id: str
    event_id: str
    rule_id: str
    title: str
    severity: Severity
    risk_score: int
    description: str
    mitre_techniques: list[str]
    evidence: dict[str, Any]
    created_at: datetime
    event_timestamp: datetime | None = None
    host: str | None = None
    process: str | None = None


@dataclass(slots=True)
class IncidentDetail:
    incident: Incident
    events: list[StoredEvent]
    detections: list[StoredDetection]


class SQLiteStorage:
    """Small SQLite store with immutable, first-write-wins inserts."""

    def __init__(self, database: str | Path = Path("data/siberai.db")) -> None:
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connection = sqlite3.connect(self.database)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self.initialize()
        except sqlite3.Error as error:
            raise StorageError(f"Unable to initialize SQLite database: {error}") from error

    def __enter__(self) -> "SQLiteStorage":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            record_id INTEGER,
            timestamp TEXT NOT NULL,
            source_type TEXT NOT NULL,
            category TEXT NOT NULL,
            host TEXT,
            user TEXT,
            process TEXT,
            parent_process TEXT,
            command_line TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            raw_json TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS detections (
            detection_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
            description TEXT NOT NULL,
            mitre_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events(event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_detections_created_at ON detections(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_detections_event_id ON detections(event_id);
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
            host TEXT,
            process_guid TEXT,
            primary_event_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (primary_event_id) REFERENCES events(event_id)
        );
        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY (incident_id, event_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
            FOREIGN KEY (event_id) REFERENCES events(event_id)
        );
        CREATE TABLE IF NOT EXISTS incident_detections (
            incident_id TEXT NOT NULL,
            detection_id TEXT NOT NULL,
            PRIMARY KEY (incident_id, detection_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
            FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_incidents_process_guid ON incidents(process_guid, status);
        """
        try:
            self._connection.executescript(schema)
            self._upgrade_events_schema()
            self._connection.commit()
        except sqlite3.Error as error:
            raise StorageError(f"Unable to initialize SQLite schema: {error}") from error

    def _upgrade_events_schema(self) -> None:
        existing = {row[1] for row in self._connection.execute("PRAGMA table_info(events)")}
        additions = {
            "process_guid": "TEXT",
            "process_id": "INTEGER",
            "source_port": "INTEGER",
            "destination_port": "INTEGER",
            "protocol": "TEXT",
            "initiated": "INTEGER",
            "source_hostname": "TEXT",
            "destination_hostname": "TEXT",
        }
        for column, column_type in additions.items():
            if column not in existing:
                self._connection.execute(f"ALTER TABLE events ADD COLUMN {column} {column_type}")

    def store_event(self, event: SecurityEvent, record_id: int | None = None) -> bool:
        created_at = _utc_now_text()
        if record_id is None:
            record_id = _record_id_from_raw(event.raw)
        values = (
            event.event_id, record_id, _utc_text(event.timestamp), event.source_type,
            event.category, event.host, event.user, event.process, event.parent_process,
            event.command_line, event.source_ip, event.destination_ip,
            event.process_guid, event.process_id, event.source_port,
            event.destination_port, event.protocol,
            int(event.initiated) if event.initiated is not None else None,
            event.source_hostname, event.destination_hostname,
            json.dumps(event.raw, sort_keys=True), created_at,
        )
        return self._insert(
            """INSERT OR IGNORE INTO events (
                event_id, record_id, timestamp, source_type, category, host, user,
                process, parent_process, command_line, source_ip, destination_ip,
                process_guid, process_id, source_port, destination_port, protocol,
                initiated, source_hostname, destination_hostname, raw_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
            "event",
        )

    def store_detection(self, detection: Detection) -> bool:
        values = (
            detection.detection_id, detection.event_id, detection.rule_id,
            detection.title, detection.severity.value, detection.risk_score,
            detection.description, json.dumps(detection.mitre_techniques),
            json.dumps(detection.evidence, sort_keys=True), _utc_now_text(),
        )
        return self._insert(
            """INSERT OR IGNORE INTO detections (
                detection_id, event_id, rule_id, title, severity, risk_score,
                description, mitre_json, evidence_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
            "detection",
        )

    def recent_events(self, limit: int = 20) -> list[StoredEvent]:
        _validate_limit(limit)
        rows = self._query(
            "SELECT * FROM events ORDER BY timestamp DESC, record_id DESC LIMIT ?",
            (limit,),
        )
        return [_stored_event(row) for row in rows]

    def get_event(self, event_id: str) -> StoredEvent | None:
        rows = self._query("SELECT * FROM events WHERE event_id = ?", (event_id,))
        return _stored_event(rows[0]) if rows else None

    def recent_detections(self, limit: int = 20) -> list[StoredDetection]:
        _validate_limit(limit)
        rows = self._query(
            """SELECT d.*, e.timestamp AS event_timestamp, e.host AS host, e.process AS process
               FROM detections d JOIN events e ON e.event_id = d.event_id
               ORDER BY e.timestamp DESC LIMIT ?""",
            (limit,),
        )
        return [_stored_detection(row) for row in rows]

    def detections_for_event(self, event_id: str) -> list[StoredDetection]:
        rows = self._query(
            """SELECT d.*, e.timestamp AS event_timestamp, e.host AS host, e.process AS process
               FROM detections d JOIN events e ON e.event_id = d.event_id
               WHERE d.event_id = ? ORDER BY d.created_at DESC""",
            (event_id,),
        )
        return [_stored_detection(row) for row in rows]

    def get_detection(self, detection_id: str) -> StoredDetection | None:
        rows = self._query(
            """SELECT d.*, e.timestamp AS event_timestamp, e.host AS host, e.process AS process
               FROM detections d JOIN events e ON e.event_id = d.event_id
               WHERE d.detection_id = ?""",
            (detection_id,),
        )
        return _stored_detection(rows[0]) if rows else None

    def store_incident(self, incident: Incident) -> bool:
        return self._insert(
            """INSERT OR IGNORE INTO incidents (
                incident_id, title, status, severity, risk_score, host, process_guid,
                primary_event_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.incident_id, incident.title, incident.status.value,
                incident.severity.value, incident.risk_score, incident.host,
                incident.process_guid, incident.primary_event_id,
                _utc_text(incident.created_at), _utc_text(incident.updated_at),
            ),
            "incident",
        )

    def attach_incident_event(self, incident_id: str, event_id: str) -> bool:
        return self._insert(
            "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
            (incident_id, event_id), "incident event relationship",
        )

    def attach_incident_detection(self, incident_id: str, detection_id: str) -> bool:
        return self._insert(
            "INSERT OR IGNORE INTO incident_detections (incident_id, detection_id) VALUES (?, ?)",
            (incident_id, detection_id), "incident detection relationship",
        )

    def update_incident(
        self, incident_id: str, *, title: str, severity: Severity,
        risk_score: int, updated_at: datetime,
    ) -> None:
        try:
            cursor = self._connection.execute(
                """UPDATE incidents SET title = ?, severity = ?, risk_score = ?, updated_at = ?
                   WHERE incident_id = ?""",
                (title, severity.value, risk_score, _utc_text(updated_at), incident_id),
            )
            if cursor.rowcount != 1:
                raise StorageError(f"Incident not found: {incident_id}")
            self._connection.commit()
        except sqlite3.Error as error:
            self._connection.rollback()
            raise StorageError(f"Unable to update incident: {error}") from error

    def recent_incidents(self, limit: int = 20) -> list[Incident]:
        _validate_limit(limit)
        rows = self._query("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,))
        return [self._stored_incident(row) for row in rows]

    def get_incident(self, incident_id: str) -> Incident | None:
        rows = self._query("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        return self._stored_incident(rows[0]) if rows else None

    def get_incident_detail(self, incident_id: str) -> IncidentDetail | None:
        incident = self.get_incident(incident_id)
        if incident is None:
            return None
        event_rows = self._query(
            """SELECT e.* FROM events e JOIN incident_events ie ON ie.event_id = e.event_id
               WHERE ie.incident_id = ? ORDER BY e.timestamp ASC, e.record_id ASC""",
            (incident_id,),
        )
        detection_rows = self._query(
            """SELECT d.*, e.timestamp AS event_timestamp, e.host AS host, e.process AS process
               FROM detections d JOIN incident_detections id ON id.detection_id = d.detection_id
               JOIN events e ON e.event_id = d.event_id
               WHERE id.incident_id = ? ORDER BY d.created_at ASC""",
            (incident_id,),
        )
        return IncidentDetail(
            incident=incident,
            events=[_stored_event(row) for row in event_rows],
            detections=[_stored_detection(row) for row in detection_rows],
        )

    def find_open_incident(
        self, process_guid: str, host: str | None, timestamp: datetime,
        window_seconds: int,
    ) -> Incident | None:
        rows = self._query(
            """SELECT i.* FROM incidents i JOIN events p ON p.event_id = i.primary_event_id
               WHERE i.status = ? AND i.process_guid = ?
                 AND (i.host IS NULL OR ? IS NULL OR lower(i.host) = lower(?))
                 AND abs(strftime('%s', p.timestamp) - strftime('%s', ?)) <= ?
               ORDER BY i.updated_at DESC LIMIT 1""",
            (IncidentStatus.OPEN.value, process_guid, host, host, _utc_text(timestamp), window_seconds),
        )
        return self._stored_incident(rows[0]) if rows else None

    def related_events(
        self, process_guid: str, host: str | None, timestamp: datetime,
        window_seconds: int, limit: int = 100,
    ) -> list[StoredEvent]:
        _validate_limit(limit)
        rows = self._query(
            """SELECT * FROM events WHERE process_guid = ?
                 AND (host IS NULL OR ? IS NULL OR lower(host) = lower(?))
                 AND abs(strftime('%s', timestamp) - strftime('%s', ?)) <= ?
               ORDER BY timestamp ASC, record_id ASC LIMIT ?""",
            (process_guid, host, host, _utc_text(timestamp), window_seconds, limit),
        )
        return [_stored_event(row) for row in rows]

    def _stored_incident(self, row: sqlite3.Row) -> Incident:
        event_ids = [item[0] for item in self._query(
            "SELECT event_id FROM incident_events WHERE incident_id = ? ORDER BY event_id", (row["incident_id"],)
        )]
        detection_ids = [item[0] for item in self._query(
            "SELECT detection_id FROM incident_detections WHERE incident_id = ? ORDER BY detection_id", (row["incident_id"],)
        )]
        return Incident(
            incident_id=row["incident_id"], title=row["title"],
            status=IncidentStatus(row["status"]), severity=Severity(row["severity"]),
            risk_score=row["risk_score"], created_at=_parse_datetime(row["created_at"]),
            updated_at=_parse_datetime(row["updated_at"]), host=row["host"],
            process_guid=row["process_guid"], primary_event_id=row["primary_event_id"],
            event_ids=event_ids, detection_ids=detection_ids,
        )

    def _insert(self, sql: str, values: tuple[object, ...], label: str) -> bool:
        try:
            cursor = self._connection.execute(sql, values)
            self._connection.commit()
            return cursor.rowcount == 1
        except sqlite3.Error as error:
            self._connection.rollback()
            raise StorageError(f"Unable to store {label}: {error}") from error

    def _query(self, sql: str, values: tuple[object, ...]) -> list[sqlite3.Row]:
        try:
            return list(self._connection.execute(sql, values))
        except sqlite3.Error as error:
            raise StorageError(f"Unable to query SQLite database: {error}") from error


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("stored timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now_text() -> str:
    return _utc_text(datetime.now(timezone.utc))


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _record_id_from_raw(raw: dict[str, Any] | None) -> int | None:
    system = raw.get("_System") if isinstance(raw, dict) else None
    value = system.get("RecordID") if isinstance(system, dict) else None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid event record ID: {value!r}") from error


def _validate_limit(limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer between 1 and 1000")


def _stored_event(row: sqlite3.Row) -> StoredEvent:
    return StoredEvent(
        event_id=row["event_id"], record_id=row["record_id"],
        timestamp=_parse_datetime(row["timestamp"]), source_type=row["source_type"],
        category=row["category"], host=row["host"], user=row["user"],
        process=row["process"], parent_process=row["parent_process"],
        command_line=row["command_line"], source_ip=row["source_ip"],
        destination_ip=row["destination_ip"], process_guid=row["process_guid"],
        process_id=row["process_id"], source_port=row["source_port"],
        destination_port=row["destination_port"], protocol=row["protocol"],
        initiated=bool(row["initiated"]) if row["initiated"] is not None else None,
        source_hostname=row["source_hostname"], destination_hostname=row["destination_hostname"],
        raw=json.loads(row["raw_json"]),
        created_at=_parse_datetime(row["created_at"]),
    )


def _stored_detection(row: sqlite3.Row) -> StoredDetection:
    return StoredDetection(
        detection_id=row["detection_id"], event_id=row["event_id"],
        rule_id=row["rule_id"], title=row["title"], severity=Severity(row["severity"]),
        risk_score=row["risk_score"], description=row["description"],
        mitre_techniques=json.loads(row["mitre_json"]),
        evidence=json.loads(row["evidence_json"]),
        created_at=_parse_datetime(row["created_at"]),
        event_timestamp=_parse_datetime(row["event_timestamp"]) if "event_timestamp" in row.keys() else None,
        host=row["host"] if "host" in row.keys() else None,
        process=row["process"] if "process" in row.keys() else None,
    )
