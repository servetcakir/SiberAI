import unittest
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from engine.api.app import create_app, get_storage
from engine.detection.engine import detect
from engine.ingestion.sysmon import normalize_process_create
from engine.ingestion.sysmon_xml import parse_process_create_xml
from engine.storage.sqlite import SQLiteStorage, StorageError
from engine.tests.test_sysmon_xml import sysmon_xml
from engine.ingestion.sysmon import normalize_sysmon_event
from engine.ingestion.sysmon_xml import parse_sysmon_xml
from engine.tests.test_sysmon_network import network_xml
from engine.correlation.engine import correlate
from engine.analysis.decision_engine import analyze_incident


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "api.db"
        with SQLiteStorage(self.database) as storage:
            older = normalize_process_create(parse_process_create_xml(sysmon_xml(record_id=8421)))
            newer = normalize_process_create(
                parse_process_create_xml(
                    sysmon_xml(
                        record_id=8422,
                        command_line="powershell.exe -NoProfile Get-Process",
                    )
                )
            )
            newer.event_id = "{NEWER-EVENT}"
            storage.store_event(older, 8421)
            storage.store_detection(detect(older)[0])
            storage.store_event(newer, 8422)
            self.event_id = older.event_id
            self.detection_id = detect(older)[0].detection_id

        self.app = create_app()

        def temporary_storage() -> Iterator[SQLiteStorage]:
            with SQLiteStorage(self.database) as storage:
                yield storage

        self.app.dependency_overrides[get_storage] = temporary_storage
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.client.close()
        self.temporary_directory.cleanup()

    def test_health_endpoint(self) -> None:
        response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"status": "ok", "service": "siberai-engine", "database": "available"},
        )

    def test_event_list_is_newest_first_and_omits_raw(self) -> None:
        response = self.client.get("/api/events?limit=2")

        self.assertEqual(response.status_code, 200)
        events = response.json()
        self.assertEqual([event["record_id"] for event in events], [8422, 8421])
        self.assertNotIn("raw", events[0])

    def test_event_limit_validation(self) -> None:
        self.assertEqual(self.client.get("/api/events?limit=0").status_code, 422)
        self.assertEqual(self.client.get("/api/events?limit=201").status_code, 422)

    def test_event_detail_includes_raw_and_detections(self) -> None:
        response = self.client.get(f"/api/events/{self.event_id}")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["event_id"], self.event_id)
        self.assertEqual(body["raw"]["_System"]["RecordID"], "8421")
        self.assertEqual(body["detections"][0]["rule_id"], "DET-PS-001")

    def test_event_detail_returns_404(self) -> None:
        response = self.client.get("/api/events/missing")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Security event not found"})

    def test_event_list_represents_network_event(self) -> None:
        network = normalize_sysmon_event(parse_sysmon_xml(network_xml(record_id=8423)))
        with SQLiteStorage(self.database) as storage:
            storage.store_event(network, 8423)
        event = self.client.get("/api/events?limit=1").json()[0]
        self.assertEqual(event["category"], "network_connection")
        self.assertEqual(event["source_port"], 54321)
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["protocol"], "tcp")

    def test_event_detail_represents_network_event(self) -> None:
        network = normalize_sysmon_event(parse_sysmon_xml(network_xml(record_id=8423)))
        with SQLiteStorage(self.database) as storage:
            storage.store_event(network, 8423)
        event = self.client.get(f"/api/events/{network.event_id}").json()
        self.assertEqual(event["process_guid"], "{NET-PROCESS-GUID}")
        self.assertEqual(event["source_ip"], "192.168.1.25")
        self.assertIs(event["initiated"], True)
        self.assertEqual(event["detections"], [])

    def test_detection_list_includes_event_context(self) -> None:
        response = self.client.get("/api/detections?limit=10")

        self.assertEqual(response.status_code, 200)
        detection = response.json()[0]
        self.assertEqual(detection["detection_id"], self.detection_id)
        self.assertEqual(detection["host"], "WS-FIN-042.siberai.local")
        self.assertEqual(detection["process"], "powershell.exe")
        self.assertIsNotNone(detection["event_timestamp"])

    def test_detection_detail_retrieval(self) -> None:
        response = self.client.get(f"/api/detections/{self.detection_id}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["mitre_techniques"], ["T1059.001"])
        self.assertEqual(response.json()["process"], "powershell.exe")

    def test_detection_detail_returns_404(self) -> None:
        self.assertEqual(self.client.get("/api/detections/missing").status_code, 404)

    def create_incident(self) -> str:
        event = normalize_process_create(parse_process_create_xml(sysmon_xml(record_id=8421)))
        detection = detect(event)[0]
        with SQLiteStorage(self.database) as storage:
            result = correlate(event, [detection], storage)
            detail = storage.get_incident_detail(result.incident.incident_id)
            storage.store_analysis(analyze_incident(detail.incident, detail.events, detail.detections))
        return result.incident.incident_id

    def test_incident_list_endpoint(self) -> None:
        incident_id = self.create_incident()
        response = self.client.get("/api/incidents?limit=10")
        self.assertEqual(response.status_code, 200)
        incident = response.json()[0]
        self.assertEqual(incident["incident_id"], incident_id)
        self.assertEqual(incident["event_count"], 2)
        self.assertEqual(incident["detection_count"], 1)

    def test_incident_detail_endpoint(self) -> None:
        incident_id = self.create_incident()
        response = self.client.get(f"/api/incidents/{incident_id}")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["severity"], "high")
        self.assertEqual(body["events"][0]["event_id"], self.event_id)
        self.assertEqual(body["detections"][0]["rule_id"], "DET-PS-001")
        self.assertNotIn("raw", body["events"][0])

    def test_unknown_incident_returns_404(self) -> None:
        response = self.client.get("/api/incidents/missing")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Incident not found"})

    def test_analysis_endpoint_returns_structured_analysis(self) -> None:
        incident_id = self.create_incident()
        response = self.client.get(f"/api/incidents/{incident_id}/analysis")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["incident_id"], incident_id)
        self.assertEqual(body["verdict"], "suspicious")
        self.assertEqual(body["engine_version"], "decision-v0")
        self.assertEqual(body["reason_codes"], ["encoded_powershell"])
        self.assertEqual(body["evidence"][0]["rule_id"], "DET-PS-001")

    def test_analysis_endpoint_distinguishes_missing_incident_and_analysis(self) -> None:
        missing = self.client.get("/api/incidents/missing/analysis")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json(), {"detail": "Incident not found"})
        event = normalize_process_create(parse_process_create_xml(sysmon_xml(record_id=8421)))
        with SQLiteStorage(self.database) as storage:
            incident = correlate(event, [detect(event)[0]], storage).incident
            storage._connection.execute("DELETE FROM incident_analyses WHERE incident_id = ?", (incident.incident_id,))
            storage._connection.commit()
        no_analysis = self.client.get(f"/api/incidents/{incident.incident_id}/analysis")
        self.assertEqual(no_analysis.status_code, 404)
        self.assertEqual(no_analysis.json(), {"detail": "Incident analysis not found"})

    def test_database_failure_does_not_leak_path(self) -> None:
        secret_path = r"C:\secret\private\siberai.db"

        def failed_storage() -> Iterator[SQLiteStorage]:
            raise StorageError(f"Unable to query {secret_path}")
            yield  # pragma: no cover

        self.app.dependency_overrides[get_storage] = failed_storage
        response = self.client.get("/api/events")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Database unavailable"})
        self.assertNotIn(secret_path, response.text)

    def test_cors_allows_local_next_development_origin(self) -> None:
        response = self.client.options(
            "/api/events",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["access-control-allow-origin"], "http://localhost:3000")

    def test_no_mutation_routes_exist(self) -> None:
        mutation_methods = {"POST", "PUT", "PATCH", "DELETE"}
        for route in self.app.routes:
            if getattr(route, "path", "").startswith("/api/"):
                self.assertTrue(mutation_methods.isdisjoint(route.methods or set()))


if __name__ == "__main__":
    unittest.main()
