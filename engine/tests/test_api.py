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
