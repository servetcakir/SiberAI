import logging
import os
from collections.abc import Iterator

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from engine.api.schemas import (
    DetectionResponse,
    EventDetailResponse,
    EventResponse,
    HealthResponse,
    IncidentDetailResponse,
    IncidentResponse,
    IncidentAnalysisResponse,
)
from engine.storage.sqlite import SQLiteStorage, StorageError
from engine.models.incident import Incident


logger = logging.getLogger(__name__)
DEFAULT_DATABASE = "data/siberai.db"


def _database_path() -> str:
    return os.environ.get("SIBERAI_DATABASE", DEFAULT_DATABASE)


def get_storage() -> Iterator[SQLiteStorage]:
    with SQLiteStorage(_database_path()) as storage:
        yield storage


def _incident_response(incident: Incident) -> IncidentResponse:
    return IncidentResponse(
        incident_id=incident.incident_id,
        title=incident.title,
        status=incident.status,
        severity=incident.severity,
        risk_score=incident.risk_score,
        host=incident.host,
        process_guid=incident.process_guid,
        primary_event_id=incident.primary_event_id,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        event_count=len(incident.event_ids),
        detection_count=len(incident.detection_ids),
    )


def create_app() -> FastAPI:
    application = FastAPI(title="SiberAI Engine API", version="0.1.0")
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Accept", "Content-Type"],
    )

    @application.exception_handler(StorageError)
    async def storage_error_handler(request: Request, error: StorageError) -> JSONResponse:
        logger.error("Storage operation failed for API route %s", request.url.path)
        return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

    @application.get("/api/health", response_model=HealthResponse)
    def health(storage: SQLiteStorage = Depends(get_storage)) -> HealthResponse:
        storage.recent_events(1)
        return HealthResponse(status="ok", service="siberai-engine", database="available")

    @application.get("/api/events", response_model=list[EventResponse])
    def events(
        limit: int = Query(default=50, ge=1, le=200),
        storage: SQLiteStorage = Depends(get_storage),
    ) -> list[EventResponse]:
        return [EventResponse.model_validate(event) for event in storage.recent_events(limit)]

    @application.get("/api/events/{event_id}", response_model=EventDetailResponse)
    def event_detail(
        event_id: str,
        storage: SQLiteStorage = Depends(get_storage),
    ) -> EventDetailResponse:
        event = storage.get_event(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Security event not found")
        detections = storage.detections_for_event(event_id)
        return EventDetailResponse(
            **EventResponse.model_validate(event).model_dump(),
            raw=event.raw,
            detections=[DetectionResponse.model_validate(item) for item in detections],
        )

    @application.get("/api/detections", response_model=list[DetectionResponse])
    def detections(
        limit: int = Query(default=50, ge=1, le=200),
        storage: SQLiteStorage = Depends(get_storage),
    ) -> list[DetectionResponse]:
        return [DetectionResponse.model_validate(item) for item in storage.recent_detections(limit)]

    @application.get("/api/detections/{detection_id}", response_model=DetectionResponse)
    def detection_detail(
        detection_id: str,
        storage: SQLiteStorage = Depends(get_storage),
    ) -> DetectionResponse:
        detection = storage.get_detection(detection_id)
        if detection is None:
            raise HTTPException(status_code=404, detail="Detection not found")
        return DetectionResponse.model_validate(detection)

    @application.get("/api/incidents", response_model=list[IncidentResponse])
    def incidents(
        limit: int = Query(default=50, ge=1, le=200),
        storage: SQLiteStorage = Depends(get_storage),
    ) -> list[IncidentResponse]:
        return [_incident_response(item) for item in storage.recent_incidents(limit)]

    @application.get("/api/incidents/{incident_id}", response_model=IncidentDetailResponse)
    def incident_detail(
        incident_id: str,
        storage: SQLiteStorage = Depends(get_storage),
    ) -> IncidentDetailResponse:
        detail = storage.get_incident_detail(incident_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return IncidentDetailResponse(
            **_incident_response(detail.incident).model_dump(),
            events=[EventResponse.model_validate(item) for item in detail.events],
            detections=[DetectionResponse.model_validate(item) for item in detail.detections],
        )

    @application.get(
        "/api/incidents/{incident_id}/analysis",
        response_model=IncidentAnalysisResponse,
    )
    def incident_analysis(
        incident_id: str,
        storage: SQLiteStorage = Depends(get_storage),
    ) -> IncidentAnalysisResponse:
        if storage.get_incident(incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        analysis = storage.get_analysis(incident_id)
        if analysis is None:
            raise HTTPException(status_code=404, detail="Incident analysis not found")
        return IncidentAnalysisResponse.model_validate(analysis)

    return application


app = create_app()
