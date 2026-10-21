"""Security event ingestion API."""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.events import SecurityEventCreate, SecurityEventResponse
from app.services.events import record_security_event
from telemetry.authentication import normalize as normalize_authentication
from telemetry.cloudtrail import normalize as normalize_cloudtrail

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
def ingest_event(event_request: SecurityEventCreate, db: Session = Depends(get_db)) -> SecurityEventResponse:
    event = record_security_event(
        db=db,
        event_id=str(uuid.uuid4()),
        event_type=event_request.event_type,
        actor=event_request.actor,
        source=event_request.source,
        outcome=event_request.outcome,
        payload=event_request.payload,
    )
    return SecurityEventResponse.model_validate(event, from_attributes=True)


@router.post("/authentication", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
def ingest_authentication(payload: dict[str, Any], db: Session = Depends(get_db)) -> SecurityEventResponse:
    normalized = normalize_authentication(payload)
    event = record_security_event(
        db=db,
        event_id=str(uuid.uuid4()),
        event_type=normalized["event_type"],
        actor=normalized["actor"],
        source=normalized["source"],
        outcome=normalized["outcome"],
        payload=normalized["payload"],
        occurred_at=normalized["created_at"],
    )
    return SecurityEventResponse.model_validate(event, from_attributes=True)


@router.post("/cloudtrail", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
def ingest_cloudtrail(payload: dict[str, Any], db: Session = Depends(get_db)) -> SecurityEventResponse:
    normalized = normalize_cloudtrail(payload)
    event = record_security_event(
        db=db,
        event_id=str(uuid.uuid4()),
        event_type=normalized["event_type"],
        actor=normalized["actor"],
        source=normalized["source"],
        outcome=normalized["outcome"],
        payload=normalized["payload"],
        occurred_at=normalized["created_at"],
    )
    return SecurityEventResponse.model_validate(event, from_attributes=True)
