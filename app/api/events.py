"""Security event ingestion API."""

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.events import SecurityEventCreate, SecurityEventResponse
from app.services.events import record_security_event

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
