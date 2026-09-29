"""Incident triage API."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.incident import Incident
from app.schemas.incidents import IncidentResponse, IncidentUpdate

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentResponse])
def list_incidents(db: Session = Depends(get_db)) -> list[IncidentResponse]:
    incidents = db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()
    return [IncidentResponse.model_validate(incident, from_attributes=True) for incident in incidents]


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> IncidentResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return IncidentResponse.model_validate(incident, from_attributes=True)


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: str, incident_update: IncidentUpdate, db: Session = Depends(get_db)
) -> IncidentResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    incident.status = incident_update.status
    incident.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(incident)
    return IncidentResponse.model_validate(incident, from_attributes=True)
