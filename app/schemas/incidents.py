"""Incident schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

IncidentStatus = Literal["open", "acknowledged", "resolved"]


class IncidentResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: IncidentStatus
    finding_id: str
    evidence: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class IncidentUpdate(BaseModel):
    status: IncidentStatus
