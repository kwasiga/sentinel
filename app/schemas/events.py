"""Security event schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityEventCreate(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    actor: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=100)
    outcome: str = Field(min_length=1, max_length=50)
    payload: dict[str, Any] = Field(default_factory=dict)


class SecurityEventResponse(BaseModel):
    id: str
    event_type: str
    actor: str
    source: str
    outcome: str
    payload: dict[str, Any]
    created_at: datetime
