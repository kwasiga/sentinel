"""Security event schemas."""

from datetime import datetime

from pydantic import BaseModel


class SecurityEventResponse(BaseModel):
    id: str
    event_type: str
    actor: str
    source: str
    outcome: str
    created_at: datetime
