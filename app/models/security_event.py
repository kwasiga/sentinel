"""Security event persistence model."""

from datetime import datetime

from sqlalchemy import DateTime, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    actor: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(100))
    outcome: Mapped[str] = mapped_column(String(50))
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
