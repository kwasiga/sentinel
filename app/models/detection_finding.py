"""Persisted results produced by detection rules."""

from datetime import datetime

from sqlalchemy import DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class DetectionFinding(Base):
    __tablename__ = "detection_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_name: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(50))
    key: Mapped[str] = mapped_column(String(512), index=True)
    evidence: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
