"""Security-event fan-out to PostgreSQL and Redis."""

import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.config import settings
from detection.engine import evaluate_event
from app.models.security_event import SecurityEvent


def record_security_event(
    *, db: Session, event_id: str, event_type: str, actor: str, outcome: str, payload: dict, source: str = "api"
) -> SecurityEvent:
    event = SecurityEvent(
        id=event_id,
        event_type=event_type,
        actor=actor,
        source=source,
        outcome=outcome,
        payload=payload,
        created_at=datetime.utcnow(),
    )
    db.add(event)
    db.commit()

    if settings.REDIS_URL:
        try:
            import redis

            client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
            client.xadd("security-events", {"event": json.dumps(_event_dict(event))})
        except Exception:
            # Redis is a secondary delivery path; database persistence remains authoritative.
            pass

    evaluate_event(db, event)

    return event


def _event_dict(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "event_type": event.event_type,
        "actor": event.actor,
        "source": event.source,
        "outcome": event.outcome,
        "payload": event.payload,
        "created_at": event.created_at.isoformat(),
    }
