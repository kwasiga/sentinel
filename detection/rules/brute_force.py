"""Detect repeated failed logins from one IP against one account."""

from dataclasses import dataclass
from datetime import datetime

from app.config import settings
from app.models.security_event import SecurityEvent
from detection.state import state


@dataclass(frozen=True)
class BruteForceFinding:
    rule_name: str
    key: str
    evidence_ids: list[str]
    threshold: int
    window_seconds: int
    detected_at: datetime


def detect(event: SecurityEvent) -> BruteForceFinding | None:
    if event.event_type != "authentication.login" or event.outcome != "failure":
        return None

    ip_address = event.payload.get("ip_address")
    username = event.payload.get("username") or event.actor
    if not ip_address or not username:
        return None

    key = f"{ip_address}:{username}"
    evidence_ids, threshold_crossed = state.add_failure(
        key=key,
        event_id=event.id,
        occurred_at=event.created_at,
        window_seconds=settings.BRUTE_FORCE_WINDOW_SECONDS,
        threshold=settings.BRUTE_FORCE_THRESHOLD,
    )
    if not threshold_crossed:
        return None

    return BruteForceFinding(
        rule_name="BRUTE_FORCE",
        key=key,
        evidence_ids=evidence_ids,
        threshold=settings.BRUTE_FORCE_THRESHOLD,
        window_seconds=settings.BRUTE_FORCE_WINDOW_SECONDS,
        detected_at=event.created_at,
    )
