"""Detect repeated failed logins against many accounts from one source IP."""

from dataclasses import dataclass
from datetime import datetime

from app.config import settings
from app.models.security_event import SecurityEvent
from detection.state import state


@dataclass(frozen=True)
class PasswordSprayFinding:
    rule_name: str
    key: str
    evidence_ids: list[str]
    accounts: list[str]
    threshold: int
    window_seconds: int
    detected_at: datetime


def detect(event: SecurityEvent) -> PasswordSprayFinding | None:
    if event.event_type != "authentication.login" or event.outcome != "failure":
        return None
    ip_address = event.payload.get("ip_address") or event.payload.get("source_ip")
    username = event.payload.get("username") or event.actor
    if not ip_address or not username:
        return None
    key = str(ip_address)
    event_ids, accounts, crossed = state.add_distinct_actor(
        key=key,
        event_id=event.id,
        actor=str(username),
        occurred_at=event.created_at,
        window_seconds=settings.PASSWORD_SPRAY_WINDOW_SECONDS,
        threshold=settings.PASSWORD_SPRAY_MIN_ACCOUNTS,
    )
    if not crossed:
        return None
    return PasswordSprayFinding(
        rule_name="PASSWORD_SPRAY",
        key=key,
        evidence_ids=event_ids,
        accounts=accounts,
        threshold=settings.PASSWORD_SPRAY_MIN_ACCOUNTS,
        window_seconds=settings.PASSWORD_SPRAY_WINDOW_SECONDS,
        detected_at=event.created_at,
    )
