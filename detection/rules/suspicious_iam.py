"""Detect high-impact AWS IAM changes from normalized CloudTrail events."""

from dataclasses import dataclass
from datetime import datetime

from app.config import settings
from app.models.security_event import SecurityEvent


@dataclass(frozen=True)
class SuspiciousIAMFinding:
    rule_name: str
    key: str
    evidence_ids: list[str]
    action: str
    detected_at: datetime


def detect(event: SecurityEvent) -> SuspiciousIAMFinding | None:
    if event.event_type != "cloudtrail.iam" or event.outcome != "success":
        return None
    action = str(event.payload.get("action", ""))
    suspicious_actions = {item.strip() for item in settings.SUSPICIOUS_IAM_ACTIONS.split(",") if item.strip()}
    if action not in suspicious_actions:
        return None
    resource = str(event.payload.get("resource") or event.actor)
    return SuspiciousIAMFinding(
        rule_name="SUSPICIOUS_IAM_CHANGE",
        key=f"{event.actor}:{action}:{resource}",
        evidence_ids=[event.id],
        action=action,
        detected_at=event.created_at,
    )
