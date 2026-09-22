"""Run detection rules and persist findings."""

import uuid

from sqlalchemy.orm import Session

from app.models.detection_finding import DetectionFinding
from app.models.security_event import SecurityEvent
from detection.rules.brute_force import detect as detect_brute_force


def evaluate_event(db: Session, event: SecurityEvent) -> DetectionFinding | None:
    finding = detect_brute_force(event)
    if finding is None:
        return None

    persisted = DetectionFinding(
        id=str(uuid.uuid4()),
        rule_name=finding.rule_name,
        severity="high",
        key=finding.key,
        evidence={
            "event_ids": finding.evidence_ids,
            "threshold": finding.threshold,
            "window_seconds": finding.window_seconds,
            "detected_at": finding.detected_at.isoformat(),
        },
        created_at=finding.detected_at,
    )
    db.add(persisted)
    db.commit()
    return persisted
