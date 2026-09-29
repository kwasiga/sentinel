"""Run detection rules and persist findings."""

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.detection_finding import DetectionFinding
from app.models.incident import Incident
from app.models.security_event import SecurityEvent
from detection.rules.brute_force import detect as detect_brute_force
from detection.rules.port_scan import detect as detect_port_scan


def evaluate_event(db: Session, event: SecurityEvent) -> DetectionFinding | None:
    finding = detect_brute_force(event) or detect_port_scan(event)
    if finding is None:
        return None

    evidence = {
        "event_ids": finding.evidence_ids,
        "threshold": finding.threshold,
        "window_seconds": finding.window_seconds,
        "detected_at": finding.detected_at.isoformat(),
    }
    if hasattr(finding, "ports"):
        evidence["ports"] = finding.ports

    persisted = DetectionFinding(
        id=str(uuid.uuid4()),
        rule_name=finding.rule_name,
        severity="high",
        key=finding.key,
        evidence=evidence,
        created_at=finding.detected_at,
    )
    db.add(persisted)
    db.commit()
    create_incident(db, persisted)
    return persisted


def create_incident(db: Session, finding: DetectionFinding) -> Incident:
    incident = Incident(
        id=str(uuid.uuid4()),
        title=_incident_title(finding.rule_name),
        severity=finding.severity,
        status="open",
        finding_id=finding.id,
        evidence=finding.evidence,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(incident)
    db.commit()
    return incident


def _incident_title(rule_name: str) -> str:
    titles = {
        "BRUTE_FORCE": "Possible brute-force login attack",
        "PORT_SCAN": "Possible TCP port scan",
    }
    return titles.get(rule_name, f"Security finding: {rule_name}")
