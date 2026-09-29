"""Detect one source probing many TCP ports on one destination."""

from dataclasses import dataclass
from datetime import datetime

from app.config import settings
from app.models.security_event import SecurityEvent
from detection.state import state


@dataclass(frozen=True)
class PortScanFinding:
    rule_name: str
    key: str
    evidence_ids: list[str]
    ports: list[int]
    threshold: int
    window_seconds: int
    detected_at: datetime


def detect(event: SecurityEvent) -> PortScanFinding | None:
    if event.event_type != "network.tcp.connection":
        return None

    source_ip = event.payload.get("source_ip")
    destination_ip = event.payload.get("destination_ip")
    destination_port = event.payload.get("destination_port")
    protocol = str(event.payload.get("protocol", "tcp")).lower()
    if protocol != "tcp" or not source_ip or not destination_ip:
        return None

    try:
        port = int(destination_port)
    except (TypeError, ValueError):
        return None

    if port < 1 or port > 65535:
        return None

    key = f"{source_ip}:{destination_ip}"
    evidence_ids, ports, threshold_crossed = state.add_unique_value(
        key=key,
        event_id=event.id,
        value=port,
        occurred_at=event.created_at,
        window_seconds=settings.PORT_SCAN_WINDOW_SECONDS,
        threshold=settings.PORT_SCAN_THRESHOLD,
    )
    if not threshold_crossed:
        return None

    return PortScanFinding(
        rule_name="PORT_SCAN",
        key=key,
        evidence_ids=evidence_ids,
        ports=ports,
        threshold=settings.PORT_SCAN_THRESHOLD,
        window_seconds=settings.PORT_SCAN_WINDOW_SECONDS,
        detected_at=event.created_at,
    )
