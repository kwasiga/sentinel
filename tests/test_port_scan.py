from datetime import datetime, timedelta

from app.models.security_event import SecurityEvent
from detection.rules.port_scan import detect
from detection.state import DetectionState


def test_port_scan_requires_unique_ports_to_same_destination(monkeypatch) -> None:
    import detection.rules.port_scan as rule

    local_state = DetectionState()
    monkeypatch.setattr(rule, "state", local_state)
    monkeypatch.setattr(rule.settings, "PORT_SCAN_THRESHOLD", 3)
    base = datetime(2026, 1, 1, 12, 0, 0)

    for index, port in enumerate([22, 80]):
        event = SecurityEvent(
            id=f"event-{index}",
            event_type="network.tcp.connection",
            actor="workstation-17",
            source="endpoint-agent",
            outcome="refused",
            payload={
                "source_ip": "10.0.1.25",
                "destination_ip": "10.0.2.10",
                "destination_port": port,
                "protocol": "tcp",
            },
            created_at=base + timedelta(seconds=index),
        )
        assert detect(event) is None

    event = SecurityEvent(
        id="event-2",
        event_type="network.tcp.connection",
        actor="workstation-17",
        source="endpoint-agent",
        outcome="refused",
        payload={
            "source_ip": "10.0.1.25",
            "destination_ip": "10.0.2.10",
            "destination_port": 443,
            "protocol": "tcp",
        },
        created_at=base + timedelta(seconds=2),
    )
    finding = detect(event)

    assert finding is not None
    assert finding.rule_name == "PORT_SCAN"
    assert finding.key == "10.0.1.25:10.0.2.10"
    assert finding.ports == [22, 80, 443]
    assert finding.evidence_ids == ["event-0", "event-1", "event-2"]


def test_port_scan_ignores_repeated_ports_and_other_protocols(monkeypatch) -> None:
    import detection.rules.port_scan as rule

    local_state = DetectionState()
    monkeypatch.setattr(rule, "state", local_state)
    monkeypatch.setattr(rule.settings, "PORT_SCAN_THRESHOLD", 3)
    base = datetime(2026, 1, 1, 12, 0, 0)

    events = [
        ("event-0", 443, "tcp"),
        ("event-1", 443, "tcp"),
        ("event-2", 53, "udp"),
        ("event-3", 80, "tcp"),
    ]
    for index, (event_id, port, protocol) in enumerate(events):
        event = SecurityEvent(
            id=event_id,
            event_type="network.tcp.connection",
            actor="workstation-17",
            source="endpoint-agent",
            outcome="refused",
            payload={
                "source_ip": "10.0.1.25",
                "destination_ip": "10.0.2.10",
                "destination_port": port,
                "protocol": protocol,
            },
            created_at=base + timedelta(seconds=index),
        )
        assert detect(event) is None
