from datetime import datetime, timedelta

from app.models.security_event import SecurityEvent
from detection.rules.brute_force import detect
from detection.state import DetectionState


def test_brute_force_requires_same_ip_and_account_within_window(monkeypatch) -> None:
    import detection.rules.brute_force as rule

    local_state = DetectionState()
    monkeypatch.setattr(rule, "state", local_state)
    base = datetime(2026, 1, 1, 12, 0, 0)

    for index in range(4):
        event = SecurityEvent(
            id=f"event-{index}",
            event_type="authentication.login",
            actor="alice",
            source="api",
            outcome="failure",
            payload={"username": "alice", "ip_address": "203.0.113.10"},
            created_at=base + timedelta(seconds=index),
        )
        assert detect(event) is None

    event = SecurityEvent(
        id="event-4",
        event_type="authentication.login",
        actor="alice",
        source="api",
        outcome="failure",
        payload={"username": "alice", "ip_address": "203.0.113.10"},
        created_at=base + timedelta(seconds=4),
    )
    finding = detect(event)

    assert finding is not None
    assert finding.rule_name == "BRUTE_FORCE"
    assert finding.evidence_ids == [f"event-{index}" for index in range(5)]


def test_brute_force_does_not_mix_accounts_or_expired_events(monkeypatch) -> None:
    import detection.rules.brute_force as rule

    local_state = DetectionState()
    monkeypatch.setattr(rule, "state", local_state)
    base = datetime(2026, 1, 1, 12, 0, 0)

    for index in range(5):
        event = SecurityEvent(
            id=f"event-{index}",
            event_type="authentication.login",
            actor="alice" if index < 4 else "bob",
            source="api",
            outcome="failure",
            payload={
                "username": "alice" if index < 4 else "bob",
                "ip_address": "203.0.113.10",
            },
            created_at=base + timedelta(seconds=index),
        )
        assert detect(event) is None

    expired = SecurityEvent(
        id="expired",
        event_type="authentication.login",
        actor="alice",
        source="api",
        outcome="failure",
        payload={"username": "alice", "ip_address": "203.0.113.10"},
        created_at=base + timedelta(seconds=61),
    )
    assert detect(expired) is None
