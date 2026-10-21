"""Convert supported provider telemetry into Sentinel's canonical event shape."""

from datetime import datetime, timezone
from typing import Any


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def normalize_authentication(payload: dict[str, Any], *, source: str = "authentication") -> dict[str, Any]:
    """Normalize a generic authentication event with common provider aliases."""
    username = payload.get("username") or payload.get("user") or payload.get("principal")
    ip_address = payload.get("ip_address") or payload.get("source_ip") or payload.get("client_ip")
    outcome = str(payload.get("outcome") or payload.get("result") or "unknown").lower()
    if outcome in {"failed", "denied", "failure", "error"}:
        outcome = "failure"
    elif outcome in {"success", "succeeded", "allowed", "ok"}:
        outcome = "success"
    return {
        "event_type": "authentication.login",
        "actor": str(username or "unknown"),
        "source": source,
        "outcome": outcome,
        "payload": {**payload, "username": username or "unknown", "ip_address": ip_address or "unknown"},
        "created_at": _timestamp(payload.get("timestamp") or payload.get("time")),
    }


def normalize_cloudtrail(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize an AWS CloudTrail record into a Sentinel security event."""
    identity = payload.get("userIdentity") or {}
    principal = identity.get("arn") or identity.get("principalId") or "unknown"
    action = str(payload.get("eventName") or "")
    error = payload.get("errorCode")
    event_source = str(payload.get("eventSource") or "unknown")
    normalized_payload = {
        **payload,
        "action": action,
        "resource": payload.get("requestParameters") or payload.get("resources") or principal,
        "source_ip": payload.get("sourceIPAddress"),
        "aws_region": payload.get("awsRegion"),
    }
    return {
        "event_type": "cloudtrail.iam" if event_source == "iam.amazonaws.com" else "cloudtrail.api",
        "actor": str(principal),
        "source": "aws-cloudtrail",
        "outcome": "failure" if error else "success",
        "payload": normalized_payload,
        "created_at": _timestamp(payload.get("eventTime")),
    }
