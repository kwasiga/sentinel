"""Authentication telemetry adapter."""

from typing import Any

from telemetry.normalizer import normalize_authentication


def normalize(payload: dict[str, Any], *, source: str = "authentication") -> dict[str, Any]:
    return normalize_authentication(payload, source=source)
