"""AWS CloudTrail telemetry adapter."""

from typing import Any

from telemetry.normalizer import normalize_cloudtrail


def normalize(record: dict[str, Any]) -> dict[str, Any]:
    return normalize_cloudtrail(record)
