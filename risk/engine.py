"""Deterministic risk scoring for detection findings."""

from app.config import settings

RULE_BASE_SCORES = {
    "BRUTE_FORCE": 60,
    "PASSWORD_SPRAY": 65,
    "PORT_SCAN": 60,
    "SUSPICIOUS_IAM_CHANGE": 75,
}


def score_finding(rule_name: str, evidence: dict) -> int:
    """Return a bounded 0-100 score, increasing with stronger evidence."""
    score = RULE_BASE_SCORES.get(rule_name, 25)
    threshold = evidence.get("threshold")
    observed = evidence.get("observed")
    if isinstance(threshold, int) and threshold > 0 and isinstance(observed, int):
        score += min(20, max(0, (observed - threshold) * 4))
    return min(100, max(0, score))


def severity_for_score(score: int) -> str:
    if score >= settings.RISK_CRITICAL_THRESHOLD:
        return "critical"
    if score >= settings.RISK_HIGH_THRESHOLD:
        return "high"
    if score >= settings.RISK_MEDIUM_THRESHOLD:
        return "medium"
    return "low"
