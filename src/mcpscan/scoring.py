from __future__ import annotations

from .models import Finding

SEVERITY_WEIGHTS = {"HIGH": 35, "MEDIUM": 15, "LOW": 5}

MAX_SCORE = 100


def risk_score(findings: list[Finding]) -> int:
    """Deterministic 0-100 score: severity weights summed, capped at 100."""
    total = sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)
    return min(MAX_SCORE, total)


def risk_band(findings: list[Finding]) -> str:
    severities = {finding.severity for finding in findings}
    if "HIGH" in severities:
        return "high"
    if "MEDIUM" in severities:
        return "medium"
    return "low"
