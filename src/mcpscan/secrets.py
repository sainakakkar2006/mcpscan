"""Secret detection patterns adapted from secret-scanner-cli.

https://github.com/sainakakkar2006/secret-scanner-cli — the Rule dataclass,
the regexes below, and mask_secret are reused directly from that project.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]
    secret_group: str = "secret"


SECRET_RULES = [
    Rule(
        name="AWS access key",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>AKIA[0-9A-Z]{16})"),
    ),
    Rule(
        name="GitHub token",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>gh[pousr]_[A-Za-z0-9_]{20,})"),
    ),
    Rule(
        name="Slack token",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>xox[baprs]-[A-Za-z0-9-]{20,})"),
    ),
    Rule(
        name="Private key block",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>-----BEGIN [A-Z ]*PRIVATE KEY-----)"),
    ),
    Rule(
        name="Environment assignment with secret-like name",
        severity="MEDIUM",
        pattern=re.compile(
            r"(?i)\b(?P<secret>(?:api[_-]?key|secret|password|token)\s*=\s*['\"]?[^'\"\s#]+)"
        ),
    ),
]


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * max(len(secret) - 8, 4)}{secret[-4:]}"


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return (rule name, masked value) for every secret-like match in text."""
    hits: list[tuple[str, str]] = []
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            hits.append((rule.name, mask_secret(match.group(rule.secret_group))))
    return hits
