from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Callable

from .models import Manifest, Tool


@dataclass(frozen=True)
class Check:
    """A declarative detector, mirroring Secret Scanner's Rule pattern.

    `detect` receives a Tool (scope "tool") or a Manifest (scope "server")
    and returns one detail string per issue found.
    """

    name: str
    severity: str
    scope: str
    remediation: str
    detect: Callable[..., list[str]]


# --- check 1: tool_poisoning -------------------------------------------------

_IMPERATIVE_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+(?:instructions|messages|prompts)"),
    re.compile(r"(?i)\bdisregard\b[^.]{0,60}\binstructions\b"),
    re.compile(r"(?i)\balways\s+(?:send|forward|include|call|invoke)\b"),
    re.compile(r"(?i)\bbefore\s+(?:responding|answering|replying)\b"),
    re.compile(r"(?i)\bdo\s+not\s+(?:tell|inform|mention|reveal|warn)\b[^.]{0,60}\buser\b"),
    re.compile(r"(?i)\bsystem\s+prompt\b"),
    re.compile(r"(?i)\byou\s+must\s+(?:now\s+)?(?:send|call|use|run|execute)\b"),
]

# zero-width chars, word joiner, BOM, bidi overrides, invisible bidi isolates
_HIDDEN_UNICODE = re.compile(
    "[​‌‍⁠﻿‪-‮⁦-⁩]"
)

_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")


def _decodes_as_base64(blob: str) -> bool:
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (ValueError, TypeError):
        return False
    return all(32 <= byte < 127 or byte in (9, 10, 13) for byte in decoded)


def detect_tool_poisoning(tool: Tool) -> list[str]:
    details: list[str] = []
    description = tool.description

    for pattern in _IMPERATIVE_PATTERNS:
        match = pattern.search(description)
        if match:
            details.append(f"description contains agent-directed instruction: {match.group(0)!r}")

    if _HIDDEN_UNICODE.search(description):
        details.append("description contains hidden/invisible Unicode characters")

    for blob in _BASE64_BLOB.findall(description):
        if _decodes_as_base64(blob):
            details.append(f"description contains a decodable base64 blob ({len(blob)} chars)")
            break

    return details


# --- check 2: broad_scope ----------------------------------------------------

_EXEC_KEYWORDS = re.compile(r"(?i)\b(exec|shell|eval|subprocess|spawn)\b")
_EXEC_PROP_NAMES = re.compile(r"(?i)\b(exec|shell|eval|subprocess|spawn|command|cmd|script)\b")
_ENV_KEYWORDS = re.compile(r"(?i)\b(env|environ|environment\s+variables?)\b")
_ROOT_PATH_VALUES = {"/", "~", "/*", "/**", "file:///"}


def detect_broad_scope(tool: Tool) -> list[str]:
    details: list[str] = []

    for permission in tool.permissions:
        if permission == "*" or permission.endswith(":*"):
            details.append(f"wildcard permission requested: {permission!r}")
        elif _EXEC_KEYWORDS.search(permission):
            details.append(f"execution permission requested: {permission!r}")
        elif _ENV_KEYWORDS.search(permission):
            details.append(f"environment-variable access requested: {permission!r}")

    schema_text = json.dumps(tool.schema)
    properties = tool.schema.get("properties", {})
    if isinstance(properties, dict):
        for prop_name, prop in properties.items():
            if _EXEC_PROP_NAMES.search(prop_name):
                details.append(f"schema exposes an execution parameter: {prop_name!r}")
            if isinstance(prop, dict) and prop.get("default") in _ROOT_PATH_VALUES:
                details.append(
                    f"schema parameter {prop_name!r} defaults to the filesystem root ({prop.get('default')!r})"
                )
    if _ENV_KEYWORDS.search(schema_text) and "environment" not in tool.name:
        details.append("schema references environment variables")

    return details


CHECKS: list[Check] = [
    Check(
        name="tool_poisoning",
        severity="HIGH",
        scope="tool",
        remediation="Remove agent-directed instructions, hidden Unicode, and encoded payloads from tool descriptions; descriptions should only describe what the tool does.",
        detect=detect_tool_poisoning,
    ),
    Check(
        name="broad_scope",
        severity="HIGH",
        scope="tool",
        remediation="Narrow permissions to the tool's stated purpose: no wildcard scopes, no shell/exec parameters, no default root-filesystem access.",
        detect=detect_broad_scope,
    ),
]
