from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Callable

from .models import Manifest, Tool
from .secrets import find_secrets


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


# --- check 3: exfiltration_path ----------------------------------------------

_SENSITIVE_SOURCE = re.compile(
    r"(?i)\b(env(?:ironment)?\s+variables?|\.env\b|secrets?|credentials?|api[_ -]?keys?|tokens?|private\s+keys?|ssh\s+keys?|password)"
)
_SINK_PROP_NAMES = re.compile(r"(?i)(url|uri|endpoint|webhook|callback|destination|remote)")
_SINK_VERBS = re.compile(r"(?i)\b(send|post|upload|forward|transmit|sync|exfiltrate)s?\b")


def detect_exfiltration_path(tool: Tool) -> list[str]:
    text = f"{tool.description} {json.dumps(tool.schema)} {' '.join(tool.permissions)}"

    sources: list[str] = []
    for rule_name, masked in find_secrets(text):
        sources.append(f"secret-like value ({rule_name}: {masked})")
    source_match = _SENSITIVE_SOURCE.search(text)
    if source_match:
        sources.append(f"sensitive data reference ({source_match.group(0)!r})")

    sinks: list[str] = []
    properties = tool.schema.get("properties", {})
    if isinstance(properties, dict):
        for prop_name in properties:
            if _SINK_PROP_NAMES.search(prop_name):
                sinks.append(f"network sink parameter {prop_name!r}")
    if _SINK_VERBS.search(tool.description) and re.search(
        r"(?i)\b(webhook|https?://|external|remote|server|endpoint)\b", tool.description
    ):
        sinks.append("description pairs a send verb with an external destination")

    if sources and sinks:
        return [f"{sources[0]} can flow to {sinks[0]}"]
    return []


# --- check 4: missing_auth (server scope) -------------------------------------


def detect_missing_auth(manifest: Manifest) -> list[str]:
    details: list[str] = []
    auth_type = str(manifest.auth.get("type", "")).lower() if manifest.auth else ""
    if not auth_type or auth_type == "none":
        details.append("server declares no authentication or scoped consent")
    if manifest.transport.startswith("http://"):
        details.append(f"unencrypted transport: {manifest.transport!r}")
    return details


# --- check 5: supply_chain (server scope) --------------------------------------

_UNPINNED_VERSIONS = {"", "latest", "*"}

POPULAR_SERVERS = [
    "filesystem",
    "github",
    "gitlab",
    "slack",
    "postgres",
    "sqlite",
    "puppeteer",
    "playwright",
    "fetch",
    "memory",
    "sentry",
    "stripe",
    "notion",
    "linear",
]


def _edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b))
            )
        previous = current
    return previous[-1]


def detect_supply_chain(manifest: Manifest) -> list[str]:
    details: list[str] = []

    version = manifest.version.strip()
    if version.lower() in _UNPINNED_VERSIONS or version.startswith(("^", "~", ">", "<")):
        details.append(f"version is not pinned: {version or '<missing>'!r}")

    if not manifest.publisher.strip():
        details.append("publisher is missing or unknown")

    name = manifest.name.strip().lower()
    if name and name not in POPULAR_SERVERS:
        for popular in POPULAR_SERVERS:
            if _edit_distance(name, popular) == 1:
                details.append(f"server name {manifest.name!r} typosquats popular server {popular!r}")
                break

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
    Check(
        name="exfiltration_path",
        severity="HIGH",
        scope="tool",
        remediation="Separate sensitive-data access from network egress: a tool that reads env/files/secrets must not also accept an arbitrary URL or webhook destination.",
        detect=detect_exfiltration_path,
    ),
    Check(
        name="missing_auth",
        severity="MEDIUM",
        scope="server",
        remediation="Require authentication with scoped consent (e.g. OAuth2 with least-privilege scopes) and serve the endpoint over HTTPS.",
        detect=detect_missing_auth,
    ),
    Check(
        name="supply_chain",
        severity="MEDIUM",
        scope="server",
        remediation="Pin an exact server version, declare a verifiable publisher, and avoid names that shadow popular servers.",
        detect=detect_supply_chain,
    ),
]
