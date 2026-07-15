from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from .models import Manifest, Tool

_SCHEMA_KEYS = ("inputSchema", "input_schema", "schema", "parameters")
_PERMISSION_KEYS = ("permissions", "scopes")


def load_manifest(target: str | Path | dict) -> Manifest:
    """Load an MCP manifest from a .json file, an http(s) URL, or an inline dict."""
    if isinstance(target, dict):
        return parse_manifest(target)

    text = str(target)
    if text.startswith(("http://", "https://")):
        raw = _fetch_url(text)
        manifest = parse_manifest(raw)
        if not manifest.transport:
            return Manifest(
                name=manifest.name,
                version=manifest.version,
                publisher=manifest.publisher,
                transport=text,
                auth=manifest.auth,
                tools=manifest.tools,
            )
        return manifest

    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(f"manifest does not exist: {path}")
    return parse_manifest(json.loads(path.read_text(encoding="utf-8")))


def parse_manifest(raw: dict | list) -> Manifest:
    if isinstance(raw, list):
        raw = {"tools": raw}
    if not isinstance(raw, dict):
        raise ValueError("manifest must be a JSON object or a list of tools")

    raw_tools = raw.get("tools", [])
    if not isinstance(raw_tools, list):
        raise ValueError("manifest 'tools' must be a list")

    return Manifest(
        name=str(raw.get("name", "")),
        version=str(raw.get("version", "")),
        publisher=str(raw.get("publisher", raw.get("author", ""))),
        transport=str(raw.get("transport", raw.get("url", raw.get("endpoint", "")))),
        auth=raw.get("auth") or {},
        tools=tuple(parse_tool(entry) for entry in raw_tools),
    )


def parse_tool(raw: dict) -> Tool:
    if not isinstance(raw, dict) or not raw.get("name"):
        raise ValueError(f"tool entry is missing a name: {raw!r}")

    schema: dict = {}
    for key in _SCHEMA_KEYS:
        if isinstance(raw.get(key), dict):
            schema = raw[key]
            break

    permissions: tuple[str, ...] = ()
    for key in _PERMISSION_KEYS:
        if isinstance(raw.get(key), list):
            permissions = tuple(str(item) for item in raw[key])
            break

    return Tool(
        name=str(raw["name"]),
        description=str(raw.get("description", "")),
        schema=schema,
        permissions=permissions,
    )


def _fetch_url(url: str, *, timeout: float = 10.0) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))
