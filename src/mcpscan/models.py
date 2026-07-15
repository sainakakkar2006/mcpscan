from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Tool:
    """One tool published by an MCP server's manifest."""

    name: str
    description: str = ""
    schema: dict = field(default_factory=dict)
    permissions: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "schema": self.schema,
            "permissions": list(self.permissions),
        }


@dataclass(frozen=True)
class Manifest:
    """An MCP server manifest: server metadata plus its published tools."""

    name: str = ""
    version: str = ""
    publisher: str = ""
    transport: str = ""
    auth: dict = field(default_factory=dict)
    tools: tuple[Tool, ...] = ()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "publisher": self.publisher,
            "transport": self.transport,
            "auth": self.auth,
            "tools": [tool.to_dict() for tool in self.tools],
        }


@dataclass(frozen=True)
class Finding:
    tool: str
    check: str
    severity: str
    detail: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "check": self.check,
            "severity": self.severity,
            "detail": self.detail,
            "remediation": self.remediation,
        }
