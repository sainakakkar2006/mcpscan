from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, Manifest
from .scoring import risk_band, risk_score


def report_payload(manifest: Manifest, findings: list[Finding]) -> dict:
    return {
        "risk_score": risk_score(findings),
        "band": risk_band(findings),
        "total_findings": len(findings),
        "inventory": [tool.to_dict() for tool in manifest.tools],
        "findings": [finding.to_dict() for finding in findings],
    }


def findings_to_json(manifest: Manifest, findings: list[Finding]) -> str:
    return json.dumps(report_payload(manifest, findings), indent=2, sort_keys=True)


def findings_to_text(manifest: Manifest, findings: list[Finding]) -> str:
    lines = [
        f"Server: {manifest.name or '<unnamed>'}",
        f"Risk score: {risk_score(findings)}/100 ({risk_band(findings)})",
        f"Tools: {len(manifest.tools)}",
        "",
    ]
    for tool in manifest.tools:
        lines.append(f"- {tool.name}")
        if tool.description:
            lines.append(f"    {tool.description}")
        if tool.permissions:
            lines.append(f"    permissions: {', '.join(tool.permissions)}")
    lines.append("")

    if not findings:
        lines.append("No findings.")
        return "\n".join(lines).rstrip()

    lines.append(f"{len(findings)} finding(s)")
    lines.append("")
    for finding in findings:
        lines.extend(
            [
                f"{finding.tool} [{finding.severity}] {finding.check}",
                f"  detail: {finding.detail}",
                f"  fix: {finding.remediation}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def findings_to_markdown(manifest: Manifest, findings: list[Finding]) -> str:
    lines = [
        f"# MCPScan report — {manifest.name or '<unnamed>'}",
        "",
        f"**Risk score:** {risk_score(findings)}/100 (**{risk_band(findings)}**)",
        f"**Findings:** {len(findings)}",
        "",
        "## Tool inventory",
        "",
        "| Tool | Description | Permissions |",
        "| --- | --- | --- |",
    ]
    for tool in manifest.tools:
        description = tool.description.replace("|", "\\|")
        permissions = ", ".join(tool.permissions) or "—"
        lines.append(f"| `{tool.name}` | {description} | {permissions} |")

    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines).rstrip()

    for finding in findings:
        lines.extend(
            [
                f"### `{finding.tool}` — {finding.check} ({finding.severity})",
                "",
                f"{finding.detail}",
                "",
                f"**Fix:** {finding.remediation}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def write_report(content: str, out_path: str | Path) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + "\n", encoding="utf-8")
