from __future__ import annotations

from typing import Iterable

from .checks import CHECKS, Check
from .models import Finding, Manifest

SERVER_TOOL_NAME = "<server>"


def scan_manifest(
    manifest: Manifest,
    *,
    checks: Iterable[Check] = CHECKS,
    use_llm: bool = False,
) -> list[Finding]:
    """Run every check against a manifest and return the findings."""
    findings: list[Finding] = []

    for check in checks:
        if check.scope == "server":
            for detail in check.detect(manifest):
                findings.append(_finding(SERVER_TOOL_NAME, check, detail))
        else:
            for tool in manifest.tools:
                for detail in check.detect(tool):
                    findings.append(_finding(tool.name, check, detail))

    if use_llm:
        findings.extend(_llm_findings(manifest, findings))

    return findings


def _finding(tool_name: str, check: Check, detail: str) -> Finding:
    return Finding(
        tool=tool_name,
        check=check.name,
        severity=check.severity,
        detail=detail,
        remediation=check.remediation,
    )


def _llm_findings(manifest: Manifest, existing: list[Finding]) -> list[Finding]:
    from .llm import classify_description

    already_flagged = {f.tool for f in existing if f.check == "tool_poisoning"}
    findings: list[Finding] = []
    for tool in manifest.tools:
        if tool.name in already_flagged or not tool.description:
            continue
        if classify_description(tool.description):
            findings.append(
                Finding(
                    tool=tool.name,
                    check="tool_poisoning",
                    severity="HIGH",
                    detail="LLM classifier judged the description to contain injected agent instructions",
                    remediation="Rewrite the description to only describe what the tool does.",
                )
            )
    return findings
