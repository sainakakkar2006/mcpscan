"""FastAPI service wrapper: POST /scan accepts a manifest, returns the JSON report.

Install with `pip install mcpscan[api]` and run:
    uvicorn mcpscan.api:app
"""

from __future__ import annotations

from .engine import scan_manifest
from .loader import parse_manifest
from .reporting import report_payload


def create_app():
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError as error:
        raise RuntimeError(
            "the API requires the 'fastapi' package: pip install mcpscan[api]"
        ) from error

    app = FastAPI(
        title="MCPScan",
        description="Security scanner for MCP servers and AI-agent tool configurations.",
        version="0.1.0",
    )

    @app.post("/scan")
    def scan(manifest: dict) -> dict:
        try:
            parsed = parse_manifest(manifest)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error))
        findings = scan_manifest(parsed)
        return report_payload(parsed, findings)

    return app


try:
    app = create_app()
except RuntimeError:  # fastapi not installed; CLI-only usage
    app = None
