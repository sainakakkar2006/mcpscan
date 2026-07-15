from __future__ import annotations

import argparse

from .loader import load_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpscan",
        description="Scan MCP server manifests for security issues.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="scan a manifest file or MCP endpoint URL")
    scan.add_argument("target", help="path to a manifest .json file or an http(s) endpoint URL")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    manifest = load_manifest(args.target)
    print(_inventory_text(manifest))
    return 0


def _inventory_text(manifest) -> str:
    lines = [f"Server: {manifest.name or '<unnamed>'}"]
    if manifest.version:
        lines.append(f"Version: {manifest.version}")
    if manifest.publisher:
        lines.append(f"Publisher: {manifest.publisher}")
    lines.append(f"Tools: {len(manifest.tools)}")
    lines.append("")
    for tool in manifest.tools:
        lines.append(f"- {tool.name}")
        if tool.description:
            lines.append(f"    {tool.description}")
        if tool.permissions:
            lines.append(f"    permissions: {', '.join(tool.permissions)}")
    return "\n".join(lines).rstrip()
