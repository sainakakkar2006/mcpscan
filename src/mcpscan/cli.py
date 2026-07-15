from __future__ import annotations

import argparse

from .engine import scan_manifest
from .loader import load_manifest
from .reporting import findings_to_json, findings_to_markdown, findings_to_text, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpscan",
        description="Scan MCP server manifests for security issues.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="scan a manifest file or MCP endpoint URL")
    scan.add_argument("target", help="path to a manifest .json file or an http(s) endpoint URL")
    scan.add_argument("--format", choices=["text", "json", "md"], default="text")
    scan.add_argument("--out", help="optional report path")
    scan.add_argument(
        "--no-fail",
        action="store_true",
        help="always exit with code 0, even when HIGH findings exist",
    )
    scan.add_argument(
        "--llm",
        action="store_true",
        help="also run the LLM tool-poisoning classifier (requires the 'llm' extra)",
    )

    return parser


_FORMATTERS = {
    "text": findings_to_text,
    "json": findings_to_json,
    "md": findings_to_markdown,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    manifest = load_manifest(args.target)
    findings = scan_manifest(manifest, use_llm=args.llm)
    report = _FORMATTERS[args.format](manifest, findings)

    if args.out:
        write_report(report, args.out)
    print(report)

    has_high = any(finding.severity == "HIGH" for finding in findings)
    if has_high and not args.no_fail:
        return 1
    return 0
