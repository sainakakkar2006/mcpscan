"""Run MCPScan against the labeled benchmark corpus and report precision/recall.

Usage:
    PYTHONPATH=src python3 scripts/benchmark.py

Each manifest in examples/benchmark/ is labeled in labels.json with the
(tool, check) pairs a scanner should report. Findings are deduplicated to
(tool, check) pairs before comparison.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from mcpscan.engine import scan_manifest
from mcpscan.loader import load_manifest

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "examples" / "benchmark"


def main() -> int:
    labels = json.loads((BENCHMARK_DIR / "labels.json").read_text(encoding="utf-8"))

    per_check: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    totals = {"tp": 0, "fp": 0, "fn": 0}

    for manifest_name, expected_pairs in sorted(labels.items()):
        manifest = load_manifest(BENCHMARK_DIR / manifest_name)
        findings = scan_manifest(manifest)

        expected = {(tool, check) for tool, check in expected_pairs}
        actual = {(finding.tool, finding.check) for finding in findings}

        for tool, check in actual & expected:
            per_check[check]["tp"] += 1
        for tool, check in actual - expected:
            per_check[check]["fp"] += 1
            print(f"  FP {manifest_name}: {tool}/{check}")
        for tool, check in expected - actual:
            per_check[check]["fn"] += 1
            print(f"  FN {manifest_name}: {tool}/{check}")

    print(f"{'check':<20} {'tp':>3} {'fp':>3} {'fn':>3} {'precision':>10} {'recall':>8}")
    for check, counts in sorted(per_check.items()):
        for key in totals:
            totals[key] += counts[key]
        print(
            f"{check:<20} {counts['tp']:>3} {counts['fp']:>3} {counts['fn']:>3} "
            f"{_ratio(counts['tp'], counts['tp'] + counts['fp']):>10} "
            f"{_ratio(counts['tp'], counts['tp'] + counts['fn']):>8}"
        )

    print(
        f"{'overall':<20} {totals['tp']:>3} {totals['fp']:>3} {totals['fn']:>3} "
        f"{_ratio(totals['tp'], totals['tp'] + totals['fp']):>10} "
        f"{_ratio(totals['tp'], totals['tp'] + totals['fn']):>8}"
    )

    return 1 if totals["fp"] or totals["fn"] else 0


def _ratio(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "n/a"
    return f"{numerator / denominator:.2f}"


if __name__ == "__main__":
    raise SystemExit(main())
