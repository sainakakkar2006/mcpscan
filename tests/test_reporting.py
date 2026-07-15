import json
import tempfile
import unittest
from pathlib import Path

from mcpscan.models import Finding, Manifest, Tool
from mcpscan.reporting import (
    findings_to_json,
    findings_to_markdown,
    findings_to_text,
    write_report,
)

MANIFEST = Manifest(
    name="notes-server",
    tools=(Tool(name="list_notes", description="List notes.", permissions=("notes:read",)),),
)

FINDING = Finding(
    tool="list_notes",
    check="tool_poisoning",
    severity="HIGH",
    detail="description contains agent-directed instruction",
    remediation="Remove it.",
)


class ReportingTests(unittest.TestCase):
    def test_json_report_matches_output_contract(self):
        payload = json.loads(findings_to_json(MANIFEST, [FINDING]))
        self.assertEqual(
            set(payload),
            {"risk_score", "band", "total_findings", "inventory", "findings"},
        )
        self.assertEqual(payload["band"], "high")
        self.assertEqual(payload["total_findings"], 1)
        self.assertEqual(payload["inventory"][0]["name"], "list_notes")

    def test_text_report_lists_inventory_and_findings(self):
        report = findings_to_text(MANIFEST, [FINDING])
        self.assertIn("Risk score:", report)
        self.assertIn("list_notes", report)
        self.assertIn("tool_poisoning", report)

    def test_text_report_with_no_findings(self):
        self.assertIn("No findings.", findings_to_text(MANIFEST, []))

    def test_markdown_report_has_inventory_table(self):
        report = findings_to_markdown(MANIFEST, [FINDING])
        self.assertIn("| Tool | Description | Permissions |", report)
        self.assertIn("### `list_notes` — tool_poisoning (HIGH)", report)

    def test_write_report_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as temp_name:
            out = Path(temp_name) / "nested" / "report.md"
            write_report("hello", out)
            self.assertEqual(out.read_text(encoding="utf-8"), "hello\n")


if __name__ == "__main__":
    unittest.main()
