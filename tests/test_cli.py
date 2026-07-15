import contextlib
import io
import json
import unittest
from pathlib import Path

from mcpscan.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def run_cli(argv: list[str]) -> tuple[int, str]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = main(argv)
    return code, stdout.getvalue()


class CliTests(unittest.TestCase):
    def test_clean_manifest_exits_zero(self):
        code, output = run_cli(["scan", str(EXAMPLES / "clean_manifest.json")])
        self.assertEqual(code, 0)
        self.assertIn("list_notes", output)

    def test_poisoned_manifest_exits_nonzero(self):
        code, output = run_cli(["scan", str(EXAMPLES / "poisoned_manifest.json")])
        self.assertEqual(code, 1)
        self.assertIn("tool_poisoning", output)

    def test_no_fail_forces_exit_zero(self):
        code, _ = run_cli(["scan", str(EXAMPLES / "poisoned_manifest.json"), "--no-fail"])
        self.assertEqual(code, 0)

    def test_json_format_emits_output_contract(self):
        code, output = run_cli(
            ["scan", str(EXAMPLES / "poisoned_manifest.json"), "--format", "json", "--no-fail"]
        )
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertIn("risk_score", payload)
        self.assertIn("inventory", payload)


if __name__ == "__main__":
    unittest.main()
