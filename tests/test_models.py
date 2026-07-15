import dataclasses
import unittest

from mcpscan.models import Finding, Manifest, Tool


class ModelTests(unittest.TestCase):
    def test_tool_to_dict_converts_permissions_to_list(self):
        tool = Tool(name="list_notes", description="List notes.", permissions=("notes:read",))
        payload = tool.to_dict()
        self.assertEqual(payload["name"], "list_notes")
        self.assertEqual(payload["permissions"], ["notes:read"])

    def test_manifest_to_dict_includes_tools(self):
        manifest = Manifest(name="notes-server", tools=(Tool(name="list_notes"),))
        payload = manifest.to_dict()
        self.assertEqual(payload["name"], "notes-server")
        self.assertEqual(payload["tools"][0]["name"], "list_notes")

    def test_finding_is_frozen(self):
        finding = Finding(
            tool="read_file",
            check="tool_poisoning",
            severity="HIGH",
            detail="imperative phrase",
            remediation="remove it",
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            finding.severity = "LOW"


if __name__ == "__main__":
    unittest.main()
