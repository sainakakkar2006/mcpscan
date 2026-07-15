import json
import tempfile
import unittest
from pathlib import Path

from mcpscan.loader import load_manifest, parse_manifest


class LoaderTests(unittest.TestCase):
    def test_loads_manifest_from_json_file(self):
        raw = {
            "name": "notes-server",
            "version": "1.2.3",
            "tools": [
                {
                    "name": "list_notes",
                    "description": "List notes.",
                    "inputSchema": {"type": "object"},
                    "permissions": ["notes:read"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "manifest.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            manifest = load_manifest(path)

        self.assertEqual(manifest.name, "notes-server")
        self.assertEqual(len(manifest.tools), 1)
        self.assertEqual(manifest.tools[0].name, "list_notes")
        self.assertEqual(manifest.tools[0].permissions, ("notes:read",))

    def test_loads_manifest_from_inline_dict(self):
        manifest = load_manifest({"tools": [{"name": "ping", "description": "Ping."}]})
        self.assertEqual(manifest.tools[0].name, "ping")

    def test_parses_bare_tool_list(self):
        manifest = parse_manifest([{"name": "ping"}])
        self.assertEqual(len(manifest.tools), 1)

    def test_accepts_alternate_schema_and_scope_keys(self):
        manifest = parse_manifest(
            {"tools": [{"name": "t", "schema": {"type": "object"}, "scopes": ["a"]}]}
        )
        self.assertEqual(manifest.tools[0].schema, {"type": "object"})
        self.assertEqual(manifest.tools[0].permissions, ("a",))

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_manifest("/definitely/missing/manifest.json")

    def test_tool_without_name_raises(self):
        with self.assertRaises(ValueError):
            parse_manifest({"tools": [{"description": "no name"}]})


if __name__ == "__main__":
    unittest.main()
