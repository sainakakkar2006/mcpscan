import json
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed (pip install mcpscan[api])")
class ApiTests(unittest.TestCase):
    def setUp(self):
        from mcpscan.api import create_app

        self.client = TestClient(create_app())

    def test_scan_poisoned_manifest_returns_report(self):
        manifest = json.loads((EXAMPLES / "poisoned_manifest.json").read_text(encoding="utf-8"))
        response = self.client.post("/scan", json=manifest)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["band"], "high")
        self.assertGreater(payload["total_findings"], 0)

    def test_invalid_manifest_returns_422(self):
        response = self.client.post("/scan", json={"tools": [{"description": "no name"}]})
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
