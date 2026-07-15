import unittest

from mcpscan.models import Finding
from mcpscan.scoring import risk_band, risk_score


def _finding(severity: str) -> Finding:
    return Finding(tool="t", check="c", severity=severity, detail="d", remediation="r")


class ScoringTests(unittest.TestCase):
    def test_empty_findings_score_zero_low(self):
        self.assertEqual(risk_score([]), 0)
        self.assertEqual(risk_band([]), "low")

    def test_weights_are_deterministic(self):
        findings = [_finding("HIGH"), _finding("MEDIUM"), _finding("LOW")]
        self.assertEqual(risk_score(findings), 55)

    def test_score_caps_at_100(self):
        findings = [_finding("HIGH")] * 10
        self.assertEqual(risk_score(findings), 100)

    def test_band_follows_worst_severity(self):
        self.assertEqual(risk_band([_finding("MEDIUM")]), "medium")
        self.assertEqual(risk_band([_finding("MEDIUM"), _finding("HIGH")]), "high")
        self.assertEqual(risk_band([_finding("LOW")]), "low")


if __name__ == "__main__":
    unittest.main()
