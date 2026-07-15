import unittest

from mcpscan.secrets import find_secrets, mask_secret


class SecretsTests(unittest.TestCase):
    def test_finds_and_masks_aws_key(self):
        hits = find_secrets("example key AKIA1234567890ABCDEF in text")
        self.assertEqual(len(hits), 1)
        rule_name, masked = hits[0]
        self.assertEqual(rule_name, "AWS access key")
        self.assertNotIn("1234567890", masked)

    def test_clean_text_has_no_hits(self):
        self.assertEqual(find_secrets("List the titles of saved notes."), [])

    def test_mask_secret_matches_secret_scanner_behavior(self):
        self.assertEqual(mask_secret("abc"), "***")
        self.assertEqual(mask_secret("AKIA1234567890ABCDEF"), "AKIA************CDEF")


if __name__ == "__main__":
    unittest.main()
