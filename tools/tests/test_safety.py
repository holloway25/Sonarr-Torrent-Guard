"""Fresh assessment checks."""

import copy
import unittest

from safety import SafetyError, check_fresh


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.original = {"instance": "HD", "hash": "a" * 40, "decision": "would_fail",
                         "public_source_confirmed": True, "ownership_fingerprint": "b" * 64,
                         "manifest_fingerprint": "c" * 64, "checked_at": 1000}
        self.ready = {"status": "verified", "automatic_retry": True, "interactive_retry": True}
        self.fresh = {"assessment": copy.deepcopy(self.original), "readiness": self.ready}
    def test_rechecks_reject_identity_manifest_source_decision_and_staleness(self):
        changes = [("ownership_fingerprint", "d" * 64), ("manifest_fingerprint", "d" * 64),
                   ("hash", "d" * 40), ("instance", "UHD"), ("decision", "keep"),
                   ("public_source_confirmed", False), ("checked_at", 980),
                   ("checked_at", 1001), ("checked_at", float("nan"))]
        for field, value in changes:
            fresh = copy.deepcopy(self.fresh)
            fresh["assessment"][field] = value
            with self.subTest(field=field), self.assertRaises(SafetyError):
                check_fresh(self.original, fresh, now=1000)

if __name__ == "__main__":
    unittest.main()
