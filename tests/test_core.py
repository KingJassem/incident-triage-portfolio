import unittest
from triage_portfolio.core import assess, process_batch, ValidationError

BASE = {"event_id": "INC-1001", "observed_at": "2026-11-11T09:00:00-06:00",
        "source": "identity_monitor", "category": "authentication",
        "signal": "failed_logins", "account_alias": "user_alpha"}


class TriageTests(unittest.TestCase):
    def test_failed_logins_trigger_human_review(self):
        result = assess(BASE)
        self.assertEqual(result["severity"], "medium")
        self.assertTrue(result["human_review_required"])
        self.assertEqual(result["observed_at"], "2026-11-11T15:00:00Z")

    def test_impossible_travel_escalation(self):
        result = assess({**BASE, "signal": "impossible_travel"})
        self.assertEqual(result["severity"], "high")
        self.assertIn("do not self-contain", result["recommended_action"])

    def test_routine_event_low(self):
        result = assess({**BASE, "category": "connectivity", "signal": "routine"})
        self.assertEqual(result["severity"], "low")
        self.assertFalse(result["human_review_required"])

    def test_reject_unexpected_pii(self):
        with self.assertRaisesRegex(ValidationError, "Unsupported fields"):
            assess({**BASE, "email_address": "someone@example.invalid"})

    def test_reject_category_signal_mismatch(self):
        with self.assertRaisesRegex(ValidationError, "Incompatible"):
            assess({**BASE, "category": "connectivity", "signal": "suspicious_link"})

    def test_dedupe_and_invalid_inputs(self):
        results = process_batch([BASE, BASE, {**BASE, "event_id": "INC-1002", "observed_at": "bad"}])
        self.assertEqual(results["counts"], {"accepted": 1, "duplicates": 1, "rejected": 1, "human_review": 1})

    def test_missing_timezone_rejected(self):
        with self.assertRaisesRegex(ValidationError, "timezone"):
            assess({**BASE, "observed_at": "2026-11-11T12:00:00"})

    def test_no_automated_containment(self):
        self.assertIn("no account, network", assess(BASE)["automation_limit"])


if __name__ == "__main__":
    unittest.main()
