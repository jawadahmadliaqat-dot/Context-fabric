"""Test suite for context-fabric. Run from repo root:
    python3 -m unittest discover -s tests -v
"""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from context_fabric.evaluator import PolicyEvaluator
from context_fabric.store import ContextStore, Context
from context_fabric.token import TokenGenerator, verify_token

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_KEY = b"test-key-only-for-unittests"
TTL = 60


def ctx(**over):
    base = {"user_present": True, "user_role": "GUEST", "ambient_state": "HOME", "time_of_day": "DAY"}
    base.update(over)
    return base


class ScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evaluator = PolicyEvaluator.from_file(REPO_ROOT / "policies.json")
        cls.gen = TokenGenerator(cls.evaluator, ttl_seconds=TTL, key=TEST_KEY)

    def test_1_intruder_unknown_at_night_unlock_denied(self):
        context = ctx(user_present=False, user_role="UNKNOWN", ambient_state="HOME", time_of_day="NIGHT")
        token = self.gen.generate({"actor_role": "UNKNOWN", "action": "UnlockDoor", "resource": "SmartLock"}, context)
        self.assertEqual(token["decision"], "DENY")
        self.assertNotIn("signature", token)
        self.assertEqual(token["allowed_capabilities"], [])
        self.assertTrue(token["reason"])

    def test_2_guest_day_toggles_livingroom_lights_allowed(self):
        context = ctx(user_present=True, user_role="GUEST", ambient_state="HOME", time_of_day="DAY")
        token = self.gen.generate({"actor_role": "GUEST", "action": "ToggleLight", "resource": "LivingRoomLights"}, context)
        self.assertEqual(token["decision"], "ALLOW")
        self.assertIn("livingroom.lights.toggle", token["allowed_capabilities"])
        self.assertIn("signature", token)
        ok, reason = verify_token(token, key=TEST_KEY)
        self.assertTrue(ok, reason)

    def test_3_guest_unlock_denied(self):
        context = ctx(user_present=True, user_role="GUEST", ambient_state="HOME", time_of_day="DAY")
        token = self.gen.generate({"actor_role": "GUEST", "action": "UnlockDoor", "resource": "SmartLock"}, context)
        self.assertEqual(token["decision"], "DENY")
        self.assertIn("guest_smartlock_forbid", token["matched_forbid_ids"])
        self.assertNotIn("signature", token)

    def test_4_owner_home_unlock_allowed(self):
        context = ctx(user_present=True, user_role="OWNER", ambient_state="HOME", time_of_day="DAY")
        token = self.gen.generate({"actor_role": "OWNER", "action": "UnlockDoor", "resource": "SmartLock"}, context)
        self.assertEqual(token["decision"], "ALLOW")
        self.assertIn("smartlock.unlock", token["allowed_capabilities"])
        ok, reason = verify_token(token, key=TEST_KEY)
        self.assertTrue(ok, reason)

    def test_5a_guest_heater_during_sleep_denied(self):
        context = ctx(user_present=True, user_role="GUEST", ambient_state="SLEEP", time_of_day="NIGHT")
        token = self.gen.generate({"actor_role": "GUEST", "action": "ModifyHeater", "resource": "Heater"}, context)
        self.assertEqual(token["decision"], "DENY")
        self.assertNotIn("signature", token)

    def test_5b_unlock_while_away_and_absent_denied_even_for_owner(self):
        context = ctx(user_present=False, user_role="OWNER", ambient_state="AWAY", time_of_day="DAY")
        token = self.gen.generate({"actor_role": "OWNER", "action": "UnlockDoor", "resource": "SmartLock"}, context)
        self.assertEqual(token["decision"], "DENY")
        self.assertIn("away_no_unlock_when_absent", token["matched_forbid_ids"])


class TokenVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evaluator = PolicyEvaluator.from_file(REPO_ROOT / "policies.json")
        cls.gen = TokenGenerator(cls.evaluator, ttl_seconds=TTL, key=TEST_KEY)
        cls.context = ctx(user_present=True, user_role="OWNER", ambient_state="HOME", time_of_day="DAY")
        cls.token = cls.gen.generate({"actor_role": "OWNER", "action": "UnlockDoor", "resource": "SmartLock"}, cls.context)

    def test_expired_token_fails_verification(self):
        self.assertEqual(self.token["decision"], "ALLOW")
        future = datetime.now(timezone.utc) + timedelta(seconds=TTL + 10)
        ok, reason = verify_token(self.token, key=TEST_KEY, now=future)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_tampered_signature_fails_verification(self):
        tampered = dict(self.token)
        tampered["allowed_capabilities"] = ["smartlock.unlock", "crypto_engine.admin"]
        ok, reason = verify_token(tampered, key=TEST_KEY)
        self.assertFalse(ok)
        self.assertIn("signature", reason)

        tampered2 = dict(self.token)
        tampered2["signature"] = "0" * 64
        ok2, _ = verify_token(tampered2, key=TEST_KEY)
        self.assertFalse(ok2)

    def test_ttl_is_short_and_fields_present(self):
        self.assertEqual(self.token["ttl_seconds"], TTL)
        for field in ("decision_id", "user_role", "issued_at", "expires_at", "signature", "allowed_capabilities"):
            self.assertIn(field, self.token)
        self.assertEqual(self.token["user_role"], "OWNER")


class ContextStoreTests(unittest.TestCase):
    def test_store_roundtrip_and_validation(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            store = ContextStore(Path(d) / "context.json")
            store.update(user_present=True, user_role="OWNER", ambient_state="AWAY", time_of_day="NIGHT")
            loaded = store.get()
            self.assertEqual(loaded, Context(True, "OWNER", "AWAY", "NIGHT"))
            with self.assertRaises(ValueError):
                store.update(user_role="SUPERUSER")


if __name__ == "__main__":
    unittest.main()
