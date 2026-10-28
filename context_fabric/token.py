"""Token Generator + Verifier.

Emits signed policy_decision.json tokens.

Signing scheme (DEV SCHEME — documented limitation):
  HMAC-SHA256 over the canonical token body. Canonical body = the token
  dict without the "signature" field, serialised with
  json.dumps(sort_keys=True, separators=(",", ":")) as UTF-8.
  Key resolution, in order:
    1. env var CONTEXT_FABRIC_SIGNING_KEY
    2. file named by env var CONTEXT_FABRIC_KEY_FILE
    3. file `dev_signing_key.txt` in the repo root (a local DEV key file,
       NOT committed; the committed sample token uses the documented
       SAMPLE_DEV_KEY so its verification mechanism is reproducible)
  HMAC is symmetric: anyone with the key can forge tokens. Production
  must replace this with asymmetric signing (e.g. Ed25519) and a real
  key-management system. Do not treat this dev scheme as production crypto.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEV_KEY_FALLBACK_NOTICE = "dev_signing_key.txt is a development key only; never use it in production."
SAMPLE_DEV_KEY = "context-fabric-dev-sample-key"  # documented dev-only key used for the committed sample token

REPO_ROOT = Path(__file__).resolve().parent.parent


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def resolve_key(explicit_key: str | None = None) -> bytes:
    if explicit_key:
        return explicit_key.encode("utf-8")
    env_key = os.environ.get("CONTEXT_FABRIC_SIGNING_KEY")
    if env_key:
        return env_key.encode("utf-8")
    key_file = os.environ.get("CONTEXT_FABRIC_KEY_FILE")
    if key_file:
        return Path(key_file).read_text(encoding="utf-8").strip().encode("utf-8")
    dev_file = REPO_ROOT / "dev_signing_key.txt"
    if dev_file.exists():
        return dev_file.read_text(encoding="utf-8").strip().encode("utf-8")
    raise RuntimeError(
        "No signing key: set CONTEXT_FABRIC_SIGNING_KEY, CONTEXT_FABRIC_KEY_FILE, "
        "or provide dev_signing_key.txt in the repo root."
    )


def canonical_body(token_without_signature: dict) -> bytes:
    return json.dumps(token_without_signature, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(token_without_signature: dict, key: bytes) -> str:
    return hmac.new(key, canonical_body(token_without_signature), hashlib.sha256).hexdigest()


class TokenGenerator:
    def __init__(self, evaluator, ttl_seconds: int = 60, key: bytes | None = None):
        self.evaluator = evaluator
        self.ttl_seconds = int(ttl_seconds)
        self._key = key

    @property
    def key(self) -> bytes:
        if self._key is None:
            self._key = resolve_key()
        return self._key

    def generate(self, intent: dict, context: dict) -> dict:
        """Returns an ALLOW token dict (with signature) or a DENY dict.

        A DENY dict has decision="DENY", a human-readable reason, empty
        allowed_capabilities, and NO signature field — it is never a usable token.
        """
        result = self.evaluator.evaluate(intent, context)
        now = _utcnow()
        base = {
            "decision_id": str(uuid.uuid4()),
            "user_role": intent.get("actor_role") or context.get("user_role"),
            "action": intent.get("action"),
            "resource": intent.get("resource"),
            "issued_at": _iso(now),
        }
        if result.decision != "ALLOW":
            return {
                **base,
                "decision": "DENY",
                "allowed_capabilities": [],
                "expires_at": _iso(now),  # already expired / not usable
                "reason": result.reason,
                "matched_forbid_ids": result.matched_forbid_ids,
                "matched_permit_ids": result.matched_permit_ids,
            }
        token = {
            **base,
            "decision": "ALLOW",
            "allowed_capabilities": result.allowed_capabilities,
            "expires_at": _iso(now + timedelta(seconds=self.ttl_seconds)),
            "ttl_seconds": self.ttl_seconds,
            "ambient_state": context.get("ambient_state"),
            "matched_permit_ids": result.matched_permit_ids,
        }
        token["signature"] = sign(token, self.key)
        return token


def verify_token(token: dict, key: bytes | None = None, now: datetime | None = None) -> tuple[bool, str]:
    """Verify signature + expiry + decision. Returns (ok, reason)."""
    if not isinstance(token, dict):
        return False, "token is not a JSON object"
    if token.get("decision") != "ALLOW":
        return False, f"decision is {token.get('decision')!r}, not ALLOW"
    signature = token.get("signature")
    if not signature:
        return False, "missing signature"
    try:
        signing_key = key if key is not None else resolve_key()
    except Exception as exc:  # no key available
        return False, f"no signing key available: {exc}"
    body = {k: v for k, v in token.items() if k != "signature"}
    expected = sign(body, signing_key)
    if not hmac.compare_digest(expected, str(signature)):
        return False, "signature mismatch (tampered or wrong key)"
    try:
        expires = _parse_iso(token["expires_at"])
    except Exception:
        return False, "missing or malformed expires_at"
    current = now or _utcnow()
    if current >= expires:
        return False, f"token expired at {token['expires_at']}"
    return True, "signature valid and token not expired"
