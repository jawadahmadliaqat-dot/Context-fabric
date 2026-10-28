# INTERFACE.md — context-fabric (Layer 2)

Contract consumed by Layer 3 (`software-trust-layer`, Agent 2).
Canonical token filename: **`policy_decision.json`**
(Agent 2's brief also mentioned `policy_token.json`; accept both on read,
always write the canonical name.)

## 1. Context State Store

File: `context.json` (path configurable via `--context-file`).

```json
{
  "user_present": true,
  "user_role": "GUEST",
  "ambient_state": "HOME",
  "time_of_day": "DAY"
}
```

| Fact | Type / values |
|---|---|
| `user_present` | `bool` |
| `user_role` | `"OWNER" \| "GUEST" \| "UNKNOWN"` |
| `ambient_state` | `"HOME" \| "SLEEP" \| "AWAY"` |
| `time_of_day` | `"MORNING" \| "DAY" \| "EVENING" \| "NIGHT"` |

API: `ContextStore(path).get() -> Context`, `.update(**facts) -> Context`
(validates enums, raises `ValueError`), `.set_context(ctx)`.
CLI: `python3 -m context_fabric.cli context show|update --user-role ... --ambient-state ... --time-of-day ... --user-present true|false`

## 2. Policy file format — and its mapping to AWS Cedar

`policies.json` is **not Cedar** and is not parsed by Cedar. It mirrors
Cedar's structure so a later port is mechanical:

| This file | Cedar equivalent |
|---|---|
| `policies[]` | a Cedar policy set |
| `effect: "Permit" / "Forbid"` | `permit` / `forbid` |
| `principal: {"user_role": "GUEST"}` | `principal == User::"GUEST"` (role entity) |
| `action: ["ToggleLight", ...]` (`"*"` = any) | `action in [Action::"ToggleLight", ...]` |
| `resource: ["LivingRoomLights"]` (`"*"` = any) | `resource == Device::"LivingRoomLights"` |
| `condition: {"ambient_state": ["HOME"], "user_present": true}` | a `when { context.ambient_state in [...] && context.user_present }` clause; list = membership, scalar = equality, `{}` = always |
| `allowed_capabilities: ["livingroom.lights.toggle"]` | no direct Cedar field; these are the capability tags this layer grants on ALLOW (Cedar port would emit them from annotations / a downstream mapping) |
| default DENY, Forbid overrides Permit | Cedar's own semantics |

Evaluator semantics (explicit): default DENY → any matching Forbid = DENY →
otherwise ALLOW iff ≥1 Permit matches. Rules are data in `policies.json`;
changing behaviour means editing that file, not the evaluator code.

Intent input:

```json
{"actor_role": "GUEST", "action": "UnlockDoor", "resource": "SmartLock"}
```

## 3. Token format — `policy_decision.json`

Schema: `policy_decision.schema.json` (also copied to
`~/workspace/ambient-os/contracts/`).

ALLOW token (real sample, signature truncated for display):

```json
{
  "decision": "ALLOW",
  "decision_id": "bb66b64d-ee8e-48c2-beeb-e6c00c8447e0",
  "user_role": "GUEST",
  "action": "ToggleLight",
  "resource": "LivingRoomLights",
  "allowed_capabilities": ["livingroom.lights.toggle"],
  "ambient_state": "HOME",
  "matched_permit_ids": ["guest_livingroom_lights_permit"],
  "issued_at": "2026-10-28T17:05:36Z",
  "expires_at": "2026-10-28T17:06:36Z",
  "ttl_seconds": 60,
  "signature": "157a2cb9..."
}
```

Fields: `decision`, `allowed_capabilities` (allowed capability tags / peripherals
granted), `user_role`, `action`, `resource`, `issued_at` / `expires_at`
(UTC, `YYYY-MM-DDTHH:MM:SSZ`), `decision_id` (UUID4), `ttl_seconds`,
`signature`. TTL default **60s**, configurable via `--ttl` /
`TokenGenerator(ttl_seconds=...)`.

DENY result: returned/printed as
`{decision: "DENY", reason: "<human-readable>", allowed_capabilities: [], matched_forbid_ids: [...], ...}`
with **no `signature` field** and an already-past `expires_at`. The CLI
exits 2 and writes no token file. A DENY can never pass verification.

## 4. Signature scheme (dev scheme — limitation stated plainly)

- Algorithm: HMAC-SHA256, hex digest in `signature`.
- Signed bytes: canonical body = token dict without `signature`,
  `json.dumps(sort_keys=True, separators=(",", ":"))`, UTF-8.
- Key resolution order: 1) env `CONTEXT_FABRIC_SIGNING_KEY`,
  2) file at env `CONTEXT_FABRIC_KEY_FILE`,
  3) `dev_signing_key.txt` in the repo root (local **dev key only**, not committed,
  so today's sample is verifiable by the other layers).
- Limitation: HMAC is symmetric; key holders can forge tokens. Production
  requires asymmetric signing (e.g. Ed25519) + real KMS. Do not deploy
  the dev key scheme.

## 5. Verification (for Agent 2 / any consumer)

```python
from context_fabric.token import verify_token
ok, reason = verify_token(token_dict)          # (bool, str)
# or: python3 -m context_fabric.cli verify --token policy_decision.json
```

Checks, in order: `decision == "ALLOW"`, signature present, HMAC matches
(constant-time `hmac.compare_digest`), `expires_at` parses and is in the
future. Expired tokens and tampered tokens both fail — both cases are
covered by tests.

## 6. Handshake for the Core Pipeline

1. Agent 1 → contracts: `firmware_manifest.json` (+ schema).
2. Agent 3 (this repo) → contracts: `policy_decision.json` + `policy_decision.schema.json` ✅ done.
3. Agent 2 reads both, permits only MMIO in the manifest **and** a capability
   in a valid, unexpired `policy_decision.json`; anything else traps.

`ambience-os` (Layer 1) is **not** started here — Golden Rule: it comes
only after all three building blocks' interfaces are ready.

## Upstream contract — Firmware-Liberation-Engine (READ-ONLY)

This layer's contract was aligned by *reading* the Layer 4 repo
(github.com/jawadahmadliaqat-dot/Firmware-Liberation-Engine, commit 69f71b7).
That repo is never modified from here — reading is for the contract only.

What was read, and what it means for the handshake:

- **Chip profiles** (`stm32f1_profile.json`, `stm32f4_profile.json`):
  `{"chip": ..., "blocks": [{"start": "0x40000000", "end": "0x40000400", "name": "TIM2"}, ...]}`
  — the peripheral vocabulary and address ranges a `firmware_manifest.json`
  is built from (`verified_mmio_ranges` entries come from these blocks).
- **Extractor report** (`analysis_reports/*.json`): `binary_name`,
  `language` (e.g. `ARM:LE:32:v8`), `mmio_access_total`, `may_access_total`
  (may = could-touch, not certain) — a non-zero may set maps to proof
  status `UNRESOLVED_MAY`, never to a clean verified claim.
- **Classifier** (`classify_mmio.py`): an address inside a known profile
  block is *known*; outside every block it is **SUSPECT**. Downstream,
  SUSPECT/out-of-block and `forbidden_regions` are hard-deny — a
  `policy_decision.json` from this layer can never override bedrock.
- **Lean verdicts**: `PASS` / `FAIL` (checks: `generic`, `bmp`
  driver-confinement, `blink`). Layer 3 should only trust a manifest
  whose proof status corresponds to a Lean PASS (`VERIFIED_LEAN4`).

Division of labour: this layer grants *semantic* capabilities
(`livingroom.lights.toggle`, `smartlock.unlock`). It carries no MMIO
addresses. Layer 3 intersects the token's `allowed_capabilities`
(mapped to peripherals by the orchestrator) with the manifest's
`verified_mmio_ranges`, and traps anything outside them.
