"""CLI for context-fabric.

Usage (from repo root):
  python3 -m context_fabric.cli context show
  python3 -m context_fabric.cli context update --user-present true --user-role GUEST --ambient-state HOME --time-of-day DAY
  python3 -m context_fabric.cli generate --actor-role GUEST --action ToggleLight --resource LivingRoomLights --out policy_decision.json
  python3 -m context_fabric.cli evaluate --actor-role GUEST --action UnlockDoor --resource SmartLock
  python3 -m context_fabric.cli verify --token policy_decision.json
Exit codes: 0 = ALLOW / verify OK / success, 2 = DENY / verify failed, 1 = usage/error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluator import PolicyEvaluator
from .store import ContextStore
from .token import TokenGenerator, verify_token

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICIES = REPO_ROOT / "policies.json"
DEFAULT_CONTEXT = REPO_ROOT / "context.json"


def _bool(s: str) -> bool:
    if s.lower() in ("true", "1", "yes"):
        return True
    if s.lower() in ("false", "0", "no"):
        return False
    raise argparse.ArgumentTypeError("expected true/false")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="context-fabric")
    p.add_argument("--policies", default=str(DEFAULT_POLICIES))
    p.add_argument("--context-file", default=str(DEFAULT_CONTEXT))
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("context")
    csub = c.add_subparsers(dest="context_cmd", required=True)
    csub.add_parser("show")
    u = csub.add_parser("update")
    u.add_argument("--user-present", type=_bool)
    u.add_argument("--user-role")
    u.add_argument("--ambient-state")
    u.add_argument("--time-of-day")

    for name in ("evaluate", "generate"):
        e = sub.add_parser(name)
        e.add_argument("--actor-role", required=True)
        e.add_argument("--action", required=True)
        e.add_argument("--resource", required=True)
        if name == "generate":
            e.add_argument("--ttl", type=int, default=60)
            e.add_argument("--out", default=None, help="Write ALLOW token here. DENY is never written as a token file.")

    v = sub.add_parser("verify")
    v.add_argument("--token", required=True)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    store = ContextStore(args.context_file)

    if args.cmd == "context":
        if args.context_cmd == "show":
            print(json.dumps(store.get().to_dict(), indent=2, sort_keys=True))
            return 0
        facts = {}
        for attr, key in (("user_present", "user_present"), ("user_role", "user_role"),
                          ("ambient_state", "ambient_state"), ("time_of_day", "time_of_day")):
            val = getattr(args, attr)
            if val is not None:
                facts[key] = val
        print(json.dumps(store.update(**facts).to_dict(), indent=2, sort_keys=True))
        return 0

    evaluator = PolicyEvaluator.from_file(args.policies)
    context = store.get().to_dict()

    if args.cmd == "evaluate":
        intent = {"actor_role": args.actor_role, "action": args.action, "resource": args.resource}
        result = evaluator.evaluate(intent, context)
        print(json.dumps({
            "decision": result.decision, "reason": result.reason,
            "allowed_capabilities": result.allowed_capabilities,
            "matched_permit_ids": result.matched_permit_ids,
            "matched_forbid_ids": result.matched_forbid_ids,
            "context": context, "intent": intent,
        }, indent=2, sort_keys=True))
        return 0 if result.decision == "ALLOW" else 2

    if args.cmd == "generate":
        intent = {"actor_role": args.actor_role, "action": args.action, "resource": args.resource}
        token = TokenGenerator(evaluator, ttl_seconds=args.ttl).generate(intent, context)
        print(json.dumps(token, indent=2, sort_keys=True))
        if token["decision"] != "ALLOW":
            print("DENY: no token file written.", file=sys.stderr)
            return 2
        if args.out:
            Path(args.out).write_text(json.dumps(token, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0

    if args.cmd == "verify":
        token = json.loads(Path(args.token).read_text(encoding="utf-8"))
        ok, reason = verify_token(token)
        print(json.dumps({"valid": ok, "reason": reason}, indent=2))
        return 0 if ok else 2

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
