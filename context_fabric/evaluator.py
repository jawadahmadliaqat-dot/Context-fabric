"""Declarative Policy Evaluator.

Policy file format: JSON, mirroring AWS Cedar's structure:
  {id, effect: Permit|Forbid, principal:{user_role}, action:[...],
   resource:[...], condition:{fact: value | [values]}, allowed_capabilities:[...]}

Semantics (Cedar-like, stated explicitly here):
  - Default is DENY.
  - Any matching Forbid overrides any Permit.
  - Otherwise ALLOW only if at least one Permit matches.
  - "*" matches any principal role / action / resource.
  - A condition value that is a list means "fact must be one of these";
    a scalar means equality. An empty condition always matches.
Rules live in policies.json, NOT hardcoded here. This module only
implements matching semantics.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Presentation / derivation only: turns a granted (action, resource) into a
# readable capability tag when a Permit policy grants "*".
_CAPABILITY_HINTS = {
    ("UnlockDoor", "SmartLock"): "smartlock.unlock",
    ("LockDoor", "SmartLock"): "smartlock.lock",
    ("ToggleLight", "LivingRoomLights"): "livingroom.lights.toggle",
    ("TurnOnLight", "LivingRoomLights"): "livingroom.lights.toggle",
    ("TurnOffLight", "LivingRoomLights"): "livingroom.lights.toggle",
    ("ModifyHeater", "Heater"): "heater.modify",
    ("ModifyHeater", "LivingRoomHeater"): "heater.modify",
    ("ModifyHeater", "BedroomHeater"): "heater.modify",
}


def derive_capability(action: str, resource: str) -> str:
    return _CAPABILITY_HINTS.get((action, resource), f"{resource.lower()}.{action.lower()}")


def load_policies(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


@dataclass
class EvaluationResult:
    decision: str  # "ALLOW" | "DENY"
    reason: str
    matched_permit_ids: list[str] = field(default_factory=list)
    matched_forbid_ids: list[str] = field(default_factory=list)
    allowed_capabilities: list[str] = field(default_factory=list)


def _matches(value, patterns) -> bool:
    return "*" in patterns or value in patterns


def _condition_matches(condition: dict, facts: dict) -> bool:
    for key, expected in (condition or {}).items():
        actual = facts.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


class PolicyEvaluator:
    def __init__(self, policy_doc: dict):
        self.policies = policy_doc.get("policies", [])

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEvaluator":
        return cls(load_policies(path))

    def evaluate(self, intent: dict, context: dict) -> EvaluationResult:
        """intent: {actor_role, action, resource}; context: store facts dict."""
        actor = intent.get("actor_role") or context.get("user_role")
        action = intent.get("action")
        resource = intent.get("resource")
        if not actor or not action or not resource:
            return EvaluationResult("DENY", "Intent must include actor_role (or context user_role), action and resource.")
        # Principal facts come from the actor; other facts from context.
        facts = {**context, "user_role": actor}

        permits, forbids, caps = [], [], []
        for pol in self.policies:
            principal = (pol.get("principal") or {}).get("user_role", "*")
            if principal != "*" and principal != actor:
                continue
            if not _matches(action, pol.get("action", [])):
                continue
            if not _matches(resource, pol.get("resource", [])):
                continue
            if not _condition_matches(pol.get("condition", {}), facts):
                continue
            if pol.get("effect") == "Forbid":
                forbids.append(pol["id"])
            elif pol.get("effect") == "Permit":
                permits.append(pol["id"])
                for cap in pol.get("allowed_capabilities", []):
                    caps.append(derive_capability(action, resource) if cap == "*" else cap)

        if forbids:
            return EvaluationResult(
                "DENY",
                f"Denied by forbidding policy/policies: {', '.join(forbids)}.",
                permits, forbids, [],
            )
        if permits:
            return EvaluationResult(
                "ALLOW",
                f"Allowed by policy/policies: {', '.join(permits)}.",
                permits, forbids, sorted(set(caps)),
            )
        return EvaluationResult(
            "DENY",
            f"No permitting policy matches role={actor} action={action} resource={resource} "
            f"in context {facts}; default is DENY.",
            permits, forbids, [],
        )
