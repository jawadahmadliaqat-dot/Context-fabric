"""Context State Store.

Maintains dynamic environment facts as JSON on disk.
Facts:
  user_present: bool
  user_role: "OWNER" | "GUEST" | "UNKNOWN"
  ambient_state: "HOME" | "SLEEP" | "AWAY"
  time_of_day: "MORNING" | "DAY" | "EVENING" | "NIGHT"
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

VALID_ROLES = ("OWNER", "GUEST", "UNKNOWN")
VALID_AMBIENT_STATES = ("HOME", "SLEEP", "AWAY")
VALID_TIMES_OF_DAY = ("MORNING", "DAY", "EVENING", "NIGHT")

DEFAULT_CONTEXT = {
    "user_present": False,
    "user_role": "UNKNOWN",
    "ambient_state": "HOME",
    "time_of_day": "DAY",
}


def _validate(facts: dict) -> dict:
    out = dict(facts)
    if "user_present" in out and not isinstance(out["user_present"], bool):
        raise ValueError("user_present must be a bool")
    if "user_role" in out and out["user_role"] not in VALID_ROLES:
        raise ValueError(f"user_role must be one of {VALID_ROLES}, got {out['user_role']!r}")
    if "ambient_state" in out and out["ambient_state"] not in VALID_AMBIENT_STATES:
        raise ValueError(f"ambient_state must be one of {VALID_AMBIENT_STATES}, got {out['ambient_state']!r}")
    if "time_of_day" in out and out["time_of_day"] not in VALID_TIMES_OF_DAY:
        raise ValueError(f"time_of_day must be one of {VALID_TIMES_OF_DAY}, got {out['time_of_day']!r}")
    unknown = set(out) - set(DEFAULT_CONTEXT)
    if unknown:
        raise ValueError(f"unknown context facts: {sorted(unknown)}")
    return out


@dataclass
class Context:
    user_present: bool = False
    user_role: str = "UNKNOWN"
    ambient_state: str = "HOME"
    time_of_day: str = "DAY"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Context":
        merged = {**DEFAULT_CONTEXT, **_validate(dict(data))}
        return cls(**merged)


class ContextStore:
    """JSON-file backed store. Simple API: get() / update(**facts) / set_context()."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.exists():
            self._save(Context())

    def _save(self, ctx: Context) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(ctx.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def get(self) -> Context:
        if not self.path.exists():
            return Context()
        return Context.from_dict(json.loads(self.path.read_text(encoding="utf-8")))

    def update(self, **facts) -> Context:
        current = self.get().to_dict()
        current.update(facts)
        ctx = Context.from_dict(current)  # validates
        self._save(ctx)
        return ctx

    def set_context(self, ctx: Context) -> Context:
        ctx = Context.from_dict(ctx.to_dict())
        self._save(ctx)
        return ctx
