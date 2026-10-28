"""context-fabric: Layer 2 of AmbientOS (Policy & Context Fabric).

Turns contextual inputs into validated, signed action permissions.
Python 3 standard library only.
"""
from .store import ContextStore, Context, VALID_ROLES, VALID_AMBIENT_STATES, VALID_TIMES_OF_DAY
from .evaluator import PolicyEvaluator, EvaluationResult, load_policies
from .token import TokenGenerator, verify_token, DEV_KEY_FALLBACK_NOTICE

__all__ = [
    "ContextStore", "Context",
    "VALID_ROLES", "VALID_AMBIENT_STATES", "VALID_TIMES_OF_DAY",
    "PolicyEvaluator", "EvaluationResult", "load_policies",
    "TokenGenerator", "verify_token", "DEV_KEY_FALLBACK_NOTICE",
]
__version__ = "0.1.0"
