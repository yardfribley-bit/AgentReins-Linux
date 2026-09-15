from __future__ import annotations

from policy.ir import Enforcement, Policy


class PolicyValidationError(ValueError):
    pass


def validate_policy(policy: Policy) -> Policy:
    if not policy.scope.executable.strip():
        raise PolicyValidationError("policy scope must name an executable")
    if not policy.rules:
        raise PolicyValidationError("natural-language policy produced no enforceable rules")
    if policy.mode == "observe" and any(
        rule.enforcement in {Enforcement.DENY, Enforcement.REQUIRE_APPROVAL}
        for rule in policy.rules
    ):
        raise PolicyValidationError(
            "blocking rules require explicit enforce mode; preview in observe mode first"
        )
    return policy
