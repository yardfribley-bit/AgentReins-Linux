from __future__ import annotations

from policy.ir import Enforcement, Policy


_ENFORCEMENT = {
    Enforcement.OBSERVE: "none",
    Enforcement.RECORD: "none",
    Enforcement.REQUIRE_APPROVAL: "user_inspection",
    Enforcement.DENY: "stop",
}


def to_agentspec(policy: Policy) -> str:
    """Render the AgentReins IR as an auditable AgentSpec-compatible rule set."""
    blocks = []
    for index, rule in enumerate(policy.rules, start=1):
        event = rule.action.value.replace(".", "_")
        blocks.append(
            f"rule @{policy.policy_id.replace('-', '_')}_{index}\n"
            f"trigger {event}\n"
            "check true\n"
            f"enforce {_ENFORCEMENT[rule.enforcement]}\n"
            "end"
        )
    return "\n\n".join(blocks)
