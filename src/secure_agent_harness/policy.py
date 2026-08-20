"""Fail-closed authorization for model-proposed tool calls."""

from .contracts import PolicyDecision, ToolCallProposal

ALLOWED_ARGUMENTS = {
    "read_finding": frozenset({"finding_id"}),
    "read_workload": frozenset({"resource_id"}),
    "read_patching_sop": frozenset({"sop_id"}),
}

ACTION_WORDS = ("create", "delete", "patch", "reboot", "start", "stop", "terminate", "update", "write")


def authorize(call: ToolCallProposal) -> PolicyDecision:
    expected = ALLOWED_ARGUMENTS.get(call.tool_name)
    if expected is None:
        requires_approval = any(word in call.tool_name.lower() for word in ACTION_WORDS)
        return PolicyDecision(
            tool_name=call.tool_name,
            allowed=False,
            reason_code="TOOL_NOT_ALLOWLISTED",
            requires_approval=requires_approval,
            reason="Tool is not in the Issue 1 read-only allow-list.",
        )

    actual = frozenset(call.arguments)
    if actual != expected or any(not value.strip() for value in call.arguments.values()):
        return PolicyDecision(
            tool_name=call.tool_name,
            allowed=False,
            reason_code="ARGUMENT_CONTRACT_MISMATCH",
            reason="Arguments do not exactly match the tool contract.",
        )

    return PolicyDecision(
        tool_name=call.tool_name,
        allowed=True,
        reason_code="TOOL_ALLOWED",
        reason="Exact read-only tool and argument contract matched.",
    )
