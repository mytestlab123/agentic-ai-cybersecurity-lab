"""Untrusted plan producer boundary."""

from typing import Protocol

from .contracts import AgentPlan, ToolCallProposal, UserRequest


class Model(Protocol):
    def plan(self, request: UserRequest) -> AgentPlan: ...


class ScriptedModel:
    """Local deterministic stand-in for a future probabilistic LLM."""

    def plan(self, request: UserRequest) -> AgentPlan:
        prompt = request.prompt.lower()
        if any(word in prompt for word in ("terminate", "delete", "patch now")):
            return AgentPlan(
                summary="Propose a mutation for policy review.",
                tool_calls=(
                    ToolCallProposal(
                        tool_name="terminate_instance",
                        arguments={"resource_id": "EC2_RESOURCE_01"},
                    ),
                ),
            )

        return AgentPlan(
            summary="Read synthetic finding, workload, and patching guidance.",
            tool_calls=(
                ToolCallProposal(
                    tool_name="read_finding",
                    arguments={"finding_id": "FINDING_01"},
                ),
                ToolCallProposal(
                    tool_name="read_workload",
                    arguments={"resource_id": "EC2_RESOURCE_01"},
                ),
                ToolCallProposal(
                    tool_name="read_patching_sop",
                    arguments={"sop_id": "SOP_PATCHING_01"},
                ),
            ),
        )
