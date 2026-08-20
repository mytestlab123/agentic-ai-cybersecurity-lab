"""Typed data crossing the model, policy, and tool boundaries."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class UserRequest(Contract):
    request_id: str = Field(pattern=r"^REQUEST_[0-9]{2}$")
    prompt: str = Field(min_length=1, max_length=500)


class ToolCallProposal(Contract):
    tool_name: str = Field(min_length=1, max_length=80)
    arguments: dict[str, str]


class AgentPlan(Contract):
    summary: str = Field(min_length=1, max_length=300)
    tool_calls: tuple[ToolCallProposal, ...]


class Finding(Contract):
    finding_id: str
    resource_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str


class Workload(Contract):
    resource_id: str
    environment: Literal["SYNTHETIC_LAB"]
    owner_role: str
    change_window: str


class PatchingSop(Contract):
    sop_id: str
    title: str
    steps: tuple[str, ...]


class PolicyDecision(Contract):
    tool_name: str
    allowed: bool
    reason: str
    requires_approval: bool = False


class ToolResult(Contract):
    tool_name: str
    data: dict[str, Any]


class HarnessResult(Contract):
    request_id: str
    status: Literal["COMPLETED", "BLOCKED", "FAILED"]
    plan_summary: str
    policy_decisions: tuple[PolicyDecision, ...]
    tool_results: tuple[ToolResult, ...] = ()
    errors: tuple[str, ...] = ()
