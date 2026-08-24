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


class SanitizedInstance(Contract):
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    environment: Literal["SYNTHETIC_LAB"]
    state: Literal["RUNNING", "STOPPED", "PENDING", "TERMINATED", "UNKNOWN"]
    size_class: Literal["SMALL", "MEDIUM", "LARGE", "UNKNOWN"]


class PolicyDecision(Contract):
    tool_name: str
    allowed: bool
    reason_code: Literal[
        "TOOL_ALLOWED",
        "TOOL_NOT_ALLOWLISTED",
        "ARGUMENT_CONTRACT_MISMATCH",
    ]
    reason: str
    requires_approval: bool = False


class AuditEvent(Contract):
    stage: Literal["MODEL_OUTPUT_VALIDATION", "POLICY_AUTHORIZATION"]
    outcome: Literal["BLOCKED"]
    reason_code: Literal[
        "MODEL_OUTPUT_REJECTED",
        "TOOL_NOT_ALLOWLISTED",
        "ARGUMENT_CONTRACT_MISMATCH",
    ]


class ToolResult(Contract):
    tool_name: str
    data: dict[str, Any]


class HarnessResult(Contract):
    request_id: str
    status: Literal["COMPLETED", "BLOCKED", "FAILED"]
    plan_summary: str
    policy_decisions: tuple[PolicyDecision, ...]
    audit_events: tuple[AuditEvent, ...] = ()
    tool_results: tuple[ToolResult, ...] = ()
    errors: tuple[str, ...] = ()
