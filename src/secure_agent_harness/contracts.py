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


class PocRequest(Contract):
    """User input for the local Inspector-to-SSM visual proof."""

    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    lab_env: Literal["SYNTHETIC_LAB"]


class PocInspectorFinding(Contract):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    lab_env: Literal["SYNTHETIC_LAB"]
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    finding_state: Literal["ACTIVE", "RESOLVED"]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str = Field(min_length=1, max_length=160)


class PocSsmNode(Contract):
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    lab_env: Literal["SYNTHETIC_LAB"]
    managed_state: Literal["MANAGED", "NOT_MANAGED"]
    readiness: Literal["READY", "NOT_READY"]


class PocPatchCompliance(Contract):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    patch_state: Literal["MISSING", "COMPLIANT"]
    reboot_required: bool


class PocEvidence(Contract):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    lab_env: Literal["SYNTHETIC_LAB"]
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    finding_state: Literal["ACTIVE", "RESOLVED"]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    instance_state: Literal["RUNNING", "STOPPED", "PENDING", "TERMINATED", "UNKNOWN"]
    managed_state: Literal["MANAGED", "NOT_MANAGED"]
    readiness: Literal["READY", "NOT_READY"]
    patch_state: Literal["MISSING", "COMPLIANT"]
    reboot_required: bool


class PocRemediationProposal(Contract):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    action: Literal["MOCK_PATCH"]
    requires_approval: Literal[True]
    mutation_performed: Literal[False]


class PocResult(Contract):
    run_id: str = Field(pattern=r"^POC_RUN_[0-9]{2}$")
    status: Literal["AWAITING_APPROVAL", "REJECTED", "MOCK_COMPLETED", "BLOCKED"]
    reason_code: Literal[
        "APPROVAL_REQUIRED",
        "HUMAN_REJECTED",
        "MOCK_REMEDIATION_NOOP",
        "CVE_NOT_FOUND",
        "REQUEST_REJECTED",
        "RUN_NOT_FOUND",
    ]
    message: str = Field(min_length=1, max_length=180)
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    lab_env: Literal["SYNTHETIC_LAB"]
    evidence: PocEvidence | None = None
    proposal: PocRemediationProposal | None = None
    executed_calls: tuple[str, ...] = ()
    policy_reason_codes: tuple[str, ...] = ()


class PocEvent(Contract):
    sequence: int = Field(ge=1)
    event_type: Literal[
        "RUN_STARTED",
        "TOOL_CALL_START",
        "TOOL_CALL_END",
        "RESULT",
        "APPROVAL_REQUIRED",
        "APPROVAL_DECISION",
        "MOCK_REMEDIATION",
        "BLOCKED",
    ]
    tool_name: str | None = None
    reason_code: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
