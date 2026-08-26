"""Typed data crossing the model, policy, and tool boundaries."""

from datetime import datetime
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


class ReadOnlyTarget(Contract):
    """Runtime-only target binding; never returned as model-visible evidence."""

    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    instance_id: str = Field(min_length=1, max_length=128)


class ReadOnlyCheck(Contract):
    check_name: Literal[
        "INSPECTOR_FINDING",
        "FINDING_EC2_BINDING",
        "EC2_TARGET",
        "EC2_TAGS",
        "SSM_MANAGED_NODE",
        "SSM_PATCH_SUMMARY",
    ]
    outcome: Literal["PASS", "NO_GO"]
    reason_code: Literal[
        "FINDING_MATCHED",
        "FINDING_NOT_FOUND",
        "FINDING_AMBIGUOUS",
        "FINDING_RESOURCE_MISMATCH",
        "EC2_TARGET_MATCHED",
        "EC2_TARGET_NOT_FOUND",
        "EC2_TARGET_AMBIGUOUS",
        "EC2_TAGS_MATCHED",
        "EC2_TAGS_MISMATCH",
        "SSM_NODE_READY",
        "SSM_NODE_NOT_FOUND",
        "SSM_NODE_NOT_READY",
        "SSM_PATCH_SUMMARY_READY",
        "SSM_PATCH_SUMMARY_NOT_FOUND",
        "SSM_PATCH_SUMMARY_INVALID",
        "SSM_PATCH_STATE_READY",
        "READ_BACKEND_FAILED",
    ]


class AwsVulnerablePackage(Contract):
    """Small, sanitized projection of one Inspector package record."""

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}$")
    installed_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    fixed_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")


class AwsPatchSummary(Contract):
    """Safe counts from the SSM AWS:PatchSummary inventory type."""

    installed_count: int = Field(ge=0)
    missing_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    security_non_compliant_count: int = Field(ge=0)
    critical_non_compliant_count: int = Field(ge=0)
    installed_pending_reboot_count: int = Field(default=0, ge=0)
    operation: Literal["Scan", "Install", "Unknown"] = "Unknown"


class AwsReadOnlyEvidence(Contract):
    """Safe projection of exact-target Inspector, EC2, and SSM reads."""

    source: Literal["AWS_READ_ONLY"]
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    finding_count: int = Field(ge=1)
    finding_state: Literal["ACTIVE", "RESOLVED", "UNKNOWN"]
    finding_severity: Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    finding_ec2_bound: Literal[True]
    instance_state: Literal["RUNNING", "STOPPED", "PENDING", "TERMINATED", "UNKNOWN"]
    expected_tags_verified: Literal[True]
    ssm_managed: Literal[True]
    ssm_readiness: Literal["READY", "NOT_READY"]
    packages: tuple[AwsVulnerablePackage, ...] = ()
    patch_summary: AwsPatchSummary | None = None
    checks: tuple[ReadOnlyCheck, ...]
    executed_calls: tuple[
        Literal[
            "inspector.list_findings",
            "ec2.describe_instances",
            "ssm.describe_instance_information",
            "ssm.list_inventory_entries",
            "ssm.describe_instance_patch_states",
        ],
        ...,
    ]


class AwsReadOnlyResult(Contract):
    """Fail-closed result for the optional read-only AWS evidence lane."""

    status: Literal["READY", "BLOCKED"]
    reason_code: Literal[
        "READ_ONLY_EVIDENCE_READY",
        "FINDING_NOT_FOUND",
        "FINDING_AMBIGUOUS",
        "FINDING_RESOURCE_MISMATCH",
        "EC2_TARGET_NOT_FOUND",
        "EC2_TARGET_AMBIGUOUS",
        "EC2_TAGS_MISMATCH",
        "SSM_NODE_NOT_FOUND",
        "SSM_NODE_NOT_READY",
        "SSM_PATCH_SUMMARY_NOT_FOUND",
        "SSM_PATCH_SUMMARY_INVALID",
        "READ_BACKEND_FAILED",
    ]
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    evidence: AwsReadOnlyEvidence | None = None
    executed_calls: tuple[str, ...] = ()
    message: str = Field(min_length=1, max_length=180)


class SecCopCsvRequest(Contract):
    """Browser input for one exact-target SecCop comparison."""

    csv_text: str = Field(min_length=1, max_length=500_000)
    instance_id: str = Field(pattern=r"^i-[0-9a-f]{8,17}$")
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    package_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}$")
    region: Literal["ap-southeast-1", "ap-south-1"] = "ap-southeast-1"


class SecCopAdvisoryRequest(Contract):
    """Typed one-package advisory input for the simple live demo path."""

    target_alias: Literal["LAB_SERVER_01"] = "LAB_SERVER_01"
    advisory_id: str = Field(pattern=r"^ALAS[0-9]{1,2}-[0-9]{4}-[0-9]{4,}$")
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    package_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}$")
    installed_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    fixed_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    region: Literal["ap-southeast-1", "ap-south-1"] = "ap-southeast-1"


class SecCopAdvisoryComparison(Contract):
    """Sanitized result for the no-instance-ID advisory journey."""

    status: Literal["READY", "BLOCKED"]
    reason_code: Literal[
        "SECCOP_ADVISORY_READY",
        "ADVISORY_INPUT_INVALID",
        "EC2_TARGET_NOT_FOUND",
        "EC2_TARGET_AMBIGUOUS",
        "EC2_TARGET_NOT_READY",
        "EC2_TAGS_MISMATCH",
        "SSM_NODE_NOT_FOUND",
        "SSM_NODE_NOT_READY",
        "SSM_ADVISORY_NOT_FOUND",
        "SSM_COMMAND_TIMEOUT",
        "AWS_BACKEND_UNAVAILABLE",
    ]
    advisory_id: str = Field(pattern=r"^ALAS[0-9]{1,2}-[0-9]{4}-[0-9]{4,}$")
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    target_alias: Literal["LAB_SERVER_01"]
    package_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}$")
    installed_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    fixed_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    ssm_readiness: Literal["READY", "NOT_READY", "UNKNOWN"]
    message: str = Field(min_length=1, max_length=220)
    executed_calls: tuple[str, ...] = ()


class SecCopScanRequest(Contract):
    """The primary demo scan has a fixed, server-owned source set."""

    mode: Literal["DEMO"] = "DEMO"


class SecCopScanSourceStatus(Contract):
    """Safe progress state for one source in the manager-facing scan."""

    source_type: Literal["EC2_PACKAGE", "S3_ARTIFACT", "ECR_IMAGE"]
    label: str = Field(min_length=1, max_length=60)
    state: Literal["COMPLETE", "BLOCKED"]
    reason_code: Literal["SECCOP_SOURCE_READY", "SECCOP_SOURCE_BLOCKED"]


class SecCopFinding(Contract):
    """Alias-only finding card shared by the three POC source types."""

    finding_id: str = Field(pattern=r"^FINDING_[0-9]{2}$")
    source_type: Literal["EC2_PACKAGE", "S3_ARTIFACT", "ECR_IMAGE"]
    resource_alias: Literal["LAB_SERVER_01", "ARTIFACT_01", "IMAGE_01"]
    reference: str = Field(pattern=r"^(CVE-[0-9]{4}-[0-9]{4,}|[A-Z]+_RULE_[0-9]{2})$")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str = Field(min_length=1, max_length=100)
    problem_summary: str = Field(min_length=1, max_length=180)
    observed_state: str = Field(min_length=1, max_length=120)
    recommended_state: str = Field(min_length=1, max_length=180)
    remediation_mode: Literal["REAL_APPROVAL_REQUIRED", "DEMO_ONLY", "NONE"]
    reason_code: Literal[
        "SECCOP_EC2_FINDING_CONFIRMED",
        "SECCOP_S3_FIXTURE_FINDING",
        "SECCOP_ECR_FIXTURE_FINDING",
        "SECCOP_S3_FINDING_CONFIRMED",
        "SECCOP_ECR_FINDING_CONFIRMED",
    ]
    action_label: Literal["Review live fix", "View suggested fix", "Review and fix"]


class SecCopScanResult(Contract):
    """Sanitized result for one fixed-source POC scan."""

    scan_id: str = Field(pattern=r"^SECCOP_SCAN_[0-9]{2}$")
    status: Literal["READY", "PARTIAL", "NO_FINDINGS", "BLOCKED"]
    reason_code: Literal[
        "SECCOP_SCAN_READY",
        "SECCOP_SCAN_PARTIAL",
        "SECCOP_SCAN_NO_FINDINGS",
        "SECCOP_SCAN_BLOCKED",
    ]
    source_status: tuple[SecCopScanSourceStatus, ...]
    findings: tuple[SecCopFinding, ...]
    message: str = Field(min_length=1, max_length=220)


class SecCopComparison(Contract):
    """Sanitized CSV-to-live comparison returned to the browser."""

    status: Literal["READY", "BLOCKED"]
    reason_code: Literal[
        "SECCOP_COMPARISON_READY",
        "CSV_SCHEMA_INVALID",
        "CSV_TARGET_MISMATCH",
        "CSV_CVE_NOT_FOUND",
        "CSV_PACKAGE_NOT_FOUND",
        "AWS_READ_ONLY_BLOCKED",
        "AWS_BACKEND_UNAVAILABLE",
    ]
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    csv_row_count: int = Field(ge=0)
    csv_match_count: int = Field(ge=0)
    live_result: AwsReadOnlyResult | None = None
    message: str = Field(min_length=1, max_length=220)


class SecCopRemediationProposal(Contract):
    """Deterministic, approval-required proposal; never an AWS mutation."""

    proposal_id: str = Field(pattern=r"^SECCOP_PROPOSAL_[0-9]{2}$")
    status: Literal["READY", "BLOCKED"]
    reason_code: Literal[
        "SECCOP_REMEDIATION_PROPOSAL_READY",
        "SECCOP_ADVISORY_READY",
        "ADVISORY_INPUT_INVALID",
        "ADVISORY_VERSION_MISMATCH",
        "CSV_SCHEMA_INVALID",
        "CSV_TARGET_MISMATCH",
        "CSV_CVE_NOT_FOUND",
        "CSV_MATCH_AMBIGUOUS",
        "CSV_PACKAGE_NOT_FOUND",
        "NO_FIXED_VERSION",
        "EC2_TARGET_NOT_FOUND",
        "EC2_TARGET_AMBIGUOUS",
        "EC2_TARGET_NOT_READY",
        "EC2_TAGS_MISMATCH",
        "SSM_NODE_NOT_FOUND",
        "SSM_NODE_NOT_READY",
        "SSM_ADVISORY_NOT_FOUND",
        "SSM_COMMAND_TIMEOUT",
        "AWS_READ_ONLY_BLOCKED",
        "AWS_BACKEND_UNAVAILABLE",
    ]
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    severity: Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    package_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}$")
    installed_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    fixed_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    action: Literal["SSM_INSTALL_SECURITY_UPDATE", "NONE"]
    reboot_policy: Literal["NO_REBOOT", "EXPLICIT_APPROVAL_REQUIRED", "UNKNOWN"]
    requires_approval: bool
    mutation_performed: Literal[False]
    proposal_hash: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    approval_expires_at: datetime | None = None
    read_executed_calls: tuple[str, ...] = ()
    message: str = Field(min_length=1, max_length=220)


class SecCopApprovalResult(Contract):
    """Phase 2A approval record; the decision path performs no mutation."""

    status: Literal["APPROVED_NO_MUTATION", "REJECTED"]
    reason_code: Literal["HUMAN_APPROVED_NO_MUTATION", "HUMAN_REJECTED"]
    proposal_id: str = Field(pattern=r"^SECCOP_PROPOSAL_[0-9]{2}$")
    mutation_performed: Literal[False]
    proposal_hash: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    approval_expires_at: datetime | None = None
    executed_calls: tuple[str, ...] = ()
    message: str = Field(min_length=1, max_length=220)


class SecCopRemediationRequest(Contract):
    """Approval-bound request for the one-target Phase 2B operation."""

    proposal_id: str = Field(pattern=r"^SECCOP_PROPOSAL_[0-9]{2}$")
    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reboot_approved: Literal[False] = False


class SecCopRemediationResult(Contract):
    """Sanitized SSM execution and immediate follow-up result."""

    status: Literal["COMPLETED", "BLOCKED", "FAILED"]
    reason_code: Literal[
        "SSM_REMEDIATION_VERIFIED",
        "SSM_REMEDIATION_PENDING_RESCAN",
        "SSM_PACKAGE_VERSION_VERIFIED",
        "SSM_PACKAGE_SOURCE_NOT_READY",
        "SSM_COMMAND_FAILED",
        "SSM_COMMAND_TIMEOUT",
        "SSM_VERIFICATION_FAILED",
        "SSM_APPROVAL_REQUIRED",
        "SSM_APPROVAL_BINDING_MISMATCH",
        "SSM_APPROVAL_EXPIRED",
        "SSM_APPROVAL_ALREADY_USED",
        "PROPOSAL_NOT_FOUND",
        "AWS_BACKEND_UNAVAILABLE",
    ]
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    resource_alias: str = Field(pattern=r"^EC2_RESOURCE_[0-9]{2}$")
    package_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}$")
    fixed_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    before_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    after_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    change_state: Literal["NOT_STARTED", "ATTEMPTED", "COMPLETED"]
    verification_status: Literal["VERIFIED", "PENDING_RESCAN", "NOT_AVAILABLE"]
    reboot_approved: Literal[False]
    mutation_performed: bool
    executed_calls: tuple[str, ...] = ()
    evidence_path: str | None = None
    message: str = Field(min_length=1, max_length=240)
