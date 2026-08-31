"""Deterministic local Inspector-to-SSM visual proof.

The module deliberately uses the existing complete-plan harness and a local
tool registry. It is a browser/demo adapter, not an AWS adapter: no SDK, model
API, AgentCore runtime, or mutation path exists here.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .contracts import (
    AgentPlan,
    PocEvidence,
    PocEvent,
    PocInspectorFinding,
    PocRequest,
    PocRemediationProposal,
    PocResult,
    PocSsmNode,
    PocVerificationResult,
    SanitizedInstance,
    ToolCallProposal,
    ToolResult,
    UserRequest,
)
from .fixtures import POC_INSPECTOR_FINDINGS
from .harness import AgentHarness
from .tools import ToolRegistry


_RESOURCE_ALIAS = "EC2_RESOURCE_01"


class PocPlanModel:
    """Scripted stand-in that proposes only the four synthetic read checks."""

    def __init__(self, cve_id: str, lab_env: str) -> None:
        self.cve_id = cve_id
        self.lab_env = lab_env

    def plan(self, request: UserRequest) -> AgentPlan:
        del request
        return AgentPlan(
            summary="Inspect a synthetic CVE and prepare a gated mock patch proposal.",
            tool_calls=(
                ToolCallProposal(
                    tool_name="mock_inspector_finding",
                    arguments={"cve_id": self.cve_id, "lab_env": self.lab_env},
                ),
                ToolCallProposal(
                    tool_name="mock_instance_context",
                    arguments={"resource_alias": _RESOURCE_ALIAS},
                ),
                ToolCallProposal(
                    tool_name="mock_ssm_node_context",
                    arguments={"resource_alias": _RESOURCE_ALIAS, "lab_env": self.lab_env},
                ),
                ToolCallProposal(
                    tool_name="mock_patch_compliance",
                    arguments={"cve_id": self.cve_id, "resource_alias": _RESOURCE_ALIAS},
                ),
            ),
        )


@dataclass
class _PocSession:
    result: PocResult
    events: list[PocEvent]


class _Events:
    def __init__(self) -> None:
        self.items: list[PocEvent] = []

    def add(
        self,
        event_type: str,
        *,
        tool_name: str | None = None,
        reason_code: str | None = None,
        data: dict[str, object] | None = None,
    ) -> None:
        self.items.append(
            PocEvent(
                sequence=len(self.items) + 1,
                event_type=event_type,
                tool_name=tool_name,
                reason_code=reason_code,
                data=data or {},
            )
        )


def _evidence(results: tuple[ToolResult, ...]) -> PocEvidence:
    by_name = {result.tool_name: result.data for result in results}
    finding = PocInspectorFinding.model_validate(by_name["mock_inspector_finding"])
    instance = SanitizedInstance.model_validate(by_name["mock_instance_context"])
    node = PocSsmNode.model_validate(by_name["mock_ssm_node_context"])
    patch = by_name["mock_patch_compliance"]
    return PocEvidence(
        cve_id=finding.cve_id,
        lab_env=finding.lab_env,
        resource_alias=finding.resource_alias,
        finding_state=finding.finding_state,
        severity=finding.severity,
        instance_state=instance.state,
        managed_state=node.managed_state,
        readiness=node.readiness,
        patch_state=str(patch["patch_state"]),
        reboot_required=bool(patch["reboot_required"]),
    )


class PocEngine:
    """Run and hold one local synthetic flow until a human decision."""

    def __init__(self) -> None:
        self._next_run = 1
        self._sessions: dict[str, _PocSession] = {}

    def _run_id(self) -> str:
        if self._next_run > 99:
            raise RuntimeError("Local POC run limit reached; restart the server.")
        run_id = f"POC_RUN_{self._next_run:02d}"
        self._next_run += 1
        return run_id

    def start(self, request: PocRequest) -> _PocSession:
        run_id = self._run_id()
        request_number = int(run_id[-2:])
        events = _Events()
        events.add(
            "RUN_STARTED",
            data={"cve_id": request.cve_id, "lab_env": request.lab_env},
        )

        if request.cve_id not in POC_INSPECTOR_FINDINGS:
            result = PocResult(
                run_id=run_id,
                status="BLOCKED",
                reason_code="CVE_NOT_FOUND",
                message="Synthetic CVE fixture unavailable; no tools executed.",
                cve_id=request.cve_id,
                lab_env=request.lab_env,
            )
            events.add(
                "BLOCKED",
                reason_code=result.reason_code,
                data={"executed_calls": []},
            )
            session = _PocSession(result=result, events=events.items)
            self._sessions[run_id] = session
            return session

        tools = ToolRegistry()
        harness = AgentHarness(PocPlanModel(request.cve_id, request.lab_env), tools)
        harness_result = harness.run(
            UserRequest(
                request_id=f"REQUEST_{request_number:02d}",
                prompt="Inspect the selected synthetic CVE.",
            )
        )

        if harness_result.status != "COMPLETED":
            reason_code = (
                harness_result.audit_events[0].reason_code
                if harness_result.audit_events
                else "REQUEST_REJECTED"
            )
            result = PocResult(
                run_id=run_id,
                status="BLOCKED",
                reason_code="REQUEST_REJECTED",
                message="Synthetic plan was blocked before tool execution.",
                cve_id=request.cve_id,
                lab_env=request.lab_env,
                executed_calls=tuple(tools.executed_calls),
                policy_reason_codes=tuple(decision.reason_code for decision in harness_result.policy_decisions),
            )
            events.add(
                "BLOCKED",
                reason_code=reason_code,
                data={"executed_calls": tools.executed_calls},
            )
            session = _PocSession(result=result, events=events.items)
            self._sessions[run_id] = session
            return session

        for tool_result in harness_result.tool_results:
            events.add("TOOL_CALL_START", tool_name=tool_result.tool_name)
            events.add(
                "TOOL_CALL_END",
                tool_name=tool_result.tool_name,
                data=tool_result.data,
            )

        evidence = _evidence(harness_result.tool_results)
        proposal = PocRemediationProposal(
            proposal_id=f"POC_PROPOSAL_{request_number:02d}",
            cve_id=evidence.cve_id,
            resource_alias=evidence.resource_alias,
            package_name="demo-package",
            observed_version="1.0.0",
            expected_fixed_version="1.1.0",
            action="MOCK_PATCH",
            approval_expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
            requires_approval=True,
            mutation_performed=False,
        )
        result = PocResult(
            run_id=run_id,
            status="AWAITING_APPROVAL",
            reason_code="APPROVAL_REQUIRED",
            message="Read-only synthetic evidence is ready for human review.",
            cve_id=evidence.cve_id,
            lab_env=evidence.lab_env,
            evidence=evidence,
            proposal=proposal,
            executed_calls=tuple(tools.executed_calls),
            policy_reason_codes=tuple(
                decision.reason_code for decision in harness_result.policy_decisions
            ),
        )
        events.add("RESULT", data=evidence.model_dump(mode="json"))
        events.add(
            "APPROVAL_REQUIRED",
            reason_code=result.reason_code,
            data=proposal.model_dump(mode="json"),
        )
        session = _PocSession(result=result, events=events.items)
        self._sessions[run_id] = session
        return session

    def verify(self, run_id: str) -> PocVerificationResult:
        """Prove approval binding and honest post-SSM verification locally."""

        session = self._sessions[run_id]
        proposal = session.result.proposal
        if proposal is None or session.result.status != "MOCK_COMPLETED":
            return PocVerificationResult(
                run_id=run_id,
                status="BLOCKED",
                reason_code="APPROVAL_BYPASS_DENIED",
                resource_alias=proposal.resource_alias if proposal else "EC2_RESOURCE_01",
                package_name=proposal.package_name if proposal else "demo-package",
                ssm_status="NOT_RUN",
                package_state="NOT_CHECKED",
                inspector_state="NOT_CHECKED",
                verification_status="NOT_AVAILABLE",
                mutation_performed=False,
                message="Verification was denied because the exact proposal has not been approved.",
            )
        return PocVerificationResult(
            run_id=run_id,
            status="COMPLETED",
            reason_code="INSPECTOR_RESCAN_PENDING",
            resource_alias=proposal.resource_alias,
            package_name=proposal.package_name,
            ssm_status="SUCCESS",
            package_state="FIXED",
            inspector_state="ACTIVE",
            verification_status="PENDING_RESCAN",
            mutation_performed=False,
            message="The mocked SSM step succeeded, but Inspector is still active; closure remains pending.",
        )

    def decide(self, run_id: str, approve: bool) -> _PocSession:
        session = self._sessions[run_id]
        if session.result.status != "AWAITING_APPROVAL":
            return session

        if approve:
            session.result = session.result.model_copy(
                update={
                    "status": "MOCK_COMPLETED",
                    "reason_code": "MOCK_REMEDIATION_NOOP",
                    "message": "Approved demo action recorded; no mutation was performed.",
                }
            )
            session.events.append(
                PocEvent(
                    sequence=len(session.events) + 1,
                    event_type="APPROVAL_DECISION",
                    reason_code="APPROVAL_ACCEPTED",
                    data={"decision": "APPROVE"},
                )
            )
            session.events.append(
                PocEvent(
                    sequence=len(session.events) + 1,
                    event_type="MOCK_REMEDIATION",
                    reason_code="MOCK_REMEDIATION_NOOP",
                    data={
                        "mutation_performed": False,
                        "executed_calls": list(session.result.executed_calls),
                    },
                )
            )
        else:
            session.result = session.result.model_copy(
                update={
                    "status": "REJECTED",
                    "reason_code": "HUMAN_REJECTED",
                    "message": "Human rejected the mock remediation; no mutation was performed.",
                }
            )
            session.events.append(
                PocEvent(
                    sequence=len(session.events) + 1,
                    event_type="APPROVAL_DECISION",
                    reason_code="HUMAN_REJECTED",
                    data={"decision": "REJECT"},
                )
            )
        return session
