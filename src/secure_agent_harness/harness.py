"""Deterministic orchestration around an untrusted model plan."""

from pydantic import ValidationError

from .contracts import AgentPlan, AuditEvent, HarnessResult, UserRequest
from .model import Model
from .policy import authorize
from .tools import FixtureNotFoundError, ToolRegistry


class AgentHarness:
    def __init__(self, model: Model, tools: ToolRegistry | None = None) -> None:
        self.model = model
        self.tools = tools or ToolRegistry()

    def run(self, request: UserRequest) -> HarnessResult:
        raw_plan = self.model.plan(request)
        try:
            plan = AgentPlan.model_validate(raw_plan)
        except ValidationError:
            return HarnessResult(
                request_id=request.request_id,
                status="BLOCKED",
                plan_summary="Rejected malformed model output.",
                policy_decisions=(),
                audit_events=(
                    AuditEvent(
                        stage="MODEL_OUTPUT_VALIDATION",
                        outcome="BLOCKED",
                        reason_code="MODEL_OUTPUT_REJECTED",
                    ),
                ),
                errors=("Model output did not match the AgentPlan contract.",),
            )

        decisions = tuple(authorize(call) for call in plan.tool_calls)

        if not plan.tool_calls or any(not decision.allowed for decision in decisions):
            return HarnessResult(
                request_id=request.request_id,
                status="BLOCKED",
                plan_summary=plan.summary,
                policy_decisions=decisions,
                audit_events=tuple(
                    AuditEvent(
                        stage="POLICY_AUTHORIZATION",
                        outcome="BLOCKED",
                        reason_code=decision.reason_code,
                    )
                    for decision in decisions
                    if not decision.allowed and decision.reason_code != "TOOL_ALLOWED"
                ),
                errors=("Complete plan denied before tool execution.",),
            )

        results = []
        try:
            for call in plan.tool_calls:
                results.append(self.tools.execute(call))
        except (FixtureNotFoundError, KeyError, ValueError) as exc:
            return HarnessResult(
                request_id=request.request_id,
                status="FAILED",
                plan_summary=plan.summary,
                policy_decisions=decisions,
                tool_results=tuple(results),
                errors=(str(exc),),
            )

        return HarnessResult(
            request_id=request.request_id,
            status="COMPLETED",
            plan_summary=plan.summary,
            policy_decisions=decisions,
            tool_results=tuple(results),
        )
