"""Deterministic orchestration around an untrusted model plan."""

from .contracts import HarnessResult, UserRequest
from .model import Model
from .policy import authorize
from .tools import FixtureNotFoundError, ToolRegistry


class AgentHarness:
    def __init__(self, model: Model, tools: ToolRegistry | None = None) -> None:
        self.model = model
        self.tools = tools or ToolRegistry()

    def run(self, request: UserRequest) -> HarnessResult:
        plan = self.model.plan(request)
        decisions = tuple(authorize(call) for call in plan.tool_calls)

        if not plan.tool_calls or any(not decision.allowed for decision in decisions):
            return HarnessResult(
                request_id=request.request_id,
                status="BLOCKED",
                plan_summary=plan.summary,
                policy_decisions=decisions,
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
