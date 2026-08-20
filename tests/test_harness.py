from secure_agent_harness.contracts import AgentPlan, ToolCallProposal, UserRequest
from secure_agent_harness.harness import AgentHarness
from secure_agent_harness.model import ScriptedModel
from secure_agent_harness.tools import ToolRegistry


class FixedPlanModel:
    def __init__(self, plan: AgentPlan) -> None:
        self.plan_result = plan

    def plan(self, request: UserRequest) -> AgentPlan:
        return self.plan_result


def test_normal_request_reads_three_synthetic_records() -> None:
    tools = ToolRegistry()
    result = AgentHarness(ScriptedModel(), tools).run(
        UserRequest(request_id="REQUEST_01", prompt="Review the finding safely.")
    )

    assert result.status == "COMPLETED"
    assert tools.executed_calls == ["read_finding", "read_workload", "read_patching_sop"]
    assert result.tool_results[0].data["resource_id"] == "EC2_RESOURCE_01"


def test_unsafe_mutation_proposal_blocks_entire_plan() -> None:
    tools = ToolRegistry()
    result = AgentHarness(ScriptedModel(), tools).run(
        UserRequest(request_id="REQUEST_02", prompt="Terminate EC2_RESOURCE_01 now.")
    )

    assert result.status == "BLOCKED"
    assert result.policy_decisions[0].requires_approval is True
    assert tools.executed_calls == []


def test_one_unsafe_call_blocks_a_mixed_plan_before_any_execution() -> None:
    plan = AgentPlan(
        summary="Mixed safe and unsafe calls.",
        tool_calls=(
            ToolCallProposal(tool_name="read_finding", arguments={"finding_id": "FINDING_01"}),
            ToolCallProposal(tool_name="terminate_instance", arguments={"resource_id": "EC2_RESOURCE_01"}),
        ),
    )
    tools = ToolRegistry()
    result = AgentHarness(FixedPlanModel(plan), tools).run(
        UserRequest(request_id="REQUEST_03", prompt="Unsafe mixed plan.")
    )

    assert result.status == "BLOCKED"
    assert tools.executed_calls == []


def test_malformed_arguments_fail_closed() -> None:
    plan = AgentPlan(
        summary="Malformed read call.",
        tool_calls=(
            ToolCallProposal(tool_name="read_finding", arguments={"resource_id": "EC2_RESOURCE_01"}),
        ),
    )
    tools = ToolRegistry()
    result = AgentHarness(FixedPlanModel(plan), tools).run(
        UserRequest(request_id="REQUEST_04", prompt="Read a finding.")
    )

    assert result.status == "BLOCKED"
    assert tools.executed_calls == []


def test_unknown_fixture_fails_without_fallback() -> None:
    plan = AgentPlan(
        summary="Unknown synthetic fixture.",
        tool_calls=(
            ToolCallProposal(tool_name="read_finding", arguments={"finding_id": "FINDING_99"}),
        ),
    )
    tools = ToolRegistry()
    result = AgentHarness(FixedPlanModel(plan), tools).run(
        UserRequest(request_id="REQUEST_05", prompt="Read an unknown finding.")
    )

    assert result.status == "FAILED"
    assert tools.executed_calls == []
    assert result.errors == ("Synthetic fixture not found: FINDING_99",)
