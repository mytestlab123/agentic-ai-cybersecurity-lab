from secure_agent_harness.contracts import AgentPlan, ToolCallProposal, UserRequest
from secure_agent_harness.harness import AgentHarness
from secure_agent_harness.model import ScriptedModel
from secure_agent_harness.tools import ToolRegistry


class FixedPlanModel:
    def __init__(self, plan: AgentPlan) -> None:
        self.plan_result = plan

    def plan(self, request: UserRequest) -> AgentPlan:
        return self.plan_result


class MalformedPlanModel:
    def plan(self, request: UserRequest) -> object:
        return {"summary": "", "tool_calls": "not-a-list"}


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
    assert result.policy_decisions[0].reason_code == "TOOL_NOT_ALLOWLISTED"
    assert len(result.audit_events) == 1
    assert result.audit_events[0].stage == "POLICY_AUTHORIZATION"
    assert result.audit_events[0].outcome == "BLOCKED"
    assert result.audit_events[0].reason_code == "TOOL_NOT_ALLOWLISTED"
    assert "EC2_RESOURCE_01" not in result.audit_events[0].model_dump_json()
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


def test_malformed_model_output_fails_closed() -> None:
    tools = ToolRegistry()
    result = AgentHarness(MalformedPlanModel(), tools).run(
        UserRequest(request_id="REQUEST_06", prompt="Return malformed output.")
    )

    assert result.status == "BLOCKED"
    assert result.policy_decisions == ()
    assert result.tool_results == ()
    assert tools.executed_calls == []
    assert result.errors == ("Model output did not match the AgentPlan contract.",)
    assert len(result.audit_events) == 1
    assert result.audit_events[0].stage == "MODEL_OUTPUT_VALIDATION"
    assert result.audit_events[0].outcome == "BLOCKED"
    assert result.audit_events[0].reason_code == "MODEL_OUTPUT_REJECTED"
    assert "not-a-list" not in result.model_dump_json()
