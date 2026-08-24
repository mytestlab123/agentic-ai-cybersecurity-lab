from pathlib import Path

import pytest
from pydantic import ValidationError

from secure_agent_harness.contracts import PocRequest
from secure_agent_harness.poc import PocEngine


def _request(cve_id: str = "CVE-2099-0001") -> PocRequest:
    return PocRequest(cve_id=cve_id, lab_env="SYNTHETIC_LAB")


def test_poc_emits_read_only_activity_and_waits_for_approval() -> None:
    session = PocEngine().start(_request())

    assert session.result.status == "AWAITING_APPROVAL"
    assert session.result.reason_code == "APPROVAL_REQUIRED"
    assert session.result.evidence.resource_alias == "EC2_RESOURCE_01"
    assert session.result.evidence.patch_state == "MISSING"
    assert session.result.proposal.mutation_performed is False
    assert session.result.executed_calls == (
        "mock_inspector_finding",
        "mock_instance_context",
        "mock_ssm_node_context",
        "mock_patch_compliance",
    )
    assert session.result.policy_reason_codes == ("TOOL_ALLOWED",) * 4
    assert [event.event_type for event in session.events].count("TOOL_CALL_START") == 4
    assert "RAW_INSTANCE_ID_01" not in session.result.model_dump_json()
    assert "PRIVATE_IP_01" not in session.result.model_dump_json()


def test_reject_records_a_decision_without_a_mutation() -> None:
    engine = PocEngine()
    session = engine.start(_request())

    rejected = engine.decide(session.result.run_id, approve=False)

    assert rejected.result.status == "REJECTED"
    assert rejected.result.reason_code == "HUMAN_REJECTED"
    assert rejected.result.executed_calls == session.result.executed_calls
    assert rejected.events[-1].event_type == "APPROVAL_DECISION"
    assert all(event.event_type != "MOCK_REMEDIATION" for event in rejected.events)


def test_approve_records_only_a_noop_mock_remediation() -> None:
    engine = PocEngine()
    session = engine.start(_request())

    approved = engine.decide(session.result.run_id, approve=True)

    assert approved.result.status == "MOCK_COMPLETED"
    assert approved.result.reason_code == "MOCK_REMEDIATION_NOOP"
    assert approved.result.executed_calls == session.result.executed_calls
    assert approved.events[-1].event_type == "MOCK_REMEDIATION"
    assert approved.events[-1].data["mutation_performed"] is False


def test_unknown_synthetic_cve_blocks_before_any_tool() -> None:
    session = PocEngine().start(_request("CVE-2099-0002"))

    assert session.result.status == "BLOCKED"
    assert session.result.reason_code == "CVE_NOT_FOUND"
    assert session.result.executed_calls == ()
    assert [event.event_type for event in session.events] == ["RUN_STARTED", "BLOCKED"]


def test_request_contract_rejects_non_cve_input() -> None:
    with pytest.raises(ValidationError):
        PocRequest(cve_id="not-a-cve", lab_env="SYNTHETIC_LAB")


def test_browser_surface_is_local_and_has_the_gate_controls() -> None:
    html = (Path(__file__).parents[1] / "web" / "poc_chat.html").read_text()

    assert "/api/run" in html
    assert "/api/decision" in html
    assert "Approve mock remediation" in html
    assert "Reject" in html
    assert "No AWS, AgentCore, or SSM call" in html
