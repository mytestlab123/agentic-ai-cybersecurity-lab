from pathlib import Path
import gzip
import json
import os
import subprocess
import sys
from threading import Thread
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from pydantic import ValidationError

from secure_agent_harness.contracts import (
    AwsReadOnlyEvidence,
    AwsReadOnlyResult,
    PocRequest,
    SecCopScanRequest,
    SecCopCsvRequest,
    SecCopRemediationResult,
)
from secure_agent_harness.poc import PocEngine
from secure_agent_harness import poc_server
from secure_agent_harness.poc_server import (
    _CodexPreflightError,
    _Handler,
    _codex_request,
    _collect_codex_turn,
    _HybridSession,
    _public_remediation_payload,
    _reject_s3_proposal,
    _run_codex_preflight,
)
from secure_agent_harness.seccop_scan import review_demo_cve
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import seccop_demo  # noqa: E402
import issue47_s3_compliance as issue47  # noqa: E402


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
    assert "/api/live-evidence" in html
    assert "/api/scan" in html
    assert "/api/ask" in html
    assert "/api/demo/reject" in html
    assert "isS3Risk ? 'Remediate'" in html
    assert "Exposure-risk remediation rejected" in html
    assert "/api/cve-review" in html
    assert "/api/codex-preflight" in html
    assert "Check Codex connection" in html
    assert "Check a CVE" in html
    assert "Scan environment" in html
    assert "Suggested fix only" in html
    assert "/api/live-proposal" in html
    assert "/api/live-decision" in html
    assert "Upload read-only evidence" in html
    assert "Approve mock remediation" in html
    assert "Generate remediation suggestion" in html
    assert "GovTech inference: not used" not in html
    assert "Reject" in html
    assert "A server change always needs a separate review and approval" in html


@pytest.mark.parametrize(
    ("source", "payload", "decision", "action", "verification"),
    [
        ("ecr", {"status": "READY", "state": "NON_COMPLIANT", "reason_code": "SECCOP_ECR_NON_COMPLIANT"}, "Awaiting review", "Not completed", "Awaiting provider truth"),
        ("s3", {"status": "REJECTED", "state": "NON_COMPLIANT", "reason_code": "HUMAN_REJECTED"}, "Rejected", "Not completed", "Not run"),
        ("ec2", {"status": "VERIFIED", "state": "COMPLIANT", "reason_code": "SECCOP_EC2_IMDSV2_REMEDIATED"}, "Approved", "Completed", "verified"),
        ("ecr", {"status": "NO_FINDINGS", "state": "COMPLIANT", "reason_code": "SECCOP_ECR_COMPLIANT"}, "No decision required", "No action required", "clean or compliant"),
        ("s3", {"status": "NO_FINDINGS", "state": "COMPLIANT", "reason_code": "SECCOP_S3_COMPLIANT"}, "No decision required", "No action required", "clean or compliant"),
        ("ec2", {"status": "COMPLIANT", "reason_code": "SECCOP_EC2_IMDSV2_COMPLIANT"}, "No decision required", "No action required", "clean or compliant"),
        ("ec2", {"status": "BLOCKED", "state": "PENDING", "reason_code": "TARGET_NOT_ALLOWED"}, "No decision", "Not completed", "Not complete"),
        ("ecr", {"status": "PENDING", "state": "UNKNOWN", "reason_code": "SECCOP_ECR_SUBMISSION_UNKNOWN", "safe_retry_action": "RECONCILE_BEFORE_RETRY"}, "Awaiting a safe terminal", "Not completed", "Pending provider reconciliation"),
    ],
)
def test_governance_timeline_preserves_five_stage_truth(
    source: str, payload: dict[str, object], decision: str, action: str, verification: str
) -> None:
    timeline = poc_server._governance_timeline(source, payload)

    assert set(timeline) == {"provider_evidence", "recommendation", "human_decision", "deterministic_action", "verification"}
    assert timeline["provider_evidence"].startswith("Provider evidence:")
    assert timeline["recommendation"].startswith("Recommendation:")
    assert decision in timeline["human_decision"]
    assert action in timeline["deterministic_action"]
    assert verification in timeline["verification"]


def test_manager_timeline_is_rendered_from_result_payload_only() -> None:
    html = (Path(__file__).parents[1] / "web" / "poc_chat.html").read_text()

    assert "function renderGovernanceTimeline(parent, timeline)" in html
    for label in ("Provider evidence", "Recommendation", "Human decision", "Deterministic action", "Verification"):
        assert label in html
    assert "result.governance_timeline" in html


def test_s3_proposal_reject_is_bound_and_non_mutating() -> None:
    poc_server._S3_PROPOSALS.clear()
    poc_server._S3_PROPOSALS["SECCOP_PROPOSAL_TEST"] = {"proposal_hash": "hash", "consumed": False}

    result = _reject_s3_proposal("SECCOP_PROPOSAL_TEST", "hash")

    assert result["status"] == "REJECTED"
    assert result["reason_code"] == "HUMAN_REJECTED"
    assert result["mutation_performed"] is False
    assert "SECCOP_PROPOSAL_TEST" not in poc_server._S3_PROPOSALS


class _FakeCodexTransport:
    def __init__(self, messages: list[dict[str, object]]) -> None:
        self.messages = list(messages)
        self.sent: list[dict[str, object]] = []

    def send(self, message: dict[str, object]) -> None:
        self.sent.append(message)

    def receive(self, timeout: float) -> dict[str, object]:
        assert timeout > 0
        if not self.messages:
            raise RuntimeError("fake App Server stream exhausted")
        return self.messages.pop(0)

    def close(self) -> None:
        return None


def _codex_ready_messages() -> list[dict[str, object]]:
    return [
        {"id": 1, "result": {"userAgent": "codex"}},
        {"id": 2, "result": {"account": {"type": "chatgpt"}, "requiresOpenaiAuth": True}},
        {"id": 3, "result": {"data": [], "nextCursor": None}},
        {"id": 4, "result": {"thread": {"id": "THREAD_ALIAS_01"}}},
        {"id": 5, "result": {"turn": {"id": "TURN_ALIAS_01"}}},
        {"method": "turn/started", "params": {"threadId": "THREAD_ALIAS_01", "turn": {"id": "TURN_ALIAS_01"}}},
        {"method": "item/started", "params": {"item": {"id": "ITEM_ALIAS_01", "type": "agentMessage"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "SecCop App Server preflight ready."}},
        {"method": "item/completed", "params": {"item": {"id": "ITEM_ALIAS_01", "type": "agentMessage"}}},
        {"method": "turn/completed", "params": {"threadId": "THREAD_ALIAS_01", "turn": {"id": "TURN_ALIAS_01", "status": "completed"}}},
    ]


def test_codex_preflight_maps_only_allowed_app_server_events() -> None:
    transport = _FakeCodexTransport(_codex_ready_messages())

    result = _run_codex_preflight(transport)

    assert result == {
        "status": "READY",
        "reason_code": "CODEX_CONNECTED",
        "codex_status": "CODEX_CONNECTED",
        "auth_status": "CODEX_AUTHENTICATED",
        "thread_status": "THREAD_ACTIVE",
        "aws_mcp_status": "AWS_MCP_UNAVAILABLE",
        "response_text": "SecCop App Server preflight ready.",
        "message": "Codex App Server completed one isolated no-tool preflight turn.",
    }
    assert [item["method"] for item in transport.sent] == [
        "initialize", "initialized", "account/read", "mcpServerStatus/list", "thread/start", "turn/start"
    ]


def test_codex_preflight_stops_when_authentication_is_unavailable() -> None:
    transport = _FakeCodexTransport([
        {"id": 1, "result": {"userAgent": "codex"}},
        {"id": 2, "result": {"account": None, "requiresOpenaiAuth": True}},
    ])

    result = _run_codex_preflight(transport)

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "CODEX_NOT_AUTHENTICATED"
    assert result["thread_status"] == "NOT_STARTED"
    assert all(item["method"] != "thread/start" for item in transport.sent)


def test_codex_preflight_rejects_forbidden_tool_event_and_interrupts() -> None:
    messages = _codex_ready_messages()[:5] + [
        {"method": "item/started", "params": {"item": {"id": "ITEM_ALIAS_02", "type": "commandExecution"}}},
        {"id": 99, "result": {}},
    ]
    transport = _FakeCodexTransport(messages)

    result = _run_codex_preflight(transport)

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "CODEX_EVENT_REJECTED"
    assert transport.sent[-1]["method"] == "turn/interrupt"


def test_codex_preflight_rejects_forbidden_rpc_before_transport() -> None:
    transport = _FakeCodexTransport([])

    with pytest.raises(_CodexPreflightError, match="CODEX_RPC_REJECTED"):
        _codex_request(transport, 6, "command/exec", {}, [])

    assert transport.sent == []


def test_hybrid_turn_rejects_command_event() -> None:
    transport = _FakeCodexTransport([
        {"id": 7, "result": {"turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "item/started", "params": {"item": {"id": "ITEM_ALIAS_02", "type": "commandExecution"}}},
    ])

    with pytest.raises(_CodexPreflightError, match="CODEX_EVENT_REJECTED"):
        _collect_codex_turn(_HybridSession(transport, "THREAD_ALIAS_01", [], 7), "Safe prompt")


def test_hybrid_turn_does_not_accept_idle_thread_status_as_completion() -> None:
    transport = _FakeCodexTransport([
        {"id": 7, "result": {"turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "Idle completion."}},
        {"method": "thread/status/changed", "params": {"threadId": "THREAD_ALIAS_01", "status": {"type": "idle"}}},
    ])
    session = _HybridSession(transport, "THREAD_ALIAS_01", [], 7)

    with pytest.raises(RuntimeError, match="stream exhausted"):
        _collect_codex_turn(session, "Safe prompt")
    assert session.turns_completed == 0


def test_hybrid_turn_uses_completed_agent_message_text_when_delta_is_empty() -> None:
    transport = _FakeCodexTransport([
        {"id": 7, "result": {"turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "item/completed", "params": {"item": {
            "id": "ITEM_ALIAS_02", "type": "agentMessage", "text": "Completed fallback.",
        }}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_02", "status": "completed"}}},
    ])

    assert _collect_codex_turn(_HybridSession(transport, "THREAD_ALIAS_01", [], 7), "Safe prompt") == "Completed fallback."


def test_hybrid_turn_ignores_buffered_completion_from_prior_turn() -> None:
    transport = _FakeCodexTransport([
        {"id": 7, "result": {"turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_01", "status": "completed"}}},
        {"method": "item/completed", "params": {"item": {
            "id": "ITEM_ALIAS_02", "type": "agentMessage", "text": "Current completion.",
        }}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_02", "status": "completed"}}},
    ])

    assert _collect_codex_turn(_HybridSession(transport, "THREAD_ALIAS_01", [], 7), "Safe prompt") == "Current completion."


@pytest.mark.parametrize("completed_text", ["/home/private/path", 42, None])
def test_hybrid_turn_rejects_unsafe_or_missing_completed_agent_message_text(completed_text: object) -> None:
    transport = _FakeCodexTransport([
        {"id": 7, "result": {"turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "item/completed", "params": {"item": {
            "id": "ITEM_ALIAS_02", "type": "agentMessage", "text": completed_text,
        }}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_02", "status": "completed"}}},
    ])

    with pytest.raises(_CodexPreflightError, match="CODEX_APP_SERVER_OUTPUT_REJECTED"):
        _collect_codex_turn(_HybridSession(transport, "THREAD_ALIAS_01", [], 7), "Safe prompt")


def test_hybrid_turn_waits_for_matching_completion_after_idle() -> None:
    transport = _FakeCodexTransport([
        {"id": 7, "result": {"turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "thread/status/changed", "params": {"threadId": "THREAD_ALIAS_01", "status": {"type": "idle"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "Real explanation."}},
        {"method": "item/completed", "params": {"item": {"id": "ITEM_ALIAS_02", "type": "agentMessage", "text": "Real explanation."}}},
        {"method": "turn/completed", "params": {"threadId": "THREAD_ALIAS_01", "turn": {"id": "TURN_ALIAS_02", "status": "completed"}}},
    ])
    session = _HybridSession(transport, "THREAD_ALIAS_01", [], 7)
    assert _collect_codex_turn(session, "Safe prompt") == "Real explanation."
    assert session.turns_completed == 1


def test_ecr_scan_request_bounds_user_text_without_granting_authority() -> None:
    request = SecCopScanRequest.model_validate({"mode": "DEMO", "request_text": "Explain the ECR finding and safe next step."})
    assert request.request_text.startswith("Explain")
    with pytest.raises(ValidationError):
        SecCopScanRequest.model_validate({"mode": "DEMO", "request_text": "run aws cli with arn:example:ecr:private"})


def test_ecr_codex_before_after_uses_one_sanitized_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _FakeCodexTransport([
        {"id": 1, "result": {"userAgent": "codex"}},
        {"id": 2, "result": {"account": {"type": "chatgpt"}}},
        {"id": 3, "result": {"thread": {"id": "THREAD_ALIAS_01"}}},
        {"id": 4, "result": {"turn": {"id": "TURN_ALIAS_01"}}},
        {"method": "turn/started", "params": {"threadId": "THREAD_ALIAS_01", "turn": {"id": "TURN_ALIAS_01"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "Before explanation from facts."}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_01", "status": "completed"}}},
        {"id": 5, "result": {"turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "turn/started", "params": {"threadId": "THREAD_ALIAS_01", "turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "After explanation from verified facts."}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_02", "status": "completed"}}},
    ])
    monkeypatch.setattr(poc_server, "_CodexProcessTransport", lambda: transport)
    monkeypatch.setenv("SECCOP_ECR_APP_SERVER", "1")
    monkeypatch.setattr(poc_server, "_CODEX_OBSERVABILITY", {"source": "NONE", "active": False, "lifecycle": "FRESH", "turns_completed": 0})
    monkeypatch.setattr(poc_server, "_trace_codex", lambda *_args, **_kwargs: None)
    before = poc_server._start_ecr_codex_explanation("Investigate and explain the safe next step.", {
        "scanner_mode": "ECR_ENHANCED_SCANNING", "package_ecosystem": "JAVASCRIPT_NPM",
        "cve_id": "CVE-2020-8203", "package_name": "lodash", "installed_version": "4.17.15",
        "severity": "HIGH", "state": "NON_COMPLIANT",
    })
    after = poc_server._finish_ecr_codex_explanation({"scanner_mode": "ECR_ENHANCED_SCANNING", "package_ecosystem": "JAVASCRIPT_NPM", "cve_id": "CVE-2020-8203", "state": "COMPLIANT", "status": "VERIFIED"})
    assert before["reason_code"] == "ECR_CODEX_BEFORE_READY"
    assert after["reason_code"] == "ECR_CODEX_AFTER_EXPLAINED"
    prompts = [item["params"]["input"][0]["text"] for item in transport.sent if item.get("method") == "turn/start"]
    assert "Investigate and explain" in prompts[0]
    assert "lodash" in prompts[0] and "CVE-2020-8203" in prompts[0]
    assert "COMPLIANT" in prompts[1] and "CVE-2020-8203" in prompts[1]
    assert all("sha256:" not in prompt and "arn:" not in prompt for prompt in prompts)
    assert [item["params"]["threadId"] for item in transport.sent if item.get("method") == "turn/start"] == ["THREAD_ALIAS_01", "THREAD_ALIAS_01"]


def test_ecr_codex_after_fails_closed_when_thread_is_lost() -> None:
    poc_server._close_hybrid_session()
    result = poc_server._finish_ecr_codex_explanation({"state": "COMPLIANT"})
    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "CODEX_THREAD_UNAVAILABLE"


def test_ecr_codex_after_uses_bounded_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    poc_server._HYBRID_SESSION = _HybridSession(
        _FakeCodexTransport([]), "THREAD_ALIAS_01", [], 1, {}, "ECR_BEFORE_COMPLETE", 1,
    )
    observed: list[float] = []

    def fake_collect(_session: object, _prompt: str, *, receive_timeout: float = 180.0) -> str:
        observed.append(receive_timeout)
        raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")

    monkeypatch.setattr(poc_server, "_collect_codex_turn", fake_collect)
    try:
        result = poc_server._finish_ecr_codex_explanation({"state": "COMPLIANT", "status": "VERIFIED"})
    finally:
        poc_server._close_hybrid_session()
    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "CODEX_APP_SERVER_UNAVAILABLE"
    assert observed == [poc_server._ECR_TURN_TIMEOUT]


def test_ecr_codex_after_fails_closed_when_continuity_marker_is_missing() -> None:
    poc_server._HYBRID_SESSION = _HybridSession(_FakeCodexTransport([]), "THREAD_ALIAS_01", [], 1, {})
    try:
        result = poc_server._finish_ecr_codex_explanation({"state": "COMPLIANT", "status": "VERIFIED"})
    finally:
        poc_server._close_hybrid_session()
    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "CODEX_THREAD_CONTINUITY_LOST"


@pytest.mark.parametrize("source", ["ecr", "s3", "ec2"])
def test_source_codex_reasoning_binds_before_question_and_after_to_one_source(
    monkeypatch: pytest.MonkeyPatch, source: str,
) -> None:
    transport = _FakeCodexTransport([
        {"id": 1, "result": {"userAgent": "codex"}},
        {"id": 2, "result": {"account": {"type": "chatgpt"}}},
        {"id": 3, "result": {"thread": {"id": "THREAD_ALIAS_01"}}},
        {"id": 4, "result": {"turn": {"id": "TURN_ALIAS_01"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "Before explanation."}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_01", "status": "completed"}}},
        {"id": 5, "result": {"turn": {"id": "TURN_ALIAS_02"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "Question explanation."}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_02", "status": "completed"}}},
        {"id": 6, "result": {"turn": {"id": "TURN_ALIAS_03"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "After explanation."}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_03", "status": "completed"}}},
    ])
    monkeypatch.setattr(poc_server, "_CodexProcessTransport", lambda: transport)
    monkeypatch.setenv("SECCOP_ECR_APP_SERVER", "1")
    monkeypatch.setattr(poc_server, "_CODEX_OBSERVABILITY", {"source": "NONE", "active": False, "lifecycle": "FRESH", "turns_completed": 0})
    facts = {
        "ecr": {"state": "NON_COMPLIANT", "scanner_mode": "ECR_ENHANCED_SCANNING", "package_ecosystem": "PYTHON", "cve_id": "CVE-2020-8203", "package_name": "urllib3", "installed_version": "1.24.1", "severity": "HIGH"},
        "s3": {"state": "NON_COMPLIANT", "config_rule_name": "s3-bucket-level-public-access-prohibited", "remediation_document": "AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock", "findings": [{"observed_state": "Block Public Access absent"}]},
        "ec2": {"state": "NON_COMPLIANT", "config_rule_name": "ec2-imdsv2-check-rnd-lab01", "metadata_http_tokens": "optional"},
    }[source]
    poc_server._close_hybrid_session()
    poc_server._CODEX_INVESTIGATION_SOURCE = None
    assert poc_server._codex_status() == {"status": "OK", "app_server": "ENABLED", "current_source": "NONE", "session": "INACTIVE", "lifecycle": "FRESH", "completed_turns": 0}
    before = poc_server._start_source_codex_explanation(source, "Explain the safe next step.", facts)
    assert poc_server._codex_status() == {"status": "OK", "app_server": "ENABLED", "current_source": source.upper(), "session": "ACTIVE", "lifecycle": "BEFORE_COMPLETE", "completed_turns": 1}
    question = poc_server._ask_source_codex(source, "What should the operator review?")
    assert poc_server._codex_status()["lifecycle"] == "QUESTION_COMPLETE"
    assert poc_server._codex_status()["completed_turns"] == 2
    after = poc_server._finish_source_codex_explanation(source, {"status": "VERIFIED", "state": "COMPLIANT"})

    assert before["reason_code"] == f"{source.upper()}_CODEX_BEFORE_READY"
    assert question["reason_code"] == f"{source.upper()}_CODEX_QUESTION_READY"
    assert after["reason_code"] == f"{source.upper()}_CODEX_AFTER_EXPLAINED"
    assert [item["params"]["threadId"] for item in transport.sent if item.get("method") == "turn/start"] == ["THREAD_ALIAS_01"] * 3
    prompt = next(item["params"]["input"][0]["text"] for item in transport.sent if item.get("method") == "turn/start")
    assert ({"ecr": "package ecosystem: PYTHON", "s3": "Config rule: s3-bucket-level-public-access-prohibited", "ec2": "IMDSv2 HttpTokens state: optional"}[source]) in prompt
    assert ({"ecr": "Block Public Access", "s3": "package ecosystem", "ec2": "package ecosystem"}[source]) not in prompt
    assert source.upper() in after["message"]
    assert poc_server._HYBRID_SESSION is None
    assert poc_server._codex_status() == {"status": "OK", "app_server": "ENABLED", "current_source": source.upper(), "session": "INACTIVE", "lifecycle": "AFTER_COMPLETED", "completed_turns": 3}


def test_ec2_codex_prompt_uses_structured_state_not_presentation_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _FakeCodexTransport([
        {"id": 1, "result": {"userAgent": "codex"}},
        {"id": 2, "result": {"account": {"type": "chatgpt"}}},
        {"id": 3, "result": {"thread": {"id": "THREAD_ALIAS_01"}}},
        {"id": 4, "result": {"turn": {"id": "TURN_ALIAS_01"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "Before explanation."}},
        {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_01", "status": "completed"}}},
    ])
    monkeypatch.setattr(poc_server, "_CodexProcessTransport", lambda: transport)
    monkeypatch.setattr(poc_server, "_trace_codex", lambda *_args, **_kwargs: None)
    poc_server._close_hybrid_session()

    result = poc_server._start_source_codex_explanation("ec2", "Explain the safe next step.", {
        "state": "NON_COMPLIANT",
        "config_rule_name": "ec2-imdsv2-check-rnd-lab01",
        "findings": [{"observed_state": "HttpTokens=optional; Config NON_COMPLIANT"}],
    })
    try:
        assert result["reason_code"] == "EC2_CODEX_BEFORE_READY"
        turn_start = next(item for item in transport.sent if item.get("method") == "turn/start")
        prompt = turn_start["params"]["input"][0]["text"]
        assert "IMDSv2 HttpTokens state: optional" in prompt
        assert "HttpTokens=optional; Config NON_COMPLIANT" not in prompt
    finally:
        poc_server._close_hybrid_session()


@pytest.mark.parametrize("facts", [
    {"state": "UNKNOWN"},
    {"state": "NON_COMPLIANT", "metadata_http_tokens": "optional; Config NON_COMPLIANT"},
])
def test_ec2_codex_prompt_fails_closed_before_transport_for_unstructured_state(
    monkeypatch: pytest.MonkeyPatch, facts: dict[str, object],
) -> None:
    monkeypatch.setattr(poc_server, "_CodexProcessTransport", lambda: pytest.fail("transport must not start"))
    poc_server._close_hybrid_session()

    result = poc_server._start_source_codex_explanation("ec2", "Explain the safe next step.", facts)

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "CODEX_PROMPT_FACTS_REJECTED"


def test_codex_status_endpoint_is_readonly_and_excludes_private_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECCOP_ECR_APP_SERVER", "1")
    monkeypatch.setattr(poc_server, "_CODEX_OBSERVABILITY", {"source": "S3", "active": True, "lifecycle": "BEFORE_COMPLETE", "turns_completed": 1})
    proposals_before = dict(poc_server._SECCOP_PROPOSALS)
    approvals_before = dict(poc_server._SECCOP_APPROVALS)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.loads(urlopen(f"http://127.0.0.1:{server.server_port}/api/codex-status").read())
    finally:
        server.shutdown()
    assert payload == {"status": "OK", "app_server": "ENABLED", "current_source": "S3", "session": "ACTIVE", "lifecycle": "BEFORE_COMPLETE", "completed_turns": 1}
    assert not ({"thread", "prompt", "path", "model", "trace", "token", "credential", "proposal", "approval", "action", "target"} & set(payload))
    assert poc_server._SECCOP_PROPOSALS == proposals_before
    assert poc_server._SECCOP_APPROVALS == approvals_before


def test_codex_reset_preserves_conflict_protection_then_allows_fresh_source_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TrackingTransport(_FakeCodexTransport):
        def __init__(self, messages: list[dict[str, object]]) -> None:
            super().__init__(messages)
            self.closed = False

        def close(self) -> None:
            self.closed = True

    def messages() -> list[dict[str, object]]:
        return [
            {"id": 1, "result": {"userAgent": "codex"}}, {"id": 2, "result": {"account": {"type": "chatgpt"}}}, {"id": 3, "result": {"thread": {"id": "THREAD_ALIAS_01"}}},
            {"id": 4, "result": {"turn": {"id": "TURN_ALIAS_01"}}}, {"method": "item/agentMessage/delta", "params": {"delta": "Before."}}, {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_01", "status": "completed"}}},
        ]

    transports = [TrackingTransport(messages()) for _ in range(3)]
    pending_transports = list(transports)
    monkeypatch.setattr(poc_server, "_CodexProcessTransport", lambda: pending_transports.pop(0))
    monkeypatch.setattr(poc_server, "_trace_codex", lambda *_args, **_kwargs: None)
    monkeypatch.setenv("SECCOP_ECR_APP_SERVER", "1")
    monkeypatch.setattr(poc_server, "_CODEX_OBSERVABILITY", {"source": "NONE", "active": False, "lifecycle": "FRESH", "turns_completed": 0})
    poc_server._close_hybrid_session()

    assert poc_server._start_source_codex_explanation("ecr", "Explain the safe next step.", {"state": "NON_COMPLIANT"})["status"] == "READY"
    assert poc_server._start_source_codex_explanation("s3", "Explain this other finding.", {"state": "NON_COMPLIANT"})["reason_code"] == "CODEX_INVESTIGATION_BUSY"
    assert poc_server._reset_codex_investigation()["reason_code"] == "CODEX_SESSION_RESET"
    assert transports[0].closed is True
    assert poc_server._codex_status() == {"status": "OK", "app_server": "ENABLED", "current_source": "NONE", "session": "INACTIVE", "lifecycle": "FRESH", "completed_turns": 0}
    assert poc_server._start_source_codex_explanation("s3", "Explain the safe next step.", {"state": "NON_COMPLIANT"})["status"] == "READY"
    assert poc_server._reset_codex_investigation()["reason_code"] == "CODEX_SESSION_RESET"
    assert transports[1].closed is True
    assert poc_server._start_source_codex_explanation("ec2", "Explain the safe next step.", {"state": "NON_COMPLIANT"})["status"] == "READY"
    assert poc_server._reset_codex_investigation()["reason_code"] == "CODEX_SESSION_RESET"
    assert transports[2].closed is True


def test_codex_reset_endpoint_is_local_only_and_private_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    class TrackingTransport(_FakeCodexTransport):
        def __init__(self) -> None:
            super().__init__([])
            self.closed = False

        def close(self) -> None:
            self.closed = True

    transport = TrackingTransport()
    monkeypatch.setenv("SECCOP_ECR_APP_SERVER", "1")
    monkeypatch.setattr(poc_server, "_HYBRID_SESSION", _HybridSession(transport, "THREAD_ALIAS_01", [], 4, {}, "ECR_BEFORE_COMPLETE", 1))
    monkeypatch.setattr(poc_server, "_CODEX_INVESTIGATION_SOURCE", "ecr")
    monkeypatch.setattr(poc_server, "_CODEX_OBSERVABILITY", {"source": "ECR", "active": True, "lifecycle": "BEFORE_COMPLETE", "turns_completed": 1})
    proposals_before = dict(poc_server._SECCOP_PROPOSALS)
    approvals_before = dict(poc_server._SECCOP_APPROVALS)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        rejected = Request(f"http://127.0.0.1:{server.server_port}/api/codex-reset", data=b'{"unexpected":true}', headers={"Content-Type": "application/json"}, method="POST")
        with pytest.raises(HTTPError) as error:
            urlopen(rejected)
        assert error.value.code == 400
        assert json.loads(error.value.read()) == {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"}
        assert transport.closed is False
        assert poc_server._HYBRID_SESSION is not None
        assert poc_server._codex_status() == {"status": "OK", "app_server": "ENABLED", "current_source": "ECR", "session": "ACTIVE", "lifecycle": "BEFORE_COMPLETE", "completed_turns": 1}
        request = Request(f"http://127.0.0.1:{server.server_port}/api/codex-reset", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        payload = json.loads(urlopen(request).read())
    finally:
        server.shutdown()
    assert payload == {"result": {"status": "READY", "reason_code": "CODEX_SESSION_RESET", "message": "The local Codex investigation was reset; provider and approval state are unchanged."}, "events": []}
    assert transport.closed is True
    assert poc_server._SECCOP_PROPOSALS == proposals_before
    assert poc_server._SECCOP_APPROVALS == approvals_before
    assert not ({"thread", "prompt", "path", "model", "trace", "token", "credential", "provider", "proposal", "approval", "action", "target"} & set(payload["result"]))


def test_source_codex_question_rejects_wrong_source_and_missing_scan() -> None:
    poc_server._close_hybrid_session()
    poc_server._CODEX_INVESTIGATION_SOURCE = None
    assert poc_server._ask_source_codex("s3", "Explain this.")["reason_code"] == "CODEX_SCAN_REQUIRED"
    poc_server._HYBRID_SESSION = _HybridSession(_FakeCodexTransport([]), "THREAD_ALIAS_01", [], 4, {}, "ECR_BEFORE_COMPLETE", 1)
    poc_server._CODEX_INVESTIGATION_SOURCE = "ecr"
    try:
        assert poc_server._ask_source_codex("s3", "Explain this.")["reason_code"] == "CODEX_THREAD_CONTINUITY_LOST"
    finally:
        poc_server._close_hybrid_session()
        poc_server._CODEX_INVESTIGATION_SOURCE = None


def test_busy_codex_investigation_gives_the_safe_local_recovery_action() -> None:
    result = poc_server._hybrid_blocked("CODEX_INVESTIGATION_BUSY", close_session=False)

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "CODEX_INVESTIGATION_BUSY"
    assert result["message"] == (
        "A source-bound AI explanation is already active. Select New investigation "
        "before starting another AI explanation; provider and approval state are unchanged."
    )


def test_source_codex_rejects_busy_malformed_and_wrong_source_without_losing_valid_investigation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _FakeCodexTransport([
        {"id": 1, "result": {"userAgent": "codex"}}, {"id": 2, "result": {"account": {"type": "chatgpt"}}}, {"id": 3, "result": {"thread": {"id": "THREAD_ALIAS_01"}}},
        {"id": 4, "result": {"turn": {"id": "TURN_ALIAS_01"}}}, {"method": "item/agentMessage/delta", "params": {"delta": "Before."}}, {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_01", "status": "completed"}}},
        {"id": 5, "result": {"turn": {"id": "TURN_ALIAS_02"}}}, {"method": "item/agentMessage/delta", "params": {"delta": "Question."}}, {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_02", "status": "completed"}}},
        {"id": 6, "result": {"turn": {"id": "TURN_ALIAS_03"}}}, {"method": "item/agentMessage/delta", "params": {"delta": "After."}}, {"method": "turn/completed", "params": {"turn": {"id": "TURN_ALIAS_03", "status": "completed"}}},
    ])
    monkeypatch.setattr(poc_server, "_CodexProcessTransport", lambda: transport)
    monkeypatch.setattr(poc_server, "_trace_codex", lambda *_args, **_kwargs: None)
    poc_server._close_hybrid_session()
    assert poc_server._start_source_codex_explanation("ecr", "Explain the safe next step.", {"state": "NON_COMPLIANT"})["status"] == "READY"
    active = poc_server._HYBRID_SESSION
    assert poc_server._start_source_codex_explanation("s3", "Explain this other finding.", {"state": "NON_COMPLIANT"})["reason_code"] == "CODEX_INVESTIGATION_BUSY"
    assert poc_server._ask_source_codex("ecr", "x" * 301)["reason_code"] == "REQUEST_REJECTED"
    assert poc_server._ask_source_codex("s3", "Explain this.")["reason_code"] == "CODEX_THREAD_CONTINUITY_LOST"
    assert poc_server._HYBRID_SESSION is active
    assert poc_server._ask_source_codex("ecr", "What should the operator review?")["status"] == "READY"
    assert poc_server._finish_source_codex_explanation("ecr", {"status": "VERIFIED", "state": "COMPLIANT"})["status"] == "READY"
    assert poc_server._HYBRID_SESSION is None


def test_source_reasoning_routes_only_the_matching_finalized_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {
        "SECCOP_DEMO_BACKEND": "AWS", "SECCOP_ECR_S3_COMBINED": "1", "SECCOP_ECR_OPERATOR_MVP": "1", "SECCOP_ECR_APP_SERVER": "1",
        "SECCOP_ECR_SCANNER": "inspector", "SECCOP_S3_COMPLIANCE_E2E": "1", "SECCOP_PROFILE": "amit", "AWS_REGION": "ap-southeast-1", "SECCOP_S3_BUCKET": "S3_DRIFT_ALIAS",
    }.items():
        monkeypatch.setenv(name, value)
    routed: list[tuple[str, str, set[str]]] = []
    monkeypatch.setattr(poc_server, "_attach_source_reasoning", lambda source, command, payload, _request: routed.append((source, command, set(payload))))

    def fake_run(args: list[str], **_: object) -> SimpleNamespace:
        if "ecr-scan" in args:
            return SimpleNamespace(stdout=json.dumps({"status": "READY", "reason_code": "SECCOP_ECR_NON_COMPLIANT", "state": "NON_COMPLIANT"}))
        return SimpleNamespace(stdout=json.dumps({"status": "READY", "reason_code": "SECCOP_S3_NON_COMPLIANT", "state": "NON_COMPLIANT", "config_rule_name": "s3-bucket-level-public-access-prohibited", "remediation_document": "AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock", "findings": []}))

    monkeypatch.setattr(poc_server.subprocess, "run", fake_run)
    poc_server._run_real_demo("scan", source="ecr")
    poc_server._run_real_demo("scan", source="s3")

    assert [(source, command) for source, command, _keys in routed] == [("ecr", "scan"), ("s3", "scan")]
    assert {"proposal_id", "proposal_hash"}.issubset(routed[1][2])


def test_source_timeout_is_pending_and_never_claims_no_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECCOP_DEMO_BACKEND", "AWS")
    monkeypatch.setenv("SECCOP_ECR_OPERATOR_MVP", "1")
    monkeypatch.setenv("SECCOP_ECR_SCANNER", "inspector")
    monkeypatch.setenv("SECCOP_PROFILE", "amit")
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")
    monkeypatch.setattr(poc_server.subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("fixture", 1)))

    result = poc_server._run_real_demo("scan", source="ecr")

    assert result["reason_code"] == "SECCOP_ECR_SUBMISSION_UNKNOWN"
    assert result["mutation_state"] == "UNKNOWN"
    assert result["safe_retry_action"] == "RECONCILE_BEFORE_RETRY"


class _FakeProcess:
    def __init__(self, *, running: bool, timeout_first_wait: bool = False) -> None:
        self.running = running
        self.timeout_first_wait = timeout_first_wait
        self.terminated = False
        self.killed = False
        self.wait_calls: list[float] = []

    def poll(self) -> int | None:
        return None if self.running else 0

    def terminate(self) -> None:
        self.terminated = True
        self.running = False

    def kill(self) -> None:
        self.killed = True
        self.running = False

    def wait(self, timeout: float) -> int:
        self.wait_calls.append(timeout)
        if self.timeout_first_wait and len(self.wait_calls) == 1:
            raise poc_server.subprocess.TimeoutExpired("codex", timeout)
        self.running = False
        return 0


def test_codex_transport_close_reaps_exited_and_kills_stuck_process() -> None:
    closed: list[bool] = []
    exited = poc_server._CodexProcessTransport.__new__(poc_server._CodexProcessTransport)
    exited.process = _FakeProcess(running=False)
    exited._stderr_handle = SimpleNamespace(close=lambda: closed.append(True))
    exited._closed = False
    exited.close()
    assert len(exited.process.wait_calls) == 1
    assert closed == [True]

    stuck = poc_server._CodexProcessTransport.__new__(poc_server._CodexProcessTransport)
    stuck.process = _FakeProcess(running=True, timeout_first_wait=True)
    stuck._stderr_handle = SimpleNamespace(close=lambda: closed.append(True))
    stuck._closed = False
    stuck.close()
    assert stuck.process.terminated is True
    assert stuck.process.killed is True
    assert len(stuck.process.wait_calls) == 2


def test_codex_transport_keeps_multiple_buffered_protocol_lines() -> None:
    read_fd, write_fd = os.pipe()
    stream = None
    try:
        os.write(write_fd, b'{"id":1,"result":{}}\n{"id":2,"result":{}}\n')
        os.close(write_fd)
        transport = poc_server._CodexProcessTransport.__new__(poc_server._CodexProcessTransport)
        stream = os.fdopen(read_fd, "rb")
        transport.process = SimpleNamespace(stdout=stream)
        transport._stdout_buffer = b""
        assert transport.receive(1.0)["id"] == 1
        assert transport.receive(1.0)["id"] == 2
    finally:
        try:
            os.close(write_fd)
        except OSError:
            pass
        if stream is not None:
            stream.close()


def test_public_remediation_payload_excludes_private_evidence_path() -> None:
    result = SecCopRemediationResult(
        status="COMPLETED", reason_code="SSM_REMEDIATION_VERIFIED", cve_id="CVE-2099-0001",
        resource_alias="EC2_RESOURCE_01", change_state="COMPLETED", verification_status="VERIFIED",
        reboot_approved=False, mutation_performed=True, evidence_path="/private/evidence.json", message="Verified.",
    )

    assert "evidence_path" not in _public_remediation_payload(result)


def test_demo_cve_review_checks_three_sources_with_aliases_only() -> None:
    result = review_demo_cve("CVE-2099-0001")

    assert result.status == "READY"
    assert result.reason_code == "SECCOP_CVE_REVIEW_READY"
    assert result.match_count == 3
    assert [item.status for item in result.source_results] == ["FOUND", "FOUND", "FOUND"]
    assert "i-" not in result.model_dump_json()
    assert "arn:" not in result.model_dump_json()

    missing = review_demo_cve("CVE-2099-0002")
    assert missing.status == "NOT_FOUND"
    assert missing.reason_code == "SECCOP_CVE_NOT_FOUND"
    assert missing.match_count == 0


def test_demo_scan_returns_three_alias_only_findings_and_no_mutation_controls() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(
            f"http://127.0.0.1:{server.server_port}/api/scan",
            data=json.dumps({"mode": "DEMO"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        payload = json.loads(urlopen(request).read().decode())
        result = payload["result"]
        assert result["status"] == "READY"
        assert [item["source_type"] for item in result["source_status"]] == [
            "EC2_PACKAGE",
            "S3_ARTIFACT",
            "ECR_IMAGE",
        ]
        assert len(result["findings"]) == 3
        assert result["findings"][0]["remediation_mode"] == "REAL_APPROVAL_REQUIRED"
        assert all(item["remediation_mode"] == "DEMO_ONLY" for item in result["findings"][1:])
        assert "i-" not in json.dumps(payload)
        assert "arn:" not in json.dumps(payload)
        assert all("Approve" not in json.dumps(item) for item in result["findings"][1:])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ecr_scan_names_storage_and_scanner(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeAws:
        def run(self, *args: str, input_text: str | None = None) -> str:
            assert args == ("ecr", "get-login-password")
            return "SYNTHETIC_TOKEN"

    def fake_trivy(args: list[str], *, input_text: str | None = None) -> dict[str, object]:
        assert args[-1].endswith(":demo-current")
        assert "--image-src" in args and "remote" in args
        return {"Results": [{"Vulnerabilities": [{}]}]}

    monkeypatch.setattr(seccop_demo, "_run_trivy", fake_trivy)
    result = seccop_demo._scan_ecr(FakeAws(), tmp_path, "registry.invalid/demo")

    assert result["storage_provider"] == "AWS_ECR"
    assert result["scanner_provider"] == "LOCAL_TRIVY"


def _inspector_fixture(*, tag: str = "demo-current", digest: str | None = None) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    image_digest = digest or "sha256:" + "a" * 64
    image = {"imageTags": [tag], "imageDigest": image_digest}
    account = {"accounts": [{"resourceState": {"ecr": {"status": "ENABLED"}}}]}
    coverage = {
        "coveredResources": [
            {
                "resourceId": f"ECR_IMAGE_ALIAS/{image_digest}",
                "scanType": "PACKAGE",
                "scanStatus": {"statusCode": "INACTIVE", "reason": "SCAN_FREQUENCY_SCAN_ON_PUSH"},
            }
        ]
    }
    finding = {
        "status": "ACTIVE",
        "type": "PACKAGE_VULNERABILITY",
        "severity": "HIGH",
        "resources": [
            {
                "type": "AWS_ECR_CONTAINER_IMAGE",
                "details": {"awsEcrContainerImage": {"repositoryName": seccop_demo.ECR_REPOSITORY, "imageHash": image_digest}},
            }
        ],
        "packageVulnerabilityDetails": {
            "vulnerabilityId": seccop_demo.BAD_CVE,
            "vulnerablePackages": [{"name": "urllib3", "version": "1.24.1"}],
        },
    }
    return {"imageDetails": [image]}, account, coverage, {"findings": [finding]}


class _FakeInspectorAws:
    def __init__(self, responses: tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]) -> None:
        self.image, self.account, self.coverage, self.findings = responses
        self.calls: list[tuple[str, ...]] = []

    def json(self, *args: str) -> dict[str, object]:
        self.calls.append(args)
        if args[:2] == ("ecr", "describe-images"):
            return self.image
        if args[:2] == ("inspector2", "batch-get-account-status"):
            return self.account
        if args[:2] == ("inspector2", "list-coverage"):
            return self.coverage
        if args[:2] == ("inspector2", "list-findings"):
            return self.findings
        raise AssertionError(f"unexpected AWS read: {args[:2]}")


def test_inspector_ecr_maps_exact_finding_without_digest_or_raw_payload() -> None:
    aws = _FakeInspectorAws(_inspector_fixture())

    result = seccop_demo._scan_ecr_inspector(aws)

    assert result == {
        "source": "ECR_IMAGE",
        "alias": "ECR_IMAGE_01",
        "state": "NON_COMPLIANT",
        "reason_code": "SECCOP_ECR_INSPECTOR_FINDING",
        "storage_provider": "AWS_ECR",
        "scanner_provider": "AMAZON_INSPECTOR",
        "scanner_mode": "ECR_ENHANCED_SCANNING",
        "cve_id": "CVE-2019-11324",
        "package_name": "urllib3",
        "installed_version": "1.24.1",
        "severity": "HIGH",
    }
    assert "sha256:" not in json.dumps(result)
    assert any(call[:2] == ("inspector2", "list-findings") for call in aws.calls)


def test_inspector_ecr_clean_absence_is_compliant() -> None:
    image, account, coverage, _ = _inspector_fixture()
    aws = _FakeInspectorAws((image, account, coverage, {"findings": []}))

    result = seccop_demo._scan_ecr_inspector(aws)

    assert result["state"] == "COMPLIANT"
    assert result["reason_code"] == "SECCOP_ECR_INSPECTOR_CVE_ABSENT"


def test_inspector_ecr_pending_readiness_is_not_claimed_clean() -> None:
    image, account, coverage, findings = _inspector_fixture()
    coverage["coveredResources"][0]["scanStatus"] = {"statusCode": "ACTIVE", "reason": "PENDING_INITIAL_SCAN"}
    aws = _FakeInspectorAws((image, account, coverage, findings))

    result = seccop_demo._scan_ecr_inspector(aws)

    assert result["state"] == "PENDING_RESCAN"
    assert result["reason_code"] == "SECCOP_ECR_SCAN_PENDING"


def test_inspector_ecr_rejects_wrong_or_missing_coverage() -> None:
    image, account, coverage, findings = _inspector_fixture()
    coverage["coveredResources"][0]["resourceId"] = "ECR_IMAGE_ALIAS/sha256:" + "b" * 64
    wrong = seccop_demo._scan_ecr_inspector(_FakeInspectorAws((image, account, coverage, findings)))
    assert wrong["state"] == "BLOCKED"
    assert wrong["reason_code"] == "SECCOP_ECR_COVERAGE_MISMATCH"

    coverage["coveredResources"] = []
    missing = seccop_demo._scan_ecr_inspector(_FakeInspectorAws((image, account, coverage, findings)))
    assert missing["state"] == "BLOCKED"
    assert missing["reason_code"] == "SECCOP_ECR_COVERAGE_MISMATCH"


def test_inspector_ecr_rejects_ambiguous_tag() -> None:
    image, account, coverage, findings = _inspector_fixture()
    image["imageDetails"] = [image["imageDetails"][0], image["imageDetails"][0].copy()]

    result = seccop_demo._scan_ecr_inspector(_FakeInspectorAws((image, account, coverage, findings)))

    assert result["state"] == "BLOCKED"
    assert result["reason_code"] == "SECCOP_ECR_TAG_AMBIGUOUS"


def test_inspector_fixture_selector_uses_retained_public_aliases(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = {
        "source": "ECR_IMAGE", "alias": "ECR_IMAGE_01", "state": "COMPLIANT",
        "reason_code": "SECCOP_ECR_INSPECTOR_CVE_ABSENT", "scanner_provider": "AMAZON_INSPECTOR",
        "scanner_mode": "ECR_ENHANCED_SCANNING", "cve_id": seccop_demo.BAD_CVE,
    }
    selected: list[str] = []

    def fake_scan(*_: object, tag: str, **__: object) -> dict[str, object]:
        selected.append(tag)
        return source

    monkeypatch.setattr(seccop_demo, "_scan_ecr_inspector", fake_scan)
    monkeypatch.setattr(seccop_demo, "_scan_ecr", lambda *_: pytest.fail("Trivy path used for Inspector selection"))

    vulnerable = seccop_demo._ecr_scan(object(), tmp_path, ecr_scanner="inspector", ecr_fixture="vulnerable")
    clean = seccop_demo._ecr_scan(object(), tmp_path, ecr_scanner="inspector", ecr_fixture="clean")
    invalid = seccop_demo._ecr_scan(object(), tmp_path, ecr_scanner="inspector", ecr_fixture="unknown")

    assert selected == ["issue53-live-vulnerable", "issue53-live-clean"]
    assert vulnerable["status"] == "NO_FINDINGS"
    assert clean["reason_code"] == "SECCOP_ECR_COMPLIANT"
    assert invalid["status"] == "BLOCKED"
    assert invalid["reason_code"] == "SECCOP_ECR_EVIDENCE_BLOCKED"


def test_multi_image_fixture_builder_has_distinct_python_and_npm_package_metadata(tmp_path: Path) -> None:
    python_files = seccop_demo._image_files(tmp_path, seccop_demo.BAD_VERSION, "python", "python")
    npm_files = seccop_demo._image_files(tmp_path, seccop_demo.NPM_BAD_VERSION, "npm", "npm")

    python_layer = gzip.open(python_files[1], "rb").read()
    npm_layer = gzip.open(npm_files[1], "rb").read()
    assert b"urllib3==1.24.1" in python_layer
    assert b'"name": "lodash"' in npm_layer
    assert python_files[2].read_bytes() != npm_files[2].read_bytes()
    assert seccop_demo._ecr_fixture_spec("npm-vulnerable") == {
        "tag": "issue53-npm-vulnerable", "cve_id": seccop_demo.NPM_CVE, "ecosystem": "JAVASCRIPT_NPM",
    }


def test_inspector_coverage_falls_back_to_repository_for_digest_correlation() -> None:
    fixture = _inspector_fixture()

    class FallbackAws(_FakeInspectorAws):
        def __init__(self, responses: tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]) -> None:
            super().__init__(responses)
            self.coverage_reads = 0

        def json(self, *args: str) -> dict[str, object]:
            if args[:2] == ("inspector2", "list-coverage"):
                self.coverage_reads += 1
                if self.coverage_reads == 1:
                    self.calls.append(args)
                    return {"coveredResources": []}
            return super().json(*args)

    aws = FallbackAws(fixture)
    result = seccop_demo._scan_ecr_inspector(aws)

    assert result["state"] == "NON_COMPLIANT"
    assert result["reason_code"] == "SECCOP_ECR_INSPECTOR_FINDING"
    assert aws.coverage_reads == 2


def test_inspector_finding_pagination_is_consumed_before_ambiguity_check() -> None:
    fixture = _inspector_fixture()

    class PagedAws(_FakeInspectorAws):
        def __init__(self, responses: tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]) -> None:
            super().__init__(responses)
            self.finding_reads = 0

        def json(self, *args: str) -> dict[str, object]:
            if args[:2] == ("inspector2", "list-findings"):
                self.finding_reads += 1
                self.calls.append(args)
                return {"findings": []} if self.finding_reads == 2 else {"findings": self.findings["findings"], "nextToken": "TOKEN_ALIAS_01"}
            return super().json(*args)

    aws = PagedAws(fixture)
    result = seccop_demo._scan_ecr_inspector(aws)

    assert result["state"] == "NON_COMPLIANT"
    assert result["reason_code"] == "SECCOP_ECR_INSPECTOR_FINDING"
    assert aws.finding_reads == 2


def test_ecr_operator_maps_inspector_result_and_preserves_trivy_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    inspector_source = {
        "source": "ECR_IMAGE", "alias": "ECR_IMAGE_01", "state": "NON_COMPLIANT",
        "reason_code": "SECCOP_ECR_INSPECTOR_FINDING", "scanner_provider": "AMAZON_INSPECTOR",
        "scanner_mode": "ECR_ENHANCED_SCANNING", "cve_id": seccop_demo.BAD_CVE,
        "package_name": "urllib3", "installed_version": "1.24.1", "severity": "HIGH",
    }
    monkeypatch.setattr(seccop_demo, "_scan_ecr_inspector", lambda *_, **__: inspector_source)
    monkeypatch.setattr(seccop_demo, "_scan_ecr", lambda *_: pytest.fail("Trivy path used for Inspector selection"))

    inspector = seccop_demo._ecr_scan(object(), tmp_path, ecr_scanner="inspector")

    assert inspector["status"] == "READY"
    assert inspector["reason_code"] == "SECCOP_ECR_NON_COMPLIANT"
    assert inspector["state"] == "NON_COMPLIANT"
    assert inspector["scanner_provider"] == "AMAZON_INSPECTOR"
    assert inspector["scanner_mode"] == "ECR_ENHANCED_SCANNING"
    assert inspector["findings"][0]["package_name"] == "urllib3"

    monkeypatch.setattr(seccop_demo, "_scan_ecr", lambda *_: {"state": "COMPLIANT", "vulnerabilities": 0})
    monkeypatch.setattr(seccop_demo, "_repo_uri", lambda *_: "registry.invalid/demo")
    trivy = seccop_demo._ecr_scan(object(), tmp_path)
    assert trivy["reason_code"] == "SECCOP_ECR_COMPLIANT"


def test_ecr_approve_uses_matching_clean_fixture_and_current_verification(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    promoted: list[str] = []
    scanned: list[tuple[str, str | None]] = []

    monkeypatch.setattr(seccop_demo, "_ecr_promote_fixture", lambda _aws, _directory, fixture: promoted.append(fixture))

    def fake_scan(_aws: object, _directory: Path, _scanner: str, fixture: str, tag_override: str | None = None) -> dict[str, object]:
        scanned.append((fixture, tag_override))
        return {"reason_code": "SECCOP_ECR_COMPLIANT"}

    monkeypatch.setattr(seccop_demo, "_ecr_scan_selected", fake_scan)

    result = seccop_demo._ecr_fix(object(), tmp_path, ecr_scanner="inspector", ecr_fixture="current")

    assert result["status"] == "VERIFIED"
    assert promoted == ["current-clean"]
    assert scanned == [("current", "demo-current")]


def test_ecr_scan_tag_override_reads_mutable_current_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    selected: list[str] = []

    def fake_scan(_aws: object, *, tag: str, **_: object) -> dict[str, object]:
        selected.append(tag)
        return {"source": "ECR_IMAGE", "alias": "ECR_IMAGE_01", "state": "COMPLIANT", "reason_code": "SECCOP_ECR_INSPECTOR_CVE_ABSENT", "scanner_provider": "AMAZON_INSPECTOR", "scanner_mode": "ECR_ENHANCED_SCANNING", "cve_id": seccop_demo.BAD_CVE}

    monkeypatch.setattr(seccop_demo, "_scan_ecr_inspector", fake_scan)
    result = seccop_demo._ecr_scan(
        object(), tmp_path, ecr_scanner="inspector", ecr_fixture="current", tag_override="demo-current"
    )

    assert result["reason_code"] == "SECCOP_ECR_COMPLIANT"
    assert selected == ["demo-current"]


def test_ecr_scan_rejects_unrelated_fixture_or_tag_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(seccop_demo, "_scan_ecr_inspector", lambda *_args, **_kwargs: pytest.fail("mismatched override must fail closed"))

    arbitrary = seccop_demo._ecr_scan(object(), tmp_path, ecr_scanner="inspector", ecr_fixture="current", tag_override="other-tag")
    mismatched = seccop_demo._ecr_scan(object(), tmp_path, ecr_scanner="inspector", ecr_fixture="npm-vulnerable", tag_override="demo-current")

    assert arbitrary["reason_code"] == "SECCOP_ECR_EVIDENCE_BLOCKED"
    assert mismatched["reason_code"] == "SECCOP_ECR_EVIDENCE_BLOCKED"


def test_ecr_operator_switches_scan_to_current_after_fix_and_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECCOP_DEMO_BACKEND", "AWS")
    monkeypatch.setenv("SECCOP_ECR_OPERATOR_MVP", "1")
    monkeypatch.setenv("SECCOP_ECR_SCANNER", "inspector")
    monkeypatch.setenv("SECCOP_PROFILE", "amit")
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")
    monkeypatch.delenv("SECCOP_ECR_APP_SERVER", raising=False)
    monkeypatch.setattr(poc_server, "_ECR_APPROVAL_READY", False)
    monkeypatch.setattr(poc_server, "_ECR_SCAN_TAG_OVERRIDE", None)
    captured: list[list[str]] = []

    def fake_run(args: list[str], **_: object) -> SimpleNamespace:
        captured.append(args)
        command = next(item for item in ("ecr-scan", "ecr-fix", "ecr-reset") if item in args)
        payload = {
            "ecr-scan": {"status": "READY", "reason_code": "SECCOP_ECR_NON_COMPLIANT"},
            "ecr-fix": {"status": "VERIFIED", "reason_code": "SECCOP_ECR_PROMOTION_VERIFIED"},
            "ecr-reset": {"status": "READY", "reason_code": "SECCOP_ECR_REOPEN_READY"},
        }[command]
        return SimpleNamespace(stdout=json.dumps(payload))

    monkeypatch.setattr(poc_server.subprocess, "run", fake_run)
    assert poc_server._run_real_demo("scan")["reason_code"] == "SECCOP_ECR_NON_COMPLIANT"
    monkeypatch.setattr(poc_server, "_ECR_APPROVAL_READY", True)
    assert poc_server._run_real_demo("fix", source="ecr")["status"] == "VERIFIED"
    assert poc_server._run_real_demo("scan")["status"] == "READY"
    assert captured[-1][captured[-1].index("--ecr-tag-override") + 1] == "demo-current"
    assert poc_server._run_real_demo("reset")["status"] == "READY"
    assert poc_server._run_real_demo("scan")["status"] == "READY"
    assert captured[-1][captured[-1].index("--ecr-tag-override") + 1] == "demo-current"


def test_ecr_operator_api_passes_explicit_scanner_without_running_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECCOP_DEMO_BACKEND", "AWS")
    monkeypatch.setenv("SECCOP_ECR_OPERATOR_MVP", "1")
    monkeypatch.setenv("SECCOP_ECR_SCANNER", "inspector")
    monkeypatch.setenv("SECCOP_PROFILE", "amit")
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")
    captured: list[list[str]] = []

    def fake_run(args: list[str], **_: object) -> SimpleNamespace:
        captured.append(args)
        return SimpleNamespace(stdout=json.dumps({"status": "READY", "reason_code": "SECCOP_ECR_NON_COMPLIANT"}))

    monkeypatch.setattr(poc_server.subprocess, "run", fake_run)
    result = poc_server._run_real_demo("scan")

    assert result["reason_code"] == "SECCOP_ECR_NON_COMPLIANT"
    assert captured[0][captured[0].index("--ecr-scanner") + 1] == "inspector"


def test_legacy_live_entrypoint_requires_explicit_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECCOP_DEMO_BACKEND", "AWS")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("SECCOP_PROFILE", raising=False)
    monkeypatch.setattr(poc_server.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("profile gate must run before subprocess"))

    result = poc_server._run_real_demo("scan")

    assert result["reason_code"] == "AWS_PROFILE_REQUIRED"


def test_ecr_compliant_rescan_skips_codex_before_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECCOP_DEMO_BACKEND", "AWS")
    monkeypatch.setenv("SECCOP_ECR_OPERATOR_MVP", "1")
    monkeypatch.setenv("SECCOP_ECR_SCANNER", "inspector")
    monkeypatch.setenv("SECCOP_PROFILE", "amit")
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")
    monkeypatch.setenv("SECCOP_ECR_APP_SERVER", "1")
    monkeypatch.setattr(poc_server.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=json.dumps({"status": "NO_FINDINGS", "reason_code": "SECCOP_ECR_COMPLIANT"})))
    monkeypatch.setattr(poc_server, "_start_ecr_codex_explanation", lambda *_args: pytest.fail("compliant rescan must not start Codex BEFORE"))

    result = poc_server._run_real_demo("scan", source="ecr")

    assert result["reason_code"] == "SECCOP_ECR_COMPLIANT"
    assert "agent" not in result


def test_ec2_operator_uses_explicit_read_only_profile_in_combined_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECCOP_DEMO_BACKEND", "AWS")
    monkeypatch.setenv("SECCOP_ECR_S3_COMBINED", "1")
    monkeypatch.setenv("SECCOP_ECR_OPERATOR_MVP", "1")
    monkeypatch.setenv("SECCOP_S3_COMPLIANCE_E2E", "1")
    monkeypatch.setenv("SECCOP_EC2_IMDSV2_E2E", "1")
    monkeypatch.setenv("SECCOP_PROFILE", "amit")
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")
    monkeypatch.setenv("SECCOP_EC2_PROFILE", "ihis_dev")
    monkeypatch.setenv("SECCOP_EC2_REGION", "ap-southeast-1")
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> SimpleNamespace:
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return SimpleNamespace(stdout=json.dumps({
            "status": "COMPLIANT",
            "reason_code": "SECCOP_EC2_IMDSV2_COMPLIANT",
            "findings": [],
        }))

    monkeypatch.setattr(poc_server.subprocess, "run", fake_run)
    result = poc_server._run_real_demo("scan", source="ec2")

    assert result["reason_code"] == "SECCOP_EC2_IMDSV2_COMPLIANT"
    args = captured["args"]
    env = captured["env"]
    assert isinstance(args, list)
    assert args[args.index("--profile") + 1] == "ihis_dev"
    assert args[args.index("--region") + 1] == "ap-southeast-1"
    assert isinstance(env, dict)
    assert env["AWS_PROFILE"] == "ihis_dev"
    assert env["SECCOP_PROFILE"] == "ihis_dev"


def test_combined_health_mode_advertises_all_three_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SECCOP_ECR_S3_COMBINED", "SECCOP_ECR_OPERATOR_MVP", "SECCOP_S3_COMPLIANCE_E2E", "SECCOP_EC2_IMDSV2_E2E"):
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("SECCOP_DEMO_BACKEND", "AWS")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.loads(urlopen(f"http://127.0.0.1:{server.server_port}/api/health").read())
        assert payload["review_mode"] == "ECR_S3_EC2_COMBINED"
        assert payload["enabled_sources"] == ["ec2", "ecr", "s3"]
    finally:
        server.shutdown()


def _complete_unified_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, str]:
    evidence_dir = tmp_path / "s3-evidence"
    evidence_dir.mkdir(mode=0o700)
    state_path = tmp_path / "s3-state.json"
    state_path.write_text(json.dumps({
        "bucket": "S3_DRIFT_ALIAS",
        "automatic": False,
        "config_rule_name": "s3-bucket-level-public-access-prohibited",
        "config_source": "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
        "remediation_document": "AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock",
        "remediation_document_version": "8",
        "resource_type": "AWS::S3::Bucket",
    }), encoding="utf-8")
    state_path.chmod(0o600)
    map_path = tmp_path / "ec2-lab01-map.json"
    map_path.write_text(json.dumps({
        "profile": "ihis_dev",
        "region": "ap-southeast-1",
        "DEV_EC2_LAB_01": "i-" + "0" * 8,
    }), encoding="utf-8")
    map_path.chmod(0o600)
    settings = {
        "SECCOP_DEMO_BACKEND": "AWS",
        "SECCOP_ECR_S3_COMBINED": "1",
        "SECCOP_ECR_OPERATOR_MVP": "1",
        "SECCOP_ECR_APP_SERVER": "1",
        "SECCOP_ECR_SCANNER": "inspector",
        "SECCOP_S3_COMPLIANCE_E2E": "1",
        "SECCOP_EC2_IMDSV2_E2E": "1",
        "SECCOP_EC2_RND_REARM": "1",
        "SECCOP_PROFILE": "amit",
        "AWS_PROFILE": "amit",
        "AWS_DEFAULT_PROFILE": "amit",
        "AWS_REGION": "ap-southeast-1",
        "AWS_DEFAULT_REGION": "ap-southeast-1",
        "SECCOP_EC2_PROFILE": "ihis_dev",
        "SECCOP_EC2_REGION": "ap-southeast-1",
        "SECCOP_S3_BUCKET": "S3_DRIFT_ALIAS",
        "SECCOP_S3_EVIDENCE_DIR": str(evidence_dir),
        "SECCOP_S3_PROTECTED_BUCKETS": "S3_PROTECTED_01,S3_PROTECTED_02",
        "SECCOP_S3_STATE": str(state_path),
        "SECCOP_EC2_RND_TARGET_MAP": str(map_path),
    }
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    return settings


def test_unified_runtime_preflight_requires_all_source_bindings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    settings = _complete_unified_runtime(monkeypatch, tmp_path)

    poc_server._validate_unified_runtime()

    monkeypatch.delenv("SECCOP_S3_STATE")
    with pytest.raises(RuntimeError, match="RUNTIME_CONFIG_INVALID:SECCOP_S3_STATE"):
        poc_server._validate_unified_runtime()
    monkeypatch.setenv("SECCOP_S3_STATE", settings["SECCOP_S3_STATE"])
    monkeypatch.delenv("SECCOP_ECR_SCANNER")
    with pytest.raises(RuntimeError, match="RUNTIME_CONFIG_INVALID:SECCOP_ECR_SCANNER"):
        poc_server._validate_unified_runtime()
    monkeypatch.setenv("SECCOP_ECR_SCANNER", settings["SECCOP_ECR_SCANNER"])
    monkeypatch.delenv("SECCOP_ECR_APP_SERVER")
    with pytest.raises(RuntimeError, match="RUNTIME_CONFIG_INVALID:SECCOP_ECR_APP_SERVER"):
        poc_server._validate_unified_runtime()
    monkeypatch.setenv("SECCOP_ECR_APP_SERVER", settings["SECCOP_ECR_APP_SERVER"])
    monkeypatch.delenv("SECCOP_S3_EVIDENCE_DIR")
    with pytest.raises(RuntimeError, match="RUNTIME_CONFIG_INVALID:SECCOP_S3_EVIDENCE_DIR"):
        poc_server._validate_unified_runtime()
    monkeypatch.setenv("SECCOP_S3_EVIDENCE_DIR", settings["SECCOP_S3_EVIDENCE_DIR"])
    Path(settings["SECCOP_S3_EVIDENCE_DIR"]).chmod(0o755)
    with pytest.raises(RuntimeError, match="RUNTIME_CONFIG_INVALID:SECCOP_S3_EVIDENCE_DIR"):
        poc_server._validate_unified_runtime()
    Path(settings["SECCOP_S3_EVIDENCE_DIR"]).chmod(0o700)
    monkeypatch.delenv("SECCOP_EC2_RND_TARGET_MAP")
    with pytest.raises(RuntimeError, match="RUNTIME_CONFIG_INVALID:SECCOP_EC2_RND_TARGET_MAP"):
        poc_server._validate_unified_runtime()


def test_unified_runtime_launcher_check_uses_fixed_port(tmp_path: Path) -> None:
    class _Env:
        def setenv(self, name: str, value: str) -> None:
            os.environ[name] = value

    original = os.environ.copy()
    try:
        settings = _complete_unified_runtime(_Env(), tmp_path)
        config_path = tmp_path / "runtime.env"
        config_path.write_text("\n".join(f"{name}={value}" for name, value in settings.items()) + "\n", encoding="utf-8")
        config_path.chmod(0o600)
        script = Path(__file__).parents[1] / "scripts" / "start-unified-seccop.sh"
        result = subprocess.run(
            [str(script), "--check"],
            cwd=script.parents[1],
            env={
                **os.environ,
                "POC_PORT": "9999",
                "SECCOP_RUNTIME_ENV": str(config_path),
                "SECCOP_PYTHON": sys.executable,
            },
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "SECCOP_RUNTIME_READY POC_PORT=2222"
    finally:
        os.environ.clear()
        os.environ.update(original)


def test_unified_runtime_launcher_rejects_non_600_runtime_file(tmp_path: Path) -> None:
    class _Env:
        def setenv(self, name: str, value: str) -> None:
            os.environ[name] = value

    original = os.environ.copy()
    try:
        settings = _complete_unified_runtime(_Env(), tmp_path)
        config_path = tmp_path / "runtime.env"
        config_path.write_text("\n".join(f"{name}={value}" for name, value in settings.items()) + "\n", encoding="utf-8")
        config_path.chmod(0o200)
        script = Path(__file__).parents[1] / "scripts" / "start-unified-seccop.sh"
        result = subprocess.run(
            [str(script), "--check"],
            cwd=script.parents[1],
            env={
                **os.environ,
                "SECCOP_RUNTIME_ENV": str(config_path),
                "SECCOP_PYTHON": sys.executable,
            },
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 2
        assert result.stderr.strip() == "RUNTIME_CONFIG_INVALID:SECCOP_RUNTIME_ENV"
    finally:
        os.environ.clear()
        os.environ.update(original)


def test_unified_runtime_launcher_ignores_inherited_missing_required_value(tmp_path: Path) -> None:
    class _Env:
        def setenv(self, name: str, value: str) -> None:
            os.environ[name] = value

    original = os.environ.copy()
    try:
        settings = _complete_unified_runtime(_Env(), tmp_path)
        config_path = tmp_path / "runtime.env"
        config_path.write_text(
            "\n".join(
                f"{name}={value}"
                for name, value in settings.items()
                if name != "SECCOP_ECR_APP_SERVER"
            ) + "\n",
            encoding="utf-8",
        )
        config_path.chmod(0o600)
        script = Path(__file__).parents[1] / "scripts" / "start-unified-seccop.sh"
        result = subprocess.run(
            [str(script), "--check"],
            cwd=script.parents[1],
            env={
                **os.environ,
                "SECCOP_RUNTIME_ENV": str(config_path),
                "SECCOP_PYTHON": sys.executable,
                "SECCOP_ECR_APP_SERVER": "1",
            },
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 2
        assert result.stderr.strip() == "RUNTIME_CONFIG_INVALID:SECCOP_ECR_APP_SERVER"
    finally:
        os.environ.clear()
        os.environ.update(original)


def test_ec2_rnd_route_is_fixed_lab01_with_reject_then_approved_remediation(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {
        "SECCOP_DEMO_BACKEND": "AWS",
        "SECCOP_ECR_S3_COMBINED": "1",
        "SECCOP_EC2_IMDSV2_E2E": "1",
        "SECCOP_EC2_RND_REARM": "1",
        "SECCOP_EC2_PROFILE": "ihis_dev",
        "SECCOP_EC2_REGION": "ap-southeast-1",
    }.items():
        monkeypatch.setenv(name, value)
    poc_server._EC2_PROPOSALS.clear()
    captured: list[list[str]] = []

    def fake_run(args: list[str], **_: object) -> SimpleNamespace:
        captured.append(args)
        command = next(item for item in ("ec2-rnd-scan", "ec2-rnd-reject", "ec2-rnd-apply", "ec2-rnd-reopen") if item in args)
        payload = {
            "ec2-rnd-scan": {
                "status": "READY",
                "reason_code": "SECCOP_EC2_IMDSV2_NON_COMPLIANT",
                "state": "NON_COMPLIANT",
                "resource_alias": "DEV_EC2_LAB_01",
                "config_rule_name": "ec2-imdsv2-check-rnd-lab01",
                "findings": [],
            },
            "ec2-rnd-reject": {
                "status": "REJECTED",
                "reason_code": "HUMAN_REJECTED",
                "state": "NON_COMPLIANT",
                "resource_alias": "DEV_EC2_LAB_01",
                "mutation_performed": False,
            },
            "ec2-rnd-apply": {
                "status": "VERIFIED",
                "reason_code": "SECCOP_EC2_IMDSV2_REMEDIATED",
                "state": "COMPLIANT",
                "resource_alias": "DEV_EC2_LAB_01",
                "metadata_http_tokens": "required",
                "automation_status": "Success",
            },
            "ec2-rnd-reopen": {
                "status": "READY",
                "reason_code": "SECCOP_EC2_IMDSV2_NON_COMPLIANT",
                "state": "NON_COMPLIANT",
                "resource_alias": "DEV_EC2_LAB_01",
                "config_rule_name": "ec2-imdsv2-check-rnd-lab01",
                "findings": [],
                "reopen_status": "REOPENED",
                "mutation_performed": True,
            },
        }[command]
        return SimpleNamespace(stdout=json.dumps(payload))

    monkeypatch.setattr(poc_server.subprocess, "run", fake_run)
    scan = poc_server._run_real_demo("scan", source="ec2")
    assert scan["reason_code"] == "SECCOP_EC2_IMDSV2_NON_COMPLIANT"
    assert captured[0][captured[0].index("--alias") + 1] == "DEV_EC2_LAB_01"
    rejected = poc_server._run_real_demo("reject", source="ec2", proposal_id=scan["proposal_id"], proposal_hash=scan["proposal_hash"])
    assert rejected["reason_code"] == "HUMAN_REJECTED"
    assert rejected["mutation_performed"] is False
    replay = poc_server._run_real_demo("fix", source="ec2", proposal_id=scan["proposal_id"], proposal_hash=scan["proposal_hash"])
    assert replay["reason_code"] == "APPROVAL_REQUIRED"
    fresh = poc_server._run_real_demo("scan", source="ec2")
    verified = poc_server._run_real_demo("fix", source="ec2", proposal_id=fresh["proposal_id"], proposal_hash=fresh["proposal_hash"])
    assert verified["reason_code"] == "SECCOP_EC2_IMDSV2_REMEDIATED"
    assert verified["metadata_http_tokens"] == "required"
    assert captured[-1][captured[-1].index("--alias") + 1] == "DEV_EC2_LAB_01"
    assert captured[-1][-1] == "--confirm"
    reopened = poc_server._run_real_demo("reset", source="ec2")
    assert reopened["reason_code"] == "SECCOP_EC2_IMDSV2_NON_COMPLIANT"
    assert reopened["reopen_status"] == "REOPENED"
    assert "proposal_id" in reopened
    blocked = poc_server._run_real_demo("scan", source="ec2", target_alias="DEV_EC2_UNAPPROVED")
    assert blocked["reason_code"] == "TARGET_NOT_ALLOWED"


def test_ec2_rnd_reopen_already_open_skips_config_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    target = {"MetadataOptions": {"HttpTokens": "optional"}}
    rule = {"Scope": {"ComplianceResourceId": "EC2_RESOURCE_01"}, "Source": {"SourceIdentifier": issue47.EC2_CONFIG_SOURCE}, "ConfigRuleState": "ACTIVE"}
    monkeypatch.setattr(issue47, "_ec2_rnd_target", lambda *_: ("EC2_RESOURCE_01", target))
    monkeypatch.setattr(issue47, "_ec2_rnd_binding", lambda *_: rule)
    monkeypatch.setattr(issue47, "_ec2_rnd_current_compliance", lambda *_: "NON_COMPLIANT")
    monkeypatch.setattr(issue47, "_ec2_rnd_compliance", lambda *_: pytest.fail("Config evaluation must not run when the finding is open"))

    result = issue47._ec2_rnd_reopen("ihis_dev", "ap-southeast-1", issue47.EC2_RND_ALIAS_LAB01, True)

    assert result["reason_code"] == "FINDING_ALREADY_OPEN"
    assert result["mutation_performed"] is False


def test_ecr_reopen_is_idempotent_when_the_finding_is_already_open(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(seccop_demo, "_ecr_scan", lambda *_: {"reason_code": "SECCOP_ECR_NON_COMPLIANT"})
    monkeypatch.setattr(seccop_demo, "_push_image", lambda *_: pytest.fail("unexpected ECR mutation"))

    result = seccop_demo._ecr_reset(object(), tmp_path)

    assert result["reason_code"] == "SECCOP_ECR_REOPEN_READY"


def test_browser_has_persistent_ecr_reopen_control() -> None:
    html = (Path(__file__).parents[1] / "web" / "poc_chat.html").read_text()

    assert "configureEcrReview" in html
    assert "Scan ECR image" in html
    assert "Reopen this ECR finding?" in html
    assert "ECR_OPERATOR" in Path(__file__).parents[1].joinpath("src/secure_agent_harness/poc_server.py").read_text()


def test_browser_uses_clean_verification_copy_for_compliant_ecr_rescan() -> None:
    html = (Path(__file__).parents[1] / "web" / "poc_chat.html").read_text()

    assert "result.status === 'NO_FINDINGS' && result.state === 'COMPLIANT'" in html
    assert "Clean verification" in html
    assert "Amazon Inspector verified the approved ECR digest is clean." in html
    assert "No active package findings were returned for the approved ECR digest." in html
    assert "ECR_CODEX_BEFORE_READY" not in html
    assert "sanitized BEFORE facts" not in html


def test_browser_source_composer_forwards_questions_without_rescanning() -> None:
    html = (Path(__file__).parents[1] / "web" / "poc_chat.html").read_text()

    form_handler = html.split("form.addEventListener('submit'", 1)[1].split("newChat.addEventListener", 1)[0]
    assert "await askSecCop(prompt)" in form_handler
    assert "/api/ask" in html
    assert "if (ecrReview || s3Review) { startScan(runButton); return; }" not in html
    assert "ECR promotion blocked" in html
    assert 'id="codex-status"' in html
    assert "/api/codex-status" in html
    assert "void refreshCodexStatus();" in html
    assert "async function resetCodexInvestigation()" in html
    assert "/api/codex-reset" in html
    assert "if (!await resetCodexInvestigation()) return;" in html
    assert "await refreshCodexStatus();" in html


def test_browser_sidebar_and_composer_management_view() -> None:
    html = (Path(__file__).parents[1] / "web" / "poc_chat.html").read_text()

    assert "Technical evidence fallback" not in html
    assert "AI USAGE" not in html
    assert 'id="composer-wrap" class="composer-wrap hidden"' in html
    assert 'id="toggle-composer" class="btn primary"' in html
    assert "Show Ask SecCop" in html
    assert "Hide Ask SecCop" in html
    assert "aria-expanded" in html
    assert "advisory-upload" in html and "scan-environment" in html
    assert "function configureEcrReview(" in html
    assert "function configureS3Review(" in html
    assert "ECR_S3_EC2_COMBINED" in html
    assert "DEV_EC2_LAB_01" in html
    assert "fixed LAB_01 still accepts IMDSv1" in html
    assert "id=\"reopen-s3-finding\"" in html
    assert "RND_REOPEN_REQUIRED" not in html
    ec2_view = html.split("function configureEc2Review", 1)[1].split("function configureUnifiedReview", 1)[0]
    assert "reopenS3FindingButton.hidden = false" in ec2_view
    assert "reopenS3FindingButton.textContent = 'Reopen Finding'" in ec2_view
    assert "ec2ReopenReady" not in html
    assert "The approved DEMO reset was blocked." not in html
    assert "Reopen fixed DEV_EC2_LAB_01?" in html
    assert "FINDING_ALREADY_OPEN" in html
    for control_id in ("scan-environment", "reopen-s3-finding", "start-real-demo", "advisory-upload", "compare-live", "csv-upload", "compare-csv"):
        assert f'id="{control_id}"' in html
    assert '<div class="live-panel hidden" aria-hidden="true" hidden>' in html
    assert '<div id="backend-note" class="side-footer hidden" aria-hidden="true" hidden></div>' in html
    assert 'id="mode-status" class="status-pill"' not in html
    assert 'welcome-mark' not in html
    assert "ECR Vulnerability Scanning Review" in html
    assert "ECR Operator Review" not in html
    assert "ECR + S3 + EC2 review" not in html
    assert "toggleComposerButton.classList.remove('hidden')" in html


def test_lab01_cli_has_private_self_service_mapping_diagnostic() -> None:
    script = (Path(__file__).parents[1] / "scripts" / "ec2-lab01-kiss.sh").read_text()

    assert "configure --instance-id <id>" in script
    assert "public example placeholder" in script
    assert "mapping instance is invalid" not in script
    assert "status|reset --confirm|reopen --confirm" in script


def test_live_evidence_upload_validates_without_echoing_untrusted_payload() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(
            f"http://127.0.0.1:{server.server_port}/api/live-evidence",
            data=json.dumps(
                {
                    "status": "BLOCKED",
                    "reason_code": "REQUEST_REJECTED",
                    "cve_id": "CVE-2099-0001",
                    "resource_alias": "EC2_RESOURCE_01",
                    "message": "safe",
                    "unexpected": "attacker-controlled payload",
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urlopen(request)
        except HTTPError as error:
            body = error.read().decode()
            assert error.code == 400
            assert "attacker-controlled payload" not in body
            assert "REQUEST_REJECTED" in body
        else:
            raise AssertionError("malformed evidence upload unexpectedly passed")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_live_csv_blocks_target_mismatch_without_calling_aws() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(
            f"http://127.0.0.1:{server.server_port}/api/live-csv",
            data=json.dumps(
                {
                    "csv_text": (
                        "instance_id,cve_id,severity,package_name,installed_version,fixed_version,status\n"
                        "i-0123456789abcdef0,CVE-2026-0001,HIGH,kernel,1.0,1.1,ACTIVE\n"
                    ),
                    "instance_id": "i-aaaaaaaaaaaaaaaaa",
                    "cve_id": "CVE-2026-0001",
                    "region": "ap-southeast-1",
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        payload = json.loads(urlopen(request).read().decode())
        assert payload["result"]["status"] == "BLOCKED"
        assert payload["result"]["reason_code"] == "CSV_TARGET_MISMATCH"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _ready_live_result() -> AwsReadOnlyResult:
    return AwsReadOnlyResult(
        status="READY",
        reason_code="READ_ONLY_EVIDENCE_READY",
        cve_id="CVE-2026-0001",
        resource_alias="EC2_RESOURCE_01",
        evidence=AwsReadOnlyEvidence(
            source="AWS_READ_ONLY",
            cve_id="CVE-2026-0001",
            resource_alias="EC2_RESOURCE_01",
            finding_count=1,
            finding_state="ACTIVE",
            finding_severity="HIGH",
            finding_ec2_bound=True,
            instance_state="RUNNING",
            expected_tags_verified=True,
            ssm_managed=True,
            ssm_readiness="READY",
            checks=(),
            executed_calls=(
                "inspector.list_findings",
                "ec2.describe_instances",
                "ssm.describe_instance_information",
            ),
        ),
        executed_calls=(
            "inspector.list_findings",
            "ec2.describe_instances",
            "ssm.describe_instance_information",
        ),
        message="ready",
    )


def test_live_proposal_is_typed_and_has_no_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(poc_server, "collect_live_evidence", lambda **_: _ready_live_result())
    request = SecCopCsvRequest(
        csv_text=(
            "instance_id,cve_id,severity,package_name,installed_version,fixed_version,status\n"
            "i-0123456789abcdef0,CVE-2026-0001,HIGH,kernel,1.0,1.1,ACTIVE\n"
        ),
        instance_id="i-0123456789abcdef0",
        cve_id="CVE-2026-0001",
        region="ap-southeast-1",
    )

    proposal = poc_server._live_proposal(request)

    assert proposal.status == "READY"
    assert proposal.reason_code == "SECCOP_REMEDIATION_PROPOSAL_READY"
    assert proposal.action == "SSM_INSTALL_SECURITY_UPDATE"
    assert proposal.requires_approval is True
    assert proposal.mutation_performed is False
    assert proposal.resource_alias == "EC2_RESOURCE_01"
    assert "i-0123456789abcdef0" not in proposal.model_dump_json()


def test_live_proposal_blocks_ambiguous_csv_before_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fail_if_called(**_: object) -> AwsReadOnlyResult:
        calls.append("aws")
        return _ready_live_result()

    monkeypatch.setattr(poc_server, "collect_live_evidence", fail_if_called)
    request = SecCopCsvRequest(
        csv_text=(
            "instance_id,cve_id,severity,package_name,installed_version,fixed_version,status\n"
            "i-0123456789abcdef0,CVE-2026-0001,HIGH,kernel,1.0,1.1,ACTIVE\n"
            "i-0123456789abcdef0,CVE-2026-0001,HIGH,openssl,2.0,2.1,ACTIVE\n"
        ),
        instance_id="i-0123456789abcdef0",
        cve_id="CVE-2026-0001",
        region="ap-southeast-1",
    )

    proposal = poc_server._live_proposal(request)

    assert proposal.status == "BLOCKED"
    assert proposal.reason_code == "CSV_MATCH_AMBIGUOUS"
    assert calls == []
