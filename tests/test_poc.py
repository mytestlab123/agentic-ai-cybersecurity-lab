from pathlib import Path
import json
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from pydantic import ValidationError

from secure_agent_harness.contracts import (
    AwsReadOnlyEvidence,
    AwsReadOnlyResult,
    PocRequest,
    SecCopCsvRequest,
    SecCopDecisionRequest,
    SecCopRemediationRequest,
)
from secure_agent_harness.poc import PocEngine
from secure_agent_harness import aws_remediation
from secure_agent_harness import poc_server
from secure_agent_harness.poc_server import _Handler
from secure_agent_harness.seccop_scan import review_demo_cve
from http.server import ThreadingHTTPServer


def _request(cve_id: str = "CVE-2099-0001") -> PocRequest:
    return PocRequest(cve_id=cve_id, lab_env="SYNTHETIC_LAB")


def test_poc_emits_read_only_activity_and_waits_for_approval() -> None:
    session = PocEngine().start(_request())

    assert session.result.status == "AWAITING_APPROVAL"
    assert session.result.reason_code == "APPROVAL_REQUIRED"
    assert session.result.evidence.resource_alias == "EC2_RESOURCE_01"
    assert session.result.evidence.patch_state == "MISSING"
    assert session.result.proposal.mutation_performed is False
    assert session.result.proposal.ssm_document == "AWS-RunShellScript"
    assert session.result.proposal.ssm_operation == "REPO_OWNED_ONE_PACKAGE_UPDATE"
    assert session.result.proposal.reboot_option == "NoReboot"
    assert session.result.proposal.approval_state == "AWAITING_APPROVAL"
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


def test_mock_golden_path_denies_bypass_and_keeps_ssm_success_pending() -> None:
    engine = PocEngine()
    session = engine.start(_request())

    bypass = engine.verify(session.result.run_id)

    assert bypass.status == "BLOCKED"
    assert bypass.reason_code == "APPROVAL_BYPASS_DENIED"
    assert bypass.ssm_status == "NOT_RUN"
    assert bypass.mutation_performed is False

    engine.decide(session.result.run_id, approve=True)
    pending = engine.verify(session.result.run_id)

    assert pending.status == "COMPLETED"
    assert pending.ssm_status == "SUCCESS"
    assert pending.package_state == "FIXED"
    assert pending.inspector_state == "ACTIVE"
    assert pending.verification_status == "PENDING_RESCAN"
    assert pending.mutation_performed is False


def test_browser_requests_cannot_supply_binding_hash_or_ssm_authority() -> None:
    with pytest.raises(ValidationError):
        SecCopDecisionRequest(
            proposal_id="SECCOP_PROPOSAL_01",
            decision="APPROVE",
            proposal_hash="a" * 64,
        )

    with pytest.raises(ValidationError):
        SecCopRemediationRequest(
            proposal_id="SECCOP_PROPOSAL_01",
            reboot_approved=False,
            document_name="AWS-RunShellScript",
        )


def test_allowlisted_ssm_adapter_owns_document_and_command() -> None:
    class FakeCli:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, dict[str, object]]] = []

        def call(self, service: str, operation: str, payload: dict[str, object]) -> dict[str, object]:
            self.calls.append((service, operation, payload))
            return {"Command": {"CommandId": "COMMAND_01"}}

    cli = FakeCli()
    command = aws_remediation._install_command(aws_remediation._package_target("demo-package", "1.1.0"))
    payload = aws_remediation._render_remote_payload(command)

    command_id = aws_remediation._send(
        cli,
        instance_id="INSTANCE_01",
        command=payload,
        comment="bounded test",
    )

    assert command_id == "COMMAND_01"
    assert cli.calls == [
        (
            "ssm",
            "send-command",
            {
                "DocumentName": "AWS-RunShellScript",
                "InstanceIds": ["INSTANCE_01"],
                "Parameters": {"commands": [payload]},
                "Comment": "bounded test",
            },
        )
    ]
    assert "/usr/bin/bash -n" in payload
    assert "/usr/bin/bash \"$script_path\"" in payload
    assert "sha256sum -c" in payload
    with pytest.raises(aws_remediation.AwsRemediationBackendError):
        aws_remediation._package_target("demo-package;uname", "1.1.0")


def test_ssm_success_alone_never_marks_inspector_verified() -> None:
    assert poc_server._closure_outcome(inspector_resolved=False) == (
        "SSM_REMEDIATION_PENDING_RESCAN",
        "PENDING_RESCAN",
    )
    assert poc_server._closure_outcome(inspector_resolved=True) == (
        "SSM_REMEDIATION_VERIFIED",
        "VERIFIED",
    )


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
    assert "/api/cve-review" in html
    assert "Check a CVE" in html
    assert "Scan environment" in html
    assert "Suggested fix only" in html
    assert "/api/live-proposal" in html
    assert "/api/live-decision" in html
    assert "/api/mock-verification" in html
    assert "Upload read-only evidence" in html
    assert "Approve mock remediation" in html
    assert "Generate remediation suggestion" in html
    assert "GovTech inference: not used" in html
    assert "Reject" in html
    assert "A server change always needs a separate review and approval" in html


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
    assert proposal.ssm_document == "AWS-RunShellScript"
    assert proposal.ssm_operation == "REPO_OWNED_ONE_PACKAGE_UPDATE"
    assert proposal.reboot_option == "NoReboot"
    assert proposal.reboot_policy == "NO_REBOOT"
    assert proposal.approval_state == "AWAITING_APPROVAL"
    assert proposal.requires_approval is True
    assert proposal.mutation_performed is False
    assert proposal.resource_alias == "EC2_RESOURCE_01"
    assert "proposal_hash" not in proposal.model_dump()
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
