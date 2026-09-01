from pathlib import Path
import json
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
    _run_codex_preflight,
)
from secure_agent_harness.seccop_scan import review_demo_cve
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import seccop_demo  # noqa: E402


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
    assert "GovTech inference: not used" in html
    assert "Reject" in html
    assert "A server change always needs a separate review and approval" in html


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


def test_ecr_operator_maps_inspector_result_and_preserves_trivy_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    inspector_source = {
        "source": "ECR_IMAGE", "alias": "ECR_IMAGE_01", "state": "NON_COMPLIANT",
        "reason_code": "SECCOP_ECR_INSPECTOR_FINDING", "scanner_provider": "AMAZON_INSPECTOR",
        "scanner_mode": "ECR_ENHANCED_SCANNING", "cve_id": seccop_demo.BAD_CVE,
        "package_name": "urllib3", "installed_version": "1.24.1", "severity": "HIGH",
    }
    monkeypatch.setattr(seccop_demo, "_scan_ecr_inspector", lambda *_: inspector_source)
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
