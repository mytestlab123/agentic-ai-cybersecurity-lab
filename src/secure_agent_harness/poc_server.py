"""Small dependency-free local web server for the Issue 5 visual proof."""

import json
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .aws_live import (
    AwsLiveBackendError,
    AwsLiveTargetError,
    collect_live_evidence,
    collect_target_readiness,
    resolve_demo_target,
)
from .aws_remediation import collect_package_advisory, execute_package_remediation
from .contracts import (
    AwsReadOnlyResult,
    PocRequest,
    SecCopApprovalResult,
    SecCopComparison,
    SecCopCveReviewRequest,
    SecCopAdvisoryComparison,
    SecCopAdvisoryRequest,
    SecCopCsvRequest,
    SecCopScanRequest,
    SecCopRemediationRequest,
    SecCopRemediationProposal,
    SecCopRemediationResult,
)
from .poc import PocEngine
from .seccop_csv import SecCopCsvError, parse_csv
from .seccop_scan import review_demo_cve, run_demo_scan


_HTML_PATH = Path(__file__).resolve().parents[2] / "web" / "poc_chat.html"
_DEMO_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "seccop_demo.py"
_ENGINE = PocEngine()
_SECCOP_PROPOSALS: dict[str, SecCopRemediationProposal] = {}
_SECCOP_REQUESTS: dict[str, SecCopCsvRequest] = {}
_SECCOP_ADVISORIES: dict[str, SecCopAdvisoryRequest] = {}
_SECCOP_TARGET_IDS: dict[str, str] = {}


@dataclass(frozen=True)
class _ApprovalRecord:
    proposal_hash: str
    expires_at: datetime
    consumed: bool = False


_SECCOP_APPROVALS: dict[str, _ApprovalRecord] = {}
_NEXT_PROPOSAL_ID = 1
_APPROVAL_TTL = timedelta(minutes=15)
_ADVISORY_REASON_CODES = {
    "SECCOP_ADVISORY_READY",
    "ADVISORY_INPUT_INVALID",
    "ADVISORY_VERSION_MISMATCH",
    "EC2_TARGET_NOT_FOUND",
    "EC2_TARGET_AMBIGUOUS",
    "EC2_TARGET_NOT_READY",
    "EC2_TAGS_MISMATCH",
    "SSM_NODE_NOT_FOUND",
    "SSM_NODE_NOT_READY",
    "SSM_ADVISORY_NOT_FOUND",
    "SSM_COMMAND_TIMEOUT",
    "AWS_BACKEND_UNAVAILABLE",
}


def _session_payload(session: Any) -> dict[str, object]:
    return {
        "result": session.result.model_dump(mode="json"),
        "events": [event.model_dump(mode="json") for event in session.events],
    }


def _next_proposal_id() -> str:
    global _NEXT_PROPOSAL_ID
    proposal_id = f"SECCOP_PROPOSAL_{_NEXT_PROPOSAL_ID:02d}"
    _NEXT_PROPOSAL_ID += 1
    return proposal_id


def _approval_expiry() -> datetime:
    return datetime.now(timezone.utc) + _APPROVAL_TTL


def _real_demo_enabled() -> bool:
    return os.environ.get("SECCOP_DEMO_BACKEND", "LOCAL").upper() == "AWS"


def _run_real_demo(command: str, *, source: str | None = None) -> dict[str, object]:
    """Run the repo-owned AWS DEMO command and return sanitized JSON only."""

    if not _real_demo_enabled():
        return {
            "status": "BLOCKED",
            "reason_code": "AWS_DEMO_DISABLED",
            "message": "The local server is using synthetic mode. Enable the AWS DEMO backend explicitly.",
        }
    allowed_commands = {"start", "scan", "rescan", "fix"}
    if command not in allowed_commands:
        return {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED", "message": "The DEMO command was not allowed."}
    args = [
        sys.executable,
        str(_DEMO_SCRIPT),
        command,
        "--profile",
        os.environ.get("AWS_PROFILE", os.environ.get("SECCOP_PROFILE", "vagent")),
        "--region",
        os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "ap-southeast-1")),
    ]
    if source is not None:
        args.extend(["--source", source])
    if command in {"start", "fix"}:
        args.append("--confirm")
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return {
            "status": "BLOCKED",
            "reason_code": "AWS_DEMO_COMMAND_UNAVAILABLE",
            "message": "The AWS DEMO command could not be completed.",
        }
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError):
        return {
            "status": "BLOCKED",
            "reason_code": "AWS_DEMO_OUTPUT_INVALID",
            "message": "The AWS DEMO returned invalid output.",
        }
    if not isinstance(payload, dict):
        return {
            "status": "BLOCKED",
            "reason_code": "AWS_DEMO_OUTPUT_INVALID",
            "message": "The AWS DEMO returned an invalid result.",
        }
    if completed.returncode != 0 and payload.get("status") != "BLOCKED":
        return {
            "status": "BLOCKED",
            "reason_code": "AWS_DEMO_COMMAND_FAILED",
            "message": "The AWS DEMO command did not complete.",
        }
    return payload


def _proposal_hash(
    *,
    proposal_id: str,
    request: SecCopCsvRequest | SecCopAdvisoryRequest,
    instance_id: str | None = None,
    cve_id: str,
    resource_alias: str,
    package_name: str | None,
    fixed_version: str | None,
    action: str,
    reboot_policy: str,
    expires_at: datetime,
) -> str:
    binding = {
        "proposal_id": proposal_id,
        "region": request.region,
        "instance_id": instance_id or "TARGET_RESOLVED_SERVER_SIDE",
        "cve_id": cve_id,
        "resource_alias": resource_alias,
        "package_name": package_name,
        "fixed_version": fixed_version,
        "action": action,
        "reboot_policy": reboot_policy,
        "approval_expires_at": expires_at.isoformat(),
    }
    canonical = json.dumps(binding, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verified_package_version(evidence: Any, package_name: str | None) -> str | None:
    if evidence is None or not package_name:
        return None
    for package in getattr(evidence, "packages", ()):
        if getattr(package, "name", None) == package_name:
            return getattr(package, "installed_version", None)
    return None


def _live_proposal(request: SecCopCsvRequest) -> SecCopRemediationProposal:
    """Re-run the read-only gate and derive one exact package proposal."""

    try:
        document = parse_csv(
            request.csv_text,
            instance_id=request.instance_id,
            cve_id=request.cve_id,
            package_name=request.package_name,
        )
    except SecCopCsvError as error:
        return SecCopRemediationProposal(
            proposal_id=_next_proposal_id(),
            status="BLOCKED",
            reason_code=error.reason_code,
            cve_id=request.cve_id,
            resource_alias="EC2_RESOURCE_01",
            severity="UNKNOWN",
            action="NONE",
            reboot_policy="UNKNOWN",
            requires_approval=False,
            mutation_performed=False,
            message="The remediation proposal was blocked by the CSV input contract.",
        )
    if document.match_count != 1:
        return SecCopRemediationProposal(
            proposal_id=_next_proposal_id(),
            status="BLOCKED",
            reason_code="CSV_MATCH_AMBIGUOUS",
            cve_id=request.cve_id,
            resource_alias="EC2_RESOURCE_01",
            severity="UNKNOWN",
            action="NONE",
            reboot_policy="UNKNOWN",
            requires_approval=False,
            mutation_performed=False,
            message="The selected CVE must resolve to exactly one CSV package row.",
        )
    try:
        live_result = collect_live_evidence(
            region=request.region,
            instance_id=request.instance_id,
            cve_id=request.cve_id,
        )
    except (AwsLiveBackendError, OSError, TimeoutError):
        return SecCopRemediationProposal(
            proposal_id=_next_proposal_id(),
            status="BLOCKED",
            reason_code="AWS_BACKEND_UNAVAILABLE",
            cve_id=request.cve_id,
            resource_alias="EC2_RESOURCE_01",
            severity="UNKNOWN",
            action="NONE",
            reboot_policy="UNKNOWN",
            requires_approval=False,
            mutation_performed=False,
            message="The read-only AWS gate could not be completed.",
        )
    if live_result.status != "READY" or live_result.evidence is None:
        return SecCopRemediationProposal(
            proposal_id=_next_proposal_id(),
            status="BLOCKED",
            reason_code="AWS_READ_ONLY_BLOCKED",
            cve_id=request.cve_id,
            resource_alias=live_result.resource_alias,
            severity="UNKNOWN",
            action="NONE",
            reboot_policy="UNKNOWN",
            requires_approval=False,
            mutation_performed=False,
            message="A remediation proposal requires ready read-only AWS evidence.",
        )

    row = document.matching_rows[0]
    proposal_id = _next_proposal_id()
    expires_at = _approval_expiry() if row.fixed_version else None
    action = "SSM_INSTALL_SECURITY_UPDATE" if row.fixed_version else "NONE"
    reboot_policy = "EXPLICIT_APPROVAL_REQUIRED" if row.fixed_version else "UNKNOWN"
    proposal_hash = (
        _proposal_hash(
            proposal_id=proposal_id,
            request=request,
            cve_id=row.cve_id,
            resource_alias=live_result.resource_alias,
            package_name=row.package_name,
            fixed_version=row.fixed_version,
            action=action,
            reboot_policy=reboot_policy,
            expires_at=expires_at,
        )
        if expires_at is not None
        else "0" * 64
    )
    proposal = SecCopRemediationProposal(
        proposal_id=proposal_id,
        status="READY" if row.fixed_version else "BLOCKED",
        reason_code=(
            "SECCOP_REMEDIATION_PROPOSAL_READY"
            if row.fixed_version
            else "NO_FIXED_VERSION"
        ),
        cve_id=row.cve_id,
        resource_alias=live_result.resource_alias,
        severity=row.severity,
        package_name=row.package_name,
        installed_version=row.installed_version,
        fixed_version=row.fixed_version,
        action=action,
        reboot_policy=reboot_policy,
        requires_approval=bool(row.fixed_version),
        mutation_performed=False,
        proposal_hash=proposal_hash,
        approval_expires_at=expires_at,
        read_executed_calls=live_result.evidence.executed_calls,
        message=(
            "A deterministic package-level remediation proposal is ready for human approval."
            if row.fixed_version
            else "The finding has no fixed version in the supplied evidence."
        ),
    )
    if proposal.status == "READY":
        _SECCOP_PROPOSALS[proposal.proposal_id] = proposal
        _SECCOP_REQUESTS[proposal.proposal_id] = request
    return proposal


def _advisory_comparison(request: SecCopAdvisoryRequest) -> SecCopAdvisoryComparison:
    """Run the simple, no-instance-ID read-only journey."""

    fields = {
        "advisory_id": request.advisory_id,
        "cve_id": request.cve_id,
        "target_alias": request.target_alias,
        "package_name": request.package_name,
        "installed_version": request.installed_version,
        "fixed_version": request.fixed_version,
        "severity": request.severity,
        "ssm_readiness": "UNKNOWN",
        "executed_calls": (),
    }
    try:
        target = resolve_demo_target(region=request.region)
    except AwsLiveTargetError as error:
        return SecCopAdvisoryComparison(
            status="BLOCKED",
            reason_code=error.reason_code,
            message="SecCop could not select exactly one live demo server.",
            **fields,
        )
    except (AwsLiveBackendError, OSError, TimeoutError):
        return SecCopAdvisoryComparison(
            status="BLOCKED",
            reason_code="AWS_BACKEND_UNAVAILABLE",
            message="The live AWS check could not be completed.",
            **fields,
        )

    readiness = collect_target_readiness(region=request.region, target=target)
    fields["executed_calls"] = readiness.executed_calls
    fields["ssm_readiness"] = readiness.ssm_readiness
    if readiness.status != "READY":
        reason = readiness.reason_code
        if reason not in _ADVISORY_REASON_CODES:
            reason = "AWS_BACKEND_UNAVAILABLE"
        return SecCopAdvisoryComparison(
            status="BLOCKED",
            reason_code=reason,
            message="The server is not ready for a safe read-only check.",
            **fields,
        )

    advisory = collect_package_advisory(
        region=request.region,
        instance_id=target.instance_id,
        advisory_id=request.advisory_id,
        package_name=request.package_name,
    )
    fields["executed_calls"] = tuple(fields["executed_calls"]) + tuple(
        str(item) for item in advisory.get("executed_calls", ())
    )
    advisory_reason = str(advisory.get("reason_code", "AWS_BACKEND_UNAVAILABLE"))
    if advisory.get("status") != "READY":
        if advisory_reason not in _ADVISORY_REASON_CODES:
            advisory_reason = "AWS_BACKEND_UNAVAILABLE"
        return SecCopAdvisoryComparison(
            status="BLOCKED",
            reason_code=advisory_reason,
            message="The package advisory could not be confirmed on the selected server.",
            **fields,
        )

    actual_version = str(advisory.get("before_version", ""))
    if not actual_version.startswith(request.installed_version):
        return SecCopAdvisoryComparison(
            status="BLOCKED",
            reason_code="ADVISORY_VERSION_MISMATCH",
            message="The uploaded package version does not match the selected server.",
            **fields,
        )
    return SecCopAdvisoryComparison(
        status="READY",
        reason_code="SECCOP_ADVISORY_READY",
        message="The server and one small package advisory are ready for review.",
        **fields,
    )


def _advisory_proposal(request: SecCopAdvisoryRequest) -> SecCopRemediationProposal:
    comparison = _advisory_comparison(request)
    proposal_id = _next_proposal_id()
    if comparison.status != "READY":
        proposal = SecCopRemediationProposal(
            proposal_id=proposal_id,
            status="BLOCKED",
            reason_code=comparison.reason_code,
            cve_id=request.cve_id,
            resource_alias="EC2_RESOURCE_01",
            severity=comparison.severity,
            package_name=request.package_name,
            installed_version=request.installed_version,
            fixed_version=request.fixed_version,
            action="NONE",
            reboot_policy="UNKNOWN",
            requires_approval=False,
            mutation_performed=False,
            message="The live package proposal was blocked by a read-only safety check.",
        )
        return proposal
    try:
        target = resolve_demo_target(region=request.region)
    except (AwsLiveBackendError, AwsLiveTargetError, OSError, TimeoutError):
        return SecCopRemediationProposal(
            proposal_id=proposal_id,
            status="BLOCKED",
            reason_code="AWS_BACKEND_UNAVAILABLE",
            cve_id=request.cve_id,
            resource_alias="EC2_RESOURCE_01",
            severity=request.severity,
            package_name=request.package_name,
            installed_version=request.installed_version,
            fixed_version=request.fixed_version,
            action="NONE",
            reboot_policy="UNKNOWN",
            requires_approval=False,
            mutation_performed=False,
            message="The live target could not be reselected safely.",
        )
    expires_at = _approval_expiry()
    proposal_hash = _proposal_hash(
        proposal_id=proposal_id,
        request=request,
        instance_id=target.instance_id,
        cve_id=request.cve_id,
        resource_alias="EC2_RESOURCE_01",
        package_name=request.package_name,
        fixed_version=request.fixed_version,
        action="SSM_INSTALL_SECURITY_UPDATE",
        reboot_policy="EXPLICIT_APPROVAL_REQUIRED",
        expires_at=expires_at,
    )
    proposal = SecCopRemediationProposal(
        proposal_id=proposal_id,
        status="READY",
        reason_code="SECCOP_ADVISORY_READY",
        cve_id=request.cve_id,
        resource_alias="EC2_RESOURCE_01",
        severity=request.severity,
        package_name=request.package_name,
        installed_version=request.installed_version,
        fixed_version=request.fixed_version,
        action="SSM_INSTALL_SECURITY_UPDATE",
        reboot_policy="EXPLICIT_APPROVAL_REQUIRED",
        requires_approval=True,
        mutation_performed=False,
        proposal_hash=proposal_hash,
        approval_expires_at=expires_at,
        read_executed_calls=comparison.executed_calls,
        message="A one-package fix is ready. Approve once to update the server; no reboot will be requested.",
    )
    _SECCOP_PROPOSALS[proposal_id] = proposal
    _SECCOP_ADVISORIES[proposal_id] = request
    _SECCOP_TARGET_IDS[proposal_id] = target.instance_id
    return proposal


class _Handler(BaseHTTPRequestHandler):
    server_version = "secure-agent-poc/1.0"

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, object] | None:
        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            return None
        # CSV uploads are bounded by SecCopCsvRequest at 500 KiB. Keep the
        # transport cap slightly above that contract while rejecting floods.
        if length < 0 or length > 600_000:
            return None
        try:
            payload = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/api/health":
            self._send_json(
                200,
                {
                    "status": "OK",
                    "mode": "AWS_DEMO" if _real_demo_enabled() else "LOCAL_SYNTHETIC",
                    "demo_backend": "AWS" if _real_demo_enabled() else "LOCAL",
                },
            )
            return
        if self.path != "/":
            self._send_json(404, {"status": "BLOCKED", "reason_code": "NOT_FOUND"})
            return
        try:
            body = _HTML_PATH.read_bytes()
        except OSError:
            self._send_json(500, {"status": "FAILED", "reason_code": "UI_ASSET_MISSING"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        payload = self._read_json()
        if payload is None:
            self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
            return

        if self.path == "/api/run":
            try:
                request = PocRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            session = _ENGINE.start(request)
            self._send_json(200, _session_payload(session))
            return

        if self.path == "/api/scan":
            try:
                SecCopScanRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            result = _run_real_demo("scan") if _real_demo_enabled() else run_demo_scan().model_dump(mode="json")
            self._send_json(200, {"result": result, "events": []})
            return

        if self.path == "/api/cve-review":
            try:
                request = SecCopCveReviewRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "CVE_INPUT_INVALID"})
                return
            result = review_demo_cve(request.cve_id).model_dump(mode="json")
            self._send_json(200, {"result": result, "events": []})
            return

        if self.path == "/api/demo/start":
            if payload.get("confirm") is not True:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "CONFIRM_REQUIRED"})
                return
            self._send_json(200, {"result": _run_real_demo("start"), "events": []})
            return

        if self.path == "/api/demo/fix":
            source = payload.get("source")
            if source not in {"s3", "ecr"} or payload.get("confirm") is not True:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            self._send_json(200, {"result": _run_real_demo("fix", source=source), "events": []})
            return

        if self.path == "/api/demo/rescan":
            self._send_json(200, {"result": _run_real_demo("rescan"), "events": []})
            return

        if self.path == "/api/live-evidence":
            try:
                result = AwsReadOnlyResult.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            self._send_json(
                200,
                {"result": result.model_dump(mode="json"), "events": []},
            )
            return

        if self.path == "/api/live-advisory":
            try:
                request = SecCopAdvisoryRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            comparison = _advisory_comparison(request)
            self._send_json(200, {"result": comparison.model_dump(mode="json"), "events": []})
            return

        if self.path == "/api/live-csv":
            try:
                request = SecCopCsvRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            try:
                document = parse_csv(
                    request.csv_text,
                    instance_id=request.instance_id,
                    cve_id=request.cve_id,
                    package_name=request.package_name,
                )
            except SecCopCsvError as error:
                result = SecCopComparison(
                    status="BLOCKED",
                    reason_code=error.reason_code,
                    cve_id=request.cve_id,
                    resource_alias="EC2_RESOURCE_01",
                    csv_row_count=0,
                    csv_match_count=0,
                    message="CSV evidence was blocked by the SecCop input contract.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return
            try:
                live_result = collect_live_evidence(
                    region=request.region,
                    instance_id=request.instance_id,
                    cve_id=request.cve_id,
                )
            except (AwsLiveBackendError, OSError, TimeoutError):
                result = SecCopComparison(
                    status="BLOCKED",
                    reason_code="AWS_BACKEND_UNAVAILABLE",
                    cve_id=request.cve_id,
                    resource_alias="EC2_RESOURCE_01",
                    csv_row_count=document.row_count,
                    csv_match_count=document.match_count,
                    message="The live AWS comparison could not be completed.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return
            result = SecCopComparison(
                status="READY" if live_result.status == "READY" else "BLOCKED",
                reason_code=(
                    "SECCOP_COMPARISON_READY"
                    if live_result.status == "READY"
                    else "AWS_READ_ONLY_BLOCKED"
                ),
                cve_id=request.cve_id,
                resource_alias="EC2_RESOURCE_01",
                csv_row_count=document.row_count,
                csv_match_count=document.match_count,
                live_result=live_result,
                message=(
                    "CSV evidence matched the exact live AWS target."
                    if live_result.status == "READY"
                    else "The live AWS evidence gate blocked this comparison."
                ),
            )
            self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
            return

        if self.path == "/api/live-proposal":
            try:
                request = SecCopCsvRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            proposal = _live_proposal(request)
            self._send_json(200, {"result": proposal.model_dump(mode="json"), "events": []})
            return

        if self.path == "/api/live-advisory-proposal":
            try:
                request = SecCopAdvisoryRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            proposal = _advisory_proposal(request)
            self._send_json(200, {"result": proposal.model_dump(mode="json"), "events": []})
            return

        if self.path == "/api/live-decision":
            proposal_id = payload.get("proposal_id")
            decision = payload.get("decision")
            if not isinstance(proposal_id, str) or decision not in {"APPROVE", "REJECT"}:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            proposal = _SECCOP_PROPOSALS.get(proposal_id)
            if proposal is None or proposal.status != "READY":
                self._send_json(404, {"status": "BLOCKED", "reason_code": "PROPOSAL_NOT_FOUND"})
                return
            proposal_hash = payload.get("proposal_hash")
            if not isinstance(proposal_hash, str) or proposal_hash != proposal.proposal_hash:
                self._send_json(
                    409,
                    {
                        "status": "BLOCKED",
                        "reason_code": "PROPOSAL_BINDING_MISMATCH",
                        "message": "The approval did not match the exact proposal.",
                    },
                )
                return
            if proposal.approval_expires_at is None or proposal.approval_expires_at <= datetime.now(timezone.utc):
                self._send_json(
                    409,
                    {
                        "status": "BLOCKED",
                        "reason_code": "APPROVAL_EXPIRED",
                        "message": "This proposal expired; generate a new proposal before approving.",
                    },
                )
                return
            approved = decision == "APPROVE"
            if approved:
                _SECCOP_APPROVALS[proposal_id] = _ApprovalRecord(
                    proposal_hash=proposal.proposal_hash,
                    expires_at=proposal.approval_expires_at,
                )
            else:
                _SECCOP_APPROVALS.pop(proposal_id, None)
            result = SecCopApprovalResult(
                status="APPROVED_NO_MUTATION" if approved else "REJECTED",
                reason_code="HUMAN_APPROVED_NO_MUTATION" if approved else "HUMAN_REJECTED",
                proposal_id=proposal_id,
                mutation_performed=False,
                proposal_hash=proposal.proposal_hash,
                approval_expires_at=proposal.approval_expires_at,
                message=(
                    "Approval recorded for the next phase; no AWS mutation was performed."
                    if approved
                    else "Human rejected the proposal; no AWS mutation was performed."
                ),
            )
            self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
            return

        if self.path == "/api/live-remediation":
            try:
                remediation_request = SecCopRemediationRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            proposal = _SECCOP_PROPOSALS.get(remediation_request.proposal_id)
            request = _SECCOP_REQUESTS.get(remediation_request.proposal_id)
            advisory_request = _SECCOP_ADVISORIES.get(remediation_request.proposal_id)
            instance_id = _SECCOP_TARGET_IDS.get(remediation_request.proposal_id)
            if request is not None:
                instance_id = request.instance_id
            if proposal is None or (request is None and advisory_request is None) or instance_id is None:
                result = SecCopRemediationResult(
                    status="BLOCKED",
                    reason_code="PROPOSAL_NOT_FOUND",
                    cve_id="CVE-0000-0000",
                    resource_alias="EC2_RESOURCE_01",
                    change_state="NOT_STARTED",
                    verification_status="NOT_AVAILABLE",
                    reboot_approved=False,
                    mutation_performed=False,
                    message="The approved proposal could not be found.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return
            approval = _SECCOP_APPROVALS.get(remediation_request.proposal_id)
            if approval is None:
                result = SecCopRemediationResult(
                    status="BLOCKED",
                    reason_code="SSM_APPROVAL_REQUIRED",
                    cve_id=proposal.cve_id,
                    resource_alias=proposal.resource_alias,
                    package_name=proposal.package_name,
                    fixed_version=proposal.fixed_version,
                    change_state="NOT_STARTED",
                    verification_status="NOT_AVAILABLE",
                    reboot_approved=False,
                    mutation_performed=False,
                    message="Human approval is required before the server can be changed.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return
            if approval.proposal_hash != remediation_request.proposal_hash:
                result = SecCopRemediationResult(
                    status="BLOCKED",
                    reason_code="SSM_APPROVAL_BINDING_MISMATCH",
                    cve_id=proposal.cve_id,
                    resource_alias=proposal.resource_alias,
                    package_name=proposal.package_name,
                    fixed_version=proposal.fixed_version,
                    change_state="NOT_STARTED",
                    verification_status="NOT_AVAILABLE",
                    reboot_approved=False,
                    mutation_performed=False,
                    message="The approved action no longer matches the proposal.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return
            now = datetime.now(timezone.utc)
            if approval.expires_at <= now:
                result = SecCopRemediationResult(
                    status="BLOCKED",
                    reason_code="SSM_APPROVAL_EXPIRED",
                    cve_id=proposal.cve_id,
                    resource_alias=proposal.resource_alias,
                    package_name=proposal.package_name,
                    fixed_version=proposal.fixed_version,
                    change_state="NOT_STARTED",
                    verification_status="NOT_AVAILABLE",
                    reboot_approved=False,
                    mutation_performed=False,
                    message="The approval expired before the fix started.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return
            if approval.consumed:
                result = SecCopRemediationResult(
                    status="BLOCKED",
                    reason_code="SSM_APPROVAL_ALREADY_USED",
                    cve_id=proposal.cve_id,
                    resource_alias=proposal.resource_alias,
                    package_name=proposal.package_name,
                    fixed_version=proposal.fixed_version,
                    change_state="NOT_STARTED",
                    verification_status="NOT_AVAILABLE",
                    reboot_approved=False,
                    mutation_performed=False,
                    message="This one-time approval was already used.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return
            if proposal.package_name is None or proposal.fixed_version is None:
                result = SecCopRemediationResult(
                    status="BLOCKED",
                    reason_code="SSM_PACKAGE_SOURCE_NOT_READY",
                    cve_id=proposal.cve_id,
                    resource_alias=proposal.resource_alias,
                    change_state="NOT_STARTED",
                    verification_status="NOT_AVAILABLE",
                    reboot_approved=False,
                    mutation_performed=False,
                    message="The proposal has no exact package and fixed version to apply.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return

            # Consume before dispatch so a retry or concurrent browser request
            # cannot reuse the same approval for a second mutation.
            _SECCOP_APPROVALS[remediation_request.proposal_id] = replace(approval, consumed=True)

            execution = execute_package_remediation(
                region=request.region if request is not None else advisory_request.region,
                instance_id=instance_id,
                cve_id=proposal.cve_id,
                package_name=proposal.package_name,
                fixed_version=proposal.fixed_version,
            )
            execution_reason = str(execution["reason_code"])
            executed_calls = tuple(str(item) for item in execution.get("executed_calls", ()))
            execution_after_version = execution.get("after_version")
            if execution["change_state"] != "COMPLETED":
                result = SecCopRemediationResult(
                    status=(
                        "BLOCKED"
                        if execution_reason in {"SSM_PACKAGE_SOURCE_NOT_READY", "AWS_BACKEND_UNAVAILABLE"}
                        else "FAILED"
                    ),
                    reason_code=execution_reason,
                    cve_id=proposal.cve_id,
                    resource_alias=proposal.resource_alias,
                    package_name=proposal.package_name,
                    fixed_version=proposal.fixed_version,
                    before_version=proposal.installed_version,
                    change_state=str(execution["change_state"]),
                    verification_status="NOT_AVAILABLE",
                    reboot_approved=False,
                    mutation_performed=bool(execution["mutation_performed"]),
                    executed_calls=executed_calls,
                    evidence_path=str(execution["evidence_path"]),
                    message=(
                        "The package source was not ready; no package change was started."
                        if execution_reason == "SSM_PACKAGE_SOURCE_NOT_READY"
                        else "The package changed, but the exact post-change version could not be verified."
                        if execution_reason == "SSM_VERIFICATION_FAILED"
                        else "The approved SSM operation did not complete. Review the saved evidence before retrying."
                    ),
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return

            try:
                verification = collect_live_evidence(
                    region=request.region if request is not None else advisory_request.region,
                    instance_id=instance_id,
                    cve_id=proposal.cve_id,
                )
            except (AwsLiveBackendError, OSError, TimeoutError):
                if isinstance(execution_after_version, str) and execution_after_version:
                    result = SecCopRemediationResult(
                        status="COMPLETED",
                        reason_code="SSM_PACKAGE_VERSION_VERIFIED",
                        cve_id=proposal.cve_id,
                        resource_alias=proposal.resource_alias,
                        package_name=proposal.package_name,
                        fixed_version=proposal.fixed_version,
                        before_version=proposal.installed_version,
                        after_version=execution_after_version,
                        change_state="COMPLETED",
                        verification_status="VERIFIED",
                        reboot_approved=False,
                        mutation_performed=True,
                        executed_calls=executed_calls,
                        evidence_path=str(execution["evidence_path"]),
                        message="The package version was verified; Inspector still needs to refresh before the finding can close.",
                    )
                    self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                    return
                result = SecCopRemediationResult(
                    status="FAILED",
                    reason_code="AWS_BACKEND_UNAVAILABLE",
                    cve_id=proposal.cve_id,
                    resource_alias=proposal.resource_alias,
                    package_name=proposal.package_name,
                    fixed_version=proposal.fixed_version,
                    change_state="COMPLETED",
                    verification_status="NOT_AVAILABLE",
                    reboot_approved=False,
                    mutation_performed=True,
                    executed_calls=executed_calls + ("inspector.list_findings",),
                    evidence_path=str(execution["evidence_path"]),
                    message="The package change completed, but the follow-up security check was unavailable.",
                )
                self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
                return

            executed_calls += tuple(verification.executed_calls)
            resolved = bool(
                verification.status == "READY"
                and verification.evidence is not None
                and verification.evidence.finding_state == "RESOLVED"
            )
            after_version = (
                execution_after_version
                if isinstance(execution_after_version, str) and execution_after_version
                else _verified_package_version(verification.evidence, proposal.package_name)
            )
            package_verified = isinstance(execution_after_version, str) and bool(execution_after_version)
            result = SecCopRemediationResult(
                status="COMPLETED",
                reason_code=(
                    "SSM_REMEDIATION_VERIFIED"
                    if resolved
                    else "SSM_PACKAGE_VERSION_VERIFIED"
                    if package_verified
                    else "SSM_REMEDIATION_PENDING_RESCAN"
                ),
                cve_id=proposal.cve_id,
                resource_alias=proposal.resource_alias,
                package_name=proposal.package_name,
                fixed_version=proposal.fixed_version,
                before_version=proposal.installed_version,
                after_version=after_version,
                change_state="COMPLETED",
                verification_status="VERIFIED" if (resolved or package_verified) else "PENDING_RESCAN",
                reboot_approved=False,
                mutation_performed=True,
                executed_calls=executed_calls,
                evidence_path=str(execution["evidence_path"]),
                message=(
                    "The approved package change completed and the follow-up check shows the finding resolved."
                    if resolved
                    else "The package version was verified; Inspector still needs to refresh before the finding can close."
                    if package_verified
                    else "The approved package change completed; the follow-up scan still needs to refresh before closure."
                ),
            )
            self._send_json(200, {"result": result.model_dump(mode="json"), "events": []})
            return

        if self.path == "/api/decision":
            run_id = payload.get("run_id")
            decision = payload.get("decision")
            if not isinstance(run_id, str) or decision not in {"APPROVE", "REJECT"}:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            try:
                session = _ENGINE.decide(run_id, decision == "APPROVE")
            except KeyError:
                self._send_json(404, {"status": "BLOCKED", "reason_code": "RUN_NOT_FOUND"})
                return
            self._send_json(200, _session_payload(session))
            return

        self._send_json(404, {"status": "BLOCKED", "reason_code": "NOT_FOUND"})

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def main() -> None:
    try:
        port = int(os.environ.get("POC_PORT", "8765"))
    except ValueError as exc:
        raise SystemExit("POC_PORT must be an integer.") from exc
    if not 1024 <= port <= 65535:
        raise SystemExit("POC_PORT must be between 1024 and 65535.")
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"Issue 5 local POC: http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
