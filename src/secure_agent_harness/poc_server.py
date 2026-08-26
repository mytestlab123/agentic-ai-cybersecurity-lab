"""Small dependency-free local web server for the Issue 5 visual proof."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .aws_live import AwsLiveBackendError, collect_live_evidence
from .contracts import (
    AwsReadOnlyResult,
    PocRequest,
    SecCopApprovalResult,
    SecCopComparison,
    SecCopCsvRequest,
    SecCopRemediationProposal,
)
from .poc import PocEngine
from .seccop_csv import SecCopCsvError, parse_csv


_HTML_PATH = Path(__file__).resolve().parents[2] / "web" / "poc_chat.html"
_ENGINE = PocEngine()
_SECCOP_PROPOSALS: dict[str, SecCopRemediationProposal] = {}
_NEXT_PROPOSAL_ID = 1


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


def _live_proposal(request: SecCopCsvRequest) -> SecCopRemediationProposal:
    """Re-run the read-only gate and derive one exact package proposal."""

    try:
        document = parse_csv(
            request.csv_text,
            instance_id=request.instance_id,
            cve_id=request.cve_id,
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
    proposal = SecCopRemediationProposal(
        proposal_id=_next_proposal_id(),
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
        action="SSM_INSTALL_SECURITY_UPDATE" if row.fixed_version else "NONE",
        reboot_policy="EXPLICIT_APPROVAL_REQUIRED" if row.fixed_version else "UNKNOWN",
        requires_approval=bool(row.fixed_version),
        mutation_performed=False,
        read_executed_calls=live_result.evidence.executed_calls,
        message=(
            "A deterministic package-level remediation proposal is ready for human approval."
            if row.fixed_version
            else "The finding has no fixed version in the supplied evidence."
        ),
    )
    if proposal.status == "READY":
        _SECCOP_PROPOSALS[proposal.proposal_id] = proposal
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
            self._send_json(200, {"status": "OK", "mode": "LOCAL_SYNTHETIC"})
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
            approved = decision == "APPROVE"
            result = SecCopApprovalResult(
                status="APPROVED_NO_MUTATION" if approved else "REJECTED",
                reason_code="HUMAN_APPROVED_NO_MUTATION" if approved else "HUMAN_REJECTED",
                proposal_id=proposal_id,
                mutation_performed=False,
                message=(
                    "Approval recorded for the next phase; no AWS mutation was performed."
                    if approved
                    else "Human rejected the proposal; no AWS mutation was performed."
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
