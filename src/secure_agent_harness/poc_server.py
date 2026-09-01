"""Small dependency-free local web server for the Issue 5 visual proof."""

import json
import hashlib
import os
import re
import selectors
import subprocess
import sys
import time
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
    discover_patchable_findings,
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
    SecCopFinding,
    SecCopScanResult,
    SecCopScanSourceStatus,
    SecCopRemediationRequest,
    SecCopRemediationProposal,
    SecCopRemediationResult,
)
from .poc import PocEngine
from .seccop_csv import SecCopCsvError, parse_csv
from .seccop_scan import review_demo_cve, run_demo_scan


_HTML_PATH = Path(__file__).resolve().parents[2] / "web" / "poc_chat.html"
_DEMO_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "seccop_demo.py"
_S3_COMPLIANCE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "issue47_s3_compliance.py"
_ENGINE = PocEngine()
_SECCOP_PROPOSALS: dict[str, SecCopRemediationProposal] = {}
_SECCOP_REQUESTS: dict[str, SecCopCsvRequest] = {}
_SECCOP_ADVISORIES: dict[str, SecCopAdvisoryRequest] = {}
_SECCOP_TARGET_IDS: dict[str, str] = {}
_SERVER_SCAN_REQUEST: SecCopAdvisoryRequest | None = None
_HYBRID_SESSION: "_HybridSession | None" = None
_S3_APPROVAL_READY = False
_ECR_APPROVAL_READY = False


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

_CODEX_ALLOWED_METHODS = {
    "initialize",
    "account/read",
    "mcpServerStatus/list",
    "mcpServer/tool/call",
    "thread/start",
    "turn/start",
    "turn/interrupt",
}
_CODEX_SAFE_NOTIFICATIONS = {
    "thread/started",
    "thread/status/changed",
    "turn/started",
    "item/started",
    "item/completed",
    "item/agentMessage/delta",
    "turn/completed",
    "mcpServer/startupStatus/updated",
    "remoteControl/status/changed",
    "thread/tokenUsage/updated",
    "account/rateLimits/updated",
}
_CODEX_SAFE_ITEM_TYPES = {"userMessage", "agentMessage", "reasoning"}
_CODEX_PREFLIGHT_PROMPT = "Reply with exactly: SecCop App Server preflight ready. Do not use tools."
_AWS_MCP_SAFE_TOOLS = {
    "aws___get_regional_availability", "aws___get_tasks", "aws___list_regions",
    "aws___read_documentation", "aws___retrieve_skill", "aws___search_documentation",
}


class _CodexPreflightError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _CodexProcessTransport:
    def __init__(self, *, knowledge_only: bool = False) -> None:
        command = ["codex", "app-server", "--stdio"]
        if knowledge_only:
            profile = os.environ.get("SECCOP_PROFILE", "")
            region = os.environ.get("AWS_REGION", "ap-southeast-1")
            if not profile or not re.fullmatch(r"[A-Za-z0-9_.-]+", profile):
                raise _CodexPreflightError("AWS_MCP_UNAVAILABLE")
            overrides = (
                'mcp_servers.aws-mcp.command="uvx"',
                'mcp_servers.aws-mcp.args=["mcp-proxy-for-aws@1.6.4","https://aws-mcp.us-east-1.api.aws/mcp",'
                f'"--profile","{profile}","--metadata","AWS_REGION={region}","--read-only","--disable-telemetry"]',
                "mcp_servers.aws-mcp.startup_timeout_sec=90",
                "mcp_servers.aws-mcp.tool_timeout_sec=120",
                'mcp_servers.aws-mcp.env={SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"}',
                "mcp_servers.aws_knowledge.enabled=false",
                "mcp_servers.openaiDeveloperDocs.enabled=false",
            )
            for override in overrides:
                command.extend(("-c", override))
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

    def send(self, message: dict[str, object]) -> None:
        if self.process.stdin is None:
            raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")
        self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def receive(self, timeout: float) -> dict[str, object]:
        if self.process.stdout is None:
            raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        try:
            if not selector.select(timeout):
                raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")
            line = self.process.stdout.readline()
        finally:
            selector.close()
        if not line:
            raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED") from exc
        if not isinstance(message, dict):
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        return message

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)


@dataclass
class _HybridSession:
    transport: Any
    thread_id: str
    pending: list[dict[str, object]]
    next_id: int
    context: dict[str, object] | None = None


def _close_hybrid_session() -> None:
    global _HYBRID_SESSION
    if _HYBRID_SESSION is not None:
        _HYBRID_SESSION.transport.close()
        _HYBRID_SESSION = None


def _collect_codex_turn(session: _HybridSession, prompt: str) -> str:
    request_id = session.next_id
    session.next_id += 1
    turn = _codex_request(
        session.transport, request_id, "turn/start",
        {"threadId": session.thread_id, "input": [{"type": "text", "text": prompt}]},
        session.pending,
    ).get("turn")
    if not isinstance(turn, dict) or not isinstance(turn.get("id"), str):
        raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
    response_parts: list[str] = []
    for _ in range(500):
        event = session.pending.pop(0) if session.pending else session.transport.receive(180)
        method = event.get("method")
        params = event.get("params")
        if not isinstance(method, str) or method not in _CODEX_SAFE_NOTIFICATIONS or "id" in event or not isinstance(params, dict):
            raise _CodexPreflightError("CODEX_EVENT_REJECTED")
        if method in {"item/started", "item/completed"}:
            item = params.get("item")
            if not isinstance(item, dict) or item.get("type") not in _CODEX_SAFE_ITEM_TYPES:
                raise _CodexPreflightError("CODEX_EVENT_REJECTED")
        elif method == "item/agentMessage/delta":
            if not isinstance(params.get("delta"), str):
                raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
            response_parts.append(params["delta"])
        elif method == "turn/completed":
            completed = params.get("turn")
            if not isinstance(completed, dict) or completed.get("status") != "completed":
                raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")
            return _safe_codex_text("".join(response_parts))
    raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")


def _hybrid_blocked(reason_code: str) -> dict[str, object]:
    _close_hybrid_session()
    return {
        "status": "BLOCKED", "reason_code": reason_code,
        "aws_evidence_status": "SECCOP_ADAPTER", "aws_mcp_status": "AWS_MCP_UNAVAILABLE",
        "aws_mcp_mode": "READ_ONLY", "tool_activity": [],
        "message": "The optional AI explanation was unavailable; deterministic controls remain active.",
    }


def _run_aws_knowledge_check() -> None:
    """Prove the constrained MCP lane without attaching tools to the agent turn."""

    transport = _CodexProcessTransport(knowledge_only=True)
    pending: list[dict[str, object]] = []
    try:
        _codex_request(transport, 1, "initialize", {"clientInfo": {"name": "seccop_knowledge", "version": "0.1.0"}}, pending)
        transport.send({"method": "initialized", "params": {}})
        thread = _codex_request(transport, 2, "thread/start", {
            "ephemeral": True, "approvalPolicy": "never", "sandbox": "read-only", "model": "gpt-5.6-luna",
        }, pending).get("thread")
        if not isinstance(thread, dict) or not isinstance(thread.get("id"), str):
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        aws_server = None
        request_id = 3
        for _ in range(12):
            inventory = _codex_request(transport, request_id, "mcpServerStatus/list", {"detail": "full", "threadId": thread["id"]}, pending)
            request_id += 1
            servers = inventory.get("data")
            aws_server = next((item for item in servers or [] if isinstance(item, dict) and item.get("name") == "aws-mcp"), None)
            if isinstance(aws_server, dict) and aws_server.get("runtimeStatus") == "connected" and aws_server.get("tools"):
                break
            time.sleep(2)
        else:
            raise _CodexPreflightError("AWS_MCP_UNAVAILABLE")
        tools = aws_server.get("tools")
        if not isinstance(tools, dict) or set(tools) != _AWS_MCP_SAFE_TOOLS:
            raise _CodexPreflightError("AWS_MCP_TOOL_INVENTORY_REJECTED")
        knowledge = _codex_request(transport, request_id, "mcpServer/tool/call", {
            "server": "aws-mcp", "threadId": thread["id"], "tool": "aws___search_documentation",
            "arguments": {"search_phrase": "AWS Systems Manager package patching verification best practices", "limit": 2, "topics": ["general"]},
        }, pending, 120)
        if knowledge.get("isError") is True or not isinstance(knowledge.get("content"), list):
            raise _CodexPreflightError("AWS_MCP_TOOL_FAILED")
    finally:
        transport.close()


def _run_hybrid_startup_proof() -> dict[str, object]:
    """Prove Codex auth/thread and AWS MCP knowledge as isolated read-only lanes."""

    codex = _run_codex_preflight()
    if codex.get("status") != "READY":
        return _hybrid_blocked(str(codex.get("reason_code", "CODEX_APP_SERVER_UNAVAILABLE")))
    try:
        _run_aws_knowledge_check()
    except (OSError, _CodexPreflightError) as error:
        return _hybrid_blocked(error.reason_code if isinstance(error, _CodexPreflightError) else "AWS_MCP_UNAVAILABLE")
    return {
        "status": "READY", "reason_code": "HYBRID_STARTUP_PROVEN",
        "codex_status": "CODEX_CONNECTED", "aws_mcp_status": "AWS_MCP_KNOWLEDGE_ONLY",
    }


def _start_hybrid_explanation(request: SecCopAdvisoryRequest, *, evidence_status: str = "SECCOP_ADAPTER") -> dict[str, object]:
    global _HYBRID_SESSION
    _close_hybrid_session()
    if os.environ.get("SECCOP_AWS_MCP") != "1":
        return _hybrid_blocked("AWS_MCP_UNAVAILABLE")
    try:
        transport = _CodexProcessTransport()
        pending: list[dict[str, object]] = []
        _codex_request(transport, 1, "initialize", {"clientInfo": {"name": "seccop_hybrid", "version": "0.1.0"}}, pending)
        transport.send({"method": "initialized", "params": {}})
        account = _codex_request(transport, 2, "account/read", {"refreshToken": False}, pending)
        if account.get("account") is None and account.get("requiresOpenaiAuth") is True:
            raise _CodexPreflightError("CODEX_NOT_AUTHENTICATED")
        thread = _codex_request(transport, 3, "thread/start", {
            "ephemeral": True, "approvalPolicy": "never", "sandbox": "read-only", "model": "gpt-5.6-luna",
        }, pending).get("thread")
        if not isinstance(thread, dict) or not isinstance(thread.get("id"), str):
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        session = _HybridSession(transport, thread["id"], pending, 5)
        _HYBRID_SESSION = session
        handshake = _collect_codex_turn(session, _CODEX_PREFLIGHT_PROMPT)
        if handshake != "SecCop App Server preflight ready.":
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        _run_aws_knowledge_check()
        response = (
            f"{request.package_name} {request.installed_version} is affected by {request.cve_id}; "
            f"the reviewed target version is {request.fixed_version}. Human approval is required before any change."
        )
        return {
            "status": "READY", "reason_code": "HYBRID_INTEGRATION_READY",
            "aws_evidence_status": evidence_status, "aws_mcp_status": "AWS_MCP_KNOWLEDGE_ONLY",
            "aws_mcp_mode": "READ_ONLY", "tool_activity": ["AWS documentation searched"],
            "response_text": response, "message": "Codex connectivity, deterministic evidence, and AWS knowledge are ready.",
        }
    except (OSError, _CodexPreflightError) as error:
        return _hybrid_blocked(error.reason_code if isinstance(error, _CodexPreflightError) else "CODEX_APP_SERVER_UNAVAILABLE")


def _ecr_codex_facts(scan: dict[str, object]) -> str:
    """Project only server-owned ECR/Inspector facts into a Codex prompt."""

    fields = (
        ("resource alias", "ECR_IMAGE_01"),
        ("storage provider", "AWS_ECR"),
        ("scanner", scan.get("scanner_mode") or "ECR_ENHANCED_SCANNING"),
        ("package ecosystem", scan.get("package_ecosystem") or "UNKNOWN"),
        ("CVE", scan.get("cve_id") or "UNKNOWN"),
        ("package", scan.get("package_name") or "none reported"),
        ("installed version", scan.get("installed_version") or "none reported"),
        ("severity", scan.get("severity") or "UNKNOWN"),
        ("state", scan.get("state") or scan.get("status") or "UNKNOWN"),
    )
    safe = []
    for label, value in fields:
        text = " ".join(str(value).split())
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ./:+_()\-]{0,119}", text):
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        safe.append(f"{label}: {text}")
    return "\n".join(safe)


def _start_ecr_codex_explanation(request_text: str, scan: dict[str, object]) -> dict[str, object]:
    """Send the real ECR request and sanitized BEFORE facts through one thread."""

    global _HYBRID_SESSION
    _close_hybrid_session()
    try:
        request = " ".join(request_text.split())
        if not request or len(request) > 300 or re.search(r"(?:arn:|sha256:|AKIA|aws\s+cli|(?:secret|credential|token)|/home/|\\Users\\)", request, re.IGNORECASE):
            raise _CodexPreflightError("REQUEST_REJECTED")
        transport = _CodexProcessTransport()
        pending: list[dict[str, object]] = []
        _codex_request(transport, 1, "initialize", {"clientInfo": {"name": "seccop_ecr", "version": "0.1.0"}}, pending)
        transport.send({"method": "initialized", "params": {}})
        account = _codex_request(transport, 2, "account/read", {"refreshToken": False}, pending)
        if account.get("account") is None and account.get("requiresOpenaiAuth") is True:
            raise _CodexPreflightError("CODEX_NOT_AUTHENTICATED")
        thread = _codex_request(transport, 3, "thread/start", {
            "ephemeral": True, "approvalPolicy": "never", "sandbox": "read-only", "model": "gpt-5.6-luna",
        }, pending).get("thread")
        if not isinstance(thread, dict) or not isinstance(thread.get("id"), str):
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        session = _HybridSession(transport, thread["id"], pending, 4, dict(scan))
        _HYBRID_SESSION = session
        prompt = (
            "User request: " + request + "\n\n"
            "Sanitized BEFORE facts:\n" + _ecr_codex_facts(scan) + "\n\n"
            "Explain the finding and recommend the safe, approval-gated next step. Do not use tools."
        )
        response = _collect_codex_turn(session, prompt)
        return {
            "status": "READY", "reason_code": "ECR_CODEX_BEFORE_READY",
            "aws_evidence_status": "AMAZON_INSPECTOR", "aws_mcp_status": "NOT_USED",
            "aws_mcp_mode": "READ_ONLY", "tool_activity": ["One read-only Codex thread"],
            "response_text": response, "message": "Codex explained the real Inspector finding from sanitized BEFORE facts.",
        }
    except (OSError, _CodexPreflightError) as error:
        return _hybrid_blocked(error.reason_code if isinstance(error, _CodexPreflightError) else "CODEX_APP_SERVER_UNAVAILABLE")


def _finish_ecr_codex_explanation(after: dict[str, object]) -> dict[str, object]:
    """Continue the exact ECR thread with sanitized AFTER facts."""

    session = _HYBRID_SESSION
    if session is None:
        return _hybrid_blocked("CODEX_THREAD_UNAVAILABLE")
    try:
        before = session.context or {}
        after_facts = dict(after)
        for field in ("scanner_mode", "package_ecosystem", "cve_id"):
            if field not in after_facts and field in before:
                after_facts[field] = before[field]
        if not after_facts.get("state"):
            after_facts["state"] = "COMPLIANT" if after_facts.get("status") == "VERIFIED" else after_facts.get("status", "UNKNOWN")
        prompt = (
            "Sanitized AFTER facts for the same ECR review:\n" + _ecr_codex_facts(after_facts) + "\n\n"
            "Explain the verified final state in two short plain-language sentences. Do not use tools."
        )
        response = _collect_codex_turn(session, prompt)
        return {
            "status": "READY", "reason_code": "ECR_CODEX_AFTER_EXPLAINED",
            "aws_evidence_status": "AMAZON_INSPECTOR", "aws_mcp_status": "NOT_USED",
            "aws_mcp_mode": "READ_ONLY", "tool_activity": ["Same read-only Codex thread continued"],
            "response_text": response, "message": "Codex explained the verified ECR AFTER state on the same thread.",
        }
    except _CodexPreflightError as error:
        return _hybrid_blocked(error.reason_code)
    finally:
        _close_hybrid_session()


def _finish_hybrid_explanation(result: SecCopRemediationResult) -> dict[str, object]:
    session = _HYBRID_SESSION
    if session is None:
        return _hybrid_blocked("CODEX_THREAD_UNAVAILABLE")
    try:
        response = _collect_codex_turn(session,
            "Explain this sanitized follow-up in two short plain-language sentences. Do not use tools. "
            f"Target LAB_SERVER_01; package {result.package_name}; before {result.before_version}; after {result.after_version}; "
            f"verification {result.verification_status}."
        )
        return {
            "status": "READY", "reason_code": "HYBRID_AFTER_EXPLAINED",
            "aws_evidence_status": "SECCOP_ADAPTER", "aws_mcp_status": "AWS_MCP_KNOWLEDGE_ONLY",
            "aws_mcp_mode": "READ_ONLY", "tool_activity": ["Same read-only thread continued"],
            "response_text": response, "message": "Security Copilot explained the verified follow-up.",
        }
    except _CodexPreflightError as error:
        return _hybrid_blocked(error.reason_code)
    finally:
        _close_hybrid_session()


def _codex_request(
    transport: Any,
    request_id: int,
    method: str,
    params: dict[str, object],
    pending: list[dict[str, object]],
    timeout: float = 15,
) -> dict[str, object]:
    if method not in _CODEX_ALLOWED_METHODS:
        raise _CodexPreflightError("CODEX_RPC_REJECTED")
    transport.send({"method": method, "id": request_id, "params": params})
    for _ in range(100):
        message = transport.receive(timeout)
        if message.get("id") != request_id:
            event_method = message.get("method")
            if "id" in message or event_method not in _CODEX_SAFE_NOTIFICATIONS:
                raise _CodexPreflightError("CODEX_EVENT_REJECTED")
            pending.append(message)
            continue
        if "error" in message:
            raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")
        result = message.get("result")
        if not isinstance(result, dict):
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        return result
    raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")


def _safe_codex_text(value: str) -> str:
    text = " ".join(value.split())[:300]
    if not text or re.search(r"(?:/home/|/mnt/|\\Users\\|arn:|\bi-[0-9a-f]{8,17}\b|sk-[A-Za-z0-9])", text):
        raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
    return text


def _run_codex_preflight(transport: Any | None = None) -> dict[str, object]:
    owned_transport = transport is None
    thread_id: str | None = None
    turn_id: str | None = None
    pending: list[dict[str, object]] = []
    if transport is None:
        try:
            transport = _CodexProcessTransport()
        except OSError:
            return _codex_blocked("CODEX_APP_SERVER_UNAVAILABLE")
    try:
        _codex_request(
            transport,
            1,
            "initialize",
            {"clientInfo": {"name": "seccop_poc", "title": "Security Copilot", "version": "0.1.0"}},
            pending,
        )
        transport.send({"method": "initialized", "params": {}})
        account = _codex_request(transport, 2, "account/read", {"refreshToken": False}, pending)
        if account.get("account") is None and account.get("requiresOpenaiAuth") is True:
            return _codex_blocked("CODEX_NOT_AUTHENTICATED", auth_status="CODEX_NOT_AUTHENTICATED")
        auth_status = "CODEX_AUTHENTICATED" if account.get("account") is not None else "CODEX_AUTH_NOT_REQUIRED"
        _codex_request(transport, 3, "mcpServerStatus/list", {"detail": "toolsAndAuthOnly"}, pending)
        thread = _codex_request(
            transport,
            4,
            "thread/start",
            {"ephemeral": True, "approvalPolicy": "never", "sandbox": "read-only", "model": "gpt-5.6-luna"},
            pending,
        ).get("thread")
        if not isinstance(thread, dict) or not isinstance(thread.get("id"), str):
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        thread_id = thread["id"]
        turn = _codex_request(
            transport,
            5,
            "turn/start",
            {"threadId": thread_id, "input": [{"type": "text", "text": _CODEX_PREFLIGHT_PROMPT}]},
            pending,
        ).get("turn")
        if not isinstance(turn, dict) or not isinstance(turn.get("id"), str):
            raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
        turn_id = turn["id"]
        response_parts: list[str] = []
        for _ in range(500):
            event = pending.pop(0) if pending else transport.receive(90)
            method = event.get("method")
            if not isinstance(method, str) or method not in _CODEX_SAFE_NOTIFICATIONS or "id" in event:
                raise _CodexPreflightError("CODEX_EVENT_REJECTED")
            params = event.get("params")
            if not isinstance(params, dict):
                raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
            if method in {"item/started", "item/completed"}:
                item = params.get("item")
                if not isinstance(item, dict) or item.get("type") not in _CODEX_SAFE_ITEM_TYPES:
                    raise _CodexPreflightError("CODEX_EVENT_REJECTED")
            elif method == "item/agentMessage/delta":
                delta = params.get("delta")
                if not isinstance(delta, str):
                    raise _CodexPreflightError("CODEX_APP_SERVER_OUTPUT_REJECTED")
                response_parts.append(delta)
            elif method == "turn/completed":
                completed = params.get("turn")
                if not isinstance(completed, dict) or completed.get("status") != "completed":
                    raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")
                return {
                    "status": "READY",
                    "reason_code": "CODEX_CONNECTED",
                    "codex_status": "CODEX_CONNECTED",
                    "auth_status": auth_status,
                    "thread_status": "THREAD_ACTIVE",
                    "aws_mcp_status": "AWS_MCP_UNAVAILABLE",
                    "response_text": _safe_codex_text("".join(response_parts)),
                    "message": "Codex App Server completed one isolated no-tool preflight turn.",
                }
        raise _CodexPreflightError("CODEX_APP_SERVER_UNAVAILABLE")
    except _CodexPreflightError as error:
        if thread_id is not None and turn_id is not None:
            try:
                _codex_request(transport, 99, "turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, pending)
            except _CodexPreflightError:
                pass
        return _codex_blocked(error.reason_code)
    finally:
        if owned_transport:
            transport.close()


def _codex_blocked(reason_code: str, *, auth_status: str = "UNKNOWN") -> dict[str, object]:
    return {
        "status": "BLOCKED",
        "reason_code": reason_code,
        "codex_status": "CODEX_APP_SERVER_UNAVAILABLE" if reason_code != "CODEX_EVENT_REJECTED" else "CODEX_EVENT_REJECTED",
        "auth_status": auth_status,
        "thread_status": "NOT_STARTED",
        "aws_mcp_status": "AWS_MCP_UNAVAILABLE",
        "message": "The isolated Codex App Server preflight stopped safely.",
    }


def _session_payload(session: Any) -> dict[str, object]:
    return {
        "result": session.result.model_dump(mode="json"),
        "events": [event.model_dump(mode="json") for event in session.events],
    }


def _public_remediation_payload(result: SecCopRemediationResult) -> dict[str, object]:
    """Keep private evidence paths server-side."""

    return result.model_dump(mode="json", exclude={"evidence_path"})


def _next_proposal_id() -> str:
    global _NEXT_PROPOSAL_ID
    proposal_id = f"SECCOP_PROPOSAL_{_NEXT_PROPOSAL_ID:02d}"
    _NEXT_PROPOSAL_ID += 1
    return proposal_id


def _approval_expiry() -> datetime:
    return datetime.now(timezone.utc) + _APPROVAL_TTL


def _real_demo_enabled() -> bool:
    return os.environ.get("SECCOP_DEMO_BACKEND", "LOCAL").upper() == "AWS"


def _run_real_demo(command: str, *, source: str | None = None, request_text: str | None = None) -> dict[str, object]:
    """Run the repo-owned AWS DEMO command and return sanitized JSON only."""

    if not _real_demo_enabled():
        return {
            "status": "BLOCKED",
            "reason_code": "AWS_DEMO_DISABLED",
            "message": "The local server is using synthetic mode. Enable the AWS DEMO backend explicitly.",
        }
    global _S3_APPROVAL_READY, _ECR_APPROVAL_READY
    if os.environ.get("SECCOP_ECR_OPERATOR_MVP") == "1":
        mapped = {"start": "ecr-start", "scan": "ecr-scan", "fix": "ecr-fix", "reset": "ecr-reset"}.get(command)
        if mapped is None or (mapped == "ecr-fix" and (source != "ecr" or not _ECR_APPROVAL_READY)):
            return {"status": "BLOCKED", "reason_code": "APPROVAL_REQUIRED", "message": "Approve the exact ECR proposal before promotion."}
        ecr_scanner = os.environ.get("SECCOP_ECR_SCANNER", "trivy").lower()
        if ecr_scanner not in {"trivy", "inspector"}:
            return {"status": "BLOCKED", "reason_code": "SECCOP_ECR_SCANNER_INVALID", "message": "The ECR scanner selection is invalid."}
        args = [sys.executable, str(_DEMO_SCRIPT), mapped, "--profile", os.environ["SECCOP_PROFILE"], "--region", os.environ["AWS_REGION"]]
        args.extend(["--ecr-scanner", ecr_scanner])
        args.extend(["--ecr-fixture", os.environ.get("SECCOP_ECR_FIXTURE", "current")])
        if mapped != "ecr-scan": args.append("--confirm")
        completed = subprocess.run(args, capture_output=True, text=True, check=False, timeout=300, env=os.environ.copy())
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {"status": "BLOCKED", "reason_code": "SECCOP_ECR_BACKEND_BLOCKED", "message": "The ECR operation was blocked."}
        if mapped == "ecr-scan" and payload.get("reason_code") == "SECCOP_ECR_NON_COMPLIANT": _ECR_APPROVAL_READY = True
        if mapped in {"ecr-fix", "ecr-reset"} and payload.get("status") in {"VERIFIED", "READY"}: _ECR_APPROVAL_READY = False
        if os.environ.get("SECCOP_ECR_APP_SERVER") == "1" and mapped == "ecr-scan":
            payload["agent"] = _start_ecr_codex_explanation(
                request_text or "Investigate the ECR finding and explain the safe next step.", payload,
            )
        elif os.environ.get("SECCOP_ECR_APP_SERVER") == "1" and mapped == "ecr-fix" and payload.get("status") in {"VERIFIED", "READY"}:
            payload["agent_after"] = _finish_ecr_codex_explanation(payload)
        return payload
    if os.environ.get("SECCOP_S3_COMPLIANCE_E2E") == "1":
        mapped = {"scan": "scan", "fix": "apply", "reset": "reset"}.get(command)
        if mapped is None or (mapped == "apply" and (source != "s3" or not _S3_APPROVAL_READY)):
            return {"status": "BLOCKED", "reason_code": "APPROVAL_REQUIRED", "message": "Approve the exact S3 proposal before remediation."}
        args = [sys.executable, str(_S3_COMPLIANCE_SCRIPT), mapped, "--profile", os.environ["SECCOP_PROFILE"], "--region", os.environ["AWS_REGION"], "--bucket", os.environ["SECCOP_S3_BUCKET"]]
        completed = subprocess.run(args, capture_output=True, text=True, check=False, timeout=120, env=os.environ.copy())
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {"status": "BLOCKED", "reason_code": "SECCOP_S3_BACKEND_BLOCKED", "message": "The S3 operation was blocked."}
        if mapped == "scan":
            protected_buckets = os.environ.get("SECCOP_S3_PROTECTED_BUCKETS", "").split(",")
            aliases = ["Finance reports", "Audit logs", "Application backups"]
            states = ["ACTION REQUIRED" if payload.get("reason_code") == "SECCOP_S3_NON_COMPLIANT" else "PROTECTED"]
            for bucket in filter(None, protected_buckets):
                companion = subprocess.run(args[:-1] + [bucket], capture_output=True, text=True, check=False, timeout=120, env=os.environ.copy())
                try:
                    companion_payload = json.loads(companion.stdout)
                except json.JSONDecodeError:
                    return {"status": "BLOCKED", "reason_code": "SECCOP_S3_BACKEND_BLOCKED", "message": "The S3 operation was blocked."}
                if companion_payload.get("reason_code") != "SECCOP_S3_COMPLIANT":
                    return {"status": "BLOCKED", "reason_code": "SECCOP_S3_BACKEND_BLOCKED", "message": "The S3 operation was blocked."}
                states.append("PROTECTED")
            payload["bucket_status"] = [{"label": alias, "state": state} for alias, state in zip(aliases, states, strict=False)]
            if payload.get("reason_code") == "SECCOP_S3_NON_COMPLIANT": _S3_APPROVAL_READY = True
        if mapped == "apply" and payload.get("status") == "VERIFIED": _S3_APPROVAL_READY = False
        if mapped == "reset" and payload.get("reason_code") == "SECCOP_S3_RESET_READY": _S3_APPROVAL_READY = False
        return payload
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


def _live_server_scan() -> SecCopScanResult:
    """Discover and validate one exact live finding without browser-supplied authority."""

    global _SERVER_SCAN_REQUEST
    _SERVER_SCAN_REQUEST = None
    try:
        candidates = discover_patchable_findings(region="ap-southeast-1")
    except (AwsLiveBackendError, AwsLiveTargetError, OSError, TimeoutError):
        candidates = ()
    for candidate in candidates:
        advisory = collect_package_advisory(
            region="ap-southeast-1",
            instance_id=candidate.target.instance_id,
            advisory_id=candidate.advisory_id,
            package_name=candidate.package_name,
        )
        actual = advisory.get("before_version")
        if advisory.get("status") != "READY" or not isinstance(actual, str) or not actual.startswith(candidate.installed_version):
            continue
        _SERVER_SCAN_REQUEST = SecCopAdvisoryRequest(
            advisory_id=candidate.advisory_id,
            cve_id=candidate.cve_id,
            severity=candidate.severity,
            package_name=candidate.package_name,
            installed_version=candidate.installed_version,
            fixed_version=candidate.fixed_version,
            region="ap-southeast-1",
        )
        finding = SecCopFinding(
            finding_id="FINDING_01", source_type="EC2_PACKAGE", resource_alias="LAB_SERVER_01",
            cve_id=candidate.cve_id, reference=candidate.cve_id, severity=candidate.severity,
            title="Live server package update",
            problem_summary="Inspector found one server package with a vendor security update.",
            observed_state="Installed package is older than the fixed version",
            recommended_state="Review and approve the exact one-package update.",
            remediation_mode="REAL_APPROVAL_REQUIRED", reason_code="SECCOP_EC2_FINDING_CONFIRMED",
            action_label="Review live fix",
        )
        return SecCopScanResult(
            scan_id="SECCOP_SCAN_01", status="READY", reason_code="SECCOP_SCAN_READY",
            source_status=(
                SecCopScanSourceStatus(source_type="EC2_PACKAGE", label="Live server packages", state="COMPLETE", reason_code="SECCOP_SOURCE_READY"),
                SecCopScanSourceStatus(source_type="S3_ARTIFACT", label="Stored artifacts (read-only)", state="COMPLETE", reason_code="SECCOP_SOURCE_READY"),
                SecCopScanSourceStatus(source_type="ECR_IMAGE", label="Container images (read-only)", state="COMPLETE", reason_code="SECCOP_SOURCE_READY"),
            ), findings=(finding,),
            message="One real EC2 finding is ready. Review the exact package fix before approval.",
        )
    return SecCopScanResult(
        scan_id="SECCOP_SCAN_01", status="NO_FINDINGS", reason_code="SECCOP_SCAN_NO_FINDINGS",
        source_status=(SecCopScanSourceStatus(source_type="EC2_PACKAGE", label="Live server packages", state="BLOCKED", reason_code="SECCOP_SOURCE_BLOCKED"),),
        findings=(), message="No verified patchable server finding is ready yet.",
    )


def _fixture_hybrid_scan() -> SecCopScanResult:
    """Prepare sanitized local evidence without claiming an AWS account read."""

    global _SERVER_SCAN_REQUEST
    _SERVER_SCAN_REQUEST = SecCopAdvisoryRequest(
        advisory_id="ALAS2-2099-0001", cve_id="CVE-2099-0001", severity="HIGH",
        package_name="demo-package", installed_version="1.0", fixed_version="1.1",
        region="ap-southeast-1",
    )
    scan = run_demo_scan()
    finding = scan.findings[0].model_copy(update={
        "title": "Server package example",
        "problem_summary": "A sanitized fixture represents an older server package.",
        "recommended_state": "Use a separately approved live run before changing a server.",
        "remediation_mode": "DEMO_ONLY",
        "action_label": "View suggested fix",
    })
    return scan.model_copy(update={
        "findings": (finding, *scan.findings[1:]),
        "message": "Three sanitized findings are ready for a local integration review. No AWS resource was read or changed.",
    })


def _fixture_hybrid_status(request: SecCopAdvisoryRequest) -> dict[str, object]:
    """Render only after the repo runner proves both local integration lanes."""

    return {
        "status": "READY", "reason_code": "HYBRID_INTEGRATION_READY",
        "aws_evidence_status": "DETERMINISTIC_FIXTURE",
        "aws_mcp_status": "AWS_MCP_KNOWLEDGE_ONLY", "aws_mcp_mode": "READ_ONLY",
        "tool_activity": ["AWS documentation searched during startup proof"],
        "response_text": (
            f"{request.package_name} {request.installed_version} is affected by {request.cve_id}; "
            f"the reviewed target version is {request.fixed_version}. Human approval is required before any change."
        ),
        "message": "Startup-proven Codex connectivity, deterministic evidence, and AWS knowledge are ready.",
    }


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
                    "review_mode": "ECR_OPERATOR" if os.environ.get("SECCOP_ECR_OPERATOR_MVP") == "1" else "S3_COMPLIANCE" if os.environ.get("SECCOP_S3_COMPLIANCE_E2E") == "1" else "GENERAL",
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

        if self.path == "/api/codex-preflight":
            if payload:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            self._send_json(200, {"result": _run_codex_preflight(), "events": []})
            return

        if self.path == "/api/scan":
            try:
                request = SecCopScanRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            if os.environ.get("SECCOP_S3_COMPLIANCE_E2E") == "1" or os.environ.get("SECCOP_ECR_OPERATOR_MVP") == "1":
                result = _run_real_demo("scan", request_text=request.request_text)
                agent = result.pop("agent", None)
                response: dict[str, object] = {"result": result, "events": []}
                if agent is not None:
                    response["agent"] = agent
                self._send_json(200, response)
                return
            fixture_hybrid = os.environ.get("SECCOP_HYBRID_FIXTURE") == "1"
            scan = _live_server_scan() if _real_demo_enabled() else _fixture_hybrid_scan() if fixture_hybrid else run_demo_scan()
            response: dict[str, object] = {"result": scan.model_dump(mode="json"), "events": []}
            if (_real_demo_enabled() or fixture_hybrid) and scan.status == "READY" and _SERVER_SCAN_REQUEST is not None:
                response["agent"] = (
                    _fixture_hybrid_status(_SERVER_SCAN_REQUEST)
                    if fixture_hybrid and os.environ.get("SECCOP_HYBRID_STARTUP_PROVEN") == "1"
                    else _start_hybrid_explanation(
                        _SERVER_SCAN_REQUEST,
                        evidence_status="SECCOP_ADAPTER" if _real_demo_enabled() else "DETERMINISTIC_FIXTURE",
                    )
                )
            self._send_json(200, response)
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

        if self.path == "/api/demo/reset":
            if payload != {"confirm": True}:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            self._send_json(200, {"result": _run_real_demo("reset"), "events": []})
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

        if self.path == "/api/live-scan-proposal":
            if payload or _SERVER_SCAN_REQUEST is None:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            proposal = _advisory_proposal(_SERVER_SCAN_REQUEST)
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
                self._send_json(200, {"result": _public_remediation_payload(result), "events": []})
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
                self._send_json(200, {"result": _public_remediation_payload(result), "events": []})
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
                self._send_json(200, {"result": _public_remediation_payload(result), "events": []})
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
                self._send_json(200, {"result": _public_remediation_payload(result), "events": []})
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
                self._send_json(200, {"result": _public_remediation_payload(result), "events": []})
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
                self._send_json(200, {"result": _public_remediation_payload(result), "events": []})
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
                self._send_json(200, {"result": _public_remediation_payload(result), "events": []})
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
                        reason_code="SSM_REMEDIATION_PENDING_RESCAN",
                        cve_id=proposal.cve_id,
                        resource_alias=proposal.resource_alias,
                        package_name=proposal.package_name,
                        fixed_version=proposal.fixed_version,
                        before_version=proposal.installed_version,
                        after_version=execution_after_version,
                        change_state="COMPLETED",
                        verification_status="PENDING_RESCAN",
                        reboot_approved=False,
                        mutation_performed=True,
                        executed_calls=executed_calls,
                        evidence_path=str(execution["evidence_path"]),
                        message="The package version was verified; Inspector still needs to refresh before the finding can close.",
                    )
                    public_result = _public_remediation_payload(result)
                    public_result["agent_after"] = _finish_hybrid_explanation(result)
                    self._send_json(200, {"result": public_result, "events": []})
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
                public_result = _public_remediation_payload(result)
                public_result["agent_after"] = _finish_hybrid_explanation(result)
                self._send_json(200, {"result": public_result, "events": []})
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
                    else "SSM_REMEDIATION_PENDING_RESCAN"
                ),
                cve_id=proposal.cve_id,
                resource_alias=proposal.resource_alias,
                package_name=proposal.package_name,
                fixed_version=proposal.fixed_version,
                before_version=proposal.installed_version,
                after_version=after_version,
                change_state="COMPLETED",
                verification_status="VERIFIED" if resolved else "PENDING_RESCAN",
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
            public_result = _public_remediation_payload(result)
            public_result["agent_after"] = _finish_hybrid_explanation(result)
            self._send_json(200, {"result": public_result, "events": []})
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
