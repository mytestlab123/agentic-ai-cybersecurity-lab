"""One-target, approval-bound SSM remediation for the SecCop demo.

The module deliberately builds the remote command from validated CSV fields.
No model text or browser-provided shell command is accepted.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AwsRemediationBackendError(RuntimeError):
    """AWS CLI or response-shape failure kept inside the backend boundary."""


class AwsRemediationTimeout(AwsRemediationBackendError):
    """The SSM command did not reach a terminal state in the bounded wait."""


class _AwsCli:
    def __init__(self, *, region: str, profile: str = "amit") -> None:
        self.region = region
        self.profile = profile

    def call(self, service: str, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
            json.dump(payload, handle)
            handle.flush()
            completed = subprocess.run(
                [
                    "aws",
                    "--profile",
                    self.profile,
                    "--region",
                    self.region,
                    service,
                    operation,
                    "--cli-input-json",
                    f"file://{handle.name}",
                    "--output",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
        if completed.returncode != 0:
            raise AwsRemediationBackendError("AWS SSM backend unavailable.")
        try:
            value = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AwsRemediationBackendError("AWS SSM returned invalid data.") from exc
        if not isinstance(value, dict):
            raise AwsRemediationBackendError("AWS SSM returned an invalid object.")
        return value


_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
_TERMINAL = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}


def _validate_package(package_name: str, fixed_version: str) -> None:
    if not _PACKAGE_RE.fullmatch(package_name) or not _VERSION_RE.fullmatch(fixed_version):
        raise AwsRemediationBackendError("Package scope failed the remediation contract.")


def _package_target(package_name: str, fixed_version: str) -> str:
    _validate_package(package_name, fixed_version)
    # Inspector reports the RPM epoch (for example ``0:2.7...``), but yum's
    # name-version-release selector expects the epoch to be omitted. Keep the
    # original Inspector value in evidence while translating only the command
    # argument at this boundary.
    yum_version = fixed_version.split(":", 1)[1] if ":" in fixed_version else fixed_version
    return f"{package_name}-{yum_version}"


def _preflight_command(target: str) -> str:
    quoted_target = shlex.quote(target)
    return "\n".join(
        [
            "set -eu",
            "printf 'SECCOP_PREFLIGHT=START\\n'",
            "command -v yum >/dev/null 2>&1",
            "command -v timeout >/dev/null 2>&1",
            "temp_dir=$(mktemp -d /tmp/seccop-source-preflight.XXXXXX)",
            "cleanup() { rm -rf \"$temp_dir\"; }",
            "trap cleanup EXIT",
            f"timeout 75 yum -q install -y --downloadonly --downloaddir=\"$temp_dir\" {quoted_target}",
            "find \"$temp_dir\" -maxdepth 1 -type f -name '*.rpm' | grep -q .",
            "printf 'SECCOP_PREFLIGHT=READY\\n'",
        ]
    )


def _install_command(target: str) -> str:
    quoted_target = shlex.quote(target)
    return "\n".join(
        [
            "set -eu",
            "printf 'SECCOP_INSTALL=START\\n'",
            f"timeout 120 yum install -y {quoted_target}",
            "printf 'SECCOP_INSTALL=SUCCESS\\n'",
        ]
    )


def _verification_command(package_name: str) -> str:
    if not _PACKAGE_RE.fullmatch(package_name):
        raise AwsRemediationBackendError("Package scope failed the remediation contract.")
    quoted_package = shlex.quote(package_name)
    return "\n".join(
        [
            "set -eu",
            "printf 'SECCOP_VERIFY=START\\n'",
            f"rpm -q --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}\\n' {quoted_package}",
            "printf 'SECCOP_VERIFY=SUCCESS\\n'",
        ]
    )


def _verified_version(stdout: object, package_name: str) -> str | None:
    if not isinstance(stdout, str):
        return None
    prefix = f"{package_name}-"
    for line in stdout.splitlines():
        value = line.strip()
        if value.startswith(prefix) and len(value) > len(prefix):
            return value[len(prefix) :]
    return None


def _send(cli: _AwsCli, *, instance_id: str, command: str, comment: str) -> str:
    response = cli.call(
        "ssm",
        "send-command",
        {
            "DocumentName": "AWS-RunShellScript",
            "InstanceIds": [instance_id],
            "Parameters": {"commands": [command]},
            "Comment": comment,
        },
    )
    command_id = response.get("Command", {}).get("CommandId")
    if not isinstance(command_id, str) or not command_id:
        raise AwsRemediationBackendError("SSM did not return a command identifier.")
    return command_id


def _wait(cli: _AwsCli, *, command_id: str, instance_id: str, timeout_seconds: int = 180) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: AwsRemediationBackendError | None = None
    while time.monotonic() < deadline:
        try:
            response = cli.call(
                "ssm",
                "get-command-invocation",
                {"CommandId": command_id, "InstanceId": instance_id},
            )
            status = response.get("Status")
            if isinstance(status, str) and status in _TERMINAL:
                return response
        except AwsRemediationBackendError as exc:
            last_error = exc
        time.sleep(2)
    if last_error is not None:
        raise AwsRemediationTimeout("SSM command wait timed out.") from last_error
    raise AwsRemediationTimeout("SSM command wait timed out.")


def _write_json(directory: Path, name: str, value: object) -> None:
    (directory / name).write_text(
        json.dumps(value, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _evidence_dir() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = Path.home() / ".AGENTS-temp" / "agentic-ai-cybersecurity-lab" / "ssm-remediation" / stamp
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def execute_package_remediation(
    *,
    region: str,
    instance_id: str,
    cve_id: str,
    package_name: str,
    fixed_version: str,
) -> dict[str, object]:
    """Preflight the package source, install one exact package, and save evidence.

    The function performs a mutation only when the caller has already passed
    the approval gate. It never reboots the host.
    """

    target = _package_target(package_name, fixed_version)
    evidence = _evidence_dir()
    _write_json(
        evidence,
        "request.json",
        {
            "region": region,
            "instance_id": instance_id,
            "cve_id": cve_id,
            "package_name": package_name,
            "fixed_version": fixed_version,
            "reboot_approved": False,
            "operation": "one-package-yum-install",
        },
    )
    _write_json(evidence, "preflight-command.json", {"document": "AWS-RunShellScript", "command": _preflight_command(target)})
    _write_json(evidence, "install-command.json", {"document": "AWS-RunShellScript", "command": _install_command(target)})

    cli = _AwsCli(region=region)
    try:
        preflight_id = _send(
            cli,
            instance_id=instance_id,
            command=_preflight_command(target),
            comment="Security Copilot package-source check",
        )
        _write_json(evidence, "preflight-dispatch.json", {"command_id": preflight_id})
        preflight = _wait(cli, command_id=preflight_id, instance_id=instance_id)
    except AwsRemediationTimeout:
        _write_json(evidence, "summary.json", {"stage": "preflight", "status": "TIMEOUT"})
        return {
            "change_state": "NOT_STARTED",
            "reason_code": "SSM_COMMAND_TIMEOUT",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": False,
            "executed_calls": ("ssm.send_command", "ssm.get_command_invocation"),
            "evidence_path": str(evidence),
        }
    except AwsRemediationBackendError:
        return {
            "change_state": "NOT_STARTED",
            "reason_code": "AWS_BACKEND_UNAVAILABLE",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": False,
            "executed_calls": (),
            "evidence_path": str(evidence),
        }
    _write_json(evidence, "preflight-response.json", preflight)
    preflight_status = preflight.get("Status")
    if preflight_status != "Success":
        _write_json(evidence, "summary.json", {"stage": "preflight", "status": preflight_status})
        return {
            "change_state": "NOT_STARTED",
            "reason_code": "SSM_PACKAGE_SOURCE_NOT_READY",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": False,
            "executed_calls": ("ssm.send_command", "ssm.get_command_invocation"),
            "evidence_path": str(evidence),
        }

    try:
        install_id = _send(
            cli,
            instance_id=instance_id,
            command=_install_command(target),
            comment="Security Copilot approved package remediation",
        )
        _write_json(evidence, "install-dispatch.json", {"command_id": install_id})
    except AwsRemediationBackendError:
        return {
            "change_state": "NOT_STARTED",
            "reason_code": "AWS_BACKEND_UNAVAILABLE",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": False,
            "executed_calls": ("ssm.send_command",),
            "evidence_path": str(evidence),
        }
    try:
        install = _wait(cli, command_id=install_id, instance_id=instance_id)
    except AwsRemediationTimeout:
        _write_json(evidence, "summary.json", {"stage": "install", "status": "TIMEOUT"})
        return {
            "change_state": "ATTEMPTED",
            "reason_code": "SSM_COMMAND_TIMEOUT",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": True,
            "executed_calls": ("ssm.send_command", "ssm.get_command_invocation"),
            "evidence_path": str(evidence),
        }
    except AwsRemediationBackendError:
        return {
            "change_state": "ATTEMPTED",
            "reason_code": "AWS_BACKEND_UNAVAILABLE",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": True,
            "executed_calls": ("ssm.send_command", "ssm.get_command_invocation"),
            "evidence_path": str(evidence),
        }
    _write_json(evidence, "install-response.json", install)
    install_status = install.get("Status")
    if install_status != "Success":
        _write_json(evidence, "summary.json", {"stage": "install", "status": install_status})
        return {
            "change_state": "ATTEMPTED",
            "reason_code": "SSM_COMMAND_FAILED",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": True,
            "executed_calls": ("ssm.send_command", "ssm.get_command_invocation"),
            "evidence_path": str(evidence),
        }

    verification_command = _verification_command(package_name)
    _write_json(
        evidence,
        "verification-command.json",
        {"document": "AWS-RunShellScript", "command": verification_command},
    )
    try:
        verification_id = _send(
            cli,
            instance_id=instance_id,
            command=verification_command,
            comment="Security Copilot package version verification",
        )
        _write_json(evidence, "verification-dispatch.json", {"command_id": verification_id})
        verification = _wait(cli, command_id=verification_id, instance_id=instance_id)
    except (AwsRemediationTimeout, AwsRemediationBackendError):
        return {
            "change_state": "ATTEMPTED",
            "reason_code": "SSM_VERIFICATION_FAILED",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": True,
            "executed_calls": (
                "ssm.send_command",
                "ssm.get_command_invocation",
            ),
            "evidence_path": str(evidence),
        }
    _write_json(evidence, "verification-response.json", verification)
    verification_status = verification.get("Status")
    after_version = _verified_version(verification.get("StandardOutputContent"), package_name)
    if verification_status != "Success" or after_version is None:
        _write_json(
            evidence,
            "summary.json",
            {
                "stage": "verification",
                "status": verification_status,
                "after_version": after_version,
            },
        )
        return {
            "change_state": "ATTEMPTED",
            "reason_code": "SSM_VERIFICATION_FAILED",
            "verification_status": "NOT_AVAILABLE",
            "mutation_performed": True,
            "executed_calls": (
                "ssm.send_command",
                "ssm.get_command_invocation",
            ),
            "evidence_path": str(evidence),
        }
    _write_json(
        evidence,
        "summary.json",
        {"stage": "verification", "status": verification_status, "after_version": after_version},
    )
    return {
        "change_state": "COMPLETED",
        "reason_code": "SSM_PACKAGE_VERSION_VERIFIED",
        "verification_status": "VERIFIED",
        "mutation_performed": True,
        "executed_calls": (
            "ssm.send_command",
            "ssm.get_command_invocation",
        ),
        "after_version": after_version,
        "evidence_path": str(evidence),
    }
