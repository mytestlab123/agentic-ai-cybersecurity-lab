"""Exact-target AWS CLI adapter for the SecCop browser comparison."""

from __future__ import annotations

import json
import subprocess
import tempfile
from typing import Any

from .aws_read_only import AwsReadOnlyEvidenceSource
from .contracts import ReadOnlyTarget, AwsReadOnlyResult


class AwsLiveBackendError(RuntimeError):
    """Generic backend failure; AWS stderr never crosses the UI boundary."""


class _AwsCli:
    def __init__(self, region: str, profile: str = "amit") -> None:
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
            raise AwsLiveBackendError("AWS backend unavailable.")
        if not completed.stdout.strip():
            return {}
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise AwsLiveBackendError("AWS backend returned invalid data.") from exc
        if not isinstance(value, dict):
            raise AwsLiveBackendError("AWS backend returned an invalid object.")
        return value


class _Inspector:
    def __init__(self, cli: _AwsCli) -> None:
        self.cli = cli

    def list_findings(self, **kwargs: Any) -> dict[str, Any]:
        return self.cli.call("inspector2", "list-findings", kwargs)


class _Ec2:
    def __init__(self, cli: _AwsCli) -> None:
        self.cli = cli

    def describe_instances(self, **kwargs: Any) -> dict[str, Any]:
        return self.cli.call("ec2", "describe-instances", kwargs)


class _Ssm:
    def __init__(self, cli: _AwsCli) -> None:
        self.cli = cli

    def describe_instance_information(self, **kwargs: Any) -> dict[str, Any]:
        return self.cli.call("ssm", "describe-instance-information", kwargs)

    def list_inventory_entries(self, **kwargs: Any) -> dict[str, Any]:
        return self.cli.call("ssm", "list-inventory-entries", kwargs)

    def describe_instance_patch_states(self, **kwargs: Any) -> dict[str, Any]:
        return self.cli.call("ssm", "describe-instance-patch-states", kwargs)


def collect_live_evidence(
    *,
    region: str,
    instance_id: str,
    cve_id: str,
    resource_alias: str = "EC2_RESOURCE_01",
) -> AwsReadOnlyResult:
    """Run the existing fail-closed adapter against one exact target."""

    cli = _AwsCli(region)
    source = AwsReadOnlyEvidenceSource(
        _Inspector(cli),
        _Ec2(cli),
        _Ssm(cli),
        required_tags={"Project": "Security Copilot", "Environment": "seccop-demo"},
    )
    return source.collect(
        cve_id,
        ReadOnlyTarget(resource_alias=resource_alias, instance_id=instance_id),
        include_patch_summary=False,
    )
