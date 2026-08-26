"""Exact-target AWS CLI adapter for the SecCop browser comparison."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any

from .aws_read_only import AwsReadOnlyEvidenceSource
from .contracts import ReadOnlyTarget, AwsReadOnlyResult


class AwsLiveBackendError(RuntimeError):
    """Generic backend failure; AWS stderr never crosses the UI boundary."""


class AwsLiveTargetError(AwsLiveBackendError):
    """Target discovery failure with a stable, UI-safe reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__("The configured live demo target could not be selected.")
        self.reason_code = reason_code


@dataclass(frozen=True)
class AwsTargetReadiness:
    status: str
    reason_code: str
    instance_state: str = "UNKNOWN"
    ssm_readiness: str = "UNKNOWN"
    executed_calls: tuple[str, ...] = ()


class _AwsCli:
    def __init__(self, region: str, profile: str | None = None) -> None:
        self.region = region
        self.profile = profile or os.environ.get("SECCOP_AWS_PROFILE", "vagent")

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


def resolve_demo_target(
    *,
    region: str,
    resource_alias: str = "EC2_RESOURCE_01",
) -> ReadOnlyTarget:
    """Resolve one running demo host without asking the user for an instance ID."""

    target_name = os.environ.get("SECCOP_TARGET_NAME", "seccop-project1-old-ami-host-r01")
    cli = _AwsCli(region)
    response = _Ec2(cli).describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": [target_name]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ],
    )
    reservations = response.get("Reservations")
    if not isinstance(reservations, list):
        raise AwsLiveTargetError("EC2_TARGET_NOT_FOUND")
    matches: list[str] = []
    for reservation in reservations:
        if not isinstance(reservation, dict):
            raise AwsLiveTargetError("EC2_TARGET_NOT_FOUND")
        instances = reservation.get("Instances")
        if not isinstance(instances, list):
            raise AwsLiveTargetError("EC2_TARGET_NOT_FOUND")
        for instance in instances:
            if isinstance(instance, dict) and isinstance(instance.get("InstanceId"), str):
                matches.append(instance["InstanceId"])
    if not matches:
        raise AwsLiveTargetError("EC2_TARGET_NOT_FOUND")
    if len(matches) != 1:
        raise AwsLiveTargetError("EC2_TARGET_AMBIGUOUS")
    return ReadOnlyTarget(resource_alias=resource_alias, instance_id=matches[0])


def collect_target_readiness(
    *,
    region: str,
    target: ReadOnlyTarget,
) -> AwsTargetReadiness:
    """Perform exact EC2 and SSM reads for the discovered target."""

    cli = _AwsCli(region)
    ec2 = _Ec2(cli)
    ssm = _Ssm(cli)
    calls: list[str] = []
    try:
        calls.append("ec2.describe_instances")
        response = ec2.describe_instances(InstanceIds=[target.instance_id])
        reservations = response.get("Reservations")
        instances: list[dict[str, Any]] = []
        if isinstance(reservations, list):
            for reservation in reservations:
                if isinstance(reservation, dict) and isinstance(reservation.get("Instances"), list):
                    instances.extend(
                        item for item in reservation["Instances"]
                        if isinstance(item, dict) and item.get("InstanceId") == target.instance_id
                    )
        if len(instances) != 1:
            return AwsTargetReadiness("BLOCKED", "EC2_TARGET_NOT_FOUND", executed_calls=tuple(calls))
        state = instances[0].get("State")
        state_name = state.get("Name", "UNKNOWN") if isinstance(state, dict) else "UNKNOWN"
        instance_state = str(state_name).upper()
        if instance_state != "RUNNING":
            return AwsTargetReadiness(
                "BLOCKED",
                "EC2_TARGET_NOT_READY",
                instance_state=instance_state,
                executed_calls=tuple(calls),
            )
        raw_tags = instances[0].get("Tags")
        tags = {
            item.get("Key"): item.get("Value")
            for item in raw_tags
            if isinstance(item, dict)
        } if isinstance(raw_tags, list) else {}
        if tags.get("Project") != "Security Copilot" or tags.get("Environment") != "seccop-demo":
            return AwsTargetReadiness(
                "BLOCKED",
                "EC2_TAGS_MISMATCH",
                instance_state=instance_state,
                executed_calls=tuple(calls),
            )
        calls.append("ssm.describe_instance_information")
        node_response = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [target.instance_id]}],
            MaxResults=50,
        )
        nodes = node_response.get("InstanceInformationList")
        matches = [
            node for node in nodes
            if isinstance(node, dict) and node.get("InstanceId") == target.instance_id
        ] if isinstance(nodes, list) else []
        if len(matches) != 1:
            return AwsTargetReadiness(
                "BLOCKED",
                "SSM_NODE_NOT_FOUND",
                instance_state=instance_state,
                executed_calls=tuple(calls),
            )
        readiness = "READY" if str(matches[0].get("PingStatus", "")).upper() == "ONLINE" else "NOT_READY"
        if readiness != "READY":
            return AwsTargetReadiness(
                "BLOCKED",
                "SSM_NODE_NOT_READY",
                instance_state=instance_state,
                ssm_readiness=readiness,
                executed_calls=tuple(calls),
            )
        return AwsTargetReadiness(
            "READY",
            "TARGET_READY",
            instance_state=instance_state,
            ssm_readiness=readiness,
            executed_calls=tuple(calls),
        )
    except (AwsLiveBackendError, OSError, TimeoutError):
        return AwsTargetReadiness("BLOCKED", "AWS_BACKEND_UNAVAILABLE", executed_calls=tuple(calls))
