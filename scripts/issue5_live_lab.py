#!/usr/bin/env python3
"""Bounded Issue 5 EC2/Inspector/SSM lab operator.

The default command is a read-only preflight.  ``apply`` is deliberately
explicit, requires every target boundary, refuses public networking, and
launches exactly one tagged instance.  ``collect`` only reads exact-target
Inspector, EC2, and SSM evidence and writes the sanitized result consumed by
the local UI.  Raw AWS responses and identifiers never enter that result.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Keep the operator runnable from a clean checkout without requiring an
# editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_agent_harness.aws_read_only import AwsReadOnlyEvidenceSource
from secure_agent_harness.contracts import ReadOnlyTarget


REPO_NAME = "agentic-ai-cybersecurity-lab"
PROJECT_TAG = "agentcore-inspector-ssm-poc"
ENVIRONMENT_TAG = "lab"
DEFAULT_ALIAS = "EC2_RESOURCE_01"
DEFAULT_INSTANCE_TYPE = "t3.small"
DEFAULT_VOLUME_SIZE = 20
DEFAULT_EVIDENCE_DIR = Path.home() / ".AGENTS-temp" / REPO_NAME / "live-lab"


class BackendFailure(RuntimeError):
    """A generic CLI failure that must not expose backend text."""


class AwsCli:
    def __init__(self, profile: str, region: str) -> None:
        self.profile = profile
        self.region = region

    def call(self, service: str, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
            json.dump(payload, handle)
            handle.flush()
            command = [
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
            ]
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        if completed.returncode != 0:
            raise BackendFailure("AWS read failed.")
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise BackendFailure("AWS returned invalid JSON.") from exc
        if not isinstance(value, dict):
            raise BackendFailure("AWS returned an invalid object.")
        return value

    def identity_check(self) -> None:
        command = [
            "aws",
            "--profile",
            self.profile,
            "--region",
            self.region,
            "sts",
            "get-caller-identity",
            "--output",
            "json",
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            raise BackendFailure("AWS identity check failed.")

    def wait_terminated(self, instance_id: str) -> None:
        command = [
            "aws",
            "--profile",
            self.profile,
            "--region",
            self.region,
            "ec2",
            "wait",
            "instance-terminated",
            "--instance-ids",
            instance_id,
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            raise BackendFailure("Instance termination was not confirmed.")


class InspectorClient:
    def __init__(self, aws: AwsCli) -> None:
        self.aws = aws

    def list_findings(self, **kwargs: Any) -> dict[str, Any]:
        return self.aws.call("inspector2", "list-findings", kwargs)


class Ec2Client:
    def __init__(self, aws: AwsCli) -> None:
        self.aws = aws

    def describe_instances(self, **kwargs: Any) -> dict[str, Any]:
        return self.aws.call("ec2", "describe-instances", kwargs)


class SsmClient:
    def __init__(self, aws: AwsCli) -> None:
        self.aws = aws

    def describe_instance_information(self, **kwargs: Any) -> dict[str, Any]:
        return self.aws.call("ssm", "describe-instance-information", kwargs)

    def list_inventory_entries(self, **kwargs: Any) -> dict[str, Any]:
        return self.aws.call("ssm", "list-inventory-entries", kwargs)


@dataclass(frozen=True)
class LaunchPlan:
    image_id: str
    subnet_id: str
    security_group_id: str
    iam_instance_profile: str
    instance_type: str
    vpc_id: str
    inspector_enabled: bool
    private_network_ready: bool
    security_group_ready: bool
    iam_ready: bool
    image_ready: bool

    @property
    def ready(self) -> bool:
        return all(
            (
                self.image_ready,
                self.private_network_ready,
                self.security_group_ready,
                self.iam_ready,
                self.inspector_enabled,
            )
        )


def _single(items: Any) -> dict[str, Any] | None:
    return items[0] if isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict) else None


def _selected_route_table(route_tables: list[dict[str, Any]], subnet_id: str) -> dict[str, Any] | None:
    for route_table in route_tables:
        associations = route_table.get("Associations", [])
        if any(
            isinstance(association, dict)
            and association.get("SubnetId") == subnet_id
            for association in associations
        ):
            return route_table
    for route_table in route_tables:
        associations = route_table.get("Associations", [])
        if any(isinstance(association, dict) and association.get("Main") for association in associations):
            return route_table
    return None


def build_plan(args: argparse.Namespace, aws: AwsCli) -> LaunchPlan:
    aws.identity_check()
    try:
        image_response = aws.call(
            "ec2",
            "describe-images",
            {"ImageIds": [args.image_id], "Owners": [args.image_owner]},
        )
    except BackendFailure:
        image_response = {"Images": []}
    image = _single(image_response.get("Images"))
    image_ready = bool(
        image
        and image.get("State") == "available"
        and str(image.get("OwnerId")) == args.image_owner
    )

    try:
        subnet_response = aws.call(
            "ec2",
            "describe-subnets",
            {"SubnetIds": [args.subnet_id]},
        )
    except BackendFailure:
        subnet_response = {"Subnets": []}
    subnet = _single(subnet_response.get("Subnets"))
    vpc_id = str(subnet.get("VpcId")) if subnet else ""
    route_response = (
        aws.call("ec2", "describe-route-tables", {"Filters": [{"Name": "vpc-id", "Values": [vpc_id]}]})
        if vpc_id
        else {"RouteTables": []}
    )
    route_table = _selected_route_table(route_response.get("RouteTables", []), args.subnet_id)
    endpoint_response = (
        aws.call("ec2", "describe-vpc-endpoints", {"Filters": [{"Name": "vpc-id", "Values": [vpc_id]}]})
        if vpc_id
        else {"VpcEndpoints": []}
    )
    endpoint_services = {
        str(endpoint.get("ServiceName"))
        for endpoint in endpoint_response.get("VpcEndpoints", [])
        if isinstance(endpoint, dict) and endpoint.get("State") == "available"
    }
    required_endpoint_names = {
        f"com.amazonaws.{args.region}.{service}" for service in ("ssm", "ssmmessages", "ec2messages")
    }
    has_ssm_endpoints = required_endpoint_names.issubset(endpoint_services)
    routes = route_table.get("Routes", []) if route_table else []
    default_route = next(
        (
            route
            for route in routes
            if isinstance(route, dict) and route.get("DestinationCidrBlock") == "0.0.0.0/0"
        ),
        None,
    )
    default_target = str(default_route.get("NatGatewayId", "")) if default_route else ""
    private_network_ready = bool(
        subnet
        and subnet.get("State") == "available"
        and subnet.get("MapPublicIpOnLaunch") is False
        and (has_ssm_endpoints or default_target.startswith("nat-"))
    )

    try:
        group_response = aws.call(
            "ec2",
            "describe-security-groups",
            {"GroupIds": [args.security_group_id]},
        )
    except BackendFailure:
        group_response = {"SecurityGroups": []}
    group = _single(group_response.get("SecurityGroups"))
    security_group_ready = bool(
        group
        and len(group.get("IpPermissions", [])) == 0
        and len(group.get("IpPermissionsEgress", [])) > 0
    )

    try:
        profile_response = aws.call(
            "iam",
            "get-instance-profile",
            {"InstanceProfileName": args.iam_instance_profile},
        )
    except BackendFailure:
        profile_response = {}
    iam_ready = bool(profile_response.get("InstanceProfile"))

    account_status = aws.call("inspector2", "batch-get-account-status", {})
    status = account_status.get("accounts", [])
    account = _single(status) or {}
    resource_state = account.get("resourceState", {})
    ec2_state = resource_state.get("ec2", {}) if isinstance(resource_state, dict) else {}
    inspector_enabled = str(ec2_state.get("status", account.get("resourceStatus", ""))).upper() == "ENABLED"

    return LaunchPlan(
        image_id=args.image_id,
        subnet_id=args.subnet_id,
        security_group_id=args.security_group_id,
        iam_instance_profile=args.iam_instance_profile,
        instance_type=args.instance_type,
        vpc_id=vpc_id,
        inspector_enabled=inspector_enabled,
        private_network_ready=private_network_ready,
        security_group_ready=security_group_ready,
        iam_ready=iam_ready,
        image_ready=image_ready,
    )


def print_plan(plan: LaunchPlan) -> None:
    print("LIVE_LAB_PLAN")
    print("IMAGE_AVAILABLE", "PASS" if plan.image_ready else "NO_GO")
    print("PRIVATE_SSM_NETWORK", "PASS" if plan.private_network_ready else "NO_GO")
    print("SECURITY_GROUP_NO_INGRESS", "PASS" if plan.security_group_ready else "NO_GO")
    print("IAM_INSTANCE_PROFILE", "PASS" if plan.iam_ready else "NO_GO")
    print("INSPECTOR_ENABLED", "PASS" if plan.inspector_enabled else "NO_GO")
    print("LAUNCH", "READY" if plan.ready else "BLOCKED")


def _tags(args: argparse.Namespace) -> list[dict[str, str]]:
    expires = datetime.now(timezone.utc) + timedelta(hours=args.ttl_hours)
    return [
        {"Key": "Name", "Value": args.name},
        {"Key": "Project", "Value": PROJECT_TAG},
        {"Key": "Environment", "Value": ENVIRONMENT_TAG},
        {"Key": "Owner", "Value": args.owner},
        {"Key": "Purpose", "Value": "inspector-ssm-vulnerability-lab"},
        {"Key": "Issue", "Value": "5"},
        {"Key": "Repo", "Value": REPO_NAME},
        {"Key": "TTLHours", "Value": str(args.ttl_hours)},
        {"Key": "ExpiresAt", "Value": expires.isoformat()},
        {"Key": "Cleanup", "Value": "terminate-after-demo"},
    ]


def apply_plan(args: argparse.Namespace, aws: AwsCli, plan: LaunchPlan) -> int:
    if not args.confirm:
        print("BLOCKED CONFIRMATION_REQUIRED")
        return 2
    if not plan.ready:
        print("BLOCKED PREFLIGHT_NO_GO")
        return 2
    command_payload = {
        "ImageId": args.image_id,
        "InstanceType": args.instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "IamInstanceProfile": {"Name": args.iam_instance_profile},
        "NetworkInterfaces": [
            {
                "DeviceIndex": 0,
                "SubnetId": args.subnet_id,
                "Groups": [args.security_group_id],
                "AssociatePublicIpAddress": False,
                "DeleteOnTermination": True,
            }
        ],
        "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1},
        "BlockDeviceMappings": [
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {
                    "DeleteOnTermination": True,
                    "VolumeType": "gp3",
                    "VolumeSize": DEFAULT_VOLUME_SIZE,
                    "Encrypted": True,
                },
            }
        ],
        "TagSpecifications": [{"ResourceType": "instance", "Tags": _tags(args)}],
    }
    response = aws.call("ec2", "run-instances", command_payload)
    instances = response.get("Instances")
    instance = _single(instances)
    if not instance or not instance.get("InstanceId"):
        print("BLOCKED LAUNCH_RESPONSE_INVALID")
        return 2
    instance_id = str(instance["InstanceId"])
    readback = aws.call("ec2", "describe-instances", {"InstanceIds": [instance_id]})
    launched = _single(
        [
            item
            for reservation in readback.get("Reservations", [])
            if isinstance(reservation, dict)
            for item in reservation.get("Instances", [])
            if isinstance(item, dict) and item.get("InstanceId") == instance_id
        ]
    )
    if (
        not launched
        or launched.get("PublicIpAddress") is not None
        or launched.get("SubnetId") != args.subnet_id
    ):
        print("BLOCKED LAUNCH_NETWORK_READBACK")
        return 2
    DEFAULT_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (DEFAULT_EVIDENCE_DIR / "target.json").write_text(
        json.dumps({"instance_id": instance_id, "resource_alias": DEFAULT_ALIAS}, indent=2) + "\n",
        encoding="utf-8",
    )
    print("INSTANCE_CREATED")
    print("RESOURCE_ALIAS", DEFAULT_ALIAS)
    print("PUBLIC_IP", "MUST_BE_NULL")
    return 0


def collect(args: argparse.Namespace, aws: AwsCli) -> int:
    instance_id = args.instance_id
    if not instance_id:
        target_file = args.target_file or (DEFAULT_EVIDENCE_DIR / "target.json")
        try:
            instance_id = str(json.loads(Path(target_file).read_text(encoding="utf-8"))["instance_id"])
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            print("BLOCKED TARGET_NOT_FOUND")
            return 2
    target = ReadOnlyTarget(resource_alias=args.resource_alias, instance_id=instance_id)
    source = AwsReadOnlyEvidenceSource(InspectorClient(aws), Ec2Client(aws), SsmClient(aws))
    result = source.collect(args.cve_id, target, include_patch_summary=True)
    output = args.output or (DEFAULT_EVIDENCE_DIR / "sanitized-evidence.json")
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    print("EVIDENCE_STATUS", result.status)
    print("REASON_CODE", result.reason_code)
    print("EVIDENCE_FILE", output_path)
    return 0 if result.status == "READY" else 2


def cleanup(args: argparse.Namespace, aws: AwsCli) -> int:
    if not args.confirm:
        print("BLOCKED CONFIRMATION_REQUIRED")
        return 2
    instance_id = args.instance_id
    if not instance_id:
        target_file = args.target_file or (DEFAULT_EVIDENCE_DIR / "target.json")
        try:
            instance_id = str(json.loads(Path(target_file).read_text(encoding="utf-8"))["instance_id"])
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            print("BLOCKED TARGET_NOT_FOUND")
            return 2
    response = aws.call("ec2", "describe-instances", {"InstanceIds": [instance_id]})
    instance = _single(
        [
            item
            for reservation in response.get("Reservations", [])
            if isinstance(reservation, dict)
            for item in reservation.get("Instances", [])
            if isinstance(item, dict) and item.get("InstanceId") == instance_id
        ]
    )
    if not instance:
        print("CLEANUP_ALREADY_ABSENT")
        return 0
    tags = {tag.get("Key"): tag.get("Value") for tag in instance.get("Tags", []) if isinstance(tag, dict)}
    if tags.get("Project") != PROJECT_TAG or tags.get("Environment") != ENVIRONMENT_TAG:
        print("BLOCKED TARGET_TAGS_MISMATCH")
        return 2
    aws.call("ec2", "terminate-instances", {"InstanceIds": [instance_id]})
    aws.wait_terminated(instance_id)
    print("CLEANUP_CONFIRMED")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--profile", default="amit")
    root.add_argument("--region", default="ap-southeast-1")
    sub = root.add_subparsers(dest="command", required=True)
    for command in ("plan", "apply"):
        item = sub.add_parser(command)
        item.add_argument("--image-id", required=True)
        item.add_argument("--image-owner", required=True)
        item.add_argument("--subnet-id", required=True)
        item.add_argument("--security-group-id", required=True)
        item.add_argument("--iam-instance-profile", required=True)
        item.add_argument("--instance-type", default=DEFAULT_INSTANCE_TYPE)
        item.add_argument("--name", default="issue5-inspector-ssm-lab")
        item.add_argument("--owner", default="amit")
        item.add_argument("--ttl-hours", type=int, choices=range(1, 25), default=24)
        if command == "apply":
            item.add_argument("--confirm", action="store_true")
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--cve-id", required=True)
    collect_parser.add_argument("--instance-id")
    collect_parser.add_argument("--target-file", type=Path)
    collect_parser.add_argument("--resource-alias", default=DEFAULT_ALIAS)
    collect_parser.add_argument("--output", type=Path)
    cleanup_parser = sub.add_parser("cleanup")
    cleanup_parser.add_argument("--instance-id")
    cleanup_parser.add_argument("--target-file", type=Path)
    cleanup_parser.add_argument("--confirm", action="store_true")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        aws = AwsCli(args.profile, args.region)
        if args.command in {"plan", "apply"}:
            plan = build_plan(args, aws)
            print_plan(plan)
            if args.command == "apply":
                return apply_plan(args, aws, plan)
            return 0 if plan.ready else 2
        if args.command == "collect":
            return collect(args, aws)
        if args.command == "cleanup":
            return cleanup(args, aws)
    except (BackendFailure, ValueError):
        print("BLOCKED READ_BACKEND_FAILED")
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
