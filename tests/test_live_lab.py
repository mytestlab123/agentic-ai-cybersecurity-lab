import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

from issue5_live_lab import LaunchPlan, apply_plan, build_plan  # noqa: E402


class FakeAws:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def identity_check(self) -> None:
        self.calls.append(("sts", "get-caller-identity", {}))

    def call(self, service: str, operation: str, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append((service, operation, payload))
        if operation == "describe-images":
            return {"Images": [{"State": "available", "OwnerId": "OWNER_A"}]}
        if operation == "describe-subnets":
            return {
                "Subnets": [
                    {
                        "VpcId": "VPC_A",
                        "State": "available",
                        "MapPublicIpOnLaunch": True,
                    }
                ]
            }
        if operation == "describe-route-tables":
            return {
                "RouteTables": [
                    {
                        "Associations": [{"Main": True}],
                        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-A"}],
                    }
                ]
            }
        if operation == "describe-vpc-endpoints":
            return {"VpcEndpoints": []}
        if operation == "describe-security-groups":
            return {"SecurityGroups": [{"IpPermissions": [], "IpPermissionsEgress": [{}]}]}
        if operation == "get-instance-profile":
            return {"InstanceProfile": {"InstanceProfileName": "PROFILE_A"}}
        if operation == "batch-get-account-status":
            return {
                "accounts": [
                    {"resourceState": {"ec2": {"status": "ENABLED"}}}
                ]
            }
        raise AssertionError(f"unexpected operation: {operation}")


def args() -> argparse.Namespace:
    return argparse.Namespace(
        image_id="AMI_A",
        image_owner="OWNER_A",
        subnet_id="SUBNET_A",
        security_group_id="SG_A",
        iam_instance_profile="PROFILE_A",
        instance_type="t3.small",
        region="ap-southeast-1",
        name="issue5-lab",
        owner="amit",
        ttl_hours=24,
        ttl="25-08-26",
        revision="2ab0e2c",
        confirm=False,
    )


def test_plan_blocks_public_subnet_even_when_other_checks_pass() -> None:
    fake = FakeAws()

    plan = build_plan(args(), fake)

    assert plan.image_ready is True
    assert plan.security_group_ready is True
    assert plan.iam_ready is True
    assert plan.inspector_enabled is True
    assert plan.private_network_ready is False
    assert plan.ready is False


def test_apply_requires_confirmation_before_run_instances() -> None:
    fake = FakeAws()
    plan = LaunchPlan(
        image_id="AMI_A",
        subnet_id="SUBNET_A",
        security_group_id="SG_A",
        iam_instance_profile="PROFILE_A",
        instance_type="t3.small",
        vpc_id="VPC_A",
        inspector_enabled=True,
        private_network_ready=True,
        security_group_ready=True,
        iam_ready=True,
        image_ready=True,
    )

    assert apply_plan(args(), fake, plan) == 2
    assert all(operation != "run-instances" for _service, operation, _payload in fake.calls)
