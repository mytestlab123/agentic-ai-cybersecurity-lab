from collections.abc import Mapping

from secure_agent_harness.aws_read_only import AwsReadOnlyEvidenceSource
from secure_agent_harness.contracts import ReadOnlyTarget


TARGET = ReadOnlyTarget(resource_alias="EC2_RESOURCE_01", instance_id="INSTANCE_ID_01")


class FakeInspector:
    def __init__(self, findings: list[Mapping[str, object]], fail: bool = False) -> None:
        self.findings = findings
        self.fail = fail
        self.calls: list[dict[str, object]] = []

    def list_findings(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("attacker-controlled backend detail")
        return {"findings": self.findings}


class FakeEc2:
    def __init__(self, instance: Mapping[str, object]) -> None:
        self.instance = instance
        self.calls: list[dict[str, object]] = []

    def describe_instances(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(kwargs)
        return {"Reservations": [{"Instances": [self.instance]}]}


class FakeSsm:
    def __init__(self, node: Mapping[str, object] | None) -> None:
        self.node = node
        self.calls: list[dict[str, object]] = []

    def describe_instance_information(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(kwargs)
        return {"InstanceInformationList": [] if self.node is None else [self.node]}


def finding(instance_id: str = "INSTANCE_ID_01") -> dict[str, object]:
    return {
        "findingArn": "arn:aws:inspector2:REGION:ACCOUNT_ID:finding/FINDING_ID",
        "awsAccountId": "ACCOUNT_ID",
        "status": "ACTIVE",
        "severity": "HIGH",
        "description": "attacker-controlled finding text",
        "resources": [{"type": "AWS_EC2_INSTANCE", "id": instance_id}],
    }


def instance(tags: list[dict[str, str]] | None = None) -> dict[str, object]:
    return {
        "InstanceId": "INSTANCE_ID_01",
        "PrivateIpAddress": "PRIVATE_IP_01",
        "State": {"Name": "running"},
        "Tags": tags
        if tags is not None
        else [
            {"Key": "Project", "Value": "agentcore-inspector-ssm-poc"},
            {"Key": "Environment", "Value": "lab"},
        ],
    }


def node(ping_status: str = "Online") -> dict[str, object]:
    return {
        "InstanceId": "INSTANCE_ID_01",
        "PingStatus": ping_status,
        "IPAddress": "PRIVATE_IP_01",
        "PlatformType": "Linux",
    }


def source(
    findings: list[Mapping[str, object]] | None = None,
    tags: list[dict[str, str]] | None = None,
    ssm_node: Mapping[str, object] | None = None,
    inspector_fail: bool = False,
) -> tuple[AwsReadOnlyEvidenceSource, FakeInspector, FakeEc2, FakeSsm]:
    inspector = FakeInspector(findings if findings is not None else [finding()], inspector_fail)
    ec2 = FakeEc2(instance(tags))
    ssm = FakeSsm(node() if ssm_node is None else ssm_node)
    return AwsReadOnlyEvidenceSource(inspector, ec2, ssm), inspector, ec2, ssm


def test_ready_evidence_is_exactly_bound_and_sanitized() -> None:
    evidence_source, inspector, ec2, ssm = source()

    result = evidence_source.collect("cve-2099-0001", TARGET)

    assert result.status == "READY"
    assert result.reason_code == "READ_ONLY_EVIDENCE_READY"
    assert result.evidence.finding_ec2_bound is True
    assert result.evidence.expected_tags_verified is True
    assert result.evidence.ssm_readiness == "READY"
    assert result.executed_calls == (
        "inspector.list_findings",
        "ec2.describe_instances",
        "ssm.describe_instance_information",
    )
    assert inspector.calls[0]["filterCriteria"] == {
        "vulnerabilityId": [{"comparison": "EQUALS", "value": "CVE-2099-0001"}]
    }
    assert ec2.calls[0] == {"InstanceIds": ["INSTANCE_ID_01"]}
    assert ssm.calls[0] == {
        "Filters": [{"Key": "InstanceIds", "Values": ["INSTANCE_ID_01"]}],
        "MaxResults": 50,
    }
    serialized = result.model_dump_json()
    for raw_value in (
        "INSTANCE_ID_01",
        "PRIVATE_IP_01",
        "ACCOUNT_ID",
        "FINDING_ID",
        "attacker-controlled finding text",
    ):
        assert raw_value not in serialized


def test_zero_findings_blocks_before_ec2_or_ssm() -> None:
    evidence_source, _inspector, ec2, ssm = source(findings=[])

    result = evidence_source.collect("CVE-2099-0001", TARGET)

    assert result.status == "BLOCKED"
    assert result.reason_code == "FINDING_NOT_FOUND"
    assert result.executed_calls == ("inspector.list_findings",)
    assert ec2.calls == []
    assert ssm.calls == []


def test_multiple_findings_blocks_as_ambiguous() -> None:
    evidence_source, _inspector, ec2, ssm = source(findings=[finding(), finding()])

    result = evidence_source.collect("CVE-2099-0001", TARGET)

    assert result.status == "BLOCKED"
    assert result.reason_code == "FINDING_AMBIGUOUS"
    assert ec2.calls == []
    assert ssm.calls == []


def test_finding_for_a_different_instance_blocks_before_ec2() -> None:
    evidence_source, _inspector, ec2, ssm = source(findings=[finding("OTHER_INSTANCE_01")])

    result = evidence_source.collect("CVE-2099-0001", TARGET)

    assert result.status == "BLOCKED"
    assert result.reason_code == "FINDING_RESOURCE_MISMATCH"
    assert ec2.calls == []
    assert ssm.calls == []


def test_missing_required_tags_blocks_before_ssm() -> None:
    evidence_source, _inspector, ec2, ssm = source(
        tags=[{"Key": "Project", "Value": "wrong-project"}]
    )

    result = evidence_source.collect("CVE-2099-0001", TARGET)

    assert result.status == "BLOCKED"
    assert result.reason_code == "EC2_TAGS_MISMATCH"
    assert len(ec2.calls) == 1
    assert ssm.calls == []


def test_ssm_not_ready_is_a_no_go() -> None:
    evidence_source, _inspector, _ec2, _ssm = source(ssm_node=node("ConnectionLost"))

    result = evidence_source.collect("CVE-2099-0001", TARGET)

    assert result.status == "BLOCKED"
    assert result.reason_code == "SSM_NODE_NOT_READY"
    assert result.executed_calls == (
        "inspector.list_findings",
        "ec2.describe_instances",
        "ssm.describe_instance_information",
    )


def test_backend_error_is_generic_and_fail_closed() -> None:
    evidence_source, _inspector, ec2, ssm = source(inspector_fail=True)

    result = evidence_source.collect("CVE-2099-0001", TARGET)

    assert result.status == "BLOCKED"
    assert result.reason_code == "READ_BACKEND_FAILED"
    assert result.message == "Read-only AWS evidence did not pass the required binding gate."
    assert result.executed_calls == ("inspector.list_findings",)
    assert ec2.calls == []
    assert ssm.calls == []
    assert "attacker-controlled backend detail" not in result.model_dump_json()
