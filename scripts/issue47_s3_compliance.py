#!/usr/bin/env python3
"""One bounded S3 Block Public Access SecCop proof; aliases stay public."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


CONFIG_RULE = "s3-bucket-level-public-access-prohibited"
CONFIG_SOURCE = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
CONFIG_RECORDER = "seccop-issue55-s3-recorder"
CONFIG_CHANNEL = "seccop-issue55-s3-delivery"
SSM_DOCUMENT = "AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock"
SSM_DOCUMENT_VERSION = "8"
AUTOMATION_ROLE = "SecCopIssue55S3Automation"
CONFIG_SERVICE_ROLE = "AWSServiceRoleForConfig"
CONFIG_TIMEOUT_SECONDS = 240

# Issue #55 EC2 compliance slice.  This remains in the existing bounded
# compliance operator so the EC2 path does not become a second runner.
EC2_CONFIG_RULE = "ec2-imdsv2-check"
EC2_CONFIG_SOURCE = "EC2_IMDSV2_CHECK"
EC2_SSM_DOCUMENT = "AWSConfigRemediation-EnforceEC2InstanceIMDSv2"
EC2_SSM_DOCUMENT_VERSION = "4"
EC2_AUTOMATION_ROLE = "SecCopIssue55S3Automation"
EC2_AUTOMATION_POLICY = "SecCopIssue55Ec2ImdsV2"
EC2_TARGET_NAME = "seccop-amit-inspector-host-r01"
EC2_INSTANCE_PROFILE = "AmazonSSMRoleForInstancesQuickSetup"
EC2_AMI_NAME = "al2023-ami-2023.12.20260831.0-kernel-6.18-x86_64"
EC2_CONFIG_TIMEOUT_SECONDS = 360
EC2_RETAIN_TTL = "01-10-26"
EC2_RETAIN_PURPOSE = "SecCop Issue 55 retained EC2 IMDSv2 Config demo"
EC2_DEV_REUSED_ROLE = "ami-factory-dev-demo-role"

# Issue #55 DEV R&D rearm. IDs stay in a mode-600 runtime map; hashes pin the
# map to the two approved targets without publishing identifiers in source.
EC2_RND_ALIAS_LAB01 = "DEV_EC2_LAB_01"
EC2_RND_ALIAS_LAB02 = "DEV_EC2_LAB_02"
EC2_RND_RULE_LAB01 = "ec2-imdsv2-check-rnd-lab01"
EC2_RND_TARGET_MAP = "SECCOP_EC2_RND_TARGET_MAP"
EC2_RND_ID_HASHES = {
    EC2_RND_ALIAS_LAB01: "0230ddaa9efd2c86f7b86e869df3a7c511a55174b782fd270f91aeca4c0afec2",
    EC2_RND_ALIAS_LAB02: "2f134e50a001511ff0147258b80e4e381506ccf5c8950e5cb055454dc66862e3",
}


def call(args: list[str], *, allow_missing: bool = False) -> dict[str, Any]:
    completed = subprocess.run(args, capture_output=True, text=True, check=False, timeout=60)
    if completed.returncode and not allow_missing:
        evidence("aws-error", {"command": args[3:] if len(args) > 3 else args, "stderr": completed.stderr[-2000:]})
        raise RuntimeError("AWS command failed")
    try:
        value = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("AWS returned invalid output") from exc
    return value if isinstance(value, dict) else {}


def aws(profile: str, region: str, *args: str, allow_missing: bool = False) -> dict[str, Any]:
    return call(["aws", "--profile", profile, "--region", region, *args, "--output", "json"], allow_missing=allow_missing)


def evidence(name: str, value: object) -> None:
    root = os.environ.get("SECCOP_S3_EVIDENCE_DIR")
    if not root:
        return
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{name}.json"
    path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")
    path.chmod(0o600)


def state_path() -> Path:
    value = os.environ.get("SECCOP_S3_STATE")
    if not value:
        raise RuntimeError("S3 Config state path is missing")
    return Path(value)


def load_state() -> dict[str, Any]:
    path = state_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("S3 Config state is unavailable") from exc
    if not isinstance(value, dict):
        raise RuntimeError("S3 Config state is invalid")
    return value


def save_state(value: dict[str, Any]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def account_id(profile: str, region: str) -> str:
    identity = aws(profile, region, "sts", "get-caller-identity")
    value = identity.get("Account")
    if not isinstance(value, str) or not value.isdigit():
        raise RuntimeError("AWS account identity is unavailable")
    evidence("account-identity", identity)
    return value


def bucket_exists(profile: str, region: str, bucket: str) -> bool:
    completed = subprocess.run(
        ["aws", "--profile", profile, "--region", region, "s3api", "head-bucket", "--bucket", bucket],
        capture_output=True, text=True, check=False, timeout=60,
    )
    return completed.returncode == 0


def role_arn(profile: str, region: str, role_name: str) -> str:
    result = aws(profile, region, "iam", "get-role", "--role-name", role_name, allow_missing=True)
    value = result.get("Role", {}).get("Arn")
    if not isinstance(value, str) or not value.startswith("arn:"):
        raise RuntimeError("Required IAM role is unavailable")
    return value


def _write_json_temp(name: str, value: object) -> Path:
    root = Path(os.environ.get("SECCOP_S3_EVIDENCE_DIR", "/tmp"))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / name
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return path


def _s3_safety(profile: str, region: str, bucket: str, *, allow_bpa: bool = True) -> bool:
    ownership = aws(profile, region, "s3api", "get-bucket-ownership-controls", "--bucket", bucket)
    if ownership.get("OwnershipControls", {}).get("Rules") != [{"ObjectOwnership": "BucketOwnerEnforced"}]:
        raise RuntimeError("Bucket ownership enforcement is absent")
    must_be_missing(profile, region, "s3api", "get-bucket-policy", "--bucket", bucket)
    must_be_missing(profile, region, "s3api", "get-bucket-website", "--bucket", bucket)
    acl = aws(profile, region, "s3api", "get-bucket-acl", "--bucket", bucket)
    public_uris = {"http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}
    if any(isinstance(g, dict) and isinstance(g.get("Grantee"), dict) and g["Grantee"].get("URI") in public_uris for g in acl.get("Grants", [])):
        raise RuntimeError("Bucket has a public ACL")
    objects = aws(profile, region, "s3api", "list-objects-v2", "--bucket", bucket)
    if objects.get("KeyCount", 0) != 0:
        raise RuntimeError("Bucket is not empty")
    result = aws(profile, region, "s3api", "get-public-access-block", "--bucket", bucket, allow_missing=True)
    configured = result.get("PublicAccessBlockConfiguration", {})
    protected = all(configured.get(key) is True for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
    if allow_bpa and configured and not protected:
        raise RuntimeError("Bucket-level Block Public Access is not cleanly absent or fully enabled")
    evidence(f"bucket-{bucket}", {"ownership": ownership, "acl": acl, "objects": objects, "bpa": configured})
    return protected


def _config_service_role_arn(account: str) -> str:
    return f"arn:aws:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"


def _ensure_service_role(profile: str, region: str, account: str) -> str:
    result = aws(profile, region, "iam", "get-role", "--role-name", CONFIG_SERVICE_ROLE, allow_missing=True)
    arn = result.get("Role", {}).get("Arn")
    if not isinstance(arn, str):
        aws(profile, region, "iam", "create-service-linked-role", "--aws-service-name", "config.amazonaws.com")
        time.sleep(3)
        arn = _config_service_role_arn(account)
    evidence("config-service-role", {"present": True, "managed": True})
    return arn


def _config_tags() -> dict[str, str]:
    return {"Name": "seccop-issue55-s3-config", "dev": "amit", "project": "agentic-ai-cybersecurity-lab", "created": "2026-09-02", "tools": "cdx", "environment": "dev", "owner": "amit", "version": "issue55", "TTL": "01-10-26", "purpose": "S3 Config manual remediation proof", "phase": "issue55", "cleanup": "keep"}


def _ensure_delivery_bucket(profile: str, region: str, bucket: str) -> None:
    if not bucket_exists(profile, region, bucket):
        aws(profile, region, "s3api", "create-bucket", "--bucket", bucket, "--create-bucket-configuration", f"LocationConstraint={region}")
        aws(profile, region, "s3api", "put-bucket-ownership-controls", "--bucket", bucket, "--ownership-controls", "Rules=[{ObjectOwnership=BucketOwnerEnforced}]")
        tagset = {"TagSet": [{"Key": key, "Value": value} for key, value in _config_tags().items()]}
        aws(profile, region, "s3api", "put-bucket-tagging", "--bucket", bucket, "--tagging", f"file://{_write_json_temp('delivery-tags.json', tagset)}")
        bpa = {key: True for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
        aws(profile, region, "s3api", "put-public-access-block", "--bucket", bucket, "--public-access-block-configuration", f"file://{_write_json_temp('delivery-bpa.json', bpa)}")
    account = account_id(profile, region)
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "ConfigBucketRead", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": ["s3:GetBucketAcl", "s3:ListBucket", "s3:GetBucketLocation"], "Resource": f"arn:aws:s3:::{bucket}", "Condition": {"StringEquals": {"AWS:SourceAccount": account}}},
        {"Sid": "ConfigBucketWrite", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/Config/*", "Condition": {"StringEquals": {"AWS:SourceAccount": account, "s3:x-amz-acl": "bucket-owner-full-control"}}},
    ]}
    aws(profile, region, "s3api", "put-bucket-policy", "--bucket", bucket, "--policy", f"file://{_write_json_temp('delivery-policy.json', policy)}")
    ownership = aws(profile, region, "s3api", "get-bucket-ownership-controls", "--bucket", bucket)
    if ownership.get("OwnershipControls", {}).get("Rules") != [{"ObjectOwnership": "BucketOwnerEnforced"}]:
        raise RuntimeError("Config delivery bucket ownership verification failed")
    bpa = aws(profile, region, "s3api", "get-public-access-block", "--bucket", bucket)
    if not all(bpa.get("PublicAccessBlockConfiguration", {}).get(key) is True for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
        raise RuntimeError("Config delivery bucket BPA verification failed")


def _ensure_automation_role(profile: str, region: str, account: str, bucket: str) -> str:
    existing = aws(profile, region, "iam", "get-role", "--role-name", AUTOMATION_ROLE, allow_missing=True)
    arn = existing.get("Role", {}).get("Arn")
    if not isinstance(arn, str):
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        created = aws(profile, region, "iam", "create-role", "--role-name", AUTOMATION_ROLE, "--assume-role-policy-document", f"file://{_write_json_temp('automation-trust.json', trust)}", "--description", "SecCop Issue 55 S3 manual remediation")
        arn = created.get("Role", {}).get("Arn")
        if not isinstance(arn, str):
            raise RuntimeError("Automation role creation failed")
        time.sleep(5)
    tagset = [{"Key": key, "Value": value} for key, value in _config_tags().items()]
    aws(profile, region, "iam", "tag-role", "--role-name", AUTOMATION_ROLE, "--tags", f"file://{_write_json_temp('automation-tags.json', tagset)}")
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"], "Resource": f"arn:aws:s3:::{bucket}"}]}
    aws(profile, region, "iam", "put-role-policy", "--role-name", AUTOMATION_ROLE, "--policy-name", "SecCopIssue55S3BucketPublicAccessBlock", "--policy-document", f"file://{_write_json_temp('automation-policy.json', policy)}")
    evidence("automation-role", {"role": "SecCopIssue55S3Automation", "scope": "S3_BUCKET_ALIAS_03", "actions": ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"]})
    return arn


def _config_setup(profile: str, region: str, bucket: str, delivery_bucket: str) -> dict[str, Any]:
    if _s3_safety(profile, region, bucket):
        raise RuntimeError("S3 drift target is already protected")
    account = account_id(profile, region)
    config_role = _ensure_service_role(profile, region, account)
    _ensure_delivery_bucket(profile, region, delivery_bucket)
    automation_arn = _ensure_automation_role(profile, region, account, bucket)
    recording = {"allSupported": False, "includeGlobalResourceTypes": False, "resourceTypes": ["AWS::S3::Bucket"]}
    aws(profile, region, "configservice", "put-configuration-recorder", "--configuration-recorder", json.dumps({"name": CONFIG_RECORDER, "roleARN": config_role}), "--recording-group", f"file://{_write_json_temp('recording-group.json', recording)}")
    channel = {"name": CONFIG_CHANNEL, "s3BucketName": delivery_bucket}
    aws(profile, region, "configservice", "put-delivery-channel", "--delivery-channel", f"file://{_write_json_temp('delivery-channel.json', channel)}")
    aws(profile, region, "configservice", "start-configuration-recorder", "--configuration-recorder-name", CONFIG_RECORDER)
    rule = {"ConfigRuleName": CONFIG_RULE, "Description": "SecCop Issue 55 exact retained S3 drift target", "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"], "ComplianceResourceId": bucket}, "Source": {"Owner": "AWS", "SourceIdentifier": CONFIG_SOURCE}}
    aws(profile, region, "configservice", "put-config-rule", "--config-rule", f"file://{_write_json_temp('config-rule.json', rule)}")
    remediation = {"ConfigRuleName": CONFIG_RULE, "TargetType": "SSM_DOCUMENT", "TargetId": SSM_DOCUMENT, "TargetVersion": SSM_DOCUMENT_VERSION, "Parameters": {"AutomationAssumeRole": {"StaticValue": {"Values": [automation_arn]}}, "BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}}}, "Automatic": False}
    aws(profile, region, "configservice", "put-remediation-configurations", "--remediation-configurations", f"file://{_write_json_temp('remediation.json', [remediation])}")
    time.sleep(5)
    status = aws(profile, region, "configservice", "describe-configuration-recorder-status")
    evidence("config-setup", {"recorder": CONFIG_RECORDER, "channel": CONFIG_CHANNEL, "rule": CONFIG_RULE, "source": CONFIG_SOURCE, "document": SSM_DOCUMENT, "document_version": SSM_DOCUMENT_VERSION, "recorder_status": status})
    state = {"bucket": bucket, "delivery_bucket": delivery_bucket, "config_rule_name": CONFIG_RULE, "config_source": CONFIG_SOURCE, "config_recorder": CONFIG_RECORDER, "config_channel": CONFIG_CHANNEL, "automation_role_arn": automation_arn, "remediation_document": SSM_DOCUMENT, "remediation_document_version": SSM_DOCUMENT_VERSION, "resource_type": "AWS::S3::Bucket", "automatic": False}
    save_state(state)
    return {"status": "READY", "reason_code": "SECCOP_S3_CONFIG_READY", "config_rule_name": CONFIG_RULE, "remediation_document": SSM_DOCUMENT, "message": "The exact S3 Config manual-remediation path is ready."}


def _config_compliance(profile: str, region: str, bucket: str, *, expected: str, trigger: bool = True) -> str:
    if trigger:
        started = False
        for attempt in range(3):
            try:
                aws(profile, region, "configservice", "start-config-rules-evaluation", "--config-rule-names", CONFIG_RULE)
                started = True
                break
            except RuntimeError:
                if attempt == 2:
                    break
                time.sleep(10)
        if not started:
            evidence("config-evaluation-trigger", {"status": "RATE_LIMITED", "rule": CONFIG_RULE})
    deadline = time.monotonic() + CONFIG_TIMEOUT_SECONDS
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = aws(profile, region, "configservice", "get-compliance-details-by-resource", "--resource-type", "AWS::S3::Bucket", "--resource-id", bucket)
        results = [item for item in latest.get("EvaluationResults", []) if item.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {}).get("ConfigRuleName") == CONFIG_RULE]
        if results:
            state = str(results[0].get("ComplianceType", "UNKNOWN"))
            evidence(f"config-compliance-{expected.lower()}", latest)
            if state == expected:
                return state
        time.sleep(10)
    evidence(f"config-compliance-timeout-{expected.lower()}", latest)
    raise RuntimeError(f"Config compliance did not reach {expected}")


def _automation_executions(profile: str, region: str) -> list[dict[str, Any]]:
    result = aws(profile, region, "ssm", "describe-automation-executions", "--filters", "Key=DocumentNamePrefix,Values=" + SSM_DOCUMENT, "--max-results", "10")
    values = result.get("AutomationExecutionMetadataList", [])
    return [item for item in values if isinstance(item, dict) and item.get("DocumentName") == SSM_DOCUMENT and str(item.get("DocumentVersion")) == SSM_DOCUMENT_VERSION]


def _ec2_evidence(name: str, value: object) -> None:
    root = os.environ.get("SECCOP_EC2_EVIDENCE_DIR")
    if not root:
        return
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{name}.json"
    path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _ec2_call(profile: str, region: str, *args: str, allow_missing: bool = False) -> dict[str, Any]:
    completed = subprocess.run(
        ["aws", "--profile", profile, "--region", region, *args, "--output", "json"],
        capture_output=True, text=True, check=False, timeout=90,
    )
    if completed.returncode and not allow_missing:
        _ec2_evidence("aws-error", {"operation": args[0:3], "stderr": completed.stderr[-2000:]})
        raise RuntimeError("EC2 AWS operation failed")
    try:
        value = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("EC2 AWS returned invalid output") from exc
    return value if isinstance(value, dict) else {}


def _ec2_state_path() -> Path:
    value = os.environ.get("SECCOP_EC2_STATE")
    if not value:
        raise RuntimeError("EC2 state path is missing")
    return Path(value)


def _ec2_load_state() -> dict[str, Any]:
    try:
        value = json.loads(_ec2_state_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("EC2 state is unavailable") from exc
    if not isinstance(value, dict) or value.get("target_name") != EC2_TARGET_NAME:
        raise RuntimeError("EC2 state target binding is invalid")
    return value


def _ec2_save_state(value: dict[str, Any]) -> None:
    path = _ec2_state_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _ec2_role_name() -> str:
    return os.environ.get("SECCOP_EC2_AUTOMATION_ROLE", EC2_AUTOMATION_ROLE)


def _ec2_policy_name() -> str:
    return os.environ.get("SECCOP_EC2_AUTOMATION_POLICY", EC2_AUTOMATION_POLICY)


def _ec2_reuse_role() -> bool:
    return os.environ.get("SECCOP_EC2_REUSE_ROLE") == "1"


def _ec2_write_json(name: str, value: object) -> Path:
    root = Path(os.environ.get("SECCOP_EC2_EVIDENCE_DIR", "/tmp"))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / name
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return path


def _ec2_retain_tags(profile: str, region: str, instance_id: str, group_id: str, volume_id: str | None) -> None:
    resources = [instance_id, group_id] + ([volume_id] if volume_id else [])
    tags = [
        "Key=Cleanup,Value=keep",
        "Key=cleanup,Value=keep",
        f"Key=TTL,Value={EC2_RETAIN_TTL}",
        f"Key=Purpose,Value={EC2_RETAIN_PURPOSE}",
        f"Key=purpose,Value={EC2_RETAIN_PURPOSE}",
        "Key=phase,Value=issue55-ec2-config-retained-arm",
        "Key=Issue,Value=55",
        "Key=ExpiresAt,Value=2026-10-01T23:59:00+08:00",
    ]
    _ec2_call(profile, region, "ec2", "create-tags", "--resources", *resources, "--tags", *tags)
    _ec2_evidence("retention-tags", {"resource_aliases": ["EC2_RESOURCE_01", "SG_EC2_RESOURCE_01", "EBS_EC2_ROOT_01"], "cleanup": "keep", "TTL": EC2_RETAIN_TTL, "purpose": "REUSABLE_EC2_CONFIG_IMDSV2_DEMO"})


def _ec2_account(profile: str, region: str) -> str:
    identity = _ec2_call(profile, region, "sts", "get-caller-identity")
    account = identity.get("Account")
    if not isinstance(account, str) or not account.isdigit():
        raise RuntimeError("EC2 AWS account identity is unavailable")
    _ec2_evidence("identity", identity)
    return account


def _ec2_select_subnet(profile: str, region: str) -> str:
    response = _ec2_call(
        profile, region, "ec2", "describe-subnets", "--filters",
        "Name=tag:Name,Values=public", "Name=map-public-ip-on-launch,Values=true", "Name=state,Values=available",
    )
    candidates = [item for item in response.get("Subnets", []) if isinstance(item, dict)]
    if len(candidates) != 1 or not isinstance(candidates[0].get("SubnetId"), str):
        raise RuntimeError("Approved public subnet selection is not unique")
    _ec2_evidence("selected-subnet", {"candidate_count": len(candidates), "approved_alias": "PUBLIC_SUBNET_01", "available_ips": candidates[0].get("AvailableIpAddressCount")})
    return str(candidates[0]["SubnetId"])


def _ec2_budget_gate(profile: str, region: str, account: str) -> None:
    result = _ec2_call(profile, region, "budgets", "describe-budgets", "--account-id", account)
    budgets = result.get("Budgets", [])
    if not budgets:
        raise RuntimeError("Monthly budget evidence is unavailable")
    budget = budgets[0]
    limit = float(budget.get("BudgetLimit", {}).get("Amount", "0"))
    forecast = float(budget.get("CalculatedSpend", {}).get("ForecastedSpend", {}).get("Amount", "0"))
    _ec2_evidence("budget", {"monthly_limit_usd": limit, "forecast_usd": forecast})
    if limit <= 0 or forecast >= 20.0:
        raise RuntimeError("EC2 cost forecast exceeded the approved USD 20 gate")


def _ec2_target(profile: str, region: str) -> dict[str, Any]:
    target_id = os.environ.get("SECCOP_EC2_TARGET_ID")
    if not target_id:
        try:
            target_id = str(_ec2_load_state().get("instance_id", ""))
        except RuntimeError:
            target_id = ""
    if target_id:
        response = _ec2_call(profile, region, "ec2", "describe-instances", "--instance-ids", target_id)
        instances = [item for reservation in response.get("Reservations", []) if isinstance(reservation, dict) for item in reservation.get("Instances", []) if isinstance(item, dict)]
        if len(instances) != 1:
            raise RuntimeError("EC2 target ID is missing or ambiguous")
        return instances[0]
    response = _ec2_call(
        profile, region, "ec2", "describe-instances", "--filters",
        f"Name=tag:Name,Values={EC2_TARGET_NAME}", "Name=tag:Repo,Values=agentic-ai-cybersecurity-lab",
        "Name=instance-state-name,Values=pending,running,stopping,stopped",
    )
    instances = [
        item for reservation in response.get("Reservations", []) if isinstance(reservation, dict)
        for item in reservation.get("Instances", []) if isinstance(item, dict)
    ]
    if len(instances) != 1:
        raise RuntimeError("EC2 target is missing or ambiguous")
    return instances[0]


def _ec2_wait_ssm(profile: str, region: str, instance_id: str) -> None:
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        response = _ec2_call(
            profile, region, "ssm", "describe-instance-information",
            "--filters", f"Key=InstanceIds,Values={instance_id}",
        )
        nodes = [item for item in response.get("InstanceInformationList", []) if isinstance(item, dict) and item.get("InstanceId") == instance_id]
        if len(nodes) == 1 and nodes[0].get("PingStatus") == "Online":
            _ec2_evidence("ssm-online", {"resource_alias": "EC2_RESOURCE_01", "state": "Online"})
            return
        time.sleep(5)
    raise RuntimeError("EC2 SSM registration did not reach Online")


def _ec2_rnd_targets() -> dict[str, str]:
    value = os.environ.get(EC2_RND_TARGET_MAP)
    if not value:
        raise RuntimeError("DEV R&D target map is missing")
    path = Path(value)
    if not path.is_absolute() or ".AGENTS-temp" not in path.parts or path.stat().st_mode & 0o077:
        raise RuntimeError("DEV R&D target map must be a private runtime file")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("DEV R&D target map is unavailable") from exc
    if not isinstance(raw, dict) or raw.get("profile") != "ihis_dev" or raw.get("region") != "ap-southeast-1":
        raise RuntimeError("DEV R&D target map context is invalid")
    expected = {EC2_RND_ALIAS_LAB01, EC2_RND_ALIAS_LAB02}
    if set(raw) != {"profile", "region", *expected}:
        raise RuntimeError("DEV R&D target map aliases are invalid")
    targets: dict[str, str] = {}
    for alias in expected:
        instance_id = raw.get(alias)
        if not isinstance(instance_id, str) or not re.fullmatch(r"i-[0-9a-f]+", instance_id):
            raise RuntimeError("DEV R&D target map contains an invalid target")
        digest = hashlib.sha256(instance_id.encode()).hexdigest()
        if digest != EC2_RND_ID_HASHES[alias]:
            raise RuntimeError("DEV R&D target map target is outside the approved allowlist")
        targets[alias] = instance_id
    return targets


def _ec2_rnd_rule(alias: str) -> str:
    if alias == EC2_RND_ALIAS_LAB01:
        return EC2_RND_RULE_LAB01
    if alias == EC2_RND_ALIAS_LAB02:
        return EC2_CONFIG_RULE
    raise RuntimeError("DEV R&D target alias is not approved")


def _ec2_rnd_target(profile: str, region: str, alias: str) -> tuple[str, dict[str, Any]]:
    targets = _ec2_rnd_targets()
    if alias not in targets:
        raise RuntimeError("DEV R&D target alias is not approved")
    instance_id = targets[alias]
    response = _ec2_call(profile, region, "ec2", "describe-instances", "--instance-ids", instance_id)
    instances = [item for reservation in response.get("Reservations", []) if isinstance(reservation, dict) for item in reservation.get("Instances", []) if isinstance(item, dict)]
    if len(instances) != 1 or instances[0].get("InstanceId") != instance_id:
        raise RuntimeError("DEV R&D target is missing or ambiguous")
    target = instances[0]
    if target.get("State", {}).get("Name") != "running" or target.get("PublicIpAddress") is not None:
        raise RuntimeError("DEV R&D target is not running and private")
    if target.get("MetadataOptions", {}).get("HttpTokens") not in {"optional", "required"}:
        raise RuntimeError("DEV R&D target metadata state is unavailable")
    groups = target.get("SecurityGroups", [])
    if len(groups) != 1 or not isinstance(groups[0], dict) or not isinstance(groups[0].get("GroupId"), str):
        raise RuntimeError("DEV R&D target security-group shape is invalid")
    sg = _ec2_call(profile, region, "ec2", "describe-security-groups", "--group-ids", groups[0]["GroupId"])
    if len(sg.get("SecurityGroups", [])) != 1 or sg["SecurityGroups"][0].get("IpPermissions") != []:
        raise RuntimeError("DEV R&D target security group is not zero-ingress")
    _ec2_wait_ssm(profile, region, instance_id)
    _ec2_evidence("rnd-target-" + alias.lower(), {"resource_alias": alias, "state": "running", "metadata_tokens": target["MetadataOptions"]["HttpTokens"], "ssm": "Online", "public_ipv4": False, "zero_ingress": True})
    return instance_id, target


def _ec2_rnd_binding(profile: str, region: str, alias: str, *, allow_missing: bool = False) -> dict[str, Any]:
    rule_name = _ec2_rnd_rule(alias)
    result = _ec2_call(profile, region, "configservice", "describe-config-rules", "--config-rule-names", rule_name, allow_missing=allow_missing)
    rules = result.get("ConfigRules", [])
    if not rules:
        if allow_missing:
            return {}
        raise RuntimeError("DEV R&D Config rule is missing")
    if len(rules) != 1:
        raise RuntimeError("DEV R&D Config rule is ambiguous")
    return rules[0]


def _ec2_rnd_compliance(profile: str, region: str, alias: str, instance_id: str, expected: str) -> str:
    rule_name = _ec2_rnd_rule(alias)
    try:
        _ec2_call(profile, region, "configservice", "start-config-rules-evaluation", "--config-rule-names", rule_name)
    except RuntimeError:
        _ec2_evidence("rnd-config-evaluation-trigger", {"resource_alias": alias, "status": "RATE_LIMITED"})
    latest: dict[str, Any] = {}
    deadline = time.monotonic() + EC2_CONFIG_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            latest = _ec2_call(profile, region, "configservice", "get-compliance-details-by-resource", "--resource-type", "AWS::EC2::Instance", "--resource-id", instance_id)
        except RuntimeError:
            time.sleep(10)
            continue
        results = [item for item in latest.get("EvaluationResults", []) if item.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {}).get("ConfigRuleName") == rule_name]
        if results and str(results[0].get("ComplianceType")) == expected:
            _ec2_evidence("rnd-config-compliance-" + alias.lower() + "-" + expected.lower(), latest)
            return expected
        time.sleep(10)
    _ec2_evidence("rnd-config-compliance-timeout-" + alias.lower() + "-" + expected.lower(), latest)
    raise RuntimeError("DEV R&D Config compliance did not reach the expected state")


def _ec2_rnd_preflight(profile: str, region: str) -> dict[str, Any]:
    if profile != "ihis_dev" or region != "ap-southeast-1":
        raise RuntimeError("DEV R&D rearm requires ihis_dev/ap-southeast-1")
    targets = _ec2_rnd_targets()
    statuses: list[dict[str, Any]] = []
    for alias in (EC2_RND_ALIAS_LAB01, EC2_RND_ALIAS_LAB02):
        instance_id, target = _ec2_rnd_target(profile, region, alias)
        rule = _ec2_rnd_binding(profile, region, alias, allow_missing=(alias == EC2_RND_ALIAS_LAB01))
        if alias == EC2_RND_ALIAS_LAB02 and (rule.get("Source", {}).get("Owner") != "AWS" or rule.get("Source", {}).get("SourceIdentifier") != EC2_CONFIG_SOURCE or rule.get("Scope", {}).get("ComplianceResourceTypes") != ["AWS::EC2::Instance"] or rule.get("Scope", {}).get("ComplianceResourceId") != instance_id or rule.get("ConfigRuleState") != "ACTIVE"):
            raise RuntimeError("Existing LAB_02 Config rule is outside the exact approved target")
        if alias == EC2_RND_ALIAS_LAB02:
            binding = _ec2_call(profile, region, "configservice", "describe-remediation-configurations", "--config-rule-names", EC2_CONFIG_RULE).get("RemediationConfigurations", [])
            if len(binding) != 1 or binding[0].get("TargetId") != EC2_SSM_DOCUMENT or str(binding[0].get("TargetVersion")) != EC2_SSM_DOCUMENT_VERSION or binding[0].get("Automatic") is not False:
                raise RuntimeError("Existing LAB_02 remediation binding is outside the exact manual envelope")
        statuses.append({"resource_alias": alias, "state": target["MetadataOptions"]["HttpTokens"], "config_rule": "PRESENT" if rule else "MISSING", "rule_scope": "EXACT" if rule and rule.get("Scope", {}).get("ComplianceResourceId") == instance_id else "UNSET"})
    _ec2_evidence("rnd-preflight", {"profile": profile, "region": region, "targets": statuses, "aliases": list(targets)})
    return {"status": "READY", "reason_code": "SECCOP_EC2_RND_PREFLIGHT_READY", "targets": statuses, "message": "Both fixed DEV R&D targets passed the running/private/SSM preflight."}


def _ec2_rnd_setup(profile: str, region: str) -> dict[str, Any]:
    _ec2_rnd_preflight(profile, region)
    account = _ec2_account(profile, region)
    role = _ec2_call(profile, region, "iam", "get-role", "--role-name", EC2_DEV_REUSED_ROLE)
    role_arn = role.get("Role", {}).get("Arn")
    if not isinstance(role_arn, str) or not role_arn.startswith("arn:"):
        raise RuntimeError("Approved reusable Automation role is unavailable")
    trust = role.get("Role", {}).get("AssumeRolePolicyDocument", {})
    principals = [statement.get("Principal", {}).get("Service") for statement in trust.get("Statement", []) if isinstance(statement, dict)] if isinstance(trust, dict) else []
    if not any(service == "ssm.amazonaws.com" or isinstance(service, list) and "ssm.amazonaws.com" in service for service in principals):
        raise RuntimeError("Approved reusable Automation role does not trust SSM")
    rule_name = EC2_RND_RULE_LAB01
    instance_id, target = _ec2_rnd_target(profile, region, EC2_RND_ALIAS_LAB01)
    if target.get("MetadataOptions", {}).get("HttpTokens") != "optional":
        raise RuntimeError("LAB_01 metadata is not optional; no metadata mutation is permitted")
    rule = _ec2_rnd_binding(profile, region, EC2_RND_ALIAS_LAB01, allow_missing=True)
    if rule and (rule.get("Source", {}).get("Owner") != "AWS" or rule.get("Source", {}).get("SourceIdentifier") != EC2_CONFIG_SOURCE or rule.get("Scope", {}).get("ComplianceResourceTypes") != ["AWS::EC2::Instance"] or rule.get("Scope", {}).get("ComplianceResourceId") != instance_id):
        raise RuntimeError("Existing LAB_01 Config rule is outside the exact approved target")
    if not rule:
        payload = {"ConfigRuleName": rule_name, "Description": "Issue #55 DEV R&D exact EC2 IMDSv2 control", "Scope": {"ComplianceResourceTypes": ["AWS::EC2::Instance"], "ComplianceResourceId": instance_id}, "Source": {"Owner": "AWS", "SourceIdentifier": EC2_CONFIG_SOURCE}}
        rule_file = _ec2_write_json("rnd-lab01-config-rule.json", payload)
        _ec2_call(profile, region, "configservice", "put-config-rule", "--config-rule", f"file://{rule_file}")
        rule = _ec2_rnd_binding(profile, region, EC2_RND_ALIAS_LAB01)
    arn = rule.get("ConfigRuleArn")
    if not isinstance(arn, str):
        raise RuntimeError("LAB_01 Config rule ARN is unavailable")
    tags_file = _ec2_write_json("rnd-lab01-tags.json", [{"Key": "cleanup", "Value": "keep"}, {"Key": "TTL", "Value": EC2_RETAIN_TTL}])
    _ec2_call(profile, region, "configservice", "tag-resource", "--resource-arn", arn, "--tags", f"file://{tags_file}")
    existing = _ec2_call(profile, region, "configservice", "describe-remediation-configurations", "--config-rule-names", rule_name, allow_missing=True).get("RemediationConfigurations", [])
    if existing and (len(existing) != 1 or existing[0].get("TargetId") != EC2_SSM_DOCUMENT or str(existing[0].get("TargetVersion")) != EC2_SSM_DOCUMENT_VERSION or existing[0].get("Automatic") is not False):
        raise RuntimeError("Existing LAB_01 remediation binding is outside the exact manual envelope")
    if not existing:
        remediation = {"ConfigRuleName": rule_name, "TargetType": "SSM_DOCUMENT", "TargetId": EC2_SSM_DOCUMENT, "TargetVersion": EC2_SSM_DOCUMENT_VERSION, "Parameters": {"AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}}, "InstanceId": {"ResourceValue": {"Value": "RESOURCE_ID"}}}, "Automatic": False}
        remediation_file = _ec2_write_json("rnd-lab01-remediation.json", [remediation])
        _ec2_call(profile, region, "configservice", "put-remediation-configurations", "--remediation-configurations", f"file://{remediation_file}")
    _ec2_evidence("rnd-lab01-binding", {"resource_alias": EC2_RND_ALIAS_LAB01, "rule": rule_name, "source": EC2_CONFIG_SOURCE, "document": EC2_SSM_DOCUMENT, "document_version": EC2_SSM_DOCUMENT_VERSION, "automatic": False, "role_alias": "AMI_FACTORY_DEV_DEMO_ROLE"})
    state = _ec2_rnd_compliance(profile, region, EC2_RND_ALIAS_LAB01, instance_id, "NON_COMPLIANT")
    return {"status": "READY", "reason_code": "SECCOP_EC2_RND_LAB01_READY", "resource_alias": EC2_RND_ALIAS_LAB01, "state": state, "message": "The fixed LAB_01 DEV R&D target is ready with the exact manual Config binding."}


def _ec2_rnd_scan(profile: str, region: str, alias: str) -> dict[str, Any]:
    instance_id, target = _ec2_rnd_target(profile, region, alias)
    rule = _ec2_rnd_binding(profile, region, alias)
    if rule.get("Scope", {}).get("ComplianceResourceId") != instance_id or rule.get("Source", {}).get("SourceIdentifier") != EC2_CONFIG_SOURCE or rule.get("ConfigRuleState") != "ACTIVE":
        raise RuntimeError("DEV R&D Config rule scope is not exact")
    expected = "NON_COMPLIANT" if target["MetadataOptions"]["HttpTokens"] == "optional" else "COMPLIANT"
    state = _ec2_rnd_compliance(profile, region, alias, instance_id, expected)
    if state == "NON_COMPLIANT":
        return {"status": "READY", "reason_code": "SECCOP_EC2_IMDSV2_NON_COMPLIANT", "state": state, "resource_alias": alias, "config_rule_name": _ec2_rnd_rule(alias), "findings": [{"finding_id": "FINDING_01", "source_type": "EC2_CONFIG", "resource_alias": alias, "reference": "EC2_IMDSV2_RULE_01", "severity": "MEDIUM", "title": "DEV R&D target accepts IMDSv1", "problem_summary": "AWS Config found a fixed DEV target that still accepts IMDSv1.", "observed_state": "HttpTokens=optional; Config NON_COMPLIANT", "recommended_state": "Use the explicit Reopen Finding action only for LAB_02.", "remediation_mode": "REAL_APPROVAL_REQUIRED", "reason_code": "SECCOP_EC2_IMDSV2_FINDING", "action_label": "Reopen Finding"}], "message": "DEV R&D rearm evidence shows the selected fixed target is intentionally NON_COMPLIANT."}
    return {"status": "NO_FINDINGS", "reason_code": "SECCOP_EC2_IMDSV2_COMPLIANT", "state": state, "resource_alias": alias, "config_rule_name": _ec2_rnd_rule(alias), "findings": [], "message": "AWS Config verified the selected DEV R&D target is IMDSv2 compliant."}


def _ec2_rnd_rearm(profile: str, region: str, alias: str, confirm: bool) -> dict[str, Any]:
    if alias != EC2_RND_ALIAS_LAB02 or not confirm:
        raise RuntimeError("Only confirmed LAB_02 DEV R&D rearm is allowed")
    instance_id, target = _ec2_rnd_target(profile, region, alias)
    rule = _ec2_rnd_binding(profile, region, alias)
    binding = _ec2_call(profile, region, "configservice", "describe-remediation-configurations", "--config-rule-names", EC2_CONFIG_RULE).get("RemediationConfigurations", [])
    if rule.get("Scope", {}).get("ComplianceResourceId") != instance_id or len(binding) != 1 or binding[0].get("TargetId") != EC2_SSM_DOCUMENT or str(binding[0].get("TargetVersion")) != EC2_SSM_DOCUMENT_VERSION or binding[0].get("Automatic") is not False:
        raise RuntimeError("LAB_02 Config binding is not exact")
    changed = target["MetadataOptions"]["HttpTokens"] != "optional"
    if changed:
        _ec2_call(profile, region, "ec2", "modify-instance-metadata-options", "--instance-id", instance_id, "--http-tokens", "optional")
    _, after = _ec2_rnd_target(profile, region, alias)
    if after["MetadataOptions"]["HttpTokens"] != "optional":
        raise RuntimeError("LAB_02 metadata did not reach optional")
    state = _ec2_rnd_compliance(profile, region, alias, instance_id, "NON_COMPLIANT")
    _ec2_evidence("rnd-rearm-lab02", {"resource_alias": alias, "metadata_tokens": "optional", "config": state, "mutation_performed": changed, "intentional": True})
    return {"status": "REARMED", "reason_code": "SECCOP_EC2_RND_REARMED", "state": state, "resource_alias": alias, "metadata_http_tokens": "optional", "mutation_performed": changed, "message": "The confirmed LAB_02 DEV R&D rearm is intentionally left IMDSv1-compatible for testing."}


def _ec2_recorder_setup(profile: str, region: str) -> bool:
    recorders = _ec2_call(profile, region, "configservice", "describe-configuration-recorders").get("ConfigurationRecorders", [])
    channels = _ec2_call(profile, region, "configservice", "describe-delivery-channels").get("DeliveryChannels", [])
    if len(recorders) != 1 or len(channels) != 1:
        raise RuntimeError("Existing Config recorder/delivery dependency is not exact")
    recorder = recorders[0]
    if recorder.get("name") != CONFIG_RECORDER or not isinstance(recorder.get("roleARN"), str):
        raise RuntimeError("Existing Config recorder is not the approved recorder")
    group = recorder.get("recordingGroup", {})
    types = list(group.get("resourceTypes", [])) if isinstance(group, dict) else []
    if "AWS::S3::Bucket" not in types:
        raise RuntimeError("Existing S3 recorder scope would not be preserved")
    if "AWS::EC2::Instance" in types:
        return False
    config = {"name": CONFIG_RECORDER, "roleARN": recorder["roleARN"]}
    recording_group = {"allSupported": False, "includeGlobalResourceTypes": False, "resourceTypes": sorted(set(types + ["AWS::EC2::Instance"]))}
    payload = Path(os.environ.get("SECCOP_EC2_EVIDENCE_DIR", "/tmp")) / "configuration-recorder.json"
    payload.write_text(json.dumps(config), encoding="utf-8"); payload.chmod(0o600)
    group_file = payload.with_name("recording-group.json")
    group_file.write_text(json.dumps(recording_group), encoding="utf-8"); group_file.chmod(0o600)
    _ec2_call(profile, region, "configservice", "stop-configuration-recorder", "--configuration-recorder-name", CONFIG_RECORDER)
    _ec2_call(profile, region, "configservice", "put-configuration-recorder", "--configuration-recorder", f"file://{payload}", "--recording-group", f"file://{group_file}")
    _ec2_call(profile, region, "configservice", "start-configuration-recorder", "--configuration-recorder-name", CONFIG_RECORDER)
    status = _ec2_call(profile, region, "configservice", "describe-configuration-recorder-status")
    matching = [item for item in status.get("ConfigurationRecordersStatus", []) if item.get("name") == CONFIG_RECORDER]
    if len(matching) != 1 or matching[0].get("recording") is not True:
        raise RuntimeError("Existing Config recorder did not return to recording")
    _ec2_evidence("recorder-updated", {"recorder": CONFIG_RECORDER, "preserved_resource_types": recording_group["resourceTypes"], "recording": True})
    return True


def _ec2_config_setup(profile: str, region: str, instance_id: str, account: str) -> None:
    role_name = _ec2_role_name()
    policy_name = _ec2_policy_name()
    role = _ec2_call(profile, region, "iam", "get-role", "--role-name", role_name, allow_missing=True)
    role_arn = role.get("Role", {}).get("Arn")
    if _ec2_reuse_role():
        if role_name != EC2_DEV_REUSED_ROLE:
            raise RuntimeError("DEV reuse is pinned to the approved AMI-factory role")
        if not isinstance(role_arn, str):
            raise RuntimeError("Approved reusable Automation role is unavailable")
        trust = role.get("Role", {}).get("AssumeRolePolicyDocument", {})
        principals = [statement.get("Principal", {}).get("Service") for statement in trust.get("Statement", []) if isinstance(statement, dict)] if isinstance(trust, dict) else []
        if not any(service == "ssm.amazonaws.com" or isinstance(service, list) and "ssm.amazonaws.com" in service for service in principals):
            raise RuntimeError("Approved reusable Automation role does not trust SSM")
        _ec2_evidence("automation-role-reused", {"role_alias": "AMI_FACTORY_DEV_DEMO_ROLE", "role_unchanged": True, "trust": "SSM"})
    elif not isinstance(role_arn, str):
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        trust_file = _ec2_write_json("ec2-automation-trust.json", trust)
        created = _ec2_call(profile, region, "iam", "create-role", "--role-name", role_name, "--assume-role-policy-document", f"file://{trust_file}", "--description", "SecCop Issue 55 DEV EC2 IMDSv2 manual remediation")
        role_arn = created.get("Role", {}).get("Arn")
        if not isinstance(role_arn, str):
            raise RuntimeError("DEV Automation role creation failed")
        role_tags = [
            "Key=Name,Value=seccop-issue55-dev-ec2-automation",
            "Key=dev,Value=amit",
            "Key=project,Value=agentic-ai-cybersecurity-lab",
            "Key=created,Value=2026-09-03",
            "Key=tools,Value=cdx",
            "Key=environment,Value=dev",
            "Key=owner,Value=amit",
            "Key=version,Value=issue55",
            f"Key=TTL,Value={EC2_RETAIN_TTL}",
            f"Key=purpose,Value={EC2_RETAIN_PURPOSE}",
            "Key=phase,Value=issue55-dev-nessus-imdsv2-e2e",
            "Key=cleanup,Value=keep",
        ]
        _ec2_call(profile, region, "iam", "tag-role", "--role-name", role_name, "--tags", *role_tags)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Ec2DescribeForImdsVerification", "Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
            {"Sid": "Ec2ModifyExactTarget", "Effect": "Allow", "Action": "ec2:ModifyInstanceMetadataOptions", "Resource": f"arn:aws:ec2:{region}:{account}:instance/{instance_id}"},
        ],
    }
    policy_file = Path(os.environ.get("SECCOP_EC2_EVIDENCE_DIR", "/tmp")) / "ec2-automation-policy.json"
    policy_file.write_text(json.dumps(policy), encoding="utf-8"); policy_file.chmod(0o600)
    if not _ec2_reuse_role():
        _ec2_call(profile, region, "iam", "put-role-policy", "--role-name", role_name, "--policy-name", policy_name, "--policy-document", f"file://{policy_file}")
    rule_probe = _ec2_call(profile, region, "configservice", "describe-config-rules", "--config-rule-names", EC2_CONFIG_RULE, allow_missing=True)
    existing_rules = rule_probe.get("ConfigRules", [])
    if existing_rules:
        existing = existing_rules[0] if len(existing_rules) == 1 else {}
        if (existing.get("ConfigRuleName") != EC2_CONFIG_RULE or existing.get("Source", {}).get("Owner") != "AWS" or existing.get("Source", {}).get("SourceIdentifier") != EC2_CONFIG_SOURCE or existing.get("Scope", {}).get("ComplianceResourceTypes") != ["AWS::EC2::Instance"] or existing.get("Scope", {}).get("ComplianceResourceId") != instance_id):
            raise RuntimeError("Existing EC2 Config rule is outside the exact approved target")
    else:
        rule = {"ConfigRuleName": EC2_CONFIG_RULE, "Description": "Issue #55 exact EC2 IMDSv2 control", "Scope": {"ComplianceResourceTypes": ["AWS::EC2::Instance"], "ComplianceResourceId": instance_id}, "Source": {"Owner": "AWS", "SourceIdentifier": EC2_CONFIG_SOURCE}}
        rule_file = policy_file.with_name("ec2-config-rule.json"); rule_file.write_text(json.dumps(rule), encoding="utf-8"); rule_file.chmod(0o600)
        _ec2_call(profile, region, "configservice", "put-config-rule", "--config-rule", f"file://{rule_file}")
    rule_probe = _ec2_call(profile, region, "configservice", "describe-config-rules", "--config-rule-names", EC2_CONFIG_RULE)
    config_rule_arn = rule_probe.get("ConfigRules", [{}])[0].get("ConfigRuleArn") if rule_probe.get("ConfigRules") else None
    if not isinstance(config_rule_arn, str) or not config_rule_arn.startswith("arn:"):
        raise RuntimeError("EC2 Config rule ARN was not returned")
    _ec2_call(profile, region, "configservice", "tag-resource", "--resource-arn", config_rule_arn, "--tags", "Key=cleanup,Value=keep", f"Key=TTL,Value={EC2_RETAIN_TTL}", f"Key=Purpose,Value={EC2_RETAIN_PURPOSE}", "Key=phase,Value=issue55-ec2-config-retained-arm")
    remediation = {"ConfigRuleName": EC2_CONFIG_RULE, "TargetType": "SSM_DOCUMENT", "TargetId": EC2_SSM_DOCUMENT, "TargetVersion": EC2_SSM_DOCUMENT_VERSION, "Parameters": {"AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}}, "InstanceId": {"ResourceValue": {"Value": "RESOURCE_ID"}}}, "Automatic": False}
    remediation_file = policy_file.with_name("ec2-remediation.json"); remediation_file.write_text(json.dumps([remediation]), encoding="utf-8"); remediation_file.chmod(0o600)
    _ec2_call(profile, region, "configservice", "put-remediation-configurations", "--remediation-configurations", f"file://{remediation_file}")
    _ec2_evidence("config-bindings", {"rule": EC2_CONFIG_RULE, "source": EC2_CONFIG_SOURCE, "document": EC2_SSM_DOCUMENT, "document_version": EC2_SSM_DOCUMENT_VERSION, "automatic": False, "role": "AMI_FACTORY_DEV_DEMO_ROLE" if _ec2_reuse_role() else "AUTOMATION_ROLE_ISSUE55_01", "resource_alias": "EC2_RESOURCE_01"})


def ec2_adopt(profile: str, region: str, instance_id: str) -> dict[str, Any]:
    if profile != "ihis_dev" or region != "ap-southeast-1" or not re.fullmatch(r"i-[0-9a-f]+", instance_id):
        raise RuntimeError("DEV adoption requires the exact approved profile, region, and target")
    if not _ec2_reuse_role() or _ec2_role_name() != EC2_DEV_REUSED_ROLE:
        raise RuntimeError("DEV adoption requires the approved AMI-factory Automation role reuse")
    account = _ec2_account(profile, region)
    response = _ec2_call(profile, region, "ec2", "describe-instances", "--instance-ids", instance_id)
    instances = [item for reservation in response.get("Reservations", []) if isinstance(reservation, dict) for item in reservation.get("Instances", []) if isinstance(item, dict)]
    if len(instances) != 1:
        raise RuntimeError("Approved DEV target is missing or ambiguous")
    target = instances[0]
    if target.get("State", {}).get("Name") != "running" or target.get("PublicIpAddress") is not None or target.get("MetadataOptions", {}).get("HttpTokens") != "optional":
        raise RuntimeError("Approved DEV target is not running, private, and optional-token")
    groups = target.get("SecurityGroups", [])
    if len(groups) != 1 or not isinstance(groups[0], dict) or not isinstance(groups[0].get("GroupId"), str):
        raise RuntimeError("Approved DEV target security-group shape is invalid")
    group_id = str(groups[0]["GroupId"])
    sg = _ec2_call(profile, region, "ec2", "describe-security-groups", "--group-ids", group_id)
    if len(sg.get("SecurityGroups", [])) != 1 or sg["SecurityGroups"][0].get("IpPermissions") != []:
        raise RuntimeError("Approved DEV target security group is not zero-ingress")
    _ec2_wait_ssm(profile, region, instance_id)
    recorders = _ec2_call(profile, region, "configservice", "describe-configuration-recorders").get("ConfigurationRecorders", [])
    statuses = _ec2_call(profile, region, "configservice", "describe-configuration-recorder-status").get("ConfigurationRecordersStatus", [])
    if len(recorders) != 1 or len(statuses) != 1 or statuses[0].get("recording") is not True:
        raise RuntimeError("DEV Config recorder is not a single active recorder")
    group = recorders[0].get("recordingGroup", {})
    if not (group.get("allSupported") is True or "AWS::EC2::Instance" in group.get("resourceTypes", [])):
        raise RuntimeError("DEV Config recorder does not record EC2 instances")
    _ec2_save_state({"target_name": EC2_TARGET_NAME, "target_alias": "DEV_EC2_RESOURCE_01", "instance_id": instance_id, "security_group_id": group_id, "profile": profile, "region": region, "recorder": recorders[0].get("name")})
    os.environ["SECCOP_EC2_TARGET_ID"] = instance_id
    _ec2_config_setup(profile, region, instance_id, account)
    _ec2_save_state({"target_name": EC2_TARGET_NAME, "target_alias": "DEV_EC2_RESOURCE_01", "instance_id": instance_id, "security_group_id": group_id, "profile": profile, "region": region, "recorder": recorders[0].get("name"), "role_name": _ec2_role_name(), "policy_name": _ec2_policy_name(), "config_rule": EC2_CONFIG_RULE})
    _ec2_evidence("dev-target-ready", {"resource_alias": "DEV_EC2_RESOURCE_01", "target_state": "running", "metadata_tokens": "optional", "ssm": "Online", "public_ipv4": False, "zero_ingress": True, "recorder": "EXISTING_ACTIVE_EC2_RECORDING"})
    return {"status": "READY", "reason_code": "SECCOP_EC2_DEV_TARGET_READY", "resource_alias": "DEV_EC2_RESOURCE_01", "state": "NON_COMPLIANT_BASELINE_READY"}


def ec2_setup(profile: str, region: str) -> dict[str, Any]:
    if profile != "amit" or region != "ap-southeast-1":
        raise RuntimeError("EC2 Issue #55 requires amit/ap-southeast-1")
    account = _ec2_account(profile, region)
    _ec2_budget_gate(profile, region, account)
    subnet_id = _ec2_select_subnet(profile, region)
    existing = _ec2_call(profile, region, "ec2", "describe-instances", "--filters", f"Name=tag:Name,Values={EC2_TARGET_NAME}", "Name=tag:Repo,Values=agentic-ai-cybersecurity-lab", "Name=instance-state-name,Values=pending,running,stopping,stopped")
    if any(reservation.get("Instances") for reservation in existing.get("Reservations", []) if isinstance(reservation, dict)):
        raise RuntimeError("EC2 target name is already in use")
    repo_dir = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.update({"SECCOP_PROFILE": profile, "SECCOP_REGION": region, "SECCOP_AMI_NAME_PATTERN": os.environ.get("SECCOP_EC2_AMI_NAME_PATTERN", EC2_AMI_NAME), "TF_VAR_instance_type": "t3.micro"})
    start = subprocess.run([
        str(repo_dir / "scripts" / "start-demo.sh"), "--ec2-only", "--profile", profile, "--region", region,
        "--expected-principal", "amit", "--instance-profile", EC2_INSTANCE_PROFILE, "--subnet-id", subnet_id,
        "--target-name", EC2_TARGET_NAME, "--confirm",
    ], capture_output=True, text=True, check=False, timeout=900, env=env)
    _ec2_evidence("target-start", {"returncode": start.returncode, "stdout": start.stdout[-2000:], "stderr": start.stderr[-2000:]})
    if start.returncode != 0:
        raise RuntimeError("Repo-owned EC2 target start was blocked")
    target = _ec2_target(profile, region)
    instance_id = target.get("InstanceId")
    if not isinstance(instance_id, str) or target.get("InstanceType") not in {"t3.nano", "t3.micro", "t3.small"}:
        raise RuntimeError("EC2 target shape is outside the approved small-instance envelope")
    groups = target.get("SecurityGroups", [])
    if len(groups) != 1 or not isinstance(groups[0], dict) or not isinstance(groups[0].get("GroupId"), str):
        raise RuntimeError("EC2 target security-group shape is invalid")
    group_id = groups[0]["GroupId"]
    sg = _ec2_call(profile, region, "ec2", "describe-security-groups", "--group-ids", group_id)
    if len(sg.get("SecurityGroups", [])) != 1 or sg["SecurityGroups"][0].get("IpPermissions") != []:
        raise RuntimeError("EC2 target security group is not zero-ingress")
    volume_id = target.get("BlockDeviceMappings", [{}])[0].get("Ebs", {}).get("VolumeId") if target.get("BlockDeviceMappings") else None
    # Persist the exact target binding before subsequent setup mutations so a
    # failure in recorder/rule wiring still leaves the repo-owned cleanup path
    # able to remove only this disposable instance and its dedicated SG.
    _ec2_save_state({"target_name": EC2_TARGET_NAME, "instance_id": instance_id, "security_group_id": group_id, "volume_id": volume_id, "subnet_id": subnet_id, "profile": profile, "region": region})
    _ec2_retain_tags(profile, region, instance_id, group_id, volume_id)
    _ec2_call(profile, region, "ec2", "modify-instance-metadata-options", "--instance-id", instance_id, "--http-tokens", "optional")
    _ec2_wait_ssm(profile, region, instance_id)
    recorder_changed = _ec2_recorder_setup(profile, region)
    _ec2_config_setup(profile, region, instance_id, account)
    state = {"target_name": EC2_TARGET_NAME, "instance_id": instance_id, "security_group_id": group_id, "volume_id": volume_id, "subnet_id": subnet_id, "recorder_changed": recorder_changed, "role_policy": EC2_AUTOMATION_POLICY, "config_rule": EC2_CONFIG_RULE, "profile": profile, "region": region}
    _ec2_save_state(state)
    after = _ec2_target(profile, region)
    metadata = after.get("MetadataOptions", {})
    if metadata.get("HttpTokens") != "optional":
        raise RuntimeError("EC2 target did not reach the required initial optional-token state")
    _ec2_evidence("target-ready", {"resource_alias": "EC2_RESOURCE_01", "metadata_tokens": "optional", "ssm": "Online", "zero_ingress": True})
    return {"status": "READY", "reason_code": "SECCOP_EC2_IMDSV2_SETUP_READY", "resource_alias": "EC2_RESOURCE_01", "state": "NON_COMPLIANT_BASELINE_READY"}


def _ec2_compliance(profile: str, region: str, instance_id: str, expected: str) -> str:
    try:
        _ec2_call(profile, region, "configservice", "start-config-rules-evaluation", "--config-rule-names", EC2_CONFIG_RULE)
    except RuntimeError:
        pass
    deadline = time.monotonic() + EC2_CONFIG_TIMEOUT_SECONDS
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = _ec2_call(profile, region, "configservice", "get-compliance-details-by-resource", "--resource-type", "AWS::EC2::Instance", "--resource-id", instance_id)
        results = [item for item in latest.get("EvaluationResults", []) if item.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {}).get("ConfigRuleName") == EC2_CONFIG_RULE]
        if results:
            state = str(results[0].get("ComplianceType", "UNKNOWN"))
            if state == expected:
                _ec2_evidence(f"config-compliance-{expected.lower()}", latest)
                return state
        time.sleep(10)
    _ec2_evidence(f"config-compliance-timeout-{expected.lower()}", latest)
    raise RuntimeError(f"EC2 Config compliance did not reach {expected}")


def ec2_scan(profile: str, region: str) -> dict[str, Any]:
    state = _ec2_load_state(); target = _ec2_target(profile, region); instance_id = state["instance_id"]
    if target.get("InstanceId") != instance_id or target.get("State", {}).get("Name") != "running":
        raise RuntimeError("EC2 target is not the exact running target")
    tokens = target.get("MetadataOptions", {}).get("HttpTokens")
    expected = "NON_COMPLIANT" if tokens == "optional" else "COMPLIANT" if tokens == "required" else "UNKNOWN"
    if expected == "UNKNOWN" or _ec2_compliance(profile, region, instance_id, expected) != expected:
        raise RuntimeError("EC2 Config and metadata states did not agree")
    if expected == "NON_COMPLIANT":
        return {"status": "READY", "reason_code": "SECCOP_EC2_IMDSV2_NON_COMPLIANT", "state": "NON_COMPLIANT", "config_rule_name": EC2_CONFIG_RULE, "source_status": [{"source_type": "EC2_CONFIG", "label": "EC2 IMDSv2 Config control", "state": "COMPLETE", "reason_code": "SECCOP_SOURCE_READY"}], "findings": [{"finding_id": "FINDING_01", "source_type": "EC2_CONFIG", "resource_alias": "EC2_RESOURCE_01", "reference": "EC2_IMDSV2_RULE_01", "severity": "MEDIUM", "title": "EC2 IMDSv2 is not enforced", "problem_summary": "AWS Config found an EC2 instance that still accepts IMDSv1.", "observed_state": "HttpTokens=optional; Config NON_COMPLIANT", "recommended_state": "Run only the manual AWS-managed IMDSv2 Automation and verify COMPLIANT.", "remediation_mode": "REAL_APPROVAL_REQUIRED", "reason_code": "SECCOP_EC2_IMDSV2_FINDING", "action_label": "Remediate"}], "message": "AWS Config found one EC2 IMDSv2 compliance finding. Human approval is required before remediation."}
    return {"status": "NO_FINDINGS", "reason_code": "SECCOP_EC2_IMDSV2_COMPLIANT", "state": "COMPLIANT", "config_rule_name": EC2_CONFIG_RULE, "source_status": [{"source_type": "EC2_CONFIG", "label": "EC2 IMDSv2 Config control", "state": "COMPLETE", "reason_code": "SECCOP_SOURCE_READY"}], "findings": [], "message": "AWS Config verified the EC2 target is IMDSv2 compliant."}


def ec2_reject(profile: str, region: str) -> dict[str, Any]:
    result = ec2_scan(profile, region)
    if result.get("reason_code") != "SECCOP_EC2_IMDSV2_NON_COMPLIANT":
        raise RuntimeError("EC2 rejection requires a fresh NON_COMPLIANT finding")
    return {"status": "REJECTED", "reason_code": "HUMAN_REJECTED", "state": "NON_COMPLIANT", "mutation_performed": False, "message": "The EC2 IMDSv2 remediation proposal was rejected; no AWS mutation was performed."}


def _ec2_automation(profile: str, region: str, before_ids: set[str]) -> dict[str, Any]:
    deadline = time.monotonic() + 480
    while time.monotonic() < deadline:
        executions = _ec2_call(profile, region, "ssm", "describe-automation-executions", "--filters", f"Key=DocumentNamePrefix,Values={EC2_SSM_DOCUMENT}", "--max-results", "50").get("AutomationExecutionMetadataList", [])
        fresh = [item for item in executions if isinstance(item, dict) and item.get("DocumentName") == EC2_SSM_DOCUMENT and str(item.get("AutomationExecutionId")) not in before_ids]
        if fresh:
            execution = fresh[0]; status = execution.get("AutomationExecutionStatus")
            if status in {"Success", "Failed", "TimedOut", "Cancelled"}:
                execution_id = execution.get("AutomationExecutionId")
                if status != "Success" or not isinstance(execution_id, str):
                    raise RuntimeError("IMDSv2 Automation did not reach Success")
                detail = _ec2_call(profile, region, "ssm", "get-automation-execution", "--automation-execution-id", execution_id)
                steps = _ec2_call(profile, region, "ssm", "describe-automation-step-executions", "--automation-execution-id", execution_id)
                _ec2_evidence("automation-terminal", {"status": "Success", "execution": detail, "steps": steps})
                return {"status": "Success", "execution_alias": "AUTOMATION_EXECUTION_01"}
        time.sleep(10)
    raise RuntimeError("IMDSv2 Automation did not reach a terminal state")


def ec2_apply(profile: str, region: str) -> dict[str, Any]:
    state = _ec2_load_state(); before = ec2_scan(profile, region)
    if before.get("reason_code") != "SECCOP_EC2_IMDSV2_NON_COMPLIANT":
        raise RuntimeError("EC2 remediation requires a fresh NON_COMPLIANT finding")
    configs = _ec2_call(profile, region, "configservice", "describe-remediation-configurations", "--config-rule-names", EC2_CONFIG_RULE).get("RemediationConfigurations", [])
    if len(configs) != 1 or configs[0].get("TargetId") != EC2_SSM_DOCUMENT or configs[0].get("Automatic") is not False or str(configs[0].get("TargetVersion")) != EC2_SSM_DOCUMENT_VERSION:
        raise RuntimeError("EC2 remediation binding is not exact and manual")
    existing = _ec2_call(profile, region, "ssm", "describe-automation-executions", "--filters", f"Key=DocumentNamePrefix,Values={EC2_SSM_DOCUMENT}", "--max-results", "50").get("AutomationExecutionMetadataList", [])
    before_ids = {str(item.get("AutomationExecutionId")) for item in existing if isinstance(item, dict)}
    started = _ec2_call(profile, region, "configservice", "start-remediation-execution", "--config-rule-name", EC2_CONFIG_RULE, "--resource-keys", json.dumps([{"resourceType": "AWS::EC2::Instance", "resourceId": state["instance_id"]}]))
    _ec2_evidence("remediation-start", started)
    automation = _ec2_automation(profile, region, before_ids)
    target = _ec2_target(profile, region)
    if target.get("MetadataOptions", {}).get("HttpTokens") != "required":
        raise RuntimeError("EC2 IMDSv2 metadata verification failed")
    if _ec2_compliance(profile, region, state["instance_id"], "COMPLIANT") != "COMPLIANT":
        raise RuntimeError("EC2 Config COMPLIANT verification failed")
    return {"status": "VERIFIED", "reason_code": "SECCOP_EC2_IMDSV2_REMEDIATED", "state": "COMPLIANT", "metadata_http_tokens": "required", "automation_status": automation["status"], "message": "AWS Config remediation completed through AWSConfigRemediation-EnforceEC2InstanceIMDSv2 and the protected EC2 state was verified."}


def ec2_cleanup(profile: str, region: str) -> dict[str, Any]:
    try:
        state = _ec2_load_state()
    except RuntimeError:
        return {"status": "CLEANED", "reason_code": "SECCOP_EC2_CLEANUP_VERIFIED", "resource_alias": "EC2_RESOURCE_01", "already_absent": True}
    errors: list[str] = []
    try:
        _ec2_call(profile, region, "configservice", "delete-remediation-configuration", "--config-rule-name", EC2_CONFIG_RULE, allow_missing=True)
        for _ in range(30):
            remaining_remediation = _ec2_call(profile, region, "configservice", "describe-remediation-configurations", "--config-rule-names", EC2_CONFIG_RULE, allow_missing=True)
            if not remaining_remediation.get("RemediationConfigurations"):
                break
            time.sleep(2)
        else:
            errors.append("config-remediation-remains")
    except RuntimeError:
        errors.append("delete-remediation-configuration")
    if "config-remediation-remains" not in errors:
        for attempt in range(6):
            try:
                _ec2_call(profile, region, "configservice", "delete-config-rule", "--config-rule-name", EC2_CONFIG_RULE, allow_missing=True)
                break
            except RuntimeError:
                if attempt == 5:
                    errors.append("delete-config-rule")
                else:
                    time.sleep(2)
        if "delete-config-rule" not in errors:
            for _ in range(30):
                remaining_rule = _ec2_call(profile, region, "configservice", "describe-config-rules", "--config-rule-names", EC2_CONFIG_RULE, allow_missing=True)
                if not remaining_rule.get("ConfigRules"):
                    break
                time.sleep(2)
            else:
                errors.append("config-rule-remains")
    try:
        _ec2_call(profile, region, "iam", "delete-role-policy", "--role-name", EC2_AUTOMATION_ROLE, "--policy-name", EC2_AUTOMATION_POLICY, allow_missing=True)
    except RuntimeError:
        errors.append("delete-role-policy")
    repo_dir = Path(__file__).resolve().parents[1]
    env = os.environ.copy(); env.update({"SECCOP_PROFILE": profile, "SECCOP_REGION": region, "SECCOP_AMI_NAME_PATTERN": os.environ.get("SECCOP_EC2_AMI_NAME_PATTERN", EC2_AMI_NAME)})
    subnet = str(state.get("subnet_id", ""))
    cleanup = subprocess.run([str(repo_dir / "scripts" / "cleanup-demo.sh"), "--ec2-only", "--profile", profile, "--region", region, "--expected-principal", "amit", "--instance-profile", EC2_INSTANCE_PROFILE, "--subnet-id", subnet, "--target-name", EC2_TARGET_NAME, "--confirm"], capture_output=True, text=True, check=False, timeout=900, env=env)
    _ec2_evidence("target-cleanup", {"returncode": cleanup.returncode, "stdout": cleanup.stdout[-2000:], "stderr": cleanup.stderr[-2000:]})
    if cleanup.returncode != 0:
        errors.append("repo-owned-ec2-cleanup")
    remaining = _ec2_call(profile, region, "ec2", "describe-instances", "--filters", f"Name=tag:Name,Values={EC2_TARGET_NAME}", "Name=tag:Repo,Values=agentic-ai-cybersecurity-lab", "Name=instance-state-name,Values=pending,running,stopping,stopped")
    if any(reservation.get("Instances") for reservation in remaining.get("Reservations", []) if isinstance(reservation, dict)):
        errors.append("target-remains")
    rule = _ec2_call(profile, region, "configservice", "describe-config-rules", "--config-rule-names", EC2_CONFIG_RULE, allow_missing=True)
    rem = _ec2_call(profile, region, "configservice", "describe-remediation-configurations", "--config-rule-names", EC2_CONFIG_RULE, allow_missing=True)
    if rule.get("ConfigRules") or rem.get("RemediationConfigurations"):
        errors.append("config-binding-remains")
    else:
        errors = [error for error in errors if error not in {"config-remediation-remains", "config-rule-remains", "delete-remediation-configuration", "delete-config-rule"}]
    if errors:
        raise RuntimeError("EC2 cleanup verification failed")
    _ec2_state_path().unlink(missing_ok=True)
    return {"status": "CLEANED", "reason_code": "SECCOP_EC2_CLEANUP_VERIFIED", "resource_alias": "EC2_RESOURCE_01", "target_absent": True, "config_binding_absent": True}


def must_be_missing(profile: str, region: str, *args: str) -> None:
    completed = subprocess.run(["aws", "--profile", profile, "--region", region, *args, "--output", "json"], capture_output=True, text=True, check=False, timeout=60)
    if completed.returncode == 0:
        raise RuntimeError("The disposable bucket has an unsafe optional configuration")
    if "NoSuch" not in completed.stderr and "NotFound" not in completed.stderr:
        raise RuntimeError("The disposable bucket safety check was unavailable")


def tags() -> dict[str, str]:
    return {
        "Name": "seccop-issue47-s3-bpa-e2e",
        "dev": "amit", "project": "agentic-ai-cybersecurity-lab", "created": "2026-09-01",
        "tools": "cdx", "environment": "dev", "owner": "amit", "version": "issue47",
        "TTL": "01-09-26", "purpose": "S3 Block Public Access compliance proof",
        "phase": "issue47", "cleanup": "delete",
    }


def scan(profile: str, region: str, bucket: str) -> dict[str, Any]:
    protected = _s3_safety(profile, region, bucket)
    state = load_state() if os.environ.get("SECCOP_S3_STATE") and state_path().exists() else None
    config_state = None
    if state and state.get("bucket") == bucket:
        config_state = _config_compliance(profile, region, bucket, expected="COMPLIANT" if protected else "NON_COMPLIANT")
    evidence("scan-summary", {"bucket_alias": "S3_BUCKET_ALIAS_03", "local_protected": protected, "config_compliance": config_state or "NOT_CONFIGURED"})
    return {
        "scan_id": f"SECCOP_S3_SCAN_{int(time.time())}", "status": "NO_FINDINGS" if protected else "READY", "state": "COMPLIANT" if protected else "NON_COMPLIANT", "reason_code": "SECCOP_S3_COMPLIANT" if protected else "SECCOP_S3_NON_COMPLIANT",
        "config_rule_name": CONFIG_RULE if config_state else None, "config_source": CONFIG_SOURCE if config_state else None, "remediation_document": SSM_DOCUMENT if config_state else None,
        "source_status": [{"source_type": "S3_BUCKET", "label": "S3 exposure-risk control", "state": "COMPLETE", "reason_code": "SECCOP_S3_CONTROL_READ"}],
        "findings": [] if protected else [{
            "finding_id": "S3_BPA_01", "source_type": "S3_BUCKET", "resource_alias": "S3_BUCKET_ALIAS_03",
            "cve_id": "NOT_APPLICABLE", "reference": "S3_BLOCK_PUBLIC_ACCESS", "severity": "NOT_APPLICABLE",
            "title": "S3 exposure risk: Block Public Access is missing", "problem_summary": "Bucket-level public access protection is not configured.",
            "observed_state": "Block Public Access absent", "recommended_state": "Enable all four Block Public Access controls.",
            "remediation_mode": "REAL_APPROVAL_REQUIRED", "reason_code": "SECCOP_S3_EXPOSURE_RISK", "action_label": "Review exposure-risk remediation", "config_rule_name": CONFIG_RULE, "remediation_document": SSM_DOCUMENT,
        }],
        "message": "SecCop detected an S3 exposure risk. Human approval is required before changing the protected state." if not protected else "SecCop verified the S3 bucket is protected.",
    }


def apply(profile: str, region: str, bucket: str) -> dict[str, Any]:
    state = load_state()
    if state.get("bucket") != bucket or state.get("config_rule_name") != CONFIG_RULE or state.get("config_source") != CONFIG_SOURCE or state.get("remediation_document") != SSM_DOCUMENT or state.get("remediation_document_version") != SSM_DOCUMENT_VERSION or state.get("automatic") is not False:
        raise RuntimeError("S3 remediation binding is invalid")
    before = scan(profile, region, bucket)
    if before.get("reason_code") != "SECCOP_S3_NON_COMPLIANT":
        raise RuntimeError("S3 remediation requires a fresh NON_COMPLIANT finding")
    configs = aws(profile, region, "configservice", "describe-remediation-configurations", "--config-rule-names", CONFIG_RULE)
    configured = configs.get("RemediationConfigurations", [])
    if len(configured) != 1 or configured[0].get("TargetId") != SSM_DOCUMENT or str(configured[0].get("TargetVersion")) != SSM_DOCUMENT_VERSION or configured[0].get("Automatic") is not False:
        raise RuntimeError("S3 remediation configuration is not exact and manual")
    existing_execution_ids = {str(item.get("AutomationExecutionId")) for item in _automation_executions(profile, region)}
    keys = [{"resourceType": "AWS::S3::Bucket", "resourceId": bucket}]
    started = aws(profile, region, "configservice", "start-remediation-execution", "--config-rule-name", CONFIG_RULE, "--resource-keys", json.dumps(keys))
    evidence("remediation-start", started)
    deadline = time.monotonic() + 420
    status = {}
    automation = {}
    while time.monotonic() < deadline:
        status = aws(profile, region, "configservice", "describe-remediation-execution-status", "--config-rule-name", CONFIG_RULE)
        executions = [item for item in _automation_executions(profile, region) if str(item.get("AutomationExecutionId")) not in existing_execution_ids]
        if executions:
            automation = executions[0]
            if automation.get("AutomationExecutionStatus") in {"Success", "Failed", "TimedOut", "Cancelled"}:
                if automation.get("AutomationExecutionStatus") != "Success":
                    raise RuntimeError("S3 remediation Automation failed")
                break
        time.sleep(10)
    else:
        raise RuntimeError("S3 remediation execution timed out")
    evidence("remediation-status", {"config": status, "automation": automation})
    protected = _s3_safety(profile, region, bucket)
    if not protected or _config_compliance(profile, region, bucket, expected="COMPLIANT") != "COMPLIANT":
        raise RuntimeError("S3 protection verification failed")
    return {"status": "VERIFIED", "reason_code": "SECCOP_S3_EXPOSURE_RISK_REMEDIATED", "state": "COMPLIANT", "config_rule_name": CONFIG_RULE, "remediation_document": SSM_DOCUMENT, "message": "SecCop detected and remediated an S3 exposure risk by enabling Block Public Access, then verified the protected state."}


def reset(profile: str, region: str, bucket: str) -> dict[str, Any]:
    """Return one server-owned, empty private bucket to the approved demo drift."""
    before = scan(profile, region, bucket)
    if before["reason_code"] == "SECCOP_S3_NON_COMPLIANT":
        return {"status": "READY", "reason_code": "SECCOP_S3_RESET_READY", "message": "The approved S3 exposure-risk demo is already action required."}
    if before["reason_code"] != "SECCOP_S3_COMPLIANT":
        raise RuntimeError("Reset requires a verified protected bucket")
    aws(profile, region, "s3api", "delete-public-access-block", "--bucket", bucket)
    if os.environ.get("SECCOP_S3_STATE") and state_path().exists():
        _config_compliance(profile, region, bucket, expected="NON_COMPLIANT")
    after = scan(profile, region, bucket)
    if after["reason_code"] != "SECCOP_S3_NON_COMPLIANT":
        raise RuntimeError("S3 reset verification failed")
    return {"status": "READY", "reason_code": "SECCOP_S3_RESET_READY", "message": "The approved S3 exposure-risk demo was reset to action required."}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("setup", "create", "scan", "apply", "reset", "cleanup", "ec2-setup", "ec2-adopt", "ec2-scan", "ec2-reject", "ec2-apply", "ec2-cleanup", "ec2-rnd-preflight", "ec2-rnd-setup", "ec2-rnd-scan", "ec2-rnd-rearm"))
    parser.add_argument("--profile", required=True); parser.add_argument("--region", required=True); parser.add_argument("--bucket")
    parser.add_argument("--instance-id")
    parser.add_argument("--delivery-bucket")
    parser.add_argument("--extra-bucket", action="append", default=[])
    parser.add_argument("--protected", action="store_true")
    parser.add_argument("--alias")
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "ec2-setup":
            output = ec2_setup(args.profile, args.region)
        elif args.command == "ec2-adopt":
            if not args.instance_id:
                raise RuntimeError("DEV EC2 instance ID is required")
            output = ec2_adopt(args.profile, args.region, args.instance_id)
        elif args.command == "ec2-scan":
            output = ec2_scan(args.profile, args.region)
        elif args.command == "ec2-reject":
            output = ec2_reject(args.profile, args.region)
        elif args.command == "ec2-apply":
            output = ec2_apply(args.profile, args.region)
        elif args.command == "ec2-cleanup":
            output = ec2_cleanup(args.profile, args.region)
        elif args.command == "ec2-rnd-preflight":
            output = _ec2_rnd_preflight(args.profile, args.region)
        elif args.command == "ec2-rnd-setup":
            output = _ec2_rnd_setup(args.profile, args.region)
        elif args.command == "ec2-rnd-scan":
            if args.alias not in {EC2_RND_ALIAS_LAB01, EC2_RND_ALIAS_LAB02}:
                raise RuntimeError("DEV R&D target alias is required")
            output = _ec2_rnd_scan(args.profile, args.region, args.alias)
        elif args.command == "ec2-rnd-rearm":
            if args.alias not in {EC2_RND_ALIAS_LAB01, EC2_RND_ALIAS_LAB02}:
                raise RuntimeError("DEV R&D target alias is required")
            output = _ec2_rnd_rearm(args.profile, args.region, args.alias, args.confirm)
        elif args.command == "setup":
            if not args.delivery_bucket:
                raise RuntimeError("Config delivery bucket is required")
            output = _config_setup(args.profile, args.region, args.bucket, args.delivery_bucket)
        elif args.command == "create":
            if not args.bucket:
                raise RuntimeError("S3 bucket is required")
            aws(args.profile, args.region, "s3api", "create-bucket", "--bucket", args.bucket, "--create-bucket-configuration", f"LocationConstraint={args.region}")
            aws(args.profile, args.region, "s3api", "put-bucket-ownership-controls", "--bucket", args.bucket, "--ownership-controls", "Rules=[{ObjectOwnership=BucketOwnerEnforced}]")
            tagset = {"TagSet": [{"Key": key, "Value": value} for key, value in tags().items()]}
            tagfile = Path(os.environ["SECCOP_S3_TAGS"]); tagfile.write_text(json.dumps(tagset), encoding="utf-8")
            aws(args.profile, args.region, "s3api", "put-bucket-tagging", "--bucket", args.bucket, "--tagging", f"file://{tagfile}")
            # Some accounts apply bucket-level Block Public Access at creation.
            # The approved proof needs that one control absent, but the bucket
            # is already empty, BucketOwnerEnforced, and has no policy or website.
            aws(args.profile, args.region, "s3api", "delete-public-access-block", "--bucket", args.bucket, allow_missing=True)
            if args.protected:
                apply(args.profile, args.region, args.bucket)
            output = {"status": "READY", "reason_code": "SECCOP_S3_BASELINE_READY"}
        elif args.command == "scan":
            if not args.bucket:
                raise RuntimeError("S3 bucket is required")
            output = scan(args.profile, args.region, args.bucket)
        elif args.command == "apply":
            if not args.bucket:
                raise RuntimeError("S3 bucket is required")
            output = apply(args.profile, args.region, args.bucket)
        elif args.command == "reset":
            if not args.bucket:
                raise RuntimeError("S3 bucket is required")
            output = reset(args.profile, args.region, args.bucket)
        else:
            if not args.bucket:
                raise RuntimeError("S3 bucket is required")
            for bucket in [args.bucket, *args.extra_bucket]:
                aws(args.profile, args.region, "s3api", "delete-bucket", "--bucket", bucket)
            output = {"status": "DELETED", "reason_code": "SECCOP_S3_CLEANUP_VERIFIED"}
        print(json.dumps(output, separators=(",", ":")))
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        print(json.dumps({"status": "BLOCKED", "reason_code": "SECCOP_S3_BACKEND_BLOCKED", "message": "The bounded S3 compliance operation was blocked."}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
