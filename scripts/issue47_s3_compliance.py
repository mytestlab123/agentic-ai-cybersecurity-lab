#!/usr/bin/env python3
"""One bounded S3 Block Public Access SecCop proof; aliases stay public."""

from __future__ import annotations

import argparse
import json
import os
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
    parser.add_argument("command", choices=("setup", "create", "scan", "apply", "reset", "cleanup"))
    parser.add_argument("--profile", required=True); parser.add_argument("--region", required=True); parser.add_argument("--bucket", required=True)
    parser.add_argument("--delivery-bucket")
    parser.add_argument("--extra-bucket", action="append", default=[])
    parser.add_argument("--protected", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "setup":
            if not args.delivery_bucket:
                raise RuntimeError("Config delivery bucket is required")
            output = _config_setup(args.profile, args.region, args.bucket, args.delivery_bucket)
        elif args.command == "create":
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
        elif args.command == "scan": output = scan(args.profile, args.region, args.bucket)
        elif args.command == "apply": output = apply(args.profile, args.region, args.bucket)
        elif args.command == "reset": output = reset(args.profile, args.region, args.bucket)
        else:
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
