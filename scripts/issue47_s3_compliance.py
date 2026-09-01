#!/usr/bin/env python3
"""One bounded S3 Block Public Access SecCop proof; aliases stay public."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def call(args: list[str], *, allow_missing: bool = False) -> dict[str, Any]:
    completed = subprocess.run(args, capture_output=True, text=True, check=False, timeout=60)
    if completed.returncode and not allow_missing:
        raise RuntimeError("AWS command failed")
    try:
        value = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("AWS returned invalid output") from exc
    return value if isinstance(value, dict) else {}


def aws(profile: str, region: str, *args: str, allow_missing: bool = False) -> dict[str, Any]:
    return call(["aws", "--profile", profile, "--region", region, *args, "--output", "json"], allow_missing=allow_missing)


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
    ownership = aws(profile, region, "s3api", "get-bucket-ownership-controls", "--bucket", bucket)
    rules = ownership.get("OwnershipControls", {}).get("Rules", [])
    if rules != [{"ObjectOwnership": "BucketOwnerEnforced"}]:
        raise RuntimeError("Bucket ownership enforcement is absent")
    must_be_missing(profile, region, "s3api", "get-bucket-policy", "--bucket", bucket)
    must_be_missing(profile, region, "s3api", "get-bucket-website", "--bucket", bucket)
    acl = aws(profile, region, "s3api", "get-bucket-acl", "--bucket", bucket)
    grants = acl.get("Grants", [])
    if any(isinstance(item, dict) and isinstance(item.get("Grantee"), dict) and item["Grantee"].get("URI") in {"http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"} for item in grants):
        raise RuntimeError("Bucket has a public ACL")
    objects = aws(profile, region, "s3api", "list-objects-v2", "--bucket", bucket)
    if objects.get("KeyCount", 0) != 0:
        raise RuntimeError("Bucket is not empty")
    result = aws(profile, region, "s3api", "get-public-access-block", "--bucket", bucket, allow_missing=True)
    configured = result.get("PublicAccessBlockConfiguration", {})
    protected = all(configured.get(key) is True for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
    if configured and not protected:
        raise RuntimeError("Bucket-level Block Public Access is not cleanly absent or fully enabled")
    return {
        "scan_id": "SECCOP_S3_SCAN_01", "status": "READY", "reason_code": "SECCOP_S3_COMPLIANT" if protected else "SECCOP_S3_NON_COMPLIANT",
        "source_status": [{"source_type": "S3_BUCKET", "label": "S3 exposure-risk control", "state": "COMPLETE", "reason_code": "SECCOP_S3_CONTROL_READ"}],
        "findings": [] if protected else [{
            "finding_id": "S3_BPA_01", "source_type": "S3_BUCKET", "resource_alias": "S3_BUCKET_01",
            "cve_id": "NOT_APPLICABLE", "reference": "S3_BLOCK_PUBLIC_ACCESS", "severity": "NOT_APPLICABLE",
            "title": "S3 exposure risk: Block Public Access is missing", "problem_summary": "Bucket-level public access protection is not configured.",
            "observed_state": "Block Public Access absent", "recommended_state": "Enable all four Block Public Access controls.",
            "remediation_mode": "REAL_APPROVAL_REQUIRED", "reason_code": "SECCOP_S3_EXPOSURE_RISK", "action_label": "Review exposure-risk remediation",
        }],
        "message": "SecCop detected an S3 exposure risk. Human approval is required before changing the protected state." if not protected else "SecCop verified the S3 bucket is protected.",
    }


def apply(profile: str, region: str, bucket: str) -> dict[str, Any]:
    payload = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    config = Path(os.environ["SECCOP_S3_CONFIG"])
    config.write_text(json.dumps(payload), encoding="utf-8")
    aws(profile, region, "s3api", "put-public-access-block", "--bucket", bucket, "--public-access-block-configuration", f"file://{config}")
    after = scan(profile, region, bucket)
    if after["reason_code"] != "SECCOP_S3_COMPLIANT":
        raise RuntimeError("S3 protection verification failed")
    return {"status": "VERIFIED", "reason_code": "SECCOP_S3_EXPOSURE_RISK_REMEDIATED", "state": "COMPLIANT", "message": "SecCop detected and remediated an S3 exposure risk by enabling Block Public Access, then verified the protected state."}


def reset(profile: str, region: str, bucket: str) -> dict[str, Any]:
    """Return one server-owned, empty private bucket to the approved demo drift."""
    before = scan(profile, region, bucket)
    if before["reason_code"] != "SECCOP_S3_COMPLIANT":
        raise RuntimeError("Reset requires a verified protected bucket")
    aws(profile, region, "s3api", "delete-public-access-block", "--bucket", bucket)
    after = scan(profile, region, bucket)
    if after["reason_code"] != "SECCOP_S3_NON_COMPLIANT":
        raise RuntimeError("S3 reset verification failed")
    return {"status": "READY", "reason_code": "SECCOP_S3_RESET_READY", "message": "The approved S3 exposure-risk demo was reset to action required."}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("create", "scan", "apply", "reset", "cleanup"))
    parser.add_argument("--profile", required=True); parser.add_argument("--region", required=True); parser.add_argument("--bucket", required=True)
    parser.add_argument("--extra-bucket", action="append", default=[])
    parser.add_argument("--protected", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "create":
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
