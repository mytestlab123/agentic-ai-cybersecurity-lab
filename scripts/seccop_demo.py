#!/usr/bin/env python3
"""Small, repeatable SecCop DEMO baseline for Project1.

The script owns only tagged demo artifacts. It deliberately does not enable
GuardDuty, create networking, or change the EC2 package. The existing SecCop
EC2 approval path remains authoritative for the server fix. Its ``cleanup``
command deletes only the two tag-owned S3 buckets and the tag-owned ECR
repository; EC2 cleanup remains in the Terraform wrapper.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


BAD_VERSION = "1.24.1"
CLEAN_VERSION = "2.7.0"
BAD_CVE = "CVE-2019-11324"
NPM_BAD_VERSION = "4.17.15"
NPM_CLEAN_VERSION = "4.17.21"
NPM_CVE = "CVE-2020-8203"
DEFAULT_TARGET_NAME = "seccop-project1-old-ami-host-r01"
ECR_REPOSITORY = "seccop-ecr-operator-mvp"
ECR_FIXTURE_TAGS = {
    "current": "demo-current",
    "vulnerable": "issue53-live-vulnerable",
    "clean": "issue53-live-clean",
    "python-vulnerable": "issue53-vulnerable",
    "python-clean": "issue53-clean",
    "npm-vulnerable": "issue53-npm-vulnerable",
    "npm-clean": "issue53-npm-clean",
}
ECR_FIXTURE_SPECS = {
    "current": {"tag": "demo-current", "cve_id": BAD_CVE, "ecosystem": "PYTHON"},
    "vulnerable": {"tag": "issue53-live-vulnerable", "cve_id": BAD_CVE, "ecosystem": "PYTHON"},
    "clean": {"tag": "issue53-live-clean", "cve_id": BAD_CVE, "ecosystem": "PYTHON"},
    "python-vulnerable": {"tag": "issue53-vulnerable", "cve_id": BAD_CVE, "ecosystem": "PYTHON"},
    "python-clean": {"tag": "issue53-clean", "cve_id": BAD_CVE, "ecosystem": "PYTHON"},
    "npm-vulnerable": {"tag": "issue53-npm-vulnerable", "cve_id": NPM_CVE, "ecosystem": "JAVASCRIPT_NPM"},
    "npm-clean": {"tag": "issue53-npm-clean", "cve_id": NPM_CVE, "ecosystem": "JAVASCRIPT_NPM"},
}


class DemoError(RuntimeError):
    """A safe, operator-readable DEMO failure."""


@dataclass(frozen=True)
class Config:
    profile: str
    region: str
    target_name: str
    evidence_root: Path


class AwsCli:
    def __init__(self, config: Config) -> None:
        self.config = config

    def run(self, *args: str, input_text: str | None = None) -> str:
        command = [
            "aws",
            "--profile",
            self.config.profile,
            "--region",
            self.config.region,
            *args,
        ]
        result = subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or "AWS command failed."
            raise DemoError(detail[:220])
        return result.stdout

    def json(self, *args: str) -> dict[str, Any]:
        try:
            value = json.loads(self.run(*args))
        except json.JSONDecodeError as error:
            raise DemoError("AWS returned invalid JSON.") from error
        if not isinstance(value, dict):
            raise DemoError("AWS returned an invalid object.")
        return value


def _account_suffix(aws: AwsCli) -> str:
    identity = aws.json("sts", "get-caller-identity")
    account = identity.get("Account")
    if not isinstance(account, str) or not account.isdigit():
        raise DemoError("The selected AWS profile did not return an account.")
    return account[-8:]


def _bucket_names(aws: AwsCli) -> tuple[str, str]:
    suffix = _account_suffix(aws)
    return f"seccop-demo-current-{suffix}", f"seccop-demo-reset-{suffix}"


def _repo_uri(aws: AwsCli) -> str:
    repositories = aws.json("ecr", "describe-repositories", "--repository-names", ECR_REPOSITORY)
    items = repositories.get("repositories")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise DemoError("The SecCop ECR repository could not be read.")
    uri = items[0].get("repositoryUri")
    if not isinstance(uri, str) or not uri:
        raise DemoError("The SecCop ECR repository URI was invalid.")
    return uri


def _ensure_bucket(aws: AwsCli, bucket: str) -> None:
    exists = True
    try:
        aws.run("s3api", "head-bucket", "--bucket", bucket)
    except DemoError:
        exists = False
    if not exists:
        create_args = ["s3api", "create-bucket", "--bucket", bucket]
        if aws.config.region != "us-east-1":
            create_args.extend(
                ["--create-bucket-configuration", f"LocationConstraint={aws.config.region}"]
            )
        aws.run(*create_args)
    aws.run(
        "s3api",
        "put-public-access-block",
        "--bucket",
        bucket,
        "--public-access-block-configuration",
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    )
    aws.run("s3api", "put-bucket-versioning", "--bucket", bucket, "--versioning-configuration", "Status=Enabled")
    tags = {"TagSet": [{"Key": "Project", "Value": "Security Copilot"}, {"Key": "Cleanup", "Value": "seccop-demo-only"}]}
    tag_file = _write_json(aws.config.evidence_root, "s3-tags.json", tags)
    aws.run("s3api", "put-bucket-tagging", "--bucket", bucket, "--tagging", f"file://{tag_file}")
    lifecycle = {
        "Rules": [
            {
                "ID": "seccop-demo-retention",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"Days": 7},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
            }
        ]
    }
    lifecycle_file = _write_json(aws.config.evidence_root, "s3-lifecycle.json", lifecycle)
    aws.run("s3api", "put-bucket-lifecycle-configuration", "--bucket", bucket, "--lifecycle-configuration", f"file://{lifecycle_file}")


def _write_json(directory: Path, name: str, value: object) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def _write_requirements(directory: Path) -> tuple[Path, Path]:
    bad = directory / "requirements-bad.txt"
    clean = directory / "requirements-clean.txt"
    bad.write_text(f"urllib3=={BAD_VERSION}\n", encoding="utf-8")
    clean.write_text(f"urllib3=={CLEAN_VERSION}\n", encoding="utf-8")
    return bad, clean


def _seed_s3(aws: AwsCli, directory: Path) -> tuple[str, str]:
    current, reset = _bucket_names(aws)
    _ensure_bucket(aws, current)
    _ensure_bucket(aws, reset)
    bad, clean = _write_requirements(directory)
    for path, key in ((bad, "baseline/bad/requirements.txt"), (clean, "baseline/clean/requirements.txt")):
        aws.run("s3", "cp", str(path), f"s3://{reset}/{key}")
    aws.run(
        "s3api",
        "copy-object",
        "--bucket",
        current,
        "--key",
        "demo/requirements.txt",
        "--copy-source",
        f"{reset}/baseline/bad/requirements.txt",
    )
    return current, reset


def _image_files(directory: Path, version: str, label: str, ecosystem: str = "python") -> tuple[Path, Path, Path]:
    layer_tar = directory / f"{label}-layer.tar"
    layer_gz = directory / f"{label}-layer.tar.gz"
    config_file = directory / f"{label}-config.json"
    manifest_file = directory / f"{label}-manifest.json"
    if ecosystem not in {"python", "npm"}:
        raise DemoError("The ECR fixture ecosystem is unsupported.")
    with tarfile.open(layer_tar, "w") as archive:
        if ecosystem == "python":
            metadata = ("Metadata-Version: 2.1\nName: urllib3\n" f"Version: {version}\n").encode()
            files = (
                ("app/requirements.txt", f"urllib3=={version}\n".encode()),
                ("usr/local/lib/python3.11/site-packages/urllib3-" + version + ".dist-info/METADATA", metadata),
            )
            command = ["/bin/sh"]
        else:
            package = json.dumps({"name": "lodash", "version": version, "license": "MIT"}, sort_keys=True).encode()
            lock = json.dumps({"name": "seccop-npm-fixture", "lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": version}}}, sort_keys=True).encode()
            files = (
                ("app/package.json", package),
                ("app/package-lock.json", lock),
                ("usr/local/lib/node_modules/lodash/package.json", package),
            )
            command = ["node", "app/index.js"]
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    raw_layer = layer_tar.read_bytes()
    uncompressed_digest = hashlib.sha256(raw_layer).hexdigest()
    with layer_gz.open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
            compressed.write(raw_layer)
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Cmd": command},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{uncompressed_digest}"]},
        "history": [{"created": "1970-01-01T00:00:00Z", "created_by": f"SecCop DEMO {ecosystem}"}],
    }
    config_bytes = json.dumps(config, separators=(",", ":"), sort_keys=True).encode()
    config_file.write_bytes(config_bytes)
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    layer_digest = hashlib.sha256(layer_gz.read_bytes()).hexdigest()
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": f"sha256:{config_digest}",
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_gz.stat().st_size,
                "digest": f"sha256:{layer_digest}",
            }
        ],
    }
    manifest_file.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    return config_file, layer_gz, manifest_file


def _upload_blob(aws: AwsCli, repository: str, path: Path, digest: str) -> None:
    check = aws.json(
        "ecr",
        "batch-check-layer-availability",
        "--repository-name",
        repository,
        "--layer-digests",
        digest,
    )
    available = check.get("layers")
    if isinstance(available, list) and available and isinstance(available[0], dict):
        if available[0].get("layerAvailability") == "AVAILABLE":
            return
    upload = aws.json("ecr", "initiate-layer-upload", "--repository-name", repository)
    upload_id = upload.get("uploadId")
    part_size = path.stat().st_size
    if not isinstance(upload_id, str) or part_size == 0:
        raise DemoError("ECR returned an invalid layer upload.")
    aws.run(
        "ecr",
        "upload-layer-part",
        "--repository-name",
        repository,
        "--upload-id",
        upload_id,
        "--part-first-byte",
        "0",
        "--part-last-byte",
        str(part_size - 1),
        "--layer-part-blob",
        f"fileb://{path}",
    )
    aws.run(
        "ecr",
        "complete-layer-upload",
        "--repository-name",
        repository,
        "--upload-id",
        upload_id,
        "--layer-digest",
        digest,
    )


def _push_image(aws: AwsCli, directory: Path, version: str, tag: str, ecosystem: str = "python") -> Path:
    config_file, layer_file, manifest_file = _image_files(directory, version, tag, ecosystem)
    config_digest = hashlib.sha256(config_file.read_bytes()).hexdigest()
    layer_digest = hashlib.sha256(layer_file.read_bytes()).hexdigest()
    _upload_blob(aws, ECR_REPOSITORY, config_file, f"sha256:{config_digest}")
    _upload_blob(aws, ECR_REPOSITORY, layer_file, f"sha256:{layer_digest}")
    try:
        aws.run(
            "ecr",
            "put-image",
            "--repository-name",
            ECR_REPOSITORY,
            "--image-tag",
            tag,
            "--image-manifest",
            f"file://{manifest_file}",
        )
    except DemoError as error:
        # A repeated start is idempotent when this exact immutable image/tag
        # already exists.  A mutable demo-current tag is still updated below.
        if "ImageAlreadyExistsException" not in str(error):
            raise
    return manifest_file


def _ensure_ecr(aws: AwsCli, directory: Path) -> str:
    try:
        uri = _repo_uri(aws)
    except DemoError:
        created = aws.json(
            "ecr",
            "create-repository",
            "--repository-name",
            ECR_REPOSITORY,
            "--image-tag-mutability",
            "MUTABLE",
            "--tags",
            "Key=Name,Value=seccop-ecr-operator-mvp",
            "Key=dev,Value=amit",
            "Key=project,Value=agentic-ai-cybersecurity-lab",
            "Key=created,Value=2026-09-01",
            "Key=tools,Value=cdx",
            "Key=environment,Value=dev",
            "Key=owner,Value=amit",
            "Key=version,Value=ecr-operator-mvp",
            "Key=TTL,Value=01-10-26",
            "Key=purpose,Value=Reusable SecCop ECR operator demo",
            "Key=phase,Value=reusable-demo",
            "Key=cleanup,Value=keep",
        )
        repositories = created.get("repository")
        if not isinstance(repositories, dict) or not isinstance(repositories.get("repositoryUri"), str):
            raise DemoError("ECR did not return the created repository.")
        uri = str(repositories["repositoryUri"])
    lifecycle = {
        "rules": [
            {
                "rulePriority": 1,
                "description": "Keep the small SecCop DEMO image set",
                "selection": {"tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 6},
                "action": {"type": "expire"},
            }
        ]
    }
    lifecycle_file = _write_json(directory, "ecr-lifecycle.json", lifecycle)
    aws.run("ecr", "put-lifecycle-policy", "--repository-name", ECR_REPOSITORY, "--lifecycle-policy-text", f"file://{lifecycle_file}")
    _push_image(aws, directory, BAD_VERSION, "demo-bad")
    _push_image(aws, directory, CLEAN_VERSION, "demo-clean")
    # Reuse the deterministic bad manifest for the current DEMO tag.
    _push_image(aws, directory, BAD_VERSION, "demo-current")
    _write_json(directory, "ecr-ready.json", {"source": "ECR_IMAGE", "state": "NON_COMPLIANT"})
    return uri


def _ecr_fixtures(aws: AwsCli, directory: Path) -> dict[str, Any]:
    """Push the two new npm manifests while reusing retained Python fixtures."""

    _repo_uri(aws)
    pushed = []
    for version, fixture in ((NPM_BAD_VERSION, "npm-vulnerable"), (NPM_CLEAN_VERSION, "npm-clean")):
        tag = _ecr_fixture_tag(fixture)
        manifest_file = _push_image(aws, directory, version, tag, ecosystem="npm")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        pushed.append({
            "fixture": fixture,
            "tag": tag,
            "ecosystem": "JAVASCRIPT_NPM",
            "version": version,
            "config_digest": manifest["config"]["digest"],
            "layer_digest": manifest["layers"][0]["digest"],
            "state": "PUSHED",
        })
    _write_json(directory, "ecr-fixtures-pushed.json", {"fixtures": pushed})
    return {"status": "READY", "reason_code": "SECCOP_ECR_FIXTURES_PUSHED", "fixtures": pushed}


def _target_instance(aws: AwsCli) -> tuple[str, dict[str, Any]]:
    response = aws.json(
        "ec2",
        "describe-instances",
        "--filters",
        f"Name=tag:Name,Values={aws.config.target_name}",
        "Name=instance-state-name,Values=running",
    )
    matches: list[dict[str, Any]] = []
    for reservation in response.get("Reservations", []):
        if not isinstance(reservation, dict):
            continue
        for instance in reservation.get("Instances", []):
            if isinstance(instance, dict):
                matches.append(instance)
    if len(matches) != 1:
        raise DemoError("SecCop could not select exactly one running EC2 DEMO target.")
    instance_id = matches[0].get("InstanceId")
    if not isinstance(instance_id, str):
        raise DemoError("The EC2 DEMO target did not have an instance ID.")
    return instance_id, matches[0]


def _scan_ec2(aws: AwsCli) -> dict[str, Any]:
    instance_id, _ = _target_instance(aws)
    response = aws.json("ssm", "describe-instance-patch-states", "--instance-ids", instance_id)
    states = response.get("InstancePatchStates")
    if not isinstance(states, list) or len(states) != 1 or not isinstance(states[0], dict):
        raise DemoError("SSM has no usable patch summary for the EC2 DEMO target.")
    state = states[0]
    missing = state.get("MissingCount")
    security = state.get("SecurityNonCompliantCount")
    if not isinstance(missing, int) or not isinstance(security, int):
        raise DemoError("SSM returned an invalid patch summary.")
    compliant = missing == 0 and security == 0
    return {
        "source": "EC2_PACKAGE",
        "alias": "LAB_SERVER_01",
        "state": "COMPLIANT" if compliant else "NON_COMPLIANT",
        "reason_code": "SECCOP_EC2_COMPLIANT" if compliant else "SECCOP_EC2_NON_COMPLIANT",
        "missing_patches": missing,
        "security_non_compliant": security,
    }


def _run_trivy(args: list[str], *, input_text: str | None = None) -> dict[str, Any]:
    try:
        result = subprocess.run(args, input=input_text, capture_output=True, text=True, check=False)
    except OSError as error:
        raise DemoError("Trivy is not installed or could not be started.") from error
    if result.returncode != 0:
        raise DemoError("The artifact/image scan could not be completed.")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise DemoError("Trivy returned invalid JSON.") from error
    if not isinstance(value, dict):
        raise DemoError("Trivy returned an invalid result.")
    return value


def _vulnerability_count(result: dict[str, Any]) -> int:
    count = 0
    for item in result.get("Results", []):
        if isinstance(item, dict) and isinstance(item.get("Vulnerabilities"), list):
            count += len(item["Vulnerabilities"])
    return count


def _scan_s3(aws: AwsCli, directory: Path) -> dict[str, Any]:
    current, _ = _bucket_names(aws)
    # Keep the lock-file name so Trivy applies its Python dependency parser.
    downloaded = directory / "requirements.txt"
    aws.run("s3", "cp", f"s3://{current}/demo/requirements.txt", str(downloaded))
    result = _run_trivy(["trivy", "fs", "--quiet", "--format", "json", str(downloaded.parent)])
    vulnerabilities = _vulnerability_count(result)
    return {
        "source": "S3_ARTIFACT",
        "alias": "ARTIFACT_01",
        "state": "NON_COMPLIANT" if vulnerabilities else "COMPLIANT",
        "reason_code": "SECCOP_S3_NON_COMPLIANT" if vulnerabilities else "SECCOP_S3_COMPLIANT",
        "vulnerabilities": vulnerabilities,
    }


def _scan_ecr(aws: AwsCli, directory: Path, uri: str) -> dict[str, Any]:
    password = aws.run("ecr", "get-login-password")
    result = _run_trivy(
        [
            "trivy",
            "image",
            "--quiet",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--image-src",
            "remote",
            "--username",
            "AWS",
            "--password-stdin",
            f"{uri}:demo-current",
        ],
        input_text=password,
    )
    vulnerabilities = _vulnerability_count(result)
    return {
        "source": "ECR_IMAGE",
        "alias": "IMAGE_01",
        "state": "NON_COMPLIANT" if vulnerabilities else "COMPLIANT",
        "reason_code": "SECCOP_ECR_NON_COMPLIANT" if vulnerabilities else "SECCOP_ECR_COMPLIANT",
        "storage_provider": "AWS_ECR",
        "scanner_provider": "LOCAL_TRIVY",
        "vulnerabilities": vulnerabilities,
    }


def _ecr_public_result(cve_id: str, state: str, reason_code: str, **fields: Any) -> dict[str, Any]:
    return {
        "source": "ECR_IMAGE",
        "alias": "ECR_IMAGE_01",
        "state": state,
        "reason_code": reason_code,
        "storage_provider": "AWS_ECR",
        "scanner_provider": "AMAZON_INSPECTOR",
        "scanner_mode": "ECR_ENHANCED_SCANNING",
        "cve_id": cve_id,
        **fields,
    }


def _ecr_fixture_tag(fixture: str) -> str:
    try:
        return ECR_FIXTURE_TAGS[fixture]
    except KeyError as error:
        raise DemoError("The ECR fixture selector is invalid.") from error


def _ecr_fixture_spec(fixture: str) -> dict[str, str]:
    try:
        return ECR_FIXTURE_SPECS[fixture]
    except KeyError as error:
        raise DemoError("The ECR fixture selector is invalid.") from error


def _scan_ecr_inspector(aws: AwsCli, *, tag: str = "demo-current", cve_id: str = BAD_CVE) -> dict[str, Any]:
    """Read one ECR tag and its exact Inspector evidence without mutation."""

    if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve_id):
        return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_CVE_INVALID")
    try:
        image_response = aws.json(
            "ecr",
            "describe-images",
            "--repository-name",
            ECR_REPOSITORY,
            "--image-ids",
            f"imageTag={tag}",
        )
        details = image_response.get("imageDetails")
        matches = [
            item for item in details
            if isinstance(item, dict) and tag in (item.get("imageTags") or [])
        ] if isinstance(details, list) else []
        if len(matches) != 1:
            return _ecr_public_result(
                cve_id,
                "BLOCKED",
                "SECCOP_ECR_TAG_AMBIGUOUS" if len(matches) > 1 else "SECCOP_ECR_TAG_NOT_FOUND",
            )
        digest = matches[0].get("imageDigest")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_DIGEST_INVALID")

        account = aws.json("inspector2", "batch-get-account-status")
        accounts = account.get("accounts")
        ecr_state = accounts[0].get("resourceState", {}).get("ecr", {}).get("status") if isinstance(accounts, list) and len(accounts) == 1 and isinstance(accounts[0], dict) else None
        if ecr_state != "ENABLED":
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_INSPECTOR_DISABLED")

        coverage_filter = json.dumps(
            {
                "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}],
                "ecrRepositoryName": [{"comparison": "EQUALS", "value": ECR_REPOSITORY}],
                "ecrImageTags": [{"comparison": "EQUALS", "value": tag}],
            },
            separators=(",", ":"),
        )
        coverage_response = aws.json("inspector2", "list-coverage", "--filter-criteria", coverage_filter, "--max-results", "100")
        covered = coverage_response.get("coveredResources")
        if not isinstance(covered, list):
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_COVERAGE_INVALID")
        if not covered:
            repository_filter = json.dumps(
                {
                    "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}],
                    "ecrRepositoryName": [{"comparison": "EQUALS", "value": ECR_REPOSITORY}],
                },
                separators=(",", ":"),
            )
            coverage_response = aws.json("inspector2", "list-coverage", "--filter-criteria", repository_filter, "--max-results", "100")
            covered = coverage_response.get("coveredResources")
            if not isinstance(covered, list):
                return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_COVERAGE_INVALID")
        coverage_matches = [item for item in covered if isinstance(item, dict) and digest in str(item.get("resourceId", ""))]
        if len(coverage_matches) != 1:
            return _ecr_public_result(
                cve_id,
                "BLOCKED",
                "SECCOP_ECR_COVERAGE_AMBIGUOUS" if len(coverage_matches) > 1 else "SECCOP_ECR_COVERAGE_MISMATCH",
            )
        coverage = coverage_matches[0]
        if coverage.get("scanType") != "PACKAGE":
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_COVERAGE_UNSUPPORTED")
        scan_status = coverage.get("scanStatus")
        status_code = scan_status.get("statusCode") if isinstance(scan_status, dict) else None
        status_reason = scan_status.get("reason") if isinstance(scan_status, dict) else None
        if status_code == "ACTIVE" and status_reason in {"PENDING_INITIAL_SCAN", "SCAN_IN_PROGRESS"}:
            return _ecr_public_result(cve_id, "PENDING_RESCAN", "SECCOP_ECR_SCAN_PENDING")
        if not (
            status_code == "INACTIVE" and status_reason == "SCAN_FREQUENCY_SCAN_ON_PUSH"
            or status_code == "ACTIVE" and status_reason == "SUCCESSFUL"
        ):
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_SCAN_NOT_READY")

        finding_filter = json.dumps(
            {
                "ecrImageHash": [{"comparison": "EQUALS", "value": digest}],
                "ecrImageRepositoryName": [{"comparison": "EQUALS", "value": ECR_REPOSITORY}],
                "vulnerabilityId": [{"comparison": "EQUALS", "value": cve_id}],
            },
            separators=(",", ":"),
        )
        finding_args = ["inspector2", "list-findings", "--filter-criteria", finding_filter, "--max-results", "100"]
        findings: list[Any] = []
        seen_tokens: set[str] = set()
        for _ in range(10):
            finding_response = aws.json(*finding_args)
            page = finding_response.get("findings")
            if not isinstance(page, list):
                return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_FINDINGS_AMBIGUOUS")
            findings.extend(page)
            token = finding_response.get("nextToken")
            if not token:
                break
            if not isinstance(token, str) or token in seen_tokens:
                return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_FINDINGS_AMBIGUOUS")
            seen_tokens.add(token)
            finding_args = [*finding_args, "--next-token", token]
        else:
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_FINDINGS_AMBIGUOUS")
        active = [item for item in findings if isinstance(item, dict) and item.get("status") == "ACTIVE"]
        if len(active) > 1:
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_FINDINGS_AMBIGUOUS")
        if not active:
            return _ecr_public_result(cve_id, "COMPLIANT", "SECCOP_ECR_INSPECTOR_CVE_ABSENT")
        finding = active[0]
        resources = finding.get("resources")
        resource_matches = []
        for resource in resources if isinstance(resources, list) else []:
            if not isinstance(resource, dict) or resource.get("type") != "AWS_ECR_CONTAINER_IMAGE":
                continue
            image = resource.get("details", {}).get("awsEcrContainerImage", {})
            if image.get("repositoryName") == ECR_REPOSITORY and image.get("imageHash") == digest:
                resource_matches.append(resource)
        if len(resource_matches) != 1:
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_FINDING_RESOURCE_MISMATCH")
        details = finding.get("packageVulnerabilityDetails")
        packages = details.get("vulnerablePackages") if isinstance(details, dict) else None
        package = packages[0] if isinstance(packages, list) and packages and isinstance(packages[0], dict) else None
        name = package.get("name") if isinstance(package, dict) else None
        version = package.get("version") if isinstance(package, dict) else None
        severity = finding.get("severity")
        if finding.get("type") != "PACKAGE_VULNERABILITY" or finding.get("packageVulnerabilityDetails", {}).get("vulnerabilityId") != cve_id:
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_FINDING_MISMATCH")
        if not isinstance(name, str) or not isinstance(version, str) or not isinstance(severity, str):
            return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_FINDING_INVALID")
        return _ecr_public_result(
            cve_id,
            "NON_COMPLIANT",
            "SECCOP_ECR_INSPECTOR_FINDING",
            package_name=name,
            installed_version=version,
            severity=severity,
        )
    except (DemoError, TypeError, AttributeError, KeyError, IndexError):
        return _ecr_public_result(cve_id, "BLOCKED", "SECCOP_ECR_READ_FAILED")


def _scan(aws: AwsCli, directory: Path, *, ecr_scanner: str = "trivy", ecr_fixture: str = "current") -> dict[str, Any]:
    if ecr_scanner == "inspector":
        try:
            fixture = _ecr_fixture_spec(ecr_fixture)
        except DemoError:
            fixture = None
        sources = [_scan_ec2(aws), _scan_s3(aws, directory), _scan_ecr_inspector(aws, tag=fixture["tag"], cve_id=fixture["cve_id"])] if fixture else [_scan_ec2(aws), _scan_s3(aws, directory), _ecr_public_result(BAD_CVE, "BLOCKED", "SECCOP_ECR_FIXTURE_INVALID")]
        if fixture:
            sources[-1]["package_ecosystem"] = fixture["ecosystem"]
    else:
        uri = _repo_uri(aws)
        sources = [_scan_ec2(aws), _scan_s3(aws, directory), _scan_ecr(aws, directory, uri)]
    _write_json(directory, "scan.json", {"sources": sources})
    source_status = [
        {
            "source_type": source["source"],
            "label": {
                "EC2_PACKAGE": "Server packages",
                "S3_ARTIFACT": "Stored artifact",
                "ECR_IMAGE": "Container image",
            }[source["source"]],
            "state": "PENDING_RESCAN" if source["state"] == "PENDING_RESCAN" else "BLOCKED" if source["state"] == "BLOCKED" else "COMPLETE",
            "reason_code": source.get("reason_code", "SECCOP_SOURCE_READY") if source["source"] == "ECR_IMAGE" and ecr_scanner == "inspector" else "SECCOP_SOURCE_READY",
        }
        for source in sources
    ]
    findings = []
    for index, source in enumerate(sources, start=1):
        if source["state"] in {"COMPLIANT", "PENDING_RESCAN", "BLOCKED"}:
            continue
        if source["source"] == "EC2_PACKAGE":
            reference = "CVE-2099-0001"
            title = "Old server package"
            problem = "The demo server still has security patches waiting to be installed."
            observed = f"{source['security_non_compliant']} security updates are missing."
            recommended = "Review the live package check, approve one exact update, then scan again."
        elif source["source"] == "S3_ARTIFACT":
            reference = BAD_CVE
            title = "Non-compliant stored artifact"
            problem = "The stored requirements file contains an old library with a known CVE."
            observed = f"Trivy found {source['vulnerabilities']} vulnerabilities."
            recommended = "Approve replacement with the clean, validated requirements file."
        elif source.get("scanner_provider") == "AMAZON_INSPECTOR":
            reference = source["cve_id"]
            title = "Inspector ECR finding"
            problem = "Amazon Inspector reported the target CVE for this exact ECR image digest."
            observed = f"Inspector reported {source['package_name']} {source['installed_version']} at {source['severity']} severity."
            recommended = "Review the exact clean-digest recommendation; no mutation is performed by this scan."
        else:
            reference = BAD_CVE
            title = "Non-compliant container image"
            problem = "The image contains an old library with a known CVE."
            observed = f"Trivy found {source['vulnerabilities']} vulnerabilities."
            recommended = "Approve promotion of the clean, validated image digest."
        findings.append(
            {
                "finding_id": f"FINDING_{index:02d}",
                "source_type": source["source"],
                "resource_alias": source["alias"],
                "reference": reference,
                "severity": source.get("severity", "HIGH"),
                "title": title,
                "problem_summary": problem,
                "observed_state": observed,
                "recommended_state": recommended,
                "remediation_mode": "REAL_APPROVAL_REQUIRED",
                "reason_code": "SECCOP_EC2_FINDING_CONFIRMED"
                if source["source"] == "EC2_PACKAGE"
                else "SECCOP_S3_FINDING_CONFIRMED"
                if source["source"] == "S3_ARTIFACT"
                else "SECCOP_ECR_FINDING_CONFIRMED",
                "action_label": "Review live fix" if source["source"] == "EC2_PACKAGE" else "Review and fix",
            }
        )
    overall_state = "BLOCKED" if any(source["state"] == "BLOCKED" for source in sources) else "PENDING_RESCAN" if any(source["state"] == "PENDING_RESCAN" for source in sources) else "READY"
    return {
        "status": overall_state,
        "reason_code": "SECCOP_ECR_EVIDENCE_BLOCKED" if overall_state == "BLOCKED" else "SECCOP_ECR_SCAN_PENDING" if overall_state == "PENDING_RESCAN" else "SECCOP_SCAN_READY",
        "scan_id": "SECCOP_SCAN_01",
        "source_status": source_status,
        "findings": findings,
        "sources": sources,
        "message": (
            "The three DEMO sources were checked."
            if findings or overall_state != "READY"
            else "The three DEMO sources are compliant."
        ),
    }


def _fix(aws: AwsCli, source: str, directory: Path) -> dict[str, Any]:
    if source == "ec2":
        raise DemoError("Use the SecCop live approval screen for the EC2 package fix.")
    if source == "s3":
        current, reset = _bucket_names(aws)
        aws.run(
            "s3api",
            "copy-object",
            "--bucket",
            current,
            "--key",
            "demo/requirements.txt",
            "--copy-source",
            f"{reset}/baseline/clean/requirements.txt",
        )
        return {"source": "S3_ARTIFACT", "alias": "ARTIFACT_01", "state": "FIXED", "reason_code": "SECCOP_S3_FIX_APPLIED"}
    if source == "ecr":
        images = aws.json(
            "ecr",
            "batch-get-image",
            "--repository-name",
            ECR_REPOSITORY,
            "--image-ids",
            "imageTag=demo-clean",
            "--accepted-media-types",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        items = images.get("images")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            raise DemoError("The clean ECR image was not available.")
        manifest = items[0].get("imageManifest")
        if not isinstance(manifest, str):
            raise DemoError("The clean ECR image manifest was invalid.")
        manifest_file = _write_json(directory, "clean-image-manifest.json", json.loads(manifest))
        aws.run(
            "ecr",
            "put-image",
            "--repository-name",
            ECR_REPOSITORY,
            "--image-tag",
            "demo-current",
            "--image-manifest",
            f"file://{manifest_file}",
        )
        return {"source": "ECR_IMAGE", "alias": "IMAGE_01", "state": "FIXED", "reason_code": "SECCOP_ECR_FIX_APPLIED"}
    raise DemoError("Choose one source: ec2, s3, or ecr.")


def _ecr_scan(aws: AwsCli, directory: Path, *, ecr_scanner: str = "trivy", ecr_fixture: str = "current") -> dict[str, Any]:
    if ecr_scanner == "inspector":
        try:
            fixture = _ecr_fixture_spec(ecr_fixture)
            source = _scan_ecr_inspector(aws, tag=fixture["tag"], cve_id=fixture["cve_id"])
            source["package_ecosystem"] = fixture["ecosystem"]
        except DemoError:
            source = _ecr_public_result(BAD_CVE, "BLOCKED", "SECCOP_ECR_FIXTURE_INVALID")
        state = source["state"]
        if state == "NON_COMPLIANT":
            finding = {
                "finding_id": "ECR_IMAGE_01", "source_type": "ECR_IMAGE", "resource_alias": source["alias"],
                "cve_id": source["cve_id"], "reference": source["cve_id"], "severity": source["severity"],
                "scanner_provider": source["scanner_provider"], "scanner_mode": source["scanner_mode"],
                "package_name": source["package_name"], "installed_version": source["installed_version"],
                "title": "Inspector ECR finding", "problem_summary": "Amazon Inspector reported the target CVE for this exact ECR image.",
                "observed_state": f"Amazon Inspector reported {source['package_name']} {source['installed_version']} at {source['severity']} severity.",
                "recommended_state": "Review the exact clean-digest recommendation; no mutation is performed by this scan.",
                "remediation_mode": "REAL_APPROVAL_REQUIRED", "reason_code": "SECCOP_ECR_FINDING_CONFIRMED", "action_label": "Review ECR finding",
            }
        else:
            finding = None
        result: dict[str, Any] = {
            "status": "READY" if state == "NON_COMPLIANT" else "NO_FINDINGS" if state == "COMPLIANT" else state,
            "reason_code": "SECCOP_ECR_NON_COMPLIANT" if state == "NON_COMPLIANT" else "SECCOP_ECR_COMPLIANT" if state == "COMPLIANT" else "SECCOP_ECR_SCAN_PENDING" if state == "PENDING_RESCAN" else "SECCOP_ECR_EVIDENCE_BLOCKED",
            "state": state,
            "scanner_provider": source["scanner_provider"],
            "scanner_mode": source["scanner_mode"],
            "cve_id": source["cve_id"],
            "package_ecosystem": source.get("package_ecosystem", "UNKNOWN"),
            "source_status": [{"source_type": "ECR_IMAGE", "label": "ECR image scanned by Amazon Inspector", "state": "COMPLETE" if state in {"NON_COMPLIANT", "COMPLIANT"} else state, "reason_code": source["reason_code"]}],
            "findings": [finding] if finding else [],
            "message": "SecCop found a known ECR finding from Amazon Inspector; human approval is required before any promotion." if state == "NON_COMPLIANT" else "SecCop verified the ECR demo-current image is clean with Amazon Inspector." if state == "COMPLIANT" else "SecCop could not claim a current ECR Inspector result; rescan is required." if state == "PENDING_RESCAN" else "SecCop blocked the ECR Inspector evidence because the read-only proof was not usable.",
        }
        for field in ("package_name", "installed_version", "severity"):
            if field in source:
                result[field] = source[field]
        if "package_ecosystem" in source:
            result["package_ecosystem"] = source["package_ecosystem"]
        return result

    source = _scan_ecr(aws, directory, _repo_uri(aws))
    vulnerable = source["state"] == "NON_COMPLIANT"
    return {
        "status": "READY" if vulnerable else "NO_FINDINGS",
        "reason_code": "SECCOP_ECR_NON_COMPLIANT" if vulnerable else "SECCOP_ECR_COMPLIANT",
        "source_status": [{"source_type": "ECR_IMAGE", "label": "ECR image scanned by local Trivy", "state": "COMPLETE", "reason_code": "SECCOP_ECR_TRIVY_READ"}],
        "findings": [] if not vulnerable else [{
            "finding_id": "ECR_IMAGE_01", "source_type": "ECR_IMAGE", "resource_alias": "ECR_IMAGE_01",
            "cve_id": BAD_CVE, "reference": BAD_CVE, "severity": "HIGH",
            "title": "Known-vulnerable ECR image", "problem_summary": "The current demo image contains the known vulnerable library.",
            "observed_state": f"Local Trivy found {source['vulnerabilities']} vulnerabilities.",
            "recommended_state": "Promote the clean validated image digest to demo-current.",
            "remediation_mode": "REAL_APPROVAL_REQUIRED", "reason_code": "SECCOP_ECR_FINDING_CONFIRMED", "action_label": "Review ECR promotion",
        }],
        "message": "SecCop found a known-vulnerable ECR image. Human approval is required before promotion." if vulnerable else "SecCop verified the ECR demo-current image is clean.",
    }


def _ecr_scan_selected(aws: AwsCli, directory: Path, ecr_scanner: str, ecr_fixture: str = "current") -> dict[str, Any]:
    """Select the provider while retaining the legacy Trivy call shape."""

    return _ecr_scan(aws, directory) if ecr_scanner == "trivy" else _ecr_scan(aws, directory, ecr_scanner=ecr_scanner, ecr_fixture=ecr_fixture)


def _ecr_start(aws: AwsCli, directory: Path, *, ecr_scanner: str = "trivy", ecr_fixture: str = "current") -> dict[str, Any]:
    _ensure_ecr(aws, directory)
    result = _ecr_scan_selected(aws, directory, ecr_scanner, ecr_fixture)
    if result["reason_code"] != "SECCOP_ECR_NON_COMPLIANT":
        raise DemoError("The ECR baseline did not produce the approved finding.")
    return result


def _ecr_fix(aws: AwsCli, directory: Path, *, ecr_scanner: str = "trivy", ecr_fixture: str = "current") -> dict[str, Any]:
    _fix(aws, "ecr", directory)
    result = _ecr_scan_selected(aws, directory, ecr_scanner, ecr_fixture)
    if result["reason_code"] != "SECCOP_ECR_COMPLIANT":
        raise DemoError("The ECR clean digest verification failed.")
    provider = "Amazon Inspector" if ecr_scanner == "inspector" else "local Trivy"
    return {"status": "VERIFIED", "reason_code": "SECCOP_ECR_PROMOTION_VERIFIED", "state": "COMPLIANT", "message": f"SecCop promoted the clean ECR digest and verified the result with {provider}."}


def _ecr_reset(aws: AwsCli, directory: Path, *, ecr_scanner: str = "trivy", ecr_fixture: str = "current") -> dict[str, Any]:
    before = _ecr_scan_selected(aws, directory, ecr_scanner, ecr_fixture)
    if before["reason_code"] == "SECCOP_ECR_NON_COMPLIANT":
        return {"status": "READY", "reason_code": "SECCOP_ECR_REOPEN_READY", "message": "The ECR finding is already action required."}
    _push_image(aws, directory, BAD_VERSION, "demo-current")
    after = _ecr_scan_selected(aws, directory, ecr_scanner, ecr_fixture)
    if after["reason_code"] != "SECCOP_ECR_NON_COMPLIANT":
        raise DemoError("The ECR reopen verification failed.")
    provider = "Amazon Inspector" if ecr_scanner == "inspector" else "local Trivy"
    return {"status": "READY", "reason_code": "SECCOP_ECR_REOPEN_READY", "message": f"The ECR finding was reopened and reread with {provider}."}


def _tag_map(tags: Any) -> dict[str, str]:
    if not isinstance(tags, list):
        return {}
    return {
        str(item["Key"]): str(item["Value"])
        for item in tags
        if isinstance(item, dict) and isinstance(item.get("Key"), str) and isinstance(item.get("Value"), str)
    }


def _bucket_cleanup_state(aws: AwsCli, bucket: str) -> bool:
    try:
        aws.run("s3api", "head-bucket", "--bucket", bucket)
    except DemoError as error:
        if "404" in str(error) or "Not Found" in str(error):
            return False
        raise DemoError("The DEMO bucket could not be checked safely.") from error
    try:
        response = aws.json("s3api", "get-bucket-tagging", "--bucket", bucket)
    except DemoError as error:
        raise DemoError("The DEMO bucket tags could not be checked safely.") from error
    tags = _tag_map(response.get("TagSet"))
    if tags.get("Project") != "Security Copilot" or tags.get("Cleanup") != "seccop-demo-only":
        raise DemoError("A DEMO bucket did not have the expected ownership tags.")
    return True


def _delete_bucket(aws: AwsCli, bucket: str) -> dict[str, Any]:
    if not _bucket_cleanup_state(aws, bucket):
        return {"bucket": bucket, "state": "ABSENT", "reason_code": "SECCOP_S3_ALREADY_CLEAN"}
    versions = aws.json("s3api", "list-object-versions", "--bucket", bucket)
    if versions.get("IsTruncated") is True:
        raise DemoError("The DEMO bucket contains too many versions for one safe cleanup pass.")
    objects: list[dict[str, str]] = []
    for field in ("Versions", "DeleteMarkers"):
        entries = versions.get(field, [])
        if not isinstance(entries, list):
            raise DemoError("The DEMO bucket returned an invalid version list.")
        for item in entries:
            if not isinstance(item, dict) or not isinstance(item.get("Key"), str) or not isinstance(item.get("VersionId"), str):
                raise DemoError("The DEMO bucket returned an invalid object version.")
            objects.append({"Key": item["Key"], "VersionId": item["VersionId"]})
    if objects:
        payload = _write_json(aws.config.evidence_root, f"delete-{bucket}.json", {"Objects": objects, "Quiet": True})
        aws.run("s3api", "delete-objects", "--bucket", bucket, "--delete", f"file://{payload}")
    aws.run("s3api", "delete-bucket", "--bucket", bucket)
    try:
        aws.run("s3api", "head-bucket", "--bucket", bucket)
    except DemoError as error:
        if "404" in str(error) or "Not Found" in str(error):
            return {"bucket": bucket, "state": "DELETED", "reason_code": "SECCOP_S3_DELETED"}
        raise DemoError("The DEMO bucket deletion could not be verified safely.") from error
    raise DemoError("The DEMO bucket still exists after cleanup.")


def _repository_cleanup_state(aws: AwsCli) -> tuple[bool, str | None]:
    try:
        response = aws.json("ecr", "describe-repositories", "--repository-names", ECR_REPOSITORY)
    except DemoError as error:
        if "RepositoryNotFoundException" in str(error):
            return False, None
        raise DemoError("The DEMO ECR repository could not be checked safely.") from error
    items = response.get("repositories")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise DemoError("The DEMO ECR repository returned an invalid description.")
    arn = items[0].get("repositoryArn")
    if not isinstance(arn, str) or not arn:
        raise DemoError("The DEMO ECR repository did not return an ownership ARN.")
    tags = _tag_map(aws.json("ecr", "list-tags-for-resource", "--resource-arn", arn).get("tags"))
    if tags.get("Project") != "Security Copilot" or tags.get("Cleanup") != "seccop-demo-only":
        raise DemoError("The DEMO ECR repository did not have the expected ownership tags.")
    return True, arn


def _cleanup(aws: AwsCli, directory: Path) -> dict[str, Any]:
    """Delete only the tag-owned S3/ECR DEMO artifacts after preflight."""

    current, reset = _bucket_names(aws)
    current_exists = _bucket_cleanup_state(aws, current)
    reset_exists = _bucket_cleanup_state(aws, reset)
    repository_exists, _ = _repository_cleanup_state(aws)
    artifacts: list[dict[str, Any]] = []
    if current_exists:
        artifacts.append(_delete_bucket(aws, current))
    if reset_exists:
        artifacts.append(_delete_bucket(aws, reset))
    if repository_exists:
        aws.run("ecr", "delete-repository", "--repository-name", ECR_REPOSITORY, "--force")
        try:
            aws.json("ecr", "describe-repositories", "--repository-names", ECR_REPOSITORY)
        except DemoError as error:
            if "RepositoryNotFoundException" in str(error):
                artifacts.append({"repository": ECR_REPOSITORY, "state": "DELETED", "reason_code": "SECCOP_ECR_DELETED"})
            else:
                raise DemoError("The DEMO ECR deletion could not be verified safely.") from error
        else:
            raise DemoError("The DEMO ECR repository still exists after cleanup.")
    if not artifacts:
        artifacts = [{"state": "ABSENT", "reason_code": "SECCOP_ARTIFACTS_ALREADY_CLEAN"}]
    return {"status": "CLEANED", "reason_code": "SECCOP_ARTIFACTS_CLEANED", "artifacts": artifacts}


def _start(aws: AwsCli, directory: Path) -> dict[str, Any]:
    # Do the non-mutating EC2 gate first.  Never downgrade a clean host just
    # to make a presentation finding appear.
    ec2 = _scan_ec2(aws)
    if ec2["state"] == "COMPLIANT":
        raise DemoError("The EC2 DEMO target is already compliant; restore the pinned old AMI with separate approval.")
    _seed_s3(aws, directory)
    _ensure_ecr(aws, directory)
    return {
        "status": "READY",
        "sources": [
            {"source": "EC2_PACKAGE", "alias": "LAB_SERVER_01", "state": ec2["state"], "reason_code": ec2["reason_code"]},
            {"source": "S3_ARTIFACT", "alias": "ARTIFACT_01", "state": "NON_COMPLIANT", "reason_code": "SECCOP_S3_BASELINE_READY"},
            {"source": "ECR_IMAGE", "alias": "IMAGE_01", "state": "NON_COMPLIANT", "reason_code": "SECCOP_ECR_BASELINE_READY"},
        ],
        "message": "The S3 and ECR DEMO baselines are ready; the existing EC2 target was checked.",
    }


def _verify(aws: AwsCli, directory: Path) -> dict[str, Any]:
    """Run one bounded live scan/fix/rescan rehearsal and restore the baseline."""

    _start(aws, directory)
    try:
        before = _scan(aws, directory)
        states_before = {item["alias"]: item["state"] for item in before["sources"]}
        if any(state != "NON_COMPLIANT" for state in states_before.values()):
            raise DemoError("The DEMO baseline did not contain three non-compliant sources.")
        s3_fix = _fix(aws, "s3", directory)
        ecr_fix = _fix(aws, "ecr", directory)
        after = _scan(aws, directory)
        states_after = {item["alias"]: item["state"] for item in after["sources"]}
        if states_after.get("ARTIFACT_01") != "COMPLIANT" or states_after.get("IMAGE_01") != "COMPLIANT":
            raise DemoError("The approved S3/ECR fixes did not produce a clean rescan.")
        return {
            "status": "PARTIAL",
            "reason_code": "SECCOP_VERIFY_EC2_APPROVAL_PENDING",
            "before": states_before,
            "fixes": [s3_fix, ecr_fix],
            "after": states_after,
            "message": "S3 and ECR verified clean; the EC2 package still needs the existing human approval path.",
        }
    finally:
        _start(aws, directory)


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare and verify the SecCop three-source DEMO.")
    parser.add_argument("command", choices=("start", "scan", "rescan", "fix", "status", "verify", "cleanup", "ecr-start", "ecr-scan", "ecr-fix", "ecr-reset", "ecr-fixtures"))
    parser.add_argument("--source", choices=("ec2", "s3", "ecr"))
    parser.add_argument("--profile", default=os.environ.get("SECCOP_PROFILE", "vagent"))
    parser.add_argument("--region", default=os.environ.get("SECCOP_REGION", "ap-southeast-1"))
    parser.add_argument("--target-name", default=os.environ.get("SECCOP_TARGET_NAME", DEFAULT_TARGET_NAME))
    parser.add_argument(
        "--ecr-scanner",
        choices=("trivy", "inspector"),
        default=os.environ.get("SECCOP_ECR_SCANNER", "trivy"),
        help="select the ECR evidence provider for scan/rescan/status",
    )
    parser.add_argument(
        "--ecr-fixture",
        choices=tuple(ECR_FIXTURE_TAGS),
        default=os.environ.get("SECCOP_ECR_FIXTURE", "current"),
        help="select the retained ECR fixture alias for Inspector reads",
    )
    parser.add_argument("--confirm", action="store_true", help="allow the requested DEMO preparation/fix")
    args = parser.parse_args()
    if args.command in {"start", "fix", "verify", "cleanup", "ecr-start", "ecr-fix", "ecr-reset", "ecr-fixtures"} and not args.confirm:
        print(json.dumps({"status": "BLOCKED", "reason_code": "CONFIRM_REQUIRED", "message": "Use --confirm for DEMO preparation, cleanup, or a fix."}))
        return 2
    root = Path.home() / ".AGENTS-temp" / "agentic-ai-cybersecurity-lab" / "seccop-demo"
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="run-", dir=root) as run_dir:
        config = Config(args.profile, args.region, args.target_name, Path(run_dir))
        aws = AwsCli(config)
        try:
            aws.run("sts", "get-caller-identity")
            if args.command == "ecr-start":
                result = _ecr_start(aws, Path(run_dir), ecr_scanner=args.ecr_scanner, ecr_fixture=args.ecr_fixture)
            elif args.command == "ecr-fixtures":
                result = _ecr_fixtures(aws, Path(run_dir))
            elif args.command == "ecr-scan":
                result = _ecr_scan(aws, Path(run_dir), ecr_scanner=args.ecr_scanner, ecr_fixture=args.ecr_fixture)
            elif args.command == "ecr-fix":
                result = _ecr_fix(aws, Path(run_dir), ecr_scanner=args.ecr_scanner, ecr_fixture=args.ecr_fixture)
            elif args.command == "ecr-reset":
                result = _ecr_reset(aws, Path(run_dir), ecr_scanner=args.ecr_scanner, ecr_fixture=args.ecr_fixture)
            elif args.command == "start":
                result = _start(aws, Path(run_dir))
            elif args.command == "cleanup":
                result = _cleanup(aws, Path(run_dir))
            elif args.command == "verify":
                result = _verify(aws, Path(run_dir))
            elif args.command in {"scan", "rescan", "status"}:
                result = _scan(aws, Path(run_dir), ecr_scanner=args.ecr_scanner, ecr_fixture=args.ecr_fixture)
            else:
                if args.source is None:
                    raise DemoError("--source is required for fix.")
                result = _fix(aws, args.source, Path(run_dir))
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except DemoError as error:
            print(json.dumps({"status": "BLOCKED", "reason_code": "SECCOP_DEMO_BLOCKED", "message": "The bounded SecCop DEMO operation was blocked."}))
            return 1


if __name__ == "__main__":
    sys.exit(main())
