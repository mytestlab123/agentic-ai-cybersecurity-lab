#!/usr/bin/env python3
"""Export exact-target AWS Inspector package findings for SecCop."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_agent_harness.seccop_csv import SecCopCsvRow, write_csv


class BackendFailure(RuntimeError):
    """Generic AWS failure; service text never enters stdout or the CSV."""


def aws_call(profile: str, region: str, payload: dict[str, Any]) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
        json.dump(payload, handle)
        handle.flush()
        completed = subprocess.run(
            [
                "aws",
                "--profile",
                profile,
                "--region",
                region,
                "inspector2",
                "list-findings",
                "--cli-input-json",
                f"file://{handle.name}",
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    if completed.returncode != 0:
        raise BackendFailure("Inspector export failed.")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BackendFailure("Inspector returned invalid data.") from exc
    if not isinstance(value, dict):
        raise BackendFailure("Inspector returned an invalid object.")
    return value


def _safe(value: Any, pattern: str) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        return None
    return value


def export_rows(profile: str, region: str, instance_id: str) -> list[SecCopCsvRow]:
    request: dict[str, Any] = {
        "filterCriteria": {
            "resourceId": [{"comparison": "EQUALS", "value": instance_id}],
            "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
        },
        "maxResults": 100,
    }
    findings: list[dict[str, Any]] = []
    for _ in range(20):
        response = aws_call(profile, region, request)
        page = response.get("findings")
        if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
            raise BackendFailure("Inspector returned an invalid findings page.")
        findings.extend(page)
        token = response.get("nextToken")
        if not token:
            break
        request["nextToken"] = token
    else:
        raise BackendFailure("Inspector pagination did not terminate.")

    rows: list[SecCopCsvRow] = []
    for finding in findings:
        resources = finding.get("resources")
        if not isinstance(resources, list) or not any(
            isinstance(resource, dict)
            and resource.get("type") == "AWS_EC2_INSTANCE"
            and resource.get("id") == instance_id
            for resource in resources
        ):
            continue
        details = finding.get("packageVulnerabilityDetails")
        if not isinstance(details, dict):
            continue
        cve_id = _safe(details.get("vulnerabilityId"), r"CVE-[0-9]{4}-[0-9]{4,}")
        severity = _safe(str(finding.get("severity", "")).upper(), r"(INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)")
        packages = details.get("vulnerablePackages")
        if not cve_id or not severity or not isinstance(packages, list):
            continue
        for package in packages[:20]:
            if not isinstance(package, dict):
                continue
            name = _safe(package.get("name"), r"[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}")
            installed = _safe(package.get("version"), r"[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}")
            fixed_raw = package.get("fixedInVersion")
            fixed = (
                _safe(fixed_raw, r"[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}")
                if fixed_raw is not None
                else None
            )
            if not name or not installed or (fixed_raw is not None and not fixed):
                continue
            rows.append(
                SecCopCsvRow(
                    instance_id=instance_id,
                    cve_id=cve_id,
                    severity=severity,
                    package_name=name,
                    installed_version=installed,
                    fixed_version=fixed,
                    status="ACTIVE",
                )
            )
    return rows


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--profile", default="amit")
    root.add_argument("--region", default="ap-southeast-1")
    root.add_argument("--instance-id", required=True)
    root.add_argument("--output", type=Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", args.instance_id):
        print("BLOCKED TARGET_CONTRACT_INVALID")
        return 2
    try:
        rows = export_rows(args.profile, args.region, args.instance_id)
    except (BackendFailure, OSError, subprocess.SubprocessError):
        print("BLOCKED INSPECTOR_EXPORT_FAILED")
        return 2
    if not rows:
        print("BLOCKED NO_ACTIVE_PACKAGE_FINDINGS")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(write_csv(rows), encoding="utf-8")
    print("SECCOP_INSPECTOR_CSV_READY")
    print("ROWS", len(rows))
    print("CSV_FILE", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
