"""Small deterministic multi-source scan for the SecCop POC.

The scan is deliberately fixture-backed. It demonstrates one operator journey
without adding S3/ECR permissions or pretending those sources were remediated.
The existing EC2 advisory and SSM path remains the only real mutation path.
"""

from .contracts import (
    SecCopCveReviewResult,
    SecCopCveSourceResult,
    SecCopFinding,
    SecCopScanResult,
    SecCopScanSourceStatus,
)


def run_demo_scan() -> SecCopScanResult:
    """Return three sanitized findings for the manager-facing demo."""

    return SecCopScanResult(
        scan_id="SECCOP_SCAN_01",
        status="READY",
        reason_code="SECCOP_SCAN_READY",
        source_status=(
            SecCopScanSourceStatus(
                source_type="EC2_PACKAGE",
                label="Server packages",
                state="COMPLETE",
                reason_code="SECCOP_SOURCE_READY",
            ),
            SecCopScanSourceStatus(
                source_type="S3_ARTIFACT",
                label="Stored artifact",
                state="COMPLETE",
                reason_code="SECCOP_SOURCE_READY",
            ),
            SecCopScanSourceStatus(
                source_type="ECR_IMAGE",
                label="Container image",
                state="COMPLETE",
                reason_code="SECCOP_SOURCE_READY",
            ),
        ),
        findings=(
            SecCopFinding(
                finding_id="FINDING_01",
                source_type="EC2_PACKAGE",
                resource_alias="LAB_SERVER_01",
                cve_id="CVE-2099-0001",
                reference="CVE-2099-0001",
                severity="HIGH",
                title="Old server package",
                problem_summary="A server package needs a live check before it is updated.",
                observed_state="Older package in the demo scenario",
                recommended_state="Confirm the live advisory, then apply the approved update.",
                remediation_mode="REAL_APPROVAL_REQUIRED",
                reason_code="SECCOP_EC2_FINDING_CONFIRMED",
                action_label="Review live fix",
            ),
            SecCopFinding(
                finding_id="FINDING_02",
                source_type="S3_ARTIFACT",
                resource_alias="ARTIFACT_01",
                cve_id="CVE-2099-0001",
                reference="ARTIFACT_RULE_01",
                severity="MEDIUM",
                title="Old stored artifact",
                problem_summary="A stored build contains an old library file.",
                observed_state="Known-old file in the demo artifact",
                recommended_state="Replace it with the approved build after validation.",
                remediation_mode="DEMO_ONLY",
                reason_code="SECCOP_S3_FIXTURE_FINDING",
                action_label="View suggested fix",
            ),
            SecCopFinding(
                finding_id="FINDING_03",
                source_type="ECR_IMAGE",
                resource_alias="IMAGE_01",
                cve_id="CVE-2099-0001",
                reference="IMAGE_RULE_01",
                severity="HIGH",
                title="Old container package",
                problem_summary="A container image contains an old package.",
                observed_state="Old package in the demo image",
                recommended_state="Rebuild, scan, and promote a verified image digest.",
                remediation_mode="DEMO_ONLY",
                reason_code="SECCOP_ECR_FIXTURE_FINDING",
                action_label="View suggested fix",
            ),
        ),
        message="Three demo findings are ready. Only the server path can request a real approved fix.",
    )


def review_demo_cve(cve_id: str) -> SecCopCveReviewResult:
    """Check one normalized CVE against every deterministic demo source."""

    scan = run_demo_scan()
    findings_by_source = {finding.source_type: finding for finding in scan.findings}
    source_results: list[SecCopCveSourceResult] = []
    for source in scan.source_status:
        finding = findings_by_source.get(source.source_type)
        if source.state != "COMPLETE":
            source_results.append(
                SecCopCveSourceResult(
                    source_type=source.source_type,
                    label=source.label,
                    resource_alias=(finding.resource_alias if finding else _source_alias(source.source_type)),
                    status="UNAVAILABLE",
                    reason_code="SECCOP_SOURCE_UNAVAILABLE",
                    summary="This source did not complete its check.",
                    action_label="No action",
                )
            )
            continue
        if finding and finding.cve_id == cve_id:
            source_results.append(
                SecCopCveSourceResult(
                    source_type=source.source_type,
                    label=source.label,
                    resource_alias=finding.resource_alias,
                    status="FOUND",
                    reason_code="SECCOP_CVE_MATCH",
                    finding_id=finding.finding_id,
                    summary=f"{finding.title}: {finding.problem_summary}",
                    action_label=("Review fix" if source.source_type == "EC2_PACKAGE" else "View suggestion"),
                )
            )
        else:
            source_results.append(
                SecCopCveSourceResult(
                    source_type=source.source_type,
                    label=source.label,
                    resource_alias=(finding.resource_alias if finding else _source_alias(source.source_type)),
                    status="NOT_FOUND",
                    reason_code="SECCOP_CVE_NOT_FOUND",
                    summary=f"No matching CVE in the completed {source.label.lower()} check.",
                    action_label="No action",
                )
            )

    matches = sum(1 for item in source_results if item.status == "FOUND")
    unavailable = any(item.status == "UNAVAILABLE" for item in source_results)
    if unavailable:
        status = "PARTIAL"
        reason_code = "SECCOP_CVE_REVIEW_PARTIAL"
        message = f"{cve_id} was checked, but one or more sources were unavailable."
    elif matches:
        status = "READY"
        reason_code = "SECCOP_CVE_REVIEW_READY"
        message = f"{cve_id} was found in {matches} demo source(s). Review the suggested next step."
    else:
        status = "NOT_FOUND"
        reason_code = "SECCOP_CVE_NOT_FOUND"
        message = f"{cve_id} was not found in the completed demo source checks."
    return SecCopCveReviewResult(
        status=status,
        reason_code=reason_code,
        cve_id=cve_id,
        source_results=tuple(source_results),
        match_count=matches,
        message=message,
    )


def _source_alias(source_type: str) -> str:
    return {
        "EC2_PACKAGE": "LAB_SERVER_01",
        "S3_ARTIFACT": "ARTIFACT_01",
        "ECR_IMAGE": "IMAGE_01",
    }[source_type]
