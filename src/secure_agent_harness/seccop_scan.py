"""Small deterministic multi-source scan for the SecCop POC.

The scan is deliberately fixture-backed. It demonstrates one operator journey
without adding S3/ECR permissions or pretending those sources were remediated.
The existing EC2 advisory and SSM path remains the only real mutation path.
"""

from .contracts import (
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
