"""Synthetic fixtures safe for public learning examples."""

from .contracts import Finding, PatchingSop, Workload

FINDINGS = {
    "FINDING_01": Finding(
        finding_id="FINDING_01",
        resource_id="EC2_RESOURCE_01",
        severity="HIGH",
        title="Synthetic package update required",
    )
}

WORKLOADS = {
    "EC2_RESOURCE_01": Workload(
        resource_id="EC2_RESOURCE_01",
        environment="SYNTHETIC_LAB",
        owner_role="ROLE_READONLY_01",
        change_window="SATURDAY_02_00_UTC",
    )
}

PATCHING_SOPS = {
    "SOP_PATCHING_01": PatchingSop(
        sop_id="SOP_PATCHING_01",
        title="Synthetic patch planning procedure",
        steps=(
            "Review the synthetic finding.",
            "Confirm the synthetic workload window.",
            "Prepare a plan and request human approval before any mutation.",
        ),
    )
}
