"""Synthetic fixtures safe for public learning examples."""

from .contracts import Finding, PatchingSop, PocInspectorFinding, Workload

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

RAW_INSTANCE_RESPONSES = {
    "EC2_RESOURCE_01": {
        "InstanceId": "RAW_INSTANCE_ID_01",
        "PrivateIpAddress": "PRIVATE_IP_01",
        "PrivateDnsName": "PRIVATE_DNS_01",
        "VpcId": "VPC_ID_01",
        "SubnetId": "SUBNET_ID_01",
        "State": {"Name": "running"},
        "InstanceType": "INSTANCE_TYPE_LARGE",
        "Tags": [{"Key": "Name", "Value": "SYNTHETIC_NAME_01"}],
    }
}

# Issue 5 uses an intentionally future-looking CVE identifier so the browser
# proof is clearly synthetic and cannot be mistaken for live vulnerability
# intelligence.
POC_INSPECTOR_FINDINGS = {
    "CVE-2099-0001": PocInspectorFinding(
        cve_id="CVE-2099-0001",
        lab_env="SYNTHETIC_LAB",
        resource_alias="EC2_RESOURCE_01",
        finding_state="ACTIVE",
        severity="HIGH",
        title="Synthetic package update required",
    )
}
