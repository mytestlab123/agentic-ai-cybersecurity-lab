"""Injected-client, fail-closed AWS read-only evidence adapter.

This module intentionally has no boto3 dependency and never constructs a live
client. A caller must inject already-authorized Inspector2, EC2, and SSM
clients. Tests use fakes; a future runtime adapter can provide boto3 clients
only after the exact account, region, and target gates are approved.
"""

from collections.abc import Mapping
import re
from typing import Any, Protocol

from .contracts import (
    AwsReadOnlyEvidence,
    AwsReadOnlyResult,
    AwsPatchSummary,
    AwsVulnerablePackage,
    ReadOnlyCheck,
    ReadOnlyTarget,
)


class InspectorReadClient(Protocol):
    def list_findings(self, **kwargs: Any) -> Mapping[str, Any]: ...


class Ec2ReadClient(Protocol):
    def describe_instances(self, **kwargs: Any) -> Mapping[str, Any]: ...


class SsmReadClient(Protocol):
    def describe_instance_information(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_inventory_entries(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def describe_instance_patch_states(self, **kwargs: Any) -> Mapping[str, Any]: ...


_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_DEFAULT_REQUIRED_TAGS = {
    "Project": "Security Copilot",
    "Environment": "seccop-demo",
}


class AwsReadOnlyEvidenceSource:
    """Collect exact-target evidence without broad discovery or mutation."""

    def __init__(
        self,
        inspector: InspectorReadClient,
        ec2: Ec2ReadClient,
        ssm: SsmReadClient,
        required_tags: Mapping[str, str] | None = None,
    ) -> None:
        self._inspector = inspector
        self._ec2 = ec2
        self._ssm = ssm
        self._required_tags = dict(required_tags or _DEFAULT_REQUIRED_TAGS)
        self._executed_calls: list[str] = []

    def collect(
        self,
        cve_id: str,
        target: ReadOnlyTarget,
        *,
        include_patch_summary: bool = False,
    ) -> AwsReadOnlyResult:
        normalized_cve = cve_id.strip().upper()
        if not _CVE_RE.fullmatch(normalized_cve):
            raise ValueError("cve_id must match the CVE contract.")

        self._executed_calls = []
        findings = self._list_findings(normalized_cve, target.instance_id)
        if findings is None:
            return self._blocked(normalized_cve, target.resource_alias, "READ_BACKEND_FAILED")
        if not findings:
            return self._blocked(normalized_cve, target.resource_alias, "FINDING_NOT_FOUND")
        if len(findings) != 1:
            return self._blocked(normalized_cve, target.resource_alias, "FINDING_AMBIGUOUS")

        finding = findings[0]
        if not self._finding_binds_to_target(finding, target.instance_id):
            return self._blocked(normalized_cve, target.resource_alias, "FINDING_RESOURCE_MISMATCH")

        instance = self._read_exact_instance(target.instance_id)
        if instance is None:
            return self._blocked(normalized_cve, target.resource_alias, "EC2_TARGET_NOT_FOUND")
        if instance is False:
            return self._blocked(normalized_cve, target.resource_alias, "READ_BACKEND_FAILED")
        if not self._tags_match(instance.get("Tags")):
            return self._blocked(normalized_cve, target.resource_alias, "EC2_TAGS_MISMATCH")

        managed = self._read_exact_ssm_node(target.instance_id)
        if managed is None:
            return self._blocked(normalized_cve, target.resource_alias, "SSM_NODE_NOT_FOUND")
        if managed is False:
            return self._blocked(normalized_cve, target.resource_alias, "READ_BACKEND_FAILED")
        if str(managed.get("PingStatus", "")).upper() != "ONLINE":
            return self._blocked(normalized_cve, target.resource_alias, "SSM_NODE_NOT_READY")

        patch_summary = None
        patch_check_reason = "SSM_PATCH_SUMMARY_READY"
        if include_patch_summary:
            patch_state, patch_summary = self._read_patch_summary(target.instance_id)
            if patch_state == "NOT_FOUND":
                patch_state, patch_summary = self._read_patch_states(target.instance_id)
                patch_check_reason = "SSM_PATCH_STATE_READY"
            if patch_state == "NOT_FOUND":
                return self._blocked(
                    normalized_cve,
                    target.resource_alias,
                    "SSM_PATCH_SUMMARY_NOT_FOUND",
                )
            if patch_state == "INVALID":
                return self._blocked(
                    normalized_cve,
                    target.resource_alias,
                    "SSM_PATCH_SUMMARY_INVALID",
                )
            if patch_state == "FAILED":
                return self._blocked(
                    normalized_cve,
                    target.resource_alias,
                    "READ_BACKEND_FAILED",
                )

        checks = (
            ReadOnlyCheck(
                check_name="INSPECTOR_FINDING",
                outcome="PASS",
                reason_code="FINDING_MATCHED",
            ),
            ReadOnlyCheck(
                check_name="FINDING_EC2_BINDING",
                outcome="PASS",
                reason_code="FINDING_MATCHED",
            ),
            ReadOnlyCheck(
                check_name="EC2_TARGET",
                outcome="PASS",
                reason_code="EC2_TARGET_MATCHED",
            ),
            ReadOnlyCheck(
                check_name="EC2_TAGS",
                outcome="PASS",
                reason_code="EC2_TAGS_MATCHED",
            ),
            ReadOnlyCheck(
                check_name="SSM_MANAGED_NODE",
                outcome="PASS",
                reason_code="SSM_NODE_READY",
            ),
        )
        if include_patch_summary:
            checks += (
                ReadOnlyCheck(
                    check_name="SSM_PATCH_SUMMARY",
                    outcome="PASS",
                    reason_code=patch_check_reason,
                ),
            )
        evidence = AwsReadOnlyEvidence(
            source="AWS_READ_ONLY",
            cve_id=normalized_cve,
            resource_alias=target.resource_alias,
            finding_count=1,
            finding_state=self._finding_state(finding),
            finding_severity=self._finding_severity(finding),
            finding_ec2_bound=True,
            instance_state=self._instance_state(instance),
            expected_tags_verified=True,
            ssm_managed=True,
            ssm_readiness="READY",
            packages=self._packages(finding),
            patch_summary=patch_summary,
            checks=checks,
            executed_calls=tuple(self._executed_calls),
        )
        return AwsReadOnlyResult(
            status="READY",
            reason_code="READ_ONLY_EVIDENCE_READY",
            cve_id=normalized_cve,
            resource_alias=target.resource_alias,
            evidence=evidence,
            executed_calls=tuple(self._executed_calls),
            message="Read-only Inspector, EC2, and SSM evidence matched the exact target.",
        )

    def _read_patch_summary(
        self,
        instance_id: str,
    ) -> tuple[str, AwsPatchSummary | None]:
        response = self._call(
            "ssm.list_inventory_entries",
            self._ssm.list_inventory_entries,
            InstanceId=instance_id,
            TypeName="AWS:PatchSummary",
            MaxResults=50,
        )
        if response is None:
            return "FAILED", None
        entries = response.get("Entries")
        if not isinstance(entries, list):
            return "INVALID", None
        if len(entries) != 1 or not isinstance(entries[0], Mapping):
            return "NOT_FOUND" if not entries else "INVALID", None
        entry = entries[0]
        fields = {
            "installed_count": entry.get("InstalledCount", 0),
            "missing_count": entry.get("MissingCount", 0),
            "failed_count": entry.get("FailedCount", 0),
            "security_non_compliant_count": entry.get("SecurityNonCompliantCount", 0),
            "critical_non_compliant_count": entry.get("CriticalNonCompliantCount", 0),
        }
        if not all(isinstance(value, int) and value >= 0 for value in fields.values()):
            return "INVALID", None
        return "READY", AwsPatchSummary(**fields)

    def _read_patch_states(
        self,
        instance_id: str,
    ) -> tuple[str, AwsPatchSummary | None]:
        operation = getattr(self._ssm, "describe_instance_patch_states", None)
        if operation is None:
            return "NOT_FOUND", None
        response = self._call(
            "ssm.describe_instance_patch_states",
            operation,
            InstanceIds=[instance_id],
            MaxResults=50,
        )
        if response is None:
            return "FAILED", None
        states = response.get("InstancePatchStates")
        if not isinstance(states, list):
            return "INVALID", None
        matches = [
            state
            for state in states
            if isinstance(state, Mapping) and state.get("InstanceId") == instance_id
        ]
        if len(matches) != 1:
            return "NOT_FOUND" if not matches else "INVALID", None
        state = matches[0]
        fields = {
            "installed_count": state.get("InstalledCount", 0),
            "missing_count": state.get("MissingCount", 0),
            "failed_count": state.get("FailedCount", 0),
            "security_non_compliant_count": state.get("SecurityNonCompliantCount", 0),
            "critical_non_compliant_count": state.get("CriticalNonCompliantCount", 0),
            "installed_pending_reboot_count": state.get("InstalledPendingRebootCount", 0),
        }
        if not all(isinstance(value, int) and value >= 0 for value in fields.values()):
            return "INVALID", None
        operation_name = state.get("Operation", "Unknown")
        fields["operation"] = operation_name if operation_name in {"Scan", "Install"} else "Unknown"
        return "READY", AwsPatchSummary(**fields)

    @staticmethod
    def _packages(finding: Mapping[str, Any]) -> tuple[AwsVulnerablePackage, ...]:
        details = finding.get("packageVulnerabilityDetails")
        raw_packages = details.get("vulnerablePackages") if isinstance(details, Mapping) else None
        if not isinstance(raw_packages, list):
            return ()
        packages: list[AwsVulnerablePackage] = []
        for raw in raw_packages[:20]:
            if not isinstance(raw, Mapping):
                continue
            name = AwsReadOnlyEvidenceSource._safe_package_value(raw.get("name"))
            installed = AwsReadOnlyEvidenceSource._safe_package_value(raw.get("version"))
            fixed_raw = raw.get("fixedInVersion")
            fixed = (
                AwsReadOnlyEvidenceSource._safe_package_value(fixed_raw)
                if fixed_raw is not None
                else None
            )
            if name is None or installed is None or (fixed_raw is not None and fixed is None):
                continue
            packages.append(
                AwsVulnerablePackage(
                    name=name,
                    installed_version=installed,
                    fixed_version=fixed,
                )
            )
        return tuple(packages)

    @staticmethod
    def _safe_package_value(value: Any) -> str | None:
        if not isinstance(value, str) or not 1 <= len(value) <= 80:
            return None
        return value if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,79}", value) else None

    def _list_findings(self, cve_id: str, instance_id: str) -> list[Mapping[str, Any]] | None:
        request: dict[str, Any] = {
            "filterCriteria": {
                "vulnerabilityId": [{"comparison": "EQUALS", "value": cve_id}],
                "resourceId": [{"comparison": "EQUALS", "value": instance_id}],
            },
            "maxResults": 100,
        }
        findings: list[Mapping[str, Any]] = []
        for _ in range(20):
            response = self._call("inspector.list_findings", self._inspector.list_findings, **request)
            if response is None:
                return None
            page = response.get("findings")
            if not isinstance(page, list) or not all(isinstance(item, Mapping) for item in page):
                return None
            findings.extend(page)
            token = response.get("nextToken")
            if not token:
                return findings
            request["nextToken"] = token
        return None

    def _read_exact_instance(self, instance_id: str) -> Mapping[str, Any] | bool | None:
        response = self._call(
            "ec2.describe_instances",
            self._ec2.describe_instances,
            InstanceIds=[instance_id],
        )
        if response is None:
            return False
        reservations = response.get("Reservations")
        if not isinstance(reservations, list):
            return False
        matches: list[Mapping[str, Any]] = []
        for reservation in reservations:
            if not isinstance(reservation, Mapping):
                return False
            instances = reservation.get("Instances")
            if not isinstance(instances, list):
                return False
            matches.extend(
                instance
                for instance in instances
                if isinstance(instance, Mapping) and instance.get("InstanceId") == instance_id
            )
        if len(matches) != 1:
            return None if not matches else False
        return matches[0]

    def _read_exact_ssm_node(self, instance_id: str) -> Mapping[str, Any] | bool | None:
        response = self._call(
            "ssm.describe_instance_information",
            self._ssm.describe_instance_information,
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}],
            MaxResults=50,
        )
        if response is None:
            return False
        nodes = response.get("InstanceInformationList")
        if not isinstance(nodes, list):
            return False
        matches = [
            node
            for node in nodes
            if isinstance(node, Mapping) and node.get("InstanceId") == instance_id
        ]
        if len(matches) != 1:
            return None if not matches else False
        return matches[0]

    def _call(self, name: str, operation: Any, **kwargs: Any) -> Mapping[str, Any] | None:
        self._executed_calls.append(name)
        try:
            response = operation(**kwargs)
        except Exception:
            return None
        return response if isinstance(response, Mapping) else None

    def _blocked(self, cve_id: str, resource_alias: str, reason_code: str) -> AwsReadOnlyResult:
        return AwsReadOnlyResult(
            status="BLOCKED",
            reason_code=reason_code,
            cve_id=cve_id,
            resource_alias=resource_alias,
            executed_calls=tuple(self._executed_calls),
            message="Read-only AWS evidence did not pass the required binding gate.",
        )

    def _finding_binds_to_target(self, finding: Mapping[str, Any], instance_id: str) -> bool:
        resources = finding.get("resources")
        if not isinstance(resources, list):
            return False
        return any(
            isinstance(resource, Mapping)
            and resource.get("type") == "AWS_EC2_INSTANCE"
            and resource.get("id") == instance_id
            for resource in resources
        )

    def _tags_match(self, raw_tags: Any) -> bool:
        if not isinstance(raw_tags, list):
            return False
        tags = {
            tag.get("Key"): tag.get("Value")
            for tag in raw_tags
            if isinstance(tag, Mapping)
        }
        return all(tags.get(key) == value for key, value in self._required_tags.items())

    @staticmethod
    def _finding_state(finding: Mapping[str, Any]) -> str:
        status = str(finding.get("status", "")).upper()
        if status in {"ACTIVE", "IN_PROGRESS"}:
            return "ACTIVE"
        if status in {"CLOSED", "RESOLVED", "SUPPRESSED"}:
            return "RESOLVED"
        return "UNKNOWN"

    @staticmethod
    def _finding_severity(finding: Mapping[str, Any]) -> str:
        severity = str(finding.get("severity", "")).upper()
        return severity if severity in {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"} else "UNKNOWN"

    @staticmethod
    def _instance_state(instance: Mapping[str, Any]) -> str:
        state = instance.get("State")
        name = state.get("Name") if isinstance(state, Mapping) else None
        return name.upper() if isinstance(name, str) and name.upper() in {"RUNNING", "STOPPED", "PENDING", "TERMINATED"} else "UNKNOWN"
