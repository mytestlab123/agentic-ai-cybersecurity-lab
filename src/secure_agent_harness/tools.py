"""Deterministic read-only tools over synthetic in-memory fixtures."""

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from .contracts import (
    PocInspectorFinding,
    PocPatchCompliance,
    PocSsmNode,
    SanitizedInstance,
    ToolCallProposal,
    ToolResult,
)
from .fixtures import (
    FINDINGS,
    PATCHING_SOPS,
    POC_INSPECTOR_FINDINGS,
    RAW_INSTANCE_RESPONSES,
    WORKLOADS,
)
from .sanitization import sanitize_instance_record


class FixtureNotFoundError(LookupError):
    """Raised when an exact synthetic fixture identifier is unknown."""


def _read_fixture(fixtures: dict[str, BaseModel], fixture_id: str) -> BaseModel:
    try:
        return fixtures[fixture_id]
    except KeyError as exc:
        raise FixtureNotFoundError(f"Synthetic fixture not found: {fixture_id}") from exc


def _read_sanitized_instance(resource_alias: str) -> SanitizedInstance:
    try:
        raw = RAW_INSTANCE_RESPONSES[resource_alias]
    except KeyError as exc:
        raise FixtureNotFoundError(f"Synthetic fixture not found: {resource_alias}") from exc
    return sanitize_instance_record(raw, resource_alias)


def _read_poc_finding(cve_id: str, lab_env: str) -> PocInspectorFinding:
    if lab_env != "SYNTHETIC_LAB":
        raise FixtureNotFoundError("Synthetic lab environment not found.")
    try:
        return POC_INSPECTOR_FINDINGS[cve_id]
    except KeyError as exc:
        raise FixtureNotFoundError("Synthetic CVE fixture not found.") from exc


def _read_poc_ssm_node(resource_alias: str, lab_env: str) -> PocSsmNode:
    if lab_env != "SYNTHETIC_LAB" or resource_alias not in RAW_INSTANCE_RESPONSES:
        raise FixtureNotFoundError("Synthetic managed-node fixture not found.")
    return PocSsmNode(
        resource_alias=resource_alias,
        lab_env="SYNTHETIC_LAB",
        managed_state="MANAGED",
        readiness="READY",
    )


def _read_poc_patch_compliance(cve_id: str, resource_alias: str) -> PocPatchCompliance:
    finding = POC_INSPECTOR_FINDINGS.get(cve_id)
    if finding is None or finding.resource_alias != resource_alias:
        raise FixtureNotFoundError("Synthetic patch-compliance fixture not found.")
    return PocPatchCompliance(
        cve_id=cve_id,
        resource_alias=resource_alias,
        patch_state="MISSING",
        reboot_required=True,
    )


class ToolRegistry:
    def __init__(self) -> None:
        self.executed_calls: list[str] = []
        self._tools: dict[str, tuple[frozenset[str], Callable[[dict[str, str]], BaseModel]]] = {
            "read_finding": (
                frozenset({"finding_id"}),
                lambda args: _read_fixture(FINDINGS, args["finding_id"]),
            ),
            "read_workload": (
                frozenset({"resource_id"}),
                lambda args: _read_fixture(WORKLOADS, args["resource_id"]),
            ),
            "read_patching_sop": (
                frozenset({"sop_id"}),
                lambda args: _read_fixture(PATCHING_SOPS, args["sop_id"]),
            ),
            "read_sanitized_instance": (
                frozenset({"resource_alias"}),
                lambda args: _read_sanitized_instance(args["resource_alias"]),
            ),
            "mock_inspector_finding": (
                frozenset({"cve_id", "lab_env"}),
                lambda args: _read_poc_finding(args["cve_id"], args["lab_env"]),
            ),
            "mock_instance_context": (
                frozenset({"resource_alias"}),
                lambda args: _read_sanitized_instance(args["resource_alias"]),
            ),
            "mock_ssm_node_context": (
                frozenset({"resource_alias", "lab_env"}),
                lambda args: _read_poc_ssm_node(args["resource_alias"], args["lab_env"]),
            ),
            "mock_patch_compliance": (
                frozenset({"cve_id", "resource_alias"}),
                lambda args: _read_poc_patch_compliance(args["cve_id"], args["resource_alias"]),
            ),
        }

    def execute(self, call: ToolCallProposal) -> ToolResult:
        _argument_names, reader = self._tools[call.tool_name]
        record = reader(call.arguments)
        self.executed_calls.append(call.tool_name)
        return ToolResult(tool_name=call.tool_name, data=record.model_dump(mode="json"))
