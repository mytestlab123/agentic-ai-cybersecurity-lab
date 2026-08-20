"""Deterministic read-only tools over synthetic in-memory fixtures."""

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from .contracts import ToolCallProposal, ToolResult
from .fixtures import FINDINGS, PATCHING_SOPS, WORKLOADS


class FixtureNotFoundError(LookupError):
    """Raised when an exact synthetic fixture identifier is unknown."""


def _read_fixture(fixtures: dict[str, BaseModel], fixture_id: str) -> BaseModel:
    try:
        return fixtures[fixture_id]
    except KeyError as exc:
        raise FixtureNotFoundError(f"Synthetic fixture not found: {fixture_id}") from exc


class ToolRegistry:
    def __init__(self) -> None:
        self.executed_calls: list[str] = []
        self._tools: dict[str, tuple[str, Callable[[str], BaseModel]]] = {
            "read_finding": ("finding_id", lambda value: _read_fixture(FINDINGS, value)),
            "read_workload": ("resource_id", lambda value: _read_fixture(WORKLOADS, value)),
            "read_patching_sop": ("sop_id", lambda value: _read_fixture(PATCHING_SOPS, value)),
        }

    def execute(self, call: ToolCallProposal) -> ToolResult:
        argument_name, reader = self._tools[call.tool_name]
        record = reader(call.arguments[argument_name])
        self.executed_calls.append(call.tool_name)
        return ToolResult(tool_name=call.tool_name, data=record.model_dump(mode="json"))
