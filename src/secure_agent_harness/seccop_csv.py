"""Strict, small CSV boundary for the SecCop live comparison."""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field


class SecCopCsvError(ValueError):
    """Safe parser error with a stable UI reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class SecCopCsvRow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    instance_id: str = Field(pattern=r"^i-[0-9a-f]{8,17}$")
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    severity: str = Field(pattern=r"^(INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)$")
    package_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,79}$")
    installed_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    fixed_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@~-]{0,63}$")
    status: str = Field(pattern=r"^(ACTIVE|RESOLVED)$")


class SecCopCsvDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rows: tuple[SecCopCsvRow, ...]
    matching_rows: tuple[SecCopCsvRow, ...]

    @property
    def row_count(self) -> int:
        return len(self.rows)

    @property
    def match_count(self) -> int:
        return len(self.matching_rows)


CSV_COLUMNS = (
    "instance_id",
    "cve_id",
    "severity",
    "package_name",
    "installed_version",
    "fixed_version",
    "status",
)
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def parse_csv(text: str, *, instance_id: str, cve_id: str) -> SecCopCsvDocument:
    """Parse only the canonical export shape; never echo raw CSV fields."""

    if len(text.encode("utf-8")) > 500_000:
        raise SecCopCsvError("CSV_SCHEMA_INVALID")
    normalized_cve = cve_id.strip().upper()
    if not _CVE_RE.fullmatch(normalized_cve):
        raise SecCopCsvError("CSV_SCHEMA_INVALID")

    reader = csv.DictReader(io.StringIO(text, newline=""))
    if tuple(reader.fieldnames or ()) != CSV_COLUMNS:
        raise SecCopCsvError("CSV_SCHEMA_INVALID")

    rows: list[SecCopCsvRow] = []
    try:
        for raw in reader:
            if len(rows) >= 5_000:
                raise SecCopCsvError("CSV_SCHEMA_INVALID")
            if None in raw or any(value is None for value in raw.values()):
                raise SecCopCsvError("CSV_SCHEMA_INVALID")
            row = SecCopCsvRow(
                instance_id=str(raw["instance_id"]),
                cve_id=str(raw["cve_id"]).upper(),
                severity=str(raw["severity"]).upper(),
                package_name=str(raw["package_name"]),
                installed_version=str(raw["installed_version"]),
                fixed_version=str(raw["fixed_version"]) or None,
                status=str(raw["status"]).upper(),
            )
            rows.append(row)
    except SecCopCsvError:
        raise
    except Exception as exc:
        raise SecCopCsvError("CSV_SCHEMA_INVALID") from exc

    if not rows:
        raise SecCopCsvError("CSV_SCHEMA_INVALID")
    if any(row.instance_id != instance_id for row in rows):
        raise SecCopCsvError("CSV_TARGET_MISMATCH")
    matching = tuple(row for row in rows if row.cve_id == normalized_cve)
    if not matching:
        raise SecCopCsvError("CSV_CVE_NOT_FOUND")
    return SecCopCsvDocument(rows=tuple(rows), matching_rows=matching)


def write_csv(rows: Iterable[SecCopCsvRow]) -> str:
    """Render the canonical export shape for a local evidence file."""

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row.model_dump())
    return output.getvalue()
