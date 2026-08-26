import pytest

from secure_agent_harness.seccop_csv import SecCopCsvError, parse_csv, write_csv


CSV = """instance_id,cve_id,severity,package_name,installed_version,fixed_version,status
i-0123456789abcdef0,CVE-2026-0001,HIGH,kernel,1.0,1.1,ACTIVE
i-0123456789abcdef0,CVE-2026-0002,MEDIUM,openssl,2.0,2.1,ACTIVE
"""


def test_canonical_csv_filters_the_selected_cve() -> None:
    document = parse_csv(
        CSV,
        instance_id="i-0123456789abcdef0",
        cve_id="CVE-2026-0001",
    )

    assert document.row_count == 2
    assert document.match_count == 1
    assert document.matching_rows[0].package_name == "kernel"
    assert "i-0123456789abcdef0" in write_csv(document.matching_rows)


def test_csv_target_mismatch_blocks() -> None:
    with pytest.raises(SecCopCsvError, match="CSV_TARGET_MISMATCH"):
        parse_csv(CSV, instance_id="i-aaaaaaaaaaaaaaaaa", cve_id="CVE-2026-0001")


def test_csv_cve_mismatch_blocks() -> None:
    with pytest.raises(SecCopCsvError, match="CSV_CVE_NOT_FOUND"):
        parse_csv(CSV, instance_id="i-0123456789abcdef0", cve_id="CVE-2026-9999")


def test_csv_schema_is_strict() -> None:
    with pytest.raises(SecCopCsvError, match="CSV_SCHEMA_INVALID"):
        parse_csv(
            CSV.replace("status\n", "status,raw_payload\n"),
            instance_id="i-0123456789abcdef0",
            cve_id="CVE-2026-0001",
        )
