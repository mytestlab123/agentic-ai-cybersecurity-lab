"""Focused no-AWS checks for the Issue #47 S3 reset command."""

import importlib.util
from pathlib import Path


def _module():
    path = Path(__file__).parents[1] / "scripts" / "issue47_s3_compliance.py"
    spec = importlib.util.spec_from_file_location("issue47_s3_compliance", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reset_is_idempotent_when_the_private_empty_bucket_is_already_open(monkeypatch) -> None:
    module = _module()
    calls: list[tuple[object, ...]] = []

    monkeypatch.setattr(module, "scan", lambda *_: {"reason_code": "SECCOP_S3_NON_COMPLIANT"})
    monkeypatch.setattr(module, "aws", lambda *args, **kwargs: calls.append((args, kwargs)))

    result = module.reset("PROFILE_ALIAS", "REGION_ALIAS", "BUCKET_ALIAS")

    assert result["reason_code"] == "SECCOP_S3_RESET_READY"
    assert calls == []
