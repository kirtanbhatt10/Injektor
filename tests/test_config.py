from pathlib import Path

import pytest

from injector.config import TargetConfig, load_cases


def test_cases_load():
    assert len(load_cases(Path(__file__).parents[1] / "injector" / "cases" / "default.yaml")) == 4


def test_cases_reject_invalid_yaml(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("- id: bad\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_cases(f)


def test_target_requires_explicit_endpoint(monkeypatch):
    monkeypatch.delenv("INJECTOR_ENDPOINT", raising=False)
    monkeypatch.delenv("INJECTOR_MODEL", raising=False)
    with pytest.raises(ValueError, match="explicitly"):
        TargetConfig.from_env()


def test_target_rejects_remote_plain_http(monkeypatch):
    monkeypatch.setenv("INJECTOR_ENDPOINT", "http://example.com/v1/chat/completions")
    monkeypatch.setenv("INJECTOR_MODEL", "test")
    with pytest.raises(ValueError, match="HTTPS"):
        TargetConfig.from_env()
