from pathlib import Path

import pytest

from injektor.config import TargetConfig, load_cases

DEFAULT_CASES = Path(__file__).parents[1] / "injektor" / "cases" / "default.yaml"
CASE = ("- id: a\n  category: c\n  description: d\n  test_input: t\n"
        "  expected_safe_behavior: e\n  severity: high\n")


def test_cases_load():
    assert len(load_cases(DEFAULT_CASES)) == 10


def test_cases_reject_invalid_yaml(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("- id: bad\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_cases(f)


@pytest.mark.parametrize("extra", [
    "  canaries: abc\n",        # a bare string would become one canary per character
    "  canaries: ['']\n",       # an empty canary matches every response
    "  canaries: [5]\n",
    "  canaries: 5\n",
    "  indicators: ['']\n",
    "  indicators: ['(unclosed']\n",
])
def test_cases_reject_malformed_canaries_and_indicators(tmp_path, extra):
    f = tmp_path / "cases.yaml"
    f.write_text(CASE + extra, encoding="utf-8")
    with pytest.raises(ValueError):
        load_cases(f)


def test_builtin_prompts_never_contain_their_own_canary():
    for case in load_cases(DEFAULT_CASES):
        assert "{{" not in case.test_input
        for canary in case.canaries:
            assert canary.casefold() not in case.test_input.casefold()


def test_target_requires_explicit_endpoint(monkeypatch):
    monkeypatch.delenv("INJEKTOR_ENDPOINT", raising=False)
    monkeypatch.delenv("INJEKTOR_MODEL", raising=False)
    with pytest.raises(ValueError, match="explicitly"):
        TargetConfig.from_env()


def test_target_rejects_remote_plain_http(monkeypatch):
    monkeypatch.setenv("INJEKTOR_ENDPOINT", "http://example.com/v1/chat/completions")
    monkeypatch.setenv("INJEKTOR_MODEL", "test")
    with pytest.raises(ValueError, match="HTTPS"):
        TargetConfig.from_env()


@pytest.mark.parametrize("endpoint", [
    "http://127.0.0.1:abc/v1", "http://127.0.0.1:99999/v1", "http://127.0.0.1:8765/v 1",
    "http://127.0.0.1:8765/v1\tx", "http://127.0.0.1.example.com/v1", "http://user:pw@127.0.0.1/v1",
    "http://10.0.0.5/v1", "ftp://127.0.0.1/v1", "file:///etc/passwd",
])
def test_target_rejects_unsafe_or_malformed_endpoints(monkeypatch, endpoint):
    monkeypatch.setenv("INJEKTOR_ENDPOINT", endpoint)
    monkeypatch.setenv("INJEKTOR_MODEL", "test")
    with pytest.raises(ValueError):
        TargetConfig.from_env()


@pytest.mark.parametrize("endpoint", [
    "http://127.0.0.1:8765/v1/chat/completions", "http://localhost:8765/v1", "http://[::1]:8765/v1",
    "https://api.example.com/v1/chat/completions",
])
def test_target_accepts_loopback_http_and_remote_https(monkeypatch, endpoint):
    monkeypatch.setenv("INJEKTOR_ENDPOINT", endpoint)
    monkeypatch.setenv("INJEKTOR_MODEL", "test")
    assert TargetConfig.from_env().endpoint == endpoint


@pytest.mark.parametrize("name,value", [("INJEKTOR_TIMEOUT", "nan"), ("INJEKTOR_TIMEOUT", "inf"),
                                        ("INJEKTOR_TIMEOUT", "0"), ("INJEKTOR_RETRIES", "4"),
                                        ("INJEKTOR_RETRIES", "-1"), ("INJEKTOR_RETRIES", "1.5")])
def test_target_bounds_timeout_and_retries(monkeypatch, name, value):
    monkeypatch.setenv("INJEKTOR_ENDPOINT", "http://127.0.0.1:8765/v1")
    monkeypatch.setenv("INJEKTOR_MODEL", "test")
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        TargetConfig.from_env()
