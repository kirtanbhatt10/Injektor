"""Configuration and attack-case loading with strict validation."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml


@dataclass(frozen=True)
class TargetConfig:
    endpoint: str
    model: str
    api_key_env: str = "INJEKTOR_API_KEY"
    timeout: float = 15.0
    retries: int = 1

    @classmethod
    def from_env(cls) -> "TargetConfig":
        endpoint = os.getenv("INJEKTOR_ENDPOINT", "").strip()
        model = os.getenv("INJEKTOR_MODEL", "").strip()
        if not endpoint or not model:
            raise ValueError("Set INJEKTOR_ENDPOINT and INJEKTOR_MODEL explicitly.")
        if any(ch.isspace() or not ch.isprintable() for ch in endpoint):
            raise ValueError("INJEKTOR_ENDPOINT must not contain whitespace or control characters.")
        try:
            parsed = urlsplit(endpoint)
            parsed.port  # accessing the property validates it
        except ValueError as exc:
            raise ValueError("INJEKTOR_ENDPOINT is not a valid URL.") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("INJEKTOR_ENDPOINT must be an absolute http(s) URL.")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Endpoint URL must not contain credentials or a fragment.")
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Non-local endpoints must use HTTPS.")
        try:
            timeout = float(os.getenv("INJEKTOR_TIMEOUT", "15"))
            retries = int(os.getenv("INJEKTOR_RETRIES", "1"))
        except ValueError as exc:
            raise ValueError("INJEKTOR_TIMEOUT and INJEKTOR_RETRIES must be numeric.") from exc
        if not 0.1 <= timeout <= 120:
            raise ValueError("INJEKTOR_TIMEOUT must be between 0.1 and 120 seconds.")
        if not 0 <= retries <= 3:
            raise ValueError("INJEKTOR_RETRIES must be between 0 and 3.")
        return cls(endpoint, model, os.getenv("INJEKTOR_API_KEY_ENV", "INJEKTOR_API_KEY"), timeout, retries)

    def credential(self) -> str | None:
        return os.getenv(self.api_key_env)


@dataclass(frozen=True)
class AttackCase:
    id: str
    category: str
    description: str
    test_input: str
    expected_safe_behavior: str
    severity: str
    canaries: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()


def load_cases(path: str | Path) -> list[AttackCase]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Could not load test cases: {exc}") from exc
    if not isinstance(raw, list) or not raw:
        raise ValueError("Test case file must contain a non-empty YAML list.")
    cases, seen = [], set()
    required = {"id", "category", "description", "test_input", "expected_safe_behavior", "severity"}
    for item in raw:
        if not isinstance(item, dict) or required - item.keys():
            raise ValueError("Every case must be a mapping with all required fields.")
        if not all(isinstance(item[k], str) and item[k].strip() for k in required):
            raise ValueError("Required test case fields must be non-empty strings.")
        if item["id"] in seen:
            raise ValueError(f"Duplicate test case ID: {item['id']}")
        if item["severity"] not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"Invalid severity in case {item['id']}.")
        seen.add(item["id"])
        canaries = _string_list(item, "canaries")
        indicators = _string_list(item, "indicators")
        for pattern in indicators:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid indicator regex in case {item['id']}: {exc}") from exc
        cases.append(AttackCase(**{k: item[k] for k in required},
                              canaries=canaries, indicators=indicators))
    return cases


def _string_list(item: dict, key: str) -> tuple[str, ...]:
    """A bare string would be split into characters, and '' matches every response."""
    value = item.get(key, [])
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise ValueError(f"'{key}' in case {item['id']} must be a list of non-empty strings.")
    return tuple(value)
