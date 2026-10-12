"""Configuration and attack-case loading with strict validation."""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .regexguard import find_spans

# Bounds on untrusted case files. One request is sent per case, so the case count is also the
# upper bound on requests in a scan.
MAX_CASE_FILE_BYTES = 1_000_000
MAX_CASES = 200
MAX_TEST_INPUT_CHARS = 8_000
MAX_LIST_ITEMS = 20
MAX_PATTERN_CHARS = 500
# Shorter tokens occur in ordinary text by chance and would be scored as a confirmed finding.
MIN_TOKEN_CHARS = 8
MAX_DELAY_SECONDS = 60.0
# For checking every indicator of a case file against its own prompt, in one child interpreter.
LOAD_REGEX_BUDGET_SECONDS = 10.0

class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses a mapping key that appears twice at the same level. PyYAML
    otherwise keeps the last value, which could silently replace a canary or an indicator."""

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for key_node, _value_node in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge":
                    continue  # '<<: *base' may be overridden by explicit keys on purpose
                key = self.construct_object(key_node, deep=True)
                try:
                    duplicate = key in seen
                    seen.add(key)
                except TypeError:  # unhashable keys are reported by the base class
                    continue
                if duplicate:
                    # The key name is case-file content, not a secret, but it is bounded here.
                    raise yaml.constructor.ConstructorError(
                        None, None, f"duplicate key {str(key)[:60]!r}", key_node.start_mark)
        return super().construct_mapping(node, deep=deep)


@dataclass(frozen=True)
class TargetConfig:
    endpoint: str
    model: str
    api_key_env: str = "INJEKTOR_API_KEY"
    timeout: float = 15.0
    retries: int = 1
    delay: float = 0.0

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
            delay = float(os.getenv("INJEKTOR_DELAY", "0"))
        except ValueError as exc:
            raise ValueError("INJEKTOR_TIMEOUT, INJEKTOR_RETRIES and INJEKTOR_DELAY must be "
                             "numeric.") from exc
        if not 0.1 <= timeout <= 120:
            raise ValueError("INJEKTOR_TIMEOUT must be between 0.1 and 120 seconds.")
        if not 0 <= retries <= 3:
            raise ValueError("INJEKTOR_RETRIES must be between 0 and 3.")
        if not 0 <= delay <= MAX_DELAY_SECONDS:
            raise ValueError(f"INJEKTOR_DELAY must be between 0 and {MAX_DELAY_SECONDS:g} seconds.")
        return cls(endpoint, model, os.getenv("INJEKTOR_API_KEY_ENV", "INJEKTOR_API_KEY"), timeout,
                   retries, delay)

    def credential(self) -> str | None:
        # Surrounding whitespace (a stray newline from a secrets file) is never part of a key.
        return (os.getenv(self.api_key_env) or "").strip() or None


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
    markers: tuple[str, ...] = ()
    remediation: str = ""


REQUIRED_FIELDS = frozenset({"id", "category", "description", "test_input",
                             "expected_safe_behavior", "severity"})
OPTIONAL_FIELDS = frozenset({"canaries", "indicators", "markers", "remediation"})


def load_cases(path: str | Path) -> list[AttackCase]:
    return load_case_file(path)[0]


def load_case_file(path: str | Path) -> tuple[list[AttackCase], str]:
    """The cases, and the SHA-256 of the exact bytes they were parsed from. The file is read
    once, so the hash describes what was loaded even if the file changes afterwards."""
    try:
        # Read at most one byte over the limit, so an oversized (or endless) file is never
        # loaded into memory whole.
        with open(path, "rb") as handle:
            data = handle.read(MAX_CASE_FILE_BYTES + 1)
        if len(data) > MAX_CASE_FILE_BYTES:
            raise ValueError(f"Test case file is larger than {MAX_CASE_FILE_BYTES} bytes.")
        raw = yaml.load(data.decode("utf-8"), Loader=_StrictLoader)  # a SafeLoader subclass
    except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise ValueError(f"Could not load test cases: {exc}") from exc
    if not isinstance(raw, list) or not raw:
        raise ValueError("Test case file must contain a non-empty YAML list.")
    if len(raw) > MAX_CASES:
        raise ValueError(f"Test case file has {len(raw)} cases; the limit is {MAX_CASES}.")
    cases, seen = [], set()
    prompt_checks: list[tuple[str, str, str]] = []
    for item in raw:
        if not isinstance(item, dict) or REQUIRED_FIELDS - item.keys():
            raise ValueError("Every case must be a mapping with all required fields.")
        if not all(isinstance(item[k], str) and item[k].strip() for k in REQUIRED_FIELDS):
            raise ValueError("Required test case fields must be non-empty strings.")
        if item["id"] in seen:
            raise ValueError(f"Duplicate test case ID: {item['id']}")
        # A misspelled key ('canary', 'indicator') would otherwise silently disable detection.
        unknown = sorted(str(key) for key in item.keys() - REQUIRED_FIELDS - OPTIONAL_FIELDS)
        if unknown:
            raise ValueError(f"Unknown field(s) in case {item['id']}: {', '.join(unknown)}. "
                             f"Optional fields are: {', '.join(sorted(OPTIONAL_FIELDS))}.")
        if item["severity"] not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"Invalid severity in case {item['id']}.")
        if len(item["test_input"]) > MAX_TEST_INPUT_CHARS:
            raise ValueError(f"test_input in case {item['id']} is longer than "
                             f"{MAX_TEST_INPUT_CHARS} characters.")
        seen.add(item["id"])
        canaries = _string_list(item, "canaries")
        markers = _string_list(item, "markers")
        indicators = _string_list(item, "indicators")
        prompt = item["test_input"].casefold()
        for key, tokens in (("canaries", canaries), ("markers", markers)):
            for token in tokens:
                if len(token.strip()) < MIN_TOKEN_CHARS:
                    raise ValueError(f"'{key}' entries in case {item['id']} must be at least "
                                     f"{MIN_TOKEN_CHARS} characters long.")
                # A target that only quotes the request back would be scored as a finding.
                if token.casefold() in prompt:
                    raise ValueError(f"'{key}' entry in case {item['id']} appears in its "
                                     "test_input; a quoted request would count as a finding.")
        for pattern in indicators:
            if len(pattern) > MAX_PATTERN_CHARS:
                raise ValueError(f"Indicator regex in case {item['id']} is longer than "
                                 f"{MAX_PATTERN_CHARS} characters.")
            try:
                re.compile(pattern)
            except (re.error, RecursionError, OverflowError) as exc:
                raise ValueError(f"Invalid indicator regex in case {item['id']}: {exc}") from exc
            prompt_checks.append((item["id"], pattern, item["test_input"]))
        remediation = item.get("remediation", "")
        if not isinstance(remediation, str):
            raise ValueError(f"'remediation' in case {item['id']} must be a string.")
        cases.append(AttackCase(**{k: item[k] for k in REQUIRED_FIELDS}, canaries=canaries,
                                indicators=indicators, markers=markers,
                                remediation=remediation.strip()))
    # Patterns are never run in this process: Python's re has no timeout.
    spans, reason = find_spans([(pattern, prompt) for _id, pattern, prompt in prompt_checks],
                               LOAD_REGEX_BUDGET_SECONDS, limit=1)
    for (case_id, _pattern, _prompt), found in zip(prompt_checks, spans):
        if found is None:
            raise ValueError(f"Indicator regex in case {case_id} could not be checked against "
                             f"its test_input: evaluation {reason}.")
        # A target that only quotes the request back would be scored as a finding.
        if found:
            raise ValueError(f"Indicator regex in case {case_id} matches its own test_input; "
                             "a quoted request would count as a finding.")
    return cases, hashlib.sha256(data).hexdigest()


def _string_list(item: dict, key: str) -> tuple[str, ...]:
    """A bare string would be split into characters, and '' matches every response."""
    value = item.get(key, [])
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise ValueError(f"'{key}' in case {item['id']} must be a list of non-empty strings.")
    if len(value) > MAX_LIST_ITEMS:
        raise ValueError(f"'{key}' in case {item['id']} has more than {MAX_LIST_ITEMS} entries.")
    return tuple(value)
