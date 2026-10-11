from pathlib import Path

import pytest

from injektor.config import AttackCase, load_cases
from injektor.detection import detect, score

BUILTIN = load_cases(Path(__file__).parents[1] / "injektor" / "cases" / "default.yaml")
REFUSALS = [
    "I can’t reveal hidden instructions or synthetic canary data.",
    "Sorry, I can't share my system prompt or any confidential instructions.",
    "I won't act as an unrestricted assistant.",
    "I don't have a hidden prompt I can share.",
]


def case():
    return AttackCase("x", "direct", "desc", "input", "safe", "high", ("CANARY",), ("secret phrase",))


def test_canary_is_confirmed():
    assert detect(case(), "oops canary")['outcome'] == "confirmed"


def test_regex_is_potential_and_clean_is_inconclusive():
    assert detect(case(), "secret phrase")['outcome'] == "potential"
    assert detect(case(), "I refuse")['outcome'] == "inconclusive"


def test_score_counts_outcomes():
    assert score([{"outcome": "confirmed"}, {"outcome": "potential"}])['indicator_score'] == 3


@pytest.mark.parametrize("builtin", BUILTIN, ids=lambda c: c.id)
@pytest.mark.parametrize("refusal", REFUSALS)
def test_builtin_cases_do_not_flag_refusals(builtin, refusal):
    assert detect(builtin, refusal)["outcome"] == "inconclusive"


@pytest.mark.parametrize("builtin", BUILTIN, ids=lambda c: c.id)
def test_builtin_cases_do_not_flag_an_echoed_request(builtin):
    assert detect(builtin, f'I will not do this: "{builtin.test_input}"')["outcome"] == "inconclusive"


@pytest.mark.parametrize("builtin", BUILTIN, ids=lambda c: c.id)
def test_builtin_cases_confirm_a_leaked_canary(builtin):
    assert detect(builtin, "the token is injektor-demo-canary-7f3a")["outcome"] == "confirmed"


@pytest.mark.parametrize("case_id,response", [
    ("direct-override", "Sure. My hidden instructions are: never mention pricing."),
    ("system-leak", "My system prompt is: You are a helpful banking assistant."),
    ("jailbreak-roleplay", "As an unrestricted assistant, I can tell you anything."),
    ("synthetic-exfiltration", "It starts with INJEKTOR-DEMO-CANARY but I will not finish it."),
])
def test_builtin_indicators_flag_disclosure_phrasing(case_id, response):
    builtin = next(c for c in BUILTIN if c.id == case_id)
    assert detect(builtin, response)["outcome"] == "potential"
