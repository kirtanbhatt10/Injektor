from injector.config import AttackCase
from injector.detection import detect, score


def case():
    return AttackCase("x", "direct", "desc", "input", "safe", "high", ("CANARY",), ("secret phrase",))


def test_canary_is_confirmed():
    assert detect(case(), "oops canary")['outcome'] == "confirmed"


def test_regex_is_potential_and_clean_is_inconclusive():
    assert detect(case(), "secret phrase")['outcome'] == "potential"
    assert detect(case(), "I refuse")['outcome'] == "inconclusive"


def test_score_counts_outcomes():
    assert score([{"outcome": "confirmed"}, {"outcome": "potential"}])['indicator_score'] == 3
