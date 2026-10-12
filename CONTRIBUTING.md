# Contributing to Injektor

Thanks for your interest in improving Injektor!

## Getting set up

```bash
git clone https://github.com/kirtanbhatt10/Injektor.git
cd Injektor
python -m venv .venv
# Activate the environment, then:
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check .
pytest
```

Both must pass; CI runs the same checks on every push and pull request.

## Guidelines

- **Keep it safe.** Never add features that store API keys, full model outputs or environment values in reports, and keep the demo server loopback-only.
- **New test cases** go in YAML. Canaries must never appear in `test_input`, and indicators should match disclosure phrasing rather than refusal wording.
- **Add tests** for any behaviour change. Tests must not require paid API credentials.
- Keep pull requests focused and describe *why* the change is needed.

## Reporting bugs and ideas

Open an issue with steps to reproduce, the expected result and what actually happened. For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead.
