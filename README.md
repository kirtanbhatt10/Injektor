# Injector

Injector is an open-source CLI harness for running a controlled set of prompt-injection checks against an explicitly configured OpenAI-compatible endpoint. Outcomes are heuristic indicators, not proof of security or insecurity. Only assess systems you own or are authorized to test.

## Install

Requires Python 3.10 or newer.

```sh
python -m venv .venv
# Activate the environment, then:
pip install -e ".[dev]"
```

## Local demo (no API key)

The demo is intentionally vulnerable by default. It uses only a synthetic canary and binds only to loopback. Never expose it to a network.

Terminal 1:

```sh
injector demo --mode vulnerable
```

Terminal 2 (PowerShell):

```powershell
$env:INJECTOR_ENDPOINT = "http://127.0.0.1:8765/v1/chat/completions"
$env:INJECTOR_MODEL = "injector-demo"
injector scan --output reports
injector report reports/report.json
```

Compare safe mode by restarting the server with `injector demo --mode safe` and running the scan again. Vulnerable mode should report four `confirmed` outcomes and safe mode four `inconclusive` outcomes. Demo host and port can be changed; host must remain loopback (`127.0.0.1`, `localhost`, or `::1`).

## Commands

```text
injector list
injector scan [--cases PATH] [--output DIR]
injector report PATH
injector demo [--mode vulnerable|safe] [--host 127.0.0.1] [--port 8765]
```

For an external target, explicitly set `INJECTOR_ENDPOINT` and `INJECTOR_MODEL`. Non-local HTTP is rejected; use HTTPS. Credentials are read only from the environment variable named by `INJECTOR_API_KEY_ENV` (default `INJECTOR_API_KEY`). Timeout is capped at 120 seconds and bounds both each socket operation and the total time spent reading one response body. Retries are capped at 3, response bodies at 1 MB, and the scanner sends requests sequentially. Redirects are never followed, and proxy environment variables are ignored. Plain HTTP is accepted only for the literal hosts `localhost`, `127.0.0.1`, and `::1`; HTTPS targets are not restricted by address, so an internal gateway can be assessed when you are authorized to do so. Do not point it at an endpoint you are not authorized to assess.

Reports include response-derived matched evidence only; they do not save complete model outputs, request headers, API keys, or environment values. Custom YAML case content is untrusted and should be reviewed before use.

## Findings and judge interface

Exact synthetic canary matches are `confirmed`; configured regex matches are `potential`; no match is `inconclusive`. A refusal alone is not considered a success.

A canary is a secret that you plant in the hidden context of the system under test (the demo server does this for you). It is never sent in a test prompt, because a target that merely quoted the request back would then be scored as a confirmed leak. To assess your own application, add a unique canary string to its system prompt and list the same string under `canaries` in a custom case file. Without a planted canary, only the regex indicators can match. The library exposes an optional caller-supplied judge callback, but it is never enabled by the CLI. LLM judges can be inconsistent, manipulated by the response being judged, and incur extra cost; judge findings are heuristic only.

The aggregate indicator score weights confirmed matches twice and potential matches once. It is a prioritization aid, not a calibrated risk score or security certification.

## Development

```sh
pip install -e ".[dev]"
pytest
ruff check .
```

Tests need no paid API credentials. HTTP behavior is covered with an in-process mock transport, and `tests/test_demo.py` scans the real demo server on an ephemeral loopback port; those tests are skipped if the environment forbids binding a local socket.
