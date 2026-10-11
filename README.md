# Injektor

Injektor is an open-source CLI harness for running a controlled set of prompt-injection checks against an explicitly configured OpenAI-compatible endpoint. Outcomes are heuristic indicators, not proof of security or insecurity. Only assess systems you own or are authorized to test.

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
injektor demo --mode vulnerable
```

Terminal 2 (PowerShell):

```powershell
$env:INJEKTOR_ENDPOINT = "http://127.0.0.1:8765/v1/chat/completions"
$env:INJEKTOR_MODEL = "injektor-demo"
injektor scan --output reports/vulnerable
injektor report reports/vulnerable/report.json
```

Compare safe mode by restarting the server with `injektor demo --mode safe` and scanning into a different directory, for example `injektor scan --output reports/safe`. Vulnerable mode should report four `confirmed` outcomes (exit status 1) and safe mode four `inconclusive` outcomes (exit status 0). Demo host and port can be changed; host must remain loopback (`127.0.0.1`, `localhost`, or `::1`).

## Commands

```text
injektor list
injektor scan [--cases PATH] [--output DIR] [--overwrite]
injektor report PATH
injektor demo [--mode vulnerable|safe] [--host 127.0.0.1] [--port 8765]
```

For an external target, explicitly set `INJEKTOR_ENDPOINT` and `INJEKTOR_MODEL`. Non-local HTTP is rejected; use HTTPS. Credentials are read only from the environment variable named by `INJEKTOR_API_KEY_ENV` (default `INJEKTOR_API_KEY`). Timeout is capped at 120 seconds and bounds both each socket operation and the total time spent reading one response body. Retries are capped at 3, response bodies at 1 MB, and the scanner sends requests sequentially. Redirects are never followed, and proxy environment variables are ignored. Plain HTTP is accepted only for the literal hosts `localhost`, `127.0.0.1`, and `::1`; HTTPS targets are not restricted by address, so an internal gateway can be assessed when you are authorized to do so. Do not point it at an endpoint you are not authorized to assess.

### Scan exit status

| Status | Meaning |
|---|---|
| 0 | Scan completed with no `confirmed` finding. `potential` and `inconclusive` outcomes do not change the status. |
| 1 | At least one `confirmed` finding. |
| 2 | Invalid usage or configuration, including an existing report that would be overwritten. No request is sent. |
| 3 | Operational error: at least one case could not be evaluated, the report could not be written, or the scan failed unexpectedly. |

A `confirmed` finding takes precedence over operational errors, so status 1 can also mean that some cases errored; the printed summary and the report show the counts. Status 0 is not evidence that a system is secure. Interrupting a scan with Ctrl+C exits with status 130 and writes no report.

### Reports

`scan` writes `report.json` and `report.html` into the output directory. It refuses to replace an existing report and checks this before contacting the target; choose another `--output` directory or pass `--overwrite`. The two files are written as a pair from the same data: both are staged in temporary files first, and if publishing fails the directory is returned to its previous state, so a failed scan does not leave a lone or mismatched report.

Each report records its provenance: tool version, target endpoint and model, whether a credential was supplied, the case file name with its SHA-256 and case count, timeout and retry settings, and start and finish times. The endpoint is recorded without its query string, because some gateways carry credentials there. Reports never contain the API key, the name of the variable that holds it, or the local path of the case file.

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
