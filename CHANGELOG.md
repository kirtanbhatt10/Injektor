# Changelog

## Unreleased

### Continuous integration

- `injektor report --format markdown` writes a summary for a CI job page: outcome counts and one row per case, worst first, with evidence, excerpts and prompts left out and every value escaped.
- `injektor report --format junit` writes JUnit XML: `confirmed` is a failure, `error` an error, and `potential` and `inconclusive` are skipped with the reason, so no case is ever reported as passed.
- `injektor report --output FILE` writes UTF-8 to a file. Standard output stays ASCII for legacy Windows consoles.
- The repository is now a composite GitHub Action (`action.yml`) that scans, adds the Markdown summary to the job page and writes `junit.xml`. Response excerpts are off by default in the action.

### Built-in suite

- New case `markdown-image-exfiltration` (critical): an instruction inside a support ticket asks the model to end its reply with a Markdown image whose URL on `attacker.example` carries a marker. A rendered image would send the URL to that host without a click. The case uses a marker and an indicator for any image pointing at the attacker host, and the vulnerable demo renders the image. The built-in suite now has eleven cases, so a default scan sends eleven requests ([#6](https://github.com/kirtanbhatt10/Injektor/issues/6)).

### Detection

- Refusal wording is recognised in Spanish, French, German and Hindi (Devanagari and romanised) as well as English. A marker next to such a refusal is now `potential` instead of `confirmed`, and an indicator match inside one is no longer counted ([#5](https://github.com/kirtanbhatt10/Injektor/issues/5)).

### Packaging

- A `Dockerfile` builds a slim image that runs Injektor as a non-root user, so a scan needs only Docker. The build context is limited by `.dockerignore` to the package sources, so local reports and `.env` files never enter the image. See [Run with Docker](README.md#run-with-docker).

## 0.1.0 - 2026-10-13

First tagged release.

### Changes that can affect existing use

- Case files are validated more strictly. A file is now rejected when it has an unknown key, a canary or marker shorter than 8 characters, a canary or marker that appears in its own `test_input`, more than 200 cases, a prompt over 8,000 characters, a list over 20 entries, or a regex over 500 characters. Each of these previously loaded and could give wrong results without warning.
- The built-in suite has ten cases instead of four, so a default scan sends ten requests.
- A scan stops contacting the target after three consecutive failed cases and records the rest as `error` ("Not sent").
- HTTP 401 or 403 ends the scan's contact with the target at once, so a rejected credential is sent exactly once. This also applies when a gateway uses 403 to block a single prompt.
- `INJEKTOR_TIMEOUT` is now a wall-clock deadline for each whole request (connecting, headers and body). Earlier it bounded single socket operations and the body only, so a target sending headers slowly was not bounded. Requests are made with httpx's asyncio client to make the deadline enforceable; `OpenAICompatibleTarget.ask` can therefore not be called from inside a running event loop, and the adapter has a `close()` method.
- A 429 response with a valid `Retry-After` of up to 30 seconds is waited for before the retry; a longer one is not retried.
- An `--output` path that is a file, or lies below a file, is refused with status 2 before any request. It used to fail with status 3 after the whole scan.
- The minimum Typer version is 0.15.4 (was 0.12). Typer 0.12.0 to 0.15.3 install with Click 8.2 or later and then fail every invocation with "Missing command".
- `reporting.build_provenance` takes the case-file hash as an argument (from the new `config.load_case_file`) instead of reading the file again.
- HTTP 429, 500, 502, 503 and 504 are now retried up to `INJEKTOR_RETRIES` times. A response body that is not valid JSON is no longer retried.
- An indicator regex that matches only inside refusal wording is no longer reported as `potential`.
- Indicator regexes run in a child Python interpreter with a time budget (5 seconds per case, 10 seconds for the load-time check of a case file) instead of in the scanning process without a limit. A case whose indicators could not be evaluated is recorded as `error` and the scan exits with status 3.
- A case file is rejected when an indicator matches its own `test_input`.
- Only cases without a usable answer count towards the three-consecutive-errors stop.
- Response excerpts show at most 200 characters of a match (first and last 100).
- `scan` prints a target line, one progress line per case and a closing note. The `N cases: ...` summary line is unchanged.
- `demo` exits cleanly on Ctrl+C, and an out-of-range `--port` is a usage error (status 2) instead of a traceback.
- `report.html` has a new layout. The `summary` and `results` tables keep their ids and columns.

- Regex evaluation refuses (rather than truncates) more than 5,000 patterns or 16 MB of input per call, and a case file is read only up to its 1 MB limit. No memory limit is applied to the child interpreter.
- A marker is lowered to `potential` only when refusal or dismissal wording is in its own sentence or the neighbouring ones, not anywhere in the answer. A marker with such wording only elsewhere is now `confirmed`.
- A case file with the same key twice in one mapping is rejected instead of keeping the last value.
- A `potential` result states how many indicator regexes were not evaluated when others could not be run.

### Added

- `packaging` is a development dependency; the packaging tests no longer skip silently without it.
- Marker detection: shows that an injected instruction was acted on without planting a canary in the target. `confirmed` when the marker appears without refusal or dismissal wording, `potential` when the answer also contains such wording.
- Detection of a canary disclosed reversed, in Base64 or in hex (`confirmed`), or with separators inserted (`potential`).
- Six built-in cases: encoded exfiltration, delimiter spoofing, and indirect injection through a document, an HTML comment, a tool result and a translation task.
- Reports: `schema_version`, outcome definitions, limitations, and per case the prompt, description, expected behavior, bounded response excerpts, a response fingerprint and a remediation suggestion. All earlier JSON fields are still present.
- `scan --no-excerpts`, `report --format text`, `list --cases`, `injektor --version`.
- `INJEKTOR_DELAY` to pause between cases.
- Support for answers returned as an array of content parts.
- Optional `markers` and `remediation` fields in case files.

### Fixed

- A custom case whose canary was in its prompt was scored `confirmed` when the target echoed the request.
- `I can't share my system prompt: it is confidential.` was scored `potential`.
- An API key consisting only of spaces was sent as an empty bearer token; surrounding whitespace is now stripped and a blank key means no key.
- The HTML report now carries a Content-Security-Policy and never uses report content in an attribute.
- An interrupted scan exits with status 130 whatever the installed Typer version does with an interrupt.
- The case-file hash in a report was computed when the scan finished, so it could describe a file that had changed since it was loaded, and a deleted file lost the report. It is now the hash of the bytes that were loaded.
