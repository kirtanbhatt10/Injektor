"""Time-bounded evaluation of indicator regexes.

Python's ``re`` has no timeout, and a backtracking pattern can run for hours on a short text.
Patterns are therefore evaluated in a child interpreter, which is killed when the budget for
the call runs out.

What is bounded: wall-clock time per call, one child at a time, the number of jobs and the size
of the payload sent to the child (MAX_JOBS, MAX_PAYLOAD_BYTES; a call over either is refused
whole, not truncated), and the size of what the child sends back. The child writes one line of
at most ``limit`` spans per job and nothing else, and patterns cannot write to its output, so
that size is at most MAX_JOBS x (limit x MAX_SPAN_BYTES + 1) bytes, which find_spans checks
before starting the child. What is not bounded: the memory and the one CPU core the child may
use until it is killed. No memory limit is set on any platform.

The child is started without a shell from an argument list that holds no case-file content;
patterns and texts reach it on standard input only. subprocess.run kills it on timeout or on
an interrupt (TerminateProcess on Windows, SIGKILL elsewhere) and waits for it, so no child
outlives the call.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Sequence

# One budget per call, shared by every pattern in it. It includes starting the interpreter.
REGEX_BUDGET_SECONDS = 5.0
MAX_SPANS_PER_PATTERN = 200
# The largest legitimate call is the load-time check of a case file: 200 cases x 20 indicators.
MAX_JOBS = 5_000
# Size of the JSON sent to the child. A case file is capped at 1 MB, which stays far below this
# even when every character is written as a six-byte \uXXXX escape.
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
# A span is "[start, end]": two integers of at most 10 digits plus punctuation.
MAX_SPAN_BYTES = 28

Span = tuple[int, int]

# Standard library only, so the child can run isolated (-I -S) from the working directory,
# the environment and site-packages.
_CHILD = """
import json, re, sys
job = json.loads(sys.stdin.buffer.read())
for pattern, index in job["jobs"]:
    spans = []
    for match in re.finditer(pattern, job["texts"][index], re.I):
        if match.end() > match.start():
            spans.append(match.span())
            if len(spans) >= job["limit"]:
                break
    sys.stdout.write(json.dumps(spans) + "\\n")
    sys.stdout.flush()
"""


def find_spans(jobs: Sequence[tuple[str, str]], budget: float = REGEX_BUDGET_SECONDS,
               limit: int = MAX_SPANS_PER_PATTERN) -> tuple[list[list[Span] | None], str]:
    """Run each (pattern, text) job, case-insensitively, within one shared time budget.

    Returns the spans of the non-empty matches per job, in order, and a reason. A job that was
    not evaluated has ``None`` instead of a list, and the reason says why; the first ``None``
    is the job that was running when evaluation stopped. The reason is empty when every job
    finished.
    """
    if not jobs:
        return [], ""
    if not sys.executable:  # embedded interpreters may not know their own path
        return [None] * len(jobs), "needs a Python interpreter path, and sys.executable is empty"
    if len(jobs) > MAX_JOBS:
        return [None] * len(jobs), f"was refused: {len(jobs)} patterns is over the limit of {MAX_JOBS}"
    if len(jobs) * (limit * MAX_SPAN_BYTES + 1) > MAX_PAYLOAD_BYTES:
        return [None] * len(jobs), "was refused: the result could be larger than the output limit"
    texts = list(dict.fromkeys(text for _pattern, text in jobs))
    position = {text: index for index, text in enumerate(texts)}
    # ASCII JSON carries lone surrogates and every other code point through the pipe unchanged.
    payload = json.dumps({"texts": texts, "limit": limit,
                          "jobs": [[pattern, position[text]] for pattern, text in jobs]})
    if len(payload) > MAX_PAYLOAD_BYTES:
        return [None] * len(jobs), (f"was refused: the patterns and texts are {len(payload)} "
                                    f"bytes, over the limit of {MAX_PAYLOAD_BYTES}")
    reason = ""
    try:
        output = subprocess.run([sys.executable, "-I", "-S", "-c", _CHILD],
                                input=payload.encode("ascii"), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=budget,
                                # Windows only: no console window when the caller has none.
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        reason = f"exceeded the {budget:g}-second time budget"
    except (OSError, ValueError) as exc:
        output = b""
        reason = f"could not be run in a child interpreter ({type(exc).__name__})"
    results: list[list[Span] | None] = []
    # Only complete lines count: the child may have been killed in the middle of one.
    for line in output.split(b"\n")[:-1][:len(jobs)]:
        try:
            results.append([(int(start), int(end)) for start, end in json.loads(line)])
        except (ValueError, TypeError):
            break
    if len(results) < len(jobs):
        reason = reason or "failed in the child interpreter"
        results.extend([None] * (len(jobs) - len(results)))
    return results, reason
