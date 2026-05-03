"""Subprocess-based ATT&CK test runner.

Safety properties:
  * Runs only tests defined in catalog.json — no arbitrary command input
    is accepted from the API.
  * Only `bash` and `python3` executors run inside the worker (it is a
    Linux container). Windows/PowerShell tests can be inspected and
    converted to a downloadable script via `scripts.generate_script`,
    but never executed locally.
  * Hard wall-clock timeout per test.
  * stdout/stderr are captured (truncated) and returned to the caller.
"""
from __future__ import annotations

import platform
import shlex
import subprocess
import time
from dataclasses import dataclass

from .loader import TechniqueTest, get_test

RUNNABLE_EXECUTORS = {"bash", "sh", "python3"}
DEFAULT_TIMEOUT = 10
MAX_TIMEOUT = 30
MAX_OUTPUT = 32 * 1024  # 32KB cap per stream


@dataclass(frozen=True)
class RunResult:
    technique_id: str
    test_name: str
    executor: str
    command: str
    argv: tuple[str, ...]
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    truncated: bool


def _truncate(s: bytes) -> tuple[str, bool]:
    if len(s) <= MAX_OUTPUT:
        return s.decode("utf-8", errors="replace"), False
    return s[:MAX_OUTPUT].decode("utf-8", errors="replace") + "\n…[truncated]", True


def _resolve_argv(test: TechniqueTest) -> list[str]:
    if test.executor in ("bash", "sh"):
        return [test.executor, "-c", test.command]
    if test.executor == "python3":
        return ["python3", "-c", test.command]
    raise ValueError(f"executor {test.executor!r} is not runnable in this worker")


def run_test(
    technique_id: str,
    test_name: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> RunResult:
    found = get_test(technique_id, test_name)
    if found is None:
        raise LookupError(f"technique/test not found: {technique_id}/{test_name}")
    _, test = found

    if test.executor not in RUNNABLE_EXECUTORS:
        raise ValueError(
            f"executor {test.executor!r} cannot run on this worker — "
            f"use the script-generation endpoint to download a runnable script for the target platform"
        )

    sysname = platform.system().lower()
    host_platform = "macos" if sysname == "darwin" else sysname
    if host_platform not in test.platforms:
        raise ValueError(
            f"test {test_name!r} is for platforms {test.platforms} — host is {host_platform!r}"
        )

    timeout = max(1, min(timeout, MAX_TIMEOUT))
    argv = _resolve_argv(test)

    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 — argv constructed from catalog only
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout, stdout_trunc = _truncate(proc.stdout)
        stderr, stderr_trunc = _truncate(proc.stderr)
        exit_code = proc.returncode
        truncated = stdout_trunc or stderr_trunc
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = (
            (exc.stderr or b"").decode("utf-8", errors="replace")
            + f"\n…[timeout after {timeout}s]"
        )
        exit_code = -9
        truncated = True

    return RunResult(
        technique_id=technique_id,
        test_name=test_name,
        executor=test.executor,
        command=test.command,
        argv=tuple(argv),
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
    )
