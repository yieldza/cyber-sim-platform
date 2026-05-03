"""Generate downloadable scripts (.ps1, .sh, .bat, .py) from a technique test.

Used when a test targets a platform other than the worker host (e.g. all
Windows-only tests), or when an analyst wants to drop the script onto a
known test endpoint and run it under their own EDR-instrumented context.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .loader import TechniqueTest, get_test

SUPPORTED_SCRIPT_FORMATS = ("ps1", "sh", "bat", "py")
EXECUTOR_TO_FORMAT = {
    "powershell": "ps1",
    "cmd": "bat",
    "bash": "sh",
    "sh": "sh",
    "python3": "py",
}


def _header(technique_id: str, test: TechniqueTest, comment: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sigs = "\n".join(f"{comment}   - {s}" for s in test.expected_signals) or f"{comment}   (none recorded)"
    return (
        f"{comment} ─────────────────────────────────────────────────────────────────\n"
        f"{comment}  CSP — Cyber Sim Platform: ATT&CK simulation script\n"
        f"{comment}  Technique: {technique_id} / test: {test.name}\n"
        f"{comment}  Executor:  {test.executor}    Platforms: {', '.join(test.platforms)}\n"
        f"{comment}  Generated: {ts}\n"
        f"{comment}\n"
        f"{comment}  Description: {test.description}\n"
        f"{comment}  Expected detections (configure your SIEM/EDR for these):\n"
        f"{sigs}\n"
        f"{comment}\n"
        f"{comment}  SAFETY: this script runs benign telemetry-emitting commands only.\n"
        f"{comment}  Run on systems you own or are authorized to test.\n"
        f"{comment} ─────────────────────────────────────────────────────────────────\n"
    )


def generate_script(technique_id: str, test_name: str) -> tuple[str, str, str]:
    """Return (filename, mime, content) for a downloadable script."""
    found = get_test(technique_id, test_name)
    if found is None:
        raise LookupError(f"technique/test not found: {technique_id}/{test_name}")
    _, test = found

    fmt = EXECUTOR_TO_FORMAT.get(test.executor)
    if fmt is None:
        raise ValueError(f"no script format for executor {test.executor!r}")

    safe_id = technique_id.replace(".", "_")
    safe_name = test.name.replace(" ", "_")
    filename = f"{safe_id}__{safe_name}.{fmt}"

    if fmt == "ps1":
        body = (
            _header(technique_id, test, "#")
            + "\n$ErrorActionPreference = 'Continue'\n"
            + "Write-Host '[CSP] starting:' '"
            + technique_id + "/" + test.name + "'\n"
            + test.command + "\n"
            + ("\n# cleanup\n" + test.cleanup + "\n" if test.cleanup else "")
            + "Write-Host '[CSP] done.'\n"
        )
        mime = "application/octet-stream"
    elif fmt == "bat":
        body = (
            _header(technique_id, test, "REM")
            + "\n@echo off\n"
            + f"echo [CSP] starting: {technique_id}/{test.name}\n"
            + test.command + "\n"
            + (test.cleanup + "\n" if test.cleanup else "")
            + "echo [CSP] done.\n"
        )
        mime = "application/octet-stream"
    elif fmt == "sh":
        body = (
            "#!/usr/bin/env bash\n"
            + _header(technique_id, test, "#")
            + "\nset -u\n"
            + f"echo '[CSP] starting: {technique_id}/{test.name}'\n"
            + test.command + "\n"
            + (test.cleanup + "\n" if test.cleanup else "")
            + "echo '[CSP] done.'\n"
        )
        mime = "text/x-shellscript"
    elif fmt == "py":
        body = (
            "#!/usr/bin/env python3\n"
            + _header(technique_id, test, "#")
            + "\nimport subprocess, sys\n"
            + f"print('[CSP] starting: {technique_id}/{test.name}')\n"
            + f"subprocess.run({test.command!r}, shell=True, check=False)\n"
            + (f"subprocess.run({test.cleanup!r}, shell=True, check=False)\n" if test.cleanup else "")
            + "print('[CSP] done.')\n"
        )
        mime = "text/x-python"
    else:
        raise AssertionError("unreachable")

    return filename, mime, body
