"""Regression test for the em-dash mojibake bug (v0.7.1).

Symptom: PowerShell on Windows reads .ps1 files using the system ANSI
codepage by default. UTF-8 em-dash (0xE2 0x80 0x94) becomes 'â€"',
where the literal '"' inside that triplet prematurely closes any
PowerShell double-quoted string that contained it. The result is a
cascade of parser errors and the agent fails to start at all.

To stay safe across all locales, the agent scripts MUST be ASCII-clean.
This test enforces that constraint at CI time.

Other risky scripts in scope:
- .cmd launcher (cmd.exe also uses an OEM codepage)
- C# source (csc handles UTF-8 fine, but Console output mojibakes)
- bash scripts shipped to operators (mostly fine, but keep them grep-able)
"""
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]

# Files that MUST be pure ASCII because they're consumed by Windows
# tooling that defaults to ANSI / OEM codepages.
ASCII_ONLY = [
    "agent/powershell/csp-agent.ps1",
    "agent/powershell/csp-agent.cmd",
    "agent/csharp/CspAgent.cs",
    "agent/python/csp_agent.py",
    "scripts/build-and-push.sh",
]


@pytest.mark.parametrize("relpath", ASCII_ONLY)
def test_agent_script_is_ascii_clean(relpath):
    p = REPO_ROOT / relpath
    raw = p.read_bytes()
    # Locate the first non-ASCII byte for a clear error message.
    for i, b in enumerate(raw):
        if b > 0x7F:
            # Print a small surrounding window to aid debugging.
            start = max(0, i - 20)
            end = min(len(raw), i + 20)
            snippet = raw[start:end].decode("utf-8", errors="replace")
            pytest.fail(
                f"{relpath}: non-ASCII byte 0x{b:02X} at offset {i}\n"
                f"  context: ...{snippet!r}...\n"
                f"  Windows tooling (PowerShell, cmd.exe) reads these files "
                f"in ANSI/OEM codepage and will mojibake the character, "
                f"breaking string terminators. Use ASCII only."
            )


# PowerShell reserves a set of names as "common parameters" — they're
# attached to every advanced function/script automatically. Declaring a
# param block parameter with one of these names produces:
#   "A parameter with the name 'X' was defined multiple times for the command."
# and the script exits with code 1 before any line of body code runs.
#
# Source: about_CommonParameters — the full list as of PS 7.x.
POWERSHELL_RESERVED = {
    "Verbose", "Debug", "ErrorAction", "WarningAction", "InformationAction",
    "ErrorVariable", "WarningVariable", "InformationVariable",
    "OutVariable", "OutBuffer", "PipelineVariable",
    "WhatIf", "Confirm",
}

def test_ps1_param_block_avoids_reserved_names():
    """Regression guard for v0.7.2 — '$Verbose' shadowing -Verbose."""
    import re
    p = REPO_ROOT / "agent/powershell/csp-agent.ps1"
    text = p.read_text(encoding="utf-8")
    # Grab the contiguous param(...) block at the top of the script.
    m = re.search(r"param\s*\((.*?)\)", text, flags=re.DOTALL)
    assert m, "could not locate param(...) block in csp-agent.ps1"
    block = m.group(1)
    # Match `$Foo` after a type cast like `[switch]` / `[string]` etc.
    names = re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\b", block)
    clashes = [n for n in names if n in POWERSHELL_RESERVED]
    assert not clashes, (
        f"csp-agent.ps1 param block declares PowerShell-reserved names: "
        f"{clashes}. Rename them (e.g. $Verbose -> $VerboseLog). "
        f"PowerShell auto-attaches -Verbose / -Debug / etc as common "
        f"parameters; declaring them again throws "
        f"'parameter ... was defined multiple times for the command' "
        f"and the script exits before any body code runs."
    )
