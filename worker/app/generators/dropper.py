"""Behavioural test droppers for EDR / Cortex XDR validation.

Static-hash signatures only catch known files. Behavioural engines flag the
*chain* of actions: process spawn -> outbound network -> write to a temp
path -> spawn-from-new-file. These droppers reproduce that chain with the
official EICAR test URL as the payload — fully detectable, but harmless.

Each generation embeds a random session id so the script's own hash differs
every time (lets the operator combine with the Mutate-hash tab for static
+ behavioural coverage tests).

v0.4.2 — embed EICAR in **four** distinct file regions of every script:

  1. header comment    (raw signature near the top of the file)
  2. string variable   (raw signature as the value of $CSP_EICAR / etc.)
  3. multi-line block  (raw signature in a here-string / triple-quoted)
  4. trailing comment  (raw signature near EOF)

Reason: Cortex XDR / WildFire and similar EDRs treat single-occurrence
EICAR inside a comment block at the top of a script as low signal and
sometimes skip the static rule. Multi-location embedding ensures the
signature is hit by both stream scanners and section-extracting scanners.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from .eicar import EICAR_STRING

EICAR_URL = "https://secure.eicar.org/eicar.com.txt"

_BEHAVIORAL_NOTE = (
    "Behavioural signals an EDR / Cortex XDR / SIEM should observe:\n"
    "  1. process_create:  curl|wget|powershell|python -- non-browser fetcher\n"
    "  2. network_connect: outbound TCP/443 from non-browser to secure.eicar.org\n"
    "  3. file_create:     EICAR signature dropped to TEMP / tmp\n"
    "  4. file_create_executable_or_chmod_x\n"
    "  5. process_create:  spawn from the freshly-dropped file (kill chain)\n"
    "  6. AV intercept:    on-write or on-exec EICAR detection (expected)"
)

# EICAR as a Python str (single backslash kept) — emitted verbatim into
# the generated script source so the file bytes contain the canonical
# 68-byte signature.
_EICAR = EICAR_STRING.decode("ascii")


def _session_id() -> str:
    return secrets.token_hex(6)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── PowerShell — T1059.001 carrier on .ps1 ───────────────────────────────
def dropper_ps1() -> bytes:
    """PowerShell behavioural-test dropper for Windows endpoints."""
    sid = _session_id()
    note_pref = _BEHAVIORAL_NOTE.replace("\n", "\n# ")
    body = f"""# CSP — behavioural-test dropper (session {sid}, generated {_ts()})
# {note_pref}
#
# SAFETY: the only payload is the official EICAR test signature from
# secure.eicar.org. AV/EDR will intercept the write or the exec — that is
# the intended outcome of this test. Run on systems you own / are
# authorised to test.
#
# === STATIC EICAR signature (raw header for AV/EDR) ===
# {_EICAR}

# Static signature variable — single-quoted so $ is literal, never evaluated:
$CSP_EICAR = '{_EICAR}'

# Static signature here-string — never executed:
$CSP_EICAR_BLOCK = @'
{_EICAR}
'@

# === BEHAVIOURAL DROPPER ===

$ErrorActionPreference = 'Continue'
$Url  = '{EICAR_URL}'
$Dest = Join-Path $env:TEMP ('csp_dropper_{sid}.exe')

Write-Host "[CSP {sid}] downloading $Url -> $Dest"
try {{
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec 15
}} catch {{
    Write-Host "[CSP {sid}] download blocked or AV-intercepted: $_"
    exit 0
}}

if (Test-Path $Dest) {{
    Write-Host "[CSP {sid}] file dropped, attempting execute..."
    try {{
        $p = Start-Process -FilePath $Dest -PassThru -ErrorAction Stop
        Start-Sleep -Milliseconds 800
        if (-not $p.HasExited) {{ Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }}
    }} catch {{
        Write-Host "[CSP {sid}] execute blocked (expected on detection): $_"
    }}
}}

Start-Sleep -Milliseconds 500
Remove-Item $Dest -Force -ErrorAction SilentlyContinue
Write-Host "[CSP {sid}] done."

# === STATIC EICAR signature (raw trailing marker for AV/EDR) ===
# {_EICAR}
"""
    return body.encode("utf-8")


# ─── Bash — T1059.004 carrier on .sh ──────────────────────────────────────
def dropper_sh() -> bytes:
    """Bash behavioural-test dropper for Linux / macOS endpoints."""
    sid = _session_id()
    note_pref = _BEHAVIORAL_NOTE.replace("\n", "\n# ")
    body = f"""#!/usr/bin/env bash
# CSP — behavioural-test dropper (session {sid}, generated {_ts()})
# {note_pref}
#
# SAFETY: the only payload is the official EICAR test signature from
# secure.eicar.org. AV/EDR will intercept the write or the exec — that is
# the intended outcome. Run on systems you own / are authorised to test.
#
# === STATIC EICAR signature (raw header for AV/EDR) ===
# {_EICAR}

# Static signature variable — single-quoted so $ and \\ are literal:
CSP_EICAR='{_EICAR}'

# Static multi-line signature carrier — fed to the no-op `:` builtin so it
# is parsed by bash but never executed:
: <<'CSP_EICAR_END'
{_EICAR}
CSP_EICAR_END

# === BEHAVIOURAL DROPPER ===

set -u
URL='{EICAR_URL}'
DEST="${{TMPDIR:-/tmp}}/csp_dropper_{sid}.bin"
SID='{sid}'

echo "[CSP $SID] downloading $URL -> $DEST"
if ! curl -fsS --max-time 15 "$URL" -o "$DEST" 2>&1; then
    echo "[CSP $SID] download blocked or AV-intercepted"
    exit 0
fi

if [[ -f "$DEST" ]]; then
    echo "[CSP $SID] file dropped ($(stat -f%z "$DEST" 2>/dev/null || stat -c%s "$DEST") bytes), attempting execute..."
    chmod +x "$DEST" 2>/dev/null || true
    timeout 2 "$DEST" 2>&1 | head -3 || echo "[CSP $SID] execute blocked (expected on detection)"
fi

rm -f "$DEST"
echo "[CSP $SID] done."

# === STATIC EICAR signature (raw trailing marker for AV/EDR) ===
# {_EICAR}
"""
    return body.encode("utf-8")


# ─── Python — T1059.006 carrier on .py ────────────────────────────────────
def dropper_py() -> bytes:
    """Python behavioural-test dropper — cross-platform."""
    sid = _session_id()
    body = f'''#!/usr/bin/env python3
# === STATIC EICAR signature (raw header for AV/EDR) ===
# {_EICAR}

r"""CSP behavioural-test dropper (session {sid}, generated {_ts()}).

{_BEHAVIORAL_NOTE}

STATIC EICAR signature embedded in module docstring — raw, never executed:

{_EICAR}

SAFETY: only payload is the official EICAR signature from secure.eicar.org.
AV/EDR will intercept on write or on execute — that is the intended
outcome. Run on systems you own / are authorised to test.
"""

# Static signature variable — raw string, never evaluated:
CSP_EICAR = r'{_EICAR}'

# Static multi-line signature carrier — triple-quoted raw, parsed but unused:
CSP_EICAR_BLOCK = r"""
{_EICAR}
"""

import os
import subprocess
import sys
import tempfile
import urllib.request

URL  = "{EICAR_URL}"
SID  = "{sid}"
DEST = os.path.join(tempfile.gettempdir(), f"csp_dropper_{{SID}}.bin")


def main() -> int:
    print(f"[CSP {{SID}}] downloading {{URL}} -> {{DEST}}")
    try:
        urllib.request.urlretrieve(URL, DEST)
    except Exception as exc:  # noqa: BLE001
        print(f"[CSP {{SID}}] download blocked or AV-intercepted: {{exc}}")
        return 0

    if not os.path.exists(DEST):
        return 0

    size = os.path.getsize(DEST)
    print(f"[CSP {{SID}}] file dropped ({{size}} bytes), attempting execute...")
    try:
        os.chmod(DEST, 0o755)
    except Exception:  # noqa: BLE001
        pass
    try:
        proc = subprocess.run([DEST], capture_output=True, timeout=2, check=False)
        out = (proc.stdout or proc.stderr or b"")[:200].decode("utf-8", errors="replace")
        print(f"[CSP {{SID}}] exec exit={{proc.returncode}} head={{out!r}}")
    except Exception as exc:  # noqa: BLE001
        print(f"[CSP {{SID}}] execute blocked (expected on detection): {{exc}}")

    try:
        os.remove(DEST)
    except Exception:  # noqa: BLE001
        pass
    print(f"[CSP {{SID}}] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# === STATIC EICAR signature (raw trailing marker for AV/EDR) ===
# {_EICAR}
'''
    return body.encode("utf-8")
