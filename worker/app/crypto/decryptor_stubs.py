"""Generate runnable decryptor scripts for EDR / XDR test workflows.

Each stub embeds:
  - the ciphertext as base64,
  - the key (and iv for AES) as base64,
  - decryption code that writes the plaintext to disk.

Operators drop the encrypted blob + decryptor stub onto a test endpoint;
EDR / Cortex XDR should observe the runtime decryption chain:

  process_create (powershell.exe / python.exe) ->
    file_read (the encrypted blob, if not embedded) ->
    in-memory decrypt loop ->
    file_create (plaintext output) ->
    (operator may then spawn the dropped plaintext to extend the chain).

Supported languages:

  ps1   PowerShell. xor-16 uses stdlib bitwise XOR; aes-128-cbc uses
        System.Security.Cryptography.Aes (stdlib on every Windows host).

  py    Python 3. xor-16 uses stdlib only. aes-128-cbc requires the
        `cryptography` package on the target — the stub falls back to a
        clear error message if the import fails.

  bat   Windows .cmd launcher that re-invokes powershell.exe with
        ExecutionPolicy Bypass on the produced .ps1 (so the operator can
        double-click on Windows without ExecutionPolicy fights). Generated
        as a sibling file when lang='bat' is requested.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone

SUPPORTED_LANGS = ("ps1", "py", "bat")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decryptor_script(
    ciphertext: bytes,
    key: bytes,
    algo: str = "xor-16",
    iv: bytes = b"",
    lang: str = "ps1",
    output_filename: str = "decrypted.bin",
) -> bytes:
    """Render a runnable decryptor script for the given algorithm + language."""
    if lang not in SUPPORTED_LANGS:
        raise ValueError(f"lang must be one of {SUPPORTED_LANGS}, got {lang!r}")
    if algo not in ("xor-16", "aes-128-cbc"):
        raise ValueError(f"unknown algo: {algo}")

    if lang == "ps1":
        return _ps1(ciphertext, key, algo, iv, output_filename)
    if lang == "py":
        return _py(ciphertext, key, algo, iv, output_filename)
    if lang == "bat":
        return _bat(ciphertext, key, algo, iv, output_filename)
    raise AssertionError("unreachable")  # pragma: no cover


# ─── PowerShell ────────────────────────────────────────────────────────────
def _ps1(ct: bytes, key: bytes, algo: str, iv: bytes, out_name: str) -> bytes:
    ct_b64 = _b64(ct)
    key_b64 = _b64(key)
    iv_b64 = _b64(iv)
    if algo == "xor-16":
        body = f"""# CSP decryptor stub — algo=xor-16  generated={_ts()}
# Restores the embedded ciphertext to plaintext on disk.
$Ciphertext = '{ct_b64}'
$KeyB64     = '{key_b64}'
$OutName    = '{out_name}'

$ct  = [Convert]::FromBase64String($Ciphertext)
$key = [Convert]::FromBase64String($KeyB64)
$plain = New-Object byte[] $ct.Length
for ($i = 0; $i -lt $ct.Length; $i++) {{
    $plain[$i] = $ct[$i] -bxor $key[$i % $key.Length]
}}
[System.IO.File]::WriteAllBytes($OutName, $plain)
Write-Host "[CSP-dec] xor-16: wrote $($plain.Length) bytes -> $OutName"
"""
    else:  # aes-128-cbc
        body = f"""# CSP decryptor stub — algo=aes-128-cbc  generated={_ts()}
# Restores the embedded ciphertext to plaintext on disk.
$Ciphertext = '{ct_b64}'
$KeyB64     = '{key_b64}'
$IVB64      = '{iv_b64}'
$OutName    = '{out_name}'

$ct  = [Convert]::FromBase64String($Ciphertext)
$key = [Convert]::FromBase64String($KeyB64)
$iv  = [Convert]::FromBase64String($IVB64)

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Mode = 'CBC'
$aes.Padding = 'PKCS7'
$aes.Key = $key
$aes.IV  = $iv
$dec = $aes.CreateDecryptor()
$plain = $dec.TransformFinalBlock($ct, 0, $ct.Length)
$dec.Dispose(); $aes.Dispose()

[System.IO.File]::WriteAllBytes($OutName, $plain)
Write-Host "[CSP-dec] aes-128-cbc: wrote $($plain.Length) bytes -> $OutName"
"""
    return body.encode("utf-8")


# ─── Python ────────────────────────────────────────────────────────────────
def _py(ct: bytes, key: bytes, algo: str, iv: bytes, out_name: str) -> bytes:
    ct_b64 = _b64(ct)
    key_b64 = _b64(key)
    iv_b64 = _b64(iv)
    if algo == "xor-16":
        body = f'''#!/usr/bin/env python3
"""CSP decryptor stub — algo=xor-16  generated={_ts()}.

Restores the embedded ciphertext to plaintext on disk. Zero deps.
"""
import base64, sys

CT  = "{ct_b64}"
KEY = base64.b64decode("{key_b64}")
OUT = "{out_name}"

ct = base64.b64decode(CT)
plain = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(ct))
with open(OUT, "wb") as f:
    f.write(plain)
print(f"[CSP-dec] xor-16: wrote {{len(plain)}} bytes -> {{OUT}}")
'''
    else:  # aes-128-cbc
        body = f'''#!/usr/bin/env python3
"""CSP decryptor stub — algo=aes-128-cbc  generated={_ts()}.

Requires the `cryptography` package on the target endpoint.
Install with:   pip install cryptography
"""
import base64, sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
except Exception as exc:
    sys.stderr.write(f"[CSP-dec] missing cryptography package: {{exc}}\\n")
    sys.stderr.write("           install: pip install cryptography\\n")
    sys.exit(2)

CT  = "{ct_b64}"
KEY = base64.b64decode("{key_b64}")
IV  = base64.b64decode("{iv_b64}")
OUT = "{out_name}"

ct = base64.b64decode(CT)
cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
dec = cipher.decryptor()
padded = dec.update(ct) + dec.finalize()
unp = PKCS7(128).unpadder()
plain = unp.update(padded) + unp.finalize()

with open(OUT, "wb") as f:
    f.write(plain)
print(f"[CSP-dec] aes-128-cbc: wrote {{len(plain)}} bytes -> {{OUT}}")
'''
    return body.encode("utf-8")


# ─── Windows .cmd launcher (pairs with the .ps1) ───────────────────────────
def _bat(ct: bytes, key: bytes, algo: str, iv: bytes, out_name: str) -> bytes:
    """Generate a .cmd that re-invokes powershell.exe on the sibling .ps1
    with ExecutionPolicy Bypass. Operator must download the matching
    .ps1 from the CSP UI into the same folder.
    """
    body = f"""@echo off
:: CSP decryptor launcher — pairs with decryptor.ps1
:: generated={_ts()}  algo={algo}  out={out_name}
::
:: Place this .cmd in the same folder as decryptor.ps1 and run.
:: The launcher invokes powershell.exe with -ExecutionPolicy Bypass
:: (process-scoped) so the host machine policy is not modified.

setlocal
set "DIR=%~dp0"
set "PS=%DIR%decryptor.ps1"
if not exist "%PS%" (
    echo [csp-dec] ERROR: decryptor.ps1 not found next to this launcher.
    echo                  Place both files in the SAME folder.
    pause
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS%"
endlocal
"""
    return body.encode("utf-8")
