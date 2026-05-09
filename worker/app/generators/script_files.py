"""Script-style EICAR carriers mapped to specific MITRE ATT&CK techniques.

Generated artefacts are static files (no behaviour at rest) — the EICAR
signature is embedded so AV detects the file, while the file's *type*
exercises EDR / XDR rules that look at script-host execution chains:

  hta            T1218.005 — Mshta abuse                         (.hta)
  vbs            T1059.005 — VBScript                            (.vbs)
  js             T1059.007 — JScript via Windows Script Host     (.js)
  html-smuggle   T1027.006 — HTML smuggling (Blob + auto-click)  (.html)

v0.4.2 — multi-location EICAR (header + string variable + trailing) on
each carrier. Cortex XDR / WildFire and similar EDRs require multiple
hits or extracted-section hits before they fire on script files; a
single in-comment hit at the top of the file is sometimes filtered out.
"""
from __future__ import annotations

import base64
import secrets
from datetime import datetime, timezone

from .eicar import EICAR_STRING

_EICAR = EICAR_STRING.decode("ascii")  # single-backslash, raw form


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sid() -> str:
    return secrets.token_hex(6)


# ─── T1218.005 — HTA (HTML Application via mshta.exe) ─────────────────────
def eicar_hta() -> bytes:
    sid = _sid()
    body = f"""<!DOCTYPE HTML>
<!-- CSP HTA test — T1218.005 Mshta abuse (session {sid}) -->
<!-- STATIC EICAR (raw header): {_EICAR} -->
<html>
<head>
<title>CSP HTA Test ({sid})</title>
<HTA:APPLICATION ID="csp_hta" APPLICATIONNAME="CSP-HTA" SCROLL="no" SINGLEINSTANCE="yes" />
<!-- Generated {_ts()} session={sid} -->
</head>
<body style="font-family:sans-serif;background:#111;color:#eee;padding:20px">
<h1>CSP HTA Test</h1>
<p>Technique: <b>T1218.005 — Mshta abuse</b>. Run via:</p>
<pre>mshta.exe csp_hta_{sid}.hta</pre>
<p>Detection signals expected:</p>
<ul>
<li>process_create: <code>mshta.exe</code> with .hta on the command line</li>
<li>process_create chain: mshta -> wscript.shell COM -> cmd.exe</li>
<li>YARA / static AV match on the embedded EICAR signature</li>
</ul>

<!-- Static EICAR carrier (raw text in body, picked up by stream scanners) -->
<pre id="eicar">{_EICAR}</pre>

<!-- Static EICAR carrier (textarea — also indexed as DOM text) -->
<textarea style="display:none">{_EICAR}</textarea>

<script language="VBScript">
On Error Resume Next
' Static EICAR signature (constant, never evaluated):
' {_EICAR}
Const CSP_EICAR = "{_EICAR}"

' Behavioural-only: spawn benign cmd via WshShell. Real EDR sees the
' mshta -> shell chain regardless of the command run.
Set sh = CreateObject("WScript.Shell")
sh.Run "cmd /c echo CSP-HTA-test-{sid}", 0, True
self.close()
</script>
</body>
</html>
<!-- STATIC EICAR (raw trailing marker): {_EICAR} -->
"""
    return body.encode("utf-8")


# ─── T1059.005 — VBScript ─────────────────────────────────────────────────
def eicar_vbs() -> bytes:
    sid = _sid()
    body = f"""' CSP VBScript Test File — T1059.005 (Visual Basic)
' Generated: {_ts()}   session: {sid}
'
' === STATIC EICAR signature (raw header for AV/EDR) ===
' {_EICAR}
'
' Run with:   wscript csp_{sid}.vbs   or   cscript csp_{sid}.vbs
'
' Detection signals expected:
'   - process_create: wscript.exe / cscript.exe with .vbs on cmdline
'   - YARA / static signature match on EICAR string
'   - VBScript COM activation telemetry (WScript.Shell)

' Static signature constant — declared and never used:
Const CSP_EICAR = "{_EICAR}"

On Error Resume Next
Dim WshShell, sid
sid = "{sid}"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Popup "CSP-VBS-test-" & sid, 1, "CSP", 64
WshShell.Run "cmd /c echo CSP-VBS-test-" & sid, 0, True
WScript.Quit 0

' === STATIC EICAR signature (raw trailing marker for AV/EDR) ===
' {_EICAR}
"""
    return body.encode("utf-8")


# ─── T1059.007 — JScript ──────────────────────────────────────────────────
def eicar_js() -> bytes:
    sid = _sid()
    body = f"""// CSP JScript Test File — T1059.007 (JavaScript / Windows Script Host)
// Generated: {_ts()}   session: {sid}
//
// === STATIC EICAR signature (raw header for AV/EDR) ===
// {_EICAR}
//
// Run with:   wscript csp_{sid}.js   or   cscript csp_{sid}.js
//
// Detection signals expected:
//   - process_create: wscript.exe / cscript.exe with .js on cmdline
//   - JScript engine activation (jscript.dll loaded by Script Host)
//   - WScript.Shell COM creation
//   - EICAR static signature in file content

// Static signature variable — single-quoted so $ is literal, never run:
var CSP_EICAR = '{_EICAR}';

// Static multi-line signature carrier (string literal, never executed):
var CSP_EICAR_BLOCK = (
  '{_EICAR}'
);

try {{
    var sid = "{sid}";
    var sh = WScript.CreateObject("WScript.Shell");
    sh.Run("cmd /c echo CSP-JS-test-" + sid, 0, true);
    WScript.Echo("CSP-JS-test-" + sid);
}} catch (e) {{
    // Benign — only matters when run under Windows Script Host.
}}

// === STATIC EICAR signature (raw trailing marker for AV/EDR) ===
// {_EICAR}
"""
    return body.encode("utf-8")


# ─── T1027.006 — HTML smuggling ───────────────────────────────────────────
def eicar_html_smuggle() -> bytes:
    """HTML file that reconstructs EICAR client-side via Blob + auto-clicks
    a download link. Tests whether web proxies / email gateways / EDRs
    detect HTML-smuggling delivery. AV will catch the dropped file."""
    sid = _sid()
    payload_b64 = base64.b64encode(EICAR_STRING).decode("ascii")
    body = f"""<!DOCTYPE html>
<!-- CSP HTML-smuggling test — T1027.006 (session {sid}) -->
<!-- STATIC EICAR (raw header): {_EICAR} -->
<html lang="en">
<head>
<meta charset="utf-8">
<title>CSP HTML-smuggling test ({sid})</title>
<style>
  body {{ font-family: -apple-system, sans-serif; background:#0b1020; color:#e6ecff; padding:32px; max-width:720px; margin:auto; }}
  pre  {{ background:#060a18; padding:8px; border-radius:4px; overflow:auto; }}
  code {{ color:#58e1c8; }}
</style>
</head>
<body>
<h1>HTML-smuggling test (T1027.006)</h1>
<p>Session: <code>{sid}</code> · generated: <code>{_ts()}</code></p>
<p>This page reconstructs the EICAR test signature client-side from a
base64 string and triggers an automatic download. Detection signals
expected:</p>
<ul>
  <li>Web proxy / email gateway: blob-URL download from an HTML page</li>
  <li>Browser AV: on-disk write of the dropped file</li>
  <li>EDR: file_create from the browser process to the Downloads folder</li>
  <li>Static AV: EICAR signature in the dropped file</li>
</ul>
<p><button id="dl">Download EICAR test file</button>
   (auto-fires after 500 ms)</p>

<!-- Static EICAR carrier (raw text inside <pre>, indexed by stream scanners) -->
<pre>EICAR (also embedded in the smuggled blob):
{_EICAR}</pre>

<!-- Static EICAR carrier (hidden textarea, indexed as DOM text) -->
<textarea style="display:none">{_EICAR}</textarea>

<script>
// Static signature (single-quoted, never executed against EICAR semantics):
var CSP_EICAR = '{_EICAR}';

(function () {{
  var b64 = "{payload_b64}";
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  var blob = new Blob([bytes], {{ type: "application/octet-stream" }});
  var url  = URL.createObjectURL(blob);
  var a    = document.createElement("a");
  a.href = url;
  a.download = "eicar-from-html-smuggle-{sid}.com";
  document.getElementById("dl").addEventListener("click", function () {{ a.click(); }});
  // auto-trigger so it works as a passive test:
  setTimeout(function () {{ a.click(); }}, 500);
}})();
</script>
</body>
</html>
<!-- STATIC EICAR (raw trailing marker): {_EICAR} -->
"""
    return body.encode("utf-8")
