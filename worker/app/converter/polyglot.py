"""Extension / format conversion utilities.

Two strategies are exposed:

1. **Rewrap** — extract the EICAR signature payload from one file and rewrap
   it in a different container. This tests whether the scanner uses MIME
   detection only (which the rewrap defeats) or scans content (which still
   trips the EICAR signature).

2. **Polyglot ZIP+PDF** — produces a single byte stream that parses as both
   a valid PDF (via leading %PDF marker) and a valid ZIP (trailing central
   directory). Used to verify how scanners disambiguate formats.

These techniques are well documented in academic literature on container
format ambiguity; they help blue teams measure detection coverage gaps.
"""
from __future__ import annotations

from ..generators import (
    com_file,
    dropper_ps1,
    dropper_py,
    dropper_sh,
    eicar_apk,
    eicar_docx,
    eicar_hta,
    eicar_html_smuggle,
    eicar_js,
    eicar_pdf,
    eicar_vbs,
    minimal_pe,
    raw_eicar,
)

SUPPORTED_TARGETS = (
    "eicar", "com", "pe", "pdf", "apk", "docx",
    "dropper-ps1", "dropper-sh", "dropper-py",
    "hta", "vbs", "js", "html-smuggle",
)


def detect_format(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        if b"AndroidManifest.xml" in data[:4096] or b"classes.dex" in data:
            return "apk"
        if b"word/document.xml" in data[:4096] or b"word/document.xml" in data:
            return "docx"
        return "zip"
    if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
        return "eicar"
    return "unknown"


def rewrap_eicar(target: str) -> bytes:
    """Generate a fresh EICAR-bearing artifact in the requested container."""
    target = target.lower()
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported target: {target}")
    if target == "eicar":
        return raw_eicar()
    if target == "com":
        return com_file()
    if target == "pe":
        return minimal_pe()
    if target == "pdf":
        return eicar_pdf()
    if target == "apk":
        return eicar_apk()
    if target == "docx":
        return eicar_docx()
    if target == "dropper-ps1":
        return dropper_ps1()
    if target == "dropper-sh":
        return dropper_sh()
    if target == "dropper-py":
        return dropper_py()
    if target == "hta":
        return eicar_hta()
    if target == "vbs":
        return eicar_vbs()
    if target == "js":
        return eicar_js()
    if target == "html-smuggle":
        return eicar_html_smuggle()
    raise AssertionError("unreachable")  # pragma: no cover


def polyglot_zip_pdf(zip_payload: bytes | None = None, pdf_text: str = "") -> bytes:
    """Concatenate a PDF prefix with a ZIP body; both magic markers remain valid.

    The PDF parser locates `%PDF` near the start and `%%EOF` at its trailer;
    the ZIP parser scans backward for the End-of-Central-Directory record.
    Trailing bytes do not invalidate the PDF, and leading bytes do not
    invalidate the ZIP — so a crafted concatenation parses as both.
    """
    if zip_payload is None:
        zip_payload = eicar_apk()
    pdf = eicar_pdf(extra_text=pdf_text or "polyglot test container")
    return pdf + zip_payload
