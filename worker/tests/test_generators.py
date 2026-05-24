"""Tests for EICAR-bearing file generators.

Every generator must embed the EICAR signature so AV/EDR can detect it.
These tests assert that constraint plus per-format structural sanity.
"""
import io
import zipfile

import pytest

from app.generators import (
    EICAR_STRING,
    com_file,
    dropper_ps1,
    dropper_sh,
    dropper_py,
    eicar_apk,
    eicar_docx,
    eicar_hta,
    eicar_html_smuggle,
    eicar_js,
    eicar_pdf,
    eicar_vbs,
    minimal_pe,
    pad_artifact,
    raw_eicar,
)


EICAR_BYTES = EICAR_STRING if isinstance(EICAR_STRING, bytes) else EICAR_STRING.encode("ascii")


# ---------- raw EICAR ------------------------------------------------------
def test_raw_eicar_exact_length():
    data = raw_eicar()
    assert data == EICAR_BYTES
    assert len(data) == 68


# ---------- COM ------------------------------------------------------------
def test_com_contains_eicar():
    data = com_file()
    assert EICAR_BYTES in data
    assert len(data) >= 68


# ---------- PE -------------------------------------------------------------
def test_pe_is_valid_structure_with_eicar():
    data = minimal_pe()
    # MZ + PE signatures
    assert data[:2] == b"MZ", "PE must start with MZ header"
    assert b"PE\x00\x00" in data, "must contain PE signature"
    # multi-location EICAR embedding (v0.4.1+)
    assert data.count(EICAR_BYTES) >= 10, "PE must embed EICAR multiple times"
    # ~9 KB minimum
    assert len(data) >= 4096


# ---------- PDF ------------------------------------------------------------
def test_pdf_header_and_eicar():
    data = eicar_pdf()
    assert data.startswith(b"%PDF-"), "must be a PDF"
    assert EICAR_BYTES in data, "PDF must embed EICAR"
    assert b"%%EOF" in data


# ---------- ZIP-based: APK, DOCX -------------------------------------------
@pytest.mark.parametrize("gen_fn,suffix", [
    (eicar_apk, "apk"),
    (eicar_docx, "docx"),
])
def test_zip_container_eicar_uncompressed(gen_fn, suffix):
    data = gen_fn()
    zf = zipfile.ZipFile(io.BytesIO(data), mode="r")
    # at least one entry must contain EICAR
    found_eicar = False
    has_stored = False
    for info in zf.infolist():
        if info.compress_type == zipfile.ZIP_STORED:
            has_stored = True
        with zf.open(info) as f:
            if EICAR_BYTES in f.read():
                found_eicar = True
    assert found_eicar, f"{suffix} container must contain EICAR"
    assert has_stored, (
        f"{suffix} must include at least one ZIP_STORED entry "
        f"so byte scanners detect EICAR without inflating"
    )


# ---------- Behavioral droppers (multi-location EICAR) ---------------------
@pytest.mark.parametrize("gen_fn,name", [
    (dropper_ps1, "ps1"),
    (dropper_sh, "sh"),
    (dropper_py, "py"),
])
def test_droppers_contain_multiple_eicar(gen_fn, name):
    data = gen_fn()
    # v0.4.2+ — 4-5 EICAR copies per dropper for reliable detection.
    assert data.count(EICAR_BYTES) >= 3, (
        f"dropper-{name} must embed EICAR multiple times "
        f"(was {data.count(EICAR_BYTES)})"
    )


# ---------- Script-host carriers -------------------------------------------
@pytest.mark.parametrize("gen_fn,name", [
    (eicar_hta, "hta"),
    (eicar_vbs, "vbs"),
    (eicar_js, "js"),
    (eicar_html_smuggle, "html-smuggle"),
])
def test_script_carriers_multi_location_eicar(gen_fn, name):
    data = gen_fn()
    assert data.count(EICAR_BYTES) >= 3, (
        f"{name} script carrier must embed EICAR multiple times "
        f"(was {data.count(EICAR_BYTES)})"
    )


# ---------- Padding --------------------------------------------------------
def test_pad_artifact_grows_to_target():
    base = raw_eicar()
    target_bytes = 4096
    padded = pad_artifact(base, "eicar", target_bytes)
    assert len(padded) >= target_bytes
    # padded artifact must still detect as EICAR
    assert EICAR_BYTES in padded


def test_pad_artifact_idempotent_when_already_large():
    base = b"X" * 10000 + EICAR_BYTES
    padded = pad_artifact(base, "eicar", 1000)
    # Should not shrink a file that already exceeds the target.
    assert len(padded) >= len(base)
