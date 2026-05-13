"""Pad a generated artifact up to a user-specified target size.

The user picks a `target_size_kb` (1..20480 = up to 20 MB) on the Generate
tab. Each file type has its own padding strategy chosen so the padded
file stays parseable by its intended consumer:

  - PE  : binary filler appended to the overlay region (after the last
          raw section). PE loaders / scanners ignore trailing bytes.
  - PDF : comment lines (`%`-prefixed) appended after `%%EOF`. PDF
          viewers stop at the first `%%EOF`; AV scanners see the rest.
  - APK / DOCX (ZIP-based): trailing bytes after the central directory.
          ZIP parsers scan backward for EOCD, so trailing data is
          tolerated.
  - Script files (.ps1/.sh/.py/.vbs/.js): language-specific comment
          lines appended after the last existing line.
  - HTA / html-smuggle: HTML `<!-- … -->` comments appended after the
          closing `</html>`.

Each padding block embeds the EICAR signature so the static-detection
guarantee from v0.4.x extends across the entire padded file.

Hard cap: 20 MB (matches API-level validation).
"""
from __future__ import annotations

from .eicar import EICAR_STRING

MAX_PAD_TARGET_BYTES = 20 * 1024 * 1024   # 20 MB

# Mapping file_type -> (prefix, suffix) used to wrap each repeated EICAR
# block. Prefix typically opens a comment (or is binary padding) and
# suffix closes it / adds whitespace.
_PADDING_STYLE: dict[str, tuple[bytes, bytes]] = {
    "eicar":         (b"\n",            b"\n"),
    "com":           (b"\n",            b"\n"),
    "pe":            (b"\x00" * 16,     b"\x00" * 32),    # binary overlay padding
    "pdf":           (b"\n% ",          b"\n"),           # PDF comment
    "apk":           (b"\n# ",          b"\n"),
    "docx":          (b"\n# ",          b"\n"),
    "dropper-ps1":   (b"\n# ",          b"\n"),
    "dropper-sh":    (b"\n# ",          b"\n"),
    "dropper-py":    (b"\n# ",          b"\n"),
    "vbs":           (b"\n' ",          b"\n"),
    "js":            (b"\n// ",         b"\n"),
    "hta":           (b"\n<!-- ",       b" -->\n"),
    "html-smuggle":  (b"\n<!-- ",       b" -->\n"),
}
_DEFAULT_STYLE = (b"\n# ", b"\n")


def pad_artifact(data: bytes, file_type: str, target_size_bytes: int) -> bytes:
    """Append EICAR-bearing filler bytes until `data` reaches the target.

    Raises:
        ValueError: if target exceeds the 20 MB cap.
    """
    if target_size_bytes > MAX_PAD_TARGET_BYTES:
        raise ValueError(
            f"target_size_bytes={target_size_bytes} exceeds 20 MB cap "
            f"({MAX_PAD_TARGET_BYTES})"
        )
    if target_size_bytes <= len(data):
        return data

    prefix, suffix = _PADDING_STYLE.get(file_type, _DEFAULT_STYLE)
    block = prefix + b"EICAR " + EICAR_STRING + suffix
    needed = target_size_bytes - len(data)
    repeats = (needed // len(block)) + 1
    filler = block * repeats
    return (data + filler)[:target_size_bytes]
