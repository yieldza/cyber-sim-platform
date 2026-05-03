"""Minimal PDF containing the EICAR string in a content stream.

Built as a parseable PDF 1.4 document with a single page rendering the
EICAR signature as text — AV/EDR scanners will extract the string from the
stream object during static analysis.
"""

from .eicar import EICAR_STRING


def eicar_pdf(extra_text: str = "") -> bytes:
    eicar_text = EICAR_STRING.decode("ascii", errors="replace")
    body = f"BT /F1 12 Tf 50 750 Td ({eicar_text}) Tj ET"
    if extra_text:
        safe = extra_text.replace("(", "\\(").replace(")", "\\)")
        body += f" BT /F1 10 Tf 50 720 Td ({safe}) Tj ET"
    stream = body.encode("latin-1")

    objects: list[bytes] = []

    def obj(n: int, content: bytes) -> bytes:
        return f"{n} 0 obj\n".encode() + content + b"\nendobj\n"

    objects.append(obj(1, b"<< /Type /Catalog /Pages 2 0 R >>"))
    objects.append(obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"))
    objects.append(obj(
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    ))
    stream_obj = (
        f"<< /Length {len(stream)} >>\nstream\n".encode()
        + stream
        + b"\nendstream"
    )
    objects.append(obj(4, stream_obj))
    objects.append(obj(5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for o in objects:
        offsets.append(len(out))
        out += o

    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += b"trailer\n"
    out += f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode()
    out += b"startxref\n"
    out += f"{xref_pos}\n".encode()
    out += b"%%EOF\n"
    return bytes(out)
