"""DOCX (Office Open XML) containing the EICAR signature in document body."""
import io
import zipfile

from .eicar import EICAR_STRING

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""

DOCUMENT_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t xml:space="preserve">{eicar}</w:t></w:r></w:p>
    <w:sectPr/>
  </w:body>
</w:document>
"""


def eicar_docx() -> bytes:
    eicar_text = EICAR_STRING.decode("ascii")
    document = DOCUMENT_TEMPLATE.format(eicar=eicar_text)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES)
        z.writestr("_rels/.rels", ROOT_RELS)
        # document.xml stored uncompressed so static scanners see EICAR raw.
        z.writestr(
            zipfile.ZipInfo("word/document.xml"),
            document,
            compress_type=zipfile.ZIP_STORED,
        )
    return buf.getvalue()
