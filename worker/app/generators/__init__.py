from .eicar import EICAR_STRING, raw_eicar, com_file
from .pe import minimal_pe
from .pdf import eicar_pdf
from .apk import eicar_apk
from .docx import eicar_docx

__all__ = [
    "EICAR_STRING",
    "raw_eicar",
    "com_file",
    "minimal_pe",
    "eicar_pdf",
    "eicar_apk",
    "eicar_docx",
]
