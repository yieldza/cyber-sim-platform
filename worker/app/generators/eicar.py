"""EICAR test signature generators.

The EICAR Anti-Virus test file is a standard, harmless string used to test
detection. Distributing files containing it is safe and intentional for
blue-team testing.
"""

EICAR_STRING: bytes = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def raw_eicar() -> bytes:
    return EICAR_STRING


def com_file() -> bytes:
    """A .com file is just the raw EICAR string — it is also valid 16-bit DOS code."""
    return EICAR_STRING
