"""Minimal valid PE32 generator.

Produces a tiny PE32 (Windows i386) executable containing the EICAR string
in a .data section. Header structure follows the Microsoft PE/COFF spec so
AV/EDR static parsers will recognize the format and locate the test signature.

Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
"""
from __future__ import annotations

import struct

from .eicar import EICAR_STRING

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
DOS_STUB_SIZE = 0x40


def minimal_pe(payload: bytes | None = None, subsystem: str = "console") -> bytes:
    """Build a minimal PE32 with `payload` (default EICAR) embedded in .data."""
    if payload is None:
        payload = EICAR_STRING

    subsystem_val = 3 if subsystem == "console" else 2  # CUI=3, GUI=2

    # ---- DOS header (64 bytes) ----
    dos = bytearray(DOS_STUB_SIZE)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, DOS_STUB_SIZE)  # e_lfanew

    # ---- PE signature ----
    pe_sig = b"PE\x00\x00"

    # ---- COFF File Header (20 bytes) ----
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine = IMAGE_FILE_MACHINE_I386
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        224,     # SizeOfOptionalHeader (PE32)
        0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    # ---- Optional Header PE32 (224 bytes) ----
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,        # Magic = PE32
        1, 0,         # Linker version
        0,            # SizeOfCode
        FILE_ALIGN,   # SizeOfInitializedData
        0,            # SizeOfUninitializedData
        0x1000,       # AddressOfEntryPoint (RVA into .data; harmless for static scan)
        0x1000,       # BaseOfCode
        0x1000,       # BaseOfData (PE32 only)
        0x00400000,   # ImageBase
        SECTION_ALIGN,
        FILE_ALIGN,
        4, 0,         # OS version
        0, 0,         # Image version
        4, 0,         # Subsystem version
        0,            # Win32VersionValue
        0x2000,       # SizeOfImage (headers + 1 section)
        FILE_ALIGN,   # SizeOfHeaders
        0,            # CheckSum
        subsystem_val,
        0,            # DllCharacteristics
        0x100000, 0x1000,   # Stack reserve / commit
        0x100000, 0x1000,   # Heap reserve / commit
        0,            # LoaderFlags
        16,           # NumberOfRvaAndSizes
    )
    # 16 data directory entries (8 bytes each), all zero
    opt += b"\x00" * (16 * 8)

    # ---- Section Header for .data (40 bytes) ----
    raw_size = ((len(payload) + FILE_ALIGN - 1) // FILE_ALIGN) * FILE_ALIGN or FILE_ALIGN
    section_hdr = (
        b".data\x00\x00\x00" +
        struct.pack(
            "<IIIIIIHHI",
            len(payload),     # VirtualSize
            0x1000,           # VirtualAddress
            raw_size,         # SizeOfRawData
            FILE_ALIGN,       # PointerToRawData
            0, 0,             # PointerToRelocations / LineNumbers
            0, 0,             # NumberOf Relocations / LineNumbers
            0xC0000040,       # READ | WRITE | INITIALIZED_DATA
        )
    )

    headers = bytes(dos) + pe_sig + coff + opt + section_hdr
    headers = headers + b"\x00" * (FILE_ALIGN - len(headers))

    section_data = payload + b"\x00" * (raw_size - len(payload))
    return headers + section_data
