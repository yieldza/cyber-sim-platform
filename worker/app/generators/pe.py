"""PE32 generator with EICAR signature embedded in multiple locations.

Why multi-location: Cortex XDR / WildFire (and other behavioural EDRs)
filter out files that look "structurally broken" before applying static
signature rules. The v0.1.0 PE (1 KB, entry point inside a non-executable
section, no DOS stub) passed file-content scanners but was being silently
skipped by Cortex XDR (user report 2026-05-09).

This generator produces a structurally valid ~12 KB PE32 with the EICAR
signature embedded in *four* distinct file regions, so that any engine
which scans the file as a stream — and any engine which extracts and
scans individual sections — hits at least one copy:

  1. DOS stub area    — bytes between MZ header and PE header
  2. .text section    — after a tiny `xor eax,eax; ret` entry stub
  3. .data section    — at section start *and* end
  4. PE overlay       — appended after the last raw section

Reference:
  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
"""
from __future__ import annotations

import struct

from .eicar import EICAR_STRING

FILE_ALIGN    = 0x200
SECTION_ALIGN = 0x1000

# DOS stub area lives at [0x40 .. e_lfanew). We pick e_lfanew = 0x100 so
# there are 192 bytes of stub area — enough for the standard "cannot run
# in DOS mode" message AND the 68-byte EICAR signature.
E_LFANEW = 0x100

# Section sizes — keep multiples of FILE_ALIGN and SECTION_ALIGN.
SIZE_OF_HEADERS = 0x400      # 1 KB headers (rounded up to FILE_ALIGN)
SIZE_OF_TEXT    = 0x1000     # 4 KB code section
SIZE_OF_DATA    = 0x1000     # 4 KB data section
SIZE_OF_IMAGE   = 0x4000     # headers + .text + .data, section-aligned

# x86 entry stub: xor eax, eax ; ret — clean exit code 0.
# (Without an import on KERNEL32!ExitProcess this won't actually unwind
# cleanly when run, but the AV scanner only cares that the entry point
# points at valid-looking code in an executable section.)
ENTRY_STUB = b"\x33\xC0\xC3"


def minimal_pe(payload: bytes | None = None, subsystem: str = "console") -> bytes:
    if payload is None:
        payload = EICAR_STRING

    subsystem_val = 3 if subsystem == "console" else 2  # CUI=3, GUI=2

    # ─── 1. DOS header + DOS stub area (length = E_LFANEW) ──────────────
    dos = bytearray(E_LFANEW)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, E_LFANEW)

    # Standard DOS stub message (visible if the file is run on real DOS).
    stub_msg = (
        b"This program is a CSP EICAR-test PE - benign, for AV/EDR "
        b"detection testing only.\r\n$"
    )
    stub_off = 0x40
    dos[stub_off:stub_off + len(stub_msg)] = stub_msg

    # Embed EICAR right after the stub message, padded so it is on its own
    # line of bytes — most signature scanners walking the stub will see it.
    eicar_dos_off = stub_off + len(stub_msg) + 4
    if eicar_dos_off + len(payload) <= E_LFANEW:
        dos[eicar_dos_off:eicar_dos_off + len(payload)] = payload

    # ─── 2. PE signature + COFF header ──────────────────────────────────
    pe_sig = b"PE\x00\x00"
    NUM_SECTIONS = 2
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,           # Machine = i386
        NUM_SECTIONS,
        0,                # TimeDateStamp
        0,                # PointerToSymbolTable
        0,                # NumberOfSymbols
        224,              # SizeOfOptionalHeader (PE32)
        0x0102,           # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    # ─── 3. Optional header (PE32, 224 bytes) ───────────────────────────
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,            # Magic = PE32
        1, 0,             # Linker version
        SIZE_OF_TEXT,     # SizeOfCode
        SIZE_OF_DATA,     # SizeOfInitializedData
        0,                # SizeOfUninitializedData
        0x1000,           # AddressOfEntryPoint (RVA into .text)
        0x1000,           # BaseOfCode
        0x2000,           # BaseOfData (PE32 only)
        0x00400000,       # ImageBase
        SECTION_ALIGN,
        FILE_ALIGN,
        4, 0,             # OS version
        0, 0,             # Image version
        4, 0,             # Subsystem version
        0,                # Win32VersionValue
        SIZE_OF_IMAGE,
        SIZE_OF_HEADERS,
        0,                # CheckSum
        subsystem_val,
        0,                # DllCharacteristics
        0x100000, 0x1000, # Stack reserve / commit
        0x100000, 0x1000, # Heap reserve / commit
        0,                # LoaderFlags
        16,               # NumberOfRvaAndSizes
    )
    opt += b"\x00" * (16 * 8)   # 16 data directories, all zero

    # ─── 4. Section headers ─────────────────────────────────────────────
    text_hdr = (
        b".text\x00\x00\x00" +
        struct.pack(
            "<IIIIIIHHI",
            SIZE_OF_TEXT,           # VirtualSize
            0x1000,                 # VirtualAddress
            SIZE_OF_TEXT,           # SizeOfRawData
            SIZE_OF_HEADERS,        # PointerToRawData
            0, 0,                   # PointerToRelocations / LineNumbers
            0, 0,                   # NumberOfRelocations / LineNumbers
            0x60000020,             # CODE | EXECUTE | READ
        )
    )
    data_hdr = (
        b".data\x00\x00\x00" +
        struct.pack(
            "<IIIIIIHHI",
            SIZE_OF_DATA,
            0x2000,
            SIZE_OF_DATA,
            SIZE_OF_HEADERS + SIZE_OF_TEXT,
            0, 0,
            0, 0,
            0xC0000040,             # READ | WRITE | INITIALIZED_DATA
        )
    )

    # Assemble headers + zero-pad to SIZE_OF_HEADERS.
    headers = bytes(dos) + pe_sig + coff + opt + text_hdr + data_hdr
    headers = headers + b"\x00" * (SIZE_OF_HEADERS - len(headers))

    # ─── 5. .text section content (4 KB) ────────────────────────────────
    # Tiny x86 entry stub at offset 0; rest of section interleaves EICAR.
    text = bytearray(SIZE_OF_TEXT)
    text[0:len(ENTRY_STUB)] = ENTRY_STUB
    pos = 0x10
    while pos + len(payload) + 0x10 < SIZE_OF_TEXT:
        text[pos:pos + len(payload)] = payload
        pos += len(payload) + 0x60     # space them out so engines see fresh hits

    # ─── 6. .data section content (4 KB) — EICAR at start AND end ───────
    data = bytearray(SIZE_OF_DATA)
    data[0:len(payload)] = payload
    data[SIZE_OF_DATA - len(payload):SIZE_OF_DATA] = payload

    # ─── 7. Overlay (appended after the last raw section) ───────────────
    # Some scanners explicitly walk the overlay region. Two copies, with
    # zero padding between them so each is independently anchored.
    overlay = (b"\x00" * 16) + payload + (b"\x00" * 64) + payload + (b"\x00" * 16)

    return headers + bytes(text) + bytes(data) + overlay


def pe_eicar_locations(blob: bytes) -> list[int]:
    """Helper used by smoke tests: return offsets where EICAR appears."""
    out: list[int] = []
    start = 0
    while True:
        idx = blob.find(EICAR_STRING, start)
        if idx < 0:
            return out
        out.append(idx)
        start = idx + 1
