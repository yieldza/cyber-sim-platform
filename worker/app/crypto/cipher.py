"""Symmetric obfuscation ciphers for EDR / XDR encrypted-payload tests.

The goal is *not* cryptographic confidentiality — it is to hide the static
EICAR signature from on-disk scanners so the operator can exercise the
EDR's runtime-decryption chain:

  drop encrypted blob -> drop decryptor stub -> spawn decryptor ->
  in-memory / on-disk decrypt -> spawn original file

Two algorithms are provided:

  xor-16          16-byte cycling XOR. Zero-dependency in any language.
                  The decryptor stubs (PowerShell + Python) use only stdlib.
                  Trivially weak as crypto, but perfectly adequate to
                  obfuscate the EICAR signature for static scanners.

  aes-128-cbc     AES-128-CBC with PKCS7 padding. Random 16-byte key + IV.
                  Requires the `cryptography` package on the worker; the
                  PowerShell decryptor uses System.Security.Cryptography
                  (stdlib on every Windows host). Python decryptor needs
                  the `cryptography` package on the target — falls back
                  to xor-16 if cryptography is not importable at run-time.

The encrypted blob always carries a tiny header so the decryptor can
self-describe without out-of-band metadata, but the public encrypt()
returns the algo + key + iv separately so the API layer can persist them
in artifact metadata.
"""
from __future__ import annotations

import os
import secrets
from typing import Literal

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    _HAVE_AES = True
except Exception:  # noqa: BLE001
    _HAVE_AES = False


SUPPORTED_ALGOS = ("xor-16", "aes-128-cbc")
Algo = Literal["xor-16", "aes-128-cbc"]


def random_key(algo: str = "xor-16") -> bytes:
    if algo == "xor-16":
        return secrets.token_bytes(16)
    if algo == "aes-128-cbc":
        return secrets.token_bytes(16)
    raise ValueError(f"unknown algo: {algo}")


def random_iv(algo: str = "aes-128-cbc") -> bytes:
    if algo == "aes-128-cbc":
        return secrets.token_bytes(16)
    if algo == "xor-16":
        return b""           # XOR has no IV
    raise ValueError(f"unknown algo: {algo}")


def encrypt(data: bytes, algo: str = "xor-16",
            key: bytes | None = None, iv: bytes | None = None) -> dict:
    """Encrypt `data` under `algo`. Returns dict with ciphertext + key + iv.

    Raises:
        ValueError: if `algo` is unknown or AES is unavailable.
    """
    if algo == "xor-16":
        k = key or random_key(algo)
        if len(k) != 16:
            raise ValueError("xor-16 key must be 16 bytes")
        ct = bytes(b ^ k[i % 16] for i, b in enumerate(data))
        return {"ciphertext": ct, "key": k, "iv": b"", "algo": algo}

    if algo == "aes-128-cbc":
        if not _HAVE_AES:
            raise ValueError("aes-128-cbc requires the `cryptography` package")
        k = key or random_key(algo)
        i = iv or random_iv(algo)
        if len(k) != 16 or len(i) != 16:
            raise ValueError("aes-128-cbc requires 16-byte key and 16-byte iv")
        padder = PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(k), modes.CBC(i))
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return {"ciphertext": ct, "key": k, "iv": i, "algo": algo}

    raise ValueError(f"unknown algo: {algo}")


def decrypt(ciphertext: bytes, key: bytes, algo: str = "xor-16",
            iv: bytes | None = None) -> bytes:
    if algo == "xor-16":
        if len(key) != 16:
            raise ValueError("xor-16 key must be 16 bytes")
        return bytes(b ^ key[i % 16] for i, b in enumerate(ciphertext))

    if algo == "aes-128-cbc":
        if not _HAVE_AES:
            raise ValueError("aes-128-cbc requires the `cryptography` package")
        if iv is None or len(iv) != 16:
            raise ValueError("aes-128-cbc decrypt requires 16-byte iv")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unp = PKCS7(128).unpadder()
        return unp.update(padded) + unp.finalize()

    raise ValueError(f"unknown algo: {algo}")
