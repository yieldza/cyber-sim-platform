"""Hash mutation utilities for testing whether EDR/AV uses static-hash blocking
versus content/behavioral signatures.

Mutations append bytes to non-critical regions of the file (end of file,
section padding). For container formats (ZIP, PDF) trailing bytes after
EOF are often tolerated by parsers — useful to verify if your scanner
re-hashes after stripping container padding.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass


def hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


@dataclass
class MutationResult:
    data: bytes
    iterations: int
    before: dict[str, str]
    after: dict[str, str]


def append_random(data: bytes, n: int = 16) -> MutationResult:
    if n <= 0:
        raise ValueError("n must be positive")
    before = hashes(data)
    new_data = data + secrets.token_bytes(n)
    return MutationResult(new_data, 1, before, hashes(new_data))


def append_hash(data: bytes, algo: str = "sha256") -> MutationResult:
    """Append the file's own digest as raw bytes — embeds a self-fingerprint."""
    algo = algo.lower()
    if algo not in ("md5", "sha1", "sha256"):
        raise ValueError("algo must be md5, sha1, or sha256")
    before = hashes(data)
    digest = hashlib.new(algo, data).digest()
    new_data = data + digest
    return MutationResult(new_data, 1, before, hashes(new_data))


def pad_to_length(data: bytes, target_len: int, fill: bytes = b"\x00") -> MutationResult:
    if target_len <= len(data):
        raise ValueError("target_len must be greater than current length")
    before = hashes(data)
    pad = (fill * ((target_len - len(data)) // len(fill) + 1))[: target_len - len(data)]
    new_data = data + pad
    return MutationResult(new_data, 1, before, hashes(new_data))


def mutate_until_prefix(
    data: bytes,
    target_prefix: str,
    algo: str = "sha256",
    max_iterations: int = 1_000_000,
    chunk_size: int = 8,
) -> MutationResult:
    """Brute-force append random bytes until digest starts with `target_prefix`.

    The hash space makes this practical only for short prefixes (<=4 hex chars).
    Capped by `max_iterations` to keep the worker responsive.
    """
    target_prefix = target_prefix.lower()
    if any(c not in "0123456789abcdef" for c in target_prefix):
        raise ValueError("prefix must be hex")
    if len(target_prefix) > 6:
        raise ValueError("prefix length capped at 6 hex chars (~16M tries)")

    before = hashes(data)
    h = hashlib.new

    for i in range(1, max_iterations + 1):
        suffix = os.urandom(chunk_size)
        candidate = data + suffix
        digest = h(algo, candidate).hexdigest()
        if digest.startswith(target_prefix):
            return MutationResult(candidate, i, before, hashes(candidate))

    raise RuntimeError(
        f"prefix {target_prefix!r} not found within {max_iterations} iterations"
    )
