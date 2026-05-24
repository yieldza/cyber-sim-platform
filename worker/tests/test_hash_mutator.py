"""Tests for the hash mutator — append_random / append_hash / pad / until_prefix."""
import hashlib

import pytest

from app.hash_mutator import (
    append_hash,
    append_random,
    hashes,
    mutate_until_prefix,
    pad_to_length,
)


def test_hashes_returns_all_three_algorithms():
    h = hashes(b"hello")
    assert "sha256" in h and "sha1" in h and "md5" in h
    assert h["sha256"] == hashlib.sha256(b"hello").hexdigest()


def test_append_random_changes_hash():
    base = b"X" * 100
    h_before = hashlib.sha256(base).hexdigest()
    result = append_random(base, n=32)
    assert len(result.data) == len(base) + 32
    assert result.after["sha256"] != h_before
    assert result.before["sha256"] == h_before


def test_append_random_rejects_non_positive_n():
    with pytest.raises(ValueError):
        append_random(b"X", n=0)


def test_append_hash_is_deterministic():
    base = b"deterministic"
    a = append_hash(base, algo="sha256")
    b = append_hash(base, algo="sha256")
    assert a.data == b.data, "append_hash must be deterministic for same input"


def test_append_hash_rejects_unknown_algorithm():
    with pytest.raises(ValueError):
        append_hash(b"X", algo="bogus256")


def test_pad_to_length_pads_with_nulls():
    base = b"ABC"
    result = pad_to_length(base, target_len=10)
    assert len(result.data) == 10
    assert result.data.startswith(b"ABC")
    assert result.data.endswith(b"\x00")


def test_pad_to_length_rejects_shrink():
    base = b"X" * 100
    with pytest.raises(ValueError):
        pad_to_length(base, target_len=10)


def test_mutate_until_prefix_finds_match_short_prefix():
    base = b"seed"
    # 1-char hex prefix → ~16 tries on average. Cap higher for safety.
    result = mutate_until_prefix(base, target_prefix="a", algo="sha256", max_iterations=2_000)
    assert result.after["sha256"].startswith("a")


def test_mutate_until_prefix_rejects_non_hex_prefix():
    with pytest.raises(ValueError):
        mutate_until_prefix(b"seed", target_prefix="zz", algo="sha256")


def test_mutate_until_prefix_rejects_overlong_prefix():
    with pytest.raises(ValueError):
        mutate_until_prefix(b"seed", target_prefix="aaaaaaa", algo="sha256")


def test_mutate_until_prefix_caps_iterations():
    base = b"seed"
    # 6 hex chars + tiny iter cap → unreachable; must raise.
    with pytest.raises(RuntimeError):
        mutate_until_prefix(base, target_prefix="ffffff", algo="sha256", max_iterations=5)
