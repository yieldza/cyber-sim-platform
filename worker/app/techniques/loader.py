"""Catalog loader and read-only accessors for ATT&CK techniques."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

CATALOG_PATH = Path(__file__).parent / "catalog.json"


@dataclass(frozen=True)
class TechniqueTest:
    name: str
    description: str
    executor: str
    command: str
    platforms: tuple[str, ...]
    expected_signals: tuple[str, ...]
    cleanup: str | None = None


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    platforms: tuple[str, ...]
    description: str
    tests: tuple[TechniqueTest, ...] = field(default_factory=tuple)


@lru_cache(maxsize=1)
def _load_raw() -> dict:
    with CATALOG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def list_techniques() -> tuple[Technique, ...]:
    raw = _load_raw()
    out: list[Technique] = []
    for t in raw.get("techniques", []):
        tests = tuple(
            TechniqueTest(
                name=tt["name"],
                description=tt.get("description", ""),
                executor=tt["executor"],
                command=tt["command"],
                platforms=tuple(tt.get("platforms", [])),
                expected_signals=tuple(tt.get("expected_signals", [])),
                cleanup=tt.get("cleanup"),
            )
            for tt in t.get("tests", [])
        )
        out.append(
            Technique(
                id=t["id"],
                name=t["name"],
                tactic=t["tactic"],
                platforms=tuple(t.get("platforms", [])),
                description=t.get("description", ""),
                tests=tests,
            )
        )
    return tuple(out)


def get_technique(technique_id: str) -> Technique | None:
    for t in list_techniques():
        if t.id == technique_id:
            return t
    return None


def get_test(technique_id: str, test_name: str) -> tuple[Technique, TechniqueTest] | None:
    tech = get_technique(technique_id)
    if tech is None:
        return None
    for tt in tech.tests:
        if tt.name == test_name:
            return tech, tt
    return None
