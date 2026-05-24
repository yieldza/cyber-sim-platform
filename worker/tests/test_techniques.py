"""Tests for the ATT&CK technique catalog + runner + detection rule generator."""
import pytest

from app.techniques import (
    SUPPORTED_RULE_FORMATS,
    SUPPORTED_SCRIPT_FORMATS,
    generate_rule,
    generate_script,
    get_technique,
    list_techniques,
    run_test,
)


def test_catalog_has_minimum_coverage():
    techs = list_techniques()
    # Post v0.5.0 catalog — 43 techniques across 9 tactics.
    assert len(techs) >= 40, f"catalog too small: {len(techs)}"
    tactics = {t.tactic for t in techs}
    expected = {
        "execution", "discovery", "defense-evasion", "persistence",
        "credential-access", "lateral-movement", "command-and-control",
    }
    missing = expected - tactics
    assert not missing, f"missing tactics: {missing}"


def test_every_technique_has_at_least_one_test():
    for t in list_techniques():
        assert t.tests, f"{t.id} has no tests"


def test_get_technique_lookup_by_id():
    t = get_technique("T1059.004")
    assert t is not None
    assert t.name == "Command and Scripting Interpreter: Unix Shell"
    assert any(tt.name == "whoami_via_bash" for tt in t.tests)


def test_get_technique_missing_returns_none():
    assert get_technique("T9999.999") is None


# ---------- runner ---------------------------------------------------------
def test_run_simple_bash_test_succeeds():
    r = run_test("T1059.004", "whoami_via_bash", timeout=10)
    assert r.technique_id == "T1059.004"
    assert r.test_name == "whoami_via_bash"
    assert r.exit_code == 0
    assert r.duration_ms >= 0
    # whoami output should contain at least one non-empty line
    assert r.stdout.strip()


def test_run_missing_technique_raises():
    with pytest.raises(LookupError):
        run_test("T9999.999", "nope", timeout=5)


def test_run_missing_test_raises():
    with pytest.raises(LookupError):
        run_test("T1059.004", "this_test_does_not_exist", timeout=5)


# ---------- script generator -----------------------------------------------
def test_generate_script_returns_each_supported_format():
    # whoami_via_bash is .sh on linux; iterate over the formats that exist
    # by hitting techniques whose executor lines up.
    formats = SUPPORTED_SCRIPT_FORMATS
    assert formats, "script formats must be enumerable"
    # bash test → .sh
    filename, mime, content = generate_script("T1059.004", "whoami_via_bash")
    assert filename.endswith(".sh")
    assert content.strip()


# ---------- detection-rule generator (Approach B) --------------------------
@pytest.mark.parametrize("rule_format", list(SUPPORTED_RULE_FORMATS))
def test_generate_rule_all_formats(rule_format):
    r = generate_rule("T1059.004", "whoami_via_bash", rule_format)
    assert r.rule_format == rule_format
    assert r.technique_id == "T1059.004"
    assert r.test_name == "whoami_via_bash"
    assert r.rule.strip()
    # Format-specific structural checks
    if rule_format == "xql":
        assert "dataset" in r.rule
        assert "filter" in r.rule
    elif rule_format == "sigma":
        assert r.rule.startswith("title:")
        assert "detection:" in r.rule
        assert "logsource:" in r.rule
    elif rule_format == "spl":
        assert "table" in r.rule


def test_generate_rule_rejects_unknown_format():
    with pytest.raises(ValueError):
        generate_rule("T1059.004", "whoami_via_bash", "kql-pretend")


def test_generate_rule_missing_technique_raises():
    with pytest.raises(LookupError):
        generate_rule("T9999.999", "nope", "xql")


def test_generate_rule_btp_technique_includes_executor_hint():
    # T1055 (Process Injection BTP) is windows-only → uses powershell executor.
    r = generate_rule("T1055", "notepad_spawns_cmd", "xql")
    assert "powershell" in r.rule.lower() or "powershell.exe" in r.rule.lower()
