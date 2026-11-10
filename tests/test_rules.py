import json
from pathlib import Path

from forkwatch.cli import main
from forkwatch.scanner import scan

FIX = Path(__file__).parent / "fixtures" / "glamsterdam"


def test_vulnerable_solidity_hits_every_advisory():
    res = scan(FIX / "vulnerable.sol")
    advisories = {f.advisory for f in res.findings}
    assert advisories == {f"FW-GLAM-{i}" for i in range(1, 9)}


def test_vulnerable_solidity_expected_rules():
    res = scan(FIX / "vulnerable.sol")
    got = {(f.rule, f.confidence) for f in res.findings}
    expected = {
        ("failure-branch-writes-storage", "likely"),
        ("marker-before-unchecked-call", "possible"),
        ("set-clear-around-call", "possible"),
        ("revert-data-oog-guess", "likely"),
        ("post-call-gas-ratio", "likely"),
        ("unchecked-create", "likely"),
        ("unchecked-create", "possible"),
        ("fixed-gas-call", "likely"),
        ("gasleft-metering", "likely"),
        ("fixed-gas-reserve", "likely"),
        ("min-gas-check", "possible"),
        ("stipend-transfer", "possible"),
        ("7702-unprotected-init", "possible"),
    }
    assert expected <= got


def test_zero_idle_lock_modifier_and_context_slot():
    res = scan(FIX / "vulnerable.sol")
    msgs = [f.message for f in res.findings if f.rule == "set-clear-around-call"]
    assert any("modifier `lock`" in m for m in msgs)
    assert any("`currentSender`" in m for m in msgs)


def test_fixed_solidity_is_quiet():
    assert scan(FIX / "fixed.sol").findings == []


def test_common_safe_shapes_are_quiet():
    # false positives found while triaging the Sourcify sample (seed 1), rewritten as fixtures.
    # Batch.run's set-then-unset marker is a genuine INV-2 shape, so that one finding stays.
    got = [(f.rule, f.line) for f in scan(FIX / "quiet.sol").findings]
    assert got == [("set-clear-around-call", 58)]


def test_vyper_rules():
    res = scan(FIX / "splitter.vy")
    assert {f.rule for f in res.findings} == {"fixed-gas-call", "failure-branch-writes-storage", "stipend-transfer"}


def test_offchain_rules():
    res = scan(FIX / "relayer.ts")
    rules = {(f.rule, f.confidence) for f in res.findings}
    assert ("offchain-fixed-gas", "possible") in rules
    assert ("offchain-7702", "likely") in rules


def test_tests_dirs_skipped_unless_asked(tmp_path):
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "A.t.sol").write_text((FIX / "vulnerable.sol").read_text())
    assert scan(tmp_path).findings == []
    assert scan(tmp_path, include_tests=True).findings


def test_toolchain_detection(tmp_path):
    (tmp_path / "foundry.toml").write_text('[profile.default]\nevm_version = "prague"\n')
    assert scan(tmp_path).toolchain.evm_versions == {"foundry.toml": "prague"}


def test_sarif_and_markdown(tmp_path, capsys):
    out = tmp_path / "r.sarif"
    assert main(["scan", str(FIX), "--format", "sarif", "-o", str(out)]) == 0
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert main(["scan", str(FIX), "--format", "markdown", "--fail-on", "likely"]) == 1
    md = capsys.readouterr().out
    assert "forkwatch:issue" in md and "FW-GLAM-1" in md and "glamsterdam@ethereum.org" in md
