"""Walk a repository, detect its toolchain, and run the rules for one fork."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding
from .rules.offchain import scan_offchain
from .rules.solidity import scan_solidity
from .rules.vyper import scan_vyper

SKIP_DIRS = {".git", "node_modules", "lib", "out", "cache", "artifacts", "typechain", "typechain-types",
             "broadcast", ".venv", "venv", "dist", "build", "coverage", "target", "__pycache__", ".next"}
TEST_DIRS = {"test", "tests", "spec", "mocks", "mock"}
OFFCHAIN_EXT = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rs", ".toml", ".yaml", ".yml", ".json"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "foundry.lock"}
MAX_BYTES = 2_000_000


@dataclass
class Toolchain:
    tools: list[str] = field(default_factory=list)
    evm_versions: dict[str, str] = field(default_factory=dict)  # config file -> evm version
    solc_pragmas: set[str] = field(default_factory=set)


@dataclass
class ScanResult:
    root: str
    fork: str
    files_scanned: int
    findings: list[Finding]
    toolchain: Toolchain


def detect_toolchain(root: Path) -> Toolchain:
    tc = Toolchain()
    foundry = root / "foundry.toml"
    if foundry.exists():
        tc.tools.append("foundry")
        m = re.search(r"^\s*evm_version\s*=\s*[\"']?(\w+)", foundry.read_text(errors="replace"), re.M)
        tc.evm_versions["foundry.toml"] = m.group(1) if m else "default"
    for name in ("hardhat.config.ts", "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs"):
        p = root / name
        if p.exists():
            tc.tools.append("hardhat")
            m = re.search(r"evmVersion\s*:\s*[\"'](\w+)", p.read_text(errors="replace"))
            tc.evm_versions[name] = m.group(1) if m else "default"
    return tc


def _is_test_path(rel: Path) -> bool:
    return bool(set(p.lower() for p in rel.parts[:-1]) & TEST_DIRS) or rel.name.endswith((".t.sol", ".s.sol"))


def iter_files(root: Path, include_tests: bool):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or not p.is_file():
            continue
        if p.name in SKIP_FILES or p.stat().st_size > MAX_BYTES:
            continue
        if not include_tests and _is_test_path(rel):
            continue
        yield p


def scan(root: str | Path, fork: str = "glamsterdam", include_tests: bool = False,
         offchain: bool = True) -> ScanResult:
    if fork != "glamsterdam":
        raise ValueError(f"no rules for fork {fork!r} yet")
    root = Path(root)
    base = root if root.is_dir() else root.parent
    findings: list[Finding] = []
    count = 0
    for p in iter_files(root, include_tests):
        rel = str(p.relative_to(base))
        suffix = p.suffix.lower()
        if suffix == ".sol":
            src = p.read_text(errors="replace")
            findings += scan_solidity(rel, src)
        elif suffix in (".vy", ".vyi"):
            src = p.read_text(errors="replace")
            findings += scan_vyper(rel, src)
        elif offchain and suffix in OFFCHAIN_EXT:
            src = p.read_text(errors="replace")
            findings += scan_offchain(rel, src)
        else:
            continue
        count += 1
    findings.sort(key=Finding.sort_key)
    return ScanResult(str(root), fork, count, findings, detect_toolchain(base))
