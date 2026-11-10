"""Glamsterdam rules for Vyper source. Line-based; Vyper's syntax keeps these shapes on one line."""

from __future__ import annotations

import re

from ..findings import Finding

RULES = [
    (re.compile(r"\braw_call\s*\(.*revert_on_failure\s*=\s*False"), "failure-branch-writes-storage", "FW-GLAM-1",
     "possible", "`raw_call` with `revert_on_failure=False`: check what the failure branch records. A starved call "
     "can make that outcome permanent."),
    (re.compile(r"\b(raw_call|extcall|staticcall)\b.*\bgas\s*=\s*[0-9][0-9_]*"), "fixed-gas-call", "FW-GLAM-4",
     "likely", "External call with a fixed gas amount. Re-check it at Amsterdam prices."),
    (re.compile(r"\bcreate_\w+\s*\(.*revert_on_failure\s*=\s*False"), "unchecked-create", "FW-GLAM-3",
     "possible", "Contract creation with `revert_on_failure=False`: check the result for a zero address."),
    (re.compile(r"(?<![\w.])send\s*\("), "stipend-transfer", "FW-GLAM-7",
     "possible", "`send` forwards a 2,300 gas stipend, which cannot create a storage slot in a receiving contract."),
    (re.compile(r"\w+\s*-\s*msg\.gas\b"), "gasleft-metering", "FW-GLAM-5",
     "possible", "Meters cost by subtracting `msg.gas` readings; msg.gas can now rise and misses reservoir-paid state gas."),
]


def scan_vyper(path: str, src: str) -> list[Finding]:
    out = []
    for i, line in enumerate(src.splitlines(), 1):
        code = line.split("#", 1)[0]
        for rx, rule, adv, conf, msg in RULES:
            if rx.search(code):
                out.append(Finding(rule, adv, path, i, conf, msg, line.strip()))
    return out
