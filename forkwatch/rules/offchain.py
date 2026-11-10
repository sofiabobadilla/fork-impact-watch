"""Glamsterdam rules for off-chain code and config: bots, relayers, deploy scripts, wallets."""

from __future__ import annotations

import re

from ..findings import Finding

FIXED_GAS = re.compile(
    r"\b(gasLimit|gas_limit|GasLimit|maxGas|max_gas|callbackGasLimit|gas)\b[\"']?\s*[:=]\s*"
    r"(?:BigInt\(|big\.NewInt\(|U256::from\()?[\"']?(?P<val>[0-9][0-9_,]{3,})n?\b"
)
AUTH_7702 = re.compile(r"\b(authorizationList|signAuthorization|SetCodeTx|setCodeTx|SignedAuthorization|"
                       r"authorization_list|sign_authorization)\b")
OLD_AUTH_COST = re.compile(r"\b25_?000n?\b|\b25,000\b")


def scan_offchain(path: str, src: str) -> list[Finding]:
    out = []
    lines = src.splitlines()
    auth_lines = [i for i, l in enumerate(lines) if AUTH_7702.search(l)]
    for i, line in enumerate(lines, 1):
        m = FIXED_GAS.search(line)
        if m:
            val = int(re.sub(r"[_,]", "", m.group("val")))
            if 21_000 <= val <= 30_000_000:
                out.append(Finding("offchain-fixed-gas", "FW-GLAM-4", path, i, "possible",
                                   f"Fixed gas limit {val:,} in off-chain code or config. Transactions that create "
                                   "storage or accounts can need several times more after Glamsterdam.",
                                   line.strip()))
    for i in auth_lines:
        near = any(OLD_AUTH_COST.search(lines[j]) for j in range(max(0, i - 5), min(len(lines), i + 6)))
        out.append(Finding("offchain-7702", "FW-GLAM-8", path, i + 1, "likely" if near else "possible",
                           ("Budgets the old 25,000 gas per 7702 authorization; an empty account now costs 235,606. "
                            if near else "Sends EIP-7702 authorizations. ")
                           + "A mined type-4 transaction is not proof the delegation applied: check the account's code.",
                           lines[i].strip()))
    return out
