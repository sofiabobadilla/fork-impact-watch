# Fork Impact Watch

Dependabot-style alerts for Ethereum hard forks. Each fork changes gas costs or EVM behavior that live
contracts, bots and relayers rely on. `forkwatch` ships a machine-readable advisory per broken assumption,
scans your repository for code that relies on it, and keeps one issue per fork up to date as the fork
moves from testnet to mainnet.

The first target is **Glamsterdam** (EIP-7773), whose EIP-8037 and EIP-8038 change how state creation and
state access are charged. Core developers postponed the Hoodi testnet activation on 22 October 2026 to study
how this affects deployed contracts. The advisories follow the eight invariants published by the Ethereum
Foundation in [glamsterdam-gas-invariants](https://github.com/ethereum/glamsterdam-gas-invariants) and the
analysis by [ChainSecurity](https://www.chainsecurity.com/blog/glamsterdam-gas/).

## Use it

```bash
pip install .
forkwatch status
forkwatch scan path/to/repo
forkwatch scan path/to/repo --format markdown   # issue body
forkwatch scan path/to/repo --format sarif -o forkwatch.sarif
```

In CI, copy [`examples/forkwatch.yml`](examples/forkwatch.yml). It runs on push and daily, posts findings as
one issue titled `Fork impact: glamsterdam`, and uploads SARIF so findings show as code-scanning alerts.

## What it checks

| Advisory | Invariant | Rule | Looks for |
|---|---|---|---|
| FW-GLAM-1 | INV-1 | `failure-branch-writes-storage` | Storage writes in the failure branch of a low-level call or `catch` |
| FW-GLAM-2 | INV-2 | `set-clear-around-call` | A storage slot set, an external call, then the slot cleared to zero (including zero-idle lock modifiers) |
| FW-GLAM-3 | INV-3 | `revert-data-oog-guess`, `post-call-gas-ratio`, `unchecked-create` | Inferring out-of-gas from empty revert data or a 1/63 ratio after a call; unchecked CREATE/CREATE2 |
| FW-GLAM-4 | INV-4 | `fixed-gas-call`, `offchain-fixed-gas` | `{gas: N}` with a literal or constant; fixed `gasLimit` in bots, scripts and config |
| FW-GLAM-5 | INV-5 | `gasleft-metering` | `start - gasleft()` metering, worse inside `unchecked` |
| FW-GLAM-6 | INV-6 | `marker-before-unchecked-call` | A one-shot flag or nonce written before a call whose failure does not revert |
| FW-GLAM-7 | INV-7 | `fixed-gas-reserve`, `min-gas-check`, `stipend-transfer` | `gasleft() - RESERVE` forwarding, minimum-gas checks without 63/64, `transfer`/`send` |
| FW-GLAM-8 | INV-8 | `7702-unprotected-init`, `offchain-7702` | Unprotected `initialize` on 7702 delegates; type-4 senders budgeting 25,000 per authorization |

Each finding is **likely** (the code has the risky shape, and the caller picks the gas) or **possible** (a
red flag to read in context). Findings are inferred from source, never confirmed. The rules are lexical
patterns, not a Solidity parser, so they miss renamed or assembly-heavy code.

Not covered yet: the other 16 scheduled Glamsterdam EIPs (see `coverage` in
[`forkwatch/data/advisories/glamsterdam.yaml`](forkwatch/data/advisories/glamsterdam.yaml)).

## Layout

- `forkwatch/data/forks.yaml`: fork status per network. A change here is what makes CI re-alert.
- `forkwatch/data/advisories/<fork>.yaml`: one advisory per broken assumption, with EIPs, fix and reference.
- `forkwatch/rules/`: Solidity, Vyper and off-chain rules.
- `tests/fixtures/glamsterdam/`: vulnerable and fixed examples; `pytest` checks both.
- `eval/`: runs the scanner over random samples of verified contracts from Sourcify; results in [`eval/REPORT.md`](eval/REPORT.md).

## Disclosure

If a finding looks exploitable in someone else's deployed contract, report it privately to that team and to
glamsterdam@ethereum.org. Do not open public issues. The evaluation publishes aggregate counts only; raw
per-contract results stay out of the repository (`eval/data/` is ignored).

## License

MIT
