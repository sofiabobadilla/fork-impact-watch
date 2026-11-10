# Evaluation on verified mainnet contracts (Glamsterdam rules)

Run on 9 November 2026 with forkwatch 0.1.0. Aggregate numbers only: per-contract results stay in the
ignored `eval/data*/` folders, because a finding can point at a live, possibly affected contract.

## Method

- **Samples.** Two independent random samples of Ethereum mainnet contracts verified on Sourcify
  (`eval/sourcify_sample.py`): up to 10 contracts after each of many random Sourcify match IDs, so the
  sample spans Sourcify's whole history instead of the most recent uploads (which were dominated by one
  factory's clones). Contracts with identical sources are scanned once.
  - **Seed 1 (tuning):** 300 unique contracts. Used to find and fix false positives.
  - **Seed 2 (held out):** 256 unique contracts (the oversampled draw ran out of unique sources before
    300). Scanned once, with the final rules, after tuning was done.
- **Scope.** All Solidity files in each verified source bundle, including bundled libraries. Off-chain rules
  do not apply (no off-chain code on Sourcify).
- **Triage.** Every unique finding was read in context, except `stipend-transfer`, where a random 20
  (seed 1) and 15 (seed 2) were read. A finding counts as correct when the code has the red-flag shape that
  the advisory and the EF invariant describe. This is **shape precision**, not exploitability: no finding was
  tested under Glamsterdam rules, and most correct findings are low impact (see below).
- **Recall** is not measured: there is no public ground truth of affected contracts yet. The fixtures in
  `tests/fixtures/glamsterdam/` check that every advisory fires on its intended shape.

## Results

| | Seed 1, first rules | Seed 1, final rules (tuning set) | Seed 2, final rules (held out) |
|---|---|---|---|
| Contracts scanned | 300 | 300 | 256 |
| Contracts with any finding | 79 | 64 | 48 |
| Unique findings | 123 | 100 | 59 |
| Shape precision, all rules except stipend | 32 / 56 (57%) | 32 / 33 (97%) | 11 / 13 (85%) |
| Shape precision, `stipend-transfer` (sampled) | 20 / 20 | 20 / 20 | 15 / 15 |

Per rule, final rules:

| Rule | Advisory | Seed 1 | Seed 2 (held out) |
|---|---|---|---|
| `set-clear-around-call` | FW-GLAM-2 | 19 / 19 | 8 / 8 |
| `gasleft-metering` | FW-GLAM-5 | 5 / 5 | 2 / 2 |
| `fixed-gas-call` | FW-GLAM-4 | 4 / 4 | none found |
| `failure-branch-writes-storage` | FW-GLAM-1 | 2 / 3 | 0 / 2 |
| `revert-data-oog-guess` | FW-GLAM-3 | 1 / 1 | 1 / 1 |
| `unchecked-create` | FW-GLAM-3 | 1 / 1 | none found |
| `stipend-transfer` | FW-GLAM-7 | 67 found, 20 / 20 sampled | 46 found, 15 / 15 sampled |

## What changed during tuning (seed 1 only)

Each fix follows the EF invariant's own definition and is pinned by `tests/fixtures/glamsterdam/quiet.sol`:

- `failure-branch-writes-storage`: ignore branches that revert anyway, `+=`/`-=` credits (pull payments the
  owner can still claim), and rollbacks of a slot set before the call. The EF text: recording a failure is
  fine if someone can try again.
- `revert-data-oog-guess`: flag empty-revert-data checks only when a path commits something (a return or a
  storage write); ERC721-style receiver checks revert on every path. Drop the `returndatasize()` token-transfer
  idiom, which folds return data into a success flag.
- `unchecked-create`: accept `address(x) != address(0)` as a check.
- `7702-unprotected-init`: ignore empty `initialize` stubs.
- `marker-before-unchecked-call`: ignore locks released after the call.

## Reading the numbers

- **The rules find the shapes they claim to.** On the held-out sample, 11 of 13 non-stipend findings had
  the advisory's red-flag shape, and every sampled stipend finding was a real 2,300-gas ETH transfer.
- **Most correct findings are low impact.** Zero-idle swap locks in token contracts and `transfer` to an
  owner EOA match the shapes but rarely matter. `stipend-transfer` is noisy by design and should be
  filtered or shown last.
- **The weakest rule is FW-GLAM-1.** Its false positives are retry or escrow designs that a lexical rule
  cannot tell apart from a final failure record. This is where a semantic analysis (Slither) is needed.
- **Likely findings are rare.** 1 contract in the held-out sample had a `likely` finding outside bundled
  libraries. Anything that looks exploitable on manual review goes privately to the team and to
  glamsterdam@ethereum.org, never into this repository.
- **Small samples.** 13 held-out non-stipend findings give a wide uncertainty band; a larger run is the
  first milestone of the grant.
