"""Run forkwatch over a sample of verified Ethereum mainnet contracts from Sourcify.

Downloads sources into DATA_DIR (kept out of git: per-contract results can point at live, possibly
affected contracts and must not be published). Writes an aggregate summary with no addresses.

    python -I eval/sourcify_sample.py --n 300 --data /path/outside/repo
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

from forkwatch.scanner import scan

API = "https://sourcify.dev/server/v2"


def get(url: str, tries: int = 6) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "forkwatch-eval/0.1"})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code != 429 or i == tries - 1:
                raise
            time.sleep(int(e.headers.get("Retry-After") or 2 ** (i + 1)))
    raise RuntimeError("unreachable")


def list_contracts(n: int, chain: int, seed: int, cache: Path) -> list[dict]:
    """Spread the sample over Sourcify's whole history: a few contracts after each random matchId.

    Taking the newest contracts instead gives a sample dominated by one factory's clones.
    Progress is saved to `cache` after every request, so an interrupted run resumes where it stopped.
    """
    state = json.loads(cache.read_text()) if cache.exists() else {}
    if state.get("seed") != seed or state.get("chain") != chain:
        state = {"seed": seed, "chain": chain, "draws": 0, "contracts": []}
    rng = random.Random(seed)
    top = state.get("top") or int(get(f"{API}/contracts/{chain}?limit=1")["results"][0]["matchId"])
    state["top"] = top
    for _ in range(state["draws"]):  # replay the random draws already used
        rng.randrange(1, top)
    seen = {c["address"] for c in state["contracts"]}
    while len(state["contracts"]) < n * 2.2:  # oversample: duplicates by source are dropped later
        after = rng.randrange(1, top)
        for c in get(f"{API}/contracts/{chain}?limit=10&afterMatchId={after}")["results"]:
            if c["address"] not in seen:
                seen.add(c["address"])
                state["contracts"].append(c)
        state["draws"] += 1
        cache.write_text(json.dumps(state))
        if state["draws"] % 20 == 0:
            print(f"listed {len(state['contracts'])}", flush=True)
        time.sleep(0.3)
    return state["contracts"]


def safe_rel(path: str) -> Path:
    parts = [p for p in Path(path).parts if p not in ("", ".", "..", "/")]
    return Path(*parts) if parts else Path("unnamed.sol")


def fetch(c: dict, chain: int, dest: Path) -> bool:
    if dest.exists():
        return True
    data = get(f"{API}/contract/{chain}/{c['address']}?fields=sources")
    sources = data.get("sources") or {}
    if not sources:
        return False
    for path, s in sources.items():
        p = dest / safe_rel(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(s.get("content", ""))
    return True


def is_library_path(path: str) -> bool:
    return path.startswith(("@", "lib/", "node_modules/")) or "/node_modules/" in path or "openzeppelin" in path.lower()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--chain", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1, help="fixes which contracts are sampled")
    ap.add_argument("--data", required=True, help="directory outside the repo for sources and raw results")
    ap.add_argument("--summary", default="eval/summary.json")
    args = ap.parse_args()

    data = Path(args.data)
    data.mkdir(parents=True, exist_ok=True)
    contracts = list_contracts(args.n, args.chain, args.seed, data / "sample.json")

    raw = []
    hashes = set()
    scanned = 0
    for c in contracts:
        if scanned >= args.n:
            break
        d = data / "src" / c["address"].lower()
        try:
            if not fetch(c, args.chain, d):
                continue
        except Exception as e:  # network errors: skip the contract, keep the run going
            print("skip", c["address"], e)
            continue
        h = hashlib.sha256(b"".join(p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file())).hexdigest()
        if h in hashes:  # same sources as a contract already scanned (clones, factories)
            continue
        hashes.add(h)
        scanned += 1
        if scanned % 25 == 0:
            print(f"scanned {scanned}/{args.n}", flush=True)
        res = scan(d, include_tests=True, offchain=False)
        for f in res.findings:
            content = (d / f.path).read_text(errors="replace")
            raw.append({**f.__dict__, "address": c["address"],
                        "file_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
                        "library": is_library_path(f.path)})
        time.sleep(0.3)

    (data / "findings.json").write_text(json.dumps(raw, indent=1))

    with_any = len({r["address"] for r in raw})
    with_likely = len({r["address"] for r in raw if r["confidence"] == "likely" and not r["library"]})
    unique = {(r["file_hash"], r["rule"], r["line"]): r for r in raw}
    summary = {
        "sample": {"source": "Sourcify v2, a few contracts after each of many random matchIds", "chain": args.chain,
                   "requested": args.n, "scanned": scanned,
                   "seed": args.seed, "deduplicated_by": "sha256 of all source files"},
        "contracts_with_any_finding": with_any,
        "contracts_with_likely_finding_outside_libraries": with_likely,
        "findings_total": len(raw),
        "findings_unique_by_file_content": len(unique),
        "by_rule": Counter(f"{r['advisory']} {r['rule']} ({r['confidence']})" for r in unique.values()),
        "by_rule_outside_libraries": Counter(f"{r['advisory']} {r['rule']} ({r['confidence']})"
                                             for r in unique.values() if not r["library"]),
    }
    Path(args.summary).write_text(json.dumps(summary, indent=2, sort_keys=True))
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
