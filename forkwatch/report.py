"""Render scan results as a terminal summary, a GitHub issue body, JSON, or SARIF."""

from __future__ import annotations

import json
import os
from collections import defaultdict

from . import __version__
from .advisories import advisory_meta, fork_status_line, load_advisories
from .scanner import ScanResult

MARKER = "<!-- forkwatch:issue -->"


def _link(path: str, line: int) -> str:
    server, repo, sha = (os.environ.get(k) for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_SHA"))
    if server and repo and sha:
        return f"[{path}:{line}]({server}/{repo}/blob/{sha}/{path}#L{line})"
    return f"`{path}:{line}`"


def text(res: ScanResult) -> str:
    adv = load_advisories(res.fork)
    lines = [fork_status_line(res.fork), f"{res.files_scanned} files scanned, {len(res.findings)} findings", ""]
    for f in res.findings:
        lines.append(f"[{f.confidence:8}] {f.advisory} {adv[f.advisory].invariant:6} {f.path}:{f.line}  {f.rule}")
        lines.append(f"           {f.message}")
    return "\n".join(lines)


def markdown(res: ScanResult) -> str:
    adv = load_advisories(res.fork)
    meta = advisory_meta(res.fork)
    by_adv = defaultdict(list)
    for f in res.findings:
        by_adv[f.advisory].append(f)
    likely = sum(f.confidence == "likely" for f in res.findings)

    out = [MARKER, f"## Fork impact: {fork_status_line(res.fork)}", ""]
    if not res.findings:
        out.append(f"No red flags found in {res.files_scanned} files for the rules shipped so far.")
    else:
        out.append(f"**{len(res.findings)} places to review** ({likely} likely, "
                   f"{len(res.findings) - likely} possible) in {res.files_scanned} files.")
    out += ["", "These are pattern matches, inferred from source. None is confirmed until a test under the "
            "new fork rules shows it. Anything exploitable: report privately to the affected team and "
            "glamsterdam@ethereum.org, not in a public issue.", ""]
    if res.toolchain.evm_versions:
        tc = ", ".join(f"`{k}`: {v}" for k, v in res.toolchain.evm_versions.items())
        out += [f"Toolchain EVM target: {tc}. Add a CI run against the new fork once your toolchain supports it.", ""]
    for aid in sorted(by_adv):
        a = adv[aid]
        out += [f"### {aid} · {a.invariant}: {a.title}", "", a.summary, "", f"**Fix:** {a.fix} "
                f"([details]({a.reference}))", ""]
        for f in by_adv[aid]:
            out.append(f"- [ ] **{f.confidence}** {_link(f.path, f.line)}: {f.message}")
            for n in f.notes:
                out.append(f"  - {n}")
        out.append("")
    out.append(f"<sub>forkwatch {__version__} · advisories reviewed against EIPs "
               f"{', '.join(map(str, meta['coverage']['reviewed']))}; "
               f"{len(meta['coverage']['not_yet_reviewed'])} other scheduled EIPs not yet covered.</sub>")
    return "\n".join(out)


def as_json(res: ScanResult) -> str:
    return json.dumps({
        "root": res.root, "fork": res.fork, "files_scanned": res.files_scanned,
        "toolchain": {"tools": res.toolchain.tools, "evm_versions": res.toolchain.evm_versions},
        "findings": [f.__dict__ for f in res.findings],
    }, indent=2)


def sarif(res: ScanResult) -> str:
    adv = load_advisories(res.fork)
    rules = {}
    results = []
    for f in res.findings:
        a = adv[f.advisory]
        rid = f"{f.advisory}/{f.rule}"
        rules.setdefault(rid, {
            "id": rid, "name": f.rule,
            "shortDescription": {"text": a.title},
            "fullDescription": {"text": a.summary},
            "helpUri": a.reference,
            "help": {"text": a.fix},
            "properties": {"tags": ["security", res.fork] + [f"EIP-{e}" for e in a.eips]},
        })
        results.append({
            "ruleId": rid,
            "level": "warning" if f.confidence == "likely" else "note",
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path},
                "region": {"startLine": f.line},
            }}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "forkwatch", "version": __version__,
                                "informationUri": "https://github.com/ethereum/glamsterdam-gas-invariants",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }, indent=2)


FORMATS = {"text": text, "markdown": markdown, "json": as_json, "sarif": sarif}
