"""Glamsterdam rules for Solidity source (EIP-8037 / EIP-8038)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..findings import Finding
from ..solidity import Contract, Function, blank_comments_and_strings, line_of, match_brace, parse

NUMERIC = re.compile(r"^\s*\(?\s*[0-9][0-9_]*(\s*(e\d+|\*\s*[0-9_]+))?\s*\)?\s*$")
ZEROISH = re.compile(r"^\s*(0|false|address\(0\)|bytes32\(0\)|0x0+|\w+\(0\))\s*$")
# A call that leaves this contract. Interface calls are recognised by a cast, `IFoo(x).bar(`,
# or by the try keyword; plain `x.bar(` is too often a library or struct member to count.
EXTERNAL_CALL = re.compile(
    r"\.(call|delegatecall|staticcall)\s*(\{[^{}]*\})?\s*\("
    r"|\.(transfer|send)\s*\("
    r"|\b(try)\b"
    r"|\b[A-Z]\w*\([^;()]*\)\.\w+\s*(\{[^{}]*\})?\s*\("
    r"|\bsafeTransfer\w*\s*\(|\bfunctionCall\w*\s*\("
    r"|\b_;"
)
LOW_LEVEL = re.compile(r"\.(call|delegatecall)\s*(\{[^{}]*\})?\s*\(")


@dataclass
class CallSite:
    start: int  # offset in function body
    end: int  # offset just after the statement
    kind: str  # "lowlevel" or "try"
    ok_var: str | None
    failure_branches: list[tuple[int, int]]  # (start, end) offsets in the body
    reverts_on_failure: bool
    gas_option: str | None


def _stmt_start(body: str, idx: int) -> int:
    j = max(body.rfind(";", 0, idx), body.rfind("{", 0, idx), body.rfind("}", 0, idx))
    return j + 1


def _stmt_end(body: str, idx: int) -> int:
    depth = 0
    for k in range(idx, len(body)):
        ch = body[k]
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == ";" and depth <= 0:
            return k + 1
    return len(body)


def _branch_after(body: str, idx: int) -> tuple[int, int]:
    """The statement or block starting at idx (after an `if (...)` or `else`)."""
    k = idx
    while k < len(body) and body[k].isspace():
        k += 1
    if k < len(body) and body[k] == "{":
        return k, match_brace(body, k) + 1
    return k, _stmt_end(body, k)


def _gas_option(opts: str | None) -> str | None:
    if not opts:
        return None
    m = re.search(r"\bgas\s*:\s*([^,}]+)", opts)
    return m.group(1).strip() if m else None


def _call_sites(fn: Function) -> list[CallSite]:
    body = fn.body
    sites: list[CallSite] = []

    for m in LOW_LEVEL.finditer(body):
        s = _stmt_start(body, m.start())
        e = _stmt_end(body, m.start())
        stmt = body[s:e]
        okm = re.match(r"\s*\(\s*bool\s+(\w+)", stmt) or re.match(r"\s*\(\s*(\w+)\s*,", stmt) \
            or re.match(r"\s*(?:bool\s+)?(\w+)\s*=\s*", stmt)
        ok = okm.group(1) if okm else None
        rest = body[e:]
        branches = []
        reverts = False
        if ok:
            if re.search(rf"\brequire\s*\(\s*{ok}\b|\bassert\s*\(\s*{ok}\b", rest):
                reverts = True
            for im in re.finditer(r"\bif\s*\(", rest):
                cond_end = match_brace(rest, im.end() - 1, "(", ")")
                cond = rest[im.end():cond_end]
                if re.fullmatch(rf"\s*!\s*{ok}\s*(\|\|.*)?", cond, re.S):
                    b = _branch_after(rest, cond_end + 1)
                    if re.match(r"\s*\{?\s*revert\b", rest[b[0]:b[1]]):
                        reverts = True
                    else:
                        branches.append((e + b[0], e + b[1]))
                elif re.fullmatch(rf"\s*{ok}\s*", cond):
                    b = _branch_after(rest, cond_end + 1)
                    em = re.match(r"\s*else\b", rest[b[1]:])
                    if em:
                        eb = _branch_after(rest, b[1] + em.end())
                        if re.match(r"\s*\{?\s*revert\b", rest[eb[0]:eb[1]]):
                            reverts = True
                        else:
                            branches.append((e + eb[0], e + eb[1]))
        sites.append(CallSite(m.start(), e, "lowlevel", ok, branches, reverts, _gas_option(m.group(2))))

    for m in re.finditer(r"\btry\b", body):
        # find the success block: the first `{` not immediately after a word (call options)
        k = m.end()
        block = -1
        depth = 0
        while k < len(body):
            ch = body[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "{" and depth == 0:
                prev = body[:k].rstrip()[-1:]
                if prev and (prev.isalnum() or prev == "_"):
                    k = match_brace(body, k)  # call options like {gas: X}
                else:
                    block = k
                    break
            k += 1
        if block == -1:
            continue
        opts = re.search(r"\{([^{}]*)\}\s*\(", body[m.end():block])
        k = match_brace(body, block) + 1
        branches = []
        reverts = True
        while True:
            cm = re.match(r"\s*catch\b[^{]*\{", body[k:])
            if not cm:
                break
            cb = k + cm.end() - 1
            ce = match_brace(body, cb) + 1
            if not re.search(r"\brevert\b|\brequire\s*\(", body[cb:ce]):
                reverts = False
            branches.append((cb, ce))
            k = ce
        sites.append(CallSite(m.start(), k, "try", None, branches, reverts,
                              _gas_option(opts.group(0) if opts else None)))
    return sites


class _Ctx:
    def __init__(self, path: str, clean: str, raw: str, contracts: list[Contract]):
        self.path = path
        self.clean = clean
        self.raw_lines = raw.splitlines()
        self.contracts = contracts
        self.state_vars = set().union(*(c.state_vars for c in contracts)) if contracts else set()
        self.constants = {}
        for c in contracts:
            self.constants.update(c.constants)
        self.findings: list[Finding] = []
        names = sorted(self.state_vars, key=len, reverse=True)
        self.write_re = None
        if names:
            alt = "|".join(map(re.escape, names))
            self.write_re = re.compile(
                rf"(?<![\w.])(?P<lhs>(?:{alt})(?:\s*\[[^;=]*\])*(?:\.\w+)*)\s*"
                rf"(?P<op>=(?!=)|\+=|-=|\|=|&=|\+\+|--)"
                rf"|\bdelete\s+(?P<del>(?:{alt})\b[^;]*)"
                rf"|(?:\+\+|--)\s*(?P<pre>(?:{alt})\b)"
                rf"|(?<![\w.])(?P<push>(?:{alt})(?:\s*\[[^;=]*\])*)\.push\s*\("
            )

    def add(self, rule, advisory, fn_body_start, offset, confidence, message, notes=None):
        line = line_of(self.clean, fn_body_start + offset)
        snippet = self.raw_lines[line - 1].strip() if line - 1 < len(self.raw_lines) else ""
        self.findings.append(Finding(rule, advisory, self.path, line, confidence, message, snippet, notes or []))

    def storage_writes(self, text: str):
        if not self.write_re:
            return []
        return list(self.write_re.finditer(text))


def _pre_call_gas_check(body: str, call_offset: int) -> bool:
    before = body[:call_offset]
    return bool(re.search(r"\b(require|if)\s*\([^;]*gasleft\(\)", before))


def _reverts_unconditionally(block: str) -> bool:
    """A `revert` at the block's own level, not behind an `if`: the whole transaction reverts anyway."""
    inner = block.strip()
    if inner.startswith("{"):
        inner = inner[1:inner.rfind("}")] if "}" in inner else inner[1:]
    flat = list(inner)
    for m in re.finditer(r"\{", inner):  # blank nested blocks
        if flat[m.start()] != "{":
            continue
        end = match_brace(inner, m.start())
        for k in range(m.start(), min(end + 1, len(flat))):
            flat[k] = " "
    flat = "".join(flat)
    for m in re.finditer(r"\brevert\b|\b_revert\s*\(", flat):
        stmt = flat[_stmt_start(flat, m.start()):m.start()]
        if not re.search(r"\b(if|else)\b|\?", stmt):
            return True
    return False


def _lhs_key(w: re.Match) -> str:
    return " ".join((w.group("lhs") or w.group("del") or w.group("pre") or w.group("push") or "").split())


def _marking_writes(ctx: _Ctx, branch: str, written_before: set[str]) -> list[re.Match]:
    """Writes that record an outcome. Skips rollbacks of slots set before the call (the item stays
    retryable) and `+=`/`-=` bookkeeping such as pull-payment credits, which the owner can still claim."""
    out = []
    for w in ctx.storage_writes(branch):
        if w.group("op") in ("+=", "-="):
            continue
        if _lhs_key(w) in written_before:
            continue
        out.append(w)
    return out


def _rule_failure_branch(ctx: _Ctx, fn: Function, sites: list[CallSite]):
    """FW-GLAM-1 / FW-GLAM-6: failure branch of an external call records an outcome in storage."""
    for site in sites:
        written_before = {_lhs_key(w) for w in ctx.storage_writes(fn.body[:site.start])}
        for (bs, be) in site.failure_branches:
            branch = fn.body[bs:be]
            if _reverts_unconditionally(branch):
                continue
            writes = _marking_writes(ctx, branch, written_before)
            if not writes:
                continue
            gas_checked = _pre_call_gas_check(fn.body, site.start)
            likely = fn.permissionless and not gas_checked
            notes = []
            notes.append("caller picks the gas: function is callable by anyone" if fn.permissionless
                         else "function has access control: impact depends on who can call it")
            if gas_checked:
                notes.append("a gasleft() check runs before the call; confirm it covers the callee's needs at Amsterdam prices")
            ctx.add("failure-branch-writes-storage", "FW-GLAM-1", fn.body_start, bs + writes[0].start(),
                    "likely" if likely else "possible",
                    f"`{fn.name}`: the failure branch of an external call writes storage. A caller who starves "
                    "the call can make this outcome permanent (also see INV-6).", notes)


def _rule_marker_before_call(ctx: _Ctx, fn: Function, sites: list[CallSite]):
    """FW-GLAM-6: a one-shot marker is set before a call whose failure does not revert."""
    if not fn.permissionless:
        return
    for site in sites:
        if site.reverts_on_failure:
            continue
        before = fn.body[:site.start]
        after = fn.body[site.end:]
        for w in ctx.storage_writes(before):
            stmt = before[w.start():_stmt_end(before, w.start())]
            key = re.escape(_lhs_key(w))
            if key and re.search(rf"{key}\s*=\s*(false|0)\b|\bdelete\s+{key}", after):
                continue  # a lock that is released after the call, not a one-shot marker
            if re.search(r"=\s*true\b|\+\+|\+=\s*1\b", stmt) or w.group("pre"):
                if _pre_call_gas_check(fn.body, site.start):
                    break
                ctx.add("marker-before-unchecked-call", "FW-GLAM-6", fn.body_start, w.start(), "possible",
                        f"`{fn.name}`: a one-shot marker is written before an external call whose failure does "
                        "not revert. If the call is starved, the marker stays used up.")
                break


def _rule_set_clear(ctx: _Ctx, fn: Function):
    """FW-GLAM-2: slot set to non-zero, external call, slot cleared again."""
    body = fn.body
    calls = [m.start() for m in EXTERNAL_CALL.finditer(body)]
    if not calls:
        return
    writes = ctx.storage_writes(body)
    sets = {}
    for w in writes:
        if w.group("lhs") and w.group("op") == "=":
            lhs = " ".join(w.group("lhs").split())
            rhs_end = _stmt_end(body, w.end())
            rhs = body[w.end():rhs_end].rstrip(";")
            if ZEROISH.match(rhs):
                first = sets.get(lhs)
                if first is not None and any(first < c < w.start() for c in calls):
                    _report_set_clear(ctx, fn, lhs, first)
                    sets.pop(lhs)
            else:
                sets.setdefault(lhs, w.start())
        elif w.group("del"):
            lhs = " ".join(w.group("del").split())
            first = sets.get(lhs)
            if first is not None and any(first < c < w.start() for c in calls):
                _report_set_clear(ctx, fn, lhs, first)
                sets.pop(lhs)


def _report_set_clear(ctx, fn, lhs, offset):
    where = "modifier" if fn.visibility == "modifier" else "function"
    ctx.add("set-clear-around-call", "FW-GLAM-2", fn.body_start, offset, "possible",
            f"{where} `{fn.name}`: `{lhs}` is set, an external call runs, then it is cleared to zero. If it was "
            "zero when the transaction started, clearing it refills gas mid-call. Prefer transient storage.")


def _rule_reverted_call_guess(ctx: _Ctx, fn: Function, sites: list[CallSite]):
    """FW-GLAM-3: guessing out-of-gas from revert data or gasleft() after a call; unchecked CREATE."""
    body = fn.body
    first_call = min((s.start for s in sites), default=None)
    for m in re.finditer(r"catch\s*\(\s*bytes\s+memory\s+(\w+)\s*\)", body):
        var = m.group(1)
        blk = body.find("{", m.end())
        end = match_brace(body, blk)
        catch_block = body[blk:end]
        lm = re.search(rf"\b{var}\.length\s*==\s*0\b", catch_block)
        # Only a problem when one of the paths commits something. ERC721-style receiver checks
        # revert on every path and are left alone.
        commits = re.search(r"\breturn\b", catch_block) or ctx.storage_writes(catch_block)
        if lm and commits:
            ctx.add("revert-data-oog-guess", "FW-GLAM-3", fn.body_start, blk + lm.start(), "likely",
                    f"`{fn.name}`: treats empty revert data as out-of-gas. A reverting intermediate call can hand "
                    "gas back and wrap the error, so the other branch runs.")
    # Assembly `if iszero(returndatasize())` branches; the token-transfer idiom that folds
    # returndatasize() into the success flag with and()/or() is not a failure guess.
    for m in re.finditer(r"\bif\s+iszero\s*\(\s*returndatasize\s*\(\s*\)\s*\)", body):
        ctx.add("revert-data-oog-guess", "FW-GLAM-3", fn.body_start, m.start(), "possible",
                f"`{fn.name}`: branches on empty return data; do not infer out-of-gas from it.")
    if first_call is not None:
        # The B1/B2 shape: `gasleft() <= before / 63` after the call. The pre-call fix shape
        # `gasleft() * 63 / 64 >= need` has the ratio on gasleft's own side and is not matched.
        ratio = re.compile(r"gasleft\s*\(\s*\)\s*[<>]=?\s*[^;]*?/\s*6[34]\b"
                           r"|/\s*6[34]\s*[<>]=?\s*gasleft\s*\(\s*\)")
        m = ratio.search(body, first_call)
        if m:
            ctx.add("post-call-gas-ratio", "FW-GLAM-3", fn.body_start, m.start(), "likely",
                    f"`{fn.name}`: compares gasleft() with a 1/63 or 1/64 ratio after a call to detect "
                    "out-of-gas. Gas handed back by reverted calls defeats this check.")
    for m in re.finditer(r"\bpop\s*\(\s*create2?\s*\(", body):
        ctx.add("unchecked-create", "FW-GLAM-3", fn.body_start, m.start(), "likely",
                f"`{fn.name}`: discards the CREATE/CREATE2 result. A failed deployment leaves an address with no code.")
    for m in re.finditer(r"(\w+)\s*:=\s*create2?\s*\(", body):
        var = m.group(1)
        after = body[m.end():]
        if not re.search(rf"iszero\s*\(\s*{var}\b|\b{var}\s*\)?\s*[!=]=\s*address\(0\)|\b{var}\.code\.length"
                         rf"|extcodesize\s*\(\s*{var}\b|address\(0\)\s*[!=]=\s*(address\()?\s*{var}\b",
                         after):
            ctx.add("unchecked-create", "FW-GLAM-3", fn.body_start, m.start(), "possible",
                    f"`{fn.name}`: CREATE/CREATE2 result `{var}` is not checked for zero or empty code.")


def _resolve_numeric(ctx: _Ctx, expr: str) -> tuple[bool, str]:
    expr = expr.strip()
    if NUMERIC.match(expr):
        return True, expr
    name = re.fullmatch(r"\w+", expr)
    if name and expr in ctx.constants:
        val = ctx.constants[expr]
        return (bool(NUMERIC.match(val)), f"{expr} = {val}" if val else expr)
    return False, expr


def _rule_fixed_gas(ctx: _Ctx, fn: Function, sites: list[CallSite]):
    """FW-GLAM-4 and FW-GLAM-7: fixed gas amounts and reserves on calls."""
    body = fn.body
    for m in re.finditer(r"\{\s*[^{}]*\bgas\s*:\s*([^,}]+)[^{}]*\}\s*\(|\.gas\s*\(\s*([^()]+)\)", body):
        expr = (m.group(1) or m.group(2)).strip()
        if re.search(r"gasleft\s*\(\s*\)\s*-", expr):
            ctx.add("fixed-gas-reserve", "FW-GLAM-7", fn.body_start, m.start(), "likely",
                    f"`{fn.name}`: forwards `{expr}`, keeping a fixed reserve for the work after the call. "
                    "Writing a new slot afterwards can now cost 110,020 gas.")
            continue
        fixed, shown = _resolve_numeric(ctx, expr)
        if fixed:
            ctx.add("fixed-gas-call", "FW-GLAM-4", fn.body_start, m.start(), "likely",
                    f"`{fn.name}`: external call with a fixed gas amount ({shown}). Re-check it at Amsterdam "
                    "prices, especially when the callee may create storage or accounts.")
        elif expr in ctx.constants:
            ctx.add("fixed-gas-call", "FW-GLAM-4", fn.body_start, m.start(), "possible",
                    f"`{fn.name}`: external call gas comes from constant/immutable `{expr}`, which cannot be "
                    "changed without an upgrade.")


def _rule_min_gas_check(ctx: _Ctx, fn: Function):
    """FW-GLAM-7: minimum-gas checks without the 63/64 factor."""
    for m in re.finditer(r"\b(require|if)\s*\(", fn.body):
        end = match_brace(fn.body, m.end() - 1, "(", ")")
        cond = fn.body[m.end():end]
        if re.search(r"gasleft\s*\(\s*\)\s*[<>]=?|[<>]=?\s*gasleft\s*\(\s*\)", cond) and not re.search(r"\b6[34]\b", cond):
            ctx.add("min-gas-check", "FW-GLAM-7", fn.body_start, m.start(), "possible",
                    f"`{fn.name}`: minimum-gas check without the 63/64 factor. Re-size it at Amsterdam prices.")


def _rule_stipend(ctx: _Ctx, fn: Function):
    """FW-GLAM-7: transfer/send forward only 2,300 gas."""
    for m in re.finditer(r"\.(transfer|send)\s*\(", fn.body):
        end = match_brace(fn.body, m.end() - 1, "(", ")")
        args = fn.body[m.end():end]
        depth = 0
        commas = 0
        for ch in args:
            depth += ch in "([{"
            depth -= ch in ")]}"
            commas += ch == "," and depth == 0
        if commas == 0 and args.strip():
            ctx.add("stipend-transfer", "FW-GLAM-7", fn.body_start, m.start(), "possible",
                    f"`{fn.name}`: ETH `{m.group(1)}` forwards 2,300 gas, which cannot create a storage slot in a "
                    "receiving contract. Fine for EOAs; breaks for vaults and smart wallets that record deposits.")


def _rule_gas_metering(ctx: _Ctx, fn: Function):
    """FW-GLAM-5: subtracting two gasleft() readings."""
    body = fn.body
    starts = set(re.findall(r"\b(\w+)\s*=\s*gasleft\s*\(\s*\)", body))
    if not starts:
        return
    unchecked = []
    for um in re.finditer(r"\bunchecked\s*\{", body):
        b = um.end() - 1
        unchecked.append((b, match_brace(body, b)))
    alt = "|".join(map(re.escape, starts))
    for m in re.finditer(rf"\b({alt})\s*-\s*gasleft\s*\(\s*\)", body):
        inside = any(a < m.start() < b for a, b in unchecked)
        ctx.add("gasleft-metering", "FW-GLAM-5", fn.body_start, m.start(), "likely" if inside else "possible",
                f"`{fn.name}`: meters cost as `{m.group(1)} - gasleft()`"
                + (" inside `unchecked`, which wraps to a huge value if gasleft() went up."
                   if inside else ". gasleft() can now rise, so this can revert, and it misses reservoir-paid state gas."))


def _rule_7702_init(ctx: _Ctx, fn: Function, file_mentions_7702: bool):
    """FW-GLAM-8: unprotected initialize/setup on a possible 7702 delegate."""
    if not file_mentions_7702:
        return
    if re.fullmatch(r"(initialize|setup|init)\w*", fn.name, re.I) and fn.permissionless and fn.body.strip():
        if not re.search(r"ecrecover|isValidSignature|SignatureChecker|ECDSA|address\(this\)", fn.body + fn.modifiers):
            ctx.add("7702-unprotected-init", "FW-GLAM-8", fn.body_start, 0, "possible",
                    f"`{fn.name}`: callable by anyone and not bound to a signature or self-call. If accounts "
                    "delegate to this contract via EIP-7702, an exposed authorization lets anyone initialize it.")


def scan_solidity(path: str, src: str) -> list[Finding]:
    clean = blank_comments_and_strings(src)
    contracts = parse(clean)
    ctx = _Ctx(path, clean, src, contracts)
    mentions_7702 = bool(re.search(r"7702|0xef0100|delegat(ed|ion)\s+account", src, re.I))
    for c in contracts:
        if c.kind == "interface":
            continue
        for fn in c.functions:
            if fn.visibility == "modifier":
                _rule_set_clear(ctx, fn)
                continue
            sites = _call_sites(fn)
            _rule_failure_branch(ctx, fn, sites)
            _rule_marker_before_call(ctx, fn, sites)
            _rule_set_clear(ctx, fn)
            _rule_reverted_call_guess(ctx, fn, sites)
            _rule_fixed_gas(ctx, fn, sites)
            _rule_min_gas_check(ctx, fn)
            _rule_stipend(ctx, fn)
            _rule_gas_metering(ctx, fn)
            _rule_7702_init(ctx, fn, mentions_7702)
    return ctx.findings
