"""Just enough Solidity structure for pattern rules: contracts, state variables, functions.

This is a lexical approximation, not a parser. It works on source with comments and string
literals blanked out (same length, newlines kept), so offsets map straight back to lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


def blank_comments_and_strings(src: str) -> str:
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            # keep the quotes so expressions stay well formed
            out.append(c + " " * (j - i - 2) + (src[j - 1] if j - i >= 2 else ""))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def match_brace(text: str, open_idx: int, open_ch: str = "{", close_ch: str = "}") -> int:
    """Index of the bracket closing the one at open_idx, or len(text) if unbalanced."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return len(text)


@dataclass
class Function:
    name: str
    start: int  # offset of the `function` keyword
    body_start: int  # offset just after `{`
    body_end: int  # offset of the closing `}`
    header: str
    body: str
    visibility: str
    modifiers: str

    @property
    def permissionless(self) -> bool:
        """Anyone can call it, so the caller picks the gas."""
        if self.visibility not in ("external", "public"):
            return False
        if re.search(r"\b(only[A-Z_]\w*|auth|requiresAuth|restricted)\b", self.modifiers):
            return False
        if re.search(r"msg\.sender\s*[!=]=|[!=]=\s*msg\.sender|_checkOwner\(|_checkRole\(|hasRole\(|_msgSender\(\)\s*[!=]=",
                     self.body):
            return False
        return True


@dataclass
class Contract:
    kind: str
    name: str
    start: int
    body_start: int
    body_end: int
    state_vars: set[str] = field(default_factory=set)
    constants: dict[str, str] = field(default_factory=dict)  # name -> value expression
    transient_vars: set[str] = field(default_factory=set)
    functions: list[Function] = field(default_factory=list)


_CONTRACT_RE = re.compile(r"\b(abstract\s+contract|contract|library|interface)\s+(\w+)[^{;]*\{")
_FUNC_RE = re.compile(r"\b(function\s+(\w+)|constructor|fallback|receive|modifier\s+(\w+))\s*\(")
_SKIP_BLOCK_RE = re.compile(r"\b(struct|enum|event|error)\b[^{;]*\{")
_DECL_KEYWORDS = {"public", "private", "internal", "constant", "immutable", "transient", "override"}


def _strip_blocks(body: str, pattern: re.Pattern) -> str:
    out = list(body)
    for m in pattern.finditer(body):
        brace = body.find("{", m.start())
        if brace == -1:
            continue
        end = match_brace(body, brace)
        for k in range(m.start(), min(end + 1, len(out))):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def _parse_state(contract_body: str, c: Contract) -> None:
    text = _strip_blocks(contract_body, _SKIP_BLOCK_RE)
    # blank function and modifier bodies
    out = list(text)
    for m in _FUNC_RE.finditer(text):
        paren = text.find("(", m.start())
        close = match_brace(text, paren, "(", ")")
        semi = text.find(";", close)
        brace = text.find("{", close)
        if brace != -1 and (semi == -1 or brace < semi):
            end = match_brace(text, brace)
        else:
            end = semi if semi != -1 else len(text)
        for k in range(m.start(), min(end + 1, len(out))):
            if out[k] != "\n":
                out[k] = " "
    text = "".join(out)
    for stmt in text.split(";"):
        s = " ".join(stmt.split())
        if not s or s.startswith(("using ", "pragma ", "import ")):
            continue
        s = re.sub(r"mapping\s*\(.*\)", "mapping", s)
        lhs, _, rhs = s.partition("=")
        words = re.findall(r"[A-Za-z_]\w*", lhs)
        if len(words) < 2:
            continue
        name = words[-1]
        quals = set(words[1:-1]) & _DECL_KEYWORDS
        if "constant" in quals or "immutable" in quals:
            c.constants[name] = rhs.strip()
        elif "transient" in quals:
            c.transient_vars.add(name)
        else:
            c.state_vars.add(name)


def parse(clean: str) -> list[Contract]:
    contracts = []
    for m in _CONTRACT_RE.finditer(clean):
        brace = clean.find("{", m.end() - 1)
        end = match_brace(clean, brace)
        c = Contract(kind=m.group(1).split()[-1], name=m.group(2), start=m.start(),
                     body_start=brace + 1, body_end=end)
        body = clean[brace + 1:end]
        _parse_state(body, c)
        for fm in _FUNC_RE.finditer(body):
            abs_start = brace + 1 + fm.start()
            paren = clean.find("(", abs_start)
            close = match_brace(clean, paren, "(", ")")
            semi = clean.find(";", close)
            fbrace = clean.find("{", close)
            if fbrace == -1 or (semi != -1 and semi < fbrace):
                continue  # declaration only
            fend = match_brace(clean, fbrace)
            header = clean[abs_start:fbrace]
            vis = re.search(r"\b(external|public|internal|private)\b", header[close - abs_start:])
            name = fm.group(2) or fm.group(3) or fm.group(1)
            if fm.group(1).startswith("modifier"):
                visibility = "modifier"
            elif name in ("receive", "fallback"):
                visibility = "external"
            elif name == "constructor":
                visibility = "constructor"
            else:
                visibility = vis.group(1) if vis else "public"
            c.functions.append(Function(
                name=name, start=abs_start, body_start=fbrace + 1, body_end=fend,
                header=header, body=clean[fbrace + 1:fend], visibility=visibility,
                modifiers=header[close - abs_start + 1:],
            ))
        contracts.append(c)
    return contracts


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1
