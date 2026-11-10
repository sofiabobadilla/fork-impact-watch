"""Load fork status and advisories shipped with the package."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources

import yaml


@dataclass(frozen=True)
class Advisory:
    id: str
    eips: tuple[int, ...]
    invariant: str
    reference: str
    title: str
    summary: str
    fix: str


def _data(path: str) -> dict:
    return yaml.safe_load(resources.files("forkwatch").joinpath("data", path).read_text())


def load_forks() -> dict:
    return _data("forks.yaml")


def load_advisories(fork: str) -> dict[str, Advisory]:
    raw = _data(f"advisories/{fork}.yaml")
    out = {}
    for a in raw["advisories"]:
        out[a["id"]] = Advisory(
            id=a["id"],
            eips=tuple(a["eips"]),
            invariant=a["invariant"],
            reference=a["reference"],
            title=a["title"],
            summary=a["summary"],
            fix=a["fix"],
        )
    return out


def advisory_meta(fork: str) -> dict:
    raw = _data(f"advisories/{fork}.yaml")
    return {k: v for k, v in raw.items() if k != "advisories"}


def fork_status_line(fork: str) -> str:
    info = load_forks()["forks"][fork]
    parts = []
    for net, s in info["networks"].items():
        when = f" {s['activation'][:10]}" if s.get("activation") else ""
        parts.append(f"{net}: {s['status']}{when}")
    return f"{info['name']} (EIP-{info['meta_eip']}) · " + " · ".join(parts)
