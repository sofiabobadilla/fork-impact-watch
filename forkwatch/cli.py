"""Find code that an upcoming Ethereum hard fork breaks."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .advisories import fork_status_line, load_forks
from .report import FORMATS
from .scanner import scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="forkwatch", description=__doc__)
    p.add_argument("--version", action="version", version=f"forkwatch {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a repository or file for code an upcoming fork breaks")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--fork", default="glamsterdam")
    s.add_argument("--format", choices=sorted(FORMATS), default="text")
    s.add_argument("--output", "-o", help="write the report here instead of stdout")
    s.add_argument("--include-tests", action="store_true", help="also scan test/, mocks and *.t.sol")
    s.add_argument("--no-offchain", action="store_true", help="skip TS/JS/Python/Go/Rust and config files")
    s.add_argument("--fail-on", choices=["never", "likely", "possible"], default="never",
                   help="exit 1 when findings at this confidence or higher exist")

    sub.add_parser("status", help="show the status of known forks")

    args = p.parse_args(argv)
    if args.cmd == "status":
        for fork in load_forks()["forks"]:
            print(fork_status_line(fork))
        return 0

    res = scan(args.path, args.fork, include_tests=args.include_tests, offchain=not args.no_offchain)
    out = FORMATS[args.format](res)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(out + "\n")
    else:
        print(out)
    if args.fail_on == "likely" and any(f.confidence == "likely" for f in res.findings):
        return 1
    if args.fail_on == "possible" and res.findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
