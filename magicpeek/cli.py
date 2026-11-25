"""Command line interface for magicpeek."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .core import EXT_KINDS, MagicpeekError, audit

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_ERROR = 2


def _note(record) -> str:
    if record.status != "mismatch":
        return ""
    kinds = ", ".join(sorted(EXT_KINDS.get(record.extension, set()))) or "something else"
    return "  (.%s means %s, found %s)" % (record.extension, kinds, record.kind)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="magicpeek",
        description="Compare a file's real type (from its magic bytes) with its extension.",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("-q", "--quiet", action="store_true", help="print nothing, just set the exit code")
    parser.add_argument("paths", nargs="+", metavar="PATH", help="files or directories (walked recursively)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        records = audit([Path(item) for item in args.paths])
    except MagicpeekError as exc:
        print("magicpeek: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    summary = {
        "total": len(records),
        "ok": sum(1 for record in records if record.status == "ok"),
        "mismatch": sum(1 for record in records if record.status == "mismatch"),
        "unknown": sum(1 for record in records if record.status == "unknown"),
        "no-ext": sum(1 for record in records if record.status == "no-ext"),
    }

    if args.json:
        print(
            json.dumps(
                {
                    "files": [
                        {
                            "path": str(record.path),
                            "extension": record.extension,
                            "kind": record.kind,
                            "label": record.label,
                            "status": record.status,
                        }
                        for record in records
                    ],
                    "summary": summary,
                },
                indent=2,
            )
        )
    elif not args.quiet:
        for record in records:
            note = _note(record)
            print("%-8s  %s  %s%s" % (record.status, record.path, record.label, note))
        print(
            "\n%d file(s): %d ok, %d mismatch, %d unknown, %d without extension"
            % (summary["total"], summary["ok"], summary["mismatch"], summary["unknown"], summary["no-ext"])
        )

    return EXIT_MISMATCH if summary["mismatch"] else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
