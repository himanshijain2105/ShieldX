"""Command-line interface for CY-03 Provenance Verifier.

Supports single JSON files, JSONL batch files, and directories of
JSON files.  Outputs machine-readable JSON/JSONL predictions.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .parser import parse_batch
from .verifier import CY03Verifier


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CY-03 Software Supply-Chain Provenance Verifier",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Input JSON file, JSONL file, or directory of JSON files.",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for results (JSON or JSONL).  Defaults to stdout.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "jsonl"],
        default="jsonl",
        help="Output format (default: jsonl).",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress timing/summary info on stderr.",
    )
    args = parser.parse_args()

    verifier = CY03Verifier()
    input_path = Path(args.input)

    # ---------- Load cases ----------
    cases_raw: list[dict] = []

    if input_path.is_dir():
        for fp in sorted(input_path.glob("*.json")):
            with open(fp, encoding="utf-8") as f:
                cases_raw.append(json.load(f))
    elif input_path.suffix == ".jsonl":
        with open(input_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    cases_raw.append(json.loads(line))
    else:
        with open(input_path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            cases_raw.extend(data)
        elif "cases" in data:
            cases_raw.extend(data["cases"])
        else:
            cases_raw.append(data)

    # ---------- Verify ----------
    t0 = time.perf_counter()
    results = [verifier.verify(c) for c in cases_raw]
    elapsed = time.perf_counter() - t0

    # ---------- Output ----------
    if args.format == "json":
        out_str = json.dumps(results, indent=2)
    else:
        out_str = "\n".join(json.dumps(r) for r in results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_str + "\n")
    else:
        print(out_str)

    # ---------- Summary ----------
    if not args.quiet:
        n = len(results)
        passes = sum(1 for r in results if r["verdict"] == "PASS")
        fails = n - passes
        print(
            f"\n--- {n} cases verified in {elapsed:.3f}s "
            f"({passes} PASS, {fails} FAIL) ---",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()