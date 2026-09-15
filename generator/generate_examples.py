"""Generate example provenance cases for development and testing."""

from __future__ import annotations

import json
import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from generator.clean_case import generate_clean_case
from generator.mutate_case import (
    mutate_bad_hash,
    mutate_bad_signer,
    mutate_missing_step,
    mutate_unexpected_product,
    mutate_wrong_order,
)


def main() -> None:
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../examples"))
    os.makedirs(out_dir, exist_ok=True)

    cases = {
        "clean": generate_clean_case("case_clean_ex"),
        "missing_step": mutate_missing_step(
            generate_clean_case("case_missing_ex"), "compile",
        )[0],
        "bad_hash": mutate_bad_hash(
            generate_clean_case("case_hash_ex"), "package",
        )[0],
        "bad_signer": mutate_bad_signer(
            generate_clean_case("case_signer_ex"), "scan",
        )[0],
        "bad_product": mutate_unexpected_product(
            generate_clean_case("case_prod_ex"), "publish",
        )[0],
        "wrong_order": mutate_wrong_order(
            generate_clean_case("case_order_ex"), 3, 4,
        )[0],
    }

    # Write individual JSON files
    for name, case_data in cases.items():
        fp = os.path.join(out_dir, f"{name}.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(case_data, f, indent=2)

    # Write combined JSONL benchmark
    jsonl_path = os.path.join(out_dir, "benchmark.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for case_data in cases.values():
            f.write(json.dumps(case_data) + "\n")

    print(f"Generated {len(cases)} example files + benchmark.jsonl in {out_dir}/")


if __name__ == "__main__":
    main()
