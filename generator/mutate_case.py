"""Mutation operators for provenance test-case generation.

Each mutator takes a clean case dict and applies a single mutation
matching one of the five failure families. The default content mutators
retain the original signature to model tampering. Isolated variants re-sign
the altered attestation so tests can exercise one invariant independently.

Returns (mutated_case, target_step_id).
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Tuple

from src.cy03.models import CANONICAL_STEPS
from src.cy03.hashing import compute_step_payload
from src.cy03.signatures import derive_keypair_hex, sign_payload


def _resign(step: Dict[str, Any]) -> None:
    """Re-sign the record after an isolated content mutation."""
    step["signature"] = sign_payload(
        step["signer_id"],
        compute_step_payload(step["step_id"], step["materials"], step["products"]),
    )


def mutate_missing_step(
    case: Dict[str, Any],
    target_step: str = "compile",
) -> Tuple[Dict[str, Any], str]:
    """Remove a required step entirely."""
    c = copy.deepcopy(case)
    c["steps"] = [s for s in c["steps"] if s["step_id"] != target_step]
    return c, target_step


def mutate_bad_hash(
    case: Dict[str, Any],
    target_step: str = "package",
) -> Tuple[Dict[str, Any], str]:
    """Replace all product hashes of a step with a bogus value."""
    c = copy.deepcopy(case)
    for s in c["steps"]:
        if s["step_id"] == target_step:
            for p in s["products"]:
                p["hash"] = "0" * 64
    return c, target_step


def mutate_bad_hash_isolated(
    case: Dict[str, Any],
    target_step: str = "package",
) -> Tuple[Dict[str, Any], str]:
    """Change a product hash while retaining a valid attestation signature."""
    c, target = mutate_bad_hash(case, target_step)
    for step in c["steps"]:
        if step["step_id"] == target:
            _resign(step)
            break
    return c, target


def mutate_bad_signer(
    case: Dict[str, Any],
    target_step: str = "scan",
) -> Tuple[Dict[str, Any], str]:
    """Change the signer to an unauthorized identity."""
    c = copy.deepcopy(case)
    for s in c["steps"]:
        if s["step_id"] == target_step:
            s["signer_id"] = "eve_attacker"
    return c, target_step


def mutate_bad_signer_isolated(
    case: Dict[str, Any],
    target_step: str = "scan",
) -> Tuple[Dict[str, Any], str]:
    """Use a valid but layout-unauthorized signer and signature."""
    c = copy.deepcopy(case)
    attacker = "eve_attacker"
    _, public_key = derive_keypair_hex(attacker)
    c["public_verification_material"]["public_keys"][attacker] = public_key
    for step in c["steps"]:
        if step["step_id"] == target_step:
            step["signer_id"] = attacker
            _resign(step)
            break
    return c, target_step


def mutate_unexpected_product(
    case: Dict[str, Any],
    target_step: str = "publish",
) -> Tuple[Dict[str, Any], str]:
    """Replace products with unexpected artifact names."""
    c = copy.deepcopy(case)
    for s in c["steps"]:
        if s["step_id"] == target_step:
            s["products"] = [
                {"name": "malicious_backdoor.sh", "hash": "bad" + "0" * 61},
            ]
    return c, target_step


def mutate_unexpected_product_isolated(
    case: Dict[str, Any],
    target_step: str = "publish",
) -> Tuple[Dict[str, Any], str]:
    """Substitute a product while retaining a valid attestation signature."""
    c, target = mutate_unexpected_product(case, target_step)
    for step in c["steps"]:
        if step["step_id"] == target:
            _resign(step)
            break
    return c, target


def mutate_wrong_order(
    case: Dict[str, Any],
    idx1: int = 3,
    idx2: int = 4,
) -> Tuple[Dict[str, Any], str]:
    """Swap two adjacent steps to violate canonical ordering.

    Returns the step that moved *forward* (to an earlier position) as
    the "target" — this matches the evaluator convention.
    """
    c = copy.deepcopy(case)
    i, j = min(idx1, idx2), max(idx1, idx2)
    c["steps"][i], c["steps"][j] = c["steps"][j], c["steps"][i]
    # The step now at position i moved forward → it's the primary target
    return c, c["steps"][i]["step_id"]


# -----------------------------------------------------------------------
# Convenience: apply a mutation to a freshly generated clean case
# -----------------------------------------------------------------------

ALL_MUTATORS = {
    "missing_required_step": mutate_missing_step,
    "unexpected_product_hash": mutate_bad_hash,
    "unauthorized_signer": mutate_bad_signer,
    "unexpected_product": mutate_unexpected_product,
    "wrong_order": mutate_wrong_order,
}

ISOLATED_MUTATORS = {
    "unexpected_product_hash": mutate_bad_hash_isolated,
    "unauthorized_signer": mutate_bad_signer_isolated,
    "unexpected_product": mutate_unexpected_product_isolated,
}
