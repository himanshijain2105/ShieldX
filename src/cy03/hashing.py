"""Hashing and canonical payload computation for CY-03.

Provides deterministic artifact-hash generation per the spec formula
and canonical JSON payload construction for signature operations.
The payload format follows in-toto conventions: step content is signed
but signer identity is NOT part of the payload (identity is established
by the key used, not by a field inside the signed envelope).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, List


def compute_artifact_hash(case_id: str, step_id: str) -> str:
    """Compute deterministic artifact hash.

    Formula: SHA256("artifact:20260911:<case>:<step>")
    """
    seed = f"artifact:20260911:{case_id}:{step_id}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def canonicalize_artifacts(artifacts: List[Any]) -> List[dict]:
    """Sort and serialize a list of artifacts deterministically.

    Accepts Artifact objects (with .name/.hash) or dicts.
    Returns a sorted list of {"hash": ..., "name": ...} dicts.
    """
    result: List[dict] = []
    for a in artifacts:
        if hasattr(a, "name") and hasattr(a, "hash"):
            result.append({"hash": a.hash, "name": a.name})
        elif isinstance(a, dict):
            result.append({"hash": a["hash"], "name": a["name"]})
    return sorted(result, key=lambda x: x["name"])


def compute_step_payload(
    step_id: str,
    materials: List[Any] | None = None,
    products: List[Any] | None = None,
) -> bytes:
    """Compute the canonical payload bytes for signing/verification.

    The payload is a deterministic canonical JSON string containing
    step_id, materials, and products.  Signer identity is intentionally
    excluded (per in-toto conventions).

    Determinism is guaranteed by:
    - ``sort_keys=True`` on the outer dict
    - Artifact lists sorted by name
    - Compact separators with no whitespace
    """
    payload_dict = {
        "materials": canonicalize_artifacts(materials or []),
        "products": canonicalize_artifacts(products or []),
        "step_id": step_id,
    }
    return json.dumps(
        payload_dict, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
