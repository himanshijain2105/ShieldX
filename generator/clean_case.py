"""Generate a cryptographically valid (clean) provenance case.

Produces a complete case with proper material chains, correct product
hashes, and valid Ed25519/HMAC signatures that the verifier will accept.
"""

from __future__ import annotations

from typing import Any, Dict

from src.cy03.hashing import compute_artifact_hash, compute_step_payload
from src.cy03.models import (
    CANONICAL_STEPS,
    DEFAULT_AUTHORIZED_SIGNERS,
    DEFAULT_EXPECTED_PRODUCTS,
    Artifact,
)
from src.cy03.signatures import derive_keypair_hex, sign_payload


def generate_clean_case(case_id: str = "case_clean") -> Dict[str, Any]:
    """Generate a valid provenance case with all 8 steps.

    The case includes:
    - Correct product names and hashes per the spec formula.
    - Material chains: products of step N become materials of step N+1.
    - Valid cryptographic signatures over canonical payloads.
    - Public verification material for all functionaries.
    """
    # Derive public keys for all signers
    all_signer_ids: set[str] = set()
    for v in DEFAULT_AUTHORIZED_SIGNERS.values():
        if isinstance(v, list):
            all_signer_ids.update(v)
        else:
            all_signer_ids.add(v)

    public_keys: Dict[str, str] = {}
    for signer_id in all_signer_ids:
        _, pub_hex = derive_keypair_hex(signer_id)
        public_keys[signer_id] = pub_hex

    steps: list[Dict[str, Any]] = []
    expected_hashes: Dict[str, Dict[str, str]] = {}
    prev_products: list[Dict[str, str]] = []

    for step_id in CANONICAL_STEPS:
        signer_id = DEFAULT_AUTHORIZED_SIGNERS[step_id]
        if isinstance(signer_id, list):
            signer_id = signer_id[0]

        prod_names = DEFAULT_EXPECTED_PRODUCTS[step_id]
        prod_hash = compute_artifact_hash(case_id, step_id)
        products = [{"name": name, "hash": prod_hash} for name in prod_names]
        expected_hashes[step_id] = {name: prod_hash for name in prod_names}

        # Materials = independent copies of previous step's products
        materials = [{"name": p["name"], "hash": p["hash"]} for p in prev_products]

        # Build Artifact objects for payload computation
        mat_objs = [Artifact(m["name"], m["hash"]) for m in materials]
        prod_objs = [Artifact(p["name"], p["hash"]) for p in products]

        payload = compute_step_payload(step_id, mat_objs, prod_objs)
        sig = sign_payload(signer_id, payload)

        steps.append({
            "step_id": step_id,
            "signer_id": signer_id,
            "signature": sig,
            "materials": materials,
            "products": products,
        })

        prev_products = list(products)

    return {
        "case_id": case_id,
        "layout": {
            "canonical_steps": list(CANONICAL_STEPS),
            "authorized_signers": {
                step_id: list(signers)
                for step_id, signers in DEFAULT_AUTHORIZED_SIGNERS.items()
            },
            "expected_products": {
                step_id: list(products)
                for step_id, products in DEFAULT_EXPECTED_PRODUCTS.items()
            },
            "expected_product_hashes": expected_hashes,
        },
        "public_verification_material": {"public_keys": public_keys},
        "steps": steps,
    }
