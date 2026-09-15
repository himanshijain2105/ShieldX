"""Small independent case builder for verifier regression tests.

It deliberately owns its policy tables and canonical payload/hash formatting
instead of importing the production verifier's development constants.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # Match the documented development mode without production imports.
    serialization = None
    Ed25519PrivateKey = None


REFERENCE_STEPS = ("fetch", "deps", "compile", "test", "package", "scan", "sign", "publish")
REFERENCE_SIGNERS = {
    "fetch": "alice", "deps": "alice", "compile": "bob", "test": "bob",
    "package": "carol", "scan": "carol", "sign": "dave", "publish": "dave",
}
REFERENCE_PRODUCTS = {
    "fetch": "src.tar.gz", "deps": "vendor.tar.gz", "compile": "app.o", "test": "test.log",
    "package": "app.tar.gz", "scan": "scan.json", "sign": "app.tar.gz.sig", "publish": "release.tar.gz",
}


def _hash(case_id: str, step_id: str) -> str:
    return hashlib.sha256(f"artifact:20260911:{case_id}:{step_id}".encode()).hexdigest()


def _seed(signer_id: str) -> bytes:
    return hashlib.sha256(f"key:20260911:{signer_id}".encode()).digest()


def _private_key(signer_id: str) -> Any:
    """Derive an oracle-only Ed25519 key without production crypto helpers."""
    if Ed25519PrivateKey is None:
        return None
    return Ed25519PrivateKey.from_private_bytes(_seed(signer_id))


def reference_public_key(signer_id: str) -> str:
    """Return the raw Ed25519 public key encoded as hexadecimal."""
    private_key = _private_key(signer_id)
    if private_key is None:
        return hashlib.sha256(_seed(signer_id)).hexdigest()
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def reference_sign(signer_id: str, payload: bytes) -> str:
    """Sign a payload through the oracle's independent Ed25519 path."""
    private_key = _private_key(signer_id)
    if private_key is None:
        return hmac.new(_seed(signer_id), payload, hashlib.sha256).hexdigest()
    return private_key.sign(payload).hex()


def _payload(step_id: str, materials: list[dict[str, str]], products: list[dict[str, str]]) -> bytes:
    return json.dumps(
        {
            "materials": sorted(materials, key=lambda item: item["name"]),
            "products": sorted(products, key=lambda item: item["name"]),
            "step_id": step_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def build_reference_case(case_id: str = "reference_clean") -> dict[str, Any]:
    """Build a clean case using only this module's independent policy table."""
    public_keys = {signer: reference_public_key(signer) for signer in set(REFERENCE_SIGNERS.values())}
    steps: list[dict[str, Any]] = []
    expected_hashes: dict[str, dict[str, str]] = {}
    previous_products: list[dict[str, str]] = []
    for step_id in REFERENCE_STEPS:
        product = {"name": REFERENCE_PRODUCTS[step_id], "hash": _hash(case_id, step_id)}
        materials = [dict(item) for item in previous_products]
        signature = reference_sign(REFERENCE_SIGNERS[step_id], _payload(step_id, materials, [product]))
        steps.append({
            "step_id": step_id,
            "signer_id": REFERENCE_SIGNERS[step_id],
            "signature": signature,
            "materials": materials,
            "products": [product],
        })
        expected_hashes[step_id] = {product["name"]: product["hash"]}
        previous_products = [product]
    return {
        "case_id": case_id,
        "layout": {
            "canonical_steps": list(REFERENCE_STEPS),
            "authorized_signers": {step: [signer] for step, signer in REFERENCE_SIGNERS.items()},
            "expected_products": {step: [product] for step, product in REFERENCE_PRODUCTS.items()},
            "expected_product_hashes": expected_hashes,
        },
        "public_verification_material": {"public_keys": public_keys},
        "steps": steps,
    }
