"""Cryptographic signature operations for CY-03.

Primary: Ed25519 via the ``cryptography`` library.
Fallback: HMAC-SHA256 when Ed25519 raw-key import is unavailable.

Key derivation per spec: seed = SHA256("key:20260911:<signer_id>").
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

# ---------------------------------------------------------------------------
# Detect whether Ed25519 is available (cached at module level)
# ---------------------------------------------------------------------------

_ED25519_AVAILABLE: bool | None = None


def _has_ed25519() -> bool:
    global _ED25519_AVAILABLE
    if _ED25519_AVAILABLE is None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            # Quick smoke test — can we import a 32-byte seed?
            _seed = b"\x00" * 32
            Ed25519PrivateKey.from_private_bytes(_seed)
            _ED25519_AVAILABLE = True
        except Exception:
            _ED25519_AVAILABLE = False
    return _ED25519_AVAILABLE


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def _derive_seed(signer_id: str) -> bytes:
    """Derive a 32-byte seed from signer_id per spec formula."""
    return hashlib.sha256(f"key:20260911:{signer_id}".encode("utf-8")).digest()


def derive_keypair_hex(signer_id: str) -> tuple[str, str]:
    """Derive a keypair and return (private_key_hex, public_key_hex).

    Uses Ed25519 when available; otherwise HMAC-SHA256 surrogate keys.
    """
    seed = _derive_seed(signer_id)

    if _has_ed25519():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization

        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key()

        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv_bytes.hex(), pub_bytes.hex()

    # HMAC fallback: deterministic surrogate keys
    priv_hex = seed.hex()
    pub_hex = hashlib.sha256(seed).hexdigest()
    return priv_hex, pub_hex


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_payload(signer_id: str, payload: bytes) -> str:
    """Sign *payload* with *signer_id*'s private key.  Returns hex."""
    seed = _derive_seed(signer_id)

    if _has_ed25519():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        return priv.sign(payload).hex()

    # HMAC-SHA256 fallback
    return _hmac.new(seed, payload, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_signature(
    public_key_hex: str,
    payload: bytes,
    signature_hex: str,
    *,
    signer_id: str | None = None,
) -> bool:
    """Verify *signature_hex* over *payload* using *public_key_hex*.

    For the HMAC fallback, *signer_id* must be provided so the
    symmetric key can be re-derived.

    Returns ``True`` iff the signature is valid.
    """
    if _has_ed25519():
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pub.verify(bytes.fromhex(signature_hex), payload)
            return True
        except Exception:
            return False

    # HMAC-SHA256 fallback — requires signer_id
    if signer_id is None:
        return False
    seed = _derive_seed(signer_id)
    expected = _hmac.new(seed, payload, hashlib.sha256).hexdigest()
    return _hmac.compare_digest(expected, signature_hex)