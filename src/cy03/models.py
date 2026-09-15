"""Normalized data models for CY-03 provenance verification.

The parser accepts one documented case shape and converts it into these models.
Policy constraints are deliberately represented as supplied or unsupplied: the
verifier must never turn absent evaluator policy into a guessed constraint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


CANONICAL_STEPS: List[str] = [
    "fetch", "deps", "compile", "test", "package", "scan", "sign", "publish",
]

# Development-only values used by the synthetic case builder. Validators do
# not import or use these values as a fallback policy.
DEFAULT_AUTHORIZED_SIGNERS: Dict[str, List[str]] = {
    "fetch": ["alice"], "deps": ["alice"], "compile": ["bob"],
    "test": ["bob"], "package": ["carol"], "scan": ["carol"],
    "sign": ["dave"], "publish": ["dave"],
}
DEFAULT_EXPECTED_PRODUCTS: Dict[str, List[str]] = {
    "fetch": ["src.tar.gz"], "deps": ["vendor.tar.gz"],
    "compile": ["app.o"], "test": ["test.log"],
    "package": ["app.tar.gz"], "scan": ["scan.json"],
    "sign": ["app.tar.gz.sig"], "publish": ["release.tar.gz"],
}

FAILURE_SEVERITIES: Dict[str, int] = {
    "structural_error": 110,
    "missing_required_step": 100,
    "unauthorized_signer": 90,
    "invalid_signature": 88,
    "unexpected_product": 85,
    "unexpected_product_hash": 80,
    "wrong_order": 70,
    "material_product_mismatch": 65,
}


class ConstraintState(str, Enum):
    """Whether a policy was supplied by the evaluator and can be enforced."""

    SUPPLIED = "supplied"
    UNSUPPLIED = "unsupplied"


class CaseParseError(ValueError):
    """Raised when an input cannot be normalized into the documented schema."""


def _reject_unknown_keys(data: Dict[str, Any], *, allowed: set[str], context: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise CaseParseError(f"{context} contains unsupported fields: {', '.join(unknown)}.")


@dataclass(frozen=True)
class Artifact:
    name: str
    hash: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, context: str) -> "Artifact":
        if not isinstance(data, dict):
            raise CaseParseError(f"{context} must be an object.")
        _reject_unknown_keys(data, allowed={"name", "hash"}, context=context)
        name, digest = data.get("name"), data.get("hash")
        if not isinstance(name, str) or not name:
            raise CaseParseError(f"{context}.name must be a non-empty string.")
        if not isinstance(digest, str) or not digest:
            raise CaseParseError(f"{context}.hash must be a non-empty string.")
        return cls(name=name, hash=digest)

    def to_dict(self) -> Dict[str, str]:
        return {"hash": self.hash, "name": self.name}


@dataclass(frozen=True)
class StepRecord:
    step_id: str
    signer_id: str
    signature: str
    materials: List[Artifact] = field(default_factory=list)
    products: List[Artifact] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, index: int) -> "StepRecord":
        context = f"steps[{index}]"
        if not isinstance(data, dict):
            raise CaseParseError(f"{context} must be an object.")
        _reject_unknown_keys(
            data,
            allowed={"step_id", "signer_id", "signature", "materials", "products"},
            context=context,
        )
        step_id, signer_id, signature = (
            data.get("step_id"), data.get("signer_id"), data.get("signature"),
        )
        for field_name, value in {
            "step_id": step_id, "signer_id": signer_id, "signature": signature,
        }.items():
            if not isinstance(value, str) or not value:
                raise CaseParseError(
                    f"{context}.{field_name} must be a non-empty string.",
                )
        materials = data.get("materials", [])
        products = data.get("products", [])
        if not isinstance(materials, list) or not isinstance(products, list):
            raise CaseParseError(f"{context}.materials and .products must be lists.")
        return cls(
            step_id=step_id,
            signer_id=signer_id,
            signature=signature,
            materials=[Artifact.from_dict(item, context=f"{context}.materials[{i}]")
                       for i, item in enumerate(materials)],
            products=[Artifact.from_dict(item, context=f"{context}.products[{i}]")
                      for i, item in enumerate(products)],
        )


@dataclass(frozen=True)
class LayoutSpec:
    """Authoritative layout constraints after one-time normalization.

    ``canonical_steps`` is benchmark-defined. The other three policies are
    only enforced when their state is ``SUPPLIED`` in input ``layout``.
    """

    canonical_steps: List[str] = field(default_factory=lambda: list(CANONICAL_STEPS))
    authorized_signers: Dict[str, List[str]] = field(default_factory=dict)
    expected_products: Dict[str, List[str]] = field(default_factory=dict)
    expected_product_hashes: Dict[str, Dict[str, str]] = field(default_factory=dict)
    signer_constraints_state: ConstraintState = ConstraintState.UNSUPPLIED
    product_constraints_state: ConstraintState = ConstraintState.UNSUPPLIED
    hash_constraints_state: ConstraintState = ConstraintState.UNSUPPLIED

    @classmethod
    def from_dict(cls, data: Any) -> "LayoutSpec":
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise CaseParseError("layout must be an object when supplied.")
        _reject_unknown_keys(
            data,
            allowed={
                "canonical_steps", "authorized_signers", "expected_products",
                "expected_product_hashes",
            },
            context="layout",
        )

        canonical_steps = data.get("canonical_steps", list(CANONICAL_STEPS))
        if canonical_steps != CANONICAL_STEPS:
            raise CaseParseError(
                "layout.canonical_steps must equal the CY-03 canonical eight-step sequence.",
            )

        signers, signer_state = _parse_signer_constraints(data)
        products, product_state = _parse_product_constraints(data)
        hashes, hash_state = _parse_hash_constraints(data)
        return cls(
            authorized_signers=signers,
            expected_products=products,
            expected_product_hashes=hashes,
            signer_constraints_state=signer_state,
            product_constraints_state=product_state,
            hash_constraints_state=hash_state,
        )

    def product_policy_state(self, step_id: str) -> ConstraintState:
        """Return whether product identity is constrained for this step."""
        if step_id in self.expected_products:
            return ConstraintState.SUPPLIED
        return ConstraintState.UNSUPPLIED

    def hash_policy_state(self, step_id: str) -> ConstraintState:
        """Return whether the exact product/hash set is constrained for this step."""
        if step_id in self.expected_product_hashes:
            return ConstraintState.SUPPLIED
        return ConstraintState.UNSUPPLIED


def _parse_signer_constraints(data: Dict[str, Any]) -> tuple[Dict[str, List[str]], ConstraintState]:
    if "authorized_signers" not in data:
        return {}, ConstraintState.UNSUPPLIED
    raw = data["authorized_signers"]
    if not isinstance(raw, dict):
        raise CaseParseError("layout.authorized_signers must be an object.")
    result: Dict[str, List[str]] = {}
    for step_id, signers in raw.items():
        if not isinstance(step_id, str) or step_id not in CANONICAL_STEPS:
            raise CaseParseError("authorized_signers contains an unknown step ID.")
        if isinstance(signers, str):
            signers = [signers]
        if (not isinstance(signers, list) or not signers
                or any(not isinstance(signer, str) or not signer for signer in signers)):
            raise CaseParseError(
                f"authorized_signers['{step_id}'] must be a non-empty string list.",
            )
        result[step_id] = list(signers)
    return result, ConstraintState.SUPPLIED


def _parse_product_constraints(data: Dict[str, Any]) -> tuple[Dict[str, List[str]], ConstraintState]:
    if "expected_products" not in data:
        return {}, ConstraintState.UNSUPPLIED
    raw = data["expected_products"]
    if not isinstance(raw, dict):
        raise CaseParseError("layout.expected_products must be an object.")
    result: Dict[str, List[str]] = {}
    for step_id, names in raw.items():
        if not isinstance(step_id, str) or step_id not in CANONICAL_STEPS:
            raise CaseParseError("expected_products contains an unknown step ID.")
        if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
            raise CaseParseError(f"expected_products['{step_id}'] must be a string list.")
        result[step_id] = list(names)
    return result, ConstraintState.SUPPLIED


def _parse_hash_constraints(data: Dict[str, Any]) -> tuple[Dict[str, Dict[str, str]], ConstraintState]:
    if "expected_product_hashes" not in data:
        return {}, ConstraintState.UNSUPPLIED
    raw = data["expected_product_hashes"]
    if not isinstance(raw, dict):
        raise CaseParseError("layout.expected_product_hashes must be an object.")
    result: Dict[str, Dict[str, str]] = {}
    for step_id, hashes in raw.items():
        if not isinstance(step_id, str) or step_id not in CANONICAL_STEPS:
            raise CaseParseError("expected_product_hashes contains an unknown step ID.")
        if (not isinstance(hashes, dict)
                or any(not isinstance(name, str) or not name
                       or not isinstance(digest, str) or not digest
                       for name, digest in hashes.items())):
            raise CaseParseError(
                f"expected_product_hashes['{step_id}'] must map product names to hashes.",
            )
        result[step_id] = dict(hashes)
    return result, ConstraintState.SUPPLIED


@dataclass(frozen=True)
class Case:
    case_id: str
    steps: List[StepRecord]
    public_keys: Dict[str, str]
    layout: LayoutSpec = field(default_factory=LayoutSpec)

    @classmethod
    def from_dict(cls, data: Any) -> "Case":
        if not isinstance(data, dict):
            raise CaseParseError("A CY-03 case must be a JSON object.")
        _reject_unknown_keys(
            data,
            allowed={"case_id", "metadata", "layout", "public_verification_material", "steps"},
            context="case",
        )
        metadata = data.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise CaseParseError("metadata must be an object when supplied.")
        case_id = data.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise CaseParseError("case_id must be a non-empty string.")
        raw_steps = data.get("steps")
        if not isinstance(raw_steps, list):
            raise CaseParseError("steps must be a list.")

        if "public_verification_material" not in data:
            raise CaseParseError("public_verification_material is required.")
        pvm = data["public_verification_material"]
        if not isinstance(pvm, dict):
            raise CaseParseError("public_verification_material must be an object.")
        _reject_unknown_keys(
            pvm,
            allowed={"public_keys"},
            context="public_verification_material",
        )
        if "public_keys" not in pvm:
            raise CaseParseError("public_verification_material.public_keys is required.")
        raw_keys = pvm["public_keys"]
        if not isinstance(raw_keys, dict) or any(
            not isinstance(signer, str) or not signer or not isinstance(key, str) or not key
            for signer, key in raw_keys.items()
        ):
            raise CaseParseError("public_verification_material.public_keys must map IDs to keys.")

        return cls(
            case_id=case_id,
            steps=[StepRecord.from_dict(step, index=i) for i, step in enumerate(raw_steps)],
            public_keys=dict(raw_keys),
            layout=LayoutSpec.from_dict(data.get("layout")),
        )


@dataclass(frozen=True)
class EvidenceItem:
    """A violation observation, including its causal role for ranking."""

    violation_type: str
    step_id: str
    severity: int
    message: str
    confidence: float = 1.0
    related_steps: List[str] = field(default_factory=list)
    direct: bool = True
    propagated_from: Optional[str] = None
