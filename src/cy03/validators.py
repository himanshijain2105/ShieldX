"""Independent structural, cryptographic, artifact, and provenance checks."""

from __future__ import annotations

from collections import Counter
from typing import List

from .hashing import compute_step_payload
from .models import ConstraintState, FAILURE_SEVERITIES, Case, EvidenceItem
from .signatures import verify_signature


def validate_structure(case: Case) -> List[EvidenceItem]:
    """Identify malformed chain structure without mislabeling it as an attack.

    Parsing covers record shapes; this validator covers relationships visible
    only after the full chain has been normalized (unknown and duplicate IDs).
    """
    evidences: List[EvidenceItem] = []
    known = set(case.layout.canonical_steps)
    counts = Counter(step.step_id for step in case.steps)
    for step in case.steps:
        if step.step_id not in known:
            evidences.append(EvidenceItem(
                violation_type="structural_error", step_id=step.step_id,
                severity=FAILURE_SEVERITIES["structural_error"],
                message=f"Unknown step ID '{step.step_id}' is not part of the CY-03 layout.",
            ))
    for step_id, count in counts.items():
        if count > 1:
            evidences.append(EvidenceItem(
                violation_type="structural_error", step_id=step_id,
                severity=FAILURE_SEVERITIES["structural_error"],
                message=f"Step '{step_id}' appears {count} times; step IDs must be unique.",
            ))
    return evidences


def validate_step_completeness(case: Case) -> List[EvidenceItem]:
    evidences: List[EvidenceItem] = []
    present = {step.step_id for step in case.steps}
    for step_id in case.layout.canonical_steps:
        if step_id not in present:
            evidences.append(EvidenceItem(
                violation_type="missing_required_step", step_id=step_id,
                severity=FAILURE_SEVERITIES["missing_required_step"],
                message=f"Required step '{step_id}' is missing from the build chain.",
            ))
    return evidences


def validate_step_order(case: Case) -> List[EvidenceItem]:
    """Validate the relative order of known, non-duplicate step records."""
    canonical_index = {step_id: i for i, step_id in enumerate(case.layout.canonical_steps)}
    actual = [step.step_id for step in case.steps if step.step_id in canonical_index]
    if len(actual) != len(set(actual)):
        # Duplicates are structural errors; avoid ambiguous index-based evidence.
        return []
    expected = sorted(actual, key=canonical_index.__getitem__)
    if actual == expected:
        return []

    displaced = {
        step_id
        for observed, expected_step in zip(actual, expected)
        if observed != expected_step
        for step_id in (observed, expected_step)
    }
    return [EvidenceItem(
        violation_type="wrong_order", step_id=step_id,
        severity=FAILURE_SEVERITIES["wrong_order"],
        message=(f"Step '{step_id}' is at position {actual.index(step_id)} but expected "
                 f"position {expected.index(step_id)} in the canonical sequence."),
        related_steps=sorted(displaced - {step_id}, key=canonical_index.__getitem__),
    ) for step_id in sorted(displaced, key=canonical_index.__getitem__)]


def validate_signers(case: Case) -> List[EvidenceItem]:
    """Enforce signer authorization only when the policy was supplied."""
    if case.layout.signer_constraints_state is ConstraintState.UNSUPPLIED:
        return []
    evidences: List[EvidenceItem] = []
    for step in case.steps:
        authorized = case.layout.authorized_signers.get(step.step_id)
        if authorized is None:
            # A supplied partial policy has no rule for this step; it is not a
            # license to invent one.
            continue
        if step.signer_id not in authorized:
            evidences.append(EvidenceItem(
                violation_type="unauthorized_signer", step_id=step.step_id,
                severity=FAILURE_SEVERITIES["unauthorized_signer"],
                message=(f"Step '{step.step_id}' is signed by '{step.signer_id}', "
                         f"expected one of {authorized}."),
            ))
    return evidences


def validate_signatures(case: Case) -> List[EvidenceItem]:
    """Strictly verify each available signature; never suppress failures."""
    evidences: List[EvidenceItem] = []
    for step in case.steps:
        public_key = case.public_keys.get(step.signer_id)
        if public_key is None:
            # An unauthorized identity is already direct authorization evidence.
            # For an otherwise authorized signer, absent verification material is
            # an input/structure problem rather than an invented crypto result.
            authorized = case.layout.authorized_signers.get(step.step_id, [])
            if step.signer_id in authorized:
                evidences.append(EvidenceItem(
                    violation_type="structural_error", step_id=step.step_id,
                    severity=FAILURE_SEVERITIES["structural_error"],
                    message=(f"No public verification key was supplied for authorized signer "
                             f"'{step.signer_id}' at step '{step.step_id}'."),
                ))
            continue

        payload = compute_step_payload(step.step_id, step.materials, step.products)
        if not verify_signature(public_key, payload, step.signature, signer_id=step.signer_id):
            evidences.append(EvidenceItem(
                violation_type="invalid_signature", step_id=step.step_id,
                severity=FAILURE_SEVERITIES["invalid_signature"],
                message=f"Cryptographic signature verification failed for step '{step.step_id}'.",
            ))
    return evidences


def validate_products(case: Case) -> List[EvidenceItem]:
    """Check only evaluator-supplied product and hash constraints.

    Hashes are matched by product name so multiple products can carry distinct
    authoritative digests. No deterministic development formula is inferred.
    """
    evidences: List[EvidenceItem] = []
    name_valid: set[str] = set()
    for step in case.steps:
        if case.layout.product_policy_state(step.step_id) is ConstraintState.UNSUPPLIED:
            name_valid.add(step.step_id)
            continue
        expected_names = case.layout.expected_products[step.step_id]
        actual_names = [product.name for product in step.products]
        if sorted(actual_names) != sorted(expected_names):
            evidences.append(EvidenceItem(
                violation_type="unexpected_product", step_id=step.step_id,
                severity=FAILURE_SEVERITIES["unexpected_product"],
                message=(f"Step '{step.step_id}' produced {actual_names}; "
                         f"expected {expected_names}."),
            ))
        else:
            name_valid.add(step.step_id)

    for step in case.steps:
        if (case.layout.hash_policy_state(step.step_id) is ConstraintState.UNSUPPLIED
                or step.step_id not in name_valid):
            continue
        expected_hashes = case.layout.expected_product_hashes[step.step_id]
        actual_hashes = {product.name: product.hash for product in step.products}
        has_duplicate_names = len(actual_hashes) != len(step.products)
        if actual_hashes != expected_hashes or has_duplicate_names:
            details = ", ".join(sorted(set(actual_hashes) | set(expected_hashes)))
            evidences.append(EvidenceItem(
                violation_type="unexpected_product_hash", step_id=step.step_id,
                severity=FAILURE_SEVERITIES["unexpected_product_hash"],
                message=(f"Step '{step.step_id}' has hashes that do not match the "
                         f"authoritative layout constraint: {details}."),
            ))
    return evidences


def validate_material_chain(case: Case) -> List[EvidenceItem]:
    """Record downstream material/product discontinuities as propagated evidence."""
    evidences: List[EvidenceItem] = []
    known = set(case.layout.canonical_steps)
    by_step_id = {step.step_id: step for step in case.steps if step.step_id in known}
    if len(by_step_id) != len([step for step in case.steps if step.step_id in known]):
        return evidences
    # Provenance links are defined by the canonical layout, not the physical
    # order in which records happen to be serialized. This avoids turning an
    # order violation into a spurious material-chain root cause.
    ordered = [by_step_id[step_id] for step_id in case.layout.canonical_steps if step_id in by_step_id]
    for previous, current in zip(ordered, ordered[1:]):
        if not current.materials or not previous.products:
            continue
        previous_products = {(product.name, product.hash) for product in previous.products}
        current_materials = {(material.name, material.hash) for material in current.materials}
        if not previous_products.intersection(current_materials):
            evidences.append(EvidenceItem(
                violation_type="material_product_mismatch", step_id=current.step_id,
                severity=FAILURE_SEVERITIES["material_product_mismatch"],
                message=(f"Materials at '{current.step_id}' do not continue products from "
                         f"preceding step '{previous.step_id}'."),
                confidence=0.8,
                related_steps=[previous.step_id],
                direct=False,
                propagated_from=previous.step_id,
            ))
    return evidences
