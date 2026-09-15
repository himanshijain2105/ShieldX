"""Adversarial clean and isolated-mutation coverage for CY-03."""

from __future__ import annotations

import copy
import unittest

from generator.clean_case import generate_clean_case
from generator.mutate_case import (
    mutate_bad_hash_isolated,
    mutate_bad_signer_isolated,
    mutate_unexpected_product_isolated,
)
from src.cy03.hashing import compute_step_payload
from src.cy03.parser import parse_case
from src.cy03.signatures import sign_payload
from src.cy03.validators import validate_signatures
from src.cy03.verifier import CY03Verifier


def _step(case: dict, step_id: str) -> dict:
    return next(step for step in case["steps"] if step["step_id"] == step_id)


def _resign(step: dict) -> None:
    step["signature"] = sign_payload(
        step["signer_id"],
        compute_step_payload(step["step_id"], step["materials"], step["products"]),
    )


class TestIsolatedMutations(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def test_isolated_hash_mutation_preserves_signature_validity(self) -> None:
        case, target = mutate_bad_hash_isolated(generate_clean_case("isolated_hash"), "package")
        self.assertEqual(validate_signatures(parse_case(case)), [])
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "unexpected_product_hash")
        self.assertEqual(result["suspicious_steps"][0], target)

    def test_isolated_product_mutation_preserves_signature_validity(self) -> None:
        case, target = mutate_unexpected_product_isolated(
            generate_clean_case("isolated_product"), "package",
        )
        self.assertEqual(validate_signatures(parse_case(case)), [])
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "unexpected_product")
        self.assertEqual(result["suspicious_steps"][0], target)

    def test_isolated_signer_mutation_is_valid_but_unauthorized(self) -> None:
        case, target = mutate_bad_signer_isolated(generate_clean_case("isolated_signer"), "scan")
        self.assertEqual(validate_signatures(parse_case(case)), [])
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "unauthorized_signer")
        self.assertEqual(result["suspicious_steps"][0], target)


class TestAdversarialCleanCases(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def test_multiple_products_and_noncanonical_artifact_order_pass(self) -> None:
        case = generate_clean_case("adversarial_artifact_order")
        compile_step = _step(case, "compile")
        extra = {"name": "debug-symbols", "hash": "1" * 64}
        compile_step["products"].append(extra)
        case["layout"]["expected_products"]["compile"].append(extra["name"])
        case["layout"]["expected_product_hashes"]["compile"][extra["name"]] = extra["hash"]
        _resign(compile_step)
        compile_step["products"].reverse()
        self.assertEqual(self.verifier.verify(case)["verdict"], "PASS")

    def test_repeated_product_name_across_steps_with_distinct_hashes_passes(self) -> None:
        case = generate_clean_case("adversarial_repeated_name")
        fetch = _step(case, "fetch")
        deps = _step(case, "deps")
        compile_step = _step(case, "compile")
        fetch["products"][0]["name"] = "shared.bin"
        case["layout"]["expected_products"]["fetch"] = ["shared.bin"]
        case["layout"]["expected_product_hashes"]["fetch"] = {"shared.bin": fetch["products"][0]["hash"]}
        _resign(fetch)
        deps["materials"] = copy.deepcopy(fetch["products"])
        deps["products"][0]["name"] = "shared.bin"
        case["layout"]["expected_products"]["deps"] = ["shared.bin"]
        case["layout"]["expected_product_hashes"]["deps"] = {"shared.bin": deps["products"][0]["hash"]}
        _resign(deps)
        compile_step["materials"] = copy.deepcopy(deps["products"])
        _resign(compile_step)
        self.assertNotEqual(fetch["products"][0]["hash"], deps["products"][0]["hash"])
        self.assertEqual(self.verifier.verify(case)["verdict"], "PASS")

    def test_empty_materials_are_allowed_when_the_layout_does_not_constrain_them(self) -> None:
        case = generate_clean_case("adversarial_empty_materials")
        compile_step = _step(case, "compile")
        compile_step["materials"] = []
        _resign(compile_step)
        self.assertEqual(self.verifier.verify(case)["verdict"], "PASS")

    def test_alternate_authorized_signer_and_optional_metadata_pass(self) -> None:
        case = generate_clean_case("adversarial_authorized_signer")
        case["metadata"] = {"build": {"attempt": 2}, "source": "external-runner"}
        scan = _step(case, "scan")
        scan["signer_id"] = "alice"
        case["layout"]["authorized_signers"]["scan"].append("alice")
        _resign(scan)
        self.assertEqual(self.verifier.verify(case)["verdict"], "PASS")

    def test_explicit_empty_product_and_hash_policy_passes_with_no_output(self) -> None:
        case = generate_clean_case("adversarial_empty_products")
        fetch = _step(case, "fetch")
        deps = _step(case, "deps")
        fetch["products"] = []
        case["layout"]["expected_products"]["fetch"] = []
        case["layout"]["expected_product_hashes"]["fetch"] = {}
        _resign(fetch)
        deps["materials"] = []
        _resign(deps)
        self.assertEqual(self.verifier.verify(case)["verdict"], "PASS")
