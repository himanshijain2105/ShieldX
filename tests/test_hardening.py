"""Regression tests for strict evaluator-policy and provenance hardening."""

from __future__ import annotations

import copy
import unittest

from generator.clean_case import generate_clean_case
from src.cy03.hashing import compute_step_payload
from src.cy03.metrics import mean_reciprocal_rank, reciprocal_rank
from src.cy03.ranker import GraphRanker, StaticRanker
from src.cy03.signatures import derive_keypair_hex, sign_payload
from src.cy03.verifier import CY03Verifier
from tests.reference_oracle import build_reference_case


def _step(case: dict, step_id: str) -> dict:
    return next(step for step in case["steps"] if step["step_id"] == step_id)


def _resign(step: dict) -> None:
    step["signature"] = sign_payload(
        step["signer_id"],
        compute_step_payload(step["step_id"], step["materials"], step["products"]),
    )


class TestStrictVerification(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def test_all_invalid_signatures_are_not_suppressed(self) -> None:
        case = generate_clean_case("strict_all_signatures")
        for step in case["steps"]:
            step["signature"] = "00"
        result = self.verifier.verify(case)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["primary_violation"], "invalid_signature")
        self.assertEqual(result["evidence_count"], 8)

    def test_independent_reference_case_passes(self) -> None:
        self.assertEqual(
            self.verifier.verify(build_reference_case())["verdict"],
            "PASS",
        )

    def test_independent_reference_hash_mutation_is_detected(self) -> None:
        case = build_reference_case("reference_hash")
        _step(case, "package")["products"][0]["hash"] = "0" * 64
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "unexpected_product_hash")
        self.assertEqual(result["suspicious_steps"][0], "package")

    def test_all_authoritative_hash_mismatches_are_not_suppressed(self) -> None:
        case = generate_clean_case("strict_all_hashes")
        for step in case["steps"]:
            for product in step["products"]:
                product["hash"] = "f" * 64
            _resign(step)
        result = self.verifier.verify(case)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["primary_violation"], "unexpected_product_hash")
        self.assertGreaterEqual(result["evidence_count"], 8)

    def test_unsupplied_policy_is_not_replaced_by_development_defaults(self) -> None:
        case = generate_clean_case("no_policy_fallback")
        del case["layout"]["authorized_signers"]
        del case["layout"]["expected_products"]
        del case["layout"]["expected_product_hashes"]
        changed = _step(case, "compile")
        changed["signer_id"] = "unconstrained-signer"
        _, public_key = derive_keypair_hex("unconstrained-signer")
        case["public_verification_material"]["public_keys"]["unconstrained-signer"] = public_key
        changed["products"][0]["name"] = "unconstrained-output.bin"
        changed["products"][0]["hash"] = "a" * 64
        _resign(changed)
        # Preserve the independently verifiable material relationship; this
        # test isolates absent layout-policy fallback rather than continuity.
        successor = _step(case, "test")
        successor["materials"] = copy.deepcopy(changed["products"])
        _resign(successor)
        result = self.verifier.verify(case)
        self.assertEqual(result["verdict"], "PASS")

    def test_omitted_step_policy_is_unsupplied(self) -> None:
        case = generate_clean_case("partial_policy")
        del case["layout"]["expected_products"]["compile"]
        del case["layout"]["expected_product_hashes"]["compile"]
        changed = _step(case, "compile")
        changed["products"][0] = {"name": "unconstrained.bin", "hash": "a" * 64}
        _resign(changed)
        successor = _step(case, "test")
        successor["materials"] = copy.deepcopy(changed["products"])
        _resign(successor)
        self.assertEqual(self.verifier.verify(case)["verdict"], "PASS")

    def test_supplied_hash_policy_requires_the_complete_product_set(self) -> None:
        case = generate_clean_case("exact_hash_policy")
        del case["layout"]["expected_products"]["compile"]
        compile_step = _step(case, "compile")
        compile_step["products"] = []
        _resign(compile_step)
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "unexpected_product_hash")
        self.assertEqual(result["suspicious_steps"][0], "compile")

    def test_valid_signature_does_not_authorize_an_unapproved_signer(self) -> None:
        case = generate_clean_case("valid_but_unauthorized")
        changed = _step(case, "scan")
        changed["signer_id"] = "eve"
        _, public_key = derive_keypair_hex("eve")
        case["public_verification_material"]["public_keys"]["eve"] = public_key
        _resign(changed)
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "unauthorized_signer")
        self.assertEqual(result["suspicious_steps"][0], "scan")

    def test_invalid_signature_is_distinct_from_unauthorized_signer(self) -> None:
        case = generate_clean_case("invalid_signature")
        _step(case, "scan")["signature"] = "00"
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "invalid_signature")
        self.assertEqual(result["suspicious_steps"][0], "scan")


class TestStructuralAndProvenanceHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def test_unknown_step_is_a_structural_error(self) -> None:
        case = generate_clean_case("unknown_step")
        unknown = copy.deepcopy(_step(case, "fetch"))
        unknown["step_id"] = "deploy"
        _resign(unknown)
        case["steps"].append(unknown)
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "structural_error")
        self.assertIn("deploy", result["suspicious_steps"])

    def test_duplicate_step_is_a_structural_error(self) -> None:
        case = generate_clean_case("duplicate_step")
        case["steps"].append(copy.deepcopy(_step(case, "compile")))
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "structural_error")
        self.assertEqual(result["suspicious_steps"][0], "compile")

    def test_malformed_record_returns_a_structured_failure(self) -> None:
        case = generate_clean_case("malformed_record")
        del _step(case, "compile")["signature"]
        result = self.verifier.verify(case)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["primary_violation"], "structural_error")
        self.assertEqual(result["suspicious_steps"], ["__case__"])

    def test_missing_public_verification_material_is_structural(self) -> None:
        case = generate_clean_case("missing_pvm")
        del case["public_verification_material"]
        self.assertEqual(
            self.verifier.verify(case)["primary_violation"],
            "structural_error",
        )

    def test_unknown_schema_field_is_structural(self) -> None:
        case = generate_clean_case("unknown_field")
        case["steps"][0]["untrusted_extension"] = "not supported"
        self.assertEqual(
            self.verifier.verify(case)["primary_violation"],
            "structural_error",
        )

    def test_multiple_products_can_be_a_clean_case(self) -> None:
        case = generate_clean_case("multiple_products")
        compile_step = _step(case, "compile")
        compile_step["products"].append({"name": "debug-symbols", "hash": "1" * 64})
        case["layout"]["expected_products"]["compile"].append("debug-symbols")
        case["layout"]["expected_product_hashes"]["compile"]["debug-symbols"] = "1" * 64
        _resign(compile_step)
        result = self.verifier.verify(case)
        self.assertEqual(result["verdict"], "PASS")

    def test_graph_ranker_keeps_upstream_hash_root_ahead_of_downstream_noise(self) -> None:
        case = generate_clean_case("propagation")
        package = _step(case, "package")
        package["products"][0]["hash"] = "0" * 64
        result = self.verifier.verify(case)
        self.assertEqual(result["primary_violation"], "unexpected_product_hash")
        self.assertEqual(result["suspicious_steps"][0], "package")

    def test_static_and_graph_rankers_are_interchangeable(self) -> None:
        case = generate_clean_case("ranker_contract")
        _step(case, "test")["signature"] = "00"
        self.assertEqual(
            CY03Verifier(ranker=StaticRanker()).verify(case)["primary_violation"],
            "invalid_signature",
        )
        self.assertEqual(
            CY03Verifier(ranker=GraphRanker()).verify(case)["primary_violation"],
            "invalid_signature",
        )


class TestLocalizationMetrics(unittest.TestCase):
    def test_reciprocal_rank_and_mrr(self) -> None:
        rankings = [
            (["compile", "test"], "compile"),
            (["package", "scan"], "scan"),
            ([], "publish"),
        ]
        self.assertEqual(reciprocal_rank(rankings[0][0], rankings[0][1]), 1.0)
        self.assertAlmostEqual(mean_reciprocal_rank(rankings), 0.5)
