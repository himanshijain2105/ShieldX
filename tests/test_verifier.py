"""Comprehensive test suite for CY-03 Provenance Verifier.

Covers:
- Clean case verification (zero false positives)
- All 5 failure families with targeted step mutations
- MRR validation (mutated step at rank 1)
- Primary violation correctness
- Edge cases
- Stress test (1000+ cases)
"""

from __future__ import annotations

import time
import unittest

from generator.clean_case import generate_clean_case
from generator.mutate_case import (
    mutate_bad_hash,
    mutate_bad_signer,
    mutate_missing_step,
    mutate_unexpected_product,
    mutate_wrong_order,
)
from src.cy03.metrics import mean_reciprocal_rank
from src.cy03.models import CANONICAL_STEPS
from src.cy03.verifier import CY03Verifier


class TestCleanCases(unittest.TestCase):
    """Clean cases must always produce PASS with zero suspicious steps."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def test_single_clean_case(self) -> None:
        case = generate_clean_case("clean_basic")
        r = self.verifier.verify(case)
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(r["suspicious_steps"], [])
        self.assertIsNone(r["primary_violation"])

    def test_multiple_clean_case_ids(self) -> None:
        """Different case_ids should all pass — hashes are case-specific."""
        for i in range(20):
            case = generate_clean_case(f"clean_{i}")
            r = self.verifier.verify(case)
            self.assertEqual(r["verdict"], "PASS", f"Clean case clean_{i} failed")
            self.assertEqual(r["suspicious_steps"], [])

    def test_clean_case_has_explanation(self) -> None:
        case = generate_clean_case("clean_explain")
        r = self.verifier.verify(case)
        self.assertIn("explanation", r)
        self.assertIsInstance(r["explanation"], str)
        self.assertGreater(len(r["explanation"]), 0)


class TestMissingStep(unittest.TestCase):
    """Failure family: missing_required_step."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def _verify_missing(self, target_step: str) -> None:
        case = generate_clean_case(f"missing_{target_step}")
        mut, tgt = mutate_missing_step(case, target_step)
        r = self.verifier.verify(mut)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIn(tgt, r["suspicious_steps"])
        self.assertEqual(r["suspicious_steps"][0], tgt,
                         f"Missing step '{tgt}' should be rank 1")
        self.assertEqual(r["primary_violation"], "missing_required_step")

    def test_missing_fetch(self) -> None:
        self._verify_missing("fetch")

    def test_missing_deps(self) -> None:
        self._verify_missing("deps")

    def test_missing_compile(self) -> None:
        self._verify_missing("compile")

    def test_missing_test(self) -> None:
        self._verify_missing("test")

    def test_missing_package(self) -> None:
        self._verify_missing("package")

    def test_missing_scan(self) -> None:
        self._verify_missing("scan")

    def test_missing_sign(self) -> None:
        self._verify_missing("sign")

    def test_missing_publish(self) -> None:
        self._verify_missing("publish")


class TestUnexpectedProductHash(unittest.TestCase):
    """Failure family: unexpected_product_hash."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def _verify_bad_hash(self, target_step: str) -> None:
        case = generate_clean_case(f"hash_{target_step}")
        mut, tgt = mutate_bad_hash(case, target_step)
        r = self.verifier.verify(mut)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["suspicious_steps"][0], tgt,
                         f"Bad hash on '{tgt}' should be rank 1")
        self.assertEqual(r["primary_violation"], "unexpected_product_hash")

    def test_hash_fetch(self) -> None:
        self._verify_bad_hash("fetch")

    def test_hash_deps(self) -> None:
        self._verify_bad_hash("deps")

    def test_hash_compile(self) -> None:
        self._verify_bad_hash("compile")

    def test_hash_test(self) -> None:
        self._verify_bad_hash("test")

    def test_hash_package(self) -> None:
        self._verify_bad_hash("package")

    def test_hash_scan(self) -> None:
        self._verify_bad_hash("scan")

    def test_hash_sign(self) -> None:
        self._verify_bad_hash("sign")

    def test_hash_publish(self) -> None:
        self._verify_bad_hash("publish")


class TestUnauthorizedSigner(unittest.TestCase):
    """Failure family: unauthorized_signer."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def _verify_bad_signer(self, target_step: str) -> None:
        case = generate_clean_case(f"signer_{target_step}")
        mut, tgt = mutate_bad_signer(case, target_step)
        r = self.verifier.verify(mut)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["suspicious_steps"][0], tgt,
                         f"Bad signer on '{tgt}' should be rank 1")
        self.assertEqual(r["primary_violation"], "unauthorized_signer")

    def test_signer_fetch(self) -> None:
        self._verify_bad_signer("fetch")

    def test_signer_deps(self) -> None:
        self._verify_bad_signer("deps")

    def test_signer_compile(self) -> None:
        self._verify_bad_signer("compile")

    def test_signer_test(self) -> None:
        self._verify_bad_signer("test")

    def test_signer_package(self) -> None:
        self._verify_bad_signer("package")

    def test_signer_scan(self) -> None:
        self._verify_bad_signer("scan")

    def test_signer_sign(self) -> None:
        self._verify_bad_signer("sign")

    def test_signer_publish(self) -> None:
        self._verify_bad_signer("publish")


class TestUnexpectedProduct(unittest.TestCase):
    """Failure family: unexpected_product."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def _verify_bad_product(self, target_step: str) -> None:
        case = generate_clean_case(f"prod_{target_step}")
        mut, tgt = mutate_unexpected_product(case, target_step)
        r = self.verifier.verify(mut)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["suspicious_steps"][0], tgt,
                         f"Bad product on '{tgt}' should be rank 1")
        self.assertEqual(r["primary_violation"], "unexpected_product")

    def test_product_fetch(self) -> None:
        self._verify_bad_product("fetch")

    def test_product_deps(self) -> None:
        self._verify_bad_product("deps")

    def test_product_compile(self) -> None:
        self._verify_bad_product("compile")

    def test_product_test(self) -> None:
        self._verify_bad_product("test")

    def test_product_package(self) -> None:
        self._verify_bad_product("package")

    def test_product_scan(self) -> None:
        self._verify_bad_product("scan")

    def test_product_sign(self) -> None:
        self._verify_bad_product("sign")

    def test_product_publish(self) -> None:
        self._verify_bad_product("publish")


class TestWrongOrder(unittest.TestCase):
    """Failure family: wrong_order (adjacent step swap)."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def _verify_wrong_order(self, idx1: int, idx2: int) -> None:
        case = generate_clean_case(f"order_{idx1}_{idx2}")
        mut, tgt = mutate_wrong_order(case, idx1, idx2)
        r = self.verifier.verify(mut)
        self.assertEqual(r["verdict"], "FAIL")
        # Target should be in the suspicious list (at rank 1 or 2)
        self.assertIn(tgt, r["suspicious_steps"][:2],
                      f"Swapped step '{tgt}' should be in top 2")
        self.assertEqual(r["primary_violation"], "wrong_order")

    def test_swap_0_1(self) -> None:
        """Swap fetch ↔ deps."""
        self._verify_wrong_order(0, 1)

    def test_swap_1_2(self) -> None:
        """Swap deps ↔ compile."""
        self._verify_wrong_order(1, 2)

    def test_swap_2_3(self) -> None:
        """Swap compile ↔ test."""
        self._verify_wrong_order(2, 3)

    def test_swap_3_4(self) -> None:
        """Swap test ↔ package."""
        self._verify_wrong_order(3, 4)

    def test_swap_4_5(self) -> None:
        """Swap package ↔ scan."""
        self._verify_wrong_order(4, 5)

    def test_swap_5_6(self) -> None:
        """Swap scan ↔ sign."""
        self._verify_wrong_order(5, 6)

    def test_swap_6_7(self) -> None:
        """Swap sign ↔ publish."""
        self._verify_wrong_order(6, 7)


class TestExplanationCompleteness(unittest.TestCase):
    """Output must include top suspicious step and violated invariant."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def test_explanation_mentions_step_and_invariant(self) -> None:
        case = generate_clean_case("explain_test")
        mut, tgt = mutate_bad_hash(case, "compile")
        r = self.verifier.verify(mut)
        explanation = r["explanation"]
        # Explanation must mention the top step
        self.assertIn(tgt, explanation)
        # Explanation must be non-trivial
        self.assertGreater(len(explanation), 30)

    def test_pass_case_has_explanation(self) -> None:
        case = generate_clean_case("explain_pass")
        r = self.verifier.verify(case)
        self.assertIn("explanation", r)
        self.assertGreater(len(r["explanation"]), 10)


class TestOutputSchema(unittest.TestCase):
    """Verify output conforms to expected schema."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def test_pass_schema(self) -> None:
        case = generate_clean_case("schema_pass")
        r = self.verifier.verify(case)
        self.assertIn("case_id", r)
        self.assertIn("verdict", r)
        self.assertIn("suspicious_steps", r)
        self.assertIn("primary_violation", r)
        self.assertIn("explanation", r)
        self.assertIsInstance(r["suspicious_steps"], list)

    def test_fail_schema(self) -> None:
        case = generate_clean_case("schema_fail")
        mut, _ = mutate_bad_signer(case, "scan")
        r = self.verifier.verify(mut)
        self.assertEqual(r["case_id"], "schema_fail")
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIsInstance(r["suspicious_steps"], list)
        self.assertGreater(len(r["suspicious_steps"]), 0)
        self.assertIsInstance(r["primary_violation"], str)
        self.assertIn(r["primary_violation"], {
            "missing_required_step",
            "unauthorized_signer",
            "unexpected_product",
            "unexpected_product_hash",
            "wrong_order",
        })


class TestStressSuite(unittest.TestCase):
    """Large-scale stress test for accuracy and performance."""

    def setUp(self) -> None:
        self.verifier = CY03Verifier()

    def test_1000_case_comprehensive(self) -> None:
        """Run 200 clean + 780 mutated cases and measure localization MRR."""
        total = 0
        correct_verdicts = 0
        correct_localizations = 0
        correct_violations = 0
        mrr_rankings: list[tuple[list[str], str]] = []

        t0 = time.perf_counter()

        # 200 clean cases
        for i in range(200):
            case = generate_clean_case(f"stress_clean_{i}")
            r = self.verifier.verify(case)
            total += 1
            if r["verdict"] == "PASS":
                correct_verdicts += 1
                correct_localizations += 1  # no step to localize
                correct_violations += 1

        # 640 direct mutations (8 steps × 4 families × 20 case IDs)
        mutators = [
            ("missing_required_step", mutate_missing_step),
            ("unexpected_product_hash", mutate_bad_hash),
            ("unauthorized_signer", mutate_bad_signer),
            ("unexpected_product", mutate_unexpected_product),
        ]

        for i in range(20):
            for step_idx, step_id in enumerate(CANONICAL_STEPS):
                for expected_violation, mut_fn in mutators:
                    case = generate_clean_case(f"stress_{expected_violation}_{step_id}_{i}")
                    mut, target = mut_fn(case, step_id)
                    r = self.verifier.verify(mut)
                    mrr_rankings.append((r["suspicious_steps"], target))
                    total += 1
                    if r["verdict"] == "FAIL":
                        correct_verdicts += 1
                    if r["suspicious_steps"] and r["suspicious_steps"][0] == target:
                        correct_localizations += 1
                    if r["primary_violation"] == expected_violation:
                        correct_violations += 1

            # Wrong order swaps (7 adjacent pairs × 20)
            for j in range(len(CANONICAL_STEPS) - 1):
                case = generate_clean_case(f"stress_order_{j}_{i}")
                mut, target = mutate_wrong_order(case, j, j + 1)
                r = self.verifier.verify(mut)
                mrr_rankings.append((r["suspicious_steps"], target))
                total += 1
                if r["verdict"] == "FAIL":
                    correct_verdicts += 1
                if r["suspicious_steps"] and target in r["suspicious_steps"][:2]:
                    correct_localizations += 1
                if r["primary_violation"] == "wrong_order":
                    correct_violations += 1

        elapsed = time.perf_counter() - t0
        mrr = mean_reciprocal_rank(mrr_rankings)

        # Report
        print(f"\n{'='*60}")
        print(f"Stress test: {total} cases in {elapsed:.2f}s")
        print(f"  Verdict accuracy:      {correct_verdicts}/{total} "
              f"({100*correct_verdicts/total:.1f}%)")
        print(f"  Localization accuracy:  {correct_localizations}/{total} "
              f"({100*correct_localizations/total:.1f}%)")
        print(f"  Violation accuracy:     {correct_violations}/{total} "
              f"({100*correct_violations/total:.1f}%)")
        print(f"  Localization MRR:       {mrr:.3f} ({len(mrr_rankings)} mutated cases)")
        print(f"  Throughput:             {total/elapsed:.0f} cases/sec")
        print(f"{'='*60}")

        self.assertEqual(correct_verdicts, total,
                         f"Verdict accuracy: {correct_verdicts}/{total}")
        self.assertEqual(correct_localizations, total,
                         f"Localization accuracy: {correct_localizations}/{total}")
        self.assertEqual(correct_violations, total,
                         f"Violation accuracy: {correct_violations}/{total}")
        self.assertGreaterEqual(mrr, 0.98, f"Localization MRR: {mrr:.3f}")


if __name__ == "__main__":
    unittest.main()
