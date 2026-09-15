"""Quantitative comparison of the retained static and graph rankers."""

from __future__ import annotations

import unittest

from generator.clean_case import generate_clean_case
from generator.mutate_case import (
    mutate_bad_hash,
    mutate_bad_signer,
    mutate_missing_step,
    mutate_unexpected_product,
    mutate_wrong_order,
)
from src.cy03.benchmark import LabeledCase, benchmark_ranker, fit_learned_ranker
from src.cy03.models import CANONICAL_STEPS
from src.cy03.ranker import (
    ConstraintRanker,
    CounterfactualRepairRanker,
    GraphRanker,
    StaticRanker,
)


def _labelled_matrix(repetitions: int = 4) -> list[LabeledCase]:
    cases: list[LabeledCase] = []
    direct_mutators = (
        ("missing_required_step", mutate_missing_step),
        ("unexpected_product_hash", mutate_bad_hash),
        ("unauthorized_signer", mutate_bad_signer),
        ("unexpected_product", mutate_unexpected_product),
    )
    for run in range(repetitions):
        for step_id in CANONICAL_STEPS:
            for violation, mutate in direct_mutators:
                raw_case, target = mutate(
                    generate_clean_case(f"ranker_{violation}_{step_id}_{run}"), step_id,
                )
                cases.append(LabeledCase(raw_case, target, violation))
        for position in range(len(CANONICAL_STEPS) - 1):
            raw_case, target = mutate_wrong_order(
                generate_clean_case(f"ranker_order_{position}_{run}"), position, position + 1,
            )
            cases.append(LabeledCase(raw_case, target, "wrong_order"))
    return cases


class TestRankerBenchmark(unittest.TestCase):
    def test_ranker_strategies_are_benchmarked_quantitatively(self) -> None:
        cases = _labelled_matrix()
        static = benchmark_ranker(cases, StaticRanker())
        graph = benchmark_ranker(cases, GraphRanker())
        counterfactual = benchmark_ranker(cases, CounterfactualRepairRanker())
        constraint = benchmark_ranker(cases, ConstraintRanker())
        learned = benchmark_ranker(
            cases[1::2],
            fit_learned_ranker(cases[::2]),
        )
        print(
            f"\nRanker benchmark ({graph.case_count} cases): "
            f"Static={static.mrr:.3f}; Graph={graph.mrr:.3f}; "
            f"Counterfactual={counterfactual.mrr:.3f}; Constraint={constraint.mrr:.3f}; "
            f"Learned holdout={learned.mrr:.3f}",
        )
        self.assertEqual(static.case_count, 156)
        self.assertEqual(graph.detection_accuracy, 1.0)
        self.assertEqual(graph.primary_violation_accuracy, 1.0)
        self.assertGreater(graph.mrr, static.mrr)
        self.assertEqual(graph.mrr, 1.0)
        self.assertEqual(counterfactual.mrr, 1.0)
        self.assertEqual(constraint.mrr, 1.0)
        self.assertEqual(learned.mrr, 1.0)
