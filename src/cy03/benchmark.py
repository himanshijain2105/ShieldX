"""Quantitative, labelled comparisons for fault-localization rankers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .metrics import mean_reciprocal_rank
from .parser import parse_case
from .ranker import LearnedRanker, Ranker, RankerTrainingExample
from .verifier import CY03Verifier, collect_evidence


@dataclass(frozen=True)
class LabeledCase:
    """One benchmark case with evaluator-hidden labels revealed locally only."""

    raw_case: Mapping[str, Any]
    expected_step: str
    expected_violation: str


@dataclass(frozen=True)
class RankerMetrics:
    """Detection and localization results for a fixed labelled benchmark."""

    case_count: int
    detection_accuracy: float
    primary_violation_accuracy: float
    mrr: float


def benchmark_ranker(cases: Iterable[LabeledCase], ranker: Ranker) -> RankerMetrics:
    """Measure one ranker without coupling benchmark data to production logic."""
    labelled_cases = list(cases)
    verifier = CY03Verifier(ranker=ranker)
    results = [verifier.verify(case.raw_case) for case in labelled_cases]
    total = len(labelled_cases)
    if not total:
        return RankerMetrics(0, 0.0, 0.0, 0.0)
    return RankerMetrics(
        case_count=total,
        detection_accuracy=sum(result["verdict"] == "FAIL" for result in results) / total,
        primary_violation_accuracy=sum(
            result["primary_violation"] == case.expected_violation
            for result, case in zip(results, labelled_cases)
        ) / total,
        mrr=mean_reciprocal_rank([
            (result["suspicious_steps"], case.expected_step)
            for result, case in zip(results, labelled_cases)
        ]),
    )


def fit_learned_ranker(
    cases: Iterable[LabeledCase],
    *,
    epochs: int = 8,
    learning_rate: float = 0.01,
) -> LearnedRanker:
    """Train on locally labelled cases; callers choose a train/test split."""
    examples = []
    for labelled_case in cases:
        case = parse_case(labelled_case.raw_case)
        examples.append(RankerTrainingExample(
            case=case,
            evidences=collect_evidence(case),
            expected_step=labelled_case.expected_step,
        ))
    return LearnedRanker().fit(
        examples,
        epochs=epochs,
        learning_rate=learning_rate,
    )
