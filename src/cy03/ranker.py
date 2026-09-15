"""Replaceable, deterministic fault-localization strategies for CY-03."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Protocol, Tuple

from .models import Case, EvidenceItem


class Ranker(Protocol):
    """Stable interface for experimentally comparing ranking strategies."""

    def rank(self, case: Case, evidences: List[EvidenceItem]) -> List[str]:
        """Return suspicious step IDs in deterministic priority order."""



class StaticRanker:
    """Simple weighted baseline retained for controlled ranking experiments."""

    def rank(self, case: Case, evidences: List[EvidenceItem]) -> List[str]:
        scores: Dict[str, float] = {}
        top_severity: Dict[str, int] = {}
        canonical_index = {step_id: i for i, step_id in enumerate(case.layout.canonical_steps)}
        for evidence in evidences:
            scores[evidence.step_id] = scores.get(evidence.step_id, 0.0) + (
                evidence.severity * evidence.confidence
            )
            top_severity[evidence.step_id] = max(
                top_severity.get(evidence.step_id, 0), evidence.severity,
            )
        return sorted(
            scores,
            key=lambda step_id: (
                -scores[step_id],
                -top_severity.get(step_id, 0),
                canonical_index.get(step_id, len(canonical_index) + 1),
                step_id,
            ),
        )


class GraphRanker:
    """Rank direct evidence above downstream symptoms in the provenance chain.

    Material discontinuities remain visible on their observed downstream step,
    while a bounded support credit is assigned to their upstream producer. This
    models a single upstream mutation without allowing propagated observations
    to eclipse a directly observed root cause.
    """

    propagated_step_weight = 0.35
    upstream_support_weight = 0.70
    order_forward_bonus = 5.0

    def rank(self, case: Case, evidences: List[EvidenceItem]) -> List[str]:
        scores: Dict[str, float] = {}
        top_severity: Dict[str, int] = {}
        canonical_index = {step_id: i for i, step_id in enumerate(case.layout.canonical_steps)}

        for evidence in evidences:
            weighted = evidence.severity * evidence.confidence
            if evidence.direct:
                scores[evidence.step_id] = scores.get(evidence.step_id, 0.0) + weighted
            else:
                scores[evidence.step_id] = scores.get(evidence.step_id, 0.0) + (
                    weighted * self.propagated_step_weight
                )
                if evidence.propagated_from:
                    scores[evidence.propagated_from] = scores.get(evidence.propagated_from, 0.0) + (
                        weighted * self.upstream_support_weight
                    )

            top_severity[evidence.step_id] = max(
                top_severity.get(evidence.step_id, 0), evidence.severity,
            )

        # For adjacent swaps, the forward-moved step is the evaluator's root
        # convention. The bonus only resolves an otherwise symmetric finding.
        actual_index = {step.step_id: index for index, step in enumerate(case.steps)}
        for evidence in evidences:
            if evidence.violation_type != "wrong_order":
                continue
            canonical = canonical_index.get(evidence.step_id)
            actual = actual_index.get(evidence.step_id)
            if canonical is not None and actual is not None and canonical > actual:
                scores[evidence.step_id] += (canonical - actual) * self.order_forward_bonus

        return sorted(
            scores,
            key=lambda step_id: (
                -scores[step_id],
                -top_severity.get(step_id, 0),
                canonical_index.get(step_id, len(canonical_index) + 1),
                step_id,
            ),
        )


def _candidate_steps(evidences: List[EvidenceItem]) -> set[str]:
    """Collect all steps that could plausibly repair at least one finding."""
    candidates = {evidence.step_id for evidence in evidences}
    for evidence in evidences:
        candidates.update(evidence.related_steps)
        if evidence.propagated_from:
            candidates.add(evidence.propagated_from)
    return candidates


def _canonical_index(case: Case) -> Dict[str, int]:
    return {step_id: index for index, step_id in enumerate(case.layout.canonical_steps)}


def _forward_displacement(case: Case, step_id: str) -> float:
    canonical = _canonical_index(case).get(step_id)
    actual = {step.step_id: index for index, step in enumerate(case.steps)}.get(step_id)
    if canonical is None or actual is None:
        return 0.0
    return float(max(canonical - actual, 0))


def _sort_scores(case: Case, scores: Dict[str, float]) -> List[str]:
    canonical_index = _canonical_index(case)
    return sorted(
        scores,
        key=lambda step_id: (
            -scores[step_id],
            canonical_index.get(step_id, len(canonical_index) + 1),
            step_id,
        ),
    )


class CounterfactualRepairRanker:
    """Rank the one-step repair that removes the most weighted evidence.

    Each candidate is evaluated counterfactually: direct evidence owned by the
    candidate, order evidence involving it, and downstream evidence explicitly
    attributed to it are treated as repaired. The remaining weighted evidence
    is the minimum-repair objective; lower remainder ranks higher.
    """

    order_forward_bonus = 5.0

    def rank(self, case: Case, evidences: List[EvidenceItem]) -> List[str]:
        candidates = _candidate_steps(evidences)
        scores = {candidate: 0.0 for candidate in candidates}
        for candidate in candidates:
            repaired_weight = 0.0
            for evidence in evidences:
                weight = evidence.severity * evidence.confidence
                if evidence.direct:
                    if candidate == evidence.step_id or (
                        evidence.violation_type == "wrong_order"
                        and candidate in evidence.related_steps
                    ):
                        repaired_weight += weight
                elif evidence.propagated_from == candidate:
                    repaired_weight += weight
            scores[candidate] = repaired_weight + (
                self.order_forward_bonus * _forward_displacement(case, candidate)
            )
        return _sort_scores(case, scores)


class ConstraintRanker:
    """Rank candidates by the number of violated constraints they explain.

    A direct finding belongs to its recorded step; an order finding belongs to
    both endpoints; and a propagated relationship finding belongs to its named
    upstream producer. This is a compact minimal-inconsistent-set approximation
    for the benchmark's single-primary-mutation contract.
    """

    order_forward_bonus = 0.1
    direct_constraint_weight = 2.0

    def rank(self, case: Case, evidences: List[EvidenceItem]) -> List[str]:
        candidates = _candidate_steps(evidences)
        scores = {candidate: 0.0 for candidate in candidates}
        for evidence in evidences:
            if evidence.direct:
                explained_by = {evidence.step_id}
                if evidence.violation_type == "wrong_order":
                    explained_by.update(evidence.related_steps)
            else:
                explained_by = {evidence.propagated_from or evidence.step_id}
            for candidate in explained_by:
                if candidate in scores:
                    scores[candidate] += (
                        self.direct_constraint_weight if evidence.direct else 1.0
                    )
        for candidate in scores:
            scores[candidate] += self.order_forward_bonus * _forward_displacement(case, candidate)
        return _sort_scores(case, scores)


@dataclass(frozen=True)
class RankerTrainingExample:
    """Local labelled evidence used to fit ``LearnedRanker`` explicitly."""

    case: Case
    evidences: List[EvidenceItem]
    expected_step: str


class LearnedRanker:
    """A deterministic pairwise linear ranker trained on local labels only.

    It deliberately has no ML dependency and no implicit training data. Call
    ``fit`` with labelled local examples before evaluation; its fallback weights
    match the interpretable graph baseline so an untrained instance is safe.
    """

    _fallback_weights = (1.0, 0.70, 0.35, 0.0, 5.0)

    def __init__(self) -> None:
        self._weights = self._fallback_weights
        self.is_fitted = False

    @property
    def weights(self) -> Tuple[float, float, float, float, float]:
        """Expose learned weights for reproducible benchmark reporting."""
        return self._weights

    def fit(
        self,
        examples: Iterable[RankerTrainingExample],
        *,
        epochs: int = 8,
        learning_rate: float = 0.01,
    ) -> "LearnedRanker":
        """Fit a pairwise perceptron from explicitly labelled local examples."""
        if epochs < 1 or learning_rate <= 0:
            raise ValueError("epochs and learning_rate must be positive.")
        training_examples = list(examples)
        weights = [0.0] * len(self._fallback_weights)
        for _ in range(epochs):
            for example in training_examples:
                features = _feature_map(example.case, example.evidences)
                target = features.get(example.expected_step)
                if target is None:
                    continue
                for candidate, candidate_features in features.items():
                    if candidate == example.expected_step:
                        continue
                    if _dot(weights, target) <= _dot(weights, candidate_features):
                        for index, value in enumerate(target):
                            weights[index] += learning_rate * (value - candidate_features[index])
        self._weights = tuple(weights)  # type: ignore[assignment]
        self.is_fitted = True
        return self

    def rank(self, case: Case, evidences: List[EvidenceItem]) -> List[str]:
        return _sort_scores(
            case,
            {
                step_id: _dot(self._weights, features)
                for step_id, features in _feature_map(case, evidences).items()
            },
        )


def _feature_map(case: Case, evidences: List[EvidenceItem]) -> Dict[str, Tuple[float, ...]]:
    """Create label-independent, provenance-derived ranker features."""
    candidates = _candidate_steps(evidences)
    features: Dict[str, Tuple[float, ...]] = {}
    for candidate in candidates:
        direct_strength = sum(
            evidence.severity * evidence.confidence
            for evidence in evidences
            if evidence.direct and evidence.step_id == candidate
        )
        upstream_strength = sum(
            evidence.severity * evidence.confidence
            for evidence in evidences
            if not evidence.direct and evidence.propagated_from == candidate
        )
        symptom_strength = sum(
            evidence.severity * evidence.confidence
            for evidence in evidences
            if not evidence.direct and evidence.step_id == candidate
        )
        direct_count = float(sum(
            evidence.direct and evidence.step_id == candidate for evidence in evidences
        ))
        features[candidate] = (
            direct_strength,
            upstream_strength,
            symptom_strength,
            direct_count,
            _forward_displacement(case, candidate),
        )
    return features


def _dot(weights: Iterable[float], features: Iterable[float]) -> float:
    return sum(weight * feature for weight, feature in zip(weights, features))


_PRIMARY_PRECEDENCE = (
    "structural_error",
    "missing_required_step",
    "unauthorized_signer",
    "unexpected_product",
    "unexpected_product_hash",
    "wrong_order",
    # A content/order violation can invalidate its signed envelope. Preserve
    # that cryptographic evidence, but report the direct domain cause first.
    "invalid_signature",
    "material_product_mismatch",
)


def rank_and_localize(
    evidences: List[EvidenceItem],
    case: Case,
    *,
    ranker: Ranker | None = None,
) -> Tuple[str, List[str], Optional[str], str]:
    """Produce the benchmark result using the supplied ranking strategy."""
    if not evidences:
        return (
            "PASS", [], None,
            "All verification checks passed. No provenance failures detected.",
        )

    sorted_steps = (ranker or GraphRanker()).rank(case, evidences)
    top_step = sorted_steps[0]
    top_direct = [
        evidence for evidence in evidences
        if evidence.step_id == top_step and evidence.direct
    ]
    # A step promoted only by downstream support should explain its strongest
    # linked observation, while normal cases always choose direct evidence.
    candidates = top_direct or [evidence for evidence in evidences if evidence.step_id == top_step]
    violation_types = {evidence.violation_type for evidence in candidates}
    primary_violation = next(
        violation for violation in _PRIMARY_PRECEDENCE if violation in violation_types
    )
    messages = [
        evidence.message for evidence in candidates
        if evidence.violation_type == primary_violation
    ] or [evidence.message for evidence in candidates]
    return "FAIL", sorted_steps, primary_violation, _build_explanation(
        top_step, primary_violation, messages,
    )


def _build_explanation(top_step: str, primary_violation: str, messages: List[str]) -> str:
    descriptions = {
        "structural_error": f"The input structure associated with '{top_step}' is invalid.",
        "missing_required_step": f"Required step '{top_step}' is absent from the build chain.",
        "unauthorized_signer": f"Step '{top_step}' was signed by an unauthorized functionary.",
        "invalid_signature": f"Step '{top_step}' has an invalid cryptographic signature.",
        "unexpected_product": f"Step '{top_step}' produced an unexpected artifact.",
        "unexpected_product_hash": f"Step '{top_step}' produced an artifact with an unexpected hash.",
        "wrong_order": f"Step '{top_step}' is out of canonical build order.",
        "material_product_mismatch": f"Step '{top_step}' breaks material/product continuity.",
    }
    detail = f" Detail: {messages[0]}" if messages else ""
    return descriptions[primary_violation] + detail
