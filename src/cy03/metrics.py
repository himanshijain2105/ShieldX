"""Deterministic localization metrics used by the benchmark harness."""

from __future__ import annotations

from collections.abc import Iterable, Sequence


def reciprocal_rank(ranked_steps: Sequence[str], expected_step: str) -> float:
    """Return the reciprocal rank of one expected root cause, or zero."""
    try:
        return 1.0 / (ranked_steps.index(expected_step) + 1)
    except ValueError:
        return 0.0


def mean_reciprocal_rank(rankings: Iterable[tuple[Sequence[str], str]]) -> float:
    """Calculate MRR across mutated cases with known target steps.

    Clean cases are intentionally excluded: they have no fault-localization
    target and therefore do not belong in the MRR denominator.
    """
    reciprocal_ranks = [
        reciprocal_rank(ranked_steps, expected_step)
        for ranked_steps, expected_step in rankings
    ]
    return sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else 0.0
