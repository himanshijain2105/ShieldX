"""Core verifier orchestrator for CY-03.

Runs all validators, aggregates evidence, and produces a structured
verification result.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import Case, CaseParseError, EvidenceItem
from .parser import parse_case
from .ranker import Ranker, rank_and_localize
from .validators import (
    validate_material_chain,
    validate_products,
    validate_signatures,
    validate_signers,
    validate_structure,
    validate_step_completeness,
    validate_step_order,
)


def collect_evidence(case: Case) -> List[EvidenceItem]:
    """Run the fixed validator set once for ranker training or evaluation."""
    evidences: List[EvidenceItem] = []
    evidences.extend(validate_structure(case))
    evidences.extend(validate_step_completeness(case))
    evidences.extend(validate_step_order(case))
    evidences.extend(validate_signers(case))
    evidences.extend(validate_signatures(case))
    evidences.extend(validate_products(case))
    evidences.extend(validate_material_chain(case))
    return evidences


class CY03Verifier:
    """Provenance verifier and fault localizer."""

    def __init__(self, *, ranker: Ranker | None = None) -> None:
        self._ranker = ranker

    def verify(self, raw_input: Any) -> Dict[str, Any]:
        """Verify a single provenance case.

        Parameters
        ----------
        raw_input : dict | str
            A single case as a dict or JSON string.

        Returns
        -------
        dict
            Structured verification result with verdict, suspicious
            steps, primary violation, and explanation.
        """
        try:
            case = parse_case(raw_input)
        except (CaseParseError, TypeError, ValueError) as exc:
            return self._structural_failure(raw_input, str(exc))
        return self._verify_case(case)

    def verify_case(self, case: Case) -> Dict[str, Any]:
        """Verify a pre-parsed ``Case`` object."""
        return self._verify_case(case)

    def _verify_case(self, case: Case) -> Dict[str, Any]:
        evidences = collect_evidence(case)

        verdict, suspicious_steps, primary_violation, explanation = (
            rank_and_localize(evidences, case, ranker=self._ranker)
        )

        return {
            "case_id": case.case_id,
            "verdict": verdict,
            "suspicious_steps": suspicious_steps,
            "primary_violation": primary_violation,
            "explanation": explanation,
            "evidence_count": len(evidences),
        }

    @staticmethod
    def _structural_failure(raw_input: Any, message: str) -> Dict[str, Any]:
        """Return a deterministic result for inputs that cannot be parsed."""
        case_id = raw_input.get("case_id", "unknown") if isinstance(raw_input, dict) else "unknown"
        return {
            "case_id": case_id if isinstance(case_id, str) else "unknown",
            "verdict": "FAIL",
            "suspicious_steps": ["__case__"],
            "primary_violation": "structural_error",
            "explanation": f"Input is structurally invalid: {message}",
            "evidence_count": 1,
        }
