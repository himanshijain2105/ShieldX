"""Input parsing for CY-03.

Handles single JSON objects, lists of cases, and JSONL streams.
"""

from __future__ import annotations

import json
from typing import Any, List

from .models import Case


def parse_case(raw_input: Any) -> Case:
    """Parse a single provenance case from a dict or JSON string."""
    if isinstance(raw_input, str):
        data = json.loads(raw_input)
    else:
        data = raw_input
    return Case.from_dict(data)


def parse_batch(raw_input: Any) -> List[Case]:
    """Parse one or more cases from various input formats.

    Accepted formats:
    - A JSON string/dict representing a single case
    - A JSON list of case dicts
    - A JSONL string (one JSON object per line)
    """
    if isinstance(raw_input, list):
        return [parse_case(item) for item in raw_input]

    if isinstance(raw_input, dict):
        # Single case or wrapper with a "cases" key
        if "cases" in raw_input:
            return [parse_case(c) for c in raw_input["cases"]]
        return [parse_case(raw_input)]

    if isinstance(raw_input, str):
        text = raw_input.strip()
        # Try JSON array first
        if text.startswith("["):
            items = json.loads(text)
            return [parse_case(item) for item in items]
        # Try single JSON object
        if text.startswith("{") and "\n" not in text:
            return [parse_case(text)]
        # JSONL — one JSON object per line
        cases: List[Case] = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                cases.append(parse_case(line))
        return cases

    # Fallback: treat as single case
    return [parse_case(raw_input)]
