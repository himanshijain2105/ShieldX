# CY-03 Software Supply-Chain Provenance Verifier

**CY-03 Software Supply-Chain Provenance Verifier** is a deterministic attestation verifier and fault-localization engine for the fixed eight-step build chain. It normalizes an evaluator case once, checks structure, order, authorization, signatures, supplied artifact constraints, and material continuity, then ranks root-cause candidates while discounting downstream noise.

## Verification contract

The supported case shape is exact: required `case_id` (string), `steps` (list), and `public_verification_material.public_keys` (object); optional `metadata` (object) and `layout` (object). `steps[*]` accepts only `step_id`, `signer_id`, `signature`, `materials`, and `products`; artifacts accept only `name` and `hash`. Unknown fields in these verification objects are structural errors. The canonical CY-03 step sequence is always enforced. Within `layout`, the supported fields are:

- `authorized_signers`: `{step_id: [signer_id, ...]}`
- `expected_products`: `{step_id: [artifact_name, ...]}`
- `expected_product_hashes`: `{step_id: {artifact_name: hash}}`

Policy state is per step: omitting a policy field, or omitting a step from a supplied mapping, means **unsupplied** and skips only that policy check for that step. An explicitly supplied `expected_products[step] = []` or `expected_product_hashes[step] = {}` requires that step to produce no products. A non-empty hash mapping requires the exact product-name/hash set, including required products. No state is replaced with benchmark-development defaults. Every attempted signature verification and every authoritative hash mismatch is reported; there is no adaptive suppression. Invalid record shapes, duplicate IDs, and unknown IDs are returned as `structural_error`, distinct from provenance violations.

---

## Quick Start

### 1. Installation

Install the package in editable mode within your Python 3.10+ environment:

```bash
pip install -e .
```

Or install runtime dependencies directly:

```bash
pip install -r requirements.txt
```

### 2. Verify an Example Case

Verify a clean, valid provenance case:

```bash
python3 -m cy03.cli --input examples/clean.json
```

Or use the installed console script:

```bash
cy03-verify --input examples/clean.json
```

---

## Usage Examples

The command-line interface supports single JSON case files, newline-delimited JSONL streams, and directories of test cases.

### 1. Single File Verification

Verify a single attestation case and format the output as indented JSON:

```bash
python3 -m cy03.cli --input examples/missing_step.json --format json
```

**Sample Output:**
```json
[
  {
    "case_id": "case_missing_ex",
    "verdict": "FAIL",
    "suspicious_steps": [
      "compile",
      "deps",
      "test"
    ],
    "primary_violation": "missing_required_step",
    "explanation": "Required step 'compile' is absent from the build chain. Detail: Required step 'compile' is missing from the build chain.",
    "evidence_count": 2
  }
]
```

### 2. Batch Verification with JSONL

Process a large batch of provenance cases via JSONL stream and write results to an output file:

```bash
python3 -m cy03.cli --input examples/benchmark.jsonl --output results.jsonl --format jsonl
```

### 3. Directory Verification

Process all `*.json` files located within a directory:

```bash
python3 -m cy03.cli --input examples/ --format json
```

### 4. Quiet Mode

Suppress timing and summary statistics emitted to `stderr`:

```bash
python3 -m cy03.cli --input examples/benchmark.jsonl --quiet
```

---

## Architecture Diagram

The verification engine executes an end-to-end deterministic evaluation pipeline:

```
                            Input Provenance Attestation
                        (JSON Case / JSONL Stream / Dict)
                                        │
                                        ▼
                           ┌─────────────────────────┐
                           │      parse_case()       │
                           │  • Schema Normalization │
                           │  • Explicit constraint state
                           └────────────┬────────────┘
                                        │
                                        ▼
                             ┌─────────────────────┐
                             │     Case Object     │
                             └──────────┬──────────┘
                                        │
         ┌──────────────────────────────┼──────────────────────────────┐
         │                              │                              │
         ▼                              ▼                              ▼
┌───────────────────┐          ┌───────────────────┐          ┌───────────────────┐
│ Step Completeness │          │  Step Ordering    │          │ Signer Authority  │
│  8 Canonical Steps│          │ Relative Sequence │          │ Functionary Map   │
│  (Severity: 100)  │          │  (Severity: 70)   │          │  (Severity: 90)   │
└────────┬──────────┘          └────────┬──────────┘          └────────┬──────────┘
         │                              │                              │
         ▼                              ▼                              ▼
┌───────────────────┐          ┌───────────────────┐          ┌───────────────────┐
│ Cryptographic Sig │          │ Product Artifacts │          │  Material Chain   │
│  Ed25519 / HMAC   │          │  Names & Hashes   │          │ N Product -> N+1  │
│  (Strict result)  │          │  (Supplied policy) │          │  Material Flow    │
└────────┬──────────┘          └────────┬──────────┘          └────────┬──────────┘
         │                              │                              │
         └──────────────────────────────┼──────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │     Evidence Aggregator     │
                         │    List[EvidenceItem]       │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │      Ranking Engine         │
│ • Direct evidence scoring   │
│ • Propagation-aware support │
                         │ • Forward-Displacement Tie  │
│ • Replaceable ranker API    │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │   Final Structured Output   │
                         │ • verdict: PASS / FAIL      │
                         │ • suspicious_steps: [...]   │
                         │ • primary_violation: ...    │
                         │ • explanation: human string │
                         └─────────────────────────────┘
```

---

## Running Tests

The test suite covers independent-oracle cases, isolated mutations, adversarial clean cases, strict no-suppression behavior, policy absence, structural failures, and a 980-case stress matrix. Its labelled 156-case ranker comparison measures Static MRR 0.910 and Graph, Counterfactual, and Constraint MRR 1.000; the learned ranker reaches 1.000 on a disjoint 78-case holdout.

```bash
python3 -m unittest discover -s tests -v
```

**Current release validation:**
```
----------------------------------------------------------------------
Ran 74 tests

OK

Ranker benchmark (156 cases): Static=0.910; Graph=1.000;
Counterfactual=1.000; Constraint=1.000; Learned holdout=1.000

Stress test: 980 cases
  Verdict accuracy:      980/980 (100.0%)
  Localization accuracy: 980/980 (100.0%)
  Violation accuracy:    980/980 (100.0%)
  Localization MRR:      1.000 (780 mutated cases)
```

---

## Project Structure

```
cy03-provenance/
├── README.md                      # Project overview, quick start, and CLI usage
├── SPEC.md                        # Formal canonical 8-step build specification & contracts
├── TECHNICAL.md                   # Technical architecture, ranking algorithm, and crypto specs
├── THREAT_MODEL.md                # Threat actors, attack vectors, detection, and limitations
├── pyproject.toml                 # Package definition and cy03-verify console script entrypoint
├── requirements.txt               # Dependencies (cryptography >= 41.0.0)
│
├── generator/                     # Synthetic case generator and mutation test operators
│   ├── __init__.py
│   ├── clean_case.py              # Generates cryptographically valid 8-step cases
│   ├── generate_examples.py       # Generates sample JSON files and benchmark.jsonl
│   └── mutate_case.py             # Applies single-mutation failure family operators
│
├── src/
│   └── cy03/                      # Core verifier implementation package
│       ├── __init__.py            # Package export
│       ├── cli.py                 # Command-line interface with batch and streaming support
│       ├── hashing.py             # Artifact hashing and canonical payload formatting
│       ├── models.py              # Data models (Case, StepRecord, Artifact, EvidenceItem)
│       ├── parser.py              # JSON and JSONL input parser
│       ├── benchmark.py           # Labelled local ranker evaluation helpers
│       ├── ranker.py              # Fault-localization ranking engine (MRR optimization)
│       ├── signatures.py          # Ed25519 signing/verifying with HMAC-SHA256 fallback
│       ├── validators.py          # Structural and provenance invariant validators
│       └── verifier.py            # Orchestrator coordinating validation and ranking
│
└── tests/                         # 74 regression tests and a 980-case stress evaluation
```

---

## Additional Documentation

For deeper details on security analysis and technical implementation:

- **Threat Model & Limitations**: Consult [THREAT_MODEL.md](THREAT_MODEL.md) for threat actors, detection mechanics, and design limitations.
- **Technical Architecture**: Consult [TECHNICAL.md](TECHNICAL.md) for validator algorithms, ranking strategies, and computational complexity.
- **Specification Contract**: Consult [SPEC.md](SPEC.md) for canonical step sequences and failure severities.
