# Technical Architecture — CY-03 Provenance Verifier

## Verification pipeline

```text
untrusted JSON
  -> strict parse and normalization
  -> structural checks
  -> order / authorization / signature / artifact checks
  -> material-product relationship checks
  -> direct and propagated evidence
  -> replaceable ranker
  -> PASS or FAIL with ranked steps and primary invariant
```

`models.py` is the normalized boundary. Validators receive only `Case`, `LayoutSpec`, and `StepRecord` instances; they do not interpret alternate wire formats or import the synthetic generator's policy constants.

## Input and policy semantics

The benchmark's canonical sequence is fixed:

```text
fetch -> deps -> compile -> test -> package -> scan -> sign -> publish
```

`layout.authorized_signers`, `layout.expected_products`, and `layout.expected_product_hashes` each have an explicit per-step state:

- **supplied** — enforce the evaluator-provided constraint;
- **unsupplied** — do not invent a fallback constraint.

Omitting the field, or omitting a step key from a supplied map, is unsupplied for that step. An explicitly present empty product list or hash map means that step must produce no products. A non-empty `expected_product_hashes[step]` map requires the exact product-name/hash set; it is not merely a check against products that happened to be emitted. This permits multiple outputs per step and makes hash checking an authoritative comparison, not an inferred development formula. The development generator still uses the published deterministic formula, but writes its resulting values into the case layout.

## Structural and provenance findings

Malformed JSON records, missing required fields, invalid layouts, unknown step IDs, and duplicate step IDs yield `structural_error`. These are intentionally distinct from the five benchmark provenance families.

Provenance validators produce:

- `missing_required_step`
- `wrong_order`
- `unauthorized_signer`
- `invalid_signature`
- `unexpected_product`
- `unexpected_product_hash`
- `material_product_mismatch`

Signer authorization and cryptographic validity are separate: a valid signature from an unapproved key is still unauthorized, while a corrupted signature from an approved signer is `invalid_signature`.

## Strict cryptographic behavior

Signature verification uses the canonical payload of `step_id`, sorted materials, and sorted products. Every signature with supplied public material is verified. A failure is emitted as `invalid_signature`; failures are never globally suppressed because they are widespread.

The implementation uses Ed25519 through `cryptography` when available and retains the documented deterministic HMAC development fallback for environments that cannot import Ed25519 raw keys.

## Provenance-aware localization

Every `EvidenceItem` is either direct or propagated. A product/material continuity failure is recorded on the observed downstream step and carries its upstream producer in `propagated_from`.

`GraphRanker` gives full weight to direct observations, a reduced weight to the downstream symptom, and bounded support to the upstream producer. This keeps a mutated producer ahead of later chain noise. Adjacent-order evidence uses a small forward-displacement tie-breaker to match the benchmark convention.

`StaticRanker` implements the simpler weighted baseline. `CounterfactualRepairRanker` ranks the one-step repair that removes the most weighted evidence. `ConstraintRanker` uses a minimal-inconsistent-set approximation: direct findings belong to their record, order findings to both endpoints, and propagated findings to their named producer. All satisfy the `Ranker` protocol and can be passed to `CY03Verifier(ranker=...)`, making controlled MRR comparisons possible without touching parsing or validation.

`LearnedRanker` is a dependency-free, deterministic pairwise linear ranker. It only learns when `fit()` receives explicitly labelled local `RankerTrainingExample` values; it never reads evaluator labels or trains implicitly during verification. Its label-independent features are direct evidence strength/count, upstream and downstream propagation strength, and forward order displacement. An untrained instance uses interpretable graph-baseline weights.

`metrics.mean_reciprocal_rank()` measures MRR over `(ranked_steps, expected_step)` pairs. The stress harness feeds it only mutated cases, so clean cases do not dilute localization MRR; the test output prints the exact measured value and the number of scored cases.

The material-chain validator follows canonical predecessor links rather than serialized record order. Consequently, an adjacent order swap is not misinterpreted as a product-flow defect. On the checked-in 156-case **local labelled** comparison, `StaticRanker` measured **0.910 MRR**; `GraphRanker`, `CounterfactualRepairRanker`, and `ConstraintRanker` each measured **1.000 MRR**. `LearnedRanker` measured **1.000 MRR** on a disjoint 78-case local holdout after training on the other 78 cases. All strategies retained 100% detection and primary-violation accuracy on their scored sets. The broader 780-mutated-case local stress matrix also measures 1.000 MRR for `GraphRanker`.

These are regression results for synthetic, locally labelled cases—not a prediction of hidden-evaluator performance. The hidden evaluator supplies its own layouts, provenance records, public material, and unknown fault labels; its detection, clean-case, and localization scores must be measured independently.

Primary-violation selection is deterministic. Structural errors and direct benchmark violations outrank a signature failure caused by the same content mutation; a lone invalid signature remains the primary finding.

## Complexity

For `n` step records and at most `m` artifacts per record, parsing and checks are `O(n * m log m)` because canonical payload construction sorts artifacts. Ranking is `O(n log n)`. The CY-03 chain has eight steps, so the practical runtime is dominated by signature verification.

## Test strategy

The suite retains the full mutation matrix and adds an independent reference oracle. It owns its policy, canonicalization, key derivation, and signing path; it uses Ed25519 directly when `cryptography` is available and an independently implemented documented HMAC development fallback otherwise. Isolated mutations re-sign altered records so content, signer authorization, and signature validity can be tested separately. Adversarial clean cases cover multiple and reordered artifacts, repeated names across steps with distinct hashes, optional metadata, alternate authorized signers, and explicit empty-output policies. The production verifier has no dependency on the synthetic generator or test oracle.
