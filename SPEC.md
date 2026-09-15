# CY-03 Specification & Contract

- **8-Step Canonical Build Sequence**: `fetch` -> `deps` -> `compile` -> `test` -> `package` -> `scan` -> `sign` -> `publish`
- **Authorized Functionaries**:
  - `fetch`: alice
  - `deps`: alice
  - `compile`: bob
  - `test`: bob
  - `package`: carol
  - `scan`: carol
  - `sign`: dave
  - `publish`: dave
- **Five Failure Families**:
  1. `missing_required_step` (Severity: 100)
  2. `unauthorized_signer` (Severity: 90)
  3. `unexpected_product` (Severity: 85)
  4. `unexpected_product_hash` (Severity: 80)
  5. `wrong_order` (Severity: 70)
- **Artifact Hash Formula**: `SHA256("artifact:20260911:<case>:<step>")`
- **Key Derivation**: `SHA256("key:20260911:<signer_id>")` → Ed25519 seed
- **Signature Payload**: Canonical JSON of `{materials, products, step_id}` (signer excluded per in-toto conventions)
- **Single Mutation Invariant**: Each evaluation case contains at most one primary mutation

## Input Schema

Each case is a JSON object with required `case_id`, `steps`, and `public_verification_material.public_keys`; optional `metadata` and `layout` objects are allowed. A step contains only `step_id`, `signer_id`, `signature`, `materials`, and `products`. Each artifact contains only `name` and `hash`. The layout accepts only `canonical_steps`, `authorized_signers`, `expected_products`, and `expected_product_hashes`.

The canonical sequence is fixed. Policy is per step: a missing field or missing step key is **unsupplied** and is not enforced. An explicit `expected_products[step] = []` or `expected_product_hashes[step] = {}` is **supplied** and requires no products at that step. A non-empty hash mapping requires an exact product-name/hash match, including product presence.
