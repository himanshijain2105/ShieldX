# CY-03 Threat Model and Limits

## Security boundary

The verifier treats every case record as untrusted data. It only parses JSON and validates deterministic evidence; it does not execute artifacts, invoke commands from metadata, or import modules named by an attestation.

## Covered attacks

| Attack | Detection |
| --- | --- |
| Remove a required build step | `missing_required_step` |
| Swap adjacent build steps | `wrong_order` with deterministic forward-step ranking |
| Use an unapproved signing identity | `unauthorized_signer` |
| Corrupt an approved signer's envelope | `invalid_signature` |
| Substitute or rename a product | `unexpected_product` when product policy is supplied |
| Alter an authoritative product digest | `unexpected_product_hash` when hash policy is supplied |
| Break product-to-material continuity | `material_product_mismatch`, treated as downstream evidence |
| Supply duplicate, unknown, or malformed records | `structural_error` |

## Verification rules

Authorization, product identity, and expected hashes are evaluated only from supplied evaluator layout constraints. Missing policy does not activate the project's development defaults. The canonical eight-step chain remains benchmark-defined.

Signature and authoritative hash failures are never suppressed. A large number of failures may indicate a producer/verifier compatibility problem, but it is still verification evidence and is reported to the caller rather than silently discarded.

## Localization model

An upstream product mutation may cause material discontinuities farther along the chain. The verifier distinguishes direct evidence from propagated evidence; the graph ranker reduces the score of downstream symptoms and gives bounded support to the upstream producer. This is designed for the benchmark's single-primary-mutation assumption, not for forensic certainty in an arbitrary multi-incident system.

## Assumptions and limitations

- The input layout and public verification material arrive from a trusted channel. A malicious replacement policy can redefine what the verifier accepts.
- The verifier validates the defined eight-step boundary only; it does not recursively attest third-party dependencies or build environments.
- It does not validate timestamps, key revocation, certificate chains, transparency logs, or replay freshness.
- The HMAC path is a deterministic development compatibility mechanism, not a replacement for Ed25519 in production-grade systems.
- An unknown signature canonicalization produces `invalid_signature`; compatibility encodings must be explicitly added and tested rather than inferred silently.
