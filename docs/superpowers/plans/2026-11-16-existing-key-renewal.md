# Existing-key renewal implementation plan

> Execute inline, with a fresh whole-change review before publication.

Goal: produce fresh public GitHub/HF registration proofs with their existing provider-held keys.
Architecture: a fingerprint-pinned overlay on the immutable v4 image; offline GH command and authenticated HF server.
Spec: docs/superpowers/specs/2026-11-16-existing-key-renewal-design.md

Global constraints: never generate/export replacement private keys, write provider secrets, touch Cloudflare, or authorize production. Runtime identity, image, ceremony and expected key must all match. No private data in logs or artifacts.

Review focus: wrong unique secret selected; expired ceremony after signing; old provisioning accidentally invoked; workflow source differs from approved commit; HTTP auth/body ambiguity or cached response after expiry.

## Task 1: renewal overlay
- [ ] Write real-crypto tests for same-key renewal, changed ceremony, missing/wrong keys, identity/image/pin/window refusal, no provisioning, authenticated HTTP/replay/expiry.
- [ ] Run red; implement tools/renew_existing.py; run green.
- [ ] Add a protected GH renewal workflow template and pinned HF Docker overlay; provide reproducible operator commands without changing live state.
- [ ] Run full project verification and separate review. Publish candidate source with CAS and report the next operator step.
