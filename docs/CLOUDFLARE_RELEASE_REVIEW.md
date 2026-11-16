# Cloudflare release-review candidate

This adapter adds bounded `POST /v1/review-vote` to the existing Worker and Durable Object. It retains `HssEnrollmentObject`, namespace/object identity, enrolled key, registration cache and external immutable leaf markers. Success produces a normal v1 CF HSS vote and remains production_authorized=false / KEEP_CLOSED.

## Configuration and credentials

`tools/prepare_cf_review.py` runs offline in the accepted witness image, using its reviewed generation-14 staging request and pinned public R13 material. Inputs are the independently reviewed enrollment policy and pinned CF enrollment configuration. It checks manifest validity, native policy shape, stage digest and verifier/AK/PCR pins. It emits public-only files under a unique `cf-review-config.*` directory. No credential is read or created.

Apply `cf-review-variables.json` only after source review. It includes explicit `ARDA_CF_RELEASE_ENABLED=true`, `ARDA_CF_RELEASE_CONFIG_JSON`, its SHA256 pin, and separately `ARDA_CF_ENROLLMENT_JSON`. Each value fits the documented 5KB Worker binding limit. The config pins the policy digest, approved staging bindings and manifest validity, complete public R13 verification inputs, Wasm and anchor. It remains usable after the earlier enrollment ceremony expires, while the approved policy/manifest windows remain valid.

Create a distinct random 64-lowercase-hex review-client credential, store its file privately and set `ARDA_CF_REVIEW_CLIENT_TOKEN` as a Worker secret. This is a client credential, not a signing private key or HF account token. Keep `ARDA_CF_ANCHOR_TOKEN` in place. Setup/enrollment operations retain their existing separate credential. No private key crosses providers.

The reviewed installer modifies public source and its bundle manifest only. It verifies the exact prior/current source pins, immutable Wasm/build metadata, Wrangler configuration and dependency lock. It backs up changed public files before atomic replacements. It neither deploys, edits secrets, touches the key/counter, resets storage nor changes a Durable Object migration. Its source upgrade is replayable; unexpected source, symlinks or modified Wasm are refused before any patch.

## Requests and acceptance

Public `/healthz` reports `release_review_only` after release activation; authenticated `GET /v1/review-status` additionally uses `X-ARDA-Review-Token`. Both are read-only. The existing enrollment status route remains available separately.

A review request has exactly `{schema,proposal,capture}` using schema `arda.pq.witness_request.v1`. Supply canonical Python-compatible JSON with the same approved proposal/full R13 capture used by GitHub and HF. Send application/json and the distinct review credential as `X-ARDA-Review-Token` over HTTPS. The capture is at most120 seconds old, and the proposal/vote cannot outlive its R13 receipt, enrollment or approved staging manifest. Prepare all providers before collecting that short-lived capture; do not extend timestamps to conceal queue/startup delay.

Cloudflare independently verifies pinned Ed25519 challenge and receipt signatures, the raw RSA TPM quote/qualification/selection/PCR digest, approved PCR baseline, exact node/boot and evidence digests. It validates policy, generation, manifest, deployment, artifact root, staging request, machine identity, nonce and proposal ID. Caller-supplied PASS flags, keys, policies, times and arbitrary message bytes are rejected.

Only an accepted request reaches the existing guarded HSS primitive. It burns the immutable external marker before signing, atomically stores advanced key + public vote + nonce index, synchronizes, reads the committed vote, rechecks the original configuration pin and monotonic clock after all awaits, then releases the public vote. Configuration inputs are captured before reading the request body; health metadata is also checked against that exact snapshot. Retrieval of an exact cached vote requires a still-live validated request and matching policy/config/key/nonce; it consumes no new leaf. Reusing a nonce for a different proposal is refused. Uncertainty quarantines the key. Never delete a burn marker, restore a signing counter or re-enroll as a retry shortcut.

## Operator sequence

1. Install the immutable reviewed public patch into the existing CF bundle, preserving Wasm and namespace.
2. Run the public preparer inside the pinned witness image with the reviewed policy SHA256 and existing CF config pin; inspect the public output.
3. Set the distinct review-client secret; apply the public bindings; run Wrangler dry-run and deploy the reviewed source to the same Worker. Check read-only review health and exact policy/key/config hashes.
4. After GH/HF review runtimes are ready, capture fresh R13 evidence, request all three votes and verify their signatures plus all proposal/evidence bindings independently.

Applying bindings/deploying this adapter enables review voting only. Rekor verification and actual ARDA production admission/one-time mutation remain separate implementation and acceptance work.

## Disposable tests

The ordinary suite includes independent real-crypto R13/proposal tampering and real Wasm HSS service tests. `node tools/test_cf_review_runtime.mjs` uses real workerd SQLite, the real Worker entry point and real Wasm with mocked GitHub traffic: q0 enrollment, configuration reload retaining the same key, invalid request refusal, q1 release vote verified by native Python HSS backend, a complete three-algorithm certificate joined with disposable GitHub/HF signatures and independently verified with raw R13 evidence, and cache replay holding q2. The same runtime test can be run against the installer-upgraded original public bundle to exercise its exact accepted Wasm. `node tools/test_cf_storage_runtime.mjs` retains earlier enrollment/orphan/replacement acceptance. No live provider or production key is used. Installer smoke tests additionally use the original accepted public CF bundle when available; its Wasm is preserved exactly.
