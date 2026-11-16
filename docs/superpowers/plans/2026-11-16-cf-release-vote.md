# CF release-vote implementation plan

> Execute with superpowers:executing-plans inline; one fresh final review.

Goal: safely issue ordinary CF release-review votes using the enrolled HSS key.
Architecture: WebCrypto R13/proposal validator, in-place DO dispatcher, externally guarded HSS signing with atomic public cache.
Tech: ES modules, Workers WebCrypto/SQLite, existing HSS Wasm, Python native verification/preparation.
Spec: docs/superpowers/specs/2026-11-16-cf-release-vote-design.md

Global constraints: same Durable Object/key and external anchor; no network/real keys during tests; no live deployment or production authorization; exact policy/stage/R13/config pins and closed results.

Review focus: numeric PCR key canonicalization; valid receipt hiding an invalid quote; changed configuration or expiry across awaits; enrollment/review concurrency; key rollback or lost marker/signature response causing leaf reuse.

## Task 1: independent validation
Files: cloudflare/review-protocol.mjs, cloudflare/r13-capture.mjs, cloudflare/release-config.mjs and focused Node tests.
Interfaces: canonicalProtocol(value), validateReleaseConfig(env,wasmSha,now), validateReview(config,request,now) -> fixed vote payload plus proposal hash/window.
- [x] Add real-crypto fixtures/tests, run RED.
- [x] Implement exact Python-compatible protocol, fixed configuration and proposal validation; run GREEN and tamper matrix.

## Task 2: HSS service and runtime
Files: cloudflare/hss-guard.mjs, cloudflare/release-service.mjs, providers/cloudflare/worker.mjs, tests and real SQLite runtime acceptance.
Interfaces: GuardedHssSigner optional votePayload with atomic cache; CloudflareWitnessService shared POST gate, review route and enrollment fallback.
- [x] Add RED tests for atomic vote cache, replay, expiry, quarantine, invalid requests without burns and concurrent operations.
- [x] Implement, verify GREEN and independently native-verify real disposable HSS votes.
- [x] Exercise same Worker entry point in disposable workerd with SQLite/Wasm and mocked external anchor; no live network.

## Task 3: reviewable delivery
Files: tools/prepare_cf_review.py, tools/install_cf_review.py, deployment/runbook/acceptance metadata.
- [x] Add RED preparation/pin/install tests; implement minimal public tools; verify GREEN.
- [x] Full run_verification.py, real runtime acceptance, Wrangler dry-run, fresh whole-change review.
- [x] Fix Important/Critical findings with regression RED→GREEN and full suite; publish immutable candidate and operator commands without deploying.
