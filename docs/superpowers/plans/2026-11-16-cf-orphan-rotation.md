# Controlled orphan replacement implementation plan

> **For agentic workers:** implement natively; use executing-plans to execute task by task and requesting-code-review for the complete candidate.

**Goal:** Replace only a pinned orphaned Cloudflare enrollment key while preserving its original state and marker.
**Architecture:** Read-only protected-anchor verification, authenticated compare-and-replace operation in the existing DO, single atomic retirement/new-key/receipt write, curl-based host transport and offline native verification.
**Tech Stack:** JavaScript Workers/workerd, SQLite DO storage, existing Wasm, Python stdlib, curl, accepted Docker verifier.
**Spec:** docs/superpowers/specs/2026-11-16-cf-orphan-rotation-design.md

## Global constraints
- Never reset a serialized counter, sign from retirement storage, export a private key, or remove a marker.
- No rotation of completed/quarantined/changed keys. No implicit signing during replacement.
- Same HSS_SIGNER binding, HssEnrollmentObject, object name and namespace. Production false / KEEP_CLOSED.
- Original ceremonies are immutable; expired mutation requests refuse.

## Review focus
- Interrupted commit and replay must not overwrite the retirement archive or create a second replacement.
- Old/public ceremony and anchor receipt must bind the complete registration message, not merely fingerprint.
- Authentication, wrong counter/pin, expiry and concurrent mutation must refuse before generation.
- Operator transport must not expose credentials, retry POSTs, or discard a returned public proof.
- Test real SQLite storage and native verification as well as targeted failure cases.

## Task 1: Anchor marker reads and atomic replacement
- [x] Add failing tests for valid marker reads, wrong ref/tag/message/protection and redirect refusal.
- [x] Implement fixed GET-only readBurn validation in cloudflare/hss-anchor.mjs.
- [x] Add failing tests for archived bytes/counter, replay, completed-key refusal, wrong fingerprint/counter/tag, unauthenticated/expired request and uncertain commit.
- [x] Implement cloudflare/hss-rotation.mjs and explicit authenticated route; leave normal enrollment rules unchanged.
- [x] Run node suites and real SQLite/Wasm integration check.

## Task 2: Operator client and release candidate
- [x] Test curl command/header construction, response retention, invalid pins/expiry and native verification failure preservation.
- [x] Implement tools/cf_operator.py; status, replace and enroll are separate operations. No network retries.
- [x] Update fixed public export allowlist and operator runbook. Provide a pinned patch installer for existing reviewed bundle; do not rebuild/change its Wasm.
- [x] Run complete verification, obtain independent review and publish candidate changes only.
- [ ] Give one explicit deployment/replacement step at a time; inspect public receipt before enrollment. Never claim live success without user output/native proof.
