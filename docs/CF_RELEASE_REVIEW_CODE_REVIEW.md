# CF release-review independent code review and fix record

One fresh independent read-only whole-change review requested changes for two Important findings and found no Critical or Minor findings. Both findings were reproduced with disposable real Wasm before correction.

1. The initial config pin was captured after asynchronous body/R13 validation. A correctly pinned new config could therefore be associated with an old approved proposal. Fixed by capturing approval inputs/pin before awaits and enforcing the exact original pin before signing and release. Regression: `a valid config change during body reading cannot sign the previous approved manifest` (RED→GREEN, zero burns on refusal). Read-only health now uses the same snapshot discipline; its regression also observed RED→GREEN.
2. A final durable cache read occurred after expiry/config checks. Fixed by reading the committed vote before the last checks, with no awaited operation after them. Regressions: final-read expiry/config changes and within-lease clock rollback (RED→GREEN). One request-scoped monotonic clock now covers config, key, marker, signature and response phases.

Final full suite270 PASS. Real disposable workerd/SQLite tests pass against the exact accepted8e716... Wasm, including actual enrollment, same-key config reload, HSS release vote, cache replay and a complete native-verified three-algorithm R13-bound certificate. Original enrollment/orphan replacement acceptance remains green. Exact public-bundle installation/reapplication and Wrangler dry-run pass. See CF_RELEASE_REVIEW_ACCEPTANCE.json for exact hashes.

Declined-to-judge items remain explicit: live Cloudflare deployment/permissions/bindings/namespace/custody; live GitHub ruleset enforcement/availability; live provider voting, Rekor and actual ARDA production admission. These were not performed or claimed by development tests. No second review cycle or live signing was used to claim that the fixes passed.
