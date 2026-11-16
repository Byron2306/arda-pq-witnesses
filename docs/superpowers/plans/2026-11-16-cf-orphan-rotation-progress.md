# SDD ledger — plan: docs/superpowers/plans/2026-11-16-cf-orphan-rotation.md

Ruling: implement natively in the existing isolated source export and synchronize through the GitHub candidate branch with CAS — this session has no local git checkout; do not manufacture a second divergent repository.
Pre-flight: Task 1 produces the explicit replacement route and public receipt; Task 2 binds that exact request/response and never retries a POST.
Ruling: the original ceremony expires 2026-11-16T02:58:38Z; add offline prepare to create a genuinely new nonce/window/config while preserving the old configuration. Old HF/GH proofs cannot be reused under the new ceremony; their private keys remain untouched and require fresh provider-local registration proofs later.
Task 1: anchor readBurn and replacement refusal/replay/archive tests RED→GREEN. Targeted Node suites 39 passed. Real storage fault fixture in progress.
Task 2: host curl client tests RED→GREEN (7 passed); fresh ceremony preparation added. Response body preserved before native verification. Verifier image pinned before enrollment network call.

Task 1: complete — Node rotation/anchor suites now pass, including expired-original/new-current ceremony, refusal gates, exact replay, lost commit acknowledgment and read-only receipt retrieval after expiry. Real workerd/SQLite legacy-gap fixture replaced and re-enrolled successfully; independent native replacement proof PASS. Zero live provider calls.
Task 2: complete pending final full-suite record — 13 operator tests, 3 installer tests, clean Wrangler dry-run, exact reviewed Lenovo bundle patch smoke PASS with unchanged Wasm8e.
Final: fixed inherited curl config/credential leak — first argument --disable plus scrubbed child environment; focused regression RED→GREEN.
Final: fixed expired public receipt availability — return exact typed/allowlisted receipt through existing authenticated status; regression RED→GREEN, expired POST still refuses.
Ruling: use read-only status rather than permit expired replacement POST replay — preserves strict mutation expiry; costs a different read operation for public receipt recovery.
Final: fixed incomplete receipt acceptance — exact field set, old/new ceremony/config/request/marker/time binding; incomplete self-hashed receipt regression RED→GREEN.
Final: fixed readiness/coverage gap — execute pinned native verifier before enroll POST; probe-failure regression RED→GREEN, main() tests prove no POST on preflight failure and response retention on post-response native failure.
Final: fixed HTTP/1 fallback success reporting — preserve response but refuse success; regression RED→GREEN.
Final: no deferred minor findings. No live deployment, key rotation or enrollment performed by this execution.

Final full verification: 221 tests PASS after all code/test changes. Real SQLite/workerd replacement, exact replay and new enrollment PASS; replacement signature verified natively. Public Wasm and source dry-run PASS; exact reviewed Lenovo bundle installer smoke PASS. Upstream OpenSSL deprecation warnings remain recorded in the normal verification report. No live provider changes.

Final installer review: no new Critical/Important findings; all 3 installer tests pass. Publish the existing candidate branch / draft PR only; no merge or live provider action.
