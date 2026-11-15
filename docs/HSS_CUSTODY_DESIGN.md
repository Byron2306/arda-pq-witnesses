# Cloudflare HSS custody candidate

Retain all three fixed schemes and current public registrations. Add a narrow HSS Wasm engine from the pinned vendor, a signer-side external leaf-burn gate, and a separate enrollment-only Durable Object worker. Do not enable production.

Before every signature, create a unique GitHub ref for (public-key SHA256, leaf index), pointing to an annotated tag that commits to exact message bytes/hash and a fresh attempt nonce. Never update/delete refs, never sign on existing-ref or uncertain response, and never trust locally cached authorization receipts. Fresh repository rules must enforce tag update/deletion protection with no bypass actors. Use a dedicated anchor repository and read/write-contents credential without rules administration.

Store the updated private state durably before releasing a signature. Rollback to an already burned leaf quarantines that key; there is no automatic skip, state reset, counter override or reuse. After a crash between burn and durable update, operator-reviewed key rotation is required. Stateless registrations can be retained/reviewed separately; changing HSS key requires a new all-three pinned enrollment policy. Missing-anchor-service means refusal.

This prevents honest signer software from reusing a leaf after Cloudflare database rollback/clone, assuming protected GitHub refs and honest fresh HTTPS replies. It does not withstand private-key theft, modified signer code, rollback of both independent services or malicious independent anchor administration. GitHub provides an external state dependency, not another review vote. A GitHub outage prevents signing.

Worker initially exposes only authenticated enrollment with pinned ceremony/image identity; no release-vote or arbitrary signing endpoint. Generating its registration consumes leaf zero. Existing R13 worker is separate and unchanged. Worker readiness/cost/CPU budget must be accepted before real key generation. No paid plan change or live deployment is authorized implicitly by these sources.

Validation covers Wasm signature interoperability against native upstream verification, bounded RNG and memory, cloned/rolled-back storage, competing instances, uncertain external writes, failed durable sync, expiry, exhaustion, rules weakening, and no key generation at ordinary startup. Fake GitHub/DO tests are explicit simulations. Actual provider protection and Workers runtime acceptance remain separate.
