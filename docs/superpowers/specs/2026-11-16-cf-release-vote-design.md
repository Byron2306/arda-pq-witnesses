# Cloudflare release-vote adapter

Authorization: Byron said go after the explicit next task was the release-vote adapter using the enrolled HSS key. Implementation choices are delegated; proceed inline. This is bounded review voting, with no production execution authority or interlock release.

## Approach

Extend the existing Durable Object in place. Keep its namespace, class, object name, enrolled key, registration cache and leaf markers. Add an independently pinned release configuration and distinct review-client token. Alternative separate signer/key is rejected: it discards the completed enrollment. Signing arbitrary bytes from a caller is rejected: Cloudflare independently appraises the same exact proposal and R13 material as the stateless providers.

Configuration pins the complete closed enrollment policy, approved staging bindings, R13 verifier/AK SPKIs, PCR policy and identities, external anchor and Wasm. A public preparation tool verifies the policy/archive pins and existing generation-14 stage/public-R13 files before generating it. The request contains only schema, proposal and full raw R13 capture. No caller PASS object or alternate policy/key/time/path is accepted. New protocol JSON serialization must match Python even for PCR numeric-looking string keys; leave legacy enrollment serialization untouched.

Use Workers WebCrypto for pinned Ed25519 challenge/receipt and RSA PKCS1v15 SHA256 raw TPM quote verification. Port the existing pinned protocol with source attribution; preserve frozen R13 source. Bound the challenge to 120 seconds and the proposal/vote to its capture and enrollment window. Require exact proposed generation, artifact root, manifest, machine and boot bindings from approved configuration. Return an ordinary v1 CF HSS vote compatible with the existing native consumer.

A shared dispatcher serializes all POST operations across enrollment and review. Invalid requests consume no leaf. The existing external immutable GitHub leaf marker remains authoritative across storage rollback. Extend GuardedHssSigner to bind an internally supplied vote payload to its domain-separated message and atomically commit the public cached vote and advanced key; synchronize before release. Cache by proposal hash, check policy/key/proposal/capture/window on replay and withhold if the key is quarantined. A lost external-marker response, signing/durability uncertainty, expiry or rollback never releases an unsafe signature. Do not add retry, reset, restore or recovery-to-ACTIVE shortcuts.

GET release health is read-only and discloses public hashes/state only. POST /v1/review-vote authenticates before body/config parsing, accepts bounded canonical JSON only and returns sanitized errors. Successful votes remain production_authorized=false / KEEP_CLOSED. Disabled/missing release configuration leaves existing enrollment routes working.

## Acceptance

Real cryptographic challenge/quote/receipt tamper tests, proposal/config/key substitution and expiry tests before leaf burn, HSS vote native verification, atomic cache/restart/replay/concurrency/lost-response/rollback tests, real disposable workerd SQLite + Wasm acceptance and Wrangler dry-run. Full existing suite green. Fresh independent review before candidate publication. No live CF deployment/signing or key mutation during development; hand over an immutable install/config/deploy candidate after tests.
