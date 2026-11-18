# Cloudflare HSS custody v5 candidate

This is an enrollment/custody candidate, not a production release signer. It does not modify the R13 Worker, existing HF/GitHub keys, D14 deployment payload, BPF maps or production consumer. No live Cloudflare HSS key has been created by development or tests. Test keys are disposable and never enrolled.

## Implemented boundary

The fixed profile remains one-level HSS, LMS SHA256 N32 H10, LMOTS SHA256 N32 W8. Public keys are 60 bytes, signatures 1456 bytes and the pinned vendor's SECRET_METHOD=2 private serialization is 64 bytes. Leaf counters are read in the vendor's fixed big-endian format; this adapter never overwrites or resets a counter. All 1024 leaves include the registration proof, so a successful registration at q=0 leaves 1023 subsequent leaves.

The unmodified Cisco reference tree is verified against vendor/UPSTREAM.json before each build. Wasm compilation uses Zig 0.14.1 and the pinned Linux amd64 wheel hash. Only the build copy of sha256.h changes USE_OPENSSL from 1 to 0 to enable upstream's portable SHA256. The native verifier stays on OpenSSL and independently checks the Wasm signatures. Build metadata records the Wasm and wrapper hashes. This is not an independent cryptographic audit or a FIPS validation.

Before each signature the guard checks key/public/configuration binding, time and exhaustion. It reads the current GitHub tag rules, requires active update/deletion protection with no bypass, creates an annotated tag containing SHA256 commitments to the exact message/context plus a fresh attempt nonce, then creates the fixed ref `refs/tags/arda-hss-leaf-<key-sha256>-<four-digit-leaf>`. Only an exact 201 create response can authorize the primitive call. No existing-marker success, cached authorization, HTTP redirect, automatic retry, update or delete operation exists in the signer adapter. The GitHub anchor is an online external state dependency, not another PQ vote or a post-quantum transparency proof.

After native/Wasm signing verifies its own public key and q, the guard durably stores and synchronizes advanced private state before releasing signature bytes. A lost anchor response, existing marker, uncertain storage or late expiry returns no signature and quarantines the key after any attempted external reservation. A restored database pointing at a burned leaf cannot sign it again. There is intentionally no auto-skip, counter override or reset route. A quarantined key needs operator-reviewed rotation and a new pinned policy; do not remove its marker tags.

Threat assumptions: this protects honest, unchanged signer code against Cloudflare database rollback/crash/cloning while the separate GitHub anchor remains protected and HTTPS replies are fresh/honest. It does not protect stolen private keys, modified signer code, compromised CSPRNG, or combined rollback/removal of the independent anchor. The GitHub administrator can still destroy the repository/rules; the CF contents token must not have rules/repository administration. Multiple schemes/platforms do not imply independent human operators. Honest GitHub outages stop signing.

## Deployment shape and costs

The new dedicated Worker is `arda-pq-release-witness`, with SQLite Durable Object `HssEnrollmentObject`. The outer Worker authenticates POSTs before forwarding to the fixed object name. All expensive HSS computation runs inside the Durable Object, not the normal Worker entry point. Cloudflare currently documents SQLite Durable Objects on Free and Paid plans and a default 30-second DO CPU allowance; actual account limits and hosted execution must be checked. No script in this candidate upgrades a plan or enables billing.

Sources: https://developers.cloudflare.com/durable-objects/platform/limits/ and https://developers.cloudflare.com/durable-objects/platform/pricing/ . Normal Worker CPU limits differ; do not infer the DO budget from the normal Worker table. Node test wall times are not Cloudflare CPU acceptance measurements.

The service has only:

- GET /healthz: public enrollment-only status; no key generation.
- Authenticated POST /v1/self-test: a fresh disposable HSS key signs a fixed self-test message, returns public proof only, and writes no durable key or anchor marker. This is the first hosted acceptance step.
- Authenticated POST /v1/enroll-cf: the explicit operator ceremony; creates and retains an HSS key inside the DO, burns q=0 externally, returns its standard signed public registration, and caches that public record. Repeating against a completed record returns the cache without another signature. A lost record after counter advance refuses further generation/signing.

There is no arbitrary-message, key export, reset, raw-state upload, or release-vote route. The guarded primitive is internal code; a validated R13/proposal release-vote adapter remains separate unfinished work.

## Keep the accepted v4 stateless witnesses

The existing ceremony's image_digest continues to refer to the accepted v4 GitHub/HF image, not a Cloudflare OCI image. Cloudflare runs a separately built Wasm module pinned in the CF configuration and generated bundle manifest. These configuration comparisons are not independent remote code attestation. Do not change the already accepted HF/GitHub image to v5 merely to use the v5 build/client utilities. Existing registration proofs and stage inputs remain unchanged. If the ceremony expires, do not extend its timestamps or fabricate a fresh proof; arrange an independently reviewed re-registration ceremony while preserving the provider-held keys.

## 1. Build and export

Build the root Dockerfile on the operator Lenovo using the retained, reviewed BASE_IMAGE and NODE_IMAGE digests. The build installs compiler-only dependencies in a private venv and runs the complete verification runner, including real Wasm/native/Python interoperability tests. A build can access package repositories but no provider signing credentials are needed.

Use `tools/export_cf_bundle.py --out /output/arda-cf-hss-v5.tar.gz` inside that tested image with only an operator output directory mounted at /output. The whitelist includes Worker source, dependency lock, compiled Wasm, build metadata and a manifest; it never includes .dev.vars, provider tokens, enrollment private state, key files or broad working directories. Extract the bundle and run `npm ci` in providers/cloudflare. Pinned Wrangler is 4.162.0. `wrangler deploy --dry-run` bundles without deploying. No live deploy runs automatically.

## 2. Dedicated external anchor (before real key enrollment)

Create a public `Byron2306/arda-hss-leaf-anchor` repository with an initial README commit. Use this dedicated repository rather than granting CF write access to the existing GitHub witness source. Record the actual genesis commit SHA.

Create a tag ruleset with enforcement Active, exact target `refs/tags/arda-hss-leaf-*`, no exclusions and no bypass actors. Enable Restrict updates and Restrict deletions. Do not restrict creation: CF must be able to create the first marker, and never change it. Read the actual ruleset API JSON and its ID; do not handwrite a receipt. GitHub public-repository rulesets are available on Free plans according to its current docs: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository .

The standalone stdlib client `tools/probe_hss_anchor.py --out anchor-probe.json`, with ARDA_CF_ANCHOR_TOKEN supplied only through the environment, tests the actual repository, pinned genesis and ruleset 27318098. It races two creates for a new synthetic tag, then attempts forced update/deletion on that probe only; no real HSS key exists for its domain-separated synthetic fingerprint. Only rule-specific refusals, unchanged readback and stable rules count as acceptance. The probe leaves one intentionally protected public marker. Never supply or reuse a real HSS fingerprint.

Actual create-race, forced-update and delete refusal must be tested using disposable probe markers and the same actor permissions before real HSS enrollment. A rules JSON declaration is not proof of enforcement. This acceptance has not happened here because the dedicated repository and its credential are not configured. Never probe using a real HSS leaf. Keep the immutable probe records as public acceptance evidence; do not weaken the rules to delete them.

Create a short-lived fine-grained CF anchor token restricted to that repository with Contents read/write only. It must have no Administration/rules bypass capability and must never be the GitHub witness setup token. Store it only as Cloudflare secret ARDA_CF_ANCHOR_TOKEN. All operations are fixed to this repository; it cannot write the witness source repository.

## 3. Public configuration and independent setup credential

After reviewing actual rules JSON, use `tools/prepare_cf_config.py --ceremony ceremony.json --ceremony-sha256 REVIEWED_PIN --ruleset-json actual-ruleset.json --genesis-commit ACTUAL_SHA --out-dir cf-configuration`. It requires the built Wasm metadata, active exact-scope rules with no bypass, current fixed provider identities and unexpired original ceremony. It prints CF_CONFIG_SHA256 and writes cf-config.json and public variables.

Supply ARDA_CF_CONFIG_JSON as its exact canonical one-line JSON and ARDA_CF_CONFIG_SHA256 as its reviewed raw SHA. The configuration includes actual anchor repository/rules pins and independent Wasm SHA. For convenience JSON can be supplied using Wrangler secret input even though it is public; preserve exact bytes and keep tokens separate.

Create a distinct random 64-lowercase-hex operator client credential on the operator machine and store it as ARDA_CF_SETUP_CLIENT_TOKEN in Cloudflare secret settings. This is not a provider signing key and may also be held by the operator client. Never reuse the HF setup credential or anchor write token. No value is bundled, and no token should be pasted into chat or shell command arguments.

## 4. Explicit hosted acceptance then enrollment

Deploy only this dedicated Worker, never the R13 Worker. First use tools/enroll_cf_remote.py --mode self-test with --url, --config, --config-sha256 and --out, supplying only ARDA_CF_SETUP_CLIENT_TOKEN through the environment. The client restricts the HTTPS origin to this Worker's workers.dev name, disables redirects/proxies/retries, and independently verifies the fixed-message disposable HSS proof against the native verifier. Confirm Cloudflare runtime/CPU/storage acceptance and actual tag-protection acceptance before proceeding.

Only after those checks, invoke the same client with --mode enroll explicitly. That generates the retained key in Cloudflare, reserves q=0 externally and returns a public registration whose exact ceremony/identity/signature is independently verified. No actual provider key leaves Cloudflare. The response may be lost after remote key storage/burn: stop and inspect state; never blindly retry or restore/reset the counter. A completed public record can be fetched again without signing; uncertain interrupted state requires review/rotation.

Review the public key and registration hashes independently, then add the third record to the all-three policy finalizer. The finalizer still sets production_authorized=false and KEEP_CLOSED. Registration is not a live release vote, R13 evidence, Rekor inclusion, SERAPH challenge, dispatch permit or kernel authority. Keep the setup service paused/disabled after public registration acceptance until a separate reviewed release-vote adapter is ready. Retain the anchor credential only for that future guarded signer; removing it prevents future signatures.

## Acceptance status at publication

Local Node tests exercise real HSS Wasm signatures and native/Python public proof verification, plus explicit simulated GitHub/storage fault and concurrency cases. Wrangler dry-run bundling passed. Local workerd disposable self-test passed, and its returned HSS proof was independently verified by the native verifier (about 7.3 seconds local elapsed wall time, not a hosted CPU measurement). Explicit listen/inspector addresses were needed to avoid this environment's interface-discovery restriction. The local test did not mutate a GitHub anchor or enroll a real key. Actual protected-tag enforcement and hosted Cloudflare acceptance remain required. No production cutover, remote HSS key generation, live vote, Rekor publication, plan change or billing change was performed.
