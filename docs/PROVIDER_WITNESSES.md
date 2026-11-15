# GitHub and HF witness candidate

Version 3 implements both stateless signing paths and packages deployment templates. No GitHub workflow has been enabled or dispatched, no HF Space created, no provider secret provisioned, and no production key generated/enrolled. Docker is unavailable in the build environment; the Docker recipes and workflow have static checks but no image build or hosted acceptance result. Cloudflare HSS signing and Rekor verification remain open.

## What the witnesses actually check

Both fixed-provider entry points require an operator-pinned full enrollment policy, exact reviewed staging request, enrolled verifier/AK public keys, matching PCR-policy commitment, a fresh signed R13 challenge, independently verified raw TPM quote and receipt, and exact proposal bindings. Requests contain only schema, proposal and capture. They cannot set provider, key, algorithm, trusted time, lease length, source paths or an execution action. The only action is `review_staged_release`.

The GitHub entry point additionally checks the 26 changed Python source files copied from the reviewed candidate against `REVIEWED_SOURCE_FILES.json` and the actual staged-artifact hashes. This is bounded source-hash verification, not a reproducible BPF build, a complete dependency-closure proof or evidence of host execution. The source manifest is itself pinned in operator configuration.

The HF entry point independently checks the stage/policy/evidence bindings and emits only SLH-DSA-SHA2-192s votes. It does not use an LLM as a final release authority.

Each entry point derives the public key from its provider-held private PKCS8 key and requires byte-for-byte agreement with the enrolled public key and fixed parameter set. ML-DSA-65 belongs to GitHub; SLH-DSA-SHA2-192s belongs to HF. OpenSSL signs and then verifies the generated signature before release. The clock is checked again after signing; an expired vote or backward clock observation returns no vote. Secrets never come from the request or output artifacts.

These are stateless signature schemes. Repeating an approved request can produce another valid vote within its original validity window. This does not consume a new execution right: the complete quorum consumer must still use its durable nonce/review-intent ledger. Provider ephemeral storage is not claimed as an authoritative replay ledger.

## HF HTTP candidate

`tools/serve_hf.py` starts only after complete operator configuration, all-three public-key enrollment and a matching HF private-key secret are present. There is no key generation, enrollment or file-upload route. Public health exposes only provider, algorithm and public-key digest.

POST `/v1/review-vote` requires a distinct 256-bit bearer credential, authenticated before body parsing, canonical JSON, a single bounded Content-Length and application/json. Bodies over 64 KiB, duplicate JSON keys, conflicting Content-Length, content/transfer encodings, unknown fields and unknown routes are refused. Every response closes the connection. Socket timeouts and a bounded thread pool limit concurrent resource use. Requests, credentials, keys, bodies and OpenSSL error text are not logged.

Successful responses wrap an ordinary v1 vote with `production_authorized: false` and KEEP_CLOSED. The client extracts the vote for complete quorum verification; HTTP 200 is not release admission. This is a locally tested candidate HTTP adapter, not completed hosted/production security acceptance. Hosting must terminate HTTPS; do not send bearer credentials over public plaintext HTTP.

## Configuration and custody

The raw provider configuration must hash to the operator-supplied `ARDA_PROVIDER_CONFIG_SHA256`. It pins the raw enrollment-file digest, exact stage-request digest, reviewed source-manifest digest, image digest and runtime identity. Missing placeholders fail closed. Draft templates are intentionally not valid runtime configurations.

GitHub reads public `operator-config/github.json` and `operator-config/enrollment.json` from the approved checkout. It requires the configured repository, exact workflow reference, commit SHA and GITHUB_ACTIONS=true. These environment comparisons are configuration checks, not cryptographic proof of GitHub provenance. OIDC/Sigstore provenance and Rekor proof validation are still separate work.

HF reads `ARDA_PROVIDER_CONFIG_JSON` and `ARDA_ENROLLMENT_JSON` at runtime. Public configuration is supplied after the immutable image is built, avoiding a self-referential image digest embedded in its own contents. It requires the exact configured SPACE_ID. Its image-digest environment value is a declared configuration binding, not remote hardware/image attestation; actual deployed-image acceptance remains required.

Private runtime secrets:

- GitHub: `ARDA_GITHUB_SIGNER_PKCS8_B64`.
- HF: `ARDA_HF_SIGNER_PKCS8_B64` and distinct `ARDA_HF_CLIENT_TOKEN`.

No such live values are included. Private signing bytes are used only in owner-only temporary files in private directories, removed after operations. Protect the provider process, image, administrators and secret settings. Different platforms and algorithms alone do not establish independent operators or compromise domains. Do not copy live provider private keys onto the enrolled Lenovo as a shortcut.

## GitHub workflow template

`providers/github/arda-pq-review.yml` is provided outside `.github/workflows`; extracting this package activates nothing. The template is manual-dispatch only, disabled unless ARDA_PROVIDER_DEPLOYMENT_ENABLED is true, uses a named review environment, read-only repository permissions and immutable action revisions. Operator review of the environment/branch protection and account capabilities is required before secret enrollment.

The request is data supplied through an environment value and decoded to a private temporary file, never interpolated into shell source. The approved commit and immutable runner-image reference are checked before running containers. Tests run without signing secrets. The signing container has no network, a read-only root/workspace, dropped capabilities and a private temporary filesystem. It receives only the selected signing secret by environment variable name. Only the resulting vote is uploaded; the raw R13 capture is not selected as an output artifact. Dispatch inputs and provider logs still have the hosting platform's visibility/retention rules; review that before sending host metadata.

Action revisions were resolved from the official repositories: checkout v4.2.2 (`11bd71901bbe5b1630ceea73d27597364c9af683`) and upload-artifact v4.6.2 (`ea165f8d65b6e75b540449e92b4886f43607fa02`). Their pinning is not an independent security audit or a statement that they are the latest versions.

## Image templates and operational acceptance

The root Dockerfile requires explicitly supplied immutable BASE_IMAGE and NODE_IMAGE references. It installs the runtime/build packages, checks the entire source candidate through its test runner, and switches to UID 1000. Base selection, dependency provenance, image build, final image-digest approval and real provider execution have not been performed here. Do not substitute an unreviewed mutable tag to bypass an enrollment failure.

For HF, copy `providers/hf/Dockerfile` and `providers/hf/SPACE_README.md` into a dedicated Space only after review. That thin Dockerfile uses an already built immutable witness image. Public configuration and private secrets are supplied at runtime; operator-config is excluded from the image build context. Keep this separate from the existing BEAST semantic witness unless a migration is explicitly reviewed.

R13 evidence lasts at most 120 seconds in the current service. Queueing, environment approval, image startup or tests can exhaust that window. The current template refuses stale input. Live orchestration must arrange readiness before collecting the shared fresh capture; this candidate does not extend attestation validity to hide latency.

## Local validation and open gates

Tests generate disposable keys and TPM-shaped fixture quotes, verify real provider ML-DSA and SLH-DSA votes, join both new votes with a fixture HSS signature into an R13-bound three-algorithm certificate, exercise loopback HTTP authorization/framing failures, validate configuration/image/identity mismatches and source tamper refusal. Neither fixtures nor runtime-environment assertions prove a live provider vote.

Before activation: choose and review provider identities, build/pin images, establish actual all-three key custody/enrollment, demonstrate hosted execution and provenance, solve rollback-safe Cloudflare HSS signing, integrate verified Rekor proofs, bind the consumer to the actual permitted mutation, then stage/install/recover through an approved later release. Generation 14 is still sealed and unsigned; its runtime has not gained this verifier merely because the standalone package exists.

References:

- https://huggingface.co/docs/hub/spaces-sdks-docker
- https://huggingface.co/docs/hub/spaces-overview
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
- https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments

## Current test counts

The complete local runner reports 123 tests: 94 PQ/R13/provider Python tests, 8 original R13 Python tests, 5 original Worker Node tests and 16 reservation-ledger Node tests. The 94 include actual loopback HTTP traffic and a three-algorithm R13-bound certificate assembled using both new provider signing paths plus an HSS fixture. Native HSS upstream vectors run separately. Actual GitHub/HF calls, live key generation/enrollment, Docker image builds, Rekor publication and Cloudflare runtime acceptance are all unexecuted here.
