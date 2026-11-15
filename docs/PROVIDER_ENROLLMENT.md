# Provider-local enrollment ceremony (v4)

Status: code and local fixture validation only. No live keys created or enrolled, no setup token provisioned, no real secret-store calls tested. The current v3 Space is expected to refuse startup. V4 does not change that startup gate. Its image must be built, tested, published and independently selected before the setup commands below are usable. Do not use the existing v3 image for v4 tools.

## What this completes

V4 adds a public setup document, provider-local ML-DSA/SLH-DSA key generation, uniquely named provider secret uploads, signed public registrations, all-three policy finalization, and generation of exact runtime configuration values. GitHub secret encryption uses PyNaCl sealed boxes following GitHub's API. HF uses its fixed HTTPS Space secret endpoint. HTTPS redirects, implicit environment proxies, retries and raw provider error logging are disabled.

A registration proves possession of the private key. It does not prove platform provenance, deployed image contents or readback from the secret store. Native environment comparisons are an operational guard, not remote attestation. Setup credentials and provider administrators can still compromise custody. Tests use temporary fixture keys and mocked transports; they do not establish hosted acceptance.

## Key custody and retries

Run `tools/enroll_provider.py` only within the selected provider environment, with the reviewed v4 code/image. Never run it on the Lenovo or in this assistant workspace for actual provider keys. Do not run it as the normal Space CMD. It is an explicit one-shot command, not an HTTP route, and has no automatic retry mode.

Each generated key is saved as `ARDA_GITHUB_SIGNER_PKCS8_B64_<PUBLIC_KEY_SHA256_UPPERCASE>` or the corresponding `ARDA_HF_...` name. Existing enrolled names are not overwritten by a retry (except a cryptographically negligible public-key collision). A failed or uncertain upload releases no registration. An uploaded key may be orphaned if the response, process or public output is lost. Review and delete orphaned secrets manually; never infer enrollment from a secret's existence. The provider selection remains unchanged until an operator pins an exact public registration in a finalized policy.

Private bytes remain in the provider process, owner-only temporary key files and its secret store. The implementation cannot promise Python memory zeroization. Temporary files are removed on ordinary completion/error; the setup container should use ephemeral /tmp. Only public registrations are printed or selected as output artifacts. Setup tokens are not passed into OpenSSL subprocesses and must never appear in commands, chat, repository files or artifacts.

## 1. Build v4 and prepare a public ceremony

Build the root Dockerfile with reviewed immutable BASE_IMAGE and NODE_IMAGE arguments. It now includes libc6-dev and python3-nacl. The build executes the full verification runner. Publish the resulting image and obtain its registry digest. That digest differs from v3. Keep the HF Space on the old pinned image until v4 is accepted; do not replace its CMD with a bootstrap generator.

On the operator machine (public files only):

```
python3 tools/prepare_enrollment.py \
  --image-digest sha256:YOUR_REVIEWED_V4_DIGEST \
  --cloudflare-identity YOUR_ACTUAL_REVIEWED_RELEASE_WITNESS_ID \
  --out ceremony.json
```

The command fixes GitHub `Byron2306/arda-pq-witnesses` and HF `Byron230686/arda-pq-policy-witness`, adds a random public nonce, and produces a one-day setup window. It does not accept placeholder keys or create provider keys. The Cloudflare identity must identify the release witness, not silently reuse the separate R13 attestation identity. Its exact value remains an operator selection until that service is implemented. Registration proofs are setup-time receipts; the final closed enrollment policy has a separately declared 30-day validity.

Record CEREMONY_SHA256 independently. Review all identities and image digest before enabling generation. A new/expired ceremony requires new reviewed registrations; never extend existing proof times.

## 2. GitHub setup

`providers/github/arda-pq-enroll.yml` is an inactive template. Install it as `.github/workflows/arda-pq-enroll.yml` only after reviewing its exact source. It has manual dispatch, a repository-wide setup concurrency group, read-only GITHUB_TOKEN permissions, a named setup environment, an explicit enabled variable and approved workflow-commit pin. No workflow is active merely because this source repository is cloned.

The ordinary GITHUB_TOKEN cannot set repository secrets. Supply a short-lived fine-grained setup credential scoped only to this repository, with the required Actions secrets write permission, through the environment secret `ARDA_ENROLLMENT_STORE_TOKEN`. Configure protection on the named setup environment and restrict approved workflow branches. Do not reuse a package publishing credential or expose the setup credential to review-vote jobs.

Set variables ARDA_WITNESS_IMAGE to the reviewed immutable v4 image, ARDA_APPROVED_ENROLLMENT_COMMIT to the exact installed workflow commit, and enable ARDA_ENROLLMENT_ENABLED only for the ceremony. Dispatch with canonical ceremony base64 and its separately reviewed digest. The command checks repository/main ref/approved commit and the image binding before secret use. Retrieve only the public registration artifact, independently verify its proof and digest, then disable setup and remove/revoke the credential. A failed/retried dispatch creates another distinct key; do not select the newest one automatically.

## 3. HF setup (separate temporary authenticated app)

V4 provides a setup-only server so interactive shell access is not required. It never generates keys merely by starting. Normal tools/serve_hf.py is unchanged; use the temporary setup CMD only for this ceremony after the v4 image has passed build and hosted review:

```
CMD ["python3", "tools/serve_hf_enrollment.py"]
```

The Space Dockerfile must still FROM the independently accepted v4 image by digest. Supply these **public variables** through Space settings:

- ARDA_ENROLLMENT_CEREMONY_JSON: the exact canonical ceremony.json bytes (one line).
- ARDA_ALLOW_PROVIDER_KEY_PROVISIONING: its independently reviewed SHA256.
- ARDA_IMAGE_DIGEST: the accepted v4 sha256 digest matching that ceremony.

Supply these **temporary secrets** only through Space secret settings:

- ARDA_ENROLLMENT_STORE_TOKEN: short-lived, least-privilege HF credential that can write Space secrets for this Space only. This is a setup credential, not the signing key.
- ARDA_HF_SETUP_CLIENT_TOKEN: a fresh independent 256-bit random credential as 64 lowercase hex characters. Generate this operator client credential locally; keep it out of shell history and chat. This is not a signing private key.

Native SPACE_ID must match the ceremony. Startup should report HF_ENROLLMENT_ONLY_WAITING_FOR_AUTHENTICATED_REQUEST. /healthz reports enrollment_only and WAITING. No private key is generated yet. The app implements only authenticated POST /v1/enroll-hf, accepts only a pinned ceremony request and has no vote route. It authenticates X-ARDA-Setup-Token before parsing the bounded canonical JSON body; HF gateway authentication for a private Space uses the separate standard Authorization header.

On the operator machine, with the setup-client credential in ARDA_HF_SETUP_CLIENT_TOKEN and a read-scoped HF gateway credential in HF_TOKEN (environment only), run tools/enroll_hf_remote.py --ceremony ceremony.json --ceremony-sha256 REVIEWED_SHA --out hf-registration.json. This client is fixed to this Space's direct HTTPS hostname, disables proxies/redirects/retries, and verifies the public SLH-DSA registration proof before saving it. It neither generates nor downloads a provider private key. Exact hosted private-gateway behavior has not been accepted yet; authentication failure stays refused.

The explicit request generates the key inside HF, uploads it directly to this Space's secret store under the key-derived name, and returns only the public signed registration. Subsequent calls to that same live process return the same cached public record. A concurrent call is refused; a failed provisioning attempt cannot be retried in-process. Key upload may cause a platform restart. A restart clears the cache and returns to WAITING; it never repeats generation without another authenticated request. An uncertain response is an orphaned-key case requiring operator review before an explicit retry, which creates a distinct candidate rather than overwriting the old one. These are stateless keys; no HSS state is involved.

Independently review/pin the returned public registration. Then remove/revoke the setup store token, remove the setup-client token, and restore the normal tools/serve_hf.py CMD. Do not leave this setup service deployed for ongoing release reviews. Normal startup must still refuse until the all-three public enrollment and exact runtime configuration are finalized. A separate operator client bearer credential is required for the eventual review endpoint; it is not the setup token or signing key. V4 also accepts X-ARDA-Review-Token for application authentication on the normal review endpoint, leaving Authorization for the private HF gateway. Legacy application bearer authentication remains supported when the custom header is absent; an invalid custom token never falls back. Real hosted gateway acceptance is still required before votes are claimed operational.

## 4. Cloudflare and finalization

No HSS provisioning/signing implementation is added. A real Cloudflare registration must be produced by the future reviewed stateful signer, using exactly the registration payload and domain in arda_quorum/enrollment.py. Producing that proof consumes an HSS leaf; its state discipline must include setup signatures as well as release votes. The independent state anchor, restore/recovery rules, concurrency and signer enforcement are unresolved. The existing review ledger alone does not provide rollback-safe HSS custody. Do not enroll fixture keys as a workaround.

Only after three real provider public registrations have been independently reviewed, use tools/finalize_enrollment.py with --ceremony, --ceremony-sha256, --github-record/--github-pin, --hf-record/--hf-pin, --cloudflare-record/--cloudflare-pin, --github-commit, --epoch and --out-dir. Every record pin is operator input. The command verifies the proof and exact ceremony/provider binding, then creates enrollment.json, separate provider configuration files, HF runtime variables, GitHub variables and a closed result report. GitHub configuration files belong under operator-config. The output leaves ARDA_PROVIDER_DEPLOYMENT_ENABLED=false. Provider environment comparisons and registration proofs do not auto-approve real deployment provenance.

The HF runtime selects its key-derived secret name using the pinned enrollment key. The old fixed secret name remains accepted for v3 compatibility, but conflicting fixed/named values are refused. GitHub's review template maps the operator-selected key-derived secret through the existing fixed environment name; the signer still checks its public key against enrollment.

Hosted key readback/proof, live three-provider votes, R13 freshness, verified Rekor inclusion, HSS signer review and the actual production consumer remain separate requirements. All outputs retain PRODUCTION_AUTHORIZED=FALSE and INTERLOCK=KEEP_CLOSED.
