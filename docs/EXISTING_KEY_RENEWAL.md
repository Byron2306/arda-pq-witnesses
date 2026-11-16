# Renew GitHub/HF registration proofs with existing keys

Cloudflare enrollment is already complete. Do not run Cloudflare enrollment/replacement again. Both stateless providers must sign the same fresh canonical ceremony, retaining their existing provider-local private keys. This is enrollment evidence only: production remains unauthorized and the interlock remains closed.

## Immutable base and separately reviewed overlay

Use `ghcr.io/byron2306/arda-pq-witness@sha256:02dc4bacda942f58d040cc9093174d2cd6fc84fafc098bf0263a4ff61bda99bd`. The existing image's enrollment, crypto and provider HTTP modules are unchanged; `tools/renew_existing.py` is an additional hash-pinned overlay. The wrapper has different source/image identity from its base. Nothing claims the wrapper itself has the v4 image digest. No new base image or private-key provisioning is required.

The exact existing key fingerprints are:

| Provider | Key SHA256 |
| --- | --- |
| GitHub | `d6aaed60d09f77fd5bdfbc6b67e9831a12696cace8871330927072822baff09f` |
| Hugging Face | `41750e2996a98bec74bb40db35bf9f370fcdbef26c02650e029085f7abee3fe1` |

The script selects only the fingerprint-named secret. It refuses missing keys, mismatching derived public keys and conflicting generic aliases. It requires provider identity, canonical ceremony SHA256, image binding, explicit renewal enable and a live ceremony window. It signs the existing enrollment domain and verifies each new proof natively before release. A failed request does not generate a replacement private key. HF caches its public result for authenticated retrieval within the ceremony window; restarting may create another stateless signature with the same key, which has no HSS leaf counter.

## GitHub

The candidate branch replaces only its copy of the already registered `.github/workflows/arda-pq-enroll.yml` with the renewal workflow, also available as `providers/github/arda-pq-renew.yml`. Main's provisioning workflow remains disabled. The protected environment is still `arda-pq-enrollment`; any configured human approval remains in force. If that environment allows only main, review its deployment branch restriction before allowing this specific candidate branch. Never bypass an unexpected refusal by enabling the provisioning workflow.

Set repository variables with `gh variable set --repo Byron2306/arda-pq-witnesses`:

- `ARDA_ENROLLMENT_ENABLED=false` (keeps main's old provisioning path off).
- `ARDA_EXISTING_KEY_RENEWAL_ENABLED=true`.
- `ARDA_APPROVED_RENEWAL_COMMIT` = exact reviewed candidate commit.
- `ARDA_APPROVED_RENEWAL_REF=refs/heads/candidate/cloudflare-hss-v5-20261115`.

Dispatch the registered `arda-pq-enroll.yml` file on that candidate branch with `ceremony_b64` and `ceremony_sha256`. The source commit and ref must both match the approved variables before the key step starts. The pinned overlay is fetched and checked before loading the key. The signing container is read-only, has no networking or write credential, and receives only the existing uniquely named GitHub signer secret. Artifact `arda-github-renewed-public-registration` contains only `github-registration.json`. Independently verify its key and ceremony before policy assembly. Disable `ARDA_EXISTING_KEY_RENEWAL_ENABLED` after evidence has been collected.

## Hugging Face

Use the existing Space `Byron230686/arda-pq-policy-witness`. Preserve its signer secret and `ARDA_HF_SETUP_CLIENT_TOKEN`; neither belongs in Git, an archive, a terminal log or chat. Do not supply an enrollment-store write token to the renewal tool.

Prepare a new Space Git commit that copies the reviewed `tools/renew_existing.py` to `renew_existing.py` and `providers/hf/Dockerfile.renewal` to `Dockerfile`. Keep the Space's existing README Docker metadata (`sdk: docker`, app port 7860). The Dockerfile checks the overlay's SHA256 and inherits the pinned v4 base as UID 1000.

Set these **public variables** in the Space:

- `ARDA_RENEWAL_CEREMONY_JSON`: exact canonical fresh `ceremony.json` text, no trailing newline.
- `ARDA_ALLOW_EXISTING_KEY_RENEWAL`: SHA256 of those exact ceremony bytes.
- `ARDA_RENEWAL_EXPECTED_KEY_SHA256`: the HF fingerprint in the table above.

The Dockerfile supplies the pinned `ARDA_IMAGE_DIGEST`. Remove a conflicting Space override rather than changing the ceremony's image field. Remove unused provisioning-store credentials after local review; keep the provider-held signer secret. Startup prints `HF_EXISTING_KEY_RENEWAL_WAITING_FOR_AUTHENTICATED_REQUEST`; no signature is made at startup. `/healthz` reports only public identity/ceremony/state. Only `POST /v1/renew-hf` with `X-ARDA-Setup-Token` can request a new proof. The old `/v1/enroll-hf` and vote routes return 404.

Client execution: mount the reviewed overlay into `/app/tools/renew_existing.py` in the same pinned immutable image, mount the ceremony read-only and an empty output parent writable, and run:

```
python3 tools/renew_existing.py hf-client \
  --ceremony /ceremony.json --ceremony-sha256 REVIEWED_CEREMONY_SHA256 \
  --expected-key-sha256 41750e2996a98bec74bb40db35bf9f370fcdbef26c02650e029085f7abee3fe1 \
  --out-dir /output/hf-renewal
```

Forward `ARDA_HF_SETUP_CLIENT_TOKEN` by environment name; for a private Space also forward `HF_TOKEN` for gateway access. The fixed HTTPS client refuses redirects and retries, retains the public response before native verification, and writes `hf-registration.json` only after ceremony, signature, provider and existing-key checks pass. It refuses an existing output directory before contacting the Space. If it reports a refusal, inspect the retained output and current deployment before any new action.

After all three public registrations are verified against the same live ceremony, use the existing finalizer to create a closed enrollment policy. Key possession proofs do not independently prove hosted custody, provider votes, R13 freshness, Rekor inclusion or production admission.
