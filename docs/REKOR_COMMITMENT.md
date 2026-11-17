# ARDA Rekor commitment candidate

This workflow can publish transparency evidence. Neither the workflow nor the
verifier checks quorum signatures, fresh R13 evidence, signer custody, replay, or
production admission. A successful verifier result always reports
`production_authorized=false` and `interlock=KEEP_CLOSED`.

## Workflow

`.github/workflows/arda-rekor-commitment.yml` has one manual input, the
lowercase SHA-256 of the canonical ARDA quorum certificate. It never reads the
certificate, checks out the repository, or accesses a PQ signing key. It
reconstructs the 129-byte `arda.pq.public_commitment.v1` JSON and submits its
signature and signing evidence to the public Sigstore instance using Rekor v2.
The run artifact contains the commitment and its Sigstore bundle.

Do not dispatch with any real digest until public logging has been approved.
Dispatch inputs, the signing identity, and signature metadata can be public.
Use a disposable synthetic certificate for a first operational check if
approval does not cover the historical commitment.

Before activation, review and merge the workflow on the protected default
branch of `Byron2306/arda-pq-witnesses`. Configure the existing or newly
created `arda-rekor-signing` environment to allow deployments only from
`main` and require the intended reviewers. The job's
`github.ref_protected` condition checks for configured branch protection or a
ruleset. It does not prove that your protections require review or that your
environment has reviewers configured. Keep the signing workflow itself under
reviewed changes. The verifier pins the workflow path and ref, not one
particular Git commit.

## Verifier policy

Provision these independently of the bundle submitter.

- Obtain a Sigstore production **client trust configuration**, not a bare
  trusted root and not the staging trust file. Review the TUF-authenticated
  snapshot and the production Rekor v2 log that ARDA is intended to accept.
- In the policy below, set `trust_config_sha256` to the SHA-256 of the exact
  approved configuration bytes. Set `rekor_log_id_sha256` to the lowercase hex
  encoding of the selected trusted root's `tlogs[].logId.keyId` after
  Base64 decoding. Do not hash that ID again or select it from the evidence
  bundle. The template placeholders are intentionally invalid.
- Store the approved policy SHA-256 in a trusted operator or admission
  configuration separate from the certificate, bundle, and their directory.
  Supplying a digest computed from an unreviewed policy beside a new bundle
  does not establish trust. Review trust changes before replacing either pin.

```json
{
  "schema": "arda.pq.rekor_policy.v1",
  "certificate_identity": "https://github.com/Byron2306/arda-pq-witnesses/.github/workflows/arda-rekor-commitment.yml@refs/heads/main",
  "oidc_issuer": "https://token.actions.githubusercontent.com",
  "trust_config_sha256": "<approved client trust configuration SHA-256>",
  "rekor_log_id_sha256": "<approved Rekor v2 log ID as 64 lowercase hex characters>"
}
```

## Verify a bundle

From the repo root, with variables pointing to the reviewed local inputs and
`ARDA_REKOR_POLICY_SHA256` populated from protected configuration, run:

```bash
"$HOME/.venvs/arda-rekor-v451/bin/python" -m tools.verify_rekor_commitment \\
  --certificate "$ARDA_CERTIFICATE" \\
  --bundle "$ARDA_SIGSTORE_BUNDLE" \\
  --trust-config "$ARDA_SIGSTORE_TRUST_CONFIG" \\
  --policy "$ARDA_REKOR_POLICY" \\
  --policy-sha256 "$ARDA_REKOR_POLICY_SHA256"
```

The verifier reconstructs the exact signed bytes from the local canonical
certificate. The bundle must have one Rekor v2 hashedrekord message-signature
entry with the approved log ID, an inclusion proof, and a checkpoint. The
proof's tree size must match the signed note. Sigstore independently validates
the signature and identity, certificate chain and timestamp evidence, log
entry binding, Merkle inclusion, and checkpoint signature. It receives private
snapshots of the prechecked inputs and runs offline. It does not trust a JSON
success flag from the submitter.

Local checks run without network access and mock Sigstore's subprocess boundary.

```bash
python3 -m unittest discover -s tests -p test_rekor_commitment.py -v
```

Hosted workflow acceptance and real cryptographic verification of an
ARDA-specific bundle are still required. For a future fresh admission test,
measure bundle availability against the existing proposal/R13 expiry, and
refuse admission if evidence arrives too late. A valid proof obtained after
expiry cannot authorize an expired certificate.
