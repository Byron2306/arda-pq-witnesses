# R13 Hosted Cryptographic Verification V3

Off-host GitHub-hosted validation of the *exact* signed R13 v2 capture archive
(`issued_challenge`, `evidence`, `receipt`). Reuses `r13-source/r13_v2.py`,
including strict challenge signature verification, receipt signature
verification, and all challenge/evidence/receipt digest and boot bindings.

**Public repository:** NEVER commit an R13 archive, bearer token, private key,
raw TPM evidence, production verifier signing key, or SSH credential.

The public repository contains the independently pinned R13 Ed25519 verifier
public key, Lenovo AK public key, and approved PCR policy. These are compared
against the checked-in expected SPKI pin, AK and full policy digest. If your
active R13 enrollment has rotated from these public references, this gate
REFUSES until the independent reference is deliberately updated.

Configure GitHub repository Actions variables:
- `ARDA_R13_NODE_ID`: enrolled R13 node ID
- `ARDA_R13_VERIFIER_ID`: enrolled R13 verifier ID

Configure a GitHub Actions **repository secret** named
`ARDA_R13_CAPTURE_B64` with the canonical base64 of one signed v2
`attest_cloud.py` capture. No secrets are needed for the default REFUSE run.
This workflow never prints the archive and only uploads safe review metadata.
A secret is not an ideal durable evidence transport; it is a **manual V3
trial**, not an automated evidence inbox. Use approved private HTTPS artifact
ingress for production. In particular, secrets are shared across permitted
repository workflows, so workflow and repository maintainers are inside
the operational trust boundary.

The signed R13 challenge normally expires **120 seconds after issuance**.
The archive must be captured and the workflow started/verified within that
remaining validity. The verifier refuses expiry. Once signed, a capture can
otherwise be re-evaluated within its validity window; V3 does **not** implement
a persistent cross-run replay ledger or guarantee one-time GitHub acceptance.
Cloudflare's challenge consumption prevents resending a quote to mint a new
receipt, not repeated reading of the same signed receipt. Treat an archive
review as point-in-time cryptographic validation only.

A valid R13 receipt sets `r13_receipt_verified=true` and
`r13_receipt_fresh=true` but **never authorizes** independent software
attestation, Phase 4, hardware-rooted OS grade, or production cutover.
The outer status remains REFUSE and GEN14 stays KEEP_CLOSED.

The R13 client/Worker quote proof is bound to a client-reported Linux boot ID,
not a TPM-originated independently discovered boot identity. Software-runtime
trust still requires a genuine independent sensor and a separately authorized
Phase 4 issuer.

Run unit tests locally with `cryptography>=41` installed:
`python3 -m unittest discover -s tools/r13_offhost_gate -p 'test_*.py' -v`.
