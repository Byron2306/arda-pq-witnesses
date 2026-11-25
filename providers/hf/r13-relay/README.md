---
title: ARDA R13 Encrypted Evidence Relay (separate, non-authoritative)
sdk: docker
app_port: 7860
---

# ARDA R13 Encrypted Evidence Relay V4

**This is NOT the existing ARDA PQ/Hugging Face witness. Deploy as a separate reviewed Space.**

V4 accepts a fresh R13 v2 capture over authenticated HTTPS. It immediately encrypts the archive to a separately controlled GitHub X25519 public key, stores only a one-time ticket/challenge digest in SQLite, and dispatches an encrypted message through GitHub's repository_dispatch API. The GitHub workflow claims the ticket once, decrypts only in the runner, and verifies challenge and evidence receipt through existing V3 cryptographic verification. No plaintext R13 capture is placed in public GitHub artifacts or event payloads.

## Required independent provisioning

A dedicated Hugging Face Space must have a real persistent volume mounted at /data. The relay fails startup without a mounted persistent volume. Ephemeral storage is NOT sufficient for replay prevention.

HF Space secrets:
- ARDA_RELAY_INGEST_TOKEN: high-entropy sender bearer. Present only in Valinor's private token file and HF relay.
- ARDA_RELAY_CLAIM_TOKEN: separate high-entropy bearer. Present only in HF relay and GitHub Actions.
- ARDA_RELAY_GITHUB_TOKEN: fine-grained GitHub token with Contents write permission restricted to Byron2306/arda-pq-witnesses for repository_dispatch. Only on HF, NEVER Valinor.
HF Space variables:
- ARDA_RELAY_GITHUB_REPO: Byron2306/arda-pq-witnesses
- ARDA_RELAY_RECIPIENT_PUBLIC_B64: X25519 recipient public key (32 raw bytes encoded as canonical base64).
- ARDA_RELAY_STATE_MOUNT: /data (must be an actual persistent mount).

GitHub Actions secrets:
- ARDA_RELAY_PRIVATE_B64: corresponding X25519 32-byte private key in canonical base64, **generated under independent off-host custody, never on Valinor and never placed on HF**.
- ARDA_RELAY_CLAIM_TOKEN: the same relay claim bearer.

GitHub Actions variables:
- ARDA_RELAY_BASE_URL: exact deployed HTTPS Space origin (no trailing slash).
- ARDA_R13_NODE_ID: enrolled R13 node ID.
- ARDA_R13_VERIFIER_ID: enrolled Cloudflare R13 verifier ID.

The existing checked-in Cloudflare R13 Ed25519 public key, AK public key, and approved PCR policy remain the independently pinned references for V3 verification. Re-enrollment must be separately reviewed, never inferred from submitted evidence.

## Submit from Valinor

Generate a fresh signed R13 capture with the existing r13-source/attest_cloud.py using its already enrolled AK, verifier pin and token. Use the existing CLI documentation; do not invent AK handle or policy values. Then submit immediately:

```bash
umask 077
python3 tools/r13_offhost_gate/send_capture.py \
  --capture "$HOME/path/to/fresh-r13-capture.json" \
  --token-file "$HOME/.config/arda/r13-relay-ingest.token" \
  --relay-origin "https://YOUR-SEPARATE-RELAY.hf.space"
```

Never publish raw TPM evidence, capture archives, private keys, bearer tokens or GitHub PATs in this public repository or its logs. Confirm mode 0600 file ownership.

## Claims and limitations

The relay provides atomic duplicate challenge rejection and a durable single-use ticket on its configured persistent SQLite volume. Failed dispatch burns the challenge ID, intentionally. A malicious privileged HF administrator, GitHub maintainer, or compromise of relay/GitHub credentials remains in the trust boundary. This is scoped relay replay resistance, not globally irreversible proof. A 120-second challenge deadline includes GitHub scheduling latency; if expired, verification REFUSES.

The first relay stage only parses the unsigned JSON challenge metadata and checks freshness before dispatch; GitHub independently checks the real signed challenge, receipt, evidence hashes and pins. The R13 protocol binds a client-reported boot ID to a TPM quote. It is NOT an independent runtime BPF observation, a Phase 4 signing authority, a replacement for the legacy Acer Phase 4 verifier, or GEN14 approval.

The GitHub result always retains status REFUSE, Phase4=false, OS-grade=false and KEEP_CLOSED, including on a cryptographically verified R13 receipt.

**Pre-production tasks:** threat-model review, supply-chain image/digest pinning, deployment integration tests, secure GitHub credential rotation, recipient key generation ceremony, persistent volume validation and real hardware capture trial. Do not merge or deploy as authorized Phase4 service.
