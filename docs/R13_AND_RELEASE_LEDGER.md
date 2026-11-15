# R13 source review and isolated integration

The actual Cloudflare entry point is a 415-byte Durable Object adapter. It imports `handle`, `ingress` and `Ledger` from `verifier.mjs`. The supplied implementation authenticates an exact canonical JSON request, verifies the enrolled RSA AK's raw TPM quote and approved PCR tuple, atomically consumes the challenge, synchronizes storage, and only then issues an Ed25519 evidence receipt. Its receipt explicitly denies production cutover. The existing service has no release-signing endpoint. Its source remains unchanged in this package.

The supplied five Node/SQLite tests pass. They cover concurrent replay (one receipt), expiry, malformed/unauthenticated traffic, quote/PCR/AK/qualification binding and ledger reconstruction. Eight supplied Python tests also pass. These are local tests, not a new live Cloudflare acceptance run.

## New independent evidence gate

`arda_quorum/r13_bridge.py` imports an unchanged copy of the supplied Python R13 protocol. The gate snapshots operator-pinned configuration, verifies the verifier's SPKI and enrolled AK's SPKI, and requires the independently approved PCR policy hash. It never learns a new baseline from a capture.

Each verification independently checks the signed challenge, exact node/verifier/boot/policy context, bounded freshness, raw RSA TPM quote signature, PCR selection/digest/approved values and signed receipt. The receipt alone is insufficient. A regression deliberately resigns a receipt over a forged raw quote using the fixture verifier key; the gate still refuses it. Another test obtains a genuine receipt from the unmodified JavaScript handler and verifies it in Python.

`verify_with_r13()` binds the full canonical capture digest to the exact PQ proposal, requires the proposal to be issued after the receipt and expire no later than it, then verifies all three PQ votes. It never accepts a supplied PASS boolean. Its output remains REFUSE for admission because Rekor, live stateful signer review and the production consumer remain open.

The TPM quote is rooted in the enrolled AK, not manufacturer certification; that distinction remains. Existing RSA/Ed25519 infrastructure has not been replaced by PQ primitives. An evidence PASS does not approve a changed boot baseline or release generation.

## New separate leaf-reservation component

`cloudflare/release-ledger.mjs` is an internal library matching the SQLite Durable Object storage interface. It is not imported into the R13 Worker, exposes no `fetch` route and never loads a private key or creates a signature.

Trusted candidate setup can initialize a new key identity once. Normal reservation never auto-enrolls an empty database or resets an existing key. One transaction advances the key's next-leaf counter and inserts a unique nonce/message/proposal/evidence intent. A successful storage synchronization precedes a returned reservation; expiry after commit leaves the index used but returns no reservation. Synchronization uncertainty quarantines the key. Index exhaustion, epoch/policy/anchor mismatch, clock rollback and duplicate nonces refuse. An external anchor hash is bound as metadata only; it is NOT verified as anti-rollback proof.

The BURNED_REVIEW_ONLY state means the ledger will not allocate that index again in its current history. It does not erase or consume an actual cryptographic private key. A future HSS signer must independently follow the reserved index and exact message, with durable state protection. The receiver-side ledger cannot stop a signer from ignoring it.

The 16 tests use Node's actual SQLite implementation with a model of the Durable Object API. They cover concurrency, reconstruction, atomic counter/intent rollback, sync failure, expiry-after-commit, exhaustion and input mutation. They do not establish real Workers scheduling, storage failure semantics, backup-restore resistance, independent operator custody or safe private-key persistence.

Cloudflare SQLite-backed Durable Objects support point-in-time recovery. Therefore their transactional counter alone cannot establish irreversible monotonic signing state across restoration. No live HSS key should be enrolled until a reviewed external monotonic authority or an equivalent nonreuse design is implemented and tested. This package deliberately does not deploy a signer or turn a reservation into a vote.

## Public pin inventory

`tools/inspect_r13_configuration.py` reads only the documented public pins file and three public-key paths. It compares them to the reviewed generation-14 deployment and writes a public metadata report. It never reads `deploy-secrets.json`, tokens or private keys, and performs no network request or TPM operation. File matches do not by themselves prove which key the live service uses; a fresh authenticated capture must prove that.

The older installed verifier key `28bcd365...e7d367` and the proposal pin `3fc3be4f...fed8679` are different identities. They are not interchangeable. The inventory may locate the dedicated Cloudflare public key under `$HOME/.local/state/arda-r13-cloudflare/verifier-public.pem`; it does not silently replace an installed key or rewrite a profile.

## Host steps

Run `python3 run_verification.py` without sudo. Expected counts are 61 PQ/R13 Python tests, 8 original R13 Python tests, 5 original Worker Node tests and 16 new ledger Node tests: 90 total. Native upstream HSS vectors run separately. The runner clears R13_WRANGLER only for its local unit-test subprocesses so it cannot accidentally claim the optional real-runtime test was executed.

Then run:

```bash
python3 tools/inspect_r13_configuration.py \
  --out "$HOME/arda-pq-r13-public-pin-report.json"
```

Return the test output and public report. No source deployment, key enrollment, R13 key rotation, selector publication, TPM extension or generation-14 modification occurs in either step.

## References

- https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/
- https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/
- Frozen supplied source digests: `R13_SOURCE_PROVENANCE.json`.

## Integration regressions found and fixed

Two candidate defects were reproduced before correction. The combined evidence/quorum path initially retained caller-owned containers across evidence verification; it now snapshots the entire certificate, enrollment, expected bindings and capture before invoking the gate. A concurrent reservation could also return a leaf after another request had quarantined the key during synchronization. It now rechecks quarantine and the committed intent after the await, before returning an index. Both reproductions are retained as passing regression tests.
