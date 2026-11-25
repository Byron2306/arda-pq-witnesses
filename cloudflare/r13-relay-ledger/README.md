# ARDA R13 relay ledger, isolated Cloudflare Durable Object

## Security boundary

This is a **separate Cloudflare Worker**, not the current R13 verifier. It holds no TPM AK private key and issues no Phase 4 verdict. Its single SQLite-backed Durable Object namespace persists challenge IDs and tickets, and conditionally permits exactly one claim per ticket. All callers route through the same named object, so there is no per-region split-brain counter.

Cloudflare Durable Objects SQLite is an actual transactional storage backend. The Hugging Face Xet bucket should **not** hold SQLite WAL or locking files. It can remain attached for unrelated audit assets, but is not required by the V4 replay ledger.

## Deployment prerequisites

- Deploy only from a reviewed branch. Use a dedicated Cloudflare Worker named `arda-r13-relay-ledger`, separate from `arda-r13-verifier`.
- Review `wrangler.json` and `src/worker.mjs`; `new_sqlite_classes` deliberately provisions a new Durable Object class.
- Create an independent 48+ character random `RELAY_LEDGER_SHARED_SECRET` as a **Worker secret**, NOT a variable. The SAME secret is provided only as `ARDA_RELAY_LEDGER_TOKEN` in the HF Space secrets. Never copy it to Valinor or GitHub.
- Deploy from this directory: `npx wrangler deploy` after configuring Cloudflare authentication. Use installed reviewed Wrangler, do not make deployment automatic.
- Obtain the exact deployed HTTPS origin, and set HF variable `ARDA_RELAY_LEDGER_URL` to that origin. This Worker exposes only authenticated POST `/reserve` and `/claim`.
- The HF relay must retain `ARDA_RELAY_STANDBY_ONLY=1` until all credentials and private-key custody are ready and this service has passed real DO concurrency, restart and replay tests.
- Never send `RELAY_LEDGER_SHARED_SECRET` to browser pages or include it in logs.

## The two operations

`POST /reserve`: `{ticket, challenge_id, envelope_sha256, expires_at}`. 201 only on a durable unique insert; 409 on duplicate challenge or ticket, 400 malformed request. The HF relay must reserve before GitHub dispatch. A failed dispatch intentionally burns the challenge.

`POST /claim`: `{ticket, envelope_sha256}`. 200 only when the atomic conditional update changes exactly one currently unused and unexpired row; otherwise 409. GitHub still claims through the HF relay, which authenticates separately.

The Durable Object authorizes only **one encrypted-receipt transport claim**, not freshness or TPM verification by itself. Only the GitHub R13 signed receipt verifier can claim cryptographic verification, and even that cannot authorize Phase 4 or GEN14.

The current ledger retains challenge identifiers indefinitely to prevent late replay. Add bounded retention and explicit epoch semantics only after a separate anti-replay threat review.

## Hosted validation

GitHub PR CI runs `node --test cloudflare/r13-relay-ledger/src/worker.test.mjs` (simulated SqlStorage, NOT an actual Cloudflare DO) plus Python relay tests. The next acceptance stage is a deployed DO with controlled live restarts, concurrent claims and fault injection. Don't call it production-ready based solely on simulated tests.

**No new ARDA production authority. GEN14 interlock stays KEEP_CLOSED.**
