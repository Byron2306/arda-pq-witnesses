# Hugging Face Docker Space startup: intentionally disabled standby

The default V4 relay refuses startup until ALL required production configuration,
approved transactional state storage and off-host key custody are present. The
error `MISSING_RELAY_CONFIGURATION` is a deliberate guard, not a Docker failure.

For a safe startup and connectivity test only, set the following **Space variable**:

`ARDA_RELAY_STANDBY_ONLY=1`

Restart the Space. `GET /health` returns:

`{"status":"standby","ingest_enabled":false,"phase4_authorized":false,"interlock":"KEEP_CLOSED"}`

Both `POST /v1/submit` and `POST /v1/claim` return HTTP 503
`RELAY_STANDBY`. No secret is needed, no ledger is opened, and no evidence
is accepted or sent to GitHub.

**Do not turn off standby merely to clear an error.** The Xet bucket is
object storage, not proven SQLite transactional storage. The current SQLite
WAL replay ledger MUST NOT run against a bucket mount without validated
locking, consistency and crash-recovery guarantees. Replace it with an
approved transactional state service and exercise crash/restart, concurrent
claim and duplicate-challenge tests before enabling intake.

On HF Space upload, use the updated `gateway.py` from PR #14:
`providers/hf/r13-relay/gateway.py`. The Space root has `Dockerfile`,
`gateway.py`, `crypto_box.py`, `README.md`.

Space variable settings are private to that Space's runtime; no keys,
bearer tokens, signing credentials or encrypted evidence should be committed
to its repository. Keep `ARDA_RELAY_STANDBY_ONLY=1` while integrating state.
