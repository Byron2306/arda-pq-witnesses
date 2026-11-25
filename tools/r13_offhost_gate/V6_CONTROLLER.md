# R13 V6 crash-recoverable synthetic test operator runbook

**Non-production.** GEN14_INTERLOCK=KEEP_CLOSED. No real capture may enter V6.

## Prerequisites

* Pull reviewed code and deploy `providers/hf/r13-relay/gateway.py` to the Space **in standby**.
* Verify `/health` reports `status=standby`, `ingest_enabled=false`, `synthetic_test_enabled=false`, `phase4_authorized=false`, `interlock=KEEP_CLOSED`.
* Python environment must contain `huggingface_hub`. The local ingest bearer exists at `~/.config/arda/r13-relay-ingest.token`; never print it.
* All controller steps use the same Linux user and `~/.local/state/arda-r13/v6-controller.json`; file permissions are 0600. **Do not delete this journal if a submit outcome is uncertain.**

Set `PY="$HOME/.config/arda/hf-admin-venv/bin/python"`; run from repository root:

```bash
git fetch origin main
PY="$HOME/.config/arda/hf-admin-venv/bin/python"
C="tools/r13_offhost_gate/v6_controller.py"
"$PY" "$C" status
"$PY" "$C" arm
"$PY" "$C" open
"$PY" "$C" ready
```

`ready` is a **single check**: it refuses while HF is restarting and must be run again only after the Space updates. It requires the live health to match both `test_backend=github-v6` **and the exact deadline**. Never call submit until `LIVE_V6_WINDOW=READY`.

Exactly one attempt:

```bash
"$PY" "$C" submit
```

If terminal dies during `submit`, treat the result as unknown and **DO NOT retry**. The journal marks `SUBMISSION_ATTEMPTED` before its outbound HTTP POST. A 202 confirms only accepted GitHub dispatch; Cloudflare reserve/claim must be verified from GitHub Actions.

Close regardless of the result:

```bash
"$PY" "$C" close
"$PY" "$C" verify-close
```

If `verify-close` refuses, the HF environment may be propagating. Repeat **only** `verify-close` after the restart. Do not open any additional test window until live standby is confirmed. The deadline also expires after at most 300 seconds. `close` is repeatable.

When the terminal exits or the journal is uncertain, recover with `status` then `close` and `verify-close`. An old `SUBMISSION_ATTEMPTED` is not proof of a successful dispatch.

For GitHub, inspect only the latest `repository_dispatch` event of `arda-r13-github-ledger-v6.yml`; expected receipt is `SYNTHETIC_TRANSPORT_DECRYPTED_R13_NOT_VERIFIED` with production authorization false. A successful workflow status alone is insufficient.
