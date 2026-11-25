# R13 GitHub-hosted off-host review gate

This is a **safe first deployment cut** for the public `arda-pq-witnesses` repository. It runs unit tests on an ephemeral GitHub-hosted runner and emits a small, non-authoritative refusal report. It **does not** ingest sensitive Lenovo TPM quotes, SSH credentials, R13 tokens, signed evidence archives or private keys.

## Why no live evidence yet?

The source V2 observer requires: pinned SSH host identity, a reachable host, least-privilege remote BPF reads, an off-host private signing identity, an operator-approved independent reference, and fresh signed R13 evidence for the same boot. The Lenovo is on a private LAN and this repository is public. Neither the host telemetry nor the off-host key can be safely inferred, copied, or posted to public Actions artifacts.

The code under `tools/r13_offhost_gate` is **not the V2 off-host collector**; it is a new non-authoritative bootstrap gate. The actual V2 collector should only be deployed on a properly secured independent runner once host reachability and key custody are approved. This workflow deliberately does not pretend to have deployed it.

Run the workflow manually from GitHub Actions when the workflow is present on the default branch. Verify the artifact `arda-r13-offhost-review-refusal` and its `KEEP_CLOSED` status.

## Trust boundaries

- R13 signed hardware receipt does not prove independently measured runtime software.
- Host-controlled SSH telemetry is not independent kernel observation.
- GitHub-hosted execution by itself is not an authorized Phase 4 issuer.
- No workflow step writes `/var/lib/arda/verifier/latest-verdict.json`, enrolls a key, authorizes OS grade or changes GEN14.
- Never add an SSH observer private key generated on Valinor to GitHub secrets.
- Before an operational run, independently control the reviewer repo, reviewed workflow, signer, reference, and external authorization.

**Next cut**: attach the existing V2 source and tests to a protected workflow with a securely authenticated evidence-delivery channel, verified provenance, no raw-public-artifact exposure, and no self-issued OS-grade verdict.
