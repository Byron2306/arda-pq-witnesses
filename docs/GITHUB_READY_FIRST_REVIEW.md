# GitHub ready-first review candidate

The accepted image and existing ML-DSA signer remain unchanged. The workflow reads externally pinned public configuration, validates that its identity names the actual workflow commit/ref, and mounts it under the image's /app/operator-config. This removes the configuration/commit self-reference without changing the accepted image.

Before announcing readiness it pulls the immutable accepted image and runs its host preflight without the signing secret. The image's previously accepted test evidence remains applicable; the workflow does not rerun source tests from a mutable checkout. After the ready artifact has uploaded, it polls a dedicated public branch arda-review-inbox/<64-hex-session> for request.json for at most ten minutes. Only public JSON is accepted. No code is fetched or executed from that branch. GitHub token permissions are contents:read.

The canonical inbox envelope has exactly schema='arda.github.review_inbox.v1', session, run_id (string), run_attempt (string), request (the complete canonical witness request object). The session and run/attempt must match readiness. A request is passed to the accepted image's existing signer only in a separate step. That signer independently checks the proposal, raw TPM quote and receipt, R13 expiry, policy, enrolled key, source closure, and runtime identity before releasing a vote. No TTL extension or synthetic capture is permitted.

Public config is generated after publication with the final workflow commit identity. The source closure and stage pins describe the accepted image contents. The repository checkout is used only for the workflow's public inbox/config helpers, never mounted over the signing runtime.

Do not enable provisioning/renewal. Do not reset or re-enroll CF. Keep the production interlock closed. Readiness alone is not a release vote or production admission. Environment controls and live Actions execution still need operator-side verification; no live run has been performed by these tests.

Validation: eight focused Python tests cover external config acceptance, wrong ref/commit/image/policy/hash, unknown fields, inbox replay across sessions/runs/attempts, noncanonical/duplicate JSON, malformed request fields, and oversize input. Workflow YAML parsed successfully. Live GitHub execution remains unverified.
