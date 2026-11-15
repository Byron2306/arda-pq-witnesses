# Provider key enrollment

The approved provider split remains GitHub ML-DSA-65, HF SLH-DSA-SHA2-192s, and Cloudflare HSS/LMS. Existing runtime refuses startup until complete enrollment.

Use a pinned, bounded ceremony document. Stateless key generation executes only through an explicitly enabled provider-local command, checks the configured native provider identity first, uploads the private DER as base64 directly to that provider secret store under a public-key-derived name, and returns only a domain-separated signed public registration. No live key generation occurs in the build or tests. A retry generates a different uniquely named key and does not change previously selected keys. Ambiguous upload failures return no registration; orphaned secrets require operator cleanup. API redirects and environment proxies are disabled.

Registration proves possession, not platform provenance or secret-store readback. The operator must review exact registration hashes independently. Complete policy creation requires three approved registration hashes and valid proofs; partial registration never produces a runtime enrollment. Cloudflare signing is not added: no HSS key or fixture may be substituted for its future real registration, and HSS registration itself consumes a leaf. Rollback-safe state handling and independent hosted acceptance remain blockers.

HF runtime selects the key-derived secret name from its pinned enrollment, with the old fixed name accepted only for backward compatibility and conflicting values refused. The normal witness has no enrollment HTTP route. A separately selected temporary setup app authenticates a pinned explicit POST; startup/health never generates keys and no vote route exists. Setup is once per process, with failure refusing retries and restart requiring a new explicit request. Unique names prevent a retried stateless candidate overwriting an earlier key. Setup credentials must be removed after the ceremony.

Alternatives considered: host-generated private keys violate intended provider custody; automatic generation at ordinary Space startup risks unwanted repeated keys and hides readiness. Provider-local explicit provisioning separates setup from vote service.

Validation: real disposable ML/SLH proof signatures; identity and pin failures before key generation; isolated provider transport with simulated APIs; sealed-box encryption; proof tampering, missing providers, wrong hashes, secret-upload failure, and runtime selection. External APIs and hosted bootstrap are untested until the operator runs them.
