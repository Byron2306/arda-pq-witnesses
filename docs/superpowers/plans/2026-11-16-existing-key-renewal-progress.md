# Ledger: existing-key-renewal

Pre-flight: GH and HF share only tools/renew_existing.py. Both preserve the same accepted v4 base and signature schema. No existing provisioning code will be changed.
Ruling: deliver template under providers/github, without editing active .github workflow; user can install a separately named renewal workflow after review. This keeps provisioning disabled and avoids changing current GitHub enrollment behavior.
Archive verification: all five public SHA256 pins match; native HSS check_record passes at current UTC 2026-11-16T08:04Z. Ceremony expires 2026-11-17T04:59:45Z.

Task 1: core RED→GREEN, 10 real-crypto / HTTP / CLI tests pass.
Ruling: also place the renewal workflow in the candidate branch at the already registered arda-pq-enroll.yml path, retaining the template copy. Main remains unchanged; a distinct enable switch and approved ref+commit gate prevent old provisioning. This permits dispatch on the candidate without merging the complete Cloudflare PR. Risk: an environment restricted to main will block the candidate run and require operator review of that restriction.

HF client response verifier RED→GREEN: rejects changed authority, foreign provider and key substitution; 11 focused tests pass. Active original workflow on main is not mutated. Source differences checked: v4/v5 enrollment.py, provider_witness.py and provider_http.py are byte-identical.

Task 1: complete. Final full run_verification.py →234 PASS; focused renewal tests11 PASS; executable GitHub preflight rejects wrong approved commit before creating files and accepts matching source. No Docker runtime available locally; pinned-image live runtime validation remains a provider step.
Final review: fresh read-only reviewer found no Critical/Important/Minor issues. Declined live GH/HF settings, gateway access and pinned-image execution: these remain explicitly unverified until operator runs the candidate. No production/live provider changes by this implementation.

Follow-up 2026-11-16: deployed HF commit064a134e reported RUNTIME_ERROR with only the generic refusal. Root cause remains unknown because startup swallowed check identifiers. Added fixed-stage diagnostic instrumentation only, retaining the generic exception string and all checks. Regression tests: missing named signer produces EXISTING_NAMED_SECRET; missing setup-client token emits HF_CLIENT_TOKEN without any private key text. Both tests observed RED then GREEN;13 focused tests pass. This is observability, not a claimed repair of hosted configuration.

Follow-up verification: full run_verification.py →236 PASS. Diagnostic identifiers are locally selected constants; no upstream exception messages or environment values are emitted. Hosted failure remains unresolved until diagnostic output is collected.
