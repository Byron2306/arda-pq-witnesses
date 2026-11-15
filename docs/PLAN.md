# Implementation plan

1. Add failing tests for strict encoding, fixed enrollment and all-three real signature verification; implement OpenSSL and pinned HSS verification adapters.
2. Add failing tests for exact proposal, witness role, policy, expiry and no-downgrade binding; implement the pure quorum verifier.
3. Add failing tests for nonce/leaf replay, concurrent attempts and process restart; implement private transactional review-intent storage.
4. Add a generation-14 request reader and a minimal public-commitment builder. Verify the request before preparing a fresh, short-lived unsigned proposal.
5. Run all package tests, HSS upstream test vectors and the existing candidate suite. Package source, provenance, host preflight and verification commands. Keep production admission closed.
