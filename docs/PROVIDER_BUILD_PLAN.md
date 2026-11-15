# GitHub and HF witness candidate

Implement fixed-provider stateless PQ signing entry points. Trusted configuration pins the complete enrollment policy, reviewed staging request, verifier/AK public keys, approved PCR policy and reviewed source manifest. Requests contain only a proposal and an R13 capture. Every request revalidates the exact stage commitments, fresh raw quote/receipt and local policy before signing; it cannot choose a provider, algorithm, key, clock or validity window. GitHub additionally verifies the 26 changed Python source files against the staged artifact hashes. This is not a reproducible BPF build claim.

Private keys are provider-held runtime secrets; the service derives their public keys and refuses any mismatch with the enrolled key. No production key is generated or enrolled by this build. The GitHub manual workflow must use immutable action revisions and an operator-pinned container image. The HF endpoint authenticates before reading a bounded canonical JSON body and never accepts arbitrary files or commands.

Tests use real ML-DSA/SLH-DSA signatures and disposable R13/PQ fixtures, plus loopback HTTP refusal tests. Cloudflare HSS signing, Rekor proof verification, immutable image selection, actual provider enrollment/deployment and production admission remain blocked. Existing R13 service and sealed generation 14 remain unchanged.
