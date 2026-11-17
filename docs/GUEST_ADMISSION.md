# Disposable guest admission candidate

This test harness composes the PQ/R13 review and offline Rekor verifier with the
existing projection coordinator and projection journal. The coordinator's only
adapter in this harness is a private file holding a modeled selector. No boot
file, BPF map, cgroup, sealed generation, provider, or running ARDA service is
modified. Every model result reports `production_authorized=false` and
`interlock=KEEP_CLOSED`.

## Boundary under test

The reviewed runtime's `projection_ctl.py apply` uses an independently signed
projection permit. A PQ review certificate and transparency proof do not
replace that permit. The guest caller supplies the expected target from a
trusted staging context, an independently pinned enrollment and Rekor policy,
the pinned R13 verifier, and the guest release public key. These inputs must
not be sourced from a certificate or proof selected by the requester.

1. Check the scope, boot, generation, manifest identity and digest against the
   expected activation plan. Verify all three PQ votes and the bound R13 raw
   quote and receipt against the pinned inputs.
2. Verify the projection permit with the pinned release key and the exact plan.
   For this harness, the signed v1 permit ID uses a domain-separated 128-bit
   digest of the exact reviewed certificate. This is a guest convention, not a
   deployment of a new permit format or signer. Refuse a permit whose lifetime
   extends past any review evidence.
3. Verify the Rekor bundle offline for the same canonical certificate. Recheck
   the permit clock, then reserve the review nonce, certificate and HSS leaf in
   the review journal. The coordinator separately consumes the permit and
   journals publish intent before the adapter writes the guest selector.

A dead process does not make a consumed review or permit reusable. A crash
between the two journal commits can burn the review without ever touching the
selector. The existing coordinator aborts a pending publication when it still
observes the prior selector, or quarantines to generation zero if publication
was observed. Neither recovery path re-publishes the attempted generation.

## Run without sudo in a disposable Linux guest

With OpenSSL 3.5+, a C compiler, make, Python with cryptography/PyYAML and the
repository's vendor files, run from the repository root:

```bash
python3 tools/build_native.py &&
python3 -m unittest discover -s tests -p test_guest_admission.py -v
```

The suite uses actual fixture PQ, R13 and permit signatures, the reviewed
SQLite journals and coordinator, and child processes that exit without cleanup
at the journal and publication boundaries. It checks that the Rekor wrapper
receives the exact commitment but stubs its Sigstore subprocess. The separately
run Gate 2 synthetic test exercises actual offline Sigstore. No provider or
live witness key is used here.

The pass does not establish actual kernel publication or guest reboot recovery,
power-loss behavior, rollback resistance of the journal storage, or custody of
a live stateful signer. Before considering a real cutover, run the guest
exercise with the actual guest adapter and a reviewed real-evidence path, and
bind the resulting consumer and authority configuration into a new measured
release. The original reviewed runtime and sealed generation remain untouched.
