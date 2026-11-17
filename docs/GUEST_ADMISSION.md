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

## Opt-in kernel-adapter acceptance

Inside a disposable x86-64 Linux VM such as the D3282 guest, build the
fixtures as the normal user and run the read-only check:

```bash
python3 tools/build_native.py &&
python3 -m tools.run_guest_kernel_admission --preflight
```

The guest needs cgroup v2, bpftool, fsverity, a filesystem supporting fs-verity
for the fixture directory (default /var/tmp), and the reviewed release's
proof_file_measurement.py. The check reports its exact default path. If a
byte-identical copy is elsewhere, pass `--measurement-source /absolute/path` to
both commands that invoke the runner. A different hash is refused. Build and
run the Python interpreter with the same cryptography/PyYAML dependencies.

When the preflight reports ready, execute **inside that VM only**:

```bash
sudo unshare --mount --propagation private -- +  python3 -m tools.run_guest_kernel_admission
```

Pass `--work-parent /absolute/guest/path` if /var/tmp is on a filesystem that
cannot enable fs-verity. The runner uses a fresh bpffs in the private mount
namespace and empty test cgroups. It creates disposable maps and an isolated
measured ledger, uses the unmodified reviewed BpfProjectionAdapter, and reads
back the actual map contents after publication and recovery. It does not
open the production pins or database, load or attach an LSM program, or
authorize a deployment. The stage transaction only seeds the fixture ledger.

Expect 15 cases and `GATE_3_KERNEL_ADAPTER=PASS`. This is actual kernel-map,
scope and fs-verity coverage, not attached LSM enforcement or a reboot test.
The signatures and R13 capture use disposable fixtures bound to this boot ID,
and the Rekor subprocess is stubbed just as in the file-backed suite.

### Boot from the archived D3282 setup

D3282 launches short-lived initramfs boots, not an installed VM disk. This
separate launcher reuses the verified packer's archive builder and pinned
kernel. It does not run D3282's systemd test or load its LSM object. It adds
the Gate 3 dependencies, a different init, and one newly created ext4 image
with fs-verity enabled. QEMU gets no host disk, host shared filesystem,
network adapter or monitor. The scratch image and initramfs are discarded
after the run. The host retains the serial log and a JSON receipt.

From this repository on the Debian host, **without sudo**:

```bash
/usr/bin/python3 tools/build_native.py &&
/usr/bin/python3 -m tools.run_gate3_d3282_vm \
  --d3282 "$HOME/ainur-restoration-v1/Valinor-D3.28.2"
```

If bpftool is not installed, download and extract the official Debian
package to a temporary directory and provide its binary with
`--bpftool /absolute/path/to/bpftool`. No host package installation is
required. Use `--tcg` if the ordinary user cannot open /dev/kvm.

Expect `GATE_3_VM_HOST_RECEIPT=PASS` after `GATE_3_KERNEL_ADAPTER=PASS tests=15`.
A build or QEMU boot alone does not count as a pass.
