"""Opt-in acceptance tests using the reviewed BPF adapter and disposable maps."""
import argparse
import base64
import hashlib
from importlib.machinery import ModuleSpec
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import ModuleType
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MEASUREMENT_SOURCE = Path("/usr/lib/arda/releases/campaign-d-6e3159ece165402e/"
                          "arda_os/backend/services/proof_file_measurement.py")
MEASUREMENT_SHA256 = "f0154a16f10b4d182323564dd37b0ab682edaa612b9a0ff71bde68e93577c769"
BOOT = Path("/proc/sys/kernel/random/boot_id")
CGROUP = Path("/sys/fs/cgroup")
BINARIES = ("bpftool", "fsverity", "mount", "umount", "systemd-detect-virt")
CLOSED = {"production_authorized": False, "interlock": "KEEP_CLOSED"}


def pinned_bytes(path, expected):
    with path.open("rb") as handle:
        raw = handle.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"runtime hash mismatch: {path}")
    return raw


def preflight(source):
    blockers = [name for name in BINARIES if not shutil.which(name)]
    kind = "unknown"
    if "systemd-detect-virt" not in blockers:
        run = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True,
                             text=True, timeout=5, check=False)
        kind = run.stdout.strip()
        if run.returncode or kind in {"", "none"}:
            blockers.append("disposable_vm_required")
    if platform.machine() != "x86_64" or not (CGROUP / "cgroup.controllers").is_file():
        blockers.append("x86_64_cgroup_v2_required")
    try:
        pinned_bytes(source, MEASUREMENT_SHA256)
    except (OSError, ValueError) as exc:
        blockers.append("measurement_source")
        measurement = str(exc)
    else:
        measurement = "pinned"
    if not all((ROOT / "build" / name).is_file()
               for name in ("BUILD.json", "hss-verify", "test-hss-sign")):
        blockers.append("native_fixture_build")
    return dict(ready=not blockers, blockers=blockers, vm=kind, measurement=measurement,
                measurement_path=str(source), **CLOSED)


def load_reviewed_runtime(source):
    runtime = ROOT / "reviewed-runtime"
    index = json.loads((ROOT / "REVIEWED_SOURCE_FILES.json").read_bytes())["files"]
    for entry in index:
        pinned_bytes(ROOT / entry["path"], entry["sha256"])
    raw = pinned_bytes(source, MEASUREMENT_SHA256)
    sys.path[:0] = [str(runtime), str(ROOT / "tests")]
    module_id = "backend.services.proof_file_measurement"
    module = ModuleType(module_id)
    module.__file__ = str(source)
    module.__package__ = "backend.services"
    module.__spec__ = ModuleSpec(module_id, loader=None, origin=str(source))
    sys.modules[module_id] = module
    exec(compile(raw, str(source), "exec"), module.__dict__)
    return module


def command(*args):
    return subprocess.run(args, check=True, timeout=25, stdout=subprocess.DEVNULL)


def kernel_tests(work, pin_mount, measurement, boot_id):
    from backend.services.measured_identity import MeasuredProjectionGenerationStore
    from backend.services.projection_bpf import (
        BpfProjectionAdapter, CONTRACTS, MAP_NAMES, cgroup_kernel_id, manifest_digest,
    )
    from backend.services.projection_journal import Journal
    import test_guest_admission as model
    import test_quorum
    from arda_quorum.quorum import DOMAIN, canonical, sha
    from tools.guest_admission import GuestAdmission

    def seed_map(path, key, value):
        command("bpftool", "map", "update", "pinned", str(path),
                "key", "hex", *[f"{b:02x}" for b in key],
                "value", "hex", *[f"{b:02x}" for b in value])

    class KernelAdmissionTests(model.GuestAdmissionTests):
        @classmethod
        def setUpClass(cls):
            super().setUpClass(boot_id=boot_id)

        def prepare_backend(self):
            # Case data, journals and all six pins are fresh. The cgroup is empty.
            self.case = self.root
            self.pins = pin_mount / self.case.name
            self.pins.mkdir(mode=0o700)
            self.addCleanup(self.clear_pins)
            self.scope = CGROUP / ("arda_gate3_" + self.case.name)
            self.scope.mkdir(mode=0o700)
            self.addCleanup(self.scope.rmdir)
            self.plan.update(scope_id=cgroup_kernel_id(self.scope), scope_path=str(self.scope))

            policy_gen = "gate3-disposable-kernel-fixture"
            prefix = hashlib.sha256(policy_gen.encode()).digest()[:8]
            for name, (ks, vs) in CONTRACTS.items():
                kind = "hash" if name in {"active_generation_map", "measured_exec_map",
                                          "verity_identity_map"} else "array"
                capacity = 8192 if kind == "hash" else 1
                command("bpftool", "map", "create", str(self.pins / name), "type", kind,
                        "key", str(ks), "value", str(vs), "entries", str(capacity),
                        "name", MAP_NAMES[name][:15])
            seed_map(self.pins / "state_map", bytes(4), struct.pack("<I", 3))
            seed_map(self.pins / "policy_state_map", bytes(4), prefix + struct.pack("<II", 1, 1))
            seed_map(self.pins / "active_generation_map", struct.pack("<Q", self.plan["scope_id"]),
                     struct.pack("<Q", self.plan["prior_generation"]))

            self.manifest_dir = self.case / "manifests"
            self.manifest_dir.mkdir(mode=0o700)
            self.db = self.case / "measured.sqlite3"
            artifact = self.case / "measured-fixture"
            artifact.write_bytes(b"ARDA Gate 3 disposable measured fixture\n")
            command("fsverity", "enable", str(artifact))
            measured = measurement.open_measured(str(artifact))
            try:
                algorithm, digest = measured.algorithm, measured.digest.lower()
            finally:
                measured.close()
            manifest = dict(schema_version="arda.measured_manifest.v1",
                            manifest_id=self.plan["manifest_id"], generation=self.plan["generation"],
                            node_id=self.plan["node_id"], policy_generation=policy_gen,
                            entries=[dict(path=str(artifact), fs_verity_algorithm_id=algorithm,
                                          fs_verity_digest=digest)])
            self.plan["manifest_digest"] = manifest_digest(manifest)
            (self.manifest_dir / "fixture.json").write_bytes(canonical(manifest))
            stage = Journal(self.case / "staging-journal", boot_id=lambda: boot_id,
                            clock=lambda: self.now)
            store = MeasuredProjectionGenerationStore(str(self.db))
            try:
                with stage.bootstrap(dict(self.plan, action="stage")) as tx:
                    store.stage(dict(
                        **{k: self.plan[k] for k in ("manifest_id", "node_id", "generation",
                                                     "manifest_digest")},
                        cgroup_id=str(self.plan["scope_id"]), cgroup_kernel_id=self.plan["scope_id"],
                        enforcement_mode="scoped_strict", policy_generation=policy_gen,
                        checked_paths=[str(artifact)], loader_digest_specs=[f"{algorithm}:{digest}"],
                    ))
                    tx.prepared({})
                    tx.publish_intent()
                    tx.published()
                    tx.commit()
            finally:
                store.close()
            self.expected["manifest_digest"] = self.plan["manifest_digest"]
            self.cert["proposal"].update(self.expected)
            for vote in self.cert["votes"]:
                payload = vote["payload"]
                payload["proposal_sha256"] = sha(canonical(self.cert["proposal"]))
                sig = test_quorum.QuorumTests.signers.sign(payload["provider"],
                                                         DOMAIN + canonical(payload))
                vote["signature_b64"] = base64.b64encode(sig).decode()

        def clear_pins(self):
            for path in self.pins.iterdir():
                path.unlink()
            self.pins.rmdir()

        def open_guest(self):
            # Opens new DB and pin handles even in the crashed/restarted process.
            test = self
            store = MeasuredProjectionGenerationStore(str(self.db))
            self.addCleanup(store.close)

            class KernelGuest(GuestAdmission):
                def _open_selector(self, initial_generation):
                    adapter = BpfProjectionAdapter(store, pin_root=test.pins,
                                                   manifest_dir=test.manifest_dir)
                    test.addCleanup(adapter.close)
                    return adapter

            return KernelGuest(
                self.root, boot_id=boot_id, clock=lambda: self.now,
                scope_id=self.plan["scope_id"], scope_path=self.plan["scope_path"],
                initial_generation=13, backends=test_quorum.QuorumTests.backend,
                release_key=self.release_key.public_key(),
            )

        def test_expiry_before_selector_write_aborts_and_keeps_prior(self):
            publish = self.guest.selector.publish

            def expire(scope, generation):
                self.now = 1100
                return publish(scope, generation)

            with patch.object(self.guest.selector, "publish", expire):
                with self.assertRaisesRegex(ValueError, "permit_expired_or_future"):
                    self.apply()
            self.assertEqual(self.guest.active_generation(), 13)
            row, = self.guest.journal.rows()
            # Unlike the file-only model, the real adapter has prepared allow rows.
            self.assertEqual(row["phase"], "DIRTY")
            self.assertEqual(self.guest.recover(row["txid"])["phase"], "ABORTED")
            self.assertEqual(self.guest.active_generation(), 13)
            for key in ("measured_exec_map", "verity_identity_map"):
                self.assertEqual(self.guest.selector.maps[key].rows(), {})

        def test_kernel_readback_matches_committed_store_and_inventory(self):
            self.apply()
            self.assertEqual(self.guest.active_generation(), 14)
            row, = self.guest.journal.rows()
            self.assertEqual(row["phase"], "COMMITTED")
            self.assertEqual(self.guest.selector.store.get_record(self.plan["manifest_id"])["state"],
                             "active")
            inventory = row["inventory"]["rows"]
            self.assertEqual({item["map"] for item in inventory},
                             {"measured_exec_map", "verity_identity_map"})
            self.assertEqual(len(inventory), 2)
            for item in inventory:
                m = self.guest.selector.maps[item["map"]]
                self.assertEqual(m.info["id"], item["map_id"])
                self.assertEqual(m.read(bytes.fromhex(item["key"])), bytes.fromhex(item["value"]))

    # Keep all fixture journals and files on the guest's explicitly selected volume.
    with patch.object(model.tempfile, "tempdir", str(work)):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(KernelAdmissionTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true", help="read-only prerequisite check")
    parser.add_argument("--measurement-source", type=Path, default=MEASUREMENT_SOURCE)
    parser.add_argument("--work-parent", type=Path, default=Path("/var/tmp"),
                        help="guest directory on a filesystem supporting fs-verity")
    args = parser.parse_args()
    report = preflight(args.measurement_source)
    print(json.dumps(report, sort_keys=True), flush=True)
    if not report["ready"] or args.preflight:
        return int(not report["ready"])
    if os.geteuid() != 0 or os.stat("/proc/self/ns/mnt").st_ino == os.stat("/proc/1/ns/mnt").st_ino:
        raise SystemExit("Run explicitly inside the disposable guest in a new private mount namespace")
    measurement = load_reviewed_runtime(args.measurement_source)
    with TemporaryDirectory(prefix="arda_gate3_", dir=args.work_parent.resolve(strict=True)) as temp:
        work = Path(temp)
        probe = work / "verity-probe"
        probe.write_bytes(b"ARDA Gate 3 fs-verity probe\n")
        command("fsverity", "enable", str(probe))
        measurement.open_measured(str(probe)).close()
        probe.unlink()
        pins = work / "pins"
        pins.mkdir(mode=0o700)
        command("mount", "-t", "bpf", "-o", "nosuid,nodev,noexec", "bpf", str(pins))
        try:
            result = kernel_tests(work, pins, measurement, BOOT.read_text().strip())
        finally:
            command("umount", str(pins))
    if result.wasSuccessful() and result.testsRun:
        print(f"GATE_3_KERNEL_ADAPTER=PASS tests={result.testsRun}")
        print("PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
