from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import gate3_vm_init
from tools import run_gate3_d3282_vm as vm


class Gate3VmLaunchTests(unittest.TestCase):
    def test_executable_preserves_multicall_symlink_name(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            kmod = root / "kmod"
            kmod.write_text("#!/bin/sh\ncase \"$0\" in */modprobe) exit 0;; esac\nexit 67\n")
            kmod.chmod(0o755)
            alias = root / "modprobe"
            alias.symlink_to(kmod)
            with patch.object(vm.shutil, "which", return_value=str(alias)):
                path = vm.executable("modprobe")
            run = subprocess.run([path, "-C", "/dev/null", "--show-depends", "virtio_blk"],
                                 check=False, timeout=5)
            self.assertEqual(run.returncode, 0)
            self.assertEqual(path, alias)

    def test_qemu_has_no_host_mount_or_network_device(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            disk = root / "fixture.ext4"
            command = vm.qemu_command("qemu-system-x86_64", root / "kernel",
                                      root / "initramfs", disk, "kvm")
        self.assertIn("-nodefaults", command)
        self.assertIn("-no-reboot", command)
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertEqual(command.count("-drive"), 1)
        self.assertEqual(command[command.index("-drive") + 1],
                         f"file={disk},format=raw,if=virtio")
        self.assertTrue(all(x not in command for x in ("-virtfs", "-fsdev", "-netdev")))

    def test_format_pins_ext4_block_size_to_the_verity_merkle_block_size(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            mkfs = root / "mkfs.ext4"
            mkfs.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$0.args"\n')
            mkfs.chmod(0o755)
            disk = root / "fixture.ext4"
            vm.format_fixture_disk(mkfs, disk)
            args = (root / "mkfs.ext4.args").read_text().splitlines()
            self.assertEqual(disk.stat().st_size, 128 * 1024 * 1024)
            self.assertIn("-b", args)
            self.assertEqual(args[args.index("-b") + 1], "4096")
            self.assertEqual(args[args.index("-O") + 1], "verity")
            self.assertEqual(args[-1], str(disk))

    def test_missing_virtio_module_selects_pinned_kernel_nvme_support(self):
        config = {"CONFIG_EXT4_FS=y", "CONFIG_FS_VERITY=y", "CONFIG_VIRTIO_PCI=y",
                  "CONFIG_VIRTIO_BLK=m", "CONFIG_BLK_DEV_NVME=y"}

        def missing(name):
            raise FileNotFoundError(name)

        storage, modules = vm.choose_storage(config, missing)
        self.assertEqual(storage, "nvme")
        self.assertEqual(modules, [])

    def test_nvme_qemu_and_guest_agree_on_the_single_disposable_device(self):
        command = vm.qemu_command("qemu", Path("/tmp/kernel"), Path("/tmp/init"),
                                  Path("/tmp/fixture.ext4"), "kvm", "nvme")
        cmdline = command[command.index("-append") + 1]
        self.assertIn("nvme,drive=gate3_fixture,serial=ARDA_GATE3_FIXTURE", command)
        self.assertEqual(command.count("-drive"), 1)
        self.assertEqual(gate3_vm_init.disk_for_cmdline(cmdline), Path("/dev/nvme0n1"))
        with self.assertRaises(ValueError):
            gate3_vm_init.disk_for_cmdline(cmdline + " arda_gate3_disk=ide")

    def test_ext4_is_required_regardless_of_the_disk_frontend(self):
        with self.assertRaisesRegex(ValueError, "EXT4_FS"):
            vm.choose_storage({"CONFIG_FS_VERITY=y", "CONFIG_BLK_DEV_NVME=y"}, lambda _: [])

    def test_guest_uses_generic_crc32c_without_requiring_host_cpu_features(self):
        config = {"CONFIG_FS_VERITY=y", "CONFIG_EXT4_FS=m", "CONFIG_VIRTIO_PCI=y",
                  "CONFIG_VIRTIO_BLK=m"}
        virtio = Path("/lib/modules/fixture/virtio_blk.ko.xz")
        accelerated = Path("/lib/modules/fixture/arch/x86/crypto/crc32c-intel.ko.xz")
        generic = Path("/lib/modules/fixture/kernel/crypto/crc32c_generic.ko.xz")
        jbd2 = Path("/lib/modules/fixture/jbd2.ko.xz")
        ext4 = Path("/lib/modules/fixture/ext4.ko.xz")
        drivers = {"ext4": [accelerated, generic, jbd2, ext4], "virtio_blk": [virtio]}
        self.assertEqual(vm.choose_storage(config, drivers.__getitem__),
                         ("virtio", [virtio, generic, jbd2, ext4]))
        drivers["ext4"].remove(generic)
        self.assertEqual(vm.choose_storage(config, drivers.__getitem__),
                         ("virtio", [virtio, accelerated, jbd2, ext4]))
        self.assertEqual(vm.choose_storage(config | {"CONFIG_CRYPTO_CRC32C=y"},
                                           drivers.__getitem__),
                         ("virtio", [virtio, jbd2, ext4]))

    def test_ide_is_a_fallback_and_mounts_only_the_fixture_disk(self):
        config = {"CONFIG_FS_VERITY=y", "CONFIG_EXT4_FS=y", "CONFIG_ATA_PIIX=y",
                  "CONFIG_BLK_DEV_SD=y"}
        storage, modules = vm.choose_storage(config, lambda _: [])
        self.assertEqual((storage, modules), ("ide", []))
        cmd = vm.qemu_command("qemu", Path("/tmp/kernel"), Path("/tmp/init"),
                              Path("/tmp/fixture.ext4"), "kvm", storage)
        self.assertEqual(cmd[cmd.index("-machine") + 1], "pc")
        self.assertEqual(cmd[cmd.index("-drive") + 1], "file=/tmp/fixture.ext4,format=raw,if=ide")
        self.assertEqual(gate3_vm_init.disk_for_cmdline(cmd[cmd.index("-append") + 1]),
                         Path("/dev/sda"))

    def test_host_verdict_requires_both_guest_markers_and_clean_qemu_exit(self):
        passed = ("GATE_3_KERNEL_ADAPTER=PASS tests=15\n"
                  "PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED\n"
                  "GATE_3_VM_INIT=PASS\nGATE_3_VM_ENTROPY=READY\n")
        self.assertTrue(vm.serial_passed(0, passed))
        self.assertFalse(vm.serial_passed(124, passed))
        self.assertFalse(vm.serial_passed(0, passed.replace("tests=15", "tests=1")))
        self.assertFalse(vm.serial_passed(0, passed + "GATE_3_VM_INIT=FAIL\n"))
        self.assertFalse(vm.serial_passed(0, passed + "[   27.03] Kernel panic - not syncing\n"))
        self.assertFalse(vm.serial_passed(0, passed.replace("GATE_3_VM_INIT=PASS\n", "")))
        self.assertFalse(vm.serial_passed(0, passed.replace("GATE_3_VM_ENTROPY=READY\n", "")))

    def test_modprobe_output_never_executes_install_rules(self):
        self.assertEqual(vm.module_paths("builtin virtio\ninsmod /lib/modules/a.ko\n"),
                         [Path("/lib/modules/a.ko")])
        with self.assertRaises(ValueError):
            vm.module_paths("install /bin/unexpected\n")

    def test_init_refuses_non_pid1_without_mounting_anything(self):
        with patch.object(gate3_vm_init.os, "getpid", return_value=42), \
                patch.object(gate3_vm_init, "command") as launch:
            self.assertEqual(gate3_vm_init.supervise(), 1)
        launch.assert_not_called()

    def test_guest_crypto_works_with_no_legacy_provider_module(self):
        code = """
import os
assert os.environ.get('CRYPTOGRAPHY_OPENSSL_NO_LEGACY') == '1'
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

message = b'Gate 3 disposable crypto probe'
ed = ed25519.Ed25519PrivateKey.generate()
ed.public_key().verify(ed.sign(message), message)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pad = padding.PKCS1v15()
key.public_key().verify(key.sign(message, pad, hashes.SHA256()), message,
                        pad, hashes.SHA256())
"""
        with TemporaryDirectory() as empty_modules:
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code],
                                    env={**gate3_vm_init.GUEST_ENV,
                                         "OPENSSL_MODULES": empty_modules},
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_archive_packs_measurement_and_guest_tools_not_the_old_loader(self):
        files, data, seeds = {}, {}, []

        class Recorder:
            def add(self, *args, **kwargs):
                pass

            def file(self, name, path, mode=None):
                files[name] = (path, mode)
                if name == "/gate3/boot.seed":
                    seeds.append(path.read_bytes())

            def data(self, name, raw):
                data[name] = raw

            def save(self, path):
                path.write_bytes(b"test archive")

        pack = SimpleNamespace(Image=Recorder, INTERPRETER="/fake/ld.so",
                               RELEASE_NAME="fixture", deps=lambda _path: [])
        with TemporaryDirectory() as d, \
                patch.object(vm, "executable", return_value=Path("/fake/bin")), \
                patch.object(vm, "guest_modules", return_value=[]), \
                patch.object(vm.sysconfig, "get_path", return_value="/usr/lib/fixture-python"), \
                patch.object(vm, "copy_python_dependencies"):
            archive = vm.build_initramfs(pack, Path(d), None, b"pinned fixture")
            self.assertEqual(archive.read_bytes(), b"test archive")
            init_path, _ = files["/init"]
            self.assertEqual(init_path.read_bytes()[:4], b"\x7fELF")
            host_run = subprocess.run([init_path], capture_output=True, timeout=5)
            self.assertNotEqual(host_run.returncode, 0)
            self.assertIn(b"guest PID 1 required", host_run.stderr)
            self.assertFalse((Path(d) / "boot.seed").exists())
            vm.build_initramfs(pack, Path(d), None, b"pinned fixture")
        self.assertEqual(data[str(vm.MEASUREMENT_SOURCE)], b"pinned fixture")
        self.assertEqual(files["/gate3/init.py"][0].name, "gate3_vm_init.py")
        self.assertEqual(files["/gate3/boot.seed"][1], 0o400)
        self.assertEqual([len(seed) for seed in seeds], [32, 32])
        self.assertNotEqual(*seeds)
        self.assertIn("/usr/bin/bpftool", files)
        self.assertIn("/gate3/tools/run_guest_kernel_admission.py", files)
        self.assertNotIn("/d3282/loader", files)
        self.assertNotIn("/d3282/arda.o", data)
