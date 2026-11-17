from pathlib import Path
import subprocess
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

    def test_host_verdict_requires_both_guest_markers_and_clean_qemu_exit(self):
        passed = ("GATE_3_KERNEL_ADAPTER=PASS tests=15\n"
                  "PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED\n"
                  "GATE_3_VM_INIT=PASS\n")
        self.assertTrue(vm.serial_passed(0, passed))
        self.assertFalse(vm.serial_passed(124, passed))
        self.assertFalse(vm.serial_passed(0, passed.replace("tests=15", "tests=1")))
        self.assertFalse(vm.serial_passed(0, passed + "GATE_3_VM_INIT=FAIL\n"))
        self.assertFalse(vm.serial_passed(0, passed + "[   27.03] Kernel panic - not syncing\n"))
        self.assertFalse(vm.serial_passed(0, passed.replace("GATE_3_VM_INIT=PASS\n", "")))

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

    def test_archive_packs_measurement_and_guest_tools_not_the_old_loader(self):
        files, data = {}, {}

        class Recorder:
            def add(self, *args, **kwargs):
                pass

            def file(self, name, path, mode=None):
                files[name] = (path, mode)

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
        self.assertEqual(data[str(vm.MEASUREMENT_SOURCE)], b"pinned fixture")
        self.assertEqual(files["/init"][0].name, "gate3_vm_init.py")
        self.assertIn("/usr/bin/bpftool", files)
        self.assertIn("/gate3/tools/run_guest_kernel_admission.py", files)
        self.assertNotIn("/d3282/loader", files)
        self.assertNotIn("/d3282/arda.o", data)
