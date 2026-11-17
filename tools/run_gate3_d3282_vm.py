#!/usr/bin/env python3
"""Boot Gate 3 with D3282's pinned kernel and initramfs builder, unprivileged."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import sysconfig
from tempfile import TemporaryDirectory, mkdtemp

from tools.run_guest_kernel_admission import MEASUREMENT_SHA256, MEASUREMENT_SOURCE, pinned_bytes


ROOT = Path(__file__).resolve().parents[1]
TEST_FIXTURES = (
    "fixture_crypto.py", "test_quorum.py", "test_r13_bridge.py", "test_r13_quorum.py",
    "test_rekor_commitment.py", "test_guest_admission.py",
)
TOOLS = ("run_guest_kernel_admission.py", "guest_admission.py", "verify_rekor_commitment.py")
EXPECTED = ("GATE_3_KERNEL_ADAPTER=PASS tests=15", "PRODUCTION_AUTHORIZED=FALSE",
            "INTERLOCK=KEEP_CLOSED", "GATE_3_VM_INIT=PASS")


def qemu_command(qemu, kernel, archive, disk, accel):
    if accel not in {"kvm", "tcg"} or "," in str(disk):
        raise ValueError("invalid QEMU scratch path or acceleration mode")
    return [str(qemu), "-accel", accel, "-m", "1024", "-smp", "2", "-nodefaults",
            "-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none",
            "-no-reboot", "-kernel", str(kernel), "-initrd", str(archive),
            "-append", "console=ttyS0 rdinit=/init panic=1 arda_gate3_vm=1",
            "-drive", f"file={disk},format=raw,if=virtio"]


def serial_passed(returncode, serial):
    lines = [s.strip() for s in serial.splitlines()]
    return (returncode == 0 and all(lines.count(marker) == 1 for marker in EXPECTED)
            and not any(s.startswith("GATE_3_VM_INIT=FAIL") or "Kernel panic" in s for s in lines))


def load_d3282(directory):
    spec = importlib.util.spec_from_file_location("_arda_d3282_pack", directory / "pack.py")
    pack = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = pack
    sys.path.insert(0, str(directory))
    try:
        spec.loader.exec_module(pack)
    finally:
        sys.path.pop(0)
    pack.verify_manifest()
    return pack


def executable(name, override=None):
    candidate = override or shutil.which(name) or Path("/usr/sbin") / name
    # Preserve argv[0] for multicall binaries such as modprobe -> kmod.
    path = Path(candidate).absolute()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"not an executable: {path}")
    return path


def module_paths(output):
    paths = []
    for line in output.splitlines():
        fields = line.split()
        if not fields or (len(fields) == 2 and fields[0] == "builtin"):
            continue
        if len(fields) != 2 or fields[0] != "insmod" or not Path(fields[1]).is_absolute():
            raise ValueError(f"unsupported module dependency record: {line}")
        paths.append(Path(fields[1]))
    return paths


def guest_modules(release):
    expected_root = (Path("/lib/modules") / release).resolve()
    config_path = Path("/boot") / f"config-{release}"
    config = set(config_path.read_text().splitlines()) if config_path.is_file() else set()
    if config and "CONFIG_FS_VERITY=y" not in config:
        raise ValueError(f"pinned kernel config lacks CONFIG_FS_VERITY=y: {config_path}")
    paths = {}
    targets = [("virtio_pci", "VIRTIO_PCI"), ("virtio_blk", "VIRTIO_BLK"), ("ext4", "EXT4_FS")]
    if "CONFIG_CRYPTO_SHA256=m" in config:
        targets.append(("sha256_generic", "CRYPTO_SHA256"))
    for name, symbol in targets:
        if f"CONFIG_{symbol}=y" in config:
            continue
        if config and f"CONFIG_{symbol}=m" not in config:
            raise ValueError(f"pinned kernel config lacks {symbol}: {config_path}")
        modprobe = executable("modprobe")
        output = subprocess.check_output(
            [modprobe, "-C", "/dev/null", "--set-version", release, "--show-depends", name],
            text=True, timeout=15,
        )
        for path in module_paths(output):
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(expected_root):
                raise ValueError(f"module outside kernel release: {path}")
            paths[resolved] = path
    return list(paths.values())


def copy_python_dependencies(add):
    for name in ("cryptography", "yaml", "cffi", "_cffi_backend", "pycparser", "typing_extensions"):
        spec = importlib.util.find_spec(name)
        if spec is None:
            if name in {"cryptography", "yaml"}:
                raise ValueError(f"Debian system Python is missing {name}")
            continue
        for directory in spec.submodule_search_locations or ():
            base = Path(directory)
            for path in sorted(base.rglob("*")):
                if path.is_file() and path.suffix in {".py", ".so"}:
                    add(f"/gate3/pydeps/{name}/{path.relative_to(base)}", path)
        if not spec.submodule_search_locations:
            source = Path(spec.origin)
            add(f"/gate3/pydeps/{source.name}", source)


def build_initramfs(pack, stage, bpftool, measurement):
    builder = pack.Image()
    for name in ("/dev", "/proc", "/sys", "/run", "/tmp", "/etc", "/root", "/work"):
        builder.add(name, stat.S_IFDIR | (0o1777 if name == "/tmp" else 0o755))
    builder.add("/dev/console", stat.S_IFCHR | 0o600, major=5, minor=1)
    builder.add("/dev/null", stat.S_IFCHR | 0o666, major=1, minor=3)
    builder.data("/etc/passwd", b"root:x:0:0:root:/root:/bin/false\n")
    builder.data("/etc/group", b"root:x:0:\n")
    builder.data("/etc/os-release", b'ID=valinor\nPRETTY_NAME="Valinor Gate 3 disposable guest"\n')
    builder.data(str(MEASUREMENT_SOURCE), measurement)
    builder.file("/init", ROOT / "tools/gate3_vm_init.py", 0o555)
    libraries = {str(pack.INTERPRETER)}

    def add(dest, path, executable_mode=False):
        builder.file(dest, path, 0o555 if executable_mode else 0o644)
        if executable_mode or path.suffix == ".so":
            libraries.update(str(p) for p in pack.deps(path))

    for name in ("python3", "mount", "umount", "unshare", "systemd-detect-virt",
                 "openssl", "fsverity", "bpftool"):
        path = Path("/usr/bin/python3") if name == "python3" else executable(
            name, bpftool if name == "bpftool" else None)
        add(f"/usr/bin/{name}", path, True)
    modules = guest_modules(pack.RELEASE_NAME)
    if modules:
        # kmod dispatches by argv[0], including when copied as insmod.
        add("/usr/bin/insmod", executable("insmod"), True)
        for path in modules:
            builder.file(str(path), path)
    builder.data("/gate3/modules", "".join(f"{p}\n" for p in modules).encode())

    stdlib = Path(sysconfig.get_path("stdlib"))
    if stdlib.parent != Path("/usr/lib"):
        raise ValueError("use /usr/bin/python3 to match the guest interpreter")
    excluded = {"site-packages", "dist-packages", "__pycache__", "test", "tests",
                "ensurepip", "idlelib", "tkinter", "turtledemo", "venv"}
    for path in sorted(stdlib.rglob("*")):
        if path.is_file() and not (set(path.relative_to(stdlib).parts) & excluded):
            add(str(path), path)
    copy_python_dependencies(add)
    runtime = json.loads((ROOT / "REVIEWED_SOURCE_FILES.json").read_bytes())["files"]
    for rel in ("REVIEWED_SOURCE_FILES.json", "build/BUILD.json",
                *(p["path"] for p in runtime), *(f"tests/{name}" for name in TEST_FIXTURES),
                *(f"tools/{name}" for name in TOOLS),
                *(str(p.relative_to(ROOT)) for p in (ROOT / "arda_quorum").glob("*.py"))):
        add("/gate3/" + rel, ROOT / rel)
    for name in ("hss-verify", "test-hss-sign"):
        add(f"/gate3/build/{name}", ROOT / "build" / name, True)
    for name in sorted(libraries):
        builder.file(name, name, 0o555)
        if name.startswith("/usr/lib/") and Path(name.removeprefix("/usr")).exists():
            builder.file(name.removeprefix("/usr"), name, 0o555)
        if name.startswith("/lib/") and Path("/usr" + name).exists():
            builder.file("/usr" + name, name, 0o555)
    archive = stage / "gate3.cpio.gz"
    builder.save(archive)
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--d3282", type=Path, required=True)
    parser.add_argument("--measurement-source", type=Path, default=MEASUREMENT_SOURCE)
    parser.add_argument("--bpftool", type=Path)
    parser.add_argument("--tcg", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0 or platform.machine() != "x86_64":
        raise ValueError("run as the ordinary x86-64 Debian user, without sudo")
    if Path(sysconfig.get_path("stdlib")).parent != Path("/usr/lib"):
        raise ValueError("use /usr/bin/python3")
    if not args.tcg and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise ValueError("KVM unavailable to this user, rerun with --tcg")
    measurement = pinned_bytes(args.measurement_source, MEASUREMENT_SHA256)
    qemu = executable("qemu-system-x86_64")
    mkfs = executable("mkfs.ext4")
    pack = load_d3282(args.d3282.resolve(strict=True))
    accel = "tcg" if args.tcg else "kvm"
    evidence = Path(mkdtemp(prefix="gate3-vm-evidence-", dir=Path.cwd()))
    serial = evidence / "guest.serial.log"
    print(f"GATE_3_VM_EVIDENCE={evidence}", flush=True)
    with TemporaryDirectory(prefix="arda_gate3_vm_") as tmp:
        stage = Path(tmp)
        kernel = stage / "kernel"
        kernel.write_bytes(pack.checked(Path("/boot") / f"vmlinuz-{pack.RELEASE_NAME}",
                                        pack.KERNEL_SHA, "KERNEL"))
        archive = build_initramfs(pack, stage, args.bpftool, measurement)
        disk = stage / "fixture.ext4"
        with disk.open("xb") as handle:
            handle.truncate(128 * 1024 * 1024)
        subprocess.run([mkfs, "-q", "-F", "-O", "verity", disk], check=True, timeout=30)
        with serial.open("xb") as log:
            try:
                rc = subprocess.run(qemu_command(qemu, kernel, archive, disk, accel),
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=480 if args.tcg else 180).returncode
            except subprocess.TimeoutExpired:
                rc = 124
        raw = serial.read_bytes()
        decoded = raw.decode(errors="replace")
        passed = serial_passed(rc, decoded)
        receipt = dict(passed=passed, qemu_exit=rc, accel=accel, serial_sha256=hashlib.sha256(raw).hexdigest(),
                       kernel_sha256=pack.KERNEL_SHA, initramfs_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                       production_authorized=False, interlock="KEEP_CLOSED")
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("\n".join(decoded.splitlines()[-45:]))
    print("GATE_3_VM_HOST_RECEIPT=" + ("PASS" if passed else "FAIL"))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"GATE_3_VM_HOST_ERROR={exc}") from exc
