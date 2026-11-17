#!/usr/bin/python3 -I
"""PID 1 for the separate Gate 3 initramfs. Never run on the host."""
import ctypes
import os
from pathlib import Path
import stat
import subprocess
import sys
import time


GUEST_FLAG = "arda_gate3_vm=1"
GUEST_ROOT = Path("/gate3")
GUEST_ENV = {"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "HOME": "/root",
             "LANG": "C", "TMPDIR": "/tmp", "OPENSSL_CONF": "/dev/null"}


def command(*argv):
    subprocess.run(argv, check=True, timeout=20, env=GUEST_ENV)


def guest_flag():
    return GUEST_FLAG in Path("/proc/cmdline").read_text().split()


def run_admission():
    if os.getpid() == 1 or not guest_flag() or not GUEST_ROOT.is_dir():
        raise ValueError("diskless Gate 3 child required")
    sys.path[:0] = [str(GUEST_ROOT), str(GUEST_ROOT / "pydeps")]
    from tools import run_guest_kernel_admission
    sys.argv = ["run_guest_kernel_admission", "--work-parent", "/work"]
    return run_guest_kernel_admission.main()


def supervise():
    if os.getpid() != 1:
        print("GATE_3_VM_INIT=FAIL guest PID 1 required", file=sys.stderr)
        return 1
    if Path("/proc/cmdline").is_file() and not guest_flag():
        print("GATE_3_VM_INIT=FAIL guest boot flag missing", file=sys.stderr)
        return 1
    try:
        command("/usr/bin/mount", "-n", "-t", "proc", "proc", "/proc")
        if not guest_flag():
            raise ValueError("guest boot flag missing")
        Path("/etc/mtab").symlink_to("/proc/self/mounts")
        command("/usr/bin/mount", "-n", "-t", "sysfs", "sysfs", "/sys")
        command("/usr/bin/mount", "-n", "-t", "devtmpfs", "devtmpfs", "/dev")
        command("/usr/bin/mount", "-n", "-t", "cgroup2", "cgroup2", "/sys/fs/cgroup")
        command("/usr/bin/systemd-detect-virt", "--vm")
        for module in (GUEST_ROOT / "modules").read_text().splitlines():
            command("/usr/bin/insmod", module)
        disk = Path("/dev/vda")
        for _ in range(20):
            if disk.exists():
                break
            time.sleep(0.25)
        if not stat.S_ISBLK(disk.stat().st_mode):
            raise ValueError("disposable ext4 block device unavailable")
        command("/usr/bin/mount", "-n", "-t", "ext4", "-o", "nodev,nosuid,noexec",
                str(disk), "/work")
        try:
            subprocess.run(
                ["/usr/bin/unshare", "--mount", "--propagation", "private", "--",
                 "/usr/bin/python3", "-I", "-B", "/init", "run"],
                timeout=360, check=True, env=GUEST_ENV, cwd=GUEST_ROOT,
            )
        finally:
            command("/usr/bin/umount", "/work")
        print("GATE_3_VM_INIT=PASS", flush=True)
    except Exception as exc:
        print(f"GATE_3_VM_INIT=FAIL {type(exc).__name__}: {exc}", flush=True)
    os.sync()
    ctypes.CDLL(None, use_errno=True).reboot(0x4321FEDC)  # Linux RB_POWER_OFF
    return 1  # PID 1 must not report success if guest power-off fails.


if __name__ == "__main__":
    raise SystemExit(run_admission() if sys.argv[1:] == ["run"] else supervise())
