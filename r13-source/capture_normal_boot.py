#!/usr/bin/env python3
"""Collect a local Valinor PCR candidate. No approval, upload, or TPM mutation."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import uuid

BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
CMDLINE = Path("/proc/cmdline")
TEST_BOOT = "45abb5ae-8614-4905-b85f-2c1c036730ad"
PCRS = (0, 1, 4, 7, 8, 9, 11)
KERNEL = "6.12.111-valinor"
CAP = 16 * 1024 * 1024

COMMANDS = {
    "uname": ("/usr/bin/uname", "-r"),
    "pcr": ("/usr/bin/sudo", "-n", "/usr/bin/tpm2_pcrread", "-T", "device:/dev/tpmrm0",
            "sha256:0,1,4,7,8,9,11"),
    "eventlog": ("/usr/bin/sudo", "-n", "/usr/bin/cat",
                 "/sys/kernel/security/tpm0/binary_bios_measurements"),
    "hash": ("/usr/bin/sudo", "-n", "/usr/bin/sha256sum", "--"),
}


class CaptureError(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise CaptureError(why)


def run(name, *args):
    try:
        return subprocess.run((*COMMANDS[name], *args), stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise CaptureError(f"READ_FAILED_{name.upper()}") from exc


def parse_pcrs(raw):
    rows = raw.decode("ascii").strip().splitlines()
    need(bool(rows) and rows[0].strip() == "sha256:", "PCR_BANK")
    result = {}
    for row in rows[1:]:
        if not row.strip():
            continue
        m = re.fullmatch(r"\s*([0-9]+)\s*:\s*0x([0-9a-fA-F]{64})\s*", row)
        need(m is not None, "PCR_FORMAT")
        n = int(m[1])
        need(n not in result, "PCR_DUPLICATE")
        result[n] = m[2].lower()
    need(set(result) == set(PCRS), "PCR_SET")
    return result


def collect(command=run, read=Path.read_bytes):
    boot_raw = read(BOOT_ID)
    boot = boot_raw.decode("ascii").strip()
    try:
        parsed_boot = uuid.UUID(boot)
    except ValueError as exc:
        raise CaptureError("BOOT_ID_FORMAT") from exc
    need(str(parsed_boot) == boot and parsed_boot.int != 0, "BOOT_ID_FORMAT")
    need(boot != TEST_BOOT, "TEST_BOOT_STILL_RUNNING")
    release = command("uname")
    need(release.decode("ascii").strip() == KERNEL, "UNEXPECTED_KERNEL")
    cmdline = read(CMDLINE)
    need(0 < len(cmdline) <= 16384, "CMDLINE_SIZE")
    first = command("pcr")
    pcrs = parse_pcrs(first)
    eventlog = command("eventlog")
    need(0 < len(eventlog) <= CAP, "EVENTLOG_SIZE")
    hashes = command("hash", "/boot/vmlinuz-" + KERNEL, "/boot/initrd.img-" + KERNEL)
    need(parse_pcrs(command("pcr")) == pcrs, "PCR_CHANGED")
    need(read(BOOT_ID) == boot_raw, "BOOT_CHANGED")
    report = {
        "schema": "arda.r13.normal_boot_candidate.v1",
        "status": "CANDIDATE_NOT_APPROVED",
        "boot_id": boot,
        "kernel_release": KERNEL,
        "sha256_pcrs": pcrs,
        "zero_pcrs": [n for n in PCRS if pcrs[n] == "0"*64],
        "eventlog_sha256": hashlib.sha256(eventlog).hexdigest(),
        "boot_file_hashes_are_current_disk_contents": True,
    }
    return {"candidate.json": (json.dumps(report, sort_keys=True, indent=2)+"\n").encode(),
            "live-pcrs.txt": first, "firmware-eventlog.bin": eventlog,
            "boot-id.txt": boot_raw, "kernel-release.txt": release, "cmdline.txt": cmdline,
            "boot-files.sha256": hashes}


def pack(path, data):
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            with tarfile.open(fileobj=output, mode="w:gz") as t:
                for name, raw in data.items():
                    member = tarfile.TarInfo(name)
                    member.mode = 0o600
                    member.size = len(raw)
                    t.addfile(member, io.BytesIO(raw))
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    try:
        data = collect()
        pack(args.out, data)
    except (OSError, ValueError) as exc:
        p.exit(1, f"R13_NORMAL_BOOT_CAPTURE_REFUSED={exc}\n")
    report = json.loads(data["candidate.json"])
    print("R13_NORMAL_BOOT_BASELINE=CANDIDATE_NOT_APPROVED")
    print(f"R13_NORMAL_BOOT_ID={report['boot_id']}")
    print("R13_NORMAL_BOOT_ZERO_PCRS=" + (",".join(map(str, report["zero_pcrs"])) or "none"))
    print(f"R13_NORMAL_BOOT_CAPTURE={args.out}")


if __name__ == "__main__":
    main()
