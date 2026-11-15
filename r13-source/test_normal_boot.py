import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from capture_normal_boot import TEST_BOOT, CaptureError, collect, pack

BOOT = "12345678-1234-4abc-abcd-123456789012"
KERNEL = b"6.12.111-valinor\n"
PCRS = b"sha256:\n" + b"".join(
    f"  {n}: 0x{n+1:02x}".encode() + f"{n+1:02x}".encode()*31 + b"\n"
    for n in (0, 1, 4, 7, 8, 9, 11)
)


class NormalBootTests(unittest.TestCase):
    def fixture(self, boots=(BOOT, BOOT), readings=(PCRS, PCRS)):
        boots, readings = iter(boots), iter(readings)

        def run(*cmd):
            if cmd[0] == "uname":
                return KERNEL
            if cmd[0] == "pcr":
                return next(readings)
            if cmd[0] == "eventlog":
                return b"fixture event log"
            if cmd[0] == "hash":
                return b"".join(
                    f"{hashlib.sha256(x.encode()).hexdigest()}  {x}\n".encode() for x in cmd[1:]
                )
            self.fail(f"Unexpected operation {cmd[0]}")

        def read(path):
            if path.name == "boot_id":
                return next(boots).encode() + b"\n"
            if path.name == "cmdline":
                return b"BOOT_IMAGE=/boot/vmlinuz-6.12.111-valinor ro quiet\n"
            self.fail("Unexpected local read")

        return run, read

    def test_collects_candidate_only_in_a_private_new_archive(self):
        data = collect(*self.fixture())
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "candidate.tar.gz"
            pack(archive, data)
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            with tarfile.open(archive) as t:
                self.assertEqual(set(t.getnames()), {
                    "candidate.json", "live-pcrs.txt", "firmware-eventlog.bin",
                    "boot-id.txt", "kernel-release.txt", "cmdline.txt", "boot-files.sha256",
                })
                report = json.load(t.extractfile("candidate.json"))
                self.assertEqual(report["boot_id"], BOOT)
                self.assertEqual(report["status"], "CANDIDATE_NOT_APPROVED")
                self.assertEqual(report["sha256_pcrs"]["11"], "0c"*32)
            with self.assertRaises(FileExistsError):
                pack(archive, data)

    def test_refuses_test_boot_and_boot_drift(self):
        with self.assertRaisesRegex(CaptureError, "TEST_BOOT_STILL_RUNNING"):
            collect(*self.fixture(boots=(TEST_BOOT,)))
        with self.assertRaisesRegex(CaptureError, "BOOT_CHANGED"):
            collect(*self.fixture(boots=(BOOT, "23456789-1234-4abc-abcd-123456789012")))

    def test_refuses_pcr_drift_but_reports_stable_zero(self):
        zero = PCRS.replace(b"0c"*32, b"00"*32)
        with self.assertRaisesRegex(CaptureError, "PCR_CHANGED"):
            collect(*self.fixture(readings=(PCRS, zero)))
        data = collect(*self.fixture(readings=(zero, zero)))
        self.assertEqual(json.loads(data["candidate.json"])["zero_pcrs"], [11])

    def test_refuses_incomplete_bank(self):
        with self.assertRaisesRegex(CaptureError, "PCR_SET"):
            collect(*self.fixture(readings=(b"sha256:\n  0: 0x"+b"00"*32+b"\n",)))
