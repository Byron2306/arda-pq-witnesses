"""Unprivileged tests for the opt-in guest runner's pre-write checks."""
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools import run_guest_kernel_admission as runner


class KernelRunnerPreflightTests(unittest.TestCase):
    def test_runtime_import_rejects_unpinned_bytes(self):
        with TemporaryDirectory() as work:
            path = Path(work) / "proof_file_measurement.py"
            path.write_bytes(b"unreviewed fixture")
            with self.assertRaisesRegex(ValueError, "runtime hash mismatch"):
                runner.pinned_bytes(path, runner.MEASUREMENT_SHA256)

    def test_runtime_import_returns_the_exact_pinned_bytes(self):
        with TemporaryDirectory() as work:
            path = Path(work) / "proof_file_measurement.py"
            raw = b"# fixture\n"
            path.write_bytes(raw)
            self.assertEqual(runner.pinned_bytes(path, hashlib.sha256(raw).hexdigest()), raw)

    def test_unprivileged_readiness_never_claims_kernel_pass(self):
        state = runner.preflight(Path("/does-not-exist/measurement-helper"))
        self.assertFalse(state["production_authorized"])
        self.assertNotIn("kernel_adapter_passed", state)
        self.assertFalse(state["ready"])
        self.assertIn("measurement_source", state["blockers"])
