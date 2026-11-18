import base64
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib

from tools import gen12_release_authority as signer


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.der = signer.new_der()
        with tempfile.TemporaryDirectory() as td:
            key = Path(td) / "key"
            signer.write_der(key, cls.der)
            cls.pem = signer.pem_from_der(key)
        cls.pin = signer.sha(cls.pem)
        cls.p = {"generation": 12, "production_admission_authorized": False,
                 "schema": "arda.boot.deployment.v1",
                 "boot_scope_path": "/sys/fs/cgroup/system.slice/arda-ring0.service",
                 "manifest_id": "measured-b28567e939474e3ea436872aadd9e1c3",
                 "artifacts": {f"/boot/test-fixture-{i}": "00" * 32 for i in range(569)}}
        cls.now = 1700000000

    def setUp(self):
        fixture_pin = signer.sha(signer.canonical(self.p))
        ctx = patch.object(signer, "TEMPLATE_PIN", fixture_pin)
        self.addCleanup(ctx.stop)
        ctx.start()

    def sign(self):
        return signer.issue(self.p, self.der, self.pin, "24", clock=lambda: self.now)

    def test_detached_signature_roundtrip(self):
        receipt = self.sign()
        self.assertNotIn("artifacts", json.dumps(receipt))
        self.assertNotIn(base64.b64encode(self.der).decode(), json.dumps(receipt))
        result = signer.assemble(self.p, receipt, self.pem, self.pin, self.now)
        self.assertEqual(result["payload"]["generation"], 12)
        self.assertIs(result["payload"]["production_admission_authorized"], False)
        self.assertEqual(len(base64.b64decode(result["signature_b64"])), 64)

    def test_exact_template_pin_detects_manifest_and_artifact_mutations(self):
        for field, value in (("manifest_id", "changed"), ("artifacts", {}), ("issued_at", self.now)):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "reviewed_template_hash"):
                    signer.issue(dict(self.p, **{field: value}), self.der, self.pin, "24")

    def test_no_gen14_or_production_even_if_template_pin_changes(self):
        for change in ({"generation": 14}, {"production_admission_authorized": True},
                       {"production_admission_authorized": 0}):
            p = dict(self.p, **change)
            with self.subTest(change=change), patch.object(signer, "TEMPLATE_PIN", signer.sha(signer.canonical(p))):
                with self.assertRaisesRegex(ValueError, "gen12_boot_only"):
                    signer.issue(p, self.der, self.pin, "24")

    def test_key_pin_and_legacy_key_rejected(self):
        for pin in ("", "00" * 32, signer.LEGACY_PEM_PIN):
            with self.subTest(pin=pin), self.assertRaisesRegex(ValueError, "release_public_key_pin"):
                signer.issue(self.p, self.der, pin, "24")
        with self.assertRaisesRegex(ValueError, "release_private_key_type"):
            signer.issue(self.p, b"bad key", self.pin, "24")

    def test_receipt_tamper_expiry_and_rollback(self):
        receipt = self.sign()
        edited = copy.deepcopy(receipt)
        edited["deployment_fields"]["deployment_id"] = "00" * 16
        with self.assertRaisesRegex(ValueError, "openssl_operation_failed"):
            signer.assemble(self.p, edited, self.pem, self.pin, self.now)
        for now in (self.now - 1, receipt["deployment_fields"]["expires_at"]):
            with self.subTest(now=now), self.assertRaisesRegex(ValueError, "deployment_time_window"):
                signer.assemble(self.p, receipt, self.pem, self.pin, now)
        with self.assertRaisesRegex(ValueError, "deployment_time_window"):
            signer.issue(self.p, self.der, self.pin, "24", clock=iter([self.now, self.now - 1]).__next__)
        with self.assertRaisesRegex(ValueError, "release_lifetime"):
            signer.issue(self.p, self.der, self.pin, "721")

    def test_compressed_template_bound_and_no_trailing_data(self):
        raw = zlib.compress(signer.canonical(self.p), 9)
        self.assertEqual(signer.decode_template(base64.b64encode(raw).decode()), self.p)
        for bad in (raw + b"x", raw[:-4], zlib.compress(b"a" * (signer.CAP + 1))):
            with self.assertRaisesRegex(ValueError, "template_secret_compression"):
                signer.decode_template(base64.b64encode(bad).decode())

    def test_workflow_identity_and_reviewed_commit(self):
        commit = "a" * 40
        env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
               "GITHUB_REPOSITORY": signer.REPO, "GITHUB_REPOSITORY_ID": signer.REPO_ID,
               "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true",
               "GITHUB_WORKFLOW_REF": signer.REPO + "/.github/workflows/arda-release-gen12-continuity.yml@refs/heads/main",
               "ARDA_RELEASE_APPROVED_COMMIT": commit, "GITHUB_SHA": commit, "ARDA_RELEASE_ENABLED": "true"}
        signer.protect_context(env, "sign")
        for field in env:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "unapproved_workflow_context"):
                signer.protect_context(dict(env, **{field: ""}), "sign")
        with self.assertRaisesRegex(ValueError, "unapproved_workflow_context"):
            signer.protect_context(env, "enroll")

    def test_enroll_creates_only_public_output_and_does_not_regenerate(self):
        with tempfile.TemporaryDirectory() as td:
            seen = []
            def github(token, *args, data=b""):
                self.assertEqual(token, "test-token")
                seen.append((args, data))
                return b"[]"
            destination = Path(td) / "public.pem"
            logs = io.StringIO()
            with contextlib.redirect_stdout(logs):
                signer.enroll("test-token", destination, td, github=github, generate=lambda: self.der)
            self.assertEqual(destination.read_bytes(), self.pem)
            self.assertEqual(list(Path(td).iterdir()), [destination])
            self.assertEqual(seen[-1][0], ("secret", "set", signer.KEY_SECRET, "--app", "actions",
                                         "--env", signer.ENVIRONMENT))
            self.assertEqual(seen[-1][1], base64.b64encode(self.der))
            self.assertNotIn(seen[-1][1].decode(), logs.getvalue())

            def exists(*args, **kwargs):
                return json.dumps([{"name": signer.KEY_SECRET}]).encode()
            with self.assertRaisesRegex(ValueError, "release_key_already_enrolled"):
                signer.enroll("test-token", Path(td) / "second.pem", td, github=exists,
                              generate=lambda: self.fail("must not generate a replacement key"))


if __name__ == "__main__":
    unittest.main()
