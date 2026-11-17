"""Offline tests. The subprocess boundary is mocked, never the trust decision."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from arda_quorum.proposal import public_commitment
from arda_quorum.quorum import canonical, sha


class RekorCommitmentTests(unittest.TestCase):
    def setUp(self):
        from tools import verify_rekor_commitment as gate

        self.gate = gate
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.cert = {"proposal": {"generation": 14}, "votes": [{}, {}, {}]}
        self.log_id = bytes(range(32))
        self.trust = {"mediaType": "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json",
                      "trustedRoot": {"tlogs": [{"logId": {"keyId": self.b64(self.log_id)}}]}}
        self.policy = {
            "schema": "arda.pq.rekor_policy.v1",
            "certificate_identity": (
                "https://github.com/Byron2306/arda-pq-witnesses/"
                ".github/workflows/arda-rekor-commitment.yml@refs/heads/main"
            ),
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "trust_config_sha256": sha(canonical(self.trust)),
            "rekor_log_id_sha256": self.log_id.hex(),
        }
        self.bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                       "messageSignature": {},
                       "verificationMaterial": {"tlogEntries": [{
                           "logId": {"keyId": self.b64(self.log_id)},
                           "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
                           "inclusionProof": {"checkpoint": {"envelope": "fixture-log\n1\n"
                                                               + self.b64(bytes(32)) + "\n\n— fixture signature\n"},
                                              "hashes": [], "logIndex": "0", "treeSize": "1",
                                              "rootHash": self.b64(bytes(32))},
                       }]}}
        self.cert_path = self.write("certificate.json", self.cert)
        self.trust_path = self.write("trust.json", self.trust)
        self.bundle_path = self.write("bundle.json", self.bundle)
        self.policy_path = self.write("policy.json", self.policy)
        self.policy_pin = sha(self.policy_path.read_bytes())

    @staticmethod
    def b64(value):
        return base64.b64encode(value).decode("ascii")

    def write(self, name, value):
        p = self.root / name
        p.write_bytes(canonical(value))
        return p

    def verify(self):
        return self.gate.verify(
            self.cert_path, self.bundle_path, self.trust_path,
            self.policy_path, self.policy_pin,
        )

    def test_delegates_exact_commitment_offline_and_grants_no_authority(self):
        def check(command, **kwargs):
            self.assertEqual(command[:4], [sys.executable, "-I", "-m", "sigstore"])
            self.assertIn("--offline", command)
            self.assertEqual(command[command.index("--cert-identity") + 1],
                             self.policy["certificate_identity"])
            self.assertEqual(command[command.index("--cert-oidc-issuer") + 1],
                             self.policy["oidc_issuer"])
            self.assertEqual(Path(command[-1]).read_bytes(),
                             canonical(public_commitment(self.cert)))
            for arg, original in (("--bundle", self.bundle_path),
                                  ("--trust-config", self.trust_path)):
                snapshot = Path(command[command.index(arg) + 1])
                self.assertNotEqual(snapshot, original)
                self.assertEqual(snapshot.read_bytes(), original.read_bytes())
            return subprocess.CompletedProcess(command, 0)
        with patch.object(subprocess, "run", side_effect=check) as run:
            result = self.verify()
        self.assertEqual(run.call_count, 1)
        self.assertTrue(result["transparency_verified"])
        self.assertFalse(result["production_authorized"])
        self.assertEqual(result["interlock"], "KEEP_CLOSED")

    def test_sigstore_refusal_cannot_become_a_receipt(self):
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaisesRegex(ValueError, "sigstore_verification_refused"):
                self.verify()

    def test_unapproved_policy_or_trust_bytes_rejected_before_sigstore(self):
        with patch.object(subprocess, "run") as run:
            self.policy_path.write_bytes(self.policy_path.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "rekor_policy_pin"):
                self.verify()
            self.write("policy.json", self.policy)
            self.trust_path.write_bytes(self.trust_path.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "rekor_trust_pin"):
                self.verify()
            run.assert_not_called()

    def test_policy_must_name_dedicated_workflow_and_github_issuer(self):
        for field in ("certificate_identity", "oidc_issuer"):
            with self.subTest(field=field), patch.object(subprocess, "run") as run:
                self.write("policy.json", {**self.policy, field: "https://example.invalid"})
                self.policy_pin = sha(self.policy_path.read_bytes())
                with self.assertRaisesRegex(ValueError, "rekor_signer_policy"):
                    self.verify()
                run.assert_not_called()

    def test_policy_log_must_be_in_the_pinned_trust_snapshot(self):
        self.write("policy.json", {**self.policy, "rekor_log_id_sha256": "ab" * 32})
        self.policy_pin = sha(self.policy_path.read_bytes())
        with patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "rekor_log_not_in_trust_config"):
                self.verify()
            run.assert_not_called()

    def test_missing_proof_checkpoint_wrong_log_or_format_fail_before_sigstore(self):
        for mode, reason in (
            ("proof", "rekor_inclusion_proof_required"),
            ("checkpoint", "rekor_signed_checkpoint_required"),
            ("log", "rekor_log_id_mismatch"),
            ("format", "rekor_entry_profile"),
            ("second", "rekor_exactly_one_entry"),
            ("tree_size", "rekor_checkpoint_tree_size_mismatch"),
        ):
            with self.subTest(mode=mode), patch.object(subprocess, "run") as run:
                bundle = copy.deepcopy(self.bundle)
                entries = bundle["verificationMaterial"]["tlogEntries"]
                entry = entries[0]
                if mode == "proof":
                    del entry["inclusionProof"]
                elif mode == "checkpoint":
                    del entry["inclusionProof"]["checkpoint"]
                elif mode == "log":
                    entry["logId"]["keyId"] = self.b64(bytes(32))
                elif mode == "format":
                    entry["kindVersion"]["version"] = "0.0.1"
                elif mode == "tree_size":
                    entry["inclusionProof"]["treeSize"] = "2"
                else:
                    entries.append(copy.deepcopy(entry))
                self.write("bundle.json", bundle)
                with self.assertRaisesRegex(ValueError, reason):
                    self.verify()
                run.assert_not_called()

    def test_rejects_noncanonical_certificate(self):
        self.cert_path.write_bytes(json.dumps(self.cert).encode())
        with patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "rekor_certificate_canonical"):
                self.verify()
            run.assert_not_called()

class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/arda-rekor-commitment.yml"
        cls.workflow = yaml.safe_load(path.read_text())
        cls.job = cls.workflow["jobs"]["sign-commitment"]
        cls.materialize, cls.sign, cls.upload = cls.job["steps"]

    def test_workflow_has_only_manual_digest_input_and_no_checkout(self):
        self.assertEqual(list(self.workflow["on"]), ["workflow_dispatch"])
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(list(inputs), ["certificate_sha256"])
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(self.job["permissions"], {"id-token": "write"})
        self.assertIn("github.ref_protected", self.job["if"])
        self.assertIn("refs/heads/main", self.job["if"])
        self.assertIn("1458361210", self.job["if"])
        self.assertEqual(self.job["environment"], "arda-rekor-signing")
        self.assertEqual(self.sign["with"]["inputs"], "public-commitment.json")
        from tools import verify_rekor_commitment as verify

        self.assertEqual(self.sign["with"]["verify-cert-identity"], verify.IDENTITY)
        self.assertEqual(self.sign["with"]["verify-oidc-issuer"], verify.ISSUER)
        self.assertEqual(self.sign["with"]["rekor-version"], "2")
        self.assertEqual(self.sign["with"]["release-signing-artifacts"], "false")
        self.assertEqual(self.upload["with"]["path"].splitlines(),
                         ["public-commitment.json", "public-commitment.json.sigstore.json"])
        for action in (self.sign, self.upload):
            self.assertRegex(action["uses"], r"@[0-9a-f]{40}$")
        self.assertNotIn("${{", self.materialize["run"])

    def test_workflow_materializes_exact_synthetic_bytes_locally(self):
        digest = "ab" * 32
        with tempfile.TemporaryDirectory() as work:
            result = self.render(work, digest)
            self.assertEqual(result.returncode, 0, result.stderr)
            raw = (Path(work) / "public-commitment.json").read_bytes()
        self.assertEqual(len(raw), 129)
        self.assertEqual(sha(raw), "f2e5713d66042c24b2273eb5ed0f2d6a5625daf492cb34f1041dd960175d3cb7")

    def test_workflow_rejects_malformed_digest_without_writing(self):
        for digest in ("A" * 64, "a" * 63, "a" * 64 + "\n"):
            with self.subTest(digest=digest), tempfile.TemporaryDirectory() as work:
                self.assertNotEqual(self.render(work, digest).returncode, 0)
                self.assertFalse((Path(work) / "public-commitment.json").exists())

    def render(self, work, digest):
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", self.materialize["run"]],
            cwd=work, env={**os.environ, "ARDA_CERTIFICATE_SHA256": digest},
            capture_output=True, timeout=10, check=False,
        )


if __name__ == "__main__":
    unittest.main()
