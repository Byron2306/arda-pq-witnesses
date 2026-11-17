"""Disposable test keys and selector. Only the external Sigstore process is stubbed."""
import base64
import copy
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_quorum
import test_r13_bridge
import test_r13_quorum
import test_rekor_commitment
from arda_quorum.proposal import public_commitment
from arda_quorum.quorum import canonical, sha
from tools import verify_rekor_commitment as rekor

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reviewed-runtime"))
from backend.services.projection_journal import PERMIT_DOMAIN


class GuestAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls, *, boot_id=None):
        from tools import guest_admission

        cls.gate = guest_admission
        test_r13_quorum.BoundQuorumTests.setUpClass(boot_id=boot_id)
        cls.addClassCleanup(test_r13_quorum.BoundQuorumTests.tearDownClass)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.now = 1000
        self.release_key = Ed25519PrivateKey.generate()
        self.cert = copy.deepcopy(test_r13_quorum.BoundQuorumTests.certificate)
        self.expected = dict(test_r13_quorum.BoundQuorumTests.expected)
        self.enrollment = copy.deepcopy(test_quorum.QuorumTests.policy)
        self.plan = dict(action="activate", scope_id=11, scope_path="/sys/fs/cgroup/guest-arda",
                         prior_generation=13, node_id="guest",
                         **{k: self.expected[k] for k in ("generation", "manifest_id", "manifest_digest")})
        self.prepare_backend()
        self.guest = self.open_guest()
        self.rekor = test_rekor_commitment.RekorCommitmentTests()
        self.addCleanup(self.rekor.doCleanups)
        self.rekor.setUp()
        self.sigstore_exit = 0
        self.after_rekor = lambda: None
        offline = SimpleNamespace(run=self.verify_offline_fixture, DEVNULL=subprocess.DEVNULL)
        mocked = patch.object(rekor, "subprocess", offline)
        mocked.start()
        self.addCleanup(mocked.stop)

    def prepare_backend(self):
        pass

    def open_guest(self):
        return self.gate.GuestAdmission(
            self.root, boot_id=self.expected["boot_id"], clock=lambda: self.now,
            scope_id=11, scope_path="/sys/fs/cgroup/guest-arda", initial_generation=13,
            backends=test_quorum.QuorumTests.backend, release_key=self.release_key.public_key(),
        )

    def verify_offline_fixture(self, cmd, **kwargs):
        self.assertEqual(cmd[:4], [sys.executable, "-I", "-m", "sigstore"])
        self.assertIn("--offline", cmd)
        self.assertEqual(Path(cmd[-1]).read_bytes(), canonical(public_commitment(self.cert)))
        self.after_rekor()
        return subprocess.CompletedProcess(cmd, self.sigstore_exit)

    def permit(self, **replacements):
        payload = dict(self.plan, schema="arda.projection.permit.v1",
                       permit_id=self.gate.guest_permit_id(sha(canonical(self.cert))),
                       boot_id=self.expected["boot_id"], issued_at=1000, expires_at=1100,
                       production_cutover_authorized=True)
        payload.update(replacements)
        sig = self.release_key.sign(PERMIT_DOMAIN + canonical(payload))
        return dict(payload=payload, signature_b64=base64.b64encode(sig).decode())

    def apply(self, guest=None, **overrides):
        args = dict(
            plan=self.plan, certificate=self.cert, enrollment=self.enrollment,
            enrollment_sha256=sha(canonical(self.enrollment)), expected=self.expected,
            capture=test_r13_bridge.R13BridgeTests.capture, r13_gate=test_r13_bridge.R13BridgeTests.gate,
            permit=self.permit(), bundle_path=self.rekor.bundle_path, trust_path=self.rekor.trust_path,
            rekor_policy_path=self.rekor.policy_path, rekor_policy_sha256=self.rekor.policy_pin,
        )
        args.update(overrides)
        return (guest or self.guest).activate(**args)

    def untouched(self):
        self.assertEqual(self.guest.active_generation(), 13)
        self.assertEqual(self.guest.journal.rows(), [])
        with self.guest.review.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM reviews").fetchone()[0], 0)

    def test_exact_evidence_and_signed_permit_publish_one_guest_generation(self):
        result = self.apply()
        self.assertEqual(result["phase"], "COMMITTED")
        self.assertEqual(self.guest.active_generation(), 14)
        self.assertIs(result["production_authorized"], False)
        self.assertEqual(result["interlock"], "KEEP_CLOSED")
        with self.assertRaisesRegex(ValueError, "guest_review_consumption_refused"):
            self.apply(guest=self.open_guest())
        self.assertEqual(len(self.guest.journal.rows()), 1)

    def test_wrong_generation_refuses_before_consuming_anything(self):
        with self.assertRaisesRegex(ValueError, "guest_plan_review_binding"):
            self.apply(plan=dict(self.plan, generation=15), permit=self.permit(generation=15))
        self.untouched()

    def test_valid_permit_for_another_certificate_is_not_interchangeable(self):
        with self.assertRaisesRegex(ValueError, "guest_permit_certificate_binding"):
            self.apply(permit=self.permit(permit_id="f" * 32))
        self.untouched()

    def test_permit_cannot_outlive_review(self):
        with self.assertRaisesRegex(ValueError, "guest_permit_outlives_review"):
            self.apply(permit=self.permit(expires_at=1101))
        self.untouched()

    def test_expiry_while_verifying_rekor_refuses_without_consumption(self):
        self.after_rekor = lambda: setattr(self, "now", 1100)
        with self.assertRaisesRegex(ValueError, "permit_expired_or_future"):
            self.apply()
        self.untouched()

    def test_clock_rollback_after_rekor_refuses_without_consumption(self):
        self.after_rekor = lambda: setattr(self, "now", 999)
        with self.assertRaisesRegex(ValueError, "guest_clock_invalid_or_rollback"):
            self.apply()
        self.untouched()

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
        self.assertEqual(row["phase"], "ABORTED")

    def test_expiry_after_selector_write_quarantines_on_recovery(self):
        publish = self.guest.selector.publish

        def expire(scope, generation):
            publish(scope, generation)
            self.now = 1100

        with patch.object(self.guest.selector, "publish", expire):
            with self.assertRaisesRegex(ValueError, "permit_expired_or_future"):
                self.apply()
        self.assertEqual(self.guest.active_generation(), 14)
        row, = self.guest.journal.rows()
        self.assertEqual(row["phase"], "DIRTY")
        self.assertEqual(self.guest.recover(row["txid"])["phase"], "QUARANTINED")
        self.assertEqual(self.guest.active_generation(), 0)

    def test_valid_permit_for_wrong_scope_does_not_consume(self):
        wrong_scope = self.plan["scope_id"] + 1
        with self.assertRaisesRegex(ValueError, "guest_selector_scope"):
            self.apply(plan=dict(self.plan, scope_id=wrong_scope), permit=self.permit(scope_id=wrong_scope))
        self.untouched()

    def test_rekor_refusal_and_unpinned_enrollment_do_not_consume_or_publish(self):
        self.sigstore_exit = 1
        with self.assertRaisesRegex(ValueError, "sigstore_verification_refused"):
            self.apply()
        with self.assertRaisesRegex(ValueError, "guest_enrollment_pin"):
            self.apply(enrollment_sha256="0" * 64)
        self.untouched()

    def test_fake_r13_and_bad_pq_signature_do_not_consume_or_publish(self):
        with self.assertRaisesRegex(ValueError, "guest_bound_quorum_refused"):
            self.apply(capture={"r13_valid": True})
        bad = copy.deepcopy(self.cert)
        sig = bytearray(base64.b64decode(bad["votes"][0]["signature_b64"]))
        sig[-1] ^= 1
        bad["votes"][0]["signature_b64"] = base64.b64encode(sig).decode()
        with self.assertRaisesRegex(ValueError, "guest_bound_quorum_refused"):
            self.apply(certificate=bad)
        self.untouched()

    def fork_and_crash(self, child):
        def reopened_child():
            self.guest = self.open_guest()
            child()

        process = multiprocessing.get_context("fork").Process(target=reopened_child)
        process.start()
        try:
            process.join(20)
            self.assertEqual(process.exitcode, 71)
        finally:
            if process.is_alive():
                process.kill()
                process.join()
            process.close()

    def test_process_crash_between_journals_cannot_reuse_review(self):
        def child():
            self.guest.coordinator.apply = lambda *_: os._exit(71)
            self.apply()

        self.fork_and_crash(child)
        reopened = self.open_guest()
        self.assertEqual(reopened.active_generation(), 13)
        self.assertEqual(reopened.journal.rows(), [])
        with self.assertRaisesRegex(ValueError, "guest_review_consumption_refused"):
            self.apply(guest=reopened)

    def crash_at_publish(self, published):
        def child():
            publish = self.guest.selector.publish

            def stop(scope, generation):
                if published:
                    publish(scope, generation)
                os._exit(71)

            self.guest.selector.publish = stop
            self.apply()

        self.fork_and_crash(child)
        recovered = self.open_guest()
        row, = recovered.journal.rows()
        self.assertEqual(row["phase"], "PUBLISH_INTENT")
        self.assertEqual(recovered.active_generation(), 14 if published else 13)
        receipt = recovered.recover(row["txid"])
        self.assertEqual(receipt["phase"], "QUARANTINED" if published else "ABORTED")
        self.assertEqual(recovered.active_generation(), 0 if published else 13)
        self.assertIs(receipt["production_authorized"], False)
        self.assertEqual(receipt["interlock"], "KEEP_CLOSED")
        with self.assertRaisesRegex(ValueError, "guest_review_consumption_refused"):
            self.apply(guest=self.open_guest())
        self.assertEqual(len(recovered.journal.rows()), 1)

    def test_process_crash_before_publish_keeps_prior_and_burns_review(self):
        self.crash_at_publish(published=False)

    def test_process_crash_after_publish_recovers_to_deny_and_burns_review(self):
        self.crash_at_publish(published=True)
