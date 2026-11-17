"""Exercise the reviewed projection consumer over a private file selector only."""
from pathlib import Path
import os
from tempfile import TemporaryDirectory
from threading import Lock

from backend.services.production_files import protected_json, publish_json
from backend.services.projection_coordinator import ProjectionCoordinator
from backend.services.projection_journal import Journal, require_transaction, validate_plan, verify_permit

from arda_quorum.journal import ReviewJournal
from arda_quorum.quorum import canonical, hex64, need, sha, strict_load
from arda_quorum.r13_bridge import verify_with_r13
from tools import verify_rekor_commitment as rekor

_CLOSED = dict(production_authorized=False, interlock="KEEP_CLOSED")


def guest_permit_id(certificate_sha256):
    """Bind an existing v1 permit signature to one exact certificate in this guest."""
    need(hex64(certificate_sha256), "guest_certificate_digest")
    return sha(b"ARDA/GUEST-CERTIFICATE-PERMIT/v1\0" + bytes.fromhex(certificate_sha256))[:32]


class _Clock:
    def __init__(self, source):
        self.source, self.last, self.lock = source, 0, Lock()

    def __call__(self):
        with self.lock:
            now = self.source()
            need(type(now) is int and now > 0 and now >= self.last, "guest_clock_invalid_or_rollback")
            self.last = now
            return now


class _FileSelector:
    """No BPF, cgroups, systemd or measured-state writes. Only this model file."""
    def __init__(self, journal, scope_id, scope_path, initial_generation):
        self.scope_id, self.scope_path = scope_id, scope_path
        self.path = journal.root / "guest-selector.json"
        need(type(initial_generation) is int and 0 <= initial_generation < 2**63,
             "guest_initial_generation")
        self.owner = os.geteuid()
        with journal.locked():
            if not self.path.exists():
                need(not journal.rows(), "guest_selector_missing_after_transaction")
                self._write(initial_generation)
            self.active(scope_id)

    def _write(self, generation):
        publish_json(self.path, {"scope_id": self.scope_id, "scope_path": self.scope_path,
                                 "generation": generation}, mode=0o600)

    def validate_scope(self, plan):
        need(plan["scope_id"] == self.scope_id and plan["scope_path"] == self.scope_path,
             "guest_selector_scope")

    def validate_recovery_scope(self, plan, row):
        self.validate_scope(plan)

    def active(self, scope):
        need(scope == self.scope_id, "guest_selector_scope")
        state = protected_json(self.path, cap=4096, owner=self.owner)
        need(state.keys() == {"scope_id", "scope_path", "generation"}, "guest_selector_shape")
        self.validate_scope(state)
        generation = state["generation"]
        need(type(generation) is int and 0 <= generation < 2**63, "guest_selector_generation")
        return generation

    def prepare(self, plan):
        return {"generation": plan["generation"], "guest_only": True}

    def verify_prepared(self, plan, inventory):
        need(inventory == self.prepare(plan), "guest_projection_inventory")

    def publish(self, scope, generation):
        tx = require_transaction()
        tx.allow_selector(scope, generation)
        # Mirror the reviewed BPF writer's operation record before mutation.
        # Without it a failed post-write check could be mistaken for a clean abort.
        tx.note("guest_selector_write", {"scope_id": scope, "before": self.active(scope),
                                         "generation": generation})
        tx.allow_selector(scope, generation)
        self._write(generation)

    def finalize(self, plan):
        self.verify_final(plan)

    def verify_final(self, plan):
        need(self.active(plan["scope_id"]) == plan["generation"], "guest_final_selector")

    def abort_prepared(self, plan, row):
        # No inactive rows to remove in the file model.
        need(self.active(plan["scope_id"]) == plan["prior_generation"], "guest_prior_selector")

    def reconcile_quarantine(self, plan):
        need(self.active(plan["scope_id"]) == 0, "guest_quarantine_selector")


class GuestAdmission:
    """Trusted in-process harness. Paths and pins are supplied by the guest operator."""
    def __init__(self, state_dir, *, boot_id, clock, scope_id, scope_path, initial_generation,
                 backends, release_key):
        root = Path(state_dir)
        root.mkdir(mode=0o700, exist_ok=True)
        self.clock = _Clock(clock)
        self.boot_id = boot_id
        self.release_key = release_key
        self.scope_id, self.scope_path = scope_id, scope_path
        self.review = ReviewJournal(root / "review.sqlite3", backends=backends, clock=self.clock)
        self.journal = Journal(root / "projection", boot_id=lambda: self.boot_id, clock=self.clock)
        self.selector = self._open_selector(initial_generation)
        self.coordinator = ProjectionCoordinator(self.journal, self.selector)

    def _open_selector(self, initial_generation):
        return _FileSelector(self.journal, self.scope_id, self.scope_path, initial_generation)

    def active_generation(self):
        return self.selector.active(self.scope_id)

    def activate(self, *, plan, certificate, enrollment, enrollment_sha256, expected, capture,
                 r13_gate, permit, bundle_path, trust_path, rekor_policy_path, rekor_policy_sha256):
        # Verify and consume the same immutable snapshots throughout the attempt.
        plan, certificate, enrollment, expected, capture, permit = (
            strict_load(canonical(value))
            for value in (plan, certificate, enrollment, expected, capture, permit)
        )
        validate_plan(plan)
        need(plan["action"] == "activate", "guest_activation_only")
        need(plan["scope_id"] == self.scope_id and plan["scope_path"] == self.scope_path,
             "guest_selector_scope")
        need(sha(canonical(enrollment)) == enrollment_sha256, "guest_enrollment_pin")
        need(expected["boot_id"] == self.boot_id, "guest_expected_boot_binding")
        need(all(plan[k] == expected[k] and type(plan[k]) is type(expected[k])
                 for k in ("generation", "manifest_id", "manifest_digest")), "guest_plan_review_binding")
        start = self.clock()
        checked = verify_with_r13(certificate, enrollment, expected=expected, capture=capture,
                                  r13_gate=r13_gate, now=start, backends=self.review.backends)
        need(checked["quorum_valid"] and checked["r13_valid"], "guest_bound_quorum_refused")
        raw = canonical(certificate)
        digest = sha(raw)
        need(checked["certificate_sha256"] == digest, "guest_checked_certificate_binding")
        signed = verify_permit(permit, self.release_key, plan, self.boot_id, start)
        need(signed.payload["permit_id"] == guest_permit_id(digest), "guest_permit_certificate_binding")
        need(certificate["proposal"]["issued_at"] <= signed.payload["issued_at"]
             and signed.payload["expires_at"] <= checked["expires_at"], "guest_permit_outlives_review")

        with TemporaryDirectory(prefix="guest-rekor-", dir=self.journal.root) as directory:
            path = Path(directory) / "certificate.json"
            path.write_bytes(raw)
            result = rekor.verify(path, bundle_path, trust_path, rekor_policy_path, rekor_policy_sha256)
        need(result["transparency_verified"] is True and result["certificate_sha256"] == digest,
             "guest_rekor_certificate_binding")

        signed.check(plan, self.boot_id, self.clock())
        review = self.review.consume(certificate, enrollment, expected=expected)
        need(review["review_consumed"] is True and review["certificate_sha256"] == digest,
             "guest_review_consumption_refused")
        # If the process dies here the review remains consumed. The coordinator's
        # own journal consumes the signed permit and owns recovery from its INTENT onward.
        projected = self.coordinator.apply(plan, signed)
        return dict(phase=projected["phase"], txid=projected["txid"],
                    guest_generation=projected["generation"], certificate_sha256=digest, **_CLOSED)

    def recover(self, txid):
        return dict(self.coordinator.recover(txid), **_CLOSED)
