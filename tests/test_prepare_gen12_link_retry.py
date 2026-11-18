import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools import gen12_release_authority as signer
from tools import prepare_gen12_link_retry as retry


class RetryTests(unittest.TestCase):
    def fixture(self):
        old_root = str(retry.OLD_ROOT) + "/"
        obj = "backend/services/bpf/arda_physical_lsm.o"
        unchanged = "/boot/vmlinuz-test"
        before = {"generation": 12, "production_admission_authorized": False,
                  "bpf_object_path": old_root + obj,
                  "artifacts": {old_root + obj: "0" * 64, unchanged: "1" * 64}}
        for rel, (was, _) in retry.PATCHES.items():
            before["artifacts"][old_root + rel] = was
        for i in range(564):
            before["artifacts"][old_root + f"fixture/{i}"] = "2" * 64
        after = dict(before, bpf_object_path=str(retry.NEW_ROOT / obj))
        after["artifacts"] = {
            str(retry.NEW_ROOT / Path(k).relative_to(retry.OLD_ROOT))
            if k.startswith(old_root) else k: v for k, v in before["artifacts"].items()
        }
        for rel, (_, now) in retry.PATCHES.items():
            after["artifacts"][str(retry.NEW_ROOT / rel)] = now
        return before, after

    def test_rebase_updates_only_three_content_digests_and_the_fixed_release_root(self):
        before, after = self.fixture()
        with (patch.object(retry, "OLD_TEMPLATE_SHA256", retry.sha(retry.canonical(before))),
              patch.object(retry, "NEW_TEMPLATE_SHA256", retry.sha(retry.canonical(after)))):
            self.assertEqual(retry.derive(before), after)
            self.assertIs(retry.derive(before)["production_admission_authorized"], False)
            tampered = copy.deepcopy(before)
            tampered["artifacts"]["/boot/vmlinuz-test"] = "3" * 64
            with self.assertRaisesRegex(ValueError, "baseline deployment fields"):
                retry.derive(tampered)

    def test_pinned_old_envelope_is_required_even_for_unsigned_request(self):
        old, _ = self.fixture()
        envelope = {"payload": dict(old, deployment_id="f" * 32, issued_at=1, expires_at=2),
                    "signature_b64": "fixture"}
        raw = retry.canonical(envelope) + b"\n"
        with TemporaryDirectory() as tmp, patch.object(retry, "OLD_ENVELOPE_SHA256", retry.sha(raw)):
            path = Path(tmp) / "old.json"
            path.write_bytes(raw)
            self.assertEqual(retry.baseline(path), old)
            path.write_bytes(json.dumps(envelope).encode())
            with self.assertRaisesRegex(ValueError, "baseline envelope SHA-256"):
                retry.baseline(path)

    def test_pin_is_single_and_shared_with_signer(self):
        self.assertEqual(signer.TEMPLATE_PIN, retry.NEW_TEMPLATE_SHA256)
        self.assertNotEqual(signer.TEMPLATE_PIN, retry.OLD_TEMPLATE_SHA256)

    def test_verified_copy_checks_digest_and_ignores_checkout_modes(self):
        with TemporaryDirectory() as tmp:
            parent = Path(tmp)
            source = parent / "source.py"
            source.write_bytes(b"pinned python")
            source.chmod(0o777)
            output = parent / "copied" / source.name
            retry.verified_copy(source, retry.sha(source.read_bytes()), target=output, root_owned=False)
            self.assertEqual(output.read_bytes(), source.read_bytes())
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            with self.assertRaisesRegex(ValueError, "artifact SHA-256 mismatch"):
                retry.verified_copy(source, "0" * 64, root_owned=False)
            symlink = parent / "symlink.py"
            symlink.symlink_to(source)
            with self.assertRaises(OSError):
                retry.verified_copy(symlink, retry.sha(source.read_bytes()), root_owned=False)


    def test_empty_regular_artifact_is_accepted_only_for_empty_digest(self):
        with TemporaryDirectory() as tmp:
            parent = Path(tmp)
            source = parent / "__init__.py"
            target = parent / "copied" / "__init__.py"
            source.touch()
            retry.verified_copy(source, retry.EMPTY_SHA256, target=target, root_owned=False)
            self.assertEqual(target.read_bytes(), b"")
            retry.verified_copy(target, retry.EMPTY_SHA256, root_owned=False)
            with self.assertRaisesRegex(ValueError, "unprotected input"):
                retry.verified_copy(source, retry.sha(b"not empty"), root_owned=False)
            with self.assertRaisesRegex(ValueError, "unprotected input"):
                retry.baseline(source)
            source.write_bytes(b"unexpected bytes")
            with self.assertRaisesRegex(ValueError, "artifact SHA-256 mismatch"):
                retry.verified_copy(source, retry.EMPTY_SHA256, root_owned=False)

if __name__ == "__main__":
    unittest.main()
