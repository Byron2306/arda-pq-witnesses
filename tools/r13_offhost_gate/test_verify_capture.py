import base64
import json
import sys
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519
sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_capture import review_secret, result, PIN, expected_policy
from r13_v2 import public_pin

class HostedV3ContractTests(unittest.TestCase):
    def test_no_archive_refuses(self):
        x=review_secret("",node_id="lenovo-valinor",verifier_id="r13-verifier")
        self.assertEqual(x["status"],"REFUSE")
        self.assertFalse(x["r13_receipt_verified"])
    def test_bad_base64_refuses(self):
        x=review_secret("%%%%",node_id="lenovo-valinor",verifier_id="r13-verifier")
        self.assertFalse(x["r13_receipt_verified"])
    def test_tampered_archive_refuses(self):
        s=base64.b64encode(json.dumps({"schema":"arda.r13.capture.v2","issued_challenge":{},
                "evidence":{},"receipt":{}}).encode()).decode()
        x=review_secret(s,node_id="lenovo-valinor",verifier_id="r13-verifier")
        self.assertFalse(x["r13_receipt_verified"])
    def test_oversized_archive_refuses(self):
        x=review_secret("A"*50000,node_id="lenovo-valinor",verifier_id="r13-verifier")
        self.assertFalse(x["r13_receipt_verified"])
    def test_never_promotes_authority(self):
        x=result("r13_hardware_receipt_verified_no_runtime_authority",
                 verified=True,boot_id="f231250d-455f-4923-a564-546032076314",evidence_sha256="a"*64)
        self.assertTrue(x["r13_receipt_verified"])
        for name in ("independent_software_runtime_attestation","phase4_verdict_verified",
                     "hardware_rooted_os_grade_authorized","production_cutover_authorized"):
            self.assertIs(x[name],False)
        self.assertEqual(x["interlock"],"KEEP_CLOSED")
    def test_pin_matches_checked_in_key(self):
        from cryptography.hazmat.primitives import serialization
        root=Path(__file__).resolve().parents[2]
        key=serialization.load_pem_public_key((root/"providers/public-r13/verifier-public.pem").read_bytes())
        self.assertEqual(public_pin(key),PIN)
    def test_expected_policy_well_formed(self):
        self.assertEqual(len(expected_policy().sha256),64)
