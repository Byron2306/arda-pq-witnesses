from argparse import Namespace
import json
from pathlib import Path
import stat
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from prepare_deploy import prepare
from r13_v2 import PCRS, Refusal, public_pin


class PrepareTests(unittest.TestCase):
    def test_enrollment_requires_independent_pin_and_creates_private_state_once(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            ak = rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key()
            pem, pcr, state = (root / name for name in ('ak.pem','approved.json','private'))
            pem.write_bytes(ak.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
            pcr.write_text(json.dumps({str(n): f"{n+1:02x}"*32 for n in PCRS}))
            args = Namespace(ak_public_pem=pem, ak_spki_sha256="0"*64, approved_pcrs=pcr,state_dir=state)
            with self.assertRaisesRegex(Refusal,'AK_PIN_MISMATCH'):
                prepare(args)
            self.assertFalse(state.exists())
            args.ak_spki_sha256 = public_pin(ak)
            result = prepare(args)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode),0o700)
            for name in ("deploy-secrets.json","lenovo.token","verifier-public.pem","pins.json"):
                self.assertEqual(stat.S_IMODE((state/name).stat().st_mode),0o600)
            secrets = json.loads((state/"deploy-secrets.json").read_text())
            self.assertEqual((state/"lenovo.token").read_text().strip(),secrets["R13_TOKEN"])
            self.assertNotIn(secrets["R13_TOKEN"],json.dumps(result))
            with self.assertRaises(FileExistsError):
                prepare(args)
