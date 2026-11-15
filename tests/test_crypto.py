import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

class CryptoTests(unittest.TestCase):
    def test_crypto_backend_exists_without_fallback(self):
        self.assertIsNotNone(importlib.util.find_spec('arda_quorum.crypto'), 'real PQ verification backend required')

ROOT=Path(__file__).resolve().parents[1]

from arda_quorum.crypto import Backends,ML,SLH,HSS,validate_key
from fixture_crypto import Signers

class RealSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signers=Signers();cls.backends=Backends();cls.message=b'ARDA/PQ-REAL-TEST/v1\0'+b'exact proposal'
        cls.signatures={role:cls.signers.sign(role,cls.message) for role in ('github','hf','cloudflare')}
    @classmethod
    def tearDownClass(cls):cls.signers.close()
    def test_all_three_real_schemes_verify(self):
        for role,algorithm in [('github',ML),('hf',SLH),('cloudflare',HSS)]:
            with self.subTest(algorithm=algorithm):self.assertTrue(self.backends.verify(algorithm,self.signers.keys[role],self.message,self.signatures[role]))
    def test_tampered_signatures_refused(self):
        for role,algorithm in [('github',ML),('hf',SLH),('cloudflare',HSS)]:
            bad=bytearray(self.signatures[role]);bad[-1]^=1
            self.assertFalse(self.backends.verify(algorithm,self.signers.keys[role],self.message,bytes(bad)))
    def test_message_tampering_refused_for_every_scheme(self):
        for role,algorithm in [('github',ML),('hf',SLH),('cloudflare',HSS)]:
            self.assertFalse(self.backends.verify(algorithm,self.signers.keys[role],self.message+b'x',self.signatures[role]))
    def test_algorithm_substitution_refused(self):
        self.assertFalse(self.backends.verify(SLH,self.signers.keys['github'],self.message,self.signatures['github']))
        self.assertFalse(self.backends.verify('Ed25519',self.signers.keys['github'],self.message,self.signatures['github']))
    def test_truncated_key_and_signature_refused(self):
        for role,algorithm in [('github',ML),('hf',SLH),('cloudflare',HSS)]:
            self.assertFalse(self.backends.verify(algorithm,self.signers.keys[role][:-1],self.message,self.signatures[role]))
            self.assertFalse(self.backends.verify(algorithm,self.signers.keys[role],self.message,self.signatures[role][:-1]))
    def test_missing_hss_backend_never_falls_back(self):
        self.backends.hss=Path('/missing-hss')
        try:self.assertFalse(self.backends.verify(HSS,self.signers.keys['cloudflare'],self.message,self.signatures['cloudflare']))
        finally:self.backends.hss=ROOT/'build/hss-verify'
