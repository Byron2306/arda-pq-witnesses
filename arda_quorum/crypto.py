"""Fixed-parameter PQ verification through OpenSSL and pinned HSS reference code."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ML='ML-DSA-65'
SLH='SLH-DSA-SHA2-192s'
HSS='HSS-LMS-SHA256-N32-H10-W8'
# Exact DER SubjectPublicKeyInfo encodings; absent algorithm parameters only.
SPKI={ML:(1974,bytes.fromhex('308207b2300b0609608648016503040312038207a100')),
      SLH:(66,bytes.fromhex('3040300b0609608648016503040316033100'))}
LMS_PREFIX=bytes.fromhex('000000010000000600000004')


def validate_key(algorithm,key):
    if type(key) is not bytes:raise ValueError('public_key_bytes')
    if algorithm in SPKI:
        size,prefix=SPKI[algorithm]
        if len(key)!=size or not key.startswith(prefix):raise ValueError('public_key_algorithm_or_encoding')
    elif algorithm==HSS:
        if len(key)!=60 or not key.startswith(LMS_PREFIX):raise ValueError('hss_public_key_parameters')
    else:raise ValueError('unsupported_algorithm')


class Backends:
    def __init__(self,root=None):
        self.root=Path(root) if root else Path(__file__).resolve().parents[1]
        self.openssl=Path(shutil.which('openssl') or '/missing-openssl').resolve()
        self.hss=self.root/'build/hss-verify'
        self.openssl_pin=self._sha(self.openssl)
        manifest=json.loads((self.root/'build/BUILD.json').read_text())
        self.hss_pin=manifest['binary_sha256']['hss-verify']
        if self._sha(self.hss)!=self.hss_pin:raise ValueError('hss_backend_pin')

    @staticmethod
    def _sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def verify(self,algorithm,key,message,signature):
        try:
            validate_key(algorithm,key)
            if type(message) is not bytes or not 0<len(message)<=16384:raise ValueError('message_size')
            if type(signature) is not bytes or not 0<len(signature)<=65536:raise ValueError('signature_size')
            if algorithm==HSS and len(signature)!=1456:raise ValueError('hss_signature_size')
            if self._sha(self.openssl)!=self.openssl_pin or self._sha(self.hss)!=self.hss_pin:
                raise ValueError('crypto_backend_changed')
            with tempfile.TemporaryDirectory(prefix='arda-pq-verify-') as directory:
                root=Path(directory)
                for name,raw in (('key',key),('message',message),('signature',signature)):(root/name).write_bytes(raw)
                if algorithm==HSS:
                    command=[str(self.hss),str(root/'key'),str(root/'message'),str(root/'signature')]
                else:
                    command=[str(self.openssl),'pkeyutl','-verify','-pubin','-keyform','DER','-inkey',str(root/'key'),
                        '-rawin','-in',str(root/'message'),'-sigfile',str(root/'signature')]
                # No inherited OpenSSL config/provider overrides or shell expansion.
                result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,timeout=15,
                    env={'PATH':os.defpath,'OPENSSL_CONF':'/dev/null'})
                return result.returncode==0
        except (ValueError,OSError,subprocess.SubprocessError):return False
