"""Disposable real signature fixtures. No production keys or enrollment."""
from pathlib import Path
import select
import subprocess
import tempfile
from arda_quorum.crypto import ML,SLH,HSS
ROOT=Path(__file__).resolve().parents[1]

class Signers:
    def __init__(self):
        self.temp=tempfile.TemporaryDirectory(prefix='arda-pq-test-keys-');self.root=Path(self.temp.name)
        self.keys={}
        self.hss=None
        try:
            for label,algorithm in [('github',ML),('hf',SLH)]:
                subprocess.run(['openssl','genpkey','-algorithm',algorithm,'-out',str(self.root/(label+'.pem'))],check=True,capture_output=True,timeout=30)
                self.keys[label]=subprocess.check_output(['openssl','pkey','-in',str(self.root/(label+'.pem')),'-pubout','-outform','DER'],timeout=10)
            self.hss=subprocess.Popen([str(ROOT/'build/test-hss-sign')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
            self.keys['cloudflare']=bytes.fromhex(self._line())
        except BaseException:self.close();raise
    def _line(self):
        if not select.select([self.hss.stdout],[],[],60)[0]:raise TimeoutError('HSS fixture timeout')
        line=self.hss.stdout.readline().strip()
        if not line:raise RuntimeError('HSS fixture exited')
        return line
    def sign(self,label,message):
        if label=='cloudflare':
            self.hss.stdin.write(message.hex()+'\n');self.hss.stdin.flush()
            return bytes.fromhex(self._line())
        (self.root/'message').write_bytes(message)
        return subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey',str(self.root/(label+'.pem')),'-in',str(self.root/'message')],timeout=30)
    def close(self):
        if self.hss:
            if self.hss.stdin:self.hss.stdin.close()
            try:self.hss.wait(timeout=5)
            except subprocess.TimeoutExpired:self.hss.kill();self.hss.wait()
            self.hss.stdout.close();self.hss.stderr.close()
        self.temp.cleanup()
