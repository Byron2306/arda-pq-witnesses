"""Fixed GitHub/HF PQ review voters. No production execution authority."""
import base64
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
from .crypto import validate_key
from .quorum import canonical,strict_load,sha,need,enrollment,proposal_check,DOMAIN,PROFILES,hex64
from .proposal import validate_request
from .r13_bridge import PinnedR13

REQUEST_FIELDS={'schema','proposal','capture'}

class OpenSSLSigner:
    def __init__(self,algorithm,private_key_der):
        need(type(private_key_der) is bytes and 0<len(private_key_der)<=16384,'provider_private_key_format')
        self.algorithm=algorithm;self.__private=bytes(private_key_der)
        self.binary=Path(shutil.which('openssl') or '/missing-openssl').resolve()
        self.pin=sha(self.binary.read_bytes())
        with tempfile.TemporaryDirectory(prefix='arda-provider-key-') as directory:
            root=Path(directory);self._write_private(root/'key')
            public=self._run(['pkey','-inform','DER','-in',str(root/'key'),'-pubout','-outform','DER'])
        validate_key(algorithm,public);self.public=public
    def _write_private(self,path):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(self.__private)
    def _run(self,args):
        need(sha(self.binary.read_bytes())==self.pin,'provider_crypto_backend_changed')
        run=subprocess.run([str(self.binary),*args],stdin=subprocess.DEVNULL,capture_output=True,timeout=20,
            env={'PATH':os.defpath,'OPENSSL_CONF':'/dev/null'})
        need(run.returncode==0,'provider_crypto_operation_refused')
        return run.stdout
    def sign(self,message):
        need(type(message) is bytes and 0<len(message)<=16384,'provider_vote_size')
        with tempfile.TemporaryDirectory(prefix='arda-provider-sign-') as directory:
            root=Path(directory);self._write_private(root/'key');(root/'message').write_bytes(message)
            signature=self._run(['pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(root/'key'),'-in',str(root/'message')])
            (root/'public').write_bytes(self.public);(root/'signature').write_bytes(signature)
            self._run(['pkeyutl','-verify','-rawin','-pubin','-keyform','DER','-inkey',str(root/'public'),'-in',str(root/'message'),'-sigfile',str(root/'signature')])
        return signature

class ReviewWitness:
    def __init__(self,*,provider,policy_bytes,policy_file_sha256,stage_bytes,stage_request_sha256,
                 verifier_pem,ak_pem,approved_pcrs,private_key_der,source_root,source_manifest_bytes,
                 source_manifest_sha256,clock=None):
        need(provider in ('github','hf'),'provider_not_supported_here')
        self.provider=provider;self.clock=clock or time.time
        need(type(policy_bytes) is bytes and hex64(policy_file_sha256) and sha(policy_bytes)==policy_file_sha256,'provider_enrollment_file_pin')
        self.policy=strict_load(policy_bytes)
        admitted=enrollment(self.policy,self.now());self.witness,self.public=admitted[provider]
        self.expected=validate_request(stage_bytes,stage_request_sha256)
        d=strict_load(stage_bytes)['deployment']
        self.gate=PinnedR13(verifier_pem,ak_pem,approved_pcrs,dict(verifier_spki_sha256=d['r13_verifier_spki_sha256'],
            ak_spki_sha256=d['r13_ak_spki_sha256'],policy_sha256=d['r13_policy_sha256'],node_id=d['r13_subject_node_id'],verifier_id='cloudflare-r13-v2'))
        need(type(source_manifest_bytes) is bytes and hex64(source_manifest_sha256) and sha(source_manifest_bytes)==source_manifest_sha256,'provider_source_manifest_pin')
        self.sources=strict_load(source_manifest_bytes);self.source_root=Path(source_root).absolute()
        need(not self.source_root.is_symlink() and self.source_root.is_dir(),'provider_source_root')
        need(self.sources.keys()=={'schema','request_sha256','files','boundary'} and self.sources['schema']=='arda.pq.reviewed_source_closure.v1'
             and self.sources['request_sha256']==stage_request_sha256,'provider_source_manifest_binding')
        need(type(self.sources['files']) is list and len(self.sources['files'])==26,'provider_source_count')
        self.artifacts=dict(d['artifacts'])
        if provider=='github':self.check_sources()
        self.signer=OpenSSLSigner(self.witness['algorithm'],private_key_der)
        need(self.signer.public==self.public and sha(self.signer.public)==self.witness['key_sha256'],'provider_signing_key_not_enrolled')
    def now(self):
        value=self.clock();need(type(value) in (int,float) and 0<value<float('inf'),'provider_clock');return int(value)
    def check_sources(self):
        seen=set()
        for entry in self.sources['files']:
            need(type(entry) is dict and entry.keys()=={'path','artifact_path','sha256'},'provider_source_fields')
            relative=Path(entry['path'])
            need(bool(relative.parts) and not relative.is_absolute() and '..' not in relative.parts and relative.parts[0]=='reviewed-runtime'
                 and str(relative) not in seen,'provider_source_path')
            seen.add(str(relative));path=self.source_root/relative
            need(not any((self.source_root/Path(*relative.parts[:i])).is_symlink() for i in range(1,len(relative.parts)+1)),'provider_source_symlink')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                st=os.fstat(stream.fileno());need(stat.S_ISREG(st.st_mode) and st.st_size<=8*1024*1024,'provider_source_file')
                content=stream.read(8*1024*1024+1)
            need(len(content)<=8*1024*1024 and sha(content)==entry['sha256']==self.artifacts.get(entry['artifact_path']),'provider_changed_source_hash')
    def review(self,request):
        try:
            request=strict_load(canonical(request))
            need(type(request) is dict and request.keys()==REQUEST_FIELDS and request['schema']=='arda.pq.witness_request.v1','provider_request_fields')
            start=self.now();enrollment(self.policy,start)
            evidence=self.gate.verify(request['capture'],expected_boot=self.expected['boot_id'],now=start)
            need(evidence['r13_valid'],'provider_r13_evidence_refused')
            expected=dict(self.expected,r13_evidence_sha256=evidence['capture_sha256'])
            proposal=request['proposal'];proposal_check(proposal,self.policy,expected,start)
            need(evidence['issued_at']<=proposal['issued_at']<proposal['expires_at']<=evidence['expires_at'],'provider_r13_proposal_window')
            if self.provider=='github':self.check_sources()
            expires=min(proposal['expires_at'],self.policy['expires_at'],evidence['expires_at'])
            need(start<expires,'provider_vote_window')
            payload=dict(schema='arda.pq.vote.v1',witness_id=self.witness['witness_id'],provider=self.provider,
                role=self.witness['role'],algorithm=self.witness['algorithm'],key_sha256=self.witness['key_sha256'],
                policy_sha256=sha(canonical(self.policy)),proposal_sha256=sha(canonical(proposal)),decision='APPROVE',issued_at=start,expires_at=expires)
            signature=self.signer.sign(DOMAIN+canonical(payload))
            end=self.now();need(start<=end<expires,'provider_expired_or_clock_rollback_before_vote_release')
            return dict(payload=payload,signature_b64=base64.b64encode(signature).decode())
        except Exception:
            # Never expose key material, OpenSSL stderr, environment or bodies.
            raise ValueError('WITNESS_REVIEW_REFUSED') from None
