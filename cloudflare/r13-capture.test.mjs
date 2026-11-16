import test from 'node:test';import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fixture,encode,digest} from './release-fixtures.mjs';
const module=await import('./r13-capture.mjs').catch(()=>null);
test('release R13 verifier exists',()=>assert.ok(module,'independent release R13 verifier missing'));
test('Python verifies the disposable fixture and JavaScript matches its capture hash',async()=>{
 assert.ok(module);const f=fixture();
 const py=spawnSync('python3',['-c',`import json,sys,base64
from arda_quorum.r13_bridge import PinnedR13
from cryptography.hazmat.primitives import serialization
x=json.load(sys.stdin);c=x['r13'];pem=lambda b:serialization.load_der_public_key(base64.b64decode(b)).public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
r=PinnedR13(pem(c['verifier_spki_b64']),pem(c['ak_spki_b64']),c['pcrs'],c['pins']).verify(x['capture'],expected_boot=x['boot'],now=1000)
assert r['r13_valid'],r
print(r['capture_sha256'])`],{input:encode({r13:f.r13,capture:f.capture,boot:f.boot}),encoding:'utf8'});
 assert.equal(py.status,0,py.stderr);const result=await module.verifyCapture(f.r13,f.capture,f.boot,1000);assert.equal(result.capture_sha256,py.stdout.trim());assert.equal(result.expires_at,1120);
});
test('quote, receipt, challenge, PCR, baseline pins, context and expiry tamper are refused',async()=>{
 assert.ok(module);const f=fixture();
 for(const mutate of [x=>x.capture.issued_challenge.ed25519_signature_b64=Buffer.alloc(64).toString('base64'),x=>x.capture.receipt.ed25519_signature_b64=Buffer.alloc(64).toString('base64'),x=>x.capture.evidence.quote_b64=Buffer.alloc(128).toString('base64'),x=>x.capture.evidence.pcrs['11']='ff'.repeat(32),x=>x.r13.pins.ak_spki_sha256='00'.repeat(32),x=>x.r13.pins.verifier_spki_sha256='00'.repeat(32),x=>x.r13.pins.policy_sha256='00'.repeat(32),x=>x.capture.r13_valid=true,x=>x.capture.evidence.boot_id='00000000-0000-0000-0000-000000000000']){
  const x=structuredClone({r13:f.r13,capture:f.capture});mutate(x);await assert.rejects(module.verifyCapture(x.r13,x.capture,f.boot,1000));
 }
 for(const now of [999,1120])await assert.rejects(module.verifyCapture(f.r13,f.capture,f.boot,now));
 await assert.rejects(module.verifyCapture(f.r13,f.capture,'9e8897df-a2bb-4cdd-97c6-1e8ae42550fa',1000));
});
test('even a freshly signed receipt cannot conceal an invalid raw TPM signature',async()=>{
 assert.ok(module);const f=fixture();f.capture.evidence.signature_b64=Buffer.concat([Buffer.from('0014000b0100','hex'),Buffer.alloc(256)]).toString('base64');
 const p=f.capture.receipt.payload;p.quote_signature_sha256=digest(Buffer.from(f.capture.evidence.signature_b64,'base64'));p.evidence_sha256=digest(encode(f.capture.evidence));
 f.capture.receipt.ed25519_signature_b64=f.signObject('ARDA/R13/EVIDENCE-RECEIPT/v2',p);
 await assert.rejects(module.verifyCapture(f.r13,f.capture,f.boot,1000));
});
