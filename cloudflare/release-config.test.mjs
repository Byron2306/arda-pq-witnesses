import test from 'node:test';import assert from 'node:assert/strict';
import {releaseFixture,encode,digest,wireConfig} from './release-fixtures.mjs';
const module=await import('./release-config.mjs').catch(()=>null);
test('release proposal validator exists',()=>assert.ok(module,'release configuration/proposal validator missing'));
test('valid pinned configuration and raw R13 capture produce only the fixed v1 vote',async()=>{
 assert.ok(module);const f=releaseFixture(),c=await module.validateReleaseConfig(f.env,f.config.wasm_sha256,1000);
 const r=await module.validateReview(c,f.request,1000);
 assert.equal(r.payload.provider,'cloudflare');assert.equal(r.payload.policy_sha256,f.config.policy_file_sha256);assert.equal(r.payload.proposal_sha256,digest(encode(f.request.proposal)));assert.equal(r.payload.expires_at,1100);assert.equal(r.payload.decision,'APPROVE');
});
test('untrusted proposal identity, epoch, hash, capture, time or fields cannot request a vote',async()=>{
 assert.ok(module);const f=releaseFixture(),c=await module.validateReleaseConfig(f.env,f.config.wasm_sha256,1000);
 for(const mutate of [x=>x.proposal.generation++,x=>x.proposal.manifest_digest='sha256:'+'ff'.repeat(32),x=>x.proposal.machine_id_sha256='ff'.repeat(32),x=>x.proposal.boot_id='9e8897df-a2bb-4cdd-97c6-1e8ae42550fa',x=>x.proposal.epoch++,x=>x.proposal.policy_sha256='ff'.repeat(32),x=>x.proposal.r13_evidence_sha256='ff'.repeat(32),x=>x.proposal.expires_at=1121,x=>x.proposal.action='execute_release',x=>x.proposal.nonce='bad',x=>x.r13_valid=true,x=>x.proposal.issued_at=1001]){
  const x=structuredClone(f.request);mutate(x);await assert.rejects(module.validateReview(c,x,1000));
 }
 await assert.rejects(module.validateReview(c,f.request,1100));
});
test('disabled, altered, expired, foreign or substituted configuration is refused',async()=>{
 assert.ok(module);const f=releaseFixture();
 await assert.rejects(module.validateReleaseConfig({...f.env,ARDA_CF_RELEASE_ENABLED:'false'},f.config.wasm_sha256,1000));
 await assert.rejects(module.validateReleaseConfig({...f.env,ARDA_CF_RELEASE_CONFIG_SHA256:'ff'.repeat(32)},f.config.wasm_sha256,1000));
 for(const mutate of [x=>x.policy.witnesses[0].key_sha256='ff'.repeat(32),x=>x.policy.witnesses[0].role='build_witness',x=>x.policy.epoch=0,x=>x.policy.production_authorized=true,x=>x.expected.extra=true,x=>x.r13.pins.policy_sha256='ff'.repeat(32),x=>x.worker_identity='other',x=>x.wasm_sha256='ff'.repeat(32)]){
  const config=structuredClone(f.config);mutate(config);const raw=encode(wireConfig(config));await assert.rejects(module.validateReleaseConfig({...f.env,ARDA_CF_RELEASE_CONFIG_JSON:raw.toString(),ARDA_CF_RELEASE_CONFIG_SHA256:digest(raw),ARDA_CF_ENROLLMENT_JSON:encode(config.policy).toString()},f.config.wasm_sha256,1000));
 }
 await assert.rejects(module.validateReleaseConfig(f.env,f.config.wasm_sha256,2000));
});
test('a release vote cannot outlive the approved staging manifest',async()=>{
 assert.ok(module);const f=releaseFixture();f.config.stage_window={issued_at:900,expires_at:1050};
 await assert.rejects(module.validateReview(f.config,f.request,1000));
});
test('policy is supplied separately so every Cloudflare binding fits its 5KB limit',async()=>{
 assert.ok(module);const f=releaseFixture(),{policy,...wire}=f.config;
 const env={...f.env,ARDA_CF_RELEASE_CONFIG_JSON:encode(wire).toString(),ARDA_CF_RELEASE_CONFIG_SHA256:digest(encode(wire)),ARDA_CF_ENROLLMENT_JSON:encode(policy).toString()};
 const c=await module.validateReleaseConfig(env,f.config.wasm_sha256,1000);assert.equal(c.policy_file_sha256,f.config.policy_file_sha256);
});
test('release health requires a valid review token distinct from enrollment setup',async()=>{
 assert.ok(module);const f=releaseFixture();
 for(const env of [{...f.env,ARDA_CF_REVIEW_CLIENT_TOKEN:undefined},{...f.env,ARDA_CF_SETUP_CLIENT_TOKEN:f.env.ARDA_CF_REVIEW_CLIENT_TOKEN}])await assert.rejects(module.validateReleaseConfig(env,f.config.wasm_sha256,1000));
});
for(const [field,suffix] of [['nonce','\n'],['proposal_id','\u2028']])test('Python-invalid trailing line terminator in '+field+' is refused before signing',async()=>{
 assert.ok(module);const f=releaseFixture(),c=await module.validateReleaseConfig(f.env,f.config.wasm_sha256,1000),r=structuredClone(f.request);r.proposal[field]+=suffix;await assert.rejects(module.validateReview(c,r,1000));
});
