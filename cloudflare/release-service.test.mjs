import test from 'node:test';import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';import {spawnSync} from 'node:child_process';
import {HssEngine} from './hss-engine.mjs';import {releaseFixture,encode,digest,wireConfig} from './release-fixtures.mjs';
const mod=await import('./release-service.mjs').catch(()=>null);
const engine=await HssEngine.fromBytes(readFileSync(new URL('../build/hss-state.wasm',import.meta.url))),key=await engine.generate();
async function setup(){
 const f=releaseFixture(),w=f.config.policy.witnesses.find(w=>w.provider==='cloudflare');w.key_sha256=digest(key.publicKey);w.public_key_b64=Buffer.from(key.publicKey).toString('base64');
 f.config.policy_file_sha256=digest(encode(f.config.policy));f.request.proposal.policy_sha256=f.config.policy_file_sha256;
 f.env.ARDA_CF_RELEASE_CONFIG_JSON=encode(wireConfig(f.config)).toString();f.env.ARDA_CF_RELEASE_CONFIG_SHA256=digest(encode(wireConfig(f.config)));f.env.ARDA_CF_ENROLLMENT_JSON=encode(f.config.policy).toString();
 const state=key.privateState.slice();new DataView(state.buffer).setBigUint64(0,1n);
 const values=new Map([['key',{schema:'arda.hss.key_state.v1',publicKey:key.publicKey.slice(),privateState:state,key_sha256:w.key_sha256,anchor_sha256:digest(encode(f.config.anchor)),state:'ACTIVE',clock_watermark:900}],['registration',{payload:{key_sha256:w.key_sha256,public_key_b64:w.public_key_b64}}]]);
 let now=1000,failSync=false;const burns=new Map();let operations=[];
 const storage={async get(k){return structuredClone(values.get(k));},async put(k,v){operations.push('put');if(typeof k==='string')values.set(k,structuredClone(v));else for(const [name,value] of Object.entries(k))values.set(name,structuredClone(value));},async sync(){operations.push('sync');if(failSync)throw Error('fixture sync uncertainty');}};
 const anchor={configuration:f.config.anchor,async burn(r){if(burns.has(r.leaf))throw Error('duplicate external marker');burns.set(r.leaf,structuredClone(r));return {...r,ref:'refs/tags/disposable-'+r.leaf,tag_sha:'12'.repeat(20)};}};
 const options={storage,env:f.env,engine,wasmSha:f.config.wasm_sha256,clock:()=>now,anchorFactory:()=>anchor};
 const make=()=>new mod.CloudflareWitnessService(options);
 let service=mod?make():null;
 return {...f,values,burns,storage,anchor,operations,get service(){return service;},restart(){service=make();},now(n){now=n;},failSync(){failSync=true;}};
}
const request=(s,body=s.request,token='aa'.repeat(32),path='/v1/review-vote')=>new Request('https://fixture.invalid'+path,{method:'POST',headers:{'Content-Type':'application/json','X-ARDA-Review-Token':token},body:encode(body)});
test('in-place release service exists',()=>assert.ok(mod,'in-place release service missing'));
test('real HSS release vote verifies natively, commits cache with state and replays after restart',async()=>{
 assert.ok(mod);const s=await setup(),response=await s.service.fetch(request(s));assert.equal(response.status,200,await response.clone().text());const body=await response.json();assert.equal(s.burns.size,1);assert.equal(s.values.get('key').privateState[7],2);
 const q=digest(encode(s.request.proposal));assert.deepEqual(s.values.get('vote/'+q).vote,body.vote);assert.ok(s.values.get('nonce/1/'+s.request.proposal.nonce));assert.equal(body.production_authorized,false);
 const py=spawnSync('python3',['-c',`import json,sys,base64
from arda_quorum.crypto import Backends
from arda_quorum.quorum import canonical,DOMAIN
x=json.load(sys.stdin);w=next(w for w in x['policy']['witnesses'] if w['provider']=='cloudflare');v=x['vote'];assert Backends().verify(w['algorithm'],base64.b64decode(w['public_key_b64']),DOMAIN+canonical(v['payload']),base64.b64decode(v['signature_b64']))
print('NATIVE_CF_RELEASE_VOTE=PASS')`],{input:encode({policy:s.config.policy,vote:body.vote}),encoding:'utf8'});assert.equal(py.status,0,py.stderr);
 s.restart();s.now(1001);const replay=await s.service.fetch(request(s));assert.equal(replay.status,200);assert.deepEqual(await replay.json(),body);assert.equal(s.burns.size,1);
});
test('auth, body, proposal, R13 and missing/changed key refusals consume no leaf',async()=>{
 assert.ok(mod);const s=await setup();assert.equal((await s.service.fetch(request(s,s.request,'bb'.repeat(32)))).status,401);
 for(const mutate of [x=>x.proposal.generation++,x=>x.capture.receipt.payload.status='PASS_BYPASS',x=>x.production_authorized=true]){
  const x=structuredClone(s.request);mutate(x);assert.equal((await s.service.fetch(request(s,x))).status,400);
 }
 const state=s.values.get('key');state.key_sha256='ff'.repeat(32);assert.equal((await s.service.fetch(request(s))).status,409);assert.equal(s.burns.size,0);
});
test('nonce reuse for another proposal, expired cache and quarantined key are refused',async()=>{
 assert.ok(mod);const s=await setup();assert.equal((await s.service.fetch(request(s))).status,200);const x=structuredClone(s.request);x.proposal.proposal_id='ab'.repeat(16);
 assert.equal((await s.service.fetch(request(s,x))).status,409);assert.equal(s.burns.size,1);
 s.now(1100);assert.notEqual((await s.service.fetch(request(s))).status,200);s.now(1001);s.values.get('key').state='QUARANTINED';assert.equal((await s.service.fetch(request(s))).status,409);
});
test('concurrent POSTs share the gate and durability uncertainty releases no vote',async()=>{
 assert.ok(mod);const s=await setup();const results=await Promise.all([s.service.fetch(request(s)),s.service.fetch(request(s))]);assert.deepEqual(results.map(x=>x.status).sort(),[200,409]);assert.equal(s.burns.size,1);
 const failed=await setup();failed.failSync();const r=await failed.service.fetch(request(failed));assert.equal(r.status,409);assert.equal(failed.values.get('key').state,'QUARANTINED');assert.equal(failed.burns.size,1);
});
test('restoring old private state cannot reuse an externally burned release leaf',async()=>{
 assert.ok(mod);const s=await setup(),old=structuredClone([...s.values]);assert.equal((await s.service.fetch(request(s))).status,200);
 s.values.clear();for(const [k,v]of old)s.values.set(k,v);s.restart();const r=await s.service.fetch(request(s));assert.equal(r.status,409);assert.equal(s.burns.size,1);assert.equal(s.values.get('key').state,'QUARANTINED');
});
test('conflicting length headers are refused before any HSS leaf burn',async()=>{
 assert.ok(mod);const s=await setup(),r=request(s);r.headers.set('Content-Length','1, 2');assert.equal((await s.service.fetch(r)).status,400);assert.equal(s.burns.size,0);
});
test('expiry after marker creation or durable commit never releases a vote',async()=>{
 assert.ok(mod);const a=await setup(),burn=a.anchor.burn.bind(a.anchor);a.anchor.burn=async r=>{const result=await burn(r);a.now(1100);return result;};
 assert.equal((await a.service.fetch(request(a))).status,409);assert.equal(a.burns.size,1);assert.equal(a.values.get('key').privateState[7],1);assert.equal(a.values.get('key').state,'QUARANTINED');
 const b=await setup();b.storage.sync=async()=>b.now(1100);assert.equal((await b.service.fetch(request(b))).status,409);assert.equal(b.values.get('key').state,'QUARANTINED');
});
test('a changed config withholds release and an exact restored config can retrieve durable proof',async()=>{
 assert.ok(mod);const s=await setup(),pin=s.env.ARDA_CF_RELEASE_CONFIG_SHA256;s.storage.sync=async()=>{s.env.ARDA_CF_RELEASE_CONFIG_SHA256='ff'.repeat(32);};
 assert.equal((await s.service.fetch(request(s))).status,409);assert.equal(s.burns.size,1);assert.equal(s.values.get('key').privateState[7],2);
 s.env.ARDA_CF_RELEASE_CONFIG_SHA256=pin;s.restart();const replay=await s.service.fetch(request(s));assert.equal(replay.status,200);assert.equal(s.burns.size,1);
});
test('enrollment and release POSTs share one mutation gate',async()=>{
 assert.ok(mod);const s=await setup();s.env.ARDA_CF_SETUP_CLIENT_TOKEN='bb'.repeat(32);
 const vote=s.service.fetch(request(s));const enrollment=new Request('https://fixture.invalid/v1/enroll-cf',{method:'POST',headers:{'Content-Type':'application/json','X-ARDA-Setup-Token':'bb'.repeat(32)},body:'{}'});
 assert.equal((await s.service.fetch(enrollment)).status,409);assert.equal((await vote).status,200);assert.equal(s.burns.size,1);
});
test('a valid config change during body reading cannot sign the previous approved manifest',async()=>{
 assert.ok(mod);const s=await setup(),r=request(s),get=r.body.getReader.bind(r.body);
 r.body.getReader=()=>{const changed=structuredClone(s.config);changed.expected.manifest_id='different-approved-manifest';s.env.ARDA_CF_RELEASE_CONFIG_JSON=encode(wireConfig(changed)).toString();s.env.ARDA_CF_RELEASE_CONFIG_SHA256=digest(encode(wireConfig(changed)));return get();};
 assert.equal((await s.service.fetch(r)).status,409);assert.equal(s.burns.size,0);
});
test('expiry or config changes during the final durable vote read withhold the response',async()=>{
 assert.ok(mod);
 for(const change of ['expiry','config']){
  const s=await setup(),get=s.storage.get.bind(s.storage);let reads=0;
  s.storage.get=async name=>{const value=await get(name);if(name.startsWith('vote/')&&++reads===2){if(change==='expiry')s.now(1100);else {const changed=structuredClone(s.config);changed.expected.manifest_id='different-approved-manifest';s.env.ARDA_CF_RELEASE_CONFIG_JSON=encode(wireConfig(changed)).toString();s.env.ARDA_CF_RELEASE_CONFIG_SHA256=digest(encode(wireConfig(changed)));}}return value;};
  assert.equal((await s.service.fetch(request(s))).status,409,change);assert.equal(s.burns.size,1);
 }
});
test('clock rollback after signing even within the lease cannot release the cached proof',async()=>{
 assert.ok(mod);const s=await setup(),get=s.storage.get.bind(s.storage);let reads=0;s.storage.sync=async()=>s.now(1002);
 s.storage.get=async name=>{const value=await get(name);if(name.startsWith('vote/')&&++reads===2)s.now(1001);return value;};
 assert.equal((await s.service.fetch(request(s))).status,409);assert.equal(s.burns.size,1);
});
test('health cannot report an old policy with a newly changed configuration pin',async()=>{
 assert.ok(mod);const s=await setup(),get=s.storage.get.bind(s.storage);s.storage.get=async name=>{const value=await get(name);if(name==='key'){const changed=structuredClone(s.config);changed.expected.manifest_id='different-approved-manifest';s.env.ARDA_CF_RELEASE_CONFIG_JSON=encode(wireConfig(changed)).toString();s.env.ARDA_CF_RELEASE_CONFIG_SHA256=digest(encode(wireConfig(changed)));}return value;};
 const r=await s.service.fetch(new Request('https://fixture.invalid/healthz'));assert.equal(r.status,409);assert.equal(s.burns.size,0);
});
test('authenticated archive diagnostics retrieve expired public proof without signing or authorizing',async()=>{
 const s=await setup();assert.equal((await s.service.fetch(request(s))).status,200);
 const hash=digest(encode(s.request.proposal)),cached=structuredClone(s.values.get('vote/'+hash).vote),before=structuredClone([...s.values]);s.now(1100);
 const url='https://fixture.invalid/v1/review-status?proposal_sha256='+hash;
 assert.equal((await s.service.fetch(new Request(url))).status,401);
 const response=await s.service.fetch(new Request(url,{headers:{'X-ARDA-Review-Token':'aa'.repeat(32)}}));assert.equal(response.status,200);
 const body=await response.json();assert.deepEqual(body.archived_vote,cached);assert.equal(body.archived_vote_expired,true);assert.equal(body.current_authorization,false);assert.equal(body.diagnostic_read_only,true);assert.equal(body.production_authorized,false);
 assert.equal(s.burns.size,1);assert.deepEqual([...s.values],before);assert.notEqual((await s.service.fetch(request(s))).status,200);
});
test('archive diagnostics reject malformed queries and mismatched cached binding',async()=>{
 const s=await setup();assert.equal((await s.service.fetch(request(s))).status,200);const hash=digest(encode(s.request.proposal));
 for(const suffix of ['proposal_sha256=bad','proposal_sha256='+hash+'&extra=1','proposal_sha256='+hash+'&proposal_sha256='+hash]){
 const r=await s.service.fetch(new Request('https://fixture.invalid/v1/review-status?'+suffix,{headers:{'X-ARDA-Review-Token':'aa'.repeat(32)}}));assert.notEqual(r.status,200);
 }
 s.values.get('vote/'+hash).vote.payload.key_sha256='ff'.repeat(32);
 const r=await s.service.fetch(new Request('https://fixture.invalid/v1/review-status?proposal_sha256='+hash,{headers:{'X-ARDA-Review-Token':'aa'.repeat(32)}}));assert.notEqual(r.status,200);assert.equal(s.burns.size,1);
});
