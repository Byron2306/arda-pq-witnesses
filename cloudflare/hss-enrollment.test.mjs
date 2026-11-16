import test from 'node:test';import assert from 'node:assert/strict';
import {CloudflareEnrollmentService} from './hss-enrollment.mjs';
import {canonical,sha} from './hss-guard.mjs';
const now=1000,image='sha256:'+'ab'.repeat(32),wasm='cd'.repeat(32);
const ceremony={schema:'arda.pq.enrollment_ceremony.v1',nonce:'ef'.repeat(32),image_digest:image,identities:{github:'Byron2306/arda-pq-witnesses',hf:'Byron230686/arda-pq-policy-witness',cloudflare:'arda-pq-release-witness'},issued_at:900,expires_at:2000,production_authorized:false};
const anchor={schema:'arda.hss.anchor.v1',repository:'Byron2306/arda-hss-leaf-anchor',genesis_commit:'12'.repeat(20),ruleset_id:7,rules_sha256:'34'.repeat(32)};
const config={schema:'arda.cf.hss.enrollment_config.v1',worker_identity:'arda-pq-release-witness',ceremony,ceremony_sha256:await sha(canonical(ceremony)),anchor,wasm_sha256:wasm,production_authorized:false};
async function setup(){const values=new Map(),commits=[];let generations=0,burns=0;const storage={async get(k){return structuredClone(values.get(k));},async put(k,v){if(typeof k==='string')values.set(k,structuredClone(v));else for(const [name,value] of Object.entries(k))values.set(name,structuredClone(value));commits.push(structuredClone([...values]));},async sync(){}};
 const engine={leaf:s=>s[7],async generate(){generations++;const publicKey=new Uint8Array(60);publicKey.set([0,0,0,1,0,0,0,6,0,0,0,4]);return {privateState:new Uint8Array(64),publicKey};},async sign(s,p,m){const next=s.slice();next[7]++;return {privateState:next,signature:new Uint8Array(1456),leaf:0};}};
 const env={ARDA_CF_CONFIG_JSON:new TextDecoder().decode(canonical(config)),ARDA_CF_CONFIG_SHA256:await sha(canonical(config)),ARDA_CF_SETUP_CLIENT_TOKEN:'aa'.repeat(32),ARDA_CF_ANCHOR_TOKEN:'fixture-token'};
 const anchorFactory=c=>({configuration:c,async burn(r){burns++;return {...r,ref:'refs/tags/test',tag_sha:'56'.repeat(20)};}});
 const service=new CloudflareEnrollmentService({storage,env,engine,wasmSha:wasm,clock:()=>now,anchorFactory});
 return {service,env,values,storage,commits,get generations(){return generations;},get burns(){return burns;}};
}
function request(action='provision_cloudflare_key',token='aa'.repeat(32),path='/v1/enroll-cf'){return new Request('https://arda-pq-release-witness.example.workers.dev'+path,{method:'POST',headers:{'X-ARDA-Setup-Token':token,'Content-Type':'application/json'},body:new TextDecoder().decode(canonical({action,ceremony_sha256:config.ceremony_sha256}))});}
test('health and startup do not generate an HSS key',async()=>{const s=await setup();const r=await s.service.fetch(new Request('https://example/healthz'));assert.equal(r.status,200);assert.equal(s.generations,0);});
test('only explicit authenticated enrollment consumes leaf zero and caches public record',async()=>{const s=await setup();for(let i=0;i<2;i++){const r=await s.service.fetch(request());assert.equal(r.status,200,await r.clone().text());const body=await r.json();assert.equal(body.registration.payload.algorithm,'HSS-LMS-SHA256-N32-H10-W8');assert.equal(body.production_authorized,false);assert.equal(body.registration.payload.secret_name,null);}assert.equal(s.generations,1);assert.equal(s.burns,1);assert.equal(s.values.get('key').privateState[7],1);});
test('wrong credential and arbitrary vote requests do not generate keys',async()=>{const s=await setup();assert.equal((await s.service.fetch(request(undefined,'bb'.repeat(32)))).status,401);assert.equal((await s.service.fetch(request('sign'))).status,400);assert.equal((await s.service.fetch(request(undefined,undefined,'/v1/review-vote'))).status,404);assert.equal(s.generations,0);});
test('configuration pin mismatch refuses before key generation',async()=>{const s=await setup();s.env.ARDA_CF_CONFIG_SHA256='ff'.repeat(32);assert.equal((await s.service.fetch(request())).status,503);assert.equal(s.generations,0);});
test('missing public output after an advanced key never generates or signs again',async()=>{const s=await setup();assert.equal((await s.service.fetch(request())).status,200);s.values.delete('registration');assert.equal((await s.service.fetch(request())).status,409);assert.equal(s.generations,1);assert.equal(s.burns,1);});
test('disposable self-test creates no durable key and performs no anchor mutation',async()=>{const s=await setup();const r=await s.service.fetch(request('run_disposable_hss_self_test',undefined,'/v1/self-test'));assert.equal(r.status,200);const body=await r.json();assert.equal(body.disposable,true);assert.equal(body.production_authorized,false);assert.equal(s.values.has('key'),false);assert.equal(s.burns,0);});
function statusRequest(token='aa'.repeat(32)){return new Request('https://example/v1/enrollment-status',{headers:{'X-ARDA-Setup-Token':token}});}
test('authenticated inspection reads only selected public state and never changes keys',async()=>{
 const s=await setup();const privateState=new Uint8Array(64);privateState.fill(77);privateState[7]=0;
 s.values.set('key',{schema:'arda.hss.key_state.v1',state:'QUARANTINED',key_sha256:'ab'.repeat(32),privateState,publicKey:new Uint8Array(60)});
 s.service.anchorFactory=c=>({async inspect(){return {ok:false,http_status:401,reason:'ANCHOR_HTTP_REFUSED'};}});
 const before=structuredClone([...s.values]);const r=await s.service.fetch(statusRequest());assert.equal(r.status,200);
 const body=await r.json();assert.equal(body.key.present,true);assert.equal(body.key.state,'QUARANTINED');assert.equal(body.key.next_leaf,0);assert.equal(body.anchor_read_check.http_status,401);
 assert.equal(body.production_authorized,false);assert.deepEqual([...s.values],before);assert.equal(s.generations,0);assert.equal(s.burns,0);
 assert.equal(JSON.stringify(body).includes('privateState'),false);assert.equal(JSON.stringify(body).includes('publicKey'),false);
});
test('unauthenticated inspection reveals no durable key metadata',async()=>{const s=await setup();const r=await s.service.fetch(statusRequest('bb'.repeat(32)));assert.equal(r.status,401);assert.equal(s.generations,0);});
test('inspection error responses never return credentials or arbitrary exception text',async()=>{
 const s=await setup();s.env.ARDA_CF_ANCHOR_TOKEN='PRIVATE_SETUP_TOKEN';s.service.anchorFactory=()=>{throw Error('PRIVATE_SETUP_TOKEN');};
 const r=await s.service.fetch(statusRequest());assert.equal(r.status,200);assert.equal((await r.text()).includes('PRIVATE_SETUP_TOKEN'),false);
});
test('inspection can read expired-ceremony state while enrollment stays refused',async()=>{
 const s=await setup();s.service.clock=()=>3000;
 assert.equal((await s.service.fetch(statusRequest())).status,200);
 assert.equal((await s.service.fetch(request())).status,503);assert.equal(s.generations,0);
});

test('every active advanced enrollment commit contains the matching public registration',async()=>{
 const s=await setup();const r=await s.service.fetch(request());assert.equal(r.status,200);
 const body=await r.json();let advanced=0;
 for(const entries of s.commits){const snapshot=new Map(entries),key=snapshot.get('key');if(key?.state==='ACTIVE'&&key.privateState[7]===1){advanced++;assert.deepEqual(snapshot.get('registration'),body.registration);}}
 assert.ok(advanced>0);
});
test('interruption after the advanced enrollment commit leaves a recoverable public cache',async()=>{
 const s=await setup(),put=s.storage.put.bind(s.storage);let interrupted=false;
 s.storage.put=async(k,v)=>{await put(k,v);if(!interrupted&&s.values.get('key')?.privateState[7]===1&&!s.values.has('registration')){interrupted=true;throw Error('simulated interruption between separate writes');}};
 const r=await s.service.fetch(request());assert.equal(r.status,200);assert.equal(s.values.has('registration'),true);
 assert.equal((await s.service.fetch(request())).status,200);assert.equal(s.generations,1);assert.equal(s.burns,1);
});
test('uncertain atomic commit withholds output and quarantines without another burn',async()=>{
 const s=await setup(),put=s.storage.put.bind(s.storage);let failed=false;
 s.storage.put=async(k,v)=>{await put(k,v);if(typeof k==='object'&&!failed){failed=true;throw Error('lost acknowledgment after atomic commit');}};
 const r=await s.service.fetch(request());assert.equal(r.status,409);assert.equal((await r.json()).registration,undefined);
 assert.equal(s.values.get('key').state,'QUARANTINED');assert.equal(s.values.has('registration'),true);
 assert.equal((await s.service.fetch(request())).status,409);assert.equal(s.burns,1);
});
async function orphan(){
 const s=await setup();assert.equal((await s.service.fetch(request())).status,200);s.values.delete('registration');
 const old=s.values.get('key'),generate=s.service.engine.generate.bind(s.service.engine);
 s.service.engine.generate=async()=>{const k=await generate();k.publicKey[59]=99;return k;};
 s.service.anchorFactory=configuration=>({configuration,async inspect(){return {ok:true,http_status:200,reason:'ANCHOR_READ_AND_RULE_PIN_VALID'};},async readBurn(e){return {...e,kind:'registration',issued_at:1000,expires_at:2000,ref:'refs/tags/arda-hss-leaf-'+e.key_sha256+'-0000'};}});
 const input={action:'replace_orphaned_cloudflare_key',ceremony_sha256:config.ceremony_sha256,config_sha256:s.env.ARDA_CF_CONFIG_SHA256,expected_key_sha256:old.key_sha256,expected_next_leaf:1,old_ceremony:ceremony,prior_tag_sha:'56'.repeat(20)};
 return {s,old:structuredClone(old),input};
}
function rotationRequest(input,token='aa'.repeat(32)){return new Request('https://example/v1/replace-orphaned-key',{method:'POST',headers:{'X-ARDA-Setup-Token':token,'Content-Type':'application/json'},body:new TextDecoder().decode(canonical(input))});}
test('explicit orphan replacement archives original private bytes and never signs a leaf',async()=>{
 const {s,old,input}=await orphan();const r=await s.service.fetch(rotationRequest(input));assert.equal(r.status,200,await r.clone().text());
 const body=await r.json(),key=s.values.get('key'),archive=s.values.get('retired/'+old.key_sha256);
 assert.equal(key.privateState[7],0);assert.notEqual(key.key_sha256,old.key_sha256);assert.equal(body.receipt.replacement_key_sha256,key.key_sha256);
 assert.equal(archive.state,'RETIRED');assert.deepEqual(archive.original_state,old);assert.equal(s.burns,1);assert.equal(s.generations,2);assert.equal(s.values.has('registration'),false);
 assert.equal(JSON.stringify(body).includes('privateState'),false);
 const replay=await s.service.fetch(rotationRequest(input));assert.equal(replay.status,200);assert.deepEqual(await replay.json(),body);assert.equal(s.generations,2);
});
test('replacement refuses a completed registration without generating another key',async()=>{
 const {s,input}=await orphan();s.values.set('registration',{payload:{}});
 assert.equal((await s.service.fetch(rotationRequest(input))).status,409);assert.equal(s.generations,1);
});
test('replacement rejects wrong state pins, old ceremony and authentication before generation',async()=>{
 for(const change of [{expected_key_sha256:'00'.repeat(32)},{expected_next_leaf:0},{config_sha256:'00'.repeat(32)},{old_ceremony:{...ceremony,nonce:'00'.repeat(32)}}]){
  const {s,input}=await orphan();assert.notEqual((await s.service.fetch(rotationRequest({...input,...change}))).status,200);assert.equal(s.generations,1);
 }
 const {s,input}=await orphan();assert.equal((await s.service.fetch(rotationRequest(input,'bb'.repeat(32)))).status,401);assert.equal(s.generations,1);
});
test('replacement refuses quarantined or changed counters and an invalid marker',async()=>{
 for(const fault of ['quarantined','advanced','marker']){const {s,input}=await orphan();const state=s.values.get('key');
  if(fault==='quarantined')state.state='QUARANTINED';if(fault==='advanced')state.privateState[7]=2;if(fault==='marker')s.service.anchorFactory=()=>({async readBurn(){throw Error('invalid marker');}});
  assert.equal((await s.service.fetch(rotationRequest(input))).status,409);assert.equal(s.generations,1);
 }
});
test('replacement rejects expiry and preserves original state if generation crosses expiry',async()=>{
 const a=await orphan();a.s.service.clock=()=>3000;assert.equal((await a.s.service.fetch(rotationRequest(a.input))).status,503);assert.equal(a.s.generations,1);
 const {s,input,old}=await orphan(),generate=s.service.engine.generate.bind(s.service.engine);s.service.engine.generate=async()=>{const key=await generate();s.service.clock=()=>3000;return key;};
 assert.equal((await s.service.fetch(rotationRequest(input))).status,409);assert.deepEqual(s.values.get('key'),old);assert.equal(s.values.has('retired/'+old.key_sha256),false);
});
test('lost replacement commit acknowledgement can be retried without another generated key',async()=>{
 const {s,input,old}=await orphan(),put=s.storage.put.bind(s.storage);let lost=false;
 s.storage.put=async(k,v)=>{await put(k,v);if(typeof k==='object'&&Object.keys(k).some(x=>x.startsWith('retired/'))&&!lost){lost=true;throw Error('lost acknowledgment');}};
 assert.equal((await s.service.fetch(rotationRequest(input))).status,409);assert.equal(s.values.get('retired/'+old.key_sha256).state,'RETIRED');
 assert.equal((await s.service.fetch(rotationRequest(input))).status,200);assert.equal(s.generations,2);assert.equal(s.burns,1);
});
test('fresh ceremony replaces an orphan whose original ceremony has expired',async()=>{
 const {s,input}=await orphan();s.service.clock=()=>3000;
 const freshCeremony={...ceremony,nonce:'ee'.repeat(32),issued_at:2900,expires_at:4000};
 const fresh={...config,ceremony:freshCeremony,ceremony_sha256:await sha(canonical(freshCeremony))};
 s.env.ARDA_CF_CONFIG_JSON=new TextDecoder().decode(canonical(fresh));s.env.ARDA_CF_CONFIG_SHA256=await sha(canonical(fresh));
 const updated={...input,ceremony_sha256:fresh.ceremony_sha256,config_sha256:s.env.ARDA_CF_CONFIG_SHA256};
 const r=await s.service.fetch(rotationRequest(updated));assert.equal(r.status,200);assert.equal(s.values.get('key').ceremony_sha256,fresh.ceremony_sha256);
 assert.equal((await r.json()).receipt.old_ceremony_sha256,config.ceremony_sha256);
});
test('lost rotation acknowledgement remains recoverable by read-only status after expiry',async()=>{
 const {s,input}=await orphan();const r=await s.service.fetch(rotationRequest(input));assert.equal(r.status,200);const first=await r.json();
 s.service.clock=()=>3000;const status=await s.service.fetch(statusRequest());assert.equal(status.status,200);
 const body=await status.json();assert.deepEqual(body.replacement_receipt,first.receipt);assert.equal(body.replacement_receipt_sha256,first.receipt_sha256);
 assert.equal((await s.service.fetch(rotationRequest(input))).status,503);assert.equal(s.generations,2);assert.equal(s.burns,1);
});
