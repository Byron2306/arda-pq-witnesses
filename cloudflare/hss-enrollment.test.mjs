import test from 'node:test';import assert from 'node:assert/strict';
import {CloudflareEnrollmentService} from './hss-enrollment.mjs';
import {canonical,sha} from './hss-guard.mjs';
const now=1000,image='sha256:'+'ab'.repeat(32),wasm='cd'.repeat(32);
const ceremony={schema:'arda.pq.enrollment_ceremony.v1',nonce:'ef'.repeat(32),image_digest:image,identities:{github:'Byron2306/arda-pq-witnesses',hf:'Byron230686/arda-pq-policy-witness',cloudflare:'arda-pq-release-witness'},issued_at:900,expires_at:2000,production_authorized:false};
const anchor={schema:'arda.hss.anchor.v1',repository:'Byron2306/arda-hss-leaf-anchor',genesis_commit:'12'.repeat(20),ruleset_id:7,rules_sha256:'34'.repeat(32)};
const config={schema:'arda.cf.hss.enrollment_config.v1',worker_identity:'arda-pq-release-witness',ceremony,ceremony_sha256:await sha(canonical(ceremony)),anchor,wasm_sha256:wasm,production_authorized:false};
async function setup(){const values=new Map();let generations=0,burns=0;const storage={async get(k){return structuredClone(values.get(k));},async put(k,v){values.set(k,structuredClone(v));},async sync(){}};
 const engine={leaf:s=>s[7],async generate(){generations++;const publicKey=new Uint8Array(60);publicKey.set([0,0,0,1,0,0,0,6,0,0,0,4]);return {privateState:new Uint8Array(64),publicKey};},async sign(s,p,m){const next=s.slice();next[7]++;return {privateState:next,signature:new Uint8Array(1456),leaf:0};}};
 const env={ARDA_CF_CONFIG_JSON:new TextDecoder().decode(canonical(config)),ARDA_CF_CONFIG_SHA256:await sha(canonical(config)),ARDA_CF_SETUP_CLIENT_TOKEN:'aa'.repeat(32),ARDA_CF_ANCHOR_TOKEN:'fixture-token'};
 const anchorFactory=c=>({configuration:c,async burn(r){burns++;return {...r,ref:'refs/tags/test',tag_sha:'56'.repeat(20)};}});
 const service=new CloudflareEnrollmentService({storage,env,engine,wasmSha:wasm,clock:()=>now,anchorFactory});
 return {service,env,values,get generations(){return generations;},get burns(){return burns;}};
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
