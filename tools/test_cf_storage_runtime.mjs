// Disposable, offline integration check. Requires the pinned Cloudflare npm dependencies.
import {Miniflare,convertV4MiniflareOptions} from '../providers/cloudflare/node_modules/miniflare/dist/src/index.js';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {readFileSync} from 'node:fs';
import {canonical,sha} from '../cloudflare/hss-guard.mjs';
import {rulesProjection} from '../cloudflare/hss-anchor.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const wasm=readFileSync(root+'build/hss-state.wasm');const now=Math.floor(Date.now()/1000);
const rules={id:7,target:'tag',enforcement:'active',bypass_actors:[],conditions:{ref_name:{include:['refs/tags/arda-hss-leaf-*'],exclude:[]}},rules:[{type:'deletion'},{type:'update'}]};
const c={schema:'arda.cf.hss.enrollment_config.v1',worker_identity:'arda-pq-release-witness',ceremony:{schema:'arda.pq.enrollment_ceremony.v1',nonce:'ab'.repeat(32),image_digest:'sha256:'+'cd'.repeat(32),identities:{github:'Byron2306/arda-pq-witnesses',hf:'Byron230686/arda-pq-policy-witness',cloudflare:'arda-pq-release-witness'},issued_at:now-60,expires_at:now+1800,production_authorized:false},anchor:{schema:'arda.hss.anchor.v1',repository:'Byron2306/arda-hss-leaf-anchor',genesis_commit:'12'.repeat(20),ruleset_id:7,rules_sha256:await sha(canonical(rulesProjection(rules)))},wasm_sha256:await sha(wasm),production_authorized:false};c.ceremony_sha256=await sha(canonical(c.ceremony));
const text=b=>new TextDecoder().decode(b);
const paths=['providers/cloudflare/worker.mjs','cloudflare/hss-enrollment.mjs','cloudflare/hss-guard.mjs','cloudflare/hss-engine.mjs','cloudflare/hss-anchor.mjs','cloudflare/hss-rotation.mjs','cloudflare/release-service.mjs','cloudflare/release-config.mjs','cloudflare/r13-capture.mjs','cloudflare/review-protocol.mjs','build/hss-state-meta.mjs'];
const modules=paths.map(p=>({type:'ESModule',path:root+p,contents:readFileSync(root+p,'utf8')}));modules.push({type:'CompiledWasm',path:root+'build/hss-state.wasm',contents:wasm});
const options=async()=>convertV4MiniflareOptions({host:'127.0.0.1',inspectorPort:0,workers:[{name:'test',modules,modulesRoot:root,compatibilityDate:'2026-11-15',bindings:{ARDA_CF_CONFIG_JSON:text(canonical(c)),ARDA_CF_CONFIG_SHA256:await sha(canonical(c)),ARDA_CF_ANCHOR_TOKEN:'disposable-test-token',ARDA_CF_SETUP_CLIENT_TOKEN:'aa'.repeat(32)},durableObjects:{HSS_SIGNER:{className:'HssEnrollmentObject',useSQLite:true}},outboundService:'mock'},{name:'mock',modules:true,compatibilityDate:'2026-11-15',script:`const refs=new Map(),tags=new Map();export default {async fetch(r){const p=new URL(r.url).pathname;if(p.endsWith('/rulesets/7')&&r.method==='GET')return Response.json(${JSON.stringify(rules)});
if(p.endsWith('/git/tags')&&r.method==='POST'){const b=await r.json(),bytes=new Uint8Array(await crypto.subtle.digest('SHA-1',new TextEncoder().encode(JSON.stringify(b)))),sha=Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');tags.set(sha,{...b,sha,object:{type:'commit',sha:b.object}});return Response.json({sha},{status:201});}
if(p.endsWith('/git/refs')&&r.method==='POST'){const b=await r.json();if(refs.has(b.ref))return Response.json({},{status:422});refs.set(b.ref,b.sha);return Response.json({ref:b.ref,object:{type:'tag',sha:b.sha}},{status:201});}
if(p.includes('/git/ref/tags/')&&r.method==='GET'){const ref='refs/'+p.split('/git/ref/')[1];if(!refs.has(ref))return Response.json({},{status:404});return Response.json({ref,object:{type:'tag',sha:refs.get(ref)}});}
if(p.includes('/git/tags/')&&r.method==='GET'){const tag=tags.get(p.split('/git/tags/')[1]);return Response.json(tag??{},{status:tag?200:404});}
return Response.json({error:'UNEXPECTED_MOCK_REQUEST'},{status:400});}}`} ]});
let mf=new Miniflare(await options());
async function status(){const r=await mf.dispatchFetch('https://example/v1/enrollment-status',{headers:{'X-ARDA-Setup-Token':'aa'.repeat(32)}});assert.equal(r.status,200);return r.json();}
async function post(path,body){const r=await mf.dispatchFetch('https://example'+path,{method:'POST',headers:{'X-ARDA-Setup-Token':'aa'.repeat(32),'Content-Type':'application/json'},body:canonical(body)});const result=await r.json();assert.equal(r.status,200,JSON.stringify(result));return result;}
try{
 assert.equal((await status()).key.present,false);
 const input={action:'provision_cloudflare_key',ceremony_sha256:c.ceremony_sha256};
 const first=await post('/v1/enroll-cf',input);assert.ok(first.registration);
 const after=await status();assert.equal(after.key.state,'ACTIVE');assert.equal(after.key.next_leaf,1);assert.equal(after.cached_registration_present,true);
 // New disposable runtime reproduces the legacy separate-write gap through
 // a local storage wrapper. Production source files and provider state are untouched.
 await mf.dispose();
 modules[0].contents='let legacyCacheDrop=true;\n'+modules[0].contents.replace('storage:ctx.storage',`storage:{get:(...a)=>ctx.storage.get(...a),sync:()=>ctx.storage.sync(),put:async(k,v)=>{if(legacyCacheDrop&&typeof k==='object'&&k.registration){legacyCacheDrop=false;return ctx.storage.put('key',k.key);}return typeof k==='string'?ctx.storage.put(k,v):ctx.storage.put(k);}}`);
 mf=new Miniflare(await options());
 await post('/v1/enroll-cf',input);
 const orphan=await status();assert.equal(orphan.key.next_leaf,1);assert.equal(orphan.cached_registration_present,false);
 const mock=await mf.getWorker('mock'),refResponse=await mock.fetch('https://api.github.com/repos/Byron2306/arda-hss-leaf-anchor/git/ref/tags/arda-hss-leaf-'+orphan.key.key_sha256+'-0000'),ref=await refResponse.json();
 const rotation={action:'replace_orphaned_cloudflare_key',ceremony_sha256:c.ceremony_sha256,config_sha256:await sha(canonical(c)),old_ceremony:c.ceremony,expected_key_sha256:orphan.key.key_sha256,expected_next_leaf:1,prior_tag_sha:ref.object.sha};
 const replaced=await post('/v1/replace-orphaned-key',rotation);assert.notEqual(replaced.receipt.replacement_key_sha256,orphan.key.key_sha256);
 const next=await status();assert.equal(next.key.next_leaf,0);assert.equal(next.cached_registration_present,false);
 const replay=await post('/v1/replace-orphaned-key',rotation);assert.deepEqual(replay,replaced);
 const final=await post('/v1/enroll-cf',input);assert.equal(final.registration.payload.key_sha256,replaced.receipt.replacement_key_sha256);
 const verification=spawnSync('python3',['-c',`import json,sys,time
from arda_quorum.crypto import Backends
from arda_quorum.enrollment import check_record
x=json.load(sys.stdin);check_record(x['record'],x['ceremony'],now=int(time.time()),backends=Backends())
print('NATIVE_REPLACEMENT_PROOF=PASS')`],{cwd:root,input:canonical({record:final.registration,ceremony:c.ceremony}),encoding:'utf8'});
 assert.equal(verification.status,0,verification.stderr);console.log(verification.stdout.trim());
 assert.deepEqual(await post('/v1/replace-orphaned-key',rotation),replaced);
 const last=await status();assert.equal(last.key.next_leaf,1);assert.equal(last.cached_registration_present,true);assert.equal(last.anchor_read_check.ok,true);assert.equal(last.production_authorized,false);
 console.log('DISPOSABLE_SQLITE_ENROLLMENT=PASS');console.log('ORPHAN_REPLACEMENT_AND_REPLAY=PASS');console.log('POST_REPLACEMENT_ENROLLMENT=PASS');console.log('LIVE_PROVIDER_CALLS=0');console.log('PRODUCTION_AUTHORIZED=FALSE');console.log('INTERLOCK=KEEP_CLOSED');
}finally{await mf.dispose();}
