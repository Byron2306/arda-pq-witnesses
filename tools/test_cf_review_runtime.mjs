// Disposable real Worker/SQLite/Wasm review acceptance. All external calls are mocked.
import {Miniflare,convertV4MiniflareOptions} from '../providers/cloudflare/node_modules/miniflare/dist/src/index.js';
import {readFileSync,mkdtempSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {fileURLToPath} from 'node:url';import {spawnSync} from 'node:child_process';import assert from 'node:assert/strict';
import {releaseFixture,encode,digest,wireConfig} from '../cloudflare/release-fixtures.mjs';
import {rulesProjection} from '../cloudflare/hss-anchor.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),bundle=process.argv[2]?process.argv[2].replace(/\/$/,'')+'/':root,now=Math.floor(Date.now()/1000),f=releaseFixture(now),wasm=readFileSync(bundle+'build/hss-state.wasm'),wasmSha=digest(wasm);
const rules={id:7,target:'tag',enforcement:'active',bypass_actors:[],conditions:{ref_name:{include:['refs/tags/arda-hss-leaf-*'],exclude:[]}},rules:[{type:'update'},{type:'deletion'}]};
f.config.wasm_sha256=wasmSha;f.config.anchor.rules_sha256=digest(encode(rulesProjection(rules)));
const ceremony={schema:'arda.pq.enrollment_ceremony.v1',nonce:'ab'.repeat(32),image_digest:'sha256:'+'cd'.repeat(32),identities:{github:'Byron2306/arda-pq-witnesses',hf:'Byron230686/arda-pq-policy-witness',cloudflare:'arda-pq-release-witness'},issued_at:now-60,expires_at:now+1800,production_authorized:false};
const enrollment={schema:'arda.cf.hss.enrollment_config.v1',worker_identity:'arda-pq-release-witness',ceremony,ceremony_sha256:digest(encode(ceremony)),anchor:f.config.anchor,wasm_sha256:wasmSha,production_authorized:false};
const bindings={ARDA_CF_CONFIG_JSON:encode(enrollment).toString(),ARDA_CF_CONFIG_SHA256:digest(encode(enrollment)),ARDA_CF_ANCHOR_TOKEN:'fixture-only',ARDA_CF_SETUP_CLIENT_TOKEN:'aa'.repeat(32),ARDA_CF_REVIEW_CLIENT_TOKEN:'bb'.repeat(32)};
const paths=['providers/cloudflare/worker.mjs','cloudflare/hss-enrollment.mjs','cloudflare/hss-guard.mjs','cloudflare/hss-engine.mjs','cloudflare/hss-anchor.mjs','cloudflare/hss-rotation.mjs','cloudflare/release-service.mjs','cloudflare/release-config.mjs','cloudflare/r13-capture.mjs','cloudflare/review-protocol.mjs','build/hss-state-meta.mjs'];
const modules=paths.map(path=>({type:'ESModule',path:bundle+path,contents:readFileSync(bundle+path,'utf8')}));modules.push({type:'CompiledWasm',path:bundle+'build/hss-state.wasm',contents:wasm});
const mock=`const refs=new Map();export default {async fetch(r){const path=new URL(r.url).pathname;if(path.endsWith('/rulesets/7')&&r.method==='GET')return Response.json(${JSON.stringify(rules)});
if(path.endsWith('/git/tags')&&r.method==='POST')return Response.json({sha:'12'.repeat(20)},{status:201});
if(path.endsWith('/git/refs')&&r.method==='POST'){const b=await r.json();if(refs.has(b.ref))return Response.json({},{status:422});refs.set(b.ref,b.sha);return Response.json({ref:b.ref,object:{type:'tag',sha:b.sha}},{status:201});}
return Response.json({},{status:404});}}`;
const options=async()=>convertV4MiniflareOptions({host:'127.0.0.1',inspectorPort:0,workers:[{name:'test',modules,modulesRoot:bundle,compatibilityDate:'2026-11-15',bindings,durableObjects:{HSS_SIGNER:{className:'HssEnrollmentObject',useSQLite:true}},outboundService:'mock'},{name:'mock',modules:true,compatibilityDate:'2026-11-15',script:mock}]});
const mf=new Miniflare(await options()),cryptoRoot=mkdtempSync(join(tmpdir(),'arda-cf-review-interop-'));
async function post(path,body,review=false){const r=await mf.dispatchFetch('https://fixture.invalid'+path,{method:'POST',headers:{'Content-Type':'application/json',[review?'X-ARDA-Review-Token':'X-ARDA-Setup-Token']:review?'bb'.repeat(32):'aa'.repeat(32)},body:encode(body)});return {response:r,body:await r.json()};}
try{
 const stateless=spawnSync('python3',['-c',`import base64,json,os,sys
from pathlib import Path
from arda_quorum.enrollment import generate_private
from arda_quorum.provider_witness import OpenSSLSigner
from arda_quorum.quorum import sha
out={}
for provider,algorithm in [('github','ML-DSA-65'),('hf','SLH-DSA-SHA2-192s')]:
 private=generate_private(algorithm);fd=os.open(Path(sys.argv[1])/(provider+'.der'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(private)
 public=OpenSSLSigner(algorithm,private).public;out[provider]={'public_key_b64':base64.b64encode(public).decode(),'key_sha256':sha(public)}
print(json.dumps(out))`,cryptoRoot],{cwd:root,encoding:'utf8'});assert.equal(stateless.status,0,stateless.stderr);
 const publicKeys=JSON.parse(stateless.stdout);for(const w of f.config.policy.witnesses)if(publicKeys[w.provider])Object.assign(w,publicKeys[w.provider]);
 const registered=await post('/v1/enroll-cf',{action:'provision_cloudflare_key',ceremony_sha256:enrollment.ceremony_sha256});assert.equal(registered.response.status,200,JSON.stringify(registered.body));
 const w=f.config.policy.witnesses.find(w=>w.provider==='cloudflare');w.key_sha256=registered.body.registration.payload.key_sha256;w.public_key_b64=registered.body.registration.payload.public_key_b64;
 f.config.policy_file_sha256=digest(encode(f.config.policy));f.request.proposal.policy_sha256=f.config.policy_file_sha256;
 Object.assign(bindings,{ARDA_CF_RELEASE_ENABLED:'true',ARDA_CF_RELEASE_CONFIG_JSON:encode(wireConfig(f.config)).toString(),ARDA_CF_RELEASE_CONFIG_SHA256:digest(encode(wireConfig(f.config))),ARDA_CF_ENROLLMENT_JSON:encode(f.config.policy).toString()});
 await mf.setOptions(await options());
 const health=await mf.dispatchFetch('https://fixture.invalid/healthz');assert.equal(health.status,200,await health.clone().text());const status=await health.json();assert.equal(status.mode,'release_review_only');assert.equal(status.key_sha256,w.key_sha256);assert.equal(status.next_leaf,1);
 const invalid=structuredClone(f.request);invalid.proposal.manifest_id='other';assert.equal((await post('/v1/review-vote',invalid,true)).response.status,400);
 const voted=await post('/v1/review-vote',f.request,true);assert.equal(voted.response.status,200,JSON.stringify(voted.body));
 const py=spawnSync('python3',['-c',`import base64,json,sys
from arda_quorum.crypto import Backends
from arda_quorum.quorum import DOMAIN,canonical
x=json.load(sys.stdin);v=x['vote'];w=x['witness'];assert Backends().verify(w['algorithm'],base64.b64decode(w['public_key_b64']),DOMAIN+canonical(v['payload']),base64.b64decode(v['signature_b64']))
print('WORKER_NATIVE_HSS_VOTE=PASS')`],{cwd:root,input:encode({vote:voted.body.vote,witness:w}),encoding:'utf8'});assert.equal(py.status,0,py.stderr);console.log(py.stdout.trim());
 const joined=spawnSync('python3',['-c',`import base64,json,sys,time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from arda_quorum.crypto import Backends
from arda_quorum.provider_witness import OpenSSLSigner
from arda_quorum.quorum import DOMAIN,canonical,BINDINGS
from arda_quorum.r13_bridge import PinnedR13,verify_with_r13
x=json.load(sys.stdin);votes=[x['vote']]
for provider in ('github','hf'):
 w=next(w for w in x['policy']['witnesses'] if w['provider']==provider)
 payload=dict(x['vote']['payload'],**{k:w[k] for k in ('provider','role','algorithm','witness_id','key_sha256')})
 signer=OpenSSLSigner(w['algorithm'],(Path(sys.argv[1])/(provider+'.der')).read_bytes());votes.append({'payload':payload,'signature_b64':base64.b64encode(signer.sign(DOMAIN+canonical(payload))).decode()})
pem=lambda v:serialization.load_der_public_key(base64.b64decode(v)).public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
c=x['r13'];gate=PinnedR13(pem(c['verifier_spki_b64']),pem(c['ak_spki_b64']),c['pcrs'],c['pins']);proposal=x['request']['proposal']
r=verify_with_r13({'proposal':proposal,'votes':votes},x['policy'],expected={k:proposal[k] for k in BINDINGS},capture=x['request']['capture'],r13_gate=gate,now=int(time.time()),backends=Backends());assert r['quorum_valid'] and r['r13_valid'],r
assert r['production_authorized'] is False
print('REAL_WORKER_THREE_ALGORITHM_R13_CERTIFICATE=PASS')`,cryptoRoot],{cwd:root,input:encode({vote:voted.body.vote,policy:f.config.policy,request:f.request,r13:f.config.r13}),encoding:'utf8'});assert.equal(joined.status,0,joined.stderr);console.log(joined.stdout.trim());
 const replay=await post('/v1/review-vote',f.request,true);assert.equal(replay.response.status,200);assert.deepEqual(replay.body,voted.body);
 const final=await (await mf.dispatchFetch('https://fixture.invalid/healthz')).json();assert.equal(final.next_leaf,2);assert.equal(final.production_authorized,false);
 console.log('REAL_SQLITE_EXISTING_KEY_REVIEW=PASS');console.log('ATOMIC_VOTE_REPLAY=PASS');console.log('INVALID_REQUEST_NO_LEAF=PASS');console.log('LIVE_PROVIDER_CALLS=0');console.log('PRODUCTION_AUTHORIZED=FALSE');
}finally{await mf.dispose();rmSync(cryptoRoot,{recursive:true,force:true});}
