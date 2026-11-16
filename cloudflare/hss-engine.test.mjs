import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {HssEngine} from './hss-engine.mjs';
const bytes=await readFile(new URL('../build/hss-state.wasm',import.meta.url));
let engine,key,first;
test('real Wasm key generation has fixed parameters and native-verifiable signature',async()=>{
 engine=await HssEngine.fromBytes(bytes);key=await engine.generate();
 assert.equal(key.privateState.length,64);assert.equal(key.publicKey.length,60);assert.equal(engine.leaf(key.privateState),0);
 const message=new TextEncoder().encode('ARDA test-only HSS Wasm interoperability');
 first=await engine.sign(key.privateState,key.publicKey,message);
 assert.equal(first.leaf,0);assert.equal(engine.leaf(first.privateState),1);assert.equal(first.signature.length,1456);
 const dir=await mkdtemp(join(tmpdir(),'arda-hss-wasm-test-'));
 try {for(const [name,value] of [['pub',key.publicKey],['message',message],['sig',first.signature]])await writeFile(join(dir,name),value);
  assert.equal(spawnSync(new URL('../build/hss-verify',import.meta.url).pathname,['pub','message','sig'],{cwd:dir}).status,0);
 } finally {await rm(dir,{recursive:true,force:true});}
});
test('advanced state signs the next leaf without changing prior snapshot',async()=>{
 const out=await engine.sign(first.privateState,key.publicKey,new TextEncoder().encode('second test-only message'));
 assert.equal(out.leaf,1);assert.equal(engine.leaf(out.privateState),2);assert.equal(engine.leaf(key.privateState),0);
});
test('out of range state and oversized input refuse before signing',async()=>{
 const exhausted=new Uint8Array(key.privateState);new DataView(exhausted.buffer).setBigUint64(0,1024n);
 await assert.rejects(engine.sign(exhausted,key.publicKey,new Uint8Array([1])));
 await assert.rejects(engine.sign(key.privateState,key.publicKey,new Uint8Array(16385)));
 await assert.rejects(engine.sign(key.privateState,new Uint8Array(60),new Uint8Array([1])));
});
test('enrollment Worker core produces a real Python-verifiable HSS registration',async()=>{
 const {CloudflareEnrollmentService}=await import('./hss-enrollment.mjs');const {canonical,sha}=await import('./hss-guard.mjs');
 const now=1000,ceremony={schema:'arda.pq.enrollment_ceremony.v1',nonce:'ef'.repeat(32),image_digest:'sha256:'+'ab'.repeat(32),identities:{github:'Byron2306/arda-pq-witnesses',hf:'Byron230686/arda-pq-policy-witness',cloudflare:'arda-pq-release-witness'},issued_at:900,expires_at:2000,production_authorized:false};
 const anchor={schema:'arda.hss.anchor.v1',repository:'Byron2306/arda-hss-leaf-anchor',genesis_commit:'12'.repeat(20),ruleset_id:7,rules_sha256:'34'.repeat(32)};
 const config={schema:'arda.cf.hss.enrollment_config.v1',worker_identity:'arda-pq-release-witness',ceremony,ceremony_sha256:await sha(canonical(ceremony)),anchor,wasm_sha256:'cd'.repeat(32),production_authorized:false};
 const env={ARDA_CF_CONFIG_JSON:new TextDecoder().decode(canonical(config)),ARDA_CF_CONFIG_SHA256:await sha(canonical(config)),ARDA_CF_SETUP_CLIENT_TOKEN:'aa'.repeat(32)};
 const values=new Map(),storage={async get(k){return structuredClone(values.get(k));},async put(k,v){if(typeof k==='string')values.set(k,structuredClone(v));else for(const [name,value] of Object.entries(k))values.set(name,structuredClone(value));},async sync(){}};
 const service=new CloudflareEnrollmentService({storage,env,engine,wasmSha:config.wasm_sha256,clock:()=>now,anchorFactory:c=>({configuration:c,async burn(r){return {...r,ref:'refs/tags/test',tag_sha:'56'.repeat(20)};}})});
 const response=await service.fetch(new Request('https://example/v1/enroll-cf',{method:'POST',headers:{'X-ARDA-Setup-Token':'aa'.repeat(32),'Content-Type':'application/json'},body:new TextDecoder().decode(canonical({action:'provision_cloudflare_key',ceremony_sha256:config.ceremony_sha256}))}));
 assert.equal(response.status,200,await response.clone().text());const body=await response.json();
 const dir=await mkdtemp(join(tmpdir(),'arda-hss-registration-test-'));
 try{await writeFile(join(dir,'ceremony.json'),canonical(ceremony));await writeFile(join(dir,'record.json'),canonical(body.registration));
  const root=new URL('../',import.meta.url).pathname;
  const code="import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); from arda_quorum.quorum import strict_load; from arda_quorum.enrollment import check_record; from arda_quorum.crypto import Backends; check_record(strict_load(Path(sys.argv[2]).read_bytes()),strict_load(Path(sys.argv[3]).read_bytes()),now=1000,backends=Backends())";
  const checked=spawnSync(process.env.ARDA_TEST_PYTHON??'python3',['-c',code,root,join(dir,'record.json'),join(dir,'ceremony.json')],{encoding:'utf-8'});
  assert.equal(checked.status,0,checked.stderr);
 }finally{await rm(dir,{recursive:true,force:true});values.get('key')?.privateState.fill(0);values.clear();}
});
