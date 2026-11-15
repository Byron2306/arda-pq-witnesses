import test from 'node:test';import assert from 'node:assert/strict';
import {GuardedHssSigner,sha,canonical} from './hss-guard.mjs';
import {ProtectedGitHubAnchor,rulesProjection} from './hss-anchor.mjs';
const rules={id:7,target:'tag',enforcement:'active',bypass_actors:[],conditions:{ref_name:{include:['refs/tags/arda-hss-leaf-*'],exclude:[]}},rules:[{type:'update'},{type:'deletion'}]};
const cfg={schema:'arda.hss.anchor.v1',repository:'Byron2306/arda-hss-leaf-anchor',genesis_commit:'12'.repeat(20),ruleset_id:7,rules_sha256:await sha(canonical(rulesProjection(rules)))};
const pub=new Uint8Array(60);pub.set([0,0,0,1,0,0,0,6,0,0,0,4]);pub[59]=42;const key=await sha(pub);
const message=new TextEncoder().encode('test-only bounded message');
const request=()=>({kind:'registration',context_sha256:'ab'.repeat(32),message,expires_at:1100});
function network(){const refs=new Map();let lost=false,weak=false;const events=[];
 return {refs,events,lose(){lost=true;},weaken(){weak=true;},fetch:async(url,options={})=>{
  events.push(options.method??'GET');const path=new URL(url).pathname;
  if(path.endsWith('/rulesets/7'))return Response.json(weak?{...rules,enforcement:'disabled'}:rules);
  const body=JSON.parse(options.body);
  if(path.endsWith('/git/tags'))return Response.json({sha:await sha(new TextEncoder().encode(body.message)).then(x=>x.slice(0,40))},{status:201});
  if(path.endsWith('/git/refs')){if(refs.has(body.ref))return Response.json({error:'exists'},{status:422});refs.set(body.ref,body.sha);
   if(lost){lost=false;throw Error('lost response after commit');}return Response.json({ref:body.ref,object:{type:'tag',sha:body.sha}},{status:201});}
  throw Error('unexpected request');
 }};
}
function setup(net=network(),snapshot){let stored=snapshot?structuredClone(snapshot):{schema:'arda.hss.key_state.v1',publicKey:pub,privateState:new Uint8Array(64),key_sha256:key,anchor_sha256:null,state:'ACTIVE',clock_watermark:1000};
 let failSync=false,signs=0,now=1000;const events=[];
 const storage={async get(){return structuredClone(stored);},async put(k,v){events.push('put');stored=structuredClone(v);},async sync(){events.push('sync');if(failSync)throw Error('uncertain storage');}};
 const engine={leaf(s){return Number(new DataView(s.buffer,s.byteOffset).getBigUint64(0));},async sign(state,pub,msg){signs++;events.push('sign');const q=this.leaf(state),next=state.slice();new DataView(next.buffer).setBigUint64(0,BigInt(q+1));const signature=new Uint8Array(1456);new DataView(signature.buffer).setUint32(4,q);return {privateState:next,signature,leaf:q};}};
 const anchor=new ProtectedGitHubAnchor(cfg,'test-token',net.fetch,()=>now);
 const signer=new GuardedHssSigner({storage,engine,anchor,clock:()=>now});
 return {net,storage,engine,anchor,signer,events,get signs(){return signs;},snapshot(){return structuredClone(stored);},async ready(){stored.anchor_sha256=await sha(canonical(cfg));},fail(){failSync=true;},now(v){now=v;}};
}
test('external burn occurs before signing and durable sync precedes release',async()=>{const s=setup();await s.ready();const r=await s.signer.sign(request());assert.equal(r.signature_created,true,r.reason);assert.equal(s.net.refs.size,1);assert.deepEqual(s.events,['sign','put','sync']);assert.equal(s.snapshot().privateState[7],1);});
test('restored old private state cannot reuse its externally burned leaf',async()=>{const s=setup();await s.ready();const old=s.snapshot();assert.equal((await s.signer.sign(request())).signature_created,true);const restored=setup(s.net,old);const r=await restored.signer.sign(request());assert.equal(r.signature_created,false);assert.equal(restored.signs,0);assert.equal(restored.snapshot().state,'QUARANTINED');});
test('two clones sharing the same private state have only one signing winner',async()=>{const a=setup();await a.ready();const b=setup(a.net,a.snapshot());const results=await Promise.all([a.signer.sign(request()),b.signer.sign(request())]);assert.equal(results.filter(r=>r.signature_created).length,1);assert.equal(a.signs+b.signs,1);});
test('lost external create response burns leaf but never invokes crypto',async()=>{const s=setup();await s.ready();s.net.lose();const r=await s.signer.sign(request());assert.equal(r.signature_created,false);assert.equal(s.signs,0);assert.equal(s.net.refs.size,1);});
test('durability uncertainty releases no signature and quarantines the key',async()=>{const s=setup();await s.ready();s.fail();const r=await s.signer.sign(request());assert.equal(r.signature_created,false);assert.equal(s.net.refs.size,1);assert.equal(s.snapshot().state,'QUARANTINED');assert.equal((await s.signer.sign(request())).signature_created,false);});
test('weakened protection refuses before marker creation or signing',async()=>{const s=setup();await s.ready();s.net.weaken();assert.equal((await s.signer.sign(request())).signature_created,false);assert.equal(s.signs,0);assert.equal(s.net.refs.size,0);});
test('already expired requests do not consume a leaf',async()=>{const s=setup();await s.ready();const r=await s.signer.sign({...request(),expires_at:1000});assert.equal(r.signature_created,false);assert.equal(s.net.refs.size,0);});
test('exhausted state never wraps around',async()=>{const s=setup();await s.ready();const snap=s.snapshot();new DataView(snap.privateState.buffer).setBigUint64(0,1024n);const exhausted=setup(s.net,snap);assert.equal((await exhausted.signer.sign(request())).signature_created,false);assert.equal(exhausted.signs,0);});
test('rules require active tag update/deletion protection with no bypass',()=>{for(const bad of [{...rules,bypass_actors:[{actor_id:1}]},{...rules,target:'branch'},{...rules,rules:[{type:'update'}]},{...rules,conditions:{ref_name:{include:['refs/tags/*'],exclude:[]}}}])assert.throws(()=>rulesProjection(bad));});
test('vote expiry is bounded to 120 seconds even though enrollment permits a day',async()=>{const s=setup();await s.ready();const out=await s.signer.sign({...request(),kind:'vote',expires_at:1200});assert.equal(out.signature_created,false);assert.equal(s.net.refs.size,0);});
test('expiry after external burn withholds signing and retains the marker',async()=>{const s=setup();await s.ready();const base=s.anchor.fetcher;s.anchor.fetcher=async(...args)=>{const r=await base(...args);if(args[0].endsWith('/git/refs'))s.now(1100);return r;};const r=await s.signer.sign(request());assert.equal(r.signature_created,false);assert.equal(s.signs,0);assert.equal(s.net.refs.size,1);});
test('clock rollback after durable update withholds the signature',async()=>{const s=setup();await s.ready();s.storage.sync=async()=>{s.now(999);};const r=await s.signer.sign(request());assert.equal(r.signature_created,false);assert.equal(s.signs,1);assert.equal(s.snapshot().state,'QUARANTINED');});
