import {DurableObject} from 'cloudflare:workers';
import wasm from '../../build/hss-state.wasm';
import {WASM_SHA256} from '../../build/hss-state-meta.mjs';
import {HssEngine} from '../../cloudflare/hss-engine.mjs';
import {CloudflareEnrollmentService} from '../../cloudflare/hss-enrollment.mjs';
export class HssEnrollmentObject extends DurableObject {
 constructor(ctx,env){super(ctx,env);this.service=new CloudflareEnrollmentService({storage:ctx.storage,env,engine:new HssEngine(wasm),wasmSha:WASM_SHA256});}
 fetch(request){return this.service.fetch(request);}
}
export default {
 async fetch(request,env){
  const path=new URL(request.url).pathname;
  if(!((request.method==='GET'&&path==='/healthz')||(request.method==='POST'&&['/v1/enroll-cf','/v1/self-test'].includes(path))))return Response.json({error:'ENROLLMENT_ONLY',production_authorized:false},{status:404});
  // Reject unauthenticated POSTs before instantiating/accessing the durable key object.
  if(request.method==='POST'){
   const expected=env.ARDA_CF_SETUP_CLIENT_TOKEN,supplied=request.headers.get('X-ARDA-Setup-Token');let diff=0;
   if(typeof expected!=='string'||!/^[0-9a-f]{64}$/.test(expected)||typeof supplied!=='string'||supplied.length!==64)return new Response('REFUSE',{status:401});
   for(let i=0;i<64;i++)diff|=expected.charCodeAt(i)^supplied.charCodeAt(i);if(diff)return new Response('REFUSE',{status:401});
  }
  const id=env.HSS_SIGNER.idFromName('arda-pq-release-witness');return env.HSS_SIGNER.get(id).fetch(request);
 }
};
