import {DurableObject} from 'cloudflare:workers';
import wasm from '../../build/hss-state.wasm';
import {WASM_SHA256} from '../../build/hss-state-meta.mjs';
import {HssEngine} from '../../cloudflare/hss-engine.mjs';
import {CloudflareWitnessService,authorized} from '../../cloudflare/release-service.mjs';
export class HssEnrollmentObject extends DurableObject {
 constructor(ctx,env){super(ctx,env);this.service=new CloudflareWitnessService({storage:ctx.storage,env,engine:new HssEngine(wasm),wasmSha:WASM_SHA256});}
 fetch(request){return this.service.fetch(request);}
}
export default {
 async fetch(request,env){
  const path=new URL(request.url).pathname;
  const review=['/v1/review-vote','/v1/review-status'].includes(path);
  const get=request.method==='GET'&&['/healthz','/v1/enrollment-status','/v1/review-status'].includes(path);
  const post=request.method==='POST'&&['/v1/enroll-cf','/v1/self-test','/v1/replace-orphaned-key','/v1/review-vote'].includes(path);
  if(!get&&!post)return Response.json({error:'WITNESS_ROUTE_REFUSED',production_authorized:false},{status:404});
  if(review){if(!authorized(request,env.ARDA_CF_REVIEW_CLIENT_TOKEN,'X-ARDA-Review-Token'))return new Response('REFUSE',{status:401});}
  else if(post||path==='/v1/enrollment-status'){if(!authorized(request,env.ARDA_CF_SETUP_CLIENT_TOKEN,'X-ARDA-Setup-Token'))return new Response('REFUSE',{status:401});}
  const id=env.HSS_SIGNER.idFromName('arda-pq-release-witness');return env.HSS_SIGNER.get(id).fetch(request);
 }
};
