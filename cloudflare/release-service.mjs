import {CloudflareEnrollmentService} from './hss-enrollment.mjs';
import {GuardedHssSigner} from './hss-guard.mjs';
import {ProtectedGitHubAnchor} from './hss-anchor.mjs';
import {validateReleaseConfig,validateReview} from './release-config.mjs';
import {need,sha,hex64,canonicalProtocol,parseCanonical,equal,unbase64,message,window} from './review-protocol.mjs';
const reply=(status,body)=>Response.json({...body,production_authorized:false,interlock:'KEEP_CLOSED'},{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
export function authorized(request,token,header){const supplied=request.headers.get(header);if(!hex64(token)||!hex64(supplied))return false;let diff=0;for(let i=0;i<64;i++)diff|=token.charCodeAt(i)^supplied.charCodeAt(i);return diff===0;}
async function body(request){
 need(request.headers.get('Content-Type')==='application/json'&&!request.headers.has('Content-Encoding')&&!request.headers.has('Transfer-Encoding'),'CONTENT_TYPE');
 const declared=request.headers.get('Content-Length');need(declared===null||(/^[0-9]{1,6}$/.test(declared)&&Number(declared)<=65536),'CONTENT_LENGTH');
 const reader=request.body?.getReader();need(reader,'BODY_REQUIRED');const chunks=[];let size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;need(size<=65536,'BODY_SIZE');chunks.push(value);}}finally{await reader.cancel().catch(()=>{});}
 need(declared===null||Number(declared)===size,'CONTENT_LENGTH_MISMATCH');
 const raw=new Uint8Array(size);let at=0;for(const chunk of chunks){raw.set(chunk,at);at+=chunk.length;}return parseCanonical(raw,65536);
}
export class CloudflareWitnessService{
 constructor(options){this.options=options;this.env=options.env;this.storage=options.storage;this.engine=options.engine;this.clock=options.clock??(()=>Math.floor(Date.now()/1000));this.enrollment=new CloudflareEnrollmentService(options);this.busy=false;}
 async key(config,clock=this.clock){
  const [state,registration]=await Promise.all([this.storage.get('key'),this.storage.get('registration')]);
  const witness=config.policy.witnesses.find(w=>w.provider==='cloudflare');
  need(state?.schema==='arda.hss.key_state.v1'&&state.state==='ACTIVE'&&state.key_sha256===witness.key_sha256&&state.publicKey instanceof Uint8Array&&await sha(state.publicKey)===witness.key_sha256&&equal(state.publicKey,unbase64(witness.public_key_b64,60)),'RELEASE_KEY_NOT_ENROLLED');
  need(state.anchor_sha256===await sha(canonicalProtocol(config.anchor))&&registration?.payload?.key_sha256===state.key_sha256&&registration.payload.public_key_b64===witness.public_key_b64,'RELEASE_CUSTODY_BINDING');
  need(Number.isSafeInteger(state.clock_watermark)&&clock()>=state.clock_watermark,'RELEASE_CLOCK_ROLLBACK');
  const leaf=this.engine.leaf(state.privateState);need(leaf>=1&&leaf<=1024,'RELEASE_KEY_COUNTER');
  need(state.review_epoch===undefined||(Number.isSafeInteger(state.review_epoch)&&config.policy.epoch>=state.review_epoch&&(config.policy.epoch!==state.review_epoch||state.review_policy_sha256===config.policy_file_sha256)),'RELEASE_POLICY_ROLLBACK');
  return {state,leaf,witness};
 }
 async fetch(request){
  const path=new URL(request.url).pathname,isReview=['/v1/review-vote','/v1/review-status'].includes(path)||(path==='/healthz'&&this.env.ARDA_CF_RELEASE_ENABLED==='true');
  const protectedReview=isReview&&path!=='/healthz';
  if(protectedReview&&!authorized(request,this.env.ARDA_CF_REVIEW_CLIENT_TOKEN,'X-ARDA-Review-Token'))return reply(401,{error:'CF_REVIEW_REFUSED'});
  if(!isReview&&request.method==='POST'&&!authorized(request,this.env.ARDA_CF_SETUP_CLIENT_TOKEN,'X-ARDA-Setup-Token'))return reply(401,{error:'CF_ENROLLMENT_REFUSED'});
  if(isReview&&!((request.method==='GET'&&['/healthz','/v1/review-status'].includes(path))||(request.method==='POST'&&path==='/v1/review-vote')))return reply(404,{error:'CF_REVIEW_ROUTE'});
  const mutates=request.method==='POST';if(mutates&&this.busy)return reply(409,{error:'CF_WITNESS_BUSY'});if(mutates)this.busy=true;
  try{
   if(!isReview)return await this.enrollment.fetch(request);
   // Capture the approval inputs before the first configuration/body/crypto await.
   const configPin=this.env.ARDA_CF_RELEASE_CONFIG_SHA256,configurationEnv={...this.env};
   let observed=0;const clock=()=>{const now=this.clock();need(Number.isSafeInteger(now)&&now>0&&now>=observed,'REVIEW_CLOCK_ROLLBACK');observed=now;return now;};
   let config;try{config=await validateReleaseConfig(configurationEnv,this.options.wasmSha,clock());need(this.env.ARDA_CF_RELEASE_CONFIG_SHA256===configPin,'CONFIG_CHANGED');}catch{return reply(503,{error:'CF_RELEASE_NOT_CONFIGURED'});}
   if(request.method==='GET'){
    try{const {leaf,witness}=await this.key(config,clock);await validateReleaseConfig({...this.env},this.options.wasmSha,clock());need(this.env.ARDA_CF_RELEASE_CONFIG_SHA256===configPin,'CONFIG_CHANGED');window(config.policy,clock(),366*86400);window(config.stage_window,clock(),30*86400);const query=new URL(request.url).searchParams;
     const status={mode:'release_review_only',key_sha256:witness.key_sha256,next_leaf:leaf,policy_sha256:config.policy_file_sha256,config_sha256:configPin};
     if(query.size){
      need(path==='/v1/review-status'&&query.size===1&&query.has('proposal_sha256')&&hex64(query.get('proposal_sha256')),'DIAGNOSTIC_QUERY');
      const hash=query.get('proposal_sha256'),entry=await this.storage.get('vote/'+hash);
      status.diagnostic_read_only=true;status.current_authorization=false;status.archived_vote_present=Boolean(entry);
      const current=await this.storage.get('key');status.clock_watermark=current?.clock_watermark??null;
      if(entry){
       need(entry.config_sha256===configPin&&entry.epoch===config.policy.epoch&&hex64(entry.nonce),'ARCHIVE_CONTEXT');
       const p=entry.vote?.payload;need(p?.proposal_sha256===hash&&p.key_sha256===witness.key_sha256&&p.policy_sha256===config.policy_file_sha256&&p.provider==='cloudflare','ARCHIVE_BINDING');
       const nonce=await this.storage.get('nonce/'+entry.epoch+'/'+entry.nonce);need(nonce?.proposal_sha256===hash&&nonce.key_sha256===witness.key_sha256&&nonce.policy_sha256===config.policy_file_sha256,'ARCHIVE_NONCE');
       status.archived_vote=entry.vote;status.archived_vote_expired=clock()>=p.expires_at;
      }
      need(this.env.ARDA_CF_RELEASE_CONFIG_SHA256===configPin,'CONFIG_CHANGED');
     }
     return reply(200,status);}catch{return reply(409,{error:'CF_RELEASE_KEY_UNAVAILABLE'});}
   }
   let input,review;try{input=await body(request);review=await validateReview(config,input,clock());}catch{return reply(400,{error:'CF_REVIEW_REQUEST_REFUSED'});}
   try{
    await validateReleaseConfig({...this.env},this.options.wasmSha,clock());need(this.env.ARDA_CF_RELEASE_CONFIG_SHA256===configPin,'CONFIG_CHANGED');
    const {state,leaf}=await this.key(config,clock),cache=await this.storage.get('vote/'+review.proposal_sha256);
    if(cache){
     need(cache.config_sha256===configPin&&cache.epoch===config.policy.epoch&&cache.nonce===input.proposal.nonce,'CACHED_VOTE_CONTEXT');
     const v=cache.vote?.payload;need(v&&Object.keys(v).sort().join(',')===Object.keys(review.payload).sort().join(',')&&Object.keys(review.payload).filter(k=>k!=='issued_at').every(k=>v[k]===review.payload[k]),'CACHED_VOTE_BINDING');
     window(v,clock(),120);need(input.proposal.issued_at<=v.issued_at,'CACHED_VOTE_TIME');const signature=unbase64(cache.vote.signature_b64,1456);need(signature.length===1456&&new DataView(signature.buffer).getUint32(4)<leaf,'CACHED_VOTE_LEAF');
     const nonce=await this.storage.get('nonce/'+config.policy.epoch+'/'+input.proposal.nonce);need(nonce?.proposal_sha256===review.proposal_sha256&&nonce.policy_sha256===config.policy_file_sha256&&nonce.key_sha256===state.key_sha256,'CACHED_NONCE_BINDING');
     await validateReleaseConfig({...this.env},this.options.wasmSha,clock());need(this.env.ARDA_CF_RELEASE_CONFIG_SHA256===configPin,'CONFIG_CHANGED');window(v,clock(),120);
     return reply(200,{vote:cache.vote});
    }
    need(leaf<1024,'RELEASE_KEY_EXHAUSTED');
    const anchor=this.options.anchorFactory?this.options.anchorFactory(config.anchor):new ProtectedGitHubAnchor(config.anchor,this.env.ARDA_CF_ANCHOR_TOKEN,fetch,clock);
    // Establish the exact signed timestamp immediately before the guarded operation.
    await validateReleaseConfig({...this.env},this.options.wasmSha,clock());need(this.env.ARDA_CF_RELEASE_CONFIG_SHA256===configPin,'CONFIG_CHANGED');
    const now=clock();window(input.proposal,now,120);review.payload.issued_at=now;
    const signer=new GuardedHssSigner({storage:this.storage,engine:this.engine,anchor,clock,voteContext:{payload:review.payload,epoch:config.policy.epoch,nonce:input.proposal.nonce,config_sha256:configPin}});
    const result=await signer.sign({kind:'vote',context_sha256:review.proposal_sha256,message:message('ARDA/PQ-QUORUM/VOTE/v1',review.payload),expires_at:review.payload.expires_at});need(result.signature_created,'CF_GUARDED_VOTE_REFUSED');
    const committed=await this.storage.get('vote/'+review.proposal_sha256);need(committed?.vote?.payload?.proposal_sha256===review.proposal_sha256,'VOTE_COMMIT_UNAVAILABLE');
    // All awaited operations precede the final pin/window/monotonic-clock checks.
    await validateReleaseConfig({...this.env},this.options.wasmSha,clock());need(this.env.ARDA_CF_RELEASE_CONFIG_SHA256===configPin,'CONFIG_CHANGED');window(review.payload,clock(),120);
    return reply(200,{vote:committed.vote});
   }catch{return reply(409,{error:'CF_REVIEW_REFUSED_OPERATOR_REVIEW_REQUIRED'});}
  }finally{if(mutates)this.busy=false;}
 }
}
