import {need,canonical,sha,hex64,GuardedHssSigner} from './hss-guard.mjs';
import {ProtectedGitHubAnchor} from './hss-anchor.mjs';
import {encode64,registrationPayload,replaceOrphan,publicReceipt} from './hss-rotation.mjs';
export {encode64};
const decode=bytes=>new TextDecoder('utf-8',{fatal:true}).decode(bytes);
const same=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
function authorized(request,token){if(!hex64(token))return false;const supplied=request.headers.get('X-ARDA-Setup-Token');if(!hex64(supplied))return false;let diff=0;for(let i=0;i<64;i++)diff|=token.charCodeAt(i)^supplied.charCodeAt(i);return diff===0;}
function reply(status,body){return Response.json({...body,production_authorized:false,interlock:'KEEP_CLOSED'},{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});}
async function bounded(request,maximum){const reader=request.body?.getReader();need(reader,'BODY_REQUIRED');let n=0,chunks=[];
 try{for(;;){const {done,value}=await reader.read();if(done)break;n+=value.length;need(n<=maximum,'BODY_SIZE');chunks.push(value);}}finally{await reader.cancel().catch(()=>{});}
 const raw=new Uint8Array(n);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}return raw;}
export async function configuration(env,wasmSha,now,{readOnly=false}={}){
 const raw=new TextEncoder().encode(env.ARDA_CF_CONFIG_JSON??'');need(raw.length>0&&raw.length<=16384&&hex64(env.ARDA_CF_CONFIG_SHA256)&&await sha(raw)===env.ARDA_CF_CONFIG_SHA256,'CONFIGURATION_PIN');
 const c=JSON.parse(decode(raw));need(same(raw,canonical(c)),'CANONICAL_CONFIGURATION');
 need(Object.keys(c).sort().join(',')==='anchor,ceremony,ceremony_sha256,production_authorized,schema,wasm_sha256,worker_identity','CF_CONFIG_FIELDS');
 need(c.schema==='arda.cf.hss.enrollment_config.v1'&&c.worker_identity==='arda-pq-release-witness'&&c.production_authorized===false&&c.wasm_sha256===wasmSha&&hex64(wasmSha),'CF_CONFIG_IDENTITY');
 const ceremony=c.ceremony;need(ceremony&&Object.keys(ceremony).sort().join(',')==='expires_at,identities,image_digest,issued_at,nonce,production_authorized,schema','CEREMONY_FIELDS');
 need(ceremony.schema==='arda.pq.enrollment_ceremony.v1'&&ceremony.production_authorized===false&&hex64(ceremony.nonce)&&typeof ceremony.image_digest==='string'&&/^sha256:[0-9a-f]{64}$/.test(ceremony.image_digest),'CEREMONY_SCHEMA');
 need(Number.isSafeInteger(ceremony.issued_at)&&Number.isSafeInteger(ceremony.expires_at)&&0<ceremony.issued_at&&ceremony.expires_at>ceremony.issued_at&&(readOnly||(ceremony.issued_at<=now&&now<ceremony.expires_at))&&ceremony.expires_at-ceremony.issued_at<=86400,'CEREMONY_WINDOW');
 need(ceremony.identities&&Object.keys(ceremony.identities).sort().join(',')==='cloudflare,github,hf'&&ceremony.identities.cloudflare===c.worker_identity&&ceremony.identities.github==='Byron2306/arda-pq-witnesses'&&ceremony.identities.hf==='Byron230686/arda-pq-policy-witness','CEREMONY_PROVIDER_IDENTITIES');
 need(hex64(c.ceremony_sha256)&&await sha(canonical(ceremony))===c.ceremony_sha256,'CEREMONY_PIN');return c;
}
export class CloudflareEnrollmentService {
 constructor({storage,env,engine,wasmSha,clock=()=>Math.floor(Date.now()/1000),anchorFactory}){
  this.storage=storage;this.env=env;this.engine=engine;this.wasmSha=wasmSha;this.clock=clock;this.anchorFactory=anchorFactory??(c=>new ProtectedGitHubAnchor(c,env.ARDA_CF_ANCHOR_TOKEN,fetch,clock));this.busy=false;
 }
 async fetch(request){const path=new URL(request.url).pathname;
  if(!((request.method==='GET'&&['/healthz','/v1/enrollment-status'].includes(path))||(request.method==='POST'&&['/v1/enroll-cf','/v1/self-test','/v1/replace-orphaned-key'].includes(path))))return reply(404,{error:'CF_ENROLLMENT_ONLY'});
  if((request.method==='POST'||path==='/v1/enrollment-status')&&!authorized(request,this.env.ARDA_CF_SETUP_CLIENT_TOKEN))return reply(401,{error:'CF_ENROLLMENT_REFUSED'});
  let c;try{c=await configuration(this.env,this.wasmSha,this.clock(),{readOnly:path==='/v1/enrollment-status'});}catch{return reply(503,{error:'CF_ENROLLMENT_NOT_CONFIGURED'});}
  if(path==='/v1/enrollment-status'){
   try{
    const state=await this.storage.get('key'),cached=await this.storage.get('registration');
    let replacementReceipt=null;
    if(hex64(state?.rotation_request_sha256)){
     const saved=await this.storage.get('rotation/'+state.rotation_request_sha256);
     if(saved){const receipt=publicReceipt(saved);need(receipt.rotation_request_sha256===state.rotation_request_sha256&&receipt.replacement_key_sha256===state.key_sha256,'STATUS_ROTATION_BINDING');replacementReceipt=receipt;}
    }
    let nextLeaf=null;
    if(state?.privateState instanceof Uint8Array&&state.privateState.length===64){try{const leaf=this.engine.leaf(state.privateState);if(Number.isSafeInteger(leaf)&&leaf>=0&&leaf<=1024)nextLeaf=leaf;}catch{}}
    let check={ok:false,http_status:null,reason:'ANCHOR_READ_UNAVAILABLE'};
    try{check=await this.anchorFactory(c.anchor).inspect();}catch{}
    return reply(200,{mode:'enrollment_only',diagnostic_read_only:true,ceremony_sha256:c.ceremony_sha256,config_sha256:this.env.ARDA_CF_CONFIG_SHA256,
     key:{present:state!==undefined&&state!==null,state:['ACTIVE','QUARANTINED'].includes(state?.state)?state.state:'UNKNOWN',key_sha256:hex64(state?.key_sha256)?state.key_sha256:null,next_leaf:nextLeaf,ceremony_sha256:hex64(state?.ceremony_sha256)?state.ceremony_sha256:null,replaces_key_sha256:hex64(state?.replaces_key_sha256)?state.replaces_key_sha256:null},
     replacement_receipt:replacementReceipt,replacement_receipt_sha256:replacementReceipt?await sha(canonical(replacementReceipt)):null,
     cached_registration_present:cached!==undefined&&cached!==null,
     anchor_read_check:{ok:check.ok===true,http_status:Number.isInteger(check.http_status)&&check.http_status>=100&&check.http_status<=599?check.http_status:null,reason:['ANCHOR_READ_AND_RULE_PIN_VALID','ANCHOR_HTTP_REFUSED','ANCHOR_READ_OR_RULE_PIN_REFUSED'].includes(check.reason)?check.reason:'ANCHOR_READ_UNAVAILABLE'}});
   }catch{return reply(503,{error:'CF_STATUS_READ_UNAVAILABLE'});}
  }
  if(request.method==='GET')return reply(200,{mode:'enrollment_only',state:this.busy?'BUSY':'WAITING_OR_CACHED',ceremony_sha256:c.ceremony_sha256});
  if(!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')||request.headers.has('Content-Encoding'))return reply(415,{error:'CF_ENROLLMENT_REFUSED'});
  let input;
  try{const raw=await bounded(request,4096);input=JSON.parse(decode(raw));need(same(raw,canonical(input))&&input.ceremony_sha256===c.ceremony_sha256,'CF_ENROLLMENT_REQUEST');
   if(path==='/v1/replace-orphaned-key')need(Object.keys(input).sort().join(',')==='action,ceremony_sha256,config_sha256,expected_key_sha256,expected_next_leaf,old_ceremony,prior_tag_sha'&&input.action==='replace_orphaned_cloudflare_key'&&input.config_sha256===this.env.ARDA_CF_CONFIG_SHA256&&hex64(input.expected_key_sha256)&&input.expected_next_leaf===1&&/^[0-9a-f]{40}$/.test(input.prior_tag_sha),'ROTATION_REQUEST');
   else need(Object.keys(input).sort().join(',')==='action,ceremony_sha256'&&input.action===(path==='/v1/self-test'?'run_disposable_hss_self_test':'provision_cloudflare_key'),'CF_ENROLLMENT_ACTION');
  }catch{return reply(400,{error:'CF_ENROLLMENT_REFUSED'});}
  if(this.busy)return reply(409,{error:'CF_ENROLLMENT_BUSY'});this.busy=true;
  try{
   if(path==='/v1/replace-orphaned-key'){
    const oldConfig={...c,ceremony:input.old_ceremony,ceremony_sha256:await sha(canonical(input.old_ceremony))},raw=canonical(oldConfig);
    await configuration({ARDA_CF_CONFIG_JSON:decode(raw),ARDA_CF_CONFIG_SHA256:await sha(raw)},this.wasmSha,this.clock(),{readOnly:true});
    const receipt=await replaceOrphan({storage:this.storage,engine:this.engine,anchor:this.anchorFactory(c.anchor),c,oldConfig,input,clock:this.clock,validateCurrent:()=>configuration(this.env,this.wasmSha,this.clock())});
    return reply(200,{receipt,receipt_sha256:await sha(canonical(receipt))});
   }
   if(path==='/v1/self-test'){
    const key=await this.engine.generate();
    const message=new TextEncoder().encode('ARDA/HSS/DISPOSABLE-SELF-TEST/v1\0'+this.wasmSha);
    try{const result=await this.engine.sign(key.privateState,key.publicKey,message);need(result.leaf===0,'SELF_TEST_LEAF');
     await configuration(this.env,this.wasmSha,this.clock());
     return reply(200,{disposable:true,wasm_sha256:this.wasmSha,public_key_b64:encode64(key.publicKey),message_b64:encode64(message),signature_b64:encode64(result.signature)});
    }finally{key.privateState.fill(0);}
   }
   let state=await this.storage.get('key');const cached=await this.storage.get('registration');
   if(cached){need(state?.state==='ACTIVE'&&cached.payload.ceremony_sha256===c.ceremony_sha256&&cached.payload.key_sha256===state.key_sha256&&this.engine.leaf(state.privateState)>=1,'CACHED_REGISTRATION_BINDING');await configuration(this.env,this.wasmSha,this.clock());return reply(200,{registration:cached});}
   if(state)need(state.state==='ACTIVE'&&this.engine.leaf(state.privateState)===0&&state.ceremony_sha256===c.ceremony_sha256,'INTERRUPTED_ENROLLMENT_REQUIRES_REVIEW');
   if(!state){
    const key=await this.engine.generate(),now=this.clock();await configuration(this.env,this.wasmSha,now);
    need(key.privateState instanceof Uint8Array&&this.engine.leaf(key.privateState)===0&&key.publicKey instanceof Uint8Array&&key.publicKey.length===60,'HSS_KEYGEN_PARAMETERS');
    state={schema:'arda.hss.key_state.v1',publicKey:key.publicKey.slice(),privateState:key.privateState.slice(),key_sha256:await sha(key.publicKey),anchor_sha256:await sha(canonical(c.anchor)),state:'ACTIVE',clock_watermark:now,ceremony_sha256:c.ceremony_sha256,registration_issued_at:now};
    await this.storage.put('key',state);await this.storage.sync();
   }
   const payload=registrationPayload(c,state);
   const body=canonical(payload),domain=new TextEncoder().encode('ARDA/PQ-QUORUM/ENROLLMENT/v1\0'),message=new Uint8Array(domain.length+body.length);message.set(domain);message.set(body,domain.length);
   const signer=new GuardedHssSigner({storage:this.storage,engine:this.engine,anchor:this.anchorFactory(c.anchor),clock:this.clock,registrationPayload:payload});
   const result=await signer.sign({kind:'registration',context_sha256:c.ceremony_sha256,message,expires_at:c.ceremony.expires_at});
   need(result.signature_created===true&&result.leaf===0,'HSS_REGISTRATION_REFUSED');
   const registration={payload,signature_b64:encode64(result.signature)};
   await configuration(this.env,this.wasmSha,this.clock());return reply(200,{registration});
  }catch{return reply(409,{error:'CF_ENROLLMENT_REFUSED_OPERATOR_REVIEW_REQUIRED'});}finally{this.busy=false;}
 }
}
