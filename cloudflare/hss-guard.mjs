export const need=(ok,code)=>{if(!ok)throw Error(code);};
export const hex64=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
export function canonical(value){
 const normalize=v=>{if(v===null||typeof v==='boolean'||typeof v==='string')return v;
  if(typeof v==='number'){need(Number.isSafeInteger(v)&&!Object.is(v,-0),'CANONICAL_INTEGER');return v;}
  if(Array.isArray(v))return v.map(normalize);
  need(v&&typeof v==='object'&&Object.getPrototypeOf(v)===Object.prototype,'CANONICAL_OBJECT');
  return Object.fromEntries(Object.keys(v).sort().map(k=>[k,normalize(v[k])]));};
 return new TextEncoder().encode(JSON.stringify(normalize(value)).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')));
}
export async function sha(bytes){need(bytes instanceof Uint8Array,'HASH_BYTES');return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');}
const encode64=bytes=>{let text='';for(const byte of bytes)text+=String.fromCharCode(byte);return btoa(text);};
const closed=reason=>({signature_created:false,production_authorized:false,interlock:'KEEP_CLOSED',reason});
export class GuardedHssSigner {
 constructor({storage,engine,anchor,clock=()=>Math.floor(Date.now()/1000),registrationPayload,voteContext}){this.storage=storage;this.engine=engine;this.anchor=anchor;this.clock=clock;this.busy=false;this.quarantined=false;this.voteContext=voteContext===undefined?undefined:JSON.parse(new TextDecoder().decode(canonical(voteContext)));this.registrationPayload=registrationPayload===undefined?undefined:JSON.parse(new TextDecoder().decode(canonical(registrationPayload)));}
 now(){const n=this.clock();need(Number.isSafeInteger(n)&&n>0,'CLOCK');return n;}
 async sign(request){if(this.busy||this.quarantined)return closed('KEY_BUSY_OR_QUARANTINED');this.busy=true;let state,attempted=false;
  try {
   need(request&&Object.keys(request).sort().join(',')==='context_sha256,expires_at,kind,message','SIGN_REQUEST_FIELDS');
   const r={...request,message:request.message instanceof Uint8Array?request.message.slice():null};
   need(['registration','vote'].includes(r.kind)&&hex64(r.context_sha256)&&r.message&&r.message.length>0&&r.message.length<=16384,'SIGN_REQUEST');
   const start=this.now();need(Number.isSafeInteger(r.expires_at)&&start<r.expires_at&&r.expires_at-start<=(r.kind==='registration'?86400:120),'SIGN_WINDOW');
   state=await this.storage.get('key');need(state?.schema==='arda.hss.key_state.v1'&&state.state==='ACTIVE','KEY_UNAVAILABLE');
   need(state.publicKey instanceof Uint8Array&&state.publicKey.length===60&&state.privateState instanceof Uint8Array&&state.privateState.length===64,'KEY_STATE');
   need(hex64(state.key_sha256)&&await sha(state.publicKey)===state.key_sha256,'KEY_FINGERPRINT');
   need(state.anchor_sha256===await sha(canonical(this.anchor.configuration)),'ANCHOR_CONFIGURATION_BINDING');
   need(Number.isSafeInteger(state.clock_watermark)&&start>=state.clock_watermark,'CLOCK_ROLLBACK');
   const leaf=this.engine.leaf(state.privateState);need(Number.isSafeInteger(leaf)&&leaf>=0&&leaf<1024,'KEY_EXHAUSTED');
   if(this.registrationPayload!==undefined){
    const p=this.registrationPayload;
    need(r.kind==='registration'&&p.schema==='arda.pq.key_registration.v1'&&p.provider==='cloudflare'&&p.algorithm==='HSS-LMS-SHA256-N32-H10-W8'&&p.key_sha256===state.key_sha256&&p.public_key_b64===encode64(state.publicKey)&&p.ceremony_sha256===r.context_sha256&&p.expires_at===r.expires_at&&p.issued_at===state.registration_issued_at,'REGISTRATION_COMMIT_BINDING');
    const domain=new TextEncoder().encode('ARDA/PQ-QUORUM/ENROLLMENT/v1\0'),payload=canonical(p),expected=new Uint8Array(domain.length+payload.length);expected.set(domain);expected.set(payload,domain.length);
    need(expected.length===r.message.length&&expected.every((byte,i)=>byte===r.message[i]),'REGISTRATION_COMMIT_MESSAGE');
   }
   if(this.voteContext!==undefined){
    const v=this.voteContext,p=v.payload;
    need(this.registrationPayload===undefined&&v&&Object.keys(v).sort().join(',')==='config_sha256,epoch,nonce,payload'&&hex64(v.config_sha256)&&hex64(v.nonce)&&Number.isSafeInteger(v.epoch)&&v.epoch>0,'VOTE_COMMIT_CONTEXT');
    need(r.kind==='vote'&&p&&Object.keys(p).sort().join(',')==='algorithm,decision,expires_at,issued_at,key_sha256,policy_sha256,proposal_sha256,provider,role,schema,witness_id','VOTE_COMMIT_FIELDS');
    need(p.schema==='arda.pq.vote.v1'&&p.provider==='cloudflare'&&p.role==='release_witness'&&p.algorithm==='HSS-LMS-SHA256-N32-H10-W8'&&p.witness_id==='cloudflare:arda-pq-release-witness'&&p.decision==='APPROVE'&&p.key_sha256===state.key_sha256&&hex64(p.policy_sha256)&&p.proposal_sha256===r.context_sha256&&p.issued_at===start&&p.expires_at===r.expires_at,'VOTE_COMMIT_BINDING');
    need(state.review_epoch===undefined||(Number.isSafeInteger(state.review_epoch)&&v.epoch>=state.review_epoch&&(v.epoch!==state.review_epoch||state.review_policy_sha256===p.policy_sha256)),'REVIEW_POLICY_ROLLBACK');
    need(await this.storage.get('nonce/'+v.epoch+'/'+v.nonce)===undefined,'REVIEW_NONCE_ALREADY_USED');
    const domain=new TextEncoder().encode('ARDA/PQ-QUORUM/VOTE/v1\0'),body=canonical(p),expected=new Uint8Array(domain.length+body.length);expected.set(domain);expected.set(body,domain.length);
    need(expected.length===r.message.length&&expected.every((byte,i)=>byte===r.message[i]),'VOTE_COMMIT_MESSAGE');
   }
   const message_sha256=await sha(r.message);const nonce=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
   attempted=true;
   const receipt=await this.anchor.burn({kind:r.kind,key_sha256:state.key_sha256,leaf,message_sha256,context_sha256:r.context_sha256,attempt_nonce:nonce,issued_at:start,expires_at:r.expires_at});
   need(receipt?.leaf===leaf&&receipt.key_sha256===state.key_sha256&&receipt.message_sha256===message_sha256&&receipt.attempt_nonce===nonce,'ANCHOR_RECEIPT_BINDING');
   const afterBurn=this.now();need(start<=afterBurn&&afterBurn<r.expires_at,'EXPIRY_AFTER_BURN');
   const out=await this.engine.sign(state.privateState.slice(),state.publicKey.slice(),r.message);
   need(out?.leaf===leaf&&out.signature instanceof Uint8Array&&out.signature.length===1456&&new DataView(out.signature.buffer,out.signature.byteOffset).getUint32(4)===leaf,'SIGNATURE_LEAF_BINDING');
   need(out.privateState instanceof Uint8Array&&this.engine.leaf(out.privateState)===leaf+1,'PRIVATE_STATE_ADVANCE');
   const afterSign=this.now();need(afterBurn<=afterSign,'CLOCK_ROLLBACK_AFTER_SIGN');
   state={...state,privateState:out.privateState.slice(),clock_watermark:afterSign};
   if(this.registrationPayload!==undefined){
    // One atomic storage operation commits the public proof with the advanced key.
    const registration={payload:this.registrationPayload,signature_b64:encode64(out.signature)};
    await this.storage.put({key:state,registration});
   }else if(this.voteContext!==undefined){
    const v=this.voteContext,p=v.payload;
    state={...state,review_epoch:v.epoch,review_policy_sha256:p.policy_sha256};
    const vote={payload:p,signature_b64:encode64(out.signature)};
    const entry={vote,config_sha256:v.config_sha256,epoch:v.epoch,nonce:v.nonce};
    await this.storage.put({key:state,['vote/'+p.proposal_sha256]:entry,['nonce/'+v.epoch+'/'+v.nonce]:{proposal_sha256:p.proposal_sha256,policy_sha256:p.policy_sha256,key_sha256:p.key_sha256}});
   }else await this.storage.put('key',state);
   await this.storage.sync();
   const end=this.now();need(afterSign<=end&&end<r.expires_at,'EXPIRY_AFTER_DURABILITY');
   return {...closed('EXTERNALLY_BURNED_CANDIDATE_SIGNATURE'),signature_created:true,signature:out.signature.slice(),leaf,anchor_ref:receipt.ref,anchor_tag_sha:receipt.tag_sha};
  }catch {
   if(attempted){this.quarantined=true;if(state)try{await this.storage.put('key',{...state,state:'QUARANTINED'});await this.storage.sync();}catch{}}
   return closed('HSS_SIGNING_REFUSED');
  }finally{this.busy=false;}
 }
}
