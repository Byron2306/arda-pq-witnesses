// Explicit orphan replacement. Archived private state is never an active signing source.
import {need,canonical,sha,hex64} from './hss-guard.mjs';
export const encode64=bytes=>{let text='';for(const byte of bytes)text+=String.fromCharCode(byte);return btoa(text);};
export function registrationPayload(c,state){return {schema:'arda.pq.key_registration.v1',ceremony_sha256:c.ceremony_sha256,provider:'cloudflare',provider_identity:c.worker_identity,witness_id:'cloudflare:'+c.worker_identity,role:'release_witness',algorithm:'HSS-LMS-SHA256-N32-H10-W8',key_sha256:state.key_sha256,public_key_b64:encode64(state.publicKey),secret_name:null,issued_at:state.registration_issued_at,expires_at:c.ceremony.expires_at};}
export function publicReceipt(receipt){
 need(receipt&&Object.keys(receipt).sort().join(',')==='ceremony_sha256,interlock,issued_at,old_ceremony_sha256,prior_burn_ref,prior_burn_tag_sha,production_authorized,replacement_key_sha256,replacement_next_leaf,retired_key_sha256,retired_next_leaf,rotation_request_sha256,schema','ROTATION_PUBLIC_FIELDS');
 need(receipt.schema==='arda.cf.hss.rotation_receipt.v1'&&receipt.production_authorized===false&&receipt.interlock==='KEEP_CLOSED'&&receipt.retired_next_leaf===1&&receipt.replacement_next_leaf===0&&Number.isSafeInteger(receipt.issued_at)&&receipt.issued_at>0,'ROTATION_PUBLIC_SCHEMA');
 for(const name of ['ceremony_sha256','old_ceremony_sha256','rotation_request_sha256','retired_key_sha256','replacement_key_sha256'])need(hex64(receipt[name]),'ROTATION_PUBLIC_DIGEST');
 need(receipt.retired_key_sha256!==receipt.replacement_key_sha256&&/^[0-9a-f]{40}$/.test(receipt.prior_burn_tag_sha)&&receipt.prior_burn_ref==='refs/tags/arda-hss-leaf-'+receipt.retired_key_sha256+'-0000','ROTATION_PUBLIC_MARKER');
 return JSON.parse(new TextDecoder().decode(canonical(receipt)));
}
export async function replaceOrphan({storage,engine,anchor,c,oldConfig,input,clock,validateCurrent}){
 const requestSha=await sha(canonical(input)),receiptName='rotation/'+requestSha,archiveName='retired/'+input.expected_key_sha256;
 const completed=await storage.get(receiptName),state=await storage.get('key'),archive=await storage.get(archiveName);
 if(completed){
  need(completed.schema==='arda.cf.hss.rotation_receipt.v1'&&completed.rotation_request_sha256===requestSha&&completed.retired_key_sha256===input.expected_key_sha256&&completed.ceremony_sha256===c.ceremony_sha256&&completed.replacement_key_sha256===state?.key_sha256&&archive?.state==='RETIRED'&&archive.original_state?.key_sha256===input.expected_key_sha256,'ROTATION_REPLAY_BINDING');
  return publicReceipt(completed);
 }
 need(!archive&&!(await storage.get('registration')),'ROTATION_COMPLETED_OR_ARCHIVED');
 need(state?.schema==='arda.hss.key_state.v1'&&state.state==='ACTIVE'&&state.key_sha256===input.expected_key_sha256&&state.ceremony_sha256===oldConfig.ceremony_sha256,'ROTATION_OLD_KEY');
 need(state.privateState instanceof Uint8Array&&state.privateState.length===64&&state.publicKey instanceof Uint8Array&&state.publicKey.length===60&&await sha(state.publicKey)===state.key_sha256,'ROTATION_OLD_KEY_BYTES');
 need(input.expected_next_leaf===1&&engine.leaf(state.privateState)===1&&state.anchor_sha256===await sha(canonical(c.anchor)),'ROTATION_COUNTER_OR_ANCHOR');
 need(Number.isSafeInteger(state.clock_watermark)&&clock()>=state.clock_watermark,'ROTATION_CLOCK');
 const payload=canonical(registrationPayload(oldConfig,state)),domain=new TextEncoder().encode('ARDA/PQ-QUORUM/ENROLLMENT/v1\0'),message=new Uint8Array(domain.length+payload.length);message.set(domain);message.set(payload,domain.length);
 const burn=await anchor.readBurn({key_sha256:state.key_sha256,leaf:0,tag_sha:input.prior_tag_sha,context_sha256:oldConfig.ceremony_sha256,message_sha256:await sha(message)});
 need(burn.key_sha256===state.key_sha256&&burn.leaf===0&&burn.kind==='registration'&&burn.tag_sha===input.prior_tag_sha&&burn.context_sha256===oldConfig.ceremony_sha256&&burn.message_sha256===await sha(message)&&burn.issued_at>=oldConfig.ceremony.issued_at&&burn.issued_at<burn.expires_at&&burn.expires_at===oldConfig.ceremony.expires_at,'ROTATION_HISTORICAL_BURN');
 await validateCurrent();
 const key=await engine.generate();
 try{
  const now=clock();await validateCurrent();
  need(Number.isSafeInteger(now)&&now>=state.clock_watermark&&key.privateState instanceof Uint8Array&&key.privateState.length===64&&engine.leaf(key.privateState)===0&&key.publicKey instanceof Uint8Array&&key.publicKey.length===60,'ROTATION_NEW_KEY');
  const fingerprint=await sha(key.publicKey);need(fingerprint!==state.key_sha256,'ROTATION_KEY_COLLISION');
  const next={schema:'arda.hss.key_state.v1',state:'ACTIVE',privateState:key.privateState.slice(),publicKey:key.publicKey.slice(),key_sha256:fingerprint,anchor_sha256:state.anchor_sha256,clock_watermark:now,ceremony_sha256:c.ceremony_sha256,registration_issued_at:now,replaces_key_sha256:state.key_sha256,rotation_request_sha256:requestSha};
  const receipt={schema:'arda.cf.hss.rotation_receipt.v1',rotation_request_sha256:requestSha,retired_key_sha256:state.key_sha256,replacement_key_sha256:fingerprint,old_ceremony_sha256:oldConfig.ceremony_sha256,ceremony_sha256:c.ceremony_sha256,retired_next_leaf:1,replacement_next_leaf:0,prior_burn_ref:burn.ref,prior_burn_tag_sha:burn.tag_sha,issued_at:now,production_authorized:false,interlock:'KEEP_CLOSED'};
  await storage.put({[archiveName]:{schema:'arda.hss.retired_key.v1',state:'RETIRED',original_state:state,receipt},key:next,[receiptName]:receipt});
  await storage.sync();await validateCurrent();return receipt;
 }finally{if(key.privateState instanceof Uint8Array)key.privateState.fill(0);}
}
