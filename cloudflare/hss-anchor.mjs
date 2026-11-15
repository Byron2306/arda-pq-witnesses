// Dedicated external leaf markers. This adapter can CREATE refs, never update or delete them.
import {need,hex64,canonical,sha} from './hss-guard.mjs';
const REPOSITORY='Byron2306/arda-hss-leaf-anchor';
const PREFIX='arda-hss-leaf-';
export function rulesProjection(r){
 need(r&&r.target==='tag'&&r.enforcement==='active'&&Array.isArray(r.bypass_actors)&&r.bypass_actors.length===0,'ANCHOR_RULES_BYPASS');
 need(r.conditions&&Object.keys(r.conditions).join(',')==='ref_name','ANCHOR_RULE_CONDITIONS');
 const names=r.conditions.ref_name;
 need(names&&Object.keys(names).sort().join(',')==='exclude,include','ANCHOR_RULE_REF_FIELDS');
 need(names&&Array.isArray(names.include)&&names.include.length===1&&names.include[0]==='refs/tags/'+PREFIX+'*'&&Array.isArray(names.exclude)&&names.exclude.length===0,'ANCHOR_RULE_SCOPE');
 need(Array.isArray(r.rules)&&!r.rules.some(v=>v.type==='creation'),'ANCHOR_RULES_CREATION_MUST_BE_ALLOWED');
 for(const type of ['update','deletion']){const found=r.rules.filter(v=>v.type===type);need(found.length===1&&(!found[0].parameters||Object.keys(found[0].parameters).length===0),'ANCHOR_IMMUTABILITY_RULE');}
 return {target:r.target,enforcement:r.enforcement,bypass_actors:[],conditions:{ref_name:{include:[names.include[0]],exclude:[]}},rules:[{type:'deletion'},{type:'update'}]};
}
export class ProtectedGitHubAnchor {
 constructor(configuration,token,fetcher=fetch,clock=()=>Math.floor(Date.now()/1000)){
  need(configuration&&Object.keys(configuration).sort().join(',')==='genesis_commit,repository,rules_sha256,ruleset_id,schema','ANCHOR_CONFIGURATION_FIELDS');
  need(configuration.schema==='arda.hss.anchor.v1'&&configuration.repository===REPOSITORY&&/^[0-9a-f]{40}$/.test(configuration.genesis_commit)&&Number.isSafeInteger(configuration.ruleset_id)&&configuration.ruleset_id>0&&hex64(configuration.rules_sha256),'ANCHOR_CONFIGURATION');
  need(typeof token==='string'&&token.length>0&&token.length<=4096&&/^[\x21-\x7e]+$/.test(token),'ANCHOR_CREDENTIAL');
  this.configuration=JSON.parse(new TextDecoder().decode(canonical(configuration)));this.token=token;this.fetcher=fetcher;this.clock=clock;this.lastHttpStatus=null;
 }
 async request(path,method='GET',body){
  const base='https://api.github.com/repos/'+REPOSITORY;
  const allowed=(method==='GET'&&path==='/rulesets/'+this.configuration.ruleset_id)||(method==='POST'&&['/git/tags','/git/refs'].includes(path));need(allowed,'ANCHOR_ENDPOINT');
  // Native Workers fetch must be called without this adapter as its receiver.
  const fetcher=this.fetcher;
  const response=await fetcher(base+path,{method,redirect:'manual',cache:'no-store',signal:AbortSignal.timeout(15000),
   headers:{Authorization:'Bearer '+this.token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'ARDA-HSS-Leaf-Anchor-v5',...(body?{'Content-Type':'application/json'}:{})},body:body?new TextDecoder().decode(canonical(body)):undefined});
  this.lastHttpStatus=response.status;
  need(response.status===(method==='GET'?200:201),'ANCHOR_RESPONSE_UNCERTAIN_OR_REF_EXISTS');
  const reader=response.body?.getReader();need(reader,'ANCHOR_RESPONSE_BODY');let total=0,chunks=[];
  try{for(;;){const {done,value}=await reader.read();if(done)break;total+=value.length;need(total<=131072,'ANCHOR_RESPONSE_SIZE');chunks.push(value);}}finally{await reader.cancel().catch(()=>{});}
  const raw=new Uint8Array(total);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
 }
 async inspect(){
  this.lastHttpStatus=null;
  try{
   const rules=await this.request('/rulesets/'+this.configuration.ruleset_id);
   need(rules.id===this.configuration.ruleset_id&&await sha(canonical(rulesProjection(rules)))===this.configuration.rules_sha256,'ANCHOR_RULE_PIN');
   return {ok:true,http_status:this.lastHttpStatus,reason:'ANCHOR_READ_AND_RULE_PIN_VALID'};
  }catch{
   return {ok:false,http_status:this.lastHttpStatus,reason:this.lastHttpStatus!==null&&this.lastHttpStatus!==200?'ANCHOR_HTTP_REFUSED':'ANCHOR_READ_OR_RULE_PIN_REFUSED'};
  }
 }
 async burn(record){
  need(record&&Object.keys(record).sort().join(',')==='attempt_nonce,context_sha256,expires_at,issued_at,key_sha256,kind,leaf,message_sha256','LEAF_BURN_FIELDS');
  const r=JSON.parse(new TextDecoder().decode(canonical(record)));need(['registration','vote'].includes(r.kind),'LEAF_BURN_KIND');
  for(const k of ['attempt_nonce','context_sha256','key_sha256','message_sha256'])need(hex64(r[k]),'LEAF_BURN_DIGEST');
  need(Number.isSafeInteger(r.leaf)&&r.leaf>=0&&r.leaf<1024,'LEAF_BURN_INDEX');
  const now=this.clock();need(Number.isSafeInteger(r.issued_at)&&Number.isSafeInteger(r.expires_at)&&r.issued_at<=now&&now<r.expires_at&&r.expires_at-r.issued_at<=(r.kind==='registration'?86400:120),'LEAF_BURN_TIME');
  const rules=await this.request('/rulesets/'+this.configuration.ruleset_id);
  need(rules.id===this.configuration.ruleset_id&&await sha(canonical(rulesProjection(rules)))===this.configuration.rules_sha256,'ANCHOR_RULE_PIN');
  const tag=PREFIX+r.key_sha256+'-'+String(r.leaf).padStart(4,'0'),ref='refs/tags/'+tag;
  const object=await this.request('/git/tags','POST',{tag,object:this.configuration.genesis_commit,type:'commit',
   message:new TextDecoder().decode(canonical({schema:'arda.hss.leaf_burn.v1',...r})),
   tagger:{name:'ARDA HSS leaf burn',email:'arda-hss@users.noreply.github.com',date:new Date(now*1000).toISOString()}});
  need(typeof object.sha==='string'&&/^[0-9a-f]{40}$/.test(object.sha),'ANCHOR_TAG_OBJECT');
  const created=await this.request('/git/refs','POST',{ref,sha:object.sha});
  need(created.ref===ref&&created.object?.type==='tag'&&created.object.sha===object.sha,'ANCHOR_CREATED_REF_BINDING');
  return {...r,ref,tag_sha:object.sha};
 }
}
