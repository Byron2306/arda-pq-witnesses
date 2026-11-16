// Independent offline R13 v2 appraisal. Protocol/TPM layout follows frozen
// r13-source/verifier.mjs and arda_quorum/r13_protocol.py; neither source is modified.
import {need,hex64,sha,exact,equal,unbase64,message,window,snapshot,canonicalProtocol} from './review-protocol.mjs';
const PCR=[0,1,4,7,8,9,11],selection='sha256:'+PCR.join(','),id=x=>typeof x==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(x);
const boot=x=>typeof x==='string'&&/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(x)&&x!=='00000000-0000-0000-0000-000000000000';
const digest=x=>sha(canonicalProtocol(x));
const unhex=x=>Uint8Array.from(x.match(/../g),v=>parseInt(v,16));
function pcrs(x){exact(x,PCR.map(String),'PCR_FIELDS');need(PCR.every(n=>hex64(x[n])&&x[n]!=='00'.repeat(32)),'PCR_VALUES');}
class Cursor{
 constructor(bytes){this.bytes=bytes;this.at=0;}
 take(n){need(Number.isInteger(n)&&n>=0&&this.at+n<=this.bytes.length,'TPM_BOUNDS');const out=this.bytes.slice(this.at,this.at+n);this.at+=n;return out;}
 uint(n){return this.take(n).reduce((v,b)=>v*256+b,0);}
 blob(cap){const n=this.uint(2);need(n<=cap,'TPM_BLOB');return this.take(n);}
 end(){need(this.at===this.bytes.length,'TPM_TRAILING_BYTES');}
}
export async function loadR13(configuration,expectedBoot){
 const cfg=snapshot(configuration);
 exact(cfg,['verifier_spki_b64','ak_spki_b64','pcrs','pins'],'R13_CONFIG');
 const pins=cfg.pins;exact(pins,['verifier_spki_sha256','ak_spki_sha256','policy_sha256','node_id','verifier_id'],'R13_PINS');
 need(['verifier_spki_sha256','ak_spki_sha256','policy_sha256'].every(k=>hex64(pins[k]))&&id(pins.node_id)&&id(pins.verifier_id)&&boot(expectedBoot),'R13_PIN_FORMAT');pcrs(cfg.pcrs);
 const verifierBytes=unbase64(cfg.verifier_spki_b64,128),akBytes=unbase64(cfg.ak_spki_b64,1024);
 need(await sha(verifierBytes)===pins.verifier_spki_sha256&&await sha(akBytes)===pins.ak_spki_sha256,'R13_PUBLIC_KEY_PINS');
 const verifier=await crypto.subtle.importKey('spki',verifierBytes,'Ed25519',false,['verify']);
 const ak=await crypto.subtle.importKey('spki',akBytes,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 need(ak.algorithm.modulusLength>=2048&&ak.algorithm.modulusLength<=4096,'R13_AK_SIZE');
 need(await digest({schema:'arda.r13.pcr_policy.v2',ak_spki_sha256:pins.ak_spki_sha256,pcr_selection:selection,pcrs:cfg.pcrs})===pins.policy_sha256,'R13_PCR_POLICY_PIN');
 return {cfg,pins,verifier,ak};
}
export async function verifyCapture(configuration,capture,expectedBoot,now){
 const x=snapshot(capture),{cfg,pins,verifier,ak}=await loadR13(configuration,expectedBoot);
 exact(x,['schema','issued_challenge','evidence','receipt'],'CAPTURE_FIELDS');need(x.schema==='arda.r13.capture.v2','CAPTURE_SCHEMA');
 const issued=x.issued_challenge;exact(issued,['challenge','ed25519_signature_b64'],'CHALLENGE_ENVELOPE');const c=issued.challenge;
 exact(c,['schema','verifier_id','node_id','boot_id','challenge_id','nonce','issued_at','expires_at','policy_sha256'],'CHALLENGE_FIELDS');
 need(c.schema==='arda.r13.challenge.v2'&&c.verifier_id===pins.verifier_id&&c.node_id===pins.node_id&&c.boot_id===expectedBoot&&typeof c.challenge_id==='string'&&/^[0-9a-f]{32}$/.test(c.challenge_id)&&hex64(c.nonce)&&c.policy_sha256===pins.policy_sha256,'CHALLENGE_CONTEXT');window(c,now,120);
 need(await crypto.subtle.verify('Ed25519',verifier,unbase64(issued.ed25519_signature_b64,64),message('ARDA/R13/ISSUED-CHALLENGE/v2',c)),'CHALLENGE_SIGNATURE');
 const e=x.evidence;exact(e,['challenge_id','boot_id','pcrs','quote_b64','signature_b64'],'EVIDENCE_FIELDS');need(e.challenge_id===c.challenge_id&&e.boot_id===c.boot_id,'EVIDENCE_CONTEXT');pcrs(e.pcrs);
 need(PCR.every(n=>e.pcrs[n]===cfg.pcrs[n]),'PCR_BASELINE');
 const quote=unbase64(e.quote_b64,4096),signature=unbase64(e.signature_b64,1024),q=new Cursor(quote);
 need(q.uint(4)===0xff544347&&q.uint(2)===0x8018,'QUOTE_TYPE');q.blob(68);
 const qualification=unhex(await sha(message('ARDA/R13/TPM-QUOTE/v2',c)));
 need(equal(q.blob(64),qualification),'QUOTE_QUALIFICATION');q.take(25);
 need(q.uint(4)===1&&q.uint(2)===11,'QUOTE_SELECTION');const width=q.uint(1);need(width>=1&&width<=4,'QUOTE_SELECTION');
 need(q.take(width).reduce((v,b,i)=>v+b*256**i,0)===PCR.reduce((v,n)=>v+2**n,0),'QUOTE_SELECTION');
 need(equal(q.blob(32),unhex(await sha(unhex(PCR.map(n=>e.pcrs[n]).join(''))))),'QUOTE_PCR_DIGEST');q.end();
 const s=new Cursor(signature);need(s.uint(2)===0x14&&s.uint(2)===11,'QUOTE_SIGNATURE_SCHEME');const raw=s.blob(512);s.end();
 need(raw.length===Math.ceil(ak.algorithm.modulusLength/8)&&await crypto.subtle.verify('RSASSA-PKCS1-v1_5',ak,raw,quote),'QUOTE_SIGNATURE');
 const receipt=x.receipt;exact(receipt,['payload','ed25519_signature_b64'],'RECEIPT_ENVELOPE');const p=receipt.payload;
 exact(p,['schema','status','verifier_id','node_id','boot_id','challenge_id','challenge_sha256','qualification_sha256','evidence_sha256','quote_sha256','quote_signature_sha256','ak_spki_sha256','policy_sha256','pcr_selection','issued_at','expires_at','production_cutover_authorized'],'RECEIPT_FIELDS');
 need(await crypto.subtle.verify('Ed25519',verifier,unbase64(receipt.ed25519_signature_b64,64),message('ARDA/R13/EVIDENCE-RECEIPT/v2',p)),'RECEIPT_SIGNATURE');
 need(['verifier_id','node_id','boot_id','challenge_id','policy_sha256','expires_at'].every(k=>p[k]===c[k]),'RECEIPT_CONTEXT');
 need(p.schema==='arda.r13.evidence_receipt.v2'&&p.status==='PASS'&&p.production_cutover_authorized===false&&p.pcr_selection===selection&&p.ak_spki_sha256===pins.ak_spki_sha256&&Number.isSafeInteger(p.issued_at)&&c.issued_at<=p.issued_at&&p.issued_at<=now&&now<p.expires_at,'RECEIPT_POLICY_WINDOW');
 need(p.challenge_sha256===await digest(c)&&p.qualification_sha256===Array.from(qualification,b=>b.toString(16).padStart(2,'0')).join('')&&p.evidence_sha256===await digest(e)&&p.quote_sha256===await sha(quote)&&p.quote_signature_sha256===await sha(signature),'RECEIPT_DIGESTS');
 return {capture_sha256:await digest(x),issued_at:p.issued_at,expires_at:p.expires_at};
}
