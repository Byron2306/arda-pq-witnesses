const PCR = [0, 1, 4, 7, 8, 9, 11];
const PCR_KEYS = PCR.map(String);
const SELECTION = 'sha256:' + PCR.join(',');
const MAX_BODY = 65536;
const enc = new TextEncoder(), dec = new TextDecoder('utf-8', {fatal:true, ignoreBOM:true});
const HEX = /^[0-9a-f]{64}$/;
const ID = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;
const CID = /^[0-9a-f]{32}$/;
const BOOT = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const CHALLENGE = '/verify/phase4/v2/challenge';
const PROOF = '/verify/phase4/v2';
class Refusal extends Error {
  constructor(code, status=400) { super(code); this.status=status; }
}
function need(ok, code, status) { if (!ok) throw new Refusal(code,status); }
function exact(o, keys, code) {
  need(o !== null && typeof o === 'object' && !Array.isArray(o) &&
    Object.keys(o).length === keys.length && keys.every(k => Object.hasOwn(o,k)),code);
}
function match(pattern,s) {
  return typeof s === 'string' && pattern.test(s) && !s.endsWith('\n') && !s.endsWith('\r');
}
function validBoot(s) { return match(BOOT,s) && s !== '00000000-0000-0000-0000-000000000000'; }
function pcrs(o) {
  exact(o,PCR_KEYS,'PCR_FIELDS');
  need(PCR_KEYS.every(k=>match(HEX,o[k])),'PCR_VALUE_FORMAT');
  return o;
}
// Python v2's canonical JSON for the ASCII-only protocol. Sort numeric-looking keys as strings.
function canonical(o,depth=0) {
  need(depth <= 5,'JSON_DEPTH');
  if (o === null || typeof o === 'boolean' || Number.isSafeInteger(o)) return JSON.stringify(o);
  if (typeof o === 'string') {
    need(/^[\x20-\x7e]*$/.test(o) && !o.endsWith('\n') && !o.endsWith('\r'),'JSON_ASCII');
    return JSON.stringify(o);
  }
  need(typeof o === 'object' && !Array.isArray(o),'JSON_FORMAT');
  return '{'+Object.keys(o).sort().map(k=>canonical(k,depth+1)+':'+canonical(o[k],depth+1)).join(',')+'}';
}
const bytes = s => enc.encode(s);
const hex = a => Array.from(a, v=>v.toString(16).padStart(2,'0')).join('');
const unhex = s => Uint8Array.from(s.match(/../g),v=>Number.parseInt(v,16));
const sha = async a => new Uint8Array(await crypto.subtle.digest('SHA-256',a));
const shahex = async a => hex(await sha(a));
const digest = o => shahex(bytes(canonical(o)));
const fromB64 = (s,cap,code) => {
  need(typeof s === 'string' && s.length > 0 && s.length <= Math.ceil(cap/3)*4,code);
  let a;
  try { a = Uint8Array.from(atob(s), v=>v.charCodeAt(0)); } catch { throw new Refusal(code); }
  need(a.length > 0 && a.length <= cap && b64(a) === s,code);
  return a;
};
const b64 = a => btoa(String.fromCharCode(...a));
function equal(a,b) {
  if (a.length !== b.length) return false;
  let v=0;
  for(let i=0;i<a.length;i++) v |= a[i]^b[i];
  return v===0;
}
const tnow = () => Math.floor(Date.now()/1000);
const random = n => hex(crypto.getRandomValues(new Uint8Array(n)));

async function parseBody(req) {
  need(req.headers.get('Content-Type')?.split(';',1)[0].trim().toLowerCase()==='application/json','CONTENT_TYPE',415);
  need(!req.headers.has('Content-Encoding'),'CONTENT_ENCODING',415);
  need(req.body !== null,'JSON_FORMAT');
  const rd=req.body.getReader(), chunks=[];
  let n=0;
  while(true) {
    const {value,done}=await rd.read();
    if(done) break;
    n+=value.length;
    if(n>MAX_BODY) {
      void rd.cancel().catch(()=>{});
      throw new Refusal('BODY_SIZE',413);
    }
    chunks.push(value);
  }
  const merged=new Uint8Array(n);
  let at=0;
  for (const chunk of chunks) { merged.set(chunk,at); at+=chunk.length; }
  let raw,o;
  try { raw=dec.decode(merged); o=JSON.parse(raw); } catch { throw new Refusal('JSON_FORMAT'); }
  // Exact reserialization rejects duplicate keys, ambiguous numbers and noncanonical encodings.
  need(raw===canonical(o),'JSON_NOT_CANONICAL');
  return o;
}

async function authenticate(req,env) {
  need(match(HEX,env.R13_TOKEN),'VERIFIER_NOT_CONFIGURED',503);
  const got = req.headers.get('Authorization');
  need(typeof got==='string' && got.startsWith('Bearer ') && match(HEX,got.slice(7)), 'UNAUTHORIZED',401);
  const [a,b]=await Promise.all([sha(bytes(got.slice(7))),sha(bytes(env.R13_TOKEN))]);
  need(equal(a,b),'UNAUTHORIZED',401);
}

const cfgCache=new WeakMap();
async function loadConfig(env) {
  if (!cfgCache.has(env)) cfgCache.set(env,(async()=>{
    try {
      need(typeof env.R13_ENROLLMENT==='string' && env.R13_ENROLLMENT.length <= 4096,'ENROLLMENT');
      const c=JSON.parse(env.R13_ENROLLMENT);
      exact(c,['verifier_id','node_id','ak_spki_b64','ak_spki_sha256','pcrs'],'ENROLLMENT');
      need(canonical(c)===env.R13_ENROLLMENT,'ENROLLMENT');
      need(match(ID,c.verifier_id) && match(ID,c.node_id) && match(HEX,c.ak_spki_sha256),'ENROLLMENT');
      pcrs(c.pcrs);
      need(PCR_KEYS.every(k=>c.pcrs[k]!=='0'.repeat(64)),'ENROLLMENT');
      const spki=fromB64(c.ak_spki_b64,1024,'AK_ENCODING');
      need(await shahex(spki)===c.ak_spki_sha256,'AK_PIN');
      const ak=await crypto.subtle.importKey('spki',spki,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
      need(ak.algorithm.modulusLength>=2048 && ak.algorithm.modulusLength<=4096,'AK_SIZE');
      const signer=await crypto.subtle.importKey('pkcs8',fromB64(env.R13_SIGNER_PKCS8_B64,128,'SIGNER'),
        'Ed25519',false,['sign']);
      const policy=await digest({schema:'arda.r13.pcr_policy.v2',ak_spki_sha256:c.ak_spki_sha256,
        pcr_selection:SELECTION,pcrs:c.pcrs});
      return {...c,policy,ak,signer};
    } catch { throw new Refusal('VERIFIER_NOT_CONFIGURED',503); }
  })());
  return cfgCache.get(env);
}

class Cursor {
  constructor(a,code) { this.a=a; this.pos=0; this.code=code; }
  take(n) {
    need(n>=0 && this.pos+n<=this.a.length,this.code);
    const out=this.a.subarray(this.pos,this.pos+n); this.pos+=n; return out;
  }
  uint(n) { let v=0; for(const byte of this.take(n)) v=v*256+byte; return v; }
  blob(cap) { const n=this.uint(2); need(n<=cap,this.code); return this.take(n); }
  end() { need(this.pos===this.a.length,this.code); }
}

async function appraise(e,challenge,c) {
  const m=fromB64(e.quote_b64,4096,'QUOTE_ENCODING');
  const sig=fromB64(e.signature_b64,1024,'SIGNATURE_ENCODING');
  const q=new Cursor(m,'QUOTE_FORMAT');
  need(q.uint(4)===0xff544347 && q.uint(2)===0x8018,'QUOTE_TYPE');
  q.blob(68);
  const qualification=await sha(bytes('ARDA/R13/TPM-QUOTE/v2\0'+canonical(challenge)));
  need(equal(q.blob(64),qualification),'QUOTE_QUALIFICATION');
  q.take(25);
  need(q.uint(4)===1 && q.uint(2)===11,'QUOTE_SELECTION');
  const w=q.uint(1);
  need(w>=1 && w<=4,'QUOTE_SELECTION');
  const mask=q.take(w).reduce((v,b,i)=>v+b*256**i,0);
  need(mask===PCR.reduce((v,n)=>v+2**n,0),'QUOTE_SELECTION');
  const quoted=q.blob(32);
  q.end();
  const pcrHash=await sha(unhex(PCR_KEYS.map(k=>e.pcrs[k]).join('')));
  need(equal(quoted,pcrHash),'QUOTE_PCR_DIGEST');
  const s=new Cursor(sig,'QUOTE_SIGNATURE_FORMAT');
  need(s.uint(2)===0x14 && s.uint(2)===11,'QUOTE_SIGNATURE_SCHEME');
  const raw=s.blob(512); s.end();
  need(raw.length===Math.ceil(c.ak.algorithm.modulusLength/8),'QUOTE_SIGNATURE_FORMAT');
  need(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',c.ak,raw,m),'QUOTE_SIGNATURE');
  need(PCR_KEYS.every(k=>e.pcrs[k]===c.pcrs[k]),'PCR_POLICY_MISMATCH');
  const [quote_sha256,quote_signature_sha256,evidence_sha256,challenge_sha256]=await Promise.all([
    shahex(m),shahex(sig),digest(e),digest(challenge)]);
  return {quote_sha256,quote_signature_sha256,evidence_sha256,challenge_sha256,qualification_sha256:hex(qualification)};
}

export class Ledger {
  constructor(storage) {
    this.storage=storage;
    this.sql=storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS r13_challenges
      (id TEXT PRIMARY KEY, expires INTEGER NOT NULL, payload TEXT NOT NULL, consumed INTEGER)`);
  }
  issue(challenge) {
    this.storage.transactionSync(()=>{
      this.sql.exec('DELETE FROM r13_challenges WHERE expires <= ?',challenge.issued_at);
      const [row]=Array.from(this.sql.exec('SELECT COUNT(*) AS n FROM r13_challenges'));
      need(row.n<32,'CHALLENGE_LIMIT',429);
      this.sql.exec('INSERT INTO r13_challenges VALUES (?,?,?,NULL)',challenge.challenge_id,challenge.expires_at,canonical(challenge));
    });
  }
  lookup(id,now) {
    const [r]=Array.from(this.sql.exec('SELECT payload FROM r13_challenges WHERE id=? AND expires>? AND consumed IS NULL',id,now));
    need(r,'CHALLENGE_UNAVAILABLE',409);
    return r.payload;
  }
  async consume(id,now,payload) {
    const [updated]=Array.from(this.sql.exec(`UPDATE r13_challenges SET consumed=?
      WHERE id=? AND expires>? AND consumed IS NULL AND payload=? RETURNING id`,now,id,now,payload));
    need(updated?.id===id,'CHALLENGE_UNAVAILABLE',409);
    await this.storage.sync();
  }
}

async function signed(signer,domain,obj) {
  return b64(new Uint8Array(await crypto.subtle.sign('Ed25519',signer,bytes(domain+'\0'+canonical(obj)))));
}
const json = (obj,status=200) => Response.json(obj,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
function refusal(err) { return err instanceof Refusal ? json({detail:err.message},err.status) : json({detail:'VERIFIER_UNAVAILABLE'},503); }
async function route(req,env) {
  const path=new URL(req.url).pathname;
  need(req.method==='POST' && (path===CHALLENGE || path===PROOF),'NOT_FOUND',404);
  await authenticate(req,env);
  return path;
}
export async function ingress(req,env,send) {
  try { await route(req,env); return await send(req); }
  catch(err) { return refusal(err); }
}

export async function handle(req,env,getLedger,clock=tnow) {
  try {
    const path=await route(req,env), body=await parseBody(req), c=await loadConfig(env);
    const l=getLedger();
    if (path===CHALLENGE) {
      exact(body,['node_id','boot_id'],'ISSUE_FIELDS');
      need(body.node_id===c.node_id && validBoot(body.boot_id),'ISSUE_NODE_OR_BOOT');
      const now=clock(), challenge={schema:'arda.r13.challenge.v2',verifier_id:c.verifier_id,
        node_id:c.node_id,boot_id:body.boot_id,challenge_id:random(16),nonce:random(32),
        issued_at:now,expires_at:now+120,policy_sha256:c.policy};
      l.issue(challenge);
      return json({challenge,ed25519_signature_b64:await signed(c.signer,'ARDA/R13/ISSUED-CHALLENGE/v2',challenge)},201);
    }
    exact(body,['challenge_id','boot_id','pcrs','quote_b64','signature_b64'],'EVIDENCE_FIELDS');
    need(match(CID,body.challenge_id) && validBoot(body.boot_id),'EVIDENCE_IDENTIFIERS');
    pcrs(body.pcrs);
    const raw=l.lookup(body.challenge_id,clock()), challenge=JSON.parse(raw);
    need(challenge.boot_id===body.boot_id,'CHALLENGE_BOOT_MISMATCH');
    need(challenge.verifier_id===c.verifier_id && challenge.node_id===c.node_id &&
      challenge.policy_sha256===c.policy,'CHALLENGE_POLICY_CHANGED',409);
    const evidence=await appraise(body,challenge,c), issued_at=clock();
    need(challenge.issued_at<=issued_at && issued_at<challenge.expires_at,'CHALLENGE_UNAVAILABLE',409);
    await l.consume(body.challenge_id,issued_at,raw);
    const payload={schema:'arda.r13.evidence_receipt.v2',status:'PASS',verifier_id:c.verifier_id,
      node_id:c.node_id,boot_id:body.boot_id,challenge_id:body.challenge_id,...evidence,
      ak_spki_sha256:c.ak_spki_sha256,policy_sha256:c.policy,pcr_selection:SELECTION,
      issued_at,expires_at:challenge.expires_at,production_cutover_authorized:false};
    return json({payload,ed25519_signature_b64:await signed(c.signer,'ARDA/R13/EVIDENCE-RECEIPT/v2',payload)});
  } catch(err) { return refusal(err); }
}
