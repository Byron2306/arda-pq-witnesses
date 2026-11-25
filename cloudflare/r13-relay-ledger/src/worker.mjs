// Separate ARDA R13 one-time ledger. NOT the existing R13 Cloudflare verifier.
// SQLite-backed Durable Object guarantees one globally serialized reservation
// namespace, conditional single-use claim, and persistence across restarts.
const HEX32=/^[0-9a-f]{32}$/;
const HEX48=/^[0-9a-f]{48}$/;
const HEX64=/^[0-9a-f]{64}$/;
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json","cache-control":"no-store"}});
function same(a,b) {
  if (typeof a!=="string" || typeof b!=="string" || !a.length || a.length!==b.length) return false;
  let diff=0;
  for(let i=0;i<a.length;i++) diff|=a.charCodeAt(i)^b.charCodeAt(i);
  return diff===0;
}
export class R13RelayLedger {
  constructor(ctx,env) {
    this.ctx=ctx;
    this.sql=ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS claims (ticket TEXT PRIMARY KEY, challenge_id TEXT UNIQUE NOT NULL, envelope_sha256 TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)");
  }
  async fetch(request) {
    if(request.method!=="POST")return json({error:"METHOD"},405);
    let body;
    try { body=await request.json(); } catch {return json({error:"INVALID_JSON"},400);}
    const now=Math.floor(Date.now()/1000);
    if(new URL(request.url).pathname==="/reserve") {
      if(!body || Object.keys(body).sort().join(",")!=="challenge_id,envelope_sha256,expires_at,ticket" || !HEX32.test(body.challenge_id) || !HEX48.test(body.ticket) || !HEX64.test(body.envelope_sha256) || !Number.isSafeInteger(body.expires_at) || body.expires_at<=now || body.expires_at>now+300) return json({reserved:false,error:"INVALID_RESERVATION"},400);
      // Unique index is the atomic arbiter. Never delete challenges: no late replay.
      this.sql.exec("INSERT OR IGNORE INTO claims(ticket,challenge_id,envelope_sha256,expires_at,used) VALUES (?,?,?,?,0)",body.ticket,body.challenge_id,body.envelope_sha256,body.expires_at);
      // rowsWritten counts SQLite index writes too; changes() counts changed table rows.
      const changed=this.sql.exec("SELECT changes() AS changed").one().changed;
      return json({reserved:changed===1},changed===1?201:409);
    }
    if(new URL(request.url).pathname==="/claim") {
      if(!body || Object.keys(body).sort().join(",")!=="envelope_sha256,ticket" || !HEX48.test(body.ticket) || !HEX64.test(body.envelope_sha256)) return json({claimed:false,error:"INVALID_CLAIM"},400);
      this.sql.exec("UPDATE claims SET used=1 WHERE ticket=? AND envelope_sha256=? AND used=0 AND expires_at>?",body.ticket,body.envelope_sha256,now);
      const changed=this.sql.exec("SELECT changes() AS changed").one().changed;
      return json({claimed:changed===1},changed===1?200:409);
    }
    return json({error:"NOT_FOUND"},404);
  }
}
export default {
  async fetch(request,env) {
    const url=new URL(request.url);
    if(request.method!=="POST" || !["/reserve","/claim"].includes(url.pathname))return json({error:"NOT_FOUND"},404);
    if(!env.RELAY_LEDGER_SHARED_SECRET || !same(request.headers.get("authorization"),"Bearer "+env.RELAY_LEDGER_SHARED_SECRET)) return json({error:"UNAUTHORIZED"},401);
    if(!env.RELAY_LEDGER)return json({error:"LEDGER_NOT_BOUND"},503);
    if(Number(request.headers.get("content-length")||"0")>1024)return json({error:"SIZE"},413);
    const name="arda-r13-global-ledger-v1";
    const id=env.RELAY_LEDGER.idFromName(name);
    return env.RELAY_LEDGER.get(id).fetch(request);
  }
};
