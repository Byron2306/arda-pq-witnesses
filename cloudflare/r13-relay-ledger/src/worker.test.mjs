import test from 'node:test';
import assert from 'node:assert/strict';
import worker,{R13RelayLedger} from './worker.mjs';

class TestSQL {
  constructor(){this.byTicket=new Map();this.challengeIds=new Set();this.lastChanges=0}
  exec(query,...args){
    if(query.startsWith('CREATE TABLE'))return {rowsWritten:0};
    if(query==='SELECT changes() AS changed')return {one:()=>({changed:this.lastChanges})};
    if(query.startsWith('INSERT OR IGNORE')){
      const [ticket,cid,digest,expiry]=args;
      if(this.challengeIds.has(cid)||this.byTicket.has(ticket)){this.lastChanges=0;return {rowsWritten:0};}
      this.byTicket.set(ticket,{cid,digest,expiry,used:false});this.challengeIds.add(cid);
      this.lastChanges=1;
      // Cloudflare counts writes to the primary key and UNIQUE indexes separately.
      return {rowsWritten:3};
    }
    if(query.startsWith('UPDATE claims')){
      const [ticket,digest,now]=args;const row=this.byTicket.get(ticket);
      if(!row||row.digest!==digest||row.used||row.expiry<=now){this.lastChanges=0;return {rowsWritten:0};}
      row.used=true;this.lastChanges=1;return {rowsWritten:2};
    }
    throw new Error('UNKNOWN_SQL');
  }
}
function req(path,body,auth='Bearer '+('x'.repeat(48))){
  return new Request('https://ledger.example'+path,{method:'POST',headers:{authorization:auth,'content-type':'application/json'},body:JSON.stringify(body)});
}
const credential='x'.repeat(48),cid='a'.repeat(32),ticket='b'.repeat(48),digest='c'.repeat(64);
function setup(){
  const sql=new TestSQL();const ctx={storage:{sql}};
  return {sql,env:{RELAY_LEDGER:{idFromName:()=>1,get:()=>new R13RelayLedger(ctx,{})},RELAY_LEDGER_SHARED_SECRET:credential}};
}
test('reserve once and claim once, including across re-instantiation',async()=>{
  const {env}=setup(),expires_at=Math.floor(Date.now()/1000)+90;
  const reservation={challenge_id:cid,ticket,envelope_sha256:digest,expires_at};
  assert.equal((await worker.fetch(req('/reserve',reservation),env)).status,201);
  assert.equal((await worker.fetch(req('/reserve',{...reservation,ticket:'d'.repeat(48)}),env)).status,409);
  assert.equal((await worker.fetch(req('/claim',{ticket,envelope_sha256:digest}),env)).status,200);
  assert.equal((await worker.fetch(req('/claim',{ticket,envelope_sha256:digest}),env)).status,409);
});
test('wrong auth and digest do not claim',async()=>{
  const {env}=setup(),expires_at=Math.floor(Date.now()/1000)+90;
  const r={challenge_id:cid,ticket,envelope_sha256:digest,expires_at};
  assert.equal((await worker.fetch(req('/reserve',r,'Bearer incorrect'),env)).status,401);
  assert.equal((await worker.fetch(req('/reserve',r),env)).status,201);
  assert.equal((await worker.fetch(req('/claim',{ticket,envelope_sha256:'e'.repeat(64)}),env)).status,409);
  assert.equal((await worker.fetch(req('/claim',{ticket,envelope_sha256:digest}),env)).status,200);
});
test('expired reservation refuses and malformed challenge refuses',async()=>{
  const {env}=setup(),expired=Math.floor(Date.now()/1000)-2;
  assert.equal((await worker.fetch(req('/reserve',{challenge_id:cid,ticket,envelope_sha256:digest,expires_at:expired}),env)).status,400);
  assert.equal((await worker.fetch(req('/reserve',{challenge_id:'?',ticket,envelope_sha256:digest,expires_at:expired+100}),env)).status,400);
});
test('concurrent claims single winner under serialized DO',async()=>{
  const {env}=setup(),expires_at=Math.floor(Date.now()/1000)+90;
  await worker.fetch(req('/reserve',{challenge_id:cid,ticket,envelope_sha256:digest,expires_at}),env);
  const responses=await Promise.all(Array.from({length:12},()=>worker.fetch(req('/claim',{ticket,envelope_sha256:digest}),env)));
  assert.equal(responses.filter(x=>x.status===200).length,1);
});
