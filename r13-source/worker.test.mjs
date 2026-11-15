import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { generateKeyPairSync, createHash, sign, verify } from 'node:crypto';
import { handle, Ledger } from './verifier.mjs';

const pair = (alg) => alg === 'rsa' ? generateKeyPairSync(alg, { modulusLength: 2048 }) : generateKeyPairSync(alg);
const ak = pair('rsa'), ed = pair('ed25519'), wrong = pair('rsa');
const PCR = [0,1,4,7,8,9,11];
const boot_id = '9e8897df-a2bb-4cdd-97c6-1e8ae42550fa', node_id = 'lenovo-valinor';
const profile = Object.fromEntries(PCR.map(n => [n, (n+1).toString(16).padStart(2,'0').repeat(32)]));
const der = (key,type) => key.export({type,format:'der'});
const hash = data => createHash('sha256').update(data).digest();
const canonical = obj => typeof obj === 'object' && obj !== null ?
  '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}' : JSON.stringify(obj);
const b64 = a => a.toString('base64');
const token = 'aa'.repeat(32);
const base = 'https://arda-r13-verifier.dio-workflows.workers.dev';
const challengePath = '/verify/phase4/v2/challenge', proofPath = '/verify/phase4/v2';
const config = { R13_TOKEN: token, R13_SIGNER_PKCS8_B64: b64(der(ed.privateKey,'pkcs8')),
  R13_ENROLLMENT: canonical({verifier_id:'cloudflare-r13-v2',node_id,
    ak_spki_b64:b64(der(ak.publicKey,'spki')),ak_spki_sha256:hash(der(ak.publicKey,'spki')).toString('hex'),pcrs:profile}) };
function setup(env = config) {
  const db = new DatabaseSync(':memory:');
  let now = 1800000000;
  const ledger = () => new Ledger({
    sql: { exec(sql,...args) {
      const st = db.prepare(sql);
      return /^\s*(SELECT|UPDATE.+RETURNING)/is.test(sql) ? st.all(...args) : st.run(...args);
    }},
    async sync() {},
    transactionSync(fn) {
      db.exec('BEGIN IMMEDIATE');
      try { const r = fn(); db.exec('COMMIT'); return r; }
      catch (e) { db.exec('ROLLBACK'); throw e; }
    },
  });
  let l = ledger();
  return {
    post(path, body, auth=token) {
      const req = new Request(base+path, {method:'POST', headers:{Authorization:'Bearer '+auth,'Content-Type':'application/json'},
        body: typeof body === 'string' ? body : canonical(body)});
      return handle(req, env, () => l, () => now);
    },
    restart() { l = ledger(); },
    advance(s) { now += s; },
  };
}
async function issue(s) {
  const r = await s.post(challengePath,{node_id,boot_id});
  assert.equal(r.status,201);
  const signed = await r.json();
  assert(verify(null, Buffer.from('ARDA/R13/ISSUED-CHALLENGE/v2\0'+canonical(signed.challenge)),
    ed.publicKey, Buffer.from(signed.ed25519_signature_b64,'base64')));
  return signed.challenge;
}
function quote(c, { pcrs = profile, selection = PCR, key = ak.privateKey, qualification = c } = {}) {
  const hdr = Buffer.from('ff544347801800000020','hex');
  const nonce = hash(Buffer.from('ARDA/R13/TPM-QUOTE/v2\0'+canonical(qualification)));
  const sel = Buffer.from('00000001000b030000000020','hex');
  for (const n of selection) sel[7 + (n >> 3)] |= 1 << (n % 8);
  const message = Buffer.concat([hdr,nonce,Buffer.alloc(25),sel,
    hash(Buffer.concat(selection.map(n => Buffer.from(pcrs[n],'hex'))))]);
  const sig = sign('sha256',message,key);
  return {challenge_id:c.challenge_id, boot_id:c.boot_id,pcrs,quote_b64:b64(message),
    signature_b64:b64(Buffer.concat([Buffer.from('0014000b0100','hex'),sig]))};
}
test('valid quote issues pinned Ed25519 receipt and restart cannot replay', async () => {
  const s=setup(), c=await issue(s), q=quote(c);
  const res=await s.post(proofPath,q); assert.equal(res.status,200);
  const r=await res.json(); assert.equal(r.payload.status,'PASS');
  assert.equal(r.payload.production_cutover_authorized,false);
  assert.equal(r.payload.evidence_sha256, hash(canonical(q)).toString('hex'));
  assert(verify(null, Buffer.from('ARDA/R13/EVIDENCE-RECEIPT/v2\0'+canonical(r.payload)),
    ed.publicKey,Buffer.from(r.ed25519_signature_b64,'base64')));
  s.restart(); assert.equal((await s.post(proofPath,q)).status,409);
});
test('concurrent verification yields only one signed receipt', async () => {
  const s=setup(), q=quote(await issue(s));
  const rs=await Promise.all(Array.from({length:8},()=>s.post(proofPath,q)));
  assert.deepEqual(rs.map(r=>r.status).sort(),[200,409,409,409,409,409,409,409]);
});
test('expired challenge yields no receipt', async () => {
  const s=setup(), q=quote(await issue(s)); s.advance(120);
  assert.equal((await s.post(proofPath,q)).status,409);
});
test('malformed or unauthenticated requests are refused', async () => {
  const s=setup();
  assert.equal((await s.post(challengePath,{node_id,boot_id},'bb'.repeat(32))).status,401);
  assert.equal((await s.post(challengePath,'{"node_id":"first","node_id":"second"}')).status,400);
  assert.equal((await s.post(challengePath,'x'.repeat(65537))).status,413);
  assert.equal((await s.post('/verify/phase4',{node_id,boot_id})).status,404);
  assert.equal((await setup({}).post(challengePath,{node_id,boot_id})).status,503);
});
test('quote must bind the approved PCR tuple, full selection, boot challenge and enrolled AK', async () => {
  const s=setup(), c=await issue(s);
  const cases = [
    [quote(c,{pcrs:{...profile,11:'ff'.repeat(32)}}),'PCR_POLICY_MISMATCH'],
    [quote(c,{selection:PCR.slice(0,-1)}),'QUOTE_SELECTION'],
    [quote(c,{qualification:{...c,boot_id:'3e8897df-a2bb-4cdd-97c6-1e8ae42550fa'}}),'QUOTE_QUALIFICATION'],
    [quote(c,{key:wrong.privateKey}),'QUOTE_SIGNATURE'],
    [{...quote(c),pcrs:{...profile,11:'ff'.repeat(32)}},'QUOTE_PCR_DIGEST'],
  ];
  for (const [body,detail] of cases) {
    const r=await s.post(proofPath,body); assert.equal(r.status,400);
    assert.equal((await r.json()).detail,detail);
  }
  assert.equal((await s.post(proofPath,quote(c))).status,200);
});

if (process.env.R13_WRANGLER) {
  test('Cloudflare runtime with real Durable Object and Python receipt verification', async t => {
    const { spawn, spawnSync } = await import('node:child_process');
    const { fileURLToPath } = await import('node:url');
    const { mkdtempSync, rmSync, writeFileSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const root = fileURLToPath(new URL('.', import.meta.url));
    const store=mkdtempSync(join(tmpdir(),'r13-worker-'));
    const envFile=join(store,'fixture.env');
    writeFileSync(envFile,Object.entries(config).map(([k,v])=>k+"='"+v+"'").join('\n'),{mode:0o600});
    let child;
    const stop = async () => {
      if (!child || child.exitCode !== null || child.signalCode !== null) return;
      await new Promise(resolve => {
        const target=child;
        const timer=setTimeout(()=>target.kill('SIGKILL'),3000);
        target.once('exit',()=>{clearTimeout(timer);resolve();});
        target.kill('SIGTERM');
      });
    };
    const make = () => new Promise((resolve,reject) => {
      child=spawn(process.env.R13_WRANGLER,['dev','--ip','127.0.0.1','--port','0',
        '--env-file',envFile,'--persist-to',store],{cwd:root,env:{...process.env,
        WRANGLER_SEND_METRICS:'false',CI:'true'},stdio:['ignore','pipe','pipe']});
      let output='';
      const timer=setTimeout(()=>reject(new Error('Worker startup timeout: '+output)),20000);
      child.once('error',e=>{clearTimeout(timer);reject(e);});
      child.once('exit',code=>{clearTimeout(timer);reject(new Error('Worker exit '+code+': '+output));});
      for (const stream of [child.stdout,child.stderr]) stream.on('data',chunk=>{
        output += chunk.toString();
        const match=output.match(/Ready on (http:\/\/127\.0\.0\.1:\d+)/);
        if(match) {clearTimeout(timer);resolve(match[1]);}
      });
    });
    let local;
    try {
      local=await make();
      const post=(path,body,auth=token)=>fetch(local+path,{method:'POST',headers:{
        'content-type':'application/json',authorization:'Bearer '+auth},body:canonical(body)});
      assert.equal((await post(challengePath,{node_id,boot_id},'bb'.repeat(32))).status,401);
      const start=await post(challengePath,{node_id,boot_id});
      assert.equal(start.status,201);
      const issued=await start.json(), evidence=quote(issued.challenge);
      const replies=await Promise.all([post(proofPath,evidence),post(proofPath,evidence)]);
      assert.deepEqual(replies.map(r=>r.status).sort(),[200,409]);
      const receipt=await replies.find(r=>r.status===200).json();
      const py=spawnSync('python3',['-B','-c',`
import json,sys
from cryptography.hazmat.primitives import serialization
from r13_v2 import verify_issued_challenge,verify_receipt
x=json.load(sys.stdin)
key=serialization.load_pem_public_key(x["pem"].encode())
challenge=verify_issued_challenge(x["issued"],key)
assert verify_receipt(x["receipt"],key,challenge,x["evidence"])["production_cutover_authorized"] is False
`],{cwd:root,input:JSON.stringify({issued,evidence,receipt,pem:ed.publicKey.export({type:'spki',format:'pem'})}),encoding:'utf8'});
      assert.equal(py.status,0,py.stderr);
      await stop();
      local=await make();
      assert.equal((await post(proofPath,evidence)).status,409);
    } finally { await stop(); rmSync(store,{force:true,recursive:true}); }
  });
}
