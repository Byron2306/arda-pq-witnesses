// Disposable cross-language test. Prints public fixture data only; no network.
import { DatabaseSync } from 'node:sqlite';
import { generateKeyPairSync,createHash,sign } from 'node:crypto';
import { handle,Ledger } from '../r13-source/verifier.mjs';
const ak=generateKeyPairSync('rsa',{modulusLength:2048}),ed=generateKeyPairSync('ed25519');
const der=(k,t)=>k.export({type:t,format:'der'}),hash=x=>createHash('sha256').update(x).digest();
const canonical=o=>o!==null&&typeof o==='object'?'{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+canonical(o[k])).join(',')+'}':JSON.stringify(o);
const b64=x=>x.toString('base64'),hex=x=>hash(x).toString('hex');
const pcr=[0,1,4,7,8,9,11],pcrs=Object.fromEntries(pcr.map(n=>[n,(n+1).toString(16).padStart(2,'0').repeat(32)]));
const boot='b08f1e0e-6397-440f-a0ad-73313b7bf87c',node='lenovo-valinor',verifier='cloudflare-r13-v2',token='aa'.repeat(32);
const enrollment={verifier_id:verifier,node_id:node,ak_spki_b64:b64(der(ak.publicKey,'spki')),ak_spki_sha256:hex(der(ak.publicKey,'spki')),pcrs};
const env={R13_TOKEN:token,R13_SIGNER_PKCS8_B64:b64(der(ed.privateKey,'pkcs8')),R13_ENROLLMENT:canonical(enrollment)};
const db=new DatabaseSync(':memory:');
const storage={sql:{exec(sql,...args){const s=db.prepare(sql);return /^\s*SELECT|\bRETURNING\b/i.test(sql)?s.all(...args):s.run(...args);}},
 async sync(){},transactionSync(fn){db.exec('BEGIN IMMEDIATE');try{const r=fn();db.exec('COMMIT');return r;}catch(e){db.exec('ROLLBACK');throw e;}}};
const ledger=new Ledger(storage);
const post=(path,body)=>handle(new Request('https://fixture.invalid'+path,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:canonical(body)}),env,()=>ledger,()=>1000);
const issuedResponse=await post('/verify/phase4/v2/challenge',{node_id:node,boot_id:boot});if(issuedResponse.status!==201)throw Error('fixture challenge failed');
const issued=await issuedResponse.json(),c=issued.challenge;
const qualification=hash(Buffer.from('ARDA/R13/TPM-QUOTE/v2\0'+canonical(c)));
const selection=Buffer.from('00000001000b03','hex'),mask=Buffer.alloc(3);for(const n of pcr)mask[n>>3]|=1<<(n%8);
const quote=Buffer.concat([Buffer.from('ff544347801800000020','hex'),qualification,Buffer.alloc(25),selection,mask,
 Buffer.from('0020','hex'),hash(Buffer.concat(pcr.map(n=>Buffer.from(pcrs[n],'hex'))))]);
const signature=sign('sha256',quote,ak.privateKey),length=Buffer.alloc(2);length.writeUInt16BE(signature.length);
const evidence={challenge_id:c.challenge_id,boot_id:boot,pcrs,quote_b64:b64(quote),signature_b64:b64(Buffer.concat([Buffer.from('0014000b','hex'),length,signature]))};
const reply=await post('/verify/phase4/v2',evidence);if(reply.status!==200)throw Error('fixture receipt failed');
const receipt=await reply.json();
console.log(JSON.stringify({verifier_pem:ed.publicKey.export({type:'spki',format:'pem'}),ak_pem:ak.publicKey.export({type:'spki',format:'pem'}),
 pcrs,pins:{verifier_spki_sha256:hex(der(ed.publicKey,'spki')),ak_spki_sha256:enrollment.ak_spki_sha256,policy_sha256:c.policy_sha256,
 node_id:node,verifier_id:verifier},boot,capture:{schema:'arda.r13.capture.v2',issued_challenge:issued,evidence,receipt}}));
db.close();
