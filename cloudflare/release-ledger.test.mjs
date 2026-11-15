import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { ReleaseReviewLedger } from './release-ledger.mjs';

const key='11'.repeat(32),policy='22'.repeat(32),anchor='33'.repeat(32);
function setup() {
  const db=new DatabaseSync(':memory:');let now=1000,failSync=false,failCount=0,advanceSync=false;
  const storage={sql:{exec(sql,...args){const s=db.prepare(sql);return /^\s*SELECT|\bRETURNING\b/i.test(sql)?s.all(...args):s.run(...args);}},
    transactionSync(fn){db.exec('BEGIN IMMEDIATE');try{const r=fn();db.exec('COMMIT');return r;}catch(e){db.exec('ROLLBACK');throw e;}},
    async sync(){if(advanceSync)now=1200;if(failSync||failCount-->0)throw new Error('fixture sync failure');}};
  let ledger=new ReleaseReviewLedger(storage,()=>now);
  return {db,get ledger(){return ledger;},restart(){ledger=new ReleaseReviewLedger(storage,()=>now);},
    now(v){now=v;},failNextSync(){failCount=1;},syncFailure(v){failSync=v;},syncExpiry(v){advanceSync=v;},
    enroll(){return ledger.initializeCandidateKey({key_sha256:key,epoch:1,policy_sha256:policy,external_anchor_sha256:anchor,candidate_only:true});}};
}
const request=(i=0)=>({key_sha256:key,epoch:1,policy_sha256:policy,external_anchor_sha256:anchor,
  nonce:i.toString(16).padStart(64,'0'),proposal_sha256:'44'.repeat(32),message_sha256:'55'.repeat(32),
  r13_capture_sha256:'66'.repeat(32),expires_at:1100});

test('unenrolled storage refuses and never auto-bootstraps a key',async()=>{
 const s=setup();const r=await s.ledger.reserve(request());assert.equal(r.leaf_reserved,false);
 assert.equal(s.db.prepare('SELECT count(*) AS n FROM pq_review_keys').get().n,0);
});
test('reservation burns a leaf and creates no signature or production grant',async()=>{
 const s=setup();await s.enroll();const r=await s.ledger.reserve(request());
 assert.equal(r.leaf_reserved,true);assert.equal(r.leaf,0);assert.equal(r.signature_created,false);
 assert.equal(r.production_authorized,false);assert.equal(r.decision,'REFUSE');
 assert.equal(s.db.prepare('SELECT next_leaf FROM pq_review_keys').get().next_leaf,1);
});
test('concurrent different requests receive distinct one-time leaves',async()=>{
 const s=setup();await s.enroll();const rs=await Promise.all(Array.from({length:8},(_,i)=>s.ledger.reserve(request(i))));
 assert(rs.every(r=>r.leaf_reserved));assert.equal(new Set(rs.map(r=>r.leaf)).size,8);
});
test('concurrent identical nonce is consumed once',async()=>{
 const s=setup();await s.enroll();const rs=await Promise.all(Array.from({length:8},()=>s.ledger.reserve(request())));
 assert.equal(rs.filter(r=>r.leaf_reserved).length,1);
});
test('ledger reconstruction retains nonce consumption and next leaf',async()=>{
 const s=setup();await s.enroll();await s.ledger.reserve(request());s.restart();
 assert.equal((await s.ledger.reserve(request())).leaf_reserved,false);
 assert.equal((await s.ledger.reserve(request(1))).leaf,1);
});
test('same key cannot be initialized again to reset leaf state',async()=>{
 const s=setup();await s.enroll();await s.ledger.reserve(request());
 await assert.rejects(s.enroll());assert.equal((await s.ledger.reserve(request(1))).leaf,1);
});
test('epoch, policy, key and external-anchor mismatches refuse',async()=>{
 for(const field of ['epoch','policy_sha256','key_sha256','external_anchor_sha256']){
  const s=setup();await s.enroll();const r={...request(),[field]:field==='epoch'?2:'aa'.repeat(32)};
  assert.equal((await s.ledger.reserve(r)).leaf_reserved,false);
 }
});
test('expired input does not burn a leaf',async()=>{
 const s=setup();await s.enroll();assert.equal((await s.ledger.reserve({...request(),expires_at:1000})).leaf_reserved,false);
 assert.equal((await s.ledger.reserve(request())).leaf,0);
});
test('expiry while synchronizing burns the leaf and returns no reservation',async()=>{
 const s=setup();await s.enroll();s.syncExpiry(true);
 assert.equal((await s.ledger.reserve(request())).leaf_reserved,false);
 assert.equal(s.db.prepare('SELECT next_leaf FROM pq_review_keys').get().next_leaf,1);
 s.syncExpiry(false);assert.equal((await s.ledger.reserve({...request(1),expires_at:1250})).leaf,1);
});
test('uncertain storage synchronization quarantines key across reconstruction',async()=>{
 const s=setup();await s.enroll();s.syncFailure(true);
 assert.equal((await s.ledger.reserve(request())).leaf_reserved,false);
 s.syncFailure(false);s.restart();assert.equal((await s.ledger.reserve(request(1))).leaf_reserved,false);
 assert.equal(s.db.prepare('SELECT state FROM pq_review_keys').get().state,'QUARANTINED');
});
test('transaction failure rolls back the counter and intent together',async()=>{
 const s=setup();await s.enroll();s.db.exec("CREATE TRIGGER abort_intent BEFORE INSERT ON pq_review_intents BEGIN SELECT RAISE(ABORT,'fixture interruption'); END");
 assert.equal((await s.ledger.reserve(request())).leaf_reserved,false);
 assert.equal(s.db.prepare('SELECT next_leaf FROM pq_review_keys').get().next_leaf,0);
 s.db.exec('DROP TRIGGER abort_intent');assert.equal((await s.ledger.reserve(request())).leaf,0);
});
test('last allowed leaf exhausts the key and is never wrapped to zero',async()=>{
 const s=setup();await s.enroll();s.db.exec('UPDATE pq_review_keys SET next_leaf=1023');
 assert.equal((await s.ledger.reserve(request())).leaf,1023);
 assert.equal((await s.ledger.reserve(request(1))).leaf_reserved,false);
});
test('clock rollback after enrollment refuses',async()=>{
 const s=setup();await s.enroll();s.now(999);assert.equal((await s.ledger.reserve(request())).leaf_reserved,false);
});
test('unsupported fields and truthy approval flags refuse',async()=>{
 const s=setup();await s.enroll();assert.equal((await s.ledger.reserve({...request(),r13_verified:true})).leaf_reserved,false);
 assert.equal((await s.ledger.reserve({...request(),epoch:true})).leaf_reserved,false);
});
test('input mutation while awaiting storage cannot change a reserved digest',async()=>{
 const s=setup();await s.enroll();const input=request();const promise=s.ledger.reserve(input);input.message_sha256='ff'.repeat(32);
 const result=await promise;assert.equal(result.message_sha256,'55'.repeat(32));
});

test('one synchronization failure prevents concurrent reservations escaping quarantine',async()=>{
 const s=setup();await s.enroll();s.failNextSync();
 const rs=await Promise.all([s.ledger.reserve(request()),s.ledger.reserve(request(1))]);
 assert.equal(rs.filter(r=>r.leaf_reserved).length,0);
});
