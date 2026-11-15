// Isolated review-leaf reservation component. No network API or signing code.
// The external anchor is a bound identifier, NOT a verified anti-rollback proof.
const HEX=/^[0-9a-f]{64}$/;
const KEY_FIELDS=['key_sha256','epoch','policy_sha256','external_anchor_sha256','candidate_only'];
const REQUEST_FIELDS=['key_sha256','epoch','policy_sha256','external_anchor_sha256','nonce',
  'proposal_sha256','message_sha256','r13_capture_sha256','expires_at'];
class Refusal extends Error {}
const need=(ok,code)=>{if(!ok)throw new Refusal(code);};
function exact(value,fields) {
  need(value!==null && typeof value==='object' && !Array.isArray(value)
    && Object.keys(value).length===fields.length && fields.every(k=>Object.hasOwn(value,k)),'FIELDS');
}
function digest(value){need(typeof value==='string' && value.length===64 && HEX.test(value),'DIGEST');}
function epoch(value){need(Number.isSafeInteger(value) && value>0,'EPOCH');}
const closed=reason=>({decision:'REFUSE',leaf_reserved:false,signature_created:false,
  production_authorized:false,interlock:'KEEP_CLOSED',reason});

export class ReleaseReviewLedger {
  constructor(storage,clock=()=>Math.floor(Date.now()/1000)) {
    this.storage=storage;this.sql=storage.sql;this.clock=clock;this.quarantined=false;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS pq_review_keys(
      key_sha256 TEXT PRIMARY KEY,epoch INTEGER NOT NULL,policy_sha256 TEXT NOT NULL,
      external_anchor_sha256 TEXT NOT NULL,next_leaf INTEGER NOT NULL CHECK(next_leaf>=0 AND next_leaf<=1024),
      clock_watermark INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('ACTIVE','EXHAUSTED','QUARANTINED')))`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS pq_review_intents(
      nonce TEXT PRIMARY KEY,key_sha256 TEXT NOT NULL,epoch INTEGER NOT NULL,leaf INTEGER NOT NULL,
      policy_sha256 TEXT NOT NULL,external_anchor_sha256 TEXT NOT NULL,proposal_sha256 TEXT NOT NULL,
      message_sha256 TEXT NOT NULL,r13_capture_sha256 TEXT NOT NULL,created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,state TEXT NOT NULL CHECK(state='BURNED_REVIEW_ONLY'),UNIQUE(key_sha256,leaf))`);
  }
  now(){const n=this.clock();need(Number.isSafeInteger(n)&&n>0,'CLOCK');return n;}
  async initializeCandidateKey(configuration) {
    // Trusted test/operator interface only. There is intentionally no fetch route
    // exposing enrollment, reset, deletion, counter override or restore.
    exact(configuration,KEY_FIELDS);need(configuration.candidate_only===true,'CANDIDATE_ONLY');
    const c=JSON.parse(JSON.stringify(configuration));epoch(c.epoch);
    for(const k of ['key_sha256','policy_sha256','external_anchor_sha256'])digest(c[k]);
    const now=this.now();
    this.storage.transactionSync(()=>this.sql.exec('INSERT INTO pq_review_keys VALUES(?,?,?,?,0,?,\'ACTIVE\')',
      c.key_sha256,c.epoch,c.policy_sha256,c.external_anchor_sha256,now));
    try{await this.storage.sync();}
    catch(e){this.quarantined=true;this.sql.exec("UPDATE pq_review_keys SET state='QUARANTINED' WHERE key_sha256=?",c.key_sha256);throw e;}
    return {initialized_for_candidate_review_only:true,production_authorized:false,signature_created:false};
  }
  async reserve(request) {
    try {
      need(!this.quarantined,'LEDGER_QUARANTINED');exact(request,REQUEST_FIELDS);
      const r=JSON.parse(JSON.stringify(request));epoch(r.epoch);
      for(const k of REQUEST_FIELDS.filter(k=>k!=='epoch'&&k!=='expires_at'))digest(r[k]);
      const now=this.now();need(Number.isSafeInteger(r.expires_at)&&now<r.expires_at&&r.expires_at-now<=120,'EXPIRY');
      let leaf;
      this.storage.transactionSync(()=>{
        const [key]=Array.from(this.sql.exec('SELECT * FROM pq_review_keys WHERE key_sha256=?',r.key_sha256));
        need(key && key.state==='ACTIVE','KEY_UNAVAILABLE');
        need(key.epoch===r.epoch && key.policy_sha256===r.policy_sha256
          && key.external_anchor_sha256===r.external_anchor_sha256,'KEY_BINDING');
        need(now>=key.clock_watermark,'CLOCK_ROLLBACK');
        need(Number.isSafeInteger(key.next_leaf)&&key.next_leaf>=0&&key.next_leaf<1024,'KEY_EXHAUSTED');
        leaf=key.next_leaf;
        this.sql.exec('UPDATE pq_review_keys SET next_leaf=?,clock_watermark=?,state=? WHERE key_sha256=?',
          leaf+1,now,leaf===1023?'EXHAUSTED':'ACTIVE',r.key_sha256);
        this.sql.exec("INSERT INTO pq_review_intents VALUES(?,?,?,?,?,?,?,?,?,?,?,'BURNED_REVIEW_ONLY')",
          r.nonce,r.key_sha256,r.epoch,leaf,r.policy_sha256,r.external_anchor_sha256,r.proposal_sha256,
          r.message_sha256,r.r13_capture_sha256,now,r.expires_at);
      });
      try{await this.storage.sync();}
      catch {
        this.quarantined=true;
        try {
          this.sql.exec("UPDATE pq_review_keys SET state='QUARANTINED' WHERE key_sha256=?",r.key_sha256);
          await this.storage.sync();
        }catch{}
        return closed('STORAGE_UNCERTAIN_KEY_QUARANTINED');
      }
      // Another in-flight reservation may have quarantined this key while
      // this request awaited durability. Recheck before returning any index.
      const [current]=Array.from(this.sql.exec('SELECT state,next_leaf FROM pq_review_keys WHERE key_sha256=?',r.key_sha256));
      const [intent]=Array.from(this.sql.exec('SELECT leaf,message_sha256 FROM pq_review_intents WHERE nonce=? AND key_sha256=?',r.nonce,r.key_sha256));
      need(!this.quarantined && current && (current.state==='ACTIVE'||current.state==='EXHAUSTED')
        && current.next_leaf>leaf && intent?.leaf===leaf && intent.message_sha256===r.message_sha256,'KEY_QUARANTINED_OR_STATE_CHANGED');
      const final=this.now();
      need(now<=final&&final<r.expires_at,'EXPIRY_OR_CLOCK_CHANGED_AFTER_COMMIT');
      return {...closed('LEAF_BURNED_FOR_CANDIDATE_REVIEW_ONLY'),...r,leaf,leaf_reserved:true,
        state:'BURNED_REVIEW_ONLY'};
    }catch(error){return closed(error instanceof Refusal?error.message:'REVIEW_LEDGER_UNAVAILABLE');}
  }
}
