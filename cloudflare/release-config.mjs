import {need,sha,hex64,exact,window,unbase64,canonicalProtocol,parseCanonical,snapshot} from './review-protocol.mjs';
import {loadR13,verifyCapture} from './r13-capture.mjs';
import {ProtectedGitHubAnchor} from './hss-anchor.mjs';
const bindings=['generation','manifest_id','manifest_digest','deployment_sha256','artifact_root_sha256','staging_request_sha256','machine_id_sha256','boot_id'];
const proposalFields=[...bindings,'schema','action','proposal_id','nonce','epoch','policy_sha256','r13_evidence_sha256','issued_at','expires_at'];
const profiles={github:['build_witness','ML-DSA-65','github:Byron2306.arda-pq-witnesses'],hf:['policy_witness','SLH-DSA-SHA2-192s','hf:Byron230686.arda-pq-policy-witness'],cloudflare:['release_witness','HSS-LMS-SHA256-N32-H10-W8','cloudflare:arda-pq-release-witness']};
const prefixes={github:[1974,'308207b2300b0609608648016503040312038207a100'],hf:[66,'3040300b0609608648016503040316033100'],cloudflare:[60,'000000010000000600000004']};
const digest=x=>sha(canonicalProtocol(x));
export async function validateReleaseConfig(env,wasmSha,now){
 need(env.ARDA_CF_RELEASE_ENABLED==='true','RELEASE_DISABLED');
 need(hex64(env.ARDA_CF_REVIEW_CLIENT_TOKEN)&&env.ARDA_CF_REVIEW_CLIENT_TOKEN!==env.ARDA_CF_SETUP_CLIENT_TOKEN,'REVIEW_CLIENT_CREDENTIAL');
 const raw=new TextEncoder().encode(env.ARDA_CF_RELEASE_CONFIG_JSON??'');need(hex64(env.ARDA_CF_RELEASE_CONFIG_SHA256)&&await sha(raw)===env.ARDA_CF_RELEASE_CONFIG_SHA256,'RELEASE_CONFIG_PIN');
 const c=parseCanonical(raw,5120);exact(c,['schema','worker_identity','wasm_sha256','policy_file_sha256','stage_window','expected','r13','anchor','production_authorized'],'RELEASE_CONFIG_FIELDS');
 need(c.schema==='arda.cf.release_config.v1'&&c.worker_identity==='arda-pq-release-witness'&&c.production_authorized===false&&hex64(wasmSha)&&c.wasm_sha256===wasmSha,'RELEASE_CONFIG_IDENTITY');
 const policyRaw=new TextEncoder().encode(env.ARDA_CF_ENROLLMENT_JSON??'');need(await sha(policyRaw)===c.policy_file_sha256,'ENROLLMENT_BINDING');
 const p=parseCanonical(policyRaw,5120);c.policy=p;window(c.stage_window,now,30*86400);exact(c.stage_window,['issued_at','expires_at'],'STAGE_WINDOW_FIELDS');exact(p,['schema','epoch','issued_at','expires_at','production_authorized','witnesses'],'POLICY_FIELDS');
 need(p.schema==='arda.pq.enrollment.v1'&&p.production_authorized===false&&Number.isSafeInteger(p.epoch)&&p.epoch>0,'POLICY_AUTHORITY');window(p,now,366*86400);
 need(hex64(c.policy_file_sha256)&&await digest(p)===c.policy_file_sha256,'POLICY_PIN');
 need(Array.isArray(p.witnesses)&&p.witnesses.length===3,'POLICY_COVERAGE');const seen=new Set(),keys=new Set();
 for(const w of p.witnesses){
  exact(w,['witness_id','provider','role','algorithm','key_sha256','public_key_b64'],'WITNESS_FIELDS');
  need(typeof w.provider==='string'&&Object.hasOwn(profiles,w.provider)&&!seen.has(w.provider),'WITNESS_PROVIDER');
  const [role,algorithm,identity]=profiles[w.provider];need(w.role===role&&w.algorithm===algorithm&&w.witness_id===identity,'WITNESS_PROFILE');
  const pub=unbase64(w.public_key_b64,4096),[length,prefix]=prefixes[w.provider],prefixBytes=Uint8Array.from(prefix.match(/../g),v=>parseInt(v,16));
  need(pub.length===length&&prefixBytes.every((v,i)=>pub[i]===v)&&hex64(w.key_sha256)&&await sha(pub)===w.key_sha256&&!keys.has(w.key_sha256),'WITNESS_PUBLIC_KEY');seen.add(w.provider);keys.add(w.key_sha256);
 }
 exact(c.expected,bindings,'STAGE_BINDINGS');need(c.expected.generation===14&&typeof c.expected.manifest_id==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(c.expected.manifest_id)&&typeof c.expected.manifest_digest==='string'&&/^sha256:[0-9a-f]{64}$/.test(c.expected.manifest_digest),'STAGE_IDENTITY');
 need(['deployment_sha256','artifact_root_sha256','staging_request_sha256','machine_id_sha256'].every(k=>hex64(c.expected[k])),'STAGE_DIGESTS');
 await loadR13(c.r13,c.expected.boot_id);
 new ProtectedGitHubAnchor(c.anchor,'configuration-validation-only');
 return snapshot(c);
}
export async function validateReview(configuration,request,now){
 const c=snapshot(configuration),r=snapshot(request);exact(r,['schema','proposal','capture'],'REVIEW_REQUEST_FIELDS');need(r.schema==='arda.pq.witness_request.v1','REVIEW_REQUEST_SCHEMA');
 window(c.policy,now,366*86400);window(c.stage_window,now,30*86400);const p=r.proposal;exact(p,proposalFields,'PROPOSAL_FIELDS');
 need(p.schema==='arda.pq.proposal.v1'&&p.action==='review_staged_release'&&p.epoch===c.policy.epoch&&p.policy_sha256===c.policy_file_sha256,'PROPOSAL_POLICY');
 need(bindings.every(k=>p[k]===c.expected[k]&&typeof p[k]===typeof c.expected[k]),'PROPOSAL_STAGE_BINDING');
 need(typeof p.proposal_id==='string'&&/^[0-9a-f]{32}$/.test(p.proposal_id)&&hex64(p.nonce)&&hex64(p.r13_evidence_sha256),'PROPOSAL_NONCE');window(p,now,300);
 const evidence=await verifyCapture(c.r13,r.capture,p.boot_id,now);
 need(p.r13_evidence_sha256===evidence.capture_sha256&&evidence.issued_at<=p.issued_at&&p.expires_at<=evidence.expires_at&&p.expires_at<=c.stage_window.expires_at,'PROPOSAL_R13_BINDING');
 const witness=c.policy.witnesses.find(w=>w.provider==='cloudflare'),proposal_sha256=await digest(p);
 const payload={schema:'arda.pq.vote.v1',witness_id:witness.witness_id,provider:witness.provider,role:witness.role,algorithm:witness.algorithm,key_sha256:witness.key_sha256,policy_sha256:c.policy_file_sha256,proposal_sha256,decision:'APPROVE',issued_at:now,expires_at:Math.min(p.expires_at,c.policy.expires_at,evidence.expires_at)};
 need(payload.issued_at<payload.expires_at,'VOTE_WINDOW');return {payload,proposal_sha256,capture_sha256:evidence.capture_sha256};
}
