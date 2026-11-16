// Disposable cryptographic test inputs only. No provider calls or production keys.
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
const json=x=>x!==null&&typeof x==='object'?(Array.isArray(x)?'['+x.map(json).join(',')+']':'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+json(x[k])).join(',')+'}'):JSON.stringify(x);
export const encode=x=>Buffer.from(json(x));
export const digest=x=>createHash('sha256').update(x).digest('hex');
const b64=x=>Buffer.from(x).toString('base64');
export function fixture(now=1000){
 const ak=generateKeyPairSync('rsa',{modulusLength:2048}),ed=generateKeyPairSync('ed25519'),der=k=>k.export({type:'spki',format:'der'});
 const pcrs=Object.fromEntries([0,1,4,7,8,9,11].map(n=>[n,(n+1).toString(16).padStart(2,'0').repeat(32)]));
 const pcr_selection='sha256:0,1,4,7,8,9,11',akPin=digest(der(ak.publicKey)),policyPin=digest(encode({schema:'arda.r13.pcr_policy.v2',ak_spki_sha256:akPin,pcr_selection,pcrs}));
 const boot='b08f1e0e-6397-440f-a0ad-73313b7bf87c';
 const challenge={schema:'arda.r13.challenge.v2',verifier_id:'cloudflare-r13-v2',node_id:'lenovo-valinor',boot_id:boot,challenge_id:'12'.repeat(16),nonce:'34'.repeat(32),issued_at:now,expires_at:now+120,policy_sha256:policyPin};
 const qualification=Buffer.from(digest(Buffer.concat([Buffer.from('ARDA/R13/TPM-QUOTE/v2\0'),encode(challenge)])),'hex');
 const quote=Buffer.concat([Buffer.from('ff544347801800000020','hex'),qualification,Buffer.alloc(25),Buffer.from('00000001000b03930b000020','hex'),Buffer.from(digest(Buffer.concat([0,1,4,7,8,9,11].map(n=>Buffer.from(pcrs[n],'hex')))),'hex')]);
 const signature=sign('sha256',quote,ak.privateKey),len=Buffer.alloc(2);len.writeUInt16BE(signature.length);
 const evidence={challenge_id:challenge.challenge_id,boot_id:boot,pcrs,quote_b64:b64(quote),signature_b64:b64(Buffer.concat([Buffer.from('0014000b','hex'),len,signature]))};
 const signObject=(domain,x)=>b64(sign(null,Buffer.concat([Buffer.from(domain+'\0'),encode(x)]),ed.privateKey));
 const receipt={payload:{schema:'arda.r13.evidence_receipt.v2',status:'PASS',verifier_id:challenge.verifier_id,node_id:challenge.node_id,boot_id:boot,challenge_id:challenge.challenge_id,challenge_sha256:digest(encode(challenge)),qualification_sha256:qualification.toString('hex'),evidence_sha256:digest(encode(evidence)),quote_sha256:digest(quote),quote_signature_sha256:digest(Buffer.from(evidence.signature_b64,'base64')),ak_spki_sha256:akPin,policy_sha256:policyPin,pcr_selection,issued_at:now,expires_at:now+120,production_cutover_authorized:false}};
 receipt.ed25519_signature_b64=signObject('ARDA/R13/EVIDENCE-RECEIPT/v2',receipt.payload);
 const capture={schema:'arda.r13.capture.v2',issued_challenge:{challenge,ed25519_signature_b64:signObject('ARDA/R13/ISSUED-CHALLENGE/v2',challenge)},evidence,receipt};
 const r13={verifier_spki_b64:b64(der(ed.publicKey)),ak_spki_b64:b64(der(ak.publicKey)),pcrs,pins:{verifier_spki_sha256:digest(der(ed.publicKey)),ak_spki_sha256:akPin,policy_sha256:policyPin,node_id:challenge.node_id,verifier_id:challenge.verifier_id}};
 return {capture,r13,boot,signObject};
}
export function releaseFixture(now=1000){
 const f=fixture(now),hss=new Uint8Array(60);hss.set([0,0,0,1,0,0,0,6,0,0,0,4]);hss[59]=42;
 const ml=Buffer.alloc(1974);Buffer.from('308207b2300b0609608648016503040312038207a100','hex').copy(ml);
 const slh=Buffer.alloc(66);Buffer.from('3040300b0609608648016503040316033100','hex').copy(slh);
 const policy={schema:'arda.pq.enrollment.v1',epoch:1,issued_at:now-100,expires_at:now+1000,production_authorized:false,witnesses:[
  ['cloudflare','release_witness','HSS-LMS-SHA256-N32-H10-W8',hss,'cloudflare:arda-pq-release-witness'],
  ['github','build_witness','ML-DSA-65',ml,'github:Byron2306.arda-pq-witnesses'],
  ['hf','policy_witness','SLH-DSA-SHA2-192s',slh,'hf:Byron230686.arda-pq-policy-witness']
 ].map(([provider,role,algorithm,publicKey,witness_id])=>({provider,role,algorithm,public_key_b64:Buffer.from(publicKey).toString('base64'),key_sha256:digest(publicKey),witness_id}))};
 const expected={generation:14,manifest_id:'measured-fixture',manifest_digest:'sha256:'+'11'.repeat(32),deployment_sha256:'22'.repeat(32),artifact_root_sha256:'33'.repeat(32),staging_request_sha256:'44'.repeat(32),machine_id_sha256:'55'.repeat(32),boot_id:f.boot};
 const anchor={schema:'arda.hss.anchor.v1',repository:'Byron2306/arda-hss-leaf-anchor',genesis_commit:'12'.repeat(20),ruleset_id:7,rules_sha256:'66'.repeat(32)};
 const config={schema:'arda.cf.release_config.v1',worker_identity:'arda-pq-release-witness',wasm_sha256:'77'.repeat(32),policy,policy_file_sha256:digest(encode(policy)),stage_window:{issued_at:now-100,expires_at:now+1000},expected,r13:f.r13,anchor,production_authorized:false};
 const proposal={...expected,schema:'arda.pq.proposal.v1',action:'review_staged_release',epoch:1,policy_sha256:config.policy_file_sha256,r13_evidence_sha256:digest(encode(f.capture)),proposal_id:'78'.repeat(16),nonce:'9a'.repeat(32),issued_at:now,expires_at:now+100};
 const request={schema:'arda.pq.witness_request.v1',proposal,capture:f.capture};
 const env={ARDA_CF_RELEASE_ENABLED:'true',ARDA_CF_RELEASE_CONFIG_JSON:encode(wireConfig(config)).toString(),ARDA_CF_RELEASE_CONFIG_SHA256:digest(encode(wireConfig(config))),ARDA_CF_ENROLLMENT_JSON:encode(policy).toString(),ARDA_CF_REVIEW_CLIENT_TOKEN:'aa'.repeat(32)};
 return {...f,config,request,env,hss};
}

export function wireConfig(config){const {policy,...wire}=config;return wire;}
