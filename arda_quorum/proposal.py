"""Bind unsigned review proposals to the reviewed generation-14 checkpoint."""
import secrets
from .quorum import canonical,strict_load,sha,need,hex64,enrollment

REVIEWED_REQUEST_SHA256='2965b8eae264b3026d8c35c0af980187b3dbb98e1a39835aaf4b166ba3360c3f'
MANIFEST_FIELDS=('schema_version','manifest_id','generation','node_id','policy_generation','audience',
    'attestation_result_id','attestation_evidence_digest','issued_at','expires_at','entries')


def validate_request(raw,expected_sha256):
    need(hex64(expected_sha256) and sha(raw)==expected_sha256,'staging_request_pin')
    request=strict_load(raw)
    need(request['status']=='SEALED_UNSIGNED' and request['production_authorized'] is False
         and request['interlock']=='KEEP_CLOSED' and request['generation']==14,'staging_state')
    m=request['manifest'];d=request['deployment'];artifacts=d['artifacts']
    need(all(request[k]==m[k]==d[k] for k in ('generation','manifest_id','node_id')),'staging_identity')
    md='sha256:'+sha(canonical({k:m[k] for k in MANIFEST_FIELDS}))
    need(md==request['manifest_digest']==d['manifest_digest'],'staging_manifest_digest')
    need(type(artifacts) is dict and len(artifacts)==request['staged_artifact_count']==569,'staging_artifact_count')
    need(all(type(path) is str and path.startswith('/') and '..' not in path.split('/') and hex64(digest) for path,digest in artifacts.items()),'staging_artifact_shape')
    need(artifacts[d['bpf_object_path']]==request['candidate_object_sha256'],'staging_object_binding')
    entries=m['entries'];need(len(entries)==request['measured_entry_count']==137,'staging_measurement_count')
    need(len({e['path'] for e in entries})==len(entries),'staging_duplicate_measurement')
    for entry in entries:
        if entry['path'] in artifacts:
            need(entry['workload_digest']=='sha256:'+artifacts[entry['path']],'staging_measured_artifact_binding')
    need(d['production_admission_authorized'] is False,'staging_admission_closed')
    return dict(generation=14,manifest_id=m['manifest_id'],manifest_digest=md,
        deployment_sha256=sha(canonical(d)),artifact_root_sha256=sha(canonical(artifacts)),
        staging_request_sha256=sha(raw),machine_id_sha256=d['subject_machine_id_sha256'],boot_id=request['boot_id'])


def prepare_draft(raw,*,now,policy=None):
    need(type(now) is int and now>0,'draft_clock')
    bindings=validate_request(raw,REVIEWED_REQUEST_SHA256)
    if policy is not None:enrollment(policy,now)
    proposal=dict(bindings,schema='arda.pq.proposal.v1',action='review_staged_release',
        proposal_id=secrets.token_hex(16),nonce=secrets.token_hex(32),epoch=policy['epoch'] if policy else None,
        policy_sha256=sha(canonical(policy)) if policy else None,r13_evidence_sha256=None,
        issued_at=now,expires_at=now+300)
    return dict(schema='arda.pq.review_draft.v1',state='UNREADY_DRAFT',proposal=proposal,
        production_authorized=False,interlock='KEEP_CLOSED',
        blockers=(['WITNESS_ENROLLMENT_REQUIRED'] if policy is None else [])+
            ['FRESH_R13_EVIDENCE_REQUIRED','LIVE_PROVIDER_VOTES_REQUIRED','REKOR_PROOF_REQUIRED','STATEFUL_SIGNER_REVIEW_REQUIRED'])


def public_commitment(certificate):
    # Log this small object through an independently verified supported outer
    # Sigstore envelope. It is not a Rekor proof and is never counted as a vote.
    return dict(schema='arda.pq.public_commitment.v1',certificate_sha256=sha(canonical(certificate)))
