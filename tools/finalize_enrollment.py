#!/usr/bin/env python3
"""Create closed policy/configuration from exactly three operator-pinned records."""
import argparse
import os
from pathlib import Path
import re
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.enrollment import assemble
from arda_quorum.crypto import Backends
from arda_quorum.quorum import canonical,strict_load,sha,hex64,need
from arda_quorum.proposal import validate_request
ROOT=Path(__file__).resolve().parents[1]

def read(path,cap=65536):
    path=Path(path);need(path.stat().st_size<=cap,'input_size');return path.read_bytes()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ceremony',required=True);p.add_argument('--ceremony-sha256',required=True)
    for provider in ('github','hf','cloudflare'):
        p.add_argument('--'+provider+'-record',required=True);p.add_argument('--'+provider+'-pin',required=True)
    p.add_argument('--github-commit',required=True);p.add_argument('--epoch',type=int,required=True);p.add_argument('--out-dir',required=True);a=p.parse_args()
    try:
        raw=read(a.ceremony,16384);need(hex64(a.ceremony_sha256) and sha(raw)==a.ceremony_sha256,'operator_ceremony_pin')
        c=strict_load(raw);need(canonical(c)==raw,'canonical_ceremony_required')
        records=[];pins={}
        for provider in ('github','hf','cloudflare'):
            raw=read(getattr(a,provider+'_record'));record=strict_load(raw)
            need(raw==canonical(record),'canonical_registration_required');records.append(record);pins[provider]=getattr(a,provider+'_pin')
        result=assemble(c,records,pins,epoch=a.epoch,now=int(time.time()),backends=Backends())
        need(re.fullmatch('[0-9a-f]{40}',a.github_commit),'approved_github_commit_required')
        stage=(ROOT/'inputs/generation14-staging-request.json').read_bytes();stage_pin=sha(stage);validate_request(stage,stage_pin)
        source=(ROOT/'REVIEWED_SOURCE_FILES.json').read_bytes()
        need(strict_load(source)['request_sha256']==stage_pin,'source_manifest_stage_binding')
        policy=canonical(result['policy']);files={'enrollment.json':policy,'enrollment-result.json':canonical(result)}
        configs={}
        for provider in ('github','hf'):
            identity={'space_id':c['identities']['hf']} if provider=='hf' else dict(repository=c['identities']['github'],
                workflow_ref=c['identities']['github']+'/.github/workflows/arda-pq-review.yml@refs/heads/main',commit_sha=a.github_commit)
            config=dict(schema='arda.pq.provider_config.v1',provider=provider,policy_file_sha256=sha(policy),stage_request_sha256=stage_pin,
                source_manifest_sha256=sha(source),image_digest=c['image_digest'],runtime_identity=identity)
            files[provider+'.json']=canonical(config);configs[provider]=config
        hf=files['hf.json']
        files['hf-variables.json']=canonical(dict(ARDA_PROVIDER_CONFIG_JSON=hf.decode(),ARDA_PROVIDER_CONFIG_SHA256=sha(hf),
            ARDA_ENROLLMENT_JSON=policy.decode(),ARDA_IMAGE_DIGEST=c['image_digest']))
        files['github-variables.json']=canonical(dict(ARDA_GITHUB_CONFIG_SHA256=sha(files['github.json']),ARDA_APPROVED_COMMIT_SHA=a.github_commit,
            ARDA_GITHUB_SIGNER_SECRET_NAME=next(r['payload']['secret_name'] for r in records if r['payload']['provider']=='github'),
            ARDA_PROVIDER_DEPLOYMENT_ENABLED='false'))
        out=Path(a.out_dir);out.mkdir(mode=0o700)
        for name,data in files.items():
            fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(data)
        print('POLICY_SHA256='+sha(policy));print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
    except Exception:
        print('ENROLLMENT_FINALIZATION_REFUSED',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
