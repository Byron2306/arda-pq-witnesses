#!/usr/bin/env python3
"""Materialize external, commit-pinned public config; no signer credentials."""
import hashlib
import json
import os
from pathlib import Path
from github_review_inbox import canonical

IMAGE='ghcr.io/byron2306/arda-pq-witness@sha256:02dc4bacda942f58d040cc9093174d2cd6fc84fafc098bf0263a4ff61bda99bd'
POLICY='30f2dd836a36a85e5c16693b71171825b159d6da852ee595542cf03779bbc976'

def validate(env):
    config_raw=env['ARDA_GITHUB_CONFIG_JSON'].encode();policy=env['ARDA_ENROLLMENT_JSON'].encode()
    assert len(config_raw)<=16384 and len(policy)<=65536
    assert hashlib.sha256(config_raw).hexdigest()==env['ARDA_GITHUB_CONFIG_SHA256']
    config=json.loads(config_raw);assert canonical(config)==config_raw
    assert set(config)=={'schema','provider','policy_file_sha256','stage_request_sha256','source_manifest_sha256','image_digest','runtime_identity'}
    assert config['schema']=='arda.pq.provider_config.v1' and config['provider']=='github'
    assert env['ARDA_WITNESS_IMAGE']==IMAGE and config['image_digest']==IMAGE.split('@')[1]
    assert hashlib.sha256(policy).hexdigest()==config['policy_file_sha256']==POLICY
    assert env['GITHUB_SHA']==env['ARDA_APPROVED_COMMIT_SHA']
    assert config['runtime_identity']==dict(repository='Byron2306/arda-pq-witnesses',workflow_ref=env['GITHUB_WORKFLOW_REF'],commit_sha=env['GITHUB_SHA'])
    assert env['GITHUB_WORKFLOW_REF']=='Byron2306/arda-pq-witnesses/.github/workflows/arda-pq-review.yml@refs/heads/candidate/cloudflare-hss-v5-20261115'
    return config_raw,policy

def main():
    config,policy=validate(os.environ)
    out=Path(os.environ['RUNNER_TEMP'])/'arda-pq-config';out.mkdir(mode=0o700)
    for name,data in [('github.json',config),('enrollment.json',policy)]:
        with (out/name).open('xb') as stream:stream.write(data)
    print('GITHUB_PUBLIC_CONFIGURATION=PASS')

if __name__=='__main__':
    try:main()
    except Exception:
        print('GITHUB_PUBLIC_CONFIGURATION_REFUSED');raise SystemExit(1)
