#!/usr/bin/env python3
"""Prepare public-only CF review bindings from pinned enrollment and staging inputs."""
import argparse
import base64
from datetime import datetime
import math
import re
from pathlib import Path
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from arda_quorum.quorum import canonical,strict_load,sha,need,enrollment,window
from arda_quorum.proposal import validate_request,REVIEWED_REQUEST_SHA256
from arda_quorum.r13_bridge import PinnedR13
ROOT=Path(__file__).resolve().parents[1]
WASM='8e716fc5bf42ff2ce8259a18bb600a374599f7f8b5a85a37460e5d9b155f0b84'

def read(path,pin=None,cap=1048576):
    path=Path(path);need(path.stat().st_size<=cap,'INPUT_SIZE');raw=path.read_bytes()
    if pin is not None:need(sha(raw)==pin,'INPUT_PIN')
    value=strict_load(raw);need(raw==canonical(value),'INPUT_CANONICAL');return raw,value

def prepare(policy_path,policy_pin,cf_path,cf_pin,output_parent,*,root=ROOT,now=None):
    now=int(time.time()) if now is None else now;root=Path(root)
    policy_raw,policy=read(policy_path,policy_pin,5120);enrollment(policy,now)
    identities={'github':'github:Byron2306.arda-pq-witnesses','hf':'hf:Byron230686.arda-pq-policy-witness','cloudflare':'cloudflare:arda-pq-release-witness'}
    need(policy['epoch']<=2**53-1 and all(w['witness_id']==identities[w['provider']] for w in policy['witnesses']),'FIXED_PROVIDER_IDENTITIES')
    _,cf=read(cf_path,cf_pin,16384)
    need(cf.get('schema')=='arda.cf.hss.enrollment_config.v1' and cf.get('worker_identity')=='arda-pq-release-witness' and cf.get('production_authorized') is False and cf.get('wasm_sha256')==WASM,'CF_ENROLLMENT_CONFIG')
    anchor=cf.get('anchor');need(type(anchor) is dict and anchor.keys()=={'schema','repository','genesis_commit','ruleset_id','rules_sha256'} and anchor['schema']=='arda.hss.anchor.v1' and anchor['repository']=='Byron2306/arda-hss-leaf-anchor','ANCHOR_CONFIG')
    need(type(anchor['genesis_commit']) is str and re.fullmatch('[0-9a-f]{40}',anchor['genesis_commit']) and type(anchor['ruleset_id']) is int and 0<anchor['ruleset_id']<2**53 and type(anchor['rules_sha256']) is str and re.fullmatch('[0-9a-f]{64}',anchor['rules_sha256']),'ANCHOR_PINS')
    stage_raw=(root/'inputs/generation14-staging-request.json').read_bytes();expected=validate_request(stage_raw,REVIEWED_REQUEST_SHA256);stage=strict_load(stage_raw);d=stage['deployment']
    start=datetime.fromisoformat(stage['manifest']['issued_at']);end=datetime.fromisoformat(stage['manifest']['expires_at']);need(start.utcoffset() is not None and end.utcoffset() is not None,'MANIFEST_TIMEZONE')
    stage_window={'issued_at':math.ceil(start.timestamp()),'expires_at':math.floor(end.timestamp())};window(stage_window,now,30*86400)
    pins=dict(verifier_spki_sha256=d['r13_verifier_spki_sha256'],ak_spki_sha256=d['r13_ak_spki_sha256'],policy_sha256=d['r13_policy_sha256'],node_id=d['r13_subject_node_id'],verifier_id='cloudflare-r13-v2')
    public=root/'providers/public-r13';verifier=(public/'verifier-public.pem').read_bytes();ak=(public/'ak-public.pem').read_bytes();pcrs=strict_load((public/'approved-pcrs.json').read_bytes())
    PinnedR13(verifier,ak,pcrs,pins)
    encode_pem=lambda raw:base64.b64encode(serialization.load_pem_public_key(raw).public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    r13=dict(verifier_spki_b64=encode_pem(verifier),ak_spki_b64=encode_pem(ak),pcrs=pcrs,pins=pins)
    config=dict(schema='arda.cf.release_config.v1',worker_identity=cf['worker_identity'],wasm_sha256=WASM,policy_file_sha256=sha(policy_raw),stage_window=stage_window,expected=expected,r13=r13,anchor=anchor,production_authorized=False)
    raw=canonical(config)
    variables=dict(ARDA_CF_RELEASE_ENABLED='true',ARDA_CF_RELEASE_CONFIG_JSON=raw.decode(),ARDA_CF_RELEASE_CONFIG_SHA256=sha(raw),ARDA_CF_ENROLLMENT_JSON=policy_raw.decode())
    need(all(len(v.encode())<=5120 for v in variables.values()),'WORKER_BINDING_SIZE')
    # All validation completes before reserving/writing output. Contains no credential.
    out=Path(tempfile.mkdtemp(prefix='cf-review-config.',dir=output_parent))
    for name,data in [('cf-review-config.json',raw),('enrollment.json',policy_raw),('cf-review-variables.json',canonical(variables))]:
        path=out/name;path.write_bytes(data);path.chmod(0o600)
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['policy','policy-sha256','cf-config','cf-config-sha256','output-parent']:p.add_argument('--'+name,required=True)
    args=p.parse_args()
    try:
        out=prepare(args.policy,args.policy_sha256,args.cf_config,args.cf_config_sha256,args.output_parent)
        print('CF_REVIEW_CONFIG_DIR='+str(out));print('CF_REVIEW_CONFIG_SHA256='+sha((out/'cf-review-config.json').read_bytes()));print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
    except Exception:
        print('CF_REVIEW_CONFIGURATION_REFUSED',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
