#!/usr/bin/env python3
"""Build public CF setup configuration from a reviewed ceremony and actual tag rules."""
import argparse
import json
from pathlib import Path
import re
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.enrollment import check_ceremony
from arda_quorum.quorum import strict_load,canonical,sha,hex64,need
ROOT=Path(__file__).resolve().parents[1]

def read(path):
    path=Path(path);need(path.stat().st_size<=131072,'public_input_size');return path.read_bytes()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ceremony','ceremony-sha256','ruleset-json','genesis-commit','out-dir'):p.add_argument('--'+name,required=True)
    a=p.parse_args()
    try:
        raw=read(a.ceremony);need(hex64(a.ceremony_sha256) and sha(raw)==a.ceremony_sha256,'operator_ceremony_pin')
        c=strict_load(raw);need(raw==canonical(c),'canonical_ceremony');check_ceremony(c,int(time.time()))
        need(c['identities']=={'github':'Byron2306/arda-pq-witnesses','hf':'Byron230686/arda-pq-policy-witness','cloudflare':'arda-pq-release-witness'},'provider_identities')
        r=strict_load(read(a.ruleset_json));need(type(r) is dict and type(r.get('id')) is int and r['id']>0,'actual_ruleset_id_required')
        need(r.get('target')=='tag' and r.get('enforcement')=='active' and r.get('bypass_actors')==[],'active_no_bypass_tag_rules_required')
        scope={'ref_name':{'include':['refs/tags/arda-hss-leaf-*'],'exclude':[]}}
        need(r.get('conditions')==scope,'exact_anchor_tag_scope_required')
        need(type(r.get('rules')) is list and not any(v.get('type')=='creation' for v in r['rules']),'tag_creation_must_be_allowed')
        for kind in ('update','deletion'):
            matches=[v for v in r.get('rules',[]) if type(v) is dict and v.get('type')==kind]
            need(len(matches)==1 and not matches[0].get('parameters'),'tag_update_deletion_protection_required')
        projected=dict(target='tag',enforcement='active',bypass_actors=[],conditions=scope,rules=[{'type':'deletion'},{'type':'update'}])
        need(re.fullmatch('[0-9a-f]{40}',a.genesis_commit),'anchor_genesis_commit')
        build=strict_load(read(ROOT/'build/WASM_BUILD.json'));wasm=(ROOT/'build/hss-state.wasm').read_bytes()
        need(hex64(build['wasm_sha256']) and sha(wasm)==build['wasm_sha256'],'reviewed_wasm_build')
        anchor=dict(schema='arda.hss.anchor.v1',repository='Byron2306/arda-hss-leaf-anchor',genesis_commit=a.genesis_commit,ruleset_id=r['id'],rules_sha256=sha(canonical(projected)))
        config=dict(schema='arda.cf.hss.enrollment_config.v1',worker_identity='arda-pq-release-witness',ceremony=c,ceremony_sha256=a.ceremony_sha256,anchor=anchor,wasm_sha256=build['wasm_sha256'],production_authorized=False)
        raw=canonical(config);out=Path(a.out_dir);out.mkdir(mode=0o700)
        (out/'cf-config.json').write_bytes(raw)
        (out/'cf-public-vars.json').write_bytes(canonical(dict(ARDA_CF_CONFIG_JSON=raw.decode(),ARDA_CF_CONFIG_SHA256=sha(raw))))
        print('CF_CONFIG_SHA256='+sha(raw));print('WASM_SHA256='+build['wasm_sha256']);print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
    except Exception:print('CF_CONFIGURATION_PREPARATION_REFUSED',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
