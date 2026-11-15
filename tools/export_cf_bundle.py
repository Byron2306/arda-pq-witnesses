#!/usr/bin/env python3
"""Export only fixed public Worker files and built Wasm. Never exports DO state/secrets."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
ROOT=Path(__file__).resolve().parents[1]
FILES=['providers/cloudflare/'+x for x in ('worker.mjs','wrangler.toml','package.json','package-lock.json')]+['cloudflare/hss-'+x+'.mjs' for x in ('engine','anchor','guard','enrollment')]+['build/'+x for x in ('hss-state.wasm','hss-state-meta.mjs','WASM_BUILD.json')]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True);a=p.parse_args()
    data={name:(ROOT/name).read_bytes() for name in FILES}
    report=json.loads(data['build/WASM_BUILD.json']);assert hashlib.sha256(data['build/hss-state.wasm']).hexdigest()==report['wasm_sha256']
    assert data['build/hss-state-meta.mjs']==('export const WASM_SHA256='+json.dumps(report['wasm_sha256'])+';\n').encode()
    manifest=dict(schema='arda.cf.hss.public_bundle.v1',files_sha256={k:hashlib.sha256(v).hexdigest() for k,v in data.items()},production_authorized=False,interlock='KEEP_CLOSED')
    data['BUNDLE_MANIFEST.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    with Path(a.out).open('xb') as stream:
        with tarfile.open(fileobj=stream,mode='w:gz') as archive:
            for name,raw in sorted(data.items()):
                info=tarfile.TarInfo('arda-cf-hss-v5/'+name);info.size=len(raw);info.mode=0o644
                archive.addfile(info,io.BytesIO(raw))
    print('BUNDLE_SHA256='+hashlib.sha256(Path(a.out).read_bytes()).hexdigest());print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED')
if __name__=='__main__':main()
