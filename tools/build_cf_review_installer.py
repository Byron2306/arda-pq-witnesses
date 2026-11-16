#!/usr/bin/env python3
"""Package the reviewed public patch; never run as part of provider signing."""
import base64,hashlib,json,runpy,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
old=runpy.run_path(str(ROOT/'tools/install_cf_rotation.py'))['DATA']
manifest=json.loads(old['manifest']);base_pins=dict(manifest['files_sha256'])
files=['cloudflare/hss-guard.mjs','providers/cloudflare/worker.mjs','cloudflare/review-protocol.mjs','cloudflare/r13-capture.mjs','cloudflare/release-config.mjs','cloudflare/release-service.mjs','tools/prepare_cf_review.py','docs/CLOUDFLARE_RELEASE_REVIEW.md']
payload={name:(ROOT/name).read_text() for name in files}
manifest['files_sha256'].update({name:sha(text.encode()) for name,text in payload.items()})
new_manifest=json.dumps(manifest,sort_keys=True,indent=2)+'\n'
data=dict(files=payload,baseline={name:base_pins.get(name) for name in files},immutable={name:pin for name,pin in base_pins.items() if name not in files},manifest=new_manifest,allowed_manifests=[sha(old['manifest'].encode()),sha(new_manifest.encode())])
packed=base64.b64encode(zlib.compress(json.dumps(data,sort_keys=True).encode(),9)).decode()
body='''#!/usr/bin/env python3
"""Install reviewed CF public review source; preserve all signing state and Wasm."""
import argparse,base64,hashlib,json,os,tempfile,zlib
from pathlib import Path
DATA=json.loads(zlib.decompress(base64.b64decode(@PAYLOAD@)))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,code):
    if not ok:raise SystemExit(code)
def safe(base,name):
    parts=Path(name).parts
    need(parts and not Path(name).is_absolute() and '..' not in parts,'PATCH_PATH')
    need(not any(base.joinpath(*parts[:i]).is_symlink() for i in range(1,len(parts)+1)),'PATCH_SYMLINK')
    target=base/name;need(target.resolve().is_relative_to(base),'PATCH_ESCAPE');return target
def install(root):
    root=Path(root);need(not root.is_symlink(),'BUNDLE_SYMLINK');base=root.resolve();need(base.is_dir(),'BUNDLE_ROOT')
    manifest=safe(base,'BUNDLE_MANIFEST.json');need(manifest.is_file() and sha(manifest.read_bytes()) in DATA['allowed_manifests'],'BUNDLE_MANIFEST_PIN')
    for name,pin in DATA['immutable'].items():
        path=safe(base,name);need(path.is_file() and sha(path.read_bytes())==pin,'IMMUTABLE_PIN:'+name)
    pending={}
    for name,text in DATA['files'].items():
        path=safe(base,name);raw=text.encode();old=DATA['baseline'][name]
        if path.exists():need(path.is_file() and sha(path.read_bytes()) in [old,sha(raw)],'SOURCE_PIN:'+name)
        else:need(old is None,'SOURCE_MISSING:'+name)
        pending[name]=raw
    pending['BUNDLE_MANIFEST.json']=DATA['manifest'].encode()
    backup=Path(tempfile.mkdtemp(prefix='arda-cf-review-backup.',dir=base.parent))
    for name in pending:
        path=base/name
        if path.exists():
            saved=backup/name;saved.parent.mkdir(parents=True,exist_ok=True);saved.write_bytes(path.read_bytes())
    for name,raw in pending.items():
        path=base/name;path.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as stream:
            temporary=Path(stream.name);stream.write(raw);stream.flush();os.fsync(stream.fileno())
        temporary.chmod(0o644);os.replace(temporary,path)
    print('PUBLIC_SOURCE_BACKUP='+str(backup));print('CF_RELEASE_REVIEW_PATCH=PASS');print('WASM_UNCHANGED=PASS');print('PRODUCTION_AUTHORIZED=FALSE\\nINTERLOCK=KEEP_CLOSED')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bundle-root',required=True);install(p.parse_args().bundle_root)
'''.replace('@PAYLOAD@',repr(packed))
(ROOT/'tools/install_cf_review.py').write_text(body)
review={k:v for k,v in data.items() if k not in ('files','manifest')};review['files_sha256']={name:sha(text.encode()) for name,text in payload.items()};review['installer_sha256']=sha(body.encode())
(ROOT/'tools/cf_review_patch_manifest.json').write_text(json.dumps(review,sort_keys=True,indent=2)+'\n')
print('INSTALLER_SHA256='+sha(body.encode()))
