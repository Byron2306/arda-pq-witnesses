#!/usr/bin/env python3
"""Build verification code and disposable-test utilities; no installation."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def build():
    vendor=ROOT/'vendor/hash-sigs'
    metadata=json.loads((ROOT/'vendor/UPSTREAM.json').read_text())
    for entry in metadata['files']:
        raw=(vendor/entry['path']).read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if actual!=entry['git_blob_sha1'] or len(raw)!=entry['size']:
            raise ValueError('vendor_source_changed:'+entry['path'])
    target=ROOT/'build';target.mkdir(exist_ok=True)
    source=target/'hash-sigs'
    if source.exists():shutil.rmtree(source)
    shutil.copytree(vendor,source)
    subprocess.run(['make','-s','hss_lib.a','hss_verify.a','test_hss'],cwd=source,check=True,timeout=120)
    for src,out,lib in [('native/hss_verify.c','hss-verify','hss_verify.a'),('tests/hss_fixture.c','test-hss-sign','hss_lib.a')]:
        subprocess.run(['cc','-std=c11','-O2','-fstack-protector-strong','-D_FORTIFY_SOURCE=2',
            '-I',str(source),str(ROOT/src),str(source/lib),'-lcrypto','-o',str(target/out)],check=True,timeout=60)
    subprocess.run([str(source/'test_hss'),'testvector'],check=True,timeout=60)
    pins={name:hashlib.sha256((target/name).read_bytes()).hexdigest() for name in ('hss-verify','test-hss-sign')}
    (target/'BUILD.json').write_text(json.dumps(dict(schema='arda.pq.build.v1',binary_sha256=pins,upstream_tree=metadata['tree_sha']),indent=2)+'\n')
    print('NATIVE_BUILD_AND_UPSTREAM_VECTORS=PASS')

if __name__=='__main__':build()
