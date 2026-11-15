#!/usr/bin/env python3
"""Read-only compiler/crypto capability report. No keys, installation or network."""
import json
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

def main():
    executable=shutil.which('openssl')
    algorithms='';version='MISSING'
    if executable:
        version=subprocess.check_output([executable,'version'],text=True,timeout=10).strip()
        algorithms=subprocess.check_output([executable,'list','-signature-algorithms'],text=True,timeout=10)
    compiler=shutil.which('cc')
    headers=bool(compiler and subprocess.run([compiler,'-E','-x','c','-'],input='#include <openssl/sha.h>\n',text=True,capture_output=True,timeout=10).returncode==0)
    node=shutil.which('node')
    sqlite=bool(node and subprocess.run([node,'--input-type=module','-e',"import { DatabaseSync } from 'node:sqlite'; const d=new DatabaseSync(':memory:'); d.close();"],capture_output=True,timeout=10).returncode==0)
    crypto=importlib.util.find_spec('cryptography') is not None
    yaml=importlib.util.find_spec('yaml') is not None
    nacl=importlib.util.find_spec('nacl') is not None
    result=dict(node=node,node_sqlite_available=sqlite,cryptography_available=crypto,pyyaml_available=yaml,pynacl_available=nacl,schema='arda.pq.host_preflight.v1',openssl=executable,openssl_version=version,
        ml_dsa_65_available='ML-DSA-65' in algorithms,slh_dsa_sha2_192s_available='SLH-DSA-SHA2-192s' in algorithms,
        compiler=compiler,openssl_development_headers_available=headers,make=shutil.which('make'),production_authorized=False,interlock='KEEP_CLOSED')
    print(json.dumps(result,indent=2))
    return int(not all((result['ml_dsa_65_available'],result['slh_dsa_sha2_192s_available'],result['compiler'],result['make'],headers,sqlite,crypto,yaml,nacl)))

if __name__=='__main__':raise SystemExit(main())
