#!/usr/bin/env python3
"""Build locally and verify disposable fixtures. No ARDA or cloud changes."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
ROOT=Path(__file__).resolve().parent

def main():
    results=[]
    for label,command,timeout in [('preflight',[sys.executable,'tools/host_preflight.py'],30),
        ('native_and_upstream_vectors',[sys.executable,'tools/build_native.py'],180),
        ('pq_quorum_tests',[sys.executable,'-m','unittest','discover','-s','tests','-v'],120),
        ('r13_source_python',['python3','-m','unittest','discover','-s','r13-source','-v'],60),
        ('r13_worker_node',['node','--test','r13-source/worker.test.mjs'],60),
        ('release_review_ledger_node',['node','--test','cloudflare/release-ledger.test.mjs'],60)]:
        try:
            env=dict(os.environ);env.pop('R13_WRANGLER',None)  # Node/SQLite tests only; actual Workers acceptance is separate.
            run=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=timeout,env=env)
            output=run.stdout+run.stderr;code=run.returncode
        except subprocess.TimeoutExpired:output='TIMEOUT';code=124
        results.append(dict(suite=label,exit_code=code,output=output))
        print(label+': '+('PASS' if code==0 else 'FAIL'),flush=True)
        if label=='native_and_upstream_vectors' and 'warning:' in output:
            print('UPSTREAM_OPENSSL_DEPRECATION_WARNINGS=RECORDED_IN_REPORT',flush=True)
        if code:print(output,flush=True);break
    counts={}
    for r in results:
        match=re.search(r'Ran (\d+) tests?',r['output']) or re.search(r'(?:#|ℹ) tests (\d+)',r['output'])
        if match:counts[r['suite']]=int(match[1])
    match=None
    report=dict(schema='arda.pq.verification.v4',passed=len(results)==6 and all(r['exit_code']==0 for r in results),
        tests=sum(counts.values()),test_counts=counts,results=results,production_authorized=False,interlock='KEEP_CLOSED',
        live_provider_calls=0,rekor_publication_performed=False,cloudflare_runtime_acceptance_executed=False,production_signing_keys_created=False,
        stateful_cloudflare_signer_implemented=False,stateless_provider_signing_implemented=True,provider_deployment_performed=False,container_build_executed=False,provider_enrollment_implemented=True,live_enrollment_executed=False)
    (ROOT/'VERIFICATION_RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    print('TESTS='+str(report['tests']));print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED')
    return int(not report['passed'])

if __name__=='__main__':raise SystemExit(main())
