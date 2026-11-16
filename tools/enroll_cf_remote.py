#!/usr/bin/env python3
"""Explicit self-test or enrollment client. Provider private state never leaves CF."""
import argparse
import base64
import os
from pathlib import Path
import re
import sys
import time
import urllib.parse
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.crypto import Backends,HSS,validate_key
from arda_quorum.enrollment import check_ceremony,check_record
from arda_quorum.enrollment_store import NoRedirect
from arda_quorum.quorum import strict_load,canonical,sha,hex64,need,unbase64

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=('self-test','enroll'),default='self-test')
    for name in ('url','config','config-sha256','out'):p.add_argument('--'+name,required=True)
    a=p.parse_args();fd=None
    try:
        u=urllib.parse.urlsplit(a.url)
        need(u.scheme=='https' and re.fullmatch(r'arda-pq-release-witness\.[a-z0-9-]+\.workers\.dev',u.netloc) and u.path in ('','/') and not u.query and not u.fragment,'fixed_worker_https_origin_required')
        path=Path(a.config);need(path.stat().st_size<=16384,'configuration_size');raw=path.read_bytes()
        need(hex64(a.config_sha256) and sha(raw)==a.config_sha256,'operator_cf_configuration_pin')
        c=strict_load(raw);need(raw==canonical(c) and c['worker_identity']=='arda-pq-release-witness' and c['production_authorized'] is False,'cf_configuration')
        check_ceremony(c['ceremony'],int(time.time()));need(sha(canonical(c['ceremony']))==c['ceremony_sha256'],'ceremony_pin')
        token=os.environ.get('ARDA_CF_SETUP_CLIENT_TOKEN');need(hex64(token),'cf_setup_client_token')
        suffix='/v1/self-test' if a.mode=='self-test' else '/v1/enroll-cf'
        action='run_disposable_hss_self_test' if a.mode=='self-test' else 'provision_cloudflare_key'
        fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        request=urllib.request.Request(a.url.rstrip('/')+suffix,method='POST',data=canonical(dict(action=action,ceremony_sha256=c['ceremony_sha256'])),headers={'Content-Type':'application/json','X-ARDA-Setup-Token':token,'User-Agent':'ARDA-CF-HSS-Setup-v5'})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        with opener.open(request,timeout=120) as response:
            need(response.status==200,'cf_setup_status');raw=response.read(65537);need(len(raw)<=65536,'cf_response_size')
        body=strict_load(raw);need(body.get('production_authorized') is False and body.get('interlock')=='KEEP_CLOSED','cf_closed_authority')
        backend=Backends()
        if a.mode=='self-test':
            need(body.keys()=={'disposable','wasm_sha256','public_key_b64','message_b64','signature_b64','production_authorized','interlock'} and body['disposable'] is True and body['wasm_sha256']==c['wasm_sha256'],'disposable_test_response')
            public=unbase64(body['public_key_b64'],4096);validate_key(HSS,public)
            message=b'ARDA/HSS/DISPOSABLE-SELF-TEST/v1\0'+c['wasm_sha256'].encode()
            need(unbase64(body['message_b64'],1024)==message and backend.verify(HSS,public,message,unbase64(body['signature_b64'],65536)),'native_hss_self_test_verification')
            data=canonical(body);print('CF_DISPOSABLE_HSS_SELF_TEST=PASS')
        else:
            need(body.keys()=={'registration','production_authorized','interlock'},'cf_registration_response')
            record=body['registration'];need(record.get('payload',{}).get('provider')=='cloudflare','cf_registration_provider')
            check_record(record,c['ceremony'],now=int(time.time()),backends=backend);data=canonical(record)
            print('PUBLIC_REGISTRATION_SHA256='+sha(data));print('KEY_SHA256='+record['payload']['key_sha256'])
        with os.fdopen(fd,'wb') as stream:fd=None;stream.write(data)
        print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
    except Exception:
        if fd is not None:
            os.close(fd)
            try:Path(a.out).unlink()
            except OSError:pass
        print('CF_REMOTE_SETUP_REFUSED_OPERATOR_REVIEW_REQUIRED',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
