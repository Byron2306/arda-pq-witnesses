#!/usr/bin/env python3
"""Operator client: trigger provider-local setup; save only its verified public record."""
import argparse
import os
from pathlib import Path
import sys
import time
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.enrollment import check_ceremony,check_record
from arda_quorum.enrollment_store import NoRedirect
from arda_quorum.crypto import Backends
from arda_quorum.quorum import canonical,strict_load,sha,hex64,need
URL='https://byron230686-arda-pq-policy-witness.hf.space/v1/enroll-hf'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ceremony',required=True)
    p.add_argument('--ceremony-sha256',required=True);p.add_argument('--out',required=True);a=p.parse_args();fd=None
    try:
        path=Path(a.ceremony);need(path.stat().st_size<=16384,'ceremony_size');raw=path.read_bytes()
        need(hex64(a.ceremony_sha256) and sha(raw)==a.ceremony_sha256,'operator_ceremony_pin')
        c=strict_load(raw);need(raw==canonical(c),'canonical_ceremony');check_ceremony(c,int(time.time()))
        need(c['identities']['hf']=='Byron230686/arda-pq-policy-witness','fixed_space_identity')
        token=os.environ.get('ARDA_HF_SETUP_CLIENT_TOKEN');need(hex64(token),'setup_client_token')
        headers={'Content-Type':'application/json','X-ARDA-Setup-Token':token,'User-Agent':'ARDA-PQ-enrollment-client-v4'}
        hf=os.environ.get('HF_TOKEN')
        if hf:
            need(len(hf)<=4096 and all(33<=ord(ch)<=126 for ch in hf),'hf_gateway_token')
            headers['Authorization']='Bearer '+hf
        # Refuse an existing output before triggering any remote key generation.
        fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        request=urllib.request.Request(URL,data=canonical({'action':'provision_hf_key','ceremony_sha256':a.ceremony_sha256}),headers=headers,method='POST')
        with opener.open(request,timeout=90) as response:
            need(response.status==200,'setup_status');data=response.read(65537);need(len(data)<=65536,'setup_response_size')
        body=strict_load(data);need(type(body) is dict and body.keys()=={'registration','production_authorized','interlock'}
            and body['production_authorized'] is False and body['interlock']=='KEEP_CLOSED','setup_authority')
        record=body['registration'];need(record.get('payload',{}).get('provider')=='hf','setup_provider')
        check_record(record,c,now=int(time.time()),backends=Backends())
        public=canonical(record)
        with os.fdopen(fd,'wb') as stream:fd=None;stream.write(public)
        print('PUBLIC_REGISTRATION_SHA256='+sha(public));print('KEY_SHA256='+record['payload']['key_sha256'])
        print('OPERATOR_REVIEW_REQUIRED\nPRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
    except Exception:
        if fd is not None:
            os.close(fd)
            try:Path(a.out).unlink()
            except OSError:pass
        print('HF_REMOTE_ENROLLMENT_REFUSED',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
