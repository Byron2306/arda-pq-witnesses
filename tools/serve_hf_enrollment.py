#!/usr/bin/env python3
"""Explicit temporary setup CMD; key generation requires an authenticated POST."""
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.enrollment import check_ceremony
from arda_quorum.enrollment_http import SetupOnce,make_setup_server
from arda_quorum.quorum import strict_load,canonical,sha,need

def main():
    try:
        raw=os.environ['ARDA_ENROLLMENT_CEREMONY_JSON'].encode();need(len(raw)<=16384,'ceremony_size')
        ceremony=strict_load(raw);need(raw==canonical(ceremony),'canonical_ceremony')
        need(sha(raw)==os.environ['ARDA_ALLOW_PROVIDER_KEY_PROVISIONING'],'operator_ceremony_pin')
        check_ceremony(ceremony,int(time.time()))
        need(os.environ.get('SPACE_ID')==ceremony['identities']['hf'],'provider_identity')
        need(os.environ.get('ARDA_IMAGE_DIGEST')==ceremony['image_digest'],'provider_image_binding')
        need(bool(os.environ.get('ARDA_ENROLLMENT_STORE_TOKEN')),'setup_store_token_required')
        setup=SetupOnce(ceremony,os.environ)
        # Drop the process environment reference; token still exists in the isolated setup object until use.
        os.environ.pop('ARDA_ENROLLMENT_STORE_TOKEN',None)
        server=make_setup_server(setup,os.environ.get('ARDA_HF_SETUP_CLIENT_TOKEN'))
    except Exception:
        print('HF_ENROLLMENT_SETUP_NOT_CONFIGURED',file=sys.stderr);return 1
    print('HF_ENROLLMENT_ONLY_WAITING_FOR_AUTHENTICATED_REQUEST',flush=True)
    try:server.serve_forever()
    finally:server.server_close()
if __name__=='__main__':raise SystemExit(main())
