#!/usr/bin/env python3
"""Send one fresh local R13 v2 archive to the separately configured HTTPS relay."""
import argparse
import json
import os
from pathlib import Path
import stat
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None

def guarded_file(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or st.st_mode&0o077:
            raise ValueError('UNSAFE_FILE_PERMISSIONS')
        raw=f.read(limit+1)
    if not 0<len(raw)<=limit:raise ValueError('FILE_SIZE')
    return raw

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--token-file',type=Path,required=True)
    p.add_argument('--relay-origin',required=True)
    args=p.parse_args()
    if not args.relay_origin.startswith('https://') or '/' in args.relay_origin[8:] or '?' in args.relay_origin or '#' in args.relay_origin:
        raise SystemExit('REFUSE_INVALID_RELAY_ORIGIN')
    raw=guarded_file(args.capture,32768)
    token=guarded_file(args.token_file,256).decode('ascii').strip()
    if len(token)<40 or not token.isascii() or any(ord(c)<33 or ord(c)>126 for c in token):
        raise SystemExit('REFUSE_INVALID_TOKEN')
    request=urllib.request.Request(args.relay_origin+'/v1/submit',data=raw,method='POST',
        headers={'Content-Type':'application/json','Authorization':'Bearer '+token,
                 'User-Agent':'arda-r13-offhost-submit/1'})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(request,timeout=12) as resp:
            if resp.status!=202:raise ValueError('RELAY_REJECTED')
            result=json.loads(resp.read(1024))
            if result.get('schema')!='arda.r13.relay_submission.v1' or result.get('accepted') is not True:
                raise ValueError('RELAY_RESPONSE_INVALID')
        print('R13_ENCRYPTED_RELAY_SUBMITTED=TRUE')
        print('R13_RELAY_TICKET='+result['ticket'])
        print('PHASE4_AUTHORITY=FALSE')
        print('GEN14_INTERLOCK=KEEP_CLOSED')
    except (urllib.error.URLError,ValueError,KeyError):
        raise SystemExit('R13_ENCRYPTED_RELAY_REFUSE') from None
if __name__=='__main__':main()
