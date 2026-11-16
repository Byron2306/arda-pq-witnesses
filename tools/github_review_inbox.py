#!/usr/bin/env python3
"""Receive public review data after a pinned runner is ready. Never handles signer secrets."""
import base64
import json
import os
from pathlib import Path
import re
import time
import urllib.request
import urllib.error

REPO='Byron2306/arda-pq-witnesses'

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()

def decode_response(raw,session,run_id,attempt):
    if len(raw)>131072:raise ValueError('INBOX_SIZE')
    body=json.loads(raw)
    if body.get('encoding')!='base64':raise ValueError('INBOX_ENCODING')
    data=base64.b64decode(''.join(body['content'].split()),validate=True)
    if len(data)>66000:raise ValueError('ENVELOPE_SIZE')
    envelope=json.loads(data)
    if canonical(envelope)!=data:raise ValueError('ENVELOPE_CANONICAL')
    if set(envelope)!={'schema','session','run_id','run_attempt','request'}:raise ValueError('ENVELOPE_FIELDS')
    if (envelope['schema'],envelope['session'],envelope['run_id'],envelope['run_attempt']) != ('arda.github.review_inbox.v1',session,run_id,attempt):raise ValueError('INBOX_BINDING')
    request=envelope['request']
    if type(request) is not dict or set(request)!={'schema','proposal','capture'} or request['schema']!='arda.pq.witness_request.v1':raise ValueError('REQUEST_FIELDS')
    result=canonical(request)
    if len(result)>65536:raise ValueError('REQUEST_SIZE')
    return result

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def main():
    session=os.environ['ARDA_REVIEW_SESSION'];run_id=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
    assert re.fullmatch('[0-9a-f]{64}',session)
    assert re.fullmatch('[0-9]+',run_id) and re.fullmatch('[0-9]+',attempt)
    assert os.environ['GITHUB_REPOSITORY']==REPO
    out=Path(os.environ['RUNNER_TEMP'])/'arda-pq-request';out.mkdir(mode=0o700,exist_ok=True)
    ready=dict(schema='arda.github.review_ready.v1',session=session,run_id=run_id,run_attempt=attempt,commit=os.environ['GITHUB_SHA'],production_authorized=False)
    (out/'ready.json').write_bytes(canonical(ready))
    if os.environ.get('ARDA_READY_ONLY')=='true':
        print('GITHUB_REVIEW_READY');return
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    url=f'https://api.github.com/repos/{REPO}/contents/request.json?ref=arda-review-inbox/{session}'
    deadline=time.monotonic()+600
    while time.monotonic()<deadline:
        request=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','User-Agent':'ARDA-Review-Inbox','Cache-Control':'no-cache'})
        try:
            with opener.open(request,timeout=15) as response:raw=response.read(131073)
        except urllib.error.HTTPError as error:
            if error.code!=404:raise ValueError('INBOX_HTTP_REFUSED') from None
            time.sleep(2);continue
        raw=decode_response(raw,session,run_id,attempt)
        with (out/'request.json').open('xb') as stream:stream.write(raw)
        print('GITHUB_REVIEW_REQUEST_RECEIVED');return
    raise ValueError('INBOX_TIMEOUT')

if __name__=='__main__':
    try:main()
    except Exception:
        print('GITHUB_REVIEW_INBOX_REFUSED');raise SystemExit(1)
