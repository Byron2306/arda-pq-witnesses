#!/usr/bin/env python3
"""Test tag enforcement using one synthetic probe tag. Never touches real HSS leaves.
Creates two annotated probe objects and races creation of their one shared ref;
then attempts forbidden update/deletion only on that new synthetic ref.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.error
import urllib.request

REPO='Byron2306/arda-hss-leaf-anchor'
GENESIS='465548215eed2548eb3eb32d321558d41dedcdea'
RULESET_ID=27318098
BASE='https://api.github.com/repos/'+REPO
PREFIX='arda-hss-leaf-'
def need(ok,reason):
    if not ok:raise ValueError(reason)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None

def projection(r):
    need(type(r) is dict and r.get('id')==RULESET_ID and r.get('target')=='tag' and r.get('enforcement')=='active' and r.get('bypass_actors')==[],'active_no_bypass_tag_rules_required')
    scope={'ref_name':{'include':['refs/tags/'+PREFIX+'*'],'exclude':[]}}
    need(r.get('conditions')==scope,'exact_tag_scope_required')
    need(type(r.get('rules')) is list and not any(v.get('type')=='creation' for v in r['rules']),'tag_creation_must_be_allowed')
    for kind in ('update','deletion'):
        matches=[v for v in r['rules'] if v.get('type')==kind]
        need(len(matches)==1 and not matches[0].get('parameters'),'tag_update_and_delete_protection_required')
    need(r.get('current_user_can_bypass','never')=='never','probe_actor_must_not_bypass')
    return dict(target='tag',enforcement='active',bypass_actors=[],conditions=scope,rules=[{'type':'deletion'},{'type':'update'}])

class AnchorProbe:
    def __init__(self,token,request=None):
        need(type(token) is str and 0<len(token)<=4096 and all(33<=ord(c)<=126 for c in token),'anchor_token_required')
        self.__token=token;self.request=request or self._request
    def _request(self,method,path,body=None):
        # Fixed repository and endpoint families; no caller-supplied URLs or redirects.
        need(path in ('',f'/rulesets/{RULESET_ID}','/git/commits/'+GENESIS,'/git/tags','/git/refs') or
            re.fullmatch(r'/git/refs?/tags/arda-hss-leaf-[0-9a-f]{64}-0000',path),'probe_endpoint')
        req=urllib.request.Request(BASE+path,data=canonical(body) if body is not None else None,method=method,
            headers={'Authorization':'Bearer '+self.__token,'Accept':'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'ARDA-HSS-Anchor-Probe-v5'})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        try:response=opener.open(req,timeout=30)
        except urllib.error.HTTPError as error:response=error
        with response:
            raw=response.read(131073);need(len(raw)<=131072,'probe_response_size')
            return response.code,json.loads(raw) if raw else {}
    def get(self,path):
        status,body=self.request('GET',path);need(status==200,'probe_read_refused');return body
    @staticmethod
    def protection_refusal(status,body):
        # Rate limiting or a malformed request must not count as rule enforcement.
        text=json.dumps(body).lower()
        return status in (403,422) and ('rule violation' in text or ('protected' in text and ('ref' in text or 'tag' in text)))
    def run(self):
        repo=self.get('');need(repo.get('full_name')==REPO and repo.get('private') is False and repo.get('archived') is False and repo.get('fork') is False,'dedicated_public_anchor_required')
        before=projection(self.get(f'/rulesets/{RULESET_ID}'))
        need(self.get('/git/commits/'+GENESIS).get('sha')==GENESIS,'anchor_genesis_binding')
        # Synthetic fingerprint is domain-separated from public-key hashing; no HSS key exists.
        nonce=secrets.token_hex(32);fingerprint=sha(b'ARDA/HSS/ANCHOR-PROBE/v1\0'+bytes.fromhex(nonce))
        tag=PREFIX+fingerprint+'-0000';ref='refs/tags/'+tag;objects=[]
        for side in (0,1):
            payload=dict(schema='arda.hss.anchor_probe.v1',probe_nonce=nonce,probe_side=side,live_hss_key_used=False,production_authorized=False)
            status,body=self.request('POST','/git/tags',dict(tag=tag,object=GENESIS,type='commit',message=canonical(payload).decode(),tagger=dict(name='ARDA anchor acceptance probe',email='arda-hss@users.noreply.github.com',date=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))))
            need(status==201 and type(body.get('sha')) is str and re.fullmatch('[0-9a-f]{40}',body['sha']),'probe_tag_object_creation')
            objects.append(body['sha'])
        need(objects[0]!=objects[1],'distinct_probe_objects_required')
        def create(target):return self.request('POST','/git/refs',dict(ref=ref,sha=target))
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(create,objects))
        winners=[i for i,(status,body) in enumerate(results) if status==201]
        need(len(winners)==1,'single_atomic_creation_winner_required');winner=winners[0];loser=1-winner
        status,body=results[loser]
        need(status in (409,422) and 'already exists' in str(body.get('message','')).lower(),'duplicate_ref_creation_must_refuse')
        status,body=results[winner]
        need(body.get('ref')==ref and body.get('object',{}).get('type')=='tag' and body['object']['sha']==objects[winner],'created_ref_binding')
        current=self.get('/git/ref/tags/'+tag);need(current.get('object',{}).get('sha')==objects[winner],'probe_ref_readback')
        # These attempts target only our generated synthetic tag, never an existing HSS key.
        update_status,update_body=self.request('PATCH','/git/refs/tags/'+tag,dict(sha=objects[loser],force=True))
        need(self.protection_refusal(update_status,update_body),'forced_tag_update_was_not_proven_blocked')
        delete_status,delete_body=self.request('DELETE','/git/refs/tags/'+tag)
        need(self.protection_refusal(delete_status,delete_body),'tag_deletion_was_not_proven_blocked')
        current=self.get('/git/ref/tags/'+tag)
        need(current.get('ref')==ref and current.get('object',{}).get('sha')==objects[winner],'probe_ref_must_remain_unchanged')
        after=projection(self.get(f'/rulesets/{RULESET_ID}'));need(after==before,'anchor_rules_changed_during_probe')
        return dict(schema='arda.hss.anchor_acceptance.v1',repository=REPO,genesis_commit=GENESIS,ruleset_id=RULESET_ID,
            rules_projection_sha256=sha(canonical(before)),probe_ref=ref,probe_tag_sha=objects[winner],probe_nonce=nonce,
            create_statuses=[s for s,b in results],forced_update_status=update_status,delete_status=delete_status,
            single_creation_winner=True,forced_update_blocked=True,deletion_blocked=True,unchanged_ref_readback=True,
            protection_enforced=True,token_scope_independently_verified=False,live_hss_key_used=False,
            production_authorized=False,interlock='KEEP_CLOSED')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True);a=p.parse_args();fd=None
    try:
        fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        report=AnchorProbe(os.environ.get('ARDA_CF_ANCHOR_TOKEN')).run();raw=canonical(report)
        with os.fdopen(fd,'wb') as stream:fd=None;stream.write(raw)
        print('ANCHOR_PROTECTION_PROBE=PASS');print('REPORT='+str(Path(a.out).absolute()));print('REPORT_SHA256='+sha(raw));print('PROBE_REF='+report['probe_ref'])
        print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
    except Exception:
        if fd is not None:
            os.close(fd)
            try:Path(a.out).unlink()
            except OSError:pass
        print('ANCHOR_PROBE_REFUSED_STOP_AND_INSPECT',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
