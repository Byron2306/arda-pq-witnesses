#!/usr/bin/env python3
"""Recoverable, operator-driven synthetic V6 controller. Never production admission.

One invocation per stage. Journal is written BEFORE outbound submission.
Any uncertain result is terminal; never retry submit for the same journal.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.request

SPACE='Byron230686/arda-r13-evidence-relay'
BASE='https://byron230686-arda-r13-evidence-relay.hf.space'
WINDOW_SECONDS=300
STATE=Path.home()/'.local/state/arda-r13/v6-controller.json'
TOKEN=Path.home()/'.config/arda/r13-relay-ingest.token'
MARKER='arda-r13.synthetic-transport-test.v1'

class Refuse(RuntimeError):
    pass

def require(condition, reason):
    if not condition:
        raise Refuse(reason)

def read_state(path=STATE):
    if not path.exists():
        return {'phase':'NEW'}
    require(not path.is_symlink(),'STATE_SYMLINK')
    require(path.stat().st_mode & 0o077 == 0,'STATE_PERMISSIONS')
    value=json.loads(path.read_text())
    require(type(value) is dict and type(value.get('phase')) is str,'INVALID_STATE')
    return value

def write_state(value,path=STATE):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,name=tempfile.mkstemp(prefix='.v6-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as out:
            os.fchmod(out.fileno(),0o600)
            json.dump(value,out,sort_keys=True,separators=(',',':'))
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(name,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)

def api():
    from huggingface_hub import HfApi
    return HfApi()

def cfg(client):
    return client.get_space_variables(SPACE)

def var(variables,name):
    return getattr(variables.get(name),'value',None)

def status():
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request=urllib.request.Request(BASE+'/health',headers={'User-Agent':'arda-r13-v6-controller/1'},method='GET')
    with opener.open(request,timeout=15) as response:
        require(response.status==200,'HEALTH_HTTP')
        result=json.loads(response.read(2048))
    require(type(result) is dict and result.get('interlock')=='KEEP_CLOSED'
            and result.get('phase4_authorized') is False
            and result.get('ingest_enabled') is False,'UNSAFE_RUNTIME')
    return result

def standby(result):
    return result.get('status')=='standby' and result.get('synthetic_test_enabled') is False

def active_window(result,deadline):
    return (result.get('status')=='test_window' and result.get('synthetic_test_enabled') is True
            and result.get('test_backend')=='github-v6'
            and result.get('test_deadline')==deadline)

def prepare(client,record):
    require(record['phase'] in ('NEW','CLOSED'),'EXISTING_ATTEMPT_NOT_CLEARED')
    v=cfg(client)
    require(var(v,'ARDA_RELAY_STANDBY_ONLY')=='1','STANDBY_NOT_CONFIGURED')
    require('ARDA_RELAY_TEST_UNTIL' not in v,'EXISTING_WINDOW')
    require(standby(status()),'LIVE_STANDBY_NOT_CONFIRMED')
    client.add_space_variable(SPACE,'ARDA_RELAY_TEST_BACKEND','github-v6')
    v=cfg(client)
    require(var(v,'ARDA_RELAY_TEST_BACKEND')=='github-v6'
            and 'ARDA_RELAY_TEST_UNTIL' not in v,'BACKEND_NOT_ARMED')
    record.clear()
    record.update({'phase':'ARMED'})
    return 'V6_BACKEND_ARMED=PASS'

def open_window(client,record,persist):
    require(record['phase']=='ARMED','NOT_ARMED')
    v=cfg(client)
    require(var(v,'ARDA_RELAY_STANDBY_ONLY')=='1'
            and var(v,'ARDA_RELAY_TEST_BACKEND')=='github-v6'
            and 'ARDA_RELAY_TEST_UNTIL' not in v,'UNSAFE_WINDOW_CONFIG')
    require(standby(status()),'LIVE_STANDBY_NOT_CONFIRMED')
    deadline=int(time.time())+WINDOW_SECONDS
    # Persist pending intent BEFORE manipulating HF configuration.
    record.update({'phase':'OPEN_REQUESTED','deadline':deadline})
    persist()
    client.add_space_variable(SPACE,'ARDA_RELAY_TEST_UNTIL',str(deadline))
    return 'V6_WINDOW_REQUESTED=PASS'

def check_ready(client,record):
    require(record['phase'] in ('OPEN_REQUESTED','READY'),'NO_OPEN_WINDOW')
    deadline=record['deadline']
    require(int(time.time())<deadline-65,'WINDOW_TOO_CLOSE_TO_EXPIRY')
    v=cfg(client)
    require(var(v,'ARDA_RELAY_STANDBY_ONLY')=='1'
            and var(v,'ARDA_RELAY_TEST_BACKEND')=='github-v6'
            and var(v,'ARDA_RELAY_TEST_UNTIL')==str(deadline),'WINDOW_CONFIG_MISMATCH')
    require(active_window(status(),deadline),'LIVE_WINDOW_NOT_READY')
    record['phase']='READY'
    return 'LIVE_V6_WINDOW=READY'

def submit(client,record,persist):
    require(record['phase']=='READY','NOT_READY_OR_ALREADY_ATTEMPTED')
    deadline=record['deadline']
    require(int(time.time())<deadline-65,'WINDOW_TOO_CLOSE_TO_EXPIRY')
    v=cfg(client)
    require(var(v,'ARDA_RELAY_TEST_BACKEND')=='github-v6'
            and var(v,'ARDA_RELAY_TEST_UNTIL')==str(deadline),'WINDOW_CONFIG_MISMATCH')
    require(active_window(status(),deadline),'LIVE_WINDOW_NOT_READY')
    require(TOKEN.is_file() and not TOKEN.is_symlink(),'TOKEN_FILE_INVALID')
    token=TOKEN.read_text().strip()
    require(len(token)==64 and token.isalnum(),'TOKEN_INVALID')
    now=int(time.time())
    challenge={
        'schema':'arda.r13.capture.v2',
        'issued_challenge':{'challenge':{
            'challenge_id':secrets.token_hex(16),
            'issued_at':now-1,
            'expires_at':min(now+180,deadline-5)}},
        'evidence':{},
        'receipt':{'test_only':MARKER}}
    require(challenge['issued_challenge']['challenge']['expires_at']>now,'CHALLENGE_TOO_SHORT')
    body=json.dumps(challenge,separators=(',',':')).encode('ascii')
    # This is the no-retry boundary. Even a process kill after here is inconclusive.
    record['phase']='SUBMISSION_ATTEMPTED'
    record['attempted_at']=now
    persist()
    request=urllib.request.Request(BASE+'/v1/test-submit',data=body,method='POST',
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json',
                 'User-Agent':'arda-r13-v6-controller/1'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request,timeout=20) as response:
            payload=json.loads(response.read(2048))
            code=response.status
    except urllib.error.HTTPError as exc:
        with exc:
            code=exc.code
            try: payload=json.loads(exc.read(2048))
            except (ValueError,TypeError): payload={}
    except (OSError,TimeoutError,ValueError,TypeError):
        record['phase']='DISPATCH_UNCERTAIN'
        return 'V6_DISPATCH=UNCERTAIN_NO_RETRY'
    if code==202 and type(payload) is dict and payload.get('accepted') is True and payload.get('interlock')=='KEEP_CLOSED':
        record['phase']='DISPATCH_ACCEPTED'
        return 'V6_DISPATCH_HTTP=202_ACCEPTED_REVIEW_PENDING'
    record['phase']='DISPATCH_REFUSED'
    record['http_status']=code
    return 'V6_DISPATCH=REFUSED_HTTP_'+str(code)

def close_window(client,record):
    # Repeatable cleanup, including following a crash before local state was updated.
    record['phase']='CLOSING'
    client.add_space_variable(SPACE,'ARDA_RELAY_STANDBY_ONLY','1')
    for key in ('ARDA_RELAY_TEST_UNTIL','ARDA_RELAY_TEST_BACKEND'):
        if key in cfg(client):
            client.delete_space_variable(SPACE,key)
    v=cfg(client)
    require(var(v,'ARDA_RELAY_STANDBY_ONLY')=='1'
            and 'ARDA_RELAY_TEST_UNTIL' not in v
            and 'ARDA_RELAY_TEST_BACKEND' not in v,'CLEANUP_CONFIGURATION_NOT_CONFIRMED')
    record['phase']='CLEANUP_CONFIGURED'
    return 'CLEANUP_CONFIGURED=PASS'

def verify_close(client,record):
    require(record['phase'] in ('CLEANUP_CONFIGURED','CLOSED'),'CLOSE_NOT_REQUESTED')
    v=cfg(client)
    require(var(v,'ARDA_RELAY_STANDBY_ONLY')=='1'
            and 'ARDA_RELAY_TEST_UNTIL' not in v
            and 'ARDA_RELAY_TEST_BACKEND' not in v,'CLEANUP_CONFIGURATION_NOT_CONFIRMED')
    require(standby(status()),'LIVE_STANDBY_NOT_YET_CONFIRMED')
    record['phase']='CLOSED'
    return 'FINAL_LIVE_STANDBY=PASS'

def execute(command,client,record,persist):
    if command=='status':
        h=status()
        print('JOURNAL_PHASE='+record['phase'])
        print('LIVE_HEALTH='+json.dumps(h,sort_keys=True))
        return 'GEN14_INTERLOCK=KEEP_CLOSED'
    if command=='arm':return prepare(client,record)
    if command=='open':return open_window(client,record,persist)
    if command=='ready':return check_ready(client,record)
    if command=='submit':return submit(client,record,persist)
    if command=='close':return close_window(client,record)
    if command=='verify-close':return verify_close(client,record)
    raise Refuse('INVALID_COMMAND')

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('status','arm','open','ready','submit','close','verify-close'))
    args=parser.parse_args(argv)
    STATE.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    lockpath=STATE.with_suffix('.lock')
    require(not lockpath.is_symlink(),'LOCK_SYMLINK')
    with open(lockpath,'a+') as lock:
        os.fchmod(lock.fileno(),0o600)
        fcntl.flock(lock,fcntl.LOCK_EX)
        record=read_state()
        def persist():write_state(record)
        try:
            result=execute(args.command,api() if args.command!='status' else None,record,persist)
            persist()
            print(result,flush=True)
            print('GEN14_INTERLOCK=KEEP_CLOSED',flush=True)
        except (Refuse,AssertionError) as exc:
            persist()
            print('REFUSE_'+str(exc),flush=True)
            print('GEN14_INTERLOCK=KEEP_CLOSED',flush=True)
            return 1
        except Exception as exc:
            # Never print exception strings that could contain credentials or URLs.
            persist()
            print('REFUSE_OPERATION_FAILED_'+type(exc).__name__,flush=True)
            print('GEN14_INTERLOCK=KEEP_CLOSED',flush=True)
            return 1
    return 0

if __name__=='__main__':
    sys.exit(main())
