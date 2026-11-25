"""Authenticated HF R13 ingress with one-time durable claims; NO Phase4 authority."""
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from crypto_box import unb64, seal, canonical, hash_envelope

MAX_CAPTURE=32768

def require_config():
    keys=('ARDA_RELAY_INGEST_TOKEN','ARDA_RELAY_CLAIM_TOKEN','ARDA_RELAY_GITHUB_TOKEN','ARDA_RELAY_GITHUB_REPO','ARDA_RELAY_RECIPIENT_PUBLIC_B64','ARDA_RELAY_STATE_MOUNT')
    cfg={key:os.environ.get(key,'') for key in keys}
    if not all(cfg.values()):raise RuntimeError('MISSING_RELAY_CONFIGURATION')
    for name in ('ARDA_RELAY_INGEST_TOKEN','ARDA_RELAY_CLAIM_TOKEN'):
        if len(cfg[name])<40:raise RuntimeError('WEAK_RELAY_TOKEN')
    if cfg['ARDA_RELAY_INGEST_TOKEN']==cfg['ARDA_RELAY_CLAIM_TOKEN']:raise RuntimeError('TOKEN_REUSE')
    pub=unb64(cfg['ARDA_RELAY_RECIPIENT_PUBLIC_B64'])
    if len(pub)!=32:raise RuntimeError('RECIPIENT_KEY_LENGTH')
    mount=Path(cfg['ARDA_RELAY_STATE_MOUNT']).resolve(strict=True)
    if not os.path.ismount(mount):raise RuntimeError('PERSISTENT_VOLUME_REQUIRED')
    if cfg['ARDA_RELAY_GITHUB_REPO']!='Byron2306/arda-pq-witnesses':raise RuntimeError('REPO_NOT_ENROLLED')
    return cfg,pub,mount/'r13-relay-v1.sqlite3'

def initialize(db):
    with sqlite3.connect(db,timeout=10) as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.execute('PRAGMA synchronous=FULL')
        c.execute('CREATE TABLE IF NOT EXISTS claims (ticket TEXT PRIMARY KEY, challenge_id TEXT NOT NULL UNIQUE, envelope_sha256 TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)')

def extract_fresh_challenge(raw,now):
    if len(raw)>MAX_CAPTURE:raise ValueError('CAPTURE_TOO_LARGE')
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise ValueError('DUPLICATE_JSON_KEY')
            d[k]=v
        return d
    item=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
    if not isinstance(item,dict) or set(item)!={'schema','issued_challenge','evidence','receipt'} or item['schema']!='arda.r13.capture.v2':raise ValueError('CAPTURE_FIELDS')
    issued=item['issued_challenge']
    if not isinstance(issued,dict) or not isinstance(issued.get('challenge'),dict):raise ValueError('CHALLENGE_FIELDS')
    ch=issued['challenge'];cid=ch.get('challenge_id');issue=ch.get('issued_at');expiry=ch.get('expires_at')
    if not isinstance(cid,str) or len(cid)!=32 or any(x not in '0123456789abcdef' for x in cid):raise ValueError('CHALLENGE_ID')
    if type(issue)!=int or type(expiry)!=int or not issue<=now<expiry or not 0<expiry-issue<=300:raise ValueError('CHALLENGE_EXPIRED')
    return cid,expiry

class Relay:
    def __init__(self,cfg,pub,db,dispatch=None,clock=time.time):
        self.cfg,self.pub,self.db,self.clock=cfg,pub,db,clock
        self.dispatch=dispatch or self._dispatch
        initialize(db)
    def submit(self,raw):
        now=int(self.clock());cid,expiry=extract_fresh_challenge(raw,now)
        box=seal(raw,self.pub);ticket=secrets.token_hex(24);digest=hash_envelope(box)
        payload={'event_type':'arda_r13_capture_v4','client_payload':{'schema':'arda.r13.relay_dispatch.v1','ticket':ticket,'envelope_sha256':digest,'box':box}}
        if len(canonical(payload))>60000:raise ValueError('GITHUB_DISPATCH_SIZE')
        with sqlite3.connect(self.db,timeout=10,isolation_level=None) as c:
            c.execute('PRAGMA synchronous=FULL');c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT 1 FROM claims WHERE challenge_id=?',(cid,)).fetchone():
                c.rollback();raise ValueError('CHALLENGE_ALREADY_SUBMITTED')
            c.execute('INSERT INTO claims VALUES (?,?,?,?,0)',(ticket,cid,digest,expiry));c.commit()
        self.dispatch(payload)
        return {'schema':'arda.r13.relay_submission.v1','accepted':True,'ticket':ticket,'receipt_expires_at':expiry,'phase4_authorized':False}
    def claim(self,ticket,digest):
        if not isinstance(ticket,str) or len(ticket)!=48 or any(x not in '0123456789abcdef' for x in ticket):return False
        if not isinstance(digest,str) or len(digest)!=64 or any(x not in '0123456789abcdef' for x in digest):return False
        with sqlite3.connect(self.db,timeout=10,isolation_level=None) as c:
            c.execute('PRAGMA synchronous=FULL');c.execute('BEGIN IMMEDIATE')
            changed=c.execute('UPDATE claims SET used=1 WHERE ticket=? AND envelope_sha256=? AND used=0 AND expires_at>?',(ticket,digest,int(self.clock()))).rowcount
            c.commit()
        return changed==1
    def _dispatch(self,payload):
        request=urllib.request.Request('https://api.github.com/repos/'+self.cfg['ARDA_RELAY_GITHUB_REPO']+'/dispatches',data=canonical(payload),headers={'Authorization':'Bearer '+self.cfg['ARDA_RELAY_GITHUB_TOKEN'],'Accept':'application/vnd.github+json','Content-Type':'application/json','User-Agent':'arda-r13-relay/1'},method='POST')
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(request,timeout=8) as response:
            if response.status!=204:raise RuntimeError('GITHUB_DISPATCH_FAILED')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None

class Handler(BaseHTTPRequestHandler):
    relay=None
    def log_message(self,fmt,*args):pass
    def reply(self,code,data):
        body=canonical(data);self.send_response(code)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def do_GET(self):
        if urlsplit(self.path).path=='/health':self.reply(200,{'status':'standby' if self.relay is None else 'up','ingest_enabled':self.relay is not None,'phase4_authorized':False,'interlock':'KEEP_CLOSED'})
        else:self.reply(404,{'error':'NOT_FOUND'})
    def do_POST(self):
        if urlsplit(self.path).path not in ('/v1/submit','/v1/claim'):return self.reply(404,{'error':'NOT_FOUND'})
        if self.relay is None:return self.reply(503,{'error':'RELAY_STANDBY','interlock':'KEEP_CLOSED'})
        key='ARDA_RELAY_INGEST_TOKEN' if urlsplit(self.path).path=='/v1/submit' else 'ARDA_RELAY_CLAIM_TOKEN'
        bearer=self.headers.get('Authorization','')
        if not hmac.compare_digest(bearer,'Bearer '+self.relay.cfg[key]):return self.reply(401,{'error':'UNAUTHORIZED'})
        cap=MAX_CAPTURE if self.path=='/v1/submit' else 1024
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.reply(415,{'error':'CONTENT_TYPE'})
        try:
            length=int(self.headers.get('Content-Length','-1'))
            if not 0<length<=cap:return self.reply(413,{'error':'SIZE'})
            raw=self.rfile.read(length)
            if urlsplit(self.path).path=='/v1/submit':return self.reply(202,self.relay.submit(raw))
            req=json.loads(raw)
            if not isinstance(req,dict) or set(req)!={'ticket','envelope_sha256'}:raise ValueError('CLAIM_FIELDS')
            accepted=self.relay.claim(req['ticket'],req['envelope_sha256'])
            return self.reply(200 if accepted else 409,{'claimed':accepted})
        except (ValueError,KeyError,TypeError,json.JSONDecodeError):return self.reply(400,{'error':'INVALID_REQUEST'})
        except (urllib.error.URLError,RuntimeError,OSError,sqlite3.Error):return self.reply(503,{'error':'RELAY_UNAVAILABLE'})

def main():
    if os.environ.get('ARDA_RELAY_STANDBY_ONLY') == '1':
        Handler.relay=None
    else:
        cfg,pub,db=require_config()
        Handler.relay=Relay(cfg,pub,db)
    ThreadingHTTPServer(('0.0.0.0',7860),Handler).serve_forever()
if __name__=='__main__':main()
