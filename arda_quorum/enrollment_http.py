"""Separate HF setup-only service. Never generates keys at startup or serves votes."""
import hmac
from http.server import BaseHTTPRequestHandler
import re
import threading
import time
from .enrollment import check_ceremony,provision
from .provider_http import BoundedServer
from .quorum import canonical,strict_load,sha,need

class SetupOnce:
    def __init__(self,ceremony,environ,*,clock=None,provisioner=None):
        self.ceremony=strict_load(canonical(ceremony));self.environ=dict(environ);self.clock=clock or time.time
        check_ceremony(self.ceremony,int(self.clock()))
        self.pin=sha(canonical(self.ceremony));self.state='WAITING';self.lock=threading.Lock();self.record=None
        self.provisioner=provisioner or provision
    def trigger(self):
        need(self.lock.acquire(blocking=False),'setup_busy')
        try:
            check_ceremony(self.ceremony,int(self.clock()))
            if self.state=='COMPLETE':return strict_load(canonical(self.record))
            need(self.state=='WAITING','setup_failed_restart_review_required')
            self.state='RUNNING'
            try:
                record=self.provisioner(self.ceremony,'hf',environ=self.environ,now=int(self.clock()))
                check_ceremony(self.ceremony,int(self.clock()))
                self.record=strict_load(canonical(record));self.state='COMPLETE';return strict_load(canonical(self.record))
            except Exception:
                self.state='FAILED';raise ValueError('SETUP_PROVISIONING_REFUSED') from None
            finally:
                self.environ.pop('ARDA_ENROLLMENT_STORE_TOKEN',None)
        finally:self.lock.release()

def make_setup_server(setup,token,*,host='0.0.0.0',port=7860):
    need(type(token) is str and re.fullmatch('[0-9a-f]{64}',token),'setup_client_token_required')
    credential=token.encode('ascii')
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def reply(self,status,body):
            raw=canonical(dict(body,production_authorized=False,interlock='KEEP_CLOSED'));self.close_connection=True
            self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
            self.send_header('Cache-Control','no-store');self.send_header('Connection','close');self.send_header('X-Content-Type-Options','nosniff');self.end_headers()
            try:self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError):pass
        def refuse(self,status):self.reply(status,{'error':'ENROLLMENT_SETUP_REFUSED'})
        def do_GET(self):
            if self.path!='/healthz':return self.refuse(404)
            self.reply(200,{'mode':'enrollment_only','state':setup.state,'ceremony_sha256':setup.pin})
        def do_POST(self):
            if self.path!='/v1/enroll-hf':return self.refuse(404)
            tokens=self.headers.get_all('X-ARDA-Setup-Token',[])
            try:authorized=len(tokens)==1 and hmac.compare_digest(tokens[0].encode('ascii'),credential)
            except (UnicodeError,TypeError):authorized=False
            if not authorized:return self.refuse(401)
            if self.headers.get('Content-Type','').split(';',1)[0].strip().lower()!='application/json':return self.refuse(415)
            if self.headers.get_all('Content-Encoding') or self.headers.get_all('Transfer-Encoding'):return self.refuse(415)
            lengths=self.headers.get_all('Content-Length',[])
            if len(lengths)!=1 or not re.fullmatch('[0-9]{1,8}',lengths[0]):return self.refuse(400)
            size=int(lengths[0])
            if size>1024:return self.refuse(413)
            if size<=0:return self.refuse(400)
            try:
                raw=self.rfile.read(size);need(len(raw)==size,'short_body');request=strict_load(raw)
                need(canonical(request)==raw and request=={'action':'provision_hf_key','ceremony_sha256':setup.pin},'setup_request')
            except Exception:return self.refuse(400)
            try:record=setup.trigger()
            except Exception:return self.refuse(409)
            self.reply(200,{'registration':record})
        def method_refused(self):self.refuse(405)
        do_HEAD=do_OPTIONS=do_DELETE=do_PUT=do_PATCH=method_refused
    return BoundedServer((host,port),Handler)
