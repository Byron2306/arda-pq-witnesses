"""Bounded authenticated HF review API. TLS is supplied by the hosting platform."""
import hmac
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import re
import threading
from .quorum import strict_load,canonical,need

MAX_BODY=65536

class BoundedServer(ThreadingHTTPServer):
    daemon_threads=True;request_queue_size=16
    def __init__(self,address,handler):
        self.slots=threading.BoundedSemaphore(8);super().__init__(address,handler)
    def get_request(self):
        request,address=super().get_request();request.settimeout(10);return request,address
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()
    def handle_error(self,request,address):pass  # Never log request data or secrets.


def make_server(witness,token,*,host='0.0.0.0',port=7860):
    need(witness.provider=='hf','http_endpoint_hf_only')
    need(type(token) is str and re.fullmatch('[0-9a-f]{64}',token),'hf_client_token_configuration')
    credential=('Bearer '+token).encode('ascii')
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def reply(self,status,body):
            raw=canonical(body);self.close_connection=True
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store')
            self.send_header('Connection','close');self.send_header('X-Content-Type-Options','nosniff');self.end_headers()
            try:self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError):pass
        def refuse(self,status):self.reply(status,dict(error='WITNESS_REVIEW_REFUSED',production_authorized=False,interlock='KEEP_CLOSED'))
        def do_GET(self):
            if self.path!='/healthz':return self.refuse(404)
            self.reply(200,dict(status='configured_for_review_only',provider='hf',algorithm=witness.witness['algorithm'],
                key_sha256=witness.witness['key_sha256'],production_authorized=False))
        def do_POST(self):
            if self.path!='/v1/review-vote':return self.refuse(404)
            auth=self.headers.get_all('Authorization',[])
            custom=self.headers.get_all('X-ARDA-Review-Token',[])
            try:
                # Private HF gateway auth may occupy Authorization; a custom app header never falls back.
                authorized=(len(custom)==1 and hmac.compare_digest(custom[0].encode('ascii'),token.encode('ascii'))) if custom else (len(auth)==1 and hmac.compare_digest(auth[0].encode('ascii'),credential))
            except (UnicodeError,TypeError):authorized=False
            if not authorized:return self.refuse(401)
            if self.headers.get('Content-Type','').split(';',1)[0].strip().lower()!='application/json':return self.refuse(415)
            if self.headers.get_all('Content-Encoding') or self.headers.get_all('Transfer-Encoding'):return self.refuse(415)
            lengths=self.headers.get_all('Content-Length',[])
            if len(lengths)!=1 or not re.fullmatch('[0-9]{1,8}',lengths[0]):return self.refuse(400)
            size=int(lengths[0])
            if size>MAX_BODY:return self.refuse(413)
            if size<=0:return self.refuse(400)
            try:
                raw=self.rfile.read(size)
                if len(raw)!=size:return self.refuse(400)
                request=strict_load(raw)
                if canonical(request)!=raw:return self.refuse(400)
                vote=witness.review(request)
            except (ValueError,TypeError,KeyError,OSError):return self.refuse(400)
            self.reply(200,dict(vote=vote,production_authorized=False,interlock='KEEP_CLOSED'))
        def method_refused(self):return self.refuse(405)
        do_PUT=do_PATCH=do_DELETE=do_OPTIONS=do_HEAD=method_refused
    return BoundedServer((host,port),Handler)
