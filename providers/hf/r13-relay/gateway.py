"""Authenticated HF R13 ingress with one-time durable claims; NO Phase4 authority."""
import hmac
import json
import os
import secrets
import time
import socket
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from crypto_box import unb64, seal, canonical, hash_envelope
from synthetic_lane import deadline, active, synthetic_capture

MAX_CAPTURE=32768

class RelayStageError(RuntimeError):
    """Static stage code only. Never embed provider bodies, tokens or URLs."""
    def __init__(self, stage, *, http_status=None):
        if stage not in {
            'LEDGER_HTTP_REFUSAL', 'LEDGER_TRANSPORT_FAILURE',
            'LEDGER_BAD_RESPONSE', 'GITHUB_HTTP_REFUSAL',
            'GITHUB_TRANSPORT_FAILURE', 'GITHUB_BAD_RESPONSE',
        }:
            raise ValueError('INVALID_STAGE_CODE')
        if http_status is not None and (type(http_status) is not int or not 400<=http_status<=599):
            raise ValueError('INVALID_HTTP_STATUS')
        self.stage=stage
        self.http_status=http_status
        super().__init__(stage)

def require_config():
    keys=('ARDA_RELAY_INGEST_TOKEN','ARDA_RELAY_CLAIM_TOKEN','ARDA_RELAY_GITHUB_TOKEN','ARDA_RELAY_GITHUB_REPO','ARDA_RELAY_RECIPIENT_PUBLIC_B64','ARDA_RELAY_LEDGER_URL','ARDA_RELAY_LEDGER_TOKEN')
    cfg={key:os.environ.get(key,'') for key in keys}
    if not all(cfg.values()):raise RuntimeError('MISSING_RELAY_CONFIGURATION')
    for name in ('ARDA_RELAY_INGEST_TOKEN','ARDA_RELAY_CLAIM_TOKEN'):
        if len(cfg[name])<40:raise RuntimeError('WEAK_RELAY_TOKEN')
    if cfg['ARDA_RELAY_INGEST_TOKEN']==cfg['ARDA_RELAY_CLAIM_TOKEN']:raise RuntimeError('TOKEN_REUSE')
    pub=unb64(cfg['ARDA_RELAY_RECIPIENT_PUBLIC_B64'])
    if len(pub)!=32:raise RuntimeError('RECIPIENT_KEY_LENGTH')
    ledger=cfg['ARDA_RELAY_LEDGER_URL']
    parsed=urlsplit(ledger)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/') or parsed.port not in (None,443):
        raise RuntimeError('INVALID_LEDGER_ORIGIN')
    if len(cfg['ARDA_RELAY_LEDGER_TOKEN'])<40:raise RuntimeError('WEAK_LEDGER_TOKEN')
    if cfg['ARDA_RELAY_LEDGER_TOKEN'] in (cfg['ARDA_RELAY_CLAIM_TOKEN'],cfg['ARDA_RELAY_INGEST_TOKEN']):
        raise RuntimeError('LEDGER_TOKEN_REUSED')
    if cfg['ARDA_RELAY_GITHUB_REPO']!='Byron2306/arda-pq-witnesses':raise RuntimeError('REPO_NOT_ENROLLED')
    return cfg,pub
class DurableLedger:
    def __init__(self,url,token,opener=None):
        self.url=url.rstrip('/')
        self.token=token
        self.opener=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def call(self,kind,body):
        request=urllib.request.Request(self.url+'/'+kind,data=canonical(body),method='POST',
            headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json','User-Agent':'arda-r13-relay-ledger/1'})
        try:
            with self.opener.open(request,timeout=5) as response:
                data=json.loads(response.read(512))
                return response.status,data
        except urllib.error.HTTPError as exc:
            with exc:
                if exc.code==409:return 409,{}
            raise RelayStageError('LEDGER_HTTP_REFUSAL') from None
        except (urllib.error.URLError,TimeoutError,OSError) as exc:
            raise RelayStageError('LEDGER_TRANSPORT_FAILURE') from None
        except (ValueError,TypeError) as exc:
            raise RelayStageError('LEDGER_BAD_RESPONSE') from None
    def probe_transport(self):
        """Authenticated, non-mutating ledger probe: invalid claim cannot change SQL."""
        request=urllib.request.Request(self.url+'/claim',data=b'{}',method='POST',
            headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json',
                     'User-Agent':'arda-r13-relay-ledger/1'})
        try:
            with self.opener.open(request,timeout=5) as response:
                return {'probe':'UNEXPECTED_SUCCESS','http':response.status}
        except urllib.error.HTTPError as exc:
            with exc:
                # 400 INVALID_CLAIM is the expected authenticated, nonmutating path.
                try: body=json.loads(exc.read(512))
                except (ValueError,TypeError): body={}
                if exc.code==400 and body=={'claimed':False,'error':'INVALID_CLAIM'}:
                    return {'probe':'LEDGER_REACHABLE','http':400}
                # Never return upstream body/headers: they may contain untrusted data.
                return {'probe':'LEDGER_HTTP_REFUSAL','http':exc.code}
        except urllib.error.URLError as exc:
            reason=exc.reason
            if isinstance(reason,socket.gaierror): category='DNS'
            elif isinstance(reason,ssl.SSLError): category='TLS'
            elif isinstance(reason,(TimeoutError,socket.timeout)): category='TIMEOUT'
            elif isinstance(reason,ConnectionRefusedError): category='CONNECTION_REFUSED'
            else: category='NETWORK'
            return {'probe':'LEDGER_TRANSPORT_FAILURE','category':category}
        except (TimeoutError,socket.timeout):
            return {'probe':'LEDGER_TRANSPORT_FAILURE','category':'TIMEOUT'}
        except OSError:
            return {'probe':'LEDGER_TRANSPORT_FAILURE','category':'NETWORK'}
    def probe_environment_egress(self):
        """Unauthenticated comparison using environment proxy handling.
        No ledger token, payload, reservation, claim or proxy URL is exposed.
        """
        request=urllib.request.Request(self.url+'/claim',data=b'{}',method='POST',
            headers={'Content-Type':'application/json','User-Agent':'arda-r13-egress-diagnostic/1'})
        opener=urllib.request.build_opener(NoRedirect())
        try:
            with opener.open(request,timeout=5) as response:
                return {'probe':'ENVIRONMENT_ROUTE_HTTP','http':response.status}
        except urllib.error.HTTPError as exc:
            with exc: pass
            # 401 from the worker proves reachability without authenticating.
            return {'probe':'ENVIRONMENT_ROUTE_HTTP','http':exc.code}
        except urllib.error.URLError as exc:
            reason=exc.reason
            if isinstance(reason,socket.gaierror): category='DNS'
            elif isinstance(reason,ssl.SSLError): category='TLS'
            elif isinstance(reason,(TimeoutError,socket.timeout)): category='TIMEOUT'
            else: category='NETWORK'
            return {'probe':'ENVIRONMENT_ROUTE_FAILURE','category':category}
        except (TimeoutError,socket.timeout):
            return {'probe':'ENVIRONMENT_ROUTE_FAILURE','category':'TIMEOUT'}
        except OSError:
            return {'probe':'ENVIRONMENT_ROUTE_FAILURE','category':'NETWORK'}
    def probe_connection_phases(self):
        """Diagnostic only: DNS/TCP/TLS for the enrolled ledger origin, no HTTP or bearer."""
        hostname=urlsplit(self.url).hostname
        if not hostname:
            return {'probe':'PHASE_REFUSE','phase':'CONFIGURATION'}
        def ms(start):
            return round((time.monotonic()-start)*1000)
        started=time.monotonic()
        try:
            addresses=socket.getaddrinfo(hostname,443,type=socket.SOCK_STREAM)
        except socket.gaierror:
            return {'probe':'PHASE_REFUSE','phase':'DNS','category':'RESOLUTION_FAILED','dns_ms':ms(started)}
        except OSError:
            return {'probe':'PHASE_REFUSE','phase':'DNS','category':'NETWORK','dns_ms':ms(started)}
        dns_ms=ms(started)
        # Attempt one distinct IPv4 and IPv6 address each, without disclosing IPs.
        selected={}
        for family,kind,proto,_,address in addresses:
            if family in (socket.AF_INET,socket.AF_INET6) and family not in selected:
                selected[family]=(kind,proto,address)
        if not selected:
            return {'probe':'PHASE_REFUSE','phase':'DNS','category':'NO_SUPPORTED_ADDRESS','dns_ms':dns_ms}
        results=[]
        for family,(kind,proto,address) in selected.items():
            label='IPV4' if family==socket.AF_INET else 'IPV6'
            conn=None
            phase='TCP'
            start=time.monotonic()
            observation={'family':label}
            try:
                conn=socket.socket(family,kind,proto)
                conn.settimeout(2.5)
                conn.connect(address)
                observation['tcp_ms']=ms(start)
                phase='TLS'
                start=time.monotonic()
                context=ssl.create_default_context()
                with context.wrap_socket(conn,server_hostname=hostname) as tls:
                    conn=None
                    observation['tls_ms']=ms(start)
                observation.update({'phase':'TLS','status':'PASS'})
            except (socket.timeout,TimeoutError):
                observation.update({'phase':phase,'status':'TIMEOUT'})
                observation[phase.lower()+'_ms']=ms(start)
            except ssl.SSLError:
                observation.update({'phase':'TLS','status':'TLS_ERROR','tls_ms':ms(start)})
            except OSError:
                observation.update({'phase':phase,'status':'NETWORK_ERROR'})
                observation[phase.lower()+'_ms']=ms(start)
            finally:
                if conn is not None: conn.close()
            results.append(observation)
        return {'probe':'PHASE_RESULTS','dns_ms':dns_ms,'routes':results}
    def reserve(self,ticket,cid,digest,expiry):
        status,data=self.call('reserve',{'ticket':ticket,'challenge_id':cid,'envelope_sha256':digest,'expires_at':expiry})
        return status==201 and data=={'reserved':True}
    def claim(self,ticket,digest):
        status,data=self.call('claim',{'ticket':ticket,'envelope_sha256':digest})
        return status==200 and data=={'claimed':True}

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
    def __init__(self,cfg,pub,ledger,dispatch=None,clock=time.time):
        self.cfg,self.pub,self.ledger,self.clock=cfg,pub,ledger,clock
        self.dispatch=dispatch or self._dispatch
    def submit(self,raw):
        now=int(self.clock());cid,expiry=extract_fresh_challenge(raw,now)
        box=seal(raw,self.pub);ticket=secrets.token_hex(24);digest=hash_envelope(box)
        payload={'event_type':'arda_r13_capture_v4','client_payload':{'schema':'arda.r13.relay_dispatch.v1','ticket':ticket,'envelope_sha256':digest,'box':box}}
        if len(canonical(payload))>60000:raise ValueError('GITHUB_DISPATCH_SIZE')
        # Ledger reservation must complete BEFORE any GitHub dispatch.
        # Inconclusive network response fails closed. No retry with a new ticket.
        if not self.ledger.reserve(ticket,cid,digest,expiry):
            raise ValueError('LEDGER_RESERVATION_REFUSED')
        self.dispatch(payload)
        return {'schema':'arda.r13.relay_submission.v1','accepted':True,'ticket':ticket,'receipt_expires_at':expiry,'phase4_authorized':False}
    def claim(self,ticket,digest):
        if not isinstance(ticket,str) or len(ticket)!=48 or any(x not in '0123456789abcdef' for x in ticket):return False
        if not isinstance(digest,str) or len(digest)!=64 or any(x not in '0123456789abcdef' for x in digest):return False
        return self.ledger.claim(ticket,digest)
    def _dispatch(self,payload):
        request=urllib.request.Request('https://api.github.com/repos/'+self.cfg['ARDA_RELAY_GITHUB_REPO']+'/dispatches',data=canonical(payload),headers={'Authorization':'Bearer '+self.cfg['ARDA_RELAY_GITHUB_TOKEN'],'Accept':'application/vnd.github+json','Content-Type':'application/json','User-Agent':'arda-r13-relay/1'},method='POST')
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(request,timeout=8) as response:
                if response.status!=204:raise RelayStageError('GITHUB_BAD_RESPONSE')
        except urllib.error.HTTPError as exc:
            with exc: pass
            raise RelayStageError('GITHUB_HTTP_REFUSAL',http_status=exc.code) from None
        except (urllib.error.URLError,TimeoutError,OSError) as exc:
            raise RelayStageError('GITHUB_TRANSPORT_FAILURE') from None

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None

class Handler(BaseHTTPRequestHandler):
    relay=None
    test_until=None
    def log_message(self,fmt,*args):pass
    def reply(self,code,data):
        body=canonical(data);self.send_response(code)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def do_GET(self):
        if urlsplit(self.path).path=='/health':self.reply(200,{'status':'test_window' if active(self.test_until) else 'standby' if self.relay is None or self.test_until is not None else 'up','ingest_enabled':self.relay is not None and self.test_until is None,'synthetic_test_enabled':active(self.test_until),'phase4_authorized':False,'interlock':'KEEP_CLOSED'})
        else:self.reply(404,{'error':'NOT_FOUND'})
    def do_POST(self):
        route=urlsplit(self.path).path
        if route not in ('/v1/submit','/v1/claim','/v1/test-submit','/v1/test-ledger-probe'):return self.reply(404,{'error':'NOT_FOUND'})
        if self.relay is None or (self.test_until is not None and (not active(self.test_until) or route=='/v1/submit')) or (self.test_until is None and route in ('/v1/test-submit','/v1/test-ledger-probe')):
            return self.reply(503,{'error':'RELAY_STANDBY','interlock':'KEEP_CLOSED'})
        key='ARDA_RELAY_INGEST_TOKEN' if route in ('/v1/submit','/v1/test-submit','/v1/test-ledger-probe') else 'ARDA_RELAY_CLAIM_TOKEN'
        bearer=self.headers.get('Authorization','')
        if not hmac.compare_digest(bearer,'Bearer '+self.relay.cfg[key]):return self.reply(401,{'error':'UNAUTHORIZED'})
        cap=MAX_CAPTURE if route in ('/v1/submit','/v1/test-submit') else 1024
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.reply(415,{'error':'CONTENT_TYPE'})
        try:
            length=int(self.headers.get('Content-Length','-1'))
            if not 0<length<=cap:return self.reply(413,{'error':'SIZE'})
            raw=self.rfile.read(length)
            if route=='/v1/test-ledger-probe':
                if raw==b'{}':return self.reply(200,self.relay.ledger.probe_transport())
                if raw==b'{"mode":"environment"}':
                    return self.reply(200,self.relay.ledger.probe_environment_egress())
                if raw==b'{"mode":"phases"}':
                    return self.reply(200,self.relay.ledger.probe_connection_phases())
                return self.reply(400,{'error':'INVALID_PROBE'})
            if route=='/v1/test-submit':
                if not synthetic_capture(raw):return self.reply(400,{'error':'SYNTHETIC_CAPTURE_REQUIRED'})
                return self.reply(202,self.relay.submit(raw))
            if route=='/v1/submit':return self.reply(202,self.relay.submit(raw))
            req=json.loads(raw)
            if not isinstance(req,dict) or set(req)!={'ticket','envelope_sha256'}:raise ValueError('CLAIM_FIELDS')
            accepted=self.relay.claim(req['ticket'],req['envelope_sha256'])
            return self.reply(200 if accepted else 409,{'claimed':accepted})
        except (ValueError,KeyError,TypeError,json.JSONDecodeError):return self.reply(400,{'error':'INVALID_REQUEST'})
        except RelayStageError as exc:
            payload={'error':'RELAY_UNAVAILABLE','stage':exc.stage,'interlock':'KEEP_CLOSED'}
            if exc.stage=='GITHUB_HTTP_REFUSAL' and exc.http_status is not None:
                payload['upstream_http_status']=exc.http_status
            return self.reply(503,payload)
        except (urllib.error.URLError,RuntimeError,OSError):return self.reply(503,{'error':'RELAY_UNAVAILABLE','interlock':'KEEP_CLOSED'})

def main():
    Handler.test_until=deadline(os.environ)
    Handler.relay=None
    if os.environ.get('ARDA_RELAY_STANDBY_ONLY')!='1' or Handler.test_until is not None:
        cfg,pub=require_config()
        ledger=DurableLedger(cfg['ARDA_RELAY_LEDGER_URL'],cfg['ARDA_RELAY_LEDGER_TOKEN'])
        Handler.relay=Relay(cfg,pub,ledger)
    ThreadingHTTPServer(('0.0.0.0',7860),Handler).serve_forever()
if __name__=='__main__':main()
