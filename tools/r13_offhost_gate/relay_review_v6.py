"""V6 synthetic-only relay: GitHub owns durable reserve+claim, no HF-to-Cloudflare hop.

This candidate is deliberately not authorized to verify any non-synthetic R13 capture.
"""
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'providers/hf/r13-relay'))
sys.path.insert(0,str(ROOT/'tools/r13_offhost_gate'))
from crypto_box import canonical, hash_envelope, unb64, unseal
from gateway import extract_fresh_challenge, NoRedirect
from synthetic_lane import synthetic_capture
from verify_capture import result as refusal

HEX32=re.compile(r'^[0-9a-f]{32}$')
HEX48=re.compile(r'^[0-9a-f]{48}$')
HEX64=re.compile(r'^[0-9a-f]{64}$')

class GitHubLedger:
    def __init__(self, origin, token):
        parsed=urlsplit(origin)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.port not in (None,443)
            or parsed.path not in ('','/') or parsed.query or parsed.fragment):
            raise ValueError('INVALID_LEDGER_ORIGIN')
        if not isinstance(token,str) or len(token)<40:
            raise ValueError('INVALID_LEDGER_TOKEN')
        self.origin=origin.rstrip('/')
        self.token=token
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def request(self, name, body, expected_status, expected_body):
        request=urllib.request.Request(
            self.origin+'/'+name, data=canonical(body),method='POST',
            headers={'Authorization':'Bearer '+self.token,
                     'Content-Type':'application/json',
                     'User-Agent':'arda-r13-github-ledger-v6/1'})
        try:
            with self.opener.open(request,timeout=10) as response:
                return response.status==expected_status and json.loads(response.read(512))==expected_body
        except (urllib.error.URLError,ValueError,TypeError,OSError):
            return False

    def reserve(self, ticket, cid, digest, expiry):
        return self.request('reserve',{'ticket':ticket,'challenge_id':cid,
            'envelope_sha256':digest,'expires_at':expiry},201,{'reserved':True})

    def claim(self,ticket,digest):
        return self.request('claim',{'ticket':ticket,'envelope_sha256':digest},200,{'claimed':True})

def review_v6(dispatch, *, ledger, private_b64, clock=time.time):
    # Reject malformed dispatch before any access to the durable ledger.
    if type(dispatch) is not dict or set(dispatch)!={'schema','ticket','challenge_id','expires_at','envelope_sha256','box'}:
        return refusal('V6_DISPATCH_FIELDS')
    if dispatch['schema']!='arda.r13.relay_dispatch.v2':
        return refusal('V6_DISPATCH_SCHEMA')
    ticket=dispatch['ticket'];cid=dispatch['challenge_id']
    expiry=dispatch['expires_at'];digest=dispatch['envelope_sha256']
    if (not isinstance(ticket,str) or not HEX48.fullmatch(ticket)
        or not isinstance(cid,str) or not HEX32.fullmatch(cid)
        or not isinstance(digest,str) or not HEX64.fullmatch(digest)
        or type(expiry) is not int):
        return refusal('V6_DISPATCH_FIELDS')
    now=int(clock())
    if expiry<=now or expiry>now+300:
        return refusal('V6_CHALLENGE_EXPIRED')
    try:
        box=dispatch['box']
        if hash_envelope(box)!=digest:
            return refusal('V6_ENVELOPE_DIGEST')
        private=unb64(private_b64)
        if len(private)!=32:
            return refusal('V6_PRIVATE_KEY_INVALID')
        plain=unseal(box,private)
        bound_id,bound_expiry=extract_fresh_challenge(plain,now)
        if bound_id!=cid or bound_expiry!=expiry:
            return refusal('V6_CHALLENGE_BINDING')
        if not synthetic_capture(plain):
            return refusal('V6_NON_SYNTHETIC_NOT_AUTHORIZED')
    except (ValueError,TypeError,KeyError,OverflowError):
        return refusal('V6_ENVELOPE_INVALID')
    except Exception:
        return refusal('V6_ENVELOPE_INVALID')

    # The global Durable Object is the sole unique-challenge arbiter.
    # Never verify/decrypt further or dispatch on inconclusive responses.
    if not ledger.reserve(ticket,cid,digest,expiry):
        return refusal('V6_LEDGER_RESERVATION_REFUSED')
    if not ledger.claim(ticket,digest):
        return refusal('V6_LEDGER_CLAIM_REFUSED')
    return refusal('SYNTHETIC_TRANSPORT_DECRYPTED_R13_NOT_VERIFIED')

def main():
    out=Path(os.environ['ARDA_RESULT_PATH'])
    try:
        dispatch=json.loads(os.environ.get('ARDA_RELAY_PAYLOAD','{}'))
        ledger=GitHubLedger(os.environ.get('ARDA_RELAY_LEDGER_URL',''),
            os.environ.get('ARDA_RELAY_LEDGER_TOKEN',''))
        outcome=review_v6(dispatch,ledger=ledger,
            private_b64=os.environ.get('ARDA_RELAY_PRIVATE_B64',''))
    except Exception:
        outcome=refusal('V6_RUNNER_NOT_CONFIGURED')
    out.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(canonical(outcome)+b'\n')
        f.flush();os.fsync(f.fileno())
    print(canonical(outcome).decode())
if __name__=='__main__':
    main()
