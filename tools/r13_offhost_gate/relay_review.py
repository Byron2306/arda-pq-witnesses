"""GitHub one-time relay claim, decryption and R13 verification. No Phase4 authority."""
import json
import os
from pathlib import Path
import sys
import urllib.request
import urllib.error

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/r13_offhost_gate'))
sys.path.insert(0,str(ROOT/'providers/hf/r13-relay'))
from verify_capture import verify_capture, result as refusal
from crypto_box import unb64, unseal, hash_envelope, canonical
from synthetic_lane import synthetic_capture

def review(dispatch, *, token, recipient_private_b64, endpoint, node_id, verifier_id):
    if not token or not endpoint or not node_id or not verifier_id or not recipient_private_b64:
        return refusal('RELAY_RUNNER_NOT_CONFIGURED')
    if type(dispatch) is not dict or set(dispatch)!={'schema','ticket','envelope_sha256','box'} or dispatch['schema']!='arda.r13.relay_dispatch.v1':
        return refusal('RELAY_DISPATCH_FIELDS')
    box=dispatch['box'];ticket=dispatch['ticket'];digest=dispatch['envelope_sha256']
    try:
        valid_digest=(isinstance(digest,str) and hash_envelope(box)==digest)
    except (TypeError,ValueError,OverflowError):valid_digest=False
    if not valid_digest:return refusal('RELAY_ENVELOPE_DIGEST')
    if not endpoint.startswith('https://') or '?' in endpoint or '#' in endpoint or endpoint.endswith('/'):
        return refusal('RELAY_ENDPOINT_CONFIGURATION')
    data=canonical({'ticket':ticket,'envelope_sha256':digest})
    request=urllib.request.Request(endpoint+'/v1/claim',data=data,
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(request,timeout=10) as response:
            confirmation=json.loads(response.read(256))
            if response.status!=200 or confirmation!={'claimed':True}:
                return refusal('RELAY_CLAIM_REFUSED')
    except (urllib.error.URLError,ValueError,OSError):
        return refusal('RELAY_CLAIM_REFUSED')
    try:
        private=unb64(recipient_private_b64)
        if len(private)!=32:raise ValueError('KEY_LENGTH')
        plain=unseal(box,private)
        if synthetic_capture(plain):
            return refusal('SYNTHETIC_TRANSPORT_DECRYPTED_R13_NOT_VERIFIED')
        return verify_capture(plain,node_id=node_id,verifier_id=verifier_id)
    except Exception:
        return refusal('RELAY_DECRYPT_OR_R13_VERIFICATION_FAILED')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None

def main():
    out=Path(os.environ['ARDA_RESULT_PATH'])
    try:
        dispatch=json.loads(os.environ.get('ARDA_RELAY_PAYLOAD','{}'))
        result=review(dispatch,token=os.environ.get('ARDA_RELAY_CLAIM_TOKEN',''),
            recipient_private_b64=os.environ.get('ARDA_RELAY_PRIVATE_B64',''),
            endpoint=os.environ.get('ARDA_RELAY_BASE_URL',''),
            node_id=os.environ.get('ARDA_R13_NODE_ID',''),
            verifier_id=os.environ.get('ARDA_R13_VERIFIER_ID',''))
    except (ValueError,KeyError,TypeError):
        result=refusal('RELAY_INPUT_INVALID')
    out.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(canonical(result)+b'\n');f.flush();os.fsync(f.fileno())
    print(canonical(result).decode())
if __name__=='__main__':main()
