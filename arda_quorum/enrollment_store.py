"""Minimal fixed-host secret uploads. No redirects, retries, proxy inheritance or logs."""
import base64
import json
import re
import urllib.request
from .quorum import need,strict_load

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

class ProviderSecretStore:
    def __init__(self,provider,identity,token):
        need(provider in ('github','hf'),'secret_store_provider')
        need(type(identity) is str and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',identity),'secret_store_identity')
        need(type(token) is str and 0<len(token)<=4096 and all(33<=ord(c)<=126 for c in token),'secret_store_credential')
        self.provider=provider;self.identity=identity;self.__token=token
        self.root=('https://api.github.com/repos/'+identity+'/actions/secrets') if provider=='github' else ('https://huggingface.co/api/spaces/'+identity+'/secrets')
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def request(self,method,url,payload=None):
        need((method=='GET' and self.provider=='github' and url==self.root+'/public-key') or
             (method=='PUT' and self.provider=='github' and re.fullmatch(re.escape(self.root)+r'/ARDA_GITHUB_SIGNER_PKCS8_B64_[A-F0-9]{64}',url)) or
             (method=='POST' and self.provider=='hf' and url==self.root),'secret_store_endpoint')
        try:
            headers={'Authorization':'Bearer '+self.__token,'Accept':'application/json','User-Agent':'ARDA-PQ-enrollment-v4'}
            if self.provider=='github':headers['X-GitHub-Api-Version']='2022-11-28'
            if payload is not None:headers['Content-Type']='application/json'
            request=urllib.request.Request(url,data=json.dumps(payload).encode() if payload is not None else None,headers=headers,method=method)
            with self.opener.open(request,timeout=30) as response:
                need(200<=response.status<300,'secret_store_status')
                raw=response.read(65537);need(len(raw)<=65536,'secret_store_response_size')
            # Mutation replies may contain server details; never return them to the caller.
            return strict_load(raw) if method=='GET' else None
        except Exception:raise ValueError('PROVIDER_SECRET_STORE_REFUSED') from None
    def put(self,name,value):
        need(type(name) is str and re.fullmatch('ARDA_'+self.provider.upper()+'_SIGNER_PKCS8_B64_[A-F0-9]{64}',name),'unique_secret_name_required')
        need(type(value) is str and 0<len(value)<=32768,'secret_store_value')
        if self.provider=='hf':return self.request('POST',self.root,dict(key=name,value=value))
        from nacl.public import PublicKey,SealedBox
        key=self.request('GET',self.root+'/public-key')
        need(type(key) is dict and type(key.get('key_id')) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',key['key_id']),'github_store_key_id')
        public=base64.b64decode(key['key'],validate=True);need(len(public)==32,'github_store_public_key')
        encrypted=base64.b64encode(SealedBox(PublicKey(public)).encrypt(value.encode())).decode()
        return self.request('PUT',self.root+'/'+name,dict(encrypted_value=encrypted,key_id=key['key_id']))
