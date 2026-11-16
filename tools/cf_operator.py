#!/usr/bin/env python3
"""Explicit Cloudflare setup operations via curl; retain every public response."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

ORIGIN='https://arda-pq-release-witness.dio-workflows.workers.dev'
PATHS={'status':'/v1/enrollment-status','replace':'/v1/replace-orphaned-key','enroll':'/v1/enroll-cf'}
HEX64=re.compile(r'[0-9a-f]{64}\Z')
def need(ok,code):
    if not ok:raise ValueError(code)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def digest(raw):return hashlib.sha256(raw).hexdigest()
def strict_load(raw):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'DUPLICATE_JSON_KEY');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:need(False,'JSON_CONSTANT'))
def load_config(path,pin,*,now=None,read_only=False):
    need(type(pin) is str and HEX64.fullmatch(pin),'CONFIG_PIN_FORMAT')
    path=Path(path);need(path.stat().st_size<=16384,'CONFIG_SIZE');raw=path.read_bytes()
    need(digest(raw)==pin,'CONFIG_PIN_MISMATCH');c=strict_load(raw)
    need(raw==canonical(c) and c.get('schema')=='arda.cf.hss.enrollment_config.v1' and c.get('worker_identity')=='arda-pq-release-witness' and c.get('production_authorized') is False,'CONFIG_SCHEMA')
    ceremony=c['ceremony'];need(digest(canonical(ceremony))==c.get('ceremony_sha256'),'CEREMONY_PIN')
    issued,expires=ceremony['issued_at'],ceremony['expires_at'];current=int(time.time()) if now is None else now
    need(type(issued) is int and type(expires) is int and 0<issued<expires and expires-issued<=86400,'CEREMONY_STRUCTURE')
    need(read_only or issued<=current<expires,'CEREMONY_EXPIRED_OR_FUTURE')
    return c

def refresh_config(c,*,now=None,nonce=None):
    current=int(time.time()) if now is None else now
    nonce=os.urandom(32).hex() if nonce is None else nonce
    need(type(current) is int and current>0 and type(nonce) is str and HEX64.fullmatch(nonce),'NEW_CEREMONY_INPUT')
    fresh=strict_load(canonical(c));fresh['ceremony'].update(nonce=nonce,issued_at=current,expires_at=current+86400)
    fresh['ceremony_sha256']=digest(canonical(fresh['ceremony']));return fresh

def curl_request(path,token,body,*,address=None,runner=subprocess.run):
    need(path in PATHS.values(),'ENDPOINT_REFUSED');need(type(token) is str and HEX64.fullmatch(token),'TOKEN_FORMAT')
    command=['curl','--disable','--config','-','--noproxy','*','--ipv4','--http2','--retry','0','--silent','--show-error','--connect-timeout','15','--max-time','120','--max-filesize','65536','--user-agent','ARDA-CF-HSS-Setup-v5']
    if address:
        ip=str(ipaddress.IPv4Address(address));command+=['--resolve','arda-pq-release-witness.dio-workflows.workers.dev:443:'+ip]
    config='header = '+json.dumps('X-ARDA-Setup-Token: '+token)+'\nheader = "Accept: application/json"\n'
    if body is not None:
        command+=['--request','POST'];config+='header = "Content-Type: application/json"\ndata-binary = '+json.dumps(canonical(body).decode('ascii'))+'\n'
    command+=['--write-out','\nARDA_META:%{http_code}|%{remote_ip}|%{http_version}\n',ORIGIN+path]
    try:
        env={key:value for key,value in os.environ.items() if not (key.upper().endswith('_PROXY') or key in ('CURL_HOME','CURL_CA_BUNDLE','SSL_CERT_FILE','SSL_CERT_DIR','SSLKEYLOGFILE'))}
        result=runner(command,input=config.encode(),capture_output=True,timeout=130,env=env)
        raw=result.stdout;code=result.returncode
    except subprocess.TimeoutExpired as e:raw=e.stdout or b'';code=124
    response,separator,metadata=raw.rpartition(b'\nARDA_META:')
    if not separator:return {'http_status':0,'remote_ip':None,'http_version':None,'exit_code':code,'body':raw}
    try:
        status,ip,version=metadata.decode('ascii').strip().split('|');need(status.isdigit(),'TRANSPORT_METADATA')
        return {'http_status':int(status),'remote_ip':ip,'http_version':version,'exit_code':code,'body':response}
    except (ValueError,UnicodeError):return {'http_status':0,'remote_ip':None,'http_version':None,'exit_code':code,'body':raw}

def save_response(path,raw):
    with Path(path).open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
def closed(body):need(type(body) is dict and body.get('production_authorized') is False and body.get('interlock')=='KEEP_CLOSED','RESPONSE_AUTHORITY')
def verify_receipt(body,request,configuration=None,*,now=None):
    closed(body);r=body['receipt']
    fields={'schema','rotation_request_sha256','retired_key_sha256','replacement_key_sha256','old_ceremony_sha256','ceremony_sha256','retired_next_leaf','replacement_next_leaf','prior_burn_ref','prior_burn_tag_sha','issued_at','production_authorized','interlock'}
    need(type(r) is dict and r.keys()==fields,'ROTATION_RECEIPT_FIELDS')
    need(type(configuration) is dict and configuration.get('ceremony_sha256')==request['ceremony_sha256'] and request.get('config_sha256')==digest(canonical(configuration)),'ROTATION_RECEIPT_CONFIG')
    need(r['schema']=='arda.cf.hss.rotation_receipt.v1' and r['rotation_request_sha256']==digest(canonical(request)) and body.get('receipt_sha256')==digest(canonical(r)),'ROTATION_RECEIPT_PIN')
    need(r['retired_key_sha256']==request['expected_key_sha256'] and r['ceremony_sha256']==request['ceremony_sha256'] and type(r['replacement_key_sha256']) is str and HEX64.fullmatch(r['replacement_key_sha256']) and r['replacement_key_sha256']!=r['retired_key_sha256'] and type(r['retired_next_leaf']) is int and r['retired_next_leaf']==1 and type(r['replacement_next_leaf']) is int and r['replacement_next_leaf']==0,'ROTATION_RECEIPT_BINDING')
    need(r['old_ceremony_sha256']==digest(canonical(request['old_ceremony'])) and r['prior_burn_tag_sha']==request['prior_tag_sha'] and r['prior_burn_ref']=='refs/tags/arda-hss-leaf-'+request['expected_key_sha256']+'-0000','ROTATION_RECEIPT_HISTORY')
    current=int(time.time()) if now is None else now;ceremony=configuration['ceremony']
    need(type(r['issued_at']) is int and ceremony['issued_at']<=r['issued_at']<ceremony['expires_at'] and r['issued_at']<=current,'ROTATION_RECEIPT_TIME')
    closed(r);return r

DOCKER_CHECK="""import json,sys,time,os,subprocess
from pathlib import Path
from arda_quorum.crypto import Backends
from arda_quorum.enrollment import check_ceremony,check_record
from arda_quorum.quorum import strict_load,sha,canonical,need
raw=Path('/review/config.json').read_bytes();need(sha(raw)==sys.argv[1],'operator_config_pin')
c=strict_load(raw);need(raw==canonical(c),'canonical_config');check_ceremony(c['ceremony'],int(time.time()))
backend=Backends()
if len(sys.argv)>2:
 body=strict_load(Path('/review/response.json').read_bytes())
 need(body.get('production_authorized') is False and body.get('interlock')=='KEEP_CLOSED','closed_response')
 record=body['registration'];need(record.get('payload',{}).get('provider')=='cloudflare','provider')
 check_record(record,c['ceremony'],now=int(time.time()),backends=backend)
 print(json.dumps({'verified':True,'record':record},sort_keys=True,separators=(',',':')))
else:
 probe=subprocess.run([str(backend.hss)],stdin=subprocess.DEVNULL,capture_output=True,timeout=10,env={'PATH':os.defpath,'OPENSSL_CONF':'/dev/null'})
 need(probe.returncode==2,'native_verifier_exec')
 print('{"ready":true}')
"""
def docker_image(image,expected):
    need(type(expected) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',expected),'VERIFIER_IMAGE_PIN_REQUIRED')
    result=subprocess.run(['docker','image','inspect','--format','{{.Id}}',image],capture_output=True,text=True,timeout=30)
    need(result.returncode==0 and result.stdout.strip()==expected,'VERIFIER_IMAGE_PIN_MISMATCH');return expected

def offline_check(image,config,pin,response=None):
    paths=[Path(config).resolve()]+([Path(response).resolve()] if response else [])
    need(all(',' not in str(p) and '\n' not in str(p) for p in paths),'REVIEW_MOUNT_PATH')
    command=['docker','run','--rm','--pull=never','--network','none','--read-only','--user',f'{os.getuid()}:{os.getgid()}','--tmpfs','/tmp:rw,nosuid,nodev,size=64m']
    command+=['--mount',f'type=bind,src={paths[0]},dst=/review/config.json,readonly']
    if response:command+=['--mount',f'type=bind,src={paths[1]},dst=/review/response.json,readonly']
    command+=['--entrypoint','python3',image,'-c',DOCKER_CHECK,pin]+(['verify'] if response else [])
    result=subprocess.run(command,capture_output=True,text=True,timeout=60)
    need(result.returncode==0,'NATIVE_VERIFIER_REFUSED_RESPONSE_RETAINED')
    return strict_load(result.stdout)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=('prepare',*PATHS))
    for name in ('config','config-sha256','output-parent'):p.add_argument('--'+name,required=True)
    p.add_argument('--token-file');p.add_argument('--old-config');p.add_argument('--old-config-sha256');p.add_argument('--expected-key-sha256');p.add_argument('--prior-tag-sha');p.add_argument('--address')
    p.add_argument('--verifier-image',default='arda-pq-witness:v5-candidate');p.add_argument('--verifier-image-id')
    a=p.parse_args();directory=None
    try:
        c=load_config(a.config,a.config_sha256,read_only=a.operation in ('status','prepare'))
        if a.operation=='prepare':
            parent=Path(a.output_parent).resolve();need(parent.is_dir(),'OUTPUT_PARENT_REQUIRED')
            fresh=refresh_config(c);directory=Path(tempfile.mkdtemp(prefix='cf-fresh-ceremony.',dir=parent))
            files={'original-cf-config.json':canonical(c),'original-cf-config.sha256':(a.config_sha256+'\n').encode(),'ceremony.json':canonical(fresh['ceremony']),'cf-config.json':canonical(fresh),'cf-config.sha256':(digest(canonical(fresh))+'\n').encode(),'cf-public-vars.json':canonical({'ARDA_CF_CONFIG_JSON':canonical(fresh).decode(),'ARDA_CF_CONFIG_SHA256':digest(canonical(fresh))})}
            for name,raw in files.items():save_response(directory/name,raw)
            print('CF_FRESH_DIR='+str(directory));print('CEREMONY_SHA256='+fresh['ceremony_sha256']);print('CF_CONFIG_SHA256='+digest(canonical(fresh)));print('CEREMONY_EXPIRES='+str(fresh['ceremony']['expires_at']));print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
        need(a.token_file is not None,'TOKEN_FILE_REQUIRED')
        token_path=Path(a.token_file);need(token_path.stat().st_size<=128,'TOKEN_FILE_SIZE');token=token_path.read_text().strip();need(HEX64.fullmatch(token),'TOKEN_FORMAT')
        body=None;image=None
        if a.operation=='replace':
            need(type(a.expected_key_sha256) is str and HEX64.fullmatch(a.expected_key_sha256) and type(a.prior_tag_sha) is str and re.fullmatch('[0-9a-f]{40}',a.prior_tag_sha),'REPLACEMENT_PINS_REQUIRED')
            old=load_config(a.old_config or a.config,a.old_config_sha256 or a.config_sha256,read_only=True)
            body={'action':'replace_orphaned_cloudflare_key','ceremony_sha256':c['ceremony_sha256'],'config_sha256':a.config_sha256,'expected_key_sha256':a.expected_key_sha256,'expected_next_leaf':1,'old_ceremony':old['ceremony'],'prior_tag_sha':a.prior_tag_sha}
        elif a.operation=='enroll':
            image=docker_image(a.verifier_image,a.verifier_image_id);offline_check(image,a.config,a.config_sha256)
            body={'action':'provision_cloudflare_key','ceremony_sha256':c['ceremony_sha256']}
        parent=Path(a.output_parent).resolve();need(parent.is_dir(),'OUTPUT_PARENT_REQUIRED')
        directory=Path(tempfile.mkdtemp(prefix='cf-'+a.operation+'.',dir=parent));print('PUBLIC_OUTPUT_DIR='+str(directory),flush=True)
        save_response(directory/'request.json',canonical({'operation':a.operation,'body':body,'config_sha256':a.config_sha256}))
        response_path=directory/'response.json'
        with response_path.open('xb') as stream:
            result=curl_request(PATHS[a.operation],token,body,address=a.address)
            stream.write(result['body']);stream.flush();os.fsync(stream.fileno())
        metadata={k:v for k,v in result.items() if k!='body'};save_response(directory/'transport.json',canonical(metadata));print(json.dumps(metadata,sort_keys=True))
        need(result['exit_code']==0 and result['http_status']==200,'HTTP_REFUSED_RESPONSE_RETAINED')
        need(result['http_version']=='2','HTTP2_REQUIRED_RESPONSE_RETAINED')
        response=strict_load(result['body']);closed(response)
        if a.operation=='status':print(json.dumps(response,indent=2))
        elif a.operation=='replace':
            receipt=verify_receipt(response,body,c);save_response(directory/'rotation-receipt.json',canonical(receipt));print('RETIRED_KEY_SHA256='+receipt['retired_key_sha256']);print('REPLACEMENT_KEY_SHA256='+receipt['replacement_key_sha256']);print('ROTATION_RECEIPT_SHA256='+digest(canonical(receipt)))
        else:
            verified=offline_check(image,a.config,a.config_sha256,response_path);need(verified.get('verified') is True,'NATIVE_VERIFICATION')
            record=verified['record'];save_response(directory/'cloudflare-registration.json',canonical(record));print('PUBLIC_REGISTRATION_SHA256='+digest(canonical(record)));print('KEY_SHA256='+record['payload']['key_sha256'])
        print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
    except Exception as error:
        code=str(error) if isinstance(error,ValueError) and re.fullmatch('[A-Z_]{1,80}',str(error)) else type(error).__name__
        print('CF_OPERATOR_REFUSED='+code)
        if directory:print('PUBLIC_OUTPUT_RETAINED='+str(directory))
        print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 1
if __name__=='__main__':raise SystemExit(main())
