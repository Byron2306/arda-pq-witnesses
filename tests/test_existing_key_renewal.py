"""Catch key substitution, ceremony replay, provisioning and unauthenticated signing."""
import base64,copy,http.client,importlib.util,json,os,subprocess,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from arda_quorum import enrollment as e
from arda_quorum.crypto import Backends
from arda_quorum.provider_witness import OpenSSLSigner
from arda_quorum.quorum import canonical,sha
ROOT=Path(__file__).resolve().parents[1]
class ExistingKeyRenewalTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.keys={p:e.generate_private(a) for p,a in [('github','ML-DSA-65'),('hf','SLH-DSA-SHA2-192s')]}
  cls.pins={p:sha(OpenSSLSigner(a,cls.keys[p]).public) for p,a in [('github','ML-DSA-65'),('hf','SLH-DSA-SHA2-192s')]};cls.backends=Backends()
 def setUp(self):
  path=ROOT/'tools/renew_existing.py';self.assertTrue(path.exists(),'existing-key renewal overlay is missing')
  spec=importlib.util.spec_from_file_location('renew_existing',path);self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
  self.c=e.new_ceremony(nonce='ab'*32,image_digest='sha256:'+'cd'*32,identities={'github':'Byron2306/arda-pq-witnesses','hf':'Byron230686/arda-pq-policy-witness','cloudflare':'arda-pq-release-witness'},now=1000);self.now=1000
 def env(self,p):
  return {'ARDA_ALLOW_EXISTING_KEY_RENEWAL':sha(canonical(self.c)),'ARDA_IMAGE_DIGEST':self.c['image_digest'],'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':self.c['identities']['github'],'SPACE_ID':self.c['identities']['hf'],e.secret_name(p,self.pins[p]):base64.b64encode(self.keys[p]).decode()}
 def session(self,p='hf',env=None,pin=None):
  return self.m.Renewal(canonical(self.c),sha(canonical(self.c)),p,pin or self.pins[p],self.env(p) if env is None else env,clock=lambda:self.now)
 def test_renewal_keeps_real_keys_and_signs_new_ceremony(self):
  for p in ('github','hf'):
   with patch.object(e,'generate_private',side_effect=AssertionError('no key generation')),patch.object(e,'provision',side_effect=AssertionError('no provisioning')):record=self.session(p).trigger()
   verified=e.check_record(record,self.c,now=1000,backends=self.backends);self.assertEqual(verified['key_sha256'],self.pins[p]);self.assertEqual(record['payload']['ceremony_sha256'],sha(canonical(self.c)))
   self.assertNotIn(base64.b64encode(self.keys[p]).decode(),canonical(record).decode());old=copy.deepcopy(self.c);old['nonce']='ef'*32
   with self.assertRaises(ValueError):e.check_record(record,old,now=1000,backends=self.backends)
 def test_wrong_key_is_refused_before_signing(self):
  env=self.env('hf');env[e.secret_name('hf','11'*32)]=base64.b64encode(self.keys['hf']).decode()
  with patch.object(OpenSSLSigner,'sign',side_effect=AssertionError('must not sign')):
   with self.assertRaisesRegex(ValueError,'EXISTING_KEY_RENEWAL_REFUSED'):self.session(env=env,pin='11'*32).trigger()
 def test_missing_named_key_does_not_fall_back_to_alias(self):
  env=self.env('hf');env['ARDA_HF_SIGNER_PKCS8_B64']=env.pop(e.secret_name('hf',self.pins['hf']))
  with self.assertRaises(ValueError):self.session(env=env).trigger()
 def test_conflicting_alias_and_noncanonical_base64_refused(self):
  for mutate in (lambda v:v.update(ARDA_HF_SIGNER_PKCS8_B64='different'),lambda v:v.update({e.secret_name('hf',self.pins['hf']):v[e.secret_name('hf',self.pins['hf'])]+'\n'})):
   env=self.env('hf');mutate(env)
   with self.assertRaises(ValueError):self.session(env=env).trigger()
 def test_wrong_identity_image_enable_pin_and_expiry_refused(self):
  for p,field in [('github','GITHUB_REPOSITORY'),('github','GITHUB_ACTIONS'),('hf','SPACE_ID'),('hf','ARDA_IMAGE_DIGEST'),('hf','ARDA_ALLOW_EXISTING_KEY_RENEWAL')]:
   env=self.env(p);env[field]='wrong'
   with self.assertRaises(ValueError):self.session(p,env=env).trigger()
  self.now=self.c['expires_at']
  with self.assertRaises(ValueError):self.session().trigger()
 def test_noncanonical_ceremony_and_wrong_ceremony_pin_refused(self):
  for raw,pin in [(canonical(self.c)+b'\n',sha(canonical(self.c)+b'\n')),(canonical(self.c),'11'*32)]:
   with self.assertRaises(ValueError):self.m.Renewal(raw,pin,'hf',self.pins['hf'],self.env('hf'),clock=lambda:1000)
 def test_cache_is_public_defensive_copy_and_expires(self):
  session=self.session();first=session.trigger();self.assertEqual(first,session.trigger());first['payload']['key_sha256']='00'*32
  self.assertEqual(session.trigger()['payload']['key_sha256'],self.pins['hf']);self.now=self.c['expires_at']
  with self.assertRaises(ValueError):session.trigger()
 def test_expiry_during_signing_never_releases_registration(self):
  session=self.session();original=OpenSSLSigner.sign
  def late(s,message):
   result=original(s,message);self.now=self.c['expires_at'];return result
  with patch.object(OpenSSLSigner,'sign',late):
   with self.assertRaises(ValueError):session.trigger()
  self.assertEqual(session.state,'FAILED');self.assertIsNone(session.record)
 def test_http_requires_auth_exact_action_and_key_and_never_serves_votes(self):
  session=self.session();server=self.m.make_server(session,'aa'*32,host='127.0.0.1',port=0);thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.01},daemon=True);thread.start()
  def request(path,body=None,token='aa'*32):
   client=http.client.HTTPConnection(*server.server_address,timeout=20)
   try:
    client.request('GET' if body is None else 'POST',path,body=body,headers={'X-ARDA-Setup-Token':token,'Content-Type':'application/json'});res=client.getresponse();return res.status,json.loads(res.read())
   finally:client.close()
  body=canonical(dict(action='renew_hf_registration',ceremony_sha256=sha(canonical(self.c)),key_sha256=self.pins['hf']))
  try:
   self.assertEqual(request('/v1/renew-hf',body,token='bb'*32)[0],401);self.assertEqual(session.state,'WAITING');self.assertEqual(request('/v1/enroll-hf',body)[0],404)
   bad=json.loads(body);bad['action']='provision_hf_key';self.assertEqual(request('/v1/renew-hf',canonical(bad))[0],400);self.assertEqual(session.state,'WAITING')
   bad=json.loads(body);bad['key_sha256']='11'*32;self.assertEqual(request('/v1/renew-hf',canonical(bad))[0],400)
   code,data=request('/v1/renew-hf',body);self.assertEqual(code,200,data);e.check_record(data['registration'],self.c,now=1000,backends=self.backends)
   self.assertFalse(data['production_authorized']);self.assertEqual(data['interlock'],'KEEP_CLOSED');self.assertEqual(request('/v1/review-vote',body)[0],404)
   self.now=self.c['expires_at'];self.assertEqual(request('/v1/renew-hf',body)[0],409)
  finally:server.shutdown();server.server_close();thread.join(2)
 def test_cli_renewal_outputs_only_public_record_exclusive_file(self):
  self.c=e.new_ceremony(nonce='ab'*32,image_digest='sha256:'+'cd'*32,identities=self.c['identities'],now=int(time.time()))
  with tempfile.TemporaryDirectory() as directory:
   c=Path(directory)/'ceremony.json';c.write_bytes(canonical(self.c));out=Path(directory)/'github.json';args=['python3',str(ROOT/'tools/renew_existing.py'),'github','--ceremony',str(c),'--ceremony-sha256',sha(canonical(self.c)),'--expected-key-sha256',self.pins['github'],'--out',str(out)];env=dict(os.environ,**self.env('github'))
   run=subprocess.run(args,capture_output=True,text=True,env=env,timeout=30);self.assertEqual(run.returncode,0,run.stdout+run.stderr);record=json.loads(out.read_bytes());e.check_record(record,self.c,now=int(time.time()),backends=self.backends);self.assertEqual(out.stat().st_mode&0o777,0o600)
   again=subprocess.run(args,capture_output=True,text=True,env=env,timeout=30);self.assertNotEqual(again.returncode,0);self.assertNotIn(env[e.secret_name('github',self.pins['github'])],run.stdout+run.stderr+again.stdout+again.stderr)

 def test_hf_client_verifies_authority_provider_and_expected_existing_key(self):
  record=self.session().trigger();body=dict(registration=record,production_authorized=False,interlock='KEEP_CLOSED')
  self.assertEqual(self.m.verify_hf_response(canonical(body),self.c,self.pins['hf'],now=1000),canonical(record))
  for field,value in [('production_authorized',True),('interlock','OPEN')]:
   bad=copy.deepcopy(body);bad[field]=value
   with self.assertRaises(ValueError):self.m.verify_hf_response(canonical(bad),self.c,self.pins['hf'],now=1000)
  with self.assertRaises(ValueError):self.m.verify_hf_response(canonical(body),self.c,'11'*32,now=1000)
  wrong=dict(body,registration=self.session('github').trigger())
  with self.assertRaises(ValueError):self.m.verify_hf_response(canonical(wrong),self.c,self.pins['github'],now=1000)
 def test_startup_refusal_reports_only_a_fixed_diagnostic_stage(self):
  env=self.env('hf');env.pop(e.secret_name('hf',self.pins['hf']))
  with self.assertRaises(ValueError) as error:self.session(env=env)
  self.assertEqual(getattr(error.exception,'stage',None),'EXISTING_NAMED_SECRET')
  self.assertEqual(str(error.exception),'EXISTING_KEY_RENEWAL_REFUSED')
 def test_hf_startup_log_identifies_missing_client_token_without_secrets(self):
  self.c=e.new_ceremony(nonce='ab'*32,image_digest='sha256:'+'cd'*32,identities=self.c['identities'],now=int(time.time()))
  env=dict(os.environ,**self.env('hf'),ARDA_RENEWAL_CEREMONY_JSON=canonical(self.c).decode(),ARDA_RENEWAL_EXPECTED_KEY_SHA256=self.pins['hf'])
  env.pop('ARDA_HF_SETUP_CLIENT_TOKEN',None)
  run=subprocess.run(['python3',str(ROOT/'tools/renew_existing.py'),'hf-server'],env=env,capture_output=True,text=True,timeout=30)
  self.assertNotEqual(run.returncode,0)
  self.assertIn('HF_STARTUP_CHECK=HF_CLIENT_TOKEN',run.stderr)
  self.assertNotIn(env[e.secret_name('hf',self.pins['hf'])],run.stdout+run.stderr)
