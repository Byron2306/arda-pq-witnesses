import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.cf_operator import canonical, load_config, curl_request, save_response, verify_receipt

class OperatorTests(unittest.TestCase):
    def test_transport_keeps_credentials_off_argv_and_disables_proxy_redirect_retry(self):
        calls=[]
        def runner(command,**kwargs):
            calls.append((command,kwargs))
            return subprocess.CompletedProcess(command,0,b'{"production_authorized":false}\nARDA_META:200|172.67.221.27|2\n',b'')
        token='ab'*32
        result=curl_request('/v1/enrollment-status',token,None,runner=runner)
        command,kwargs=calls[0]
        self.assertNotIn(token,' '.join(command))
        self.assertIn(token,kwargs['input'].decode())
        self.assertIn('--http2',command);self.assertIn('--ipv4',command)
        self.assertIn('--noproxy',command);self.assertNotIn('--location',command)
        self.assertEqual(command[command.index('--retry')+1],'0')
        self.assertEqual(result['http_status'],200)
        self.assertEqual(result['http_version'],'2')
    def test_post_body_is_canonical_and_not_a_shell_command(self):
        calls=[]
        def runner(command,**kwargs):
            calls.append((command,kwargs));return subprocess.CompletedProcess(command,0,b'{}\nARDA_META:409|1.2.3.4|2\n',b'')
        curl_request('/v1/enroll-cf','ab'*32,{'z':1,'a':'value'},runner=runner)
        command,kwargs=calls[0];self.assertNotIn('shell',kwargs)
        self.assertIn('data-binary = "{\\"a\\":\\"value\\",\\"z\\":1}"',kwargs['input'].decode())
    def test_invalid_token_and_endpoint_refuse_before_transport(self):
        def runner(*a,**k):raise AssertionError('network must not run')
        for path,token in [('/arbitrary','ab'*32),('/v1/enroll-cf','not-a-token')]:
            with self.assertRaises(ValueError):curl_request(path,token,None,runner=runner)
    def test_failed_http_response_is_preserved_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'response.json';save_response(p,b'{"error":"failure"}')
            self.assertEqual(p.read_bytes(),b'{"error":"failure"}')
            with self.assertRaises(FileExistsError):save_response(p,b'changed')
    def test_expired_config_refuses_mutation_but_allows_read_only_inspection(self):
        c={'schema':'arda.cf.hss.enrollment_config.v1','worker_identity':'arda-pq-release-witness','production_authorized':False,'ceremony':{'issued_at':100,'expires_at':200},'ceremony_sha256':''}
        import hashlib
        c['ceremony_sha256']=hashlib.sha256(canonical(c['ceremony'])).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'config.json';raw=canonical(c);p.write_bytes(raw);pin=hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):load_config(p,pin,now=300)
            self.assertEqual(load_config(p,pin,now=300,read_only=True),c)
            with self.assertRaises(ValueError):load_config(p,'00'*32,now=150)
    def test_rotation_receipt_requires_exact_request_and_old_key(self):
        import hashlib
        configuration={'ceremony_sha256':'cd'*32,'ceremony':{'issued_at':100,'expires_at':200}}
        request={'expected_key_sha256':'ab'*32,'ceremony_sha256':'cd'*32,'old_ceremony':{'issued_at':1,'expires_at':100},'prior_tag_sha':'12'*20,'config_sha256':hashlib.sha256(canonical(configuration)).hexdigest()}
        receipt={'schema':'arda.cf.hss.rotation_receipt.v1','rotation_request_sha256':hashlib.sha256(canonical(request)).hexdigest(),'retired_key_sha256':'ab'*32,'replacement_key_sha256':'ef'*32,'ceremony_sha256':'cd'*32,'old_ceremony_sha256':hashlib.sha256(canonical(request['old_ceremony'])).hexdigest(),'prior_burn_ref':'refs/tags/arda-hss-leaf-'+'ab'*32+'-0000','prior_burn_tag_sha':'12'*20,'issued_at':150,'retired_next_leaf':1,'replacement_next_leaf':0,'production_authorized':False,'interlock':'KEEP_CLOSED'}
        body={'receipt':receipt,'receipt_sha256':hashlib.sha256(canonical(receipt)).hexdigest(),'production_authorized':False,'interlock':'KEEP_CLOSED'}
        self.assertEqual(verify_receipt(body,request,configuration,now=160),receipt)
        with self.assertRaises(ValueError):verify_receipt(body,{**request,'expected_key_sha256':'00'*32},configuration,now=160)
        for change in ({'old_ceremony_sha256':'00'*32},{'prior_burn_ref':'refs/tags/wrong'},{'prior_burn_tag_sha':'00'*20},{'issued_at':201}):
            altered={**receipt,**change};bad={**body,'receipt':altered,'receipt_sha256':hashlib.sha256(canonical(altered)).hexdigest()}
            with self.assertRaises(ValueError):verify_receipt(bad,request,configuration,now=250)
    def test_refresh_creates_new_ceremony_without_editing_old_pins_or_provider_keys(self):
        from tools.cf_operator import refresh_config
        import hashlib
        c={'schema':'arda.cf.hss.enrollment_config.v1','worker_identity':'arda-pq-release-witness','production_authorized':False,'anchor':{'unchanged':True},'wasm_sha256':'aa'*32,'ceremony':{'issued_at':100,'expires_at':200,'nonce':'bb'*32,'image_digest':'sha256:'+'cc'*32,'identities':{'github':'g','hf':'h','cloudflare':'c'},'production_authorized':False},'ceremony_sha256':''}
        c['ceremony_sha256']=hashlib.sha256(canonical(c['ceremony'])).hexdigest()
        before=canonical(c);fresh=refresh_config(c,now=300,nonce='dd'*32)
        self.assertEqual(canonical(c),before);self.assertEqual(fresh['ceremony']['issued_at'],300);self.assertEqual(fresh['ceremony']['expires_at'],86700)
        self.assertEqual(fresh['ceremony']['image_digest'],c['ceremony']['image_digest']);self.assertEqual(fresh['anchor'],c['anchor']);self.assertEqual(fresh['wasm_sha256'],c['wasm_sha256'])
        self.assertNotEqual(fresh['ceremony_sha256'],c['ceremony_sha256']);self.assertFalse(fresh['production_authorized'])
    def test_curl_ignores_inherited_config_and_tls_key_logging(self):
        from unittest.mock import patch
        captured={}
        def runner(command,**kwargs):
            captured.update(command=command,kwargs=kwargs);return subprocess.CompletedProcess(command,0,b'{}\nARDA_META:200|1.2.3.4|2\n',b'')
        with patch.dict('os.environ',{'CURL_HOME':'/tmp/untrusted','SSLKEYLOGFILE':'/tmp/keys','HTTPS_PROXY':'http://proxy.invalid'}):
            curl_request('/v1/enrollment-status','ab'*32,None,runner=runner)
        self.assertEqual(captured['command'][1],'--disable')
        for key in ('CURL_HOME','SSLKEYLOGFILE','HTTPS_PROXY'):self.assertNotIn(key,captured['kwargs']['env'])
    def test_receipt_cannot_omit_historical_bindings_even_when_self_hash_matches(self):
        import hashlib
        request={'expected_key_sha256':'ab'*32,'ceremony_sha256':'cd'*32,'old_ceremony':{'issued_at':1,'expires_at':100},'prior_tag_sha':'12'*20}
        receipt={'schema':'arda.cf.hss.rotation_receipt.v1','rotation_request_sha256':hashlib.sha256(canonical(request)).hexdigest(),'retired_key_sha256':'ab'*32,'replacement_key_sha256':'ef'*32,'ceremony_sha256':'cd'*32,'retired_next_leaf':1,'replacement_next_leaf':0,'production_authorized':False,'interlock':'KEEP_CLOSED'}
        body={'receipt':receipt,'receipt_sha256':hashlib.sha256(canonical(receipt)).hexdigest(),'production_authorized':False,'interlock':'KEEP_CLOSED'}
        with self.assertRaises(ValueError):verify_receipt(body,request)
    def test_main_preserves_response_when_native_verification_fails_after_http(self):
        import contextlib, hashlib, io, sys
        from unittest.mock import patch
        from tools.cf_operator import main
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);c={'schema':'arda.cf.hss.enrollment_config.v1','worker_identity':'arda-pq-release-witness','production_authorized':False,'ceremony':{'issued_at':900,'expires_at':2000},'ceremony_sha256':''}
            c['ceremony_sha256']=hashlib.sha256(canonical(c['ceremony'])).hexdigest();raw=canonical(c);(root/'config.json').write_bytes(raw);(root/'token').write_text('ab'*32);(root/'proof.json').write_text('{}')
            response=b'{"production_authorized":false,"interlock":"KEEP_CLOSED","registration":{"public":"candidate"}}'
            args=['cf_operator.py','enroll','--config',str(root/'config.json'),'--config-sha256',hashlib.sha256(raw).hexdigest(),'--token-file',str(root/'token'),'--output-parent',str(root),'--verifier-image-id','sha256:'+'12'*32]
            with patch.object(sys,'argv',args),patch('tools.cf_operator.time.time',return_value=1000),patch('tools.cf_operator.docker_image',return_value='sha256:'+'12'*32),patch('tools.cf_operator.offline_check',side_effect=[{'ready':True},ValueError('NATIVE_VERIFIER_REFUSED_RESPONSE_RETAINED')]),patch('tools.cf_operator.curl_request',return_value={'body':response,'http_status':200,'http_version':'2','remote_ip':'1.2.3.4','exit_code':0}),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(),1)
            outputs=list(root.glob('cf-enroll.*/response.json'));self.assertEqual(len(outputs),1);self.assertEqual(outputs[0].read_bytes(),response)
    def test_main_never_posts_when_native_preflight_fails(self):
        import contextlib, hashlib, io, sys
        from unittest.mock import patch
        from tools.cf_operator import main
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);c={'schema':'arda.cf.hss.enrollment_config.v1','worker_identity':'arda-pq-release-witness','production_authorized':False,'ceremony':{'issued_at':900,'expires_at':2000},'ceremony_sha256':''}
            c['ceremony_sha256']=hashlib.sha256(canonical(c['ceremony'])).hexdigest();raw=canonical(c);(root/'config.json').write_bytes(raw);(root/'token').write_text('ab'*32)
            args=['cf_operator.py','enroll','--config',str(root/'config.json'),'--config-sha256',hashlib.sha256(raw).hexdigest(),'--token-file',str(root/'token'),'--output-parent',str(root),'--verifier-image-id','sha256:'+'12'*32]
            with patch.object(sys,'argv',args),patch('tools.cf_operator.time.time',return_value=1000),patch('tools.cf_operator.docker_image',return_value='sha256:'+'12'*32),patch('tools.cf_operator.offline_check',side_effect=ValueError('PREFLIGHT_FAILED')),patch('tools.cf_operator.curl_request') as transport,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(),1);transport.assert_not_called()
    def test_docker_preflight_executes_native_verifier_before_accepting_readiness(self):
        import contextlib, hashlib, io, sys
        from unittest.mock import patch, Mock
        from tools.cf_operator import DOCKER_CHECK
        ceremony={'schema':'arda.pq.enrollment_ceremony.v1','nonce':'ab'*32,'image_digest':'sha256:'+'cd'*32,'identities':{'github':'Byron2306/arda-pq-witnesses','hf':'Byron230686/arda-pq-policy-witness','cloudflare':'arda-pq-release-witness'},'issued_at':900,'expires_at':2000,'production_authorized':False}
        raw=canonical({'ceremony':ceremony});backend=Mock();backend.hss=Path('/fixture/hss-verify')
        with patch.object(sys,'argv',['check',hashlib.sha256(raw).hexdigest()]),patch('pathlib.Path.read_bytes',return_value=raw),patch('time.time',return_value=1000),patch('arda_quorum.crypto.Backends',return_value=backend),patch('subprocess.run',return_value=subprocess.CompletedProcess([],126,b'',b'')),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError,'native_verifier_exec'):exec(DOCKER_CHECK,{})
    def test_main_retains_http_one_response_but_does_not_report_success(self):
        import contextlib, hashlib, io, sys
        from unittest.mock import patch
        from tools.cf_operator import main
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);c={'schema':'arda.cf.hss.enrollment_config.v1','worker_identity':'arda-pq-release-witness','production_authorized':False,'ceremony':{'issued_at':900,'expires_at':2000},'ceremony_sha256':''}
            c['ceremony_sha256']=hashlib.sha256(canonical(c['ceremony'])).hexdigest();raw=canonical(c);(root/'config.json').write_bytes(raw);(root/'token').write_text('ab'*32)
            response=b'{"production_authorized":false,"interlock":"KEEP_CLOSED"}'
            args=['cf_operator.py','status','--config',str(root/'config.json'),'--config-sha256',hashlib.sha256(raw).hexdigest(),'--token-file',str(root/'token'),'--output-parent',str(root)]
            with patch.object(sys,'argv',args),patch('tools.cf_operator.time.time',return_value=1000),patch('tools.cf_operator.curl_request',return_value={'body':response,'http_status':200,'http_version':'1.1','remote_ip':'1.2.3.4','exit_code':0}),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(main(),1)
            self.assertEqual(next(root.glob('cf-status.*/response.json')).read_bytes(),response)
