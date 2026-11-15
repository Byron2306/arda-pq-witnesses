import base64
import copy
import unittest
from unittest.mock import Mock
from arda_quorum import enrollment as e
from arda_quorum import quorum as q
from arda_quorum.crypto import Backends
from provider_fixtures import ProviderFixtures
import test_quorum as pq

class EnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ProviderFixtures.start(); cls.fx=ProviderFixtures; cls.backends=Backends()
    @classmethod
    def tearDownClass(cls):ProviderFixtures.stop()
    def setUp(self):
        self.ceremony=e.new_ceremony(nonce='ab'*32,image_digest='sha256:'+'cd'*32,
            identities={'github':'Byron2306/arda-pq-witnesses','hf':'Byron230686/arda-pq-policy-witness','cloudflare':'arda-release-witness'},now=1000)
    def record(self,provider):
        if provider!='cloudflare':return e.public_record(self.ceremony,provider,self.fx.private[provider],now=1000)
        public=pq.QuorumTests.signers.keys[provider];p=e.registration_payload(self.ceremony,provider,public,now=1000)
        return dict(payload=p,signature_b64=base64.b64encode(pq.QuorumTests.signers.sign(provider,e.REGISTRATION_DOMAIN+q.canonical(p))).decode())
    def env(self,provider):
        out={'ARDA_ALLOW_PROVIDER_KEY_PROVISIONING':q.sha(q.canonical(self.ceremony)),'ARDA_ENROLLMENT_STORE_TOKEN':'test-token','ARDA_IMAGE_DIGEST':self.ceremony['image_digest']}
        if provider=='github':out.update(GITHUB_ACTIONS='true',GITHUB_REPOSITORY=self.ceremony['identities'][provider])
        else:out['SPACE_ID']=self.ceremony['identities'][provider]
        return out
    def test_real_stateless_proofs(self):
        for p in ('github','hf'):
            record=self.record(p);e.check_record(record,self.ceremony,now=1000,backends=self.backends)
            self.assertNotIn('private',str(record));self.assertEqual(record['payload']['secret_name'],e.secret_name(p,record['payload']['key_sha256']))
    def test_tampered_identity_and_signature_refused(self):
        for field,value in [('provider_identity','attacker/space'),('ceremony_sha256','ef'*32),('key_sha256','ef'*32)]:
            r=self.record('hf');r['payload'][field]=value
            with self.assertRaises(ValueError):e.check_record(r,self.ceremony,now=1000,backends=self.backends)
    def test_expired_ceremony_and_duplicate_identity_refused(self):
        with self.assertRaises(ValueError):e.check_ceremony(self.ceremony,1000+86400)
        c=copy.deepcopy(self.ceremony);c['identities']['hf']=c['identities']['github']
        with self.assertRaises(ValueError):e.check_ceremony(c,1000)
    def test_missing_cloudflare_never_creates_policy(self):
        records=[self.record(p) for p in ('github','hf')]
        with self.assertRaisesRegex(ValueError,'all_three'):
            e.assemble(self.ceremony,records,{r['payload']['provider']:q.sha(q.canonical(r)) for r in records},epoch=1,now=1000,backends=self.backends)
    def test_all_three_reviewed_real_proofs_create_only_closed_policy(self):
        records=[self.record(p) for p in ('github','hf','cloudflare')];pins={r['payload']['provider']:q.sha(q.canonical(r)) for r in records}
        out=e.assemble(self.ceremony,records,pins,epoch=1,now=1000,backends=self.backends)
        self.assertFalse(out['production_authorized']);self.assertEqual(out['interlock'],'KEEP_CLOSED')
        self.assertIn('STATEFUL_SIGNER_REVIEW_REQUIRED',out['blockers']);q.enrollment(out['policy'],1000)
    def test_wrong_operator_record_pin_refused(self):
        records=[self.record(p) for p in ('github','hf','cloudflare')];pins={r['payload']['provider']:'ef'*32 for r in records}
        with self.assertRaises(ValueError):e.assemble(self.ceremony,records,pins,epoch=1,now=1000,backends=self.backends)
    def test_provider_identity_checked_before_keygen(self):
        for p in ('github','hf'):
            factory=Mock();store=Mock();env=self.env(p);env['GITHUB_REPOSITORY' if p=='github' else 'SPACE_ID']='attacker/witness'
            with self.assertRaises(ValueError):e.provision(self.ceremony,p,environ=env,now=1000,key_factory=factory,store=store)
            factory.assert_not_called();store.put.assert_not_called()
    def test_explicit_setup_pin_required(self):
        factory=Mock();env=self.env('hf');env['ARDA_ALLOW_PROVIDER_KEY_PROVISIONING']='00'*32
        with self.assertRaises(ValueError):e.provision(self.ceremony,'hf',environ=env,now=1000,key_factory=factory,store=Mock())
        factory.assert_not_called()
    def test_secret_upload_uses_only_derived_name(self):
        store=Mock();record=e.provision(self.ceremony,'hf',environ=self.env('hf'),now=1000,key_factory=lambda a:self.fx.private['hf'],store=store)
        store.put.assert_called_once_with(record['payload']['secret_name'],base64.b64encode(self.fx.private['hf']).decode())
    def test_store_failure_returns_no_registration(self):
        store=Mock();store.put.side_effect=RuntimeError('sensitive provider response')
        with self.assertRaisesRegex(ValueError,'PROVIDER_ENROLLMENT_REFUSED') as err:
            e.provision(self.ceremony,'hf',environ=self.env('hf'),now=1000,key_factory=lambda a:self.fx.private['hf'],store=store)
        self.assertNotIn('sensitive',str(err.exception))
    def test_real_generation_produces_distinct_key_names(self):
        first=e.public_record(self.ceremony,'github',e.generate_private('ML-DSA-65'),now=1000)
        second=e.public_record(self.ceremony,'github',e.generate_private('ML-DSA-65'),now=1000)
        self.assertNotEqual(first['payload']['secret_name'],second['payload']['secret_name'])
    def test_backend_missing_or_wrong_algorithm_refused(self):
        with self.assertRaises(ValueError):e.public_record(self.ceremony,'hf',self.fx.private['github'],now=1000)
        with self.assertRaises(ValueError):e.generate_private('HSS-LMS-SHA256-N32-H10-W8')
    def test_hf_setup_http_returns_real_provider_proof_and_only_public_bytes(self):
        import http.client
        import json
        import threading
        from arda_quorum.enrollment_http import SetupOnce,make_setup_server
        store=Mock()
        def provision(c,p,**kw):return e.provision(c,p,key_factory=lambda a:self.fx.private['hf'],store=store,**kw)
        setup=SetupOnce(self.ceremony,self.env('hf'),clock=lambda:1000,provisioner=provision)
        server=make_setup_server(setup,'aa'*32,host='127.0.0.1',port=0)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.01},daemon=True);thread.start()
        client=http.client.HTTPConnection(*server.server_address,timeout=20)
        try:
            client.request('POST','/v1/enroll-hf',body=q.canonical(dict(action='provision_hf_key',ceremony_sha256=q.sha(q.canonical(self.ceremony)))),
                headers={'X-ARDA-Setup-Token':'aa'*32,'Content-Type':'application/json'})
            response=client.getresponse();body=json.loads(response.read());self.assertEqual(response.status,200,body)
            e.check_record(body['registration'],self.ceremony,now=1000,backends=self.backends)
            self.assertNotIn(base64.b64encode(self.fx.private['hf']).decode(),str(body));store.put.assert_called_once()
        finally:client.close();server.shutdown();server.server_close();thread.join(2)
    def test_image_mismatch_checked_before_keygen(self):
        env=self.env('hf');env['ARDA_IMAGE_DIGEST']='sha256:'+'ff'*32;factory=Mock()
        with self.assertRaises(ValueError):e.provision(self.ceremony,'hf',environ=env,now=1000,key_factory=factory,store=Mock())
        factory.assert_not_called()
