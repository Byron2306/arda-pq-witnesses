import base64
import unittest
from unittest.mock import patch
from arda_quorum.enrollment_store import ProviderSecretStore, NoRedirect
from arda_quorum.enrollment import secret_name

class StoreTests(unittest.TestCase):
    def test_hf_uses_exact_secret_endpoint_without_redirects(self):
        name=secret_name('hf','ab'*32);calls=[]
        store=ProviderSecretStore('hf','Byron230686/arda-pq-policy-witness','test-token')
        store.request=lambda method,url,payload=None:calls.append((method,url,payload))
        store.put(name,'private-value')
        self.assertEqual(calls,[('POST','https://huggingface.co/api/spaces/Byron230686/arda-pq-policy-witness/secrets',dict(key=name,value='private-value'))])
    def test_github_seals_private_bytes_to_repository_key(self):
        from nacl.public import PrivateKey,SealedBox
        key=PrivateKey.generate();calls=[];name=secret_name('github','ab'*32)
        store=ProviderSecretStore('github','Byron2306/arda-pq-witnesses','test-token')
        def request(method,url,payload=None):
            calls.append((method,url,payload))
            if method=='GET':return dict(key=base64.b64encode(bytes(key.public_key)).decode(),key_id='123')
        store.request=request;store.put(name,'private-value')
        self.assertEqual(calls[0][1],'https://api.github.com/repos/Byron2306/arda-pq-witnesses/actions/secrets/public-key')
        self.assertNotIn('private-value',str(calls));body=calls[1][2]
        self.assertEqual(SealedBox(key).decrypt(base64.b64decode(body['encrypted_value'])),b'private-value')
        self.assertEqual(body['key_id'],'123');self.assertTrue(calls[1][1].endswith('/'+name))
    def test_untrusted_secret_name_and_repository_refused(self):
        with self.assertRaises(ValueError):ProviderSecretStore('hf','attacker/../repo','token')
        store=ProviderSecretStore('hf','operator/space','token')
        with self.assertRaises(ValueError):store.put('ARDA_HF_SIGNER_PKCS8_B64','value')
    def test_redirect_handler_does_not_forward_credentials(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'m',{},'https://attacker.example'))
    def test_network_failure_has_no_sensitive_diagnostics(self):
        store=ProviderSecretStore('hf','operator/space','test-token')
        with patch.object(store.opener,'open',side_effect=RuntimeError('test-token private-value')):
            with self.assertRaisesRegex(ValueError,'PROVIDER_SECRET_STORE_REFUSED') as err:
                store.put(secret_name('hf','ab'*32),'private-value')
        self.assertNotIn('test-token',str(err.exception));self.assertNotIn('private-value',str(err.exception))
    def test_wrong_host_and_plaintext_refused(self):
        store=ProviderSecretStore('hf','operator/space','test-token')
        for url in ('http://huggingface.co/api/spaces/operator/space/secrets','https://attacker.example'):
            with self.assertRaises(ValueError):store.request('POST',url,{})
