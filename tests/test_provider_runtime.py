import base64
from pathlib import Path
import shutil
import tempfile
import unittest
from arda_quorum.quorum import canonical,sha
from arda_quorum.provider_runtime import load_runtime
import test_r13_bridge as att
from provider_fixtures import ProviderFixtures as F,ROOT

class ProviderRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):F.start()
    @classmethod
    def tearDownClass(cls):F.stop()
    def setup_runtime(self,provider):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name)
        (root/'inputs').mkdir();(root/'inputs/generation14-staging-request.json').write_bytes(F.stage_bytes)
        public=root/'providers/public-r13';public.mkdir(parents=True)
        (public/'verifier-public.pem').write_bytes(att.R13BridgeTests.public)
        (public/'ak-public.pem').write_bytes(att.R13BridgeTests.ak_public)
        (public/'approved-pcrs.json').write_bytes(canonical(att.R13BridgeTests.profile))
        (root/'REVIEWED_SOURCE_FILES.json').write_bytes(F.source_bytes)
        config=dict(schema='arda.pq.provider_config.v1',provider=provider,policy_file_sha256=sha(F.policy_bytes),
            stage_request_sha256=F.stage_pin,source_manifest_sha256=sha(F.source_bytes),image_digest='sha256:'+'ab'*32,
            runtime_identity={'space_id':'operator/review'} if provider=='hf' else dict(repository='operator/review',workflow_ref='operator/review/.github/workflows/review.yml@refs/heads/main',commit_sha='cd'*20))
        raw=canonical(config)
        env=dict(ARDA_PROVIDER_CONFIG_SHA256=sha(raw),ARDA_IMAGE_DIGEST=config['image_digest'])
        if provider=='hf':
            env.update(ARDA_PROVIDER_CONFIG_JSON=raw.decode(),ARDA_ENROLLMENT_JSON=F.policy_bytes.decode(),
                ARDA_HF_SIGNER_PKCS8_B64=base64.b64encode(F.private['hf']).decode(),SPACE_ID='operator/review')
        else:
            (root/'operator-config').mkdir();(root/'operator-config/github.json').write_bytes(raw)
            (root/'operator-config/enrollment.json').write_bytes(F.policy_bytes)
            shutil.copytree(ROOT/'reviewed-runtime',root/'reviewed-runtime')
            env.update(ARDA_GITHUB_SIGNER_PKCS8_B64=base64.b64encode(F.private['github']).decode(),GITHUB_ACTIONS='true',
                GITHUB_REPOSITORY='operator/review',GITHUB_WORKFLOW_REF=config['runtime_identity']['workflow_ref'],GITHUB_SHA='cd'*20)
        return root,env
    def test_hf_loads_pinned_runtime_config_and_provider_secret(self):
        root,env=self.setup_runtime('hf');w=load_runtime('hf',root,env,clock=lambda:1000)
        self.assertEqual(w.review(F.request)['payload']['provider'],'hf')
        self.assertFalse((root/'operator-config').exists())
    def test_github_loads_pinned_identity_and_configuration(self):
        root,env=self.setup_runtime('github');w=load_runtime('github',root,env,clock=lambda:1000)
        self.assertEqual(w.review(F.request)['payload']['provider'],'github')
    def test_hf_identity_and_image_mismatch_refused(self):
        for field,value in [('SPACE_ID','different/space'),('ARDA_IMAGE_DIGEST','sha256:'+'00'*32),('ARDA_PROVIDER_CONFIG_SHA256','00'*32)]:
            root,env=self.setup_runtime('hf');env[field]=value
            with self.assertRaises(ValueError):load_runtime('hf',root,env,clock=lambda:1000)
    def test_github_commit_and_workflow_mismatch_refused(self):
        for field in ('GITHUB_SHA','GITHUB_WORKFLOW_REF','GITHUB_REPOSITORY','GITHUB_ACTIONS'):
            root,env=self.setup_runtime('github');env[field]='wrong'
            with self.assertRaises(ValueError):load_runtime('github',root,env,clock=lambda:1000)
    def test_missing_signing_secret_refused(self):
        root,env=self.setup_runtime('hf');env.pop('ARDA_HF_SIGNER_PKCS8_B64')
        with self.assertRaises(ValueError):load_runtime('hf',root,env,clock=lambda:1000)
    def test_hf_selects_key_named_secret_from_pinned_policy(self):
        from arda_quorum.enrollment import secret_name
        from arda_quorum.quorum import strict_load
        root,env=self.setup_runtime('hf');value=env.pop('ARDA_HF_SIGNER_PKCS8_B64')
        key_sha=next(w['key_sha256'] for w in strict_load(F.policy_bytes)['witnesses'] if w['provider']=='hf')
        env[secret_name('hf',key_sha)]=value
        self.assertEqual(load_runtime('hf',root,env,clock=lambda:1000).review(F.request)['payload']['provider'],'hf')
    def test_conflicting_fixed_and_key_named_secrets_refused(self):
        from arda_quorum.enrollment import secret_name
        from arda_quorum.quorum import strict_load
        root,env=self.setup_runtime('hf')
        key_sha=next(w['key_sha256'] for w in strict_load(F.policy_bytes)['witnesses'] if w['provider']=='hf')
        env[secret_name('hf',key_sha)]='AAAA'
        with self.assertRaises(ValueError):load_runtime('hf',root,env,clock=lambda:1000)
