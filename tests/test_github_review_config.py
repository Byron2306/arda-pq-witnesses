import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import github_review_config as target
from github_review_inbox import canonical

class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.policy=b'{}';self.pin=hashlib.sha256(self.policy).hexdigest()
        self.env=dict(ARDA_WITNESS_IMAGE=target.IMAGE,ARDA_APPROVED_COMMIT_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_REF='Byron2306/arda-pq-witnesses/.github/workflows/arda-pq-review.yml@refs/heads/candidate/cloudflare-hss-v5-20261115',ARDA_ENROLLMENT_JSON='{}')
        self.config=dict(schema='arda.pq.provider_config.v1',provider='github',policy_file_sha256=self.pin,stage_request_sha256='b'*64,source_manifest_sha256='c'*64,image_digest=target.IMAGE.split('@')[1],runtime_identity=dict(repository='Byron2306/arda-pq-witnesses',workflow_ref=self.env['GITHUB_WORKFLOW_REF'],commit_sha='a'*40))
        self.encode()
    def encode(self):
        raw=canonical(self.config);self.env['ARDA_GITHUB_CONFIG_JSON']=raw.decode();self.env['ARDA_GITHUB_CONFIG_SHA256']=hashlib.sha256(raw).hexdigest()
    def test_accepted_external_config(self):
        with patch.object(target,'POLICY',self.pin):self.assertEqual(target.validate(self.env),(canonical(self.config),self.policy))
    def test_wrong_ref_commit_image_and_policy_fail(self):
        for key,value in [('GITHUB_SHA','d'*40),('GITHUB_WORKFLOW_REF','wrong'),('ARDA_WITNESS_IMAGE','mutable:tag'),('ARDA_ENROLLMENT_JSON','[]'),('ARDA_GITHUB_CONFIG_SHA256','0'*64)]:
            with self.subTest(key=key),patch.object(target,'POLICY',self.pin):
                env=dict(self.env);env[key]=value
                with self.assertRaises(AssertionError):target.validate(env)
    def test_configuration_unknown_fields_fail_even_when_rehashed(self):
        self.config['extra']=True;self.encode()
        with patch.object(target,'POLICY',self.pin),self.assertRaises(AssertionError):target.validate(self.env)
if __name__=='__main__':unittest.main()
