import copy
import hashlib
import json
from pathlib import Path
import unittest
from arda_quorum import proposal as p
from arda_quorum.quorum import canonical
ROOT=Path(__file__).resolve().parents[1]

class ProposalTests(unittest.TestCase):
    def setUp(self):self.raw=(ROOT/'inputs/generation14-staging-request.json').read_bytes()
    def test_actual_generation14_binding(self):
        result=p.validate_request(self.raw,p.REVIEWED_REQUEST_SHA256)
        self.assertEqual(result['generation'],14)
        self.assertEqual(result['manifest_digest'],'sha256:381d6ac72a53bf04de639c7d73e75fb11760c94f922b955b63d5ec3ea54924e0')
    def test_unreviewed_request_refused(self):
        with self.assertRaises(ValueError):p.validate_request(self.raw+b' ',p.REVIEWED_REQUEST_SHA256)
    def test_internal_manifest_tamper_refused_even_if_request_rehashed(self):
        data=json.loads(self.raw);data['manifest']['generation']=15;raw=canonical(data)
        with self.assertRaises(ValueError):p.validate_request(raw,hashlib.sha256(raw).hexdigest())
    def test_artifact_and_measured_entry_mismatch_refused(self):
        data=json.loads(self.raw)
        path=data['added_measured_paths'][0];data['deployment']['artifacts'][path]='0'*64
        raw=canonical(data)
        with self.assertRaises(ValueError):p.validate_request(raw,hashlib.sha256(raw).hexdigest())
    def test_draft_without_enrollment_or_evidence_cannot_be_signed_as_ready(self):
        draft=p.prepare_draft(self.raw,now=1000)
        self.assertEqual(draft['state'],'UNREADY_DRAFT')
        self.assertIsNone(draft['proposal']['policy_sha256'])
        self.assertIsNone(draft['proposal']['r13_evidence_sha256'])
        self.assertFalse(draft['production_authorized'])
    def test_public_commitment_exposes_only_certificate_digest(self):
        result=p.public_commitment({'proposal':{'machine_id':'private-machine'},'votes':[]})
        self.assertEqual(set(result),{'schema','certificate_sha256'})
        self.assertNotIn('private-machine',json.dumps(result))
