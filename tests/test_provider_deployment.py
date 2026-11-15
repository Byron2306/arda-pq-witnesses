from pathlib import Path
import unittest
import json
import yaml
ROOT=Path(__file__).resolve().parents[1]

class ProviderDeploymentTests(unittest.TestCase):
    def test_workflow_is_manual_only_with_pinned_actions_and_read_permissions(self):
        x=yaml.load((ROOT/'providers/github/arda-pq-review.yml').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(set(x['on']),{'workflow_dispatch'})
        self.assertEqual(x['permissions'],{'contents':'read'})
        for step in x['jobs']['review']['steps']:
            if 'uses' in step:self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')
    def test_workflow_never_interpolates_request_or_secret_into_shell_source(self):
        x=yaml.load((ROOT/'providers/github/arda-pq-review.yml').read_text(),Loader=yaml.BaseLoader)
        for step in x['jobs']['review']['steps']:
            if 'run' in step:
                self.assertNotIn('${{',step['run'])
                self.assertNotIn('--env ARDA_GITHUB_SIGNER_PKCS8_B64=',step['run'])
        secret_steps=[step for step in x['jobs']['review']['steps'] if 'ARDA_GITHUB_SIGNER_PKCS8_B64' in step.get('env',{})]
        self.assertEqual(len(secret_steps),1)
        self.assertIn('--network=none',secret_steps[0]['run']);self.assertIn('--read-only',secret_steps[0]['run'])
    def test_no_provider_is_enabled_or_has_a_private_key_by_default(self):
        for provider in ('github','hf'):
            draft=json.loads((ROOT/'providers'/provider/'CONFIGURATION_TEMPLATE.json').read_text())
            self.assertEqual(draft['state'],'UNENROLLED')
            self.assertIsNone(draft['configuration']['policy_file_sha256'])
            self.assertIsNone(draft['configuration']['image_digest'])
        self.assertIn("ARDA_PROVIDER_DEPLOYMENT_ENABLED == 'true'",(ROOT/'providers/github/arda-pq-review.yml').read_text())
