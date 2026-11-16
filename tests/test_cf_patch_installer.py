import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import install_cf_rotation as installer

class InstallerTests(unittest.TestCase):
    def fixture(self,root):
        (root/'cloudflare').mkdir();(root/'build').mkdir()
        (root/'cloudflare/source.mjs').write_bytes(b'old source')
        (root/'build/hss-state.wasm').write_bytes(b'unchanged wasm')
        sha=lambda raw:hashlib.sha256(raw).hexdigest()
        manifest=json.dumps({'production_authorized':False,'interlock':'KEEP_CLOSED'})
        data={'immutable':{'build/hss-state.wasm':sha(b'unchanged wasm')},'entries':{'cloudflare/source.mjs':{'contents':'new source','allowed_sha256':[sha(b'old source')],'allow_absent':False}},'manifest':manifest,'allowed_manifest_sha256':[sha(manifest.encode())]}
        return data
    def test_installs_only_reviewed_source_and_preserves_wasm_and_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'bundle';root.mkdir();data=self.fixture(root)
            with patch.object(installer,'DATA',data),contextlib.redirect_stdout(io.StringIO()):
                installer.install(root);installer.install(root)
            self.assertEqual((root/'cloudflare/source.mjs').read_bytes(),b'new source')
            self.assertEqual((root/'build/hss-state.wasm').read_bytes(),b'unchanged wasm')
            backups=list(Path(directory).glob('arda-cf-rotation-backup.*/cloudflare/source.mjs'))
            self.assertEqual(len(backups),2);self.assertIn(b'old source',[p.read_bytes() for p in backups])
    def test_wrong_immutable_pin_refuses_before_any_source_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);data=self.fixture(root);(root/'build/hss-state.wasm').write_bytes(b'wrong wasm')
            with patch.object(installer,'DATA',data),self.assertRaises(SystemExit):installer.install(root)
            self.assertEqual((root/'cloudflare/source.mjs').read_bytes(),b'old source')
    def test_symlink_escape_refuses_without_touching_outside_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'bundle';root.mkdir();data=self.fixture(root)
            outside=Path(directory)/'outside';outside.write_bytes(b'old source')
            (root/'cloudflare/source.mjs').unlink();(root/'cloudflare/source.mjs').symlink_to(outside)
            with patch.object(installer,'DATA',data),self.assertRaises(SystemExit):installer.install(root)
            self.assertEqual(outside.read_bytes(),b'old source')
    def test_original_uploaded_manifest_is_accepted_without_relaxing_source_pins(self):
        original=Path(__file__).parent/'fixtures/cf-v5-original-manifest.json'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'bundle';root.mkdir();data=self.fixture(root)
            data['allowed_manifest_sha256']+=installer.DATA['allowed_manifest_sha256']
            (root/'BUNDLE_MANIFEST.json').write_bytes(original.read_bytes())
            with patch.object(installer,'DATA',data),contextlib.redirect_stdout(io.StringIO()):installer.install(root)
            self.assertEqual((root/'cloudflare/source.mjs').read_bytes(),b'new source')
            self.assertEqual((root/'build/hss-state.wasm').read_bytes(),b'unchanged wasm')
    def test_unknown_manifest_still_refuses_before_source_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);data=self.fixture(root)
            (root/'BUNDLE_MANIFEST.json').write_text('{"schema":"unexpected"}')
            with patch.object(installer,'DATA',data),self.assertRaisesRegex(SystemExit,'MANIFEST_HASH_MISMATCH'):installer.install(root)
            self.assertEqual((root/'cloudflare/source.mjs').read_bytes(),b'old source')
