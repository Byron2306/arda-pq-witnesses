import hashlib,importlib.util,runpy,shutil,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
class CFReviewInstallerTests(unittest.TestCase):
 def setUp(self):
  path=ROOT/'tools/install_cf_review.py';self.assertTrue(path.exists(),'review source installer missing')
  spec=importlib.util.spec_from_file_location('cf_review_installer',path);self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name)/'bundle';self.base.mkdir()
  old=runpy.run_path(str(ROOT/'tools/install_cf_rotation.py'))['DATA']
  original=ROOT.parent/'cf-lenovo-bundle'
  for name,pin in old['immutable'].items():
   source=original/name
   if not source.is_file() or sha(source.read_bytes())!=pin:self.skipTest('original reviewed public bundle unavailable for immutable installer fixture')
   target=self.base/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
  for name,entry in old['entries'].items():
   target=self.base/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(entry['contents'].encode())
  (self.base/'BUNDLE_MANIFEST.json').write_text(old['manifest'])
 def test_reviewed_upgrade_and_reapply_preserve_wasm_and_match_sources(self):
  wasm=(self.base/'build/hss-state.wasm').read_bytes();self.m.install(self.base);self.m.install(self.base)
  self.assertEqual((self.base/'build/hss-state.wasm').read_bytes(),wasm)
  for name in self.m.DATA['files']:
   self.assertEqual((self.base/name).read_bytes(),(ROOT/name).read_bytes(),name)
 def test_unexpected_guard_or_manifest_refused_before_any_patch(self):
  path=self.base/'cloudflare/hss-guard.mjs';before=(self.base/'providers/cloudflare/worker.mjs').read_bytes();path.write_text('unexpected')
  with self.assertRaises(SystemExit):self.m.install(self.base)
  self.assertEqual((self.base/'providers/cloudflare/worker.mjs').read_bytes(),before);self.assertFalse((self.base/'cloudflare/release-service.mjs').exists())
 def test_symlinked_new_source_and_modified_wasm_refused(self):
  target=self.base/'cloudflare/release-service.mjs';target.symlink_to(self.base/'cloudflare/hss-engine.mjs')
  with self.assertRaises(SystemExit):self.m.install(self.base)
  target.unlink();(self.base/'build/hss-state.wasm').write_bytes(b'not-reviewed')
  with self.assertRaises(SystemExit):self.m.install(self.base)
