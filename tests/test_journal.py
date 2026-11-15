import copy
from concurrent.futures import ThreadPoolExecutor
import tempfile
from pathlib import Path
import unittest
import json
import subprocess
import sys
from arda_quorum.quorum import checked_quorum
import test_quorum as fixtures
from arda_quorum import journal

class JournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixtures.QuorumTests.setUpClass()
    @classmethod
    def tearDownClass(cls):fixtures.QuorumTests.tearDownClass()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'reviews.db';self.now=[1000]
        self.j=journal.ReviewJournal(self.path,clock=lambda:self.now[0],backends=fixtures.QuorumTests.backend)
    def consume(self,j=None,c=None):
        return (j or self.j).consume(c or fixtures.QuorumTests.certificate,fixtures.QuorumTests.policy,expected=fixtures.QuorumTests.expected)
    def test_consumption_is_durable_and_never_grants_execution(self):
        result=self.consume();self.assertTrue(result['review_consumed'],result)
        self.assertFalse(result['production_authorized']);self.assertEqual(result['decision'],'REFUSE')
        self.assertEqual(self.consume()['review_consumed'],False)
    def test_reconstruction_preserves_consumed_nonce(self):
        self.assertTrue(self.consume()['review_consumed'])
        other=journal.ReviewJournal(self.path,clock=lambda:1000,backends=fixtures.QuorumTests.backend)
        self.assertFalse(self.consume(other)['review_consumed'])
    def test_invalid_certificate_does_not_consume(self):
        c=copy.deepcopy(fixtures.QuorumTests.certificate);c['votes'].pop()
        self.assertFalse(self.consume(c=c)['review_consumed'])
        self.assertTrue(self.consume()['review_consumed'])
    def test_two_concurrent_consumers_only_one_intent(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:self.consume(),range(2)))
        self.assertEqual(sum(r['review_consumed'] for r in results),1)
    def test_clock_rollback_after_consumption_refused(self):
        self.assertTrue(self.consume()['review_consumed']);self.now[0]=999
        self.assertFalse(self.consume()['review_consumed'])
    def test_expiry_during_verification_refused(self):
        calls=iter([1000,1100]);self.j.clock=lambda:next(calls)
        self.assertFalse(self.consume()['review_consumed'])
        self.j.clock=lambda:1000
        self.assertTrue(self.consume()['review_consumed'])
    def test_world_readable_database_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):journal.ReviewJournal(self.path,backends=fixtures.QuorumTests.backend)
    def test_symlink_database_refused(self):
        alias=self.path.parent/'alias';alias.symlink_to(self.path)
        with self.assertRaises(ValueError):journal.ReviewJournal(alias,backends=fixtures.QuorumTests.backend)

    def test_hss_leaf_cannot_be_consumed_under_another_nonce(self):
        c=checked_quorum(fixtures.QuorumTests.certificate,fixtures.QuorumTests.policy,fixtures.QuorumTests.expected,1000,fixtures.QuorumTests.backend)
        with self.j.connect() as db:
            db.execute("INSERT INTO reviews VALUES(?,?,?,?,?,?, 'REVIEW_INTENT')",('different-nonce','different-cert','different-proposal',1,c['hss_key_sha256'],c['hss_leaf']))
        self.assertFalse(self.consume()['review_consumed'])
        with self.j.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM reviews').fetchone()[0],1)

    def test_transaction_failure_leaves_no_partial_consumption(self):
        with self.j.connect() as db:db.execute("CREATE TRIGGER fail_review BEFORE INSERT ON reviews BEGIN SELECT RAISE(ABORT,'interruption'); END")
        self.assertFalse(self.consume()['review_consumed'])
        with self.j.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM watermark').fetchone()[0],0)
            db.execute('DROP TRIGGER fail_review')
        self.assertTrue(self.consume()['review_consumed'])

    def test_sigkill_after_commit_does_not_allow_replay(self):
        path=self.path.parent/'public-fixture.json'
        path.write_text(json.dumps(dict(certificate=fixtures.QuorumTests.certificate,policy=fixtures.QuorumTests.policy,expected=fixtures.QuorumTests.expected)))
        code="""import json,os,signal,sys
from arda_quorum.crypto import Backends
from arda_quorum.journal import ReviewJournal
x=json.load(open(sys.argv[1]));j=ReviewJournal(sys.argv[2],clock=lambda:1000,backends=Backends())
r=j.consume(x['certificate'],x['policy'],expected=x['expected']);print(json.dumps(r),flush=True)
os.kill(os.getpid(),signal.SIGKILL)
"""
        run=subprocess.run([sys.executable,'-c',code,str(path),str(self.path)],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,-9,run.stderr)
        self.assertTrue(json.loads(run.stdout)['review_consumed'])
        self.assertFalse(self.consume()['review_consumed'])

    def test_clock_rollback_during_verification_refused(self):
        calls=iter([1000,999]);self.j.clock=lambda:next(calls)
        self.assertFalse(self.consume()['review_consumed'])

    def test_older_policy_epoch_refused_after_observation(self):
        with self.j.connect() as db:db.execute('INSERT INTO watermark VALUES(1,2,1000)')
        self.assertFalse(self.consume()['review_consumed'])

    def test_shared_parent_directory_refused(self):
        self.path.parent.chmod(0o755)
        try:
            with self.assertRaises(ValueError):journal.ReviewJournal(self.path,backends=fixtures.QuorumTests.backend)
        finally:self.path.parent.chmod(0o700)
