"""Private, durable review-intent consumption. No execution/installation API."""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import time
from .quorum import checked_quorum,need

class ReviewJournal:
    def __init__(self,path,*,backends,clock=None):
        self.path=Path(path).absolute();self.backends=backends;self.clock=clock or time.time
        parent=self.path.parent
        need(not any(p.is_symlink() for p in (parent,*parent.parents)),'journal_parent_symlink')
        st=parent.stat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and not st.st_mode&0o077,'journal_private_parent')
        try:fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        except FileExistsError:
            st=self.path.lstat()
            need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and not st.st_mode&0o077 and st.st_nlink==1,'journal_private_file')
        else:os.close(fd)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS reviews(nonce TEXT PRIMARY KEY,certificate_sha256 TEXT NOT NULL UNIQUE,proposal_sha256 TEXT NOT NULL,epoch INTEGER NOT NULL,hss_key_sha256 TEXT NOT NULL,hss_leaf INTEGER NOT NULL,state TEXT NOT NULL CHECK(state=\'REVIEW_INTENT\'),UNIQUE(hss_key_sha256,hss_leaf))')
            db.execute('CREATE TABLE IF NOT EXISTS watermark(singleton INTEGER PRIMARY KEY CHECK(singleton=1),epoch INTEGER NOT NULL,clock INTEGER NOT NULL)')

    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path,isolation_level=None,timeout=15)
        try:
            db.execute('PRAGMA synchronous=FULL')
            yield db
        finally:db.close()

    def now(self):
        value=self.clock()
        need(type(value) in (float,int) and value>0 and value<float('inf'),'journal_clock_invalid')
        return int(value)

    def consume(self,certificate,policy,*,expected):
        result=dict(decision='REFUSE',review_consumed=False,production_authorized=False,interlock='KEEP_CLOSED')
        try:
            verified_at=self.now()
            checked=checked_quorum(certificate,policy,expected,verified_at,self.backends)
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                try:
                    now=self.now();need(verified_at<=now<checked['expires_at'],'quorum_expired_or_clock_rollback_before_consumption')
                    old=db.execute('SELECT epoch,clock FROM watermark WHERE singleton=1').fetchone()
                    need(old is None or (checked['epoch']>=old[0] and now>=old[1]),'policy_or_clock_rollback')
                    db.execute('INSERT INTO reviews VALUES(?,?,?,?,?,?,\'REVIEW_INTENT\')',
                        tuple(checked[k] for k in ('nonce','certificate_sha256','proposal_sha256','epoch','hss_key_sha256','hss_leaf')))
                    db.execute('INSERT INTO watermark VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET epoch=excluded.epoch,clock=excluded.clock',(checked['epoch'],now))
                    db.execute('COMMIT')
                except BaseException:
                    db.execute('ROLLBACK');raise
            result.update(checked,review_consumed=True,reason='DURABLE_REVIEW_INTENT_ONLY',
                blockers=['R13_AND_REKOR_INTEGRATION_REQUIRED','STATEFUL_SIGNER_REVIEW_REQUIRED','PRODUCTION_CONSUMER_NOT_INSTALLED'])
        except Exception as exc:result['reason']='REVIEW_INTENT_REFUSED:'+type(exc).__name__+':'+str(exc)
        return result
