"""Process-shared projection intent journal; no kernel mutation occurs here.

A consumed permit stays consumed after exceptions and crashes. An unfinished
intent blocks new writers. Recovery may close it only after explicit read-back;
this module never deletes an enrolled selector or replays an old boot's intent.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import base64
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
from types import MappingProxyType
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PERMIT_DOMAIN = b'ARDA/PROJECTION-PERMIT/v1\0'
PLAN_FIELDS = frozenset({'action', 'scope_id', 'scope_path', 'generation',
    'prior_generation', 'node_id', 'manifest_id', 'manifest_digest'})
PERMIT_FIELDS = PLAN_FIELDS | {'schema', 'permit_id', 'boot_id', 'issued_at',
    'expires_at', 'production_cutover_authorized'}
TERMINAL = frozenset({'COMMITTED', 'ABORTED', 'QUARANTINED', 'RECOVERED'})
DEFAULT_ROOT = Path('/var/lib/arda/projection-transactions')
_CURRENT = ContextVar('arda_projection_transaction', default=None)
_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _boot_valid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except (ValueError, AttributeError):
        return False


def validate_plan(plan, *, bootstrap=False):
    _need(type(plan) is dict and plan.keys() == PLAN_FIELDS, 'projection_plan_fields')
    actions = {'restore', 'stage', 'bind', 'deny'} if bootstrap else {'activate', 'rollback', 'quarantine', 'collect'}
    _need(plan['action'] in actions, 'projection_action')
    for field in ('scope_id', 'generation'):
        _need(type(plan[field]) is int and 0 < plan[field] < 2**63, 'projection_'+field)
    prior = plan['prior_generation']
    _need(prior is None or type(prior) is int and 0 <= prior < 2**63, 'projection_prior_generation')
    path = plan['scope_path']
    _need(type(path) is str and path.startswith('/sys/fs/cgroup/') and len(path) <= 4096
          and '..' not in Path(path).parts and '\x00' not in path, 'projection_scope_path')
    for field in ('node_id', 'manifest_id'):
        _need(type(plan[field]) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}', plan[field]), 'projection_'+field)
    _need(type(plan['manifest_digest']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', plan['manifest_digest']), 'projection_manifest_digest')


@dataclass(frozen=True)
class VerifiedPermit:
    payload: object

    def check(self, plan, boot_id, now):
        validate_plan(plan)
        p = self.payload
        _need(_boot_valid(boot_id) and p['boot_id'] == boot_id, 'permit_boot')
        _need(type(now) is int and p['issued_at'] <= now < p['expires_at'], 'permit_expired_or_future')
        _need(all(p[field] == plan[field] for field in PLAN_FIELDS), 'permit_plan_binding')


def verify_permit(envelope, pinned_key, plan, boot_id, now):
    validate_plan(plan)
    _need(type(envelope) is dict and envelope.keys() == {'payload', 'signature_b64'}, 'permit_envelope')
    payload = envelope['payload']
    _need(type(payload) is dict and payload.keys() == PERMIT_FIELDS, 'permit_fields')
    _need(payload['schema'] == 'arda.projection.permit.v1'
          and payload['production_cutover_authorized'] is True, 'permit_not_production_authorization')
    _need(type(payload['permit_id']) is str and re.fullmatch('[0-9a-f]{32}', payload['permit_id']), 'permit_id')
    _need(type(payload['issued_at']) is int and type(payload['expires_at']) is int
          and 0 < payload['expires_at'] - payload['issued_at'] <= 300, 'permit_time_fields')
    _need(isinstance(pinned_key, Ed25519PublicKey), 'permit_pinned_key')
    try:
        raw = base64.b64decode(envelope['signature_b64'], validate=True)
        _need(len(raw) == 64, 'permit_signature_length')
        pinned_key.verify(raw, PERMIT_DOMAIN + canonical(payload))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError('permit_signature') from exc
    result = VerifiedPermit(MappingProxyType(dict(payload)))
    result.check(plan, boot_id, now)
    return result


def current_transaction():
    tx = _CURRENT.get()
    if tx is not None:
        _need(tx.pid == os.getpid(), 'transaction_inherited_across_fork')
    return tx


def require_transaction():
    tx = current_transaction()
    _need(tx is not None, 'coordinated_projection_transaction_required')
    tx.check()
    return tx


class _LockState:
    def __init__(self):
        self.lock = threading.RLock()
        self.local = threading.local()


class Journal:
    def __init__(self, root=DEFAULT_ROOT, *, boot_id=None, clock=None, lock_timeout=10, read_only=False):
        self.root = Path(root).absolute()
        self.read_only = read_only
        self.boot_id = boot_id or (lambda: Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        self.clock = clock or (lambda: int(time.time()))
        self.lock_timeout = lock_timeout
        _need(_boot_valid(self.boot_id()), 'journal_boot_id')
        for parent in (self.root, *self.root.parents):
            _need(not parent.is_symlink(), 'journal_symlinked_directory')
        if not read_only:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.stat()
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
              and not info.st_mode & 0o077, 'journal_directory_permissions')
        with _LOCKS_GUARD:
            self._state = _LOCKS.setdefault(str(self.root), _LockState())
        with self.locked():
            if read_only:
                _need((self.root / 'journal.sqlite3').is_file() and not (self.root / 'journal.sqlite3').is_symlink(), 'journal_not_provisioned')
                return
            fd = self._secure_open('journal.sqlite3')
            os.close(fd)
            with self.connection() as con:
                con.executescript('''
                CREATE TABLE IF NOT EXISTS projection_transactions(
                    txid TEXT PRIMARY KEY, boot_id TEXT NOT NULL, plan_json TEXT NOT NULL,
                    phase TEXT NOT NULL, last_phase TEXT, inventory_json TEXT,
                    error TEXT, permit_id TEXT, started_at INTEGER NOT NULL, handoff_hash TEXT);
                CREATE TABLE IF NOT EXISTS projection_operations(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, txid TEXT NOT NULL,
                    kind TEXT NOT NULL, details_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS projection_permits(
                    permit_id TEXT PRIMARY KEY, txid TEXT NOT NULL, consumed_at INTEGER NOT NULL);
                ''')
            self._sync_directory()

    def _secure_open(self, name):
        path = self.root / name
        access = os.O_RDONLY if self.read_only else os.O_CREAT | os.O_RDWR
        fd = os.open(path, access | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and not info.st_mode & 0o077):
            os.close(fd)
            raise ValueError('journal_file_permissions')
        return fd

    def _sync_directory(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def locked(self):
        with self._state.lock:
            local = self._state.local
            if getattr(local, 'depth', 0):
                _need(local.pid == os.getpid(), 'lock_inherited_across_fork')
                local.depth += 1
                try:
                    self.check_lock()
                    yield
                finally:
                    local.depth -= 1
                return
            fd = self._secure_open('coordinator.lock')
            deadline = time.monotonic() + self.lock_timeout
            try:
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError('projection_lock_busy')
                        time.sleep(0.01)
                local.fd, local.depth, local.pid = fd, 1, os.getpid()
                self.check_lock()
                yield
            finally:
                local.depth = 0
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def check_lock(self):
        local = self._state.local
        _need(getattr(local, 'depth', 0) > 0 and local.pid == os.getpid(), 'projection_lock_not_held')
        held = os.fstat(local.fd)
        current = os.stat(self.root / 'coordinator.lock', follow_symlinks=False)
        _need(stat.S_ISREG(current.st_mode) and (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino), 'projection_lock_inode_changed')

    @contextmanager
    def connection(self):
        # The private directory protects the path throughout this open.
        path = self.root / 'journal.sqlite3'
        _need(not path.is_symlink(), 'journal_database_symlink')
        con = sqlite3.connect(path.as_uri()+'?mode=ro' if self.read_only else path,
                              uri=self.read_only, isolation_level=None, timeout=5)
        con.row_factory = sqlite3.Row
        try:
            if self.read_only:
                con.execute('PRAGMA query_only=ON')
            else:
                con.execute('PRAGMA journal_mode=WAL')
                con.execute('PRAGMA synchronous=FULL')
            con.execute('PRAGMA trusted_schema=OFF')
            yield con
        finally:
            con.close()

    def rows(self):
        with self.locked(), self.connection() as con:
            rows = []
            for record in con.execute('SELECT * FROM projection_transactions ORDER BY started_at,txid'):
                row = dict(record)
                row['plan'] = json.loads(row.pop('plan_json'))
                inventory = row.pop('inventory_json')
                row['inventory'] = json.loads(inventory) if inventory is not None else None
                row['operations'] = [dict(op, details=json.loads(op['details_json']))
                    for op in con.execute('SELECT kind,details_json FROM projection_operations WHERE txid=? ORDER BY seq', (row['txid'],))]
                rows.append(row)
            return rows

    def transaction(self, plan, permit):
        _need(isinstance(permit, VerifiedPermit), 'verified_projection_permit_required')
        return self._transaction(plan, permit, bootstrap=False)

    def bootstrap(self, plan, *, deployment=None):
        return self._transaction(plan, None, bootstrap=True, deployment=deployment)

    @contextmanager
    def _transaction(self, plan, permit, *, bootstrap, deployment=None):
        _need(not self.read_only, 'read_only_projection_journal')
        validate_plan(plan, bootstrap=bootstrap)
        _need(current_transaction() is None, 'nested_projection_transaction')
        with self.locked():
            boot = self.boot_id()
            if permit is not None:
                permit.check(plan, boot, self.clock())
            if deployment is not None:
                from .deployment_profile import VerifiedDeployment
                _need(isinstance(deployment, VerifiedDeployment), 'verified_deployment_required')
                deployment.check(self.clock()); deployment.check_plan(plan)
            with self.connection() as con:
                pending = con.execute("SELECT txid FROM projection_transactions WHERE phase NOT IN ('COMMITTED','ABORTED','QUARANTINED','RECOVERED') AND (? = 0 OR boot_id = ?) LIMIT 1",
                    (int(bootstrap and plan['action']=='restore' and deployment is not None), boot)).fetchone()
                _need(pending is None or bootstrap and plan['action']=='deny', 'unfinished_projection_intent_requires_recovery')
                txid = uuid.uuid4().hex
                permit_id = permit.payload['permit_id'] if permit else None
                con.execute('BEGIN IMMEDIATE')
                try:
                    if permit_id:
                        con.execute('INSERT INTO projection_permits VALUES(?,?,?)', (permit_id, txid, self.clock()))
                    con.execute('INSERT INTO projection_transactions(txid,boot_id,plan_json,phase,permit_id,started_at) VALUES(?,?,?,?,?,?)',
                                (txid, boot, canonical(plan).decode(), 'INTENT', permit_id, self.clock()))
                    con.execute('COMMIT')
                except sqlite3.IntegrityError as exc:
                    con.execute('ROLLBACK')
                    raise ValueError('projection_permit_replayed') from exc
                except BaseException:
                    con.execute('ROLLBACK')
                    raise
            tx = Transaction(self, txid, boot, dict(plan), permit)
            tx.deployment = deployment
            token = _CURRENT.set(tx)
            try:
                if deployment is not None:
                    tx.note('deployment_profile', {'sha256':deployment.sha256})
                yield tx
                _need(tx.phase == 'COMMITTED' or bootstrap and tx.phase == 'HANDED_OFF', 'projection_transaction_not_finalized')
            except BaseException as exc:
                if tx.phase != 'COMMITTED':
                    with self.connection() as con:
                        count = con.execute('SELECT count(*) FROM projection_operations WHERE txid=?', (txid,)).fetchone()[0]
                        con.execute('UPDATE projection_transactions SET last_phase=phase,phase=?,error=? WHERE txid=?',
                            ('DIRTY' if count else 'ABORTED', type(exc).__name__ + ': ' + str(exc)[:512], txid))
                raise
            finally:
                _CURRENT.reset(token)
                for resource in reversed(tx.resources):
                    resource.close()

    @contextmanager
    def resume_boot_restore(self, txid, secret, expected_plan, *, deployment=None):
        _need(not self.read_only and current_transaction() is None, 'invalid_boot_resume_context')
        validate_plan(expected_plan, bootstrap=True)
        _need(expected_plan['action'] == 'restore', 'only_boot_restore_can_resume')
        with self.locked():
            rows = [r for r in self.rows() if r['txid'] == txid]
            _need(len(rows) == 1, 'boot_handoff_not_found')
            row = rows[0]
            _need(row['phase'] == 'HANDED_OFF' and row['boot_id'] == self.boot_id()
                  and row['plan'] == expected_plan, 'boot_handoff_context')
            _need(type(secret) is str and re.fullmatch('[0-9a-f]{64}', secret)
                  and hmac.compare_digest(row['handoff_hash'] or '', hashlib.sha256(secret.encode()).hexdigest()), 'boot_handoff_secret')
            if deployment is not None:
                from .deployment_profile import VerifiedDeployment
                _need(isinstance(deployment, VerifiedDeployment), 'verified_deployment_required')
                deployment.check(self.clock()); deployment.check_plan(expected_plan)
                _need(any(op['kind']=='deployment_profile' and op['details'].get('sha256')==deployment.sha256
                          for op in row['operations']), 'boot_handoff_deployment_changed')
            with self.connection() as con:
                con.execute("UPDATE projection_transactions SET phase='INTENT',handoff_hash=NULL WHERE txid=?", (txid,))
            tx = Transaction(self, txid, row['boot_id'], row['plan'], None)
            tx.deployment = deployment
            token = _CURRENT.set(tx)
            try:
                tx.note('boot_restore_resumed', {'pid':os.getpid()})
                yield tx
                _need(tx.phase == 'COMMITTED', 'boot_restore_not_finalized')
            except BaseException as exc:
                if tx.phase != 'COMMITTED':
                    with self.connection() as con:
                        con.execute("UPDATE projection_transactions SET last_phase=phase,phase='DIRTY',error=? WHERE txid=?",
                                    (type(exc).__name__ + ': '+str(exc)[:512], txid))
                raise
            finally:
                _CURRENT.reset(token)
                for resource in reversed(tx.resources):resource.close()

    @contextmanager
    def recovery(self, txid):
        _need(not self.read_only, 'read_only_projection_journal')
        _need(current_transaction() is None, 'nested_recovery')
        with self.locked():
            rows = [r for r in self.rows() if r['txid'] == txid]
            _need(len(rows) == 1 and rows[0]['phase'] not in TERMINAL, 'recovery_intent_not_pending')
            row = rows[0]
            _need(row['boot_id'] == self.boot_id(), 'stale_boot_intent_preserved_no_replay')
            tx = Transaction(self, txid, row['boot_id'], row['plan'], None, recovering=True)
            tx.phase = row['phase']
            token = _CURRENT.set(tx)
            try:
                yield tx, row
            finally:
                _CURRENT.reset(token)


class Transaction:
    def __init__(self, journal, txid, boot, plan, permit, recovering=False):
        self.journal, self.txid, self.boot, self.plan, self.permit = journal, txid, boot, plan, permit
        self.phase, self.pid, self.recovering = 'INTENT', os.getpid(), recovering
        self.resources = []
        self.deployment = None

    def hold(self, resource):
        self.check()
        self.resources.append(resource)

    def check(self, *, permit=True):
        _need(self.pid == os.getpid(), 'transaction_process_changed')
        self.journal.check_lock()
        _need(self.journal.boot_id() == self.boot, 'projection_boot_changed')
        _need(self.phase not in TERMINAL, 'projection_transaction_closed')
        _need(self.phase != 'HANDED_OFF', 'projection_transaction_handed_off')
        if permit and self.permit is not None:
            self.permit.check(self.plan, self.boot, self.journal.clock())
        if self.deployment is not None:
            self.deployment.check(self.journal.clock())
            self.deployment.check_plan(self.plan)

    def note(self, kind, details):
        self.check()
        _need(type(kind) is str and 0 < len(kind) <= 64, 'projection_operation_kind')
        raw = canonical(details)
        _need(len(raw) <= 1024*1024, 'projection_operation_size')
        with self.journal.connection() as con:
            con.execute('INSERT INTO projection_operations(txid,kind,details_json) VALUES(?,?,?)',
                        (self.txid, kind, raw.decode()))

    def _phase(self, phase, inventory=None):
        self.check()
        with self.journal.connection() as con:
            if inventory is not None:
                con.execute('UPDATE projection_transactions SET inventory_json=? WHERE txid=?', (canonical(inventory).decode(), self.txid))
            con.execute('UPDATE projection_transactions SET phase=? WHERE txid=?', (phase, self.txid))
        self.phase = phase

    def prepared(self, inventory):
        _need(self.phase == 'INTENT', 'projection_prepare_phase')
        self._phase('PREPARED', inventory)

    def handoff(self, secret):
        _need(self.permit is None and self.plan['action'] == 'restore' and self.phase == 'INTENT'
              and not self.resources and type(secret) is str and re.fullmatch('[0-9a-f]{64}', secret), 'invalid_boot_handoff')
        self.check()
        with self.journal.connection() as con:
            con.execute("UPDATE projection_transactions SET phase='HANDED_OFF',handoff_hash=? WHERE txid=?",
                        (hashlib.sha256(secret.encode()).hexdigest(), self.txid))
        self.phase = 'HANDED_OFF'

    def publish_intent(self):
        _need(self.phase == 'PREPARED', 'projection_publish_phase')
        self.check()
        for resource in self.resources:
            resource.revalidate()
        self._phase('PUBLISH_INTENT')

    def published(self):
        _need(self.phase == 'PUBLISH_INTENT', 'projection_readback_phase')
        self._phase('PUBLISHED')

    def commit(self):
        _need(self.phase == 'PUBLISHED', 'projection_commit_phase')
        self._phase('COMMITTED')

    def close_recovery(self, phase):
        _need(self.recovering and phase in {'ABORTED','QUARANTINED','RECOVERED'}, 'projection_recovery_phase')
        self._phase(phase)

    def allow_selector(self, scope_id, generation):
        self.check()
        _need(scope_id == self.plan['scope_id'], 'selector_wrong_scope')
        if self.recovering:
            _need(generation == 0, 'recovery_cannot_publish_execution_authority')
        elif self.plan['action'] in {'quarantine'}:
            _need(generation == 0, 'quarantine_requires_zero_selector')
        else:
            _need(self.plan['action'] in {'activate','rollback','restore'}
                  and generation == self.plan['generation'], 'selector_not_authorized')
            if self.plan['action'] == 'restore':
                _need(self.deployment is not None, 'signed_boot_deployment_required')
        _need(self.recovering or self.phase == 'PUBLISH_INTENT', 'selector_requires_durable_publish_intent')


def default_journal():
    return Journal()
