"""Signed reservation and durable dispatch intent; no production execution API.

Trust anchors and context are supplied by a protected supervisor, never the wire.
This contract is distinct from boot deployment authority and production admission.
The database/authority require a separate protected identity at installation.
"""
import json
import math
import os
from pathlib import Path
import stat
from types import MappingProxyType
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .controller import canonical, digest, decision
from .sender import Authority

DOMAIN = b'ARDA/IRON-CITADEL/RESERVATION/v1\0'
CONTEXT = frozenset({'generation','node_id','manifest_id','manifest_digest',
    'deployment_profile_sha256','boot_id','boot_scope_path','machine_id_sha256'})
FIELDS = CONTEXT | {'schema','admission_id','operation_id','action','worker_uid',
    'worker_gid','issued_at','expires_at'}


class ReleaseAuthority(Authority):
    def __init__(self, database, *, admission_key, context, clock=None):
        if not isinstance(admission_key, Ed25519PublicKey):
            raise ValueError('admission_public_key_required')
        if type(context) is not dict or context.keys() != CONTEXT:
            raise ValueError('reservation_context_fields')
        if type(context['generation']) is not int or context['generation'] <= 0:
            raise ValueError('reservation_context_generation')
        if not all(type(context[k]) is str and context[k] for k in CONTEXT-{'generation'}):
            raise ValueError('reservation_context_values')
        self.context = MappingProxyType(dict(context))
        self.admission_key = admission_key
        path=Path(database).absolute()
        parent=path.parent
        if any(p.is_symlink() for p in (parent,*parent.parents)):
            raise ValueError('private_database_parent_symlink')
        info=parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('private_database_parent_required')
        try:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        except FileExistsError:
            info=path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise ValueError('private_database_required')
        else:
            os.close(fd)
        super().__init__(path, clock=clock, admission_guard=self._signed_guard)
        if self.context['boot_id'] != self.boot:
            raise ValueError('reservation_context_boot')
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS signed_admissions(operation_id TEXT PRIMARY KEY, envelope TEXT NOT NULL)')

    def _now(self):
        import time
        value=self.clock() if self.clock is not None else time.time()
        if type(value) not in (float,int) or not math.isfinite(value) or value <= 0:
            raise ValueError('reservation_clock')
        return value

    def _verify(self, envelope, *, check_time=True):
        if type(envelope) is not dict or envelope.keys() != {'payload','signature_hex'}:
            raise ValueError('reservation_envelope')
        p=envelope['payload']
        if type(p) is not dict or p.keys() != FIELDS:
            raise ValueError('reservation_fields')
        if p['schema'] != 'arda.iron_citadel.reservation.v1' or p['action'] != 'dispatch_intent':
            raise ValueError('reservation_action')
        if any(p[k] != self.context[k] or type(p[k]) is not type(self.context[k]) for k in CONTEXT):
            raise ValueError('reservation_context_binding')
        for k in ('admission_id','operation_id'):
            if type(p[k]) is not str or not 0 < len(p[k]) <= 256:
                raise ValueError('reservation_identity')
        for k in ('worker_uid','worker_gid'):
            if type(p[k]) is not int or not 0 <= p[k] < 2**32-1:
                raise ValueError('reservation_worker')
        for k in ('issued_at','expires_at'):
            if type(p[k]) is not int or p[k] <= 0:
                raise ValueError('reservation_time_type')
        if not 0 < p['expires_at']-p['issued_at'] <= 300:
            raise ValueError('reservation_time_window')
        if check_time and not p['issued_at'] <= self._now() < p['expires_at']:
            raise ValueError('reservation_expired_or_future')
        signature=envelope['signature_hex']
        if type(signature) is not str or len(signature) != 128:
            raise ValueError('reservation_signature_format')
        self.admission_key.verify(bytes.fromhex(signature),DOMAIN+canonical(p))
        return p

    def reserve_signed(self, envelope):
        try:
            # Snapshot untrusted containers before verification and storage.
            envelope=json.loads(canonical(envelope))
            self._verify(envelope)
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                try:
                    p=self._verify(envelope)
                    db.execute('INSERT INTO operations(operation_id,admission_id,admission_sha256,state,clock_watermark,admission_expires_at) VALUES(?,?,?,\'RESERVED\',?,?)',
                        (p['operation_id'],p['admission_id'],digest(envelope),self._now(),p['expires_at']))
                    db.execute('INSERT INTO signed_admissions VALUES(?,?)',(p['operation_id'],canonical(envelope).decode()))
                    db.execute('COMMIT')
                except BaseException:
                    db.execute('ROLLBACK')
                    raise
            return decision(True,'SIGNED_RESERVATION_STORED',admission_sha256=digest(envelope))
        except Exception:
            return decision(False,'SIGNED_RESERVATION_REFUSED')

    def _signed_guard(self, db, peer, operation_id, admission_id, admission_sha256):
        row=db.execute('SELECT envelope FROM signed_admissions WHERE operation_id=?',(operation_id,)).fetchone()
        if row is None:
            raise ValueError('signed_reservation_missing')
        # The fenced controller observes time and records its watermark before
        # refusing expiry. Checking expiry here would roll back that observation
        # and allow a later wall-clock rollback to resurrect an expired claim.
        envelope=json.loads(row[0]);p=self._verify(envelope,check_time=False)
        deadline=db.execute('SELECT admission_expires_at FROM operations WHERE operation_id=?',(operation_id,)).fetchone()
        if deadline is None or deadline[0] != p['expires_at']:
            raise ValueError('signed_reservation_deadline_binding')
        if (p['operation_id'] != operation_id or p['admission_id'] != admission_id
                or digest(envelope) != admission_sha256
                or (p['worker_uid'],p['worker_gid']) != peer.credentials[1:]):
            raise ValueError('signed_reservation_binding')

    def request(self, peer, req):
        if type(req) is not dict or req.get('action') == 'complete':
            return decision(False,'REAL_COMPLETION_EVIDENCE_REQUIRED')
        return super().request(peer,req)
