#!/usr/bin/env python3
"""D3.74T.3R: Standalone fenced controller. OFFLINE LAB ONLY."""

from contextlib import contextmanager
import hashlib
import json
import math
import sqlite3
import time
from pathlib import Path


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False
    ).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decision(allow, reason, **fields):
    return {
        "decision": "ALLOW" if allow else "REFUSE",
        "reason": reason,
        "production_authorized": False,
        "interlock": "KEEP_CLOSED",
        **fields,
    }


class FencedController:
    """Standalone laboratory controller. No inherited mutation API."""

    def __init__(self, path, *, clock=None, transaction_guard=None, transaction_commit_hook=None):
        self.__authority_guard = transaction_guard
        self.__commit_hook = transaction_commit_hook
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.__clock = clock if clock is not None else time.time

        with self.__connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("""
                    CREATE TABLE IF NOT EXISTS operations (
                        operation_id TEXT PRIMARY KEY,
                        admission_id TEXT NOT NULL UNIQUE,
                        admission_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (
                            state IN (
                                'RESERVED',
                                'DISPATCH_INTENT',
                                'UNCERTAIN',
                                'COMPLETED'
                            )
                        ),
                        owner_id TEXT,
                        fence_token INTEGER NOT NULL DEFAULT 0,
                        lease_until REAL,
                        clock_watermark REAL NOT NULL,
                        completion_sha256 TEXT,
                        admission_expires_at REAL
                    )
                """)
                columns={row[1] for row in db.execute('PRAGMA table_info(operations)')}
                if 'admission_expires_at' not in columns:
                    # An old row has no established admission deadline. Preserve
                    # its history but refuse new authority until independently rebound.
                    db.execute('ALTER TABLE operations ADD COLUMN admission_expires_at REAL')
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    @contextmanager
    def __connect(self):
        db = sqlite3.connect(
            str(self.path), timeout=15, isolation_level=None
        )
        try:
            db.execute("PRAGMA busy_timeout=15000")
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    def __time(self):
        value = self.__clock()
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError("CLOCK_INVALID")
        return float(value)

    def __transaction(self, operation_id, admission_id, admission_sha256,
                      handler, *, allow_expired=False):
        try:
            now = self.__time()
            with self.__connect() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute("""
                        SELECT state, owner_id, fence_token,
                               lease_until, clock_watermark,
                               completion_sha256, admission_expires_at
                        FROM operations
                        WHERE operation_id = ?
                          AND admission_id = ?
                          AND admission_sha256 = ?
                    """, (
                        operation_id, admission_id, admission_sha256
                    )).fetchone()

                    if row is None:
                        db.execute("ROLLBACK")
                        return decision(False, "BINDING_INVALID")

                    state, owner, token, until, watermark, completion, deadline = row
                    if self.__authority_guard is not None:
                        self.__authority_guard(db, operation_id, token)

                    if now < watermark:
                        db.execute("ROLLBACK")
                        return decision(False, "CLOCK_ROLLBACK")

                    # Persist the greatest observed clock even when a
                    # subsequent authority check refuses the operation.
                    db.execute("""
                        UPDATE operations
                        SET clock_watermark = ?
                        WHERE operation_id = ?
                    """, (now, operation_id))

                    if (not allow_expired and state != 'COMPLETED'
                            and (type(deadline) not in (int,float) or not math.isfinite(deadline)
                                 or now >= deadline)):
                        db.execute('COMMIT')
                        return decision(False, 'ADMISSION_EXPIRED_OR_UNBOUND')
                    response = handler(
                        db, now, state, owner, token, until, completion, deadline
                    )
                    if self.__commit_hook is not None:
                        self.__commit_hook(db, operation_id, response)
                    db.execute("COMMIT")
                    return response

                except BaseException:
                    db.execute("ROLLBACK")
                    raise

        except Exception as exc:
            return decision(
                False, "TRANSACTION_ERROR:" + type(exc).__name__
            )

    def reserve(self, aid, oid, admission, *, verified=False,
                expires_at=None):
        # Synthetic verification assertion. NOT production authorization.
        if verified is not True:
            return decision(False, "UNVERIFIED")

        if not all(
            isinstance(v, str) and 0 < len(v) <= 256
            for v in (aid, oid)
        ):
            return decision(False, "IDENTITY_INVALID")

        if (
            not isinstance(admission, dict)
            or admission.get("payload", {}).get("admission_id") != aid
        ):
            return decision(False, "ADMISSION_INVALID")

        try:
            now = self.__time()
            if (type(expires_at) not in (int,float) or not math.isfinite(expires_at)
                    or now >= expires_at):
                return decision(False, "ADMISSION_EXPIRED")

            ah = digest(admission)

            with self.__connect() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("""
                        INSERT INTO operations (
                            operation_id, admission_id,
                            admission_sha256, state, clock_watermark, admission_expires_at
                        )
                        VALUES (?, ?, ?, 'RESERVED', ?, ?)
                    """, (oid, aid, ah, now, float(expires_at)))
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

            return decision(
                True, "LAB_RESERVED", admission_sha256=ah
            )

        except sqlite3.IntegrityError:
            return decision(False, "REPLAY_OR_OPERATION_DUPLICATE")
        except Exception as exc:
            return decision(
                False, "RESERVATION_ERROR:" + type(exc).__name__
            )

    def claim(self, oid, aid, ah, owner_id, *, lease_seconds=30):
        if (
            not isinstance(owner_id, str)
            or not 0 < len(owner_id) <= 256
            or type(lease_seconds) not in (int, float)
            or not math.isfinite(lease_seconds)
            or not 0 < lease_seconds <= 300
        ):
            return decision(False, "CLAIM_ARGUMENT_INVALID")

        def action(db, now, state, owner, token, until, completion, deadline):
            if state != "RESERVED":
                return decision(False, "CLAIM_STATE_INVALID")

            if owner is not None and until is not None and now < until:
                return decision(False, "LEASE_ACTIVE")

            new_token = token + 1
            expiry = min(deadline, now + lease_seconds)

            db.execute("""
                UPDATE operations
                SET owner_id=?, fence_token=?, lease_until=?
                WHERE operation_id=?
            """, (owner_id, new_token, expiry, oid))

            return decision(
                True, "LAB_CLAIMED",
                owner_id=owner_id,
                fence_token=new_token,
                lease_until=expiry,
            )

        return self.__transaction(oid, aid, ah, action)

    def renew(self, oid, aid, ah, owner_id, token, *,
              lease_seconds=30):
        if (
            type(token) is not int
            or token <= 0
            or type(lease_seconds) not in (int, float)
            or not math.isfinite(lease_seconds)
            or not 0 < lease_seconds <= 300
        ):
            return decision(False, "RENEW_ARGUMENT_INVALID")

        def action(db, now, state, owner, current, until, completion, deadline):
            if state not in ("RESERVED", "DISPATCH_INTENT"):
                return decision(False, "RENEW_STATE_INVALID")

            if (
                owner != owner_id
                or current != token
                or until is None
                or now >= until
            ):
                return decision(False, "FENCE_REJECTED")

            expiry = min(deadline, max(until, now + lease_seconds))

            db.execute("""
                UPDATE operations SET lease_until=?
                WHERE operation_id=?
            """, (expiry, oid))

            return decision(
                True, "LAB_RENEWED", lease_until=expiry
            )

        return self.__transaction(oid, aid, ah, action)

    def dispatch(self, oid, aid, ah, owner_id, token):
        if type(token) is not int or token <= 0:
            return decision(False, "TOKEN_INVALID")

        def action(db, now, state, owner, current, until, completion, deadline):
            if state != "RESERVED":
                return decision(False, "DISPATCH_STATE_INVALID")

            if (
                owner != owner_id
                or current != token
                or until is None
                or now >= until
            ):
                return decision(False, "FENCE_REJECTED")

            db.execute("""
                UPDATE operations SET state='DISPATCH_INTENT'
                WHERE operation_id=?
            """, (oid,))

            return decision(True, "LAB_DISPATCH_INTENT")

        return self.__transaction(oid, aid, ah, action)

    def complete(self, oid, aid, ah, evidence, *,
                 owner_id, token):
        if type(token) is not int or token <= 0:
            return decision(False, "TOKEN_INVALID")

        if (
            not isinstance(evidence, dict)
            or evidence.get("operation_id") != oid
            or evidence.get("admission_id") != aid
            or evidence.get("admission_sha256") != ah
            or evidence.get("source") != "SYNTHETIC_LAB"
        ):
            return decision(False, "COMPLETION_BINDING_INVALID")

        evidence_hash = digest(evidence)

        def action(db, now, state, owner, current, until, stored, deadline):
            # Authority check precedes idempotency.
            if owner != owner_id or current != token:
                return decision(False, "FENCE_REJECTED")

            if state == "COMPLETED":
                if stored == evidence_hash:
                    return decision(
                        True, "LAB_COMPLETION_IDEMPOTENT",
                        completion_sha256=stored,
                    )
                return decision(False, "COMPLETION_CONFLICT")

            if state != "DISPATCH_INTENT":
                return decision(False, "COMPLETION_STATE_INVALID")

            if until is None or now >= until:
                return decision(False, "LEASE_EXPIRED")

            db.execute("""
                UPDATE operations
                SET state='COMPLETED', completion_sha256=?
                WHERE operation_id=?
            """, (evidence_hash, oid))

            return decision(
                True, "LAB_FENCED_COMPLETION",
                completion_sha256=evidence_hash,
            )

        return self.__transaction(oid, aid, ah, action)

    def recover_expired(self, oid, aid, ah):
        def action(db, now, state, owner, token, until, completion, deadline):
            if state != "DISPATCH_INTENT":
                return decision(False, "RECOVERY_STATE_INVALID")

            if until is None or now < until:
                return decision(False, "LEASE_NOT_EXPIRED")

            db.execute("""
                UPDATE operations
                SET state='UNCERTAIN',
                    owner_id=NULL,
                    lease_until=NULL,
                    fence_token=?
                WHERE operation_id=?
            """, (token + 1, oid))

            return decision(
                True, "LAB_RECOVERED_UNCERTAIN",
                fence_token=token + 1,
            )

        return self.__transaction(oid, aid, ah, action, allow_expired=True)

    def inspect(self, oid):
        with self.__connect() as db:
            return db.execute("""
                SELECT state, owner_id, fence_token,
                       lease_until, clock_watermark,
                       completion_sha256
                FROM operations WHERE operation_id=?
            """, (oid,)).fetchone()
