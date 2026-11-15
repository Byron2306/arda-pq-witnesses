"""Strict, offline-capable R13 v2 verification and signed receipts."""
from dataclasses import dataclass
import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import struct
import time
from types import MappingProxyType
import uuid
from contextlib import closing

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

PCRS = (0, 1, 4, 7, 8, 9, 11)
PCR_SELECTION = "sha256:" + ",".join(map(str, PCRS))
CHALLENGE_SCHEMA = "arda.r13.challenge.v2"
RECEIPT_SCHEMA = "arda.r13.evidence_receipt.v2"
CHALLENGE_FIELDS = frozenset(("schema", "verifier_id", "node_id", "boot_id", "challenge_id",
                              "nonce", "issued_at", "expires_at", "policy_sha256"))
EVIDENCE_FIELDS = frozenset(("challenge_id", "boot_id", "pcrs", "quote_b64", "signature_b64"))
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
MAX_BODY = 65536


class Refusal(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def need(ok, code):
    if not ok:
        raise Refusal(code)


def shape(obj, keys, code):
    need(type(obj) is dict and obj.keys() == keys, code)


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def is_boot(value):
    if type(value) is not str or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except ValueError:
        return False


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def strict_json(raw):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            need(k not in out, "JSON_DUPLICATE_KEY")
            out[k] = v
        return out

    def bad_constant(_):
        raise Refusal("JSON_NONFINITE")

    need(len(raw) <= MAX_BODY, "BODY_SIZE")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=bad_constant)
    except Refusal:
        raise
    except (ValueError, RecursionError) as exc:
        raise Refusal("JSON_FORMAT") from exc


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(obj):
    return sha(canonical(obj))


def public_pin(key):
    return sha(key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo))


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(value, cap, code):
    need(type(value) is str and 0 < len(value) <= (cap + 2) // 3 * 4, code)
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Refusal(code) from exc
    need(0 < len(data) <= cap and encode(data) == value, code)
    return data


def normalized_pcrs(values):
    shape(values, {str(n) for n in PCRS}, "PCR_FIELDS")
    need(all(matches(HEX64, v) for v in values.values()), "PCR_VALUE_FORMAT")
    return dict(values)


def validate_challenge(challenge):
    shape(challenge, CHALLENGE_FIELDS, "CHALLENGE_FIELDS")
    need(challenge["schema"] == CHALLENGE_SCHEMA and
         matches(ID, challenge["verifier_id"]) and matches(ID, challenge["node_id"]) and
         is_boot(challenge["boot_id"]) and matches(HEX32, challenge["challenge_id"]) and
         matches(HEX64, challenge["nonce"]) and matches(HEX64, challenge["policy_sha256"]) and
         type(challenge["issued_at"]) is int and type(challenge["expires_at"]) is int and
         0 < challenge["expires_at"] - challenge["issued_at"] <= 300, "CHALLENGE_FORMAT")


def qualifying_data(challenge):
    validate_challenge(challenge)
    return hashlib.sha256(b"ARDA/R13/TPM-QUOTE/v2\0" + canonical(challenge)).digest()


def sign_challenge(challenge, signer):
    validate_challenge(challenge)
    return {"challenge": challenge, "ed25519_signature_b64": encode(signer.sign(
        b"ARDA/R13/ISSUED-CHALLENGE/v2\0" + canonical(challenge)))}


def verify_issued_challenge(envelope, pinned_key):
    shape(envelope, {"challenge", "ed25519_signature_b64"}, "SIGNED_CHALLENGE_FIELDS")
    need(isinstance(pinned_key, ed25519.Ed25519PublicKey), "CHALLENGE_PUBLIC_KEY")
    challenge = envelope["challenge"]
    validate_challenge(challenge)
    signature = decode(envelope["ed25519_signature_b64"], 64, "CHALLENGE_SIGNATURE_ENCODING")
    try:
        pinned_key.verify(signature, b"ARDA/R13/ISSUED-CHALLENGE/v2\0" + canonical(challenge))
    except InvalidSignature as exc:
        raise Refusal("CHALLENGE_SIGNATURE") from exc
    return challenge


@dataclass(frozen=True)
class NodePolicy:
    ak: rsa.RSAPublicKey
    pcrs: dict

    def __post_init__(self):
        need(isinstance(self.ak, rsa.RSAPublicKey) and 2048 <= self.ak.key_size <= 4096,
             "AK_TYPE")
        normalized = normalized_pcrs(self.pcrs)
        need(all(normalized[str(n)] != "00" * 32 for n in PCRS), "PCR_POLICY_ZERO")
        object.__setattr__(self, "pcrs", MappingProxyType(normalized))

    @property
    def ak_sha256(self):
        return public_pin(self.ak)

    @property
    def sha256(self):
        return digest({"schema": "arda.r13.pcr_policy.v2", "ak_spki_sha256": self.ak_sha256,
                       "pcr_selection": PCR_SELECTION, "pcrs": dict(self.pcrs)})


class Cursor:
    def __init__(self, data, code):
        self.data = data
        self.offset = 0
        self.code = code

    def take(self, n):
        need(0 <= n <= len(self.data) - self.offset, self.code)
        out = self.data[self.offset:self.offset+n]
        self.offset += n
        return out

    def number(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def blob(self, cap):
        n = self.number(">H")
        need(n <= cap, self.code)
        return self.take(n)

    def end(self):
        need(self.offset == len(self.data), self.code)


def verify_quote(message, tss_sig, pcrs, expected_qualification, policy):
    """Appraise raw TPMS_ATTEST and TPMT_SIGNATURE against verifier-owned inputs."""
    q = Cursor(message, "QUOTE_FORMAT")
    need(q.number(">I") == 0xff544347 and q.number(">H") == 0x8018, "QUOTE_TYPE")
    q.blob(68)  # qualifiedSigner is not a substitute for the enrolled AK.
    need(hmac.compare_digest(q.blob(64), expected_qualification), "QUOTE_QUALIFICATION")
    q.take(25)  # TPMS_CLOCK_INFO and firmwareVersion.
    need(q.number(">I") == 1 and q.number(">H") == 0xb, "QUOTE_SELECTION")
    width = q.number(">B")
    need(1 <= width <= 4 and int.from_bytes(q.take(width), "little") ==
         sum(1 << n for n in PCRS), "QUOTE_SELECTION")
    quoted_digest = q.blob(32)
    q.end()
    pcr_digest = hashlib.sha256(b"".join(bytes.fromhex(pcrs[str(n)]) for n in PCRS)).digest()
    need(hmac.compare_digest(quoted_digest, pcr_digest), "QUOTE_PCR_DIGEST")
    s = Cursor(tss_sig, "QUOTE_SIGNATURE_FORMAT")
    need(s.number(">H") == 0x14 and s.number(">H") == 0xb, "QUOTE_SIGNATURE_SCHEME")
    raw = s.blob(512)
    s.end()
    need(len(raw) == (policy.ak.key_size + 7) // 8, "QUOTE_SIGNATURE_FORMAT")
    try:
        policy.ak.verify(raw, message, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise Refusal("QUOTE_SIGNATURE") from exc
    need(pcrs == policy.pcrs, "PCR_POLICY_MISMATCH")


class Verifier:
    def __init__(self, verifier_id, signer, policy, db, *, clock=time.time):
        need(matches(ID, verifier_id) and isinstance(signer, ed25519.Ed25519PrivateKey),
             "VERIFIER_CONFIGURATION")
        need(bool(policy) and all(matches(ID, node) and isinstance(p, NodePolicy)
                                  for node, p in policy.items()), "POLICY_CONFIGURATION")
        self.verifier_id, self.signer = verifier_id, signer
        self.policy, self.clock = MappingProxyType(dict(policy)), clock
        self.db = Path(db).absolute()
        parent = self.db.parent.lstat()
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
             not parent.st_mode & 0o077, "STATE_DIRECTORY_PERMISSIONS")
        fd = os.open(self.db, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 info.st_uid == os.geteuid() and not info.st_mode & 0o077, "STATE_FILE_PERMISSIONS")
        finally:
            os.close(fd)
        with closing(self.connect()) as con:
            con.execute("""CREATE TABLE IF NOT EXISTS r13v2_challenge (
                id TEXT PRIMARY KEY, node TEXT NOT NULL, expires INTEGER NOT NULL,
                payload TEXT NOT NULL, consumed INTEGER
            )""")

    def connect(self):
        con = sqlite3.connect(self.db, timeout=4, isolation_level=None)
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA trusted_schema=OFF")
        return con

    def issue(self, request):
        shape(request, {"node_id", "boot_id"}, "ISSUE_FIELDS")
        node, boot = request["node_id"], request["boot_id"]
        need(matches(ID, node) and node in self.policy and is_boot(boot), "ISSUE_NODE_OR_BOOT")
        with closing(self.connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            now = int(self.clock())
            con.execute("DELETE FROM r13v2_challenge WHERE expires <= ?", (now,))
            open_count, = con.execute(
                "SELECT count(*) FROM r13v2_challenge WHERE node=?", (node,)).fetchone()
            need(open_count < 32, "CHALLENGE_LIMIT")
            challenge = {"schema": CHALLENGE_SCHEMA, "verifier_id": self.verifier_id,
                         "node_id": node, "boot_id": boot, "challenge_id": secrets.token_hex(16),
                         "nonce": secrets.token_hex(32), "issued_at": now, "expires_at": now+120,
                         "policy_sha256": self.policy[node].sha256}
            con.execute("INSERT INTO r13v2_challenge VALUES (?, ?, ?, ?, NULL)",
                        (challenge["challenge_id"], node, challenge["expires_at"],
                         canonical(challenge).decode("ascii")))
            con.commit()
        return challenge

    def verify(self, evidence):
        shape(evidence, EVIDENCE_FIELDS, "EVIDENCE_FIELDS")
        cid, boot = evidence["challenge_id"], evidence["boot_id"]
        need(matches(HEX32, cid) and is_boot(boot), "EVIDENCE_IDENTIFIERS")
        pcrs = normalized_pcrs(evidence["pcrs"])
        message = decode(evidence["quote_b64"], 4096, "QUOTE_ENCODING")
        signature = decode(evidence["signature_b64"], 1024, "SIGNATURE_ENCODING")
        with closing(self.connect()) as con:
            row = con.execute("SELECT payload, expires, consumed FROM r13v2_challenge WHERE id=?",
                              (cid,)).fetchone()
        now = int(self.clock())
        need(row is not None and row[2] is None and now < row[1], "CHALLENGE_UNAVAILABLE")
        challenge = strict_json(row[0].encode("ascii"))
        validate_challenge(challenge)
        need(challenge["challenge_id"] == cid and challenge["verifier_id"] == self.verifier_id and
             challenge["issued_at"] <= now < challenge["expires_at"] == row[1], "CHALLENGE_UNAVAILABLE")
        need(challenge["boot_id"] == boot, "CHALLENGE_BOOT_MISMATCH")
        policy = self.policy.get(challenge["node_id"])
        need(policy is not None and policy.sha256 == challenge["policy_sha256"], "CHALLENGE_POLICY_CHANGED")
        qualification = qualifying_data(challenge)
        verify_quote(message, signature, pcrs, qualification, policy)
        with closing(self.connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            issued = int(self.clock())
            need(challenge["issued_at"] <= issued < challenge["expires_at"], "CHALLENGE_UNAVAILABLE")
            changed = con.execute("""UPDATE r13v2_challenge SET consumed=?
                    WHERE id=? AND consumed IS NULL AND expires>? AND payload=?""",
                    (issued, cid, issued, row[0])).rowcount
            need(changed == 1, "CHALLENGE_UNAVAILABLE")
            con.commit()
        payload = {
            "schema": RECEIPT_SCHEMA, "status": "PASS",
            "verifier_id": self.verifier_id, "node_id": challenge["node_id"], "boot_id": boot,
            "challenge_id": cid, "challenge_sha256": digest(challenge),
            "qualification_sha256": qualification.hex(), "evidence_sha256": digest(evidence),
            "quote_sha256": sha(message), "quote_signature_sha256": sha(signature),
            "ak_spki_sha256": policy.ak_sha256, "policy_sha256": policy.sha256,
            "pcr_selection": PCR_SELECTION, "issued_at": issued,
            "expires_at": challenge["expires_at"], "production_cutover_authorized": False,
        }
        return {"payload": payload, "ed25519_signature_b64": encode(self.signer.sign(
            b"ARDA/R13/EVIDENCE-RECEIPT/v2\0" + canonical(payload)))}


def verify_receipt(receipt, pinned_key, challenge, evidence, *, now=None):
    shape(receipt, {"payload", "ed25519_signature_b64"}, "RECEIPT_FIELDS")
    need(isinstance(pinned_key, ed25519.Ed25519PublicKey), "RECEIPT_PUBLIC_KEY")
    payload = receipt["payload"]
    shape(payload, {"schema", "status", "verifier_id", "node_id", "boot_id", "challenge_id",
                    "challenge_sha256", "qualification_sha256", "evidence_sha256", "quote_sha256",
                    "quote_signature_sha256", "ak_spki_sha256", "policy_sha256", "pcr_selection",
                    "issued_at", "expires_at", "production_cutover_authorized"}, "RECEIPT_PAYLOAD_FIELDS")
    sig = decode(receipt["ed25519_signature_b64"], 64, "RECEIPT_SIGNATURE_ENCODING")
    try:
        pinned_key.verify(sig, b"ARDA/R13/EVIDENCE-RECEIPT/v2\0" + canonical(payload))
    except InvalidSignature as exc:
        raise Refusal("RECEIPT_SIGNATURE") from exc
    qualification = qualifying_data(challenge)
    shape(evidence, EVIDENCE_FIELDS, "EVIDENCE_FIELDS")
    for field in ("boot_id", "challenge_id"):
        need(challenge[field] == evidence[field], "RECEIPT_EVIDENCE_CONTEXT")
    for field in ("verifier_id", "node_id", "boot_id", "challenge_id", "policy_sha256", "expires_at"):
        need(payload[field] == challenge[field], "RECEIPT_CHALLENGE_CONTEXT")
    current = int(time.time()) if now is None else now
    need(payload["schema"] == RECEIPT_SCHEMA and payload["status"] == "PASS" and
         payload["production_cutover_authorized"] is False and
         payload["pcr_selection"] == PCR_SELECTION and
         type(payload["issued_at"]) is int and
         challenge["issued_at"] <= payload["issued_at"] <= current < challenge["expires_at"] and
         matches(HEX64, payload["ak_spki_sha256"]), "RECEIPT_POLICY_OR_EXPIRY")
    need(payload["challenge_sha256"] == digest(challenge) and
         payload["qualification_sha256"] == qualification.hex() and
         payload["evidence_sha256"] == digest(evidence) and
         payload["quote_sha256"] == sha(decode(evidence["quote_b64"], 4096, "QUOTE_ENCODING")) and
         payload["quote_signature_sha256"] ==
         sha(decode(evidence["signature_b64"], 1024, "SIGNATURE_ENCODING")), "RECEIPT_EVIDENCE_DIGEST")
    return payload
