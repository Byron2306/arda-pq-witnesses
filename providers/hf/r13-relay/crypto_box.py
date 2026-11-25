"""Domain-separated ephemeral X25519 + HKDF-SHA256 + AES256-GCM message box."""
import base64
import hashlib
import json
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CONTEXT = b'ARDA/R13/HF-TO-GITHUB/SEALED/v1'

def b64(data): return base64.b64encode(data).decode('ascii')

def unb64(s):
    if not isinstance(s, str) or len(s) > 65536:
        raise ValueError('INVALID_BASE64')
    value = base64.b64decode(s, validate=True)
    if b64(value) != s:
        raise ValueError('INVALID_BASE64_CANONICAL')
    return value

def canonical(x): return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def hash_envelope(box): return hashlib.sha256(canonical(box)).hexdigest()

def kdf(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=CONTEXT).derive(shared)

def seal(plaintext, recipient_pub):
    if not 0 < len(plaintext) <= 32768: raise ValueError('CAPTURE_SIZE')
    eph = x25519.X25519PrivateKey.generate()
    public = x25519.X25519PublicKey.from_public_bytes(recipient_pub)
    pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    nonce = secrets.token_bytes(12)
    data = AESGCM(kdf(eph.exchange(public))).encrypt(nonce, plaintext, CONTEXT)
    return {'schema':'arda.r13.relay_box.v1', 'ephemeral_public_b64':b64(pub), 'nonce_b64':b64(nonce), 'ciphertext_b64':b64(data)}

def unseal(box, recipient_private):
    if not isinstance(box, dict) or set(box) != {'schema','ephemeral_public_b64','nonce_b64','ciphertext_b64'} or box['schema'] != 'arda.r13.relay_box.v1': raise ValueError('BOX_FIELDS')
    pub, nonce, data = (unb64(box[k]) for k in ('ephemeral_public_b64','nonce_b64','ciphertext_b64'))
    if len(pub) != 32 or len(nonce) != 12 or not 16 < len(data) <= 32784: raise ValueError('BOX_LENGTHS')
    sk = x25519.X25519PrivateKey.from_private_bytes(recipient_private)
    plain = AESGCM(kdf(sk.exchange(x25519.X25519PublicKey.from_public_bytes(pub)))).decrypt(nonce, data, CONTEXT)
    if not 0 < len(plain) <= 32768: raise ValueError('CAPTURE_SIZE')
    return plain
