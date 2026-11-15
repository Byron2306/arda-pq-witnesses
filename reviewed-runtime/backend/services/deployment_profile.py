"""Off-box signed conditional boot/deployment authority; not a quote receipt."""
import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from types import MappingProxyType
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .production_files import protected_bytes, protected_json
from .projection_journal import canonical, _need

DOMAIN = b'ARDA/BOOT-DEPLOYMENT/v1\0'
FIELDS = frozenset({'schema','deployment_id','issued_at','expires_at','subject_machine_id_sha256',
    'node_id','manifest_id','manifest_digest','generation','policy_generation','boot_scope_path',
    'loader_path','bpf_object_path','kernel_path','initrd_path','artifacts','minimum_map_capacity',
    'minimum_free_rows','production_admission_authorized','r13_policy_sha256',
    'r13_verifier_spki_sha256','r13_ak_spki_sha256','r13_subject_node_id'})


@dataclass(frozen=True)
class VerifiedDeployment:
    payload: object
    sha256: str

    def check(self, now):
        _need(type(now) is int and self.payload['issued_at'] <= now < self.payload['expires_at'], 'deployment_profile_expired_or_future')

    def check_plan(self, plan):
        p = self.payload
        _need(plan['action'] == 'restore' and plan['scope_path'] == p['boot_scope_path']
              and all(plan[k] == p[k] for k in ('node_id','manifest_id','manifest_digest','generation')), 'deployment_boot_plan_binding')

    def verify_artifacts(self):
        for name, expected in self.payload['artifacts'].items():
            _need(hashlib.sha256(protected_bytes(name, cap=512*1024*1024)).hexdigest() == expected, 'deployment_artifact_changed:'+name)
        machine = protected_bytes('/etc/machine-id', 4096).strip()
        _need(hashlib.sha256(machine).hexdigest() == self.payload['subject_machine_id_sha256'], 'deployment_subject_machine')


def verify_deployment(envelope, key, now):
    _need(type(envelope) is dict and envelope.keys() == {'payload','signature_b64'}, 'deployment_envelope')
    p = envelope['payload']
    _need(type(p) is dict and p.keys() == FIELDS and p['schema'] == 'arda.boot.deployment.v1', 'deployment_fields')
    _need(type(p['deployment_id']) is str and re.fullmatch('[0-9a-f]{32}',p['deployment_id']), 'deployment_id')
    _need(type(p['issued_at']) is int and type(p['expires_at']) is int
          and 0 < p['expires_at']-p['issued_at'] <= 30*86400, 'deployment_times')
    _need(type(p['generation']) is int and 0 < p['generation'] < 2**63, 'deployment_generation')
    _need(type(p['minimum_map_capacity']) is int and p['minimum_map_capacity'] >= 8192
          and type(p['minimum_free_rows']) is int and p['minimum_free_rows'] >= 0, 'deployment_capacity')
    _need(type(p['production_admission_authorized']) is bool, 'deployment_admission_type')
    _need(type(p['artifacts']) is dict and 4 <= len(p['artifacts']) <= 4096, 'deployment_artifacts')
    for name, digest in p['artifacts'].items():
        _need(type(name) is str and name.startswith(('/usr/lib/arda/','/usr/local/libexec/arda/','/boot/','/etc/arda/'))
              and '..' not in Path(name).parts and type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest), 'deployment_artifact_fields')
    for field in ('loader_path','bpf_object_path','kernel_path','initrd_path'):
        _need(p[field] in p['artifacts'], 'deployment_missing_critical_artifact')
    _need(type(p['subject_machine_id_sha256']) is str and re.fullmatch('[0-9a-f]{64}',p['subject_machine_id_sha256']), 'deployment_subject')
    _need(type(p['manifest_digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}',p['manifest_digest']), 'deployment_manifest_digest')
    _need(type(p['policy_generation']) is str and bool(p['policy_generation']), 'deployment_policy_generation')
    for field in ('node_id','manifest_id','r13_subject_node_id'):
        _need(type(p[field]) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}',p[field]), 'deployment_'+field)
    for field in ('r13_policy_sha256','r13_verifier_spki_sha256','r13_ak_spki_sha256'):
        _need(type(p[field]) is str and re.fullmatch('[0-9a-f]{64}',p[field]),'deployment_'+field)
    _need(type(p['boot_scope_path']) is str and p['boot_scope_path'].startswith('/sys/fs/cgroup/')
          and '..' not in Path(p['boot_scope_path']).parts, 'deployment_boot_scope')
    _need(isinstance(key, Ed25519PublicKey), 'deployment_public_key_type')
    try:
        signature = base64.b64decode(envelope['signature_b64'],validate=True)
        _need(len(signature)==64,'deployment_signature_length')
        key.verify(signature,DOMAIN+canonical(p))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise ValueError('deployment_signature') from exc
    # Copy nested artifacts to prevent mutation after verification.
    frozen = dict(p); frozen['artifacts'] = MappingProxyType(dict(p['artifacts']))
    result = VerifiedDeployment(MappingProxyType(frozen),hashlib.sha256(canonical(p)).hexdigest())
    result.check(now)
    return result


def load_profile(config_path='/etc/arda/production-profile.json', *, now):
    config = protected_json(config_path)
    raw = protected_bytes(config['release_public_key'],8192)
    _need(hashlib.sha256(raw).hexdigest() == config['release_public_key_file_sha256'], 'release_authority_pin_changed')
    key = serialization.load_pem_public_key(raw)
    deployment = verify_deployment(protected_json(config['deployment_envelope']),key,now)
    deployment.verify_artifacts()
    return config, deployment, key
