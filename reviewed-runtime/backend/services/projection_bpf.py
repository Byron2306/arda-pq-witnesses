"""Canonical pinned-map access for the scoped projection coordinator.

No map creation, loading, attachment, clearing, selector deletion or eviction.
Writes require an active durable projection transaction. Linux x86-64 only,
matching the supplied Valinor runtime's BPF syscall ABI.
"""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct

from .projection_journal import _need, require_transaction
from .proof_file_measurement import open_measured

PIN_ROOT = Path('/sys/fs/bpf/arda')
CONTRACTS = {
    'active_generation_map': (8, 8), 'measured_exec_map': (32, 4),
    'verity_identity_map': (88, 4), 'state_map': (4, 4),
    'policy_state_map': (4, 16), 'lockdown_map': (4, 4),
}
MAP_NAMES = {
    'active_generation_map': 'arda_active_generation_map',
    'measured_exec_map': 'arda_measured_exec_map',
    'verity_identity_map': 'arda_verity_identity_map',
    'state_map': 'arda_state_map', 'policy_state_map': 'arda_policy_state_map',
    'lockdown_map': 'arda_lockdown_map',
}
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long


def raw_bpf(command, attr, size):
    _need(platform.machine() == 'x86_64' and ctypes.sizeof(ctypes.c_void_p) == 8, 'unsupported_bpf_syscall_abi')
    return _LIBC.syscall(321, command, attr, size)


def _invoke(command, attr):
    rc = raw_bpf(command, attr, ctypes.sizeof(attr))
    if rc < 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
    return rc


def map_info(fd):
    info = ctypes.create_string_buffer(256)
    attr = ctypes.create_string_buffer(16)
    struct.pack_into('<IIQ', attr, 0, fd, len(info), ctypes.addressof(info))
    _invoke(15, attr)
    kind, identity, key_size, value_size, capacity, flags = struct.unpack_from('<6I', info.raw)
    name = info.raw[24:40].split(b'\0', 1)[0].decode('ascii')
    _need(0 < key_size <= 1024 and 0 < value_size <= 4096 and 0 < capacity <= 2**20, 'bpf_map_dimensions')
    return {'type': kind, 'id': identity, 'key_size': key_size,
            'value_size': value_size, 'capacity': capacity, 'flags': flags, 'name': name}


def _element_attr(fd, key, value=None):
    key_buffer = ctypes.create_string_buffer(key, len(key))
    value_buffer = ctypes.create_string_buffer(value, len(value)) if value is not None else None
    attr = ctypes.create_string_buffer(40)
    struct.pack_into('<I', attr, 0, fd)
    struct.pack_into('<Q', attr, 8, ctypes.addressof(key_buffer))
    if value_buffer is not None:
        struct.pack_into('<Q', attr, 16, ctypes.addressof(value_buffer))
    return attr, key_buffer, value_buffer


def _lookup_fd(fd, key, value_size):
    attr, kb, vb = _element_attr(fd, key, bytes(value_size))
    try:
        _invoke(1, attr)
        return vb.raw
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None
        raise


def authorize_map_write(pin_name, key, value, *, delete=False, active_reader=None):
    tx = require_transaction()
    action = tx.plan['action']
    if pin_name == 'active_generation_map':
        _need(not delete and len(key) == 8 and value is not None and len(value) == 8,
              'active_selector_deletion_forbidden')
        tx.allow_selector(struct.unpack('<Q', key)[0], struct.unpack('<Q', value)[0])
    elif pin_name in {'measured_exec_map', 'verity_identity_map'}:
        _need(len(key) >= 16, 'projection_key_size')
        scope, generation = struct.unpack_from('<QQ', key)
        _need(scope == tx.plan['scope_id'] and generation == tx.plan['generation'], 'projection_row_wrong_owner')
        if delete:
            _need(tx.recovering or action == 'collect' and tx.phase == 'PUBLISH_INTENT', 'projection_delete_requires_collection')
            _need(active_reader is not None and active_reader(scope) != generation, 'cannot_delete_active_allow_row')
        else:
            _need(not tx.recovering and action in {'activate','rollback','restore'} and tx.phase == 'INTENT'
                  and value == struct.pack('<I', 1), 'projection_prepare_not_authorized')
    elif pin_name == 'lockdown_map':
        _need(action == 'deny' and tx.phase == 'INTENT' and not delete and not tx.recovering
              and key == bytes(4) and value == struct.pack('<I',1), 'global_lockdown_release_forbidden')
    elif pin_name == 'state_map':
        _need(action == 'restore' and tx.deployment is not None and not tx.recovering and not delete
              and key == bytes(4) and value == struct.pack('<I', 3), 'global_mode_transition_forbidden')
    elif pin_name == 'policy_state_map':
        _need(action == 'restore' and tx.deployment is not None and not tx.recovering and not delete and key == bytes(4)
              and value is not None and len(value) == 16, 'global_policy_write_not_boot_restore')
        prefix, rules, flags = struct.unpack('<QII', value)
        _need(prefix != 0 and rules > 0 and flags == 1, 'boot_policy_not_present_or_triggered')
    else:
        raise ValueError('map_not_in_projection_write_contract')
    return tx


class PinnedMap:
    def __init__(self, pin_name, root=PIN_ROOT, *, read_only=False):
        _need(pin_name in CONTRACTS, 'unknown_projection_map')
        self.pin_name, self.path = pin_name, Path(root) / pin_name
        self.read_only = read_only
        path_buffer = ctypes.create_string_buffer(os.fsencode(self.path))
        attr = ctypes.create_string_buffer(16)
        struct.pack_into('<Q', attr, 0, ctypes.addressof(path_buffer))
        if read_only:
            struct.pack_into('<I', attr, 12, 8)  # BPF_F_RDONLY in supplied vmlinux.h.
        self.fd = _invoke(7, attr)
        try:
            self.info = map_info(self.fd)
            _need((self.info['key_size'], self.info['value_size']) == CONTRACTS[pin_name], 'projection_map_contract')
            _need(self.info['type'] in {1, 2}, 'projection_map_type')
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def read(self, key):
        _need(len(key) == self.info['key_size'], 'map_read_key_size')
        return _lookup_fd(self.fd, key, self.info['value_size'])

    def assert_pin_identity(self):
        other = PinnedMap(self.pin_name, self.path.parent, read_only=True)
        try:
            _need(other.info['id'] == self.info['id'], 'projection_pin_rebound')
        finally:
            other.close()

    def rows(self):
        result, previous = {}, None
        for _ in range(self.info['capacity'] + 1):
            after = ctypes.create_string_buffer(self.info['key_size'])
            key_buffer = ctypes.create_string_buffer(previous, len(previous)) if previous is not None else None
            attr = ctypes.create_string_buffer(40)
            struct.pack_into('<I', attr, 0, self.fd)
            if key_buffer is not None:
                struct.pack_into('<Q', attr, 8, ctypes.addressof(key_buffer))
            struct.pack_into('<Q', attr, 16, ctypes.addressof(after))
            try:
                _invoke(4, attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    return result
                raise
            key = after.raw
            _need(key not in result, 'map_iteration_changed_or_repeated')
            value = self.read(key)
            _need(value is not None, 'map_iteration_row_disappeared')
            result[key] = value
            previous = key
        raise ValueError('map_iteration_exceeds_capacity')

    def write(self, key, value=None, *, delete=False, active_reader=None):
        _need(not self.read_only, 'read_only_pinned_map')
        self.assert_pin_identity()
        _need(len(key) == self.info['key_size'], 'map_write_key_size')
        if not delete:
            _need(value is not None and len(value) == self.info['value_size'], 'map_write_value_size')
        tx = authorize_map_write(self.pin_name, key, value, delete=delete, active_reader=active_reader)
        before = self.read(key)
        tx.note('bpf_delete' if delete else 'bpf_update', {
            'map': self.pin_name, 'map_id': self.info['id'], 'key': key.hex(),
            'value': value.hex() if value is not None else None,
            'before': before.hex() if before is not None else None})
        attr, kb, vb = _element_attr(self.fd, key, value)
        _invoke(3 if delete else 2, attr)


def guard_legacy_bpf_write(command, attr, size, raw):
    """Apply the same boundary to existing backend/restoration raw syscalls."""
    _need(command in {2, 3}, 'guard_only_accepts_map_mutation')
    require_transaction()
    fd = struct.unpack_from('<I', attr, 0)[0]
    info = map_info(fd)
    candidates = [pin for pin, full in MAP_NAMES.items()
                  if info['name'] in {full[:15], pin[:15]}]
    _need(len(candidates) == 1, 'legacy_map_not_in_projection_contract')
    pin = candidates[0]
    _need((info['key_size'], info['value_size']) == CONTRACTS[pin], 'legacy_map_dimensions')
    key = ctypes.string_at(struct.unpack_from('<Q', attr, 8)[0], info['key_size'])
    value = ctypes.string_at(struct.unpack_from('<Q', attr, 16)[0], info['value_size']) if command == 2 else None
    target = PinnedMap(pin)
    active = None
    try:
        _need(target.info['id'] == info['id'], 'legacy_fd_not_canonical_pin')
        if command == 3:
            active = PinnedMap('active_generation_map')
        def read_active(scope):
            observed = active.read(struct.pack('<Q', scope))
            return struct.unpack('<Q', observed)[0] if observed is not None else None
        tx = authorize_map_write(pin, key, value, delete=command == 3,
                                 active_reader=read_active if active is not None else None)
        before = _lookup_fd(fd, key, info['value_size'])
        tx.note('bpf_delete' if command == 3 else 'bpf_update', {
            'map': pin, 'map_id': info['id'], 'key': key.hex(),
            'value': value.hex() if value is not None else None,
            'before': before.hex() if before is not None else None})
        return raw(command, attr, size)
    finally:
        target.close()
        if active is not None:
            active.close()


def cgroup_kernel_id(path):
    path = Path(path)
    _need(path.is_dir() and path.resolve() == path and path.is_relative_to('/sys/fs/cgroup'), 'scope_path_not_canonical_cgroup')
    class FileHandle(ctypes.Structure):
        _fields_ = [('size', ctypes.c_uint), ('kind', ctypes.c_int), ('data', ctypes.c_ubyte * 128)]
    handle = FileHandle(); handle.size = 128
    mount_id = ctypes.c_int()
    rc = _LIBC.name_to_handle_at(-100, ctypes.c_char_p(os.fsencode(path)), ctypes.byref(handle), ctypes.byref(mount_id), 0)
    _need(rc == 0 and handle.size >= 8, 'scope_kernel_handle_unavailable')
    return int.from_bytes(bytes(handle.data[:8]), 'little')


def manifest_digest(manifest):
    fields = ('schema_version','manifest_id','generation','node_id','policy_generation','audience',
              'attestation_result_id','attestation_evidence_digest','issued_at','expires_at','entries')
    raw = json.dumps({k: manifest.get(k) for k in fields}, sort_keys=True, separators=(',', ':')).encode()
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class BpfProjectionAdapter:
    def __init__(self, store, *, pin_root=PIN_ROOT, manifest_dir=Path('/var/lib/arda/projection'), minimum_capacity=8192, read_only=False):
        self.store, self.manifest_dir, self.minimum_capacity = store, Path(manifest_dir), minimum_capacity
        self.maps, self.held = {}, []
        try:
            for pin in CONTRACTS:
                self.maps[pin] = PinnedMap(pin, pin_root, read_only=read_only)
        except BaseException:
            self.close()
            raise

    def close(self):
        self.release_prepared()
        for m in self.maps.values(): m.close()

    def release_prepared(self):
        for measured in self.held: measured.close()
        self.held = []

    def active(self, scope):
        m = self.maps['active_generation_map']; m.assert_pin_identity()
        value = m.read(struct.pack('<Q', scope))
        return struct.unpack('<Q', value)[0] if value is not None else None

    def _live_scope(self, plan):
        _need(cgroup_kernel_id(plan['scope_path']) == plan['scope_id'], 'scope_kernel_identity_changed')
        for m in self.maps.values(): m.assert_pin_identity()
        _need(self.maps['state_map'].read(bytes(4)) == struct.pack('<I', 3), 'live_mode_not_scoped_strict')
        _need(self.maps['lockdown_map'].read(bytes(4)) == bytes(4), 'lockdown_active')

    def validate_scope(self, plan):
        self._live_scope(plan)
        record = self.store.get_record(plan['manifest_id'])
        _need(record is not None, 'projection_manifest_not_staged')
        _need(record['node_id'] == plan['node_id'] and record['generation'] == plan['generation']
              and record['manifest_digest'] == plan['manifest_digest'], 'projection_ledger_binding')
        _need(record['payload']['cgroup_kernel_id'] == plan['scope_id'], 'projection_ledger_scope_binding')
        allowed_states = {'staged'} if plan['action'] == 'activate' else {'active','deactivated'}
        _need(record['state'] in allowed_states, 'projection_ledger_state')
        if plan['action'] == 'activate':
            self.store.assert_newer(plan['node_id'], plan['generation'])
        policy = self.maps['policy_state_map'].read(bytes(4))
        _need(policy is not None, 'policy_state_absent')
        prefix, rules, flags = struct.unpack('<QII', policy)
        policy_gen = record['payload']['policy_generation']
        expected_prefix = struct.unpack('<Q', hashlib.sha256(policy_gen.encode()).digest()[:8])[0]
        _need(prefix == expected_prefix and rules > 0 and flags == 1, 'scope_policy_not_current')

    def validate_observed_scope(self, plan):
        # Apply the identity/policy checks for an existing cohort, never the
        # activation-only staged state or monotonic-generation precondition.
        self.validate_scope(dict(plan,action='rollback'))
        _need(self.store.get_record(plan['manifest_id'])['state']=='active', 'observed_ledger_not_active')

    def reconcile_quarantine(self, plan):
        _need(self.active(plan['scope_id'])==0,'recovery_scope_not_quarantined')
        self.store.deactivate_recovered(plan['manifest_id'])
        _need(self.store.get_record(plan['manifest_id'])['state']=='deactivated','recovery_ledger_readback')

    def validate_recovery_scope(self, plan, row):
        self._live_scope(plan)
        for operation in row['operations']:
            detail = operation['details']
            if operation['kind'] in {'bpf_update','bpf_delete'}:
                _need(detail['map'] in self.maps and self.maps[detail['map']].info['id'] == detail['map_id'], 'recovery_map_identity_changed')

    def _manifest(self, plan):
        matches = []
        for path in self.manifest_dir.glob('*.json'):
            if path.is_symlink() or not path.is_file(): continue
            info = path.stat()
            if info.st_size > 8*1024*1024: continue
            try:
                data = json.loads(path.read_text())
            except (ValueError, UnicodeError):
                continue
            if (isinstance(data, dict) and data.get('schema_version') == 'arda.measured_manifest.v1'
                    and data.get('manifest_id') == plan['manifest_id']):
                _need(info.st_uid == 0 and not info.st_mode & 0o022, 'manifest_not_root_protected')
                _need(manifest_digest(data) == plan['manifest_digest'], 'manifest_digest_mismatch')
                matches.append(data)
        _need(bool(matches) and all(item == matches[0] for item in matches),
              'canonical_manifest_missing_or_ambiguous')
        return matches[0]

    def prepare(self, plan):
        self.release_prepared()
        record = self.store.get_record(plan['manifest_id']); payload = record['payload']
        manifest = self._manifest(plan)
        entries = manifest.get('entries')
        _need(isinstance(entries, list) and bool(entries), 'manifest_entries')
        paths = [e['path'] for e in entries]
        specs = [f"{e['fs_verity_algorithm_id']}:{e['fs_verity_digest'].lower()}" for e in entries]
        _need(paths == payload['checked_paths'] and specs == payload['loader_digest_specs'], 'ledger_manifest_identity_mismatch')
        inventory = {'rows': [], 'scope_id': plan['scope_id'], 'generation': plan['generation']}
        desired = {'measured_exec_map': {}, 'verity_identity_map': {}}
        try:
            for entry in entries:
                measured = open_measured(entry['path']); self.held.append(measured)
                require_transaction().hold(measured)
                _need(measured.algorithm == entry['fs_verity_algorithm_id'] and measured.digest == entry['fs_verity_digest'].lower(), 'held_fsverity_mismatch')
                dev = ((os.major(measured.device) & 0xFFF) << 20) | (os.minor(measured.device) & 0xFFFFF)
                measured_key = struct.pack('<QQQI4x', plan['scope_id'], plan['generation'], measured.inode, dev)
                digest = bytes.fromhex(measured.digest)
                verity_key = struct.pack('<QQHH64s4x', plan['scope_id'], plan['generation'], measured.algorithm, len(digest), digest.ljust(64,b'\0'))
                desired['measured_exec_map'][measured_key] = struct.pack('<I', 1)
                desired['verity_identity_map'][verity_key] = struct.pack('<I', 1)
            prefix = struct.pack('<QQ', plan['scope_id'], plan['generation'])
            for name, keys in desired.items():
                m = self.maps[name]; rows = m.rows()
                _need(m.info['capacity'] >= self.minimum_capacity, 'intended_map_capacity_not_live')
                existing = {k:v for k,v in rows.items() if k.startswith(prefix)}
                if plan['action'] == 'activate':
                    _need(not existing, 'target_generation_has_unowned_rows')
                else:
                    _need(existing == keys, 'rollback_inventory_not_intact')
                _need(len(rows) + sum(k not in rows for k in keys) <= m.info['capacity'], 'projection_capacity_exhausted')
                for key, value in keys.items():
                    inventory['rows'].append({'map': name, 'map_id': m.info['id'], 'key': key.hex(), 'value': value.hex()})
            for measured in self.held: measured.revalidate()
            for row in inventory['rows']:
                self.maps[row['map']].write(bytes.fromhex(row['key']), bytes.fromhex(row['value']))
            return inventory
        except BaseException:
            self.release_prepared()
            raise

    def verify_prepared(self, plan, inventory):
        for measured in self.held: measured.revalidate()
        for row in inventory['rows']:
            m = self.maps[row['map']]; m.assert_pin_identity()
            _need(m.info['id'] == row['map_id'] and m.read(bytes.fromhex(row['key'])) == bytes.fromhex(row['value']), 'prepared_allow_readback_mismatch')

    def publish(self, scope, generation):
        self.maps['active_generation_map'].write(struct.pack('<Q', scope), struct.pack('<Q', generation))

    def finalize(self, plan):
        if plan['action'] == 'rollback':
            self.store.rollback_activation(plan['manifest_id'])
        else:
            self.store.activate(plan['manifest_id'])

    def verify_final(self, plan):
        row = self.store.get_record(plan['manifest_id'])
        _need(row is not None and row['state'] == 'active' and row['manifest_digest'] == plan['manifest_digest']
              and self.active(plan['scope_id']) == plan['generation'], 'projection_final_readback')
        tx = require_transaction()
        current = next(row for row in tx.journal.rows() if row['txid'] == tx.txid)
        self.verify_prepared(plan, current['inventory'])

    def deactivate(self, plan):
        self.store.deactivate(plan['manifest_id'], 'permitted_scope_quarantine')

    def verify_deactivated(self, plan):
        _need(self.store.get_record(plan['manifest_id'])['state'] == 'deactivated'
              and self.active(plan['scope_id']) == 0, 'quarantine_ledger_readback')

    def _check_inventory_row(self, plan, row):
        _need(row['map'] in {'measured_exec_map','verity_identity_map'}, 'collection_map')
        m = self.maps[row['map']]; m.assert_pin_identity()
        key = bytes.fromhex(row['key'])
        _need(m.info['id'] == row['map_id'] and len(key) == m.info['key_size']
              and struct.unpack_from('<QQ', key) == (plan['scope_id'], plan['generation']), 'collection_row_owner')
        return m, key

    def collect(self, plan, inventory):
        for row in inventory['rows']:
            m, key = self._check_inventory_row(plan, row)
            value = m.read(key)
            if value is None: continue
            _need(value.hex() == row['value'], 'collection_row_value_changed')
            m.write(key, delete=True, active_reader=self.active)

    def verify_collected(self, plan, inventory):
        for row in inventory['rows']:
            m, key = self._check_inventory_row(plan, row)
            _need(m.read(key) is None, 'collection_readback_not_absent')

    def finish_collection(self, plan):
        self.store.remove(plan['manifest_id'])

    def abort_prepared(self, plan, row):
        _need(self.active(plan['scope_id']) != plan['generation'], 'abort_target_is_active')
        created = []
        for operation in row['operations']:
            detail = operation['details']
            if (operation['kind'] == 'bpf_update' and detail.get('before') is None
                    and detail.get('map') in {'measured_exec_map','verity_identity_map'}):
                m, key = self._check_inventory_row(plan, detail)
                value = m.read(key)
                _need(value is None or value.hex() == detail['value'], 'abort_row_changed')
                if value is not None: created.append((m,key))
        for m,key in created:
            m.write(key, delete=True, active_reader=self.active)
