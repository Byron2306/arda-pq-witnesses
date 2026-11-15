"""Bounded root-owned input and durable atomic output helpers."""
import json
import os
from pathlib import Path
import stat
import tempfile


def protected_bytes(path, cap=8*1024*1024, *, owner=0, private=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
                and not info.st_mode & (0o077 if private else 0o022) and info.st_size <= cap):
            raise ValueError('unprotected_or_oversized_input:' + str(path))
        raw = handle.read(cap+1)
        if len(raw) > cap: raise ValueError('input_size_changed')
        return raw


def strict_json(raw):
    def unique(items):
        value = {}
        for key, item in items:
            if key in value: raise ValueError('duplicate_json_key')
            value[key] = item
        return value
    def reject(value): raise ValueError('nonfinite_json')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=reject)


def protected_json(path, cap=8*1024*1024, *, owner=0):
    return strict_json(protected_bytes(path, cap, owner=owner))


def publish_bytes(path, raw, *, mode=0o644):
    path = Path(path)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink(): raise ValueError('symlinked_output_directory')
    parent_info = path.parent.stat()
    if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
        raise ValueError('unprotected_output_directory')
    if path.is_symlink(): raise ValueError('symlinked_output_file')
    fd, temporary = tempfile.mkstemp(prefix='.arda-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def publish_json(path, value, *, mode=0o644):
    publish_bytes(path, (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode(), mode=mode)
