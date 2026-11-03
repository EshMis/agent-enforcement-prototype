"""Per-task authority record: a JSON file, a monotonic version, and a lock.

The owner (supervisor side) changes the record with update()/revoke(), which take an
exclusive lock and bump the version. The broker reads the CURRENT record under a shared lock
at commit time, so an owner change and a broker commit are serialised on one host.
"""
import contextlib
import fcntl
import json
import os
import time

FIELDS = ("task_id", "version", "revoked", "read_paths", "write_paths", "cpu_seconds", "mem_bytes")


def new_record(task_id, read_paths, write_paths, cpu_seconds, mem_bytes):
    return {
        "task_id": task_id,
        "version": 1,
        "revoked": False,
        "read_paths": list(read_paths),
        "write_paths": list(write_paths),
        "cpu_seconds": int(cpu_seconds),
        "mem_bytes": int(mem_bytes),
        "updated_at": time.time(),
    }


@contextlib.contextmanager
def locked(record_path, exclusive):
    fd = os.open(record_path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        os.close(fd)  # closing releases the flock


def load(record_path):
    with open(record_path, "r") as f:
        rec = json.load(f)
    missing = [k for k in FIELDS if k not in rec]
    if missing:
        raise ValueError("authority record missing fields: %s" % missing)
    return rec


def _save(record_path, rec):
    tmp = record_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, record_path)


def create(record_path, rec):
    with locked(record_path, True):
        _save(record_path, rec)


def update(record_path, **changes):
    """Owner action: change fields and bump the version."""
    with locked(record_path, True):
        rec = load(record_path)
        rec.update(changes)
        rec["version"] = rec["version"] + 1
        rec["updated_at"] = time.time()
        _save(record_path, rec)
        return rec


def revoke(record_path):
    return update(record_path, revoked=True)


def edit_without_version_bump(record_path, **changes):
    """Test helper: a direct edit that forgets to bump the version. Exists so the
    revoked-flag check can be exercised separately from the version check."""
    with locked(record_path, True):
        rec = load(record_path)
        rec.update(changes)
        _save(record_path, rec)
        return rec
