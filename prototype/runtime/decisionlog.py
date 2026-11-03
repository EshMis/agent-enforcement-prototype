"""Append-only decision log: JSON lines, O_APPEND, each line carries a hash of the previous one.

Append-only here means: only ever opened with O_APPEND by this module, writers serialised by
flock, and tampering with earlier lines is detectable by verify(). It is NOT kernel-enforced
append-only (no chattr +a, which needs root). In the sandboxed worker the file is unwritable
anyway because the seccomp filter denies write-opens.
"""
import fcntl
import hashlib
import json
import os
import time

GENESIS = "0" * 64


class DecisionLog:
    def __init__(self, path, fsync=False):
        self.path = path
        self.fsync = fsync

    def _last_hash_and_seq(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 8192))
                tail = f.read().splitlines()
        except FileNotFoundError:
            return GENESIS, 0
        for line in reversed(tail):
            if line.strip():
                try:
                    e = json.loads(line)
                    return e["hash"], e["seq"]
                except Exception:
                    break
        return GENESIS, 0

    def append(self, **entry):
        lockfd = os.open(self.path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX)
            prev, seq = self._last_hash_and_seq()
            entry["seq"] = seq + 1
            entry["ts"] = time.time()
            entry["prev"] = prev
            body = json.dumps(entry, sort_keys=True)
            entry["hash"] = hashlib.sha256((prev + body).encode()).hexdigest()
            line = json.dumps(entry, sort_keys=True) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode())
                if self.fsync:
                    os.fsync(fd)
            finally:
                os.close(fd)
            return entry
        finally:
            os.close(lockfd)

    def entries(self):
        out = []
        try:
            with open(self.path, "r") as f:
                for line in f:
                    if line.strip():
                        out.append(json.loads(line))
        except FileNotFoundError:
            pass
        return out

    def verify(self):
        """Return (ok, message). Recomputes the hash chain."""
        prev = GENESIS
        for i, e in enumerate(self.entries(), 1):
            claimed = e.pop("hash", None)
            if e.get("prev") != prev:
                return False, "line %d: prev hash mismatch" % i
            body = json.dumps(e, sort_keys=True)
            if hashlib.sha256((prev + body).encode()).hexdigest() != claimed:
                return False, "line %d: hash mismatch" % i
            if e.get("seq") != i:
                return False, "line %d: seq %r" % (i, e.get("seq"))
            prev = claimed
        return True, "ok"
