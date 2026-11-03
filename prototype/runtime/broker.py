"""Broker: owns protected writes. Rechecks the CURRENT authority record at commit time.

Protocol: newline-delimited JSON over a Unix stream socket, one task per socket.
  {"op":"write","path":P,"data":S}      enqueue+commit in one step
  {"op":"enqueue","path":P,"data":S}    queue under the record version current NOW
  {"op":"commit","qid":N}               recheck current record, then write or refuse
  {"op":"ping"}

Serve:  python -m runtime.broker --record R --log L --socket S [--fsync]
"""
import argparse
import json
import os
import socket
import sys
import threading

from . import authority
from .decisionlog import DecisionLog


def resolve(path):
    return os.path.realpath(path)


def within(real_path, roots):
    for root in roots:
        r = os.path.realpath(root)
        try:
            if os.path.commonpath([real_path, r]) == r:
                return True
        except ValueError:
            continue
    return False


class Broker:
    def __init__(self, record_path, log, fsync=False):
        self.record_path = record_path
        self.log = log
        self.fsync = fsync
        self.pending = {}
        self.next_qid = 1
        self.lock = threading.Lock()  # serialises queue state; the flock serialises against the owner

    # -- the one place that decides ------------------------------------------------------
    def _decide(self, rec, req_path, queued_version):
        """Return (ok, reason, real_path). rec must be the record the caller chose to trust."""
        if rec["revoked"]:  # CHECK_REVOKED
            return False, "revoked", None
        if queued_version is not None and rec["version"] != queued_version:  # CHECK_VERSION
            return False, "stale_version", None
        if not isinstance(req_path, str) or not os.path.isabs(req_path):
            return False, "bad_path", None
        real = resolve(req_path)
        if not within(real, rec["write_paths"]):
            return False, "out_of_scope", real
        return True, "ok", real

    def _do_write(self, real, data):
        fd = os.open(real, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data.encode())
            if self.fsync:
                os.fsync(fd)
        finally:
            os.close(fd)

    # -- operations ----------------------------------------------------------------------
    def enqueue(self, path, data):
        with authority.locked(self.record_path, False):
            rec = authority.load(self.record_path)
        with self.lock:
            qid = self.next_qid
            self.next_qid += 1
            ok, reason, _ = self._decide(rec, path, None)
            if ok:
                self.pending[qid] = {"path": path, "data": data, "version": rec["version"], "snapshot": rec}
            self.log.append(event="enqueue", task=rec["task_id"], qid=qid, path=path,
                            queued_version=rec["version"], decision="queued" if ok else "deny", reason=reason)
            return {"ok": ok, "reason": reason, "qid": qid, "version": rec["version"]}

    def commit(self, qid):
        with self.lock:
            item = self.pending.pop(qid, None)
        if item is None:
            return {"ok": False, "reason": "unknown_qid"}
        # Recheck against the record as it is NOW, holding the owner lock until the write is done.
        with authority.locked(self.record_path, False):
            rec = authority.load(self.record_path)  # RECHECK_CURRENT
            ok, reason, real = self._decide(rec, item["path"], item["version"])
            if ok:
                try:
                    self._do_write(real, item["data"])
                except OSError as e:
                    ok, reason = False, "io_error:%s" % os.strerror(e.errno)
        self.log.append(event="commit", task=rec["task_id"], qid=qid, path=item["path"],
                        queued_version=item["version"], current_version=rec["version"],
                        current_revoked=rec["revoked"], decision="allow" if ok else "deny", reason=reason)
        return {"ok": ok, "reason": reason, "qid": qid, "current_version": rec["version"]}

    def write(self, path, data):
        """Immediate write: queue under the current version and commit straight away."""
        with authority.locked(self.record_path, False):
            rec = authority.load(self.record_path)
            ok, reason, real = self._decide(rec, path, rec["version"])
            if ok:
                try:
                    self._do_write(real, data)
                except OSError as e:
                    ok, reason = False, "io_error:%s" % os.strerror(e.errno)
        self.log.append(event="write", task=rec["task_id"], path=path, version=rec["version"],
                        decision="allow" if ok else "deny", reason=reason)
        return {"ok": ok, "reason": reason, "version": rec["version"]}

    def handle(self, req):
        op = req.get("op")
        if op == "write":
            return self.write(req.get("path"), req.get("data", ""))
        if op == "enqueue":
            return self.enqueue(req.get("path"), req.get("data", ""))
        if op == "commit":
            return self.commit(req.get("qid"))
        if op == "ping":
            return {"ok": True}
        return {"ok": False, "reason": "bad_op"}


def _serve_conn(broker, conn):
    f = conn.makefile("rwb", buffering=0)
    rf = conn.makefile("r")
    try:
        for line in rf:
            try:
                reply = broker.handle(json.loads(line))
            except Exception as e:  # a malformed request must not take the broker down
                reply = {"ok": False, "reason": "broker_error:%s" % type(e).__name__}
            f.write((json.dumps(reply) + "\n").encode())
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        conn.close()


def serve(record, log_path, sock_path, fsync=False):
    log = DecisionLog(log_path, fsync=fsync)
    broker = Broker(record, log, fsync=fsync)
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv.listen(8)
    log.append(event="broker_start", task=authority.load(record)["task_id"], pid=os.getpid())
    print("READY", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_serve_conn, args=(broker, conn), daemon=True).start()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--socket", required=True)
    ap.add_argument("--fsync", action="store_true")
    a = ap.parse_args()
    serve(a.record, a.log, a.socket, a.fsync)
