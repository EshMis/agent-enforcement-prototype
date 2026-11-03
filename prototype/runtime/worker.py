"""Scripted worker scenarios. These are the 'untrusted' side: they need no model.

python -B -m runtime.worker <scenario> '<args json>'
Every scenario prints exactly one final line:  RESULT {json}
"""
import errno
import json
import os
import socket
import subprocess
import sys
import time


def broker_conn(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    return s, s.makefile("r")


def rpc(s, rf, req):
    s.sendall((json.dumps(req) + "\n").encode())
    return json.loads(rf.readline())


def out(obj):
    print("RESULT " + json.dumps(obj), flush=True)


def errname(e):
    return errno.errorcode.get(getattr(e, "errno", None) or 0, type(e).__name__)


def sc_broker_write(a):
    s, rf = broker_conn(a["socket"])
    out(rpc(s, rf, {"op": "write", "path": a["path"], "data": a.get("data", "hello")}))


def sc_queue_then_commit(a):
    """Enqueue, tell the supervisor, wait for GO on stdin, then commit (and optionally re-enqueue+commit)."""
    s, rf = broker_conn(a["socket"])
    q = rpc(s, rf, {"op": "enqueue", "path": a["path"], "data": a.get("data", "queued")})
    print("QUEUED " + json.dumps(q), flush=True)
    sys.stdin.readline()  # blocks until the supervisor has made its owner-side change
    c = rpc(s, rf, {"op": "commit", "qid": q["qid"]})
    res = {"enqueue": q, "commit": c}
    if a.get("then_reenqueue"):
        q2 = rpc(s, rf, {"op": "enqueue", "path": a["path"], "data": a.get("data", "queued") + "-again"})
        res["reenqueue"] = q2
        res["recommit"] = rpc(s, rf, {"op": "commit", "qid": q2["qid"]})
    out(res)


def sc_burn_cpu(a):
    print("START", flush=True)
    x = 0
    while True:
        x += 1


def sc_alloc_mem(a):
    chunk = a.get("chunk_mb", 16) * 1024 * 1024
    target = a.get("target_mb", 1024) * 1024 * 1024
    held, total = [], 0
    try:
        while total < target:
            b = bytearray(chunk)
            for i in range(0, chunk, 4096):
                b[i] = 1  # touch every page so RSS really grows
            held.append(b)
            total += chunk
            print("ALLOC %d" % (total // (1024 * 1024)), flush=True)
    except MemoryError:
        out({"outcome": "MemoryError", "allocated_mb": total // (1024 * 1024)})
        sys.exit(75)
    out({"outcome": "completed", "allocated_mb": total // (1024 * 1024)})


def sc_direct_write(a):
    t = a["target"]
    d = os.path.dirname(t)
    res = {}

    def attempt(name, fn):
        try:
            fn()
            res[name] = "ok"
        except OSError as e:
            res[name] = errname(e)

    def w():
        fd = os.open(t, os.O_WRONLY | os.O_TRUNC)
        os.write(fd, b"PWNED")
        os.close(fd)

    def ap():
        with open(t, "a") as f:
            f.write("PWNED")

    def rw():
        fd = os.open(t, os.O_RDWR)
        os.close(fd)

    def creat():
        fd = os.open(os.path.join(d, "newfile"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)

    def sh():
        r = subprocess.run(["/bin/sh", "-c", "echo PWNED > '%s'" % t], capture_output=True)
        if r.returncode != 0:
            raise OSError(errno.EPERM, "shell redirect failed rc=%d" % r.returncode)

    if a.get("scratch"):
        def sw():
            with open(os.path.join(a["scratch"], "ok.txt"), "w") as f:
                f.write("scratch")
        attempt("scratch_write", sw)
    attempt("open_wronly_trunc", w)
    attempt("open_append", ap)
    attempt("open_rdwr", rw)
    attempt("create_new", creat)
    attempt("truncate", lambda: os.truncate(t, 0))
    attempt("mkdir", lambda: os.mkdir(os.path.join(d, "newdir")))
    attempt("symlink", lambda: os.symlink("x", os.path.join(d, "lnk")))
    attempt("rename", lambda: os.rename(t, t + ".moved"))
    attempt("unlink", lambda: os.unlink(t))
    attempt("exec_shell_redirect", sh)
    out(res)


def sc_net_connect(a):
    try:
        c = socket.create_connection((a["host"], a["port"]), timeout=3)
        c.sendall(b"EXFIL")
        c.close()
        out({"outcome": "connected"})
    except OSError as e:
        out({"outcome": "blocked", "error": errname(e), "msg": str(e)})


def sc_va_report(a):
    """Diagnostic: how much address space does the bare interpreter hold, and does a 16 MiB bytearray fit?"""
    st = {l.split(":")[0]: l.split(":")[1].strip() for l in open("/proc/self/status") if l.startswith(("VmSize", "VmPeak", "VmRSS"))}
    import resource
    st["RLIMIT_AS"] = resource.getrlimit(resource.RLIMIT_AS)
    try:
        b = bytearray(16 << 20)
        st["alloc16MiB"] = "ok"
    except MemoryError:
        st["alloc16MiB"] = "MemoryError"
    out(st)


def sc_benign(a):
    """Benign control: n brokered writes into scope, timing each round trip."""
    s, rf = broker_conn(a["socket"])
    lat, ok = [], 0
    payload = "x" * a.get("size", 1024)
    for i in range(a["n"]):
        t0 = time.perf_counter()
        r = rpc(s, rf, {"op": "write", "path": os.path.join(a["dir"], "f%03d.txt" % i), "data": payload + str(i)})
        lat.append(time.perf_counter() - t0)
        ok += 1 if r.get("ok") else 0
    out({"n": a["n"], "ok": ok, "lat_ms": [round(x * 1000, 4) for x in lat]})


SCENARIOS = {k[3:]: v for k, v in globals().items() if k.startswith("sc_")}

if __name__ == "__main__":
    SCENARIOS[sys.argv[1]](json.loads(sys.argv[2]))
