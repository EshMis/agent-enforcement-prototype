#!/usr/bin/env python3
"""Fault panel runner (Linux). Expected outcomes are pre-registered in PANEL.md.

python3 panel.py --root <dir containing runtime/> --workdir <scratch> --reps 20 --out results.json [--traces a1,c2,...]
"""
import argparse
import json
import os
import platform
import shutil
import socket
import statistics
import sys
import tempfile
import time

ap = argparse.ArgumentParser()
ap.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)))
ap.add_argument("--workdir", default=None)
ap.add_argument("--reps", type=int, default=20)
ap.add_argument("--out", required=True)
ap.add_argument("--traces", default="")
ap.add_argument("--label", default="main")
args = ap.parse_args()
sys.path.insert(0, args.root)

from runtime import authority, sandbox  # noqa: E402
from runtime.decisionlog import DecisionLog  # noqa: E402
from runtime.supervisor import Run, TcpSink  # noqa: E402

FULL = dict(sandbox.DEFAULT_FULL)
NONE = dict(sandbox.NONE)
ONLY_NETNS = {"rlimits": True, "netns": True, "drop_caps": True, "seccomp_write": False, "seccomp_net": False}
ONLY_SECCOMP_NET = {"rlimits": True, "netns": False, "drop_caps": False, "seccomp_write": False, "seccomp_net": True}

SIGXCPU, SIGKILL = 24, 9


def read(p):
    try:
        with open(p) as f:
            return f.read()
    except FileNotFoundError:
        return None


def decisions(run, event=None):
    return [e for e in run.log.entries() if event is None or e["event"] == event]


def finish(run, passed, observed):
    ok, msg = run.log.verify()
    return {"passed": bool(passed and ok), "observed": observed, "log_chain_ok": ok}


# ---- a / b : scope --------------------------------------------------------------------------
def t_a1(run):
    run.start_broker()
    p = os.path.join(run.scope, "out.txt")
    info = run.run_worker("broker_write", {"socket": run.sock, "path": p, "data": "hello"}, FULL)
    w = decisions(run, "write")
    ok = info["result"] and info["result"]["ok"] and read(p) == "hello" and len(w) == 1 and w[0]["decision"] == "allow"
    return finish(run, ok, {"reply": info["result"], "file": read(p), "log_decisions": [d["decision"] for d in w]})


def _refused_write(run, path, reason="out_of_scope"):
    run.start_broker()
    info = run.run_worker("broker_write", {"socket": run.sock, "path": path, "data": "nope"}, FULL)
    w = decisions(run, "write")
    exists = os.path.exists(os.path.join(run.protected, "x.txt"))
    ok = info["result"] and info["result"]["ok"] is False and info["result"]["reason"] == reason and not exists \
        and len(w) == 1 and w[0]["decision"] == "deny"
    return finish(run, ok, {"reply": info["result"], "file_created": exists, "log_decisions": [d["decision"] for d in w]})


def t_b1(run):
    return _refused_write(run, os.path.join(run.protected, "x.txt"))


def t_b2(run):
    return _refused_write(run, os.path.join(run.scope, "..", "protected", "x.txt"))


def t_b3(run):
    os.symlink(run.protected, os.path.join(run.scope, "link"))
    return _refused_write(run, os.path.join(run.scope, "link", "x.txt"))


# ---- c : revoke / stale while queued -----------------------------------------------------------
def _queued(run, owner_action, then_reenqueue=False):
    run.start_broker()
    p = os.path.join(run.scope, "q.txt")

    def on_line(line, send):
        if line.startswith("QUEUED "):
            owner_action(run)
            send("GO\n")

    info = run.run_worker("queue_then_commit", {"socket": run.sock, "path": p, "data": "queued",
                                               "then_reenqueue": then_reenqueue}, FULL, on_line=on_line)
    return p, info


def t_c1(run):
    p, info = _queued(run, lambda r: authority.revoke(r.record))
    res = info["result"] or {}
    commits = decisions(run, "commit")
    ok = res.get("commit", {}).get("ok") is False and not os.path.exists(p) and commits and commits[-1]["decision"] == "deny"
    return finish(run, ok, {"commit": res.get("commit"), "file_created": os.path.exists(p),
                            "log": [(c["decision"], c["reason"]) for c in commits]})


def t_c1b(run):
    p, info = _queued(run, lambda r: authority.edit_without_version_bump(r.record, revoked=True))
    res = info["result"] or {}
    ok = res.get("commit", {}).get("ok") is False and res.get("commit", {}).get("reason") == "revoked" and not os.path.exists(p)
    return finish(run, ok, {"commit": res.get("commit"), "file_created": os.path.exists(p)})


def t_c2(run):
    p, info = _queued(run, lambda r: authority.update(r.record, cpu_seconds=10))
    res = info["result"] or {}
    ok = res.get("commit", {}).get("ok") is False and res.get("commit", {}).get("reason") == "stale_version" and not os.path.exists(p)
    return finish(run, ok, {"commit": res.get("commit"), "file_created": os.path.exists(p)})


def t_c3(run):
    p, info = _queued(run, lambda r: authority.update(r.record, cpu_seconds=10), then_reenqueue=True)
    res = info["result"] or {}
    ok = (res.get("commit", {}).get("ok") is False and res.get("recommit", {}).get("ok") is True
          and read(p) == "queued-again")
    return finish(run, ok, {"commit": res.get("commit"), "recommit": res.get("recommit"), "file": read(p)})


# ---- d / e : budgets ------------------------------------------------------------------------------
def t_d1(run):
    run.start_broker()
    info = run.run_worker("burn_cpu", {}, FULL, timeout=20)
    ex = decisions(run, "worker_exit")[-1]
    ok = (info["signal"] in (SIGXCPU, SIGKILL) and 1.8 <= info["cpu_s"] <= 4.0 and info["wall_s"] < 15
          and not info["timed_out"] and ex["decision"] == "killed")
    return finish(run, ok, {"signal": info["signal"], "cpu_s": info["cpu_s"], "wall_s": info["wall_s"],
                            "log": [ex["decision"], ex["reason"]]})


def t_e1(run):
    run.start_broker()
    info = run.run_worker("alloc_mem", {"chunk_mb": 16, "target_mb": 1024}, FULL)
    res = info["result"]
    last_alloc = [s for s in info["stdout"] if s.startswith("ALLOC")]
    refused = (info["exit_code"] == 75 and res and res["outcome"] == "MemoryError" and res["allocated_mb"] < 256) \
        or info["signal"] is not None
    ok = refused and not (res and res.get("outcome") == "completed")
    return finish(run, ok, {"exit_code": info["exit_code"], "signal": info["signal"], "result": res,
                            "last_progress": last_alloc[-1:] })


def t_e1b(run):
    run.start_broker()
    info = run.run_worker("alloc_mem", {"chunk_mb": 16, "target_mb": 2048}, FULL)
    res = info["result"]
    refused = (info["exit_code"] == 75 and res and res["outcome"] == "MemoryError" and 400 <= res["allocated_mb"] <= 800) \
        or (info["signal"] is not None)
    ok = bool(refused) and not (res and res.get("outcome") == "completed")
    return finish(run, ok, {"exit_code": info["exit_code"], "signal": info["signal"], "result": res})


def t_e0b(run):
    run.start_broker()
    info = run.run_worker("alloc_mem", {"chunk_mb": 16, "target_mb": 128}, FULL)
    res = info["result"]
    ok = info["exit_code"] == 0 and res and res["outcome"] == "completed" and res["allocated_mb"] == 128
    return finish(run, ok, {"exit_code": info["exit_code"], "result": res})


def t_e0(run):
    run.start_broker()
    info = run.run_worker("alloc_mem", {"chunk_mb": 16, "target_mb": 64}, FULL)
    res = info["result"]
    ok = info["exit_code"] == 0 and res and res["outcome"] == "completed" and res["allocated_mb"] == 64
    return finish(run, ok, {"exit_code": info["exit_code"], "result": res})


# ---- f : direct write bypass ------------------------------------------------------------------
def _listing(run):
    return sorted(os.listdir(run.protected)) + sorted("scope/" + x for x in os.listdir(run.scope))


def _direct(run, target, cfg, expect_gap):
    run.start_broker()
    before = _listing(run)
    info = run.run_worker("direct_write", {"target": target}, cfg)
    res = info["result"] or {}
    changed = read(run.secret) != "ORIGINAL" or read(run.pre) != "ORIGINAL" or _listing(run) != before
    any_ok = any(v == "ok" for v in res.values())
    if expect_gap:
        ok = any_ok and changed  # the negative control must be able to see the bypass
    else:
        ok = bool(res) and not any_ok and not changed
    return finish(run, ok, {"attempts": res, "protected_changed": changed})


def t_f1(run):
    return _direct(run, run.secret, FULL, False)


def t_f2(run):
    return _direct(run, run.pre, FULL, False)


def t_f3(run):
    abi = sandbox.landlock_abi()
    if abi < 1:
        return {"passed": None, "skipped": "no Landlock on this node (abi=%d)" % abi, "observed": {}}
    scratch = os.path.join(run.dir, "scratch")
    os.makedirs(scratch)
    cfg = {"rlimits": True, "landlock_fs": True, "landlock_scratch": [scratch]}
    run.start_broker()
    before = _listing(run)
    info = run.run_worker("direct_write", {"target": run.secret, "scratch": scratch}, cfg)
    res = info["result"] or {}
    attacks = {k: v for k, v in res.items() if k != "scratch_write"}
    changed = read(run.secret) != "ORIGINAL" or _listing(run) != before
    ok = res.get("scratch_write") == "ok" and attacks and all(v != "ok" for v in attacks.values()) and not changed \
        and read(os.path.join(scratch, "ok.txt")) == "scratch"
    return finish(run, ok, {"scratch_write": res.get("scratch_write"), "attacks": attacks, "protected_changed": changed,
                            "landlock_abi": abi})


def t_f0(run):
    return _direct(run, run.secret, NONE, True)


# ---- g : network -----------------------------------------------------------------------------
def _net(run, cfg, expect_connect):
    run.start_broker()
    sink = TcpSink()
    try:
        info = run.run_worker("net_connect", {"host": "127.0.0.1", "port": sink.port}, cfg)
        time.sleep(0.3)
        res = info["result"] or {}
        if expect_connect:
            ok = res.get("outcome") == "connected" and sink.count == 1
        else:
            ok = res.get("outcome") == "blocked" and sink.count == 0
        return finish(run, ok, {"worker": res, "sink_connections": sink.count})
    finally:
        sink.close()


def t_g1(run):
    return _net(run, FULL, False)


def t_g2(run):
    return _net(run, ONLY_NETNS, False)


def t_g3(run):
    return _net(run, ONLY_SECCOMP_NET, False)


def t_g4(run):
    abi = sandbox.landlock_abi()
    if abi < 4:
        return {"passed": None, "skipped": "Landlock net rules need ABI 4, node has %d" % abi, "observed": {}}
    return _net(run, {"rlimits": True, "landlock_net": True}, False)


def t_g0(run):
    return _net(run, NONE, True)


# ---- h : benign control + overhead ----------------------------------------------------------------
def _h(run, n, fsync):
    run.start_broker()
    d = os.path.join(run.scope, "bulk")
    os.makedirs(d)
    info = run.run_worker("benign", {"socket": run.sock, "dir": d, "n": n, "size": 1024}, FULL, timeout=120)
    res = info["result"] or {}
    files = sorted(os.listdir(d))
    # same write done directly (open/write/close, optionally fsync), unsandboxed, for the baseline
    dd = os.path.join(run.dir, "direct")
    os.makedirs(dd)
    base = []
    payload = ("x" * 1024).encode()
    for i in range(n):
        t0 = time.perf_counter()
        fd = os.open(os.path.join(dd, "f%03d.txt" % i), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, payload)
        if fsync:
            os.fsync(fd)
        os.close(fd)
        base.append((time.perf_counter() - t0) * 1000)
    ok = info["exit_code"] == 0 and res.get("ok") == n and len(files) == n
    return finish(run, ok, {"n": n, "ok": res.get("ok"), "files": len(files), "lat_ms": res.get("lat_ms", []),
                            "direct_ms": base})


def t_h1(run):
    return _h(run, 200, False)


def t_h2(run):
    return _h(run, 50, True)


TRACES = [
    ("a1", t_a1, {}), ("b1", t_b1, {}), ("b2", t_b2, {}), ("b3", t_b3, {}),
    ("c1", t_c1, {}), ("c1b", t_c1b, {}), ("c2", t_c2, {}), ("c3", t_c3, {}),
    ("d1", t_d1, {}), ("e1", t_e1, {"mem_bytes": 256 << 20}), ("e0", t_e0, {}),
    ("e1b", t_e1b, {"mem_bytes": 1024 << 20}), ("e0b", t_e0b, {"mem_bytes": 1024 << 20}),
    ("f1", t_f1, {}), ("f2", t_f2, {}), ("f3", t_f3, {}), ("f0", t_f0, {}),
    ("g1", t_g1, {}), ("g2", t_g2, {}), ("g3", t_g3, {}), ("g4", t_g4, {}), ("g0", t_g0, {}),
    ("h1", t_h1, {"mem_bytes": 512 << 20}), ("h2", t_h2, {"fsync": True, "mem_bytes": 512 << 20}),
]


def fstype(path):
    try:
        import subprocess
        return subprocess.run(["stat", "-f", "-c", "%T", path], capture_output=True, text=True).stdout.strip()
    except Exception:
        return "unknown"


def main():
    only = [x for x in args.traces.split(",") if x]
    base = args.workdir or tempfile.mkdtemp(prefix="asg-panel-")
    os.makedirs(base, exist_ok=True)
    keep = os.path.join(os.path.dirname(os.path.abspath(args.out)), "logs-%s" % args.label)
    os.makedirs(keep, exist_ok=True)
    out = {"label": args.label, "root": args.root, "reps": args.reps, "host": socket.gethostname(),
           "kernel": platform.release(), "python": sys.version.split()[0], "workdir": base,
           "workdir_fstype": fstype(base), "detect": sandbox.detect(), "started": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
           "traces": {}}
    for tid, fn, opts in TRACES:
        if only and tid not in only:
            continue
        runs = []
        for rep in range(args.reps):
            wd = os.path.join(base, "%s-%02d" % (tid, rep))
            run = Run(args.root, wd, fsync=opts.get("fsync", False), mem_bytes=opts.get("mem_bytes", 256 << 20))
            try:
                r = fn(run)
            except Exception as e:  # a crashing trace is a failed trace, with the reason kept
                r = {"passed": False, "observed": {"exception": repr(e)}, "log_chain_ok": None}
            finally:
                run.stop()
            if rep == 0 and os.path.exists(run.logpath):
                shutil.copy(run.logpath, os.path.join(keep, "%s.decisions.log" % tid))
            shutil.rmtree(wd, ignore_errors=True)
            runs.append(r)
        if all(r.get("skipped") for r in runs):
            out["traces"][tid] = {"skipped": runs[0]["skipped"], "pass": 0, "reps": len(runs), "all_pass": None}
            print("%-4s SKIPPED %s" % (tid, runs[0]["skipped"]), flush=True)
            continue
        npass = sum(1 for r in runs if r["passed"])
        entry = {"pass": npass, "reps": len(runs), "all_pass": npass == len(runs),
                 "first_observed": runs[0]["observed"],
                 "failures": [r["observed"] for r in runs if not r["passed"]][:3]}
        if tid in ("h1", "h2"):
            br = [x for r in runs for x in r["observed"].get("lat_ms", [])]
            di = [x for r in runs for x in r["observed"].get("direct_ms", [])]
            if br and di:
                q = lambda xs, f: sorted(xs)[min(len(xs) - 1, int(f * len(xs)))]
                entry["timing"] = {
                    "n_samples": len(br), "brokered_median_ms": round(statistics.median(br), 4),
                    "brokered_p95_ms": round(q(br, 0.95), 4), "brokered_p99_ms": round(q(br, 0.99), 4),
                    "direct_median_ms": round(statistics.median(di), 4), "direct_p95_ms": round(q(di, 0.95), 4),
                    "overhead_median_ms": round(statistics.median(br) - statistics.median(di), 4),
                    "per_rep_brokered_median_ms": [round(statistics.median(r["observed"]["lat_ms"]), 4) for r in runs if r["observed"].get("lat_ms")],
                }
            for r in runs:
                r["observed"].pop("lat_ms", None)
                r["observed"].pop("direct_ms", None)
            entry["first_observed"] = {k: v for k, v in entry["first_observed"].items() if k not in ("lat_ms", "direct_ms")}
        out["traces"][tid] = entry
        print("%-4s %2d/%-2d %s" % (tid, npass, len(runs), "PASS" if entry["all_pass"] else "FAIL"), flush=True)
    out["finished"] = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    with open(args.out, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
