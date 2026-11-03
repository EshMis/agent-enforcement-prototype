"""Supervisor (owner side): starts the broker, launches sandboxed workers, enforces nothing itself
beyond reading how a worker ended and logging it. Linux only for the worker launch."""
import json
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time

from . import authority
from .decisionlog import DecisionLog


class Run:
    """One fresh directory tree + broker for one trace."""

    def __init__(self, root, workdir, fsync=False, task_id="task-1", cpu_seconds=2, mem_bytes=256 << 20):
        self.root = root  # directory that contains the runtime/ package under test
        self.dir = workdir
        os.makedirs(workdir)
        self.scope = os.path.join(workdir, "scope")
        self.protected = os.path.join(workdir, "protected")
        os.makedirs(self.scope)
        os.makedirs(self.protected)
        self.secret = os.path.join(self.protected, "secret.txt")
        self.pre = os.path.join(self.scope, "pre.txt")
        for p in (self.secret, self.pre):
            with open(p, "w") as f:
                f.write("ORIGINAL")
        self.record = os.path.join(workdir, "authority.json")
        self.logpath = os.path.join(workdir, "decisions.log")
        self.sock = os.path.join(workdir, "broker.sock")
        authority.create(self.record, authority.new_record(task_id, [self.scope], [self.scope], cpu_seconds, mem_bytes))
        self.log = DecisionLog(self.logpath, fsync=fsync)
        self.fsync = fsync
        self.broker = None

    def env(self):
        e = dict(os.environ)
        e["PYTHONPATH"] = self.root
        e["PYTHONDONTWRITEBYTECODE"] = "1"
        return e

    def start_broker(self):
        cmd = [sys.executable, "-B", "-m", "runtime.broker", "--record", self.record, "--log", self.logpath,
               "--socket", self.sock]
        if self.fsync:
            cmd.append("--fsync")
        self.broker = subprocess.Popen(cmd, cwd=self.root, env=self.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        line = self.broker.stdout.readline().decode().strip()
        if line != "READY":
            raise RuntimeError("broker did not start: %r %r" % (line, self.broker.stderr.read(2000)))

    def stop(self):
        if self.broker and self.broker.poll() is None:
            self.broker.kill()
            self.broker.wait()

    def run_worker(self, scenario, args, sandbox_cfg, on_line=None, timeout=30.0):
        """Launch a worker under sandbox_cfg using the CURRENT record's budgets. Logs launch and exit."""
        rec = authority.load(self.record)
        cmd = [sys.executable, "-B", "-m", "runtime.launch", json.dumps(sandbox_cfg), str(rec["cpu_seconds"]),
               str(rec["mem_bytes"]), scenario, json.dumps(args)]
        self.log.append(event="worker_launch", task=rec["task_id"], scenario=scenario, version=rec["version"],
                        sandbox=sandbox_cfg, cpu_seconds=rec["cpu_seconds"], mem_bytes=rec["mem_bytes"])
        t0 = time.time()
        p = subprocess.Popen(cmd, cwd=self.root, env=self.env(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, close_fds=True)
        lines, err = [], []

        def pump(stream, sink, cb):
            for raw in iter(stream.readline, b""):
                s = raw.decode(errors="replace").rstrip("\n")
                sink.append(s)
                if cb:
                    cb(s)

        def send(text):
            try:
                p.stdin.write(text.encode())
                p.stdin.flush()
            except (BrokenPipeError, ValueError):
                pass

        th = [threading.Thread(target=pump, args=(p.stdout, lines, (lambda s: on_line(s, send)) if on_line else None), daemon=True),
              threading.Thread(target=pump, args=(p.stderr, err, None), daemon=True)]
        for t in th:
            t.start()
        timed_out = False
        status = rusage = None
        while True:
            pid, st, ru = os.wait4(p.pid, os.WNOHANG)
            if pid:
                status, rusage = st, ru
                break
            if time.time() - t0 > timeout:
                timed_out = True
                os.kill(p.pid, signal.SIGKILL)
            time.sleep(0.005)
        wall = time.time() - t0
        for t in th:
            t.join(2)
        try:
            p.stdin.close()
        except Exception:
            pass
        sig = os.WTERMSIG(status) if os.WIFSIGNALED(status) else None
        code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else None
        cpu = rusage.ru_utime + rusage.ru_stime
        result = None
        for s in lines:
            if s.startswith("RESULT "):
                result = json.loads(s[7:])
        info = {"exit_code": code, "signal": sig, "cpu_s": round(cpu, 3), "wall_s": round(wall, 3),
                "timed_out": timed_out, "result": result, "stdout": lines[-5:], "stderr": err[-5:]}
        reason = None
        if sig in (signal.SIGXCPU, signal.SIGKILL) and not timed_out:
            reason = "cpu_budget_exhausted" if cpu >= rec["cpu_seconds"] - 0.2 else "killed_by_signal"
        self.log.append(event="worker_exit", task=rec["task_id"], scenario=scenario, exit_code=code, signal=sig,
                        cpu_s=info["cpu_s"], wall_s=info["wall_s"], budget_cpu_s=rec["cpu_seconds"],
                        decision="killed" if reason else "exited", reason=reason)
        return info


class TcpSink:
    """Local loopback listener that counts connections (stand-in for an exfiltration endpoint)."""

    def __init__(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.count = 0
        self.received = b""
        self._stop = False
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        self.srv.settimeout(0.2)
        while not self._stop:
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.count += 1
            c.settimeout(1)
            try:
                self.received += c.recv(100)
            except OSError:
                pass
            c.close()

    def close(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass
