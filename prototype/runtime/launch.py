"""Launcher: apply the sandbox to this process, then exec the worker. Linux only.

python -B -m runtime.launch '<sandbox cfg json>' <cpu_seconds> <mem_bytes> <scenario> '<args json>'
Exits 126 (and does not exec the worker) if a requested mechanism cannot be installed.
"""
import json
import os
import sys

from . import sandbox


def main():
    cfg = json.loads(sys.argv[1])
    cpu, mem = int(sys.argv[2]), int(sys.argv[3])
    try:
        sandbox.apply(cfg, cpu, mem)
    except OSError as e:
        sys.stderr.write("LAUNCH_REFUSED %s\n" % e)
        os._exit(126)
    os.execv(sys.executable, [sys.executable, "-B", "-m", "runtime.worker", sys.argv[4], sys.argv[5]])


if __name__ == "__main__":
    main()
