#!/usr/bin/env python3
"""Create a mutated copy of the runtime by an anchored substitution that must match exactly once.

python3 mutate.py <name> <dest_root>     names: M1_skip_version, M2_skip_revoked, M3_snapshot_recheck
"""
import os
import shutil
import sys

SUBS = {
    "M1_skip_version": ('if queued_version is not None and rec["version"] != queued_version:  # CHECK_VERSION',
                        'if False:  # MUTANT: version check removed'),
    "M2_skip_revoked": ('if rec["revoked"]:  # CHECK_REVOKED', 'if False:  # MUTANT: revoked check removed'),
    "M3_snapshot_recheck": ('rec = authority.load(self.record_path)  # RECHECK_CURRENT',
                            'rec = item["snapshot"]  # MUTANT: trusts enqueue-time snapshot'),
}

name, dest = sys.argv[1], sys.argv[2]
src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runtime")
os.makedirs(dest, exist_ok=True)
dst = os.path.join(dest, "runtime")
if os.path.exists(dst):
    shutil.rmtree(dst)
shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
path = os.path.join(dst, "broker.py")
text = open(path).read()
old, new = SUBS[name]
assert text.count(old) == 1, "anchor must match exactly once, got %d" % text.count(old)
open(path, "w").write(text.replace(old, new))
assert text != open(path).read()
print("mutated", name, "->", path)
