#!/bin/bash
#$ -S /bin/bash
#$ -cwd
#$ -N asg_survey
#$ -pe def_slot 1
#$ -l h_rt=0:10:00
#$ -l mem_req=1G
#$ -l s_vmem=1G
#$ -t 1-24
# one JSON line per task: which kernel mechanisms does the node this task landed on offer?
PY=/usr/local/package/python/3.12.0/bin/python3
OUT=/home/USER/ai-safety-grants/results
mkdir -p "$OUT"
cd /home/USER/ai-safety-grants/prototype || exit 1
$PY - >> "$OUT/survey-$JOB_ID.jsonl" <<PYEOF
import json, os, platform, subprocess, sys
sys.path.insert(0, ".")
from runtime import sandbox
d = sandbox.detect()
d["host"] = platform.node()
d["task"] = os.environ.get("SGE_TASK_ID")
d["max_user_namespaces"] = open("/proc/sys/user/max_user_namespaces").read().strip()
d["cgroup_fs"] = open("/proc/mounts").read().count("cgroup2")  # lines mentioning cgroup2
d["cgroup2_mounted"] = d["cgroup_fs"] > 0
d["seccomp_status"] = [l for l in open("/proc/self/status") if l.startswith("Seccomp")][0].strip()
try:
    d["cgroup_subtree_writable"] = os.access("/sys/fs/cgroup", os.W_OK)
except Exception as e:
    d["cgroup_subtree_writable"] = repr(e)
print(json.dumps(d))
PYEOF
