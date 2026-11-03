#!/bin/bash
#$ -S /bin/bash
#$ -cwd
#$ -N asg_probe
#$ -pe def_slot 1
#$ -l h_rt=0:20:00
#$ -l mem_req=2G
#$ -l s_vmem=2G
#$ -o /home/USER/ai-safety-grants/probe.out
#$ -e /home/USER/ai-safety-grants/probe.err
echo "== host/date"; hostname; date
echo "== uname -a"; uname -a
echo "== /etc/os-release"; head -3 /etc/os-release
echo "== /sys/kernel/security/lsm"; cat /sys/kernel/security/lsm 2>&1
echo "== python3 candidates"; which python3; python3 --version 2>&1
ls /usr/local/package/python 2>&1 | head
echo "== unshare -Urn true"; unshare -Urn true; echo "rc=$?"
echo "== unshare -Ur id"; unshare -Ur id 2>&1; echo "rc=$?"
echo "== unshare -n true (no user ns)"; unshare -n true 2>&1; echo "rc=$?"
echo "== user.max_user_namespaces"; cat /proc/sys/user/max_user_namespaces 2>&1
echo "== kernel.unprivileged_userns_clone"; cat /proc/sys/kernel/unprivileged_userns_clone 2>&1
echo "== cgroup mounts"; grep cgroup /proc/mounts
echo "== /sys/fs/cgroup"; ls /sys/fs/cgroup 2>&1 | head -30
echo "== cgroup.controllers"; cat /sys/fs/cgroup/cgroup.controllers 2>&1
echo "== own cgroup"; cat /proc/self/cgroup
echo "== writable cgroup check"
for d in /sys/fs/cgroup /sys/fs/cgroup/memory /sys/fs/cgroup/cpu /sys/fs/cgroup/cpuacct $(sed -n 's#^[0-9]*:[^:]*:\(.*\)#/sys/fs/cgroup\1#p' /proc/self/cgroup | head -3); do
  if [ -w "$d" ]; then echo "writable: $d"; else echo "not writable: $d"; fi
done
mkdir /sys/fs/cgroup/asg_test 2>&1; echo "mkdir cgroup rc=$?"
echo "== ulimit -a"; ulimit -a
echo "== seccomp/NoNewPrivs"; grep -E 'Seccomp|NoNewPrivs' /proc/self/status
echo "== python probes"
for PY in python3 /usr/local/package/python/3.12.0/bin/python /home/USER/faceflow/conda/envs/ff/bin/python; do
  if command -v $PY >/dev/null 2>&1 || [ -x "$PY" ]; then echo "-- $PY"; $PY /home/USER/ai-safety-grants/probe.py 2>&1; fi
done
echo "== done"
