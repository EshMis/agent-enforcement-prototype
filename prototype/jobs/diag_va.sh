#!/bin/bash
#$ -S /bin/bash
#$ -cwd
#$ -N asg_va
#$ -pe def_slot 1
#$ -l h_rt=0:05:00
#$ -l mem_req=2G
#$ -l s_vmem=2G
PY=/usr/local/package/python/3.12.0/bin/python3
cd /home/USER/ai-safety-grants/prototype || exit 1
echo "host=$(hostname) kernel=$(uname -r)"
echo "-- no extra limit (SGE s_vmem=2G only)"; PYTHONPATH=. $PY -B -m runtime.launch '{}' 2 268435456 va_report '{}'
for MB in 256 512 1024; do echo "-- RLIMIT_AS=${MB}MiB"; PYTHONPATH=. $PY -B -m runtime.launch '{"rlimits":true}' 2 $((MB*1048576)) va_report '{}'; done
