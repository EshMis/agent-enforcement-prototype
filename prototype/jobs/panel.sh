#!/bin/bash
#$ -S /bin/bash
#$ -cwd
#$ -N asg_panel
#$ -pe def_slot 2
#$ -l h_rt=1:00:00
#$ -l mem_req=4G
#$ -l s_vmem=4G
# Required env (qsub -v): MODE (smoke|main|mutants), REPS, OUT (results dir)
: "${MODE:?smoke, main or mutants}" "${REPS:?repetitions}" "${OUT:?results dir}"
PY=/usr/local/package/python/3.12.0/bin/python3
SRC=/home/USER/ai-safety-grants/prototype
SCR=${TMPDIR:-/tmp}/asg-$JOB_ID
mkdir -p "$SCR" "$OUT"
cd "$SRC" || exit 1
echo "job=$JOB_ID host=$(hostname) kernel=$(uname -r) mode=$MODE reps=$REPS date=$(date '+%F %T %Z')"
echo "python=$($PY --version 2>&1) scratch=$SCR fs=$(stat -f -c %T "$SCR")"
case "$MODE" in
  smoke)
    $PY panel.py --root "$SRC" --workdir "$SCR/w" --reps "$REPS" --out "$OUT/smoke.json" --label smoke --traces a1,b1,c1,f1,g1,d1 ;;
  main)
    $PY panel.py --root "$SRC" --workdir "$SCR/w" --reps "$REPS" --out "$OUT/panel-main.json" --label main
    # same code, scratch on the shared home filesystem, for a second timing number
    $PY panel.py --root "$SRC" --workdir "/home/USER/ai-safety-grants/scratch-$JOB_ID" --reps "$REPS" --out "$OUT/panel-home-fs.json" --label homefs --traces a1,h1,h2
    rm -rf "/home/USER/ai-safety-grants/scratch-$JOB_ID" ;;
  mutants)
    for M in M1_skip_version M2_skip_revoked M3_snapshot_recheck; do
      $PY mutate.py "$M" "$SCR/$M" || exit 1
      $PY panel.py --root "$SCR/$M" --workdir "$SCR/w-$M" --reps "$REPS" --out "$OUT/panel-$M.json" --label "$M" --traces a1,b1,c1,c1b,c2,c3
    done ;;
esac
rm -rf "$SCR"
echo "done $(date '+%F %T %Z')"
