#!/usr/bin/env python3
"""Draw the hand-check sample: 40 observations, random.Random(20261103).sample over the sorted list of files
(open then archive). Prints text WITHOUT the rule's labels so the hand labels are made blind to the rules."""
import glob, os, random, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import classify
LOG = classify.LOG
files = sorted(glob.glob(LOG + "/*.md")) + sorted(glob.glob(LOG + "/archive/*.md"))
SEED = int(os.environ.get("SEED", "20261103"))
N_ISSUE = int(os.environ.get("N_ISSUE", "850"))
pick = random.Random(SEED).sample(files, 40)
if len(sys.argv) > 1 and sys.argv[1] == "list":
    for i, p in enumerate(pick, 1):
        print(i, os.path.relpath(p, LOG))
    sys.exit()
lo, hi = int(sys.argv[1]), int(sys.argv[2])
for i, p in enumerate(pick, 1):
    if not (lo <= i <= hi):
        continue
    d, issue = classify.parse(p)
    print("=" * 80)
    print("#%d %s status=%s" % (i, os.path.basename(p), d.get("status")))
    print("TITLE:", d.get("title", "")[:300])
    print("AREA:", d.get("area", "")[:160])
    print("ISSUE:", re.sub(r"\s+", " ", issue.replace("**Issue:**", ""))[:N_ISSUE])
    if d.get("status") == "actioned":
        print("RESOLUTION:", d.get("resolution", "")[:350])
