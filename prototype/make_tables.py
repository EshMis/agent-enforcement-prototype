#!/usr/bin/env python3
"""Turn results JSON into the markdown tables used in RESULTS.md.  python3 make_tables.py results/run2-el9/panel-main.json results/run2-el8/panel-main.json"""
import json, sys
files = sys.argv[1:]
data = [json.load(open(f)) for f in files]
ids = list(data[0]["traces"].keys())
print("| trace | " + " | ".join("%s (%s, kernel %s)" % (d["label"], d["host"], d["kernel"].split("-")[0]) for d in data) + " |")
print("|---|" + "---|" * len(data))
for t in ids:
    cells = []
    for d in data:
        e = d["traces"].get(t)
        if e is None:
            cells.append("n/a")
        elif "skipped" in e:
            cells.append("SKIPPED: " + e["skipped"])
        else:
            cells.append("%d/%d %s" % (e["pass"], e["reps"], "pass" if e["all_pass"] else "FAIL"))
    print("| %s | %s |" % (t, " | ".join(cells)))
print()
for d in data:
    print("timing", d["label"], d["host"], d["workdir_fstype"])
    for t in ("h1", "h2"):
        e = d["traces"].get(t, {})
        if "timing" in e:
            tm = dict(e["timing"]); tm.pop("per_rep_brokered_median_ms", None)
            print("  ", t, tm)
