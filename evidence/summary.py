#!/usr/bin/env python3
"""Pool the two hand-labelled samples (n=80) and report proportions with Wilson 95% intervals, plus rule-vs-hand agreement."""
import csv, glob, json, math, os, random, sys, collections
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import classify

def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(100 * (c - h), 1), round(100 * (c + h), 1)

files = sorted(glob.glob(classify.LOG + "/*.md")) + sorted(glob.glob(classify.LOG + "/archive/*.md"))
rule = {r["file"]: r for r in csv.DictReader(open(os.path.join(HERE, "classification.csv")))}
samples = [(20261103, "hand_labels.csv"), (20261104, "hand_labels_2.csv")]
hand, per = [], {}
for seed, fn in samples:
    pick = random.Random(seed).sample(files, 40)
    for h in csv.DictReader(open(os.path.join(HERE, fn))):
        r = rule[os.path.basename(pick[int(h["sample_index"]) - 1])]
        hand.append((seed, h, r))
n = len(hand)
cls = collections.Counter(h["class"] for _, h, _ in hand)
enf = n - cls["NOT_ENFORCEABLE"]
out = {"n": n, "hand_class_counts": dict(cls), "hand_runtime_enforceable": enf,
       "hand_runtime_enforceable_pct": round(100 * enf / n, 1), "wilson95": wilson(enf, n)}
rec = sum(int(h["recurrence"]) for _, h, _ in hand)
out["hand_recurrence"] = {"k": rec, "pct": round(100 * rec / n, 1), "wilson95": wilson(rec, n)}
actioned = [(h, r) for _, h, r in hand if h["resolved_by_hook_gate_script(actioned only)"] != ""]
hk = sum(int(h["resolved_by_hook_gate_script(actioned only)"]) for h, _ in actioned)
out["hand_actioned_resolved_by_executable"] = {"k": hk, "n": len(actioned), "wilson95": wilson(hk, len(actioned))}
def stats(seed_filter, col, rcol):
    rows = [(h, r) for s, h, r in hand if s == seed_filter]
    agree = sum(h["class"] == r[col] for h, r in rows)
    maj = max(collections.Counter(h["class"] for h, _ in rows).values())
    bin_h = [h["class"] != "NOT_ENFORCEABLE" for h, _ in rows]
    bin_r = [r[col] != "NOT_ENFORCEABLE" for _, r in rows]
    tp = sum(a and b for a, b in zip(bin_h, bin_r)); fp = sum((not a) and b for a, b in zip(bin_h, bin_r))
    fn = sum(a and (not b) for a, b in zip(bin_h, bin_r))
    rec_agree = sum(int(h["recurrence"]) == int(r[rcol]) for h, r in rows)
    return {"class_agree": "%d/40" % agree, "majority_class_baseline": "%d/40" % maj,
            "enforceable_vs_not: tp/fp/fn": [tp, fp, fn], "recurrence_agree": "%d/40" % rec_agree}
out["agreement"] = {
    "v1 rules, sample1": stats(20261103, "class", "recurrence_phrase"),
    "v1 rules, sample2": stats(20261104, "class", "recurrence_phrase"),
    "v2 rules, sample1 (used to tune v2: not a fair test)": stats(20261103, "class_v2", "recurrence_v2"),
    "v2 rules, sample2 (holdout)": stats(20261104, "class_v2", "recurrence_v2"),
}
tot = json.load(open(os.path.join(HERE, "counts.json")))
out["whole_log_counts"] = {k: tot[k] for k in tot if k != "log_dir"}
print(json.dumps(out, indent=1))
