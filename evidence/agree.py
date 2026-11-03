#!/usr/bin/env python3
"""Compare hand labels (hand_labels.csv) with the keyword rules (classification.csv) on the 40-item sample."""
import csv, glob, os, random, collections, sys
HERE = os.path.dirname(os.path.abspath(__file__))
SEED = int(sys.argv[1]) if len(sys.argv) > 1 else 20261103
HAND = sys.argv[2] if len(sys.argv) > 2 else "hand_labels.csv"
VER = sys.argv[3] if len(sys.argv) > 3 else "class"
RECCOL = sys.argv[4] if len(sys.argv) > 4 else "recurrence_phrase"
sys.path.insert(0, HERE)
import classify
LOG = classify.LOG
files = sorted(glob.glob(LOG + "/*.md")) + sorted(glob.glob(LOG + "/archive/*.md"))
pick = random.Random(SEED).sample(files, 40)
rule = {r["file"]: r for r in csv.DictReader(open(os.path.join(HERE, "classification.csv")))}
hand = list(csv.DictReader(open(os.path.join(HERE, HAND))))
n = agree_c = agree_r = 0
hook_n = hook_agree = 0
conf = collections.Counter()
rows = []
for h in hand:
    i = int(h["sample_index"]); r = rule[os.path.basename(pick[i - 1])]
    n += 1
    ac = h["class"] == r[VER]; agree_c += ac
    conf[(h["class"], r[VER])] += 1
    ar = int(h["recurrence"]) == int(r[RECCOL]); agree_r += ar
    ah = None
    if h["resolved_by_hook_gate_script(actioned only)"] != "":
        hook_n += 1
        ah = int(h["resolved_by_hook_gate_script(actioned only)"]) == int(r["resolution_hook_gate_script"])
        hook_agree += ah
    rows.append((i, r["file"][:50], h["class"], r[VER], h["recurrence"], r[RECCOL],
                 h["resolved_by_hook_gate_script(actioned only)"], r["resolution_hook_gate_script"]))
print("rule columns:", VER, RECCOL, "| seed:", SEED, "| hand file:", HAND)
print("class agreement: %d/%d = %.0f%%" % (agree_c, n, 100 * agree_c / n))
print("recurrence agreement: %d/%d = %.0f%%" % (agree_r, n, 100 * agree_r / n))
print("hook/gate/script resolution agreement (actioned in sample): %d/%d = %.0f%%" % (hook_agree, hook_n, 100 * hook_agree / hook_n))
print("hand-vs-rule class confusion (hand, rule): count")
for k, v in sorted(conf.items()):
    print("  ", k, v)
print("hand class totals:", dict(collections.Counter(h["class"] for h in hand)))
print("hand recurrence yes:", sum(int(h["recurrence"]) for h in hand), "| rule recurrence yes in sample:", sum(int(r[5]) for r in rows))
print("rows (idx file hand_class rule_class hand_rec rule_rec hand_hook rule_hook):")
for r in rows:
    print("  ", *r)
