#!/usr/bin/env python3
"""Keyword classification of the skill-observation log by the kind of barrier that could have prevented it.
Read-only on the log. Rules are the dictionaries below; they are the published method (see HARNESS.md).

python3 classify.py -> writes classification.csv and counts.json next to this file
"""
import csv
import glob
import json
import os
import re
import sys
from collections import Counter

LOG = os.environ.get("OBS_LOG", "observation-log")  # the private observation log; not published
HERE = os.path.dirname(os.path.abspath(__file__))

# Barrier classes. Each pattern is matched case-insensitively; the class with the most matches wins,
# ties break in the listed order. No match at all -> NOT_ENFORCEABLE (judgment / method).
CLASSES = [
    ("FILE_SCOPE", [
        r"overwr[io]te", r"clobber", r"wrong (file|path|director|worktree|branch|repo)", r"\brm -", r"deleted?\b",
        r"destroy", r"truncat", r"lost (work|edits|changes)", r"uncommitted", r"git (reset|clean|checkout|stash|restore)",
        r"force[- ]push", r"--force", r"working tree", r"worktree", r"\bcheckout\b", r"read-only", r"generated file",
        r"edit(ed)? (the )?(wrong|stale|generated)", r"wrote (to|into) ", r"written to the wrong", r"\bcwd\b",
        r"relative (path|destination)", r"scope", r"symlink", r"icloud", r"\bbackup\b"]),
    ("RESOURCE", [
        r"\boom\b", r"out of memory", r"\bmemory\b", r"\bcpu\b", r"overheat", r"load average", r"runaway", r"\bsweep\b",
        r"quota", r"usage (window|limit)", r"\bbudget", r"too many", r"thrash", r"\bhung\b", r"infinite loop",
        r"wall[- ]clock", r"disk (full|space)", r"\bkilled\b", r"\bswap\b", r"timeout", r"timed out", r"rate limit",
        r"gpu[- ]hours", r"context (window|fill|limit)", r"\bqueue(d)?\b", r"\bslots?\b", r"s_vmem", r"\bh_rt\b"]),
    ("EXTERNAL_ACTION", [
        r"\bcurl\b", r"\bnetwork\b", r"\bpublish", r"\bsent\b", r"\bsend(ing)?\b", r"e-?mail", r"\bpushed\b", r"git push",
        r"\bdeploy", r"\bmerge[ds]?\b", r"purchas", r"\bbuy\b", r"\bsubmit(ted)?\b", r"issue comment", r"\bgh (pr|issue|api)",
        r"webhook", r"\bslack\b", r"\bupload", r"\bdownload", r"production", r"outreach", r"\bposted?\b", r"\bpr\b",
        r"pull request", r"\bcomment(ed)? on\b", r"external", r"\bapi call", r"\bonline\b", r"web ?fetch"]),
    ("CREDENTIAL", [
        r"\btoken", r"password", r"\bsecret", r"credential", r"api[- ]key", r"\.env\b", r"oauth", r"ssh key", r"\bpasskey",
        r"\bauth(entic|oriz)", r"sign[- ]?in", r"\blogin\b", r"private key"]),
    ("CONCURRENCY", [
        r"sibling", r"concurrent", r"two sessions", r"another session", r"other session", r"parallel session", r"\brace\b",
        r"shared (checkout|worktree|file|state)", r"same (worktree|checkout|file) ", r"simultaneous", r"\block(ed|file)?\b",
        r"collision", r"at the same time", r"live session", r"racing", r"interleav", r"two (agents|subagents|workers)",
        r"subagents? (both|each|also|wrote|edited)"]),
]

# v2: tighter patterns written after seeing the v1 miss on hand-check sample 1 (so sample 1 is NOT a fair test of v2;
# sample 2, drawn afterwards and labelled before v2 was run on it, is). A class needs >=2 matches in the full text,
# or >=1 match in the title/area; otherwise NOT_ENFORCEABLE.
CLASSES_V2 = [
    ("FILE_SCOPE", [r"overwr[io]te", r"clobber", r"\brm -", r"silently replaced", r"bulk (deletion|cleanup)", r"emptied",
                    r"deleted (the|a|an|every|all|files?|data)", r"destroyed", r"truncated (the|a) ", r"lost (work|edits|changes)",
                    r"force[- ]push", r"git (reset --hard|clean)", r"wrong (file|path|director|worktree|branch)",
                    r"committed an empty"]),
    ("RESOURCE", [r"\boom\b", r"out of memory", r"overheat", r"runaway", r"infinite loop",
                  r"exceeded (the |its |a )?[\w ]{0,20}(cap|limit|budget|quota)", r"rate limit", r"deadline", r"fan-?out",
                  r"pegged", r"thrash", r"s_vmem"]),
    ("EXTERNAL_ACTION", [r"\b(posted|sent|pushed|published|deployed|merged|emailed|submitted) (a |an |the |it|them|to|on)",
                         r"\bgh (pr|issue) (comment|merge|create)", r"outreach", r"went out anyway", r"reply went out"]),
    ("CREDENTIAL", [r"password", r"api[- ]key", r"\bsecret\b", r"credential", r"private key",
                    r"\btoken\b.{0,40}(leak|print|expos|commit)"]),
    ("CONCURRENCY", [r"sibling session", r"another session", r"other session", r"two sessions", r"concurrent session",
                     r"parallel session", r"shared checkout", r"stale lock", r"race between", r"same worktree"]),
]

RECUR = [r"\bagain\b", r"second time", r"third time", r"\btwice\b", r"recurr", r"\brepeat(ed|s|edly)?\b", r"\bre-?occur",
         r"re-?broke", r"re-?made", r"same (mistake|failure|trap|bug|error|rule|class)", r"\b(three|four|five|\d+) times\b",
         r"despite (the |a |an )?(rule|memory|instruction|warning|note|existing)", r"already (written|in memory|documented|a rule|recorded|logged)",
         r"for the (second|third|fourth|fifth|\w+th) (time|session)", r"\bkeeps?\b", r"every session", r"previously (logged|recorded|hit)"]

# v2 recurrence: the text must tie the recurrence to a rule/instruction/earlier entry, or say the same thing happened again
RECUR_V2 = [r"second time", r"third time", r"twice before", r"\bagain\b.{0,60}(rule|skill|memory|instruction|entry|observation)",
            r"(rule|skill|memory|instruction|entry|observation|ledger|cap|limit).{0,80}(despite|already (says|said|forbids|written|in memory|documented)|was loaded)",
            r"recurred", r"re-?broke", r"for the (second|third|fourth|fifth) (time|session)", r"same (mistake|failure|trap|pattern)",
            r"(four|five|\d+) times", r"\bkeeps? (breaking|ignoring|violating|making)", r"pattern had appeared", r"every (weekly )?(review|session|time)"]

# executable-change resolutions: names a .py/.sh file or says a hook/gate/script/guard/validator was added. validate-skill-bundle.py
# (the skill linter that every skill install passes through) is excluded: it appears in boilerplate, not as the barrier.
RES_EXEC_V2 = [r"\b[\w\-/]+\.(py|sh)\b", r"(added|new|built|wrote|created|installed|now (runs|blocks|refuses)) (an? |the )?[\w\- ,]{0,40}(hook|gate|script|guard|validator|lint)",
               r"\b(hook|gate)s? (now|that|which) ", r"settings\.json"]

HOOK = [r"\bhook", r"\bgate", r"\bscript", r"\bguard", r"\bvalidator", r"\blint", r"check\.py", r"\.py\b", r"\.sh\b",
        r"pre-commit", r"settings\.json", r"\bautomat", r"enforce", r"\bci\b", r"mechanical", r"new test", r"regression test",
        r"hard[- ]block", r"deny rule"]
PROSE = [r"principle bullet", r"\bapplied\b.*\bskill", r"reference file", r"\bmemory\b", r"skill ", r"sentence", r"wording", r"documented"]


def parse(path):
    t = open(path).read()
    m = re.match(r"---\n(.*?)\n---\n(.*)", t, re.S)
    fm, body = m.group(1), m.group(2)
    d, key = {}, None
    for line in fm.split("\n"):
        mm = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if mm and not line.startswith(" "):
            key = mm.group(1)
            d[key] = mm.group(2)
        elif key:
            d[key] += " " + line.strip()
    issue = body.split("**Suggested improvement")[0]
    return d, issue


def classify_v2(head, text):
    scores = []
    for name, pats in CLASSES_V2:
        total, in_head = count(pats, text), count(pats, head)
        scores.append((name, total if (total >= 2 or in_head >= 1) else 0))
    best = max(sc for _, sc in scores)
    if best == 0:
        return "NOT_ENFORCEABLE"
    return next(n for n, sc in scores if sc == best)


def count(patterns, text):
    return sum(len(re.findall(p, text, re.I)) for p in patterns)


def classify(text):
    scores = [(name, count(pats, text)) for name, pats in CLASSES]
    best = max(s for _, s in scores)
    if best == 0:
        return "NOT_ENFORCEABLE", dict(scores)
    for name, s in scores:  # first in listed order among the tied best
        if s == best:
            return name, dict(scores)


def main():
    rows = []
    for sub in ("", "archive/"):
        for p in sorted(glob.glob(os.path.join(LOG, sub + "*.md"))):
            d, issue = parse(p)
            text = " ".join([d.get("title", ""), d.get("area", ""), issue])
            cls, scores = classify(text)
            cls2 = classify_v2(" ".join([d.get("title", ""), d.get("area", "")]), text)
            rec = count(RECUR, text) > 0
            rec2 = count(RECUR_V2, text) > 0
            sight = [int(x) for x in re.findall(r"(\d+) sightings", d.get("resolution", ""))]
            res = d.get("resolution", "")
            status = d.get("status", "")
            res_hook = status == "actioned" and count(HOOK, res) > 0
            res_exec = status == "actioned" and count(RES_EXEC_V2, res.replace("validate-skill-bundle.py", "")) > 0
            rows.append({
                "id": d.get("id"), "dir": sub.rstrip("/") or "open", "file": os.path.basename(p), "status": status,
                "class": cls, "class_v2": cls2, "scores": json.dumps(scores), "recurrence_phrase": int(rec), "recurrence_v2": int(rec2), "sightings": max(sight) if sight else 0,
                "has_resolution": int(bool(res.strip())), "resolution_hook_gate_script": int(res_hook), "resolution_exec_v2": int(res_exec),
                "title": d.get("title", "")[:140]})
    with open(os.path.join(HERE, "classification.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    actioned = [r for r in rows if r["status"] == "actioned"]
    counts = {
        "total": len(rows),
        "by_status": dict(Counter(r["status"] for r in rows)),
        "by_dir": dict(Counter(r["dir"] for r in rows)),
        "by_class_v1": dict(Counter(r["class"] for r in rows)),
        "by_class_v2": dict(Counter(r["class_v2"] for r in rows)),
        "recurrence_phrase_v1": sum(r["recurrence_phrase"] for r in rows),
        "recurrence_phrase_v2": sum(r["recurrence_v2"] for r in rows),
        "resolution_text_names_2plus_sightings": sum(1 for r in rows if r["sightings"] >= 2),
        "actioned": len(actioned),
        "actioned_with_resolution_text": sum(r["has_resolution"] for r in actioned),
        "actioned_resolution_mentions_hook_gate_script_v1": sum(r["resolution_hook_gate_script"] for r in actioned),
        "actioned_resolution_names_executable_v2": sum(r["resolution_exec_v2"] for r in actioned),
        "log_dir": LOG,
    }
    with open(os.path.join(HERE, "counts.json"), "w") as f:
        json.dump(counts, f, indent=1, sort_keys=True)
    print(json.dumps(counts, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
