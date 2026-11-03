# What the agent harness's own logs show

Measured 2026-11-02 17:06 PST (the logs are live, so later reruns will give slightly larger counts). Read-only: nothing under
`~/Developer/ops`, `~/Developer/ai-ops` or `~/.claude` was changed. Every number below has its command. All commands run from
`evidence`. One labeller (the agent that wrote the rules) made every hand
label, so "agreement" is rules versus one reader, not two independent readers.

## 1. The observation log (1,334 entries)

`python3 classify.py` reads `~/Developer/ops/skill-observations/observation-log/*.md` (463 files) and
`.../observation-log/archive/*.md` (871 files) and writes `classification.csv` (one row per entry) and `counts.json`.
Status field: 970 actioned, 315 open, 41 declined, 5 parked, 3 superseded. The folder does not match the status: 143 entries
sit in the open folder with status "actioned", so "resolved" below means status `actioned`.

**What the log is.** It is a log of improvements to the agent's skills, kept while working. It captures verification and
method mistakes much more than it captures a runtime incident, because an incident that a hook now stops is no longer a skill
gap. Treat every share below as a share of this log, not of everything that went wrong.

### 1a. Which kind of barrier could have prevented the observation

Rules (published in `classify.py`; text scanned = title + area + the Issue section, case-insensitive):

| class | v1 keywords (examples) | v2 patterns (tighter, written after the first hand check) |
|---|---|---|
| FILE_SCOPE | overwrite, clobber, deleted, git reset, worktree, backup | overwrite, clobber, `rm -`, bulk deletion, silently replaced, committed an empty |
| RESOURCE | memory, cpu, budget, queue, timeout, sweep, kill | OOM, out of memory, overheat, runaway, exceeded the cap/limit/budget, rate limit, fan-out, s_vmem |
| EXTERNAL_ACTION | send, push, merge, deploy, publish, PR, submit, post | posted/sent/pushed/published/deployed/merged/submitted + object, `gh pr` comment, outreach |
| CREDENTIAL | token, password, secret, auth, login | password, API key, secret, credential, private key |
| CONCURRENCY | sibling, concurrent, race, lock, another session | sibling/another/other session, shared checkout, stale lock, race between |
| NOT_ENFORCEABLE (judgment/method) | no class matched | no class matched |

v1: the class with most keyword matches wins, ties by the order above. v2: a class needs 2 or more matches, or 1 in the
title/area. Counts over all 1,334 entries (`counts.json`):

| class | v1 count | v2 count |
|---|---|---|
| NOT_ENFORCEABLE | 348 | 1,225 |
| EXTERNAL_ACTION | 350 | 18 |
| RESOURCE | 267 | 33 |
| FILE_SCOPE | 216 | 25 |
| CREDENTIAL | 75 | 23 |
| CONCURRENCY | 78 | 10 |

The v1 and v2 counts differ by a factor of seven on the enforceable side, which already says the keyword counts are not the
answer. The hand-checked sample is.

**Hand check.** `python3 sample.py list` (seed 20261103) and the same with `SEED=20261104` draw two random samples of 40 from
the sorted file list. `python3 sample.py 1 14` prints entries without any rule output, and I labelled each by reading it (does a
barrier on files, compute, external actions, credentials or concurrent sessions, enforced outside the model, plausibly prevent
this failure?). Labels: `hand_labels.csv` (sample 1), `hand_labels_2.csv` (sample 2). `python3 summary.py` pools them.

| | n | count | share (Wilson 95%) |
|---|---|---|---|
| a runtime barrier could plausibly have prevented it | 80 | 10 (3 resource, 3 external action, 3 file scope, 1 concurrency, 0 credential) | **12.5% (6.9 to 21.5)** |
| not enforceable by a runtime (judgment or method) | 80 | 70 | 87.5% |

Examples labelled enforceable: auto-submitters exceeding an owner's daily cap three days running (#1148); a sibling agent
overwriting a shared `build.py` (#201); `scp` replacing a remote ledger (#1086); a worker adding an unreviewed controller around a
reviewed trial adapter (#1075). Examples labelled not enforceable: a chart that rendered UTC under a PT label; a syntax check run
under the wrong interpreter; a mutation test that could not fail.

**Agreement between the rules and the hand labels** (`python3 agree.py <seed> <labels> <class column> <recurrence column>`;
detail in `agreement.txt`, `summary.json`):

| rules | sample | class agreement | "just say not enforceable" baseline | enforceable found / false alarms / missed |
|---|---|---|---|---|
| v1 | 1 | 18/40 (45%) | 32/40 | 7 / 21 / 1 |
| v1 | 2 | 10/40 (25%) | 38/40 | 2 / 28 / 0 |
| v2 | 1 (used to tune v2, not a fair test) | 35/40 (88%) | 32/40 | 4 / 1 / 4 |
| v2 | 2 (holdout, drawn after v2 was frozen) | 34/40 (85%) | 38/40 | 1 / 4 / 1 |

Plain reading: v1 is wrong on most entries, because everyday words ("send", "memory", "queue") appear in method write-ups.
v2 agrees 85% on the holdout but that is below the baseline of labelling everything not enforceable, and on the 10 entries I
labelled enforceable across both samples it finds 5 and raises 5 false alarms. **Use the hand-sample share (about one in
eight, range 7 to 22 percent), not the keyword counts.**

### 1b. Rule broken more than once

Definition used for hand labels: the entry itself says a rule, limit or instruction was violated on more than one occasion, or that
the same failure recurred. Regex: `RECUR` (v1, 24% of the log, 319 entries, mostly false: "keeps", "again", "every session" appear in
ordinary prose) and `RECUR_V2` (107 entries, 8.0%; agrees with the hand labels 36/40 on sample 1 and 40/40 on sample 2).

| measure | count | share |
|---|---|---|
| hand labels, both samples | 6 of 80 | 7.5% (3.5 to 15.4) |
| `RECUR_V2` over the whole log | 107 of 1,334 | 8.0% |
| resolution text of the entry says the issue had 2 or more "sightings" (review clusters; `counts.json` key `resolution_text_names_2plus_sightings`) | 163 of 1,334 | 12.2% |

So roughly one entry in thirteen to one in eight records a repeat. That is real but smaller than "a rule that gets broken twice" suggests
as a headline, and the log tends to record the first break of a rule, then fixes it.

### 1c. How entries were resolved

Of 970 actioned entries, 959 carry resolution text. In the great majority the resolution is an edit to skill prose ("applied to
verify-claims", "principle bullet in the target skill", "folded into a memory file").
`RES_EXEC_V2` flags resolutions that name a `.py`/`.sh` file or say a hook, gate, script or guard was added: 33 hits. I read all 33
(`exec_resolutions_reviewed.txt`): **26 changed executable code** (hooks, gate scripts, checkers, tests), 1 changed permission config,
6 were not (a pre-existing hook, prose fixes). So **26 of 970 (2.7%)** were closed by a hook, gate or script; the rest were closed by
rewording rules or adding method notes. The hand sample agrees: 1 of 56 actioned entries (1.8%, 0.3 to 9.4). The v1 keyword
rule gave 127 of 970 (13%) and is wrong; its false hits include any resolution that merely mentions a script.

**What this does to the application's sentence.** The drafts say "the fix that holds has always been a hook, gate or default, never a
clearer sentence". The log does not show that. It shows that about 97% of actioned entries were closed by something other than a code change (skill text, a memory note, a new skill) and
that it cannot say whether they held, because the log does not record recurrence after a fix except through the "sightings" count above.
What it does support: some rules were broken after being written (the 6 of 80), and a minority of failures (about 12%) are of a kind a
file, compute, network or concurrency barrier could stop.

## 2. The tool-call journal

`python3 harness_counts.py > harness_counts.json` reads `~/Developer/ai-ops/journal/events.ndjson`.

| fact | value |
|---|---|
| rows (one per tool call) | 46,512 |
| window | 2026-10-15 13:47 PDT to 2026-11-02 17:06 PST |
| rows with `wrote: true` | 14,285 (heuristic: set when the command or tool is judged to write a file) |
| distinct session ids | 188 |
| tools | Bash 45,257; Write 731; Edit 524 |
| fields | ts, session_id, cwd, tool, wrote, writes, target, agent_id |
| outcome, deny or block field | none |

The journal records what was attempted. It has no outcome, so it cannot say how many tool calls were blocked or denied. The "more
than 1,900 logged sessions" in the fact sheet comes from a different store (`ops/sessions`), which I did not recount here; the journal
holds 188 session ids.

## 3. Hook logs: blocks and denials

`~/.claude/hook-health.ndjson` (416 rows, 2026-10-27 12:09 PDT to 2026-11-02 16:58 PST; same script, section `hook_health`):

- Stop hook ran 414 times. 396 had no gate block, 15 had one, 3 had two. That is **18 runs with at least one block, 21 blocks in total.**
- PreToolUse rows: 2, both denials, both on 2026-11-01. One refused a commit chained after a test whose exit status a pipe discards;
  the other refused `codex exec` with no stdin redirect. Both are command-hygiene rules, not file, network or credential scope.
- The file holds 2 PreToolUse rows in the window, both denials, so it looks like it logs denials only. I cannot give a denial rate.

`~/.claude/state/resource-governor.log` (260 rows, 2026-10-01 to 2026-10-25): 252 `kill` actions, of which 236 orphaned browsers,
6 orphaned test, 6 orphaned dev, 3 orphaned MCP, 1 "critical pressure, largest agent job"; 8 `would-kill` (dry run). This is a process
cleanup governor that acts after the fact. It is not a per-task compute budget, and the log ends before the 28 October overheating
incident, so the data does not show whether it saw it.

## 4. What is not measured here

- Whether a barrier would have prevented any entry in practice: the labels are a reader's judgment from the write-up.
- Any rate per tool call: the journal has no denominator for denied calls.
- Whether rules written into prose were re-broken after a fix: the log does not track that.
