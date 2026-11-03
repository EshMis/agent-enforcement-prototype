# Agent enforcement prototype

A small runtime that limits what a software agent can write, spend and connect to, plus the measurements behind a grant proposal on runtime enforcement for AI agents. It is a prototype: about 1,500 lines of Python 3 using only the standard library, tested on scripted traces on one university SGE cluster.

## What it does

- **Brokered writes.** The agent's worker cannot write protected files itself. It asks a broker over a Unix socket, and the broker re-reads the task's permission record at commit time. A write queued under a permission that was later revoked or changed is refused.
- **Budgets.** CPU time and address space are capped per process with `setrlimit`.
- **Isolation.** The worker runs with all capabilities dropped, in its own user and network namespace, under a seccomp filter that denies network sockets and write-opens. On kernels that have it, Landlock can replace the seccomp write rule and give the worker a scratch directory.
- **Decision log.** Every launch, queue, commit and refusal is one JSON line carrying a hash of the line before it.

## What was measured

A fault panel of 24 scripted traces, 20 repetitions each, on two node types (RHEL 8 and RHEL 9 kernels). The expected outcome of every trace was written down and committed before the main run. Results are in [`prototype/RESULTS.md`](prototype/RESULTS.md) and the raw JSON and logs in `prototype/results/`.

In short: stale-permission commits were refused, the CPU budget killed the worker at its limit, direct writes and network access were blocked, and three deliberately broken versions of the commit-time recheck (`prototype/mutate.py`) each made the panel fail. Each brokered write added roughly 0.1 to 0.2 ms.

Limits, stated in full in section 6 of `RESULTS.md`: no limits across a group of processes (the cluster's cgroups are not writable by users), reads are not confined, budgets are read once at launch, the log has no external anchor, and the traces were written by the same author as the runtime. This is evidence that the mechanism works on these traces. It is not a security evaluation.

`evidence/` holds a separate measurement: how often failures recorded in one developer's agent-harness observation log were the kind a runtime like this could have stopped. See [`evidence/HARNESS.md`](evidence/HARNESS.md). About one in eight of a hand-labelled sample of 80 was.

## Run the tests

```
cd prototype && python3 -m unittest discover -s tests -v
```

The panel itself needs Linux with unprivileged user namespaces and seccomp: `python3 panel.py --help`. The SGE job scripts are in `prototype/jobs/`.

## What was changed for publication

- The cluster account name, login host and local paths were replaced with `USER`, `<cluster login node>` and relative paths. This edits the 12 decision logs under `results/*/logs-homefs/`, so their hash chains no longer verify. The other 99 logs are unchanged and verify.
- The observation log behind `evidence/` is private. `classification.csv` keeps the observation id and every label, without file names or titles, and `agreement.txt` lists sample rows by id. `classify.py`, `sample.py` and `agree.py` therefore cannot be rerun from this repository; they show how the published numbers were made.
- `RESULTS.md` refers to pre-registration commits in the private history. They are `49a0807` (2026-11-02 16:56 PST, panel expectations) and `13975b2` (16:59 PST, amendment and runner), both before the first results commit `a06d3e5` (17:07 PST). This repository starts from a single snapshot.

## Who made it

Written by Claude, an AI assistant, working for Eshaan Mistry, who ran it on his cluster account and is responsible for it. The hand labels in `evidence/` were also made by the assistant.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
