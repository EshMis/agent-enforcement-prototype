# Prototype enforcement runtime: measured results

Run 2026-11-03 JST (2026-11-02 PST) on the Shirokane SGE cluster, in a user home directory.
Code: about 1,500 lines of Python 3, standard library only (`runtime/`, `panel.py`, `mutate.py`, `tests/`). Expectations were
written in `PANEL.md` and committed before the main run (git history: "Pre-register fault panel expectations", then two
amendments, both dated in the file). What this is: a small prototype that shows the broker-recheck idea and some Linux
mechanisms work on this cluster. What it is not: a security evaluation, a model-driven test, or the six-month system.

## 1. Probe: what the compute nodes offer

The cluster is mixed. Two node kinds were seen, and the results differ.

| fact | el8 nodes (pc053, pc056, pc057, pc058, pc059) | el9 nodes (hc017, hc025) |
|---|---|---|
| kernel | 4.18.0-553.171.1.el8_10 (RHEL 8.10) | 5.14.0-687.54.1.el9_8 |
| `/sys/kernel/security/lsm` | `capability,yama,selinux,bpf` (no landlock) | file absent (ENOENT), so it cannot be used to detect Landlock |
| `landlock_create_ruleset` version query via ctypes | -1, ENOSYS | ABI 6 |
| `unshare -Urn true` (user + network namespace) | works, rc 0 (`unshare -n` without a user namespace: not permitted) | works (in-process unshare used by the panel) |
| cgroup | v1 (`/sys/fs/cgroup` mounted read-only; `mkdir` fails: read-only file system); no writable subtree | v2 mounted, not writable by the job user |
| `setrlimit` RLIMIT_CPU, RLIMIT_AS, RLIMIT_NPROC | all settable (SGE already sets an RLIMIT_AS soft limit equal to `s_vmem`) | same |
| seccomp-bpf | usable (`prctl(PR_SET_SECCOMP)` filter installed and enforced) | usable |
| python on compute nodes | 3.12.0 at `/usr/local/package/python/3.12.0` | same |

How measured: job 131457719 (one node, pc057), raw output `raw/probe-131457719.out`; a 24-task array, job 131458852, one JSON line
each in `raw/survey-131458852.jsonl`: 19 tasks on el8 nodes, 5 on el9, over only 6 distinct hosts, so it says nothing about the ratio
across the cluster's 595 hosts. Run 2 additionally landed on hc017 (el9). Landlock is therefore not something to count on cluster-wide.
Commands: `qsub probe.sh`; `qsub jobs/survey.sh` (both in `jobs/`).

## 2. What was built

- `runtime/authority.py`: per-task JSON record (task_id, version, revoked, read_paths, write_paths, cpu_seconds, mem_bytes). The
  owner changes it with `update()` or `revoke()`, which take an exclusive file lock and bump the version.
- `runtime/broker.py`: owns protected writes. Worker talks JSON lines over a Unix socket. `enqueue` records the record version in force;
  `commit` re-reads the CURRENT record under a shared lock and refuses on revoked, version changed, or path outside `write_paths`
  (paths resolved with realpath, so `..` and symlink escapes are refused). `write` is enqueue+commit in one step.
- `runtime/decisionlog.py`: every enqueue, write, commit and worker launch/exit is one JSON line, written with `O_APPEND` under a lock,
  each carrying a hash of the previous line. `verify()` recomputes the chain; the panel requires it to verify after every run.
- `runtime/sandbox.py` + `launch.py`: applied in the worker just before `exec`: rlimits (CPU soft=budget, hard=budget+1; AS=budget),
  user+network namespace, drop all capabilities, seccomp-bpf (deny write-opens and path-mutating syscalls; deny non-AF_UNIX sockets),
  and Landlock (write rights only under a scratch dir; TCP bind/connect denied) where the kernel has it. A requested mechanism that
  cannot be installed makes the launcher exit 126 and not start the worker.
- `runtime/supervisor.py`: starts the broker, launches workers with the budgets from the record as read at launch, records how the
  worker ended (signal, CPU seconds from `wait4`), and logs it.
- `tests/test_broker.py`: 19 unit tests, run on the Mac (`cd prototype && python3 -m unittest discover -s tests -v`; Python 3.13.2): record,
  scope, symlink and `..` escapes, revoke / flag flip / version bump / narrowing while queued, re-enqueue, the log chain and tamper
  detection. They cover broker logic only, nothing Linux-specific.

## 3. Fault panel (20 repetitions per trace, fresh directories and a fresh broker each time)

Jobs (run 2, qsub flag `-l hostname=...` picks the node family): `qsub -l hostname="hc*" -v MODE=main,REPS=20,OUT=.../results-run2/el9 jobs/panel.sh` = job **131459920**
(hc017, el9, kernel 5.14); same with `hostname="pc*"` = job **131459942** (pc056, el8, kernel 4.18). Scratch on node-local xfs.
Results: `results/run2-el9/panel-main.json`, `results/run2-el8/panel-main.json`; decision log of rep 0 for every trace in `logs-main/`.

| trace | what | expected (PANEL.md) | el9 hc017 | el8 pc056 |
|---|---|---|---|---|
| a1 | broker write inside scope | allowed | 20/20 pass | 20/20 pass |
| b1 | broker write outside scope | refused | 20/20 pass | 20/20 pass |
| b2 | `scope/../protected` | refused | 20/20 pass | 20/20 pass |
| b3 | symlink in scope pointing out | refused | 20/20 pass | 20/20 pass |
| c1 | revoked (version bumped) while queued | commit refused | 20/20 pass | 20/20 pass |
| c1b | revoked flag flipped, version NOT bumped | refused | 20/20 pass | 20/20 pass |
| c2 | version bumped (budget edit), not revoked | refused (stale) | 20/20 pass | 20/20 pass |
| c3 | after c2, re-enqueue under the new version | first refused, second allowed | 20/20 pass | 20/20 pass |
| d1 | CPU budget 2 s, busy loop | killed by signal, 1.8 to 4.0 s CPU | 20/20 pass (SIGXCPU, 2.017 s CPU, 2.04 s wall, rep 0) | 20/20 pass (2.021 s CPU) |
| e1 | memory budget 256 MiB | MemoryError or killed, allocated under 256 MiB | passes **vacuously**: 0 MiB allocated | same |
| e0 | control: allocate 64 MiB under 256 MiB | completes | **0/20 FAIL** | **0/20 FAIL** |
| e1b (post hoc) | budget 1 GiB, allocate to 2 GiB | MemoryError at 400 to 800 MiB | 20/20 pass (stopped at 768 MiB) | 20/20 pass (768 MiB) |
| e0b (post hoc) | budget 1 GiB, allocate 128 MiB | completes | 20/20 pass | 20/20 pass |
| f1 | direct write to `protected/secret.txt`, 10 syscall variants incl. `/bin/sh` redirect | all fail, file unchanged | 20/20 pass (all EPERM) | 20/20 pass |
| f2 | same against `scope/pre.txt` | same | 20/20 pass | 20/20 pass |
| f0 | NEGATIVE CONTROL, no sandbox | bypass succeeds | 20/20 as expected: 9 of 10 variants succeeded, file changed | same |
| f3 | Landlock only, private scratch dir | scratch write ok, attacks EACCES | 20/20 pass (ABI 6) | **SKIPPED: no Landlock** |
| g1 | TCP connect to local sink, full sandbox | blocked, sink sees 0 | 20/20 pass (EPERM) | 20/20 pass |
| g2 | network namespace only | blocked | 20/20 pass (ENETUNREACH) | 20/20 pass |
| g3 | seccomp socket filter only | blocked | 20/20 pass (EPERM) | 20/20 pass |
| g4 | Landlock TCP deny only | blocked (EACCES) | 20/20 pass | **SKIPPED: needs ABI 4** |
| g0 | NEGATIVE CONTROL, no sandbox | connects, sink sees 1 | 20/20 as expected | same |
| h1 | benign control, 200 brokered 1 KiB writes | all allowed, worker exits 0 | 20/20 pass | 20/20 pass |
| h2 | same, fsync on, 50 writes | all allowed | 20/20 pass | 20/20 pass |

"Pass" means the observed outcome equalled the pre-registered one and the decision-log hash chain verified. Rows f0 and g0 pass by
showing the ENFORCEMENT GAP of an unsandboxed worker: that is the panel proving it can see a bypass.

**Two things that went wrong, and are reported as they happened.**
1. e0 fails and e1 passes vacuously. The bare Python 3.12 interpreter on these nodes holds 260.6 MiB of address space (job 131459823,
   `raw/diag_va-131459823.out`: VmSize 266856 kB). `RLIMIT_AS` counts address space, so a 256 MiB budget leaves nothing: even
   `import socket` fails at that limit. The pre-registered memory test therefore proved nothing about bounding memory. I added e1b/e0b at
   1 GiB after seeing this (PANEL.md, Amendment 2); there the limit does what it should (allocation stopped at 768 MiB = 1024 minus the 261
   MiB baseline). The honest statement: a memory budget works by address-space rlimit only when it is set well above the interpreter's baseline;
   it bounds virtual size, not resident memory, and not a group of processes.
2. Run 1 (jobs 131459267 on hc025 and 131459279 on pc057) had a harness bug: the el8 run crashed at f3 because a skipped trace left no log
   to copy. Fixed, and run 2 above is the complete record. Run 1 files are in `results/run1-*`; run 1 on el9 matched run 2 apart from the added e1b/e0b.
   Also: a 1-rep smoke run (job 131458624, hc025, traces a1 b1 c1 d1 f1 g1, all green) preceded the main run.

## 4. Overhead of the broker (h1, h2)

Per brokered write, round trip measured in the worker (`perf_counter`) against the same 1 KiB `open/write/close` done directly, unsandboxed,
by the supervisor. The broker does a socket round trip, a locked read of the authority record, path resolution, the write and one
hash-chained log append. 20 repetitions.

| where the files live | writes | brokered median / p95 / p99 (ms) | direct median (ms) | **overhead, median (ms)** |
|---|---|---|---|---|
| node-local xfs, el9 hc017 (n = 4,000) | no fsync | 0.127 / 0.153 / 0.566 | 0.010 | **0.117** |
| node-local xfs, el8 pc056 (n = 4,000) | no fsync | 0.232 / 0.259 / 0.314 | 0.021 | **0.211** |
| node-local xfs, el9 / el8 (n = 1,000) | fsync on both write and log | 0.233 / 0.427 / 1.40 and 0.391 / 0.461 / 1.26 | 0.067 / 0.097 | 0.166 / 0.294 |
| shared Lustre home, el9 / el8 (n = 4,000) | no fsync | 2.31 / 3.88 / 15.7 and 2.49 / 4.07 / 16.0 | 0.456 / 0.485 | 1.86 / 2.00 |
| shared Lustre home, el9 / el8 (n = 1,000) | fsync | 4.49 / 206 / 2,962 and 4.82 / 243 / 2,394 | 1.54 / 1.79 | 2.94 / 3.03 |

So the cost is about 0.1 to 0.2 ms per write on local disk, an order of magnitude more on a shared file system, and the fsync tail on Lustre
reaches seconds (p99) because of the file system, not the broker (the direct baseline's p95 is also 35 to 120 ms there). The nodes are shared with
other users' jobs; my own mutation job ran on pc056 for about 40 s of the el8 run. The numbers are for 1 KiB writes from a Python
worker; no claim about throughput under many concurrent workers.

## 5. Mutation check (the panel can go red)

`mutate.py` copies the runtime, replaces one line with an anchored substitution that must match exactly once, and the panel is run
on the mutant. Job **131459944** (pc056, el8): `qsub -l hostname="pc*" -v MODE=mutants,REPS=20,OUT=.../mutants jobs/panel.sh`. Files:
`results/run2-mutants/`.

| mutation | what was removed | a1 | b1 | c1 | c1b | c2 | c3 | matches the prediction in PANEL.md |
|---|---|---|---|---|---|---|---|---|
| none (main run) | | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | green first |
| M1 | the version comparison (`CHECK_VERSION`) | 20/20 | 20/20 | 20/20 | 20/20 | **0/20** | **0/20** | yes: c2, c3 red |
| M2 | the revoked-flag check (`CHECK_REVOKED`) | 20/20 | 20/20 | 20/20 | **0/20** | 20/20 | 20/20 | yes: c1b red; c1 stays green because revoke also bumps the version (two overlapping checks) |
| M3 | recheck against the enqueue-time snapshot instead of the current record (`RECHECK_CURRENT`) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | **0/20** | yes |

With the recheck skipped (M1), a write queued under an older permission commits, which is the failure the design exists to prevent.
Removing the sandbox (not a code mutation) turns f and g red, shown by f0 and g0 above.

## 6. What is enforced, what is not, and why

**Enforced and measured (both node kinds unless noted)**
- A write queued under an older permission is refused at commit (c1, c1b, c2), and the broker does not refuse everything (c3). Out-of-scope paths,
  `..` and symlink escapes are refused (b1 to b3). Every decision is logged.
- A worker cannot write files directly: the seccomp filter denies every write-open and path-mutating syscall, including from a shell it executes (f1, f2).
  On el9 only, Landlock gives the finer version: the worker can write its own scratch directory and nothing else (f3).
- A worker cannot open a network connection: three independent mechanisms (g1, g2, g3), plus Landlock TCP deny on el9 (g4, not UDP).
- A CPU budget kills the worker at the budget (d1: 2.02 s CPU on a 2 s budget, SIGXCPU) and the kill is logged.
- A memory budget bounds the worker's address space (e1b), if set above the interpreter baseline.

**Not enforced, or not tested**
- Group limits. cgroups are unusable (v1 read-only on el8; v2 not writable on el9). Limits are per process: a worker that forks gets a fresh
  CPU and memory allowance per child. No process-count limit; I did not test a fork storm.
- Memory is address space, not resident memory; a Python worker needs about 261 MiB before it does anything.
- Wall-clock time is not a record field. The supervisor's timeout exists in code but is not driven by the record. A sleeping worker uses no CPU budget.
- Reads. `read_paths` is in the record, but reads are not brokered or confined; seccomp and Landlock here handle writes only.
- Revocation does not stop a running worker or change its rlimits; budgets are read once at launch. Stopping a running worker was not built.
- With seccomp the worker has no local scratch (all file writes are denied); only the Landlock configuration gives it one.
- Log integrity: append-only by convention and a hash chain. Any process running as the same user could rewrite the file and recompute the chain;
  no external anchor, no `chattr +a`.
- The broker trusts the socket path (mode 0600) and does not check peer credentials. The broker writes by path, and only the final component is
  opened with `O_NOFOLLOW`; a symlink swap in a parent directory by another process of the same user is not defended or tested.
- Unprivileged user namespaces themselves widen the kernel attack surface. The worker has all capabilities dropped and a seccomp filter, but the netns-only
  configuration (g2) does not block `unshare`. No kernel-exploit or escape testing was done.
- seccomp filter is built for x86_64 only. GPU, models, and anything involving a language model were out of scope; the traces are scripted.
- One host, one user, 20 repetitions of scripted traces written by the same person who wrote the runtime. No independent test author.
  A pass here shows the mechanism works on these traces, not that it holds against an adaptive attacker.

## 7. Exact commands

```
# local unit tests (Mac)
cd prototype && python3 -m unittest discover -s tests -v   # 19 tests OK
# probe + survey + smoke + diag
ssh <cluster login node> 'cd /home/USER/ai-safety-grants && qsub probe.sh'                       # 131457719
qsub jobs/survey.sh                                                                           # 131458852 (array 1-24)
qsub -v MODE=smoke,REPS=1,OUT=... jobs/panel.sh                                               # 131458624
qsub jobs/diag_va.sh                                                                          # 131459823
# run 1
qsub -l hostname="hc*" -v MODE=main,REPS=20,OUT=.../results/main-el9 jobs/panel.sh            # 131459267
qsub -l hostname="pc*" -v MODE=main,REPS=20,OUT=.../results/main-el8 jobs/panel.sh            # 131459279
# run 2 (the tables above)
qsub -l hostname="hc*" -v MODE=main,REPS=20,OUT=.../results-run2/el9 jobs/panel.sh            # 131459920
qsub -l hostname="pc*" -v MODE=main,REPS=20,OUT=.../results-run2/el8 jobs/panel.sh            # 131459942
qsub -l hostname="pc*" -v MODE=mutants,REPS=20,OUT=.../results-run2/mutants jobs/panel.sh     # 131459944
# tables
python3 make_tables.py results/run2-el9/panel-main.json results/run2-el8/panel-main.json
```
Every job used `-pe def_slot 2 -l h_rt=1:00:00 -l mem_req=4G -l s_vmem=4G` (set in `jobs/panel.sh`), CPU only, files only under
`/home/USER/ai-safety-grants/`, no job deleted. `qsub -w v` was run before `probe.sh`, `panel.sh` and `survey.sh` (not before `diag_va.sh`).
