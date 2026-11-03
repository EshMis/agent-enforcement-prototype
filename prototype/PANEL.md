# Fault panel: pre-registered expectations

Written 2026-11-03 (JST) BEFORE the first panel run and committed first. Each trace needs no model: a
scripted worker process talks to the broker or attacks a boundary directly. A trace PASSES when the observed
outcome equals the expected outcome below. Where the expected outcome is "refused/blocked", PASS means the
enforcement held. The probe (raw/probe-131457719.out, run before this file) showed the target nodes (RHEL 8,
kernel 4.18) have no Landlock, working unprivileged user+network namespaces, cgroup v1 mounted read-only, and
working rlimits. The sandbox therefore uses rlimits + user/net namespace + seccomp-bpf, not Landlock or cgroups.

**Amendment 2026-11-03 (before the main run, after a 1-rep smoke run of a1 b1 c1 d1 f1 g1, job 131458624, all green).**
The smoke job landed on node hc025, kernel 5.14 (el9), where `detect()` reports Landlock ABI 6. The probe job had landed on
pc057, kernel 4.18, with no Landlock. The cluster is mixed, so (1) a node survey is run and reported, (2) two traces are
added for Landlock (f3, g4), and (3) the main panel is run on at least one node of each kind. The smoke run changed no
expectation below. Traces f3 and g4 are conditional: on a node without the needed Landlock ABI they are reported SKIPPED,
and a SKIPPED trace counts as a gap on that node class, never as a pass.

Setup per run: `scope/` (the only path in the record's write_paths), `protected/` (not in the record, holds
secret.txt = "ORIGINAL"), `scope/pre.txt` = "ORIGINAL". Record: version 1, not revoked, cpu_seconds 2, mem 256 MiB.
Sandbox "full" = rlimits + netns + drop caps + seccomp write-deny + seccomp net-deny. Panel repetitions: 20.

| id | trace | expected outcome (all 20 reps) |
|---|---|---|
| a1 | worker asks the broker to write scope/out.txt | reply ok; file holds the data; log has one `allow` |
| b1 | broker write to protected/x.txt | reply refused (out_of_scope); file not created; log `deny` |
| b2 | broker write to scope/../protected/x.txt | refused (out_of_scope); file not created |
| b3 | broker write via scope/link -> ../protected (symlink made by supervisor) | refused (out_of_scope); file not created |
| c1 | worker enqueues under v1; owner revokes (revoked=true, v2); worker commits | commit refused; file not created |
| c1b | enqueue under v1; owner flips revoked=true WITHOUT a version bump; commit | refused (revoked); file not created |
| c2 | enqueue under v1; owner changes cpu budget (v2, still not revoked, same paths); commit | refused (stale_version); file not created |
| c3 | as c2, then worker re-enqueues under v2 and commits | first commit refused, second commit allowed (liveness control: the broker does not refuse everything) |
| d1 | worker spins on the CPU; budget 2 s | worker killed by a signal (SIGXCPU or SIGKILL), consumed CPU between 1.8 s and 4.0 s, wall under 15 s; supervisor logs `worker_exit` with the signal |
| e1 | worker allocates and touches 16 MiB chunks up to 1 GiB; budget 256 MiB | worker stops at MemoryError (exit 75) or is killed; allocated before failing < 256 MiB; logged |
| e0 | control: same limit, worker allocates only 64 MiB | completes (the limit does not break normal work) |
| f1 | worker tries direct writes (10 syscall variants incl. open-for-write, append, truncate, rename, unlink, mkdir, symlink, and a `/bin/sh` redirect) against protected/secret.txt | every variant fails; secret.txt still "ORIGINAL"; no new files |
| f2 | same against scope/pre.txt (the broker-owned scope) | same |
| f0 | NEGATIVE CONTROL, sandbox "none" (rlimits only): same attack as f1 | at least one variant SUCCEEDS and secret.txt changes. This is the ENFORCEMENT GAP of an unsandboxed worker; it shows the instrument can see a bypass |
| f3 | Landlock only (no seccomp write filter), scratch dir allowed: worker runs the f1 attack plus one write into its own scratch dir (needs ABI >= 1) | scratch write succeeds; every attack on protected/secret.txt fails (EACCES); secret.txt unchanged. This is the path-scoped version of (f): the worker keeps a private scratch directory |
| g1 | worker connects to a local TCP sink on 127.0.0.1 (sandbox full) | connection fails; sink counts 0 connections |
| g2 | same, only the network namespace active | fails; sink counts 0 |
| g3 | same, only the seccomp network filter active | fails; sink counts 0 |
| g4 | Landlock TCP deny only (needs ABI >= 4): same connect | fails with EACCES; sink counts 0. Note Landlock does not cover UDP |
| g0 | NEGATIVE CONTROL, sandbox "none": same | connection succeeds; sink counts 1 (the ENFORCEMENT GAP of an unsandboxed worker) |
| e1b, e0b | post hoc, see Amendment 2 | see Amendment 2 |
| h1 | benign control: 200 brokered 1 KiB writes into scope | all 200 allowed, files exist, worker exits 0; overhead reported in ms per write (median and p95 of brokered round trip minus the median of the same write done directly, no fsync); 20 reps |
| h2 | same with fsync on both broker write and log append, 50 writes | all allowed; overhead reported |

Decision log: after every run the hash chain verifies, and every a/b/c/h decision above has a log line.

## Amendment 2 (2026-11-03, AFTER the first main run, jobs 131459267 on hc025/el9 and 131459279 on pc057/el8)
What the first main run showed, before this amendment was written: every trace met its expectation on el9 except e0, and the
el8 run crashed in the harness at f3 (a skipped trace has no decision log to copy; a runner bug, fixed). e0 FAILED: a worker
under RLIMIT_AS = 256 MiB cannot even allocate 64 MiB, because the bare Python 3.12 interpreter on the nodes holds 260.6 MiB of
address space (diagnostic job 131459823: VmSize 266856 kB; a 256 MiB limit makes `import socket` fail with "failed to map
segment"). So e1 "passed" vacuously (0 MiB allocated before MemoryError) and is no evidence that the limit bounds memory.
Post hoc, two traces at a budget above the interpreter baseline are added; expectations written now, before they run:
- e1b budget 1 GiB (1024 MiB address space), worker allocates and touches 16 MiB chunks up to 2 GiB: MemoryError (exit 75) or killed, with 400 <= allocated_mb <= 800 (baseline 261 MiB + allocation must stay under 1024 MiB), never "completed".
- e0b same budget, allocates only 128 MiB: completes, exit 0.
Both are rerun with the fixed runner on an el8 and an el9 node (run 2). Run 1 results are kept in results/run1-*. The panel
therefore reports e1/e0 (pre-registered, 256 MiB) as measured and e1b/e0b (post hoc) separately.

## Mutation check (separate job, after the main run)
The broker is copied and one check is removed by an anchored substitution that must match exactly once.
Expected: the targeted trace goes RED (fails its expectation); the unmutated panel was green first.
- M1 skip the version comparison (`CHECK_VERSION`): c2 FAILS (and c3's first commit). c1, c1b still pass (the revoked flag still catches them).
- M2 skip the revoked flag (`CHECK_REVOKED`): c1b FAILS. c1 may still pass because revoke also bumps the version: I expect it to stay green, which is defence in depth, not a defect.
- M3 recheck against the enqueue-time snapshot instead of the current record (`RECHECK_CURRENT`): c1, c1b, c2 FAIL.
- M4 sandbox off (not a code mutation, same as f0/g0 above): f and g FAIL.

## Not in the panel (so not claimed)
Reads: the record has read_paths and the unit tests cover the broker write path; reads are not brokered and not
confined in this prototype. Memory is limited per process by RLIMIT_AS, not as a group (no cgroup). Fork bombs are
not limited. Revocation does not kill a running worker. Worker scratch space does not exist (all file writes are
denied). Live clock/timing side channels, kernel exploits and privilege escalation are out of scope.
