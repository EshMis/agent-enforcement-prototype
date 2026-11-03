#!/usr/bin/env python3
"""Read-only counts from the harness's own logs. Run: python3 harness_counts.py  (prints a JSON block).
Sources:
  ~/Developer/ai-ops/journal/events.ndjson      one row per tool call: ts, session_id, tool, wrote, writes, target
  ~/.claude/hook-health.ndjson                  one row per Stop/PreToolUse hook run that logged: ts, level, event, module, detail
  ~/.claude/state/resource-governor.log         one JSON row per governor action (kill of orphan/CPU-hog processes)
"""
import collections, json, os, re, time
H = os.path.expanduser("~")
fmt = lambda t: time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(t))
out = {}

ev = [json.loads(l) for l in open(H + "/Developer/ai-ops/journal/events.ndjson")]
ts = [e["ts"] for e in ev]
out["journal"] = {
    "rows": len(ev), "window": [fmt(min(ts)), fmt(max(ts))], "rows_with_wrote_true": sum(1 for e in ev if e["wrote"]),
    "distinct_session_ids": len({e["session_id"] for e in ev}), "fields": sorted(ev[0].keys()),
    "tools_top": collections.Counter(e["tool"] for e in ev).most_common(8),
    "has_outcome_or_denied_field": any(k in e for e in ev[:2000] for k in ("denied", "blocked", "outcome", "decision", "error")),
}
hh = [json.loads(l) for l in open(H + "/.claude/hook-health.ndjson")]
hts = [r["ts"] for r in hh]
stop = [r for r in hh if r["event"] == "Stop"]
blk = collections.Counter(int(re.search(r"blocked=(\d+)", r["detail"]).group(1)) for r in stop)
pre = [r for r in hh if r["event"] == "PreToolUse"]
out["hook_health"] = {
    "rows": len(hh), "window": [fmt(min(hts)), fmt(max(hts))], "stop_hook_runs": len(stop),
    "stop_runs_by_blocked_gate_count": dict(blk), "stop_gate_blocks_total": sum(k * v for k, v in blk.items()),
    "stop_runs_with_at_least_one_block": sum(v for k, v in blk.items() if k > 0),
    "pretooluse_rows": len(pre), "pretooluse_denied_rows": sum(1 for r in pre if r["detail"].startswith("denied")),
    "pretooluse_denials": [fmt(r["ts"]) + " " + r["detail"][:110] for r in pre],
}
gov = []
for l in open(H + "/.claude/state/resource-governor.log"):
    try:
        gov.append(json.loads(l))
    except ValueError:
        pass
gts = [g["ts"] for g in gov if "ts" in g]
out["resource_governor"] = {
    "rows": len(gov), "window": [fmt(min(gts)), fmt(max(gts))] if gts else None,
    "by_action_why": dict(collections.Counter((g.get("action"), g.get("why")) .__str__() for g in gov)),
}
print(json.dumps(out, indent=1))
