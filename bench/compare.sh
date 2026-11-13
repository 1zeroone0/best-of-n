#!/bin/sh
# Two programs on the same goal at one dollar limit (queue 82): `bon code`
# in two sandboxes built alike (the same trunk tree, so the same goal), the
# code role running program A in one and program B in the other, each bon
# process under the same limit. Prints, for each, whether it pushed, its
# agent processes and verified candidates, generation, wall time and cost per
# verified candidate, from its traces. See bench/README.md.
#
#   sh bench/compare.sh WIDTH [A] [B]
#
# A and B are a host file role's keys, as run.sh's PROGRAM takes them
# [both the stub]; e.g. B='program = ["/path/bon-sample"], client = "claude",
# model = "claude-haiku-5-5", context = 80000'. LIMIT is the dollar limit
# [1.00]; each agent process's is LIMIT over the widest search, so every
# search can reserve its width. Every other setting is run.sh's, alike for both.
set -eu
WIDTH=${1:?usage: compare.sh WIDTH [A] [B]}
STUB='program = ["/bin/sh", ".bon/stub.sh"]'
A=${2:-$STUB}
B=${3:-$STUB}
REPO=$(cd "$(dirname "$0")/.." && pwd)
BENCH=${BENCH:-${TMPDIR:-/tmp}/bon-bench}
LIMIT=${LIMIT:-1.00}
CX_WIDTH=${CX_WIDTH:-4}
WIDEST=$(( WIDTH > CX_WIDTH ? WIDTH : CX_WIDTH ))
AGENT_LIMIT=$(python3 -I -c "print(f'{$LIMIT / $WIDEST:.6f}')")
export LIMIT AGENT_LIMIT CX_WIDTH BENCH
TAG=${TAG:-compare-w$WIDTH}
for side in a b; do
  if [ $side = a ]; then P=$A; else P=$B; fi
  PROGRAM=$P sh "$REPO/bench/run.sh" "$WIDTH" "$TAG-$side" > "$BENCH/$TAG-$side.log" 2>&1 || { echo "$side: run.sh failed; see $BENCH/$TAG-$side.log" >&2; exit 1; }
done
python3 -I - "$BENCH" "$TAG" "$LIMIT" "$A" "$B" <<'PY'
import glob, json, os, sys
bench, tag, limit, a, b = sys.argv[1:6]
print(f"same goal, ${float(limit):.2f} limit each")
rows = [("program", "pushed", "agent processes", "verified", "generation", "wall s", "per verified")]
for side, program in (("a", a), ("b", b)):
    out = os.path.join(bench, f"results-{tag}-{side}")
    m = json.load(open(os.path.join(out, "code.json")))
    searches = [json.loads(l) for f in glob.glob(os.path.join(out, "traces-code", "*", "searches.jsonl")) for l in open(f) if l.strip()]
    code = [s for s in searches if s.get("kind") == "code"]
    pushed = any(os.path.getsize(f) > 0 for f in glob.glob(os.path.join(out, "traces-code", "*", "pushes.jsonl")))
    n = sum(s.get("agent_processes", 0) for s in code)
    v = sum(s.get("verified", 0) for s in code)
    g = sum(s.get("generation_dollars", 0) for s in searches)
    t = sum(s.get("time_dollars", 0) for s in searches)
    per = f"${(g + t) / v:.4f}" if v else "—"
    rows.append((f"{side}: {program}", "yes" if pushed else "no", str(n), str(v), f"${g:.4f}", f"{m.get('wall', 0):.0f}", per))
w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
for r in rows:
    print("  ".join(c.ljust(w[0]) if i == 0 else c.rjust(w[i]) for i, c in enumerate(r)))
PY
