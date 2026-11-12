"""Where each agent process's time went, from a run's traces: file birth
times and the seconds each supervised log records.

    python3 -I timeline.py TRACES_DIR

Per agent process (a trace directory <run>/<search>/<index>):
  setup    its trace directory made -> its argv written: a generation slot's
           wait, the working directory (materialize, chmod, ACLs), its build's
           clone (and the wait for trunk's build)
  session  the harness log's own seconds; for a stub, split into its sleep and
           its own checks (bon's cargo waits for a check slot inside them)
  judge    the harness log written -> facts.json written: the judge's build
           clone, its checks (run, or answered by the cache), the teardown
  checks   the seconds the judge's checks ran (slot waits excluded)
Prints, per search, the median and 90th percentile of each, and the span from
the first agent's start to the last one's end.
"""
import json
import os
import re
import sys


def birth(p):
    s = os.stat(p)
    return getattr(s, "st_birthtime", s.st_mtime)


def seconds(p):
    try:
        with open(p, errors="replace") as f:
            head = f.read(4096)
    except OSError:
        return None, ""
    m = re.search(r"^seconds: ([0-9.]+)", head, re.M)
    return (float(m.group(1)) if m else None), head


def agent(d):
    files = set(os.listdir(d))
    if "argv" not in files or "harness" not in files:
        return None
    start, argv, harness = birth(d), birth(os.path.join(d, "argv")), birth(os.path.join(d, "harness"))
    session, text = seconds(os.path.join(d, "harness"))
    m = re.search(r"stub-seconds: sleep ([0-9.]+) own-checks ([0-9.]+)", text)
    end = birth(os.path.join(d, "facts.json")) if "facts.json" in files else harness
    checks = 0.0
    executed = cached = 0
    for f in files - {"argv", "harness", "prompt", "facts.json", "index", "error", "killed"}:
        s, h = seconds(os.path.join(d, f))
        if h.startswith("exit: "):
            executed += 1
            checks += s or 0.0
        elif h.startswith("cached: "):
            cached += 1
    return {
        "start": start, "end": end, "setup": argv - start, "session": session or 0.0,
        "sleep": float(m.group(1)) if m else None, "own_checks": float(m.group(2)) if m else None,
        "judge": end - harness, "checks": checks, "executed": executed, "cached": cached,
    }


def quantiles(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    q = lambda f: xs[min(len(xs) - 1, int(f * len(xs)))]
    return {"median": round(q(0.5), 1), "p90": round(q(0.9), 1), "max": round(xs[-1], 1), "sum": round(sum(xs), 1)}


def main():
    root = sys.argv[1]
    out = {}
    for run in sorted(os.listdir(root)):
        r = os.path.join(root, run)
        if not os.path.isdir(r):
            continue
        for search in sorted((s for s in os.listdir(r) if s.isdigit()), key=int):
            s = os.path.join(r, search)
            agents = [a for a in (agent(os.path.join(s, i)) for i in os.listdir(s) if i.isdigit()) if a]
            if not agents:
                continue
            out[f"{run}/{search}"] = {
                "agents": len(agents),
                "span": round(max(a["end"] for a in agents) - min(a["start"] for a in agents), 1),
                **{k: quantiles(a[k] for a in agents) for k in ["setup", "session", "sleep", "own_checks", "judge", "checks"]},
                "executed": sum(a["executed"] for a in agents), "cached": sum(a["cached"] for a in agents),
            }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
