"""How full the check pool was during each search of a run, from its traces:
every check log that ran a command ("exit:") is an interval ending at the
log's birth time and lasting its recorded seconds (a check slot's wait
excluded). Agent processes' own cargo runs are not in the traces (their time
is in the program log), so with K > 0 this undercounts the pool's use.

    python3 -I util.py TRACES_DIR POOL

Per search: its span (first agent process started to last ended), the
seconds the judge's checks ran in total, the average number running, and the
fraction of the span during which POOL or more ran (the pool was full).
"""
import json
import os
import re
import sys


def birth(p):
    s = os.stat(p)
    return getattr(s, "st_birthtime", s.st_mtime)


def intervals(d):
    out = []
    for root, _, files in os.walk(d):
        for f in files:
            if f in ("program", "harness", "argv", "prompt", "facts.json", "index"):
                continue
            p = os.path.join(root, f)
            try:
                head = open(p, errors="replace").read(200)
            except OSError:
                continue
            m = re.match(r"exit: \S+\nseconds: ([0-9.]+)", head)
            if m:
                end = birth(p)
                out.append((end - float(m.group(1)), end))
    return out


def main():
    root, pool = sys.argv[1], int(sys.argv[2])
    res = {}
    for run in os.listdir(root):
        r = os.path.join(root, run)
        if not os.path.isdir(r):
            continue
        for s in sorted((x for x in os.listdir(r) if x.isdigit()), key=int):
            sd = os.path.join(r, s)
            agents = [os.path.join(sd, i) for i in os.listdir(sd) if i.isdigit()]
            if not agents:
                continue
            start = min(birth(a) for a in agents)
            end = max(birth(os.path.join(a, "facts.json")) for a in agents if os.path.exists(os.path.join(a, "facts.json")))
            iv = intervals(sd)
            events = sorted([(a, 1) for a, _ in iv] + [(b, -1) for _, b in iv])
            running, last, full, area = 0, start, 0.0, 0.0
            for t, e in events:
                t = min(max(t, start), end)
                area += running * (t - last)
                if running >= pool:
                    full += t - last
                running += e
                last = t
            span = end - start
            res[f"{run}/{s}"] = {"span": round(span, 1), "checks": len(iv), "check_seconds": round(sum(b - a for a, b in iv), 1),
                                 "average_running": round(area / span, 2) if span else 0, "pool_full_fraction": round(full / span, 3) if span else 0}
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
