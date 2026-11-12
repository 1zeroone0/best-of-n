"""Run a command and measure its whole process tree: wall time, CPU time and
peak resident memory, sampled from ps every second.

    python3 -I measure.py OUT.json -- COMMAND...

CPU is reported two ways: `cpu_rusage`, the user+system time of every
descendant that was waited for (getrusage RUSAGE_CHILDREN: sudo waits for
agent's processes, so they count), and `cpu_sampled`, the largest cumulative
time ps showed for each process of the tree (misses what lived under a
second). Peak memory is the largest sum of RSS over the tree at one sample:
bon, its git and sudo children, and everything agent runs under them.
"""
import json
import resource
import subprocess
import sys
import time


def tree(root):
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,rss=,time="], capture_output=True, text=True).stdout
    procs = {}
    children = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) < 4:
            continue
        pid, ppid, rss = int(f[0]), int(f[1]), int(f[2])
        procs[pid] = (rss, seconds(f[3]))
        children.setdefault(ppid, []).append(pid)
    seen, stack = set(), [root]
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        stack.extend(children.get(p, []))
    return {p: procs[p] for p in seen if p in procs}


def seconds(t):
    # [[dd-]hh:]mm:ss.cc
    days = 0
    if "-" in t:
        d, t = t.split("-", 1)
        days = int(d)
    parts = [float(x) for x in t.split(":")]
    s = 0.0
    for x in parts:
        s = s * 60 + x
    return days * 86400 + s


def main():
    out_path = sys.argv[1]
    cmd = sys.argv[sys.argv.index("--") + 1:]
    start = time.time()
    child = subprocess.Popen(cmd)
    peak_rss = 0
    peak_procs = 0
    cpu = {}
    while child.poll() is None:
        t = tree(child.pid)
        peak_rss = max(peak_rss, sum(r for r, _ in t.values()))
        peak_procs = max(peak_procs, len(t))
        for p, (_, c) in t.items():
            cpu[p] = max(cpu.get(p, 0.0), c)
        time.sleep(1)
    wall = time.time() - start
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {
        "command": cmd, "exit": child.returncode, "wall": round(wall, 1),
        "cpu_rusage": round(ru.ru_utime + ru.ru_stime, 1), "cpu_sampled": round(sum(cpu.values()), 1),
        "peak_rss_mb": round(peak_rss / 1024), "peak_processes": peak_procs,
    }
    with open(out_path, "w") as f:
        json.dump(result, f)
    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()
