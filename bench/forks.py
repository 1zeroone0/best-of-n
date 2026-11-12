"""What bon's own child processes cost, from a fork log: one line per process
bon ran by name, "name start end status args..." (written by a stand-in for
each program first on bon's PATH; see bench/README.md).

    python3 -I forks.py FORKS_LOG AGENT_PROCESSES

Groups each process by what it is for (the program, and for sudo the program
it runs as agent), and prints per group: how many, seconds in total, and per
agent process. A harness session (sudo ... stub.sh, claude, codex) and a
check (sudo ... /bin/sh -c) are counted apart from the fixed overhead.
"""
import collections
import json
import sys


def group(f):
    name, args = f[0], f[4:]
    if name == "sudo":
        # sudo -n -u agent [env -i VAR=... ...] ARGV
        rest = list(args)
        while rest and rest[0] in ("-n", "-u", "agent", "env", "-i"):
            rest.pop(0)
        while rest and "=" in rest[0] and not rest[0].startswith("/"):
            rest.pop(0)
        if any(".bon/stub.sh" in a or "bon-sample" in a or a in ("claude", "codex") for a in rest[:3]):
            return "session (sudo, harness)"
        if rest[:2] == ["/bin/sh", "-c"]:
            return "check (sudo, sh -c)"
        return "sudo " + (" ".join(rest[:2]) if rest[:1] == ["cp"] or rest[:1] == ["rm"] or rest[:1] == ["chmod"] else (rest[0].rsplit("/", 1)[-1] if rest else "?"))
    if name == "git":
        return "git " + (args[0] if args and not args[0].startswith("-") else " ".join(args[:3]))
    if name == "chmod":
        return "chmod " + " ".join(a for a in args[:2] if a.startswith("-") or a.startswith("+") or a[:1].isdigit() or "=" in a or a.startswith("a") or a.startswith("g") or a.startswith("u"))
    return name


def main():
    log, n = sys.argv[1], int(sys.argv[2])
    g = collections.defaultdict(lambda: [0, 0.0])
    for line in open(log, errors="replace"):
        f = line.split()
        if len(f) < 4:
            continue
        k = group(f)
        g[k][0] += 1
        g[k][1] += float(f[2]) - float(f[1])
    rows = sorted(g.items(), key=lambda kv: -kv[1][1])
    fixed = [(k, v) for k, v in rows if not k.startswith("session") and not k.startswith("check")]
    out = {
        "agent_processes": n,
        "groups": {k: {"count": v[0], "seconds": round(v[1], 1), "per_agent_count": round(v[0] / n, 2), "per_agent_seconds": round(v[1] / n, 3)} for k, v in rows},
        "fixed_per_agent": {"count": round(sum(v[0] for _, v in fixed) / n, 1), "seconds": round(sum(v[1] for _, v in fixed) / n, 2)},
    }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
