"""Count the judge's check logs in a traces directory: those that ran a command
(the log starts "exit:") and those the verdict cache answered ("cached:").
Agent processes' own logs (`program`; `harness` in older traces) are not checks.
A push's re-checks (`recheck-*`) ran a command, so they count as executed.

    python3 -I count.py TRACES
"""
import json
import os
import sys


def count(traces):
    executed = cached = 0
    for d, _, files in os.walk(traces):
        for f in files:
            if f in ("program", "harness"):
                continue
            try:
                with open(os.path.join(d, f), errors="replace") as h:
                    first = h.readline()
            except OSError:
                continue
            executed += first.startswith("exit: ")
            cached += first.startswith("cached: ")
    return executed, cached


if __name__ == "__main__":
    e, c = count(sys.argv[1])
    print(json.dumps({"checks_executed": e, "checks_cached": c}))
