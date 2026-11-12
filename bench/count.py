"""Count the judge's check logs in a traces directory: those that ran a command
(the log starts "exit:") and those the verdict cache answered ("cached:").
Agent processes' own logs (`harness`) are not checks.

    python3 -I count.py TRACES
"""
import json
import os
import sys


def count(traces):
    executed = cached = 0
    for d, _, files in os.walk(traces):
        for f in files:
            if f == "harness":
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
