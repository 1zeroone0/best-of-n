"""A program built on the kernel's emitted types (kernel.py, written by bon
types), with PyTorch: it reads searches as the kernel emits them, one JSON
object per line, and holds each search's candidates as a tensor. It decides
nothing; the kernel does.

    cargo run -q --example kernel | examples/python/.venv/bin/python examples/python/main.py
"""
import json
import sys

import torch

from kernel import Candidate, Search


def goal(search: Search) -> str:
    """The search's kind and goal, in the spec's words."""
    (name, fields), = search["kind"].items()
    target = fields["goal"]
    if name == "counterexample":
        target = "trunk" if target is None else f"search {target['search']} candidate {target['index']}"
    return f"{name} {target}"


def tensor(candidates: list[Candidate]) -> torch.Tensor:
    """One row per candidate: accepted, proved, rank, diff."""
    return torch.tensor([[c["accepted"], c["proved"], c["rank"], c["diff"]] for c in candidates], dtype=torch.float64)


for line in sys.stdin:
    if not line.startswith("{"):
        continue
    search: Search = json.loads(line)
    candidates = [c for c in search["results"] if c is not None]
    rows = tensor(candidates)
    accepted = rows[:, 0].bool()
    print(f"{goal(search)}: {len(candidates)} of {search['n']} returned, "
          f"{int(accepted.sum())} accepted, mean diff {rows[accepted, 3].mean().item():.1f}")
