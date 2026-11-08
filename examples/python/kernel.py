# Generated from src/gates.rs, src/wasm.rs by bon types. Do not edit.
from __future__ import annotations

from typing import TypedDict

# A git commit, by its hash.
Commit = str

# A path in a commit's tree.
Path = str

# One line of the queue.
Intent = str

# A WebVTT file.
Transcript = Path

# A WebVTT cue, by its start time in milliseconds.
Cue = int

# A hash of an agree check's output. Programs read it as a decimal string,
# since a JSON number loses u64 precision in a browser.
Hash = str

# A process running as agent that writes one candidate.
class AgentProcess(TypedDict):
    search: int
    index: int

# What a search is for: its kind, carrying its goal.
class KindQueue(TypedDict):
    goal: Transcript

class KindCode(TypedDict):
    goal: Commit

class KindCompaction(TypedDict):
    goal: Commit
    out: list[Hash]

class KindCounterexample(TypedDict):
    goal: AgentProcess | None

# One key: its variant.
Kind = TypedDict("Kind", {"queue": KindQueue, "code": KindCode, "compaction": KindCompaction, "counterexample": KindCounterexample}, total=False)

# One generated change, as trusted code observed it.
class Candidate(TypedDict):
    commit: Commit
    base: Commit
    accepted: bool
    proved: bool
    changed: list[Path]
    out: list[Hash]
    # Each new intent, by the cue it cites. A repeated cue: the first counts.
    intents: list[tuple[Cue, Intent]]
    # Whether this candidate's test accepts each tested commit: the goal
    # search's candidates by index, and trunk's head (or a compaction's goal)
    # as -1. A repeated index: the first counts.
    accepts: list[tuple[int, bool]]
    rejects_counterexamples: bool
    rank: int
    diff: int

# One search, once every agent process has returned: `results[i]` is what
# agent process i returned.
class Search(TypedDict):
    kind: Kind
    base: Commit
    n: int
    # The check paths the manifest declares; the authority derives from them.
    checks: list[Path]
    # The paths holding the counterexamples' tests.
    tests: list[Path]
    # The trusted code the manifest's SBOM declares; no search may change it.
    trusted: list[Path]
    limit: int
    results: list[Candidate | None]

# A gate's answer when it names no candidate.
NONE = -1

# A gate's answer when the words are not a search (or name no such agent process).
NOT_A_SEARCH = -2
