# Generated from src/gates.rs, src/wasm.rs, src/projection.rs by bon types. Do not edit.
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

# A hash of an agree check's output: an identity, not a quantity, so it is
# its own type. Programs read it as a decimal string.
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

# Everything bon shows, over the time range in `filter`.
class Projection(TypedDict):
    # Whether trunk's head has a .bon/bon.toml.
    configured: bool
    repo: Repo
    totals: Totals
    # Every bon process in range, newest first.
    processes: list[BonProcess]
    # The bon processes of one goal, together: a row of the traces.
    groups: list[GoalTrace]
    # What is wanted and not yet in the spec.
    queue: list[QueueLine] | None
    # Queue proposals waiting for engineer: patches bon queue wrote.
    proposals: list[Proposal]
    filter: Filter
    bounds: Bounds
    spec: SpecOutline | None
    system: SpecGraph | None
    sbom: SbomFile | None

# The repository and its trunk.
class Repo(TypedDict):
    name: str | None
    head: str | None
    trunk: str | None
    remote: str | None
    remote_head: str | None
    remote_time: int | None
    subject: str | None
    last_push: LastPush | None
    since_push: SincePush | None
    pushed: bool | None
    now: int

class LastPush(TypedDict):
    commit: str | None
    time: int | None

# Commits on trunk since bon last pushed, and who made them.
class SincePush(TypedDict):
    commits: int
    authors: list[str]

# What everything in range cost, and what came of it.
class Totals(TypedDict):
    cost: float
    generation: float
    time_cost: float
    pushed: float
    not_pushed: float
    in_flight: float
    rate: float | None
    per_verified_candidate: float | None
    per_push: float | None
    pushes: int
    verified: int
    candidates: int

# Where a goal came from: the goal, the commit and its subject.
About = TypedDict("About", {"goal": str, "from": str, "subject": str})

# What a push cost, and the commit it pushed.
class Push(TypedDict):
    commit: str | None
    cost: float | None
    to_selection: float | None
    counterexample: float | None
    searches: int | None
    processes: int | None

# The bon processes of one goal: one row of the traces.
class GoalTrace(TypedDict):
    kind: str
    title: str
    about: About
    outcome: str
    sentence: str
    cost: float
    generation: float
    time_cost: float
    push: Push | None
    time: int
    running: bool
    processes: list[BonProcess]

# One run of a bon command, by its pid.
class BonProcess(TypedDict):
    pid: int
    running: bool
    kind: str
    goal: str
    title: str
    about: About
    outcome: str
    sentence: str
    cost: float
    generation: float
    time_cost: float
    push: Push | None
    limit: float | None
    time: int
    # Each line of its transitions file.
    transitions: list[str]
    searches: list[SearchTrace]

# One search of a bon process, as its trace recorded it.
class SearchTrace(TypedDict):
    search: int
    kind: str
    goal: str
    params: Params
    width: int
    started: int | None
    returned: int
    accepted: int
    verified: int
    selected: int | None
    recorded_selected: int | None
    # derived (the kernel read its words), unreadable, or none.
    kernel: str
    blocked: str | None
    generation: float | None
    time_cost: float | None
    cost: float | None
    rate: float | None
    seconds: float | None
    time: int | None
    running: bool
    background: bool
    candidates: list[Facts]

# What a search was granted with.
class Params(TypedDict):
    goal: GoalRef
    base: str
    n: int | None
    limit: float | None
    authority: str

# A search's goal: a trunk commit, a selected candidate, or a transcript.
class GoalRef(TypedDict):
    trunk: str | None
    candidate: str | None
    transcript: str | None

# One agent process, from its facts.json.
class Facts(TypedDict):
    index: int
    harness: str | None
    model: str | None
    generation: float | None
    commit: str | None
    accepted: bool
    verified: bool
    rank: int | None
    diff: int | None
    added: int | None
    removed: int | None
    # killed, over limit, price mismatch.
    flags: list[str]
    logs: list[str]
    changed: list[str]
    # A hash of each agree check's output: candidates with the same agree.
    out: list[int]

# A queue proposal: a patch adding intents, each with the cue it came from.
class Proposal(TypedDict):
    name: str
    path: str
    source: str
    intents: list[ProposedIntent]
    # Cues only one candidate cited, shown apart from the proposal.
    contested: list[str]

class ProposedIntent(TypedDict):
    id: int | None
    intent: str
    cue: str | None

# One line of the queue.
class QueueLine(TypedDict):
    id: int
    intent: str

# The time range bon was asked for.
class Filter(TypedDict):
    since: int | None
    until: int | None
    find: str | None

# The earliest and latest bon process on record.
class Bounds(TypedDict):
    earliest: int | None
    latest: int | None

# The spec module as written: its state fields and its items.
class SpecOutline(TypedDict):
    path: str
    fields: list[SpecField]
    items: list[SpecItem]

# A field of the spec's state machine.
class SpecField(TypedDict):
    name: str
    type: str
    sharding: str | None
    doc: str | None

# A type, predicate, transition, property or invariant of the spec, with its `///` line.
class SpecItem(TypedDict):
    kind: str
    name: str
    doc: str | None
    reads: list[str]
    updates: list[str]
    requires: list[str]

# The spec and how it reaches the code: items, and what each ensures, implements and calls.
class SpecGraph(TypedDict):
    nodes: list[SpecNode]
    # from, to, and how: ensures, implements, calls, transition, types.
    edges: list[tuple[str, str, str]]
    trusted: list[TrustedFunction]
    counts: Counts

# One item of the spec or of the code that reaches it.
class SpecNode(TypedDict):
    id: str
    layer: str
    group: str
    name: str
    file: str
    line: int | None
    end: int | None
    doc: str | None
    # Differs from trunk.
    changed: bool
    guards: list[str]
    adds: list[str]
    removes: list[str]
    uses: list[str]
    trusted: list[str]
    proof: bool
    # A gate's contract, each clause as written.
    requires: list[str]
    ensures: list[str]

# A function in trusted code the bon process calls.
class TrustedFunction(TypedDict):
    name: str
    file: str
    line: int
    doc: str | None
    changed: bool

class Counts(TypedDict):
    predicates: int
    private: int
    trusted: int

# .bon/sbom.json, and whether it is trunk's or the working tree's.
class SbomFile(TypedDict):
    source: str
    document: Sbom

# A CycloneDX SBOM: its components, services and properties.
class Sbom(TypedDict):
    metadata: SbomMetadata
    components: list[Component]
    services: list[Service]

class SbomMetadata(TypedDict):
    properties: list[Property]

class Property(TypedDict):
    name: str
    value: str

# A library, tool or host component.
class Component(TypedDict):
    type: str
    name: str
    version: str
    group: str | None
    purl: str | None
    hashes: list[ComponentHash]

class ComponentHash(TypedDict):
    alg: str
    content: str

# A network service a harness calls.
class Service(TypedDict):
    name: str
    endpoints: list[str]
    group: str | None
