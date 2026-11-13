# Generated from src/gates.rs, src/projection.rs by bon types. Do not edit.
from __future__ import annotations

from typing import TypedDict

# POSIX permission bits.
class Permission(TypedDict):
    read: bool
    write: bool
    execute: bool

# A git commit, by its hash. Its own type: a commit is never a path.
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

class KindFoil(TypedDict):
    goal: AgentProcess
    changed: list[Path]

# One key: its variant.
Kind = TypedDict("Kind", {"queue": KindQueue, "code": KindCode, "compaction": KindCompaction, "counterexample": KindCounterexample, "foil": KindFoil}, total=False)

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
    # Whether this candidate's test accepts each foil, by its index in the
    # foil search. A repeated index: the first counts.
    accepts_foils: list[tuple[int, bool]]
    rejects_counterexamples: bool
    # Every agree check and the rank check exited 0.
    measured: bool
    # The paths the diff added, as git reports them.
    added: list[Path]
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
    # The trusted code the manifest's account declares; no search may change it.
    trusted: list[Path]
    limit: int
    results: list[Candidate | None]

# One confined user's permissions on each object the policy names, path by
# path, as trusted code observed them: None where a path does not exist.
# `build_directories[slot]` is check slot `slot`'s build directory.
class Observation(TypedDict):
    checks: list[Permission | None]
    transcripts: list[Permission | None]
    working_directory: list[Permission | None]
    repository: list[Permission | None]
    working_directories: list[Permission | None]
    toolchain: list[Permission | None]
    builds: list[Permission | None]
    state: list[Permission | None]
    build_directories: list[list[Permission | None]]

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
    # Intents no longer on the queue, and the commit that took each off, newest first.
    retired: list[Retired]
    # What no search may change: bon's directory, the checks, trusted code.
    protected: list[str]
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
    # Attempts by kind and width, by how each ended.
    attempts: list[Attempts]
    # How bon processes ended, by kind.
    ended: list[Ended]
    # How many attempts of each kind each reason blocked.
    reasons: list[Reason]
    # How many attempts of each kind exited, by when: during_a_search, or
    # after_its_searches (reported, before a transition), in older traces,
    # which hold no error; or the error the bon process recorded.
    exits: list[Reason]
    # Success probability by kind, and by attempt.
    success: list[Success]
    # Cost per verified candidate by kind, program and model.
    per_verified: list[PerVerified]
    # The host's two semaphores against wall time.
    utilization: Utilization
    # Time and cost to a push, by kind, and each search's as a fixed part
    # plus a part per distinct tree.
    run_time: list[RunTime]

# One kind's success probability, over every attempt (`attempt` none) or
# over each bon process's attempt-th attempt and the searches on it: per
# agent process, successes ÷ agent processes (successes: verified
# candidates; a foil search's foils), over reported searches; per attempt,
# pushed ÷ attempts that ended (pushed, blocked, landed).
class Success(TypedDict):
    kind: str
    attempt: int | None
    agent_processes: int
    successes: int
    ended: int
    pushed: int

# The agent processes of one kind, program and model that returned, how many
# were verified, their generation, and their share of their searches' time
# cost: cost per verified candidate is (generation + time_cost) ÷ verified.
class PerVerified(TypedDict):
    kind: str
    program: str
    model: str
    agent_processes: int
    verified: int
    generation: float
    time_cost: float

# The host's agent_processes and check_processes semaphores over the reported
# searches in range: `wall` is the union of their wall times, in seconds.
class Utilization(TypedDict):
    wall: float
    searches: int
    agent_processes: Pool
    check_processes: Pool

# One semaphore: the slot-seconds held, and its size where every search
# recorded the same one. Utilization is held ÷ (size × wall).
class Pool(TypedDict):
    held: float
    size: int | None

# One kind's run-time distribution: its pushes' time (seconds) and cost to a
# push, each as median and 90th percentile; and over `searches` of its
# reported searches, a search's seconds and cost as a fixed part plus a part
# per distinct tree, by least squares (inferred), none with too few.
class RunTime(TypedDict):
    kind: str
    pushes: int
    time: Spread
    cost: Spread
    searches: int
    fit: Fit | None

# A median (the middle value, or the mean of the middle two) and a 90th
# percentile (the ⌈0.9 n⌉-th smallest); none of no values.
class Spread(TypedDict):
    median: float | None
    p90: float | None

# Seconds and cost, each a fixed part plus a part per distinct tree.
class Fit(TypedDict):
    time: PerTree
    cost: PerTree

# A fixed part, and a part per distinct tree.
class PerTree(TypedDict):
    fixed: float
    per_tree: float

# Attempts of one kind at one width, by how each ended; `attempts` is their
# sum. An attempt is a code or compaction search with the foil and
# counterexample searches on its selection. Landed: a counterexample's test
# landed on trunk and the bon process went on. Exited: its bon process
# stopped during it, on the error it recorded or, in older traces, with no
# transition.
class Attempts(TypedDict):
    kind: str
    width: int
    attempts: int
    pushed: int
    blocked: int
    landed: int
    exited: int
    running: int

# How the bon processes of one kind ended. Exited: stopped short of a final
# transition (killed, interrupted, an error), which is not a block. `expected`
# is the share of those that pushed or blocked (1-p)^k predicts would end
# blocked, p being this kind's success probability per attempt (pushed ÷
# attempts that ended) and k the attempts each process made.
class Ended(TypedDict):
    kind: str
    pushed: int
    blocked: int
    exited: int
    running: int
    expected: float | None

# A reason attempts of one kind blocked, and how many. `inferred` of them
# have no word in their trace (from before reasons were words): the kernel
# derived the reason from the searches' words, or the trace's sentence names
# it. A block nothing names counts under "unrecorded".
class Reason(TypedDict):
    kind: str
    reason: str
    count: int
    inferred: int

# Where a goal came from: the goal, the commit and its subject.
About = TypedDict("About", {"goal": str, "from": str, "subject": str})

# What a push cost, and the commit it pushed. Cost is generation plus time,
# each summed over every bon process run to reach the push.
class Push(TypedDict):
    commit: str | None
    cost: float | None
    generation: float | None
    time_cost: float | None
    to_selection: float | None
    counterexample: float | None
    # The wall time of every search run to reach it, summed as cost is.
    seconds: float | None
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
    # Its searches' wall time, summed.
    seconds: float
    push: Push | None
    time: int
    running: bool
    processes: list[BonProcess]

# One run of a bon command, by its pid.
class BonProcess(TypedDict):
    pid: int
    # Its trace directory under .bon/traces: `<pid>`, or `<pid>.<start>` when
    # an earlier bon process had the same pid.
    trace: str
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
    # Its searches' wall time, summed.
    seconds: float
    push: Push | None
    limit: float | None
    time: int
    # Each line of its transitions file.
    transitions: list[str]
    searches: list[SearchTrace]
    # Seconds its checks of trunk took before its first search, from their logs.
    check_seconds: float | None

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
    # How many verified candidates the trace's summary recorded.
    recorded_verified: int | None
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
    # A running search's agent processes that have not returned: waiting
    # (on an agent_processes slot, or making its working directory), in
    # flight (its program runs), in checks (its program returned; it is judged).
    waiting: int
    in_flight: int
    in_checks: int
    # The host's semaphore sizes it ran under, where its trace records them.
    pools: Pools
    # How many distinct trees its candidates wrote; none where git lacks one.
    trees: int | None
    # Agent processes per behavior: for each distinct `out` its verified
    # candidates show, how many show it, in the order each first appears.
    behaviors: list[int]
    candidates: list[Facts]
    # A code or compaction search: how its attempt ended (pushed, blocked,
    # landed, exited, running).
    end: str | None
    # A blocked attempt's reason, by its word; none where nothing names it.
    reason: str | None
    # Where the reason came from: recorded (the trace's word), kernel (derived
    # from the searches' words) or sentence (the trace's sentence).
    reason_from: str | None

# The sizes of the host's two semaphores.
class Pools(TypedDict):
    agent_processes: int | None
    check_processes: int | None

# What a search was granted with.
class Params(TypedDict):
    goal: GoalRef
    base: str
    n: int | None
    limit: float | None
    authority: str

# A search's goal: a trunk commit, a candidate of a search, or a transcript.
class GoalRef(TypedDict):
    trunk: str | None
    candidate: str | None
    transcript: str | None

# One agent process, from its facts.json.
class Facts(TypedDict):
    index: int
    # The program it ran (older traces: their `harness`).
    program: str | None
    model: str | None
    generation: float | None
    commit: str | None
    accepted: bool
    # Verus verified it.
    proved: bool
    verified: bool
    rank: int | None
    diff: int | None
    lines_added: int | None
    lines_removed: int | None
    # Its commit's tree, where git has it.
    tree: str | None
    # killed, over limit, price mismatch.
    flags: list[str]
    logs: list[str]
    # Seconds its program ran, from its log.
    program_seconds: float | None
    # Seconds of its checks, summed from their logs.
    check_seconds: float | None
    changed: list[str]
    # A hash of each agree check's output: candidates with the same agree.
    out: list[int]
    # A test's verdict on each member it ran on, by index; trunk's head (or a
    # compaction's goal) is -1. Empty for a candidate that is no test.
    accepts: list[tuple[int, bool]]
    # A test's verdict on each foil it ran on, by index in the foil search.
    accepts_foils: list[tuple[int, bool]]

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

# An intent taken off the queue: by the commit on trunk's history whose diff
# removed its line, with that commit's subject and time.
class Retired(TypedDict):
    id: int
    intent: str
    commit: str
    subject: str
    time: int | None

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

# A network service a program calls.
class Service(TypedDict):
    name: str
    endpoints: list[str]
    group: str | None
