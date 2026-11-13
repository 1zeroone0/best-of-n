// Generated from src/gates.rs, src/projection.rs by bon types. Do not edit.
/** POSIX permission bits. */
export interface Permission { read: boolean; write: boolean; execute: boolean }
/** A git commit, by its hash. Its own type: a commit is never a path. */
export type Commit = string;
/** A path in a commit's tree. */
export type Path = string;
/** One line of the queue. */
export type Intent = string;
/** A WebVTT file. */
export type Transcript = Path;
/** A WebVTT cue, by its start time in milliseconds. */
export type Cue = number;
/** A hash of an agree check's output: an identity, not a quantity, so it is its own type. Programs read it as a decimal string. */
export type Hash = string;
/** A process running as agent that writes one candidate. */
export interface AgentProcess { search: number; index: number }
/** What a search is for: its kind, carrying its goal. */
export type Kind = { queue: { goal: Transcript } } | { code: { goal: Commit } } | { compaction: { goal: Commit; out: Array<Hash> } } | { counterexample: { goal: AgentProcess | null } } | { foil: { goal: AgentProcess; changed: Array<Path> } };
/** One generated change, as trusted code observed it. */
export interface Candidate { commit: Commit; base: Commit; accepted: boolean; proved: boolean; changed: Array<Path>; out: Array<Hash>; intents: Array<[Cue, Intent]>; accepts: Array<[number, boolean]>; accepts_foils: Array<[number, boolean]>; rejects_counterexamples: boolean; measured: boolean; added: Array<Path>; rank: number; diff: number }
/** One search, once every agent process has returned: `results[i]` is what agent process i returned. */
export interface Search { kind: Kind; base: Commit; n: number; checks: Array<Path>; tests: Array<Path>; trusted: Array<Path>; limit: number; results: Array<Candidate | null>; context: Array<Commit> }
/** One confined user's permissions on each object the policy names, path by path, as trusted code observed them: None where a path does not exist. `build_directories[slot]` is check slot `slot`'s build directory. */
export interface Observation { checks: Array<Permission | null>; transcripts: Array<Permission | null>; working_directory: Array<Permission | null>; repository: Array<Permission | null>; working_directories: Array<Permission | null>; toolchain: Array<Permission | null>; builds: Array<Permission | null>; state: Array<Permission | null>; build_directories: Array<Array<Permission | null>> }
/** Everything bon shows, over the time range in `filter`. */
export interface Projection { configured: boolean; repo: Repo; totals: Totals; processes: Array<BonProcess>; groups: Array<GoalTrace>; queue: Array<QueueLine> | null; proposals: Array<Proposal>; interrupts: Array<Interrupt>; retired: Array<Retired>; protected: Array<string>; filter: Filter; bounds: Bounds; spec: SpecOutline | null; system: SpecGraph | null; sbom: SbomFile | null }
/** The repository and its trunk. */
export interface Repo { name: string | null; head: string | null; trunk: string | null; remote: string | null; remote_head: string | null; remote_time: number | null; subject: string | null; last_push: LastPush | null; since_push: SincePush | null; pushed: boolean | null; now: number }
export interface LastPush { commit: string | null; time: number | null }
/** Commits on trunk since bon last pushed, and who made them. */
export interface SincePush { commits: number; authors: Array<string> }
/** What everything in range cost, and what came of it. */
export interface Totals { cost: number; generation: number; time_cost: number; pushed: number; not_pushed: number; in_flight: number; rate: number | null; per_verified_candidate: number | null; per_push: number | null; pushes: number; verified: number; candidates: number; attempts: Array<Attempts>; ended: Array<Ended>; reasons: Array<Reason>; exits: Array<Reason>; success: Array<Success>; per_verified: Array<PerVerified>; utilization: Utilization; run_time: Array<RunTime>; turnaround: Array<Turnaround> }
/** One kind of interrupt's turnaround: of its interrupts, how many resolved and how many are pending, and the seconds from raised to resolved of those that resolved, as median and 90th percentile. */
export interface Turnaround { kind: string; resolved: number; pending: number; time: Spread }
/** Every record a bon process writes, in one shape: what ran (program), what it was given (context), what it returned (output), how it was judged (verdict) and which behavior its output showed (behavior). An agent process: its program, its prompt, its candidate's commit, what its checks said (proved, accepted, rejected), its agree outputs' hashes. A check: its command, the tree it ran on, its output, its exit, its output's hash. A decision: engineer, what the interrupt showed, the commit that answered it, what came of it, the choice it showed. */
export interface Record { program: string | null; context: string | null; output: string | null; verdict: string | null; behavior: string | null }
/** What only engineer can answer, derived from the traces and never stored: pending until the action that answers it, which bon recognises from what is already recorded; there is no dismiss. Kinds: `proposal` (a queue proposal awaiting acceptance), `blocked` (an attempt blocked with its width list or its limit spent), `transcript` (a transcript the host file routes nowhere). */
export interface Interrupt { kind: string; id: string; repository: string; root: string; about: string; reason: string | null; raised: number; resolved: number | null; what: Array<string>; choices: Array<Choice>; answer: Answer | null; came_of_it: string | null; decision: Record | null; transcript: Transcript | null }
/** One choice: its name, how it is made, and what it costs, from the traces. */
export interface Choice { choice: string; how: string; cost: string }
/** The action that answered an interrupt: its commit, if it was one, and its subject, or a later attempt's trace; and which choice it showed. */
export interface Answer { commit: string | null; subject: string; choice: string }
/** A pointer to a transcript, and its hash. */
export interface Transcript { path: string; sha256: string }
/** One kind's success probability, over every attempt (`attempt` none) or over each bon process's attempt-th attempt and the searches on it: per agent process, successes ÷ agent processes (successes: verified candidates; a foil search's foils), over reported searches; per attempt, pushed ÷ attempts that ended (pushed, blocked, landed). */
export interface Success { kind: string; attempt: number | null; agent_processes: number; successes: number; ended: number; pushed: number }
/** The agent processes of one kind, program and model that returned, how many were verified, their generation, and their share of their searches' time cost: cost per verified candidate is (generation + time_cost) ÷ verified. */
export interface PerVerified { kind: string; program: string; model: string; agent_processes: number; verified: number; generation: number; time_cost: number }
/** The host's agent_processes and check_processes semaphores over the reported searches in range: `wall` is the union of their wall times, in seconds. */
export interface Utilization { wall: number; searches: number; agent_processes: Pool; check_processes: Pool }
/** One semaphore: the slot-seconds held, and its size where every search recorded the same one. Utilization is held ÷ (size × wall). */
export interface Pool { held: number; size: number | null }
/** One kind's run-time distribution: its pushes' time (seconds) and cost to a push, each as median and 90th percentile; and over `searches` of its reported searches, a search's seconds and cost as a fixed part plus a part per distinct tree, by least squares (inferred), none with too few. */
export interface RunTime { kind: string; pushes: number; time: Spread; cost: Spread; searches: number; fit: Fit | null }
/** A median (the middle value, or the mean of the middle two) and a 90th percentile (the ⌈0.9 n⌉-th smallest); none of no values. */
export interface Spread { median: number | null; p90: number | null }
/** Seconds and cost, each a fixed part plus a part per distinct tree. */
export interface Fit { time: PerTree; cost: PerTree }
/** A fixed part, and a part per distinct tree. */
export interface PerTree { fixed: number; per_tree: number }
/** Attempts of one kind at one width, by how each ended; `attempts` is their sum. An attempt is a code or compaction search with the foil and counterexample searches on its selection. Landed: a counterexample's test landed on trunk and the bon process went on. Exited: its bon process stopped during it, on the error it recorded or, in older traces, with no transition. */
export interface Attempts { kind: string; width: number; attempts: number; pushed: number; blocked: number; landed: number; exited: number; running: number }
/** How the bon processes of one kind ended. Exited: stopped short of a final transition (killed, interrupted, an error), which is not a block. `expected` is the share of those that pushed or blocked (1-p)^k predicts would end blocked, p being this kind's success probability per attempt (pushed ÷ attempts that ended) and k the attempts each process made. */
export interface Ended { kind: string; pushed: number; blocked: number; exited: number; running: number; expected: number | null }
/** A reason attempts of one kind blocked, and how many. `inferred` of them have no word in their trace (from before reasons were words): the kernel derived the reason from the searches' words, or the trace's sentence names it. A block nothing names counts under "unrecorded". */
export interface Reason { kind: string; reason: string; count: number; inferred: number }
/** Where a goal came from: the goal, the commit and its subject. */
export interface About { goal: string; from: string; subject: string }
/** What a push cost, and the commit it pushed. Cost is generation plus time, each summed over every bon process run to reach the push. */
export interface Push { commit: string | null; cost: number | null; generation: number | null; time_cost: number | null; to_selection: number | null; counterexample: number | null; seconds: number | null; searches: number | null; processes: number | null }
/** The bon processes of one goal: one row of the traces. */
export interface GoalTrace { kind: string; title: string; about: About; outcome: string; sentence: string; cost: number; generation: number; time_cost: number; seconds: number; push: Push | null; time: number; running: boolean; processes: Array<BonProcess> }
/** One run of a bon command, by its pid. */
export interface BonProcess { pid: number; trace: string; running: boolean; kind: string; goal: string; title: string; about: About; outcome: string; sentence: string; cost: number; generation: number; time_cost: number; seconds: number; push: Push | null; limit: number | null; time: number; transitions: Array<string>; searches: Array<SearchTrace>; check_seconds: number | null }
/** One search of a bon process, as its trace recorded it. */
export interface SearchTrace { search: number; kind: string; goal: string; params: Params; width: number; started: number | null; returned: number; accepted: number; verified: number; selected: number | null; recorded_selected: number | null; recorded_verified: number | null; kernel: string; blocked: string | null; generation: number | null; time_cost: number | null; cost: number | null; rate: number | null; seconds: number | null; time: number | null; running: boolean; background: boolean; waiting: number; in_flight: number; in_checks: number; pools: Pools; trees: number | null; behaviors: Array<number>; candidates: Array<Facts>; end: string | null; reason: string | null; reason_from: string | null }
/** The sizes of the host's two semaphores. */
export interface Pools { agent_processes: number | null; check_processes: number | null }
/** What a search was granted with. */
export interface Params { goal: GoalRef; base: string; n: number | null; limit: number | null; authority: string }
/** A search's goal: a trunk commit, a candidate of a search, or a transcript. */
export interface GoalRef { trunk: string | null; candidate: string | null; transcript: string | null }
/** One agent process, from its facts.json. */
export interface Facts { index: number; program: string | null; model: string | null; generation: number | null; commit: string | null; accepted: boolean; proved: boolean; verified: boolean; rank: number | null; diff: number | null; lines_added: number | null; lines_removed: number | null; tree: string | null; flags: Array<string>; logs: Array<string>; program_seconds: number | null; check_seconds: number | null; changed: Array<string>; out: Array<number>; accepts: Array<[number, boolean]>; accepts_foils: Array<[number, boolean]>; record: Record }
/** A queue proposal: a patch adding intents, each with the cue it came from. */
export interface Proposal { name: string; path: string; source: string; intents: Array<ProposedIntent>; contested: Array<string> }
export interface ProposedIntent { id: number | null; intent: string; cue: string | null }
/** An intent taken off the queue: by the commit on trunk's history whose diff removed its line, with that commit's subject and time. */
export interface Retired { id: number; intent: string; commit: string; subject: string; time: number | null }
/** One line of the queue. */
export interface QueueLine { id: number; intent: string }
/** The time range bon was asked for. */
export interface Filter { since: number | null; until: number | null; find: string | null }
/** The earliest and latest bon process on record. */
export interface Bounds { earliest: number | null; latest: number | null }
/** The spec module as written: its state fields and its items. */
export interface SpecOutline { path: string; fields: Array<SpecField>; items: Array<SpecItem> }
/** A field of the spec's state machine. */
export interface SpecField { name: string; type: string; sharding: string | null; doc: string | null }
/** A type, predicate, transition, property or invariant of the spec, with its `///` line. */
export interface SpecItem { kind: string; name: string; doc: string | null; reads: Array<string>; updates: Array<string>; requires: Array<string> }
/** The spec and how it reaches the code: items, and what each ensures, implements and calls. */
export interface SpecGraph { nodes: Array<SpecNode>; edges: Array<[string, string, string]>; trusted: Array<TrustedFunction>; counts: Counts }
/** One item of the spec or of the code that reaches it. */
export interface SpecNode { id: string; layer: string; group: string; name: string; file: string; line: number | null; end: number | null; doc: string | null; changed: boolean; guards: Array<string>; adds: Array<string>; removes: Array<string>; uses: Array<string>; trusted: Array<string>; proof: boolean; requires: Array<string>; ensures: Array<string> }
/** A function in trusted code the bon process calls. */
export interface TrustedFunction { name: string; file: string; line: number; doc: string | null; changed: boolean }
export interface Counts { predicates: number; private: number; trusted: number }
/** .bon/sbom.json, and whether it is trunk's or the working tree's. */
export interface SbomFile { source: string; document: Sbom }
/** A CycloneDX SBOM: its components, services and properties. */
export interface Sbom { metadata: SbomMetadata; components: Array<Component>; services: Array<Service> }
export interface SbomMetadata { properties: Array<Property> }
export interface Property { name: string; value: string }
/** A library, tool or host component. */
export interface Component { type: string; name: string; version: string; group: string | null; purl: string | null; hashes: Array<ComponentHash> }
export interface ComponentHash { alg: string; content: string }
/** A network service a program calls. */
export interface Service { name: string; endpoints: Array<string>; group: string | null }
