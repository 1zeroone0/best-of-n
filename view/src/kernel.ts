// Generated from src/gates.rs, src/wasm.rs, src/projection.rs by bon types. Do not edit.
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
export type Kind = { queue: { goal: Transcript } } | { code: { goal: Commit } } | { compaction: { goal: Commit; out: Array<Hash> } } | { counterexample: { goal: AgentProcess | null } };
/** One generated change, as trusted code observed it. */
export interface Candidate { commit: Commit; base: Commit; accepted: boolean; proved: boolean; changed: Array<Path>; out: Array<Hash>; intents: Array<[Cue, Intent]>; accepts: Array<[number, boolean]>; rejects_counterexamples: boolean; rank: number; diff: number }
/** One search, once every agent process has returned: `results[i]` is what agent process i returned. */
export interface Search { kind: Kind; base: Commit; n: number; checks: Array<Path>; tests: Array<Path>; trusted: Array<Path>; limit: number; results: Array<Candidate | null> }
/** A gate's answer when it names no candidate. */
export const NONE = -1;
/** A gate's answer when the words are not a search (or name no such agent process). */
export const NOT_A_SEARCH = -2;
/** Everything bon shows, over the time range in `filter`. */
export interface Projection { configured: boolean; repo: Repo; totals: Totals; processes: Array<BonProcess>; groups: Array<GoalTrace>; queue: Array<QueueLine> | null; proposals: Array<Proposal>; protected: Array<string>; filter: Filter; bounds: Bounds; spec: SpecOutline | null; system: SpecGraph | null; sbom: SbomFile | null }
/** The repository and its trunk. */
export interface Repo { name: string | null; head: string | null; trunk: string | null; remote: string | null; remote_head: string | null; remote_time: number | null; subject: string | null; last_push: LastPush | null; since_push: SincePush | null; pushed: boolean | null; now: number }
export interface LastPush { commit: string | null; time: number | null }
/** Commits on trunk since bon last pushed, and who made them. */
export interface SincePush { commits: number; authors: Array<string> }
/** What everything in range cost, and what came of it. */
export interface Totals { cost: number; generation: number; time_cost: number; pushed: number; not_pushed: number; in_flight: number; rate: number | null; per_verified_candidate: number | null; per_push: number | null; pushes: number; verified: number; candidates: number }
/** Where a goal came from: the goal, the commit and its subject. */
export interface About { goal: string; from: string; subject: string }
/** What a push cost, and the commit it pushed. */
export interface Push { commit: string | null; cost: number | null; to_selection: number | null; counterexample: number | null; searches: number | null; processes: number | null }
/** The bon processes of one goal: one row of the traces. */
export interface GoalTrace { kind: string; title: string; about: About; outcome: string; sentence: string; cost: number; generation: number; time_cost: number; push: Push | null; time: number; running: boolean; processes: Array<BonProcess> }
/** One run of a bon command, by its pid. */
export interface BonProcess { pid: number; running: boolean; kind: string; goal: string; title: string; about: About; outcome: string; sentence: string; cost: number; generation: number; time_cost: number; push: Push | null; limit: number | null; time: number; transitions: Array<string>; searches: Array<SearchTrace> }
/** One search of a bon process, as its trace recorded it. */
export interface SearchTrace { search: number; kind: string; goal: string; params: Params; width: number; started: number | null; returned: number; accepted: number; verified: number; selected: number | null; recorded_selected: number | null; kernel: string; blocked: string | null; generation: number | null; time_cost: number | null; cost: number | null; rate: number | null; seconds: number | null; time: number | null; running: boolean; background: boolean; candidates: Array<Facts> }
/** What a search was granted with. */
export interface Params { goal: GoalRef; base: string; n: number | null; limit: number | null; authority: string }
/** A search's goal: a trunk commit, a selected candidate, or a transcript. */
export interface GoalRef { trunk: string | null; candidate: string | null; transcript: string | null }
/** One agent process, from its facts.json. */
export interface Facts { index: number; harness: string | null; model: string | null; generation: number | null; commit: string | null; accepted: boolean; proved: boolean; verified: boolean; rank: number | null; diff: number | null; added: number | null; removed: number | null; flags: Array<string>; logs: Array<string>; changed: Array<string>; out: Array<number> }
/** A queue proposal: a patch adding intents, each with the cue it came from. */
export interface Proposal { name: string; path: string; source: string; intents: Array<ProposedIntent>; contested: Array<string> }
export interface ProposedIntent { id: number | null; intent: string; cue: string | null }
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
/** A network service a harness calls. */
export interface Service { name: string; endpoints: Array<string>; group: string | null }
