// Generated from src/gates.rs, src/wasm.rs by bon types. Do not edit.
/** A git commit, by its hash. */
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
