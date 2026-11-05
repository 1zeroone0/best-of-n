// Generated from src/gates.rs by cargo run --example types. Do not edit.
export type Commit = string;
export type Path = string;
export type Intent = string;
export type Transcript = Path;
export type Cue = number;
export interface AgentProcess { search: number; index: number }
export type Kind = { queue: { goal: Transcript } } | { code: { goal: Commit } } | { compaction: { goal: Commit; out: Array<string> } } | { counterexample: { goal: AgentProcess | null } };
export interface Candidate { commit: Commit; base: Commit; accepted: boolean; proved: boolean; changed: Array<Path>; out: Array<string>; intents: Array<[Cue, Intent]>; accepts: Array<[number, boolean]>; rejects_counterexamples: boolean; rank: number; diff: number }
export interface Search { kind: Kind; base: Commit; n: number; checks: Array<Path>; tests: Array<Path>; limit: number; results: Array<Candidate | null> }
