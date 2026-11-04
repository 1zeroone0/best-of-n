// Generated from src/gates.rs by cargo run --example types. Do not edit.
export type Commit = string;
export type Path = string;
export type Intent = string;
export type Transcript = Path;
export type Cue = number;
export interface AgentProcess { search: number; index: number }
export type Kind = { code: { goal: Intent } } | { map: { goal: Transcript } } | { counterexample: { goal: AgentProcess } } | { compaction: { goal: Commit; out: Array<string> } } | { scrub: { goal: Intent; path: Path } };
export interface Candidate { commit: Commit; base: Commit; checks_pass: boolean; changed: Array<Path>; out: Array<string>; intents: Array<[Cue, Intent]>; test_passes: Array<[number, boolean]>; rank: number; diff: number }
export interface Search { kind: Kind; base: Commit; n: number; checks: Array<Path>; limit: number; results: Array<Candidate | null> }
