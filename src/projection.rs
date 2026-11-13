//! The projection `bon` and `bon view` show, as types: what `view::state` builds
//! from the traces, the queue, the spec and the SBOM. Trusted code. `bon types`
//! emits these for programs, as it does the kernel's.

use serde::Deserialize;

/// Everything bon shows, over the time range in `filter`.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Projection {
    /// Whether trunk's head has a .bon/bon.toml.
    pub configured: bool,
    pub repo: Repo,
    pub totals: Totals,
    /// Every bon process in range, newest first.
    pub processes: Vec<BonProcess>,
    /// The bon processes of one goal, together: a row of the traces.
    pub groups: Vec<GoalTrace>,
    /// What is wanted and not yet in the spec.
    pub queue: Option<Vec<QueueLine>>,
    /// Queue proposals waiting for engineer: patches bon queue wrote.
    pub proposals: Vec<Proposal>,
    /// Intents no longer on the queue, and the commit that took each off, newest first.
    pub retired: Vec<Retired>,
    /// What no search may change: bon's directory, the checks, trusted code.
    pub protected: Vec<String>,
    pub filter: Filter,
    pub bounds: Bounds,
    pub spec: Option<SpecOutline>,
    pub system: Option<SpecGraph>,
    pub sbom: Option<SbomFile>,
}

/// The repository and its trunk.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Repo {
    pub name: Option<String>,
    pub head: Option<String>,
    pub trunk: Option<String>,
    pub remote: Option<String>,
    pub remote_head: Option<String>,
    pub remote_time: Option<i64>,
    pub subject: Option<String>,
    pub last_push: Option<LastPush>,
    pub since_push: Option<SincePush>,
    pub pushed: Option<bool>,
    pub now: i64,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct LastPush {
    pub commit: Option<String>,
    pub time: Option<i64>,
}

/// Commits on trunk since bon last pushed, and who made them.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SincePush {
    pub commits: u64,
    pub authors: Vec<String>,
}

/// What everything in range cost, and what came of it.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Totals {
    pub cost: f64,
    pub generation: f64,
    pub time_cost: f64,
    pub pushed: f64,
    pub not_pushed: f64,
    pub in_flight: f64,
    pub rate: Option<f64>,
    pub per_verified_candidate: Option<f64>,
    pub per_push: Option<f64>,
    pub pushes: u64,
    pub verified: u64,
    pub candidates: u64,
    /// Attempts by kind and width, by how each ended.
    pub attempts: Vec<Attempts>,
    /// How bon processes ended, by kind.
    pub ended: Vec<Ended>,
    /// How many attempts of each kind each reason blocked.
    pub reasons: Vec<Reason>,
    /// How many attempts of each kind exited, by when: during_a_search, or
    /// after_its_searches (reported, before a transition), in older traces,
    /// which hold no error; or the error the bon process recorded.
    pub exits: Vec<Reason>,
    /// Success probability by kind, and by attempt.
    pub success: Vec<Success>,
    /// Cost per verified candidate by kind, program and model.
    pub per_verified: Vec<PerVerified>,
    /// The host's two semaphores against wall time.
    pub utilization: Utilization,
    /// Time and cost to a push, by kind, and each search's as a fixed part
    /// plus a part per distinct tree.
    pub run_time: Vec<RunTime>,
}

/// One kind's success probability, over every attempt (`attempt` none) or
/// over each bon process's attempt-th attempt and the searches on it: per
/// agent process, successes ÷ agent processes (successes: verified
/// candidates; a foil search's foils), over reported searches; per attempt,
/// pushed ÷ attempts that ended (pushed, blocked, landed).
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Success {
    pub kind: String,
    pub attempt: Option<u64>,
    pub agent_processes: u64,
    pub successes: u64,
    pub ended: u64,
    pub pushed: u64,
}

/// The agent processes of one kind, program and model that returned, how many
/// were verified, their generation, and their share of their searches' time
/// cost: cost per verified candidate is (generation + time_cost) ÷ verified.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct PerVerified {
    pub kind: String,
    pub program: String,
    pub model: String,
    pub agent_processes: u64,
    pub verified: u64,
    pub generation: f64,
    pub time_cost: f64,
}

/// The host's agent_processes and check_processes semaphores over the reported
/// searches in range: `wall` is the union of their wall times, in seconds.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Utilization {
    pub wall: f64,
    pub searches: u64,
    pub agent_processes: Pool,
    pub check_processes: Pool,
}

/// One semaphore: the slot-seconds held, and its size where every search
/// recorded the same one. Utilization is held ÷ (size × wall).
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Pool {
    pub held: f64,
    pub size: Option<u64>,
}

/// One kind's run-time distribution: its pushes' time (seconds) and cost to a
/// push, each as median and 90th percentile; and over `searches` of its
/// reported searches, a search's seconds and cost as a fixed part plus a part
/// per distinct tree, by least squares (inferred), none with too few.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct RunTime {
    pub kind: String,
    pub pushes: u64,
    pub time: Spread,
    pub cost: Spread,
    pub searches: u64,
    pub fit: Option<Fit>,
}

/// A median (the middle value, or the mean of the middle two) and a 90th
/// percentile (the ⌈0.9 n⌉-th smallest); none of no values.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Spread {
    pub median: Option<f64>,
    pub p90: Option<f64>,
}

/// Seconds and cost, each a fixed part plus a part per distinct tree.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Fit {
    pub time: PerTree,
    pub cost: PerTree,
}

/// A fixed part, and a part per distinct tree.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct PerTree {
    pub fixed: f64,
    pub per_tree: f64,
}

/// Attempts of one kind at one width, by how each ended; `attempts` is their
/// sum. An attempt is a code or compaction search with the foil and
/// counterexample searches on its selection. Landed: a counterexample's test
/// landed on trunk and the bon process went on. Exited: its bon process
/// stopped during it, on the error it recorded or, in older traces, with no
/// transition.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Attempts {
    pub kind: String,
    pub width: u64,
    pub attempts: u64,
    pub pushed: u64,
    pub blocked: u64,
    pub landed: u64,
    pub exited: u64,
    pub running: u64,
}

/// How the bon processes of one kind ended. Exited: stopped short of a final
/// transition (killed, interrupted, an error), which is not a block. `expected`
/// is the share of those that pushed or blocked (1-p)^k predicts would end
/// blocked, p being this kind's success probability per attempt (pushed ÷
/// attempts that ended) and k the attempts each process made.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Ended {
    pub kind: String,
    pub pushed: u64,
    pub blocked: u64,
    pub exited: u64,
    pub running: u64,
    pub expected: Option<f64>,
}

/// A reason attempts of one kind blocked, and how many. `inferred` of them
/// have no word in their trace (from before reasons were words): the kernel
/// derived the reason from the searches' words, or the trace's sentence names
/// it. A block nothing names counts under "unrecorded".
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Reason {
    pub kind: String,
    pub reason: String,
    pub count: u64,
    pub inferred: u64,
}

/// Where a goal came from: the goal, the commit and its subject.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct About {
    pub goal: String,
    pub from: String,
    pub subject: String,
}

/// What a push cost, and the commit it pushed. Cost is generation plus time,
/// each summed over every bon process run to reach the push.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Push {
    pub commit: Option<String>,
    pub cost: Option<f64>,
    pub generation: Option<f64>,
    pub time_cost: Option<f64>,
    pub to_selection: Option<f64>,
    pub counterexample: Option<f64>,
    /// The wall time of every search run to reach it, summed as cost is.
    pub seconds: Option<f64>,
    pub searches: Option<u64>,
    pub processes: Option<u64>,
}

/// The bon processes of one goal: one row of the traces.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct GoalTrace {
    pub kind: String,
    pub title: String,
    pub about: About,
    pub outcome: String,
    pub sentence: String,
    pub cost: f64,
    pub generation: f64,
    pub time_cost: f64,
    /// Its searches' wall time, summed.
    pub seconds: f64,
    pub push: Option<Push>,
    pub time: i64,
    pub running: bool,
    pub processes: Vec<BonProcess>,
}

/// One run of a bon command, by its pid.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct BonProcess {
    pub pid: u64,
    /// Its trace directory under .bon/traces: `<pid>`, or `<pid>.<start>` when
    /// an earlier bon process had the same pid.
    pub trace: String,
    pub running: bool,
    pub kind: String,
    pub goal: String,
    pub title: String,
    pub about: About,
    pub outcome: String,
    pub sentence: String,
    pub cost: f64,
    pub generation: f64,
    pub time_cost: f64,
    /// Its searches' wall time, summed.
    pub seconds: f64,
    pub push: Option<Push>,
    pub limit: Option<f64>,
    pub time: i64,
    /// Each line of its transitions file.
    pub transitions: Vec<String>,
    pub searches: Vec<SearchTrace>,
    /// Seconds its checks of trunk took before its first search, from their logs.
    pub check_seconds: Option<f64>,
}

/// One search of a bon process, as its trace recorded it.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SearchTrace {
    pub search: u64,
    pub kind: String,
    pub goal: String,
    pub params: Params,
    pub width: u64,
    pub started: Option<i64>,
    pub returned: u64,
    pub accepted: u64,
    pub verified: u64,
    pub selected: Option<u64>,
    pub recorded_selected: Option<u64>,
    /// How many verified candidates the trace's summary recorded.
    pub recorded_verified: Option<u64>,
    /// derived (the kernel read its words), unreadable, or none.
    pub kernel: String,
    pub blocked: Option<String>,
    pub generation: Option<f64>,
    pub time_cost: Option<f64>,
    pub cost: Option<f64>,
    pub rate: Option<f64>,
    pub seconds: Option<f64>,
    pub time: Option<i64>,
    pub running: bool,
    pub background: bool,
    /// A running search's agent processes that have not returned: waiting
    /// (on an agent_processes slot, or making its working directory), in
    /// flight (its program runs), in checks (its program returned; it is judged).
    pub waiting: u64,
    pub in_flight: u64,
    pub in_checks: u64,
    /// The host's semaphore sizes it ran under, where its trace records them.
    pub pools: Pools,
    /// How many distinct trees its candidates wrote; none where git lacks one.
    pub trees: Option<u64>,
    /// Agent processes per behavior: for each distinct `out` its verified
    /// candidates show, how many show it, in the order each first appears.
    pub behaviors: Vec<u64>,
    pub candidates: Vec<Facts>,
    /// A code or compaction search: how its attempt ended (pushed, blocked,
    /// landed, exited, running).
    pub end: Option<String>,
    /// A blocked attempt's reason, by its word; none where nothing names it.
    pub reason: Option<String>,
    /// Where the reason came from: recorded (the trace's word), kernel (derived
    /// from the searches' words) or sentence (the trace's sentence).
    pub reason_from: Option<String>,
}

/// The sizes of the host's two semaphores.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Pools {
    pub agent_processes: Option<u64>,
    pub check_processes: Option<u64>,
}

/// What a search was granted with.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Params {
    pub goal: GoalRef,
    pub base: String,
    pub n: Option<u64>,
    pub limit: Option<f64>,
    pub authority: String,
}

/// A search's goal: a trunk commit, a candidate of a search, or a transcript.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct GoalRef {
    pub trunk: Option<String>,
    pub candidate: Option<String>,
    pub transcript: Option<String>,
}

/// One agent process, from its facts.json.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Facts {
    pub index: u64,
    /// The program it ran (older traces: their `harness`).
    pub program: Option<String>,
    pub model: Option<String>,
    pub generation: Option<f64>,
    pub commit: Option<String>,
    pub accepted: bool,
    /// Verus verified it.
    pub proved: bool,
    pub verified: bool,
    pub rank: Option<i64>,
    pub diff: Option<u64>,
    pub lines_added: Option<u64>,
    pub lines_removed: Option<u64>,
    /// Its commit's tree, where git has it.
    pub tree: Option<String>,
    /// killed, over limit, price mismatch.
    pub flags: Vec<String>,
    pub logs: Vec<String>,
    /// Seconds its program ran, from its log.
    pub program_seconds: Option<f64>,
    /// Seconds of its checks, summed from their logs.
    pub check_seconds: Option<f64>,
    pub changed: Vec<String>,
    /// A hash of each agree check's output: candidates with the same agree.
    pub out: Vec<u64>,
    /// A test's verdict on each member it ran on, by index; trunk's head (or a
    /// compaction's goal) is -1. Empty for a candidate that is no test.
    pub accepts: Vec<(i64, bool)>,
    /// A test's verdict on each foil it ran on, by index in the foil search.
    pub accepts_foils: Vec<(i64, bool)>,
}

/// A queue proposal: a patch adding intents, each with the cue it came from.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Proposal {
    pub name: String,
    pub path: String,
    pub source: String,
    pub intents: Vec<ProposedIntent>,
    /// Cues only one candidate cited, shown apart from the proposal.
    pub contested: Vec<String>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct ProposedIntent {
    pub id: Option<u64>,
    pub intent: String,
    pub cue: Option<String>,
}

/// An intent taken off the queue: by the commit on trunk's history whose diff
/// removed its line, with that commit's subject and time.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Retired {
    pub id: u64,
    pub intent: String,
    pub commit: String,
    pub subject: String,
    pub time: Option<i64>,
}

/// One line of the queue.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct QueueLine {
    pub id: u64,
    pub intent: String,
}

/// The time range bon was asked for.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Filter {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub find: Option<String>,
}

/// The earliest and latest bon process on record.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Bounds {
    pub earliest: Option<i64>,
    pub latest: Option<i64>,
}

/// The spec module as written: its state fields and its items.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SpecOutline {
    pub path: String,
    pub fields: Vec<SpecField>,
    pub items: Vec<SpecItem>,
}

/// A field of the spec's state machine.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SpecField {
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub sharding: Option<String>,
    pub doc: Option<String>,
}

/// A type, predicate, transition, property or invariant of the spec, with its `///` line.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SpecItem {
    pub kind: String,
    pub name: String,
    pub doc: Option<String>,
    pub reads: Vec<String>,
    pub updates: Vec<String>,
    pub requires: Vec<String>,
}

/// The spec and how it reaches the code: items, and what each ensures, implements and calls.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SpecGraph {
    pub nodes: Vec<SpecNode>,
    /// from, to, and how: ensures, implements, calls, transition, types.
    pub edges: Vec<(String, String, String)>,
    pub trusted: Vec<TrustedFunction>,
    pub counts: Counts,
}

/// One item of the spec or of the code that reaches it.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SpecNode {
    pub id: String,
    pub layer: String,
    pub group: String,
    pub name: String,
    pub file: String,
    pub line: Option<u64>,
    pub end: Option<u64>,
    pub doc: Option<String>,
    /// Differs from trunk.
    pub changed: bool,
    pub guards: Vec<String>,
    pub adds: Vec<String>,
    pub removes: Vec<String>,
    pub uses: Vec<String>,
    pub trusted: Vec<String>,
    pub proof: bool,
    /// A gate's contract, each clause as written.
    pub requires: Vec<String>,
    pub ensures: Vec<String>,
}

/// A function in trusted code the bon process calls.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct TrustedFunction {
    pub name: String,
    pub file: String,
    pub line: u64,
    pub doc: Option<String>,
    pub changed: bool,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Counts {
    pub predicates: u64,
    pub private: u64,
    pub trusted: u64,
}

/// .bon/sbom.json, and whether it is trunk's or the working tree's.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SbomFile {
    pub source: String,
    pub document: Sbom,
}

/// A CycloneDX SBOM: its components, services and properties.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Sbom {
    pub metadata: SbomMetadata,
    pub components: Vec<Component>,
    pub services: Vec<Service>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct SbomMetadata {
    pub properties: Vec<Property>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Property {
    pub name: String,
    pub value: String,
}

/// A library, tool or host component.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Component {
    pub r#type: String,
    pub name: String,
    pub version: String,
    pub group: Option<String>,
    pub purl: Option<String>,
    pub hashes: Vec<ComponentHash>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct ComponentHash {
    pub alg: String,
    pub content: String,
}

/// A network service a program calls.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Service {
    pub name: String,
    pub endpoints: Vec<String>,
    pub group: Option<String>,
}

/// The projection for the repository at `root`.
pub fn read(root: &std::path::Path, filter: &crate::view::Filter) -> Result<Projection, String> {
    serde_json::from_value(crate::view::state(root, filter)).map_err(|e| format!("the projection does not match its types: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_projection_of_a_repository_without_bon_reads() {
        let p: Projection = serde_json::from_value(serde_json::json!({ "configured": false })).unwrap();
        assert!(!p.configured && p.processes.is_empty());
    }

    #[test]
    fn a_candidate_without_verdicts_reads_as_none() {
        let f: Facts = serde_json::from_value(serde_json::json!({ "index": 0, "accepts": [], "accepts_foils": [[1, false]] })).unwrap();
        assert!(f.accepts.is_empty() && f.accepts_foils == vec![(1, false)]);
        assert!(serde_json::from_value::<Facts>(serde_json::json!({ "index": 0 })).unwrap().accepts.is_empty());
    }
}
