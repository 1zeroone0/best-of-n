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
    /// after_its_searches (reported, before a transition). The trace holds
    /// no error for either.
    pub exits: Vec<Reason>,
}

/// Attempts of one kind at one width, by how each ended; `attempts` is their
/// sum. An attempt is a code or compaction search with the foil and
/// counterexample searches on its selection. Landed: a counterexample's test
/// landed on trunk and the bon process went on. Exited: its bon process
/// stopped during it, with no transition.
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
/// blocked, p being this kind's measured push rate per attempt that ended and
/// k the attempts each process made.
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

/// A search's goal: a trunk commit, a selected candidate, or a transcript.
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
    pub harness: Option<String>,
    pub model: Option<String>,
    pub generation: Option<f64>,
    pub commit: Option<String>,
    pub accepted: bool,
    /// Verus verified it.
    pub proved: bool,
    pub verified: bool,
    pub rank: Option<i64>,
    pub diff: Option<u64>,
    pub added: Option<u64>,
    pub removed: Option<u64>,
    /// killed, over limit, price mismatch.
    pub flags: Vec<String>,
    pub logs: Vec<String>,
    /// Seconds of its model session, from its harness log.
    pub harness_seconds: Option<f64>,
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

/// A network service a harness calls.
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
