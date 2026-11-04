//! The gates: the decisions the bon process makes, as a trait whose contracts
//! are written in the spec's terms. engineer owns this file, like the spec;
//! candidates write the implementation in exec.rs and cannot weaken a contract.
//!
//! Exec types carry the spec's names and view the spec type of the same name.
//! Text (commits, paths, intents) is `Vec<char>`, whose view is the spec's
//! `Seq<char>`; trusted code converts at the edge.

use vstd::prelude::*;
use crate::spec;
pub use crate::spec::{File, Permission, User};

verus! {

// ── types ───────────────────────────────────────────────

/// A git commit, by its hash.
pub type Commit = Vec<char>;

/// A path in a commit's tree.
pub type Path = Vec<char>;

/// One line of the map.
pub type Intent = Vec<char>;

/// A WebVTT file.
pub type Transcript = Path;

/// A WebVTT cue, by its start time in milliseconds.
pub type Cue = u64;

/// A process running as agent that writes one candidate.
pub struct AgentProcess { pub search: usize, pub index: usize }

impl View for AgentProcess {
    type V = spec::AgentProcess;
    open spec fn view(&self) -> spec::AgentProcess {
        spec::AgentProcess { search: self.search as int, index: self.index as int }
    }
}

/// What a search is for: its kind, carrying its goal.
#[allow(inconsistent_fields)]
pub enum Kind {
    Code { goal: Intent },
    Map { goal: Transcript },
    Counterexample { goal: AgentProcess },
    Compaction { goal: Commit, out: Vec<u64> },
    Scrub { goal: Intent, path: Path },
}

impl View for Kind {
    type V = spec::Kind;
    open spec fn view(&self) -> spec::Kind {
        match self {
            Kind::Code { goal } => spec::Kind::Code { goal: goal@ },
            Kind::Map { goal } => spec::Kind::Map { goal: goal@ },
            Kind::Counterexample { goal } => spec::Kind::Counterexample { goal: goal@ },
            Kind::Compaction { goal, out } => spec::Kind::Compaction { goal: goal@, out: hashes(out@) },
            Kind::Scrub { goal, path } => spec::Kind::Scrub { goal: goal@, path: path@ },
        }
    }
}

/// One generated change, as trusted code observed it.
pub struct Candidate {
    pub commit: Commit,
    pub base: Commit,
    pub checks_pass: bool,
    pub changed: Vec<Path>,
    pub out: Vec<u64>,
    /// Each new intent, by the cue it cites. A repeated cue: the first counts.
    pub intents: Vec<(Cue, Intent)>,
    /// Whether this candidate's test passes on each candidate of the goal's
    /// search, by index (-1 is a compaction search's goal). A repeated index:
    /// the first counts.
    pub test_passes: Vec<(i64, bool)>,
    pub rank: i64,
    pub diff: u64,
}

impl View for Candidate {
    type V = spec::Candidate;
    open spec fn view(&self) -> spec::Candidate {
        spec::Candidate {
            commit: self.commit@,
            base: self.base@,
            checks_pass: self.checks_pass,
            changed: paths(self.changed@),
            out: hashes(self.out@),
            intents: first_by_key(self.intents@.map_values(|e: (Cue, Intent)| (e.0 as nat, e.1@))),
            test_passes: first_by_key(self.test_passes@.map_values(|e: (i64, bool)| (e.0 as int, e.1))),
            rank: self.rank as int,
            diff: self.diff as nat,
        }
    }
}

/// One search, once every agent process has returned: `results[i]` is what
/// agent process i returned.
pub struct Search {
    pub kind: Kind,
    pub base: Commit,
    pub n: usize,
    /// The check paths the manifest declares; the authority derives from them.
    pub checks: Vec<Path>,
    pub limit: u64,
    pub results: Vec<Option<Candidate>>,
}

impl View for Search {
    type V = spec::Search;
    open spec fn view(&self) -> spec::Search {
        spec::Search {
            kind: self.kind@,
            base: self.base@,
            n: self.n as nat,
            authority: spec::authority(self.kind@, paths(self.checks@)),
            limit: self.limit as nat,
            results: Map::new(
                Set::range(0int, self.results.len() as int),
                |i: int| match self.results@[i] { Some(c) => Some(c@), None => None },
            ),
        }
    }
}

// ── conversions ─────────────────────────────────────────

pub open spec fn paths(s: Seq<Path>) -> Set<spec::Path> {
    s.map_values(|p: Path| p@).to_set()
}

pub open spec fn hashes(s: Seq<u64>) -> Seq<nat> {
    s.map_values(|h: u64| h as nat)
}

/// The index of the first pair in s with key k.
pub open spec fn first<K, V>(s: Seq<(K, V)>, k: K) -> int {
    choose|i: int| 0 <= i < s.len() && s[i].0 == k && forall|j: int| 0 <= j < i ==> s[j].0 != k
}

/// The map from each key in s to the value of its first pair.
pub open spec fn first_by_key<K, V>(s: Seq<(K, V)>) -> Map<K, V> {
    Map::new(s.map_values(|e: (K, V)| e.0).to_set(), |k: K| s[first(s, k)].1)
}

/// agent's permissions on each file, as trusted code observed them.
pub open spec fn observed(checks: Permission, transcripts: Permission, working_directory: Permission, repository: Permission) -> Map<File, Permission> {
    map![
        File::Checks => checks,
        File::Transcripts => transcripts,
        File::WorkingDirectory => working_directory,
        File::Repository => repository,
    ]
}

// ── encoding ────────────────────────────────────────────
//
// How the kernel writes a search to a trace and reads it back, compiled into
// the bon process and into the gates in WebAssembly alike: words (u64), each
// list led by its length. (intents 27, 28)

/// A char as a word. Reading one back uses char::from_u32. (TCB: Rust std)
pub assume_specification[ core::char::from_u32 ](i: u32) -> (r: Option<char>)
    ensures
        r matches Some(c) ==> c as u32 == i,
        i < 0xD800 || (0xE000 <= i && i <= 0x10FFFF) ==> r is Some;

/// Text: its length, then each char.
pub open spec fn text(t: Seq<char>) -> Seq<u64> {
    seq![t.len() as u64] + t.map_values(|c: char| c as u32 as u64)
}

/// A list of texts: its length, then each text.
pub open spec fn texts(ts: Seq<Vec<char>>) -> Seq<u64> {
    seq![ts.len() as u64] + ts.map_values(|t: Vec<char>| text(t@)).flatten()
}

/// A kind: a tag (0 code, 1 map, 2 counterexample, 3 compaction, 4 scrub), then its fields.
pub open spec fn kind_words(k: Kind) -> Seq<u64> {
    match k {
        Kind::Code { goal } => seq![0u64] + text(goal@),
        Kind::Map { goal } => seq![1u64] + text(goal@),
        Kind::Counterexample { goal } => seq![2u64, goal.search as u64, goal.index as u64],
        Kind::Compaction { goal, out } => seq![3u64] + text(goal@) + seq![out.len() as u64] + out@,
        Kind::Scrub { goal, path } => seq![4u64] + text(goal@) + text(path@),
    }
}

/// A candidate, field by field in declaration order; a bool is 0 or 1, and
/// rank is its two's complement.
pub open spec fn candidate_words(c: Candidate) -> Seq<u64> {
    text(c.commit@) + text(c.base@) + seq![if c.checks_pass { 1u64 } else { 0u64 }] + texts(c.changed@)
        + seq![c.out.len() as u64] + c.out@
        + seq![c.intents.len() as u64] + c.intents@.map_values(|e: (Cue, Intent)| seq![e.0] + text(e.1@)).flatten()
        + seq![c.test_passes.len() as u64]
        + c.test_passes@.map_values(|e: (i64, bool)| seq![e.0 as u64, if e.1 { 1u64 } else { 0u64 }]).flatten()
        + seq![c.rank as u64, c.diff]
}

/// A result: 0 for none, or 1 and the candidate.
pub open spec fn result_words(r: Option<Candidate>) -> Seq<u64> {
    match r { Some(c) => seq![1u64] + candidate_words(c), None => seq![0u64] }
}

/// A search, field by field in declaration order.
pub open spec fn encoded(s: Search) -> Seq<u64> {
    kind_words(s.kind) + text(s.base@) + seq![s.n as u64] + texts(s.checks@) + seq![s.limit]
        + seq![s.results.len() as u64] + s.results@.map_values(|r: Option<Candidate>| result_words(r)).flatten()
}

/// Encoding and reading back preserve what the gates decide on. (intent 28)
pub trait Encoding {
    /// A search as words.
    fn encode(s: &Search) -> (r: Vec<u64>)
        ensures r@ == encoded(*s);

    /// Words back to a search: exactly the one they encode, with a result for
    /// each agent process; None for anything else.
    fn decode(w: &Vec<u64>) -> (r: Option<Search>)
        ensures
            r matches Some(s) ==> encoded(s) == w@ && s.results.len() == s.n,
            (exists|s: Search| #[trigger] encoded(s) == w@ && s.results.len() == s.n) ==> r is Some;

    /// Two searches with the same words are the same search to the spec.
    proof fn injective(a: Search, b: Search)
        requires encoded(a) == encoded(b),
        ensures a@ == b@;
}

// ── gates ───────────────────────────────────────────────

/// Each gate is named for the spec predicate it decides, and its contract is
/// that predicate.
pub trait Gates {
    /// agent's permissions match the policy. (intent 9)
    fn isolated(checks: Permission, transcripts: Permission, working_directory: Permission, repository: Permission) -> (r: bool)
        ensures r == spec::isolated(observed(checks, transcripts, working_directory, repository));

    /// Every check passed, and every changed path is within the authority. (intent 3)
    fn verified(s: &Search, c: &Candidate) -> (r: bool)
        ensures r == spec::verified(s@, c@);

    /// The selected candidate, if the search has one. (intents 4, 5, 17)
    fn selected(s: &Search) -> (r: Option<usize>)
        requires s.results.len() == s.n,
        ensures
            r matches Some(i) ==> spec::selected(s@, i as int),
            r is None ==> forall|i: int| !spec::selected(s@, i);

    /// No verified test of x splits t. (intent 13)
    fn cleared(x: &Search, t: &Search) -> (r: bool)
        requires x.results.len() == x.n, t.results.len() == t.n,
        ensures r == spec::cleared(x@, t@);

    /// The proposal: each agreed cue with its proposed wording, once. (intent 10)
    fn proposed(s: &Search) -> (r: Vec<(Cue, Intent)>)
        requires s.results.len() == s.n,
        ensures
            forall|k: int| 0 <= k < r.len() ==> spec::proposed(s@, r[k].0 as nat, r[k].1@),
            forall|q: Cue, w: Seq<char>| spec::proposed(s@, q as nat, w) ==>
                exists|k: int| 0 <= k < r.len() && r[k].0 == q;

    /// The cues only one verified candidate cites, once each. (intent 10)
    fn contested(s: &Search) -> (r: Vec<Cue>)
        requires s.results.len() == s.n,
        ensures
            forall|k: int| 0 <= k < r.len() ==> spec::contested(s@, r[k] as nat),
            forall|q: Cue| spec::contested(s@, q as nat) ==> r@.contains(q);
}

} // verus!
