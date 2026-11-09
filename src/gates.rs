//! The gates: the decisions the bon process makes, as a trait whose contracts
//! are written in the spec's terms. engineer owns this file, like the spec;
//! candidates write the implementation in exec.rs and cannot weaken a contract.
//!
//! Exec types carry the spec's names and view the spec type of the same name.
//! Text has a type per meaning (Commit, Path, Intent, Transcript), each a
//! `Vec<char>` whose view is the spec's type of the same name; trusted code
//! converts at the edge.

use vstd::prelude::*;
use crate::spec;
pub use crate::spec::{Object, Permission, User};

verus! {

// ── types ───────────────────────────────────────────────

/// A git commit, by its hash. Its own type: a commit is never a path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commit(pub Vec<char>);

/// A path in a commit's tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Path(pub Vec<char>);

/// One line of the queue.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Intent(pub Vec<char>);

/// A WebVTT file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transcript(pub Path);

impl View for Commit { type V = spec::Commit; open spec fn view(&self) -> spec::Commit { spec::Commit(self.0@) } }
impl View for Path { type V = spec::Path; open spec fn view(&self) -> spec::Path { spec::Path(self.0@) } }
impl View for Intent { type V = spec::Intent; open spec fn view(&self) -> spec::Intent { spec::Intent(self.0@) } }
impl View for Transcript { type V = spec::Transcript; open spec fn view(&self) -> spec::Transcript { spec::Transcript(self.0@) } }

/// A WebVTT cue, by its start time in milliseconds.
pub type Cue = u64;

/// A hash of an agree check's output: an identity, not a quantity, so it is
/// its own type. Programs read it as a decimal string.
#[derive(Clone, Copy, PartialEq, Eq, Structural)]
pub struct Hash(pub u64);

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
    Queue { goal: Transcript },
    Code { goal: Commit },
    Compaction { goal: Commit, out: Vec<Hash> },
    Counterexample { goal: Option<AgentProcess> },
    Foil { goal: AgentProcess },
}

impl View for Kind {
    type V = spec::Kind;
    open spec fn view(&self) -> spec::Kind {
        match self {
            Kind::Queue { goal } => spec::Kind::Queue { goal: goal@ },
            Kind::Code { goal } => spec::Kind::Code { goal: goal@ },
            Kind::Compaction { goal, out } => spec::Kind::Compaction { goal: goal@, out: hashes(out@) },
            Kind::Counterexample { goal } => spec::Kind::Counterexample {
                goal: match goal { Some(agent_process) => Some(agent_process@), None => None } },
            Kind::Foil { goal } => spec::Kind::Foil { goal: goal@ },
        }
    }
}

/// One generated change, as trusted code observed it.
pub struct Candidate {
    pub commit: Commit,
    pub base: Commit,
    pub accepted: bool,
    pub proved: bool,
    pub changed: Vec<Path>,
    pub out: Vec<Hash>,
    /// Each new intent, by the cue it cites. A repeated cue: the first counts.
    pub intents: Vec<(Cue, Intent)>,
    /// Whether this candidate's test accepts each tested commit: the goal
    /// search's candidates by index, and trunk's head (or a compaction's goal)
    /// as -1. A repeated index: the first counts.
    pub accepts: Vec<(i64, bool)>,
    /// Whether this candidate's test accepts each foil, by its index in the
    /// foil search. A repeated index: the first counts.
    pub accepts_foils: Vec<(i64, bool)>,
    pub rejects_counterexamples: bool,
    pub rank: i64,
    pub diff: u64,
}

impl View for Candidate {
    type V = spec::Candidate;
    open spec fn view(&self) -> spec::Candidate {
        spec::Candidate {
            commit: self.commit@,
            base: self.base@,
            accepted: self.accepted,
            proved: self.proved,
            changed: paths(self.changed@),
            out: hashes(self.out@),
            intents: first_by_key(self.intents@.map_values(|pair: (Cue, Intent)| (pair.0 as nat, pair.1@))),
            accepts: first_by_key(self.accepts@.map_values(|pair: (i64, bool)| (pair.0 as int, pair.1))),
            accepts_foils: first_by_key(self.accepts_foils@.map_values(|pair: (i64, bool)| (pair.0 as int, pair.1))),
            rejects_counterexamples: self.rejects_counterexamples,
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
    /// The paths holding the counterexamples' tests.
    pub tests: Vec<Path>,
    /// The trusted code the manifest's SBOM declares; no search may change it.
    pub trusted: Vec<Path>,
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
            authority: spec::authority(self.kind@, paths(self.checks@), paths(self.tests@), paths(self.trusted@)),
            limit: self.limit as nat,
            results: Map::new(
                Set::range(0int, self.results.len() as int),
                |i: int| match self.results@[i] { Some(candidate) => Some(candidate@), None => None },
            ),
        }
    }
}

// ── conversions ─────────────────────────────────────────

/// Exec paths as the spec's set of paths.
pub open spec fn paths(list: Seq<Path>) -> Set<spec::Path> {
    list.map_values(|path: Path| path@).to_set()
}

/// Exec hashes as the spec's naturals, in order.
pub open spec fn hashes(list: Seq<Hash>) -> Seq<nat> {
    list.map_values(|hash: Hash| hash.0 as nat)
}

/// The index of the first pair in pairs with key.
pub open spec fn first<K, V>(pairs: Seq<(K, V)>, key: K) -> int {
    choose|index: int| 0 <= index < pairs.len() && pairs[index].0 == key
        && forall|earlier: int| 0 <= earlier < index ==> pairs[earlier].0 != key
}

/// The map from each key in pairs to the value of its first pair.
pub open spec fn first_by_key<K, V>(pairs: Seq<(K, V)>) -> Map<K, V> {
    Map::new(pairs.map_values(|pair: (K, V)| pair.0).to_set(), |key: K| pairs[first(pairs, key)].1)
}

/// agent's permissions on each file, as trusted code observed them.
pub open spec fn observed(checks: Permission, transcripts: Permission, working_directory: Permission, repository: Permission, working_directories: Permission) -> Map<Object, Permission> {
    map![
        Object::Checks => checks,
        Object::Transcripts => transcripts,
        Object::WorkingDirectory => working_directory,
        Object::Repository => repository,
        Object::WorkingDirectories => working_directories,
    ]
}

// ── encoding ────────────────────────────────────────────
//
// How the kernel writes a search to a trace and reads it back, compiled into
// the bon process and into the gates in WebAssembly alike: words (u64), each
// list led by its length.

/// A char as a word. Reading one back uses char::from_u32. (TCB: Rust std)
pub assume_specification[ core::char::from_u32 ](i: u32) -> (r: Option<char>)
    ensures
        r matches Some(c) ==> c as u32 == i,
        i < 0xD800 || (0xE000 <= i && i <= 0x10FFFF) ==> r is Some;

/// Text: its length, then each char.
pub open spec fn text(chars: Seq<char>) -> Seq<u64> {
    seq![chars.len() as u64] + chars.map_values(|character: char| character as u32 as u64)
}

/// A list of texts: its length, then each text.
pub open spec fn texts(list: Seq<Path>) -> Seq<u64> {
    seq![list.len() as u64] + list.map_values(|path: Path| text(path.0@)).flatten()
}

/// A kind: a tag (0 queue, 1 code, 2 compaction, 3 counterexample, 4 foil),
/// then its fields; a counterexample's goal is 0 for trunk, or 1 and the agent
/// process; a foil's goal is the agent process.
pub open spec fn kind_words(kind: Kind) -> Seq<u64> {
    match kind {
        Kind::Queue { goal } => seq![0u64] + text(goal.0.0@),
        Kind::Code { goal } => seq![1u64] + text(goal.0@),
        Kind::Compaction { goal, out } => seq![2u64] + text(goal.0@) + seq![out.len() as u64] + out@.map_values(|hash: Hash| hash.0),
        Kind::Counterexample { goal } => match goal {
            Some(agent_process) => seq![3u64, 1u64, agent_process.search as u64, agent_process.index as u64],
            None => seq![3u64, 0u64],
        },
        Kind::Foil { goal } => seq![4u64, goal.search as u64, goal.index as u64],
    }
}

/// A bool as a word: 1 for true, 0 for false.
pub open spec fn bit(value: bool) -> u64 { if value { 1u64 } else { 0u64 } }

/// A candidate, field by field in declaration order; a bool is 0 or 1, and
/// rank is its two's complement.
pub open spec fn candidate_words(candidate: Candidate) -> Seq<u64> {
    text(candidate.commit.0@) + text(candidate.base.0@) + seq![bit(candidate.accepted), bit(candidate.proved)] + texts(candidate.changed@)
        + seq![candidate.out.len() as u64] + candidate.out@.map_values(|hash: Hash| hash.0)
        + seq![candidate.intents.len() as u64] + candidate.intents@.map_values(|pair: (Cue, Intent)| seq![pair.0] + text(pair.1.0@)).flatten()
        + seq![candidate.accepts.len() as u64]
        + candidate.accepts@.map_values(|pair: (i64, bool)| seq![pair.0 as u64, bit(pair.1)]).flatten()
        + seq![candidate.accepts_foils.len() as u64]
        + candidate.accepts_foils@.map_values(|pair: (i64, bool)| seq![pair.0 as u64, bit(pair.1)]).flatten()
        + seq![bit(candidate.rejects_counterexamples), candidate.rank as u64, candidate.diff]
}

/// A result: 0 for none, or 1 and the candidate.
pub open spec fn result_words(result: Option<Candidate>) -> Seq<u64> {
    match result { Some(candidate) => seq![1u64] + candidate_words(candidate), None => seq![0u64] }
}

/// A search, field by field in declaration order.
pub open spec fn encoded(search: Search) -> Seq<u64> {
    kind_words(search.kind) + text(search.base.0@) + seq![search.n as u64] + texts(search.checks@) + texts(search.tests@) + texts(search.trusted@) + seq![search.limit]
        + seq![search.results.len() as u64] + search.results@.map_values(|result: Option<Candidate>| result_words(result)).flatten()
}

// ── emission ────────────────────────────────────────────
//
// What programs read: a search as JSON text, in the spec's names. Hashes are
// strings, since a JSON number loses u64 precision in a browser.

/// number in decimal.
pub open spec fn decimal(number: nat) -> Seq<char>
    decreases number,
{
    let last = seq![(('0' as u32) + (number % 10) as u32) as char];
    if number < 10 { last } else { decimal(number / 10) + last }
}

/// number in decimal, with a leading - when negative.
pub open spec fn signed(number: int) -> Seq<char> {
    if number < 0 { seq!['-'] + decimal((-number) as nat) } else { decimal(number as nat) }
}

/// A hex digit.
pub open spec fn hex(digit: nat) -> char {
    if digit < 10 { (('0' as u32) + digit as u32) as char } else { (('a' as u32) + (digit - 10) as u32) as char }
}

/// One char inside a JSON string: " and \ escaped, control chars as \u00XX.
pub open spec fn escaped(character: char) -> Seq<char> {
    if character == '"' || character == '\\' { seq!['\\', character] }
    else if (character as u32) < 0x20 { seq!['\\', 'u', '0', '0', hex((character as u32 / 16) as nat), hex((character as u32 % 16) as nat)] }
    else { seq![character] }
}

/// Text as a JSON string.
pub open spec fn string(chars: Seq<char>) -> Seq<char> {
    seq!['"'] + chars.map_values(|character: char| escaped(character)).flatten() + seq!['"']
}

/// Items joined with commas, in brackets.
pub open spec fn array(items: Seq<Seq<char>>) -> Seq<char>
    decreases items.len(),
{
    seq!['['] + joined(items) + seq![']']
}

/// Items joined with commas.
pub open spec fn joined(items: Seq<Seq<char>>) -> Seq<char>
    decreases items.len(),
{
    if items.len() == 0 { seq![] }
    else if items.len() == 1 { items[0] }
    else { joined(items.drop_last()) + seq![','] + items.last() }
}

/// "name":value
pub open spec fn field(name: Seq<char>, value: Seq<char>) -> Seq<char> {
    string(name) + seq![':'] + value
}

/// Fields in braces.
pub open spec fn object(fields: Seq<Seq<char>>) -> Seq<char> {
    seq!['{'] + joined(fields) + seq!['}']
}

/// A bool as JSON: true or false.
pub open spec fn boolean(value: bool) -> Seq<char> {
    if value { seq!['t', 'r', 'u', 'e'] } else { seq!['f', 'a', 'l', 's', 'e'] }
}

/// Texts as a JSON array of strings.
pub open spec fn strings(list: Seq<Path>) -> Seq<char> {
    array(list.map_values(|path: Path| string(path.0@)))
}

/// Hashes as a JSON array of decimal strings.
pub open spec fn hash_strings(list: Seq<Hash>) -> Seq<char> {
    array(list.map_values(|hash: Hash| string(decimal(hash.0 as nat))))
}

/// A kind as {"<kind>":{fields}}.
pub open spec fn kind_json(kind: Kind) -> Seq<char> {
    match kind {
        Kind::Queue { goal } => object(seq![field("queue"@, object(seq![field("goal"@, string(goal.0.0@))]))]),
        Kind::Code { goal } => object(seq![field("code"@, object(seq![field("goal"@, string(goal.0@))]))]),
        Kind::Compaction { goal, out } => object(seq![field("compaction"@, object(seq![
            field("goal"@, string(goal.0@)), field("out"@, hash_strings(out@))]))]),
        Kind::Counterexample { goal } => object(seq![field("counterexample"@, object(seq![field("goal"@, match goal {
            Some(agent_process) => object(seq![field("search"@, decimal(agent_process.search as nat)), field("index"@, decimal(agent_process.index as nat))]),
            None => seq!['n', 'u', 'l', 'l'],
        })]))]),
        Kind::Foil { goal } => object(seq![field("foil"@, object(seq![field("goal"@,
            object(seq![field("search"@, decimal(goal.search as nat)), field("index"@, decimal(goal.index as nat))]))]))]),
    }
}

/// A candidate in the spec's names.
pub open spec fn candidate_json(candidate: Candidate) -> Seq<char> {
    object(seq![
        field("commit"@, string(candidate.commit.0@)),
        field("base"@, string(candidate.base.0@)),
        field("accepted"@, boolean(candidate.accepted)),
        field("proved"@, boolean(candidate.proved)),
        field("changed"@, strings(candidate.changed@)),
        field("out"@, hash_strings(candidate.out@)),
        field("intents"@, array(candidate.intents@.map_values(|pair: (Cue, Intent)| array(seq![decimal(pair.0 as nat), string(pair.1.0@)])))),
        field("accepts"@, array(candidate.accepts@.map_values(|pair: (i64, bool)| array(seq![signed(pair.0 as int), boolean(pair.1)])))),
        field("accepts_foils"@, array(candidate.accepts_foils@.map_values(|pair: (i64, bool)| array(seq![signed(pair.0 as int), boolean(pair.1)])))),
        field("rejects_counterexamples"@, boolean(candidate.rejects_counterexamples)),
        field("rank"@, signed(candidate.rank as int)),
        field("diff"@, decimal(candidate.diff as nat)),
    ])
}

/// A search in the spec's names; a result with no candidate is null.
pub open spec fn json(search: Search) -> Seq<char> {
    object(seq![
        field("kind"@, kind_json(search.kind)),
        field("base"@, string(search.base.0@)),
        field("n"@, decimal(search.n as nat)),
        field("checks"@, strings(search.checks@)),
        field("tests"@, strings(search.tests@)),
        field("trusted"@, strings(search.trusted@)),
        field("limit"@, decimal(search.limit as nat)),
        field("results"@, array(search.results@.map_values(|result: Option<Candidate>| match result {
            Some(candidate) => candidate_json(candidate), None => seq!['n', 'u', 'l', 'l'] }))),
    ])
}

/// Encoding and reading back preserve what the gates decide on; emission is
/// what programs read.
pub trait Encoding {
    /// A search as words.
    fn encode(search: &Search) -> (r: Vec<u64>)
        ensures r@ == encoded(*search);

    /// Words back to a search: exactly the one they encode, with a result for
    /// each agent process; None for anything else.
    fn decode(words: &Vec<u64>) -> (r: Option<Search>)
        ensures
            r matches Some(search) ==> encoded(search) == words@ && search.results.len() == search.n,
            (exists|search: Search| #[trigger] encoded(search) == words@ && search.results.len() == search.n) ==> r is Some;

    /// A search as JSON, in the spec's names.
    fn emit(search: &Search) -> (r: Vec<char>)
        ensures r@ == json(*search);

    /// Two searches with the same words are the same search to the spec.
    proof fn injective(a: Search, b: Search)
        requires encoded(a) == encoded(b),
        ensures a@ == b@;
}

// ── gates ───────────────────────────────────────────────

/// Each gate is named for the spec predicate it decides, and its contract is
/// that predicate.
pub trait Gates {
    /// agent's permissions match the policy.
    fn isolated(checks: Permission, transcripts: Permission, working_directory: Permission, repository: Permission, working_directories: Permission) -> (r: bool)
        ensures r == spec::isolated(observed(checks, transcripts, working_directory, repository, working_directories));

    /// Accepted, proved, every changed path within the authority, and for a
    /// compaction, every counterexample still rejected.
    fn verified(search: &Search, candidate: &Candidate) -> (r: bool)
        ensures r == spec::verified(search@, candidate@);

    /// The selected candidate, if the search has one.
    fn selected(search: &Search) -> (r: Option<usize>)
        requires search.results.len() == search.n,
        ensures
            r matches Some(i) ==> spec::selected(search@, i as int),
            r is None ==> forall|i: int| !spec::selected(search@, i);

    /// Two verified tests of counterexample reject a foil, and none splits
    /// tested or rejects every member of it.
    fn not_found(counterexample: &Search, tested: &Search, foils: &Search) -> (r: bool)
        requires counterexample.results.len() == counterexample.n, tested.results.len() == tested.n, foils.results.len() == foils.n,
        ensures r == spec::not_found(counterexample@, tested@, foils@);

    /// The test that lands on trunk, if counterexample found one on trunk.
    fn found_on_trunk(counterexample: &Search) -> (r: Option<usize>)
        requires counterexample.results.len() == counterexample.n,
        ensures
            r matches Some(i) ==> spec::found_on_trunk(counterexample@, i as int),
            r is None ==> forall|i: int| !spec::found_on_trunk(counterexample@, i);

    /// The test that lands on trunk, if counterexample's tests split tested.
    fn lands_on(counterexample: &Search, tested: &Search) -> (r: Option<usize>)
        requires counterexample.results.len() == counterexample.n, tested.results.len() == tested.n,
        ensures
            r matches Some(i) ==> spec::lands_on(counterexample@, tested@, i as int),
            r is None ==> forall|i: int| !spec::lands_on(counterexample@, tested@, i);

    /// The proposal: each agreed cue with its proposed wording, once, in cue order.
    fn proposed(search: &Search) -> (r: Vec<(Cue, Intent)>)
        requires search.results.len() == search.n,
        ensures
            forall|entry: int| 0 <= entry < r.len() ==> spec::proposed(search@, r[entry].0 as nat, r[entry].1@),
            forall|cue: Cue, intent: spec::Intent| spec::proposed(search@, cue as nat, intent) ==>
                exists|entry: int| 0 <= entry < r.len() && r[entry].0 == cue,
            forall|earlier: int, later: int| 0 <= earlier < later < r.len() ==> r[earlier].0 < r[later].0;

    /// The cues only one verified candidate cites, once each, in cue order.
    fn contested(search: &Search) -> (r: Vec<Cue>)
        requires search.results.len() == search.n,
        ensures
            forall|entry: int| 0 <= entry < r.len() ==> spec::contested(search@, r[entry] as nat),
            forall|cue: Cue| spec::contested(search@, cue as nat) ==> r@.contains(cue),
            forall|earlier: int, later: int| 0 <= earlier < later < r.len() ==> r[earlier] < r[later];
}

} // verus!

/// The kernel implements every gate and the encoding; a build without either fails.
#[allow(dead_code)]
fn kernel<K: Gates + Encoding>() {}
#[allow(dead_code)]
fn kernel_is_complete() { kernel::<crate::exec::Kernel>(); }
