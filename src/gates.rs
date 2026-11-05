//! The gates: the decisions the bon process makes, as a trait whose contracts
//! are written in the spec's terms. engineer owns this file, like the spec;
//! candidates write the implementation in exec.rs and cannot weaken a contract.
//!
//! Exec types carry the spec's names and view the spec type of the same name.
//! Text (commits, paths, intents) is `Vec<char>`, whose view is the spec's
//! `Seq<char>`; trusted code converts at the edge.

use vstd::prelude::*;
use crate::spec;
pub use crate::spec::{Object, Permission, User};

verus! {

// ── types ───────────────────────────────────────────────

/// A git commit, by its hash.
pub type Commit = Vec<char>;

/// A path in a commit's tree.
pub type Path = Vec<char>;

/// One line of the queue.
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
    Queue { goal: Transcript },
    Code { goal: Commit },
    Compaction { goal: Commit, out: Vec<u64> },
    Counterexample { goal: Option<AgentProcess> },
}

impl View for Kind {
    type V = spec::Kind;
    open spec fn view(&self) -> spec::Kind {
        match self {
            Kind::Queue { goal } => spec::Kind::Queue { goal: goal@ },
            Kind::Code { goal } => spec::Kind::Code { goal: goal@ },
            Kind::Compaction { goal, out } => spec::Kind::Compaction { goal: goal@, out: hashes(out@) },
            Kind::Counterexample { goal } => spec::Kind::Counterexample {
                goal: match goal { Some(p) => Some(p@), None => None } },
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
    pub out: Vec<u64>,
    /// Each new intent, by the cue it cites. A repeated cue: the first counts.
    pub intents: Vec<(Cue, Intent)>,
    /// Whether this candidate's test accepts each tested commit: the goal
    /// search's candidates by index, and trunk's head (or a compaction's goal)
    /// as -1. A repeated index: the first counts.
    pub accepts: Vec<(i64, bool)>,
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
            intents: first_by_key(self.intents@.map_values(|e: (Cue, Intent)| (e.0 as nat, e.1@))),
            accepts: first_by_key(self.accepts@.map_values(|e: (i64, bool)| (e.0 as int, e.1))),
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
            authority: spec::authority(self.kind@, paths(self.checks@), paths(self.tests@)),
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
pub open spec fn text(t: Seq<char>) -> Seq<u64> {
    seq![t.len() as u64] + t.map_values(|c: char| c as u32 as u64)
}

/// A list of texts: its length, then each text.
pub open spec fn texts(ts: Seq<Vec<char>>) -> Seq<u64> {
    seq![ts.len() as u64] + ts.map_values(|t: Vec<char>| text(t@)).flatten()
}

/// A kind: a tag (0 queue, 1 code, 2 compaction, 3 counterexample), then its
/// fields; a counterexample's goal is 0 for trunk, or 1 and the agent process.
pub open spec fn kind_words(k: Kind) -> Seq<u64> {
    match k {
        Kind::Queue { goal } => seq![0u64] + text(goal@),
        Kind::Code { goal } => seq![1u64] + text(goal@),
        Kind::Compaction { goal, out } => seq![2u64] + text(goal@) + seq![out.len() as u64] + out@,
        Kind::Counterexample { goal } => match goal {
            Some(p) => seq![3u64, 1u64, p.search as u64, p.index as u64],
            None => seq![3u64, 0u64],
        },
    }
}

pub open spec fn bit(b: bool) -> u64 { if b { 1u64 } else { 0u64 } }

/// A candidate, field by field in declaration order; a bool is 0 or 1, and
/// rank is its two's complement.
pub open spec fn candidate_words(c: Candidate) -> Seq<u64> {
    text(c.commit@) + text(c.base@) + seq![bit(c.accepted), bit(c.proved)] + texts(c.changed@)
        + seq![c.out.len() as u64] + c.out@
        + seq![c.intents.len() as u64] + c.intents@.map_values(|e: (Cue, Intent)| seq![e.0] + text(e.1@)).flatten()
        + seq![c.accepts.len() as u64]
        + c.accepts@.map_values(|e: (i64, bool)| seq![e.0 as u64, bit(e.1)]).flatten()
        + seq![bit(c.rejects_counterexamples), c.rank as u64, c.diff]
}

/// A result: 0 for none, or 1 and the candidate.
pub open spec fn result_words(r: Option<Candidate>) -> Seq<u64> {
    match r { Some(c) => seq![1u64] + candidate_words(c), None => seq![0u64] }
}

/// A search, field by field in declaration order.
pub open spec fn encoded(s: Search) -> Seq<u64> {
    kind_words(s.kind) + text(s.base@) + seq![s.n as u64] + texts(s.checks@) + texts(s.tests@) + seq![s.limit]
        + seq![s.results.len() as u64] + s.results@.map_values(|r: Option<Candidate>| result_words(r)).flatten()
}

// ── emission ────────────────────────────────────────────
//
// What programs read: a search as JSON text, in the spec's names. Hashes are
// strings, since a JSON number loses u64 precision in a browser.

/// n in decimal.
pub open spec fn decimal(n: nat) -> Seq<char>
    decreases n,
{
    let d = seq![(('0' as u32) + (n % 10) as u32) as char];
    if n < 10 { d } else { decimal(n / 10) + d }
}

/// i in decimal, with a leading - when negative.
pub open spec fn signed(i: int) -> Seq<char> {
    if i < 0 { seq!['-'] + decimal((-i) as nat) } else { decimal(i as nat) }
}

/// A hex digit.
pub open spec fn hex(d: nat) -> char {
    if d < 10 { (('0' as u32) + d as u32) as char } else { (('a' as u32) + (d - 10) as u32) as char }
}

/// One char inside a JSON string: " and \ escaped, control chars as \u00XX.
pub open spec fn escaped(c: char) -> Seq<char> {
    if c == '"' || c == '\\' { seq!['\\', c] }
    else if (c as u32) < 0x20 { seq!['\\', 'u', '0', '0', hex((c as u32 / 16) as nat), hex((c as u32 % 16) as nat)] }
    else { seq![c] }
}

/// Text as a JSON string.
pub open spec fn string(t: Seq<char>) -> Seq<char> {
    seq!['"'] + t.map_values(|c: char| escaped(c)).flatten() + seq!['"']
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

pub open spec fn boolean(b: bool) -> Seq<char> {
    if b { seq!['t', 'r', 'u', 'e'] } else { seq!['f', 'a', 'l', 's', 'e'] }
}

pub open spec fn strings(ts: Seq<Vec<char>>) -> Seq<char> {
    array(ts.map_values(|t: Vec<char>| string(t@)))
}

pub open spec fn hash_strings(hs: Seq<u64>) -> Seq<char> {
    array(hs.map_values(|h: u64| string(decimal(h as nat))))
}

/// A kind as {"<kind>":{fields}}.
pub open spec fn kind_json(k: Kind) -> Seq<char> {
    match k {
        Kind::Queue { goal } => object(seq![field("queue"@, object(seq![field("goal"@, string(goal@))]))]),
        Kind::Code { goal } => object(seq![field("code"@, object(seq![field("goal"@, string(goal@))]))]),
        Kind::Compaction { goal, out } => object(seq![field("compaction"@, object(seq![
            field("goal"@, string(goal@)), field("out"@, hash_strings(out@))]))]),
        Kind::Counterexample { goal } => object(seq![field("counterexample"@, object(seq![field("goal"@, match goal {
            Some(p) => object(seq![field("search"@, decimal(p.search as nat)), field("index"@, decimal(p.index as nat))]),
            None => seq!['n', 'u', 'l', 'l'],
        })]))]),
    }
}

/// A candidate in the spec's names.
pub open spec fn candidate_json(c: Candidate) -> Seq<char> {
    object(seq![
        field("commit"@, string(c.commit@)),
        field("base"@, string(c.base@)),
        field("accepted"@, boolean(c.accepted)),
        field("proved"@, boolean(c.proved)),
        field("changed"@, strings(c.changed@)),
        field("out"@, hash_strings(c.out@)),
        field("intents"@, array(c.intents@.map_values(|e: (Cue, Intent)| array(seq![decimal(e.0 as nat), string(e.1@)])))),
        field("accepts"@, array(c.accepts@.map_values(|e: (i64, bool)| array(seq![signed(e.0 as int), boolean(e.1)])))),
        field("rejects_counterexamples"@, boolean(c.rejects_counterexamples)),
        field("rank"@, signed(c.rank as int)),
        field("diff"@, decimal(c.diff as nat)),
    ])
}

/// A search in the spec's names; a result with no candidate is null.
pub open spec fn json(s: Search) -> Seq<char> {
    object(seq![
        field("kind"@, kind_json(s.kind)),
        field("base"@, string(s.base@)),
        field("n"@, decimal(s.n as nat)),
        field("checks"@, strings(s.checks@)),
        field("tests"@, strings(s.tests@)),
        field("limit"@, decimal(s.limit as nat)),
        field("results"@, array(s.results@.map_values(|r: Option<Candidate>| match r {
            Some(c) => candidate_json(c), None => seq!['n', 'u', 'l', 'l'] }))),
    ])
}

/// Encoding and reading back preserve what the gates decide on; emission is
/// what programs read.
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

    /// A search as JSON, in the spec's names.
    fn emit(s: &Search) -> (r: Vec<char>)
        ensures r@ == json(*s);

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
    fn verified(s: &Search, c: &Candidate) -> (r: bool)
        ensures r == spec::verified(s@, c@);

    /// The selected candidate, if the search has one.
    fn selected(s: &Search) -> (r: Option<usize>)
        requires s.results.len() == s.n,
        ensures
            r matches Some(i) ==> spec::selected(s@, i as int),
            r is None ==> forall|i: int| !spec::selected(s@, i);

    /// No verified test of x splits t.
    fn not_found(x: &Search, t: &Search) -> (r: bool)
        requires x.results.len() == x.n, t.results.len() == t.n,
        ensures r == spec::not_found(x@, t@);

    /// The test a code search carries, if x found a counterexample on trunk.
    fn found_on_trunk(x: &Search) -> (r: Option<usize>)
        requires x.results.len() == x.n,
        ensures
            r matches Some(i) ==> spec::found_on_trunk(x@, i as int),
            r is None ==> forall|i: int| !spec::found_on_trunk(x@, i);

    /// The proposal: each agreed cue with its proposed wording, once.
    fn proposed(s: &Search) -> (r: Vec<(Cue, Intent)>)
        requires s.results.len() == s.n,
        ensures
            forall|k: int| 0 <= k < r.len() ==> spec::proposed(s@, r[k].0 as nat, r[k].1@),
            forall|q: Cue, w: Seq<char>| spec::proposed(s@, q as nat, w) ==>
                exists|k: int| 0 <= k < r.len() && r[k].0 == q;

    /// The cues only one verified candidate cites, once each.
    fn contested(s: &Search) -> (r: Vec<Cue>)
        requires s.results.len() == s.n,
        ensures
            forall|k: int| 0 <= k < r.len() ==> spec::contested(s@, r[k] as nat),
            forall|q: Cue| spec::contested(s@, q as nat) ==> r@.contains(q);
}

// ── commands ────────────────────────────────────────────

/// The tokens a bon process holds: one per field of the state machine, all of
/// one instance. (Verus: tokenized state machine)
pub struct Tokens {
    pub instance: spec::bon::Instance,
    pub checks: spec::bon::checks,
    pub tests: spec::bon::tests,
    pub trunk: spec::bon::trunk,
    pub authors: spec::bon::authors,
    pub searches: spec::bon::searches,
    pub limit: spec::bon::limit,
    pub spent: spec::bon::spent,
    pub reserved: spec::bon::reserved,
}

impl Tokens {
    pub open spec fn wf(&self) -> bool {
        &&& self.checks.instance_id() == self.instance.id()
        &&& self.tests.instance_id() == self.instance.id()
        &&& self.trunk.instance_id() == self.instance.id()
        &&& self.authors.instance_id() == self.instance.id()
        &&& self.searches.instance_id() == self.instance.id()
        &&& self.limit.instance_id() == self.instance.id()
        &&& self.spent.instance_id() == self.instance.id()
        &&& self.reserved.instance_id() == self.instance.id()
    }

    /// Between commands: every search complete, nothing reserved.
    pub open spec fn settled(&self) -> bool {
        &&& self.wf()
        &&& self.reserved.value() == 0
        &&& forall|k: int| 0 <= k < self.searches.value().len() ==> spec::complete(#[trigger] self.searches.value()[k])
    }
}

/// What each bon command runs, on the bon process's one instance. A command
/// takes the instance's tokens and returns them, the same instance, settled,
/// with its spending added; a command that succeeds ran its searches on that
/// instance: so a bon process that runs several commands (a counterexample on
/// trunk, then the code search that carries its test) spends from its one limit. `spent` is what the bon process has spent, in
/// microdollars; it is the instance's.
#[cfg(not(target_arch = "wasm32"))]
pub trait Commands {
    /// The bon process's one instance, initialized from trunk's head and the
    /// limit bon.toml sets for a bon process. Once per bon process.
    fn start(root: &str) -> (r: Result<Tracked<Tokens>, String>)
        ensures
            r matches Ok(t) ==> t@.settled() && t@.spent.value() == 0 && t@.searches.value().len() == 0;

    /// bon code (compaction false) or bon compaction (true).
    fn to_push(root: &str, compaction: bool, carried: crate::trusted::Carried, spent: &mut u64, Tracked(t): Tracked<&mut Tokens>) -> (r: Result<(), String>)
        requires
            old(t).settled(),
            *old(spent) as nat == old(t).spent.value(),
        ensures
            final(t).settled(),
            final(t).instance == old(t).instance,
            final(t).limit.value() == old(t).limit.value(),
            *final(spent) as nat == final(t).spent.value(),
            // Ok is a push: its searches ran on this instance, and it pushed by its transition.
            r is Ok ==> final(t).searches.value().len() > old(t).searches.value().len()
                && final(t).trunk.value().len() == old(t).trunk.value().len() + 1;

    /// bon counterexample: a counterexample search on trunk; the tests a code
    /// search must carry, if it found one.
    fn counterexample(root: &str, spent: &mut u64, Tracked(t): Tracked<&mut Tokens>) -> (r: Result<Option<crate::trusted::Carried>, String>)
        requires
            old(t).settled(),
            *old(spent) as nat == old(t).spent.value(),
        ensures
            final(t).settled(),
            final(t).instance == old(t).instance,
            final(t).limit.value() == old(t).limit.value(),
            *final(spent) as nat == final(t).spent.value(),
            // Its search ran on this instance.
            r is Ok ==> final(t).searches.value().len() > old(t).searches.value().len();

    /// bon queue: a queue search on one transcript; the agreed intents and the
    /// contested cues.
    fn queue(root: &str, transcript: Transcript, spent: &mut u64, Tracked(t): Tracked<&mut Tokens>) -> (r: Result<(Vec<(Cue, Intent)>, Vec<Cue>), String>)
        requires
            old(t).settled(),
            *old(spent) as nat == old(t).spent.value(),
        ensures
            final(t).settled(),
            final(t).instance == old(t).instance,
            final(t).limit.value() == old(t).limit.value(),
            *final(spent) as nat == final(t).spent.value(),
            // Its search ran on this instance.
            r is Ok ==> final(t).searches.value().len() > old(t).searches.value().len();
}

} // verus!

/// The kernel implements every gate and the encoding; a build without either fails.
#[allow(dead_code)]
fn kernel<K: Gates + Encoding>() {}
#[allow(dead_code)]
fn kernel_is_complete() { kernel::<crate::exec::Kernel>(); }

/// The bon process implements every command; a build without one fails.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn bon_process<C: Commands>() {}
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn bon_process_is_complete() { bon_process::<crate::process::BonProcess>(); }
