//! bon's spec: types, predicates, then the state machine (state, init,
//! transitions, properties, invariants, proofs). Every term is from OSTEP,
//! object capabilities, Verus or Rust, or a TCB component's own terms (git,
//! WebVTT); bon's own nouns are intent, queue, transcript, candidate, check,
//! test, search, counterexample, proposal and generation.
//!
//! A candidate is rejected or accepted by the tests; an accepted candidate is
//! verified when Verus verifies it within its authority; a verified candidate
//! may be selected; a selected one may be pushed to trunk.

use vstd::prelude::*;
use verus_state_machines_macros::tokenized_state_machine;

verus! {

// ── types ───────────────────────────────────────────────

/// A git commit, by its hash. (TCB: git)
pub struct Commit(pub Seq<char>);

/// A path in a commit's tree, as git reports it. (TCB: git)
pub struct Path(pub Seq<char>);

/// One line of the queue: what is wanted and not yet in the spec.
pub struct Intent(pub Seq<char>);

/// A WebVTT file, one per recorded call. (TCB: WebVTT)
pub struct Transcript(pub Path);

/// A WebVTT cue, by its start time in milliseconds. (TCB: WebVTT)
pub type Cue = nat;

/// A POSIX user. Names match the users on this machine. Also a commit's git author.
#[allow(non_camel_case_types)]
pub enum User { engineer, agent }

/// The objects the policy gives agent rights over: files and directories
/// (OSTEP), each designated by its path.
pub enum Object {
    /// Verus (the spec and proofs) and the tests. Owner: engineer.
    Checks,
    /// The transcripts. Owner: engineer.
    Transcripts,
    /// One per agent process. Owner: agent.
    WorkingDirectory,
    /// The git repository: history and refs. Owner: engineer.
    Repository,
    /// The directory holding every working directory. agent may search it (pass
    /// through to the path it was given) but not list it or add to it, so an
    /// agent process reaches only its own working directory. Owner: engineer.
    WorkingDirectories,
}

/// POSIX permission bits.
pub struct Permission { pub read: bool, pub write: bool, pub execute: bool }

/// A process running as agent that writes one candidate: index `index` of the
/// n in search `search`. (OSTEP: process)
pub struct AgentProcess { pub search: int, pub index: int }

/// What a search is for: its kind, carrying its goal. Each kind's goal has its own type.
#[allow(inconsistent_fields)]
pub enum Kind {
    /// The goal is a transcript: candidates write queue lines. Ends in a
    /// proposal to engineer.
    Queue { goal: Transcript },
    /// The goal is trunk's head: candidates write code until trunk's checks
    /// accept it. Ends in push.
    Code { goal: Commit },
    /// The goal is trunk's head: candidates remove stale code and tests, or
    /// write them cleaner, without changing behavior. `out` is the goal's
    /// agree-check outputs, as trusted code observed them. Ends in push.
    Compaction { goal: Commit, out: Seq<nat> },
    /// Candidates write a test from the spec, never from code, looking for a
    /// behavior the spec forbids. The goal is the selected candidate of a code
    /// or compaction search, whose push it clears or blocks; or, when None,
    /// trunk's head. A test that shows the behavior lands on trunk (`land`).
    Counterexample { goal: Option<AgentProcess> },
    /// The goal is the selected candidate of a code or compaction search:
    /// candidates change it into a program trunk's tests accept and Verus
    /// rejects, a foil. A counterexample's test counts toward `not_found` only
    /// when it rejects a foil. Never pushed.
    Foil { goal: AgentProcess },
}

/// One generated change, as trusted code observed it after its agent process exited.
pub struct Candidate {
    pub commit: Commit,
    pub base: Commit,
    /// Every test accepted it: each test check exited 0. (TCB: trusted code ran them)
    pub accepted: bool,
    /// Verus verified the spec and proofs at this commit. (TCB: trusted code ran it)
    pub proved: bool,
    /// The paths the diff changed, as git reports them.
    pub changed: Set<Path>,
    /// Code: a hash of each agree check's output, in manifest order.
    pub out: Seq<nat>,
    /// Queue: each new intent, by the cue it cites.
    pub intents: Map<Cue, Intent>,
    /// Counterexample: whether this candidate's test accepts each tested
    /// commit: the goal search's candidates by index, and trunk's head (or a
    /// compaction's goal) as index -1. (TCB: trusted code ran it)
    pub accepts: Map<int, bool>,
    /// Counterexample: whether this candidate's test accepts each foil, by its
    /// index in the foil search. (TCB: trusted code ran it)
    pub accepts_foils: Map<int, bool>,
    /// Compaction: this candidate's tests reject every counterexample on
    /// trunk. (TCB: trusted code ran them)
    pub rejects_counterexamples: bool,
    pub rank: int,
    /// Lines changed against base.
    pub diff: nat,
}

/// What an agent process holds to write one candidate.
pub struct Capability {
    pub base: Commit,
    /// The paths it may change, attenuated by the search's kind at grant.
    pub authority: ISet<Path>,
    /// The generation it may spend, reserved from the bon process's limit at grant.
    pub limit: nat,
}

/// One search: n agent processes from one base.
pub struct Search {
    pub kind: Kind,
    pub base: Commit,
    pub n: nat,
    /// The authority every capability of this search carries.
    pub authority: ISet<Path>,
    /// The limit every capability of this search carries.
    pub limit: nat,
    /// index -> what that agent process returned; None if it produced no candidate.
    pub results: Map<int, Option<Candidate>>,
}

// ── predicates ──────────────────────────────────────────
//
// Names: a parameter is the word for what it is (`search`, `candidate`,
// `path`), or for its role when two of one type meet (`counterexample`, then
// `tested`, always in that order). Two letters remain: a candidate's
// index, `i` (and `j`, a second one), into `search.results`, see `at`; and a
// gate's return value, `r`. An index into `searches` is named for its search:
// `search_index`, `tested_index`, `counterexample_index`; an index into trunk
// is `trunk_index` (the head's, `head_index`).

/// bon's directory in the repository: the manifest, the queue, the SBOM and
/// the traces.
pub open spec fn bon_path() -> Path { Path(seq!['.', 'b', 'o', 'n', '/']) }

/// The queue's path, under bon's directory.
pub open spec fn queue_path() -> Path { Path(bon_path().0 + seq!['q', 'u', 'e', 'u', 'e', '.', 't', 's', 'v']) }

/// path is under one of the paths: each covers itself and every path it is a prefix of.
pub open spec fn under(paths: Set<Path>, path: Path) -> bool {
    exists|prefix: Path| paths.contains(prefix) && prefix.0.is_prefix_of(path.0)
}

/// No search may change path, except a queue search the queue: bon's directory,
/// a path under a check (the spec, the proofs, engineer's tests), or trusted
/// code (the files the manifest's SBOM declares trusted), which nothing proves.
pub open spec fn protected(checks: Set<Path>, trusted: Set<Path>, path: Path) -> bool {
    bon_path().0.is_prefix_of(path.0) || under(checks, path) || under(trusted, path)
}

/// Attenuation at grant: what a capability for this kind may change. `tests`
/// holds the counterexamples' tests on trunk: code may not change them,
/// compaction may, and a counterexample writes only there.
pub open spec fn authority(kind: Kind, checks: Set<Path>, tests: Set<Path>, trusted: Set<Path>) -> ISet<Path> {
    match kind {
        Kind::Queue { .. } => ISet::new(|path: Path| path == queue_path()),
        Kind::Code { .. } | Kind::Foil { .. } => ISet::new(|path: Path| !protected(checks, trusted, path) && !under(tests, path)),
        Kind::Compaction { .. } => ISet::new(|path: Path| !protected(checks, trusted, path)),
        Kind::Counterexample { .. } => ISet::new(|path: Path| !protected(checks, trusted, path) && under(tests, path)),
    }
}

/// Who may do what.
pub open spec fn policy(user: User, object: Object) -> Permission {
    match (user, object) {
        (User::agent, Object::Checks)           => Permission { read: true,  write: false, execute: true },
        (User::agent, Object::Transcripts)      => Permission { read: true,  write: false, execute: true },
        (User::agent, Object::WorkingDirectory) => Permission { read: true,  write: true,  execute: true },
        (User::agent, Object::Repository)       => Permission { read: false, write: false, execute: false },
        (User::agent, Object::WorkingDirectories) => Permission { read: false, write: false, execute: true },
        (User::engineer, _)                   => Permission { read: true,  write: true,  execute: true },
    }
}

/// agent's permissions, as trusted code observed them, match the policy.
pub open spec fn isolated(observed: Map<Object, Permission>) -> bool {
    forall|object: Object| observed.contains_key(object) && observed[object] == policy(User::agent, object)
}

/// The candidate at index i of search. Meaningful only when one exists.
pub open spec fn at(search: Search, i: int) -> Candidate { search.results[i]->Some_0 }

/// Every test accepted candidate.
pub open spec fn accepted(candidate: Candidate) -> bool { candidate.accepted }

/// Some test rejected candidate.
pub open spec fn rejected(candidate: Candidate) -> bool { !candidate.accepted }

/// Passed the vertical bottleneck: accepted, Verus verified it, and every
/// changed path is within the search's authority. A counterexample's
/// candidate is a test, which Verus says nothing about: it starts from
/// trunk's head, which fails Verus (and, when a gate is added or changed, does
/// not build) while a code search closes a spec change, so it is verified
/// without `proved`, and accepted when it builds on the tree it tests. A compaction's candidate also keeps
/// rejecting every counterexample.
pub open spec fn verified(search: Search, candidate: Candidate) -> bool {
    accepted(candidate) && (candidate.proved || search.kind is Counterexample)
    && (forall|path: Path| candidate.changed.contains(path) ==> search.authority.contains(path))
    && (search.kind is Compaction ==> candidate.rejects_counterexamples)
}

/// Index i of search has a candidate, and it is verified.
pub open spec fn verified_at(search: Search, i: int) -> bool {
    0 <= i < search.n && search.results.contains_key(i) && search.results[i] is Some && verified(search, at(search, i))
}

/// Every agent process has returned.
pub open spec fn complete(search: Search) -> bool {
    forall|i: int| 0 <= i < search.n ==> search.results.contains_key(i)
}

/// At least two verified candidates, and every verified pair prints the same.
/// Compaction also measures them against its goal: every verified candidate
/// prints the same as the goal. The goal never votes; it is measured.
pub open spec fn agree(search: Search) -> bool {
    complete(search) && match search.kind {
        Kind::Code { .. } =>
            (exists|i: int, j: int| i != j && verified_at(search, i) && verified_at(search, j))
            && forall|i: int, j: int| verified_at(search, i) && verified_at(search, j) ==> at(search, i).out == at(search, j).out,
        Kind::Compaction { out, .. } =>
            (exists|i: int, j: int| i != j && verified_at(search, i) && verified_at(search, j))
            && forall|i: int| verified_at(search, i) ==> at(search, i).out == out,
        _ => false,
    }
}

/// Candidate i of the tested search may be pushed: a counterexample search on
/// it found none, measured against a foil search on it.
pub open spec fn pushable(searches: Seq<Search>, tested_index: int, i: int) -> bool {
    exists|counterexample_index: int, foil_index: int|
        0 <= counterexample_index < searches.len() && 0 <= foil_index < searches.len()
        && searches[counterexample_index].kind == (Kind::Counterexample { goal: Some(AgentProcess { search: tested_index, index: i }) })
        && searches[foil_index].kind == (Kind::Foil { goal: AgentProcess { search: tested_index, index: i } })
        && not_found(searches[counterexample_index], searches[tested_index], searches[foil_index])
}

/// a at index ai outranks b at index bi: rank, then smaller diff, then earlier.
pub open spec fn beats(a: Candidate, ai: int, b: Candidate, bi: int) -> bool {
    a.rank > b.rank || (a.rank == b.rank && (a.diff < b.diff || (a.diff == b.diff && ai < bi)))
}

/// Code or compaction: index i is selected.
pub open spec fn selected(search: Search, i: int) -> bool {
    agree(search) && verified_at(search, i)
    && forall|j: int| j != i && verified_at(search, j) ==> beats(at(search, i), i, at(search, j), j)
}

/// What a counterexample's test runs on: the tested search's verified
/// candidates, and for a compaction search its goal, as index -1. The goal is
/// measured, not a voter.
pub open spec fn member(tested: Search, j: int) -> bool {
    verified_at(tested, j) || (tested.kind is Compaction && j == -1)
}

/// Counterexample: candidate, a test, splits the members of tested: it accepts
/// one and rejects another, so one shows a behavior the spec forbids. A test
/// with no result on a member counts as splitting.
pub open spec fn splits(candidate: Candidate, tested: Search) -> bool {
    exists|j1: int, j2: int| member(tested, j1) && member(tested, j2)
        && !(candidate.accepts.contains_key(j1) && candidate.accepts.contains_key(j2)
             && candidate.accepts[j1] == candidate.accepts[j2])
}

/// Counterexample: candidate, a test, rejects every member of tested. It
/// rejects what a correct implementation would accept, or tested is wrong
/// throughout; either way it does not show that nothing was found.
pub open spec fn rejects_every(candidate: Candidate, tested: Search) -> bool {
    forall|j: int| member(tested, j) ==> candidate.accepts.contains_key(j) && !candidate.accepts[j]
}

/// Foil: index j of foils holds a program trunk's tests accept and Verus
/// rejects, within the search's authority: a behavior the spec forbids that
/// trunk's tests miss.
pub open spec fn foil(foils: Search, j: int) -> bool {
    0 <= j < foils.n && foils.results.contains_key(j) && foils.results[j] is Some
    && accepted(at(foils, j)) && !at(foils, j).proved
    && forall|path: Path| at(foils, j).changed.contains(path) ==> foils.authority.contains(path)
}

/// Counterexample: candidate, a test, rejects some foil, so it can tell a
/// program the spec forbids from one it allows. A test that accepts every
/// program shows nothing.
pub open spec fn discriminates(candidate: Candidate, foils: Search) -> bool {
    exists|j: int| foil(foils, j) && candidate.accepts_foils.contains_key(j) && !candidate.accepts_foils[j]
}

/// Counterexample: some verified test of counterexample splits tested.
pub open spec fn found(counterexample: Search, tested: Search) -> bool {
    complete(counterexample) && exists|i: int| verified_at(counterexample, i) && splits(at(counterexample, i), tested)
}

/// Counterexample: every agent process of counterexample and of foils
/// returned, at least two verified tests reject a foil, and no verified test
/// splits tested or rejects every member of it: no counterexample was found.
/// Fewer than two tests that reject a foil means nothing was looked for; a
/// test that rejects every member does not split them, but is no sign that
/// nothing is wrong. Either way, neither `found` nor `not_found`, so nothing
/// it tested may be pushed.
pub open spec fn not_found(counterexample: Search, tested: Search, foils: Search) -> bool {
    complete(counterexample) && complete(foils)
    && (exists|i: int, j: int| i != j
        && verified_at(counterexample, i) && discriminates(at(counterexample, i), foils)
        && verified_at(counterexample, j) && discriminates(at(counterexample, j), foils))
    && forall|i: int| verified_at(counterexample, i) ==>
        !splits(at(counterexample, i), tested) && !rejects_every(at(counterexample, i), tested)
}

/// Counterexample on trunk: counterexample's verified test i rejects trunk's head.
pub open spec fn rejects_trunk(counterexample: Search, i: int) -> bool {
    verified_at(counterexample, i) && at(counterexample, i).accepts.contains_key(-1) && !at(counterexample, i).accepts[-1]
}

/// Counterexample on trunk: at least two verified tests reject trunk's head, so
/// trunk shows a behavior the spec forbids. Test i, of those that reject trunk
/// the highest rank, is the one that lands.
pub open spec fn found_on_trunk(counterexample: Search, i: int) -> bool {
    complete(counterexample) && rejects_trunk(counterexample, i)
    && (exists|j: int| j != i && rejects_trunk(counterexample, j))
    && forall|j: int| j != i && rejects_trunk(counterexample, j) ==> beats(at(counterexample, i), i, at(counterexample, j), j)
}

/// Counterexample: counterexample's verified test i splits tested.
pub open spec fn splits_at(counterexample: Search, tested: Search, i: int) -> bool {
    verified_at(counterexample, i) && splits(at(counterexample, i), tested)
}

/// Counterexample on a selected candidate: counterexample's verified test i
/// splits tested, the search it tested, and of the tests that do, it is the
/// highest rank.
pub open spec fn lands_on(counterexample: Search, tested: Search, i: int) -> bool {
    complete(counterexample) && complete(tested) && splits_at(counterexample, tested, i)
    && forall|j: int| j != i && splits_at(counterexample, tested, j) ==> beats(at(counterexample, i), i, at(counterexample, j), j)
}

/// Counterexample: test i of the counterexample search lands on trunk. On
/// trunk's head, the test `found_on_trunk` names; on a selected candidate, the
/// test `lands_on` names.
pub open spec fn lands(searches: Seq<Search>, counterexample_index: int, i: int) -> bool {
    0 <= counterexample_index < searches.len() && complete(searches[counterexample_index])
    && match searches[counterexample_index].kind {
        Kind::Counterexample { goal: None } => found_on_trunk(searches[counterexample_index], i),
        Kind::Counterexample { goal: Some(agent_process) } =>
            0 <= agent_process.search < searches.len()
            && lands_on(searches[counterexample_index], searches[agent_process.search], i),
        _ => false,
    }
}

// ── why a search blocked ────────────────────────────────

/// Why an attempt ended without a push or a landed test. Each reason holds
/// only where the ones before it do not, so a block has exactly one.
pub enum Blocked {
    /// Fewer than two candidates are verified.
    TooFewVerified,
    /// Two or more are verified, and they do not agree.
    Disagree,
    /// The counterexample search verified fewer than two tests, and none split
    /// the candidates.
    TooFewTests,
    /// Otherwise: a verified test rejects every candidate it tested.
    RejectsEvery,
    /// Otherwise: fewer than two verified tests reject a foil.
    Undiscriminating,
    /// The gates allowed the push, and trunk moved during the search. (git)
    TrunkMoved,
    /// The gates allowed a push or a landing, and git refused it. (git)
    Refused,
}

/// At least two of search's candidates are verified.
pub open spec fn two_verified(search: Search) -> bool {
    exists|i: int, j: int| i != j && verified_at(search, i) && verified_at(search, j)
}

/// The gates allowed tested's selected candidate i to be pushed: counterexample
/// and foils are the searches on it, and no counterexample was found.
pub open spec fn allowed(tested: Search, i: int, counterexample: Search, foils: Search) -> bool {
    selected(tested, i) && not_found(counterexample, tested, foils)
}

/// reason is why the attempt on tested blocked, its counterexample and foil
/// searches being counterexample and foils.
pub open spec fn blocked(reason: Blocked, tested: Search, counterexample: Search, foils: Search) -> bool {
    let checked = complete(counterexample) && !found(counterexample, tested);
    match reason {
        Blocked::TooFewVerified => complete(tested) && !two_verified(tested),
        Blocked::Disagree => complete(tested) && two_verified(tested) && !agree(tested),
        Blocked::TooFewTests => checked && !two_verified(counterexample),
        Blocked::RejectsEvery => checked && two_verified(counterexample)
            && exists|i: int| verified_at(counterexample, i) && rejects_every(at(counterexample, i), tested),
        Blocked::Undiscriminating => checked && complete(foils) && two_verified(counterexample)
            && (forall|i: int| verified_at(counterexample, i) ==> !rejects_every(at(counterexample, i), tested))
            && !not_found(counterexample, tested, foils),
        Blocked::TrunkMoved => exists|i: int| allowed(tested, i, counterexample, foils),
        Blocked::Refused => (exists|i: int| allowed(tested, i, counterexample, foils))
            || exists|j: int| lands_on(counterexample, tested, j),
    }
}

/// Why the attempt on tested blocked, decided by the kernel: on the selection
/// (no counterexample search yet), or on the counterexample search and the
/// foil search on it. None where it did not block, or has not finished. The
/// two git reasons, trunk moved and refused, are git's to say, not this.
pub open spec fn reason(tested: Search, counterexample: Option<Search>, foils: Option<Search>) -> Option<Blocked> {
    match counterexample {
        None =>
            if !complete(tested) { None }
            else if !two_verified(tested) { Some(Blocked::TooFewVerified) }
            else if !agree(tested) { Some(Blocked::Disagree) }
            else { None },
        Some(counterexample) =>
            if !(complete(counterexample) && !found(counterexample, tested)) { None }
            else if !two_verified(counterexample) { Some(Blocked::TooFewTests) }
            else if exists|i: int| verified_at(counterexample, i) && rejects_every(at(counterexample, i), tested) { Some(Blocked::RejectsEvery) }
            else {
                match foils {
                    Some(foils) => if complete(foils) && !not_found(counterexample, tested, foils) { Some(Blocked::Undiscriminating) } else { None },
                    None => None,
                }
            },
    }
}

/// The reason the kernel gives is one `blocked` holds for: what a block records.
pub proof fn reason_is_blocked(tested: Search, counterexample: Option<Search>, foils: Option<Search>)
    ensures
        reason(tested, counterexample, foils) matches Some(r) ==>
            blocked(r, tested, match counterexample { Some(c) => c, None => tested }, match foils { Some(f) => f, None => tested }),
{
}

/// A counterexample search on a selection that neither found a counterexample
/// nor found none blocked for exactly one of the counterexample reasons.
pub proof fn blocked_has_one_reason(counterexample: Search, tested: Search, foils: Search)
    requires
        complete(counterexample), complete(foils),
        !found(counterexample, tested), !not_found(counterexample, tested, foils),
    ensures
        blocked(Blocked::TooFewTests, tested, counterexample, foils)
        || blocked(Blocked::RejectsEvery, tested, counterexample, foils)
        || blocked(Blocked::Undiscriminating, tested, counterexample, foils),
{
}

/// Trunk commit commit, after its parent, is a selected candidate pushed once
/// a counterexample search on it found none.
pub open spec fn pushed(searches: Seq<Search>, parent: Commit, commit: Commit) -> bool {
    exists|tested_index: int, i: int| 0 <= tested_index < searches.len()
        && selected(searches[tested_index], i)
        && pushable(searches, tested_index, i)
        && searches[tested_index].base == parent
        && at(searches[tested_index], i).commit == commit
}

/// Trunk commit commit, after its parent, is a counterexample's test that landed.
pub open spec fn landed(searches: Seq<Search>, parent: Commit, commit: Commit) -> bool {
    exists|counterexample_index: int, i: int| lands(searches, counterexample_index, i)
        && searches[counterexample_index].base == parent
        && at(searches[counterexample_index], i).commit == commit
}

/// Queue: verified candidate i cites cue.
pub open spec fn cites(search: Search, i: int, cue: Cue) -> bool {
    verified_at(search, i) && at(search, i).intents.contains_key(cue)
}

/// Queue: at least two verified candidates cite cue.
pub open spec fn agreed(search: Search, cue: Cue) -> bool {
    complete(search) && exists|i: int, j: int| i != j && cites(search, i, cue) && cites(search, j, cue)
}

/// Queue: exactly one verified candidate cites cue. Shown to engineer apart from the proposal.
pub open spec fn contested(search: Search, cue: Cue) -> bool {
    complete(search) && (exists|i: int| cites(search, i, cue))
    && forall|i: int, j: int| cites(search, i, cue) && cites(search, j, cue) ==> i == j
}

/// Queue: intent is the proposal's wording for cue: the shortest among the
/// citing candidates, ties to the earliest.
pub open spec fn proposed(search: Search, cue: Cue, intent: Intent) -> bool {
    search.kind is Queue && agreed(search, cue)
    && exists|i: int| cites(search, i, cue) && at(search, i).intents[cue] == intent
        && forall|j: int| cites(search, j, cue) ==>
            intent.0.len() < at(search, j).intents[cue].0.len() || (intent.0.len() == at(search, j).intents[cue].0.len() && i <= j)
}

/// The agent processes of the search at search_index: one per index.
pub open spec fn agent_processes(search_index: int, n: nat) -> Seq<AgentProcess> {
    Seq::new(n, |i: int| AgentProcess { search: search_index, index: i })
}

/// The capabilities grant adds: one per agent process, each with the search's
/// authority and limit.
pub open spec fn granted(search_index: int, n: nat, base: Commit, attenuated: ISet<Path>, agent_process_limit: nat) -> Map<AgentProcess, Capability> {
    Map::new(agent_processes(search_index, n).to_set(), |agent_process: AgentProcess| Capability { base, authority: attenuated, limit: agent_process_limit })
}

} // verus!

tokenized_state_machine!{ bon {

    // ── state ───────────────────────────────────────────

    fields {
        /// The check paths the manifest declares at trunk's head.
        #[sharding(variable)] pub checks: Set<Path>,
        /// The paths holding the counterexamples' tests at trunk's head.
        #[sharding(variable)] pub tests: Set<Path>,
        /// The trusted code the manifest declares at trunk's head.
        #[sharding(variable)] pub trusted: Set<Path>,
        /// Trunk's history; last() is the head.
        #[sharding(variable)] pub trunk: Seq<Commit>,
        /// The git author of each trunk commit, in step with trunk.
        #[sharding(variable)] pub authors: Seq<User>,
        #[sharding(variable)] pub searches: Seq<Search>,
        /// The bon process's limit, and what it has spent and reserved against it.
        #[sharding(variable)] pub limit: nat,
        #[sharding(variable)] pub spent: nat,
        #[sharding(variable)] pub reserved: nat,
        /// Outstanding capabilities, keyed by the agent process that holds each.
        /// Each is a Verus token: the token is how Verus represents a capability;
        /// capability is the term. An agent process holds exactly one, and waiting
        /// on it consumes it.
        #[sharding(map)] pub capability: Map<AgentProcess, Capability>,
    }

    // ── init ────────────────────────────────────────────

    init!{ initialize(root: Commit, checks: Set<Path>, tests: Set<Path>, trusted: Set<Path>, limit: nat) {
        init checks = checks;
        init tests = tests;
        init trusted = trusted;
        init trunk = Seq::empty().push(root);
        init authors = Seq::empty().push(User::engineer);
        init searches = Seq::empty();
        init limit = limit;
        init spent = 0;
        init reserved = 0;
        init capability = Map::empty();
    }}

    // ── transitions ─────────────────────────────────────

    /// engineer committed to trunk, e.g. the queue, the spec or the checks.
    transition!{ advance(commit: Commit, checks: Set<Path>, tests: Set<Path>, trusted: Set<Path>) {
        update checks = checks;
        update tests = tests;
        update trusted = trusted;
        update trunk = pre.trunk.push(commit);
        update authors = pre.authors.push(User::engineer);
    }}

    /// Open a search and grant one capability per agent process, reserving each
    /// one's limit. One search runs at a time; its agent processes run in parallel.
    /// Every search starts from trunk's head: a counterexample's test is written
    /// from the spec, never from candidate code. A foil search alone starts
    /// from the selected candidate it changes.
    transition!{ grant(kind: Kind, n: nat, agent_process_limit: nat, observed: Map<Object, Permission>) {
        require isolated(observed);
        require forall|search_index: int| 0 <= search_index < pre.searches.len() ==> complete(#[trigger] pre.searches[search_index]);
        require pre.spent + pre.reserved + agent_process_limit * n <= pre.limit;
        require kind matches Kind::Code { goal } ==> goal == pre.trunk.last();
        require kind matches Kind::Compaction { goal, .. } ==> goal == pre.trunk.last();
        require kind matches Kind::Counterexample { goal: Some(agent_process) } ==>
            0 <= agent_process.search < pre.searches.len()
            && selected(pre.searches[agent_process.search], agent_process.index)
            && pre.searches[agent_process.search].base == pre.trunk.last();
        require kind matches Kind::Foil { goal: agent_process } ==>
            0 <= agent_process.search < pre.searches.len()
            && selected(pre.searches[agent_process.search], agent_process.index)
            && pre.searches[agent_process.search].base == pre.trunk.last();
        let search_index = pre.searches.len() as int;
        let base = match kind {
            Kind::Foil { goal } => at(pre.searches[goal.search], goal.index).commit,
            _ => pre.trunk.last(),
        };
        let attenuated = authority(kind, pre.checks, pre.tests, pre.trusted);
        update searches = pre.searches.push(Search { kind, base, n, authority: attenuated, limit: agent_process_limit, results: Map::empty() });
        update reserved = pre.reserved + agent_process_limit * n;
        add capability += (granted(search_index, n, base, attenuated, agent_process_limit));
    }}

    /// The bon process waits on an agent process and records what it returned and
    /// its generation, consuming its capability and settling its limit. Generation is
    /// what the agent process's models charged for its tokens, at the host file's
    /// prices (TCB: trusted code counted it). A search's cost is its generation plus
    /// time: the rate in bon.toml times its wall time. (OSTEP: wait)
    transition!{ wait(agent_process: AgentProcess, held: Capability, result: Option<Candidate>, generation: nat) {
        remove capability -= [agent_process => held];
        require result matches Some(candidate) ==> candidate.base == held.base;
        require generation <= held.limit;
        let search = pre.searches[agent_process.search];
        update searches = pre.searches.update(agent_process.search,
            Search { results: search.results.insert(agent_process.index, result), ..search });
        update spent = pre.spent + generation;
        update reserved = (pre.reserved - held.limit) as nat;
    }}

    /// Code or compaction: the selected candidate is pushed to trunk, if a
    /// counterexample search on it found none and trunk hasn't moved. (git: push)
    transition!{ push(tested_index: int, i: int, counterexample_index: int, foil_index: int) {
        require 0 <= tested_index < pre.searches.len() && 0 <= counterexample_index < pre.searches.len() && 0 <= foil_index < pre.searches.len();
        require selected(pre.searches[tested_index], i);
        require pre.searches[counterexample_index].kind == Kind::Counterexample { goal: Some(AgentProcess { search: tested_index, index: i }) };
        require pre.searches[foil_index].kind == Kind::Foil { goal: AgentProcess { search: tested_index, index: i } };
        require not_found(pre.searches[counterexample_index], pre.searches[tested_index], pre.searches[foil_index]);
        require pre.searches[tested_index].base == pre.trunk.last();
        update trunk = pre.trunk.push(at(pre.searches[tested_index], i).commit);
        update authors = pre.authors.push(User::agent);
    }}

    /// Counterexample: its test that shows a behavior the spec forbids lands on
    /// trunk by itself, if trunk hasn't moved. Trunk's checks then reject trunk
    /// until a code search writes code they accept. (git: push)
    transition!{ land(counterexample_index: int, i: int) {
        require lands(pre.searches, counterexample_index, i);
        require pre.searches[counterexample_index].base == pre.trunk.last();
        update trunk = pre.trunk.push(at(pre.searches[counterexample_index], i).commit);
        update authors = pre.authors.push(User::agent);
    }}

    // ── properties ──────────────────────────────────────

    /// What's selected is verified: exec code can rely on this.
    property!{ selection_verified(search_index: int, i: int) {
        require 0 <= search_index < pre.searches.len() && selected(pre.searches[search_index], i);
        assert verified(pre.searches[search_index], at(pre.searches[search_index], i));
    }}

    // ── invariants ──────────────────────────────────────

    #[invariant]
    pub fn trunk_nonempty(&self) -> bool {
        self.trunk.len() > 0 && self.authors.len() == self.trunk.len()
    }

    /// Each capability is held by an agent process for one open index of the
    /// running search, with that search's base, authority and limit.
    #[invariant]
    pub fn capability_open(&self) -> bool {
        forall|agent_process: AgentProcess| #[trigger] self.capability.contains_key(agent_process) ==> {
            let held = self.capability[agent_process];
            let search = self.searches[agent_process.search];
            agent_process.search == self.searches.len() - 1
            && 0 <= agent_process.index < search.n
            && !search.results.contains_key(agent_process.index)
            && held.base == search.base
            && held.authority == search.authority
            && held.limit == search.limit
        }
    }

    /// Every agent process of every search has either returned or still holds its capability.
    #[invariant]
    pub fn accounted(&self) -> bool {
        forall|search_index: int, i: int| 0 <= search_index < self.searches.len() && 0 <= i < self.searches[search_index].n
            ==> self.searches[search_index].results.contains_key(i)
                || self.capability.contains_key(AgentProcess { search: search_index, index: i })
    }

    /// Nothing spends past its limit: what is reserved is exactly the limits of
    /// the outstanding capabilities.
    #[invariant]
    pub fn within_limit(&self) -> bool {
        self.spent + self.reserved <= self.limit
        && (self.searches.len() == 0 ==> self.capability.dom().len() == 0 && self.reserved == 0)
        && (self.searches.len() > 0 ==>
            self.reserved == self.searches.last().limit * self.capability.dom().len())
    }

    /// Candidates of a search are siblings of its base.
    #[invariant]
    pub fn siblings(&self) -> bool {
        forall|search_index: int, i: int| 0 <= search_index < self.searches.len()
            && self.searches[search_index].results.contains_key(i) && self.searches[search_index].results[i] is Some
            ==> at(self.searches[search_index], i).base == self.searches[search_index].base
    }

    /// Every trunk commit authored by agent is exactly a selected, pushable
    /// candidate of a search on the previous head, or a counterexample's test
    /// that landed on it.
    #[invariant]
    pub fn trunk_exact(&self) -> bool {
        forall|trunk_index: int| 1 <= trunk_index < self.trunk.len() && self.authors[trunk_index] == User::agent ==>
            pushed(self.searches, self.trunk[trunk_index - 1], self.trunk[trunk_index])
            || landed(self.searches, self.trunk[trunk_index - 1], self.trunk[trunk_index])
    }

    // ── proofs ──────────────────────────────────────────

    #[inductive(initialize)]
    fn initialize_inductive(post: Self, root: Commit, checks: Set<Path>, tests: Set<Path>, trusted: Set<Path>, limit: nat) {}

    #[inductive(advance)]
    fn advance_inductive(pre: Self, post: Self, commit: Commit, checks: Set<Path>, tests: Set<Path>, trusted: Set<Path>) {}

    #[inductive(grant)]
    fn grant_inductive(pre: Self, post: Self, kind: Kind, n: nat, agent_process_limit: nat, observed: Map<Object, Permission>) {
        let search_index = pre.searches.len() as int;
        let processes = agent_processes(search_index, n);
        // Every earlier search is complete, so no capability is outstanding.
        assert(pre.capability.dom() =~= Set::empty()) by {
            assert forall|agent_process: AgentProcess| !pre.capability.contains_key(agent_process) by {
                if pre.capability.contains_key(agent_process) {
                    assert(complete(pre.searches[agent_process.search]));
                }
            }
        }
        // The new capabilities are exactly the new search's n agent processes.
        assert(processes.no_duplicates());
        processes.unique_seq_to_set();
        assert(post.capability.dom() =~= processes.to_set());
        assert forall|i: int| 0 <= i < n implies
            #[trigger] post.capability.contains_key(AgentProcess { search: search_index, index: i }) by {
            assert(processes[i] == AgentProcess { search: search_index, index: i });
            assert(processes.contains(AgentProcess { search: search_index, index: i }));
        }
        assert forall|agent_process: AgentProcess| #[trigger] post.capability.contains_key(agent_process) implies
            agent_process.search == search_index && 0 <= agent_process.index < n by {
            assert(processes.to_set().contains(agent_process));
            assert(processes.contains(agent_process));
        }
        assert(post.reserved == post.searches.last().limit * post.capability.dom().len()) by(nonlinear_arith)
            requires post.reserved == agent_process_limit * n, post.searches.last().limit == agent_process_limit, post.capability.dom().len() == n;
        // Earlier searches are unchanged, so their witnesses still hold.
        assert forall|trunk_index: int| 1 <= trunk_index < post.trunk.len() && post.authors[trunk_index] == User::agent implies
            pushed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index])
            || landed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index]) by {
            if pushed(pre.searches, pre.trunk[trunk_index - 1], pre.trunk[trunk_index]) {
                let (tested_index, i) = choose|tested_index: int, i: int| 0 <= tested_index < pre.searches.len()
                    && selected(pre.searches[tested_index], i)
                    && pushable(pre.searches, tested_index, i)
                    && pre.searches[tested_index].base == pre.trunk[trunk_index - 1]
                    && at(pre.searches[tested_index], i).commit == pre.trunk[trunk_index];
                assert(post.searches[tested_index] == pre.searches[tested_index]);
                let (counterexample_index, foil_index) = choose|counterexample_index: int, foil_index: int|
                    0 <= counterexample_index < pre.searches.len() && 0 <= foil_index < pre.searches.len()
                    && pre.searches[counterexample_index].kind == (Kind::Counterexample { goal: Some(AgentProcess { search: tested_index, index: i }) })
                    && pre.searches[foil_index].kind == (Kind::Foil { goal: AgentProcess { search: tested_index, index: i } })
                    && not_found(pre.searches[counterexample_index], pre.searches[tested_index], pre.searches[foil_index]);
                assert(post.searches[counterexample_index] == pre.searches[counterexample_index]);
                assert(post.searches[foil_index] == pre.searches[foil_index]);
                assert(pushable(post.searches, tested_index, i));
                assert(pushed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index]));
            } else {
                let (counterexample_index, i) = choose|counterexample_index: int, i: int| lands(pre.searches, counterexample_index, i)
                    && pre.searches[counterexample_index].base == pre.trunk[trunk_index - 1]
                    && at(pre.searches[counterexample_index], i).commit == pre.trunk[trunk_index];
                assert(post.searches[counterexample_index] == pre.searches[counterexample_index]);
                match pre.searches[counterexample_index].kind {
                    Kind::Counterexample { goal: Some(goal) } => { assert(post.searches[goal.search] == pre.searches[goal.search]); }
                    _ => {}
                }
                assert(lands(post.searches, counterexample_index, i));
                assert(landed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index]));
            }
        }
    }

    #[inductive(wait)]
    fn wait_inductive(pre: Self, post: Self, agent_process: AgentProcess, held: Capability, result: Option<Candidate>, generation: nat) {
        broadcast use vstd::set::lemma_set_remove_len;
        assert(pre.capability.contains_key(agent_process) && pre.capability[agent_process] == held);
        // Settling: one capability fewer, its limit released, its generation spent.
        assert(post.capability.dom() =~= pre.capability.dom().remove(agent_process));
        assert(post.capability.dom().len() + 1 == pre.capability.dom().len());
        let search_limit = pre.searches.last().limit;
        let outstanding = pre.capability.dom().len();
        assert(search_limit * outstanding == search_limit * (outstanding - 1) + search_limit) by(nonlinear_arith) requires outstanding >= 1;
        assert(post.searches.last().limit == search_limit);
        // The returned candidate, if any, has the capability's base, which is the search's.
        assert forall|search_index: int, i: int| 0 <= search_index < post.searches.len()
            && post.searches[search_index].results.contains_key(i) && post.searches[search_index].results[i] is Some
            implies #[trigger] at(post.searches[search_index], i).base == post.searches[search_index].base by {
            if search_index == agent_process.search && i == agent_process.index {
                assert(post.searches[search_index].results[i] == result);
                assert(held.base == pre.searches[search_index].base);
                assert(post.searches[search_index].base == pre.searches[search_index].base);
                assert(at(post.searches[search_index], i) == result->Some_0);
            } else if search_index == agent_process.search {
                assert(post.searches[search_index].results[i] == pre.searches[search_index].results[i]);
                assert(post.searches[search_index].base == pre.searches[search_index].base);
                assert(at(post.searches[search_index], i) == at(pre.searches[search_index], i));
            } else {
                assert(post.searches[search_index] == pre.searches[search_index]);
            }
        }
        // Selected searches, searches that found no counterexample, and the searches a landed test
        // depends on are complete, so they hold no capability: the one waited on here is none of them.
        assert forall|trunk_index: int| 1 <= trunk_index < post.trunk.len() && post.authors[trunk_index] == User::agent implies
            pushed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index])
            || landed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index]) by {
            if pushed(pre.searches, pre.trunk[trunk_index - 1], pre.trunk[trunk_index]) {
                let (tested_index, i) = choose|tested_index: int, i: int| 0 <= tested_index < pre.searches.len()
                    && selected(pre.searches[tested_index], i)
                    && pushable(pre.searches, tested_index, i)
                    && pre.searches[tested_index].base == pre.trunk[trunk_index - 1]
                    && at(pre.searches[tested_index], i).commit == pre.trunk[trunk_index];
                assert(complete(pre.searches[tested_index]));
                assert(tested_index != agent_process.search);
                assert(post.searches[tested_index] == pre.searches[tested_index]);
                let (counterexample_index, foil_index) = choose|counterexample_index: int, foil_index: int|
                    0 <= counterexample_index < pre.searches.len() && 0 <= foil_index < pre.searches.len()
                    && pre.searches[counterexample_index].kind == (Kind::Counterexample { goal: Some(AgentProcess { search: tested_index, index: i }) })
                    && pre.searches[foil_index].kind == (Kind::Foil { goal: AgentProcess { search: tested_index, index: i } })
                    && not_found(pre.searches[counterexample_index], pre.searches[tested_index], pre.searches[foil_index]);
                assert(complete(pre.searches[counterexample_index]) && complete(pre.searches[foil_index]));
                assert(counterexample_index != agent_process.search && foil_index != agent_process.search);
                assert(post.searches[counterexample_index] == pre.searches[counterexample_index]);
                assert(post.searches[foil_index] == pre.searches[foil_index]);
                assert(pushable(post.searches, tested_index, i));
                assert(pushed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index]));
            } else {
                let (counterexample_index, i) = choose|counterexample_index: int, i: int| lands(pre.searches, counterexample_index, i)
                    && pre.searches[counterexample_index].base == pre.trunk[trunk_index - 1]
                    && at(pre.searches[counterexample_index], i).commit == pre.trunk[trunk_index];
                assert(complete(pre.searches[counterexample_index]));
                assert(counterexample_index != agent_process.search);
                assert(post.searches[counterexample_index] == pre.searches[counterexample_index]);
                match pre.searches[counterexample_index].kind {
                    Kind::Counterexample { goal: Some(goal) } => {
                        assert(complete(pre.searches[goal.search]));
                        assert(goal.search != agent_process.search);
                        assert(post.searches[goal.search] == pre.searches[goal.search]);
                    }
                    _ => {}
                }
                assert(lands(post.searches, counterexample_index, i));
                assert(landed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index]));
            }
        }
    }

    #[inductive(push)]
    fn push_inductive(pre: Self, post: Self, tested_index: int, i: int, counterexample_index: int, foil_index: int) {
        assert(pushable(post.searches, tested_index, i));
        let head_index = post.trunk.len() - 1;
        assert(post.trunk[head_index - 1] == pre.trunk.last());
        assert(pushed(post.searches, post.trunk[head_index - 1], post.trunk[head_index]));
        assert forall|trunk_index: int| 1 <= trunk_index < post.trunk.len() && post.authors[trunk_index] == User::agent implies
            pushed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index])
            || landed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index]) by {
            if trunk_index < head_index { assert(post.trunk[trunk_index - 1] == pre.trunk[trunk_index - 1] && post.trunk[trunk_index] == pre.trunk[trunk_index] && post.authors[trunk_index] == pre.authors[trunk_index]); }
        }
    }

    #[inductive(land)]
    fn land_inductive(pre: Self, post: Self, counterexample_index: int, i: int) {
        let head_index = post.trunk.len() - 1;
        assert(post.trunk[head_index - 1] == pre.trunk.last());
        assert(landed(post.searches, post.trunk[head_index - 1], post.trunk[head_index]));
        assert forall|trunk_index: int| 1 <= trunk_index < post.trunk.len() && post.authors[trunk_index] == User::agent implies
            pushed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index])
            || landed(post.searches, post.trunk[trunk_index - 1], post.trunk[trunk_index]) by {
            if trunk_index < head_index { assert(post.trunk[trunk_index - 1] == pre.trunk[trunk_index - 1] && post.trunk[trunk_index] == pre.trunk[trunk_index] && post.authors[trunk_index] == pre.authors[trunk_index]); }
        }
    }
}}
