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
pub type Commit = Seq<char>;

/// A path in a commit's tree, as git reports it. (TCB: git)
pub type Path = Seq<char>;

/// One line of the queue: what is wanted and not yet in the spec.
pub type Intent = Seq<char>;

/// A WebVTT file, one per recorded call. (TCB: WebVTT)
pub type Transcript = Path;

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
    /// trunk's head, where a counterexample starts a code search that carries
    /// its test.
    Counterexample { goal: Option<AgentProcess> },
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

/// bon's directory in the repository: the manifest, the queue, the SBOM and
/// the traces.
pub open spec fn bon_path() -> Path { seq!['.', 'b', 'o', 'n', '/'] }

/// The queue's path, under bon's directory.
pub open spec fn queue_path() -> Path { bon_path() + seq!['q', 'u', 'e', 'u', 'e', '.', 't', 's', 'v'] }

/// p is under one of the paths: each covers itself and every path it is a prefix of.
pub open spec fn under(paths: Set<Path>, p: Path) -> bool {
    exists|c: Path| paths.contains(c) && c.is_prefix_of(p)
}

/// No search may change p, except a queue search the queue: bon's directory,
/// or a path under a check (the spec, the proofs, engineer's tests).
pub open spec fn protected(checks: Set<Path>, p: Path) -> bool {
    bon_path().is_prefix_of(p) || under(checks, p)
}

/// Attenuation at grant: what a capability for this kind may change. `tests`
/// holds the counterexamples' tests on trunk: code may not change them,
/// compaction may, and a counterexample writes only there.
pub open spec fn authority(kind: Kind, checks: Set<Path>, tests: Set<Path>) -> ISet<Path> {
    match kind {
        Kind::Queue { .. } => ISet::new(|p: Path| p == queue_path()),
        Kind::Code { .. } => ISet::new(|p: Path| !protected(checks, p) && !under(tests, p)),
        Kind::Compaction { .. } => ISet::new(|p: Path| !protected(checks, p)),
        Kind::Counterexample { .. } => ISet::new(|p: Path| !protected(checks, p) && under(tests, p)),
    }
}

/// Who may do what.
pub open spec fn policy(u: User, f: Object) -> Permission {
    match (u, f) {
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
    forall|f: Object| observed.contains_key(f) && observed[f] == policy(User::agent, f)
}

/// The candidate at index i. Meaningful only when one exists.
pub open spec fn at(s: Search, i: int) -> Candidate { s.results[i]->Some_0 }

/// Every test accepted c.
pub open spec fn accepted(c: Candidate) -> bool { c.accepted }

/// Some test rejected c.
pub open spec fn rejected(c: Candidate) -> bool { !c.accepted }

/// Passed the vertical bottleneck: accepted, Verus verified it, and every
/// changed path is within the search's authority. A compaction's candidate
/// also keeps rejecting every counterexample.
pub open spec fn verified(s: Search, c: Candidate) -> bool {
    accepted(c) && c.proved
    && (forall|p: Path| c.changed.contains(p) ==> s.authority.contains(p))
    && (s.kind is Compaction ==> c.rejects_counterexamples)
}

pub open spec fn verified_at(s: Search, i: int) -> bool {
    0 <= i < s.n && s.results.contains_key(i) && s.results[i] is Some && verified(s, at(s, i))
}

/// Every agent process has returned.
pub open spec fn complete(s: Search) -> bool {
    forall|i: int| 0 <= i < s.n ==> s.results.contains_key(i)
}

/// At least two verified candidates, and every verified pair prints the same.
/// Compaction also measures them against its goal: every verified candidate
/// prints the same as the goal. The goal never votes; it is measured.
pub open spec fn agree(s: Search) -> bool {
    complete(s) && match s.kind {
        Kind::Code { .. } =>
            (exists|i: int, j: int| i != j && verified_at(s, i) && verified_at(s, j))
            && forall|i: int, j: int| verified_at(s, i) && verified_at(s, j) ==> at(s, i).out == at(s, j).out,
        Kind::Compaction { out, .. } =>
            (exists|i: int, j: int| i != j && verified_at(s, i) && verified_at(s, j))
            && forall|i: int| verified_at(s, i) ==> at(s, i).out == out,
        _ => false,
    }
}

/// Candidate i of search k may be pushed: a counterexample search on it found none.
pub open spec fn pushable(searches: Seq<Search>, k: int, i: int) -> bool {
    exists|x: int| 0 <= x < searches.len()
        && searches[x].kind == (Kind::Counterexample { goal: Some(AgentProcess { search: k, index: i }) })
        && not_found(searches[x], searches[k])
}

/// a at index ai outranks b at index bi: rank, then smaller diff, then earlier.
pub open spec fn beats(a: Candidate, ai: int, b: Candidate, bi: int) -> bool {
    a.rank > b.rank || (a.rank == b.rank && (a.diff < b.diff || (a.diff == b.diff && ai < bi)))
}

/// Code or compaction: index i is selected.
pub open spec fn selected(s: Search, i: int) -> bool {
    agree(s) && verified_at(s, i)
    && forall|j: int| j != i && verified_at(s, j) ==> beats(at(s, i), i, at(s, j), j)
}

/// What a counterexample's test runs on: t's verified candidates, and for a
/// compaction search its goal, as index -1. The goal is measured, not a voter.
pub open spec fn member(t: Search, j: int) -> bool {
    verified_at(t, j) || (t.kind is Compaction && j == -1)
}

/// Counterexample: x's test splits the members of t: it accepts one and
/// rejects another, so one shows a behavior the spec forbids. A test with no
/// result on a member counts as splitting.
pub open spec fn splits(t: Search, x: Candidate) -> bool {
    exists|j1: int, j2: int| member(t, j1) && member(t, j2)
        && !(x.accepts.contains_key(j1) && x.accepts.contains_key(j2)
             && x.accepts[j1] == x.accepts[j2])
}

/// Counterexample: some verified candidate of x splits t.
pub open spec fn found(x: Search, t: Search) -> bool {
    complete(x) && exists|i: int| verified_at(x, i) && splits(t, at(x, i))
}

/// Counterexample: every agent process of x returned, at least two of its tests
/// are verified, and none splits t: no counterexample was found. With fewer than
/// two verified tests, nothing was looked for: neither `found` nor `not_found`,
/// so nothing it tested may be pushed.
pub open spec fn not_found(x: Search, t: Search) -> bool {
    complete(x)
    && (exists|i: int, j: int| i != j && verified_at(x, i) && verified_at(x, j))
    && forall|i: int| verified_at(x, i) ==> !splits(t, at(x, i))
}

/// Counterexample on trunk: x's verified test i rejects trunk's head.
pub open spec fn rejects_trunk(x: Search, i: int) -> bool {
    verified_at(x, i) && at(x, i).accepts.contains_key(-1) && !at(x, i).accepts[-1]
}

/// Counterexample on trunk: at least two verified tests reject trunk's head, so
/// trunk shows a behavior the spec forbids. The code search that follows
/// carries the test at index i: of those that reject trunk, the highest rank.
pub open spec fn found_on_trunk(x: Search, i: int) -> bool {
    complete(x) && rejects_trunk(x, i)
    && (exists|j: int| j != i && rejects_trunk(x, j))
    && forall|j: int| j != i && rejects_trunk(x, j) ==> beats(at(x, i), i, at(x, j), j)
}

/// Queue: verified candidate i cites cue q.
pub open spec fn cites(s: Search, i: int, q: Cue) -> bool {
    verified_at(s, i) && at(s, i).intents.contains_key(q)
}

/// Queue: at least two verified candidates cite q.
pub open spec fn agreed(s: Search, q: Cue) -> bool {
    complete(s) && exists|i: int, j: int| i != j && cites(s, i, q) && cites(s, j, q)
}

/// Queue: exactly one verified candidate cites q. Shown to engineer apart from the proposal.
pub open spec fn contested(s: Search, q: Cue) -> bool {
    complete(s) && (exists|i: int| cites(s, i, q))
    && forall|i: int, j: int| cites(s, i, q) && cites(s, j, q) ==> i == j
}

/// Queue: w is the proposal's wording for q: the shortest among the citing
/// candidates, ties to the earliest.
pub open spec fn proposed(s: Search, q: Cue, w: Intent) -> bool {
    s.kind is Queue && agreed(s, q)
    && exists|i: int| cites(s, i, q) && at(s, i).intents[q] == w
        && forall|j: int| cites(s, j, q) ==>
            w.len() < at(s, j).intents[q].len() || (w.len() == at(s, j).intents[q].len() && i <= j)
}

/// Where a search's candidates start: always trunk's head. A counterexample's
/// test is written from the spec, never from candidate code.
pub open spec fn start(kind: Kind, searches: Seq<Search>, head: Commit) -> Commit {
    head
}

/// The agent processes of search k: one per index.
pub open spec fn agent_processes(k: int, n: nat) -> Seq<AgentProcess> {
    Seq::new(n, |i: int| AgentProcess { search: k, index: i })
}

/// The capabilities grant adds: one per agent process, each with the search's
/// authority and limit.
pub open spec fn granted(k: int, n: nat, base: Commit, a: ISet<Path>, l: nat) -> Map<AgentProcess, Capability> {
    Map::new(agent_processes(k, n).to_set(), |p: AgentProcess| Capability { base, authority: a, limit: l })
}

} // verus!

tokenized_state_machine!{ bon {

    // ── state ───────────────────────────────────────────

    fields {
        /// The check paths the manifest declares at trunk's head.
        #[sharding(variable)] pub checks: Set<Path>,
        /// The paths holding the counterexamples' tests at trunk's head.
        #[sharding(variable)] pub tests: Set<Path>,
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

    /// A bon process initializes one instance, once: every command it runs, and
    /// every search of each, spends from this one limit.
    init!{ initialize(root: Commit, checks: Set<Path>, tests: Set<Path>, limit: nat) {
        init checks = checks;
        init tests = tests;
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
    transition!{ advance(c: Commit, checks: Set<Path>, tests: Set<Path>) {
        update checks = checks;
        update tests = tests;
        update trunk = pre.trunk.push(c);
        update authors = pre.authors.push(User::engineer);
    }}

    /// Open a search and grant one capability per agent process, reserving each
    /// one's limit. One search runs at a time; its agent processes run in parallel.
    transition!{ grant(kind: Kind, n: nat, l: nat, observed: Map<Object, Permission>) {
        require isolated(observed);
        require forall|k: int| 0 <= k < pre.searches.len() ==> complete(#[trigger] pre.searches[k]);
        require pre.spent + pre.reserved + l * n <= pre.limit;
        require kind matches Kind::Code { goal } ==> goal == pre.trunk.last();
        require kind matches Kind::Compaction { goal, .. } ==> goal == pre.trunk.last();
        require kind matches Kind::Counterexample { goal: Some(p) } ==>
            0 <= p.search < pre.searches.len()
            && selected(pre.searches[p.search], p.index)
            && pre.searches[p.search].base == pre.trunk.last();
        let k = pre.searches.len() as int;
        let base = start(kind, pre.searches, pre.trunk.last());
        let a = authority(kind, pre.checks, pre.tests);
        update searches = pre.searches.push(Search { kind, base, n, authority: a, limit: l, results: Map::empty() });
        update reserved = pre.reserved + l * n;
        add capability += (granted(k, n, base, a, l));
    }}

    /// The bon process waits on an agent process and records what it returned and
    /// its generation, consuming its capability and settling its limit. Generation is
    /// what the agent process's models charged for its tokens, at the host file's
    /// prices (TCB: trusted code counted it). A search's cost is its generation plus
    /// time: the rate in bon.toml times its wall time. (OSTEP: wait)
    transition!{ wait(p: AgentProcess, cap: Capability, result: Option<Candidate>, generation: nat) {
        remove capability -= [p => cap];
        require result matches Some(c) ==> c.base == cap.base;
        require generation <= cap.limit;
        let s = pre.searches[p.search];
        update searches = pre.searches.update(p.search,
            Search { results: s.results.insert(p.index, result), ..s });
        update spent = pre.spent + generation;
        update reserved = (pre.reserved - cap.limit) as nat;
    }}

    /// Code or compaction: the selected candidate is pushed to trunk, if a
    /// counterexample search on it found none and trunk hasn't moved. (git: push)
    transition!{ push(k: int, i: int, x: int) {
        require 0 <= k < pre.searches.len() && 0 <= x < pre.searches.len();
        require selected(pre.searches[k], i);
        require pre.searches[x].kind == Kind::Counterexample { goal: Some(AgentProcess { search: k, index: i }) };
        require not_found(pre.searches[x], pre.searches[k]);
        require pre.searches[k].base == pre.trunk.last();
        update trunk = pre.trunk.push(at(pre.searches[k], i).commit);
        update authors = pre.authors.push(User::agent);
    }}

    // ── properties ──────────────────────────────────────

    /// What's selected is verified: exec code can rely on this.
    property!{ selection_verified(k: int, i: int) {
        require 0 <= k < pre.searches.len() && selected(pre.searches[k], i);
        assert verified(pre.searches[k], at(pre.searches[k], i));
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
        forall|p: AgentProcess| #[trigger] self.capability.contains_key(p) ==> {
            let c = self.capability[p];
            p.search == self.searches.len() - 1
            && 0 <= p.index < self.searches[p.search].n
            && !self.searches[p.search].results.contains_key(p.index)
            && c.base == self.searches[p.search].base
            && c.authority == self.searches[p.search].authority
            && c.limit == self.searches[p.search].limit
        }
    }

    /// Every agent process of every search has either returned or still holds its capability.
    #[invariant]
    pub fn accounted(&self) -> bool {
        forall|k: int, i: int| 0 <= k < self.searches.len() && 0 <= i < self.searches[k].n
            ==> self.searches[k].results.contains_key(i)
                || self.capability.contains_key(AgentProcess { search: k, index: i })
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
        forall|k: int, i: int| 0 <= k < self.searches.len()
            && self.searches[k].results.contains_key(i) && self.searches[k].results[i] is Some
            ==> at(self.searches[k], i).base == self.searches[k].base
    }

    /// Every trunk commit authored by agent is exactly a selected, pushable
    /// candidate of a search on the previous head.
    #[invariant]
    pub fn trunk_exact(&self) -> bool {
        forall|t: int| 1 <= t < self.trunk.len() && self.authors[t] == User::agent ==>
            exists|k: int, i: int| 0 <= k < self.searches.len()
                && selected(self.searches[k], i)
                && pushable(self.searches, k, i)
                && self.searches[k].base == self.trunk[t - 1]
                && at(self.searches[k], i).commit == self.trunk[t]
    }

    // ── proofs ──────────────────────────────────────────

    #[inductive(initialize)]
    fn initialize_inductive(post: Self, root: Commit, checks: Set<Path>, tests: Set<Path>, limit: nat) {}

    #[inductive(advance)]
    fn advance_inductive(pre: Self, post: Self, c: Commit, checks: Set<Path>, tests: Set<Path>) {}

    #[inductive(grant)]
    fn grant_inductive(pre: Self, post: Self, kind: Kind, n: nat, l: nat, observed: Map<Object, Permission>) {
        let k = pre.searches.len() as int;
        let ps = agent_processes(k, n);
        // Every earlier search is complete, so no capability is outstanding.
        assert(pre.capability.dom() =~= Set::empty()) by {
            assert forall|p: AgentProcess| !pre.capability.contains_key(p) by {
                if pre.capability.contains_key(p) {
                    assert(complete(pre.searches[p.search]));
                }
            }
        }
        // The new capabilities are exactly the new search's n agent processes.
        assert(ps.no_duplicates());
        ps.unique_seq_to_set();
        assert(post.capability.dom() =~= ps.to_set());
        assert forall|i: int| 0 <= i < n implies
            #[trigger] post.capability.contains_key(AgentProcess { search: k, index: i }) by {
            assert(ps[i] == AgentProcess { search: k, index: i });
            assert(ps.contains(AgentProcess { search: k, index: i }));
        }
        assert forall|p: AgentProcess| #[trigger] post.capability.contains_key(p) implies
            p.search == k && 0 <= p.index < n by {
            assert(ps.to_set().contains(p));
            assert(ps.contains(p));
        }
        assert(post.reserved == post.searches.last().limit * post.capability.dom().len()) by(nonlinear_arith)
            requires post.reserved == l * n, post.searches.last().limit == l, post.capability.dom().len() == n;
        // Earlier searches are unchanged, so their witnesses still hold.
        assert forall|t: int| 1 <= t < post.trunk.len() && post.authors[t] == User::agent implies
            exists|kk: int, ii: int| 0 <= kk < post.searches.len()
                && selected(post.searches[kk], ii)
                && pushable(post.searches, kk, ii)
                && post.searches[kk].base == post.trunk[t - 1]
                && at(post.searches[kk], ii).commit == post.trunk[t] by {
            let (kk, ii) = choose|kk: int, ii: int| 0 <= kk < pre.searches.len()
                && selected(pre.searches[kk], ii)
                && pushable(pre.searches, kk, ii)
                && pre.searches[kk].base == pre.trunk[t - 1]
                && at(pre.searches[kk], ii).commit == pre.trunk[t];
            assert(post.searches[kk] == pre.searches[kk]);
            let x = choose|x: int| 0 <= x < pre.searches.len()
                && pre.searches[x].kind == (Kind::Counterexample { goal: Some(AgentProcess { search: kk, index: ii }) })
                && not_found(pre.searches[x], pre.searches[kk]);
            assert(post.searches[x] == pre.searches[x]);
            assert(pushable(post.searches, kk, ii));
        }
    }

    #[inductive(wait)]
    fn wait_inductive(pre: Self, post: Self, p: AgentProcess, cap: Capability, result: Option<Candidate>, generation: nat) {
        broadcast use vstd::set::lemma_set_remove_len;
        assert(pre.capability.contains_key(p) && pre.capability[p] == cap);
        // Settling: one capability fewer, its limit released, its generation spent.
        assert(post.capability.dom() =~= pre.capability.dom().remove(p));
        assert(post.capability.dom().len() + 1 == pre.capability.dom().len());
        let m = pre.searches.last().limit;
        let d = pre.capability.dom().len();
        assert(m * d == m * (d - 1) + m) by(nonlinear_arith) requires d >= 1;
        assert(post.searches.last().limit == m);
        // The returned candidate, if any, has the capability's base, which is the search's.
        assert forall|kk: int, ii: int| 0 <= kk < post.searches.len()
            && post.searches[kk].results.contains_key(ii) && post.searches[kk].results[ii] is Some
            implies #[trigger] at(post.searches[kk], ii).base == post.searches[kk].base by {
            if kk == p.search && ii == p.index {
                assert(post.searches[kk].results[ii] == result);
                assert(cap.base == pre.searches[kk].base);
                assert(post.searches[kk].base == pre.searches[kk].base);
                assert(at(post.searches[kk], ii) == result->Some_0);
            } else if kk == p.search {
                assert(post.searches[kk].results[ii] == pre.searches[kk].results[ii]);
                assert(post.searches[kk].base == pre.searches[kk].base);
                assert(at(post.searches[kk], ii) == at(pre.searches[kk], ii));
            } else {
                assert(post.searches[kk] == pre.searches[kk]);
            }
        }
        // Selected searches, and searches that found no counterexample, are complete, so they hold no capability:
        // the one waited on here belongs to neither.
        assert forall|t: int| 1 <= t < post.trunk.len() && post.authors[t] == User::agent implies
            exists|kk: int, ii: int| 0 <= kk < post.searches.len()
                && selected(post.searches[kk], ii)
                && pushable(post.searches, kk, ii)
                && post.searches[kk].base == post.trunk[t - 1]
                && at(post.searches[kk], ii).commit == post.trunk[t] by {
            let (kk, ii) = choose|kk: int, ii: int| 0 <= kk < pre.searches.len()
                && selected(pre.searches[kk], ii)
                && pushable(pre.searches, kk, ii)
                && pre.searches[kk].base == pre.trunk[t - 1]
                && at(pre.searches[kk], ii).commit == pre.trunk[t];
            assert(complete(pre.searches[kk]));
            assert(kk != p.search);
            assert(post.searches[kk] == pre.searches[kk]);
            let x = choose|x: int| 0 <= x < pre.searches.len()
                && pre.searches[x].kind == (Kind::Counterexample { goal: Some(AgentProcess { search: kk, index: ii }) })
                && not_found(pre.searches[x], pre.searches[kk]);
            assert(complete(pre.searches[x]));
            assert(x != p.search);
            assert(post.searches[x] == pre.searches[x]);
            assert(pushable(post.searches, kk, ii));
        }
    }

    #[inductive(push)]
    fn push_inductive(pre: Self, post: Self, k: int, i: int, x: int) {
        assert(pushable(post.searches, k, i));
    }
}}
