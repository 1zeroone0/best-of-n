//! bon's spec: types, predicates, then the state machine (state, init,
//! transitions, properties, invariants, proofs). Every term is from OSTEP,
//! object capabilities, Verus or Rust, or a TCB component's own terms (git,
//! WebVTT); bon's own nouns are intent, map, candidate, check, search and
//! proposal.

use vstd::prelude::*;
use verus_state_machines_macros::tokenized_state_machine;

verus! {

// ── types ───────────────────────────────────────────────

/// A git commit, by its hash. (TCB: git)
pub type Commit = Seq<char>;

/// A path in a commit's tree, as git reports it. (TCB: git)
pub type Path = Seq<char>;

/// A WebVTT cue, by its start time in milliseconds. (TCB: WebVTT)
pub type Cue = nat;

/// A POSIX user. Names match the users on this machine. Also a commit's git author.
#[allow(non_camel_case_types)]
pub enum User { engineer, agent }

/// The files the policy covers. A directory is a file (OSTEP).
pub enum File {
    /// Verus (the spec and proofs) and the tests. Owner: engineer.
    Checks,
    /// WebVTT files, one per recorded call. Owner: engineer.
    Transcripts,
    /// One per agent process. Owner: agent.
    WorkingDirectory,
    /// The git repository: history and refs. Owner: engineer.
    Repository,
}

/// POSIX permission bits.
pub struct Permission { pub read: bool, pub write: bool, pub execute: bool }

/// What a search is for.
pub enum Kind {
    /// Code for one intent in the map. A selection fast-forwards trunk.
    Code { intent: Seq<char> },
    /// Intents from one transcript. The selection is a proposal to engineer.
    Map { transcript: Path },
}

/// One generated change, as trusted code observed it after its agent process exited.
pub struct Candidate {
    pub commit: Commit,
    pub base: Commit,
    /// Every check exited 0. (TCB: trusted code ran them)
    pub checks_pass: bool,
    /// The paths the diff changed, as git reports them.
    pub changed: Set<Path>,
    /// Code: a hash of each agree check's output, in manifest order.
    pub out: Seq<nat>,
    /// Map: each new intent, by the cue it cites.
    pub intents: Map<Cue, Seq<char>>,
    pub rank: int,
    /// Lines changed against base.
    pub diff: nat,
}

/// A process running as agent that writes one candidate: index `index` of the
/// n in search `search`. (OSTEP: process)
pub struct AgentProcess { pub search: int, pub index: int }

/// The authority an agent process holds to write one candidate.
pub struct Capability {
    pub base: Commit,
    /// The paths this capability may change, attenuated by the search's kind at grant.
    pub authority: ISet<Path>,
}

/// One search: n agent processes from one base.
pub struct Search {
    pub kind: Kind,
    pub base: Commit,
    pub n: nat,
    /// The authority every capability of this search carries.
    pub authority: ISet<Path>,
    /// index -> what that agent process returned; None if it produced no candidate.
    pub results: Map<int, Option<Candidate>>,
}

// ── predicates ──────────────────────────────────────────

/// The map's path.
pub open spec fn map_path() -> Path { seq!['m', 'a', 'p'] }

/// The manifest's path. It declares the checks, so it is protected like them.
pub open spec fn manifest_path() -> Path { seq!['b', 'o', 'n', '.', 't', 'o', 'm', 'l'] }

/// No candidate may change p: the map, the manifest, or a path under a check.
/// A check path covers itself and every path it is a prefix of.
pub open spec fn protected(checks: Set<Path>, p: Path) -> bool {
    p == map_path() || p == manifest_path()
    || exists|c: Path| checks.contains(c) && c.is_prefix_of(p)
}

/// Attenuation at grant: what a capability for this kind may change. (intents 3, 10)
pub open spec fn authority(kind: Kind, checks: Set<Path>) -> ISet<Path> {
    match kind {
        Kind::Code { .. } => ISet::new(|p: Path| !protected(checks, p)),
        Kind::Map { .. } => ISet::new(|p: Path| p == map_path()),
    }
}

/// Who may do what. (intent 8)
pub open spec fn policy(u: User, f: File) -> Permission {
    match (u, f) {
        (User::agent, File::Checks)           => Permission { read: true,  write: false, execute: true },
        (User::agent, File::Transcripts)      => Permission { read: true,  write: false, execute: false },
        (User::agent, File::WorkingDirectory) => Permission { read: true,  write: true,  execute: true },
        (User::agent, File::Repository)       => Permission { read: false, write: false, execute: false },
        (User::engineer, _)                   => Permission { read: true,  write: true,  execute: true },
    }
}

/// agent's permissions, as trusted code observed them, match the policy. (intent 9)
pub open spec fn isolated(observed: Map<File, Permission>) -> bool {
    forall|f: File| observed.contains_key(f) && observed[f] == policy(User::agent, f)
}

/// The candidate at index i. Meaningful only when one exists.
pub open spec fn at(s: Search, i: int) -> Candidate { s.results[i]->Some_0 }

/// Passed the vertical bottleneck: every check passes, and every changed path
/// is within the search's authority. (intent 3)
pub open spec fn verified(s: Search, c: Candidate) -> bool {
    c.checks_pass && forall|p: Path| c.changed.contains(p) ==> s.authority.contains(p)
}

pub open spec fn verified_at(s: Search, i: int) -> bool {
    0 <= i < s.n && s.results.contains_key(i) && s.results[i] is Some && verified(s, at(s, i))
}

/// Every agent process has returned.
pub open spec fn complete(s: Search) -> bool {
    forall|i: int| 0 <= i < s.n ==> s.results.contains_key(i)
}

/// Code: at least two verified, and every verified pair prints the same. (intent 4)
pub open spec fn agree(s: Search) -> bool {
    complete(s)
    && (exists|i: int, j: int| i != j && verified_at(s, i) && verified_at(s, j))
    && forall|i: int, j: int| verified_at(s, i) && verified_at(s, j) ==> at(s, i).out == at(s, j).out
}

/// a at index ai outranks b at index bi: rank, then smaller diff, then earlier. (intent 5)
pub open spec fn beats(a: Candidate, ai: int, b: Candidate, bi: int) -> bool {
    a.rank > b.rank || (a.rank == b.rank && (a.diff < b.diff || (a.diff == b.diff && ai < bi)))
}

/// Code: index i is selected. (intents 4, 5)
pub open spec fn selected(s: Search, i: int) -> bool {
    s.kind is Code && agree(s) && verified_at(s, i)
    && forall|j: int| j != i && verified_at(s, j) ==> beats(at(s, i), i, at(s, j), j)
}

/// Map: verified candidate i cites cue q.
pub open spec fn cites(s: Search, i: int, q: Cue) -> bool {
    verified_at(s, i) && at(s, i).intents.contains_key(q)
}

/// Map: at least two verified candidates cite q. (intent 10)
pub open spec fn agreed(s: Search, q: Cue) -> bool {
    complete(s) && exists|i: int, j: int| i != j && cites(s, i, q) && cites(s, j, q)
}

/// Map: exactly one verified candidate cites q. Shown to engineer apart from the proposal.
pub open spec fn contested(s: Search, q: Cue) -> bool {
    complete(s) && (exists|i: int| cites(s, i, q))
    && forall|i: int, j: int| cites(s, i, q) && cites(s, j, q) ==> i == j
}

/// Map: w is the proposal's wording for q: the shortest among the citing
/// candidates, ties to the earliest. (intent 10)
pub open spec fn proposed(s: Search, q: Cue, w: Seq<char>) -> bool {
    s.kind is Map && agreed(s, q)
    && exists|i: int| cites(s, i, q) && at(s, i).intents[q] == w
        && forall|j: int| cites(s, j, q) ==>
            w.len() < at(s, j).intents[q].len() || (w.len() == at(s, j).intents[q].len() && i <= j)
}

/// The agent processes of search k: one per index.
pub open spec fn agent_processes(k: int, n: nat) -> Seq<AgentProcess> {
    Seq::new(n, |i: int| AgentProcess { search: k, index: i })
}

/// The capabilities grant adds: one per agent process, all with the search's authority.
pub open spec fn granted(k: int, n: nat, base: Commit, a: ISet<Path>) -> Map<AgentProcess, Capability> {
    Map::new(agent_processes(k, n).to_set(), |p: AgentProcess| Capability { base, authority: a })
}

} // verus!

tokenized_state_machine!{ bon {

    // ── state ───────────────────────────────────────────
    fields {
        /// The current intents: the map at trunk's head. (intent 1)
        #[sharding(variable)] pub map: Set<Seq<char>>,
        /// The check paths the manifest declares at trunk's head.
        #[sharding(variable)] pub checks: Set<Path>,
        /// Trunk's history; last() is the head.
        #[sharding(variable)] pub trunk: Seq<Commit>,
        /// The git author of each trunk commit, in step with trunk.
        #[sharding(variable)] pub authors: Seq<User>,
        #[sharding(variable)] pub searches: Seq<Search>,
        /// Outstanding capabilities, keyed by the agent process that holds each.
        /// Each is a Verus token: the token is how Verus represents a capability;
        /// capability is the term. An agent process holds exactly one, and waiting
        /// on it consumes it. (intent 7)
        #[sharding(map)] pub capability: Map<AgentProcess, Capability>,
    }

    // ── init ────────────────────────────────────────────
    init!{ initialize(root: Commit, intents: Set<Seq<char>>, checks: Set<Path>) {
        init map = intents;
        init checks = checks;
        init trunk = Seq::empty().push(root);
        init authors = Seq::empty().push(User::engineer);
        init searches = Seq::empty();
        init capability = Map::empty();
    }}

    // ── transitions ─────────────────────────────────────

    /// engineer committed to trunk, e.g. the map or the checks. (intent 6)
    transition!{ advance(c: Commit, intents: Set<Seq<char>>, checks: Set<Path>) {
        update map = intents;
        update checks = checks;
        update trunk = pre.trunk.push(c);
        update authors = pre.authors.push(User::engineer);
    }}

    /// Open a search and grant one capability per agent process. (intents 2, 7, 9, 10)
    transition!{ grant(kind: Kind, n: nat, observed: Map<File, Permission>) {
        require kind matches Kind::Code { intent } ==> pre.map.contains(intent);
        require isolated(observed);
        let k = pre.searches.len() as int;
        let base = pre.trunk.last();
        let a = authority(kind, pre.checks);
        update searches = pre.searches.push(Search { kind, base, n, authority: a, results: Map::empty() });
        add capability += (granted(k, n, base, a));
    }}

    /// The bon process waits on an agent process and records what it returned,
    /// consuming its capability. (OSTEP: wait) (intents 2, 7)
    transition!{ wait(p: AgentProcess, cap: Capability, result: Option<Candidate>) {
        remove capability -= [p => cap];
        require result matches Some(c) ==> c.base == cap.base;
        let s = pre.searches[p.search];
        update searches = pre.searches.update(p.search,
            Search { results: s.results.insert(p.index, result), ..s });
    }}

    /// Code: trunk fast-forwards to the selected candidate, if trunk hasn't moved. (intent 6)
    transition!{ fast_forward(k: int, i: int) {
        require 0 <= k < pre.searches.len();
        require selected(pre.searches[k], i);
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

    /// Each capability is held by an agent process for one open index of one
    /// search, with that search's base and authority. (intent 7)
    #[invariant]
    pub fn capability_open(&self) -> bool {
        forall|p: AgentProcess| #[trigger] self.capability.contains_key(p) ==> {
            let c = self.capability[p];
            0 <= p.search < self.searches.len()
            && 0 <= p.index < self.searches[p.search].n
            && !self.searches[p.search].results.contains_key(p.index)
            && c.base == self.searches[p.search].base
            && c.authority == self.searches[p.search].authority
        }
    }

    /// Every agent process of every search has either returned or still holds its capability.
    #[invariant]
    pub fn accounted(&self) -> bool {
        forall|k: int, i: int| 0 <= k < self.searches.len() && 0 <= i < self.searches[k].n
            ==> self.searches[k].results.contains_key(i)
                || self.capability.contains_key(AgentProcess { search: k, index: i })
    }

    /// Candidates of a search are siblings of its base. (intent 2)
    #[invariant]
    pub fn siblings(&self) -> bool {
        forall|k: int, i: int| 0 <= k < self.searches.len()
            && self.searches[k].results.contains_key(i) && self.searches[k].results[i] is Some
            ==> at(self.searches[k], i).base == self.searches[k].base
    }

    /// Every trunk commit authored by agent is exactly the selected candidate of a
    /// code search on the previous head. (intents 3–6)
    #[invariant]
    pub fn trunk_exact(&self) -> bool {
        forall|t: int| 1 <= t < self.trunk.len() && self.authors[t] == User::agent ==>
            exists|k: int, i: int| 0 <= k < self.searches.len()
                && selected(self.searches[k], i)
                && self.searches[k].base == self.trunk[t - 1]
                && at(self.searches[k], i).commit == self.trunk[t]
    }

    // ── proofs ──────────────────────────────────────────

    #[inductive(initialize)]
    fn initialize_inductive(post: Self, root: Commit, intents: Set<Seq<char>>, checks: Set<Path>) {}

    #[inductive(advance)]
    fn advance_inductive(pre: Self, post: Self, c: Commit, intents: Set<Seq<char>>, checks: Set<Path>) {}

    #[inductive(grant)]
    fn grant_inductive(pre: Self, post: Self, kind: Kind, n: nat, observed: Map<File, Permission>) {
        let k = pre.searches.len() as int;
        let ps = agent_processes(k, n);
        // Each agent process of the new search holds a capability.
        assert forall|i: int| 0 <= i < n implies
            #[trigger] post.capability.contains_key(AgentProcess { search: k, index: i }) by {
            assert(ps[i] == AgentProcess { search: k, index: i });
            assert(ps.contains(AgentProcess { search: k, index: i }));
        }
        // Earlier searches are unchanged, so their witnesses still hold.
        assert forall|t: int| 1 <= t < post.trunk.len() && post.authors[t] == User::agent implies
            exists|kk: int, ii: int| 0 <= kk < post.searches.len()
                && selected(post.searches[kk], ii)
                && post.searches[kk].base == post.trunk[t - 1]
                && at(post.searches[kk], ii).commit == post.trunk[t] by {
            let (kk, ii) = choose|kk: int, ii: int| 0 <= kk < pre.searches.len()
                && selected(pre.searches[kk], ii)
                && pre.searches[kk].base == pre.trunk[t - 1]
                && at(pre.searches[kk], ii).commit == pre.trunk[t];
            assert(post.searches[kk] == pre.searches[kk]);
        }
    }

    #[inductive(wait)]
    fn wait_inductive(pre: Self, post: Self, p: AgentProcess, cap: Capability, result: Option<Candidate>) {
        assert(pre.capability.contains_key(p) && pre.capability[p] == cap);
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
        // A selected search is complete, so it holds no capability: the one
        // waited on here belongs to a search that is not selected.
        assert forall|t: int| 1 <= t < post.trunk.len() && post.authors[t] == User::agent implies
            exists|kk: int, ii: int| 0 <= kk < post.searches.len()
                && selected(post.searches[kk], ii)
                && post.searches[kk].base == post.trunk[t - 1]
                && at(post.searches[kk], ii).commit == post.trunk[t] by {
            let (kk, ii) = choose|kk: int, ii: int| 0 <= kk < pre.searches.len()
                && selected(pre.searches[kk], ii)
                && pre.searches[kk].base == pre.trunk[t - 1]
                && at(pre.searches[kk], ii).commit == pre.trunk[t];
            assert(complete(pre.searches[kk]));
            assert(kk != p.search);
            assert(post.searches[kk] == pre.searches[kk]);
        }
    }

    #[inductive(fast_forward)]
    fn fast_forward_inductive(pre: Self, post: Self, k: int, i: int) {}
}}
