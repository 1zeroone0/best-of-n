//! The bon process: the drivers that hold the tokens and pass every decision
//! through a gate.

use vstd::prelude::*;
use crate::spec;
use crate::gates::*;
use crate::exec::*;
use crate::trusted;

verus! {

broadcast use {vstd::seq_lib::group_seq_properties, vstd::seq::group_seq_axioms};

/// The tokens the bon process holds: one per field of the state machine.
pub struct Tokens {
    pub instance: spec::bon::Instance,
    pub checks: spec::bon::checks,
    pub tests: spec::bon::tests,
    pub trusted: spec::bon::trusted,
    pub trunk: spec::bon::trunk,
    pub authors: spec::bon::authors,
    pub searches: spec::bon::searches,
    pub limit: spec::bon::limit,
    pub spent: spec::bon::spent,
    pub reserved: spec::bon::reserved,
    pub generation: spec::bon::generation,
}

impl Tokens {
    pub open spec fn wf(&self) -> bool {
        &&& self.checks.instance_id() == self.instance.id()
        &&& self.tests.instance_id() == self.instance.id()
        &&& self.trusted.instance_id() == self.instance.id()
        &&& self.trunk.instance_id() == self.instance.id()
        &&& self.authors.instance_id() == self.instance.id()
        &&& self.searches.instance_id() == self.instance.id()
        &&& self.limit.instance_id() == self.instance.id()
        &&& self.spent.instance_id() == self.instance.id()
        &&& self.generation.instance_id() == self.instance.id()
        &&& self.reserved.instance_id() == self.instance.id()
    }
}

/// What agent process i returned, as the spec sees it.
pub open spec fn returned(r: Option<Candidate>) -> Option<spec::Candidate> {
    match r { Some(c) => Some(c@), None => None }
}

/// Copy paths while preserving their spec values.
fn clone_paths(paths: &Vec<Path>) -> (r: Vec<Path>)
    ensures r@.map_values(|p: Path| p@) == paths@.map_values(|p: Path| p@),
{
    let mut r: Vec<Path> = Vec::new();
    let mut i = 0;
    while i < paths.len()
        invariant 0 <= i <= paths.len(), r.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j]@ == paths@[j]@,
        decreases paths.len() - i,
    {
        r.push(Path(paths[i].0.clone()));
        i += 1;
    }
    assert(r@.map_values(|p: Path| p@) =~= paths@.map_values(|p: Path| p@));
    r
}

/// No commit: the context of a search that carries none.
fn none() -> (r: Vec<Commit>)
    ensures commits(r@) == Set::<spec::Commit>::empty(),
{
    let r: Vec<Commit> = Vec::new();
    proof { assert(commits(r@) =~= Set::<spec::Commit>::empty()); }
    r
}

/// earlier is a search kind with kind's goal, of the same kind: what kind
/// may carry the candidates of (spec::carries).
pub open spec fn same_goal(earlier: spec::Kind, kind: spec::Kind) -> bool {
    match kind {
        spec::Kind::Code { goal } => earlier == (spec::Kind::Code { goal }),
        spec::Kind::Compaction { goal, .. } => earlier matches spec::Kind::Compaction { goal: other, .. } && other == goal,
        spec::Kind::Spec { goal, .. } => earlier matches spec::Kind::Spec { goal: other, .. } && other == goal,
        _ => false,
    }
}

/// commit is a code search's goal, or a candidate of previous, a search of
/// kind's kind on its goal.
pub open spec fn carried_from(kind: spec::Kind, previous: Option<&Search>, commit: spec::Commit) -> bool {
    (kind matches spec::Kind::Code { goal } && commit == goal)
    || (previous matches Some(p) && spec::candidate_commit(p@, commit) && same_goal(p@.kind, kind))
}

/// What carried returns, the kind may carry, previous being the search at
/// previous_index.
proof fn carried_carries(searches: Seq<spec::Search>, kind: spec::Kind, previous: Option<&Search>, previous_index: int, commit: spec::Commit)
    requires
        carried_from(kind, previous, commit),
        previous matches Some(p) ==> 0 <= previous_index < searches.len() && searches[previous_index] == p@,
    ensures spec::carries(searches, kind, commit),
{
    if !(kind matches spec::Kind::Code { goal } && commit == goal) {
        let p = previous->Some_0;
        assert(searches[previous_index] == p@);
        match kind {
            spec::Kind::Code { goal } => {
                assert(0 <= previous_index < searches.len() && searches[previous_index].kind == (spec::Kind::Code { goal })
                    && spec::candidate_commit(searches[previous_index], commit));
            }
            spec::Kind::Compaction { goal, .. } => {
                assert(0 <= previous_index < searches.len()
                    && (searches[previous_index].kind matches spec::Kind::Compaction { goal: other, .. } && other == goal)
                    && spec::candidate_commit(searches[previous_index], commit));
            }
            spec::Kind::Spec { goal, .. } => {
                assert(0 <= previous_index < searches.len()
                    && (searches[previous_index].kind matches spec::Kind::Spec { goal: other, .. } && other == goal)
                    && spec::candidate_commit(searches[previous_index], commit));
            }
            _ => {}
        }
    }
}

/// Exec: previous has kind's goal, of kind's kind.
fn has_same_goal(earlier: &Kind, kind: &Kind) -> (r: bool)
    ensures r ==> same_goal(earlier@, kind@),
{
    match (earlier, kind) {
        (Kind::Code { goal: a }, Kind::Code { goal: b }) => eq(&a.0, &b.0),
        (Kind::Compaction { goal: a, .. }, Kind::Compaction { goal: b, .. }) => eq(&a.0, &b.0),
        (Kind::Spec { goal: a, .. }, Kind::Spec { goal: b, .. }) => eq(&a.0, &b.0),
        _ => false,
    }
}

/// What an attempt of kind carries: a code search, its goal (its checks
/// reject it); and every unverified candidate of the previous attempt's
/// search, when that search was of this kind on this goal.
fn carried(kind: &Kind, previous: Option<&Search>) -> (r: Vec<Commit>)
    ensures forall|commit: spec::Commit| #[trigger] commits(r@).contains(commit) ==> carried_from(kind@, previous, commit),
{
    let mut r: Vec<Commit> = Vec::new();
    if let Kind::Code { goal } = kind {
        r.push(Commit(goal.0.clone()));
        proof { assert(r@[0]@ == goal@); }
    }
    assert(forall|j: int| 0 <= j < r.len() ==> carried_from(kind@, previous, #[trigger] r@[j]@));
    if let Some(p) = previous {
        if has_same_goal(&p.kind, kind) {
            let mut i = 0;
            while i < p.results.len()
                invariant
                    0 <= i <= p.results.len(), previous == Some(p), same_goal(p@.kind, kind@),
                    forall|j: int| 0 <= j < r.len() ==> carried_from(kind@, previous, #[trigger] r@[j]@),
                decreases p.results.len() - i,
            {
                if let Some(c) = &p.results[i] {
                    if !verified(p, c) {
                        proof {
                            assert(p@.results.contains_key(i as int) && p@.results[i as int] == Some(c@));
                            assert(spec::at(p@, i as int).commit == c.commit@);
                            assert(spec::candidate_commit(p@, c.commit@));
                            assert(carried_from(kind@, previous, c.commit@));
                        }
                        let ghost before = r@;
                        r.push(Commit(c.commit.0.clone()));
                        proof { assert(forall|j: int| 0 <= j < before.len() ==> r@[j] == before[j]); }
                    }
                }
                i += 1;
            }
        }
    }
    proof {
        assert forall|commit: spec::Commit| #[trigger] commits(r@).contains(commit) implies carried_from(kind@, previous, commit) by {
            let seen = r@.map_values(|c: Commit| c@);
            let j = choose|j: int| 0 <= j < seen.len() && #[trigger] seen[j] == commit;
            assert(seen[j] == r@[j]@);
        }
    }
    r
}

/// One search: grant a capability per agent process, run them, and wait on
/// each, consuming its capability.
#[verifier::spinoff_prover]
// index is read only by the contract, which cargo erases.
#[allow(unused_variables)]
fn search(
    m: &trusted::Manifest, index: usize, a: usize, kind: Kind, start: Commit, checks: &Vec<Path>, tests: &Vec<Path>, trusted: &Vec<Path>,
    l: u64, limit: u64, spent: &mut u64, target: Option<&Search>, foils: Option<&Search>, context: Vec<Commit>,
    Ghost(checks_accept): Ghost<bool>, Ghost(observed): Ghost<IMap<(User, Object), Seq<Option<Permission>>>>, Ghost(slots): Ghost<nat>, Tracked(t): Tracked<&mut Tokens>,
) -> (r: Result<Search, String>)
    requires
        old(t).wf(),
        index as int == old(t).searches.value().len(),
        kind@ is Code ==> !checks_accept,
        kind@ is Compaction || kind@ == (spec::Kind::Counterexample { goal: None }) ==> checks_accept,
        spec::isolated(observed, slots),
        forall|k: int| 0 <= k < old(t).searches.value().len() ==> spec::complete(#[trigger] old(t).searches.value()[k]),
        old(t).checks.value() == paths(checks@),
        old(t).tests.value() == paths(tests@),
        old(t).trusted.value() == paths(trusted@),
        old(t).limit.value() == limit as nat,
        old(t).spent.value() == *old(spent) as nat,
        old(t).reserved.value() == 0,
        forall|commit: spec::Commit| #[trigger] commits(context@).contains(commit) ==> spec::carries(old(t).searches.value(), kind@, commit),
        start@ == match kind@ {
            spec::Kind::Foil { goal, .. } => spec::at(old(t).searches.value()[goal.search], goal.index).commit,
            _ => old(t).trunk.value().last(),
        },
        kind@ matches spec::Kind::Code { goal } ==> goal == old(t).trunk.value().last(),
        kind@ matches spec::Kind::Compaction { goal, .. } ==> goal == old(t).trunk.value().last(),
        kind@ matches spec::Kind::Counterexample { goal: Some(p) } ==>
            0 <= p.search < old(t).searches.value().len()
            && (spec::selected(old(t).searches.value()[p.search], p.index)
                || (spec::disagree(old(t).searches.value()[p.search]) && spec::first_verified(old(t).searches.value()[p.search]) == Some(p.index)))
            && old(t).searches.value()[p.search].base == old(t).trunk.value().last(),
        kind@ matches spec::Kind::Foil { goal: p, changed } ==>
            0 <= p.search < old(t).searches.value().len()
            && spec::selected(old(t).searches.value()[p.search], p.index)
            && old(t).searches.value()[p.search].base == old(t).trunk.value().last()
            && changed == spec::at(old(t).searches.value()[p.search], p.index).changed,
    ensures
        final(t).wf(),
        final(t).instance == old(t).instance,
        final(t).checks.value() == old(t).checks.value(),
        final(t).tests.value() == old(t).tests.value(),
        final(t).trusted.value() == old(t).trusted.value(),
        final(t).trunk.value() == old(t).trunk.value(),
        final(t).authors.value() == old(t).authors.value(),
        final(t).limit.value() == old(t).limit.value(),
        r matches Ok(s) ==> {
            &&& s.results.len() == s.n
            &&& s@.kind == kind@
            &&& s@.base == start@
            &&& final(t).searches.value() == old(t).searches.value().push(s@)
            &&& spec::complete(s@)
            &&& final(t).reserved.value() == 0
            &&& final(t).spent.value() == *final(spent) as nat
        },
{
    let n = trusted::width(m, &kind, a);
    let reserve = match l.checked_mul(n as u64) { Some(x) => x, None => { return Err("limit overflow".into()); } };
    if reserve > limit || *spent > limit - reserve {
        return Err("the search would pass the bon process's limit".into());
    }
    let ghost k = t.searches.value().len() as int;
    let ghost before = t.searches.value();
    let tracked mut capability = t.instance.grant(kind@, n as nat, l as nat, observed, slots, checks_accept, commits(context@),
        &t.checks, &t.tests, &t.trusted, &t.trunk, &mut t.searches, &t.limit, &t.spent, &mut t.reserved);
    trusted::record_grant(m, &kind, n, l, &context, Ghost(checks_accept), Ghost(t.searches.value()));
    let started = trusted::clock();
    let spent_before = *spent;
    let mut results = trusted::run(m, &kind, a, &start, target, foils, &context);
    if results.len() != n {
        return Err("trusted code returned the wrong number of agent processes".into());
    }
    let mut s = Search { kind, base: start, n, checks: clone_paths(checks), tests: clone_paths(tests), trusted: clone_paths(trusted), limit: l, results: Vec::new(), context };
    proof {
        assert(s.checks@.map_values(|p: Path| p@) =~= checks@.map_values(|p: Path| p@));
        assert(s.tests@.map_values(|p: Path| p@) =~= tests@.map_values(|p: Path| p@));
        assert(s.trusted@.map_values(|p: Path| p@) =~= trusted@.map_values(|p: Path| p@));
        assert(s@.results =~= Map::empty());
        assert(s@.authority == spec::authority(kind@, paths(checks@), paths(tests@), paths(trusted@)));
        assert(t.searches.value()[k] == s@);
        let ps = spec::agent_processes(k, n as nat);
        assert forall|j: int| 0 <= j < n implies #[trigger] capability.dom().contains(spec::AgentProcess { search: k, index: j }) by {
            assert(ps[j] == spec::AgentProcess { search: k, index: j });
            assert(ps.contains(spec::AgentProcess { search: k, index: j }));
        }
    }
    let mut i: usize = 0;
    while i < n
        invariant
            t.wf(), t.instance == old(t).instance,
            t.checks.value() == old(t).checks.value(), t.tests.value() == old(t).tests.value(), t.trusted.value() == old(t).trusted.value(),
            t.trunk.value() == old(t).trunk.value(), t.authors.value() == old(t).authors.value(),
            t.limit.value() == old(t).limit.value(),
            capability.instance_id() == t.instance.id(),
            k == before.len(), k == index as int, t.searches.value().len() == k + 1,
            t.searches.value().take(k) == before,
            t.searches.value()[k] == s@,
            s.n == n, s.results.len() == i, i <= n, results.len() == n - i, s@.kind == kind@,
            s.base@ == start@, s.limit == l,
            s@.authority == spec::authority(kind@, paths(checks@), paths(tests@), paths(trusted@)),
            forall|j: int| i <= j < n ==> #[trigger] capability.dom().contains(spec::AgentProcess { search: k, index: j })
                && capability[spec::AgentProcess { search: k, index: j }] == (spec::Capability {
                    base: start@, authority: s@.authority, limit: l as nat }),
            t.reserved.value() == l as nat * (n - i) as nat,
            t.spent.value() == *spent as nat,
            *spent as nat + l as nat * (n - i) as nat <= limit as nat,
        decreases n - i,
    {
        let (r, measured) = results.remove(0);
        // A program that cannot be stopped mid-turn (codex) may overrun its limit;
        // it is charged at its limit and the overrun is in its facts.json. (TCB)
        let generation = if measured > l { trusted::record_over_limit(m); l } else { measured };
        match &r {
            Some(c) => { if !eq(&c.base.0, &s.base.0) { return Err("a candidate does not start from its base".into()); } }
            None => {}
        }
        let ghost p = spec::AgentProcess { search: k, index: i as int };
        proof {
            assert(capability.dom().contains(spec::AgentProcess { search: k, index: i as int }));
            assert(capability.dom().contains(p) && capability[p].limit == l as nat);
            let tracked cap = capability.remove(p);
            assert(cap.value().limit == l as nat);
            assert(l as nat * (n - i) as nat == l as nat * (n - i - 1) as nat + l as nat) by(nonlinear_arith)
                requires i < n;
            t.instance.wait(p, cap.value(), returned(r), measured as nat, &mut t.searches, &mut t.spent, &mut t.reserved, &mut t.generation, cap);
            assert(t.reserved.value() == l as nat * (n - (i + 1)) as nat);
        }
        let ghost old_s = s@;
        s.results.push(r);
        *spent = *spent + generation;
        proof {
            assert(s@.results =~= old_s.results.insert(i as int, returned(r)));
            assert(s@.authority == spec::authority(s.kind@, paths(s.checks@), paths(s.tests@), paths(s.trusted@)));
            assert(old_s.authority == spec::authority(s.kind@, paths(s.checks@), paths(s.tests@), paths(s.trusted@)));
            assert(s@.authority == old_s.authority);
            assert(t.searches.value()[k] =~= s@);
            assert(t.searches.value().take(k) =~= before);
            assert forall|j: int| i + 1 <= j < n implies #[trigger] capability.dom().contains(spec::AgentProcess { search: k, index: j })
                && capability[spec::AgentProcess { search: k, index: j }] == (spec::Capability {
                    base: start@, authority: s@.authority, limit: l as nat }) by {
                assert(spec::AgentProcess { search: k, index: j } != p);
            }
        }
        trusted::record_wait(m, index, i, &s.results[i], measured, Ghost(t.searches.value()));
        // Restated here so the solver carries it across the trusted call to the invariant.
        proof {
            assert(forall|j: int| i + 1 <= j < n ==> #[trigger] capability.dom().contains(spec::AgentProcess { search: k, index: j })
                && capability[spec::AgentProcess { search: k, index: j }] == (spec::Capability {
                    base: start@, authority: s@.authority, limit: l as nat }));
        }
        let ghost next = i + 1;
        let ghost held = capability;
        let ghost authority = s@.authority;
        i += 1;
        proof {
            assert forall|j: int| i <= j < n implies #[trigger] capability.dom().contains(spec::AgentProcess { search: k, index: j })
                && capability[spec::AgentProcess { search: k, index: j }] == (spec::Capability {
                    base: start@, authority: s@.authority, limit: l as nat }) by {
                assert(next <= j < n);
                assert(held.dom().contains(spec::AgentProcess { search: k, index: j }));
                assert(held[spec::AgentProcess { search: k, index: j }] == (spec::Capability {
                    base: start@, authority, limit: l as nat }));
            }
        }
    }
    proof {
        assert(s.results.len() == s.n);
        assert(t.searches.value() =~= before.push(s@));
        assert forall|j: int| 0 <= j < s.n implies s@.results.contains_key(j) by {}
        assert(spec::complete(s@));
        assert(t.reserved.value() == 0) by(nonlinear_arith) requires t.reserved.value() == l as nat * (n - n) as nat;
    }
    let v = verified_each(&s);
    let mut verified: usize = 0;
    let mut j = 0;
    while j < v.len()
        invariant 0 <= j <= v.len(), verified <= j,
        decreases v.len() - j,
    {
        if v[j] { verified = verified + 1; }
        j += 1;
    }
    let generation = if *spent >= spent_before { *spent - spent_before } else { 0 };
    trusted::report(m, &s, verified, generation, started);
    Ok(s)
}

/// Every search so far is complete.
pub open spec fn all_complete(searches: Seq<spec::Search>) -> bool {
    forall|k: int| 0 <= k < searches.len() ==> spec::complete(#[trigger] searches[k])
}

/// A complete search pushed onto complete searches leaves them complete.
proof fn all_complete_push(before: Seq<spec::Search>, after: Seq<spec::Search>, s: spec::Search)
    requires all_complete(before), spec::complete(s), after == before.push(s),
    ensures all_complete(after),
{
    assert forall|k: int| 0 <= k < after.len() implies spec::complete(#[trigger] after[k]) by {
        if k < before.len() { assert(after[k] == before[k]); }
    }
}

/// after holds every search of before, unchanged, and maybe more.
pub open spec fn extends(before: Seq<spec::Search>, after: Seq<spec::Search>) -> bool {
    before.len() <= after.len() && forall|k: int| 0 <= k < before.len() ==> after[k] == before[k]
}

/// What holds between to_push's attempts: no search is running, every search
/// so far is complete, and trunk's head is head.
pub open spec fn between(t: Tokens, observed: IMap<(User, Object), Seq<Option<Permission>>>, slots: nat, index: int, spent: u64, head: spec::Commit,
    checks: Set<spec::Path>, tests: Set<spec::Path>, trusted: Set<spec::Path>, limit: u64) -> bool {
    &&& t.wf()
    &&& spec::isolated(observed, slots)
    &&& t.searches.value().len() == index
    &&& all_complete(t.searches.value())
    &&& t.reserved.value() == 0
    &&& t.spent.value() == spent as nat
    &&& t.trunk.value().len() >= 1
    &&& t.trunk.value().last() == head
    &&& t.checks.value() == checks
    &&& t.tests.value() == tests
    &&& t.trusted.value() == trusted
    &&& t.limit.value() == limit as nat
}

/// bon code (compaction false) or bon compaction (true). Each attempt is a
/// search and, if it selects, a counterexample search on the selection; the
/// selected candidate is pushed once one clears. If its verified candidates
/// disagree instead, a counterexample search decides between their behaviors. When a test splits the
/// candidates, the best such test lands on trunk, and the next attempt runs
/// wider from that head, until the attempts run out.
pub fn to_push(root: &str, compaction: bool) -> (r: Result<(), String>) {
    hide(spec::isolated);
    let mut head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let checks = trusted::checks(&m);
    let tests = trusted::tests(&m);
    let trusted = trusted::trusted(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let (agent, observations) = trusted::observe(&m, &head)?;
    if !isolated(&agent, &observations) {
        return Err("agent or a check slot's user is not isolated: their permissions differ from the policy; run bon setup".into());
    }
    let ghost observed = observed(agent, observations@);
    let ghost slots = observations.len() as nat;
    let tracked (Tracked(instance), Tracked(checks_t), Tracked(tests_t), Tracked(trusted_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(generation), Tracked(capability))
        = spec::bon::Instance::initialize(head@, paths(checks@), paths(tests@), paths(trusted@), limit as nat);
    let tracked mut t = Tokens { instance, checks: checks_t, tests: tests_t, trusted: trusted_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved, generation };
    let mut spent: u64 = 0;
    trusted::record_initialize(&m, &head, limit);

    let attempts = trusted::attempts(&m);
    let mut a: usize = 0;
    let mut index: usize = 0;
    // The previous attempt's search, which the next carries while trunk stays.
    let mut previous: Option<Search> = None;
    let ghost mut previous_index: int = 0;
    while a < attempts
        invariant
            between(t, observed, slots, index as int, spent, head@, paths(checks@), paths(tests@), paths(trusted@), limit),
            index <= 3 * a,
            previous matches Some(p) ==> 0 <= previous_index < index && t.searches.value()[previous_index] == p@,
        decreases attempts - a,
    {
        if index > usize::MAX - 3 { return Err("too many searches".into()); }
        let ghost before = t.searches.value();
        match attempt(&m, root, compaction, &mut head, a, index, previous.as_ref(), &checks, &tests, &trusted, l, limit, &mut spent,
                      Ghost(previous_index), Ghost(observed), Ghost(slots), Tracked(&mut t))? {
            None => { return Ok(()); }
            Some((next, s0)) => {
                proof { previous_index = index as int; }
                index = next;
                previous = Some(s0);
            }
        }
        a = a + 1;
    }
    Err("blocked: no attempt was selected with no counterexample found; see .bon/traces".into())
}

/// One attempt of to_push: a search from trunk's head and, if it selects, the
/// searches on its selection; if its verified candidates disagree, the
/// counterexample search on it.
/// Ok(None) once the selection is pushed; Ok(Some(next)) to go on, next being
/// the number of searches so far.
fn attempt(
    m: &trusted::Manifest, root: &str, compaction: bool, head: &mut Commit, a: usize, index: usize, previous: Option<&Search>,
    checks: &Vec<Path>, tests: &Vec<Path>, trusted: &Vec<Path>, l: u64, limit: u64, spent: &mut u64,
    Ghost(previous_index): Ghost<int>,
    Ghost(observed): Ghost<IMap<(User, Object), Seq<Option<Permission>>>>, Ghost(slots): Ghost<nat>, Tracked(t): Tracked<&mut Tokens>,
) -> (r: Result<Option<(usize, Search)>, String>)
    requires
        index <= usize::MAX - 3,
        between(*old(t), observed, slots, index as int, *old(spent), old(head)@, paths(checks@), paths(tests@), paths(trusted@), limit),
        previous matches Some(p) ==> 0 <= previous_index < index && old(t).searches.value()[previous_index] == p@,
    ensures
        r matches Ok(Some((next, s0))) ==> next <= index + 3
            && between(*final(t), observed, slots, next as int, *final(spent), final(head)@, paths(checks@), paths(tests@), paths(trusted@), limit)
            && extends(old(t).searches.value(), final(t).searches.value())
            && index < final(t).searches.value().len() && final(t).searches.value()[index as int] == s0@,
{
    hide(spec::isolated);
    hide(spec::verified);
    hide(spec::authority);
    hide(spec::reason);
    hide(spec::blocked);
    hide(spec::complete);
    hide(spec::agree);
    // Code is for a trunk its checks reject; compaction, for one they accept.
    let accepted = trusted::trunk_accepted(m, head);
    if !compaction && accepted { return Err("trunk's checks accept it: there is no code to write".into()); }
    if compaction && !accepted { return Err("trunk's checks reject it: run bon code first".into()); }
    let kind = if compaction {
        Kind::Compaction { goal: Commit(head.0.clone()), out: trusted::agree_outputs(m, head)? }
    } else {
        Kind::Code { goal: Commit(head.0.clone()) }
    };
    // What it carries: the goal's verdicts, and the previous attempt's
    // unverified candidates' when trunk has not moved since.
    let context = carried(&kind, previous);
    let ghost before = t.searches.value();
    proof {
        assert forall|commit: spec::Commit| #[trigger] commits(context@).contains(commit) implies spec::carries(before, kind@, commit) by {
            carried_carries(before, kind@, previous, previous_index, commit);
        }
    }
    let s0 = search(m, index, a, kind, Commit(head.0.clone()), checks, tests, trusted, l, limit, spent, None, None, context,
                    Ghost(accepted), Ghost(observed), Ghost(slots), Tracked(&mut *t))?;
    proof { all_complete_push(before, t.searches.value(), s0@); }
    let ghost pushed = t.searches.value();
    let r = match selected(&s0) {
        None => {
            if let Some(reason) = blocked(&s0, None, None) {
                proof { spec::reason_is_blocked(s0@, None, None, head@); }
                trusted::record_blocked(m, reason, Ghost(s0@), Ghost(s0@), Ghost(s0@), Ghost(head@));
                return Ok(Some((index + 1, s0)));
            }
            // Two verified and no selection: they disagree.
            proof {
                reveal(spec::reason);
                reveal(spec::complete);
            }
            match first_verified(&s0) {
                Some(f) => on_disagreement(m, head, &s0, f, a, index, checks, tests, trusted, l, limit, spent, Ghost(observed), Ghost(slots), Tracked(t)),
                None => vstd::pervasive::unreached(),
            }
        }
        Some(i) => {
            assert(spec::verified_at(s0@, i as int)) by { reveal(spec::selected); }
            on_selection(m, root, head, &s0, i, a, index, checks, tests, trusted, l, limit, spent, Ghost(accepted), Ghost(observed), Ghost(slots), Tracked(t))
        }
    };
    match r {
        Ok(Some(next)) => {
            proof { assert(t.searches.value()[index as int] == pushed[index as int]); }
            Ok(Some((next, s0)))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The rest of an attempt whose search s0, at index, disagrees: a
/// counterexample search on it, its tests built on s0's first verified candidate f,
/// then a landing, or a block. Nothing of s0 is pushed.
fn on_disagreement(
    m: &trusted::Manifest, head: &mut Commit, s0: &Search, f: usize, a: usize, index: usize,
    checks: &Vec<Path>, tests: &Vec<Path>, trusted: &Vec<Path>, l: u64, limit: u64, spent: &mut u64,
    Ghost(observed): Ghost<IMap<(User, Object), Seq<Option<Permission>>>>, Ghost(slots): Ghost<nat>, Tracked(t): Tracked<&mut Tokens>,
) -> (r: Result<Option<usize>, String>)
    requires
        index <= usize::MAX - 3,
        between(*old(t), observed, slots, index as int + 1, *old(spent), old(head)@, paths(checks@), paths(tests@), paths(trusted@), limit),
        old(t).searches.value()[index as int] == s0@,
        s0.results.len() == s0.n,
        s0@.base == old(head)@,
        spec::disagree(s0@),
        spec::first_verified(s0@) == Some(f as int),
    ensures
        r matches Ok(Some(next)) ==> next <= index + 3
            && between(*final(t), observed, slots, next as int, *final(spent), final(head)@, paths(checks@), paths(tests@), paths(trusted@), limit)
            && extends(old(t).searches.value(), final(t).searches.value()),
{
    hide(spec::isolated);
    hide(spec::verified);
    hide(spec::authority);
    hide(spec::reason);
    hide(spec::blocked);
    hide(spec::complete);
    hide(spec::disagree);
    hide(spec::splits);
    hide(spec::beats);
    hide(spec::first_verified);
    trusted::record_disagreed(m, f);
    let ghost before = t.searches.value();
    let s1 = search(m, index + 1, a, Kind::Counterexample { goal: Some(AgentProcess { search: index, index: f }) },
                    Commit(head.0.clone()), checks, tests, trusted, l, limit, spent, Some(s0), None, none(),
                    Ghost(false), Ghost(observed), Ghost(slots), Tracked(&mut *t))?;
    proof {
        all_complete_push(before, t.searches.value(), s1@);
        assert(t.searches.value()[index as int] == s0@);
        assert(t.searches.value()[index as int + 1] == s1@);
    }
    match landing(&s1, s0) {
        Some(j) => {
            assert(exists|k: int| spec::lands_on(s1@, s0@, k));
            proof {
                t.instance.land(index as int + 1, j as int, &mut t.trunk, &mut t.authors, &t.searches);
            }
            if let Err(e) = trusted::land(m, &s1, j, Some(s0)) {
                assert(spec::blocked(spec::Blocked::Refused, s0@, s1@, s0@, head@)) by { reveal(spec::blocked); }
                trusted::record_blocked(m, spec::Blocked::Refused, Ghost(s0@), Ghost(s1@), Ghost(s0@), Ghost(head@));
                return Err(e);
            }
            trusted::record_land(m, index + 1, j, Ghost(t.searches.value()));
            *head = Commit(candidate(&s1, j).commit.0.clone());
        }
        None => {
            if let Some(reason) = blocked(s0, Some(&s1), None) {
                proof { spec::reason_is_blocked(s0@, Some(s1@), None, head@); }
                trusted::record_blocked(m, reason, Ghost(s0@), Ghost(s1@), Ghost(s0@), Ghost(head@));
            }
        }
    }
    Ok(Some(index + 2))
}

/// The rest of an attempt whose search s0, at index, selected i: a foil
/// search and a counterexample search on the selection, then a push or a
/// landing.
fn on_selection(
    m: &trusted::Manifest, root: &str, head: &mut Commit, s0: &Search, i: usize, a: usize, index: usize,
    checks: &Vec<Path>, tests: &Vec<Path>, trusted: &Vec<Path>, l: u64, limit: u64, spent: &mut u64,
    Ghost(accepted): Ghost<bool>, Ghost(observed): Ghost<IMap<(User, Object), Seq<Option<Permission>>>>, Ghost(slots): Ghost<nat>, Tracked(t): Tracked<&mut Tokens>,
) -> (r: Result<Option<usize>, String>)
    requires
        index <= usize::MAX - 3,
        between(*old(t), observed, slots, index as int + 1, *old(spent), old(head)@, paths(checks@), paths(tests@), paths(trusted@), limit),
        old(t).searches.value()[index as int] == s0@,
        s0.results.len() == s0.n,
        s0@.base == old(head)@,
        spec::selected(s0@, i as int),
        spec::verified_at(s0@, i as int),
    ensures
        r matches Ok(Some(next)) ==> next <= index + 3
            && between(*final(t), observed, slots, next as int, *final(spent), final(head)@, paths(checks@), paths(tests@), paths(trusted@), limit)
            && extends(old(t).searches.value(), final(t).searches.value()),
{
    hide(spec::isolated);
    hide(spec::verified);
    hide(spec::authority);
    hide(spec::selected);
    hide(spec::complete);
    trusted::record_selected(m, i);
    let ghost before1 = t.searches.value();
    let sf = search(m, index + 1, a, Kind::Foil { goal: AgentProcess { search: index, index: i }, changed: clone_paths(&candidate(s0, i).changed) },
                    Commit(candidate(s0, i).commit.0.clone()), checks, tests, trusted, l, limit, spent, Some(s0), None, none(),
                    Ghost(accepted), Ghost(observed), Ghost(slots), Tracked(&mut *t))?;
    proof {
        all_complete_push(before1, t.searches.value(), sf@);
        assert(t.searches.value()[index as int] == s0@);
    }
    let ghost before2 = t.searches.value();
    let s1 = search(m, index + 2, a, Kind::Counterexample { goal: Some(AgentProcess { search: index, index: i }) },
                    Commit(head.0.clone()), checks, tests, trusted, l, limit, spent, Some(s0), Some(&sf), none(),
                    Ghost(accepted), Ghost(observed), Ghost(slots), Tracked(&mut *t))?;
    proof {
        all_complete_push(before2, t.searches.value(), s1@);
        assert(t.searches.value()[index as int] == s0@);
        assert(t.searches.value()[index as int + 1] == sf@);
        assert(t.searches.value()[index as int + 2] == s1@);
    }
    conclude(m, root, head, s0, &sf, &s1, i, index, Ghost(*spent), Ghost(paths(checks@)), Ghost(paths(tests@)), Ghost(paths(trusted@)), Ghost(limit),
             Ghost(observed), Ghost(slots), Tracked(t))
}

/// The end of an attempt: tested search s0, at index, selected i, and the
/// foil search sf and counterexample search s1 on it ran. i is pushed if no
/// counterexample was found; the best test that splits s0 lands if one does.
fn conclude(
    m: &trusted::Manifest, root: &str, head: &mut Commit, s0: &Search, sf: &Search, s1: &Search, i: usize, index: usize,
    Ghost(spent): Ghost<u64>, Ghost(checks): Ghost<Set<spec::Path>>, Ghost(tests): Ghost<Set<spec::Path>>, Ghost(trusted): Ghost<Set<spec::Path>>,
    Ghost(limit): Ghost<u64>, Ghost(observed): Ghost<IMap<(User, Object), Seq<Option<Permission>>>>, Ghost(slots): Ghost<nat>, Tracked(t): Tracked<&mut Tokens>,
) -> (r: Result<Option<usize>, String>)
    requires
        index <= usize::MAX - 3,
        between(*old(t), observed, slots, index as int + 3, spent, old(head)@, checks, tests, trusted, limit),
        old(t).searches.value()[index as int] == s0@,
        old(t).searches.value()[index as int + 1] == sf@,
        old(t).searches.value()[index as int + 2] == s1@,
        s0.results.len() == s0.n, sf.results.len() == sf.n, s1.results.len() == s1.n,
        s0@.base == old(head)@, s1@.base == old(head)@,
        spec::selected(s0@, i as int),
        spec::verified_at(s0@, i as int),
        s1@.kind == (spec::Kind::Counterexample { goal: Some(spec::AgentProcess { search: index as int, index: i as int }) }),
        spec::foils_on(sf@, index as int, i as int),
    ensures
        r matches Ok(Some(next)) ==> next == index + 3
            && between(*final(t), observed, slots, next as int, spent, final(head)@, checks, tests, trusted, limit)
            && final(t).searches.value() == old(t).searches.value(),
{
    hide(spec::isolated);
    hide(spec::verified);
    hide(spec::authority);
    hide(spec::reason);
    hide(spec::blocked);
    hide(spec::selected);
    hide(spec::not_found);
    hide(spec::splits);
    hide(spec::beats);
    if not_found(s1, s0, sf) {
        assert(spec::allowed(s0@, i as int, s1@, sf@));
        assert(exists|k: int| spec::allowed(s0@, k, s1@, sf@));
        let now = trusted::head(root)?;
        if !eq(&now.0, &head.0) {
            assert(spec::blocked(spec::Blocked::TrunkMoved, s0@, s1@, sf@, now@)) by { reveal(spec::blocked); }
            trusted::record_blocked(m, spec::Blocked::TrunkMoved, Ghost(s0@), Ghost(s1@), Ghost(sf@), Ghost(now@));
            return Err("blocked: trunk moved during the search; run it again".into());
        }
        proof {
            t.instance.push(index as int, i as int, index as int + 2, index as int + 1, &mut t.trunk, &mut t.authors, &t.searches);
        }
        if let Err(e) = trusted::push(m, &candidate(s0, i).commit) {
            assert(spec::blocked(spec::Blocked::Refused, s0@, s1@, sf@, head@)) by { reveal(spec::blocked); }
            trusted::record_blocked(m, spec::Blocked::Refused, Ghost(s0@), Ghost(s1@), Ghost(sf@), Ghost(head@));
            return Err(e);
        }
        trusted::record_push(m, index, i, index + 2, index + 1, Ghost(t.searches.value()));
        return Ok(None);
    }
    match landing(s1, s0) {
        Some(j) => {
            assert(exists|k: int| spec::lands_on(s1@, s0@, k));
            proof {
                t.instance.land(index as int + 2, j as int, &mut t.trunk, &mut t.authors, &t.searches);
            }
            if let Err(e) = trusted::land(m, s1, j, Some(s0)) {
                assert(spec::blocked(spec::Blocked::Refused, s0@, s1@, sf@, head@)) by { reveal(spec::blocked); }
                trusted::record_blocked(m, spec::Blocked::Refused, Ghost(s0@), Ghost(s1@), Ghost(sf@), Ghost(head@));
                return Err(e);
            }
            trusted::record_land(m, index + 2, j, Ghost(t.searches.value()));
            *head = Commit(candidate(s1, j).commit.0.clone());
        }
        None => {
            if let Some(reason) = blocked(s0, Some(s1), Some(sf)) {
                proof { spec::reason_is_blocked(s0@, Some(s1@), Some(sf@), head@); }
                trusted::record_blocked(m, reason, Ghost(s0@), Ghost(s1@), Ghost(sf@), Ghost(head@));
            }
        }
    }
    Ok(Some(index + 3))
}

/// bon counterexample: tests written from the spec, never the implementation,
/// looking for what the spec forbids on trunk. When at least two verified
/// tests reject trunk, the best lands on trunk, whose checks then reject it
/// (Ok(true)); otherwise Ok(false), and nothing lands: a test that accepts
/// trunk shows nothing.
pub fn counterexample(root: &str) -> (r: Result<bool, String>) {
    let head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let checks = trusted::checks(&m);
    let tests = trusted::tests(&m);
    let trusted = trusted::trusted(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let (agent, observations) = trusted::observe(&m, &head)?;
    if !isolated(&agent, &observations) {
        return Err("agent or a check slot's user is not isolated: their permissions differ from the policy; run bon setup".into());
    }
    let accepted = trusted::trunk_accepted(&m, &head);
    if !accepted { return Err("trunk's checks reject it: run bon code first".into()); }
    let ghost observed = observed(agent, observations@);
    let ghost slots = observations.len() as nat;
    let tracked (Tracked(instance), Tracked(checks_t), Tracked(tests_t), Tracked(trusted_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(generation), Tracked(capability))
        = spec::bon::Instance::initialize(head@, paths(checks@), paths(tests@), paths(trusted@), limit as nat);
    let tracked mut t = Tokens { instance, checks: checks_t, tests: tests_t, trusted: trusted_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved, generation };
    let mut spent: u64 = 0;
    trusted::record_initialize(&m, &head, limit);
    let s = search(&m, 0, 0, Kind::Counterexample { goal: None }, Commit(head.0.clone()), &checks, &tests, &trusted, l, limit, &mut spent,
                   None, None, none(), Ghost(accepted), Ghost(observed), Ghost(slots), Tracked(&mut t))?;
    match found_on_trunk(&s) {
        Some(i) => {
            trusted::record_selected(&m, i);
            proof {
                assert(t.searches.value()[0] == s@);
                t.instance.land(0, i as int, &mut t.trunk, &mut t.authors, &t.searches);
            }
            trusted::land(&m, &s, i, None)?;
            trusted::record_land(&m, 0, i, Ghost(t.searches.value()));
            Ok(true)
        }
        None => {
            trusted::record_not_found(&m, "fewer than two verified tests reject trunk");
            Ok(false)
        }
    }
}

/// bon spec <queue-id>: spec searches for goal, an accepted intent (a queue
/// line). Its spec's files must stand alone on trunk, or nothing is reserved.
/// Attempts run along the spec search's width list until one has a verified
/// candidate, each carrying the previous attempt's unverified ones; that
/// search is returned, for its proposal to engineer. Nothing is pushed: no
/// transition takes a spec candidate to trunk (spec::proposals_never_reach_trunk).
/// Ok: the search, whose proposal trusted code writes (trusted::spec_proposal).
pub fn spec(root: &str, goal: Intent) -> (r: Result<Search, String>) {
    hide(spec::isolated);
    let head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let checks = trusted::checks(&m);
    let tests = trusted::tests(&m);
    let trusted = trusted::trusted(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let files = trusted::spec_files(&m, &head)?;
    let (agent, observations) = trusted::observe(&m, &head)?;
    if !isolated(&agent, &observations) {
        return Err("agent or a check slot's user is not isolated: their permissions differ from the policy; run bon setup".into());
    }
    let ghost observed = observed(agent, observations@);
    let ghost slots = observations.len() as nat;
    let tracked (Tracked(instance), Tracked(checks_t), Tracked(tests_t), Tracked(trusted_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(generation), Tracked(capability))
        = spec::bon::Instance::initialize(head@, paths(checks@), paths(tests@), paths(trusted@), limit as nat);
    let tracked mut t = Tokens { instance, checks: checks_t, tests: tests_t, trusted: trusted_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved, generation };
    let mut spent: u64 = 0;
    trusted::record_initialize(&m, &head, limit);
    let attempts = trusted::attempts_of(&m, &Kind::Spec { goal: Intent(goal.0.clone()), files: clone_paths(&files) });
    let mut previous: Option<Search> = None;
    let ghost mut previous_index: int = 0;
    let mut a: usize = 0;
    while a < attempts
        invariant
            t.wf(),
            spec::isolated(observed, slots),
            t.searches.value().len() == a as int,
            forall|j: int| 0 <= j < t.searches.value().len() ==> spec::complete(#[trigger] t.searches.value()[j]),
            t.reserved.value() == 0,
            t.spent.value() == spent as nat,
            t.trunk.value() == Seq::<spec::Commit>::empty().push(head@),
            t.checks.value() == paths(checks@),
            t.tests.value() == paths(tests@),
            t.trusted.value() == paths(trusted@),
            t.limit.value() == limit as nat,
            previous matches Some(p) ==> 0 <= previous_index < a && t.searches.value()[previous_index] == p@,
        decreases attempts - a,
    {
        let kind = Kind::Spec { goal: Intent(goal.0.clone()), files: clone_paths(&files) };
        let prev = previous.as_ref();
        let context = carried(&kind, prev);
        let ghost before = t.searches.value();
        proof {
            assert forall|commit: spec::Commit| #[trigger] commits(context@).contains(commit) implies spec::carries(before, kind@, commit) by {
                carried_carries(before, kind@, prev, previous_index, commit);
            }
        }
        let s = search(&m, a, a, kind, Commit(head.0.clone()), &checks, &tests, &trusted, l, limit, &mut spent,
                       None, None, context, Ghost(false), Ghost(observed), Ghost(slots), Tracked(&mut t))?;
        proof {
            assert forall|j: int| 0 <= j < t.searches.value().len() implies spec::complete(#[trigger] t.searches.value()[j]) by {
                if j < a { assert(t.searches.value()[j] == before[j]); }
            }
        }
        let v = verified_each(&s);
        let mut any = false;
        let mut j = 0;
        while j < v.len()
            invariant 0 <= j <= v.len(),
            decreases v.len() - j,
        {
            if v[j] { any = true; }
            j += 1;
        }
        if any {
            trusted::record_proposal(&m);
            return Ok(s);
        }
        proof { previous_index = a as int; }
        previous = Some(s);
        a = a + 1;
    }
    Err("no spec candidate verified: every attempt's spec changes failed Verus alone, or changed more than the spec's files; see .bon/traces".into())
}

/// bon queue: one queue search per transcript, all in one run of the bon
/// process, and for each its proposal for engineer: the agreed intents with
/// their wording, and the contested cues.
pub fn queue(root: &str, transcripts: &Vec<Transcript>) -> (r: Result<Vec<(Vec<(Cue, Intent)>, Vec<Cue>)>, String>) {
    let head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let checks = trusted::checks(&m);
    let tests = trusted::tests(&m);
    let trusted = trusted::trusted(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let (agent, observations) = trusted::observe(&m, &head)?;
    if !isolated(&agent, &observations) {
        return Err("agent or a check slot's user is not isolated: their permissions differ from the policy; run bon setup".into());
    }
    let ghost observed = observed(agent, observations@);
    let ghost slots = observations.len() as nat;
    let tracked (Tracked(instance), Tracked(checks_t), Tracked(tests_t), Tracked(trusted_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(generation), Tracked(capability))
        = spec::bon::Instance::initialize(head@, paths(checks@), paths(tests@), paths(trusted@), limit as nat);
    let tracked mut t = Tokens { instance, checks: checks_t, tests: tests_t, trusted: trusted_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved, generation };
    let mut spent: u64 = 0;
    trusted::record_initialize(&m, &head, limit);
    let mut out: Vec<(Vec<(Cue, Intent)>, Vec<Cue>)> = Vec::new();
    let mut k: usize = 0;
    while k < transcripts.len()
        invariant
            t.wf(),
            spec::isolated(observed, slots),
            t.searches.value().len() == k as int,
            forall|j: int| 0 <= j < t.searches.value().len() ==> spec::complete(#[trigger] t.searches.value()[j]),
            t.reserved.value() == 0,
            t.spent.value() == spent as nat,
            t.trunk.value() == Seq::<spec::Commit>::empty().push(head@),
            t.checks.value() == paths(checks@),
            t.tests.value() == paths(tests@),
            t.trusted.value() == paths(trusted@),
            t.limit.value() == limit as nat,
            k <= transcripts.len(),
        decreases transcripts.len() - k,
    {
        let ghost before = t.searches.value();
        let s = search(&m, k, 0, Kind::Queue { goal: Transcript(Path(transcripts[k].0.0.clone())) }, Commit(head.0.clone()), &checks, &tests, &trusted, l, limit, &mut spent,
                       None, None, none(), Ghost(false), Ghost(observed), Ghost(slots), Tracked(&mut t))?;
        proof {
            assert forall|j: int| 0 <= j < t.searches.value().len() implies spec::complete(#[trigger] t.searches.value()[j]) by {
                if j < k { assert(t.searches.value()[j] == before[j]); }
            }
        }
        trusted::record_proposal(&m);
        out.push((proposed(&s), contested(&s)));
        k += 1;
    }
    Ok(out)
}

} // verus!
