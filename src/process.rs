//! The bon process: the drivers that hold the tokens and pass every decision
//! through a gate. Not compiled for WebAssembly; the gates in exec.rs are.

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

/// One search: grant a capability per agent process, run them, and wait on
/// each, consuming its capability.
#[verifier::rlimit(400)]
#[verifier::spinoff_prover]
// index is read only by the contract, which cargo erases.
#[allow(unused_variables)]
fn search(
    m: &trusted::Manifest, index: usize, a: usize, kind: Kind, start: Commit, checks: &Vec<Path>, tests: &Vec<Path>, trusted: &Vec<Path>,
    l: u64, limit: u64, spent: &mut u64, target: Option<&Search>, foils: Option<&Search>,
    Ghost(observed): Ghost<Map<Object, Permission>>, Tracked(t): Tracked<&mut Tokens>,
) -> (r: Result<Search, String>)
    requires
        old(t).wf(),
        index as int == old(t).searches.value().len(),
        spec::isolated(observed),
        forall|k: int| 0 <= k < old(t).searches.value().len() ==> spec::complete(#[trigger] old(t).searches.value()[k]),
        old(t).checks.value() == paths(checks@),
        old(t).tests.value() == paths(tests@),
        old(t).trusted.value() == paths(trusted@),
        old(t).limit.value() == limit as nat,
        old(t).spent.value() == *old(spent) as nat,
        old(t).reserved.value() == 0,
        start@ == match kind@ {
            spec::Kind::Foil { goal, .. } => spec::at(old(t).searches.value()[goal.search], goal.index).commit,
            _ => old(t).trunk.value().last(),
        },
        kind@ matches spec::Kind::Code { goal } ==> goal == old(t).trunk.value().last(),
        kind@ matches spec::Kind::Compaction { goal, .. } ==> goal == old(t).trunk.value().last(),
        kind@ matches spec::Kind::Counterexample { goal: Some(p) } ==>
            0 <= p.search < old(t).searches.value().len()
            && spec::selected(old(t).searches.value()[p.search], p.index)
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
    let tracked mut capability = t.instance.grant(kind@, n as nat, l as nat, observed,
        &t.checks, &t.tests, &t.trusted, &t.trunk, &mut t.searches, &t.limit, &t.spent, &mut t.reserved);
    trusted::record_grant(m, &kind, n, l, Ghost(t.searches.value()));
    let started = trusted::clock();
    let spent_before = *spent;
    let mut results = trusted::run(m, &kind, a, &start, target, foils);
    if results.len() != n {
        return Err("trusted code returned the wrong number of agent processes".into());
    }
    let mut s = Search { kind, base: start, n, checks: clone_paths(checks), tests: clone_paths(tests), trusted: clone_paths(trusted), limit: l, results: Vec::new() };
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
        // A harness that cannot be stopped mid-turn (codex) may overrun its limit;
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
            t.instance.wait(p, cap.value(), returned(r), generation as nat, &mut t.searches, &mut t.spent, &mut t.reserved, cap);
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
        trusted::record_wait(m, index, i, &s.results[i], generation, Ghost(t.searches.value()));
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

/// bon code (compaction false) or bon compaction (true). Each attempt is a
/// search and, if it selects, a counterexample search on the selection; the
/// selected candidate is pushed once one clears. When a test splits the
/// candidates, the best such test lands on trunk, and the next attempt runs
/// wider from that head, until the attempts run out.
#[verifier::rlimit(100)]
#[verifier::spinoff_prover]
pub fn to_push(root: &str, compaction: bool) -> (r: Result<(), String>) {
    hide(spec::verified);
    hide(spec::authority);
    hide(spec::reason);
    hide(spec::blocked);
    hide(spec::selected);
    hide(spec::not_found);
    let mut head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let checks = trusted::checks(&m);
    let tests = trusted::tests(&m);
    let trusted = trusted::trusted(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let (pc, pt, pw, pr, pd) = trusted::observe(&m, &head)?;
    if !isolated(pc, pt, pw, pr, pd) {
        return Err("agent is not isolated: its permissions differ from the policy; run bon setup".into());
    }
    // Code is for a trunk its checks reject; compaction, for one they accept.
    let accepted = trusted::trunk_accepted(&m, &head);
    if !compaction && accepted { return Err("trunk's checks accept it: there is no code to write".into()); }
    if compaction && !accepted { return Err("trunk's checks reject it: run bon code first".into()); }
    let ghost observed = observed(pc, pt, pw, pr, pd);
    let tracked (Tracked(instance), Tracked(checks_t), Tracked(tests_t), Tracked(trusted_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(capability))
        = spec::bon::Instance::initialize(head@, paths(checks@), paths(tests@), paths(trusted@), limit as nat);
    let tracked mut t = Tokens { instance, checks: checks_t, tests: tests_t, trusted: trusted_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved };
    let mut spent: u64 = 0;
    trusted::record_initialize(&m, &head, limit);

    let attempts = trusted::attempts(&m);
    let mut a: usize = 0;
    let mut index: usize = 0;
    while a < attempts
        invariant
            t.wf(),
            spec::isolated(observed),
            t.searches.value().len() == index as int,
            forall|k: int| 0 <= k < t.searches.value().len() ==> spec::complete(#[trigger] t.searches.value()[k]),
            t.reserved.value() == 0,
            t.spent.value() == spent as nat,
            t.trunk.value().len() >= 1,
            t.trunk.value().last() == head@,
            t.checks.value() == paths(checks@),
            t.tests.value() == paths(tests@),
            t.trusted.value() == paths(trusted@),
            t.limit.value() == limit as nat,
            index <= 3 * a,
        decreases attempts - a,
    {
        if index > usize::MAX - 3 { return Err("too many searches".into()); }
        let kind = if compaction {
            Kind::Compaction { goal: Commit(head.0.clone()), out: trusted::agree_outputs(&m, &head)? }
        } else {
            Kind::Code { goal: Commit(head.0.clone()) }
        };
        let ghost before = t.searches.value();
        let s0 = search(&m, index, a, kind, Commit(head.0.clone()), &checks, &tests, &trusted, l, limit, &mut spent, None, None,
                        Ghost(observed), Tracked(&mut t))?;
        proof {
            assert(t.searches.value()[index as int] == s0@);
            assert forall|k: int| 0 <= k < t.searches.value().len() implies spec::complete(#[trigger] t.searches.value()[k]) by {
                if k < index { assert(t.searches.value()[k] == before[k]); }
            }
        }
        match selected(&s0) {
            None => {
                if let Some(reason) = blocked(&s0, None, None) {
                    proof { spec::reason_is_blocked(s0@, None, None); }
                    trusted::record_blocked(&m, reason, Ghost(s0@), Ghost(s0@), Ghost(s0@));
                }
                index = index + 1;
            }
            Some(i) => {
                assert(spec::verified_at(s0@, i as int)) by { reveal(spec::selected); }
                trusted::record_selected(&m, i);
                let ghost before1 = t.searches.value();
                let sf = search(&m, index + 1, a, Kind::Foil { goal: AgentProcess { search: index, index: i }, changed: clone_paths(&candidate(&s0, i).changed) },
                                Commit(candidate(&s0, i).commit.0.clone()), &checks, &tests, &trusted, l, limit, &mut spent, Some(&s0), None,
                                Ghost(observed), Tracked(&mut t))?;
                proof {
                    assert(t.searches.value()[index as int] == s0@);
                    assert forall|k: int| 0 <= k < t.searches.value().len() implies spec::complete(#[trigger] t.searches.value()[k]) by {
                        if k <= index { assert(t.searches.value()[k] == before1[k]); }
                    }
                }
                let ghost before2 = t.searches.value();
                let s1 = search(&m, index + 2, a, Kind::Counterexample { goal: Some(AgentProcess { search: index, index: i }) },
                                Commit(head.0.clone()), &checks, &tests, &trusted, l, limit, &mut spent, Some(&s0), Some(&sf),
                                Ghost(observed), Tracked(&mut t))?;
                proof {
                    assert(t.searches.value()[index as int] == s0@);
                    assert(t.searches.value()[index as int + 2] == s1@);
                    assert(t.searches.value()[index as int + 1] == sf@);
                    assert forall|k: int| 0 <= k < t.searches.value().len() implies spec::complete(#[trigger] t.searches.value()[k]) by {
                        if k <= index + 1 { assert(t.searches.value()[k] == before2[k]); }
                    }
                }
                if not_found(&s1, &s0, &sf) {
                    assert(spec::allowed(s0@, i as int, s1@, sf@));
                    assert(exists|k: int| spec::allowed(s0@, k, s1@, sf@));
                    let now = trusted::head(root)?;
                    if !eq(&now.0, &head.0) {
                        assert(spec::blocked(spec::Blocked::TrunkMoved, s0@, s1@, sf@)) by { reveal(spec::blocked); }
                        trusted::record_blocked(&m, spec::Blocked::TrunkMoved, Ghost(s0@), Ghost(s1@), Ghost(sf@));
                        return Err("blocked: trunk moved during the search; run it again".into());
                    }
                    proof {
                        t.instance.push(index as int, i as int, index as int + 2, index as int + 1, &mut t.trunk, &mut t.authors, &t.searches);
                    }
                    if let Err(e) = trusted::push(&m, &candidate(&s0, i).commit) {
                        assert(spec::blocked(spec::Blocked::Refused, s0@, s1@, sf@)) by { reveal(spec::blocked); }
                        trusted::record_blocked(&m, spec::Blocked::Refused, Ghost(s0@), Ghost(s1@), Ghost(sf@));
                        return Err(e);
                    }
                    trusted::record_push(&m, index, i, index + 2, index + 1, Ghost(t.searches.value()));
                    return Ok(());
                }
                match landing(&s1, &s0) {
                    Some(j) => {
                        assert(exists|k: int| spec::lands_on(s1@, s0@, k));
                        proof {
                            t.instance.land(index as int + 2, j as int, &mut t.trunk, &mut t.authors, &t.searches);
                        }
                        if let Err(e) = trusted::land(&m, &s1, j, Some(&s0)) {
                            assert(spec::blocked(spec::Blocked::Refused, s0@, s1@, sf@)) by { reveal(spec::blocked); }
                            trusted::record_blocked(&m, spec::Blocked::Refused, Ghost(s0@), Ghost(s1@), Ghost(sf@));
                            return Err(e);
                        }
                        trusted::record_land(&m, index + 2, j, Ghost(t.searches.value()));
                        head = Commit(candidate(&s1, j).commit.0.clone());
                    }
                    None => {
                        if let Some(reason) = blocked(&s0, Some(&s1), Some(&sf)) {
                            proof { spec::reason_is_blocked(s0@, Some(s1@), Some(sf@)); }
                            trusted::record_blocked(&m, reason, Ghost(s0@), Ghost(s1@), Ghost(sf@));
                        }
                    }
                }
                index = index + 3;
            }
        }
        a = a + 1;
    }
    Err("blocked: no attempt was selected with no counterexample found; see .bon/traces".into())
}

/// bon counterexample: tests written from the spec, never the implementation,
/// looking for a behavior on trunk the spec forbids. When at least two verified
/// tests reject trunk, the best lands on trunk, whose checks then reject it
/// (Ok(true)); otherwise Ok(false), and nothing lands: a test that accepts
/// trunk shows nothing.
#[verifier::rlimit(100)]
pub fn counterexample(root: &str) -> (r: Result<bool, String>) {
    let head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let checks = trusted::checks(&m);
    let tests = trusted::tests(&m);
    let trusted = trusted::trusted(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let (pc, pt, pw, pr, pd) = trusted::observe(&m, &head)?;
    if !isolated(pc, pt, pw, pr, pd) {
        return Err("agent is not isolated: its permissions differ from the policy; run bon setup".into());
    }
    if !trusted::trunk_accepted(&m, &head) { return Err("trunk's checks reject it: run bon code first".into()); }
    let ghost observed = observed(pc, pt, pw, pr, pd);
    let tracked (Tracked(instance), Tracked(checks_t), Tracked(tests_t), Tracked(trusted_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(capability))
        = spec::bon::Instance::initialize(head@, paths(checks@), paths(tests@), paths(trusted@), limit as nat);
    let tracked mut t = Tokens { instance, checks: checks_t, tests: tests_t, trusted: trusted_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved };
    let mut spent: u64 = 0;
    trusted::record_initialize(&m, &head, limit);
    let s = search(&m, 0, 0, Kind::Counterexample { goal: None }, Commit(head.0.clone()), &checks, &tests, &trusted, l, limit, &mut spent,
                   None, None, Ghost(observed), Tracked(&mut t))?;
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
    let (pc, pt, pw, pr, pd) = trusted::observe(&m, &head)?;
    if !isolated(pc, pt, pw, pr, pd) {
        return Err("agent is not isolated: its permissions differ from the policy; run bon setup".into());
    }
    let ghost observed = observed(pc, pt, pw, pr, pd);
    let tracked (Tracked(instance), Tracked(checks_t), Tracked(tests_t), Tracked(trusted_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(capability))
        = spec::bon::Instance::initialize(head@, paths(checks@), paths(tests@), paths(trusted@), limit as nat);
    let tracked mut t = Tokens { instance, checks: checks_t, tests: tests_t, trusted: trusted_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved };
    let mut spent: u64 = 0;
    trusted::record_initialize(&m, &head, limit);
    let mut out: Vec<(Vec<(Cue, Intent)>, Vec<Cue>)> = Vec::new();
    let mut k: usize = 0;
    while k < transcripts.len()
        invariant
            t.wf(),
            spec::isolated(observed),
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
                       None, None, Ghost(observed), Tracked(&mut t))?;
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
