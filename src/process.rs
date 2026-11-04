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
    pub map: spec::bon::map,
    pub checks: spec::bon::checks,
    pub trunk: spec::bon::trunk,
    pub authors: spec::bon::authors,
    pub searches: spec::bon::searches,
    pub limit: spec::bon::limit,
    pub spent: spec::bon::spent,
    pub reserved: spec::bon::reserved,
}

impl Tokens {
    pub open spec fn wf(&self) -> bool {
        &&& self.map.instance_id() == self.instance.id()
        &&& self.checks.instance_id() == self.instance.id()
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

/// One search: grant a capability per agent process, run them, and wait on
/// each, consuming its capability. (intents 2, 7, 9, 16)
#[verifier::rlimit(100)]
#[verifier::spinoff_prover]
fn search(
    m: &trusted::Manifest, index: usize, a: usize, kind: Kind, start: Commit, checks: &Vec<Path>, l: u64, limit: u64,
    spent: &mut u64, target: Option<&Search>, tests: &trusted::Tests, Ghost(observed): Ghost<Map<File, Permission>>,
    Tracked(t): Tracked<&mut Tokens>,
) -> (r: Result<Search, String>)
    requires
        old(t).wf(),
        index as int == old(t).searches.value().len(),
        spec::isolated(observed),
        forall|k: int| 0 <= k < old(t).searches.value().len() ==> spec::complete(#[trigger] old(t).searches.value()[k]),
        old(t).checks.value() == paths(checks@),
        old(t).limit.value() == limit as nat,
        old(t).spent.value() == *old(spent) as nat,
        old(t).reserved.value() == 0,
        start@ == spec::start(kind@, old(t).searches.value(), old(t).trunk.value().last()),
        kind@ matches spec::Kind::Code { goal } ==> old(t).map.value().contains(goal),
        kind@ matches spec::Kind::Compaction { goal, .. } ==> goal == old(t).trunk.value().last(),
        kind@ matches spec::Kind::Counterexample { goal } ==>
            0 <= goal.search < old(t).searches.value().len()
            && spec::selected(old(t).searches.value()[goal.search], goal.index)
            && old(t).searches.value()[goal.search].base == old(t).trunk.value().last(),
    ensures
        final(t).wf(),
        final(t).instance == old(t).instance,
        final(t).map.value() == old(t).map.value(),
        final(t).checks.value() == old(t).checks.value(),
        final(t).trunk.value() == old(t).trunk.value(),
        final(t).authors.value() == old(t).authors.value(),
        final(t).limit.value() == old(t).limit.value(),
        r matches Ok(s) ==> {
            &&& s.results.len() == s.n
            &&& s@.kind == kind@
            &&& s@.base == spec::start(kind@, old(t).searches.value(), old(t).trunk.value().last())
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
        &t.map, &t.checks, &t.trunk, &mut t.searches, &t.limit, &t.spent, &mut t.reserved);
    trusted::record(m, "grant");
    let started = trusted::clock();
    let spent_before = *spent;
    let mut results = trusted::run(m, &kind, index, a, &start, target, tests);
    if results.len() != n {
        return Err("trusted code returned the wrong number of agent processes".into());
    }
    let mut s = Search { kind, base: start, n, checks: checks.clone(), limit: l, results: Vec::new() };
    proof {
        assert(s.checks@.map_values(|p: Path| p@) =~= checks@.map_values(|p: Path| p@));
        assert(s@.results =~= Map::empty());
        assert(s@.authority == spec::authority(kind@, paths(checks@)));
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
            t.map.value() == old(t).map.value(), t.checks.value() == old(t).checks.value(),
            t.trunk.value() == old(t).trunk.value(), t.authors.value() == old(t).authors.value(),
            t.limit.value() == old(t).limit.value(),
            capability.instance_id() == t.instance.id(),
            k == before.len(), t.searches.value().len() == k + 1,
            t.searches.value().take(k) == before,
            t.searches.value()[k] == s@,
            s.n == n, s.results.len() == i, i <= n, results.len() == n - i, s@.kind == kind@,
            s.base@ == start@, s.limit == l,
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
        let cost = if measured > l { trusted::record(m, "wait: an agent process overran its limit"); l } else { measured };
        match &r {
            Some(c) => { if !eq(&c.base, &s.base) { return Err("a candidate does not start from its base".into()); } }
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
            t.instance.wait(p, cap.value(), returned(r), cost as nat, &mut t.searches, &mut t.spent, &mut t.reserved, cap);
            assert(t.reserved.value() == l as nat * (n - (i + 1)) as nat);
        }
        let ghost old_s = s@;
        s.results.push(r);
        *spent = *spent + cost;
        proof {
            assert(s@.results =~= old_s.results.insert(i as int, returned(r)));
            assert(s@.authority == old_s.authority);
            assert(t.searches.value()[k] =~= s@);
            assert(t.searches.value().take(k) =~= before);
            assert forall|j: int| i + 1 <= j < n implies #[trigger] capability.dom().contains(spec::AgentProcess { search: k, index: j })
                && capability[spec::AgentProcess { search: k, index: j }] == (spec::Capability {
                    base: start@, authority: s@.authority, limit: l as nat }) by {
                assert(spec::AgentProcess { search: k, index: j } != p);
            }
        }
        trusted::record(m, "wait");
        i += 1;
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
    trusted::report(m, index, &s, verified, generation, started);
    Ok(s)
}


/// bon code (goal is an intent) or bon compaction (no goal). Each attempt is a
/// search and, if it selects, a counterexample search on the selection; trunk
/// fast-forwards once one clears. A blocked attempt reruns wider, carrying the
/// counterexample tests into agreement, until the attempts run out.
/// (intents 2–9, 13, 15–17)
pub fn land(root: &str, goal: Option<Intent>, carried: trusted::Tests) -> (r: Result<(), String>) {
    let head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let intents = trusted::intents(&m, &head);
    match &goal {
        Some(g) => { if !contains(&intents, g) { return Err("that intent is not in the map at trunk's head".into()); } }
        None => {}
    }
    let checks = trusted::checks(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let (pc, pt, pw, pr) = trusted::observe(&m, &head)?;
    if !isolated(pc, pt, pw, pr) {
        return Err("agent is not isolated: its permissions differ from the policy; run bon setup".into());
    }
    let ghost observed = observed(pc, pt, pw, pr);
    let tracked (Tracked(instance), Tracked(map), Tracked(checks_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(capability))
        = spec::bon::Instance::initialize(head@, intent_set(intents@), paths(checks@), limit as nat);
    let tracked mut t = Tokens { instance, map, checks: checks_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved };
    let mut spent: u64 = 0;
    trusted::record(&m, "initialize");

    let attempts = trusted::attempts(&m);
    let mut tests = carried;
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
            t.trunk.value() == Seq::<spec::Commit>::empty().push(head@),
            t.map.value() == intent_set(intents@),
            t.checks.value() == paths(checks@),
            t.limit.value() == limit as nat,
            goal matches Some(g) ==> intent_set(intents@).contains(g@),
            index <= 2 * a,
        decreases attempts - a,
    {
        if index > usize::MAX - 2 { return Err("too many searches".into()); }
        let kind = match &goal {
            Some(g) => Kind::Code { goal: g.clone() },
            None => Kind::Compaction { goal: head.clone(), out: trusted::agree_outputs(&m, &head, &tests)? },
        };
        let ghost before = t.searches.value();
        let s0 = search(&m, index, a, kind, head.clone(), &checks, l, limit, &mut spent, None, &tests,
                        Ghost(observed), Tracked(&mut t))?;
        proof {
            assert(t.searches.value()[index as int] == s0@);
            assert forall|k: int| 0 <= k < t.searches.value().len() implies spec::complete(#[trigger] t.searches.value()[k]) by {
                if k < index { assert(t.searches.value()[k] == before[k]); }
            }
        }
        match selected(&s0) {
            None => {
                trusted::record(&m, "blocked: fewer than two verified candidates, or they disagree");
                index = index + 1;
            }
            Some(i) => {
                trusted::record_selected(&m, i);
                let start = head.clone();
                let ghost before1 = t.searches.value();
                let s1 = search(&m, index + 1, a, Kind::Counterexample { goal: AgentProcess { search: index, index: i } }, start,
                                &checks, l, limit, &mut spent, Some(&s0), &tests, Ghost(observed), Tracked(&mut t))?;
                proof {
                    assert(t.searches.value()[index as int] == s0@);
                    assert(t.searches.value()[index as int + 1] == s1@);
                    assert forall|k: int| 0 <= k < t.searches.value().len() implies spec::complete(#[trigger] t.searches.value()[k]) by {
                        if k <= index { assert(t.searches.value()[k] == before1[k]); }
                    }
                }
                if cleared(&s1, &s0) {
                    let now = trusted::head(root)?;
                    if !eq(&now, &head) {
                        trusted::record(&m, "blocked: trunk moved");
                        return Err("blocked: trunk moved during the search; run it again".into());
                    }
                    proof {
                        t.instance.fast_forward(index as int, i as int, index as int + 1, &mut t.trunk, &mut t.authors, &t.searches);
                    }
                    trusted::fast_forward(&m, &candidate(&s0, i).commit)?;
                    trusted::record(&m, "fast_forward");
                    return Ok(());
                }
                trusted::record(&m, "blocked: a counterexample split the agreed candidates; its tests join agreement");
                trusted::carry(&m, &mut tests, &s1);
                index = index + 2;
            }
        }
        a = a + 1;
    }
    Err("blocked: no attempt was selected and cleared; see .bon/traces".into())
}

/// bon scrub: check an intent against trunk with tests written from the spec and
/// the intent alone. An agreed pass retains the selected test on trunk (Ok(None));
/// an agreed fail means the intent is broken, and returns the test to carry into
/// a code search (Ok(Some)). (intent 21)
#[verifier::rlimit(100)]
pub fn scrub(root: &str, goal: Intent) -> (r: Result<Option<trusted::Tests>, String>) {
    let head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let intents = trusted::intents(&m, &head);
    if !contains(&intents, &goal) { return Err("that intent is not in the map at trunk's head".into()); }
    let checks = trusted::checks(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let (pc, pt, pw, pr) = trusted::observe(&m, &head)?;
    if !isolated(pc, pt, pw, pr) {
        return Err("agent is not isolated: its permissions differ from the policy; run bon setup".into());
    }
    let ghost observed = observed(pc, pt, pw, pr);
    let tracked (Tracked(instance), Tracked(map), Tracked(checks_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(capability))
        = spec::bon::Instance::initialize(head@, intent_set(intents@), paths(checks@), limit as nat);
    let tracked mut t = Tokens { instance, map, checks: checks_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved };
    let mut spent: u64 = 0;
    trusted::record(&m, "initialize");
    let attempts = trusted::scrub_attempts(&m);
    let path = trusted::scrub_test_path(&m, &goal)?;
    let none = trusted::no_tests();
    let mut a: usize = 0;
    while a < attempts
        invariant
            t.wf(),
            spec::isolated(observed),
            t.searches.value().len() == a as int,
            forall|k: int| 0 <= k < t.searches.value().len() ==> spec::complete(#[trigger] t.searches.value()[k]),
            t.reserved.value() == 0,
            t.spent.value() == spent as nat,
            t.trunk.value() == Seq::<spec::Commit>::empty().push(head@),
            t.map.value() == intent_set(intents@),
            t.checks.value() == paths(checks@),
            t.limit.value() == limit as nat,
        decreases attempts - a,
    {
        let kind = Kind::Scrub { goal: goal.clone(), path: path.clone() };
        let ghost before = t.searches.value();
        let s0 = search(&m, a, a, kind, head.clone(), &checks, l, limit, &mut spent, None, &none,
                        Ghost(observed), Tracked(&mut t))?;
        proof {
            assert(t.searches.value()[a as int] == s0@);
            assert forall|k: int| 0 <= k < t.searches.value().len() implies spec::complete(#[trigger] t.searches.value()[k]) by {
                if k < a { assert(t.searches.value()[k] == before[k]); }
            }
        }
        match selected(&s0) {
            None => { trusted::record(&m, "blocked: fewer than two verified tests, or they disagree"); }
            Some(i) => {
                trusted::record_selected(&m, i);
                let c = candidate(&s0, i);
                match test_passes_on(c, None) {
                    Some(true) => {
                        let now = trusted::head(root)?;
                        if !eq(&now, &head) { return Err("blocked: trunk moved during the scrub; run it again".into()); }
                        proof {
                            assert(s0@.kind is Scrub);
                            t.instance.retain(a as int, i as int, &mut t.trunk, &mut t.authors, &t.searches);
                        }
                        trusted::fast_forward(&m, &c.commit)?;
                        trusted::record(&m, "retain");
                        trusted::record_scrub(&m, &goal, true);
                        return Ok(None);
                    }
                    _ => {
                        trusted::record(&m, "broken: the agreed test fails on trunk");
                        trusted::record_scrub(&m, &goal, false);
                        let mut carried = trusted::no_tests();
                        trusted::require(&m, &mut carried, &s0, c);
                        return Ok(Some(carried));
                    }
                }
            }
        }
        a = a + 1;
    }
    Err("blocked: no attempt agreed; see .bon/traces".into())
}

/// bon map: one map search on a transcript, and its proposal for engineer:
/// the agreed intents with their wording, and the contested cues. (intent 10)
pub fn map(root: &str, transcript: Transcript) -> (r: Result<(Vec<(Cue, Intent)>, Vec<Cue>), String>) {
    let head = trusted::head(root)?;
    let m = trusted::manifest(root, &head)?;
    trusted::on_trunk(&m)?;
    let intents = trusted::intents(&m, &head);
    let checks = trusted::checks(&m);
    let limit = trusted::limit(&m);
    let l = trusted::agent_process_limit(&m);
    let (pc, pt, pw, pr) = trusted::observe(&m, &head)?;
    if !isolated(pc, pt, pw, pr) {
        return Err("agent is not isolated: its permissions differ from the policy; run bon setup".into());
    }
    let ghost observed = observed(pc, pt, pw, pr);
    let tracked (Tracked(instance), Tracked(map), Tracked(checks_t), Tracked(trunk), Tracked(authors),
                 Tracked(searches), Tracked(limit_t), Tracked(spent_t), Tracked(reserved), Tracked(capability))
        = spec::bon::Instance::initialize(head@, intent_set(intents@), paths(checks@), limit as nat);
    let tracked mut t = Tokens { instance, map, checks: checks_t, trunk, authors, searches, limit: limit_t, spent: spent_t, reserved };
    let mut spent: u64 = 0;
    trusted::record(&m, "initialize");
    let s = search(&m, 0, 0, Kind::Map { goal: transcript }, head.clone(), &checks, l, limit, &mut spent, None, &trusted::no_tests(),
                   Ghost(observed), Tracked(&mut t))?;
    trusted::record(&m, "proposal");
    Ok((proposed(&s), contested(&s)))
}

} // verus!
