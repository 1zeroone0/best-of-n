//! The gates, implemented and proved against their contracts in gates.rs.

use vstd::prelude::*;
use crate::spec;
use crate::gates::*;

verus! {

broadcast use {vstd::seq_lib::group_seq_properties, vstd::seq::group_seq_axioms};

// ── text ────────────────────────────────────────────────

/// a is a prefix of b.
fn is_prefix_of(a: &Vec<char>, b: &Vec<char>) -> (r: bool)
    ensures r == a@.is_prefix_of(b@),
{
    if a.len() > b.len() { return false; }
    let mut i = 0;
    while i < a.len()
        invariant a.len() <= b.len(), 0 <= i <= a.len(), forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] {
            assert(a@[i as int] != b@.subrange(0, a.len() as int)[i as int]);
            return false;
        }
        i += 1;
    }
    assert(a@ =~= b@.subrange(0, a.len() as int));
    true
}

// ── isolated ────────────────────────────────────────────

pub fn isolated(checks: Permission, transcripts: Permission, working_directory: Permission, repository: Permission) -> (r: bool)
    ensures r == spec::isolated(observed(checks, transcripts, working_directory, repository)),
{
    let ghost o = observed(checks, transcripts, working_directory, repository);
    let r = (checks.read && !checks.write && checks.execute)
        && (transcripts.read && !transcripts.write && transcripts.execute)
        && (working_directory.read && working_directory.write && working_directory.execute)
        && (!repository.read && !repository.write && !repository.execute);
    assert forall|f: File| o.contains_key(f) && (r ==> o[f] == spec::policy(User::agent, f)) by {
        match f { File::Checks => {}, File::Transcripts => {}, File::WorkingDirectory => {}, File::Repository => {} }
    }
    proof {
        if spec::isolated(o) {
            assert(o[File::Checks] == spec::policy(User::agent, File::Checks));
            assert(o[File::Transcripts] == spec::policy(User::agent, File::Transcripts));
            assert(o[File::WorkingDirectory] == spec::policy(User::agent, File::WorkingDirectory));
            assert(o[File::Repository] == spec::policy(User::agent, File::Repository));
        }
    }
    r
}

// ── verified ────────────────────────────────────────────

/// No candidate may change p. (spec::protected)
fn protected(checks: &Vec<Path>, p: &Path) -> (r: bool)
    ensures r == spec::protected(paths(checks@), p@),
{
    if eq(p, &vec!['m', 'a', 'p']) || eq(p, &vec!['b', 'o', 'n', '.', 't', 'o', 'm', 'l']) { return true; }
    let mut i = 0;
    while i < checks.len()
        invariant
            0 <= i <= checks.len(),
            p@ != spec::map_path() && p@ != spec::manifest_path(),
            forall|j: int| 0 <= j < i ==> !checks@[j]@.is_prefix_of(p@),
        decreases checks.len() - i,
    {
        if is_prefix_of(&checks[i], p) {
            proof {
                let c = checks@[i as int]@;
                assert(checks@.map_values(|q: Path| q@)[i as int] == c);
                assert(paths(checks@).contains(c));
            }
            return true;
        }
        i += 1;
    }
    proof {
        assert forall|c: spec::Path| paths(checks@).contains(c) implies !c.is_prefix_of(p@) by {
            let s = checks@.map_values(|q: Path| q@);
            assert(s.contains(c));
            let j = choose|j: int| 0 <= j < s.len() && s[j] == c;
            assert(checks@[j]@ == c);
        }
    }
    false
}

/// p is within the authority of a search of this kind.
fn authority_contains(kind: &Kind, checks: &Vec<Path>, p: &Path) -> (r: bool)
    ensures r == spec::authority(kind@, paths(checks@)).contains(p@),
{
    match kind {
        Kind::Map { .. } => eq(p, &vec!['m', 'a', 'p']),
        Kind::Scrub { path, .. } => eq(p, path),
        _ => !protected(checks, p),
    }
}

pub fn verified(s: &Search, c: &Candidate) -> (r: bool)
    ensures r == spec::verified(s@, c@),
{
    if !c.checks_pass { return false; }
    let mut i = 0;
    while i < c.changed.len()
        invariant
            0 <= i <= c.changed.len(),
            forall|j: int| 0 <= j < i ==> s@.authority.contains(#[trigger] c.changed@[j]@),
        decreases c.changed.len() - i,
    {
        proof { assert(s@.authority == spec::authority(s.kind@, paths(s.checks@))); }
        if !authority_contains(&s.kind, &s.checks, &c.changed[i]) {
            proof {
                let p = c.changed@[i as int]@;
                assert(c.changed@.map_values(|q: Path| q@)[i as int] == p);
                assert(c@.changed.contains(p));
                assert(s@.authority == spec::authority(s.kind@, paths(s.checks@)));
                assert(!s@.authority.contains(p));
            }
            return false;
        }
        i += 1;
    }
    proof {
        assert forall|p: spec::Path| c@.changed.contains(p) implies s@.authority.contains(p) by {
            let m = c.changed@.map_values(|q: Path| q@);
            assert(m.contains(p));
            let j = choose|j: int| 0 <= j < m.len() && m[j] == p;
            assert(c.changed@[j]@ == p);
        }
    }
    true
}


// ── selected ────────────────────────────────────────────

/// Whether each index of a complete search is verified.
pub fn verified_each(s: &Search) -> (v: Vec<bool>)
    requires s.results.len() == s.n,
    ensures v.len() == s.n, forall|i: int| 0 <= i < s.n ==> v[i] == spec::verified_at(s@, i),
{
    let mut v: Vec<bool> = Vec::new();
    let mut i = 0;
    while i < s.results.len()
        invariant
            s.results.len() == s.n, 0 <= i <= s.n, v.len() == i,
            forall|j: int| 0 <= j < i ==> v[j] == spec::verified_at(s@, j),
        decreases s.results.len() - i,
    {
        let b = match &s.results[i] {
            Some(c) => verified(s, c),
            None => false,
        };
        v.push(b);
        i += 1;
    }
    v
}

/// The two outputs are the eq, as the spec sees them.
fn eq_out(a: &Vec<u64>, b: &Vec<u64>) -> (r: bool)
    ensures r == (hashes(a@) == hashes(b@)),
{
    let r = a == b;
    proof {
        assert(a@ =~= hashes(a@).map_values(|h: nat| h as u64));
        assert(b@ =~= hashes(b@).map_values(|h: nat| h as u64));
        if r { assert(hashes(a@) =~= hashes(b@)); }
    }
    r
}

/// The verified candidate at index i of a complete search.
pub fn candidate(s: &Search, i: usize) -> (c: &Candidate)
    requires i < s.results.len(), spec::verified_at(s@, i as int),
    ensures c@ == spec::at(s@, i as int), c@.rank == c.rank as int, c@.diff == c.diff as nat, c@.out == hashes(c.out@),
{
    match &s.results[i] { Some(c) => c, None => vstd::pervasive::unreached() }
}

pub fn selected(s: &Search) -> (r: Option<usize>)
    requires s.results.len() == s.n,
    ensures
        r matches Some(i) ==> spec::selected(s@, i as int),
        r is None ==> forall|i: int| !spec::selected(s@, i),
{
    let v = verified_each(s);
    let ghost sv = s@;
    // Only code and compaction searches select.
    match &s.kind {
        Kind::Code { .. } => {},
        Kind::Compaction { .. } => {},
        Kind::Scrub { .. } => {},
        _ => {
            assert(forall|i: int| !spec::agree(sv) ==> !spec::selected(sv, i));
            return None;
        }
    }
    // The first two verified indices.
    let mut first: Option<usize> = None;
    let mut second: Option<usize> = None;
    let mut i = 0;
    while i < v.len()
        invariant
            sv == s@, v.len() == s.n, s.results.len() == s.n, 0 <= i <= v.len(),
            forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(sv, j),
            first is None ==> forall|j: int| 0 <= j < i ==> !v[j],
            first matches Some(f) ==> f < i && v[f as int] && forall|j: int| 0 <= j < f ==> !v[j],
            second matches Some(g) ==> first matches Some(f) && f < g < i && v[g as int],
            second is None ==> (first matches Some(f) ==> forall|j: int| f < j < i ==> !v[j]),
        decreases v.len() - i,
    {
        if v[i] && second.is_none() {
            if first.is_none() { first = Some(i); } else { second = Some(i); }
        }
        i += 1;
    }
    let (f, g) = match (first, second) {
        (Some(f), Some(g)) => (f, g),
        _ => {
            assert forall|k: int| !spec::selected(sv, k) by {
                assert(!(exists|a: int, b: int| a != b && spec::verified_at(sv, a) && spec::verified_at(sv, b)));
            }
            return None;
        }
    };
    // Every verified candidate prints the reference: the first verified
    // candidate's output for code, the goal's for compaction.
    let reference: &Vec<u64> = match &s.kind {
        Kind::Compaction { out, .. } => out,
        _ => { let c = candidate(s, f); &c.out },
    };
    proof {
        match &s.kind {
            Kind::Compaction { out, .. } => { assert(reference@ == out@); }
            _ => { assert(hashes(reference@) == spec::at(sv, f as int).out); }
        }
    }
    let mut i = 0;
    while i < v.len()
        invariant
            sv == s@, v.len() == s.n, s.results.len() == s.n, 0 <= i <= v.len(),
            forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(sv, j),
            forall|j: int| 0 <= j < i && v[j] ==> spec::at(sv, j).out == hashes(reference@),
            f < s.n, spec::verified_at(sv, f as int),
            sv.kind is Code || sv.kind is Compaction || sv.kind is Scrub,
            (sv.kind is Code || sv.kind is Scrub) ==> hashes(reference@) == spec::at(sv, f as int).out,
            sv.kind matches spec::Kind::Compaction { out, .. } ==> out == hashes(reference@),
        decreases v.len() - i,
    {
        if v[i] {
            let c = candidate(s, i);
            if !eq_out(&c.out, reference) {
                proof {
                    assert(spec::at(sv, i as int).out != hashes(reference@));
                    match &s.kind {
                        Kind::Compaction { goal, out } => {
                            assert(sv.kind == (spec::Kind::Compaction { goal: goal@, out: hashes(out@) }));
                            assert(hashes(out@) == hashes(reference@));
                            if spec::agree(sv) {
                                assert(spec::verified_at(sv, i as int));
                                assert(spec::at(sv, i as int).out == hashes(out@));
                            }
                        }
                        _ => {
                            assert(spec::verified_at(sv, f as int) && spec::verified_at(sv, i as int));
                            assert(!spec::agree(sv));
                        }
                    }
                }
                return None;
            }
        }
        i += 1;
    }
    proof {
        assert(spec::agree(sv)) by {
            assert(f != g && spec::verified_at(sv, f as int) && spec::verified_at(sv, g as int));
        }
    }
    // The highest rank, then the smallest diff, then the earliest.
    let mut best = f;
    let mut i = f + 1;
    while i < v.len()
        invariant
            sv == s@, v.len() == s.n, s.results.len() == s.n, f < i <= v.len(), f <= best < i,
            forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(sv, j),
            spec::verified_at(sv, best as int),
            forall|j: int| 0 <= j < f ==> !v[j],
            forall|j: int| 0 <= j < i && j != best && v[j] ==>
                spec::beats(spec::at(sv, best as int), best as int, spec::at(sv, j), j),
        decreases v.len() - i,
    {
        if v[i] {
            let c = candidate(s, i);
            let b = candidate(s, best);
            if c.rank > b.rank || (c.rank == b.rank && c.diff < b.diff) {
                best = i;
            }
        }
        i += 1;
    }
    Some(best)
}

// ── cleared ─────────────────────────────────────────────

/// The first pair with a key is unique.
proof fn first_by_key_at<K, V>(s: Seq<(K, V)>, k: K, i: int)
    requires 0 <= i < s.len(), s[i].0 == k, forall|j: int| 0 <= j < i ==> s[j].0 != k,
    ensures first(s, k) == i, first_by_key(s).contains_key(k), first_by_key(s)[k] == s[i].1,
{
    let f = first(s, k);
    assert(s.map_values(|e: (K, V)| e.0)[i] == k);
    assert(s.map_values(|e: (K, V)| e.0).to_set().contains(k));
    if f < i { assert(s[f].0 != k); }
    if f > i { assert(s[i].0 != k); }
}

/// No pair has the key.
proof fn first_by_key_absent<K, V>(s: Seq<(K, V)>, k: K)
    requires forall|j: int| 0 <= j < s.len() ==> s[j].0 != k,
    ensures !first_by_key(s).contains_key(k),
{
    let m = s.map_values(|e: (K, V)| e.0);
    if m.to_set().contains(k) {
        assert(m.contains(k));
        let j = choose|j: int| 0 <= j < m.len() && m[j] == k;
        assert(s[j].0 == k);
    }
}

/// The spec key of a member: index j, or -1 for a compaction search's goal.
pub open spec fn key(j: Option<usize>) -> int {
    match j { Some(j) => j as int, None => -1 }
}

/// Whether the test passes on member j, if the candidate reported it.
pub fn test_passes_on(c: &Candidate, j: Option<usize>) -> (r: Option<bool>)
    ensures
        r matches Some(b) ==> c@.test_passes.contains_key(key(j)) && c@.test_passes[key(j)] == b,
        r is None ==> !c@.test_passes.contains_key(key(j)),
{
    let ghost s = c.test_passes@.map_values(|e: (i64, bool)| (e.0 as int, e.1));
    let mut i = 0;
    while i < c.test_passes.len()
        invariant
            0 <= i <= c.test_passes.len(),
            s == c.test_passes@.map_values(|e: (i64, bool)| (e.0 as int, e.1)),
            forall|m: int| 0 <= m < i ==> s[m].0 != key(j),
        decreases c.test_passes.len() - i,
    {
        let (k, b) = c.test_passes[i];
        let hit = match j { Some(j) => (k as i128) == (j as i128), None => k == -1 };
        if hit {
            proof { first_by_key_at(s, key(j), i as int); }
            return Some(b);
        }
        i += 1;
    }
    proof { first_by_key_absent(s, key(j)); }
    None
}

/// c's test splits t's members.
fn splits(t: &Search, vt: &Vec<bool>, c: &Candidate) -> (r: bool)
    requires t.results.len() == t.n, vt.len() == t.n,
        forall|j: int| 0 <= j < t.n ==> vt[j] == spec::verified_at(t@, j),
    ensures r == spec::splits(t@, c@),
{
    let ghost tv = t@;
    let ghost tp = c@.test_passes;
    let mut value: Option<bool> = None;
    let ghost mut w: int = -1;
    match &t.kind {
        Kind::Compaction { .. } => {
            match test_passes_on(c, None) {
                None => {
                    assert(spec::member(tv, -1));
                    return true;
                }
                Some(b) => { value = Some(b); proof { w = -1; } }
            }
        }
        _ => {}
    }
    let mut j = 0;
    while j < vt.len()
        invariant
            tv == t@, tp == c@.test_passes, vt.len() == t.n, 0 <= j <= vt.len(),
            forall|m: int| 0 <= m < t.n ==> vt[m] == spec::verified_at(tv, m),
            value is None ==> !(tv.kind is Compaction) && forall|m: int| 0 <= m < j ==> !vt[m],
            value matches Some(v) ==> forall|m: int| spec::member(tv, m) && m < j ==>
                tp.contains_key(m) && tp[m] == v,
            value matches Some(v) ==> spec::member(tv, w) && w < j && tp.contains_key(w) && tp[w] == v,
        decreases vt.len() - j,
    {
        if vt[j] {
            match test_passes_on(c, Some(j)) {
                None => {
                    assert(spec::member(tv, j as int));
                    return true;
                }
                Some(b) => {
                    match value {
                        Some(v) => {
                            if b != v {
                                proof {
                                    assert(spec::member(tv, w) && spec::member(tv, j as int));
                                    assert(tp[w] != tp[j as int]);
                                }
                                return true;
                            }
                        }
                        None => { value = Some(b); proof { w = j as int; } }
                    }
                }
            }
        }
        j += 1;
    }
    proof {
        assert forall|j1: int, j2: int| spec::member(tv, j1) && spec::member(tv, j2) implies
            tp.contains_key(j1) && tp.contains_key(j2) && tp[j1] == tp[j2] by {
            assert(j1 < t.n && j2 < t.n);
        }
    }
    false
}

pub fn cleared(x: &Search, t: &Search) -> (r: bool)
    requires x.results.len() == x.n, t.results.len() == t.n,
    ensures r == spec::cleared(x@, t@),
{
    let ghost xv = x@;
    assert(spec::complete(xv)) by {
        assert forall|i: int| 0 <= i < x.n implies xv.results.contains_key(i) by {}
    }
    let vx = verified_each(x);
    let vt = verified_each(t);
    let mut i = 0;
    while i < vx.len()
        invariant
            xv == x@, vx.len() == x.n, x.results.len() == x.n, 0 <= i <= vx.len(),
            t.results.len() == t.n, vt.len() == t.n,
            forall|m: int| 0 <= m < x.n ==> vx[m] == spec::verified_at(xv, m),
            forall|m: int| 0 <= m < t.n ==> vt[m] == spec::verified_at(t@, m),
            spec::complete(xv),
            forall|m: int| 0 <= m < i && spec::verified_at(xv, m) ==> !spec::splits(t@, spec::at(xv, m)),
        decreases vx.len() - i,
    {
        if vx[i] {
            let c = candidate(x, i);
            if splits(t, &vt, c) {
                assert(spec::verified_at(xv, i as int) && spec::splits(t@, spec::at(xv, i as int)));
                return false;
            }
        }
        i += 1;
    }
    proof {
        assert forall|m: int| spec::verified_at(xv, m) implies !spec::splits(t@, spec::at(xv, m)) by {
            assert(0 <= m < x.n);
        }
    }
    true
}

// ── proposed, contested ─────────────────────────────────

/// The intent candidate c gives cue q, if it cites q.
fn intent(c: &Candidate, q: Cue) -> (r: Option<&Intent>)
    ensures
        r matches Some(w) ==> c@.intents.contains_key(q as nat) && c@.intents[q as nat] == w@,
        r is None ==> !c@.intents.contains_key(q as nat),
{
    let ghost s = c.intents@.map_values(|e: (Cue, Intent)| (e.0 as nat, e.1@));
    let mut i = 0;
    while i < c.intents.len()
        invariant
            0 <= i <= c.intents.len(),
            s == c.intents@.map_values(|e: (Cue, Intent)| (e.0 as nat, e.1@)),
            forall|m: int| 0 <= m < i ==> s[m].0 != q as nat,
        decreases c.intents.len() - i,
    {
        if c.intents[i].0 == q {
            proof { first_by_key_at(s, q as nat, i as int); }
            return Some(&c.intents[i].1);
        }
        i += 1;
    }
    proof { first_by_key_absent(s, q as nat); }
    None
}

/// w at index i is at least as short as at index j for cue q, ties to the earlier.
spec fn shortest(s: spec::Search, q: nat, i: int, j: int) -> bool {
    spec::at(s, i).intents[q].len() < spec::at(s, j).intents[q].len()
    || (spec::at(s, i).intents[q].len() == spec::at(s, j).intents[q].len() && i <= j)
}

/// Who cites q: the first two citing indices, and the one with the shortest intent.
#[verifier::rlimit(100)]
fn cites(s: &Search, v: &Vec<bool>, q: Cue) -> (r: (Option<usize>, Option<usize>, usize))
    requires s.results.len() == s.n, v.len() == s.n,
        forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(s@, j),
    ensures
        r.0 is None ==> forall|i: int| !spec::cites(s@, i, q as nat),
        r.0 matches Some(f) ==> spec::cites(s@, f as int, q as nat)
            && spec::cites(s@, r.2 as int, q as nat)
            && forall|j: int| spec::cites(s@, j, q as nat) ==> shortest(s@, q as nat, r.2 as int, j),
        r.1 matches Some(g) ==> (r.0 matches Some(f) && f != g && spec::cites(s@, g as int, q as nat)),
        r.1 is None ==> (r.0 matches Some(f) ==> forall|i: int| spec::cites(s@, i, q as nat) ==> i == f),
{
    let ghost sv = s@;
    let mut first: Option<usize> = None;
    let mut second: Option<usize> = None;
    let mut best: usize = 0;
    let mut i = 0;
    while i < v.len()
        invariant
            sv == s@, s.results.len() == s.n, v.len() == s.n, 0 <= i <= v.len(),
            forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(sv, j),
            first is None ==> forall|j: int| 0 <= j < i ==> !spec::cites(sv, j, q as nat),
            first matches Some(f) ==> f < i && spec::cites(sv, f as int, q as nat)
                && best < i && spec::cites(sv, best as int, q as nat)
                && forall|j: int| 0 <= j < i && spec::cites(sv, j, q as nat) ==> shortest(sv, q as nat, best as int, j),
            second matches Some(g) ==> (first matches Some(f) && f < g && g < i && spec::cites(sv, g as int, q as nat)),
            second is None ==> (first matches Some(f) ==> forall|j: int| 0 <= j < i && spec::cites(sv, j, q as nat) ==> j == f),
        decreases v.len() - i,
    {
        if v[i] {
            let c = candidate(s, i);
            match intent(c, q) {
                None => {}
                Some(w) => {
                    match first {
                        None => { first = Some(i); best = i; }
                        Some(_) => {
                            if second.is_none() { second = Some(i); }
                            let b = candidate(s, best);
                            let bw = match intent(b, q) { Some(bw) => bw, None => vstd::pervasive::unreached() };
                            if w.len() < bw.len() {
                                proof {
                                    assert forall|j: int| 0 <= j < i + 1 && spec::cites(sv, j, q as nat)
                                        implies shortest(sv, q as nat, i as int, j) by {
                                        if j != i { assert(shortest(sv, q as nat, best as int, j)); }
                                    }
                                }
                                best = i;
                            }
                        }
                    }
                }
            }
        }
        proof {
            assert forall|j: int| 0 <= j < i + 1 && !spec::verified_at(sv, j) implies !spec::cites(sv, j, q as nat) by {}
        }
        i += 1;
    }
    proof {
        assert forall|j: int| spec::cites(sv, j, q as nat) implies 0 <= j < s.n by {}
    }
    (first, second, best)
}

/// Every cue some verified candidate cites, once each.
fn cues(s: &Search, v: &Vec<bool>) -> (r: Vec<Cue>)
    requires s.results.len() == s.n, v.len() == s.n,
        forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(s@, j),
    ensures forall|q: Cue, i: int| spec::cites(s@, i, q as nat) ==> r@.contains(q),
{
    let ghost sv = s@;
    let mut r: Vec<Cue> = Vec::new();
    let mut i = 0;
    while i < v.len()
        invariant
            sv == s@, s.results.len() == s.n, v.len() == s.n, 0 <= i <= v.len(),
            forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(sv, j),
            forall|q: Cue, j: int| 0 <= j < i && spec::cites(sv, j, q as nat) ==> r@.contains(q),
        decreases v.len() - i,
    {
        if v[i] {
            let c = candidate(s, i);
            let ghost m = c.intents@.map_values(|e: (Cue, Intent)| (e.0 as nat, e.1@));
            let mut k = 0;
            while k < c.intents.len()
                invariant
                    sv == s@, 0 <= k <= c.intents.len(), i < s.n,
                    m == c.intents@.map_values(|e: (Cue, Intent)| (e.0 as nat, e.1@)),
                    c@ == spec::at(sv, i as int),
                    forall|q: Cue, j: int| 0 <= j < i && spec::cites(sv, j, q as nat) ==> r@.contains(q),
                    forall|p: int| 0 <= p < k ==> r@.contains(c.intents@[p].0),
                decreases c.intents.len() - k,
            {
                let q = c.intents[k].0;
                let mut seen = false;
                let mut p = 0;
                while p < r.len()
                    invariant 0 <= p <= r.len(), !seen ==> forall|x: int| 0 <= x < p ==> r@[x] != q, seen ==> r@.contains(q),
                    decreases r.len() - p,
                {
                    if r[p] == q { seen = true; }
                    p += 1;
                }
                let ghost before = r@;
                if !seen { r.push(q); }
                proof {
                    assert(r@.contains(q)) by {
                        if !seen { assert(r@[r.len() - 1] == q); }
                    }
                    assert forall|q2: Cue| before.contains(q2) implies r@.contains(q2) by {
                        let x = choose|x: int| 0 <= x < before.len() && before[x] == q2;
                        assert(r@[x] == q2);
                    }
                }
                k += 1;
            }
            proof {
                assert forall|q: Cue| spec::cites(sv, i as int, q as nat) implies r@.contains(q) by {
                    let keys = m.map_values(|e: (nat, Seq<char>)| e.0);
                    assert(c@.intents.contains_key(q as nat));
                    assert(keys.to_set().contains(q as nat));
                    assert(keys.contains(q as nat));
                    let p = choose|p: int| 0 <= p < keys.len() && keys[p] == q as nat;
                    assert(c.intents@[p].0 == q);
                }
            }
        }
        proof {
            assert forall|q: Cue| !spec::verified_at(sv, i as int) implies !spec::cites(sv, i as int, q as nat) by {}
        }
        i += 1;
    }
    proof {
        assert forall|q: Cue, j: int| spec::cites(sv, j, q as nat) implies r@.contains(q) by { assert(0 <= j < s.n); }
    }
    r
}

/// A complete search, as the view sees it.
proof fn complete(s: &Search)
    requires s.results.len() == s.n,
    ensures spec::complete(s@),
{
    assert forall|i: int| 0 <= i < s.n implies s@.results.contains_key(i) by {}
}

#[verifier::rlimit(100)]
pub fn proposed(s: &Search) -> (r: Vec<(Cue, Intent)>)
    requires s.results.len() == s.n,
    ensures
        forall|k: int| 0 <= k < r.len() ==> spec::proposed(s@, r[k].0 as nat, r[k].1@),
        forall|q: Cue, w: Seq<char>| spec::proposed(s@, q as nat, w) ==>
            exists|k: int| 0 <= k < r.len() && r[k].0 == q,
{
    hide(spec::proposed);
    hide(spec::agreed);
    let ghost sv = s@;
    let mut r: Vec<(Cue, Intent)> = Vec::new();
    match &s.kind { Kind::Map { .. } => {}, _ => { proof { reveal(spec::proposed); } return r; } }
    proof { complete(s); }
    let v = verified_each(s);
    let qs = cues(s, &v);
    let mut k = 0;
    while k < qs.len()
        invariant
            sv == s@, sv.kind is Map, spec::complete(sv), s.results.len() == s.n, v.len() == s.n, 0 <= k <= qs.len(),
            forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(sv, j),
            forall|x: int| 0 <= x < r.len() ==> #[trigger] spec::proposed(sv, r[x].0 as nat, r[x].1@),
            forall|x: int| 0 <= x < k && #[trigger] spec::agreed(sv, qs@[x] as nat) ==>
                exists|y: int| 0 <= y < r.len() && r[y].0 == qs@[x],
        decreases qs.len() - k,
    {
        let q = qs[k];
        let (first, second, best) = cites(s, &v, q);
        let ghost before = r@;
        if second.is_some() {
            let c = candidate(s, best);
            let w = match intent(c, q) { Some(w) => w.clone(), None => vstd::pervasive::unreached() };
            proof { reveal(spec::proposed); reveal(spec::agreed); }
            r.push((q, w));
        } else {
            proof { reveal(spec::agreed); }
        }
        proof {
            assert forall|x: int| 0 <= x < k + 1 && #[trigger] spec::agreed(sv, qs@[x] as nat) implies
                exists|y: int| 0 <= y < r.len() && r[y].0 == qs@[x] by {
                if x < k {
                    let y = choose|y: int| 0 <= y < before.len() && before[y].0 == qs@[x];
                    assert(r@[y] == before[y]);
                } else {
                    assert(r@[r.len() - 1].0 == q);
                }
            }
        }
        k += 1;
    }
    proof {
        assert forall|q: Cue, w: Seq<char>| spec::proposed(sv, q as nat, w) implies
            exists|y: int| 0 <= y < r.len() && r[y].0 == q by {
            reveal(spec::proposed);
            assert(spec::agreed(sv, q as nat));
            reveal(spec::agreed);
            let (a, b) = choose|a: int, b: int| a != b && spec::cites(sv, a, q as nat) && spec::cites(sv, b, q as nat);
            assert(qs@.contains(q));
            let x = choose|x: int| 0 <= x < qs.len() && qs@[x] == q;
            assert(spec::agreed(sv, qs@[x] as nat));
        }
    }
    r
}

#[verifier::rlimit(100)]
pub fn contested(s: &Search) -> (r: Vec<Cue>)
    requires s.results.len() == s.n,
    ensures
        forall|k: int| 0 <= k < r.len() ==> spec::contested(s@, r[k] as nat),
        forall|q: Cue| spec::contested(s@, q as nat) ==> r@.contains(q),
{
    let ghost sv = s@;
    proof { complete(s); }
    let v = verified_each(s);
    let qs = cues(s, &v);
    let mut r: Vec<Cue> = Vec::new();
    let mut k = 0;
    while k < qs.len()
        invariant
            sv == s@, spec::complete(sv), s.results.len() == s.n, v.len() == s.n, 0 <= k <= qs.len(),
            forall|j: int| 0 <= j < s.n ==> v[j] == spec::verified_at(sv, j),
            forall|q: Cue, i: int| spec::cites(sv, i, q as nat) ==> qs@.contains(q),
            forall|x: int| 0 <= x < r.len() ==> spec::contested(sv, r[x] as nat),
            forall|x: int| 0 <= x < k && spec::contested(sv, qs@[x] as nat) ==> r@.contains(qs@[x]),
        decreases qs.len() - k,
    {
        let q = qs[k];
        let (first, second, _) = cites(s, &v, q);
        let ghost before = r@;
        if first.is_some() && second.is_none() {
            r.push(q);
        } else {
            proof {
                if spec::contested(sv, q as nat) {
                    let i = choose|i: int| spec::cites(sv, i, q as nat);
                    if first is Some {
                        let f = first->Some_0 as int;
                        let g = second->Some_0 as int;
                        assert(spec::cites(sv, f, q as nat) && spec::cites(sv, g, q as nat) && f != g);
                    }
                }
            }
        }
        proof {
            assert forall|x: int| 0 <= x < k + 1 && spec::contested(sv, qs@[x] as nat) implies r@.contains(qs@[x]) by {
                if x < k {
                    let y = choose|y: int| 0 <= y < before.len() && before[y] == qs@[x];
                    assert(r@[y] == before[y]);
                } else {
                    assert(r@[r.len() - 1] == q);
                }
            }
        }
        k += 1;
    }
    proof {
        assert forall|q: Cue| spec::contested(sv, q as nat) implies r@.contains(q) by {
            let i = choose|i: int| spec::cites(sv, i, q as nat);
            assert(qs@.contains(q));
            let x = choose|x: int| 0 <= x < qs.len() && qs@[x] == q;
        }
    }
    r
}

// ── driving the state machine ───────────────────────────

/// a and b are the same text.
pub fn eq(a: &Vec<char>, b: &Vec<char>) -> (r: bool)
    ensures r == (a@ == b@),
{
    a.len() == b.len() && is_prefix_of(a, b)
}

/// The spec's map: the set of its intents.
pub open spec fn intent_set(s: Seq<Intent>) -> Set<spec::Intent> {
    s.map_values(|i: Intent| i@).to_set()
}

pub fn contains(xs: &Vec<Intent>, x: &Intent) -> (r: bool)
    ensures r == intent_set(xs@).contains(x@),
{
    let mut i = 0;
    while i < xs.len()
        invariant 0 <= i <= xs.len(), forall|j: int| 0 <= j < i ==> xs@[j]@ != x@,
        decreases xs.len() - i,
    {
        if eq(&xs[i], x) {
            proof { assert(xs@.map_values(|i: Intent| i@)[i as int] == x@); }
            return true;
        }
        i += 1;
    }
    proof {
        if intent_set(xs@).contains(x@) {
            let m = xs@.map_values(|i: Intent| i@);
            assert(m.contains(x@));
            let j = choose|j: int| 0 <= j < m.len() && m[j] == x@;
            assert(xs@[j]@ == x@);
        }
    }
    false
}

/// The kernel: the spec, the gates and their implementation. The bon process
/// and every program call it; it is compiled into each. (intent 27)
pub struct Kernel;

impl Gates for Kernel {
    fn isolated(checks: Permission, transcripts: Permission, working_directory: Permission, repository: Permission) -> (r: bool) {
        isolated(checks, transcripts, working_directory, repository)
    }
    fn verified(s: &Search, c: &Candidate) -> (r: bool) { verified(s, c) }
    fn selected(s: &Search) -> (r: Option<usize>) { selected(s) }
    fn cleared(x: &Search, t: &Search) -> (r: bool) { cleared(x, t) }
    fn proposed(s: &Search) -> (r: Vec<(Cue, Intent)>) { proposed(s) }
    fn contested(s: &Search) -> (r: Vec<Cue>) { contested(s) }
}

} // verus!
