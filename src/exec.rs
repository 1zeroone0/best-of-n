//! The gates, implemented and proved against their contracts in gates.rs.

use vstd::prelude::*;
use crate::spec;
use crate::gates::*;
use crate::trusted;

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

fn is_map_path(p: &Vec<char>) -> (r: bool)
    ensures r == (p@ == spec::map_path()),
{
    let r = p.len() == 3 && p[0] == 'm' && p[1] == 'a' && p[2] == 'p';
    if r { assert(p@ =~= spec::map_path()); }
    r
}

fn is_manifest_path(p: &Vec<char>) -> (r: bool)
    ensures r == (p@ == spec::manifest_path()),
{
    let r = p.len() == 8 && p[0] == 'b' && p[1] == 'o' && p[2] == 'n' && p[3] == '.'
        && p[4] == 't' && p[5] == 'o' && p[6] == 'm' && p[7] == 'l';
    if r { assert(p@ =~= spec::manifest_path()); }
    r
}

// ── isolated ────────────────────────────────────────────

fn permission_is(p: &Permission, read: bool, write: bool, execute: bool) -> (r: bool)
    ensures r == (*p == Permission { read, write, execute }),
{
    p.read == read && p.write == write && p.execute == execute
}

pub fn isolated(checks: Permission, transcripts: Permission, working_directory: Permission, repository: Permission) -> (r: bool)
    ensures r == spec::isolated(observed(checks, transcripts, working_directory, repository)),
{
    let ghost o = observed(checks, transcripts, working_directory, repository);
    let r = permission_is(&checks, true, false, true)
        && permission_is(&transcripts, true, false, true)
        && permission_is(&working_directory, true, true, true)
        && permission_is(&repository, false, false, false);
    proof {
        if r {
            assert forall|f: File| o.contains_key(f) && o[f] == spec::policy(User::agent, f) by {
                match f { File::Checks => {}, File::Transcripts => {}, File::WorkingDirectory => {}, File::Repository => {} }
            }
        } else {
            if !permission_is_spec(checks, true, false, true) {
                assert(o[File::Checks] != spec::policy(User::agent, File::Checks));
            } else if !permission_is_spec(transcripts, true, false, true) {
                assert(o[File::Transcripts] != spec::policy(User::agent, File::Transcripts));
            } else if !permission_is_spec(working_directory, true, true, true) {
                assert(o[File::WorkingDirectory] != spec::policy(User::agent, File::WorkingDirectory));
            } else {
                assert(o[File::Repository] != spec::policy(User::agent, File::Repository));
            }
        }
    }
    r
}

spec fn permission_is_spec(p: Permission, read: bool, write: bool, execute: bool) -> bool {
    p == Permission { read, write, execute }
}

// ── verified ────────────────────────────────────────────

/// No candidate may change p. (spec::protected)
fn protected(checks: &Vec<Path>, p: &Path) -> (r: bool)
    ensures r == spec::protected(paths(checks@), p@),
{
    if is_map_path(p) || is_manifest_path(p) { return true; }
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
        Kind::Map { .. } => is_map_path(p),
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

/// What the view of a complete search says about index i.
proof fn result_at(s: &Search, i: int)
    requires 0 <= i < s.results.len(),
    ensures
        s@.results.contains_key(i),
        s@.results[i] == (match s.results@[i] { Some(c) => Some(c@), None => None::<spec::Candidate> }),
{
}

/// Whether each index of a complete search is verified.
fn verified_each(s: &Search) -> (v: Vec<bool>)
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
        proof { result_at(s, i as int); }
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
    if a.len() != b.len() {
        assert(hashes(a@).len() != hashes(b@).len());
        return false;
    }
    let mut i = 0;
    while i < a.len()
        invariant a.len() == b.len(), 0 <= i <= a.len(), forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] {
            assert(hashes(a@)[i as int] != hashes(b@)[i as int]);
            return false;
        }
        i += 1;
    }
    assert(a@ =~= b@);
    true
}

/// beats is transitive.
proof fn beats_transitive(a: spec::Candidate, ai: int, b: spec::Candidate, bi: int, c: spec::Candidate, ci: int)
    requires spec::beats(a, ai, b, bi), spec::beats(b, bi, c, ci),
    ensures spec::beats(a, ai, c, ci),
{
}

/// The verified candidate at index i of a complete search.
fn candidate(s: &Search, i: usize) -> (c: &Candidate)
    requires i < s.results.len(), spec::verified_at(s@, i as int),
    ensures c@ == spec::at(s@, i as int), c@.rank == c.rank as int, c@.diff == c.diff as nat, c@.out == hashes(c.out@),
{
    proof { result_at(s, i as int); }
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
            sv.kind is Code || sv.kind is Compaction,
            sv.kind is Code ==> hashes(reference@) == spec::at(sv, f as int).out,
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
                proof {
                    let ci = spec::at(sv, i as int);
                    let bi = spec::at(sv, best as int);
                    assert(spec::beats(ci, i as int, bi, best as int));
                    assert forall|j: int| 0 <= j < i + 1 && j != i && v[j] implies
                        spec::beats(ci, i as int, spec::at(sv, j), j) by {
                        if j != best { beats_transitive(ci, i as int, bi, best as int, spec::at(sv, j), j); }
                    }
                }
                best = i;
            } else {
                proof {
                    assert(spec::beats(spec::at(sv, best as int), best as int, spec::at(sv, i as int), i as int));
                }
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
spec fn key(j: Option<usize>) -> int {
    match j { Some(j) => j as int, None => -1 }
}

/// Whether the test passes on member j, if the candidate reported it.
fn test_passes_on(c: &Candidate, j: Option<usize>) -> (r: Option<bool>)
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
        assert forall|i: int| 0 <= i < x.n implies xv.results.contains_key(i) by { result_at(x, i); }
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
    assert forall|i: int| 0 <= i < s.n implies s@.results.contains_key(i) by { result_at(s, i); }
}

/// Two distinct citers make q agreed, and the shortest citer's intent is proposed.
proof fn agreed_and_proposed(sv: spec::Search, q: nat, f: int, g: int, best: int, w: Seq<char>)
    requires
        sv.kind is Map, spec::complete(sv), f != g,
        spec::cites(sv, f, q), spec::cites(sv, g, q), spec::cites(sv, best, q),
        spec::at(sv, best).intents[q] == w,
        forall|j: int| spec::cites(sv, j, q) ==> shortest(sv, q, best, j),
    ensures spec::agreed(sv, q), spec::proposed(sv, q, w),
{
    assert forall|j: int| spec::cites(sv, j, q) implies
        w.len() < spec::at(sv, j).intents[q].len()
        || (w.len() == spec::at(sv, j).intents[q].len() && best <= j) by {
        assert(shortest(sv, q, best, j));
    }
}

/// With at most one citer, q is not agreed.
proof fn not_agreed(sv: spec::Search, q: nat, first: Option<usize>)
    requires
        first is None ==> forall|i: int| !spec::cites(sv, i, q),
        first matches Some(f) ==> forall|i: int| spec::cites(sv, i, q) ==> i == f,
    ensures !spec::agreed(sv, q),
{
    if spec::agreed(sv, q) {
        let (a, b) = choose|a: int, b: int| a != b && spec::cites(sv, a, q) && spec::cites(sv, b, q);
    }
}

/// Pushing keeps every key already present.
proof fn push_keeps<A, B>(before: Seq<(A, B)>, e: (A, B))
    ensures
        forall|y: int| 0 <= y < before.len() ==> before.push(e)[y] == before[y],
        before.push(e)[before.len() as int] == e,
{
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
            proof {
                agreed_and_proposed(sv, q as nat, first->Some_0 as int, second->Some_0 as int, best as int, w@);
            }
            r.push((q, w));
        } else {
            proof { not_agreed(sv, q as nat, first); }
        }
        proof {
            push_keeps(before, (q, r@.last().1));
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
fn eq(a: &Vec<char>, b: &Vec<char>) -> (r: bool)
    ensures r == (a@ == b@),
{
    if a.len() != b.len() { return false; }
    let mut i = 0;
    while i < a.len()
        invariant a.len() == b.len(), 0 <= i <= a.len(), forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] { return false; }
        i += 1;
    }
    assert(a@ =~= b@);
    true
}

/// The spec's map: the set of its intents.
pub open spec fn intent_set(s: Seq<Intent>) -> Set<spec::Intent> {
    s.map_values(|i: Intent| i@).to_set()
}

fn contains(xs: &Vec<Intent>, x: &Intent) -> (r: bool)
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

/// A copy of a list of paths.
fn copy(v: &Vec<Path>) -> (r: Vec<Path>)
    ensures r@.len() == v@.len(), forall|i: int| 0 <= i < v@.len() ==> r@[i]@ == v@[i]@, paths(r@) == paths(v@),
{
    let mut r: Vec<Path> = Vec::new();
    let mut i = 0;
    while i < v.len()
        invariant 0 <= i <= v.len(), r@.len() == i, forall|j: int| 0 <= j < i ==> r@[j]@ == v@[j]@,
        decreases v.len() - i,
    {
        let mut p: Vec<char> = Vec::new();
        let mut j = 0;
        while j < v[i].len()
            invariant i < v.len(), 0 <= j <= v@[i as int].len(), p@ == v@[i as int]@.take(j as int),
            decreases v@[i as int].len() - j,
        {
            p.push(v[i][j]);
            proof { assert(p@ =~= v@[i as int]@.take(j as int + 1)); }
            j += 1;
        }
        proof { assert(p@ =~= v@[i as int]@); }
        r.push(p);
        i += 1;
    }
    proof { assert(r@.map_values(|p: Path| p@) =~= v@.map_values(|p: Path| p@)); }
    r
}

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
    let mut s = Search { kind, base: start, n, checks: copy(checks), limit: l, results: Vec::new() };
    proof {
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
        assert forall|j: int| 0 <= j < s.n implies s@.results.contains_key(j) by { result_at(&s, j); }
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
    trusted::report(m, index, n, verified, generation, started);
    Ok(s)
}


/// bon code (goal is an intent) or bon compaction (no goal). Each attempt is a
/// search and, if it selects, a counterexample search on the selection; trunk
/// fast-forwards once one clears. A blocked attempt reruns wider, carrying the
/// counterexample tests into agreement, until the attempts run out.
/// (intents 2–9, 13, 15–17)
pub fn land(root: &str, goal: Option<Intent>) -> (r: Result<(), String>) {
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
    let mut tests = trusted::no_tests();
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
            Some(g) => Kind::Code { goal: copy_text(g) },
            None => Kind::Compaction { goal: copy_text(&head), out: trusted::agree_outputs(&m, &head, &tests)? },
        };
        let ghost before = t.searches.value();
        let s0 = search(&m, index, a, kind, copy_text(&head), &checks, l, limit, &mut spent, None, &tests,
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
                let start = copy_text(&candidate(&s0, i).commit);
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
    let s = search(&m, 0, 0, Kind::Map { goal: transcript }, copy_text(&head), &checks, l, limit, &mut spent, None, &trusted::no_tests(),
                   Ghost(observed), Tracked(&mut t))?;
    trusted::record(&m, "proposal");
    Ok((proposed(&s), contested(&s)))
}

/// A copy of some text.
fn copy_text(v: &Vec<char>) -> (r: Vec<char>)
    ensures r@ == v@,
{
    let mut p: Vec<char> = Vec::new();
    let mut j = 0;
    while j < v.len()
        invariant 0 <= j <= v.len(), p@ == v@.take(j as int),
        decreases v.len() - j,
    {
        p.push(v[j]);
        proof { assert(p@ =~= v@.take(j as int + 1)); }
        j += 1;
    }
    proof { assert(p@ =~= v@); }
    p
}

// ── the gates ───────────────────────────────────────────

/// The bon process: the process running as engineer that holds the state and
/// passes every decision through a gate.
pub struct BonProcess;

impl Gates for BonProcess {
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
