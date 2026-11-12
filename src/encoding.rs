//! Compositional, verified wire codecs used by the kernel.
use vstd::prelude::*;
use vstd::string::StrSliceExecFns;
use crate::gates::*;
use crate::exec::Kernel;

verus! {
broadcast use {vstd::seq_lib::group_seq_properties, vstd::seq::group_seq_axioms};

trait Wire: Sized {
    type Model;
    spec fn model(&self) -> Self::Model;
    spec fn valid_model(m: Self::Model) -> bool;
    proof fn valid(&self) ensures Self::valid_model(self.model());
    spec fn words(m: Self::Model) -> Seq<u64>;
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)>;
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>)
        requires Self::valid_model(m),
        ensures Self::words(m).len() > 0,
            Self::parse(Self::words(m) + tail) == Some((m, tail));
    fn write(&self) -> (r: Vec<u64>) ensures r@ == Self::words(self.model());
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>)
        ensures match r { Some((v, tail)) => Self::parse(w@) == Some((v.model(), tail@)), None => Self::parse(w@) is None };
}

fn append<T: Copy>(a: &mut Vec<T>, b: &Vec<T>)
    ensures final(a)@ == old(a)@ + b@,
{
    let ghost before = a@;
    let mut i = 0;
    while i < b.len()
        invariant 0 <= i <= b.len(), a@ == before + b@.take(i as int),
        decreases b.len() - i,
    { a.push(b[i]); i += 1; }
}

fn suffix(w: &Vec<u64>, n: usize) -> (r: Vec<u64>)
    requires n <= w.len(), ensures r@ == w@.skip(n as int),
{
    let mut r = Vec::new();
    let mut i = n;
    while i < w.len()
        invariant n <= i <= w.len(), r@ == w@.subrange(n as int, i as int),
        decreases w.len() - i,
    { r.push(w[i]); i += 1; }
    r
}

impl Wire for u64 {
    type Model = u64;
    spec fn model(&self) -> u64 { *self }
    spec fn valid_model(m: u64) -> bool { true }
    proof fn valid(&self) {}
    spec fn words(m: u64) -> Seq<u64> { seq![m] }
    spec fn parse(w: Seq<u64>) -> Option<(u64, Seq<u64>)> {
        if w.len() == 0 { None } else { Some((w[0], w.skip(1))) }
    }
    proof fn roundtrip(m: u64, tail: Seq<u64>) {}
    fn write(&self) -> (r: Vec<u64>) { vec![*self] }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        if w.len() == 0 { None } else { Some((w[0], suffix(w, 1))) }
    }
}

impl Wire for Hash {
    type Model = Hash;
    spec fn model(&self) -> Hash { *self }
    spec fn valid_model(m: Hash) -> bool { true }
    proof fn valid(&self) {}
    spec fn words(m: Hash) -> Seq<u64> { seq![m.0] }
    spec fn parse(w: Seq<u64>) -> Option<(Hash, Seq<u64>)> {
        if w.len() == 0 { None } else { Some((Hash(w[0]), w.skip(1))) }
    }
    proof fn roundtrip(m: Hash, tail: Seq<u64>) {}
    fn write(&self) -> (r: Vec<u64>) { vec![self.0] }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        if w.len() == 0 { None } else { Some((Hash(w[0]), suffix(w, 1))) }
    }
}

impl<A: Wire, B: Wire> Wire for (A, B) {
    type Model = (A::Model, B::Model);
    spec fn model(&self) -> Self::Model { (self.0.model(), self.1.model()) }
    spec fn valid_model(m: Self::Model) -> bool { A::valid_model(m.0) && B::valid_model(m.1) }
    proof fn valid(&self) { self.0.valid(); self.1.valid(); }
    spec fn words(m: Self::Model) -> Seq<u64> { A::words(m.0) + B::words(m.1) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> {
        match A::parse(w) { Some((a, t)) => match B::parse(t) {
            Some((b, rest)) => Some(((a, b), rest)), None => None }, None => None }
    }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) {
        A::roundtrip(m.0, B::words(m.1) + tail);
        B::roundtrip(m.1, tail);
        assert((A::words(m.0) + B::words(m.1)) + tail =~= A::words(m.0) + (B::words(m.1) + tail));
        assert(A::parse(Self::words(m) + tail) == Some((m.0, B::words(m.1) + tail)));
        assert(Self::parse(Self::words(m) + tail) == Some((m, tail)));
    }
    fn write(&self) -> (r: Vec<u64>) {
        let mut a = self.0.write(); let b = self.1.write(); append(&mut a, &b); a
    }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        let (a, t) = match A::read(w) { Some(v) => v, None => return None };
        let (b, rest) = match B::read(&t) { Some(v) => v, None => return None };
        Some(((a, b), rest))
    }
}

spec fn many_words<T: Wire>(ms: Seq<T::Model>) -> Seq<u64>
    decreases ms.len(),
{
    if ms.len() == 0 { seq![] } else { T::words(ms[0]) + many_words::<T>(ms.skip(1)) }
}
spec fn many_parse<T: Wire>(n: nat, w: Seq<u64>) -> Option<(Seq<T::Model>, Seq<u64>)>
    decreases n,
{
    if n == 0 { Some((seq![], w)) }
    else { match T::parse(w) { Some((m, t)) => match many_parse::<T>((n-1) as nat, t) {
        Some((ms, rest)) => Some((seq![m] + ms, rest)), None => None }, None => None } }
}
proof fn many_roundtrip<T: Wire>(ms: Seq<T::Model>, tail: Seq<u64>)
    requires forall|i: int| 0 <= i < ms.len() ==> <T as Wire>::valid_model(#[trigger] ms[i]),
    ensures many_words::<T>(ms).len() >= ms.len(),
        many_parse::<T>(ms.len(), many_words::<T>(ms) + tail) == Some((ms, tail)),
    decreases ms.len(),
{
    if ms.len() > 0 {
        T::roundtrip(ms[0], many_words::<T>(ms.skip(1)) + tail);
        many_roundtrip::<T>(ms.skip(1), tail);
        assert(seq![ms[0]] + ms.skip(1) =~= ms);
        assert((many_words::<T>(ms) + tail) =~= T::words(ms[0]) + (many_words::<T>(ms.skip(1)) + tail));
        assert(T::parse(many_words::<T>(ms) + tail) == Some((ms[0], many_words::<T>(ms.skip(1)) + tail)));
        assert(many_parse::<T>(ms.len(), many_words::<T>(ms) + tail) == Some((ms, tail)));
    }
}
fn read_many<T: Wire>(n: usize, w: &Vec<u64>) -> (r: Option<(Vec<T>, Vec<u64>)>)
    ensures match r { Some((v, tail)) => v.len() == n && many_parse::<T>(n as nat, w@) == Some((v@.map_values(|x: T| x.model()), tail@)), None => many_parse::<T>(n as nat, w@) is None },
    decreases n,
{
    if n == 0 { return Some((Vec::new(), w.clone())); }
    let (a, t) = match T::read(w) { Some(v) => v, None => return None };
    let (mut v, rest) = match read_many::<T>(n - 1, &t) { Some(v) => v, None => return None };
    // Build in input order without requiring Clone on kernel types.
    let ghost am = a.model();
    let ghost vm = v@.map_values(|x: T| x.model());
    let mut out = Vec::new(); out.push(a); out.append(&mut v);
    proof { assert(out@.map_values(|x: T| x.model()) =~= seq![am] + vm); }
    Some((out, rest))
}

impl<T: Wire> Wire for Vec<T> {
    type Model = Seq<T::Model>;
    spec fn model(&self) -> Self::Model { self@.map_values(|x: T| x.model()) }
    spec fn valid_model(m: Self::Model) -> bool { m.len() <= usize::MAX && forall|i: int| 0 <= i < m.len() ==> <T as Wire>::valid_model(#[trigger] m[i]) }
    proof fn valid(&self) {
        assert forall|i: int| 0 <= i < self.len() implies T::valid_model(self.model()[i]) by { self@[i].valid(); }
    }
    spec fn words(m: Self::Model) -> Seq<u64> { seq![m.len() as u64] + many_words::<T>(m) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> {
        if w.len() == 0 || w[0] > usize::MAX || w[0] > w.len() - 1 { None }
        else { many_parse::<T>(w[0] as nat, w.skip(1)) }
    }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) {
        many_roundtrip::<T>(m, tail);
        assert((Self::words(m) + tail).skip(1) =~= many_words::<T>(m) + tail);
    }
    fn write(&self) -> (r: Vec<u64>) {
        let mut r = vec![self.len() as u64];
        let mut i = 0;
        while i < self.len()
            invariant 0 <= i <= self.len(), r@ + many_words::<T>(self.model().skip(i as int)) == Self::words(self.model()),
            decreases self.len() - i,
        {
            let ghost ms = self.model().skip(i as int);
            assert(ms[0] == self@[i as int].model());
            assert(ms.skip(1) =~= self.model().skip(i as int + 1));
            let w = self[i].write(); append(&mut r, &w); i += 1;
        }
        r
    }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        if w.len() == 0 || w[0] > usize::MAX as u64 || w[0] > (w.len() - 1) as u64 { return None; }
        read_many::<T>(w[0] as usize, &suffix(w, 1))
    }
}


impl Wire for usize {
    type Model = usize;
    spec fn model(&self) -> Self::Model { *self }
    spec fn valid_model(m: Self::Model) -> bool { true }
    proof fn valid(&self) {}
    spec fn words(m: Self::Model) -> Seq<u64> { seq![m as u64] }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> {
        if w.len() > 0 && (w[0] <= usize::MAX) { Some((w[0] as usize, w.skip(1))) } else { None }
    }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) {}
    fn write(&self) -> (r: Vec<u64>) { let m = *self; vec![m as u64] }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        if w.len() == 0 || !(w[0] <= usize::MAX as u64) { return None; }
        let v = w[0] as usize; Some((v, suffix(w, 1)))
    }
}

impl Wire for i64 {
    type Model = i64;
    spec fn model(&self) -> Self::Model { *self }
    spec fn valid_model(m: Self::Model) -> bool { true }
    proof fn valid(&self) {}
    spec fn words(m: Self::Model) -> Seq<u64> { seq![m as u64] }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> {
        if w.len() > 0 && (true) { Some((w[0] as i64, w.skip(1))) } else { None }
    }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { assert((m as u64) as i64 == m) by(bit_vector); }
    fn write(&self) -> (r: Vec<u64>) { let m = *self; vec![m as u64] }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        if w.len() == 0 || !(true) { return None; }
        let v = w[0] as i64; Some((v, suffix(w, 1)))
    }
}

impl Wire for bool {
    type Model = bool;
    spec fn model(&self) -> Self::Model { *self }
    spec fn valid_model(m: Self::Model) -> bool { true }
    proof fn valid(&self) {}
    spec fn words(m: Self::Model) -> Seq<u64> { seq![if m { 1u64 } else { 0u64 }] }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> {
        if w.len() > 0 && (w[0] <= 1) { Some((w[0] == 1, w.skip(1))) } else { None }
    }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) {}
    fn write(&self) -> (r: Vec<u64>) { let m = *self; vec![if m { 1u64 } else { 0u64 }] }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        if w.len() == 0 || !(w[0] <= 1) { return None; }
        let v = w[0] == 1; Some((v, suffix(w, 1)))
    }
}

impl Wire for char {
    type Model = char;
    spec fn model(&self) -> Self::Model { *self }
    spec fn valid_model(m: Self::Model) -> bool { true }
    proof fn valid(&self) {}
    spec fn words(m: Self::Model) -> Seq<u64> { seq![m as u32 as u64] }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> {
        if w.len() > 0 && (w[0] <= 0x10FFFF && (w[0] < 0xD800 || w[0] >= 0xE000)) { Some(((w[0] as u32) as char, w.skip(1))) } else { None }
    }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) {}
    fn write(&self) -> (r: Vec<u64>) { let m = *self; vec![m as u32 as u64] }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        if w.len() == 0 || !(w[0] <= 0x10FFFF && (w[0] < 0xD800 || w[0] >= 0xE000)) { return None; }
        let v = match core::char::from_u32(w[0] as u32) { Some(c) => c, None => return None }; Some((v, suffix(w, 1)))
    }
}

impl<T: Wire> Wire for Option<T> {
    type Model = Option<T::Model>;
    spec fn model(&self) -> Self::Model { match self { Some(v) => Some(v.model()), None => None } }
    spec fn valid_model(m: Self::Model) -> bool { match m { Some(v) => <T as Wire>::valid_model(v), None => true } }
    proof fn valid(&self) { if let Some(v) = self { v.valid(); } }
    spec fn words(m: Self::Model) -> Seq<u64> { match m { Some(v) => seq![1u64] + T::words(v), None => seq![0u64] } }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> {
        if w.len() == 0 { None } else if w[0] == 0 { Some((None, w.skip(1))) }
        else if w[0] == 1 { match T::parse(w.skip(1)) { Some((v, t)) => Some((Some(v), t)), None => None } } else { None }
    }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { if let Some(v) = m {
        T::roundtrip(v, tail);
        assert((Self::words(m) + tail).skip(1) =~= T::words(v) + tail);
    } }
    fn write(&self) -> (r: Vec<u64>) { match self { None => vec![0u64], Some(v) => { let mut r = vec![1u64]; append(&mut r, &v.write()); r } } }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) {
        if w.len() == 0 { return None; }
        if w[0] == 0 { return Some((None, suffix(w, 1))); }
        if w[0] != 1 { return None; }
        match T::read(&suffix(w, 1)) { Some((v, t)) => Some((Some(v), t)), None => None }
    }
}

// Built only in proofs, which cargo erases; inconsistent_fields is Verus's lint.
#[allow(unknown_lints, dead_code)]
impl Wire for Commit {
    type Model = <Vec<char> as Wire>::Model;
    spec fn model(&self) -> Self::Model { self.0.model() }
    spec fn valid_model(m: Self::Model) -> bool { <Vec<char> as Wire>::valid_model(m) }
    proof fn valid(&self) { self.0.valid(); }
    spec fn words(m: Self::Model) -> Seq<u64> { <Vec<char> as Wire>::words(m) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> { <Vec<char> as Wire>::parse(w) }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { <Vec<char> as Wire>::roundtrip(m, tail); }
    fn write(&self) -> (r: Vec<u64>) { self.0.write() }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) { match <Vec<char> as Wire>::read(w) { Some((v, tail)) => Some((Commit(v), tail)), None => None } }
}
impl Json for Commit {
    spec fn json(&self) -> Seq<char> { string(self.0@) }
    fn emit(&self) -> (r: Vec<char>) { self.0.emit() }
}
impl Wire for Path {
    type Model = <Vec<char> as Wire>::Model;
    spec fn model(&self) -> Self::Model { self.0.model() }
    spec fn valid_model(m: Self::Model) -> bool { <Vec<char> as Wire>::valid_model(m) }
    proof fn valid(&self) { self.0.valid(); }
    spec fn words(m: Self::Model) -> Seq<u64> { <Vec<char> as Wire>::words(m) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> { <Vec<char> as Wire>::parse(w) }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { <Vec<char> as Wire>::roundtrip(m, tail); }
    fn write(&self) -> (r: Vec<u64>) { self.0.write() }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) { match <Vec<char> as Wire>::read(w) { Some((v, tail)) => Some((Path(v), tail)), None => None } }
}
impl Json for Path {
    spec fn json(&self) -> Seq<char> { string(self.0@) }
    fn emit(&self) -> (r: Vec<char>) { self.0.emit() }
}
impl Wire for Intent {
    type Model = <Vec<char> as Wire>::Model;
    spec fn model(&self) -> Self::Model { self.0.model() }
    spec fn valid_model(m: Self::Model) -> bool { <Vec<char> as Wire>::valid_model(m) }
    proof fn valid(&self) { self.0.valid(); }
    spec fn words(m: Self::Model) -> Seq<u64> { <Vec<char> as Wire>::words(m) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> { <Vec<char> as Wire>::parse(w) }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { <Vec<char> as Wire>::roundtrip(m, tail); }
    fn write(&self) -> (r: Vec<u64>) { self.0.write() }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) { match <Vec<char> as Wire>::read(w) { Some((v, tail)) => Some((Intent(v), tail)), None => None } }
}
impl Json for Intent {
    spec fn json(&self) -> Seq<char> { string(self.0@) }
    fn emit(&self) -> (r: Vec<char>) { self.0.emit() }
}
impl Wire for Transcript {
    type Model = <Vec<char> as Wire>::Model;
    spec fn model(&self) -> Self::Model { self.0.0.model() }
    spec fn valid_model(m: Self::Model) -> bool { <Vec<char> as Wire>::valid_model(m) }
    proof fn valid(&self) { self.0.0.valid(); }
    spec fn words(m: Self::Model) -> Seq<u64> { <Vec<char> as Wire>::words(m) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> { <Vec<char> as Wire>::parse(w) }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { <Vec<char> as Wire>::roundtrip(m, tail); }
    fn write(&self) -> (r: Vec<u64>) { self.0.0.write() }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) { match <Vec<char> as Wire>::read(w) { Some((v, tail)) => Some((Transcript(Path(v)), tail)), None => None } }
}
impl Json for Transcript {
    spec fn json(&self) -> Seq<char> { string(self.0.0@) }
    fn emit(&self) -> (r: Vec<char>) { self.0.0.emit() }
}
#[allow(inconsistent_fields)]
enum KindModel {
    Queue { goal: Seq<char> }, Code { goal: Seq<char> },
    Compaction { goal: Seq<char>, out: Seq<Hash> },
    Counterexample { goal: Option<(usize, usize)> },
    Foil { goal: (usize, usize), changed: Seq<Seq<char>> },
}

type AgentProcessWire = (usize, usize);
impl Wire for AgentProcess {
    type Model = <AgentProcessWire as Wire>::Model;
    spec fn model(&self) -> Self::Model { (self.search.model(), self.index.model()) }
    spec fn valid_model(m: Self::Model) -> bool { AgentProcessWire::valid_model(m) }
    proof fn valid(&self) { self.search.valid(); self.index.valid(); }
    spec fn words(m: Self::Model) -> Seq<u64> { AgentProcessWire::words(m) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> { AgentProcessWire::parse(w) }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { AgentProcessWire::roundtrip(m, tail); }
    fn write(&self) -> (r: Vec<u64>) { let mut r = self.search.write(); append(&mut r, &self.index.write()); r }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) { match AgentProcessWire::read(w) { Some(((search, index), tail)) => Some((Self { search, index }, tail)), None => None } }
}

impl Wire for Kind {
    type Model = KindModel;
    spec fn model(&self) -> Self::Model { match self {
        Kind::Queue { goal } => KindModel::Queue { goal: goal.model() },
        Kind::Code { goal } => KindModel::Code { goal: goal.model() },
        Kind::Compaction { goal, out } => KindModel::Compaction { goal: goal.model(), out: out.model() },
        Kind::Counterexample { goal } => KindModel::Counterexample { goal: goal.model() },
        Kind::Foil { goal, changed } => KindModel::Foil { goal: goal.model(), changed: changed.model() },
    } }
    spec fn valid_model(m: Self::Model) -> bool { match m {
        KindModel::Queue { goal } => <Vec<char> as Wire>::valid_model(goal),
        KindModel::Code { goal } => <Vec<char> as Wire>::valid_model(goal),
        KindModel::Compaction { goal, out } => <(Vec<char>, Vec<Hash>) as Wire>::valid_model((goal, out)),
        KindModel::Counterexample { goal } => <Option<AgentProcess> as Wire>::valid_model(goal),
        KindModel::Foil { goal, changed } => <(AgentProcess, Vec<Path>) as Wire>::valid_model((goal, changed)),
    } }
    proof fn valid(&self) { match self {
        Kind::Queue { goal } => { goal.valid(); },
        Kind::Code { goal } => { goal.valid(); },
        Kind::Compaction { goal, out } => { goal.valid(); out.valid(); },
        Kind::Counterexample { goal } => { goal.valid(); },
        Kind::Foil { goal, changed } => { goal.valid(); changed.valid(); },
    } }
    spec fn words(m: Self::Model) -> Seq<u64> { match m {
        KindModel::Queue { goal } => seq![0u64] + <Vec<char> as Wire>::words(goal),
        KindModel::Code { goal } => seq![1u64] + <Vec<char> as Wire>::words(goal),
        KindModel::Compaction { goal, out } => seq![2u64] + <(Vec<char>, Vec<Hash>) as Wire>::words((goal, out)),
        KindModel::Counterexample { goal } => seq![3u64] + <Option<AgentProcess> as Wire>::words(goal),
        KindModel::Foil { goal, changed } => seq![4u64] + <(AgentProcess, Vec<Path>) as Wire>::words((goal, changed)),
    } }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> { if w.len() == 0 { None } else { match w[0] {
        0 => match <Vec<char> as Wire>::parse(w.skip(1)) { Some((goal, tail)) => Some((KindModel::Queue { goal }, tail)), None => None },
        1 => match <Vec<char> as Wire>::parse(w.skip(1)) { Some((goal, tail)) => Some((KindModel::Code { goal }, tail)), None => None },
        2 => match <(Vec<char>, Vec<Hash>) as Wire>::parse(w.skip(1)) { Some(((goal, out), tail)) => Some((KindModel::Compaction { goal, out }, tail)), None => None },
        3 => match <Option<AgentProcess> as Wire>::parse(w.skip(1)) { Some((goal, tail)) => Some((KindModel::Counterexample { goal }, tail)), None => None },
        4 => match <(AgentProcess, Vec<Path>) as Wire>::parse(w.skip(1)) { Some(((goal, changed), tail)) => Some((KindModel::Foil { goal, changed }, tail)), None => None },
        _ => None,
    } } }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) {
        assert((Self::words(m) + tail).skip(1) =~= Self::words(m).skip(1) + tail);
        match m {
        KindModel::Queue { goal } => { <Vec<char> as Wire>::roundtrip(goal, tail); },
        KindModel::Code { goal } => { <Vec<char> as Wire>::roundtrip(goal, tail); },
        KindModel::Compaction { goal, out } => { <(Vec<char>, Vec<Hash>) as Wire>::roundtrip((goal, out), tail); },
        KindModel::Counterexample { goal } => { <Option<AgentProcess> as Wire>::roundtrip(goal, tail); },
        KindModel::Foil { goal, changed } => { <(AgentProcess, Vec<Path>) as Wire>::roundtrip((goal, changed), tail); },
    } }
    fn write(&self) -> (r: Vec<u64>) { match self {
        Kind::Queue { goal } => { let mut r = vec![0u64]; append(&mut r, &goal.write()); r },
        Kind::Code { goal } => { let mut r = vec![1u64]; append(&mut r, &goal.write()); r },
        Kind::Compaction { goal, out } => { let mut r = vec![2u64]; append(&mut r, &goal.write()); append(&mut r, &out.write()); r },
        Kind::Counterexample { goal } => { let mut r = vec![3u64]; append(&mut r, &goal.write()); r },
        Kind::Foil { goal, changed } => { let mut r = vec![4u64]; append(&mut r, &goal.write()); append(&mut r, &changed.write()); r },
    } }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) { if w.len() == 0 { return None; } let t = suffix(w, 1); match w[0] {
        0 => match <Vec<char> as Wire>::read(&t) { Some((goal, tail)) => Some((Kind::Queue { goal: Transcript(Path(goal)) }, tail)), None => None },
        1 => match <Vec<char> as Wire>::read(&t) { Some((goal, tail)) => Some((Kind::Code { goal: Commit(goal) }, tail)), None => None },
        2 => match <(Vec<char>, Vec<Hash>) as Wire>::read(&t) { Some(((goal, out), tail)) => Some((Kind::Compaction { goal: Commit(goal), out }, tail)), None => None },
        3 => match <Option<AgentProcess> as Wire>::read(&t) { Some((goal, tail)) => Some((Kind::Counterexample { goal }, tail)), None => None },
        4 => match <(AgentProcess, Vec<Path>) as Wire>::read(&t) { Some(((goal, changed), tail)) => Some((Kind::Foil { goal, changed }, tail)), None => None },
        _ => None,
    } }
}

/// Fourteen fields' words, nested as CandidateWire nests them, are the same words in order.
proof fn candidate_wire_flat(a1: Seq<u64>, a2: Seq<u64>, a3: Seq<u64>, a4: Seq<u64>, a5: Seq<u64>, a6: Seq<u64>, a7: Seq<u64>,
    a8: Seq<u64>, a9: Seq<u64>, a10: Seq<u64>, a11: Seq<u64>, a12: Seq<u64>, a13: Seq<u64>, a14: Seq<u64>)
    ensures ((a1 + (a2 + a3)) + ((a4 + a5) + (a6 + a7))) + ((a8 + (a9 + a10)) + ((a11 + a12) + (a13 + a14)))
        == a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11 + a12 + a13 + a14,
{
    assert(((a1 + (a2 + a3)) + ((a4 + a5) + (a6 + a7))) + ((a8 + (a9 + a10)) + ((a11 + a12) + (a13 + a14)))
        =~= a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11 + a12 + a13 + a14);
}

type CandidateWire =(((Commit, (Commit, bool)), ((bool, Vec<Path>), (Vec<Hash>, Vec<(u64,Intent)>))), ((Vec<(i64,bool)>, (Vec<(i64,bool)>, bool)), ((bool, Vec<Path>), (i64, u64))));
impl Wire for Candidate {
    type Model = <CandidateWire as Wire>::Model;
    spec fn model(&self) -> Self::Model { (((self.commit.model(), (self.base.model(), self.accepted.model())), ((self.proved.model(), self.changed.model()), (self.out.model(), self.intents.model()))), ((self.accepts.model(), (self.accepts_foils.model(), self.rejects_counterexamples.model())), ((self.measured.model(), self.added.model()), (self.rank.model(), self.diff.model())))) }
    spec fn valid_model(m: Self::Model) -> bool { CandidateWire::valid_model(m) }
    proof fn valid(&self) { self.commit.valid(); self.base.valid(); self.accepted.valid(); self.proved.valid(); self.changed.valid(); self.out.valid(); self.intents.valid(); self.accepts.valid(); self.accepts_foils.valid(); self.rejects_counterexamples.valid(); self.measured.valid(); self.added.valid(); self.rank.valid(); self.diff.valid(); }
    spec fn words(m: Self::Model) -> Seq<u64> { CandidateWire::words(m) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> { CandidateWire::parse(w) }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { CandidateWire::roundtrip(m, tail); }
    fn write(&self) -> (r: Vec<u64>) {
        let mut r = self.commit.write(); append(&mut r, &self.base.write()); append(&mut r, &self.accepted.write()); append(&mut r, &self.proved.write()); append(&mut r, &self.changed.write()); append(&mut r, &self.out.write()); append(&mut r, &self.intents.write()); append(&mut r, &self.accepts.write()); append(&mut r, &self.accepts_foils.write()); append(&mut r, &self.rejects_counterexamples.write()); append(&mut r, &self.measured.write()); append(&mut r, &self.added.write()); append(&mut r, &self.rank.write()); append(&mut r, &self.diff.write());
        proof {
            candidate_wire_flat(<Commit as Wire>::words(self.commit.model()), <Commit as Wire>::words(self.base.model()),
                <bool as Wire>::words(self.accepted.model()), <bool as Wire>::words(self.proved.model()),
                <Vec<Path> as Wire>::words(self.changed.model()), <Vec<Hash> as Wire>::words(self.out.model()),
                <Vec<(u64,Intent)> as Wire>::words(self.intents.model()), <Vec<(i64,bool)> as Wire>::words(self.accepts.model()),
                <Vec<(i64,bool)> as Wire>::words(self.accepts_foils.model()), <bool as Wire>::words(self.rejects_counterexamples.model()),
                <bool as Wire>::words(self.measured.model()), <Vec<Path> as Wire>::words(self.added.model()),
                <i64 as Wire>::words(self.rank.model()), <u64 as Wire>::words(self.diff.model()));
        }
        r
    }
    #[verifier::rlimit(300)]
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) { match CandidateWire::read(w) { Some(((((commit, (base, accepted)), ((proved, changed), (out, intents))), ((accepts, (accepts_foils, rejects_counterexamples)), ((measured, added), (rank, diff)))), tail)) => Some((Self { commit, base, accepted, proved, changed, out, intents, accepts, accepts_foils, rejects_counterexamples, measured, added, rank, diff }, tail)), None => None } }
}

type SearchWire = (Kind, (Commit, (usize, (Vec<Path>, (Vec<Path>, (Vec<Path>, (u64, Vec<Option<Candidate>>)))))));
impl Wire for Search {
    type Model = <SearchWire as Wire>::Model;
    spec fn model(&self) -> Self::Model { (self.kind.model(), (self.base.model(), (self.n.model(), (self.checks.model(), (self.tests.model(), (self.trusted.model(), (self.limit.model(), self.results.model()))))))) }
    spec fn valid_model(m: Self::Model) -> bool { SearchWire::valid_model(m) }
    proof fn valid(&self) { self.kind.valid(); self.base.valid(); self.n.valid(); self.checks.valid(); self.tests.valid(); self.trusted.valid(); self.limit.valid(); self.results.valid(); }
    spec fn words(m: Self::Model) -> Seq<u64> { SearchWire::words(m) }
    spec fn parse(w: Seq<u64>) -> Option<(Self::Model, Seq<u64>)> { SearchWire::parse(w) }
    proof fn roundtrip(m: Self::Model, tail: Seq<u64>) { SearchWire::roundtrip(m, tail); }
    fn write(&self) -> (r: Vec<u64>) { let mut r = self.kind.write(); append(&mut r, &self.base.write()); append(&mut r, &self.n.write()); append(&mut r, &self.checks.write()); append(&mut r, &self.tests.write()); append(&mut r, &self.trusted.write()); append(&mut r, &self.limit.write()); append(&mut r, &self.results.write()); r }
    fn read(w: &Vec<u64>) -> (r: Option<(Self, Vec<u64>)>) { match SearchWire::read(w) { Some(((kind, (base, (n, (checks, (tests, (trusted, (limit, results))))))), tail)) => Some((Self { kind, base, n, checks, tests, trusted, limit, results }, tail)), None => None } }
}

proof fn many_matches<T: Wire>(xs: Seq<T>, f: spec_fn(T) -> Seq<u64>)
    requires forall|i: int| 0 <= i < xs.len() ==> T::words(xs[i].model()) == f(xs[i]),
    ensures many_words::<T>(xs.map_values(|x: T| x.model())) == xs.map_values(f).flatten(),
    decreases xs.len(),
{
    if xs.len() > 0 {
        many_matches::<T>(xs.skip(1), f);
        assert(xs.skip(1).map_values(|x: T| x.model()) =~= xs.map_values(|x: T| x.model()).skip(1));
        assert(xs.skip(1).map_values(f) =~= xs.map_values(f).drop_first());
    }
}
proof fn singletons(xs: Seq<u64>)
    ensures xs.map_values(|x: u64| seq![x]).flatten() == xs,
    decreases xs.len(),
{
    if xs.len() > 0 {
        singletons(xs.skip(1));
        assert(xs.skip(1).map_values(|x: u64| seq![x]) =~= xs.map_values(|x: u64| seq![x]).drop_first());
        assert(seq![xs[0]] + xs.skip(1) =~= xs);
    }
}
proof fn text_words(t: Vec<char>)
    ensures <Vec<char> as Wire>::words(t.model()) == text(t@),
{
    many_matches::<char>(t@, |c: char| seq![c as u32 as u64]);
    let ws = t@.map_values(|c: char| c as u32 as u64);
    singletons(ws);
    assert(t@.map_values(|c: char| seq![c as u32 as u64]) =~= ws.map_values(|x: u64| seq![x]));
}
proof fn hashes_words(h: Vec<Hash>)
    ensures <Vec<Hash> as Wire>::words(h.model()) == seq![h.len() as u64] + h@.map_values(|hash: Hash| hash.0),
{
    many_matches::<Hash>(h@, |x: Hash| seq![x.0]); singletons(h@.map_values(|hash: Hash| hash.0));
    assert(h.model() =~= h@);
    assert(h@.map_values(|x: Hash| seq![x.0]) =~= h@.map_values(|hash: Hash| hash.0).map_values(|x: u64| seq![x]));
}
proof fn texts_words(ts: Vec<Path>)
    ensures <Vec<Path> as Wire>::words(ts.model()) == texts(ts@),
{
    assert forall|i: int| 0 <= i < ts.len() implies <Path as Wire>::words(ts@[i].model()) == text(ts@[i].0@) by { text_words(ts@[i].0); }
    many_matches::<Path>(ts@, |t: Path| text(t.0@));
}
proof fn kind_correct(k: Kind)
    ensures Kind::words(k.model()) == kind_words(k),
{
    match k {
        Kind::Queue { goal } => { text_words(goal.0.0); },
        Kind::Code { goal } => { text_words(goal.0); },
        Kind::Counterexample { goal } => {},
        Kind::Foil { changed, .. } => { texts_words(changed); },
        Kind::Compaction { goal, out } => { text_words(goal.0); hashes_words(out); },
    }
}
proof fn intents_words(xs: Vec<(u64,Intent)>)
    ensures <Vec<(u64,Intent)> as Wire>::words(xs.model())
        == seq![xs.len() as u64] + xs@.map_values(|pair: (Cue, Intent)| seq![pair.0] + text(pair.1.0@)).flatten(),
{
    assert forall|i: int| 0 <= i < xs.len() implies <(u64,Intent) as Wire>::words(xs@[i].model()) == seq![xs@[i].0] + text(xs@[i].1.0@) by { text_words(xs@[i].1.0); }
    many_matches::<(u64,Intent)>(xs@, |e: (u64,Intent)| seq![e.0] + text(e.1.0@));
}
proof fn accepts_words(xs: Vec<(i64,bool)>)
    ensures <Vec<(i64,bool)> as Wire>::words(xs.model())
        == seq![xs.len() as u64] + xs@.map_values(|pair: (i64, bool)| seq![pair.0 as u64, bit(pair.1)]).flatten(),
{
    assert forall|i: int| 0 <= i < xs.len() implies <(i64,bool) as Wire>::words(xs@[i].model()) == seq![xs@[i].0 as u64, bit(xs@[i].1)] by {
        assert(seq![xs@[i].0 as u64] + seq![bit(xs@[i].1)] =~= seq![xs@[i].0 as u64, bit(xs@[i].1)]);
    }
    many_matches::<(i64,bool)>(xs@, |e: (i64,bool)| seq![e.0 as u64, bit(e.1)]);
}
/// A candidate's words as CandidateWire nests its fields are candidate_words' pieces in order.
proof fn candidate_layout(commit: Seq<u64>, base: Seq<u64>, accepted: u64, proved: u64, changed: Seq<u64>,
    out_len: u64, out: Seq<u64>, intents_len: u64, intents: Seq<u64>, accepts_len: u64, accepts: Seq<u64>,
    foils_len: u64, foils: Seq<u64>, rejects: u64, measured: u64, added: Seq<u64>, rank: u64, diff: u64)
    ensures
        ((commit + (base + seq![accepted])) + ((seq![proved] + changed) + ((seq![out_len] + out) + (seq![intents_len] + intents))))
        + (((seq![accepts_len] + accepts) + ((seq![foils_len] + foils) + seq![rejects])) + ((seq![measured] + added) + (seq![rank] + seq![diff])))
        == commit + base + seq![accepted, proved] + changed + seq![out_len] + out + seq![intents_len] + intents
            + seq![accepts_len] + accepts + seq![foils_len] + foils + seq![rejects, measured] + added + seq![rank, diff],
{
    assert(((commit + (base + seq![accepted])) + ((seq![proved] + changed) + ((seq![out_len] + out) + (seq![intents_len] + intents))))
        + (((seq![accepts_len] + accepts) + ((seq![foils_len] + foils) + seq![rejects])) + ((seq![measured] + added) + (seq![rank] + seq![diff])))
        =~= commit + base + seq![accepted, proved] + changed + seq![out_len] + out + seq![intents_len] + intents
            + seq![accepts_len] + accepts + seq![foils_len] + foils + seq![rejects, measured] + added + seq![rank, diff]);
}
proof fn candidate_correct(c: Candidate)
    ensures Candidate::words(c.model()) == candidate_words(c),
{
    text_words(c.commit.0); text_words(c.base.0); texts_words(c.changed); texts_words(c.added); hashes_words(c.out);
    intents_words(c.intents); accepts_words(c.accepts); accepts_words(c.accepts_foils);
    candidate_layout(text(c.commit.0@), text(c.base.0@), bit(c.accepted), bit(c.proved), texts(c.changed@),
        c.out.len() as u64, c.out@.map_values(|hash: Hash| hash.0),
        c.intents.len() as u64, c.intents@.map_values(|pair: (Cue, Intent)| seq![pair.0] + text(pair.1.0@)).flatten(),
        c.accepts.len() as u64, c.accepts@.map_values(|pair: (i64, bool)| seq![pair.0 as u64, bit(pair.1)]).flatten(),
        c.accepts_foils.len() as u64, c.accepts_foils@.map_values(|pair: (i64, bool)| seq![pair.0 as u64, bit(pair.1)]).flatten(),
        bit(c.rejects_counterexamples), bit(c.measured), texts(c.added@), c.rank as u64, c.diff);
}
proof fn result_correct(r: Option<Candidate>)
    ensures <Option<Candidate> as Wire>::words(r.model()) == result_words(r),
{
    if let Some(c) = r { candidate_correct(c); }
}
/// A search's words as SearchWire nests its fields are encoded's pieces in order.
proof fn search_layout(kind: Seq<u64>, base: Seq<u64>, n: u64, checks: Seq<u64>, tests: Seq<u64>, trusted: Seq<u64>, limit: u64,
    results_len: u64, results: Seq<u64>)
    ensures kind + (base + (seq![n] + (checks + (tests + (trusted + (seq![limit] + (seq![results_len] + results)))))))
        == kind + base + seq![n] + checks + tests + trusted + seq![limit] + seq![results_len] + results,
{
    assert(kind + (base + (seq![n] + (checks + (tests + (trusted + (seq![limit] + (seq![results_len] + results)))))))
        =~= kind + base + seq![n] + checks + tests + trusted + seq![limit] + seq![results_len] + results);
}
proof fn results_words(rs: Vec<Option<Candidate>>)
    ensures <Vec<Option<Candidate>> as Wire>::words(rs.model())
        == seq![rs.len() as u64] + rs@.map_values(|result: Option<Candidate>| result_words(result)).flatten(),
{
    assert forall|i: int| 0 <= i < rs.len() implies <Option<Candidate> as Wire>::words(rs@[i].model()) == result_words(rs@[i]) by { result_correct(rs@[i]); }
    many_matches::<Option<Candidate>>(rs@, |r: Option<Candidate>| result_words(r));
}
proof fn search_correct(s: Search)
    ensures Search::words(s.model()) == encoded(s),
{
    kind_correct(s.kind); text_words(s.base.0); texts_words(s.checks); texts_words(s.tests); texts_words(s.trusted);
    results_words(s.results);
    search_layout(kind_words(s.kind), text(s.base.0@), s.n as u64, texts(s.checks@), texts(s.tests@), texts(s.trusted@), s.limit,
        s.results.len() as u64, s.results@.map_values(|result: Option<Candidate>| result_words(result)).flatten());
}
fn equal_words(a: &Vec<u64>, b: &Vec<u64>) -> (r: bool)
    ensures r == (a@ == b@),
{
    if a.len() != b.len() { return false; }
    let mut i = 0;
    while i < a.len()
        invariant a.len() == b.len(), 0 <= i <= a.len(), forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] { return false; } i += 1;
    }
    proof { assert(a@ =~= b@); }
    true
}

proof fn text_model(t: Vec<char>)
    ensures t.model() == t@,
{ assert(t.model() =~= t@); }
proof fn text_list_model(a: Vec<Path>, b: Vec<Path>)
    requires a.model() == b.model(),
    ensures paths(a@) == paths(b@),
{
    assert(a.model().len() == a.len()); assert(b.model().len() == b.len());
    assert(a@.map_values(|x: Path| x@) =~= b@.map_values(|x: Path| x@)) by {
        assert forall|i: int| 0 <= i < a.len() implies a@[i]@ == b@[i]@ by {
            assert(a.model()[i] == a@[i].model()); assert(b.model()[i] == b@[i].model());
            text_model(a@[i].0); text_model(b@[i].0);
        }
    }
}
proof fn kind_model(a: Kind, b: Kind)
    requires a.model() == b.model(), ensures a@ == b@,
{
    match (a, b) {
        (Kind::Queue { goal: a }, Kind::Queue { goal: b }) => { text_model(a.0.0); text_model(b.0.0); },
        (Kind::Code { goal: a }, Kind::Code { goal: b }) => { text_model(a.0); text_model(b.0); },
        (Kind::Compaction { goal: a, out: x }, Kind::Compaction { goal: b, out: y }) => {
            text_model(a.0); text_model(b.0);
            assert(x.model() == y.model()); assert(x.model() =~= x@); assert(y.model() =~= y@); assert(x@ =~= y@);
        },
        (Kind::Foil { changed: a, .. }, Kind::Foil { changed: b, .. }) => { text_list_model(a, b); },
        _ => {},
    }
}
#[verifier::rlimit(150)]
proof fn candidate_model(a: Candidate, b: Candidate)
    requires a.model() == b.model(), ensures a@ == b@,
{
    assert(a.commit.model() == b.commit.model()); assert(a.base.model() == b.base.model());
    assert(a.changed.model() == b.changed.model()); assert(a.out.model() == b.out.model());
    assert(a.accepts_foils.model() == b.accepts_foils.model());
    assert(a.intents.model() == b.intents.model()); assert(a.accepts.model() == b.accepts.model());
    text_model(a.commit.0); text_model(b.commit.0); text_model(a.base.0); text_model(b.base.0);
    text_list_model(a.changed, b.changed);
    assert(a.added.model() == b.added.model()); text_list_model(a.added, b.added);
    assert(a.out.model() =~= a.out@); assert(b.out.model() =~= b.out@);
    assert(a.out@ =~= b.out@);
    assert(a.accepts.model() =~= a.accepts@); assert(b.accepts.model() =~= b.accepts@);
    assert(a.accepts@ =~= b.accepts@);
    assert(a.accepts_foils.model() =~= a.accepts_foils@); assert(b.accepts_foils.model() =~= b.accepts_foils@);
    assert(a.accepts_foils@ =~= b.accepts_foils@);
    assert(a.intents.model().len() == a.intents.len()); assert(b.intents.model().len() == b.intents.len());
    assert(a.intents@.map_values(|e: (Cue,Intent)| (e.0 as nat, e.1@)) =~= b.intents@.map_values(|e: (Cue,Intent)| (e.0 as nat, e.1@))) by {
        assert forall|i: int| 0 <= i < a.intents.len() implies (a.intents@[i].0 as nat, a.intents@[i].1@) == (b.intents@[i].0 as nat, b.intents@[i].1@) by { assert(a.intents.model()[i] == a.intents@[i].model()); assert(b.intents.model()[i] == b.intents@[i].model()); text_model(a.intents@[i].1.0); text_model(b.intents@[i].1.0); }
    }
}
#[verifier::rlimit(150)]
proof fn search_model(a: Search, b: Search)
    requires a.model() == b.model(), ensures a@ == b@,
{
    assert(a.kind.model() == b.kind.model()); assert(a.base.model() == b.base.model());
    assert(a.checks.model() == b.checks.model()); assert(a.tests.model() == b.tests.model()); assert(a.trusted.model() == b.trusted.model()); assert(a.results.model() == b.results.model());
    assert(a.results.model().len() == a.results.len()); assert(b.results.model().len() == b.results.len());
    kind_model(a.kind, b.kind); text_model(a.base.0); text_model(b.base.0); text_list_model(a.checks, b.checks); text_list_model(a.tests, b.tests); text_list_model(a.trusted, b.trusted);
    assert forall|i: int| 0 <= i < a.results.len() implies a@.results[i] == b@.results[i] by {
        assert(a.results.model()[i] == a.results@[i].model()); assert(b.results.model()[i] == b.results@[i].model());
        match (a.results@[i], b.results@[i]) {
            (Some(x), Some(y)) => { candidate_model(x, y); }, _ => {},
        }
    }
    assert(a@.results =~= b@.results);
}

trait Json {
    spec fn json(&self) -> Seq<char>;
    fn emit(&self) -> (r: Vec<char>) ensures r@ == self.json();
}
fn decimal(n: u64) -> (r: Vec<char>)
    ensures r@ == crate::gates::decimal(n as nat), decreases n,
{
    let d = (n % 10) as u32 + '0' as u32;
    let c = match core::char::from_u32(d) { Some(c) => c, None => vstd::pervasive::unreached() };
    if n < 10 { vec![c] } else { let mut r = decimal(n / 10); r.push(c); r }
}
fn signed(n: i64) -> (r: Vec<char>) ensures r@ == crate::gates::signed(n as int),
{
    if n < 0 {
        let magnitude = (-(n + 1)) as u64 + 1;
        let mut r = vec!['-']; append(&mut r, &decimal(magnitude)); r
    } else { decimal(n as u64) }
}
fn hex(n: u32) -> (r: char)
    requires n < 16, ensures r == crate::gates::hex(n as nat),
{
    let d = if n < 10 { '0' as u32 + n } else { 'a' as u32 + (n - 10) };
    match core::char::from_u32(d) { Some(c) => c, None => vstd::pervasive::unreached() }
}
fn escaped(c: char) -> (r: Vec<char>) ensures r@ == crate::gates::escaped(c),
{
    if c == '"' || c == '\\' { vec!['\\', c] }
    else if (c as u32) < 0x20 { vec!['\\', 'u', '0', '0', hex(c as u32 / 16), hex(c as u32 % 16)] }
    else { vec![c] }
}
impl Json for Vec<char> {
    spec fn json(&self) -> Seq<char> { string(self@) }
    fn emit(&self) -> (r: Vec<char>) {
        let mut r = vec!['"'];
        let mut i = 0;
        while i < self.len()
            invariant 0 <= i <= self.len(), r@ == seq!['"'] + self@.take(i as int).map_values(|c: char| crate::gates::escaped(c)).flatten(),
            decreases self.len() - i,
        {
            append(&mut r, &escaped(self[i]));
            proof { self@.take(i as int).map_values(|c: char| crate::gates::escaped(c)).lemma_flatten_push(crate::gates::escaped(self@[i as int])); }
            proof { assert(self@.take(i as int + 1).map_values(|c: char| crate::gates::escaped(c)) =~= self@.take(i as int).map_values(|c: char| crate::gates::escaped(c)).push(crate::gates::escaped(self@[i as int]))); }
            i += 1;
        }
        r.push('"'); r
    }
}
fn joined(items: &Vec<Vec<char>>) -> (r: Vec<char>)
    ensures r@ == crate::gates::joined(items@.map_values(|x: Vec<char>| x@)),
{
    let mut r = Vec::new(); let mut i = 0;
    while i < items.len()
        invariant 0 <= i <= items.len(), r@ == crate::gates::joined(items@.take(i as int).map_values(|x: Vec<char>| x@)),
        decreases items.len() - i,
    {
        if i > 0 { r.push(','); }
        append(&mut r, &items[i]);
        proof { assert(items@.take(i as int + 1).map_values(|x: Vec<char>| x@).drop_last() =~= items@.take(i as int).map_values(|x: Vec<char>| x@)); }
        i += 1;
    }
    r
}
fn array(items: &Vec<Vec<char>>) -> (r: Vec<char>)
    ensures r@ == crate::gates::array(items@.map_values(|x: Vec<char>| x@)),
{
    let mut r = vec!['[']; append(&mut r, &joined(items)); r.push(']'); r
}
fn object(items: &Vec<Vec<char>>) -> (r: Vec<char>)
    ensures r@ == crate::gates::object(items@.map_values(|x: Vec<char>| x@)),
{
    let mut r = vec!['{']; append(&mut r, &joined(items)); r.push('}'); r
}
fn text_chars(s: &str) -> (r: Vec<char>) ensures r@ == s@,
{
    let mut r = Vec::new(); let mut i = 0; let len = s.unicode_len();
    while i < len
        invariant 0 <= i <= len, len == s@.len(), r@ == s@.take(i as int),
        decreases len - i,
    { r.push(s.get_char(i)); i += 1; }
    r
}
fn field(name: &str, value: &Vec<char>) -> (r: Vec<char>)
    ensures r@ == crate::gates::field(name@, value@),
{
    let mut r = text_chars(name).emit(); r.push(':'); append(&mut r, value); r
}
fn emit_array<T: Json>(items: &Vec<T>) -> (r: Vec<char>)
    ensures r@ == crate::gates::array(items@.map_values(|x: T| x.json())),
{
    let mut out: Vec<Vec<char>> = Vec::new(); let mut i = 0;
    while i < items.len()
        invariant 0 <= i <= items.len(), out.len() == i, out@.map_values(|x: Vec<char>| x@) == items@.take(i as int).map_values(|x: T| x.json()),
        decreases items.len() - i,
    {
        let item = items[i].emit();
        let ghost before = out@;
        out.push(item);
        proof {
            assert forall|j: int| 0 <= j < i + 1 implies out@[j]@ == items@[j].json() by {
                if j < i {
                    assert(before.map_values(|x: Vec<char>| x@)[j] == items@.take(i as int).map_values(|x: T| x.json())[j]);
                    assert(before[j]@ == items@[j].json());
                }
            }
        }
        proof { assert(out@.map_values(|x: Vec<char>| x@) =~= items@.take(i as int + 1).map_values(|x: T| x.json())); }
        i += 1;
    }
    array(&out)
}
impl Json for bool {
    spec fn json(&self) -> Seq<char> { boolean(*self) }
    fn emit(&self) -> (r: Vec<char>) { if *self { vec!['t','r','u','e'] } else { vec!['f','a','l','s','e'] } }
}
impl Json for u64 {
    spec fn json(&self) -> Seq<char> { string(crate::gates::decimal(*self as nat)) }
    fn emit(&self) -> (r: Vec<char>) { decimal(*self).emit() }
}
impl Json for Hash {
    spec fn json(&self) -> Seq<char> { string(crate::gates::decimal(self.0 as nat)) }
    fn emit(&self) -> (r: Vec<char>) { decimal(self.0).emit() }
}
impl Json for (u64, Intent) {
    spec fn json(&self) -> Seq<char> { crate::gates::array(seq![crate::gates::decimal(self.0 as nat), string(self.1.0@)]) }
    fn emit(&self) -> (r: Vec<char>) { { let items = vec![decimal(self.0), self.1.emit()]; proof { assert(items@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::decimal(self.0 as nat), string(self.1.0@)]); } array(&items) } }
}
impl Json for (i64, bool) {
    spec fn json(&self) -> Seq<char> { crate::gates::array(seq![crate::gates::signed(self.0 as int), boolean(self.1)]) }
    fn emit(&self) -> (r: Vec<char>) { { let items = vec![signed(self.0), self.1.emit()]; proof { assert(items@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::signed(self.0 as int), boolean(self.1)]); } array(&items) } }
}

impl Json for Candidate {
    spec fn json(&self) -> Seq<char> { candidate_json(*self) }
    fn emit(&self) -> (r: Vec<char>) { let value0 = self.commit.emit();
let value1 = self.base.emit();
let value2 = self.accepted.emit();
let value2b = self.proved.emit();
let value3 = emit_array(&self.changed);
proof {
    assert(self.changed@.map_values(|x: Path| x.json()) =~= self.changed@.map_values(|x: Path| string(x.0@)));
    assert(value3@ == strings(self.changed@));
}
let value4 = emit_array(&self.out);
proof {
    assert(self.out@.map_values(|x: Hash| x.json()) =~= self.out@.map_values(|h: Hash| string(crate::gates::decimal(h.0 as nat))));
    assert(value4@ == hash_strings(self.out@));
}
let value5 = emit_array(&self.intents);
proof {
    assert(self.intents@.map_values(|x: (Cue,Intent)| x.json()) =~= self.intents@.map_values(|e: (Cue,Intent)| crate::gates::array(seq![crate::gates::decimal(e.0 as nat), string(e.1.0@)])));
    assert(value5@ == crate::gates::array(self.intents@.map_values(|e: (Cue,Intent)| crate::gates::array(seq![crate::gates::decimal(e.0 as nat), string(e.1.0@)])))); }
let value6 = emit_array(&self.accepts);
proof {
    assert(self.accepts@.map_values(|x: (i64,bool)| x.json()) =~= self.accepts@.map_values(|e: (i64,bool)| crate::gates::array(seq![crate::gates::signed(e.0 as int), boolean(e.1)])));
    assert(value6@ == crate::gates::array(self.accepts@.map_values(|e: (i64,bool)| crate::gates::array(seq![crate::gates::signed(e.0 as int), boolean(e.1)])))); }
let value6f = emit_array(&self.accepts_foils);
proof {
    assert(self.accepts_foils@.map_values(|x: (i64,bool)| x.json()) =~= self.accepts_foils@.map_values(|e: (i64,bool)| crate::gates::array(seq![crate::gates::signed(e.0 as int), boolean(e.1)])));
    assert(value6f@ == crate::gates::array(self.accepts_foils@.map_values(|e: (i64,bool)| crate::gates::array(seq![crate::gates::signed(e.0 as int), boolean(e.1)])))); }
let value6b = self.rejects_counterexamples.emit();
let measured = self.measured.emit();
let added = emit_array(&self.added);
proof { assert(self.added@.map_values(|x: Path| x.json()) =~= self.added@.map_values(|x: Path| string(x.0@))); }
let value7 = signed(self.rank);
let value8 = decimal(self.diff);
let fields = vec![field("commit", &value0), field("base", &value1), field("accepted", &value2), field("proved", &value2b), field("changed", &value3), field("out", &value4), field("intents", &value5), field("accepts", &value6), field("accepts_foils", &value6f), field("rejects_counterexamples", &value6b), field("measured", &measured), field("added", &added), field("rank", &value7), field("diff", &value8)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("commit"@, string(self.commit.0@)), crate::gates::field("base"@, string(self.base.0@)), crate::gates::field("accepted"@, boolean(self.accepted)), crate::gates::field("proved"@, boolean(self.proved)), crate::gates::field("changed"@, strings(self.changed@)), crate::gates::field("out"@, hash_strings(self.out@)), crate::gates::field("intents"@, crate::gates::array(self.intents@.map_values(|e: (Cue,Intent)| crate::gates::array(seq![crate::gates::decimal(e.0 as nat), string(e.1.0@)])))), crate::gates::field("accepts"@, crate::gates::array(self.accepts@.map_values(|e: (i64,bool)| crate::gates::array(seq![crate::gates::signed(e.0 as int), boolean(e.1)])))), crate::gates::field("accepts_foils"@, crate::gates::array(self.accepts_foils@.map_values(|e: (i64,bool)| crate::gates::array(seq![crate::gates::signed(e.0 as int), boolean(e.1)])))), crate::gates::field("rejects_counterexamples"@, boolean(self.rejects_counterexamples)), crate::gates::field("measured"@, boolean(self.measured)), crate::gates::field("added"@, strings(self.added@)), crate::gates::field("rank"@, crate::gates::signed(self.rank as int)), crate::gates::field("diff"@, crate::gates::decimal(self.diff as nat))]); }
object(&fields) }
}
impl Json for Option<Candidate> {
    spec fn json(&self) -> Seq<char> { match self { Some(c) => candidate_json(*c), None => seq!['n','u','l','l'] } }
    fn emit(&self) -> (r: Vec<char>) { match self { Some(c) => c.emit(), None => vec!['n','u','l','l'] } }
}
impl Json for Kind {
    spec fn json(&self) -> Seq<char> { kind_json(*self) }
    fn emit(&self) -> (r: Vec<char>) { match self {
        Kind::Code { goal } => { let value0 = { let value0 = goal.emit();
let fields = vec![field("goal", &value0)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("goal"@, string(goal.0@))]); }
object(&fields) };
let fields = vec![field("code", &value0)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("code"@, crate::gates::object(seq![crate::gates::field("goal"@, string(goal.0@))]))]); }
object(&fields) },
        Kind::Queue { goal } => { let value0 = { let value0 = goal.emit();
let fields = vec![field("goal", &value0)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("goal"@, string(goal.0.0@))]); }
object(&fields) };
let fields = vec![field("queue", &value0)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("queue"@, crate::gates::object(seq![crate::gates::field("goal"@, string(goal.0.0@))]))]); }
object(&fields) },
        Kind::Compaction { goal, out } => { let value0 = { let value0 = goal.emit();
let value1 = emit_array(out);
proof {
    assert(out@.map_values(|x: Hash| x.json()) =~= out@.map_values(|h: Hash| string(crate::gates::decimal(h.0 as nat))));
    assert(value1@ == hash_strings(out@));
}
let fields = vec![field("goal", &value0), field("out", &value1)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("goal"@, string(goal.0@)), crate::gates::field("out"@, hash_strings(out@))]); }
object(&fields) };
let fields = vec![field("compaction", &value0)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("compaction"@, crate::gates::object(seq![crate::gates::field("goal"@, string(goal.0@)), crate::gates::field("out"@, hash_strings(out@))]))]); }
object(&fields) },
        Kind::Counterexample { goal } => {
let ghost g = match goal { Some(p) => crate::gates::object(seq![crate::gates::field("search"@, crate::gates::decimal(p.search as nat)), crate::gates::field("index"@, crate::gates::decimal(p.index as nat))]), None => seq!['n','u','l','l'] };
let value0 = match goal {
    Some(p) => { let value0 = decimal(p.search as u64);
        let value1 = decimal(p.index as u64);
        let fields = vec![field("search", &value0), field("index", &value1)];
        proof {
        assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("search"@, crate::gates::decimal(p.search as nat)), crate::gates::field("index"@, crate::gates::decimal(p.index as nat))]); }
        object(&fields) },
    None => vec!['n','u','l','l'],
};
assert(value0@ == g);
let value0 = { let fields = vec![field("goal", &value0)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("goal"@, g)]); }
object(&fields) };
let fields = vec![field("counterexample", &value0)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("counterexample"@, crate::gates::object(seq![crate::gates::field("goal"@, g)]))]); }
object(&fields) },
        Kind::Foil { goal: p, changed } => {
    let search = decimal(p.search as u64);
    let index = decimal(p.index as u64);
    let fields = vec![field("search", &search), field("index", &index)];
    proof { assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("search"@, crate::gates::decimal(p.search as nat)), crate::gates::field("index"@, crate::gates::decimal(p.index as nat))]); }
    let value = object(&fields);
    let changed_json = emit_array(changed);
    proof { assert(changed@.map_values(|x: Path| x.json()) =~= changed@.map_values(|x: Path| string(x.0@))); }
    let fields = vec![field("goal", &value), field("changed", &changed_json)];
    proof { assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("goal"@, value@), crate::gates::field("changed"@, strings(changed@))]); }
    let value = object(&fields);
    let fields = vec![field("foil", &value)];
    proof { assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("foil"@, value@)]); }
    object(&fields)
},
    } }
}
impl Encoding for Kernel {
    fn encode(s: &Search) -> (r: Vec<u64>) { proof { search_correct(*s); } s.write() }
    fn decode(w: &Vec<u64>) -> (r: Option<Search>) {
        proof {
            if exists|s: Search| encoded(s) == w@ && s.results.len() == s.n {
                let s = choose|s: Search| encoded(s) == w@ && s.results.len() == s.n;
                search_correct(s); s.valid(); Search::roundtrip(s.model(), Seq::empty());
                assert(Search::parse(w@) == Some((s.model(), Seq::empty())));
            }
        }
        let (s, rest) = match Search::read(w) { Some(v) => v, None => return None };
        proof { search_correct(s); }
        let back = s.write();
        if rest.len() == 0 && s.results.len() == s.n && equal_words(&back, w) { Some(s) } else { None }
    }
    fn emit(s: &Search) -> (r: Vec<char>) { let value0 = s.kind.emit();
let value1 = s.base.emit();
let value2 = decimal(s.n as u64);
let value3 = emit_array(&s.checks);
proof { assert(s.checks@.map_values(|x: Path| x.json()) =~= s.checks@.map_values(|x: Path| string(x.0@))); }
let value3b = emit_array(&s.tests);
proof { assert(s.tests@.map_values(|x: Path| x.json()) =~= s.tests@.map_values(|x: Path| string(x.0@))); }
let value3c = emit_array(&s.trusted);
proof { assert(s.trusted@.map_values(|x: Path| x.json()) =~= s.trusted@.map_values(|x: Path| string(x.0@))); }
let value4 = decimal(s.limit);
let value5 = emit_array(&s.results);
proof { assert(s.results@.map_values(|x: Option<Candidate>| x.json()) =~= s.results@.map_values(|r: Option<Candidate>| match r { Some(c) => candidate_json(c), None => seq!['n','u','l','l'] })); }
let fields = vec![field("kind", &value0), field("base", &value1), field("n", &value2), field("checks", &value3), field("tests", &value3b), field("trusted", &value3c), field("limit", &value4), field("results", &value5)];
proof {
assert(fields@.map_values(|x: Vec<char>| x@) =~= seq![crate::gates::field("kind"@, kind_json(s.kind)), crate::gates::field("base"@, string(s.base.0@)), crate::gates::field("n"@, crate::gates::decimal(s.n as nat)), crate::gates::field("checks"@, strings(s.checks@)), crate::gates::field("tests"@, strings(s.tests@)), crate::gates::field("trusted"@, strings(s.trusted@)), crate::gates::field("limit"@, crate::gates::decimal(s.limit as nat)), crate::gates::field("results"@, crate::gates::array(s.results@.map_values(|r: Option<Candidate>| match r { Some(c) => candidate_json(c), None => seq!['n','u','l','l'] })))]); }
object(&fields) }
    proof fn injective(a: Search, b: Search) {
        search_correct(a); search_correct(b); a.valid(); b.valid();
        Search::roundtrip(a.model(), Seq::empty()); Search::roundtrip(b.model(), Seq::empty());
        search_model(a, b);
    }
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_rejects_damage_and_preserves_json_boundaries() {
        let s = Search {
            kind: Kind::Code { goal: "\0\"\\😀".chars().collect() },
            base: Commit(vec![]), n: 1, checks: vec![], tests: vec![], trusted: vec![], limit: u64::MAX,
            results: vec![Some(Candidate {
                commit: Commit(vec![]), base: Commit(vec![]), accepted: true, proved: true, changed: vec![],
                out: vec![Hash(u64::MAX)], intents: vec![], accepts: vec![(i64::MIN, false)], accepts_foils: vec![],
                rejects_counterexamples: false, measured: true, added: vec![], rank: i64::MIN, diff: u64::MAX,
            })],
        };
        let words = Kernel::encode(&s);
        let back = Kernel::decode(&words).unwrap();
        assert_eq!(Kernel::encode(&back), words);
        let json: serde_json::Value = serde_json::from_str(&Kernel::emit(&back).into_iter().collect::<String>()).unwrap();
        assert_eq!(json["kind"]["code"]["goal"], "\0\"\\😀");
        assert_eq!(json["results"][0]["rank"], i64::MIN);
        assert_eq!(json["results"][0]["out"][0], u64::MAX.to_string());
        for end in 0..words.len() { assert!(Kernel::decode(&words[..end].to_vec()).is_none()); }
        let mut extra = words.clone(); extra.push(0);
        assert!(Kernel::decode(&extra).is_none());
        let mut invalid_char = words.clone(); invalid_char[2] = 0xD800;
        assert!(Kernel::decode(&invalid_char).is_none());
    }
}
