//! An agree check: the kernel's encoding and emission of fixed searches, and
//! its decisions on a search whose verified candidates disagree. The contracts in gates.rs fix them
//! exactly, so every verified candidate prints the same; a candidate that
//! differs is wrong.

use best_of_n::exec::Kernel;
use best_of_n::gates::{AgentProcess, Candidate, Encoding, Gates, Hash, Kind, Search};

/// Text as whichever text type a field takes (Commit, Path, Intent, Transcript).
fn t<T: FromIterator<char>>(s: &str) -> T { s.chars().collect() }

fn candidate(commit: &str, out: u64, rank: i64) -> Candidate {
    Candidate {
        commit: t(commit), base: t("b0"), accepted: true, proved: true,
        changed: vec![t("src/a.rs"), t("src/\"quoted\"\\path.rs")],
        out: vec![Hash(out), Hash(u64::MAX)], intents: vec![(1200, t("an intent\twith a tab"))],
        accepts: vec![(-1, true), (0, false)], accepts_foils: vec![(0, false), (1, true)], rejects_counterexamples: true, measured: true, added: vec![t("tests/c_1.rs")], rank, diff: 3,
    }
}

/// A counterexample's test: one new file, with its verdict on each member.
fn test(commit: &str, accepts: Vec<(i64, bool)>) -> Candidate {
    Candidate {
        commit: t(commit), base: t("b0"), accepted: true, proved: false, changed: vec![t("tests/c_1.rs")], out: vec![], intents: vec![],
        accepts, accepts_foils: vec![], rejects_counterexamples: false, measured: false, added: vec![t("tests/c_1.rs")], rank: 0, diff: 1,
    }
}

/// A reason's word, as trusted code records it.
fn word(reason: Option<best_of_n::spec::Blocked>) -> &'static str {
    use best_of_n::spec::Blocked::*;
    match reason {
        None => "none", Some(TooFewVerified) => "too_few_verified", Some(TooFewTests) => "too_few_tests", Some(RejectsEvery) => "rejects_every",
        Some(Undecided) => "undecided", Some(Undiscriminating) => "undiscriminating", Some(TrunkMoved) => "trunk_moved", Some(Refused) => "refused",
    }
}

fn main() {
    let kinds = [
        Kind::Queue { goal: t("transcripts/2026-11-03.vtt") },
        Kind::Code { goal: t("c0ffee") },
        Kind::Compaction { goal: t("c0ffee"), out: vec![Hash(5276956862258435173)] },
        Kind::Counterexample { goal: Some(AgentProcess { search: 0, index: 1 }) },
        Kind::Counterexample { goal: None },
        Kind::Foil { goal: AgentProcess { search: 0, index: 1 }, changed: vec![t("src/a.rs")] },
    ];
    for kind in kinds {
        let s = Search {
            kind, base: t("b0"), n: 3, checks: vec![t("src/spec.rs")], tests: vec![t("tests/counterexample.rs")], trusted: vec![t("src/trusted.rs")], limit: 9,
            results: vec![Some(candidate("x1", 7, 1)), None, Some(candidate("y2", 7, -2))],
        };
        let words = Kernel::encode(&s);
        let back = Kernel::decode(&words);
        println!("{}", Kernel::emit(&s).into_iter().collect::<String>());
        println!("{words:?}");
        println!("round trip: {}", back.as_ref().map_or(false, |b| Kernel::encode(b) == words));
        println!("selected: {:?}", back.as_ref().map(|b| Kernel::selected(b)));
        println!("found on trunk: {:?}", back.as_ref().map(|b| Kernel::found_on_trunk(b)));
    }
    // A code search whose two verified candidates show two behaviors (out 7 and 8):
    // nothing is selected and nothing blocks yet; a counterexample search on its first verified candidate decides.
    let search = |kind: Kind, results: Vec<Option<Candidate>>| Search {
        kind, base: t("b0"), n: results.len(), checks: vec![t("src/spec.rs")], tests: vec![t("tests/")], trusted: vec![t("src/trusted.rs")], limit: 9, results,
    };
    let tested = search(Kind::Code { goal: t("c0ffee") }, vec![Some(candidate("x1", 7, 1)), None, Some(candidate("y2", 8, -2))]);
    println!("disagree: selected {:?}, first verified {:?}, blocked {}", Kernel::selected(&tested), Kernel::first_verified(&tested), word(Kernel::blocked(&tested, None, None)));
    let on = || Kind::Counterexample { goal: Some(AgentProcess { search: 0, index: 0 }) };
    let cases = [
        ("a test splits them", vec![Some(test("s1", vec![(0, true), (2, false)])), Some(test("s2", vec![(0, true), (2, true)]))]),
        ("no test splits them", vec![Some(test("s1", vec![(0, true), (2, true)])), Some(test("s2", vec![(0, true), (2, true)]))]),
        ("a test has no verdict on one", vec![Some(test("s1", vec![(0, true), (2, true)])), Some(test("s2", vec![(0, true)]))]),
        ("one verified test", vec![Some(test("s1", vec![(0, true), (2, true)])), None]),
        ("a test rejects both", vec![Some(test("s1", vec![(0, false), (2, false)])), Some(test("s2", vec![(0, true), (2, true)]))]),
    ];
    for (name, tests) in cases {
        let x = search(on(), tests);
        println!("{name}: lands {:?}, blocked {}", Kernel::lands_on(&x, &tested), word(Kernel::blocked(&tested, Some(&x), None)));
    }
}
