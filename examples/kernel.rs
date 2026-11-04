//! An agree check: the kernel's encoding and emission of fixed searches. The
//! contracts in gates.rs fix both exactly, so every verified candidate prints
//! the same; a candidate that differs is wrong. (intents 4, 27)

use best_of_n::exec::Kernel;
use best_of_n::gates::{AgentProcess, Candidate, Encoding, Gates, Kind, Search};

fn t(s: &str) -> Vec<char> { s.chars().collect() }

fn candidate(commit: &str, out: u64, rank: i64) -> Candidate {
    Candidate {
        commit: t(commit), base: t("b0"), checks_pass: true,
        changed: vec![t("src/a.rs"), t("src/\"quoted\"\\path.rs")],
        out: vec![out, u64::MAX], intents: vec![(1200, t("an intent\twith a tab"))],
        test_passes: vec![(-1, true), (0, false)], rank, diff: 3,
    }
}

fn main() {
    let kinds = [
        Kind::Code { goal: t("a halve function prints half of its argument") },
        Kind::Map { goal: t("transcripts/2026-11-03.vtt") },
        Kind::Counterexample { goal: AgentProcess { search: 0, index: 1 } },
        Kind::Compaction { goal: t("c0ffee"), out: vec![5276956862258435173] },
        Kind::Scrub { goal: t("greet prints hello, world"), path: t("tests/scrub.rs") },
    ];
    for kind in kinds {
        let s = Search {
            kind, base: t("b0"), n: 3, checks: vec![t("src/spec.rs")], limit: 9,
            results: vec![Some(candidate("x1", 7, 1)), None, Some(candidate("y2", 7, -2))],
        };
        let words = Kernel::encode(&s);
        let back = Kernel::decode(&words);
        println!("{}", Kernel::emit(&s).into_iter().collect::<String>());
        println!("{words:?}");
        println!("round trip: {}", back.as_ref().map_or(false, |b| Kernel::encode(b) == words));
        println!("selected: {:?}", back.as_ref().map(|b| Kernel::selected(b)));
    }
}
