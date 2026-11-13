//! The kernel's encoding, on a search at the edges of its types: the words
//! round-trip, damaged words decode to nothing, and the JSON keeps its
//! boundaries. engineer's test: no search may change it.

use best_of_n::exec::Kernel;
use best_of_n::gates::*;

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
