//! A search as the gates saw it, as JSON: written to each search's trace as
//! search.json, and read back by the gates compiled to WebAssembly so the view
//! can re-derive each selection. Trusted: part of the TCB. Hashes (`out`) are
//! strings, since JSON numbers in a browser lose u64 precision.

use crate::gates::{AgentProcess, Candidate, Kind, Search};
use serde_json::{json, Value};

fn text(v: &Vec<char>) -> String { v.iter().collect() }
fn chars(v: &Value) -> Option<Vec<char>> { Some(v.as_str()?.chars().collect()) }
fn hashes(v: &Vec<u64>) -> Value { v.iter().map(|h| h.to_string()).collect() }
fn unhash(v: &Value) -> Option<Vec<u64>> { v.as_array()?.iter().map(|h| h.as_str()?.parse().ok()).collect() }

pub fn kind(k: &Kind) -> Value {
    match k {
        Kind::Code { goal } => json!({"code": {"goal": text(goal)}}),
        Kind::Map { goal } => json!({"map": {"goal": text(goal)}}),
        Kind::Counterexample { goal } => json!({"counterexample": {"goal": {"search": goal.search, "index": goal.index}}}),
        Kind::Compaction { goal, out } => json!({"compaction": {"goal": text(goal), "out": hashes(out)}}),
        Kind::Scrub { goal, path } => json!({"scrub": {"goal": text(goal), "path": text(path)}}),
    }
}

pub fn candidate(c: &Candidate) -> Value {
    json!({
        "commit": text(&c.commit), "base": text(&c.base), "checks_pass": c.checks_pass,
        "changed": c.changed.iter().map(text).collect::<Vec<_>>(), "out": hashes(&c.out),
        "intents": c.intents.iter().map(|(q, i)| json!([q, text(i)])).collect::<Vec<_>>(),
        "test_passes": c.test_passes.iter().map(|(j, p)| json!([j, p])).collect::<Vec<_>>(),
        "rank": c.rank, "diff": c.diff,
    })
}

pub fn search(s: &Search) -> Value {
    json!({
        "kind": kind(&s.kind), "base": text(&s.base), "n": s.n,
        "checks": s.checks.iter().map(text).collect::<Vec<_>>(), "limit": s.limit,
        "results": s.results.iter().map(|r| r.as_ref().map_or(Value::Null, candidate)).collect::<Vec<_>>(),
    })
}

pub fn parse_kind(v: &Value) -> Option<Kind> {
    let (name, k) = v.as_object()?.iter().next()?;
    Some(match name.as_str() {
        "code" => Kind::Code { goal: chars(&k["goal"])? },
        "map" => Kind::Map { goal: chars(&k["goal"])? },
        "counterexample" => Kind::Counterexample { goal: AgentProcess {
            search: k["goal"]["search"].as_u64()? as usize, index: k["goal"]["index"].as_u64()? as usize } },
        "compaction" => Kind::Compaction { goal: chars(&k["goal"])?, out: unhash(&k["out"])? },
        "scrub" => Kind::Scrub { goal: chars(&k["goal"])?, path: chars(&k["path"])? },
        _ => return None,
    })
}

pub fn parse_candidate(v: &Value) -> Option<Candidate> {
    Some(Candidate {
        commit: chars(&v["commit"])?, base: chars(&v["base"])?, checks_pass: v["checks_pass"].as_bool()?,
        changed: v["changed"].as_array()?.iter().map(chars).collect::<Option<_>>()?,
        out: unhash(&v["out"])?,
        intents: v["intents"].as_array()?.iter().map(|e| Some((e[0].as_u64()?, chars(&e[1])?))).collect::<Option<_>>()?,
        test_passes: v["test_passes"].as_array()?.iter().map(|e| Some((e[0].as_i64()?, e[1].as_bool()?))).collect::<Option<_>>()?,
        rank: v["rank"].as_i64()?, diff: v["diff"].as_u64()?,
    })
}

pub fn parse_search(v: &Value) -> Option<Search> {
    Some(Search {
        kind: parse_kind(&v["kind"])?, base: chars(&v["base"])?, n: v["n"].as_u64()? as usize,
        checks: v["checks"].as_array()?.iter().map(chars).collect::<Option<_>>()?,
        limit: v["limit"].as_u64()?,
        results: v["results"].as_array()?.iter()
            .map(|r| if r.is_null() { Some(None) } else { parse_candidate(r).map(Some) })
            .collect::<Option<_>>()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(commit: &str, out: u64, rank: i64) -> Candidate {
        Candidate {
            commit: commit.chars().collect(), base: "b".chars().collect(), checks_pass: true,
            changed: vec!["src/a.rs".chars().collect()], out: vec![out, u64::MAX],
            intents: vec![(1200, "an intent".chars().collect())], test_passes: vec![(-1, true), (0, false)],
            rank, diff: 3,
        }
    }

    /// A search survives the round trip, and the gates decide the same on both sides.
    #[test]
    fn round_trip() {
        for kind in [
            Kind::Code { goal: "g".chars().collect() },
            Kind::Compaction { goal: "h".chars().collect(), out: vec![5276956862258435173] },
            Kind::Counterexample { goal: AgentProcess { search: 0, index: 1 } },
            Kind::Scrub { goal: "g".chars().collect(), path: "tests/s.rs".chars().collect() },
            Kind::Map { goal: "t.vtt".chars().collect() },
        ] {
            let s = Search {
                kind, base: "b".chars().collect(), n: 3, checks: vec!["src/spec.rs".chars().collect()], limit: 9,
                results: vec![Some(c("x", 7, 1)), None, Some(c("y", 7, 2))],
            };
            let v = search(&s);
            let back = parse_search(&serde_json::from_str(&v.to_string()).unwrap()).unwrap();
            assert_eq!(search(&back), v);
            assert_eq!(crate::exec::selected(&back), crate::exec::selected(&s));
        }
    }
}
