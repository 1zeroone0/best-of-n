//! Interrupts: what only engineer can answer, derived from the traces and
//! never stored (D22: the view's code, not the spec). Trusted code. An
//! interrupt is pending until the action that answers it, which bon recognises
//! from what is already recorded; there is no dismiss. Its kinds:
//!
//! - `proposal`: a queue proposal awaiting acceptance. Raised when bon queue
//!   wrote it; resolved by the first commit on trunk's history that cites its
//!   transcript (`Source:`), as bon queue reads it: one that adds to the queue
//!   accepts it, one that does not rejects it.
//! - `blocked`: an attempt blocked with its width list spent (its bon process
//!   ended blocked) or its limit spent (it exited when what it had left of its
//!   limit could not reserve its last search again). Resolved by the first of:
//!   a later bon process of its kind on the same goal (run again), or a commit
//!   on trunk's history that changes the manifest, the queue or a check path
//!   (widen, raise the limit, change the spec, drop the intent).
//! - `transcript`: a transcript the host file routes nowhere. Its source is the
//!   routing of queue 80, which is to write, for each transcript it routes, a
//!   line of `routes.jsonl` in its bon process's trace, in the one shape:
//!   `{"program": "route", "context": <transcript path>, "sha256": <its
//!   hash>, "title": <meeting title>, "output": <repository root, or null>,
//!   "verdict": null, "behavior": null, "time": <unix seconds>}`. A line whose
//!   output is null is the interrupt; a later line with the same hash and an
//!   output resolves it.
//!
//! A counterexample that landed is never an interrupt: it is information, not
//! a question (D24). The derivation is a function of a set of repositories'
//! projections, so the host's listing is the same function over more of them.

use std::path::Path;

use serde_json::{json, Value};

use crate::projection::Interrupt;
use crate::view::{ago, money_or as money, share};

fn git(root: &Path, args: &[&str]) -> String { super::git(root, args).unwrap_or_default() }

fn now() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64) }

/// The choices a block offers, by the kernel's word for its reason (`limit`
/// for a limit spent): a reason only time answers is run again; a spec that
/// does not decide is changed or its intent dropped; a search that found too
/// few is widened, or the spec changed, or the intent dropped.
fn choices_for(reason: Option<&str>) -> &'static [&'static str] {
    match reason {
        Some("trunk_moved" | "refused") => &["run again"],
        Some("undecided") => &["change the spec", "drop the intent"],
        Some("limit") => &["raise the limit", "change the spec", "drop the intent"],
        _ => &["widen", "change the spec", "drop the intent"],
    }
}

/// The search kind a block's widening widens: its tests' for too few tests
/// or tests that tell no foil, else the attempt's own.
fn widened<'a>(reason: Option<&str>, kind: &'a str) -> &'a str {
    match reason { Some("too_few_tests" | "undiscriminating") => "counterexample", _ => kind }
}

/// The manifest at a commit (`HEAD`: this checkout's).
fn manifest(root: &Path, at: &str) -> toml::Value {
    toml::from_str(&git(root, &["show", &format!("{at}:.bon/bon.toml")])).unwrap_or(toml::Value::Table(Default::default()))
}

fn number(v: Option<&toml::Value>) -> Option<f64> { v.and_then(|v| v.as_float().or(v.as_integer().map(|i| i as f64))) }

/// The paths whose commits answer a block: the manifest, the queue, the checks.
fn answering_paths(m: &toml::Value) -> Vec<String> {
    let mut out = vec![".bon/bon.toml".to_string(), ".bon/queue.tsv".to_string()];
    out.extend(m.get("checks").and_then(|c| c.get("paths")).and_then(|p| p.as_array()).into_iter().flatten().filter_map(|v| v.as_str().map(String::from)));
    out
}

/// A commit on trunk's history: its hash, committer time, subject and the paths it touched.
struct Commit { hash: String, time: i64, subject: String, paths: Vec<String> }

/// The commits on this checkout's history that touch `paths`, oldest first.
fn commits(root: &Path, paths: &[String]) -> Vec<Commit> {
    let mut args = vec!["log", "--reverse", "--format=%x00%H %ct %s", "--name-only", "HEAD", "--"];
    args.extend(paths.iter().map(String::as_str));
    git(root, &args).split('\0').filter(|c| !c.trim().is_empty()).filter_map(|c| {
        let mut lines = c.lines();
        let mut head = lines.next()?.splitn(3, ' ');
        Some(Commit { hash: head.next()?.into(), time: head.next()?.parse().ok()?, subject: head.next().unwrap_or("").into(),
            paths: lines.map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect() })
    }).collect()
}

/// Which choice a commit showed: a change to a check path changes the spec; a
/// change to the manifest that adds a line naming a limit raises it, any other
/// widens; a change to the queue alone drops the intent.
fn choice_of(root: &Path, c: &Commit, m: &toml::Value) -> &'static str {
    let checks = &answering_paths(m)[2..];
    if c.paths.iter().any(|p| checks.iter().any(|k| p == k || (k.ends_with('/') && p.starts_with(k.as_str())))) { return "change the spec"; }
    if c.paths.iter().any(|p| p == ".bon/bon.toml") {
        let diff = git(root, &["show", "--format=", "-U0", &c.hash, "--", ".bon/bon.toml"]);
        return if diff.lines().any(|l| l.starts_with('+') && !l.starts_with("+++") && l.contains("limit")) { "raise the limit" } else { "widen" };
    }
    "drop the intent"
}

/// A bon process's limit and what it was charged, from its transitions:
/// `initialize <root> <limit>` and each `wait … <charged> <generation>`, in
/// microdollars; and its last grant's width and agent process limit.
fn spent(p: &Value) -> Option<(u64, u64, u64, u64)> {
    let ts: Vec<&str> = p["transitions"].as_array()?.iter().filter_map(|t| t.as_str()).collect();
    let limit = ts.iter().find_map(|t| t.strip_prefix("initialize ")?.split_whitespace().nth(1)?.parse::<u64>().ok())?;
    let charged: u64 = ts.iter().filter_map(|t| t.strip_prefix("wait ")?.split_whitespace().nth(4)?.parse::<u64>().ok()).sum();
    let grant: Vec<&str> = ts.iter().rev().find(|t| t.starts_with("grant "))?.split_whitespace().collect();
    Some((limit, charged, grant.get(1)?.parse().ok()?, grant.get(3)?.parse().ok()?))
}

/// The reason a bon process of code or compaction reaches engineer: its last
/// attempt's block word when it ended blocked (its width list spent), or
/// `limit` when it exited on a recorded error with less left of its limit than
/// its last search reserved. None otherwise.
fn block(p: &Value) -> Option<Option<String>> {
    let searches = p["searches"].as_array()?;
    let last = searches.iter().rev().find(|s| matches!(s["kind"].as_str(), Some("code" | "compaction")))?;
    match p["outcome"].as_str()? {
        "blocked" => Some(last["reason"].as_str().map(String::from)),
        "exited" if p["transitions"].as_array()?.iter().any(|t| t.as_str().is_some_and(|t| t.starts_with("exited: "))) => {
            let (limit, charged, n, l) = spent(p)?;
            (limit.saturating_sub(charged) < n * l).then(|| Some("limit".to_string()))
        }
        _ => None,
    }
}

/// When a bon process's trace last says something happened: its searches'
/// reports, else its start.
fn last_time(p: &Value) -> i64 {
    p["searches"].as_array().into_iter().flatten().filter_map(|s| s["time"].as_i64()).max().unwrap_or(p["time"].as_i64().unwrap_or(0))
}

/// What a bon process's last attempt cost (its code or compaction search and
/// every search after it), and one search of `kind`'s cost per agent process
/// and width: the last of that kind in the process.
fn attempt_cost(p: &Value, kind: &str) -> (f64, Option<(f64, u64)>) {
    let s = p["searches"].as_array().cloned().unwrap_or_default();
    let m = s.iter().rposition(|x| matches!(x["kind"].as_str(), Some("code" | "compaction"))).unwrap_or(0);
    let total = s[m..].iter().filter_map(|x| x["cost"].as_f64()).sum();
    let per = s.iter().rev().find(|x| x["kind"] == kind).and_then(|x| {
        let w = x["width"].as_u64().filter(|w| *w > 0)?;
        Some((x["cost"].as_f64()? / w as f64, w))
    });
    (total, per)
}

/// Success per agent process of `kind` at `width`, over every reported search in the projection.
fn success_at(state: &Value, kind: &str, width: u64) -> (u64, u64) {
    let mut out = (0, 0);
    for s in state["processes"].as_array().into_iter().flatten().flat_map(|p| p["searches"].as_array().into_iter().flatten()) {
        if s["kind"] != kind || s["width"].as_u64() != Some(width) || s["time"].is_null() { continue; }
        out.1 += width;
        out.0 += if kind == "foil" {
            s["candidates"].as_array().map_or(0, |c| c.iter().filter(|c| c["accepted"] == true && c["proved"] != true).count() as u64)
        } else { s["verified"].as_u64().unwrap_or(0) };
    }
    out
}

/// The median of a kind's pushes' cost, from the run-time distribution, in words.
fn push_cost(state: &Value, kind: &str) -> String {
    state["totals"]["run_time"].as_array().into_iter().flatten().find(|r| r["kind"] == kind && r["pushes"].as_u64().unwrap_or(0) > 0)
        .and_then(|r| Some(format!("a {kind} push costs {} (median of {})", money(Some(r["cost"]["median"].as_f64()?)), r["pushes"])))
        .unwrap_or_else(|| format!("no {kind} push measured yet"))
}

/// Each decision record of a repository, by its interrupt's id.
fn decisions(root: &Path) -> Vec<Value> {
    std::fs::read_to_string(root.join(best_of_n::trusted::DECISIONS)).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// Every interrupt of a set of repositories, pending and resolved, oldest
/// first: each repository's root and its projection (`view::state`).
pub fn interrupts(states: &[(&Path, &Value)]) -> Vec<Value> {
    let mut out = Vec::new();
    for (root, state) in states { out.extend(of(root, state)); }
    out.sort_by_key(|i| (i["raised"].as_i64(), i["id"].as_str().map(String::from)));
    out
}

/// One repository's interrupts.
fn of(root: &Path, state: &Value) -> Vec<Value> {
    if state["configured"] != true { return Vec::new(); }
    let m = manifest(root, "HEAD");
    let paths = answering_paths(&m);
    let history = commits(root, &paths);
    let procs: Vec<&Value> = state["processes"].as_array().into_iter().flatten().collect();
    let rate = state["totals"]["rate"].as_f64();
    let repository = state["repo"]["name"].as_str().unwrap_or("").to_string();
    let mut out = Vec::new();
    let base = |kind: &str, id: String, about: String, raised: i64| json!({ "kind": kind, "id": id, "repository": repository, "root": root.to_string_lossy(),
        "about": about, "raised": raised, "resolved": null, "reason": null, "what": [], "choices": [], "answer": null, "came_of_it": null, "decision": null, "transcript": null });

    // Attempts blocked with their width list or limit spent.
    for p in &procs {
        let kind = p["kind"].as_str().unwrap_or("");
        if !matches!(kind, "code" | "compaction") { continue; }
        let Some(reason) = block(p) else { continue };
        let raised = last_time(p);
        let mut i = base("blocked", format!("blocked {}", p["trace"].as_str().unwrap_or("")), format!("{kind} {}", p["title"].as_str().unwrap_or("")), raised);
        i["reason"] = json!(reason);
        let mains: Vec<&Value> = p["searches"].as_array().into_iter().flatten().filter(|s| s["kind"] == kind).collect();
        let widths: Vec<String> = mains.iter().filter_map(|s| s["width"].as_u64()).map(|w| w.to_string()).collect();
        let cost = |k: &str| p[k].as_f64().unwrap_or(0.0);
        i["what"] = json!([
            p["sentence"].as_str().unwrap_or(""),
            format!("{} at width {} · {} ({} generation + {} time) · trace {}", if mains.len() == 1 { "1 attempt".to_string() } else { format!("{} attempts", mains.len()) },
                widths.join(", "), money(Some(cost("cost"))), money(Some(cost("generation"))), money(Some(cost("time_cost"))), p["trace"].as_str().unwrap_or("")),
        ]);
        let r = reason.as_deref();
        let wide = widened(r, kind);
        let (last, per) = attempt_cost(p, wide);
        // The settings it ran with: the manifest at its goal.
        let ran = Some(manifest(root, p["goal"].as_str().unwrap_or("HEAD"))).filter(|r| r.get("searches").is_some()).unwrap_or_else(|| m.clone());
        let list = ran.get("searches").and_then(|s| s.get(wide)).and_then(|s| s.get("n")).map(|n| n.to_string()).unwrap_or_else(|| "unset".into());
        let limit = number(ran.get("limit"));
        let checks = paths[2..].join(", ");
        i["choices"] = json!(choices_for(r).iter().map(|c| {
            let (how, cost) = match *c {
                "run again" => (format!("bon {kind}"), format!("≈ {} (the last attempt)", money(Some(last)))),
                "widen" => (format!("raise n of [searches] {wide} in .bon/bon.toml (it ran at {list})"), match per {
                    Some((each, w)) => { let (k, n) = success_at(state, wide, w); format!("{} per agent process (the last {wide} search, width {w}); verified per agent process at width {w}: {}", money(Some(each)), share(k, n)) }
                    None => "no search of it measured yet".into(),
                }),
                "raise the limit" => (format!("raise limit in .bon/bon.toml (it ran with {})", money(limit)), match spent(p) {
                    Some((l, charged, n, a)) => format!("{} of {} spent; its next search reserves {}", money(Some(charged as f64 / 1e6)), money(Some(l as f64 / 1e6)), money(Some((n * a) as f64 / 1e6))),
                    None => format!("≈ {} an attempt", money(Some(last))),
                }),
                "change the spec" => (format!("commit to {checks}"), format!("your time{}, then an attempt ≈ {}", rate.map_or(String::new(), |r| format!(" at ${r:.0}/h")), money(Some(last)))),
                _ => ("take its line off .bon/queue.tsv".to_string(), format!("nothing more; the {} spent on it stays spent", money(Some(cost("cost"))))),
            };
            json!({ "choice": c, "how": how, "cost": cost })
        }).collect::<Vec<_>>());
        // Resolved by a later attempt on the same goal, or a commit that answers it.
        let again = procs.iter().filter(|q| q["kind"] == kind && q["goal"] == p["goal"] && q["trace"] != p["trace"] && q["time"].as_i64().is_some_and(|t| t > raised))
            .min_by_key(|q| q["time"].as_i64());
        let commit = history.iter().find(|c| c.time > raised);
        match (again, commit) {
            (Some(q), c) if c.is_none_or(|c| c.time > q["time"].as_i64().unwrap_or(0)) => {
                i["resolved"] = q["time"].clone();
                i["answer"] = json!({ "commit": null, "subject": format!("bon {kind}: trace {}", q["trace"].as_str().unwrap_or("")), "choice": "run again" });
            }
            (_, Some(c)) => {
                i["resolved"] = json!(c.time);
                i["answer"] = json!({ "commit": c.hash, "subject": c.subject, "choice": choice_of(root, c, &m) });
            }
            _ => {}
        }
        // What came of it: how the first bon process of its kind after it ended.
        if let Some(t) = i["resolved"].as_i64() {
            let next = procs.iter().filter(|q| q["kind"] == kind && q["time"].as_i64().is_some_and(|x| x >= t) && q["trace"] != p["trace"]).min_by_key(|q| q["time"].as_i64());
            i["came_of_it"] = json!(next.map(|q| format!("{}: {kind} {}", q["outcome"].as_str().unwrap_or(""), q["title"].as_str().unwrap_or(""))));
        }
        out.push(i);
    }

    // Queue proposals, each resolved by the first commit that cites its transcript.
    let cited = git(root, &["log", "--reverse", "--format=%x00%H %ct %s%n%(trailers:key=Source,valueonly)", "HEAD"]);
    let cites: Vec<(String, i64, String, Vec<String>)> = cited.split('\0').filter(|c| !c.trim().is_empty()).filter_map(|c| {
        let mut lines = c.lines();
        let mut head = lines.next()?.splitn(3, ' ');
        Some((head.next()?.to_string(), head.next()?.parse().ok()?, head.next().unwrap_or("").to_string(), lines.map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()))
    }).collect();
    let queued: Vec<u64> = state["queue"].as_array().into_iter().flatten().filter_map(|q| q["id"].as_u64()).collect();
    for pr in state["proposals"].as_array().into_iter().flatten() {
        let (source, path) = (pr["source"].as_str().unwrap_or(""), pr["path"].as_str().unwrap_or(""));
        let text = std::fs::read_to_string(root.join(path)).unwrap_or_default();
        // Raised when bon queue made its commit (the patch's first line names it), else when the patch was written.
        let raised = text.lines().next().and_then(|l| l.strip_prefix("From ")?.split_whitespace().next().map(String::from))
            .and_then(|c| git(root, &["show", "-s", "--format=%ct", &c]).parse::<i64>().ok())
            .or_else(|| std::fs::metadata(root.join(path)).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64))
            .unwrap_or(0);
        let mut i = base("proposal", format!("proposal {source}"), source.to_string(), raised);
        let intents: Vec<&Value> = pr["intents"].as_array().into_iter().flatten().collect();
        let ids: Vec<String> = intents.iter().filter_map(|x| x["id"].as_u64()).map(|n| format!("#{n}")).collect();
        let contested = pr["contested"].as_array().map_or(0, |c| c.len());
        i["what"] = json!([
            format!("bon queue proposes {} from {source}{}", if intents.len() == 1 { "1 intent".to_string() } else { format!("{} intents", intents.len()) },
                if contested > 0 { format!("; {contested} cue{} only one agent process cited", if contested == 1 { "" } else { "s" }) } else { String::new() }),
            format!("{}: {}{}", ids.join(", "), intents.first().and_then(|x| x["intent"].as_str()).unwrap_or(""), if intents.len() > 1 { " …" } else { "" }),
        ]);
        i["choices"] = json!([
            { "choice": "accept", "how": format!("git am {path}"), "cost": format!("{} queued; {}", ids.join(", "), push_cost(state, "code")) },
            { "choice": "reject", "how": format!("git commit --allow-empty -m 'queue: not {source}' -m 'Source: {source}'"), "cost": "nothing; bon queue will not propose it again" },
        ]);
        if let Some((hash, time, subject, _)) = cites.iter().find(|(_, _, _, s)| s.iter().any(|s| s == source)) {
            let added = git(root, &["diff-tree", "--no-commit-id", "--numstat", "-r", hash, "--", ".bon/queue.tsv"]).split_whitespace().next().and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
            let choice = if added > 0 { "accept" } else { "reject" };
            i["resolved"] = json!(time);
            i["answer"] = json!({ "commit": hash, "subject": subject, "choice": choice });
            let proposed: Vec<u64> = intents.iter().filter_map(|x| x["id"].as_u64()).collect();
            i["came_of_it"] = json!((choice == "accept").then(|| {
                let left = proposed.iter().filter(|n| queued.contains(n)).count();
                if left == 0 { "every intent it queued is retired".to_string() } else { format!("{left} of {} on the queue", proposed.len()) }
            }));
        }
        out.push(i);
    }

    // Transcripts routed nowhere (queue 80's routes.jsonl), each resolved by a later route of the same hash.
    let routes: Vec<Value> = std::fs::read_dir(root.join(".bon/traces")).into_iter().flatten().flatten()
        .flat_map(|e| std::fs::read_to_string(e.path().join("routes.jsonl")).unwrap_or_default().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).collect::<Vec<_>>()).collect();
    for r in routes.iter().filter(|r| r["output"].is_null()) {
        let (hash, raised) = (r["sha256"].as_str().unwrap_or(""), r["time"].as_i64().unwrap_or(0));
        let mut i = base("transcript", format!("transcript {hash}"), r["context"].as_str().unwrap_or("").to_string(), raised);
        i["what"] = json!([format!("{} (meeting title \"{}\") matches no route in the host file", r["context"].as_str().unwrap_or(""), r["title"].as_str().unwrap_or(""))]);
        i["choices"] = json!([{ "choice": "route", "how": "add a route for its meeting title to the host file", "cost": "a queue search in the repository it routes to" }]);
        if let Some(later) = routes.iter().filter(|x| x["sha256"] == hash && !x["output"].is_null() && x["time"].as_i64().is_some_and(|t| t >= raised)).min_by_key(|x| x["time"].as_i64()) {
            i["resolved"] = later["time"].clone();
            i["answer"] = json!({ "commit": null, "subject": format!("routed to {}", later["output"].as_str().unwrap_or("")), "choice": "route" });
        }
        out.push(i);
    }

    // Each one's decision record, where bon has written it: its verdict is what came of it.
    let records = decisions(root);
    for i in out.iter_mut() {
        let Some(d) = records.iter().find(|d| d["interrupt"] == i["id"]) else { continue };
        i["decision"] = json!({ "program": d["program"], "context": d["context"], "output": d["output"], "verdict": i["came_of_it"], "behavior": d["behavior"] });
        i["transcript"] = d["transcript"].clone();
    }
    out
}

/// What an interrupt showed, as one text: what happened, then each choice with its cost.
fn shown(i: &Interrupt) -> String {
    let mut lines = i.what.clone();
    lines.extend(i.choices.iter().map(|c| format!("{}: {} ({})", c.choice, c.cost, c.how)));
    lines.join("\n")
}

/// Each resolved interrupt with no decision record yet, as its record: in the
/// one shape, with the interrupt it answers and when it was raised and resolved.
pub fn unrecorded(interrupts: &[Interrupt]) -> Vec<(String, Value)> {
    interrupts.iter().filter(|i| i.resolved.is_some() && i.decision.is_none()).map(|i| (i.root.clone(), json!({
        "program": "engineer", "context": shown(i), "output": i.answer.as_ref().and_then(|a| a.commit.clone()),
        "verdict": null, "behavior": i.answer.as_ref().map(|a| a.choice.clone()),
        "interrupt": i.id, "kind": i.kind, "raised": i.raised, "resolved": i.resolved,
    }))).collect()
}

/// Turnaround by kind, from every interrupt: how many resolved and how many
/// are pending, and the median and 90th percentile of raised to resolved.
pub fn turnaround(interrupts: &[Value]) -> Vec<Value> {
    let mut kinds: Vec<&str> = interrupts.iter().filter_map(|i| i["kind"].as_str()).collect();
    kinds.sort(); kinds.dedup();
    kinds.into_iter().map(|k| {
        let of: Vec<&Value> = interrupts.iter().filter(|i| i["kind"] == k).collect();
        let secs: Vec<f64> = of.iter().filter_map(|i| Some((i["resolved"].as_i64()? - i["raised"].as_i64()?).max(0) as f64)).collect();
        json!({ "kind": k, "resolved": secs.len(), "pending": of.len() - secs.len(), "time": { "median": crate::view::median(&secs), "p90": crate::view::p90(&secs) } })
    }).collect()
}

/// Words, wrapped to `w` columns; a word longer than a line (a path in a
/// command) is never broken, so the command still runs as shown.
fn wrap(text: &str, w: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > w { out.push(std::mem::take(&mut line)); }
        if !line.is_empty() { line.push(' '); }
        line.push_str(&word);
    }
    if !line.is_empty() || out.is_empty() { out.push(line); }
    out
}

/// The pending interrupts as aligned text, `width` columns wide: each one's
/// kind, what it is about and when it was raised, what happened, then each
/// choice with what it costs and, under it, how it is made.
pub fn text(pending: &[&Interrupt], now: i64, width: usize) -> String {
    let label = pending.iter().flat_map(|i| i.choices.iter().map(|c| c.choice.chars().count() + 2).chain([i.kind.chars().count()])).max().unwrap_or(0) + 2;
    // Too narrow for two columns: each text under its label.
    let (at, room) = if width >= label + 30 { (label, width - label) } else { (4, width.saturating_sub(4).max(20)) };
    let mut out = String::new();
    // A label, and its text wrapped beside it (or, too narrow, under it).
    let put = |first: &str, text: &str, out: &mut String| {
        let lines = wrap(text, room);
        if at == label {
            for (k, l) in lines.iter().enumerate() {
                let head = if k == 0 { first } else { "" };
                out.push_str(&format!("{head}{}{l}\n", " ".repeat(at.saturating_sub(head.chars().count()))));
            }
        } else {
            if !first.trim().is_empty() { out.push_str(&format!("{first}\n")); }
            for l in lines { out.push_str(&format!("{}{l}\n", " ".repeat(at))); }
        }
    };
    for (k, i) in pending.iter().enumerate() {
        if k > 0 { out.push('\n'); }
        // The repository, where the listing spans more than one.
        let repo = if pending.iter().all(|x| x.root == i.root) { String::new() } else { format!(" · {}", i.repository) };
        put(&crate::view::cap(&i.kind), &format!("{} · raised {}{repo}", i.about, ago(now, i.raised)), &mut out);
        for w in &i.what { put("", w, &mut out); }
        for c in &i.choices {
            put(&format!("  {}", c.choice), &c.cost, &mut out);
            put("", &c.how, &mut out);
        }
    }
    out.lines().map(str::trim_end).collect::<Vec<_>>().join("\n") + "\n"
}

/// The terminal's width, when standard output is one; else no wrapping.
fn width() -> usize {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() { return usize::MAX / 2; }
    ratatui::crossterm::terminal::size().map_or(80, |(w, _)| w as usize).max(20)
}

/// `bon pending [--transcript FILE]`: this repository's pending interrupts,
/// oldest first, or one quiet line when there are none; each resolution bon
/// now recognises for the first time is recorded (`trusted::record_decision`),
/// with FILE, the transcript of the agent session that runs it, as a pointer
/// and its hash. Exits 0 when nothing is pending and 2 when something is.
pub fn run(root: &str, transcript: Option<&str>) -> Result<(), String> {
    if let Some(t) = transcript { if !Path::new(t).is_file() { return Err(format!("--transcript {t}: no such file; name this session's transcript file")); } }
    let path = Path::new(root);
    let state = crate::view::state(path, &crate::view::Filter::default());
    let all: Vec<Interrupt> = serde_json::from_value(state["interrupts"].clone()).map_err(|e| format!("the interrupts do not match their types: {e}"))?;
    let mut recorded = 0;
    for (r, record) in unrecorded(&all) {
        best_of_n::trusted::record_decision(Path::new(&r), record, transcript.map(Path::new))?;
        recorded += 1;
    }
    if recorded > 0 { if let Err(e) = best_of_n::trusted::persist(path) { eprintln!("bon: traces not persisted: {e}"); } }
    let pending: Vec<&Interrupt> = all.iter().filter(|i| i.resolved.is_none()).collect();
    let repo = state["repo"]["name"].as_str().unwrap_or("this repository");
    let noted = if recorded == 0 { String::new() } else { format!("; recorded {} answer{}", recorded, if recorded == 1 { "" } else { "s" }) };
    if pending.is_empty() { println!("nothing pending in {repo}{noted}"); return Ok(()); }
    println!("{} pending in {repo}, oldest first{noted}\n", pending.len());
    print!("{}", text(&pending, now(), width()));
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interrupt(kind: &str, raised: i64) -> Interrupt {
        serde_json::from_value(json!({ "kind": kind, "id": format!("{kind} 1"), "about": "code from 1a2b3c4", "raised": raised,
            "what": ["1 of 2 verified; too_few_verified: fewer than two verified candidates"],
            "choices": [{ "choice": "widen", "how": "raise n of [searches] code in .bon/bon.toml (now [2])", "cost": "$0.10 per agent process" },
                        { "choice": "drop the intent", "how": "take its line off .bon/queue.tsv", "cost": "nothing more" }] })).unwrap()
    }

    #[test]
    fn a_block_offers_choices_by_the_kernels_word() {
        assert_eq!(choices_for(Some("trunk_moved")), ["run again"]);
        assert_eq!(choices_for(Some("undecided")), ["change the spec", "drop the intent"]);
        assert_eq!(choices_for(Some("limit"))[0], "raise the limit");
        assert_eq!(choices_for(None)[0], "widen");
        assert_eq!((widened(Some("too_few_tests"), "code"), widened(Some("too_few_verified"), "compaction")), ("counterexample", "compaction"));
    }

    #[test]
    fn pending_text_is_aligned_at_any_width() {
        let i = interrupt("blocked", 0);
        let mut long = i.clone();
        long.choices[0].how = format!("git am .bon/traces/proposals/{}.patch", "a".repeat(60));
        for w in [24, 60, 100, 400] {
            let t = text(&[&i, &long], 3600, w);
            // Every line fits, but one that is a single unbroken word: the path stays whole.
            assert!(t.lines().all(|l| l.chars().count() <= w.max(24) || !l.trim().contains(' ')), "{w}:\n{t}");
            assert!(t.contains(&format!(".bon/traces/proposals/{}.patch", "a".repeat(60))), "{t}");
            assert!(t.contains("widen") && t.contains("raised 1h00m ago") && t.contains("Blocked"), "{t}");
        }
        // Two columns: every text starts at one column.
        let t = text(&[&i], 3600, 100);
        assert!(t.lines().all(|l| l.len() > 19 && l[..19].ends_with(' ') && !l[19..20].starts_with(' ')), "{t}");
    }

    #[test]
    fn turnaround_is_raise_to_resolve_by_kind() {
        let t = turnaround(&[json!({ "kind": "blocked", "raised": 10, "resolved": 70 }), json!({ "kind": "blocked", "raised": 10, "resolved": null }),
            json!({ "kind": "proposal", "raised": 0, "resolved": 30 })]);
        assert_eq!(t[0]["resolved"], 1);
        assert_eq!(t[0]["pending"], 1);
        assert_eq!(t[0]["time"]["median"], 60.0);
        assert_eq!(t[1]["time"]["p90"], 30.0);
    }

    #[test]
    fn a_resolution_is_recorded_once_in_the_one_shape() {
        let mut i = interrupt("blocked", 0);
        assert!(unrecorded(&[i.clone()]).is_empty());
        i.resolved = Some(60);
        i.answer = Some(crate::projection::Answer { commit: Some("abc".into()), subject: "bon.toml: wider".into(), choice: "widen".into() });
        let r = unrecorded(&[i.clone()]);
        assert_eq!(r.len(), 1);
        for k in ["program", "context", "output", "verdict", "behavior"] { assert!(r[0].1.get(k).is_some(), "{k}"); }
        assert_eq!((r[0].1["output"].as_str(), r[0].1["behavior"].as_str()), (Some("abc"), Some("widen")));
        assert!(r[0].1["context"].as_str().unwrap().contains("widen: $0.10 per agent process"));
        i.decision = Some(Default::default());
        assert!(unrecorded(&[i]).is_empty());
    }
}
