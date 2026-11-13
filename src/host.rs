//! The host as bon shows it (queue 60): which repositories exist, and across
//! them what waits on engineer and what that waiting costs, the host's two
//! pools, memory, each running bon process with those of one tree together,
//! and a journal. Trusted code; it decides nothing and stores nothing. Every
//! fact comes from the process list, the slot files, the traces, the host
//! file and the OS (`projection::Host` says each).
//!
//! Which repositories exist: those under the user layer's root (its
//! immediate directories) with a `.bon/bon.toml`, those a live bon process
//! searches (a benchmark's sandbox, anywhere), and those a route names. Run in
//! a repository, the host is that repository alone; its pools and memory are
//! still the host's, which it shares.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Every repository bon reaches: under `user`, named by a live process in
/// `live`, or named by a route; each once, by its canonical path, by name.
pub fn repositories(user: Option<&Path>, live: &[Value], routes: &[(String, PathBuf)]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |p: &Path| {
        if let Ok(c) = std::fs::canonicalize(p) { if c.join(".bon/bon.toml").is_file() && !out.contains(&c) { out.push(c); } }
    };
    if let Some(u) = user {
        let mut under: Vec<PathBuf> = std::fs::read_dir(u).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        under.sort();
        for p in &under { add(p); }
    }
    for p in live.iter().filter_map(|p| p["repository"].as_str()) { add(Path::new(p)); }
    for (_, r) in routes { add(r); }
    out.sort_by_key(|p| (p.file_name().map(|n| n.to_string_lossy().to_lowercase()), p.clone()));
    out
}

/// Each process's resident memory with all its descendants', in KB, from one
/// `ps` of every process, for the pids asked.
fn tree_memory(pids: &[u64]) -> HashMap<u64, u64> {
    let out = std::process::Command::new("ps").args(["-A", "-o", "pid=,ppid=,rss="]).stderr(std::process::Stdio::null()).output();
    let rows: Vec<(u64, u64, u64)> = out.map(|o| String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| {
        let mut f = l.split_whitespace().map(|x| x.parse::<u64>().ok());
        Some((f.next()??, f.next()??, f.next()??))
    }).collect()).unwrap_or_default();
    let mut children: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
    let mut own: HashMap<u64, u64> = HashMap::new();
    for (pid, ppid, rss) in &rows { children.entry(*ppid).or_default().push((*pid, *rss)); own.insert(*pid, *rss); }
    pids.iter().map(|p| {
        let (mut total, mut stack) = (own.get(p).copied().unwrap_or(0), vec![*p]);
        while let Some(q) = stack.pop() {
            for (c, rss) in children.get(&q).into_iter().flatten() { total += rss; stack.push(*c); }
        }
        (*p, total)
    }).collect()
}

/// The local offset from UTC, in seconds.
fn offset() -> i64 {
    std::process::Command::new("date").arg("+%z").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|z| { let z = z.trim(); let sign = if z.starts_with('-') { -1 } else { 1 }; let d: i64 = z.trim_start_matches(['+', '-']).parse().ok()?; Some(sign * ((d / 100) * 3600 + (d % 100) * 60)) })
        .unwrap_or(0)
}

/// Seconds since the epoch of this day's local midnight.
fn midnight(now: i64) -> i64 { let off = offset(); (now + off).div_euclid(86400) * 86400 - off }

/// A time as its local date and minute: 2026-11-13 09:12.
fn local(t: i64, off: i64) -> String {
    let s = (t + off).rem_euclid(86400);
    format!("{} {:02}:{:02}", crate::view::date((t + off).max(0) as u64), s / 3600, (s / 60) % 60)
}

/// Dollars to the cent, for a journal line.
fn money(d: f64) -> String { crate::view::money(d) }

/// What a bon process's attempts did that the journal tells: each push, each
/// block, each counterexample's test landed, at when its trace says it happened.
fn events_of(repository: &str, p: &Value, out: &mut Vec<Value>) {
    // A kind shown as a value, as everywhere: its first letter upper case.
    let (kind, title) = (crate::view::cap(p["kind"].as_str().unwrap_or("")), p["title"].as_str().unwrap_or(""));
    let searches: Vec<&Value> = p["searches"].as_array().into_iter().flatten().collect();
    let last = searches.iter().filter_map(|s| s["time"].as_i64()).max().unwrap_or(p["time"].as_i64().unwrap_or(0));
    let event = |time: i64, what: &str, text: String| json!({ "time": time, "repository": repository, "kind": what, "text": text });
    // A landing: an attempt whose test landed, at its searches' last report.
    for (k, _) in searches.iter().enumerate().filter(|(_, s)| s["end"] == "landed") {
        let next = searches[k + 1..].iter().position(|x| matches!(x["kind"].as_str(), Some("code" | "compaction"))).map_or(searches.len(), |j| k + 1 + j);
        let at = searches[k..next].iter().filter_map(|x| x["time"].as_i64()).max().unwrap_or(last);
        out.push(event(at, "landed", format!("{kind} {title}: a counterexample's test landed on trunk")));
    }
    match p["outcome"].as_str() {
        Some("pushed") => {
            let commit: String = p["push"]["commit"].as_str().unwrap_or("").chars().take(7).collect();
            out.push(event(p["push"]["time"].as_i64().unwrap_or(last), "pushed", format!("{kind} {title}: pushed {commit} · {}", money(p["cost"].as_f64().unwrap_or(0.0)))));
        }
        Some("blocked") => {
            let reason = searches.iter().rev().find_map(|s| s["reason"].as_str()).map_or(String::new(), |r| format!(": {}", r.replace('_', " ")));
            out.push(event(last, "blocked", format!("{kind} {title}{reason}")));
        }
        _ => {}
    }
}

/// The host's projection over `states`, each repository's root and its
/// projection (`view::state`), with `here` the repository it was read in (none:
/// the whole host), at `now`. `user`, `routes` and `live` are the host file's
/// user layer and the process list.
pub fn of(states: &[(PathBuf, Value)], here: Option<&Path>, user: Option<&Path>, live: &[Value], now: i64) -> Value {
    let today = midnight(now);
    let shown = |r: &str| states.iter().any(|(root, _)| root.as_path() == Path::new(r));
    // What waits on engineer: every repository's interrupts, and the user layer's on the whole host.
    let pairs: Vec<(&Path, &Value)> = states.iter().map(|(r, s)| (r.as_path(), s)).collect();
    let mut interrupts = crate::interrupt::interrupts(&pairs);
    if here.is_none() { if let Some(u) = user { interrupts.extend(crate::interrupt::transcripts(u)); } }
    interrupts.sort_by_key(|i| (i["raised"].as_i64(), i["id"].as_str().map(String::from)));
    // The running bon processes, as the process list and their traces say.
    let memory = tree_memory(&live.iter().filter_map(|p| p["pid"].as_u64()).collect::<Vec<_>>());
    let mut running: Vec<Value> = Vec::new();
    for e in live.iter().filter(|e| e["repository"].as_str().is_some_and(shown)) {
        let root = e["repository"].as_str().unwrap_or("");
        let state = states.iter().find(|(r, _)| r.as_path() == Path::new(root)).map(|(_, s)| s);
        let traced = state.and_then(|s| s["processes"].as_array().into_iter().flatten().find(|p| p["trace"] == e["trace"]));
        let search = traced.and_then(|p| p["searches"].as_array().and_then(|s| s.iter().rev().find(|s| s["running"] == true).or(s.last())));
        let n = |k: &str| search.and_then(|s| s[k].as_u64()).unwrap_or(0);
        running.push(json!({
            "pid": e["pid"], "repository": Path::new(root).file_name().map(|n| n.to_string_lossy().to_string()), "root": root, "trace": e["trace"],
            "background": e["background"] == true, "kind": e["kind"], "goal": e["goal"], "search": e["search"], "attempt": e["attempt"], "started": e["started"],
            "start": e["start"], "tree": e["tree"],
            "memory": memory.get(&e["pid"].as_u64().unwrap_or(0)).copied().unwrap_or(0) as f64 / 1e6,
            "sentence": traced.and_then(|p| p["sentence"].as_str()).unwrap_or("starting"),
            "width": search.and_then(|s| s["width"].as_u64()), "returned": n("returned"), "verified": n("verified"),
            "in_flight": n("in_flight"), "in_checks": n("in_checks"), "waiting": n("waiting"),
            "cost": traced.and_then(|p| p["cost"].as_f64()).unwrap_or(0.0),
        }));
    }
    // Those of one tree together: the groups in the order of their first process's start.
    running.sort_by_key(|r| (r["start"].as_i64(), r["pid"].as_u64()));
    let mut trees: Vec<Value> = Vec::new();
    for r in running {
        let tree = r["tree"].clone();
        match trees.iter_mut().find(|g| !tree.is_null() && g["tree"] == tree) {
            Some(g) => g["processes"].as_array_mut().unwrap().push(r),
            None => trees.push(json!({ "tree": tree, "processes": [r] })),
        }
    }
    // The pools, host-wide, and what the shown repositories' agent processes need of them now.
    let procs = || trees.iter().flat_map(|g| g["processes"].as_array().cloned().unwrap_or_default());
    let pools = best_of_n::trusted::host_pools();
    let held = pools.as_ref().map(best_of_n::trusted::pools_held).unwrap_or((0, 0));
    let sum = |k: &str| procs().filter_map(|p| p[k].as_u64()).sum::<u64>();
    let (total, free) = best_of_n::trusted::memory_gb();
    // engineer's time: each waited-on search's repository's rate, split among the host's.
    let waited = |e: &&Value| !e["started"].is_null() && e["background"] != true;
    let host_waited = live.iter().filter(waited).count() as u64;
    let rate_of = |root: &str| states.iter().find(|(r, _)| r.as_path() == Path::new(root)).and_then(|(_, s)| s["totals"]["rate"].as_f64()).unwrap_or(0.0);
    let mine: Vec<&Value> = live.iter().filter(waited).filter(|e| e["repository"].as_str().is_some_and(shown)).collect();
    let per_hour = mine.iter().map(|e| rate_of(e["repository"].as_str().unwrap_or(""))).sum::<f64>() / host_waited.max(1) as f64;
    // Every search's cost since midnight, its time part for engineer's.
    let searches = || states.iter().flat_map(|(_, s)| s["processes"].as_array().cloned().unwrap_or_default())
        .flat_map(|p| p["searches"].as_array().cloned().unwrap_or_default());
    let charged_today: f64 = searches().filter(|s| s["started"].as_i64().is_some_and(|t| t >= today)).filter_map(|s| s["time_cost"].as_f64()).sum();
    // Each repository, with what is pending in it and what runs.
    let repositories: Vec<Value> = states.iter().map(|(root, s)| {
        let r = root.to_string_lossy().to_string();
        let ps: Vec<&Value> = s["processes"].as_array().into_iter().flatten().collect();
        json!({ "name": root.file_name().map(|n| n.to_string_lossy().to_string()), "root": r, "configured": s["configured"] == true,
            "pending": interrupts.iter().filter(|i| i["root"] == r.as_str() && i["resolved"].is_null()).count(),
            "running": live.iter().filter(|e| e["repository"] == r.as_str()).count(),
            "latest": ps.iter().filter_map(|p| p["time"].as_i64()).max(),
            "today": ps.iter().flat_map(|p| p["searches"].as_array().into_iter().flatten()).filter(|x| x["started"].as_i64().is_some_and(|t| t >= today)).filter_map(|x| x["cost"].as_f64()).sum::<f64>() })
    }).collect();
    // The journal: what each repository's traces say happened, and each interrupt raised and resolved.
    let mut journal: Vec<Value> = Vec::new();
    for (root, s) in states {
        let name = root.file_name().map_or(String::new(), |n| n.to_string_lossy().to_string());
        for p in s["processes"].as_array().into_iter().flatten().filter(|p| p["running"] != true) { events_of(&name, p, &mut journal); }
    }
    for i in &interrupts {
        let (repo, about, kind) = (i["repository"].as_str().unwrap_or(""), i["about"].as_str().unwrap_or(""), i["kind"].as_str().unwrap_or(""));
        journal.push(json!({ "time": i["raised"], "repository": repo, "kind": "raised", "text": format!("{kind} {about}: waits on you") }));
        if let Some(t) = i["resolved"].as_i64() {
            let choice = i["answer"]["choice"].as_str().unwrap_or("answered");
            journal.push(json!({ "time": t, "repository": repo, "kind": "resolved", "text": format!("{kind} {about}: {choice}") }));
        }
    }
    journal.sort_by_key(|e| e["time"].as_i64());
    json!({
        "user": user.map(|u| u.to_string_lossy().to_string()), "here": here.map(|h| h.to_string_lossy().to_string()),
        "repositories": repositories, "turnaround": crate::interrupt::turnaround(&interrupts), "interrupts": interrupts,
        "waiting": { "searches": mine.len(), "host": host_waited, "per_hour": per_hour, "today": charged_today },
        "pools": {
            "agent_processes": { "size": pools.as_ref().map(|p| p.agent_processes), "held": held.0, "shown": sum("in_flight") },
            "check_processes": { "size": pools.as_ref().map(|p| p.check_processes), "held": held.1, "shown": sum("in_checks") },
            "check_threads": pools.as_ref().map(|p| p.threads),
        },
        "memory": { "total": total, "free": free, "bon": procs().filter_map(|p| p["memory"].as_f64()).sum::<f64>() },
        "trees": trees, "journal": journal, "now": now,
    })
}

/// Each repository's projection, read: the one at `here`, or every one the
/// host reaches. With the user layer and the process list they were read by.
pub fn read(here: Option<&Path>) -> (Vec<(PathBuf, Value)>, Option<PathBuf>, Vec<Value>) {
    let layer = best_of_n::trusted::user_layer().map(|(u, r)| (std::fs::canonicalize(&u).unwrap_or(u), r));
    let live = best_of_n::trusted::processes();
    let roots = match here {
        Some(h) => vec![std::fs::canonicalize(h).unwrap_or_else(|_| h.to_path_buf())],
        None => repositories(layer.as_ref().map(|(u, _)| u.as_path()), &live, layer.as_ref().map_or(&[][..], |(_, r)| r.as_slice())),
    };
    let states = roots.into_iter().map(|r| { let s = crate::view::state(&r, &crate::view::Filter::default()); (r, s) }).collect();
    (states, layer.map(|(u, _)| u), live)
}

/// The host's part a repository shows, from its projection already read:
/// its own processes and journal, and the host's pools and memory.
pub fn slice(root: &Path, state: &Value) -> Value {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let user = best_of_n::trusted::user_layer().map(|(u, _)| std::fs::canonicalize(&u).unwrap_or(u));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    of(&[(root.clone(), state.clone())], Some(&root), user.as_deref(), &best_of_n::trusted::processes(), now)
}

/// The host's projection, as types: the repository at `here`, or the whole host.
pub fn state(here: Option<&Path>) -> Value {
    let (states, user, live) = read(here);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    of(&states, here.map(|_| states[0].0.as_path()), user.as_deref(), &live, now)
}

/// How many journal lines the plain report prints: the latest.
const JOURNAL_LINES: usize = 12;

/// The host's projection as text, for `bon` outside every repository, in the
/// report's order and formats (`view::text`): where and what waiting costs
/// today; what waits on engineer; what runs and what it holds; what happened;
/// each repository.
pub fn text(h: &Value) -> String {
    use crate::view::{ago, cap, count, money, short, size, wrap};
    let Ok(h) = serde_json::from_value::<crate::projection::Host>(h.clone()) else { return "the host's projection does not match its types\n".into() };
    let mut out = String::new();
    let w = &h.waiting;
    out += &wrap(&format!("Host · {} · user layer {} · {} of your time today", count(h.repositories.len(), "repository", "repositories"),
        h.user.as_deref().unwrap_or("unset (no host file names user)"), money(w.today)), 0, 0);
    let pending: Vec<&crate::projection::Interrupt> = h.interrupts.iter().filter(|i| i.resolved.is_none()).collect();
    if !pending.is_empty() {
        out += &format!("\nPending  {} · bon pending has each one's choices and what each costs\n", pending.len());
        for i in &pending {
            let repo = if i.repository.is_empty() { String::new() } else { format!(" · {}", i.repository) };
            out += &wrap(&format!("{:<10} {}{repo} · raised {}", cap(&i.kind), i.about, ago(h.now, i.raised)), 2, 6);
            out += &wrap(i.what.first().map_or("", String::as_str), 6, 8);
        }
    }
    out += "\nNow\n";
    if w.searches > 0 { out += &wrap(&format!("You wait on {} · {}/h of your time", count(w.searches as usize, "search", "searches"), money(w.per_hour)), 2, 4); }
    let p = &h.pools;
    let pool = |name: &str, s: &crate::projection::Slots| s.size.map_or(format!("{name} unsized: no host file"), |n| format!("{name} {} of {n} held", s.held));
    out += &wrap(&format!("{} · {}{}", pool("agent_processes", &p.agent_processes), pool("check_processes", &p.check_processes),
        p.check_threads.map_or(String::new(), |t| format!(" · {t} threads each"))), 2, 4);
    if h.memory.total > 0.0 {
        out += &wrap(&format!("Memory {:.1} of {:.1} GB in use{}", h.memory.total - h.memory.free, h.memory.total, if h.trees.is_empty() { String::new() } else { format!(" · bon {}", size(h.memory.bon)) }), 2, 4);
    }
    let n: usize = h.trees.iter().map(|g| g.processes.len()).sum();
    out += &format!("\nbon Processes{}\n", if n > 0 { format!("  {n}") } else { String::new() });
    if n == 0 { out += "  No bon process is running\n"; }
    for g in &h.trees {
        let grouped = g.processes.len() > 1;
        if grouped { out += &format!("  Tree {} · {} bon processes from one tree\n", short(g.tree.as_deref().unwrap_or("")), g.processes.len()); }
        let ind = if grouped { 4 } else { 2 };
        for r in &g.processes {
            let what = match (r.kind.as_deref(), r.goal.as_deref()) {
                (Some(k), Some(goal)) => format!("{} {}", cap(k), if goal.chars().all(|c| c.is_ascii_hexdigit()) { format!("from {}", short(goal)) } else { goal.to_string() }),
                (Some(k), None) => cap(k),
                _ => "Between searches".to_string(),
            };
            out += &wrap(&format!("{} · {what}{} · {} · pid {} · {} · {}", r.repository, if r.background { " · background" } else { "" },
                ago(h.now, r.start), r.pid, size(r.memory), r.sentence), ind, ind + 4);
        }
    }
    out += "\nJournal\n";
    if h.journal.is_empty() { out += "  No push, block or interrupt yet\n"; }
    // As Traces: a heading for each day, then each event's time.
    let off = offset();
    let mut last_day = None;
    for e in h.journal.iter().rev().take(JOURNAL_LINES).rev() {
        let day = local(e.time, off);
        let (date, time) = day.split_once(' ').unwrap_or((&day, ""));
        if last_day.as_deref() != Some(date) { out += &format!("  {date}\n"); last_day = Some(date.to_string()); }
        out += &wrap(&format!("{time}  {:<9} {}{}", cap(&e.kind), if e.repository.is_empty() { String::new() } else { format!("{} · ", e.repository) }, e.text), 2, 4);
    }
    out += &format!("\nRepositories{}\n", if h.repositories.is_empty() { String::new() } else { format!("  {}", h.repositories.len()) });
    if h.repositories.is_empty() {
        out += &match &h.user { None => "  No host file names the user layer: bon setup writes one\n".to_string(),
            Some(u) => wrap(&format!("No repository under {u} has a .bon/bon.toml: bon init makes one"), 2, 4) };
    }
    let wide = h.repositories.iter().map(|r| r.name.chars().count()).max().unwrap_or(0);
    // A repository's root where it is not the user layer's own.
    let under = |r: &str| h.user.as_deref().is_some_and(|u| Path::new(r).parent() == Some(Path::new(u)));
    for r in &h.repositories {
        let what = if !r.configured { "no .bon/bon.toml at trunk's head".to_string() } else {
            let mut parts = Vec::new();
            if r.pending > 0 { parts.push(format!("{} pending", r.pending)); }
            if r.running > 0 { parts.push(format!("{} running", r.running)); }
            parts.push(format!("{} today", money(r.today)));
            if let Some(t) = r.latest { parts.push(format!("last ran {}", ago(h.now, t))); }
            parts.join(" · ")
        };
        out += &wrap(&format!("{:<wide$}  {what}{}", r.name, if under(&r.root) { String::new() } else { format!(" · {}", r.root) }), 2, 4 + wide);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bon-host-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    #[test]
    fn the_repositories_are_those_under_the_user_layer_those_live_processes_search_and_those_routes_name() {
        let user = tmp("repos");
        for r in ["beta", "alpha", "plain"] { std::fs::create_dir_all(user.join(r)).unwrap(); }
        for r in ["beta", "alpha"] { std::fs::create_dir_all(user.join(r).join(".bon")).unwrap(); std::fs::write(user.join(r).join(".bon/bon.toml"), "").unwrap(); }
        let far = tmp("far");
        std::fs::create_dir_all(far.join("sandbox/.bon")).unwrap();
        std::fs::write(far.join("sandbox/.bon/bon.toml"), "").unwrap();
        let live = vec![json!({ "repository": far.join("sandbox").to_string_lossy(), "pid": 1 })];
        let routes = vec![("x".to_string(), user.join("alpha")), ("y".to_string(), user.join("missing"))];
        let names: Vec<String> = repositories(Some(&user), &live, &routes).iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();
        // A directory without .bon/bon.toml is no repository; each once; by name.
        assert_eq!(names, ["alpha", "beta", "sandbox"]);
        assert!(repositories(None, &[], &[]).is_empty());
        let _ = std::fs::remove_dir_all(&user);
        let _ = std::fs::remove_dir_all(&far);
    }

    /// A repository's projection with one pushed and one blocked bon process.
    fn projected(rate: f64, now: i64) -> Value {
        json!({ "configured": false, "totals": { "rate": rate }, "processes": [
            { "trace": "10", "kind": "code", "title": "from abc1234", "outcome": "pushed", "time": now - 600, "cost": 1.5,
              "push": { "commit": "deadbeefcafe", "time": now - 300 }, "searches": [{ "kind": "code", "time": now - 400, "started": now - 600, "cost": 1.5, "time_cost": 1.0, "end": "pushed" }] },
            { "trace": "11", "kind": "code", "title": "from abc1234", "outcome": "blocked", "time": now - 200, "cost": 0.5,
              "searches": [{ "kind": "code", "time": now - 100, "started": now - 200, "cost": 0.5, "time_cost": 0.25, "end": "blocked", "reason": "too_few_verified" }] },
            { "trace": "12", "kind": "code", "title": "from fff0000", "outcome": "running", "running": true, "time": now - 50, "cost": 0.1, "sentence": "code: 2 of 8 returned",
              "searches": [{ "kind": "code", "started": now - 50, "running": true, "width": 8, "returned": 2, "in_flight": 5, "in_checks": 1, "waiting": 0 }] },
        ] })
    }

    #[test]
    fn the_host_tells_what_runs_what_happened_and_what_waiting_costs_across_repositories() {
        let now = 1_800_000_000;
        let (a, b) = (PathBuf::from("/r/alpha"), PathBuf::from("/r/beta"));
        let states = vec![(a.clone(), projected(100.0, now)), (b.clone(), projected(200.0, now))];
        let live = vec![
            json!({ "pid": 4_000_001, "start": now - 60, "repository": "/r/alpha", "trace": "12", "background": false, "started": now - 50, "tree": "t1", "kind": "code", "search": 0 }),
            json!({ "pid": 4_000_002, "start": now - 55, "repository": "/r/beta", "trace": "12", "background": false, "started": now - 50, "tree": "t1", "kind": "code", "search": 0 }),
            json!({ "pid": 4_000_003, "start": now - 40, "repository": "/r/beta", "trace": null, "background": true, "started": null, "tree": null }),
            json!({ "pid": 4_000_004, "start": now - 30, "repository": "/elsewhere", "trace": "1", "background": false, "started": now - 20, "tree": "t9" }),
        ];
        let h: crate::projection::Host = serde_json::from_value(of(&states, None, None, &live, now)).unwrap();
        // Identical trees together; a process between searches alone; another repository's not shown.
        assert_eq!(h.trees.len(), 2);
        assert_eq!(h.trees[0].processes.iter().map(|p| p.repository.as_str()).collect::<Vec<_>>(), ["alpha", "beta"]);
        assert_eq!((h.trees[0].processes[0].in_flight, h.trees[0].processes[0].width), (5, Some(8)));
        assert_eq!(h.pools.agent_processes.shown, 10);
        // Waiting: two of the host's three waited-on searches are shown, at 100 and 200 an hour, split three ways.
        assert_eq!((h.waiting.searches, h.waiting.host), (2, 3));
        assert!((h.waiting.per_hour - 100.0).abs() < 1e-9, "{}", h.waiting.per_hour);
        // The journal, oldest first: each repository's push and block.
        let kinds: Vec<(String, String)> = h.journal.iter().map(|e| (e.repository.clone(), e.kind.clone())).collect();
        assert_eq!(kinds, [("alpha".into(), "pushed".into()), ("beta".into(), "pushed".into()), ("alpha".into(), "blocked".into()), ("beta".into(), "blocked".into())]);
        assert!(h.journal[0].text.contains("pushed deadbee") && h.journal[2].text.contains("too few verified"), "{:?}", h.journal[2].text);
        assert_eq!(h.repositories.iter().map(|r| r.running).collect::<Vec<_>>(), [1, 2]);
        // In one repository: only its own.
        let one: crate::projection::Host = serde_json::from_value(of(&states[..1], Some(&a), None, &live, now)).unwrap();
        assert_eq!((one.trees.len(), one.waiting.searches, one.journal.len()), (1, 1, 2));
        assert_eq!(one.here.as_deref(), Some("/r/alpha"));
    }
}
