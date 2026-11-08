//! bon view: one read-only page on localhost over what is already on disk: what
//! is running, what was pushed, the queue, the spec, and what it all cost. Trusted code;
//! it decides nothing and stores nothing. The interface is TypeScript in
//! view/src, compiled into view/dist and embedded here.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

use best_of_n::exec::Kernel;
use best_of_n::gates::{Encoding, Gates};
use serde_json::{json, Value};

const INDEX: &str = include_str!("../view/dist/index.html");
const APP: &str = include_str!("../view/dist/app.js");
const STYLE: &str = include_str!("../view/dist/app.css");
/// The verified gates, compiled to WebAssembly (`npm run gates` in view/ builds it).
const GATES: &[u8] = include_bytes!("../view/dist/gates.wasm");

pub fn serve(root: &str, port: u16, open: bool) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("port {port}: {e}"))?;
    let url = format!("http://localhost:{port}");
    println!("bon view: {url}");
    if open { let _ = Command::new("open").arg(&url).status(); }
    let root = PathBuf::from(root);
    for stream in listener.incoming().flatten() {
        let root = root.clone();
        std::thread::spawn(move || { let _ = respond(&root, stream); });
    }
    Ok(())
}

fn respond(root: &Path, mut stream: TcpStream) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    let target = line.split_whitespace().nth(1).unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (status, kind, body) = match path {
        "/gates.wasm" => ("200 OK", "application/wasm", GATES.to_vec()),
        "/api/words" => match words(root, query) {
            Some(b) => ("200 OK", "application/octet-stream", b),
            None => ("404 Not Found", "text/plain", b"no such search".to_vec()),
        },
        "/" => ("200 OK", "text/html; charset=utf-8", INDEX.as_bytes().to_vec()),
        "/app.js" => ("200 OK", "text/javascript; charset=utf-8", APP.as_bytes().to_vec()),
        "/app.css" => ("200 OK", "text/css; charset=utf-8", STYLE.as_bytes().to_vec()),
        "/api/state" => ("200 OK", "application/json", state(root, &Filter::query(query)).to_string().into_bytes()),
        "/api/items" => match items(root, query) {
            Some(v) => ("200 OK", "application/json", v.to_string().into_bytes()),
            None => ("400 Bad Request", "text/plain", b"base and commit are hashes".to_vec()),
        },
        "/source" => match source(root, query) {
            Some(html) => ("200 OK", "text/html; charset=utf-8", html.into_bytes()),
            None => ("404 Not Found", "text/plain", b"not a tracked file".to_vec()),
        },
        "/api/log" => match log(root, query) {
            Some(text) => ("200 OK", "text/plain; charset=utf-8", text.into_bytes()),
            None => ("404 Not Found", "text/plain", b"no such log".to_vec()),
        },
        _ => ("404 Not Found", "text/plain", b"not found".to_vec()),
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len())?;
    stream.write_all(&body)
}

fn git(root: &Path, args: &[&str]) -> String {
    super::git(root, args).unwrap_or_default()
}

fn jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// A search's words, as the trace records them (little-endian u64).
fn read_words(p: &Path) -> Option<Vec<u64>> {
    let b = std::fs::read(p).ok()?;
    if b.len() % 8 != 0 { return None; }
    Some(b.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
}

/// A search's words for the gates in WebAssembly, only from under .bon/traces:
/// path=<pid>/<search>.
fn words(root: &Path, query: &str) -> Option<Vec<u8>> {
    let rel = query.strip_prefix("path=")?.replace("%2F", "/");
    if rel.contains("..") { return None; }
    std::fs::read(root.join(".bon/traces").join(rel).join("search.words")).ok()
}

/// A trace log, only from under .bon/traces.
fn log(root: &Path, query: &str) -> Option<String> {
    let rel = query.strip_prefix("path=")?.replace("%2F", "/");
    if rel.contains("..") { return None; }
    let p = root.join(".bon/traces").join(rel);
    std::fs::read_to_string(p).ok()
}

/// Which bon processes the projection covers: those last active in
/// [since, until] (unix seconds), whose pid, kind, goal, outcome or any commit
/// contains `find`. Totals are over the same set.
#[derive(Default)]
pub struct Filter { pub since: Option<u64>, pub until: Option<u64>, pub find: Option<String> }

impl Filter {
    /// From a query string: since=<unix>&until=<unix>&find=<text>.
    pub fn query(q: &str) -> Filter {
        let mut f = Filter::default();
        for (k, v) in q.split('&').filter_map(|p| p.split_once('=')) {
            let v = decode(v);
            match k {
                "since" => f.since = v.parse().ok(),
                "until" => f.until = v.parse().ok(),
                "find" if !v.is_empty() => f.find = Some(v.to_lowercase()),
                _ => {}
            }
        }
        f
    }
    /// From arguments: --since YYYY-MM-DD, --until YYYY-MM-DD (UTC, whole days), --find TEXT.
    pub fn args(args: &[String]) -> Result<Filter, String> {
        let at = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
        let day = |s: String| -> Result<u64, String> {
            let p: Vec<i64> = s.split('-').map(|x| x.parse().map_err(|_| format!("{s}: not YYYY-MM-DD"))).collect::<Result<_, _>>()?;
            let [y, m, d] = p[..] else { return Err(format!("{s}: not YYYY-MM-DD")) };
            Ok((days_from_civil(y, m, d) * 86400) as u64)
        };
        Ok(Filter {
            since: at("--since").map(day).transpose()?,
            until: at("--until").map(day).transpose()?.map(|t| t + 86399),
            find: at("--find").map(|f| f.to_lowercase()),
        })
    }
    fn covers(&self, time: u64, text: &str) -> bool {
        self.since.is_none_or(|s| time >= s) && self.until.is_none_or(|u| time <= u)
            && self.find.as_ref().is_none_or(|f| text.to_lowercase().contains(f))
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Percent-decoding for a query value.
fn decode(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    Ok(x) => { out.push(x); i += 3; }
                    Err(_) => { out.push(b'%'); i += 1; }
                }
            }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Where a log falls in an agent process's run, so logs read left to right:
/// what it was given, what it did, then each check in the order bon runs them,
/// each numbered log by its number.
fn run_order(name: &str) -> (usize, u64, String) {
    const ORDER: [&str; 14] = ["argv", "prompt", "harness", "killed", "error", "build", "test", "carried", "verify", "agree", "rank", "accepts", "counterexample", "trunk"];
    let (stem, n) = match name.rsplit_once('-') {
        Some((s, n)) if n.chars().all(|c| c.is_ascii_digit()) => (s, n.parse().unwrap_or(0)),
        _ => (name, 0),
    };
    (ORDER.iter().position(|o| *o == stem).unwrap_or(ORDER.len()), n, name.to_string())
}

/// A unix time as its UTC date, YYYY-MM-DD.
fn date(t: u64) -> String {
    let z = (t / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{m:02}-{d:02}", yoe + era * 400 + if m <= 2 { 1 } else { 0 })
}

fn now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()) }

fn money(d: f64) -> String { format!("${d:.2}") }

/// A count of things, in words: "1 candidate", "3 candidates".
fn count(n: usize, one: &str, many: &str) -> String { format!("{n} {}", if n == 1 { one } else { many }) }

/// The projection: what bon is doing, what it pushed, what is queued, and what
/// it cost, assembled from disk on every request, in the spec's words. `bon`
/// prints it; bon view draws it. Trusted code: it reads and counts; the kernel
/// re-derives each selection from the trace's words.
pub fn state(root: &Path, filter: &Filter) -> Value {
    let toml_output = Command::new("git").args(["show", "HEAD:.bon/bon.toml"]).current_dir(root).output().ok()
        .filter(|o| o.status.success());
    let configured = toml_output.is_some();
    let toml_text = toml_output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let manifest: toml::Value = toml::from_str(&toml_text).unwrap_or(toml::Value::Table(Default::default()));
    let trunk_name = manifest.get("trunk").and_then(|v| v.as_str()).unwrap_or("main").to_string();
    let remote = manifest.get("remote").and_then(|v| v.as_str()).unwrap_or("origin").to_string();
    let limit = manifest.get("limit").and_then(|v| v.as_float().or(v.as_integer().map(|i| i as f64)));
    let head = git(root, &["rev-parse", "HEAD"]);
    let remote_head = git(root, &["rev-parse", &format!("{remote}/{trunk_name}")]);

    // The queue at trunk's head: id, intent.
    // None when trunk has no queue yet.
    let queue_text = Command::new("git").args(["show", "HEAD:.bon/queue.tsv"]).current_dir(root).output().ok()
        .filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).to_string());
    let queue: Option<Vec<Value>> = queue_text.map(|t| t.lines().skip(1).filter_map(|l| {
        let (id, intent) = l.split_once('\t')?;
        Some(json!({ "id": id.trim().parse::<u64>().ok()?, "intent": intent.trim() }))
    }).collect());

    // Every bon process's trace, newest first.
    let traces = root.join(".bon/traces");
    let mut pids: Vec<(u64, PathBuf)> = std::fs::read_dir(&traces).into_iter().flatten().flatten()
        .filter_map(|e| Some((e.file_name().to_string_lossy().parse::<u64>().ok()?, e.path()))).collect();
    pids.sort_by_key(|(_, p)| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    pids.reverse();
    let (mut verified_all, mut candidates_all, mut cost_all) = (0usize, 0usize, 0f64);
    let (mut generation_all, mut time_all) = (0f64, 0f64);
    let mut processes = Vec::new();
    let mut last_push: Option<Value> = None;
    let (mut earliest, mut latest) = (u64::MAX, 0u64);
    for (pid, dir) in pids.into_iter() {
        let running = Command::new("ps").args(["-p", &pid.to_string()]).stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success());
        let transitions: Vec<String> = std::fs::read_to_string(dir.join("transitions")).unwrap_or_default()
            .lines().map(String::from).collect();
        if !running && !transitions.iter().any(|t| t.starts_with("grant ")) { continue; }
        let summaries = jsonl(&dir.join("searches.jsonl"));
        let pushes = jsonl(&dir.join("pushes.jsonl"));
        // Repository-level comparison is independent of the process filter.
        for push in &pushes {
            if last_push.as_ref().is_none_or(|p| push["time"].as_u64() > p["time"].as_u64()) {
                last_push = Some(push.clone());
            }
        }
        // Each search starts at a grant.
        let mut segments: Vec<Vec<String>> = Vec::new();
        for t in &transitions { if t.starts_with("grant") { segments.push(Vec::new()); } if let Some(s) = segments.last_mut() { s.push(t.clone()); } }
        let mut runs: Vec<(usize, PathBuf)> = std::fs::read_dir(&dir).into_iter().flatten().flatten()
            .filter_map(|e| Some((e.file_name().to_string_lossy().parse::<usize>().ok()?, e.path()))).collect();
        runs.sort_by_key(|(n, _)| *n);
        let mut searches = Vec::new();
        for (n, rdir) in runs {
            let summary = summaries.iter().find(|s| s["search"] == n).cloned().unwrap_or(Value::Null);
            let segment = segments.get(n).cloned().unwrap_or_default();
            let grant: Vec<&str> = segment.first().map(|g| g.split_whitespace().collect()).unwrap_or_default();
            let width = summary["agent_processes"].as_u64().or_else(|| grant.get(1).and_then(|w| w.parse().ok()));
            let started = grant.get(2).and_then(|t| t.parse::<u64>().ok());
            // A search that has not reported yet is running while its bon process is.
            let live = running && summary.is_null();
            // Its time: to its report, else to its last returned agent process, else (running) to now.
            let last_wait = segment.iter().rev().find_map(|t| t.strip_prefix("wait ")?.split_whitespace().next()?.parse::<u64>().ok());
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            let seconds = summary["seconds"].as_f64()
                .or_else(|| started.map(|s| (if live { now } else { last_wait.unwrap_or(s) }).saturating_sub(s) as f64));
            let kernel = read_words(&rdir.join("search.words")).as_ref().and_then(|w| Kernel::decode(w));
            // A counterexample's test is verified without `proved` (spec: verified).
            let counterexample = summary["kind"].as_str().map_or_else(|| grant.iter().any(|w| *w == "counterexample"), |k| k == "counterexample");
            let mut candidates: Vec<(usize, Value)> = std::fs::read_dir(&rdir).into_iter().flatten().flatten().filter_map(|e| {
                let i = e.file_name().to_string_lossy().parse::<usize>().ok()?;
                let facts: Value = serde_json::from_str(&std::fs::read_to_string(e.path().join("facts.json")).ok()?).ok()?;
                let logs: Vec<String> = std::fs::read_dir(e.path()).into_iter().flatten().flatten()
                    .map(|f| f.file_name().to_string_lossy().to_string())
                    .filter(|f| !matches!(f.as_str(), "index" | "facts.json" | "candidate.bundle")).collect();
                let mut logs = logs;
                logs.sort_by_key(|f| run_order(f));
                let c = &facts["candidate"];
                let accepted = c["accepted"].as_bool().unwrap_or(false);
                let verified = match &kernel {
                    Some(k) => k.results.get(i).and_then(|r| r.as_ref()).is_some_and(|x| Kernel::verified(k, x)),
                    None => accepted && (counterexample || c["proved"].as_bool().unwrap_or(false)),
                };
                Some((i, json!({
                    "index": i, "harness": facts["harness"], "model": facts["model"],
                    "generation": facts["generation_microdollars"].as_f64().map(|m| m / 1e6),
                    "commit": c["commit"], "accepted": accepted, "verified": verified,
                    "rank": c["rank"], "diff": c["diff"], "changed": c["changed"],
                    "added": c["added"],
                    "removed": c["removed"],
                    "flags": (["killed", "over_limit", "price_mismatch"]).iter().filter(|k| facts[**k] == true).collect::<Vec<_>>(),
                    "logs": logs,
                })))
            }).collect();
            candidates.sort_by_key(|(i, _)| *i);
            let returned = candidates.len();
            let accepted = candidates.iter().filter(|(_, c)| c["accepted"] == true).count();
            let verified = candidates.iter().filter(|(_, c)| c["verified"] == true).count();
            // The kernel's selection where the trace has its words; otherwise the trace's.
            let recorded = transitions.iter().find_map(|t| {
                let rest = t.strip_prefix("selected ")?;
                let (s, i) = rest.split_once(' ')?;
                (s.parse::<usize>().ok()? == n).then(|| i.parse::<usize>().ok()).flatten()
            });
            let selected = match &kernel { Some(k) => Kernel::selected(k), None => recorded };
            // Cost = generation (what the models charged) + time (rate × wall time).
            // A search stopped before its summary has its agent processes' costs, and no time.
            let generation = summary["generation_dollars"].as_f64()
                .or_else(|| { let c: f64 = candidates.iter().filter_map(|(_, c)| c["generation"].as_f64()).sum(); (returned > 0).then_some(c) });
            let time_cost = summary["time_dollars"].as_f64();
            let cost = generation.map(|g| g + time_cost.unwrap_or(0.0));
            // Kind is shown separately; goal is the kind's goal.
            let base_of = candidates.iter().find_map(|(_, c)| c["commit"].as_str().map(|x| git(root, &["rev-parse", &format!("{x}^")])))
                .filter(|b| !b.is_empty()).unwrap_or_default();
            // A grant line: grant n time [agent_process_limit] kind goal…; traces before queue 12 lack the limit.
            let at = if grant.get(3).is_some_and(|w| w.parse::<u64>().is_ok()) { 4 } else { 3 };
            let kind = summary["kind"].as_str().or_else(|| grant.get(at).copied()).unwrap_or("").to_string();
            let blocked = segment.iter().find(|t| t.starts_with("blocked")).cloned();
            let granted_goal = grant.get(at + 1..).map(|g| g.join(" ")).unwrap_or_default();
            let goal_text = summary["goal"].as_str().unwrap_or(&granted_goal);
            let goal = match kind.as_str() {
                "queue" => json!({ "transcript": goal_text }),
                "counterexample" if goal_text == "trunk" => json!({ "trunk": base_of }),
                "counterexample" => json!({ "candidate": goal_text }),
                _ => json!({ "trunk": goal_text }),
            };
            let authority = match kind.as_str() {
                "queue" => "the queue",
                "counterexample" => "the counterexamples' tests",
                "compaction" => "everything but the checks and .bon/",
                _ => "everything but the checks, .bon/ and the counterexamples' tests",
            };
            searches.push(json!({
                "params": { "goal": goal, "base": base_of, "n": width, "limit": summary["limit"], "authority": authority },
                "generation": generation, "time_cost": time_cost, "rate": summary["rate"], "background": summary["background"] == true,
                "search": n, "kind": kind, "goal": goal_text, "width": width, "started": started,
                "returned": returned, "accepted": accepted, "verified": verified,
                "selected": selected, "recorded_selected": recorded,
                "kernel": if kernel.is_some() { "derived" } else if rdir.join("search.words").exists() { "unreadable" } else { "none" },
                "blocked": blocked, "cost": cost, "seconds": seconds, "time": summary["time"], "running": live,
                "candidates": candidates.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
            }));
        }
        // A bon process's kind is its first recorded non-counterexample kind,
        // or its first recorded kind when it only searched for counterexamples.
        let kind = searches.iter().find_map(|s| s["kind"].as_str().filter(|k| !k.is_empty() && *k != "counterexample"))
            .or_else(|| searches.iter().find_map(|s| s["kind"].as_str().filter(|k| !k.is_empty())))
            .unwrap_or("").to_string();
        let goal = searches.iter().filter(|s| s["kind"] == kind).find_map(|s| s["goal"].as_str().filter(|g| !g.is_empty()).map(String::from))
            .unwrap_or_default();
        // The trunk commit it started from.
        let base = searches.iter().flat_map(|s| s["candidates"].as_array().cloned().unwrap_or_default())
            .find_map(|c| c["commit"].as_str().map(|x| git(root, &["rev-parse", &format!("{x}^")])))
            .filter(|b| !b.is_empty()).unwrap_or_default();
        let last = transitions.last().cloned().unwrap_or_default();
        // The trace's transition, past tense where it names what happened to trunk;
        // a bon process that stopped short of one exited (OSTEP: exit).
        let outcome = if running { "running" } else if last.starts_with("push") { "pushed" } else {
            ["blocked", "found", "not found", "proposal"].into_iter().find(|w| last.starts_with(w)).unwrap_or("exited")
        };
        let cost: f64 = searches.iter().filter_map(|s| s["cost"].as_f64()).sum();
        let generation: f64 = searches.iter().filter_map(|s| s["generation"].as_f64()).sum();
        let time_cost: f64 = searches.iter().filter_map(|s| s["time_cost"].as_f64()).sum();
        let push = pushes.last().cloned();
        // Its first grant, or the trace's creation time while still starting.
        let time = searches.iter().filter_map(|s| s["started"].as_u64()).min().unwrap_or_else(|| {
            std::fs::metadata(&dir).and_then(|m| m.created().or(m.modified())).ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs())
        });
        earliest = earliest.min(time); latest = latest.max(time);
        // What `find` looks in: the pid, the command, its outcome, and every commit.
        let mut text = format!("{pid} {kind} {goal} {outcome} {}", push.as_ref().and_then(|p| p["commit"].as_str()).unwrap_or(""));
        for s in &searches { for c in s["candidates"].as_array().into_iter().flatten() { text.push(' '); text.push_str(c["commit"].as_str().unwrap_or("")); } }
        if !filter.covers(time, &text) { continue; }
        for s in &searches {
            verified_all += s["verified"].as_u64().unwrap_or(0) as usize;
            candidates_all += s["returned"].as_u64().unwrap_or(0) as usize;
            cost_all += s["cost"].as_f64().unwrap_or(0.0);
            generation_all += s["generation"].as_f64().unwrap_or(0.0);
            time_all += s["time_cost"].as_f64().unwrap_or(0.0);
        }
        let main = searches.iter().find(|s| s["kind"] != "counterexample").or(searches.first());
        let tally = |s: &Value| format!("{} of {} verified",
            s["verified"].as_u64().unwrap_or(0), count(s["returned"].as_u64().unwrap_or(0) as usize, "candidate", "candidates"));
        // One sentence in plain words, each spec word qualified.
        let sentence = match outcome {
            "running" => searches.last().map(|s| {
                let w = s["width"].as_u64().map_or(String::new(), |w| format!(" of {w}"));
                format!("{}: {}{w} agent processes returned, {} verified so far", s["kind"].as_str().unwrap_or("search"), s["returned"], s["verified"])
            }).unwrap_or_else(|| "starting".into()),
            "pushed" => format!("{}, they agreed, and no counterexample split them; the selected one was pushed",
                              main.map(tally).unwrap_or_default()),
            "blocked" => format!("{}; {}", main.map(tally).unwrap_or_default(),
                                 last.trim_start_matches("blocked:").trim()),
            "found" => "verified tests reject trunk: a code search carries the selected one".into(),
            "not found" => "fewer than two verified tests reject trunk".into(),
            "proposal" => "a proposal for the queue is ready to review".into(),
            _ => {
                let earlier = transitions.iter().filter(|t| t.starts_with("blocked")).last()
                    .map(|b| format!("{}; ", b.trim_start_matches("blocked:").trim())).unwrap_or_default();
                let at = searches.last().map(|s| format!("during search {}, after {} returned", s["search"],
                    count(s["returned"].as_u64().unwrap_or(0) as usize, "agent process", "agent processes"))).unwrap_or_default();
                format!("{earlier}the bon process exited {at}; nothing was pushed")
            }
        };
        // Titles name the kind's goal: a trunk commit or a transcript.
        let net = main.and_then(|m| {
            let i = m["selected"].as_u64()?;
            let c = m["candidates"].as_array()?.iter().find(|c| c["index"] == i)?;
            Some(c["added"].as_i64()? - c["removed"].as_i64()?)
        });
        // A short title; `about` holds the whole of what it stands for.
        let started = match kind.as_str() { "code" | "compaction" => goal.clone(), "counterexample" => base.clone(), _ => String::new() };
        let at = started[..7.min(started.len())].to_string();
        let lines = |n: i64| if n == 0 { "±0 lines".to_string() } else { format!("{n:+} lines") };
        let title = match kind.as_str() {
            "code" => format!("from {at}"),
            "compaction" => match net {
                Some(n) if outcome == "pushed" => format!("{} from {at}", lines(n)),
                _ => format!("from {at}"),
            },
            "counterexample" => format!("trunk at {at}"),
            _ => goal.clone(),
        };
        let about = json!({
            "goal": goal,
            "from": at, "subject": if started.is_empty() { String::new() } else { git(root, &["log", "-1", "--format=%s", &started]) },
        });
        processes.push(json!({
            "pid": pid, "running": running, "kind": kind, "goal": goal, "title": title, "about": about, "base": base, "outcome": outcome, "sentence": sentence,
            "cost": cost, "generation": generation, "time_cost": time_cost, "push": push, "limit": limit, "time": time,
            "transitions": transitions, "searches": searches,
        }));
    }

    // Consecutive bon processes of one kind, up to the one that finishes it
    // (pushed, found, not found, a proposal), are one effort: one row.
    let mut groups: Vec<Value> = Vec::new();
    for p in processes.iter().rev() {
        let joins = groups.last().is_some_and(|g: &Value| g["kind"] == p["kind"]
            && !matches!(g["outcome"].as_str(), Some("pushed" | "found" | "not found" | "proposal")));
        if joins {
            let g = groups.last_mut().unwrap();
            for k in ["cost", "generation", "time_cost"] { g[k] = json!(g[k].as_f64().unwrap_or(0.0) + p[k].as_f64().unwrap_or(0.0)); }
            for k in ["title", "about", "outcome", "sentence", "push", "time", "running"] { g[k] = p[k].clone(); }
            g["processes"].as_array_mut().unwrap().insert(0, p.clone());
        } else {
            groups.push(json!({ "kind": p["kind"], "title": p["title"], "about": p["about"], "outcome": p["outcome"], "sentence": p["sentence"],
                "cost": p["cost"], "generation": p["generation"], "time_cost": p["time_cost"],
                "push": p["push"], "time": p["time"], "running": p["running"], "processes": [p] }));
        }
    }
    groups.reverse();
    // A push's cost is everything run to reach it: every bon process in its
    // effort, the ones that exited or were blocked first included.
    let mut push_costs = Vec::new();
    for g in groups.iter_mut() {
        if g["outcome"] == "pushed" && g["push"].is_object() {
            let cost = g["cost"].as_f64().unwrap_or(0.0);
            // The counterexample search that found none on the selection; everything
            // before it is what reaching the selection cost.
            let last_ce = g["processes"][0]["searches"].as_array().and_then(|x| x.iter().rev().find(|x| x["kind"] == "counterexample").cloned());
            let ce = last_ce.as_ref().and_then(|x| x["cost"].as_f64()).unwrap_or(0.0);
            g["push"]["cost"] = json!(cost);
            g["push"]["to_selection"] = json!(cost - ce);
            g["push"]["counterexample"] = json!(ce);
            g["push"]["processes"] = json!(g["processes"].as_array().map_or(0, |p| p.len()));
            push_costs.push(cost);
        }
    }
    // Trunk's commits after the last push: what was committed to trunk without bon.
    let since_push = last_push.as_ref().and_then(|p| p["commit"].as_str()).map(|c| {
        let log = git(root, &["log", "--format=%an", &format!("{c}..{remote_head}")]);
        let authors: std::collections::BTreeSet<String> = log.lines().map(String::from).collect();
        json!({ "commits": log.lines().count(), "authors": authors.into_iter().collect::<Vec<_>>() })
    });

    json!({
        "configured": configured,
        "groups": groups,
        "repo": {
            "name": root.file_name().map(|n| n.to_string_lossy().to_string()),
            "head": head, "trunk": trunk_name, "remote": remote, "remote_head": remote_head,
            "subject": git(root, &["log", "-1", "--format=%s", &remote_head]),
            "remote_time": git(root, &["log", "-1", "--format=%ct", &remote_head]).parse::<u64>().ok(),
            "since_push": since_push, "last_push": last_push,
            "pushed": !head.is_empty() && head == remote_head, "now": now(),
        },
        "totals": {
            "cost": cost_all, "generation": generation_all, "time_cost": time_all,
            // What reached a push, and what did not (exited, blocked, still open).
            "pushed": push_costs.iter().sum::<f64>(),
            "not_pushed": groups.iter().filter(|g| g["outcome"] != "pushed" && g["running"] != true).filter_map(|g| g["cost"].as_f64()).sum::<f64>(),
            "in_flight": groups.iter().filter(|g| g["running"] == true).filter_map(|g| g["cost"].as_f64()).sum::<f64>(),
            "rate": manifest.get("rate").and_then(|v| v.as_float().or(v.as_integer().map(|i| i as f64))),
            "per_verified_candidate": (verified_all > 0).then(|| cost_all / verified_all as f64),
            "per_push": (!push_costs.is_empty()).then(|| push_costs.iter().sum::<f64>() / push_costs.len() as f64),
            "pushes": push_costs.len(),
            "verified": verified_all, "candidates": candidates_all,
        },
        "processes": processes,
        // The range shown, and the range there is, so a page can offer it.
        "filter": { "since": filter.since, "until": filter.until, "find": filter.find },
        "bounds": { "earliest": (earliest != u64::MAX).then_some(earliest), "latest": (latest > 0).then_some(latest) },
        "queue": queue,
        "sbom": sbom(root),
        "spec": spec(root, &manifest),
        "system": system(root, &format!("{remote}/{trunk_name}")),
    })
}

/// The SBOM: trunk's, or the working tree's until it is committed.
fn sbom(root: &Path) -> Value {
    let trunk = Command::new("git").args(["show", "HEAD:.bon/sbom.json"]).current_dir(root).output().ok()
        .filter(|o| o.status.success()).and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok());
    match trunk {
        Some(d) => json!({ "source": "trunk", "document": d }),
        None => match std::fs::read(root.join(".bon/sbom.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
            Some(d) => json!({ "source": "working tree", "document": d }),
            None => Value::Null,
        },
    }
}

/// The projection as text, for `bon`.
pub fn text(s: &Value) -> String {
    if s["configured"] != true { return "no .bon/bon.toml at trunk's head: run bon init\n".into(); }
    let mut out = String::new();
    let r = &s["repo"];
    let t = &s["totals"];
    let opt = |v: &Value| v.as_f64().map_or("—".to_string(), money);
    out.push_str(&format!("{} · trunk {} {} · {} cost · {} per verified candidate · {} per push\n\n",
        r["name"].as_str().unwrap_or(""), r["trunk"].as_str().unwrap_or(""), &r["head"].as_str().unwrap_or("")[..7.min(r["head"].as_str().unwrap_or("").len())],
        opt(&t["cost"]), opt(&t["per_verified_candidate"]), opt(&t["per_push"])));
    let f = &s["filter"];
    if !f["since"].is_null() || !f["until"].is_null() || !f["find"].is_null() {
        out.push_str(&format!("only bon processes{}{}{}\n\n",
            f["since"].as_u64().map_or(String::new(), |t| format!(" since {}", date(t))),
            f["until"].as_u64().map_or(String::new(), |t| format!(" until {}", date(t))),
            f["find"].as_str().map_or(String::new(), |t| format!(" matching \"{t}\""))));
    }
    let procs = s["processes"].as_array().cloned().unwrap_or_default();
    let running: Vec<&Value> = procs.iter().filter(|p| p["running"] == true).collect();
    out.push_str("now\n");
    if running.is_empty() { out.push_str("  no search is running\n"); }
    for p in &running { out.push_str(&format!("  {} {}: {}\n", p["kind"].as_str().unwrap_or(""), p["goal"].as_str().unwrap_or(""), p["sentence"].as_str().unwrap_or(""))); }
    out.push_str("\nrecent\n");
    for g in s["groups"].as_array().into_iter().flatten().filter(|g| g["running"] != true).take(8) {
        let n = g["processes"].as_array().map_or(0, |p| p.len());
        let cost = match g["push"]["cost"].as_f64() {
            Some(c) if n > 1 => format!("{} cost; {} for the push", money(g["cost"].as_f64().unwrap_or(0.0)), money(c)),
            Some(c) => format!("{} to push", money(c)),
            None => format!("{} cost", money(g["cost"].as_f64().unwrap_or(0.0))),
        };
        out.push_str(&format!("  {:<14} {:<9} {}\n      {}\n      {}{cost}\n",
            g["kind"].as_str().unwrap_or(""), g["outcome"].as_str().unwrap_or(""), g["title"].as_str().unwrap_or(""),
            g["sentence"].as_str().unwrap_or(""), if n > 1 { format!("{n} bon processes · ") } else { String::new() }));
    }
    if s["queue"].is_null() { out.push_str("\nqueue: none at trunk's head yet (.bon/queue.tsv)\n"); return out; }
    let q = s["queue"].as_array().cloned().unwrap_or_default();
    out.push_str(&format!("\nqueue ({} not yet in the spec)\n", q.len()));
    for i in &q { out.push_str(&format!("  {:>3}  {}\n", i["id"], i["intent"].as_str().unwrap_or(""))); }
    out
}

/// The spec module, read as it is written: types, predicates, transitions,
/// properties and invariants, each with its `///` lines; transitions with the
/// state they read and update; the state's fields.
fn spec(root: &Path, manifest: &toml::Value) -> Value {
    let paths: Vec<String> = manifest.get("checks").and_then(|c| c.get("paths")).and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    let file = paths.iter().filter(|p| p.ends_with(".rs"))
        .find(|p| git(root, &["show", &format!("HEAD:{p}")]).contains("state_machine!"));
    let Some(file) = file else { return Value::Null };
    let text = git(root, &["show", &format!("HEAD:{file}")]);
    let lines: Vec<&str> = text.lines().collect();
    let mut items = Vec::new();
    let mut fields = Vec::new();
    let mut doc: Vec<String> = Vec::new();
    let mut in_fields = false;
    let name_after = |l: &str, key: &str| -> Option<String> {
        let rest = l.split(key).nth(1)?;
        Some(rest.trim_start().split(|c: char| !(c.is_alphanumeric() || c == '_')).next()?.to_string())
    };
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        if let Some(d) = l.strip_prefix("///") { doc.push(d.trim().to_string()); i += 1; continue; }
        if l.starts_with("fields {") { in_fields = true; doc.clear(); i += 1; continue; }
        if in_fields {
            if l.starts_with('}') { in_fields = false; }
            else if let Some(rest) = l.split("pub ").nth(1) {
                if let Some((name, ty)) = rest.split_once(':') {
                    let sharding = l.split("sharding(").nth(1).and_then(|s| s.split(')').next()).unwrap_or("");
                    fields.push(json!({ "name": name.trim(), "type": ty.trim().trim_end_matches(','), "sharding": sharding, "doc": doc.join(" ") }));
                }
                doc.clear();
            }
            i += 1; continue;
        }
        let item = |kind: &str, name: String, doc: &[String]| json!({ "kind": kind, "name": name, "doc": doc.join(" ") });
        if l.starts_with("pub struct ") || l.starts_with("pub enum ") || l.starts_with("pub type ") {
            let key = if l.starts_with("pub struct ") { "struct" } else if l.starts_with("pub enum ") { "enum" } else { "type" };
            if let Some(n) = name_after(l, key) { items.push(item("type", n, &doc)); }
        } else if l.contains("spec fn ") && l.starts_with("pub") {
            if let Some(n) = name_after(l, "spec fn") { items.push(item("predicate", n, &doc)); }
        } else if l.starts_with("transition!{") || l.starts_with("init!{") || l.starts_with("property!{") {
            let kind = if l.starts_with("transition!") { "transition" } else if l.starts_with("init!") { "init" } else { "property" };
            let name = l.split('{').nth(1).unwrap_or("").trim().split('(').next().unwrap_or("").trim().to_string();
            // The body, to the matching close of the macro.
            let mut body = String::new();
            let mut depth = 0i32;
            let mut j = i;
            while j < lines.len() {
                for ch in lines[j].chars() { if ch == '{' { depth += 1 } else if ch == '}' { depth -= 1 } }
                body.push_str(lines[j]); body.push('\n');
                if depth <= 0 && j > i { break; }
                j += 1;
            }
            let mut updates = Vec::new();
            let mut reads = Vec::new();
            // Its guards: each `require ...;`, which may span lines.
            let mut requires: Vec<String> = Vec::new();
            for r in body.split("require ").skip(1) {
                let r = r.split(';').next().unwrap_or("");
                requires.push(r.split_whitespace().collect::<Vec<_>>().join(" "));
            }
            for b in body.lines() {
                let t = b.trim();
                for key in ["update ", "init ", "add ", "remove "] {
                    if let Some(f) = t.strip_prefix(key).and_then(|r| r.split_whitespace().next()) {
                        if !updates.contains(&f.to_string()) { updates.push(f.to_string()); }
                    }
                }
                for part in t.split("pre.").skip(1) {
                    let f: String = part.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !f.is_empty() && !reads.contains(&f) { reads.push(f); }
                }
            }
            let mut v = item(kind, name, &doc);
            v["updates"] = json!(updates);
            v["reads"] = json!(reads);
            v["requires"] = json!(requires);
            items.push(v);
            doc.clear();
            i = j + 1; continue;
        } else if l.starts_with("#[invariant]") {
            if let Some(n) = lines.get(i + 1).and_then(|n| name_after(n, "fn")) {
                // The fields it reads: each `self.field`, to the fn's close.
                let mut reads: Vec<String> = Vec::new();
                let mut depth = 0i32;
                let mut j = i + 1;
                while j < lines.len() {
                    for ch in lines[j].chars() { if ch == '{' { depth += 1 } else if ch == '}' { depth -= 1 } }
                    for part in lines[j].split("self.").skip(1) {
                        let f: String = part.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                        if !f.is_empty() && !reads.contains(&f) { reads.push(f); }
                    }
                    if depth <= 0 && j > i + 1 { break; }
                    j += 1;
                }
                let mut v = item("invariant", n, &doc);
                v["reads"] = json!(reads);
                items.push(v);
                doc.clear();
                i = j + 1; continue;
            }
            doc.clear();
            i += 2; continue;
        }
        if !l.starts_with("#[") { doc.clear(); }
        i += 1;
    }
    json!({ "path": file, "fields": fields, "items": items })
}

/// One `fn` as written: its name, its lines (1-based, inclusive), its first `///` line,
/// and its text from the signature to its close (or, for a contract with no body, to `;`).
struct Fn { name: String, start: usize, end: usize, doc: String, body: String, public: bool }

fn fns(text: &str) -> Vec<Fn> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut doc: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        if let Some(d) = l.strip_prefix("///") { doc.push(d.trim().to_string()); i += 1; continue; }
        let head = l.split("fn ").next().unwrap_or("");
        let is_fn = l.contains("fn ") && !l.starts_with("//") && !l.contains("|")
            && head.split_whitespace().all(|w| matches!(w, "pub" | "pub(crate)" | "open" | "closed" | "spec" | "proof" | "unsafe" | "extern" | "\"C\"" | "const"));
        if !is_fn { if !l.starts_with("#[") { doc.clear(); } i += 1; continue; }
        let name: String = l.split("fn ").nth(1).unwrap_or("").chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        // The body opens on the signature's line or on a line of its own; braces before it
        // (in requires and ensures, such as `Kind::Code { goal }`) are not the body's.
        let (mut depth, mut opened, mut j) = (0i32, false, i);
        let mut body = String::new();
        while j < lines.len() {
            let t = lines[j].trim();
            if !opened && ((j == i && t.contains(" {")) || t.starts_with('{')) { opened = true; }
            if opened { for ch in lines[j].chars() { if ch == '{' { depth += 1 } else if ch == '}' { depth -= 1 } } }
            body.push_str(lines[j]); body.push('\n');
            if (opened && depth <= 0) || (!opened && lines[j].trim_end().ends_with(';')) { break; }
            j += 1;
        }
        out.push(Fn { name, start: i + 1, end: j + 1, doc: doc.first().cloned().unwrap_or_default(), body, public: head.contains("pub") });
        doc.clear();
        i = j + 1;
    }
    out
}

/// `name(` appears in text after `prefix`, as a whole word.
fn calls(text: &str, prefix: &str, name: &str) -> bool {
    let pat = format!("{prefix}{name}(");
    // With no prefix, the name must start a word: not a method, a path, or a longer name.
    text.match_indices(&pat).any(|(at, _)| !prefix.is_empty()
        || !text[..at].chars().last().map_or(false, |c| c.is_alphanumeric() || c == '_' || c == '.' || c == ':'))
}

/// The lines of each file that differ from `base` (trunk on the remote), working tree included.
fn changed_lines(root: &Path, base: &str) -> std::collections::HashMap<String, Vec<(usize, usize)>> {
    changed_lines_for(root, base, &["src", "view/src"])
}

fn changed_lines_for(root: &Path, base: &str, paths: &[&str]) -> std::collections::HashMap<String, Vec<(usize, usize)>> {
    let mut args = vec!["diff", "-U0", base, "--"];
    args.extend_from_slice(paths);
    hunks(&git(root, &args))
}

/// Each file's changed lines in a `git diff -U0`, as lines of the new version.
fn hunks(diff: &str) -> std::collections::HashMap<String, Vec<(usize, usize)>> {
    let mut out: std::collections::HashMap<String, Vec<(usize, usize)>> = Default::default();
    let mut file = String::new();
    for l in diff.lines() {
        if let Some(f) = l.strip_prefix("+++ b/") { file = f.to_string(); }
        else if let Some(h) = l.strip_prefix("@@ ") {
            // @@ -a,b +c,d @@: lines c..c+d of the new file (d = 0: a deletion before c).
            let new = h.split_whitespace().nth(1).unwrap_or("+0").trim_start_matches('+');
            let (c, d) = new.split_once(',').map(|(c, d)| (c.parse().unwrap_or(0), d.parse().unwrap_or(1))).unwrap_or((new.parse().unwrap_or(0), 1));
            out.entry(file.clone()).or_default().push((c, c + d.max(1) - 1));
        }
    }
    out
}

/// What one candidate changed against its base: each file, and each item (by file and
/// name) whose lines in the candidate's version a hunk touches. A candidate's commit
/// stays in the repository after its search, so this reads git, not the trace.
fn items(root: &Path, query: &str) -> Option<Value> {
    let (mut base, mut commit) = (String::new(), String::new());
    for kv in query.split('&') {
        match kv.split_once('=') { Some(("base", v)) => base = v.to_string(), Some(("commit", v)) => commit = v.to_string(), _ => {} }
    }
    let hex = |c: &str| c.len() >= 7 && c.len() <= 64 && c.chars().all(|x| x.is_ascii_hexdigit());
    if !hex(&base) || !hex(&commit) { return None; }
    let changed = hunks(&git(root, &["diff", "-U0", &base, &commit]));
    let mut files: Vec<&String> = changed.keys().collect();
    files.sort();
    let mut out = Vec::new();
    for f in &files {
        let text = git(root, &["show", &format!("{commit}:{f}")]);
        for item in fns(&text) {
            if changed[*f].iter().any(|&(a, b)| a <= item.end && b >= item.start) { out.push(json!([f, item.name])); }
        }
    }
    Some(json!({ "files": files, "items": out }))
}

/// The system as the source composes it, each layer named from the next by its own
/// syntax. The kernel: the spec's state machine and predicates (src/spec.rs); the
/// gates, whose `ensures` name the spec's predicates (src/gates.rs); and their
/// implementation (src/exec.rs, src/encoding.rs). Then the bon process, whose
/// functions hold the tokens and call the transitions (src/process.rs); the entry
/// points (src/main.rs, src/view.rs, src/wasm.rs); the programs (view/src); and the
/// trusted code the bon process calls (src/trusted.rs). Read from the working tree;
/// each item is marked where its lines differ from trunk.
fn system(root: &Path, base: &str) -> Value {
    let read = |f: &str| std::fs::read_to_string(root.join(f)).unwrap_or_default();
    let (spec_t, gates_t, exec_t, enc_t, proc_t, wasm_t, main_t, view_t, page_t, trusted_t) =
        (read("src/spec.rs"), read("src/gates.rs"), read("src/exec.rs"), read("src/encoding.rs"), read("src/process.rs"),
         read("src/wasm.rs"), read("src/main.rs"), read("src/view.rs"), read("view/src/main.ts"), read("src/trusted.rs"));
    if !spec_t.contains("state_machine!") { return Value::Null; }
    let changed = changed_lines(root, base);
    let hit = |file: &str, a: usize, b: usize| changed.get(file).map_or(false, |hs| hs.iter().any(|&(c, d)| c <= b && d >= a));
    let mut nodes: Vec<Value> = Vec::new();
    let mut edges: Vec<Value> = Vec::new();
    let node = |id: String, layer: &str, group: &str, name: &str, file: &str, f: Option<&Fn>, extra: Value| {
        let mut v = json!({ "id": id, "layer": layer, "group": group, "name": name, "file": file,
            "line": f.map(|f| f.start), "end": f.map(|f| f.end), "doc": f.map(|f| f.doc.clone()).unwrap_or_default(),
            "changed": f.map_or(false, |f| hit(file, f.start, f.end)) });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) { for (k, x) in e { o.insert(k.clone(), x.clone()); } }
        v
    };

    // ── spec: transitions (guards inline), then the predicates the gates cite, then the rules.
    let spec_lines: Vec<&str> = spec_t.lines().collect();
    let spec_fns = fns(&spec_t);
    let preds: Vec<&Fn> = spec_fns.iter().filter(|f| f.body.contains("spec fn")).collect();
    let mut transitions = Vec::new();
    for (i, l) in spec_lines.iter().enumerate() {
        let t = l.trim();
        if !(t.starts_with("transition!{") || t.starts_with("init!{")) { continue; }
        let name = t.split('{').nth(1).unwrap_or("").trim().split('(').next().unwrap_or("").trim().to_string();
        let (mut depth, mut j, mut body) = (0i32, i, String::new());
        while j < spec_lines.len() {
            for ch in spec_lines[j].chars() { if ch == '{' { depth += 1 } else if ch == '}' { depth -= 1 } }
            body.push_str(spec_lines[j]); body.push('\n');
            if depth <= 0 && j > i { break; }
            j += 1;
        }
        let mut doc = String::new();
        let mut k = i;
        while k > 0 && spec_lines[k - 1].trim().starts_with("///") { k -= 1; }
        if k < i { doc = spec_lines[k].trim().trim_start_matches("///").trim().to_string(); }
        let guards: Vec<String> = preds.iter().filter(|p| body.split("require").skip(1).any(|r| calls(r.split(';').next().unwrap_or(""), "", &p.name))).map(|p| p.name.clone()).collect();
        let token = |op: &str| body.lines().filter_map(|b| b.trim().strip_prefix(op).and_then(|r| r.split_whitespace().next()).map(String::from)).collect::<Vec<_>>();
        let f = Fn { name: name.clone(), start: i + 1, end: j + 1, doc, body: String::new(), public: true };
        transitions.push(node(format!("spec:{name}"), "spec", if t.starts_with("init") { "init" } else { "transition" }, &name, "src/spec.rs", Some(&f),
            json!({ "guards": guards, "adds": token("add "), "removes": token("remove ") })));
    }
    let mut rules: Vec<Value> = spec_lines.iter().enumerate().filter(|(_, l)| l.trim().starts_with("property!{"))
        .filter_map(|(i, l)| {
            let name = l.trim().trim_start_matches("property!{").trim().split('(').next()?.trim().to_string();
            let f = spec_fns.iter().find(|f| f.name == name).map(|f| Fn { name: f.name.clone(), start: i + 1, end: f.end, doc: f.doc.clone(), body: String::new(), public: true })
                .unwrap_or(Fn { name: name.clone(), start: i + 1, end: i + 1, doc: String::new(), body: String::new(), public: true });
            Some(node(format!("spec:{name}"), "spec", "property", &name, "src/spec.rs", Some(&f), json!({})))
        }).collect();
    let invariants: Vec<Value> = spec_lines.iter().enumerate().filter(|(_, l)| l.trim() == "#[invariant]")
        .filter_map(|(i, _)| spec_fns.iter().find(|f| f.start == i + 2))
        .map(|f| node(format!("spec:{}", f.name), "spec", "invariant", &f.name, "src/spec.rs", Some(f), json!({}))).collect();
    rules.extend(invariants);

    // ── gates: the trait methods, their contracts citing spec::.
    let gfns = fns(&gates_t);
    let trait_at = |name: &str| gates_t.lines().position(|l| l.trim_start().starts_with(&format!("pub trait {name}"))).map(|p| p + 1).unwrap_or(usize::MAX);
    let (gates_at, enc_at) = (trait_at("Gates"), trait_at("Encoding"));
    let mut gate_names = Vec::new();
    let mut cited: Vec<String> = Vec::new();
    let glines: Vec<&str> = gates_t.lines().collect();
    // A gate is a method of one of the two traits: indented, after its `pub trait`.
    for f in gfns.iter().filter(|f| f.start > enc_at.min(gates_at) && glines[f.start - 1].starts_with(' ')) {
        // Its trait: the nearest `pub trait` above it.
        // Its block: the nearest unindented `pub trait` or `impl` above it; a method of an impl is not a gate.
        let block = glines[..f.start - 1].iter().rev().find(|l| l.starts_with("pub trait ") || l.starts_with("impl")).copied().unwrap_or("");
        let Some(group) = block.strip_prefix("pub trait ").map(|r| r.split(|c: char| !c.is_alphanumeric()).next().unwrap_or("").to_string()) else { continue };
        let group = group.as_str();
        nodes.push(node(format!("gate:{}", f.name), "gates", group, &f.name, "src/gates.rs", Some(f), json!({ "proof": f.body.contains("proof fn") })));
        for p in &preds { if calls(&f.body, "spec::", &p.name) { edges.push(json!([format!("gate:{}", f.name), format!("spec:{}", p.name), "ensures"])); if !cited.contains(&p.name) { cited.push(p.name.clone()); } } }
        gate_names.push(f.name.clone());
    }

    // ── the types the kernel emits for programs (examples/types.rs → view/src/kernel.ts),
    //    each where gates.rs declares it.
    let emitted = read("view/src/kernel.ts");
    let mut type_names = Vec::new();
    for l in emitted.lines() {
        let Some(rest) = l.strip_prefix("export type ").or_else(|| l.strip_prefix("export interface ")) else { continue };
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        let Some(at) = glines.iter().position(|g| ["pub struct ", "pub enum ", "pub type "].iter().any(|k| g.trim_start().strip_prefix(k).map_or(false, |r| r.starts_with(&name) && !r[name.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')))) else { continue };
        let mut end = at;
        if !glines[at].trim_end().ends_with(';') { while end + 1 < glines.len() && !glines[end].starts_with('}') && !(end > at && glines[end].trim_end().ends_with('}') && !glines[end].starts_with(' ')) { end += 1; } }
        let mut k = at;
        while k > 0 && glines[k - 1].trim().starts_with("///") { k -= 1; }
        let doc = if k < at { glines[k].trim().trim_start_matches("///").trim().to_string() } else { String::new() };
        let f = Fn { name: name.clone(), start: at + 1, end: end + 1, doc, body: String::new(), public: true };
        nodes.push(node(format!("type:{name}"), "gates", "types", &name, "src/gates.rs", Some(&f), json!({})));
        type_names.push(name);
    }

    // ── implementation: each gate's, and the public functions the bon process calls.
    let efns = fns(&exec_t);
    let private: Vec<&Fn> = efns.iter().filter(|f| !f.public).collect();
    let impl_at = exec_t.lines().position(|l| l.starts_with("impl Gates for Kernel")).map(|p| p + 1).unwrap_or(usize::MAX);
    let mut kernel_names = Vec::new();
    for f in efns.iter().filter(|f| f.public && f.start < impl_at) {
        let uses: Vec<String> = private.iter().filter(|h| h.name != f.name && calls(&f.body, "", &h.name)).map(|h| h.name.clone()).collect();
        let group = if gate_names.contains(&f.name) { "gate" } else { "process" };
        nodes.push(node(format!("kernel:{}", f.name), "implementation", group, &f.name, "src/exec.rs", Some(f), json!({ "uses": uses })));
        if gate_names.contains(&f.name) { edges.push(json!([format!("kernel:{}", f.name), format!("gate:{}", f.name), "implements"])); }
        kernel_names.push(f.name.clone());
    }
    let enc_impl = enc_t.lines().position(|l| l.starts_with("impl Encoding for Kernel")).map(|p| p + 1).unwrap_or(usize::MAX);
    for f in fns(&enc_t).iter().filter(|f| f.start > enc_impl && gate_names.contains(&f.name)) {
        nodes.push(node(format!("kernel:{}", f.name), "implementation", "encoding", &f.name, "src/encoding.rs", Some(f), json!({ "uses": [] })));
        edges.push(json!([format!("kernel:{}", f.name), format!("gate:{}", f.name), "implements"]));
        kernel_names.push(f.name.clone());
    }

    // ── the bon process (tokens, gates, trusted code); the wasm32 target; entry points; programs.
    let trusted_fns = fns(&trusted_t);
    let mut trusted_used: Vec<String> = Vec::new();
    let pfns = fns(&proc_t);
    for f in &pfns {
        let fires: Vec<&Value> = transitions.iter().filter(|t| { let n = t["name"].as_str().unwrap_or(""); f.body.contains(&format!("instance.{n}(")) || f.body.contains(&format!("Instance::{n}(")) }).collect();
        let gates_called: Vec<&String> = kernel_names.iter().filter(|g| calls(&f.body, "", g)).collect();
        if fires.is_empty() && gates_called.is_empty() { continue; }
        let trusted: Vec<String> = trusted_fns.iter().filter(|t| calls(&f.body, "trusted::", &t.name)).map(|t| t.name.clone()).collect();
        for t in &trusted { if !trusted_used.contains(t) { trusted_used.push(t.clone()); } }
        let id = format!("driver:{}", f.name);
        nodes.push(node(id.clone(), "process", "function", &f.name, "src/process.rs", Some(f), json!({ "trusted": trusted })));
        for t in fires { edges.push(json!([id, t["id"], "transition"])); }
        for g in gates_called { edges.push(json!([id, format!("kernel:{g}"), "calls"])); }
        for d in pfns.iter().filter(|d| d.name != f.name && calls(&f.body, "", &d.name)) { edges.push(json!([id, format!("driver:{}", d.name), "calls"])); }
    }
    let wfns = fns(&wasm_t);
    let mut exported = Vec::new();
    for f in wfns.iter().filter(|f| f.body.contains("extern \"C\"")) {
        let id = format!("wasm:{}", f.name);
        let called: Vec<&String> = gate_names.iter().filter(|g| calls(&f.body, "Kernel::", g)).collect();
        if called.is_empty() { continue; }
        nodes.push(node(id.clone(), "target", "wasm32", &f.name, "src/wasm.rs", Some(f), json!({})));
        for g in called { if kernel_names.contains(g) { edges.push(json!([id, format!("kernel:{g}"), "calls"])); } }
        exported.push(f.name.clone());
    }
    let whole = |text: &str| Fn { name: String::new(), start: 1, end: text.lines().count().max(1), doc: text.lines().next().unwrap_or("").trim_start_matches("//!").trim().to_string(), body: text.to_string(), public: true };
    nodes.push(node("entry:cli".into(), "entry", "main", "bon", "src/main.rs", Some(&whole(&main_t)), json!({})));
    for f in pfns.iter().filter(|f| f.public && calls(&main_t, "process::", &f.name)) { edges.push(json!(["entry:cli", format!("driver:{}", f.name), "calls"])); }
    nodes.push(node("entry:view".into(), "entry", "view", "bon view", "src/view.rs", Some(&whole(&view_t)), json!({})));
    for g in gate_names.iter().filter(|g| calls(&view_t, "Kernel::", g)) { edges.push(json!(["entry:view", format!("kernel:{g}"), "calls"])); }
    nodes.push(node("program:page".into(), "program", "typescript", "the page", "view/src/main.ts", Some(&whole(&page_t)), json!({})));
    for l in page_t.lines().filter(|l| l.starts_with("import") && l.contains("from './kernel'")) {
        let names = l.split('{').nth(1).and_then(|r| r.split('}').next()).unwrap_or("");
        for n in names.split(',').map(|n| n.trim().split_whitespace().next().unwrap_or("")) {
            if type_names.iter().any(|t| t == n) { edges.push(json!(["program:page", format!("type:{n}"), "types"])); }
        }
    }
    for w in exported.iter().filter(|w| page_t.contains(&format!("call('{w}'"))) { edges.push(json!(["program:page", format!("wasm:{w}"), "calls"])); }

    // Spec nodes: the transitions, the predicates the gates cite, the rules.
    let mut spec_nodes = transitions;
    for p in preds.iter().filter(|p| cited.contains(&p.name)) { spec_nodes.push(node(format!("spec:{}", p.name), "spec", "predicate", &p.name, "src/spec.rs", Some(p), json!({}))); }
    spec_nodes.extend(rules);
    spec_nodes.extend(nodes);
    let trusted: Vec<Value> = trusted_fns.iter().filter(|t| trusted_used.contains(&t.name))
        .map(|t| json!({ "name": t.name, "line": t.start, "doc": t.doc, "changed": hit("src/trusted.rs", t.start, t.end) })).collect();
    json!({ "nodes": spec_nodes, "edges": edges, "trusted": trusted,
        "counts": { "predicates": preds.len(), "private": private.len(), "trusted": trusted_fns.len() } })
}

/// A tracked file as text, its lines numbered, `from`..`to` marked, and each line that
/// differs from trunk on the remote marked: where an item of the System view points.
/// Read from the working tree, like the view; only files git tracks.
fn source(root: &Path, query: &str) -> Option<String> {
    let mut path = String::new();
    let (mut from, mut to) = (0usize, 0usize);
    for kv in query.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = v.replace("%2F", "/").replace("%2f", "/");
        match k { "path" => path = v, "from" => from = v.parse().unwrap_or(0), "to" => to = v.parse().unwrap_or(0), _ => {} }
    }
    if path.is_empty() || !git(root, &["ls-files", "--error-unmatch", "--", &path]).lines().any(|l| l == path) { return None; }
    let text = std::fs::read_to_string(root.join(&path)).ok()?;
    let manifest = std::fs::read_to_string(root.join(".bon/bon.toml")).ok().and_then(|t| t.parse::<toml::Value>().ok());
    let remote = manifest.as_ref().and_then(|m| m.get("remote")).and_then(|v| v.as_str()).unwrap_or("origin").to_string();
    let trunk = manifest.as_ref().and_then(|m| m.get("trunk")).and_then(|v| v.as_str()).unwrap_or("main").to_string();
    let changed = changed_lines_of(root, &format!("{remote}/{trunk}"), &path);
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let to = to.max(from);
    let rows: String = text.lines().enumerate().map(|(i, l)| {
        let n = i + 1;
        let mut class = String::new();
        if from > 0 && n >= from && n <= to { class.push_str(" on"); }
        if changed.iter().any(|&(a, b)| n >= a && n <= b) { class.push_str(" diff"); }
        format!("<tr id=\"L{n}\" class=\"{}\"><td class=\"n\"><a href=\"#L{n}\">{n}</a></td><td class=\"c\">{}</td></tr>", class.trim(), esc(l))
    }).collect();
    let files = ["src/spec.rs", "src/gates.rs", "src/exec.rs", "src/encoding.rs", "src/process.rs", "src/trusted.rs", "src/main.rs", "src/view.rs", "src/wasm.rs", "view/src/main.ts", "view/src/kernel.ts", "examples/types.rs"];
    let nav: String = files.iter().map(|f| format!("<a class=\"{}\" href=\"/source?path={f}\">{f}</a>", if *f == path { "here" } else { "" })).collect();
    Some(format!(r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{p} · bon view</title><style>
:root{{color-scheme:light dark;--bg:#F3EDE0;--surface:#FAF6EE;--ink:#1B1A18;--muted:#8F887C;--line:#DDD3C1;--on:rgba(51,37,138,.12);--onbar:#33258A;--diff:#93680A}}
@media(prefers-color-scheme:dark){{:root{{--bg:#09090A;--surface:#111113;--ink:#EDEAE5;--muted:#6E6A64;--line:#24242A;--on:rgba(69,52,176,.28);--onbar:#6F5CE0;--diff:#D4A017}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:13px/1.55 "SFMono-Regular",Consolas,monospace}}
header{{position:sticky;top:0;z-index:1;display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;padding:10px 16px;background:var(--surface);border-bottom:1px solid var(--line);font-family:-apple-system,BlinkMacSystemFont,sans-serif}}
header b{{font-size:15px;margin-right:8px}}header a{{color:var(--muted);text-decoration:none;font-size:12px}}header a.here{{color:var(--ink);font-weight:600}}header a:hover{{color:var(--ink)}}
header .key{{margin-left:auto;color:var(--muted);font-size:12px}}header .key i{{display:inline-block;width:10px;height:10px;margin:0 4px 0 10px;vertical-align:-1px}}
table{{border-collapse:collapse;width:100%}}td{{padding:0 12px;vertical-align:top}}
td.n{{width:1%;text-align:right;color:var(--muted);user-select:none;border-left:3px solid transparent}}td.n a{{color:inherit;text-decoration:none}}
td.c{{white-space:pre-wrap;overflow-wrap:anywhere}}
tr.on td{{background:var(--on)}}tr.on td.n{{border-left-color:var(--onbar);color:var(--ink)}}
tr.diff td.n{{border-left-color:var(--diff)}}tr:target td{{background:var(--on)}}
</style></head><body><header><b>{p}</b>{nav}<span class="key"><i style="background:var(--onbar)"></i>the item<i style="background:var(--diff)"></i>differs from trunk</span></header><table>{rows}</table>
<script>const t=document.getElementById('L{start}');if(t&&{start}>0)t.scrollIntoView({{block:'center'}});</script></body></html>"#,
        p = esc(&path), nav = nav, rows = rows, start = from))
}

/// The lines of one file that differ from `base`, working tree included.
fn changed_lines_of(root: &Path, base: &str, path: &str) -> Vec<(usize, usize)> {
    changed_lines_for(root, base, &[path]).remove(path).unwrap_or_default()
}
