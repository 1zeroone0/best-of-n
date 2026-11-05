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
            let kernel = read_words(&rdir.join("search.words")).as_ref().and_then(|w| Kernel::decode(w));
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
                    None => accepted && c["proved"].as_bool().unwrap_or(false),
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
            let kind = summary["kind"].as_str().unwrap_or("").to_string();
            let blocked = segment.iter().find(|t| t.starts_with("blocked")).cloned();
            let goal_text = summary["goal"].as_str().unwrap_or("");
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
                "search": n, "kind": kind, "goal": summary["goal"], "width": width, "started": started,
                "returned": returned, "accepted": accepted, "verified": verified,
                "selected": selected, "recorded_selected": recorded,
                "kernel": if kernel.is_some() { "derived" } else if rdir.join("search.words").exists() { "unreadable" } else { "none" },
                "blocked": blocked, "cost": cost, "seconds": summary["seconds"], "time": summary["time"],
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
            items.push(v);
            doc.clear();
            i = j + 1; continue;
        } else if l.starts_with("#[invariant]") {
            if let Some(n) = lines.get(i + 1).and_then(|n| name_after(n, "fn")) { items.push(item("invariant", n, &doc)); }
            doc.clear();
            i += 2; continue;
        }
        if !l.starts_with("#[") { doc.clear(); }
        i += 1;
    }
    json!({ "path": file, "fields": fields, "items": items })
}
