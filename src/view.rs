//! The projection over what is already on disk: what is running, what was
//! pushed, the queue, the spec, and what it all cost, as `bon` and the terminal
//! view show it. Trusted code; it decides nothing and stores nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use best_of_n::exec::Kernel;
use best_of_n::gates::{Encoding, Gates};
use serde_json::{json, Value};

fn git(root: &Path, args: &[&str]) -> String {
    super::git(root, args).unwrap_or_default()
}

/// Each queue proposal bon queue left for engineer: its new intents with the cue
/// each came from, and its contested cues, from the patch's lines and trailers.
fn proposals(root: &Path) -> Vec<Value> {
    let dir = root.join(".bon/traces/proposals");
    let mut out: Vec<Value> = std::fs::read_dir(&dir).into_iter().flatten().flatten().filter_map(|e| {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "patch") { return None; }
        let text = std::fs::read_to_string(&path).ok()?;
        let cue_of = |id: &str| text.lines().find_map(|l| l.strip_prefix("Cue: ").and_then(|r| r.split_once(' ')).filter(|(i, _)| *i == id).map(|(_, c)| c.to_string()));
        let intents: Vec<Value> = text.lines().filter(|l| l.starts_with('+') && !l.starts_with("+++")).filter_map(|l| {
            let (id, intent) = l[1..].split_once('\t')?;
            id.parse::<u64>().ok()?;
            Some(json!({ "id": id.parse::<u64>().ok(), "intent": intent, "cue": cue_of(id) }))
        }).collect();
        let contested: Vec<String> = text.lines().filter_map(|l| l.strip_prefix("Contested: ").map(String::from)).collect();
        let source = text.lines().find_map(|l| l.strip_prefix("Source: ")).unwrap_or("").to_string();
        Some(json!({ "name": path.file_stem()?.to_string_lossy(), "path": format!(".bon/traces/proposals/{}", path.file_name()?.to_string_lossy()),
            "source": source, "intents": intents, "contested": contested }))
    }).collect();
    out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    out
}

/// Each intent no longer on the queue, with the commit on trunk's history that
/// took it off (its latest removal; a removal that adds the same id back is a
/// rewording, not a retirement), newest first, from `git log -p` of the queue.
fn retired(root: &Path, queued: &[u64]) -> Vec<Value> {
    retired_in(&git(root, &["log", "HEAD", "-p", "--format=%x00%H %ct %s", "--", ".bon/queue.tsv"]), queued)
}

fn retired_in(log: &str, queued: &[u64]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for commit in log.split('\0').filter(|c| !c.trim().is_empty()) {
        let mut lines = commit.lines();
        let head = lines.next().unwrap_or("");
        let mut words = head.splitn(3, ' ');
        let (hash, time, subject) = (words.next().unwrap_or(""), words.next().and_then(|t| t.parse::<u64>().ok()), words.next().unwrap_or(""));
        let body: Vec<&str> = lines.collect();
        let line_id = |l: &str| l.split_once('\t').and_then(|(id, _)| id.trim().parse::<u64>().ok());
        let added: Vec<u64> = body.iter().filter(|l| l.starts_with('+') && !l.starts_with("+++")).filter_map(|l| line_id(&l[1..])).collect();
        for l in body.iter().filter(|l| l.starts_with('-') && !l.starts_with("---")) {
            let Some(id) = line_id(&l[1..]) else { continue };
            if added.contains(&id) || queued.contains(&id) || out.iter().any(|r| r["id"] == id) { continue; }
            let intent = l[1..].split_once('\t').map_or("", |(_, i)| i.trim());
            out.push(json!({ "id": id, "intent": intent, "commit": hash, "subject": subject, "time": time }));
        }
    }
    out
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

/// Which bon processes the projection covers: those last active in
/// [since, until] (unix seconds), whose pid, kind, goal, outcome or any commit
/// contains `find`. Totals are over the same set.
#[derive(Default, Clone)]
pub struct Filter { pub since: Option<u64>, pub until: Option<u64>, pub find: Option<String> }

impl Filter {
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

// ── trace keys that older traces spell otherwise ────────
//
// Each reads the newer word first and the older one where the newer is absent,
// by key presence, so one function changes when a key's final name does.

/// The program an agent process ran: `program` in newer traces, `harness` in older ones.
fn program_of(facts: &Value) -> Value {
    if facts.get("program").is_some() { facts["program"].clone() } else { facts["harness"].clone() }
}

/// A candidate's lines added and removed: `lines_added` and `lines_removed` in
/// newer traces (whose `added` is the paths the diff added); `added` and
/// `removed` as numbers in older ones.
fn line_counts(c: &Value) -> (Option<u64>, Option<u64>) {
    let added = if c.get("lines_added").is_some() { c["lines_added"].as_u64() } else { c["added"].as_u64() };
    let removed = if c.get("lines_removed").is_some() { c["lines_removed"].as_u64() } else { c["removed"].as_u64() };
    (added, removed)
}

/// An agent process in the one shape (`projection::Record`): the five keys of
/// its facts.json in newer traces; in older ones, what they recorded of each:
/// its program (`program_of`), the prompt it was given (when its trace has
/// one), its candidate's commit, what its checks said (from `accepted` and
/// `proved`), its agree outputs' hashes (`out`).
fn record_of(facts: &Value, logs: &[String]) -> Value {
    let c = &facts["candidate"];
    let or = |k: &str, old: Value| if facts.get(k).is_some() { facts[k].clone() } else { old };
    let verdict = if c.is_object() { json!(if c["accepted"] != true { "rejected" } else if c["proved"] == true { "proved" } else { "accepted" }) } else { Value::Null };
    let behavior = c["out"].as_array().filter(|o| !o.is_empty()).map(|o| json!(o.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(","))).unwrap_or(Value::Null);
    json!({
        "program": program_of(facts),
        "context": or("context", if logs.iter().any(|l| l == "prompt") { json!("prompt") } else { Value::Null }),
        "output": or("output", c["commit"].clone()),
        "verdict": or("verdict", verdict),
        "behavior": or("behavior", behavior),
    })
}

/// The log of an agent process's program, by its name: `program` in newer
/// traces, `harness` in older ones.
const PROGRAM_LOGS: [&str; 2] = ["program", "harness"];

/// The error a bon process ended on, from its transitions' line `exited: <error>`.
fn exit_error(line: &str) -> Option<&str> { line.strip_prefix("exited: ").map(str::trim) }

/// The sizes of the host's two semaphores a search ran under, where its line
/// in searches.jsonl records them: `host.agent_processes` and `host.check_processes`.
/// Traces from before queue 59 record none.
fn pool_sizes(summary: &Value) -> (Option<u64>, Option<u64>) {
    (summary["host"]["agent_processes"].as_u64(), summary["host"]["check_processes"].as_u64())
}

/// The manifest's table of emitted types: `[types]`, or `[programs]` in older manifests.
fn types_table(manifest: &toml::Value) -> Option<&toml::Value> { manifest.get("types").or_else(|| manifest.get("programs")) }

/// Where a log falls in an agent process's run, so logs read left to right:
/// what it was given, what it did, then each check in the order bon runs them,
/// each numbered log by its number.
fn run_order(name: &str) -> (usize, u64, String) {
    const ORDER: [&str; 15] = ["argv", "prompt", "program", "harness", "killed", "error", "build", "test", "carried", "verify", "agree", "rank", "accepts", "counterexample", "trunk"];
    let (stem, n) = match name.rsplit_once('-') {
        Some((s, n)) if n.chars().all(|c| c.is_ascii_digit()) => (s, n.parse().unwrap_or(0)),
        _ => (name, 0),
    };
    (ORDER.iter().position(|o| *o == stem).unwrap_or(ORDER.len()), n, name.to_string())
}

/// A log's seconds, from its head: each check's and program's log starts
/// `exit: X` then `seconds: Y`. None for a log without them (argv, prompt),
/// and for a check the verdict cache answered (its first line `cached: <key>`):
/// it ran nothing, and held no slot.
fn log_seconds(p: &Path) -> Option<f64> {
    use std::io::BufRead;
    let f = std::fs::File::open(p).ok()?;
    let head: Vec<String> = std::io::BufReader::new(f).lines().take(2).map_while(Result::ok).collect();
    if head.first().is_some_and(|l| l.starts_with("cached:")) { return None; }
    head.iter().find_map(|l| l.strip_prefix("seconds: ").and_then(|s| s.trim().parse().ok()))
}

/// The seconds of the check logs among `logs` in `dir`: every log with a
/// `seconds:` head but the program's. None when none has one.
fn check_seconds<'a>(dir: &Path, logs: impl Iterator<Item = &'a str>) -> Option<f64> {
    let s: Vec<f64> = logs.filter(|l| !PROGRAM_LOGS.contains(l)).filter_map(|l| log_seconds(&dir.join(l))).collect();
    (!s.is_empty()).then(|| s.iter().sum())
}

/// The seconds an agent process's program ran, from its log's head.
fn program_seconds(dir: &Path) -> Option<f64> { PROGRAM_LOGS.iter().find_map(|l| log_seconds(&dir.join(l))) }

/// Where an agent process of a running search is, from what its trace
/// directory holds so far: waiting (no argv yet: on an agent_processes slot,
/// or making its working directory), in flight (its program runs: argv, and
/// no program log), in checks (its program returned; it is being judged: a
/// program log, and no facts.json), or returned (facts.json).
fn stage(dir: &Path) -> &'static str {
    if dir.join("facts.json").exists() { "returned" }
    else if PROGRAM_LOGS.iter().any(|l| dir.join(l).exists()) { "in_checks" }
    else if dir.join("argv").exists() { "in_flight" }
    else { "waiting" }
}

/// Each reason's word and the sentence trusted code records it with
/// (`record_blocked`), so a trace from before reasons were words can be read
/// by its sentence. One word only older traces carry is not here: `disagree`,
/// recorded (with "the verified candidates disagree") before a disagreement
/// ran a counterexample search, for the block it then was: two or more
/// verified candidates that did not agree, blocked at once with no tests. It
/// is read as written, its own reason, never as `undecided`.
const REASONS: [(&str, &str); 7] = [
    ("too_few_verified", "fewer than two verified candidates"),
    ("undecided", "the verified candidates disagree, two tests judged every one, and none splits them: the spec does not decide between them"),
    ("too_few_tests", "fewer than two verified tests, or on candidates that disagree fewer than two that judge every one, and none splits the candidates"),
    ("rejects_every", "a verified test rejects every candidate"),
    ("undiscriminating", "fewer than two verified tests judge every candidate and reject a foil"),
    ("trunk_moved", "trunk moved during the search; run it again"),
    ("refused", "git refused what the gates allowed"),
];

/// A reason's word, as trusted code records it.
fn blocked_word(b: best_of_n::spec::Blocked) -> &'static str {
    use best_of_n::spec::Blocked::*;
    match b {
        TooFewVerified => "too_few_verified", Undecided => "undecided", TooFewTests => "too_few_tests",
        RejectsEvery => "rejects_every", Undiscriminating => "undiscriminating", TrunkMoved => "trunk_moved", Refused => "refused",
    }
}

/// How one attempt ended: pushed, landed (a counterexample's test landed on
/// trunk and the process went on), blocked, exited (its bon process stopped
/// during it: on the error its `exited:` line records, or, in older traces,
/// with no transition), or running. A block's reason is the word
/// the trace recorded; for a trace from before reasons were words, the one
/// the kernel derives from its searches' words, else the one its sentence
/// names; else none (unrecorded).
#[derive(Debug, PartialEq)]
struct End { end: &'static str, reason: Option<String>, from: Option<&'static str> }

/// How each attempt of a bon process ended, by the position of its code or
/// compaction search in `searches`. An attempt is that search and the foil and
/// counterexample searches after it, up to the next attempt. `lines` are each
/// search's transitions, by position; `derive` is the kernel's reason for the
/// tested search, counterexample and foil searches at those positions, where
/// every one reported and its words decode.
fn attempt_ends(searches: &[Value], lines: &[Vec<String>], running: bool,
                derive: &dyn std::ops::Fn(usize, Option<usize>, Option<usize>) -> Option<&'static str>) -> Vec<(usize, End)> {
    let mains: Vec<usize> = (0..searches.len()).filter(|&i| matches!(searches[i]["kind"].as_str(), Some("code" | "compaction"))).collect();
    let mut out = Vec::new();
    for (k, &m) in mains.iter().enumerate() {
        let to = mains.get(k + 1).copied().unwrap_or(searches.len());
        let last = k + 1 == mains.len();
        let ls: Vec<&String> = (m..to).flat_map(|i| lines.get(i).into_iter().flatten()).collect();
        let of = |kind: &str| (m + 1..to).find(|&i| searches[i]["kind"] == kind);
        let derived = || derive(m, of("counterexample"), of("foil"));
        let end = if ls.iter().any(|t| t.starts_with("push")) { End { end: "pushed", reason: None, from: None } }
        else if ls.iter().any(|t| t.starts_with("land ")) { End { end: "landed", reason: None, from: None } }
        else if let Some(b) = ls.iter().find(|t| t.starts_with("blocked")) {
            let rest = b.trim_start_matches("blocked:").trim();
            let word = rest.split_once(": ").map(|(w, _)| w).filter(|w| w.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
            let (reason, from) = match word {
                Some(w) => (Some(w.to_string()), Some("recorded")),
                None => match derived() {
                    Some(w) => (Some(w.to_string()), Some("kernel")),
                    None => match by_sentence(rest, &searches[m], of("counterexample").map(|i| &searches[i])) { Some(w) => (Some(w.to_string()), Some("sentence")), None => (None, None) },
                },
            };
            End { end: "blocked", reason, from }
        }
        // Its bon process ended on an error it recorded: the error is the reason.
        else if let Some(e) = ls.iter().find_map(|t| exit_error(t)) { End { end: "exited", reason: Some(e.to_string()), from: Some("recorded") } }
        else if last && running { End { end: "running", reason: None, from: None } }
        else if let Some(w) = derived() { End { end: "blocked", reason: Some(w.to_string()), from: Some("kernel") } }
        // Followed by another attempt, it ended without a push: a block no word or sentence names.
        else if !last { End { end: "blocked", reason: None, from: None } }
        // Its bon process stopped with no transition: during a search, or after every search of it reported.
        else {
            let reported = (m..to).all(|i| !searches[i]["time"].is_null());
            End { end: "exited", reason: Some(if reported { "after_its_searches" } else { "during_a_search" }.into()), from: None }
        };
        out.push((m, end));
    }
    out
}

/// The reason a trace's sentence names, from before reasons were words, told
/// apart by the counts of verified candidates and tests the trace recorded
/// where the sentence named more than one: "fewer than two verified candidates,
/// or they disagree", which with two verified is disagree (the immediate block
/// of then, never undecided); and "fewer than two verified tests, and none splits the
/// candidates", which, with two verified tests, is none_splits (no test split
/// the candidates by the rules of then; today's kernel would say rejects_every
/// or undiscriminating, which only it can tell apart). Otherwise the word of
/// today's sentence it is.
fn by_sentence(sentence: &str, tested: &Value, counterexample: Option<&Value>) -> Option<&'static str> {
    let verified = |s: &Value| s["recorded_verified"].as_u64().or(s["verified"].as_u64());
    if sentence == "fewer than two verified candidates, or they disagree" {
        return Some(if verified(tested)? < 2 { "too_few_verified" } else { "disagree" });
    }
    if sentence == "fewer than two verified tests, and none splits the candidates" {
        return Some(if verified(counterexample?)? < 2 { "too_few_tests" } else { "none_splits" });
    }
    REASONS.iter().find(|(_, s)| *s == sentence).map(|(w, _)| *w)
}

/// A unix time as its UTC date, YYYY-MM-DD.
pub fn date(t: u64) -> String {
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

/// Dollars to the cent; never `$-0.00`.
pub fn money(d: f64) -> String { format!("${:.2}", if d.abs() < 0.005 { 0.0 } else { d }) }

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
    // Each run's directory: <pid>, or <pid>.<start> for a reused pid.
    let mut pids: Vec<(u64, String, PathBuf)> = std::fs::read_dir(&traces).into_iter().flatten().flatten()
        .filter_map(|e| { let name = e.file_name().to_string_lossy().to_string();
            Some((best_of_n::trusted::trace_process(&name)?.0, name, e.path())) }).collect();
    pids.sort_by_key(|(_, _, p)| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    pids.reverse();
    let (mut verified_all, mut candidates_all, mut cost_all) = (0usize, 0usize, 0f64);
    let (mut generation_all, mut time_all) = (0f64, 0f64);
    let mut processes = Vec::new();
    let mut last_push: Option<Value> = None;
    let (mut earliest, mut latest) = (u64::MAX, 0u64);
    // The traces of this repository's bon processes the user layer's process
    // list says are running. This bon process, reading its own traces after a
    // push (for cost.toml), has ended its work: only another is running.
    let me = u64::from(std::process::id());
    let live: Vec<String> = best_of_n::trusted::processes().into_iter()
        .filter(|p| p["repository"].as_str().map(Path::new) == Some(root) && p["pid"].as_u64() != Some(me))
        .filter_map(|p| p["trace"].as_str().map(String::from)).collect();
    for (pid, trace, dir) in pids.into_iter() {
        let running = live.contains(&trace);
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
        // Each search's decoded words (where it reported) and its transitions, by position.
        let mut decoded: Vec<Option<best_of_n::gates::Search>> = Vec::new();
        let mut lines: Vec<Vec<String>> = Vec::new();
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
                // Its program's run and its checks, each by its log's seconds.
                let checks_seconds = check_seconds(&e.path(), logs.iter().map(String::as_str));
                let c = &facts["candidate"];
                let accepted = c["accepted"].as_bool().unwrap_or(false);
                let verified = match &kernel {
                    Some(k) => k.results.get(i).and_then(|r| r.as_ref()).is_some_and(|x| Kernel::verified(k, x)),
                    None => accepted && (counterexample || c["proved"].as_bool().unwrap_or(false)),
                };
                let (lines_added, lines_removed) = line_counts(c);
                let record = record_of(&facts, &logs);
                Some((i, json!({
                    "index": i, "program": program_of(&facts), "role": facts["role"], "model": facts["model"],
                    // Its requests over its model's tier threshold, and what they cost beyond the base price.
                    "requests_over_tier": facts["requests_over_tier"], "over_tier": facts["over_tier_microdollars"].as_f64().map(|m| m / 1e6),
                    "generation": facts["generation_microdollars"].as_f64().map(|m| m / 1e6),
                    "commit": c["commit"], "accepted": accepted, "verified": verified,
                    "rank": c["rank"], "diff": c["diff"], "changed": c["changed"],
                    "lines_added": lines_added, "lines_removed": lines_removed,
                    "flags": (["killed", "over_limit", "price_mismatch"]).iter().filter(|k| facts[**k] == true).collect::<Vec<_>>(),
                    "logs": logs,
                    "program_seconds": program_seconds(&e.path()), "check_seconds": checks_seconds,
                    "out": c["out"],
                    "proved": c["proved"],
                    // A trace from before tests ran on foils (or a candidate that is no test) has none.
                    "accepts": if c["accepts"].is_array() { c["accepts"].clone() } else { json!([]) },
                    "accepts_foils": if c["accepts_foils"].is_array() { c["accepts_foils"].clone() } else { json!([]) },
                    "record": record,
                })))
            }).collect();
            candidates.sort_by_key(|(i, _)| *i);
            // A running search's agent processes that have not returned, by where each is.
            let mut stages = json!({ "waiting": 0, "in_flight": 0, "in_checks": 0 });
            if live {
                for e in std::fs::read_dir(&rdir).into_iter().flatten().flatten().filter(|e| e.file_name().to_string_lossy().parse::<usize>().is_ok()) {
                    let at = stage(&e.path());
                    if at != "returned" { stages[at] = json!(stages[at].as_u64().unwrap_or(0) + 1); }
                }
            }
            let (agent_pool, check_pool) = pool_sizes(&summary);
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
                "selected": selected, "recorded_selected": recorded, "recorded_verified": summary["verified"],
                "kernel": if kernel.is_some() { "derived" } else if rdir.join("search.words").exists() { "unreadable" } else { "none" },
                "blocked": blocked, "cost": cost, "seconds": seconds, "time": summary["time"], "running": live,
                "waiting": stages["waiting"], "in_flight": stages["in_flight"], "in_checks": stages["in_checks"],
                "pools": { "agent_processes": agent_pool, "check_processes": check_pool },
                "behaviors": behaviors(&candidates.iter().map(|(_, c)| c.clone()).collect::<Vec<_>>()),
                "requests_over_tier": candidates.iter().filter_map(|(_, c)| c["requests_over_tier"].as_u64()).sum::<u64>(),
                "over_tier": candidates.iter().filter_map(|(_, c)| c["over_tier"].as_f64()).sum::<f64>(),
                "candidates": candidates.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
            }));
            decoded.push((!summary.is_null()).then_some(kernel).flatten());
            lines.push(segment);
        }
        // How each attempt ended, and why it blocked: on its code or compaction search.
        let derive = |t: usize, x: Option<usize>, f: Option<usize>| -> Option<&'static str> {
            let get = |i: Option<usize>| -> Result<Option<&best_of_n::gates::Search>, ()> { match i { None => Ok(None), Some(i) => decoded.get(i).and_then(|d| d.as_ref()).map(Some).ok_or(()) } };
            let (Ok(Some(t)), Ok(x), Ok(f)) = (get(Some(t)), get(x), get(f)) else { return None };
            Kernel::blocked(t, x, f).map(blocked_word)
        };
        for (m, e) in attempt_ends(&searches, &lines, running, &derive) {
            searches[m]["end"] = json!(e.end);
            searches[m]["reason"] = json!(e.reason);
            searches[m]["reason_from"] = json!(e.from);
        }
        // A bon process's kind is its first recorded non-counterexample kind,
        // or its first recorded kind when it only searched for counterexamples.
        let kind = searches.iter().find_map(|s| s["kind"].as_str().filter(|k| !k.is_empty() && *k != "counterexample" && *k != "foil"))
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
        // Its searches' wall time, summed: the time it spent, as its time cost is charged.
        let seconds: f64 = searches.iter().filter_map(|s| s["seconds"].as_f64()).sum();
        let push = pushes.last().cloned();
        // Its first grant, or the trace's creation time while still starting.
        let time = searches.iter().filter_map(|s| s["started"].as_u64()).min().unwrap_or_else(|| {
            std::fs::metadata(&dir).and_then(|m| m.created().or(m.modified())).ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs())
        });
        earliest = earliest.min(time); latest = latest.max(time);
        // What `find` looks in: the pid, the command, its outcome, and every commit.
        let mut text = format!("{trace} {kind} {goal} {outcome} {}", push.as_ref().and_then(|p| p["commit"].as_str()).unwrap_or(""));
        for s in &searches { for c in s["candidates"].as_array().into_iter().flatten() { text.push(' '); text.push_str(c["commit"].as_str().unwrap_or("")); } }
        if !filter.covers(time, &text) { continue; }
        for s in &searches {
            verified_all += s["verified"].as_u64().unwrap_or(0) as usize;
            candidates_all += s["returned"].as_u64().unwrap_or(0) as usize;
            cost_all += s["cost"].as_f64().unwrap_or(0.0);
            generation_all += s["generation"].as_f64().unwrap_or(0.0);
            time_all += s["time_cost"].as_f64().unwrap_or(0.0);
        }
        // The code or compaction search of the attempt that ended it (an earlier
        // attempt's may have disagreed, and landed a test), else the first search.
        let main = searches.iter().rev().find(|s| s["kind"] != "counterexample" && s["kind"] != "foil").or(searches.first());
        let tally = |s: &Value| format!("{} of {} verified",
            s["verified"].as_u64().unwrap_or(0), count(s["returned"].as_u64().unwrap_or(0) as usize, "candidate", "candidates"));
        // One sentence in plain words, each spec word qualified.
        let sentence = match outcome {
            "running" => searches.last().map(|s| {
                let w = s["width"].as_u64().map_or(String::new(), |w| format!(" of {w}"));
                let n = |k: &str| s[k].as_u64().unwrap_or(0);
                let now = now_counts(n("in_flight"), n("in_checks"), n("waiting"));
                format!("{}: {}{w} agent processes returned{}, {} verified so far", s["kind"].as_str().unwrap_or("search"), s["returned"],
                    if now.is_empty() { String::new() } else { format!(" ({now})") }, s["verified"])
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
                let error = transitions.iter().rev().find_map(|t| exit_error(t)).map_or(String::new(), |e| format!(" on {e}"));
                format!("{earlier}the bon process exited {at}{error}; nothing was pushed")
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
            "pid": pid, "trace": trace, "running": running, "kind": kind, "goal": goal, "title": title, "about": about, "base": base, "outcome": outcome, "sentence": sentence,
            "cost": cost, "generation": generation, "time_cost": time_cost, "seconds": seconds, "push": push, "limit": limit, "time": time,
            "transitions": transitions, "searches": searches,
            // Its checks of trunk before its first search: trunk-test-K, trunk-verify-K, goal-agree-K.
            "check_seconds": check_seconds(&dir, std::fs::read_dir(&dir).into_iter().flatten().flatten()
                .map(|e| e.file_name().to_string_lossy().to_string()).filter(|f| f.starts_with("trunk-") || f.starts_with("goal-")).collect::<Vec<_>>().iter().map(String::as_str)),
        }));
    }

    // Each candidate's tree, and each search's count of distinct trees, from git.
    trees(root, &mut processes);

    // Consecutive bon processes of one kind, up to the one that finishes it
    // (pushed, found, not found, a proposal), are one effort: one row.
    const SUMMED: [&str; 4] = ["cost", "generation", "time_cost", "seconds"];
    let mut groups: Vec<Value> = Vec::new();
    for p in processes.iter().rev() {
        let joins = groups.last().is_some_and(|g: &Value| g["kind"] == p["kind"]
            && !matches!(g["outcome"].as_str(), Some("pushed" | "found" | "not found" | "proposal")));
        if joins {
            let g = groups.last_mut().unwrap();
            for k in SUMMED { g[k] = json!(g[k].as_f64().unwrap_or(0.0) + p[k].as_f64().unwrap_or(0.0)); }
            for k in ["title", "about", "outcome", "sentence", "push", "time", "running"] { g[k] = p[k].clone(); }
            g["processes"].as_array_mut().unwrap().insert(0, p.clone());
        } else {
            groups.push(json!({ "kind": p["kind"], "title": p["title"], "about": p["about"], "outcome": p["outcome"], "sentence": p["sentence"],
                "cost": p["cost"], "generation": p["generation"], "time_cost": p["time_cost"], "seconds": p["seconds"],
                "push": p["push"], "time": p["time"], "running": p["running"], "processes": [p] }));
        }
    }
    groups.reverse();
    // A push's cost is everything run to reach it: every bon process of its
    // kind since the last push of that kind, whatever ran in between, the ones
    // that exited or were blocked first included.
    // Cost, generation, time and seconds, each summed the same way.
    let mut since: std::collections::HashMap<String, [f64; 4]> = std::collections::HashMap::new();
    let mut reached: Vec<[f64; 4]> = vec![[0.0; 4]; groups.len()];
    for (k, g) in groups.iter().enumerate().rev() {
        let kind = g["kind"].as_str().unwrap_or_default().to_string();
        let total = since.entry(kind).or_insert([0.0; 4]);
        for (i, f) in SUMMED.iter().enumerate() { total[i] += g[*f].as_f64().unwrap_or(0.0); }
        if g["outcome"] == "pushed" { reached[k] = *total; *total = [0.0; 4]; }
    }
    let mut push_costs = Vec::new();
    for (k, g) in groups.iter_mut().enumerate() {
        if g["outcome"] == "pushed" && g["push"].is_object() {
            let [cost, generation, time_cost, seconds] = reached[k];
            g["push"]["generation"] = json!(generation);
            g["push"]["time_cost"] = json!(time_cost);
            g["push"]["seconds"] = json!(seconds);
            // The foil and counterexample searches that found none on the selection;
            // everything before them is what reaching the selection cost.
            let ce: f64 = g["processes"][0]["searches"].as_array().map_or(0.0, |x| x.iter().rev()
                .take_while(|x| x["kind"] == "counterexample" || x["kind"] == "foil")
                .filter_map(|x| x["cost"].as_f64()).sum());
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

    let mut out = json!({
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
            "attempts": attempts(&processes), "ended": ended(&processes), "reasons": reasons(&processes, "blocked"), "exits": reasons(&processes, "exited"),
            "success": success(&processes), "per_verified": per_verified(&processes), "over_tier": over_tier(&processes),
            "utilization": utilization(&processes), "run_time": run_time(&processes, &groups),
        },
        "processes": processes,
        // The range shown, and the range there is, so a view can offer it.
        "filter": { "since": filter.since, "until": filter.until, "find": filter.find },
        "bounds": { "earliest": (earliest != u64::MAX).then_some(earliest), "latest": (latest > 0).then_some(latest) },
        "retired": retired(root, &queue.iter().flatten().filter_map(|q| q["id"].as_u64()).collect::<Vec<_>>()),
        "queue": queue,
        "proposals": proposals(root),
        // What no search may change: bon's directory, the checks, trusted code.
        "protected": ([".bon/"].iter().map(|s| s.to_string())
            .chain(manifest.get("checks").and_then(|c| c.get("paths")).and_then(|p| p.as_array()).into_iter().flatten().filter_map(|v| v.as_str().map(String::from)))
            .chain(manifest.get("account").and_then(|c| c.get("trusted")).and_then(|p| p.as_array()).into_iter().flatten().filter_map(|v| v.as_str().map(String::from)))
            .collect::<Vec<_>>()),
        "sbom": sbom(root),
        "spec": spec(root, &manifest),
        "system": system(root, &format!("{remote}/{trunk_name}"), &manifest),
    });
    // What only engineer can answer, from all of the above; and how long each took him.
    let interrupts = crate::interrupt::interrupts(&[(root, &out)]);
    out["totals"]["turnaround"] = json!(crate::interrupt::turnaround(&interrupts));
    out["interrupts"] = json!(interrupts);
    out
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

/// A process's attempts: its code and compaction searches, by width.
fn main_searches(p: &Value) -> Vec<&Value> {
    p["searches"].as_array().map_or(Vec::new(), |s| s.iter().filter(|s| matches!(s["kind"].as_str(), Some("code" | "compaction"))).collect())
}

/// Attempts by kind and width, each counted once by how it ended (the `end`
/// of its code or compaction search): pushed, blocked, landed, exited or
/// running. `attempts` is their sum.
fn attempts(processes: &[Value]) -> Vec<Value> {
    let mut by: BTreeMap<(String, u64), [u64; 5]> = BTreeMap::new();
    for p in processes {
        for s in main_searches(p) {
            let e = by.entry((s["kind"].as_str().unwrap_or_default().to_string(), s["width"].as_u64().unwrap_or(0))).or_default();
            let at = match s["end"].as_str() { Some("pushed") => 0, Some("blocked") => 1, Some("landed") => 2, Some("running") => 4, _ => 3 };
            e[at] += 1;
        }
    }
    by.into_iter().map(|((kind, width), [pushed, blocked, landed, exited, running])| json!({ "kind": kind, "width": width,
        "attempts": pushed + blocked + landed + exited + running, "pushed": pushed, "blocked": blocked, "landed": landed, "exited": exited, "running": running })).collect()
}

/// How bon processes ended, by kind, and how many of those that pushed or
/// blocked (1-p)^k predicts would have blocked.
fn ended(processes: &[Value]) -> Vec<Value> {
    let mut by: BTreeMap<String, (u64, u64, u64, u64, Vec<u64>)> = BTreeMap::new();
    for p in processes {
        let main = main_searches(p);
        let Some(kind) = main.first().and_then(|s| s["kind"].as_str()) else { continue };
        let e = by.entry(kind.to_string()).or_default();
        match p["outcome"].as_str() {
            Some("pushed") => { e.0 += 1; e.4.push(main.len() as u64); }
            Some("blocked") => { e.1 += 1; e.4.push(main.len() as u64); }
            Some("running") => e.3 += 1,
            _ => e.2 += 1,
        }
    }
    let rows = attempts(processes);
    by.into_iter().map(|(kind, (pushed, blocked, exited, running, ks))| {
        let (ran, s) = rows.iter().filter(|r| r["kind"] == kind.as_str()).fold((0, 0), |(a, s), r| {
            let n = |k: &str| r[k].as_u64().unwrap_or(0);
            (a + n("pushed") + n("blocked") + n("landed"), s + n("pushed"))
        });
        let p = (ran > 0).then(|| s as f64 / ran as f64);
        let expected = p.filter(|_| !ks.is_empty()).map(|p| ks.iter().map(|k| (1.0 - p).powi(*k as i32)).sum::<f64>() / ks.len() as f64);
        json!({ "kind": kind, "pushed": pushed, "blocked": blocked, "exited": exited, "running": running, "expected": expected })
    }).collect()
}

/// How many attempts of each kind each reason blocked (`end` blocked), and how
/// many of those the reason was inferred for (its trace has no word: the
/// kernel's, or its sentence's); a block nothing names is "unrecorded". With
/// `end` exited: how many exited during a search, and after its searches reported.
fn reasons(processes: &[Value], end: &str) -> Vec<Value> {
    let mut by: BTreeMap<(String, String), (u64, u64)> = BTreeMap::new();
    for p in processes {
        for s in main_searches(p).into_iter().filter(|s| s["end"] == end) {
            let e = by.entry((s["kind"].as_str().unwrap_or_default().to_string(), s["reason"].as_str().unwrap_or("unrecorded").to_string())).or_default();
            e.0 += 1;
            if !s["reason_from"].is_null() && s["reason_from"] != "recorded" { e.1 += 1; }
        }
    }
    by.into_iter().map(|((kind, reason), (count, inferred))| json!({ "kind": kind, "reason": reason, "count": count, "inferred": inferred })).collect()
}

// ── measures ────────────────────────────────────────────

/// Every search of every process, in order.
fn all_searches(processes: &[Value]) -> impl Iterator<Item = &Value> {
    processes.iter().flat_map(|p| p["searches"].as_array().into_iter().flatten())
}

/// A search reported (its line is in searches.jsonl): its agent processes and seconds are final.
fn reported(s: &Value) -> bool { !s["time"].is_null() }

/// A search's successes: its verified candidates; a foil search's foils
/// (accepted and not proved, the spec's `foil`), which are never verified.
fn successes(s: &Value) -> u64 {
    if s["kind"] == "foil" {
        s["candidates"].as_array().map_or(0, |c| c.iter().filter(|c| c["accepted"] == true && c["proved"] != true).count() as u64)
    } else { s["verified"].as_u64().unwrap_or(0) }
}

/// The agent processes per behavior of a search: for each distinct `out` its
/// verified candidates show (a behavior, as the spec's `behaviors`), how many
/// verified candidates show it, in the order each first appears.
fn behaviors(candidates: &[Value]) -> Vec<u64> {
    let mut by: Vec<(Value, u64)> = Vec::new();
    for c in candidates.iter().filter(|c| c["verified"] == true) {
        match by.iter_mut().find(|(o, _)| *o == c["out"]) { Some(b) => b.1 += 1, None => by.push((c["out"].clone(), 1)) }
    }
    by.into_iter().map(|(_, n)| n).collect()
}

/// Each commit's tree, from git: one `git cat-file --batch-check` for all of
/// them. A commit git does not have is absent.
fn tree_ids(root: &Path, commits: &[String]) -> std::collections::HashMap<String, String> {
    use std::io::Write;
    let mut out = std::collections::HashMap::new();
    if commits.is_empty() { return out; }
    let child = Command::new("git").args(["cat-file", "--batch-check=%(objectname) %(objecttype)"]).current_dir(root)
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn();
    let Ok(mut child) = child else { return out };
    let input: String = commits.iter().map(|c| format!("{c}^{{tree}}\n")).collect();
    if let Some(mut stdin) = child.stdin.take() { let _ = stdin.write_all(input.as_bytes()); }
    let Ok(o) = child.wait_with_output() else { return out };
    // One line per commit, in order: `<tree> tree`, or `<input> missing`.
    for (c, l) in commits.iter().zip(String::from_utf8_lossy(&o.stdout).lines()) {
        if let Some(t) = l.strip_suffix(" tree") { out.insert(c.clone(), t.to_string()); }
    }
    out
}

/// How many distinct trees a search's candidates wrote: those with a commit,
/// by its tree. None when git does not know some candidate's tree.
fn distinct_trees(candidates: &[Value]) -> Option<u64> {
    let mut seen: Vec<&str> = Vec::new();
    for c in candidates.iter().filter(|c| c["commit"].is_string()) {
        let t = c["tree"].as_str()?;
        if !seen.contains(&t) { seen.push(t); }
    }
    Some(seen.len() as u64)
}

/// Each candidate's `tree` and each search's `trees` (distinct trees).
fn trees(root: &Path, processes: &mut [Value]) {
    let commits: Vec<String> = all_searches(processes).flat_map(|s| s["candidates"].as_array().into_iter().flatten())
        .filter_map(|c| c["commit"].as_str().map(String::from)).collect();
    let of = tree_ids(root, &commits);
    for p in processes.iter_mut() {
        for s in p["searches"].as_array_mut().into_iter().flatten() {
            for c in s["candidates"].as_array_mut().into_iter().flatten() {
                c["tree"] = json!(c["commit"].as_str().and_then(|x| of.get(x)));
            }
            s["trees"] = json!(distinct_trees(s["candidates"].as_array().map_or(&[][..], |v| v)));
        }
    }
}

/// Success probability by kind, over all attempts (`attempt` null) and by
/// attempt index (1 for each bon process's first code or compaction search
/// and the searches on it, 2 for its second, …): agent processes and
/// successes over reported searches, and how many attempts ended (pushed,
/// blocked, landed) and pushed. A search before any attempt (a counterexample
/// search on trunk) counts under its kind alone.
fn success(processes: &[Value]) -> Vec<Value> {
    let mut by: BTreeMap<(String, u64), [u64; 4]> = BTreeMap::new();
    for p in processes {
        let mut attempt = 0u64;
        for s in p["searches"].as_array().into_iter().flatten() {
            let kind = s["kind"].as_str().unwrap_or_default().to_string();
            let main = matches!(kind.as_str(), "code" | "compaction");
            if main { attempt += 1; }
            let ended = main && matches!(s["end"].as_str(), Some("pushed" | "blocked" | "landed"));
            for at in [0].into_iter().chain((attempt > 0).then_some(attempt)) {
                let e = by.entry((kind.clone(), at)).or_default();
                if reported(s) { e[0] += s["width"].as_u64().unwrap_or(0); e[1] += successes(s); }
                if ended { e[2] += 1; if s["end"] == "pushed" { e[3] += 1; } }
            }
        }
    }
    by.into_iter().map(|((kind, at), [n, v, ended, pushed])| json!({ "kind": kind, "attempt": (at > 0).then_some(at),
        "agent_processes": n, "successes": v, "ended": ended, "pushed": pushed })).collect()
}

/// Cost per verified candidate by kind, program and model: each row's agent
/// processes (those that returned facts), how many were verified, their
/// generation, and their share of each search's time cost (the search's time
/// × its agent processes in the row ÷ its agent processes that returned).
fn per_verified(processes: &[Value]) -> Vec<Value> {
    let mut by: BTreeMap<(String, String, String), (u64, u64, f64, f64)> = BTreeMap::new();
    for s in all_searches(processes) {
        let cs = s["candidates"].as_array().cloned().unwrap_or_default();
        let share = s["time_cost"].as_f64().unwrap_or(0.0) / cs.len().max(1) as f64;
        for c in &cs {
            let word = |v: &Value| v.as_str().unwrap_or("").to_string();
            let e = by.entry((word(&s["kind"]), word(&c["program"]), word(&c["model"]))).or_default();
            e.0 += 1;
            if c["verified"] == true { e.1 += 1; }
            e.2 += c["generation"].as_f64().unwrap_or(0.0);
            e.3 += share;
        }
    }
    by.into_iter().map(|((kind, program, model), (n, v, g, t))| json!({ "kind": kind, "program": program, "model": model,
        "agent_processes": n, "verified": v, "generation": g, "time_cost": t })).collect()
}

/// Requests over a model's tier threshold, by kind, role and model: each row's
/// agent processes that returned facts, how many of those said each request's
/// prompt (`measured`; codex's running total cannot), their requests over the
/// threshold and what those cost beyond the base price. Rows of a role that
/// reaches a model and said its requests' prompts, whether or not one crossed
/// the line (a stub has no line to cross).
fn over_tier(processes: &[Value]) -> Vec<Value> {
    let mut by: BTreeMap<(String, String, String), (u64, u64, u64, f64)> = BTreeMap::new();
    for s in all_searches(processes) {
        for c in s["candidates"].as_array().into_iter().flatten() {
            let word = |v: &Value| v.as_str().unwrap_or("").to_string();
            let e = by.entry((word(&s["kind"]), word(&c["role"]), word(&c["model"]))).or_default();
            e.0 += 1;
            if let Some(n) = c["requests_over_tier"].as_u64() { e.1 += 1; e.2 += n; }
            e.3 += c["over_tier"].as_f64().unwrap_or(0.0);
        }
    }
    by.into_iter().filter(|((_, _, model), (_, measured, _, _))| !model.is_empty() && *measured > 0).map(|((kind, role, model), (n, measured, requests, beyond))| json!({ "kind": kind, "role": role, "model": model,
        "agent_processes": n, "measured": measured, "requests": requests, "beyond": beyond })).collect()
}

/// The length of the union of intervals [start, end].
fn union_length(mut spans: Vec<(f64, f64)>) -> f64 {
    spans.sort_by(|a, b| a.0.total_cmp(&b.0));
    let (mut total, mut reach) = (0.0, f64::NEG_INFINITY);
    for (a, b) in spans {
        if b <= reach { continue; }
        total += b - a.max(reach);
        reach = b;
    }
    total
}

/// The host's two semaphores against wall time, over the reported searches in
/// range: wall is the union of their wall times; agent_processes' held
/// slot-seconds are each agent process's program seconds, check_processes'
/// each check's seconds (a cached verdict held none). A semaphore's size is
/// the one every search that records a size recorded (traces before queue 59
/// record none), else none; its utilization is over those searches alone:
/// their held slot-seconds ÷ (size × the union of their wall times).
fn utilization(processes: &[Value]) -> Value {
    let searches: Vec<&Value> = all_searches(processes).filter(|s| reported(s)).collect();
    let wall_of = |of: &[&Value]| union_length(of.iter().filter_map(|s| Some((s["started"].as_f64()?, s["started"].as_f64()? + s["seconds"].as_f64()?))).collect());
    let held_of = |of: &[&Value], k: &str| of.iter().flat_map(|s| s["candidates"].as_array().into_iter().flatten()).filter_map(|c| c[k].as_f64()).sum::<f64>();
    let pool = |k: &str, held: &str| {
        let sized: Vec<&Value> = searches.iter().copied().filter(|s| s["pools"][k].as_u64().is_some()).collect();
        let size = sized.first().and_then(|s| s["pools"][k].as_u64()).filter(|n| sized.iter().all(|s| s["pools"][k].as_u64() == Some(*n)));
        let wall = wall_of(&sized);
        let utilization = size.filter(|n| *n > 0 && wall > 0.0).map(|n| held_of(&sized, held) / (n as f64 * wall));
        json!({ "held": held_of(&searches, held), "size": size, "utilization": utilization, "sized": sized.len() })
    };
    json!({ "wall": wall_of(&searches), "searches": searches.len(),
        "agent_processes": pool("agent_processes", "program_seconds"), "check_processes": pool("check_processes", "check_seconds") })
}

/// The median: the middle value, or the mean of the two middle ones.
pub fn median(v: &[f64]) -> Option<f64> {
    let mut s = v.to_vec(); s.sort_by(f64::total_cmp);
    let n = s.len();
    if n == 0 { None } else if n % 2 == 1 { Some(s[n / 2]) } else { Some((s[n / 2 - 1] + s[n / 2]) / 2.0) }
}

/// The 90th percentile, by nearest rank: the ⌈0.9 n⌉-th smallest.
pub fn p90(v: &[f64]) -> Option<f64> {
    let mut s = v.to_vec(); s.sort_by(f64::total_cmp);
    let k = (0.9 * s.len() as f64).ceil() as usize;
    s.get(k.max(1) - 1).copied()
}

/// The fewest searches a fit is made from.
const FIT_MIN: usize = 3;

/// The least-squares line y = fixed + per · x through (x, y): None with fewer
/// than FIT_MIN points or one x for all of them, where no split is defined.
fn fit(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    let n = points.len() as f64;
    if points.len() < FIT_MIN { return None; }
    let (mx, my) = (points.iter().map(|p| p.0).sum::<f64>() / n, points.iter().map(|p| p.1).sum::<f64>() / n);
    let sxx: f64 = points.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if sxx == 0.0 { return None; }
    let per = points.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum::<f64>() / sxx;
    Some((my - per * mx, per))
}

/// The run-time distribution by kind: the time and cost to each push (the
/// seconds and cost of every bon process of its kind since the last push of
/// that kind), their median and 90th percentile; and, over the kind's
/// reported searches whose trees git knows, seconds and cost as a fixed part
/// plus a part per distinct tree, by least squares (inferred).
fn run_time(processes: &[Value], groups: &[Value]) -> Vec<Value> {
    let mut kinds: Vec<String> = Vec::new();
    for k in all_searches(processes).filter_map(|s| s["kind"].as_str()) { if !k.is_empty() && !kinds.iter().any(|x| x == k) { kinds.push(k.to_string()); } }
    kinds.sort();
    kinds.into_iter().map(|kind| {
        let pushes: Vec<&Value> = groups.iter().filter(|g| g["kind"] == kind.as_str() && g["outcome"] == "pushed").map(|g| &g["push"]).filter(|p| p.is_object()).collect();
        let of = |k: &str| pushes.iter().filter_map(|p| p[k].as_f64()).collect::<Vec<f64>>();
        let (secs, costs) = (of("seconds"), of("cost"));
        let points: Vec<(f64, f64, f64)> = all_searches(processes).filter(|s| s["kind"] == kind.as_str() && reported(s))
            .filter_map(|s| Some((s["trees"].as_f64()?, s["seconds"].as_f64()?, s["cost"].as_f64()?))).collect();
        let time = fit(&points.iter().map(|p| (p.0, p.1)).collect::<Vec<_>>());
        let cost = fit(&points.iter().map(|p| (p.0, p.2)).collect::<Vec<_>>());
        json!({ "kind": kind, "pushes": pushes.len(),
            "time": { "median": median(&secs), "p90": p90(&secs) }, "cost": { "median": median(&costs), "p90": p90(&costs) },
            "searches": points.len(),
            "fit": time.zip(cost).map(|((tf, tp), (cf, cp))| json!({ "time": { "fixed": tf, "per_tree": tp }, "cost": { "fixed": cf, "per_tree": cp } })) })
    }).collect()
}

/// Seconds as minutes and seconds, or hours and minutes: 48s, 7m48s, 31h05m.
pub fn dur(s: f64) -> String {
    let neg = s < 0.0;
    let s = s.abs().round() as u64;
    let t = if s < 60 { format!("{s}s") } else if s < 3600 { format!("{}m{:02}s", s / 60, s % 60) } else { format!("{}h{:02}m", s / 3600, (s % 3600) / 60) };
    if neg { format!("−{t}") } else { t }
}

/// A share as a percentage, with what it is of: `87% (296 of 339)`; — of none.
fn share(k: u64, n: u64) -> String { if n == 0 { "—".into() } else { format!("{:.0}% ({k} of {n})", 100.0 * k as f64 / n as f64) } }

/// The success probability table, its header first: one row per kind, and one
/// per attempt index under it where the kind ran in more than one.
pub fn success_table(t: &crate::projection::Totals) -> Vec<Vec<String>> {
    if t.success.is_empty() { return Vec::new(); }
    let mut out = vec![vec!["Success probability".to_string(), "Per agent process".into(), "Per attempt".into()]];
    let row = |label: String, r: &crate::projection::Success| vec![label, share(r.successes, r.agent_processes), share(r.pushed, r.ended)];
    for r in t.success.iter().filter(|r| r.attempt.is_none()) {
        out.push(row(cap(&r.kind), r));
        let by: Vec<&crate::projection::Success> = t.success.iter().filter(|x| x.kind == r.kind && x.attempt.is_some()).collect();
        if by.len() > 1 { for x in by { out.push(row(format!("  Attempt {}", x.attempt.unwrap_or(0)), x)); } }
    }
    out
}

/// The cost per verified candidate table, its header first: one row per kind,
/// program and model.
pub fn per_verified_table(t: &crate::projection::Totals) -> Vec<Vec<String>> {
    if t.per_verified.is_empty() { return Vec::new(); }
    let mut out = vec![["Cost per verified candidate", "Per verified", "Verified", "Agent processes", "Gen", "Time"].map(String::from).to_vec()];
    for r in &t.per_verified {
        let word = |s: &str| if s.is_empty() { "—".to_string() } else { s.to_string() };
        out.push(vec![format!("{} · {} · {}", cap(&r.kind), word(&r.program), word(&r.model)),
            if r.verified == 0 { "—".into() } else { money((r.generation + r.time_cost) / r.verified as f64) },
            r.verified.to_string(), r.agent_processes.to_string(), money(r.generation), money(r.time_cost)]);
    }
    out
}

/// The over-tier table, its header first: one row per kind, role and model
/// whose output said each request's prompt: its requests over the model's
/// tier threshold and what they cost beyond the base price.
pub fn over_tier_table(t: &crate::projection::Totals) -> Vec<Vec<String>> {
    if t.over_tier.is_empty() { return Vec::new(); }
    let mut out = vec![["Over tier", "Requests over", "Beyond base", "Agent processes"].map(String::from).to_vec()];
    for r in &t.over_tier {
        let measured = if r.measured == r.agent_processes { r.agent_processes.to_string() } else { format!("{} of {}", r.measured, r.agent_processes) };
        out.push(vec![format!("{} · {} · {}", cap(&r.kind), r.role, r.model), r.requests.to_string(), money(r.beyond), measured]);
    }
    out
}

/// The run-time distribution table, its header first: each kind that pushed,
/// its time and cost to a push; then each kind's fit per search, or why there is none.
pub fn run_time_table(t: &crate::projection::Totals) -> (Vec<Vec<String>>, Vec<String>) {
    let pushed: Vec<&crate::projection::RunTime> = t.run_time.iter().filter(|r| r.pushes > 0).collect();
    let mut rows = Vec::new();
    if !pushed.is_empty() {
        rows.push(["Run-time distribution", "Pushes", "Median", "90th percentile"].map(String::from).to_vec());
        let opt = |v: Option<f64>, f: &dyn std::ops::Fn(f64) -> String| v.map_or("—".to_string(), f);
        for r in &pushed {
            rows.push(vec![format!("{} time to a push", cap(&r.kind)), r.pushes.to_string(), opt(r.time.median, &dur), opt(r.time.p90, &dur)]);
            rows.push(vec![format!("{} cost to a push", cap(&r.kind)), r.pushes.to_string(), opt(r.cost.median, &money), opt(r.cost.p90, &money)]);
        }
    }
    let fits = t.run_time.iter().map(|r| match &r.fit {
        Some(f) => format!("{} per search (inferred, {}): time {} + {} per distinct tree · cost {} + {} per distinct tree", cap(&r.kind), count(r.searches as usize, "search", "searches"),
            dur(f.time.fixed), dur(f.time.per_tree), money(f.cost.fixed), money(f.cost.per_tree)),
        None => format!("{} per search: too few to fit ({}, {} needed, with more than one count of distinct trees)", cap(&r.kind), count(r.searches as usize, "search", "searches"), FIT_MIN),
    }).collect();
    (rows, fits)
}

/// The utilization table, its header first: each of the host's two semaphores,
/// its held slot-seconds, the wall time, their ratio, its size and utilization
/// (— where the traces have no size).
pub fn utilization_table(t: &crate::projection::Totals) -> Vec<Vec<String>> {
    let u = &t.utilization;
    if u.searches == 0 || u.wall <= 0.0 { return Vec::new(); }
    // Size and utilization only where a trace records a size; over the searches that do, said when not every one.
    let sized = [&u.agent_processes, &u.check_processes].iter().any(|p| p.size.is_some());
    let mut head = vec!["Utilization", "Held", "Wall", "Held ÷ wall"];
    if sized { head.extend(["Size", "Utilization"]); }
    let mut out = vec![head.into_iter().map(String::from).collect::<Vec<_>>()];
    for (name, p) in [("agent_processes", &u.agent_processes), ("check_processes", &u.check_processes)] {
        let mut row = vec![name.to_string(), dur(p.held), dur(u.wall), format!("{:.2}", p.held / u.wall)];
        if sized {
            row.push(p.size.map_or("—".into(), |s| s.to_string()));
            row.push(p.utilization.map_or("—".into(), |x| if p.sized < u.searches { format!("{:.0}% ({} of {} searches)", 100.0 * x, p.sized, u.searches) } else { format!("{:.0}%", 100.0 * x) }));
        }
        out.push(row);
    }
    out
}

/// The turnaround table, its header first: each kind of interrupt, how many
/// resolved and are pending, and the median and 90th percentile of the time
/// from raised to resolved.
pub fn turnaround_table(t: &crate::projection::Totals) -> Vec<Vec<String>> {
    if t.turnaround.is_empty() { return Vec::new(); }
    let mut out = vec![["Turnaround", "Resolved", "Pending", "Median", "90th percentile"].map(String::from).to_vec()];
    let opt = |v: Option<f64>| v.map_or("—".to_string(), dur);
    for r in &t.turnaround { out.push(vec![cap(&r.kind), r.resolved.to_string(), r.pending.to_string(), opt(r.time.median), opt(r.time.p90)]); }
    out
}

/// What the measures' words mean: each measure's formula, said once.
pub const MEASURE_NOTES: [(&str, &str); 11] = [
    ("Success probability per agent process", "verified ÷ agent processes, over reported searches; a foil search's foils ÷ its agent processes"),
    ("Success probability per attempt", "pushed ÷ attempts that ended (pushed, blocked, landed)"),
    ("Attempt a", "the same, over each bon process's a-th attempt and the searches on it"),
    ("Agent processes per behavior", "a search's verified candidates showing each distinct out"),
    ("Cost per verified candidate", "(Σ generation + Σ time × the row's share of each search's agent processes) ÷ verified"),
    ("Over tier", "requests whose prompt passed the model's tier threshold (`above` in the host's prices), and Σ (their cost at the tier − at the base price)"),
    ("Time, cost to a push","Σ seconds, Σ generation + time, of its kind's bon processes since its last push"),
    ("Median, 90th percentile", "the middle value (the mean of the middle two); the ⌈0.9 n⌉-th smallest"),
    ("Per search (inferred)", "least squares: seconds or cost = fixed + per tree × distinct trees, over reported searches"),
    ("Utilization", "held slot-seconds ÷ (size × wall); held: programs' seconds, checks' seconds (none for a cached verdict); wall: the union of the searches' wall times; over the searches whose trace records the size"),
    ("Turnaround", "an interrupt's raise to the action that resolved it"),
];

/// A reason attempts blocked, in words, with its count and how many of those
/// were inferred: `Too few verified (1)`, `Too few tests (5, 5 inferred)`. A
/// recorded error (an exit's reason) reads as written.
pub fn reason_count(r: &crate::projection::Reason) -> String {
    let word = r.reason.chars().all(|c| c.is_ascii_lowercase() || c == '_');
    let mut w = if word { r.reason.replace('_', " ") } else { r.reason.clone() };
    if let Some(f) = w.get_mut(0..1) { f.make_ascii_uppercase(); }
    if r.inferred > 0 { format!("{w} ({}, {} inferred)", r.count, r.inferred) } else { format!("{w} ({})", r.count) }
}

fn cap(s: &str) -> String { let mut c = s.chars(); c.next().map_or(String::new(), |f| f.to_uppercase().chain(c).collect()) }

/// The attempts table, its header first: one row per kind, and one per width
/// under it when the kind ran at more than one. Every attempt is in exactly
/// one of pushed, blocked, landed, exited and running, and All is their sum;
/// a column no attempt is in is left out, but for pushed, blocked and exited.
/// Each kind's success probability per attempt is in `success_table`.
pub fn attempt_table(t: &crate::projection::Totals) -> Vec<Vec<String>> {
    if t.attempts.is_empty() { return Vec::new(); }
    let landed = t.attempts.iter().any(|r| r.landed > 0);
    let running = t.attempts.iter().any(|r| r.running > 0);
    let mut head = vec!["Attempts", "All", "Pushed", "Blocked"];
    if landed { head.push("Landed"); }
    head.push("Exited");
    if running { head.push("Running"); }
    let mut out = vec![head.into_iter().map(String::from).collect::<Vec<_>>()];
    let row = |label: String, r: &[&crate::projection::Attempts]| {
        let n = |f: fn(&crate::projection::Attempts) -> u64| r.iter().map(|x| f(x)).sum::<u64>();
        let (pushed, blocked, l, exited, run) = (n(|x| x.pushed), n(|x| x.blocked), n(|x| x.landed), n(|x| x.exited), n(|x| x.running));
        let mut v = vec![label, (pushed + blocked + l + exited + run).to_string(), pushed.to_string(), blocked.to_string()];
        if landed { v.push(l.to_string()); }
        v.push(exited.to_string());
        if running { v.push(run.to_string()); }
        v
    };
    let mut kinds: Vec<&str> = t.attempts.iter().map(|r| r.kind.as_str()).collect();
    kinds.dedup();
    for k in kinds {
        let rows: Vec<&crate::projection::Attempts> = t.attempts.iter().filter(|r| r.kind == k).collect();
        out.push(row(cap(k), &rows));
        if rows.len() > 1 { for r in &rows { out.push(row(format!("  Width {}", r.width), &[r])); } }
    }
    out
}

/// The bon processes table, its header first: one row per kind of how its bon
/// processes ended, All their sum. Expected is how many of those that pushed or
/// blocked would have blocked, were each attempt to push at the kind's success
/// probability per attempt p: the sum over them of (1-p)^k, k its attempts.
pub fn process_table(t: &crate::projection::Totals) -> Vec<Vec<String>> {
    if t.ended.is_empty() { return Vec::new(); }
    let running = t.ended.iter().any(|e| e.running > 0);
    let mut head = vec!["Bon processes", "All", "Pushed", "Blocked", "Exited"];
    if running { head.push("Running"); }
    head.push("Expected blocked");
    let mut out = vec![head.into_iter().map(String::from).collect::<Vec<_>>()];
    for e in &t.ended {
        let mut v = vec![cap(&e.kind), (e.pushed + e.blocked + e.exited + e.running).to_string(), e.pushed.to_string(), e.blocked.to_string(), e.exited.to_string()];
        if running { v.push(e.running.to_string()); }
        v.push(e.expected.map_or("—".into(), |x| format!("{:.1}", x * (e.pushed + e.blocked) as f64)));
        out.push(v);
    }
    out
}

/// Each kind's blocked attempts by reason, which sum to its Blocked; then each
/// kind's exited attempts by when they stopped, which sum to its Exited.
pub fn reason_rows(t: &crate::projection::Totals) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for (list, how) in [(&t.reasons, "blocked by"), (&t.exits, "exited")] {
        let mut kinds: Vec<&str> = list.iter().map(|r| r.kind.as_str()).collect();
        kinds.dedup();
        out.extend(kinds.into_iter().map(|k| (format!("{} {how}", cap(k)), list.iter().filter(|r| r.kind == k).map(reason_count).collect())));
    }
    out
}

/// What the outcome tables' words mean, for a key reference or a footnote.
pub const OUTCOME_NOTES: [(&str, &str); 4] = [
    ("All", "Pushed + blocked + exited (+ landed, running)"),
    ("Exited", "Its bon process stopped: on the error it recorded, or, in older traces, with no transition"),
    ("Expected", "Σ (1 − success probability per attempt)^attempts, over processes"),
    ("Inferred", "No word: the kernel's, or the sentence's"),
];

/// A table as aligned text: the first column left, the rest right.
fn aligned(rows: &[Vec<String>]) -> Vec<String> {
    let n = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    let w: Vec<usize> = (0..n).map(|i| rows.iter().map(|r| r.get(i).map_or(0, |c| c.chars().count())).max().unwrap_or(0)).collect();
    rows.iter().map(|r| {
        let mut l = format!("{:<1$}", r[0], w[0]);
        for i in 1..r.len() { l += &format!("  {:>1$}", r[i], w[i]); }
        l.trim_end().to_string()
    }).collect()
}

/// The outcome tables as aligned text, each kind's reasons, and what the words mean.
pub fn outcome_lines(t: &crate::projection::Totals) -> Vec<String> {
    let attempts = attempt_table(t);
    if attempts.is_empty() { return Vec::new(); }
    let mut lines = aligned(&attempts);
    for (label, items) in reason_rows(t) { lines.push(format!("{label}  {}", items.join(" · "))); }
    lines.push(String::new());
    lines.extend(aligned(&process_table(t)));
    lines.push(String::new());
    lines.extend(OUTCOME_NOTES.iter().map(|(k, v)| format!("{k}: {v}")));
    lines
}

/// The measures as aligned text: success probability, cost per verified
/// candidate, the run-time distribution and utilization, then each formula.
pub fn measure_lines(t: &crate::projection::Totals) -> Vec<String> {
    let mut lines = Vec::new();
    let (run, fits) = run_time_table(t);
    for table in [success_table(t), per_verified_table(t), over_tier_table(t), run] {
        if table.is_empty() { continue; }
        lines.extend(aligned(&table));
        lines.push(String::new());
    }
    if !fits.is_empty() { lines.extend(fits); lines.push(String::new()); }
    for table in [utilization_table(t), turnaround_table(t)] {
        if !table.is_empty() { lines.extend(aligned(&table)); lines.push(String::new()); }
    }
    if lines.is_empty() { return lines; }
    lines.extend(MEASURE_NOTES.iter().map(|(k, v)| format!("{k}: {v}")));
    lines
}

fn outcomes(t: &Value) -> String {
    let lines = serde_json::from_value::<crate::projection::Totals>(t.clone()).map(|t| { let mut l = outcome_lines(&t);
        let m = measure_lines(&t); if !m.is_empty() { l.push(String::new()); l.extend(m); } l }).unwrap_or_default();
    if lines.is_empty() { String::new() } else { lines.join("\n") + "\n\n" }
}

/// What a running search's agent processes are doing: `4 in flight, 2 in
/// checks, 2 waiting`, each part left out at zero; empty when all returned.
pub fn now_counts(in_flight: u64, in_checks: u64, waiting: u64) -> String {
    [(in_flight, "in flight"), (in_checks, "in checks"), (waiting, "waiting")].iter().filter(|(n, _)| *n > 0)
        .map(|(n, w)| format!("{n} {w}")).collect::<Vec<_>>().join(", ")
}

/// The projection as text, for `bon`.
pub fn text(s: &Value) -> String {
    if s["configured"] != true { return "no .bon/bon.toml at trunk's head: run bon init\n".into(); }
    let mut out = String::new();
    let r = &s["repo"];
    let t = &s["totals"];
    let opt = |v: &Value| v.as_f64().map_or("—".to_string(), money);
    // Trunk as bon works on it, the remote's ref; then generation and time side by side, then the total.
    let trunk_head = r["remote_head"].as_str().unwrap_or("");
    out.push_str(&format!("{} · trunk {}/{} {} · {} generation + {} time{} = {} · {} per verified candidate · {} per push\n\n",
        r["name"].as_str().unwrap_or(""), r["remote"].as_str().unwrap_or(""), r["trunk"].as_str().unwrap_or(""), &trunk_head[..7.min(trunk_head.len())],
        opt(&t["generation"]), opt(&t["time_cost"]), t["rate"].as_f64().map_or(String::new(), |r| format!(" at ${r:.0}/h")),
        opt(&t["cost"]), opt(&t["per_verified_candidate"]), opt(&t["per_push"])));
    // What waits on engineer, first: each pending interrupt in a line; bon pending has its choices.
    let pending: Vec<&Value> = s["interrupts"].as_array().into_iter().flatten().filter(|i| i["resolved"].is_null()).collect();
    if !pending.is_empty() {
        out.push_str(&format!("pending ({}; bon pending has the choices and what each costs)\n", pending.len()));
        for i in &pending {
            out.push_str(&format!("  {:<10} {} · raised {} ago\n      {}\n", i["kind"].as_str().unwrap_or(""), i["about"].as_str().unwrap_or(""),
                dur((s["repo"]["now"].as_i64().unwrap_or(0) - i["raised"].as_i64().unwrap_or(0)).max(0) as f64), i["what"][0].as_str().unwrap_or("")));
        }
        out.push('\n');
    }
    out.push_str(&outcomes(t));
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
        // Generation and time side by side, then the total: to the push when it pushed.
        let split = |x: &Value| format!("{} generation + {} time = {}", money(x["generation"].as_f64().unwrap_or(0.0)),
            money(x["time_cost"].as_f64().unwrap_or(0.0)), money(x["cost"].as_f64().unwrap_or(0.0)));
        let cost = match g["push"]["cost"].as_f64() {
            Some(c) if n > 1 && (c - g["cost"].as_f64().unwrap_or(0.0)).abs() >= 0.005 => format!("{} cost; {} for the push", split(g), split(&g["push"])),
            Some(_) => format!("{} to push", split(&g["push"])),
            None => format!("{} cost", split(g)),
        };
        out.push_str(&format!("  {:<14} {:<9} {}\n      {}\n      {}{cost}\n",
            g["kind"].as_str().unwrap_or(""), g["outcome"].as_str().unwrap_or(""), g["title"].as_str().unwrap_or(""),
            g["sentence"].as_str().unwrap_or(""), if n > 1 { format!("{n} bon processes · ") } else { String::new() }));
        // A blocked search's protected change, which search found but may not make: for the model.
        let protected: Vec<String> = serde_json::from_value(s["protected"].clone()).unwrap_or_default();
        let traced: crate::projection::GoalTrace = serde_json::from_value(g.clone()).unwrap_or_default();
        for search in traced.processes.iter().flat_map(|p| &p.searches).filter(|x| x.blocked.is_some()) {
            if let Some((files, diff)) = crate::tui::needed(search, &protected) {
                out.push_str(&format!("      every accepted, proved candidate changed protected {}: review and apply: {diff}\n", files.join(", ")));
            }
        }
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
    outline(file, &git(root, &["show", &format!("HEAD:{file}")]))
}

/// The spec file's outline: its state machine's fields, and each item (type,
/// predicate, transition, property, invariant) with its doc, as Verus expresses it.
pub fn outline(file: &str, text: &str) -> Value {
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
        if l.starts_with("fields {") {
            // Fields on the same line as `fields {` and its close: read them there.
            if let Some(inner) = l.strip_prefix("fields {").and_then(|r| r.trim_end().strip_suffix('}')) {
                for part in inner.split(',').filter(|p| p.contains(':')) {
                    let p = part.split("pub ").nth(1).unwrap_or(part);
                    if let Some((name, ty)) = p.split_once(':') {
                        let sharding = part.split("sharding(").nth(1).and_then(|s| s.split(')').next()).unwrap_or("");
                        fields.push(json!({ "name": name.trim(), "type": ty.trim(), "sharding": sharding, "doc": "" }));
                    }
                }
            } else { in_fields = true; }
            doc.clear(); i += 1; continue;
        }
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

/// The spec and how it reaches the code, found from the repository's own manifest
/// and syntax, never from file names: the spec is the `checks.paths` file with a
/// state machine; the gates are each `pub trait` in `checks.paths` whose contracts
/// cite `spec::`; an implementation is an `impl <gate trait> for` anywhere; a driver
/// is a function that fires a transition; entry points and targets are the
/// `[account] trusted` files that reach a driver or a gate; trusted functions are the
/// `external_body` ones a driver calls; emitted types are `[types] from`'s
/// declarations, and programs are the files that import a `[types] types`
/// target. Read from the working tree; each item is marked where it differs from trunk.
pub fn system(root: &Path, base: &str, manifest: &toml::Value) -> Value {
    let read = |f: &str| std::fs::read_to_string(root.join(f)).unwrap_or_default();
    let list = |v: Option<&toml::Value>| -> Vec<String> { v.and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default() };
    let checks = list(manifest.get("checks").and_then(|c| c.get("paths")));
    let trusted_files = list(manifest.get("account").and_then(|s| s.get("trusted")));
    let from = list(types_table(manifest).and_then(|p| p.get("from")));
    let targets: Vec<String> = types_table(manifest).and_then(|p| p.get("types")).and_then(|t| t.as_table())
        .map(|t| t.values().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    let tracked: Vec<String> = git(root, &["ls-files"]).lines().map(String::from).collect();
    let rust: Vec<&String> = tracked.iter().filter(|f| f.ends_with(".rs")).collect();
    let Some(spec_file) = checks.iter().find(|p| p.ends_with(".rs") && read(p).contains("state_machine!")).cloned() else { return Value::Null };
    let spec_t = read(&spec_file);
    let changed = hunks(&git(root, &["diff", "-U0", base]));
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
    // Each `keyword …;` or `keyword …,` clause of a contract, verbatim, one line each.
    let clauses = |body: &str, keyword: &str| -> Vec<String> {
        let Some(rest) = body.split_once(&format!("{keyword}\n")).map(|(_, r)| r).or_else(|| body.split_once(&format!("{keyword} ")).map(|(_, r)| r)) else { return Vec::new() };
        let stop = ["requires", "ensures", "decreases", "{", "recommends"];
        let mut out = Vec::new();
        let mut cur = String::new();
        for l in rest.lines() {
            let t = l.trim();
            if stop.iter().any(|s| t.starts_with(s) && *s != keyword) || t.is_empty() { break; }
            cur.push_str(if cur.is_empty() { "" } else { " " }); cur.push_str(t);
            if t.ends_with(',') || t.ends_with(';') { out.push(cur.trim_end_matches([',', ';']).to_string()); cur.clear(); }
            if t.ends_with(';') { break; }
        }
        if !cur.is_empty() { out.push(cur.trim_end_matches([',', ';']).to_string()); }
        out
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
        let mut k = i;
        while k > 0 && spec_lines[k - 1].trim().starts_with("///") { k -= 1; }
        let doc = if k < i { spec_lines[k].trim().trim_start_matches("///").trim().to_string() } else { String::new() };
        let guards: Vec<String> = preds.iter().filter(|p| body.split("require").skip(1).any(|r| calls(r.split(';').next().unwrap_or(""), "", &p.name))).map(|p| p.name.clone()).collect();
        let token = |op: &str| body.lines().filter_map(|b| b.trim().strip_prefix(op).and_then(|r| r.split_whitespace().next()).map(String::from)).collect::<Vec<_>>();
        let f = Fn { name: name.clone(), start: i + 1, end: j + 1, doc, body: String::new(), public: true };
        transitions.push(node(format!("spec:{name}"), "spec", if t.starts_with("init") { "init" } else { "transition" }, &name, &spec_file, Some(&f),
            json!({ "guards": guards, "adds": token("add "), "removes": token("remove ") })));
    }
    let mut rules: Vec<Value> = spec_lines.iter().enumerate().filter(|(_, l)| l.trim().starts_with("property!{"))
        .filter_map(|(i, l)| {
            let name = l.trim().trim_start_matches("property!{").trim().split('(').next()?.trim().to_string();
            let f = Fn { name: name.clone(), start: i + 1, end: i + 1, doc: String::new(), body: String::new(), public: true };
            Some(node(format!("spec:{name}"), "spec", "property", &name, &spec_file, Some(&f), json!({})))
        }).collect();
    rules.extend(spec_lines.iter().enumerate().filter(|(_, l)| l.trim() == "#[invariant]")
        .filter_map(|(i, _)| spec_fns.iter().find(|f| f.start == i + 2))
        .map(|f| node(format!("spec:{}", f.name), "spec", "invariant", &f.name, &spec_file, Some(f), json!({}))));

    // ── gates: each `pub trait` in the checks whose methods' contracts cite spec::.
    let mut gate_names: Vec<String> = Vec::new();
    let mut gate_traits: Vec<String> = Vec::new();
    let mut cited: Vec<String> = Vec::new();
    for file in checks.iter().filter(|p| p.ends_with(".rs") && **p != spec_file) {
        let text = read(file);
        let lines: Vec<&str> = text.lines().collect();
        for f in fns(&text).iter().filter(|f| lines[f.start - 1].starts_with(' ')) {
            let block = lines[..f.start - 1].iter().rev().find(|l| l.starts_with("pub trait ") || l.starts_with("impl")).copied().unwrap_or("");
            let Some(tr) = block.strip_prefix("pub trait ").map(|r| r.split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("").to_string()) else { continue };
            let cites: Vec<&&Fn> = preds.iter().filter(|p| calls(&f.body, "spec::", &p.name)).collect();
            let contract = f.body.contains("ensures") || f.body.contains("requires");
            if !contract { continue; }
            if !gate_traits.contains(&tr) { gate_traits.push(tr.clone()); }
            nodes.push(node(format!("gate:{}", f.name), "gates", &tr, &f.name, file, Some(f),
                json!({ "proof": f.body.contains("proof fn"), "requires": clauses(&f.body, "requires"), "ensures": clauses(&f.body, "ensures") })));
            for p in cites { edges.push(json!([format!("gate:{}", f.name), format!("spec:{}", p.name), "ensures"])); if !cited.contains(&p.name) { cited.push(p.name.clone()); } }
            gate_names.push(f.name.clone());
        }
    }

    // ── the types emitted for programs: `[types] from`'s declarations.
    let mut type_names = Vec::new();
    for file in &from {
        let text = read(file);
        let lines: Vec<&str> = text.lines().collect();
        for (at, l) in lines.iter().enumerate() {
            let Some(rest) = ["pub struct ", "pub enum ", "pub type "].iter().find_map(|k| l.strip_prefix(k)) else { continue };
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            let mut k = at;
            while k > 0 && lines[k - 1].trim().starts_with("///") { k -= 1; }
            let doc = if k < at { lines[k].trim().trim_start_matches("///").trim().to_string() } else { String::new() };
            let f = Fn { name: name.clone(), start: at + 1, end: at + 1, doc, body: String::new(), public: true };
            nodes.push(node(format!("type:{name}"), "gates", "types", &name, file, Some(&f), json!({})));
            type_names.push(name);
        }
    }

    // ── implementation: each `impl <gate trait> for`, anywhere; its methods, at the free fn they delegate to.
    let mut kernel_names: Vec<String> = Vec::new();
    let mut impl_files: Vec<String> = Vec::new();
    let mut private = 0usize;
    for file in rust.iter().filter(|f| !checks.contains(f) && !trusted_files.contains(f)) {
        let text = read(file);
        let lines: Vec<&str> = text.lines().collect();
        let all = fns(&text);
        let mut found = false;
        for (at, l) in lines.iter().enumerate() {
            let Some(tr) = l.strip_prefix("impl ").and_then(|r| r.split(" for ").next()).map(|t| t.split('<').next().unwrap_or("").trim().to_string()) else { continue };
            if !gate_traits.contains(&tr) { continue; }
            found = true;
            for m in all.iter().filter(|m| m.start > at + 1 && lines[m.start - 1].starts_with(' ') && gate_names.contains(&m.name)) {
                if lines[at + 1..m.start - 1].iter().any(|x| x.starts_with("impl ") || x.starts_with('}')) { continue; }
                let target = all.iter().find(|f| f.name == m.name && !lines[f.start - 1].starts_with(' ')).unwrap_or(m);
                let uses: Vec<String> = all.iter().filter(|h| !h.public && h.name != target.name && calls(&target.body, "", &h.name)).map(|h| h.name.clone()).collect();
                nodes.push(node(format!("kernel:{}", m.name), "implementation", &tr, &m.name, file, Some(target), json!({ "uses": uses })));
                edges.push(json!([format!("kernel:{}", m.name), format!("gate:{}", m.name), "implements"]));
                kernel_names.push(m.name.clone());
            }
        }
        if found { private += all.iter().filter(|f| !f.public).count(); impl_files.push(file.to_string()); }
    }

    // ── drivers: the functions that fire a transition, and what they call.
    let stem = |f: &str| Path::new(f).file_stem().map_or(String::new(), |s| s.to_string_lossy().to_string());
    let trusted_fns: Vec<(String, Fn)> = trusted_files.iter().filter(|f| f.ends_with(".rs"))
        .flat_map(|f| { let text = read(f); let lines: Vec<String> = text.lines().map(String::from).collect();
            fns(&text).into_iter().filter(|x| x.start >= 2 && lines[x.start - 2].trim().starts_with("#[verifier::external_body]")).map(|x| (f.clone(), x)).collect::<Vec<_>>() })
        .collect();
    let mut trusted_used: Vec<(String, String)> = Vec::new();
    let mut drivers: Vec<(String, String)> = Vec::new();
    for file in rust.iter().filter(|f| !checks.contains(f) && !trusted_files.contains(f)) {
        let all = fns(&read(file));
        for f in &all {
            let fires: Vec<&Value> = transitions.iter().filter(|t| { let n = t["name"].as_str().unwrap_or(""); f.body.contains(&format!("instance.{n}(")) || f.body.contains(&format!("Instance::{n}(")) }).collect();
            let gates_called: Vec<&String> = if impl_files.contains(file) { Vec::new() } else { kernel_names.iter().filter(|g| calls(&f.body, "", g)).collect() };
            if fires.is_empty() && gates_called.is_empty() { continue; }
            let trusted: Vec<String> = trusted_fns.iter().filter(|(tf, t)| calls(&f.body, &format!("{}::", stem(tf)), &t.name)).map(|(_, t)| t.name.clone()).collect();
            for (tf, t) in &trusted_fns { if trusted.contains(&t.name) && !trusted_used.iter().any(|(a, b)| a == tf && *b == t.name) { trusted_used.push((tf.clone(), t.name.clone())); } }
            let id = format!("driver:{}", f.name);
            nodes.push(node(id.clone(), "process", &stem(file), &f.name, file, Some(f), json!({ "trusted": trusted })));
            for t in fires { edges.push(json!([id, t["id"], "transition"])); }
            for g in gates_called { edges.push(json!([id, format!("kernel:{g}"), "calls"])); }
            for d in all.iter().filter(|d| d.name != f.name && calls(&f.body, "", &d.name)) { edges.push(json!([id, format!("driver:{}", d.name), "calls"])); }
            drivers.push((file.to_string(), f.name.clone()));
        }
    }

    // The public functions of an implementation file that a driver calls, beside the gates.
    let driver_bodies: Vec<String> = rust.iter().filter(|f| !checks.contains(f) && !trusted_files.contains(f) && !impl_files.contains(f))
        .flat_map(|f| fns(&read(f)).into_iter().filter(|d| drivers.iter().any(|(_, n)| *n == d.name)).map(|d| d.body)).collect();
    for file in &impl_files {
        let text = read(file);
        let lines: Vec<&str> = text.lines().collect();
        for f in fns(&text).iter().filter(|f| f.public && !lines[f.start - 1].starts_with(' ') && !kernel_names.contains(&f.name)) {
            if !driver_bodies.iter().any(|b| calls(b, "", &f.name)) { continue; }
            nodes.push(node(format!("kernel:{}", f.name), "implementation", "called by drivers", &f.name, file, Some(f), json!({ "uses": [] })));
            for (df, d) in &drivers { if fns(&read(df)).iter().any(|x| x.name == *d && calls(&x.body, "", &f.name)) { edges.push(json!([format!("driver:{d}"), format!("kernel:{}", f.name), "calls"])); } }
        }
    }

    // ── entry points and targets: the trusted files that reach a driver or a gate.
    let whole = |text: &str| Fn { name: String::new(), start: 1, end: text.lines().count().max(1), doc: text.lines().find(|l| l.starts_with("//!")).unwrap_or("").trim_start_matches("//!").trim().to_string(), body: text.to_string(), public: true };
    let mut exported = Vec::new();
    for file in trusted_files.iter().filter(|f| f.ends_with(".rs")) {
        let text = read(file);
        let externs: Vec<Fn> = fns(&text).into_iter().filter(|f| f.body.contains("extern \"C\"")).collect();
        let mut reached = false;
        for f in &externs {
            let called: Vec<&String> = gate_names.iter().filter(|g| calls(&f.body, "::", g)).collect();
            if called.is_empty() { continue; }
            reached = true;
            nodes.push(node(format!("target:{}", f.name), "target", &stem(file), &f.name, file, Some(f), json!({})));
            for g in called { if kernel_names.contains(g) { edges.push(json!([format!("target:{}", f.name), format!("kernel:{g}"), "calls"])); } }
            exported.push(f.name.clone());
        }
        if reached { continue; }
        let to_drivers: Vec<&(String, String)> = drivers.iter().filter(|(df, d)| calls(&text, &format!("{}::", stem(df)), d)).collect();
        let to_gates: Vec<&String> = gate_names.iter().filter(|g| calls(&text, "::", g)).collect();
        if to_drivers.is_empty() && to_gates.is_empty() { continue; }
        let id = format!("entry:{}", stem(file));
        nodes.push(node(id.clone(), "entry", &stem(file), file, file, Some(&whole(&text)), json!({})));
        for (_, d) in to_drivers { edges.push(json!([id, format!("driver:{d}"), "calls"])); }
        for g in to_gates { if kernel_names.contains(g) { edges.push(json!([id, format!("kernel:{g}"), "calls"])); } }
    }

    // ── programs: the files that import a `[types] types` target.
    for target in &targets {
        let module = stem(target);
        let dir = Path::new(target).parent().map_or(String::new(), |d| d.to_string_lossy().to_string());
        let dirname = stem(&dir);
        // A program is in the target's own language.
        let ext = Path::new(target).extension().map_or(String::new(), |e| e.to_string_lossy().to_string());
        for file in tracked.iter().filter(|f| *f != target && f.ends_with(&format!(".{ext}"))) {
            let text = read(file);
            let imported: Vec<String> = text.lines().filter_map(|l| {
                let t = l.trim();
                if file.ends_with(".ts") && (t.contains(&format!("from './{module}'")) || t.contains(&format!("from \"./{module}\""))) { Some(t.split('{').nth(1)?.split('}').next()?.to_string()) }
                else if file.ends_with(".py") && t.starts_with(&format!("from {module} import ")) { Some(t[format!("from {module} import ").len()..].to_string()) }
                else { None }
            }).flat_map(|names| names.split(',').map(|n| n.trim().split_whitespace().next().unwrap_or("").to_string()).collect::<Vec<_>>()).collect();
            let go = file.ends_with(".go") && text.contains(&format!("/{dirname}\""));
            if imported.is_empty() && !go { continue; }
            let id = format!("program:{file}");
            let lang = if file.ends_with(".ts") { "typescript" } else if file.ends_with(".go") { "go" } else { "python" };
            nodes.push(node(id.clone(), "program", lang, file, file, Some(&whole(&text)), json!({})));
            let used: Vec<&String> = if go { type_names.iter().filter(|t| text.contains(&format!("{dirname}.{t}"))).collect() } else { type_names.iter().filter(|t| imported.contains(t)).collect() };
            for t in used { edges.push(json!([id, format!("type:{t}"), "types"])); }
            for w in exported.iter().filter(|w| text.contains(&format!("call('{w}'"))) { edges.push(json!([id, format!("target:{w}"), "calls"])); }
        }
    }

    // Spec nodes: the transitions, the predicates the gates cite, the rules; then the rest.
    let mut spec_nodes = transitions;
    for p in preds.iter().filter(|p| cited.contains(&p.name)) { spec_nodes.push(node(format!("spec:{}", p.name), "spec", "predicate", &p.name, &spec_file, Some(p), json!({}))); }
    spec_nodes.extend(rules);
    spec_nodes.extend(nodes);
    let trusted: Vec<Value> = trusted_fns.iter().filter(|(tf, t)| trusted_used.iter().any(|(a, b)| a == tf && *b == t.name))
        .map(|(tf, t)| json!({ "name": t.name, "file": tf, "line": t.start, "doc": t.doc, "changed": hit(tf, t.start, t.end) })).collect();
    json!({ "nodes": spec_nodes, "edges": edges, "trusted": trusted,
        "counts": { "predicates": preds.len(), "private": private, "trusted": trusted_fns.len() } })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A search as the projection holds it: its kind, and whether it reported.
    fn s(kind: &str, reported: bool) -> Value { json!({ "kind": kind, "time": if reported { json!(1) } else { Value::Null } }) }
    fn ls(v: &[&[&str]]) -> Vec<Vec<String>> { v.iter().map(|l| l.iter().map(|x| x.to_string()).collect()).collect() }
    fn none(_: usize, _: Option<usize>, _: Option<usize>) -> Option<&'static str> { None }
    fn end(e: &'static str, reason: Option<&str>, from: Option<&'static str>) -> End { End { end: e, reason: reason.map(String::from), from } }

    #[test]
    fn a_running_search_s_goal_is_read_from_its_grant_line_with_its_context_line_after_it() {
        // queue 73: the context is a line of its own after the grant, so the grant's tail is still the goal.
        let root = std::env::temp_dir().join(format!("bon-view-context-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let d = root.join(".bon/traces/4242");
        std::fs::create_dir_all(d.join("0")).unwrap();
        std::fs::write(d.join("transitions"), "initialize c0ffee 1\ngrant 2 0 1 code c0ffee\ncontext c0ffee 1a2b3c\n").unwrap();
        let state = state(&root, &Filter::default());
        let goals: Vec<String> = state["groups"].as_array().into_iter().flatten()
            .flat_map(|g| g["processes"].as_array().cloned().unwrap_or_default())
            .flat_map(|p| p["searches"].as_array().cloned().unwrap_or_default())
            .map(|x| x["goal"].as_str().unwrap_or("").to_string()).collect();
        assert_eq!(goals, ["c0ffee"], "{state}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn every_attempt_ends_one_way() {
        // A block in today's words, then a block in an old sentence, then a push.
        let mut searches = [s("code", true), s("foil", true), s("counterexample", true), s("code", true), s("foil", true), s("counterexample", true), s("code", true), s("counterexample", true)];
        searches[5]["recorded_verified"] = json!(1);
        let lines = ls(&[&["grant"], &["grant"], &["grant", "blocked: undiscriminating: fewer than two verified tests judge every candidate and reject a foil"],
            &["grant"], &["grant"], &["grant", "blocked: fewer than two verified tests, and none splits the candidates"], &["grant"], &["grant", "push 6 1 7"]]);
        let ends: Vec<End> = attempt_ends(&searches, &lines, false, &none).into_iter().map(|(_, e)| e).collect();
        assert_eq!(ends, [end("blocked", Some("undiscriminating"), Some("recorded")), end("blocked", Some("too_few_tests"), Some("sentence")), end("pushed", None, None)]);
        // The kernel's reason comes before a sentence's.
        let kernel = |_: usize, _: Option<usize>, _: Option<usize>| Some("rejects_every");
        assert_eq!(attempt_ends(&searches, &lines, false, &kernel)[1].1, end("blocked", Some("rejects_every"), Some("kernel")));
    }

    #[test]
    fn an_attempt_whose_candidates_disagree_ends_in_its_counterexample_search() {
        // No selection, no foil search: a counterexample search on the code search, then a landing or a block.
        let searches = [s("code", true), s("counterexample", true), s("code", true), s("counterexample", true)];
        let lines = ls(&[&["grant", "disagreed 0 1"], &["grant", "land 1 3"], &["grant", "disagreed 2 0"],
            &["grant", "blocked: undecided: the verified candidates disagree, two tests judged every one, and none splits them: the spec does not decide between them"]]);
        let ends: Vec<End> = attempt_ends(&searches, &lines, false, &none).into_iter().map(|(_, e)| e).collect();
        assert_eq!(ends, [end("landed", None, None), end("blocked", Some("undecided"), Some("recorded"))]);
        assert_eq!(by_sentence(REASONS[1].1, &json!({}), None), Some("undecided"));
        // An older trace's disagree, an immediate block with no tests, keeps its own word.
        let old = attempt_ends(&[s("code", true)], &ls(&[&["grant", "blocked: disagree: the verified candidates disagree"]]), false, &none);
        assert_eq!(old[0].1, end("blocked", Some("disagree"), Some("recorded")));
    }

    #[test]
    fn an_attempt_its_bon_process_stopped_in_exited() {
        // Stopped during its search, or after its searches reported with no transition.
        let during = attempt_ends(&[s("code", true), s("code", false)], &ls(&[&["grant", "blocked: too_few_verified: fewer than two verified candidates"], &["grant"]]), false, &none);
        assert_eq!(during[1].1, end("exited", Some("during_a_search"), None));
        let after = attempt_ends(&[s("code", true), s("counterexample", true)], &ls(&[&["grant"], &["grant"]]), false, &none);
        assert_eq!(after[0].1, end("exited", Some("after_its_searches"), None));
        // Running, it has not ended; followed by another attempt with no line, it blocked for no recorded reason.
        assert_eq!(attempt_ends(&[s("code", false)], &ls(&[&["grant"]]), true, &none)[0].1, end("running", None, None));
        assert_eq!(attempt_ends(&[s("code", true), s("code", true)], &ls(&[&["grant"], &["grant", "push"]]), false, &none)[0].1, end("blocked", None, None));
    }

    #[test]
    fn an_old_sentence_that_named_two_reasons_is_told_apart_by_the_recorded_count() {
        let sentence = "fewer than two verified candidates, or they disagree";
        assert_eq!(by_sentence(sentence, &json!({ "recorded_verified": 0, "verified": 8 }), None), Some("too_few_verified"));
        assert_eq!(by_sentence(sentence, &json!({ "recorded_verified": 5 }), None), Some("disagree"));
        // Fewer than two verified tests is today's too_few_tests; two that split nothing, none_splits.
        let tests = "fewer than two verified tests, and none splits the candidates";
        assert_eq!(by_sentence(tests, &json!({}), Some(&json!({ "recorded_verified": 0 }))), Some("too_few_tests"));
        assert_eq!(by_sentence(tests, &json!({}), Some(&json!({ "recorded_verified": 2 }))), Some("none_splits"));
        assert_eq!(by_sentence("a verified test rejects every candidate", &json!({}), None), Some("rejects_every"));
        assert_eq!(by_sentence("something else", &json!({}), None), None);
    }

    #[test]
    fn a_retired_intent_is_the_latest_commit_that_took_it_off() {
        let log = "\0bbb 20 queue: 28 reworded; 36 is in the spec\n\ndiff\n--- a/.bon/queue.tsv\n+++ b/.bon/queue.tsv\n-28\tolder words\n+28\tnewer words\n-36\tbon works on git's objects\n\
                   \0aaa 10 queue: 36, 37\n\ndiff\n--- a/.bon/queue.tsv\n+++ b/.bon/queue.tsv\n-36\tbon works on git's objects\n-37\tchecks run with root's toolchain\n";
        let r = retired_in(log, &[28]);
        // 28 was reworded and is queued; 36's latest removal is bbb; 37 left in aaa.
        assert_eq!(r.len(), 2);
        assert_eq!((r[0]["id"].as_u64(), r[0]["commit"].as_str(), r[0]["subject"].as_str()), (Some(36), Some("bbb"), Some("queue: 28 reworded; 36 is in the spec")));
        assert_eq!((r[1]["id"].as_u64(), r[1]["intent"].as_str(), r[1]["time"].as_u64()), (Some(37), Some("checks run with root's toolchain"), Some(10)));
    }

    /// A bon process of `kind` that ended `outcome`, its attempts each ended as given.
    fn process(kind: &str, outcome: &str, ends: &[(&str, Option<&str>, Option<&str>)]) -> Value {
        json!({ "outcome": outcome, "searches": ends.iter().map(|(e, r, f)| json!({ "kind": kind, "width": 8, "end": e, "reason": r, "reason_from": f })).collect::<Vec<_>>() })
    }

    #[test]
    fn older_and_newer_trace_keys_read_by_presence() {
        // The one shape: a newer trace's five keys as written; an older one's from what it recorded.
        let newer = json!({ "program": "bon-sample", "context": "prompt", "output": "c1", "verdict": "proved", "behavior": "7,9", "candidate": { "accepted": false } });
        assert_eq!(record_of(&newer, &[]), json!({ "program": "bon-sample", "context": "prompt", "output": "c1", "verdict": "proved", "behavior": "7,9" }));
        let older = json!({ "harness": "claude", "candidate": { "commit": "c2", "accepted": true, "proved": false, "out": [] } });
        assert_eq!(record_of(&older, &["argv".into(), "prompt".into()]), json!({ "program": "claude", "context": "prompt", "output": "c2", "verdict": "accepted", "behavior": null }));
        assert_eq!(record_of(&json!({ "harness": "codex", "candidate": null }), &[]), json!({ "program": "codex", "context": null, "output": null, "verdict": null, "behavior": null }));
        // program: the newer word; harness: an older trace's.
        assert_eq!(program_of(&json!({ "program": "codex", "harness": "old" })), json!("codex"));
        assert_eq!(program_of(&json!({ "harness": "claude" })), json!("claude"));
        // added: a count in older traces; the added paths in newer ones, with lines_added and lines_removed.
        assert_eq!(line_counts(&json!({ "added": 5, "removed": 9, "added_paths": [] })), (Some(5), Some(9)));
        assert_eq!(line_counts(&json!({ "added": ["src/a.rs"], "lines_added": 3, "lines_removed": 1 })), (Some(3), Some(1)));
        assert_eq!(line_counts(&json!({ "added": ["src/a.rs"] })), (None, None));
        assert_eq!(exit_error("exited: git refused: no such ref"), Some("git refused: no such ref"));
        assert_eq!(exit_error("blocked: undecided: …"), None);
        assert_eq!(pool_sizes(&json!({ "agent_processes": 8 })), (None, None));
        assert_eq!(pool_sizes(&json!({ "host": { "agent_processes": 16, "check_processes": 6 } })), (Some(16), Some(6)));
        let m = |t: &str| -> toml::Value { toml::from_str(t).unwrap() };
        assert!(types_table(&m("[types]\nfrom = [\"a\"]\n[programs]\nfrom = [\"b\"]")).unwrap().get("from").unwrap().as_array().unwrap()[0].as_str() == Some("a"));
        assert!(types_table(&m("[programs]\nfrom = [\"b\"]")).unwrap().get("from").is_some());
    }

    /// A directory of its own for one test, removed when it is dropped.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(name: &str) -> Scratch {
            let d = std::env::temp_dir().join(format!("best-of-n-view-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Scratch(d)
        }
    }
    impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

    #[test]
    fn a_cached_check_holds_no_seconds_and_a_running_agent_process_has_a_stage() {
        let d = Scratch::new("logs");
        std::fs::write(d.0.join("test-0"), "exit: 0\nseconds: 9.5\n--- stdout\n").unwrap();
        std::fs::write(d.0.join("test-1"), "cached: 33860f\nexit: 0\nseconds: 3.1\n").unwrap();
        std::fs::write(d.0.join("program"), "exit: 0\nseconds: 40.0\n").unwrap();
        assert_eq!(log_seconds(&d.0.join("test-0")), Some(9.5));
        assert_eq!(log_seconds(&d.0.join("test-1")), None);
        // The program's log is no check, by either name.
        assert_eq!(check_seconds(&d.0, ["test-0", "test-1", "program"].into_iter()), Some(9.5));
        assert_eq!(program_seconds(&d.0), Some(40.0));
        // Waiting, in flight, in checks, returned: by what its directory holds so far.
        let a = Scratch::new("stage");
        assert_eq!(stage(&a.0), "waiting");
        std::fs::write(a.0.join("argv"), "x").unwrap();
        assert_eq!(stage(&a.0), "in_flight");
        std::fs::write(a.0.join("harness"), "exit: 0\nseconds: 1.0\n").unwrap();
        assert_eq!(stage(&a.0), "in_checks");
        std::fs::write(a.0.join("facts.json"), "{}").unwrap();
        assert_eq!(stage(&a.0), "returned");
        assert_eq!(now_counts(4, 0, 2), "4 in flight, 2 waiting");
        assert_eq!(now_counts(0, 0, 0), "");
    }

    #[test]
    fn an_exit_the_trace_records_is_its_attempts_reason() {
        let ends = attempt_ends(&[s("code", false)], &ls(&[&["grant", "exited: git push refused"]]), false, &none);
        assert_eq!(ends[0].1, end("exited", Some("git push refused"), Some("recorded")));
        // Read as written, not as a word.
        assert_eq!(reason_count(&crate::projection::Reason { reason: "no such file: a_b".into(), count: 2, ..Default::default() }), "No such file: a_b (2)");
    }

    /// A candidate: verified or not, its out and its tree.
    fn cand(verified: bool, out: u64, tree: Option<&str>) -> Value {
        json!({ "verified": verified, "accepted": true, "proved": verified, "out": [out], "commit": "c", "tree": tree })
    }

    #[test]
    fn agent_processes_per_behavior_and_distinct_trees_count_what_the_candidates_show() {
        let cs = [cand(true, 7, Some("t1")), cand(true, 8, Some("t1")), cand(false, 9, Some("t2")), cand(true, 7, Some("t3"))];
        // Two behaviors: 7 shown by two verified, 8 by one; the unverified one shows none.
        assert_eq!(behaviors(&cs), vec![2, 1]);
        assert_eq!(distinct_trees(&cs), Some(3));
        // A tree git does not know leaves the count unknown; a candidate with no commit wrote none.
        assert_eq!(distinct_trees(&[cand(true, 1, None)]), None);
        assert_eq!(distinct_trees(&[json!({ "verified": false })]), Some(0));
    }

    /// A reported search of a bon process, as the measures read it.
    fn search(kind: &str, width: u64, verified: u64, end: Option<&str>) -> Value {
        json!({ "kind": kind, "width": width, "verified": verified, "end": end, "time": 1, "candidates": [] })
    }

    #[test]
    fn success_probability_counts_agent_processes_and_attempts_by_kind_and_attempt() {
        let foil = json!({ "kind": "foil", "width": 3, "time": 1, "candidates": [
            { "accepted": true, "proved": false }, { "accepted": true, "proved": true }, { "accepted": false } ] });
        let ps = [json!({ "searches": [search("code", 8, 6, Some("blocked")), foil, search("counterexample", 2, 1, None),
                                       search("code", 12, 12, Some("pushed")), search("counterexample", 2, 2, None)] }),
                  // An attempt its bon process exited in ended no way; a search that did not report counts no agent processes.
                  json!({ "searches": [json!({ "kind": "code", "width": 8, "verified": 3, "end": "exited", "time": null })] })];
        let rows = success(&ps);
        let row = |kind: &str, at: Option<u64>| rows.iter().find(|r| r["kind"] == kind && r["attempt"] == json!(at)).cloned().unwrap();
        // Code: 18 of 20 agent processes verified; 1 of the 2 attempts that ended pushed.
        assert_eq!((row("code", None)["agent_processes"].as_u64(), row("code", None)["successes"].as_u64(), row("code", None)["ended"].as_u64(), row("code", None)["pushed"].as_u64()), (Some(20), Some(18), Some(2), Some(1)));
        assert_eq!((row("code", Some(1))["ended"].as_u64(), row("code", Some(1))["pushed"].as_u64(), row("code", Some(2))["pushed"].as_u64()), (Some(1), Some(0), Some(1)));
        // A foil search's successes are its foils: accepted, not proved.
        assert_eq!(row("foil", Some(1))["successes"].as_u64(), Some(1));
        assert_eq!(row("counterexample", Some(2))["successes"].as_u64(), Some(2));
        let t: crate::projection::Totals = serde_json::from_value(json!({ "success": rows })).unwrap();
        let table = success_table(&t);
        assert_eq!(table[1], ["Code", "90% (18 of 20)", "50% (1 of 2)"]);
        assert_eq!(table[2], ["  Attempt 1", "75% (6 of 8)", "0% (0 of 1)"]);
        assert!(table.iter().any(|r| r[0] == "Counterexample" && r[2] == "—"));
    }

    #[test]
    fn cost_per_verified_candidate_shares_a_searchs_time_by_its_agent_processes() {
        let c = |program: &str, verified: bool, g: f64| json!({ "program": program, "model": "m", "verified": verified, "generation": g });
        let ps = [json!({ "searches": [{ "kind": "code", "time_cost": 30.0, "candidates": [c("a", true, 1.0), c("a", true, 1.0), c("b", false, 4.0)] }] })];
        let rows = per_verified(&ps);
        // a: 2 of the 3 agent processes, so 20 of the 30 time; b: 10.
        assert_eq!((rows[0]["program"].as_str(), rows[0]["generation"].as_f64(), rows[0]["time_cost"].as_f64(), rows[0]["verified"].as_u64()), (Some("a"), Some(2.0), Some(20.0), Some(2)));
        assert_eq!(rows[1]["time_cost"].as_f64(), Some(10.0));
        let t: crate::projection::Totals = serde_json::from_value(json!({ "per_verified": rows })).unwrap();
        let table = per_verified_table(&t);
        assert_eq!(table[1][..3], ["Code · a · m", "$11.00", "2"]);
        // None verified: no cost per verified candidate.
        assert_eq!(table[2][1], "—");
    }

    #[test]
    fn utilization_is_held_slot_seconds_over_size_times_the_union_of_wall_times() {
        assert_eq!(union_length(vec![(0.0, 10.0), (5.0, 15.0), (20.0, 25.0), (21.0, 22.0)]), 20.0);
        let sr = |started: f64, seconds: f64, size: Option<u64>| json!({ "time": 1, "started": started, "seconds": seconds,
            "pools": { "agent_processes": size, "check_processes": null },
            "candidates": [{ "program_seconds": 30.0, "check_seconds": 4.0 }, { "program_seconds": 10.0 }] });
        let u = utilization(&[json!({ "searches": [sr(0.0, 20.0, Some(4)), sr(10.0, 20.0, Some(4)), json!({ "time": null, "started": 100.0, "seconds": 50.0 })] })]);
        // Wall 30 (0 to 30); 80 agent slot-seconds; 8 check slot-seconds; size 4 recorded by both, check size by none.
        assert_eq!((u["wall"].as_f64(), u["agent_processes"]["held"].as_f64(), u["check_processes"]["held"].as_f64()), (Some(30.0), Some(80.0), Some(8.0)));
        assert_eq!((u["agent_processes"]["size"].as_u64(), u["check_processes"]["size"].as_u64()), (Some(4), None));
        let t: crate::projection::Totals = serde_json::from_value(json!({ "utilization": u })).unwrap();
        let table = utilization_table(&t);
        assert_eq!(table[1], ["agent_processes", "1m20s", "30s", "2.67", "4", "67%"]);
        assert_eq!(table[2], ["check_processes", "8s", "30s", "0.27", "—", "—"]);
        // Sizes that differ between searches are no one size.
        let v = utilization(&[json!({ "searches": [sr(0.0, 20.0, Some(4)), sr(10.0, 20.0, Some(8))] })]);
        assert!(v["agent_processes"]["size"].is_null());
        // A trace from before sizes were recorded: utilization over the searches that record one, said so.
        let w = utilization(&[json!({ "searches": [sr(0.0, 20.0, None), sr(40.0, 10.0, Some(4))] })]);
        assert_eq!((w["agent_processes"]["size"].as_u64(), w["agent_processes"]["sized"].as_u64(), w["agent_processes"]["utilization"].as_f64()), (Some(4), Some(1), Some(1.0)));
        let t: crate::projection::Totals = serde_json::from_value(json!({ "utilization": w })).unwrap();
        assert_eq!(utilization_table(&t)[1][5], "100% (1 of 2 searches)");
        // No size recorded anywhere: no Size or Utilization column.
        let t: crate::projection::Totals = serde_json::from_value(json!({ "utilization": utilization(&[json!({ "searches": [sr(0.0, 20.0, None)] })]) })).unwrap();
        assert_eq!(utilization_table(&t)[0].len(), 4);
    }

    #[test]
    fn requests_over_a_tier_are_counted_by_kind_role_and_model_with_what_they_cost_beyond_the_base() {
        let c = |role: &str, model: Option<&str>, over: Option<u64>, beyond: Option<f64>| json!({ "role": role, "model": model, "requests_over_tier": over, "over_tier": beyond });
        let p = [json!({ "searches": [
            { "kind": "code", "candidates": [c("wide", Some("claude-haiku-5-5"), Some(2), Some(0.03)), c("wide", Some("claude-haiku-5-5"), Some(0), Some(0.0)), c("wide", Some("claude-haiku-5-5"), None, None)] },
            { "kind": "code", "candidates": [c("deep", Some("gpt-6.1-sol"), None, None), c("stub", None, Some(0), Some(0.0))] },
        ] })];
        let rows = over_tier(&p);
        // A stub has no line to cross; a role whose output never says its requests (codex) is not measured.
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!((rows[0]["role"].as_str(), rows[0]["agent_processes"].as_u64(), rows[0]["measured"].as_u64(), rows[0]["requests"].as_u64()), (Some("wide"), Some(3), Some(2), Some(2)));
        let t: crate::projection::Totals = serde_json::from_value(json!({ "over_tier": rows })).unwrap();
        assert_eq!(over_tier_table(&t)[1], ["Code · wide · claude-haiku-5-5", "2", "$0.03", "2 of 3"]);
    }

    #[test]
    fn the_run_time_distribution_fits_a_fixed_part_and_a_part_per_distinct_tree() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 2.0, 3.0]), Some(2.5));
        assert_eq!(median(&[]), None);
        // Nearest rank: the ⌈0.9 n⌉-th smallest.
        assert_eq!(p90(&(1..=10).map(f64::from).collect::<Vec<_>>()), Some(9.0));
        assert_eq!(p90(&[5.0]), Some(5.0));
        // y = 60 + 5x, exactly.
        let (a, b) = fit(&[(1.0, 65.0), (4.0, 80.0), (8.0, 100.0)]).unwrap();
        assert!((a - 60.0).abs() < 1e-9 && (b - 5.0).abs() < 1e-9);
        // Too few points, or one tree count for all: no split.
        assert!(fit(&[(1.0, 65.0), (4.0, 80.0)]).is_none());
        assert!(fit(&[(8.0, 1.0), (8.0, 2.0), (8.0, 3.0)]).is_none());
        let rs = |trees: u64, seconds: f64| json!({ "kind": "code", "time": 1, "trees": trees, "seconds": seconds, "cost": seconds / 10.0 });
        let ps = [json!({ "searches": [rs(1, 65.0), rs(4, 80.0), rs(8, 100.0), json!({ "kind": "code", "time": 1, "trees": null, "seconds": 9.0, "cost": 1.0 })] })];
        let groups = [json!({ "kind": "code", "outcome": "pushed", "push": { "seconds": 600.0, "cost": 30.0 } }),
                      json!({ "kind": "code", "outcome": "pushed", "push": { "seconds": 100.0, "cost": 10.0 } }),
                      json!({ "kind": "code", "outcome": "blocked", "push": null })];
        let r = &run_time(&ps, &groups)[0];
        assert_eq!((r["pushes"].as_u64(), r["time"]["median"].as_f64(), r["time"]["p90"].as_f64(), r["cost"]["median"].as_f64()), (Some(2), Some(350.0), Some(600.0), Some(20.0)));
        // The search whose trees are unknown is left out of the fit.
        assert_eq!(r["searches"].as_u64(), Some(3));
        assert!((r["fit"]["time"]["per_tree"].as_f64().unwrap() - 5.0).abs() < 1e-9 && (r["fit"]["cost"]["fixed"].as_f64().unwrap() - 6.0).abs() < 1e-9);
        let t: crate::projection::Totals = serde_json::from_value(json!({ "run_time": [r] })).unwrap();
        let (rows, fits) = run_time_table(&t);
        assert_eq!(rows[1], ["Code time to a push", "2", "5m50s", "10m00s"]);
        assert_eq!(fits[0], "Code per search (inferred, 3 searches): time 1m00s + 5s per distinct tree · cost $6.00 + $0.50 per distinct tree");
        let few: crate::projection::Totals = serde_json::from_value(json!({ "run_time": [{ "kind": "foil", "searches": 2 }] })).unwrap();
        assert!(run_time_table(&few).0.is_empty());
        assert_eq!(run_time_table(&few).1[0], "Foil per search: too few to fit (2 searches, 3 needed, with more than one count of distinct trees)");
    }

    #[test]
    fn the_outcome_tables_add_up() {
        let ps = [
            process("code", "pushed", &[("blocked", Some("too_few_tests"), Some("sentence")), ("pushed", None, None)]),
            process("code", "exited", &[("blocked", Some("too_few_verified"), Some("recorded")), ("exited", Some("during_a_search"), None)]),
            process("code", "blocked", &[("blocked", None, None)]),
            process("code", "pushed", &[("pushed", None, None)]),
        ];
        let t: crate::projection::Totals = serde_json::from_value(json!({ "attempts": attempts(&ps), "ended": ended(&ps),
            "reasons": reasons(&ps, "blocked"), "exits": reasons(&ps, "exited") })).unwrap();
        let a = attempt_table(&t);
        assert_eq!(a[0], ["Attempts", "All", "Pushed", "Blocked", "Exited"]);
        // 6 attempts: 2 pushed, 3 blocked, 1 exited.
        assert_eq!(a[1], ["Code", "6", "2", "3", "1"]);
        // The reasons sum to Blocked, the exits to Exited; an inferred reason says so.
        let r = reason_rows(&t);
        assert_eq!(r[0], ("Code blocked by".to_string(), vec!["Too few tests (1, 1 inferred)".to_string(), "Too few verified (1)".into(), "Unrecorded (1)".into()]));
        assert_eq!(r[1], ("Code exited".to_string(), vec!["During a search (1)".to_string()]));
        // Bon processes: 4, of which 2 pushed, 1 blocked, 1 exited; expected is over the 3 that pushed or blocked.
        let p = process_table(&t);
        assert_eq!(p[0], ["Bon processes", "All", "Pushed", "Blocked", "Exited", "Expected blocked"]);
        let x = |k: i32| 0.6f64.powi(k);
        assert_eq!(p[1], ["Code", "4", "2", "1", "1", &format!("{:.1}", x(2) + x(1) + x(1))]);
    }
}
