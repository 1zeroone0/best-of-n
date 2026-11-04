//! Trusted code. Every function the verified code calls from here is
//! `#[verifier::external_body]`: Verus does not check it. The TCB is this file
//! plus what it runs: git, sudo, tar, chmod, the harnesses (`claude`, `codex`)
//! and the checks the manifest declares.
//!
//! It observes and reports facts; it decides nothing. Every decision is a gate.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use vstd::prelude::*;

use crate::gates::{Candidate, Commit, Cue, Intent, Kind, Path, Permission, Search};

// ── bon.toml ────────────────────────────────────────────

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "trunk_default")]
    pub trunk: String,
    /// The remote whose trunk is the golden trunk: searches start from it, and
    /// every fast-forward is pushed to it.
    #[serde(default = "remote_default")]
    pub remote: String,
    /// The bon process's limit, in dollars, per command.
    pub limit: f64,
    /// engineer's time, in dollars per hour.
    pub rate: f64,
    #[serde(default)]
    pub transcripts: Option<String>,
    /// PATH for agent processes and checks, from the device file. Nothing is inherited.
    #[serde(skip)]
    pub path: Vec<String>,
    pub agent_process: AgentProcessConfig,
    pub checks: Checks,
    pub harness: Vec<Harness>,
    pub counterexample: Counterexample,
    /// Prices by canonical model, from the device file.
    #[serde(skip)]
    pub prices: HashMap<String, Price>,
}

/// What is true of this machine rather than of a repository, written by
/// `bon setup` and owned by root: where agent's tools live, and model prices.
pub const DEVICE: &str = "/etc/bon/device.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Device {
    path: Vec<String>,
    prices: HashMap<String, Price>,
}

fn trunk_default() -> String { "main".into() }
fn remote_default() -> String { "origin".into() }

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AgentProcessConfig {
    /// Dollars per agent process.
    pub limit: f64,
    /// Seconds per agent process.
    pub time: u64,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Checks {
    /// Protected: no candidate may change these.
    pub paths: Vec<String>,
    /// Each must exit 0.
    pub verify: Vec<String>,
    /// Each one's output is hashed and compared.
    #[serde(default)]
    pub agree: Vec<String>,
    /// Per kind ("code", "compaction"): prints an integer.
    #[serde(default)]
    pub rank: HashMap<String, String>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Harness {
    /// "claude" or "codex".
    pub name: String,
    /// The canonical model id (e.g. claude-haiku-5-5, gpt-6.1-sol), never an alias:
    /// it is passed to the harness and keys the price table.
    pub model: String,
    /// Agent processes per attempt: attempt a runs n[a]; a shorter list repeats
    /// its last value. The longest list sets how many attempts a command makes.
    pub n: Vec<usize>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Counterexample {
    pub harness: Vec<Harness>,
    /// Where its test goes; must not be under a check path.
    pub path: String,
    /// How its test runs.
    pub test: String,
}

/// Dollars per million tokens.
#[derive(Deserialize, serde::Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub input: f64,
    /// Input read from the prompt cache.
    pub cached_input: f64,
    pub output: f64,
    /// Input written to the prompt cache, shorter TTL (Claude 5 minutes, OpenAI 30 minutes).
    pub cache_write: f64,
    /// Input written to the prompt cache, longer TTL (Claude 1 hour, OpenAI 12 hours).
    pub cache_write_long: f64,
}

/// Dollars to microdollars, the unit of every cost and limit.
fn micro(d: f64) -> u64 { (d * 1_000_000.0).round() as u64 }

// ── processes ───────────────────────────────────────────

fn sh(dir: &std::path::Path, program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program).args(args).current_dir(dir).stdin(Stdio::null()).output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

fn git(root: &std::path::Path, args: &[&str]) -> Result<String, String> { sh(root, "git", args) }

/// A command run as user agent with a cleared environment: only PATH, HOME and
/// what bon sets. (TCB: sudo)
fn as_agent(config: &Config, dir: &std::path::Path, env: &[(&str, String)], argv: &[String]) -> Command {
    let mut c = Command::new("sudo");
    c.args(["-n", "-u", "agent", "env", "-i"]);
    c.arg(format!("PATH={}", config.path.join(":")));
    c.arg("HOME=/Users/agent");
    c.arg("LANG=en_US.UTF-8");
    c.arg("TERM=dumb");
    for (k, v) in env { c.arg(format!("{k}={v}")); }
    c.args(argv);
    c.current_dir(dir);
    c
}

/// Run to completion or kill at `time`. Returns (exit 0, stdout).
fn supervise(mut c: Command, stdin: Option<String>, time: Duration, log: &std::path::Path) -> (bool, String, bool) {
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let start = Instant::now();
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => { let _ = std::fs::write(log, format!("spawn: {e}")); return (false, String::new(), false); }
    };
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        std::thread::spawn(move || { let _ = pipe.write_all(text.as_bytes()); });
    }
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let o = std::thread::spawn(move || { let mut s = String::new(); let _ = out.read_to_string(&mut s); s });
    let e = std::thread::spawn(move || { let mut s = String::new(); let _ = err.read_to_string(&mut s); s });
    let mut killed = false;
    let status = loop {
        if let Ok(Some(s)) = child.try_wait() { break Some(s); }
        if start.elapsed() >= time { let _ = child.kill(); killed = true; break child.wait().ok(); }
        std::thread::sleep(Duration::from_millis(200));
    };
    let stdout = o.join().unwrap_or_default();
    let stderr = e.join().unwrap_or_default();
    let exit = if killed { "killed".to_string() } else { status.and_then(|s| s.code()).map_or("signal".into(), |c| c.to_string()) };
    let _ = std::fs::write(log, format!("exit: {exit}\nseconds: {:.1}\n--- stdout\n{stdout}\n--- stderr\n{stderr}", start.elapsed().as_secs_f64()));
    (status.map_or(false, |s| s.success()) && !killed, stdout, killed)
}

// ── working directories ─────────────────────────────────

/// Every directory bon makes for agent processes and checks lives here.
fn scratch(name: &str) -> PathBuf {
    // /tmp is cleared on reboot: keep /tmp/bon world-writable and sticky, like /tmp.
    let base = PathBuf::from("/tmp/bon");
    if !base.exists() {
        let _ = std::fs::create_dir_all(&base);
        let _ = Command::new("chmod").arg("1777").arg(&base).status();
    }
    base.join(format!("{}-{name}", std::process::id()))
}

/// Write `commit`'s tree into `dir`, owned by engineer, group bon. (TCB: git, tar)
fn materialize(root: &std::path::Path, commit: &str, dir: &std::path::Path) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut archive = Command::new("git").args(["archive", "--format=tar", commit]).current_dir(root)
        .stdout(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    let tar = Command::new("tar").arg("-x").arg("-C").arg(dir)
        .stdin(archive.stdout.take().unwrap()).status().map_err(|e| e.to_string())?;
    if !archive.wait().map_err(|e| e.to_string())?.success() || !tar.success() {
        return Err(format!("materialize {commit}"));
    }
    sh(dir, "chgrp", &["-R", "bon", "."])?;
    Ok(())
}

/// A working directory for one agent process: agent (through group bon) may
/// write everything except the check paths, which it may read and execute but
/// not write, rename or delete. (intent 8; TCB: POSIX ACLs)
fn working_directory(root: &std::path::Path, config: &Config, commit: &str, dir: &std::path::Path) -> Result<(), String> {
    materialize(root, commit, dir)?;
    sh(dir, "chmod", &["-R", "g+rwX", "."])?;
    sh(dir, "find", &[".", "-type", "d", "-exec", "chmod", "g+s", "{}", "+"])?;
    // The checks and the transcripts: agent may read them, never change them.
    let transcripts = config.transcripts.clone().unwrap_or("transcripts".into());
    for p in config.checks.paths.iter().chain(std::iter::once(&transcripts)) {
        let target = dir.join(p.trim_end_matches('/'));
        if !target.exists() { continue; }
        let t = target.to_string_lossy().to_string();
        sh(dir, "chmod", &["-R", "g-w", &t])?;
        sh(dir, "chmod", &["-R", "+a", "user:agent deny write,append,delete,writeattr,writeextattr,writesecurity,chown,add_file,add_subdirectory,delete_child", &t])?;
        // Its ancestors cannot be renamed or deleted out from under it.
        let mut a = target.parent();
        while let Some(d) = a {
            if d == dir || !d.starts_with(dir) { break; }
            sh(dir, "chmod", &["+a", "user:agent deny delete", &d.to_string_lossy()])?;
            a = d.parent();
        }
    }
    Ok(())
}

/// A read-only checkout for running checks: agent may read and execute it and
/// write only its build directory.
fn check_directory(root: &std::path::Path, commit: &str, dir: &std::path::Path) -> Result<(), String> {
    materialize(root, commit, dir)?;
    sh(dir, "chmod", &["-R", "a-w,g+rX", "."])?;
    Ok(())
}

fn build_directory(config: &Config, name: &str) -> Result<PathBuf, String> {
    let d = scratch(name);
    let mut c = as_agent(config, std::path::Path::new("/tmp"), &[], &["mkdir".into(), "-p".into(), d.to_string_lossy().into()]);
    let ok = c.status().map_err(|e| e.to_string())?.success();
    if !ok { return Err(format!("mkdir {} as agent", d.display())); }
    Ok(d)
}

// ── checks ──────────────────────────────────────────────

fn hash(s: &str) -> u64 {
    let d = Sha256::digest(s.as_bytes());
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Run a command as agent in a read-only checkout. (exit 0, stdout)
fn run_check(config: &Config, dir: &std::path::Path, target: &std::path::Path, command: &str, log: &std::path::Path) -> (bool, String) {
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()];
    let c = as_agent(config, dir, &[("CARGO_TARGET_DIR", target.to_string_lossy().into())], &argv);
    let (ok, out, _) = supervise(c, None, Duration::from_secs(config.agent_process.time), log);
    (ok, out)
}

// ── harnesses ───────────────────────────────────────────

fn harness_argv(h: &Harness, config: &Config, dir: &std::path::Path) -> Vec<String> {
    match h.name.as_str() {
        "claude" => vec![
            "claude", "-p", "--output-format", "stream-json", "--verbose",
            "--setting-sources", "", "--strict-mcp-config", "--no-session-persistence",
            "--permission-mode", "bypassPermissions", "--model", &h.model,
            "--max-budget-usd", &format!("{}", config.agent_process.limit),
        ].into_iter().map(String::from).collect(),
        _ => vec![
            "codex", "exec", "--json", "--ephemeral", "--ignore-rules", "--skip-git-repo-check",
            "--sandbox", "workspace-write", "--color", "never", "-m", &h.model,
            "-C", &dir.to_string_lossy(), "-",
        ].into_iter().map(String::from).collect(),
    }
}

/// API-equivalent cost in microdollars, from the harness's token counts and the
/// manifest's price table: (bon's figure, the harness's own figure if it reports one).
/// Claude: the final `result` event's `modelUsage`, per model, with 5-minute and
/// 1-hour cache writes apart. Codex: the last `turn.completed`, whose usage is a
/// running total; cached and cache-write tokens are part of `input_tokens`.
fn cost(h: &Harness, config: &Config, stdout: &str) -> Result<(u64, Option<u64>, HashMap<String, Price>), String> {
    let price = |model: &str| config.prices.get(model).ok_or(format!("no price for model {model}"));
    let rate = |p: &Price, input: f64, cached: f64, output: f64, write: f64, write_long: f64| {
        (input * p.input + cached * p.cached_input + output * p.output + write * p.cache_write + write_long * p.cache_write_long) / 1_000_000.0
    };
    let events: Vec<serde_json::Value> = stdout.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    if h.name == "claude" {
        let Some(r) = events.iter().rev().find(|v| v["type"] == "result") else { return Err("no result event".into()) };
        let mut ours = 0.0;
        let mut theirs = 0.0;
        let mut used = HashMap::new();
        for (model, u) in r["modelUsage"].as_object().cloned().unwrap_or_default() {
            used.insert(model.clone(), price(&model)?.clone());
            let n = |k: &str| u[k].as_f64().unwrap_or(0.0);
            let (w5, w1) = (n("cacheCreationEphemeral5mInputTokens"), n("cacheCreationEphemeral1hInputTokens"));
            let w5 = if w5 + w1 == 0.0 { n("cacheCreationInputTokens") } else { w5 };
            ours += rate(price(&model)?, n("inputTokens"), n("cacheReadInputTokens"), n("outputTokens"), w5, w1);
            theirs += n("costUSD");
        }
        Ok((micro(ours), Some(micro(theirs)), used))
    } else {
        let Some(t) = events.iter().rev().find(|v| v["type"] == "turn.completed") else { return Err("no turn.completed event".into()) };
        let n = |k: &str| t["usage"][k].as_f64().unwrap_or(0.0);
        let (cached, write) = (n("cached_input_tokens"), n("cache_write_input_tokens"));
        let input = (n("input_tokens") - cached - write).max(0.0);
        let p = price(&h.model)?;
        Ok((micro(rate(p, input, cached, n("output_tokens"), write, 0.0)), None, HashMap::from([(h.model.clone(), p.clone())])))
    }
}

fn prompt(kind: &Kind, config: &Config, map: &str) -> String {
    let goal = match kind {
        Kind::Code { goal } => format!("Change the code so this intent holds:\n\n{}\n", goal.iter().collect::<String>()),
        Kind::Compaction { .. } => "Remove or simplify code without changing behavior.\n".to_string(),
        Kind::Counterexample { .. } => format!(
            "This code was written for an intent. Write one test, at {}, that passes on this code \
             but would fail on a different reasonable reading of the intent. It runs with: {}\n",
            config.counterexample.path, config.counterexample.test),
        Kind::Map { goal } => format!("Read the transcript at {} and append to `map` one line per need it voices: \
             the intent, a tab, then the transcript path, '#', and the cue's start time.\n", goal.iter().collect::<String>()),
    };
    format!(
        "You are working in a copy of a repository, with no git. {goal}\n\
         The checks are {paths:?}: read and run them, never change them; you cannot.\n\
         They run with: {verify:?}\n\
         The current intents, for context:\n{map}\n\
         Make the smallest change that does this. Reply with one line saying what you changed.",
        paths = config.checks.paths, verify = config.checks.verify)
}

// ── trusted interface ───────────────────────────────────

verus! {

/// The manifest at a commit.
#[verifier::external_body]
pub struct Manifest { pub config: Config, pub root: PathBuf }

#[verifier::external_body]
pub fn manifest(root: &str, commit: &Commit) -> (r: Result<Manifest, String>) {
    let root = PathBuf::from(root);
    let c: String = commit.iter().collect();
    let text = git(&root, &["show", &format!("{c}:bon.toml")]).map_err(|_| "no bon.toml at trunk's head; commit one".to_string())?;
    let mut config: Config = toml::from_str(&text).map_err(|e| format!("bon.toml: {e}"))?;
    let device: Device = toml::from_str(&std::fs::read_to_string(DEVICE).map_err(|_| format!("no {DEVICE}; run bon setup"))?)
        .map_err(|e| format!("{DEVICE}: {e}"))?;
    config.path = device.path;
    config.prices = device.prices;
    for h in config.harness.iter().chain(config.counterexample.harness.iter()) {
        if !config.prices.contains_key(&h.model) {
            return Err(format!("{DEVICE}: no price for {}; bon.toml must name canonical model ids", h.model));
        }
    }
    Ok(Manifest { config, root })
}

/// The bon process's limit, in microdollars.
#[verifier::external_body]
pub fn limit(m: &Manifest) -> u64 { micro(m.config.limit) }

/// Each agent process's limit, in microdollars.
#[verifier::external_body]
pub fn agent_process_limit(m: &Manifest) -> u64 { micro(m.config.agent_process.limit) }

#[verifier::external_body]
pub fn checks(m: &Manifest) -> Vec<Path> { m.config.checks.paths.iter().map(|p| p.chars().collect()).collect() }

/// How many agent processes one harness runs on attempt `a`.
#[verifier::external]
fn at(h: &Harness, a: usize) -> usize { h.n.get(a).or(h.n.last()).copied().unwrap_or(0) }

/// How many agent processes a search of this kind runs on attempt `a`.
#[verifier::external_body]
pub fn width(m: &Manifest, kind: &Kind, a: usize) -> usize {
    let hs = match kind { Kind::Counterexample { .. } => &m.config.counterexample.harness, _ => &m.config.harness };
    hs.iter().map(|h| at(h, a)).sum()
}

/// How many attempts a command makes: the longest width list. (intent 15)
#[verifier::external_body]
pub fn attempts(m: &Manifest) -> usize {
    m.config.harness.iter().chain(m.config.counterexample.harness.iter()).map(|h| h.n.len()).max().unwrap_or(1)
}

/// Tests carried from a counterexample search that did not clear: each joins the
/// agree checks of the later attempts in this command. (intent 13)
#[verifier::external_body]
pub struct Tests { pub files: Vec<Vec<u8>> }

#[verifier::external_body]
pub fn no_tests() -> Tests { Tests { files: Vec::new() } }

/// Carry every test the counterexample search `x` wrote.
#[verifier::external_body]
pub fn carry(m: &Manifest, tests: &mut Tests, x: &Search) {
    for c in x.results.iter().flatten() {
        let commit: String = c.commit.iter().collect();
        if let Ok(out) = Command::new("git").args(["show", &format!("{commit}:{}", m.config.counterexample.path)])
            .current_dir(&m.root).output() {
            if out.status.success() { tests.files.push(out.stdout); }
        }
    }
}

/// trunk's head, if trunk is checked out with no uncommitted changes to tracked files.
#[verifier::external_body]
pub fn head(root: &str) -> (r: Result<Commit, String>) {
    let root = PathBuf::from(root);
    let h = git(&root, &["rev-parse", "HEAD"])?;
    if !git(&root, &["status", "--porcelain", "--untracked-files=no"])?.is_empty() {
        return Err("trunk has uncommitted changes to tracked files".into());
    }
    Ok(h.chars().collect())
}

/// The branch that is checked out must be trunk.
#[verifier::external_body]
pub fn on_trunk(m: &Manifest) -> (r: Result<(), String>) {
    let b = git(&m.root, &["symbolic-ref", "--short", "HEAD"])?;
    if b != m.config.trunk { return Err(format!("on {b}; bon works on trunk ({})", m.config.trunk)); }
    let (r, t) = (&m.config.remote, &m.config.trunk);
    git(&m.root, &["fetch", "--quiet", r, t]).map_err(|e| format!("fetch {r} {t}: {e}"))?;
    let local = git(&m.root, &["rev-parse", "HEAD"])?;
    let remote = git(&m.root, &["rev-parse", &format!("{r}/{t}")])?;
    if local != remote {
        return Err(format!("trunk differs from {r}/{t}; pull or push so they match, then run again"));
    }
    Ok(())
}

/// The map's intents at a commit: the text before any tab.
#[verifier::external_body]
pub fn intents(m: &Manifest, commit: &Commit) -> Vec<Intent> {
    let c: String = commit.iter().collect();
    git(&m.root, &["show", &format!("{c}:map")]).unwrap_or_default().lines()
        .map(|l| l.split('\t').next().unwrap_or("").trim().chars().collect()).collect()
}

/// agent's effective permissions on each file the policy covers, observed by
/// asking as agent, on a probe working directory made the same way as real ones.
#[verifier::external_body]
pub fn observe(m: &Manifest, commit: &Commit) -> (r: Result<(Permission, Permission, Permission, Permission), String>) {
    let c: String = commit.iter().collect();
    let probe = scratch("probe");
    if let Err(e) = working_directory(&m.root, &m.config, &c, &probe) {
        let _ = std::fs::remove_dir_all(&probe);
        return Err(format!("agent is not set up ({e}); run bon setup"));
    }
    let ask = |path: &std::path::Path, flag: &str| -> bool {
        Command::new("sudo").args(["-n", "-u", "agent", "test", flag]).arg(path).status().map_or(false, |s| s.success())
    };
    let perm = |path: &std::path::Path| Permission { read: ask(path, "-r"), write: ask(path, "-w"), execute: ask(path, "-x") };
    let check = m.config.checks.paths.first().map(|p| probe.join(p.trim_end_matches('/'))).ok_or("no check paths")?;
    // The transcripts as agent meets them: in a working directory.
    let transcripts = probe.join(m.config.transcripts.clone().unwrap_or("transcripts".into()));
    let r = (perm(&check), if transcripts.exists() { perm(&transcripts) } else { Permission { read: true, write: false, execute: true } },
             perm(&probe), perm(&m.root.join(".git")));
    let _ = std::fs::remove_dir_all(&probe);
    Ok(r)
}

/// Run a search's agent processes in parallel and observe each: its candidate
/// (None if it produced none) and its cost in microdollars. `target` is the
/// search a counterexample attacks.
#[verifier::external_body]
pub fn run(m: &Manifest, kind: &Kind, search: usize, a: usize, start: &Commit, target: Option<&Search>, tests: &Tests) -> Vec<(Option<Candidate>, u64)> {
    let start: String = start.iter().collect();
    let hs = match kind { Kind::Counterexample { .. } => m.config.counterexample.harness.clone(), _ => m.config.harness.clone() };
    let slots: Vec<Harness> = hs.iter().flat_map(|h| std::iter::repeat(h.clone()).take(at(h, a))).collect();
    let map = git(&m.root, &["show", &format!("{start}:map")]).unwrap_or_default();
    let traces = m.root.join(".bon").join("traces").join(format!("{}", std::process::id())).join(search.to_string());
    let _ = std::fs::create_dir_all(&traces);
    std::thread::scope(|scope| {
        let handles: Vec<_> = slots.iter().enumerate().map(|(i, h)| {
            let (start, map, traces) = (&start, &map, &traces);
            scope.spawn(move || agent_process(m, kind, search, i, h, start, map, target, tests, &traces.join(i.to_string())))
        }).collect();
        handles.into_iter().map(|h| h.join().unwrap_or((None, 0))).collect()
    })
}

/// The remote's trunk fast-forwards to `commit`, then the local trunk follows.
/// The push is fast-forward only: if the remote's trunk moved, it is refused and
/// nothing changes. (TCB: git, the remote)
#[verifier::external_body]
pub fn fast_forward(m: &Manifest, commit: &Commit) -> (r: Result<(), String>) {
    let c: String = commit.iter().collect();
    let (r, t) = (&m.config.remote, &m.config.trunk);
    git(&m.root, &["push", "--quiet", r, &format!("{c}:refs/heads/{t}")])
        .map_err(|e| format!("blocked: {r}/{t} moved during the search, so the push was refused; run it again ({e})"))?;
    git(&m.root, &["merge", "--ff-only", "--quiet", &c]).map(|_| ())
}

/// A point in time, for a search's wall time.
#[verifier::external_body]
pub struct Clock { pub at: Instant }

#[verifier::external_body]
pub fn clock() -> Clock { Clock { at: Instant::now() } }

/// One search's cost per verified candidate, printed and recorded:
/// (Σ_c (g(c) + k(c)) + r·t) / v. g(c) is each agent process's measured cost; k(c)
/// is 0 because checks run locally and their time is inside t; r is bon.toml's
/// rate; t is the search's wall time; v is how many candidates the verified gate
/// passed. (intent 14)
#[verifier::external_body]
pub fn report(m: &Manifest, search: usize, n: usize, verified: usize, generation: u64, started: Clock) {
    let hours = started.at.elapsed().as_secs_f64() / 3600.0;
    let generation = generation as f64 / 1_000_000.0;
    let time = m.config.rate * hours;
    let per = if verified == 0 { None } else { Some((generation + time) / verified as f64) };
    let line = format!(
        "search {search}: {n} agent processes, {verified} verified; generation ${generation:.4} + time ${time:.4} ({:.0}s at ${}/h) = {}",
        hours * 3600.0, m.config.rate,
        per.map_or("no verified candidate".to_string(), |p| format!("${p:.4} per verified candidate")));
    eprintln!("bon: {line}");
    let d = m.root.join(".bon").join("traces").join(format!("{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    let summary = serde_json::json!({
        "search": search, "agent_processes": n, "verified": verified, "generation_dollars": generation,
        "seconds": hours * 3600.0, "rate": m.config.rate, "time_dollars": time,
        "cost_per_verified_candidate": per,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(d.join("searches.jsonl")) {
        let _ = writeln!(f, "{summary}");
    }
}

/// Append one line to this command's trace. (intent 14)
#[verifier::external_body]
pub fn record(m: &Manifest, line: &str) {
    let d = m.root.join(".bon").join("traces").join(format!("{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(d.join("transitions")) {
        let _ = writeln!(f, "{line}");
    }
}

/// The agree checks' outputs at a commit, hashed: a compaction search's goal.
#[verifier::external_body]
pub fn agree_outputs(m: &Manifest, commit: &Commit, tests: &Tests) -> (r: Result<Vec<u64>, String>) {
    let c: String = commit.iter().collect();
    let dir = scratch("goal");
    check_directory(&m.root, &c, &dir)?;
    let build = build_directory(&m.config, "goal-build")?;
    let log = m.root.join(".bon").join("traces").join(format!("{}", std::process::id()));
    let _ = std::fs::create_dir_all(&log);
    let mut out = Vec::new();
    for (k, a) in m.config.checks.agree.iter().enumerate() {
        out.push(hash(&run_check(&m.config, &dir, &build, a, &log.join(format!("goal-agree-{k}"))).1));
    }
    for (k, t) in tests.files.iter().enumerate() {
        out.push(hash(if test_on(m, &c, t, &build, &log.join(format!("goal-carried-{k}"))) { "pass" } else { "fail" }));
    }
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(out)
}

} // verus!

/// One agent process: generate, capture, observe. Its log goes under `trace`.
#[allow(clippy::too_many_arguments)]
fn agent_process(m: &Manifest, kind: &Kind, search: usize, index: usize, h: &Harness, start: &str, map: &str,
                 target: Option<&Search>, tests: &Tests, trace: &std::path::Path) -> (Option<Candidate>, u64) {
    let _ = std::fs::create_dir_all(trace);
    let config = &m.config;
    let dir = scratch(&format!("{search}-{index}"));
    if let Err(e) = working_directory(&m.root, config, start, &dir) {
        let _ = std::fs::write(trace.join("error"), e);
        return (None, 0);
    }
    let argv = harness_argv(h, config, &dir);
    let _ = std::fs::write(trace.join("argv"), argv.join(" "));
    let text = prompt(kind, config, map);
    let _ = std::fs::write(trace.join("prompt"), &text);
    let c = as_agent(config, &dir, &[], &argv);
    let (_, stdout, killed) = supervise(c, Some(text), Duration::from_secs(config.agent_process.time), &trace.join("harness"));
    // Without token counts there is no measured cost: charge the whole limit.
    let (spent, harness_cost, prices) = cost(h, config, &stdout).unwrap_or((micro(config.agent_process.limit), None, HashMap::new()));
    if killed { let _ = std::fs::write(trace.join("killed"), "time limit"); }
    let candidate = capture(m, kind, search, index, start, &dir, target, tests, trace).map_err(|e| {
        let _ = std::fs::write(trace.join("error"), &e);
    }).ok();
    let _ = std::fs::remove_dir_all(&dir);
    let build = scratch(&format!("{search}-{index}-build"));
    let _ = as_agent(config, std::path::Path::new("/tmp"), &[], &["rm".into(), "-rf".into(), build.to_string_lossy().into()]).status();
    let text = |v: &Vec<char>| v.iter().collect::<String>();
    let facts = serde_json::json!({
        "harness": h.name, "model": h.model, "cost_microdollars": spent, "killed": killed,
        "harness_cost_microdollars": harness_cost,
        // The prices this cost was computed at, so the trace stays true when the device's prices change.
        "prices": prices,
        // The harness's own figure differs from bon's by more than 5%: the price table or the harness is stale.
        "price_mismatch": harness_cost.is_some_and(|c| (c as f64 - spent as f64).abs() > 0.05 * (c.max(spent).max(1) as f64)),
        "over_limit": spent > micro(config.agent_process.limit),
        "candidate": candidate.as_ref().map(|c| serde_json::json!({
            "commit": text(&c.commit), "base": text(&c.base), "checks_pass": c.checks_pass,
            "changed": c.changed.iter().map(text).collect::<Vec<_>>(), "diff": c.diff, "rank": c.rank,
            "out": c.out, "test_passes": c.test_passes,
            "intents": c.intents.iter().map(|(q, i)| (q, text(i))).collect::<Vec<_>>(),
        })),
    });
    let _ = std::fs::write(trace.join("facts.json"), serde_json::to_string_pretty(&facts).unwrap_or_default());
    (candidate, spent)
}

/// Record the working directory as a commit whose parent is `start`, then
/// observe it: changed paths, diff, checks, agree outputs, rank, test results.
#[allow(clippy::too_many_arguments)]
fn capture(m: &Manifest, kind: &Kind, search: usize, index: usize, start: &str, dir: &std::path::Path,
           target: Option<&Search>, tests: &Tests, trace: &std::path::Path) -> Result<Candidate, String> {
    let root = &m.root;
    let config = &m.config;
    let index_file = trace.join("index");
    let with = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git").arg("--work-tree").arg(dir).args(args).current_dir(root)
            .env("GIT_INDEX_FILE", &index_file).stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).to_string()); }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    with(&["read-tree", start])?;
    with(&["add", "-A", "."])?;
    let tree = with(&["write-tree"])?;
    let _ = std::fs::remove_file(&index_file);
    let subject = match kind {
        Kind::Code { goal } => goal.iter().collect::<String>(),
        Kind::Compaction { .. } => "compaction".to_string(),
        Kind::Map { goal } => format!("map: {}", goal.iter().collect::<String>()),
        Kind::Counterexample { .. } => "counterexample".to_string(),
    };
    let message = format!("{subject}\n\nTrace: .bon/traces/{}/{search}/{index}\n", std::process::id());
    let commit = {
        let out = Command::new("git").args(["commit-tree", &tree, "-p", start, "-m", &message]).current_dir(root)
            .env("GIT_AUTHOR_NAME", "agent").env("GIT_AUTHOR_EMAIL", "agent@localhost")
            .stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).to_string()); }
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(root, &["update-ref", &format!("refs/bon/{}/{search}/{index}", std::process::id()), &commit])?;

    let numstat = git(root, &["diff-tree", "-r", "--numstat", "--no-renames", start, &commit])?;
    let mut changed = Vec::new();
    let mut diff = 0u64;
    for l in numstat.lines() {
        let f: Vec<&str> = l.splitn(3, '\t').collect();
        if f.len() < 3 { continue; }
        diff += f[0].parse::<u64>().unwrap_or(1) + f[1].parse::<u64>().unwrap_or(1);
        changed.push(f[2].chars().collect::<Path>());
    }

    // Checks run in a read-only checkout, as agent.
    let cdir = scratch(&format!("{search}-{index}-check"));
    check_directory(root, &commit, &cdir)?;
    let build = build_directory(config, &format!("{search}-{index}-build"))?;
    let mut checks_pass = true;
    for (k, v) in config.checks.verify.iter().enumerate() {
        let (ok, _) = run_check(config, &cdir, &build, v, &trace.join(format!("verify-{k}")));
        if !ok { checks_pass = false; break; }
    }
    let mut out = Vec::new();
    let mut rank = 0i64;
    if checks_pass {
        for (k, a) in config.checks.agree.iter().enumerate() {
            let (_, o) = run_check(config, &cdir, &build, a, &trace.join(format!("agree-{k}")));
            out.push(hash(&o));
        }
        for (k, t) in tests.files.iter().enumerate() {
            out.push(hash(if test_on(m, &commit, t, &build, &trace.join(format!("carried-{k}"))) { "pass" } else { "fail" }));
        }
        let which = match kind { Kind::Compaction { .. } => "compaction", _ => "code" };
        if let Some(r) = config.checks.rank.get(which) {
            let (_, o) = run_check(config, &cdir, &build, r, &trace.join("rank"));
            rank = o.trim().parse().unwrap_or(0);
        }
    }
    let mut test_passes = Vec::new();
    if let (Kind::Counterexample { .. }, Some(t)) = (kind, target) {
        let test = std::fs::read(dir.join(&config.counterexample.path)).ok();
        let mut members: Vec<(i64, String)> = Vec::new();
        if let Kind::Compaction { goal, .. } = &t.kind { members.push((-1, goal.iter().collect())); }
        for (j, r) in t.results.iter().enumerate() {
            if let Some(c) = r { members.push((j as i64, c.commit.iter().collect())); }
        }
        for (j, mc) in members {
            let passes = match &test {
                Some(bytes) => test_on(m, &mc, bytes, &build, &trace.join(format!("test-{j}"))),
                None => false,
            };
            test_passes.push((j, passes));
        }
    }
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&cdir).status();
    let _ = std::fs::remove_dir_all(&cdir);

    let intents: Vec<(Cue, Intent)> = match kind {
        Kind::Map { .. } => map_intents(root, start, &commit),
        _ => Vec::new(),
    };
    Ok(Candidate {
        commit: commit.chars().collect(),
        base: start.chars().collect(),
        checks_pass,
        changed,
        out,
        intents,
        test_passes,
        rank,
        diff,
    })
}

/// Whether a counterexample test passes on `commit`: a read-only checkout of it
/// with the test at the manifest's counterexample path, run as agent.
fn test_on(m: &Manifest, commit: &str, test: &[u8], build: &std::path::Path, log: &std::path::Path) -> bool {
    let config = &m.config;
    let dir = scratch(&format!("test-{}", hash(&format!("{commit}{log:?}"))));
    let passes = match materialize(&m.root, commit, &dir) {
        Ok(()) => {
            let p = dir.join(&config.counterexample.path);
            let _ = std::fs::create_dir_all(p.parent().unwrap_or(&dir));
            let _ = std::fs::write(&p, test);
            let _ = Command::new("chmod").args(["-R", "a-w,g+rX"]).arg(&dir).status();
            run_check(config, &dir, build, &config.counterexample.test, log).0
        }
        Err(_) => false,
    };
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    passes
}

/// A map candidate's new lines, by the cue each cites: `intent\tpath#HH:MM:SS.mmm`.
fn map_intents(root: &std::path::Path, start: &str, commit: &str) -> Vec<(Cue, Intent)> {
    let diff = git(root, &["diff", "--unified=0", start, commit, "--", "map"]).unwrap_or_default();
    diff.lines().filter(|l| l.starts_with('+') && !l.starts_with("+++")).filter_map(|l| {
        let (text, source) = l[1..].split_once('\t')?;
        let cue = source.rsplit_once('#')?.1;
        Some((parse_cue(cue)?, text.trim().chars().collect()))
    }).collect()
}

/// WebVTT timestamp to milliseconds.
fn parse_cue(t: &str) -> Option<u64> {
    let (hms, ms) = t.split_once('.').unwrap_or((t, "0"));
    let parts: Vec<u64> = hms.split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let secs = parts.iter().fold(0, |a, p| a * 60 + p);
    Some(secs * 1000 + ms.parse::<u64>().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cues() {
        assert_eq!(parse_cue("00:01:02.345"), Some(62_345));
        assert_eq!(parse_cue("01:00:00.000"), Some(3_600_000));
        assert_eq!(parse_cue("nope"), None);
    }

    fn config() -> Config {
        let mut c: Config = toml::from_str(r#"
            limit = 5.0
            rate = 150
            agent_process = { limit = 0.5, time = 60 }
            checks = { paths = ["checks/"], verify = ["true"] }
            harness = [{ name = "claude", model = "claude-haiku-5-5", n = [2, 4] }]
            counterexample = { harness = [{ name = "codex", model = "gpt-6.1-sol", n = [1] }], path = "c.sh", test = "sh c.sh" }
        "#).unwrap();
        let d: Device = toml::from_str(r#"
            path = ["/usr/bin"]
            [prices]
            "claude-haiku-5-5" = { input = 0.10, cached_input = 0.01, output = 0.50, cache_write = 0.125, cache_write_long = 0.20 }
            "gpt-6.1-sol" = { input = 2.00, cached_input = 0.10, output = 10.00, cache_write = 2.50, cache_write_long = 5.00 }
        "#).unwrap();
        c.path = d.path;
        c.prices = d.prices;
        c
    }

    #[test]
    fn widths_repeat_their_last_value_and_set_the_attempts() {
        let c = config();
        assert_eq!((at(&c.harness[0], 0), at(&c.harness[0], 1), at(&c.harness[0], 5)), (2, 4, 4));
        assert_eq!(at(&c.counterexample.harness[0], 3), 1);
    }

    #[test]
    fn device_facts_are_refused_in_bon_toml() {
        assert!(toml::from_str::<Config>("limit = 1.0\nrate = 1\npath = [\"/usr/bin\"]").is_err());
        assert!(toml::from_str::<Config>("limit = 1.0\nrate = 1\n[prices]").is_err());
    }

    #[test]
    fn claude_cost_matches_its_own_on_a_real_run() {
        // The modelUsage of the first end-to-end run; Claude Code reported $0.00245213.
        let c = config();
        let out = r#"{"type":"result","total_cost_usd":0.00245213,"modelUsage":{"claude-haiku-5-5":{"inputTokens":6,"outputTokens":527,"cacheReadInputTokens":49463,"cacheCreationInputTokens":8467,"cacheCreationEphemeral5mInputTokens":0,"cacheCreationEphemeral1hInputTokens":8467,"costUSD":0.00245213}}}"#;
        let (ours, theirs, prices) = cost(&c.harness[0], &c, out).unwrap();
        assert_eq!((ours, theirs), (2452, Some(2452)));
        assert_eq!(prices["claude-haiku-5-5"], c.prices["claude-haiku-5-5"]);
    }

    #[test]
    fn codex_cost_is_the_last_running_total_with_cached_input_apart() {
        let c = config();
        let h = &c.counterexample.harness[0];
        let out = r#"{"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":0}}
{"type":"turn.completed","usage":{"input_tokens":1000000,"cached_input_tokens":500000,"cache_write_input_tokens":0,"output_tokens":100000}}"#;
        // 500k input at $2, 500k cached at $0.10, 100k output at $10.
        let (ours, theirs, prices) = cost(h, &c, out).unwrap();
        assert_eq!((ours, theirs), (2_050_000, None));
        assert!(prices.contains_key("gpt-6.1-sol"));
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(toml::from_str::<Config>("limit = 1.0\nbogus = 2").is_err());
    }
}
