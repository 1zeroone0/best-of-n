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
    /// The bon process's limit, in dollars, per command.
    pub limit: f64,
    /// engineer's time, in dollars per hour.
    pub rate: f64,
    #[serde(default)]
    pub transcripts: Option<String>,
    /// PATH for agent processes and checks. Nothing is inherited.
    pub path: Vec<String>,
    pub agent_process: AgentProcessConfig,
    pub checks: Checks,
    pub harness: Vec<Harness>,
    pub counterexample: Counterexample,
    pub prices: HashMap<String, Price>,
}

fn trunk_default() -> String { "main".into() }

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
    pub model: String,
    pub n: usize,
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
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub input: f64,
    pub output: f64,
    #[serde(default)]
    pub cache_read: f64,
    #[serde(default)]
    pub cache_write: f64,
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
    for p in &config.checks.paths {
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

/// Tokens from a harness's JSON output, priced by the manifest. Claude: the
/// final `result` event's usage. Codex: the sum over `turn.completed` events.
fn cost(h: &Harness, config: &Config, stdout: &str) -> Result<u64, String> {
    let price = config.prices.get(&h.model).ok_or(format!("no price for model {}", h.model))?;
    let (mut i, mut o, mut cr, mut cw) = (0f64, 0f64, 0f64, 0f64);
    for line in stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let t = v["type"].as_str().unwrap_or("");
        let u = if h.name == "claude" && t == "result" { &v["usage"] }
            else if h.name != "claude" && t == "turn.completed" { &v["usage"] } else { continue };
        let n = |k: &str| u[k].as_f64().unwrap_or(0.0);
        if h.name == "claude" {
            i = n("input_tokens"); o = n("output_tokens");
            cr = n("cache_read_input_tokens"); cw = n("cache_creation_input_tokens");
        } else {
            let cached = n("cached_input_tokens");
            i += n("input_tokens") - cached; o += n("output_tokens"); cr += cached;
        }
    }
    Ok(micro((i * price.input + o * price.output + cr * price.cache_read + cw * price.cache_write) / 1_000_000.0))
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
    let config: Config = toml::from_str(&text).map_err(|e| format!("bon.toml: {e}"))?;
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

/// How many agent processes a search of this kind runs.
#[verifier::external_body]
pub fn width(m: &Manifest, kind: &Kind) -> usize {
    let hs = match kind { Kind::Counterexample { .. } => &m.config.counterexample.harness, _ => &m.config.harness };
    hs.iter().map(|h| h.n).sum()
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
    let transcripts = m.root.join(m.config.transcripts.clone().unwrap_or("transcripts".into()));
    let r = (perm(&check), if transcripts.exists() { perm(&transcripts) } else { Permission { read: true, write: false, execute: false } },
             perm(&probe), perm(&m.root.join(".git")));
    let _ = std::fs::remove_dir_all(&probe);
    Ok(r)
}

/// Run a search's agent processes in parallel and observe each: its candidate
/// (None if it produced none) and its cost in microdollars. `target` is the
/// search a counterexample attacks.
#[verifier::external_body]
pub fn run(m: &Manifest, kind: &Kind, search: usize, start: &Commit, target: Option<&Search>) -> Vec<(Option<Candidate>, u64)> {
    let start: String = start.iter().collect();
    let hs = match kind { Kind::Counterexample { .. } => m.config.counterexample.harness.clone(), _ => m.config.harness.clone() };
    let slots: Vec<Harness> = hs.iter().flat_map(|h| std::iter::repeat(h.clone()).take(h.n)).collect();
    let map = git(&m.root, &["show", &format!("{start}:map")]).unwrap_or_default();
    let traces = m.root.join(".bon").join("traces").join(format!("{}", std::process::id())).join(search.to_string());
    let _ = std::fs::create_dir_all(&traces);
    std::thread::scope(|scope| {
        let handles: Vec<_> = slots.iter().enumerate().map(|(i, h)| {
            let (start, map, traces) = (&start, &map, &traces);
            scope.spawn(move || agent_process(m, kind, search, i, h, start, map, target, &traces.join(i.to_string())))
        }).collect();
        handles.into_iter().map(|h| h.join().unwrap_or((None, 0))).collect()
    })
}

/// trunk fast-forwards to `commit`; git refuses if trunk moved. (TCB: git)
#[verifier::external_body]
pub fn fast_forward(m: &Manifest, commit: &Commit) -> (r: Result<(), String>) {
    let c: String = commit.iter().collect();
    git(&m.root, &["merge", "--ff-only", "--quiet", &c]).map(|_| ())
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
pub fn agree_outputs(m: &Manifest, commit: &Commit) -> (r: Result<Vec<u64>, String>) {
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
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(out)
}

} // verus!

/// One agent process: generate, capture, observe. Its log goes under `trace`.
#[allow(clippy::too_many_arguments)]
fn agent_process(m: &Manifest, kind: &Kind, search: usize, index: usize, h: &Harness, start: &str, map: &str,
                 target: Option<&Search>, trace: &std::path::Path) -> (Option<Candidate>, u64) {
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
    let spent = cost(h, config, &stdout).unwrap_or(micro(config.agent_process.limit));
    if killed { let _ = std::fs::write(trace.join("killed"), "time limit"); }
    let candidate = capture(m, kind, search, index, start, &dir, target, trace).map_err(|e| {
        let _ = std::fs::write(trace.join("error"), &e);
    }).ok();
    let _ = std::fs::remove_dir_all(&dir);
    let build = scratch(&format!("{search}-{index}-build"));
    let _ = as_agent(config, std::path::Path::new("/tmp"), &[], &["rm".into(), "-rf".into(), build.to_string_lossy().into()]).status();
    let text = |v: &Vec<char>| v.iter().collect::<String>();
    let facts = serde_json::json!({
        "harness": h.name, "model": h.model, "cost_microdollars": spent, "killed": killed,
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
           target: Option<&Search>, trace: &std::path::Path) -> Result<Candidate, String> {
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
            let tdir = scratch(&format!("{search}-{index}-test-{j}"));
            let passes = match (&test, materialize(root, &mc, &tdir)) {
                (Some(bytes), Ok(())) => {
                    let p = tdir.join(&config.counterexample.path);
                    let _ = std::fs::create_dir_all(p.parent().unwrap_or(&tdir));
                    let _ = std::fs::write(&p, bytes);
                    let _ = Command::new("chmod").args(["-R", "a-w,g+rX"]).arg(&tdir).status();
                    run_check(config, &tdir, &build, &config.counterexample.test, &trace.join(format!("test-{j}"))).0
                }
                _ => false,
            };
            test_passes.push((j, passes));
            let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&tdir).status();
            let _ = std::fs::remove_dir_all(&tdir);
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
        toml::from_str(r#"
            limit = 5.0
            rate = 150
            path = ["/usr/bin"]
            agent_process = { limit = 0.5, time = 60 }
            checks = { paths = ["checks/"], verify = ["true"] }
            harness = [{ name = "claude", model = "haiku", n = 2 }]
            counterexample = { harness = [{ name = "codex", model = "mini", n = 1 }], path = "c.sh", test = "sh c.sh" }
            prices = { haiku = { input = 1.0, output = 5.0, cache_read = 0.1, cache_write = 1.25 }, mini = { input = 0.25, output = 2.0 } }
        "#).unwrap()
    }

    #[test]
    fn claude_cost_is_the_result_usage_priced() {
        let c = config();
        let out = r#"{"type":"assistant"}
{"type":"result","usage":{"input_tokens":1000000,"output_tokens":100000,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}"#;
        assert_eq!(cost(&c.harness[0], &c, out), Ok(1_500_000));
    }

    #[test]
    fn codex_cost_sums_turns_and_prices_cached_input_apart() {
        let c = config();
        let h = &c.counterexample.harness[0];
        let out = r#"{"type":"turn.completed","usage":{"input_tokens":1000000,"cached_input_tokens":0,"output_tokens":0}}
{"type":"turn.completed","usage":{"input_tokens":0,"cached_input_tokens":0,"output_tokens":1000000}}"#;
        assert_eq!(cost(h, &c, out), Ok(2_250_000));
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(toml::from_str::<Config>("limit = 1.0\nbogus = 2").is_err());
    }
}
