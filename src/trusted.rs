//! Trusted code. Every function the verified code calls from here is
//! `#[verifier::external_body]`: Verus does not check it. The TCB is this file,
//! the entry points (main.rs, view.rs, wasm.rs), plus what they run: git, sudo, tar, chmod, the harnesses (`claude`, `codex`)
//! and the checks the manifest declares.
//!
//! It observes and reports facts; it decides nothing. Every decision is a gate.
//!
//! Everything bon keeps in a repository is under `.bon/`: the manifest
//! (bon.toml), the queue (queue.tsv) and the SBOM, tracked; the traces, not.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use vstd::prelude::*;

use crate::gates::{Candidate, Commit, Cue, Hash, Intent, Kind, Path, Permission, Search};
use crate::spec;
use crate::gates::Transcript;

// The text types at the trusted edge: each reads as its chars and is built from
// chars. Each stays its own type: a commit is never passed as a path.
impl std::ops::Deref for Commit { type Target = Vec<char>; fn deref(&self) -> &Vec<char> { &self.0 } }
impl std::ops::Deref for Path { type Target = Vec<char>; fn deref(&self) -> &Vec<char> { &self.0 } }
impl std::ops::Deref for Intent { type Target = Vec<char>; fn deref(&self) -> &Vec<char> { &self.0 } }
impl std::ops::Deref for Transcript { type Target = Vec<char>; fn deref(&self) -> &Vec<char> { &self.0 .0 } }
impl FromIterator<char> for Commit { fn from_iter<I: IntoIterator<Item = char>>(i: I) -> Self { Commit(i.into_iter().collect()) } }
impl FromIterator<char> for Path { fn from_iter<I: IntoIterator<Item = char>>(i: I) -> Self { Path(i.into_iter().collect()) } }
impl FromIterator<char> for Intent { fn from_iter<I: IntoIterator<Item = char>>(i: I) -> Self { Intent(i.into_iter().collect()) } }
impl FromIterator<char> for Transcript { fn from_iter<I: IntoIterator<Item = char>>(i: I) -> Self { Transcript(Path(i.into_iter().collect())) } }

// ── bon.toml ────────────────────────────────────────────

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "trunk_default")]
    pub trunk: String,
    /// The remote whose trunk is the golden trunk: searches start from it, and
    /// every selected candidate is pushed to it.
    #[serde(default = "remote_default")]
    pub remote: String,
    /// The bon process's limit, in dollars.
    pub limit: f64,
    /// engineer's time, in dollars per hour.
    pub rate: f64,
    #[serde(default)]
    pub transcripts: Option<String>,
    /// The private git remote that holds this repository's traces: they hold
    /// prompts, arguments and outputs, so never the repository's own remote.
    #[serde(default)]
    pub traces: Option<String>,
    /// PATH for agent processes and checks, from the host file. Nothing is inherited.
    #[serde(skip)]
    pub path: Vec<String>,
    pub agent_process: AgentProcessConfig,
    pub checks: Checks,
    pub harness: Vec<Harness>,
    pub counterexample: Counterexample,
    /// What `bon sbom` lists beyond the lockfiles; its `trusted` list is also every search's trusted code.
    #[serde(default)]
    pub sbom: Option<toml::Value>,
    /// What `bon types` emits for programs: read by it alone.
    #[serde(default)]
    pub programs: Option<toml::Value>,
    /// Prices by canonical model, from the host file.
    #[serde(skip)]
    pub prices: HashMap<String, Price>,
    /// How many agent processes run at once, from the host file.
    #[serde(skip)]
    pub jobs: usize,
}

/// What is true of this machine rather than of a repository, written by
/// `bon setup` and owned by root: where agent's tools live, and model prices.
pub const HOST: &str = "/etc/bon/host.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    path: Vec<String>,
    prices: HashMap<String, Price>,
    /// How many agent processes run at once; width stays what bon.toml says.
    /// Default: half the cores.
    #[serde(default)]
    jobs: Option<usize>,
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
    /// The tests: a candidate is accepted when each exits 0.
    pub test: Vec<String>,
    /// Verus: a candidate is proved when each exits 0.
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
    /// Where an agent process writes its test; under one of `tests`.
    pub path: String,
    /// The command that builds its test: a test that does not build is rejected.
    pub build: String,
    /// The command that runs its test: exit 0 means it accepts the commit.
    pub run: String,
    /// The paths holding the counterexamples' tests on trunk: code may not
    /// change them; compaction may.
    pub tests: Vec<String>,
    /// All an agent process sees besides the checks, the tests and `.bon/`:
    /// the spec and the interface, never the implementation. Empty: everything.
    #[serde(default)]
    pub visible: Vec<String>,
}

/// Where a counterexample's test lands on trunk: the counterexample path with a
/// short hash of the test before its extension, so each keeps its own file.
fn landed_path(config: &Config, test: &[u8]) -> String {
    let p = &config.counterexample.path;
    let id = format!("{:08x}", hash(&String::from_utf8_lossy(test)) >> 32);
    match p.rsplit_once('.') { Some((stem, ext)) if !ext.contains('/') => format!("{stem}_{id}.{ext}"), _ => format!("{p}_{id}") }
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

/// The directory holding every working directory: owned by engineer, mode 0711,
/// so agent may search it (pass through to a path it was given) but not list it
/// or add to it. /tmp is cleared on reboot, so bon makes it when it is missing;
/// the isolated gate checks it.
pub const WORKING_DIRECTORIES: &str = "/tmp/bon";

/// The repository's name, the last part of every working directory's path, so
/// an agent process works in a directory named like any checkout of it.
fn repository_name(root: &std::path::Path) -> String {
    root.file_name().map_or("repository".into(), |n| n.to_string_lossy().to_string())
}

/// A directory for this bon process under WORKING_DIRECTORIES:
/// `<pid>.<owner>/<rest>`, where owner names what it is for (`<search>.<index>`
/// for an agent process, `trunk`, `goal`, `probe`, `test.<hash>`). The owner's
/// directory is engineer's, group bon, mode 2750: agent may enter it, not add
/// to it.
fn scratch(name: &str) -> PathBuf {
    let base = PathBuf::from(WORKING_DIRECTORIES);
    if !base.exists() {
        let _ = std::fs::create_dir_all(&base);
    }
    let _ = Command::new("chmod").arg("0711").arg(&base).stderr(Stdio::null()).status();
    let (owner, rest) = name.split_once('/').unwrap_or((name, ""));
    let dir = base.join(format!("{}.{owner}", std::process::id()));
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = Command::new("chgrp").arg("bon").arg(&dir).status();
        let _ = Command::new("chmod").arg("2750").arg(&dir).status();
    }
    if rest.is_empty() { dir } else { dir.join(rest) }
}

/// A directory made by engineer that agent (through group bon) may write in.
fn writable_dir(d: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    let ok = Command::new("chgrp").arg("bon").arg(d).status().is_ok_and(|s| s.success())
        && Command::new("chmod").arg("2770").arg(d).status().is_ok_and(|s| s.success());
    if ok { Ok(()) } else { Err(format!("cannot make {} writable by group bon", d.display())) }
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
/// write everything except the check paths, the transcripts and `.bon/`, which
/// it may read and execute but not write, rename or delete. (TCB: POSIX ACLs)
fn working_directory(root: &std::path::Path, config: &Config, commit: &str, dir: &std::path::Path) -> Result<(), String> {
    working_directory_except(root, config, commit, dir, None, &[])
}

/// A working directory whose protected paths exclude `writable` (the queue, for
/// a queue search) and also include `more` (the tests, for a code search).
fn working_directory_except(root: &std::path::Path, config: &Config, commit: &str, dir: &std::path::Path,
                            writable: Option<&str>, more: &[String]) -> Result<(), String> {
    materialize(root, commit, dir)?;
    sh(dir, "chmod", &["-R", "g+rwX", "."])?;
    sh(dir, "find", &[".", "-type", "d", "-exec", "chmod", "g+s", "{}", "+"])?;
    // The checks, the transcripts and .bon/: agent may read them, never change them.
    let transcripts = config.transcripts.clone().unwrap_or("transcripts".into());
    let bon = BON.to_string();
    for p in config.checks.paths.iter().chain([&transcripts, &bon]).chain(more.iter()) {
        if writable.is_some_and(|w| w.starts_with(p.trim_end_matches('/'))) { continue; }
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

/// Trunk's build, made once per bon process as agent. Every candidate's build
/// directory starts as a copy-on-write clone of it, so cargo rebuilds only what
/// the candidate changed; cargo's own change detection (TCB) keeps it correct.
static WARM: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
/// Whether Verus verified trunk's head: a counterexample or queue candidate
/// changes nothing Verus reads, so it is proved exactly when trunk is.
static TRUNK_PROVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// This bon process's runs so far: names its working directories, traces and refs.
static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// The latest run's kind and goal, for its line in searches.jsonl.
static LATEST: std::sync::Mutex<(String, String)> = std::sync::Mutex::new((String::new(), String::new()));

/// A kind's name and goal, as the trace records them.
fn label(kind: &Kind) -> (String, String) {
    let text = |v: &[char]| v.iter().collect::<String>();
    match kind {
        Kind::Queue { goal } => ("queue".into(), text(goal)),
        Kind::Code { goal } => ("code".into(), text(goal)),
        Kind::Compaction { goal, .. } => ("compaction".into(), text(goal)),
        Kind::Counterexample { goal: Some(p) } => ("counterexample".into(), format!("search {} candidate {}", p.search, p.index)),
        Kind::Counterexample { goal: None } => ("counterexample".into(), "trunk".into()),
        Kind::Foil { goal: p } => ("foil".into(), format!("search {} candidate {}", p.search, p.index)),
    }
}
static WARMING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// This bon process runs as background work: no one waits on it, so its time
/// is charged at rate 0 and it costs its generation alone.
static BACKGROUND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Mark this bon process as background work.
pub fn background() { BACKGROUND.store(true, std::sync::atomic::Ordering::SeqCst); }

/// This bon process's trace directory.
fn trace_dir(root: &std::path::Path) -> PathBuf { root.join(BON).join("traces").join(format!("{}", std::process::id())) }

/// Run trunk's checks once, as agent, building trunk in the process: (every
/// test accepts trunk, Verus verifies it). Each candidate's build starts from it.
fn warm(m: &Manifest, head: &str) -> (bool, bool) {
    WARMING.store(true, std::sync::atomic::Ordering::SeqCst);
    let (config, root) = (&m.config, &m.root);
    let mut result = (false, false);
    let built = (|| -> Option<PathBuf> {
        let dir = scratch(&format!("trunk/{}", repository_name(root)));
        check_directory(root, head, &dir).ok()?;
        let build = scratch("trunk.build/build");
        writable_dir(&build).ok()?;
        let log = trace_dir(root);
        let _ = std::fs::create_dir_all(&log);
        let tests = config.checks.test.iter().enumerate().all(|(k, v)| run_check(config, &dir, &build, v, &log.join(format!("trunk-test-{k}"))).0);
        let proved = config.checks.verify.iter().enumerate().all(|(k, v)| run_check(config, &dir, &build, v, &log.join(format!("trunk-verify-{k}"))).0);
        result = (tests, proved);
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
        let _ = std::fs::remove_dir_all(&dir);
        Some(build)
    })();
    TRUNK_PROVED.store(result.1, std::sync::atomic::Ordering::SeqCst);
    let _ = WARM.set(built);
    result
}

fn build_directory(config: &Config, name: &str) -> Result<PathBuf, String> {
    let d = scratch(name);
    // Once trunk's build is under way, wait for it and start from a clone of it.
    let warm = if WARMING.load(std::sync::atomic::Ordering::SeqCst) {
        let start = Instant::now();
        while WARM.get().is_none() && start.elapsed() < Duration::from_secs(config.agent_process.time) {
            std::thread::sleep(Duration::from_millis(500));
        }
        WARM.get().cloned().flatten()
    } else { None };
    // engineer makes the directory; agent fills it with a clone of trunk's build.
    writable_dir(&d)?;
    if let Some(w) = &warm {
        let argv: Vec<String> = vec!["cp".into(), "-cR".into(), format!("{}/", w.display()), d.to_string_lossy().into()];
        let ok = as_agent(config, std::path::Path::new("/tmp"), &[], &argv).status().map_err(|e| e.to_string())?.success();
        if !ok { return Err(format!("{} as agent", argv.join(" "))); }
    }
    Ok(d)
}

/// Remove this bon process's directories under /tmp/bon, and any left by a bon
/// process no longer running. Each holds files of two owners: engineer's check
/// files (with an ACL denying agent) and agent's build output. So: engineer
/// removes its ACLs, agent removes what it can, engineer removes the rest.
pub fn cleanup(path: &[String]) {
    let me = std::process::id().to_string();
    // ps, not kill -0: kill -0 fails on another user's live process (EPERM),
    // which would read as dead.
    let running = |pid: &str| pid == me || Command::new("ps").args(["-p", pid]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    for e in std::fs::read_dir(WORKING_DIRECTORIES).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        // <pid>.<owner>; <pid>-<name> from before the working directories were 0711.
        let Some(pid) = name.split(['.', '-']).next() else { continue };
        if !pid.chars().all(|c| c.is_ascii_digit()) || (pid != me && running(pid)) { continue; }
        let p = e.path();
        let _ = Command::new("chmod").args(["-R", "-N"]).arg(&p).stderr(Stdio::null()).status();
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&p).stderr(Stdio::null()).status();
        let _ = Command::new("sudo").args(["-n", "-u", "agent", "env", "-i", &format!("PATH={}", path.join(":")), "rm", "-rf"])
            .arg(&p).current_dir("/tmp").stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(&p);
    }
}

// ── checks ──────────────────────────────────────────────

fn hash(s: &str) -> u64 {
    let d = Sha256::digest(s.as_bytes());
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Run a command as agent in a read-only checkout. (exit 0, stdout)
fn run_check(config: &Config, dir: &std::path::Path, target: &std::path::Path, command: &str, log: &std::path::Path) -> (bool, String) {
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()];
    let c = as_agent(config, dir, &[("BON_BUILD", target.to_string_lossy().into()), ("CARGO_TARGET_DIR", target.to_string_lossy().into())], &argv);
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
fn generation(h: &Harness, config: &Config, stdout: &str) -> Result<(u64, Option<u64>, HashMap<String, Price>), String> {
    let price = |model: &str| config.prices.get(model).ok_or(format!("no price for model {model}"));
    let rate = |p: &Price, input: f64, cached: f64, output: f64, write: f64, write_long: f64| {
        (input * p.input + cached * p.cached_input + output * p.output + write * p.cache_write + write_long * p.cache_write_long) / 1_000_000.0
    };
    let mut events = stdout.lines().rev().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok());
    if h.name == "claude" {
        let Some(r) = events.find(|v| v["type"] == "result") else { return Err("no result event".into()) };
        let mut ours = 0.0;
        let mut theirs = 0.0;
        let mut used = HashMap::new();
        for (model, u) in r["modelUsage"].as_object().into_iter().flatten() {
            used.insert(model.clone(), price(model)?.clone());
            let n = |k: &str| u[k].as_f64().unwrap_or(0.0);
            let (w5, w1) = (n("cacheCreationEphemeral5mInputTokens"), n("cacheCreationEphemeral1hInputTokens"));
            let w5 = if w5 + w1 == 0.0 { n("cacheCreationInputTokens") } else { w5 };
            ours += rate(price(model)?, n("inputTokens"), n("cacheReadInputTokens"), n("outputTokens"), w5, w1);
            theirs += n("costUSD");
        }
        Ok((micro(ours), Some(micro(theirs)), used))
    } else {
        let Some(t) = events.find(|v| v["type"] == "turn.completed") else { return Err("no turn.completed event".into()) };
        let n = |k: &str| t["usage"][k].as_f64().unwrap_or(0.0);
        let (cached, write) = (n("cached_input_tokens"), n("cache_write_input_tokens"));
        let input = (n("input_tokens") - cached - write).max(0.0);
        let p = price(&h.model)?;
        Ok((micro(rate(p, input, cached, n("output_tokens"), write, 0.0)), None, HashMap::from([(h.model.clone(), p.clone())])))
    }
}

fn prompt(kind: &Kind, config: &Config) -> String {
    let c = &config.counterexample;
    let blind = if c.visible.is_empty() { "" } else { "You will not see any implementation's code on purpose: write it from the spec and the checks alone." };
    let goal = match kind {
        Kind::Code { .. } => "Trunk's checks reject this code. Change the code until every check accepts it.\n".to_string(),
        Kind::Compaction { .. } => format!(
            "Remove what is stale, in the code and in the tests under {:?}, or write it cleaner, without changing \
             behavior: every check must still accept it, the program must print the same, and the tests must \
             still reject every counterexample they were written for.\n", c.tests),
        Kind::Counterexample { goal: Some(_) } => format!(
            "Several implementations were written, separately, so that trunk's checks accept them. {blind} \
             Write one test, at {}, that every correct implementation accepts and a plausible wrong reading \
             of the spec rejects. It builds with: {}. It runs with: {}.\n", c.path, c.build, c.run),
        Kind::Counterexample { goal: None } => format!(
            "{blind} Write one test, at {}, aimed at a behavior the spec forbids that an implementation \
             might still show: a correct implementation accepts it. It builds with: {}. It runs with: {}.\n",
            c.path, c.build, c.run),
        Kind::Foil { .. } => format!(
            "This code is an implementation trunk's checks accept. Change its behavior so that it does \
             something the spec forbids while every test still passes: Verus must reject it because the \
             code no longer meets the spec, not only because a proof broke. Do not change the tests under {:?}.\n",
            c.tests),
        Kind::Queue { goal } => format!(
            "Read the transcript at {} and append to {QUEUE} one line per need it voices that the spec does \
             not state yet: a tab, the intent in the speaker's words, a tab, then the transcript path, '#', \
             and the cue's start time.\n", goal.iter().collect::<String>()),
    };
    format!(
        "You are working in a copy of a repository, with no git. {goal}\n\
         The checks are {paths:?}: read and run them, never change them; you cannot.\n\
         The tests run with: {test:?}. Verus runs with: {verify:?}.\n\
         {scope} Reply with one line saying what you changed.",
        paths = config.checks.paths, test = config.checks.test, verify = config.checks.verify,
        // Smallest change is right for every kind but compaction, whose goal is to remove.
        scope = if matches!(kind, Kind::Compaction { .. }) { "" } else { "Make the smallest change that does this." })
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
    let text = git(&root, &["show", &format!("{c}:{MANIFEST}")]).map_err(|_| format!("no {MANIFEST} at trunk's head; commit one"))?;
    let mut config: Config = toml::from_str(&text).map_err(|e| format!("{MANIFEST}: {e}"))?;
    let host: Host = toml::from_str(&std::fs::read_to_string(HOST).map_err(|_| format!("no {HOST}; run bon setup"))?)
        .map_err(|e| format!("{HOST}: {e}"))?;
    config.path = host.path;
    config.prices = host.prices;
    config.jobs = host.jobs.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).max(1)));
    for h in config.harness.iter().chain(config.counterexample.harness.iter()) {
        if !config.prices.contains_key(&h.model) {
            return Err(format!("{HOST}: no price for {}; bon.toml must name canonical model ids", h.model));
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

/// The paths holding the counterexamples' tests.
#[verifier::external_body]
pub fn tests(m: &Manifest) -> Vec<Path> { m.config.counterexample.tests.iter().map(|p| p.chars().collect()).collect() }

/// The trusted code the manifest's SBOM declares: no search may change it.
#[verifier::external_body]
pub fn trusted(m: &Manifest) -> Vec<Path> {
    m.config.sbom.as_ref().and_then(|s| s.get("trusted")).and_then(|t| t.as_array())
        .map(|a| a.iter().filter_map(|p| p.as_str()).map(|p| p.chars().collect()).collect()).unwrap_or_default()
}

/// The harnesses a search of this kind draws from.
#[verifier::external]
fn harnesses(config: &Config, kind: &Kind) -> Vec<Harness> {
    match kind {
        Kind::Counterexample { .. } | Kind::Foil { .. } => config.counterexample.harness.clone(),
        _ => config.harness.clone(),
    }
}

/// How many agent processes one harness runs on attempt `a`.
#[verifier::external]
fn at(h: &Harness, a: usize) -> usize { h.n.get(a).or(h.n.last()).copied().unwrap_or(0) }

/// How many agent processes run at once: the host's `jobs`, at least one, never
/// more than the search has. Width stays what bon.toml says. (queue 26)
#[verifier::external]
fn workers(jobs: usize, width: usize) -> usize { jobs.max(1).min(width) }

/// Whether a harness's own status command says it is logged in, from its exit and output.
#[verifier::external]
fn logged_in(harness: &str, ok: bool, out: &str) -> bool {
    match harness {
        "claude" => out.contains("\"loggedIn\": true") || out.contains("\"loggedIn\":true"),
        _ => ok && out.contains("Logged in"),
    }
}

/// Before a search: each harness bon.toml names is logged in as agent, checked
/// the way bon runs it. If one is not, the command that fixes it. (queue 32)
#[verifier::external_body]
pub fn harnesses_logged_in(m: &Manifest) -> (r: Result<(), String>) {
    let mut names: Vec<&str> = m.config.harness.iter().chain(m.config.counterexample.harness.iter()).map(|h| h.name.as_str()).collect();
    names.sort(); names.dedup();
    for name in names {
        let argv: Vec<String> = match name { "claude" => vec!["claude".into(), "auth".into(), "status".into()], _ => vec!["codex".into(), "login".into(), "status".into()] };
        let (ok, out) = match as_agent(&m.config, std::path::Path::new("/tmp"), &[], &argv).output() {
            Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)),
            Err(e) => (false, e.to_string()),
        };
        if !logged_in(name, ok, &out) {
            let fix = match name { "claude" => "sudo -u agent -i claude", _ => "sudo -u agent -i codex login" };
            return Err(format!("{name} is not logged in as agent; run: {fix}"));
        }
    }
    Ok(())
}

/// How many agent processes a search of this kind runs on attempt `a`.
#[verifier::external_body]
pub fn width(m: &Manifest, kind: &Kind, a: usize) -> usize {
    harnesses(&m.config, kind).iter().map(|h| at(h, a)).sum()
}

/// How many attempts a command makes: the longest width list.
#[verifier::external_body]
pub fn attempts(m: &Manifest) -> usize {
    m.config.harness.iter().chain(m.config.counterexample.harness.iter()).map(|h| h.n.len()).max().unwrap_or(1)
}

/// A candidate commit kept in its trace as a git bundle, so it outlives git's
/// garbage collection with no ref: a counterexample's evidence. (TCB: git)
#[verifier::external]
fn bundle(m: &Manifest, commit: &str, base: &str, trace: &std::path::Path) -> Option<String> {
    let file = trace.join("candidate.bundle");
    let _ = std::fs::create_dir_all(trace);
    let ok = Command::new("git").args(["bundle", "create", "-q"]).arg(&file).arg(commit).arg(format!("^{base}"))
        .current_dir(&m.root).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    ok.then(|| file.strip_prefix(&m.root).unwrap_or(&file).to_string_lossy().to_string())
}

/// The test of x's candidate i lands on the remote's trunk by itself: its
/// commit, whose parent is trunk's head, fast-forward only; then the local trunk
/// follows. Its evidence, for compaction to keep rejecting: the members of t it
/// rejects, each kept as a bundle; or, on trunk's head (t None), trunk's head,
/// which git keeps. (TCB: git, the remote)
#[verifier::external_body]
pub fn land(m: &Manifest, x: &Search, i: usize, t: Option<&Search>) -> (r: Result<(), String>) {
    let Some(Some(c)) = x.results.get(i) else { return Err("no candidate to land".into()) };
    let commit: String = c.commit.iter().collect();
    let path = c.changed.iter().map(|p| p.iter().collect::<String>()).next()
        .ok_or_else(|| "the test changed no path".to_string())?;
    let mut evidence: Vec<String> = Vec::new();
    match t {
        None => evidence.push(x.base.iter().collect()),
        Some(t) => {
            let d = trace_dir(&m.root);
            let search = RUNS.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(2);
            for (j, accepts) in c.accepts.iter() {
                if *accepts || *j < 0 { continue; }
                if let Some(Some(e)) = t.results.get(*j as usize) {
                    let ec: String = e.commit.iter().collect();
                    let eb: String = e.base.iter().collect();
                    if bundle(m, &ec, &eb, &d.join(search.to_string()).join(j.to_string())).is_some() { evidence.push(ec); }
                }
            }
        }
    }
    let (r, tr) = (&m.config.remote, &m.config.trunk);
    git(&m.root, &["push", "--quiet", r, &format!("{commit}:refs/heads/{tr}")])
        .map_err(|e| format!("blocked: {r}/{tr} moved during the search, so the test could not land; run it again ({e})"))?;
    git(&m.root, &["merge", "--ff-only", "--quiet", &commit])?;
    append(&m.root.join(BON).join("traces").join("counterexamples.jsonl"),
           &serde_json::json!({ "test": path, "evidence": evidence }));
    Ok(())
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

/// Every test check and every verify check on a commit, run as agent in a
/// checkout without `.git`, the way candidates are judged; each one's name,
/// whether it exited 0, and its log. All of them run, not only until one fails.
#[verifier::external]
pub fn check(m: &Manifest, commit: &Commit) -> Result<Vec<(String, bool, PathBuf)>, String> {
    let (config, root) = (&m.config, &m.root);
    let c: String = commit.iter().collect();
    let dir = scratch(&format!("check/{}", repository_name(root)));
    check_directory(root, &c, &dir)?;
    let build = scratch("check.build/build");
    writable_dir(&build)?;
    let log = trace_dir(root);
    let _ = std::fs::create_dir_all(&log);
    let mut out = Vec::new();
    for (kind, list) in [("test", &config.checks.test), ("verify", &config.checks.verify)] {
        for (k, v) in list.iter().enumerate() {
            let path = log.join(format!("check-{kind}-{k}"));
            let ok = run_check(config, &dir, &build, v, &path).0;
            out.push((v.clone(), ok, path));
        }
    }
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(out)
}

/// Whether trunk's checks accept its head: every test accepts it and Verus
/// verifies it. Builds trunk for the candidates.
#[verifier::external_body]
pub fn trunk_accepted(m: &Manifest, head: &Commit) -> bool {
    let h: String = head.iter().collect();
    let (tests, proved) = warm(m, &h);
    tests && proved
}

/// agent's effective permissions on each file the policy covers, observed by
/// asking as agent, on a probe working directory made the same way as real ones.
#[verifier::external_body]
pub fn observe(m: &Manifest, commit: &Commit) -> (r: Result<(Permission, Permission, Permission, Permission, Permission), String>) {
    let c: String = commit.iter().collect();
    let probe = scratch(&format!("probe/{}", repository_name(&m.root)));
    if let Err(e) = working_directory(&m.root, &m.config, &c, &probe) {
        let _ = std::fs::remove_dir_all(&probe);
        return Err(format!("agent is not set up ({e}); run bon setup"));
    }
    let ask = |path: &std::path::Path, flag: &str| -> bool {
        Command::new("sudo").args(["-n", "-u", "agent", "test", flag]).arg(path).status().map_or(false, |s| s.success())
    };
    let perm = |path: &std::path::Path| Permission { read: ask(path, "-r"), write: ask(path, "-w"), execute: ask(path, "-x") };
    let check = m.config.checks.paths.first().map(|p| probe.join(p.trim_end_matches('/'))).ok_or("no check paths")?;
    // A check that is a file is run by an interpreter that reads it (sh, cargo),
    // so for a file, execute is whether agent can read it.
    let check_perm = |path: &std::path::Path| {
        let p = perm(path);
        if path.is_dir() { p } else { Permission { execute: p.read, ..p } }
    };
    // The transcripts as agent meets them: in a working directory.
    let transcripts = probe.join(m.config.transcripts.clone().unwrap_or("transcripts".into()));
    let r = (check_perm(&check), if transcripts.exists() { perm(&transcripts) } else { Permission { read: true, write: false, execute: true } },
             perm(&probe), perm(&m.root.join(".git")), perm(std::path::Path::new(WORKING_DIRECTORIES)));
    let _ = std::fs::remove_dir_all(&probe);
    Ok(r)
}

/// Run a search's agent processes in parallel and observe each: its candidate
/// (None if it produced none) and its cost in microdollars. `target` is the
/// search a counterexample attacks; `foils`, the foil search its tests must
/// tell from correct code.
#[verifier::external_body]
pub fn run(m: &Manifest, kind: &Kind, a: usize, start: &Commit, target: Option<&Search>, foils: Option<&Search>) -> Vec<(Option<Candidate>, u64)> {
    // Number runs once per bon process, so a command that runs several drivers
    // (a counterexample on trunk, then a code search) never reuses a working directory or trace.
    let search = RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut l) = LATEST.lock() { *l = label(kind); }
    let start: String = start.iter().collect();
    if !WARMING.load(std::sync::atomic::Ordering::SeqCst) { warm(m, &start); }
    let hs = harnesses(&m.config, kind);
    let slots: Vec<Harness> = hs.iter().flat_map(|h| std::iter::repeat(h.clone()).take(at(h, a))).collect();
    let traces = trace_dir(&m.root).join(search.to_string());
    let _ = std::fs::create_dir_all(&traces);
    // At most `jobs` agent processes at once; each worker takes the next index.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: Vec<std::sync::Mutex<(Option<Candidate>, u64)>> = slots.iter().map(|_| std::sync::Mutex::new((None, 0))).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers(m.config.jobs, slots.len()) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(h) = slots.get(i) else { break };
                *out[i].lock().unwrap() = agent_process(m, kind, search, i, h, &start, target, foils, &traces.join(i.to_string()));
            });
        }
    });
    out.into_iter().map(|c| c.into_inner().unwrap_or((None, 0))).collect()
}

/// The selected candidate is pushed to the remote's trunk, then the local trunk
/// follows. The push is fast-forward only: if the remote's trunk moved, it is
/// refused and nothing changes. (TCB: git, the remote)
#[verifier::external_body]
pub fn push(m: &Manifest, commit: &Commit) -> (r: Result<(), String>) {
    let c: String = commit.iter().collect();
    let (r, t) = (&m.config.remote, &m.config.trunk);
    git(&m.root, &["push", "--quiet", r, &format!("{c}:refs/heads/{t}")])
        .map_err(|e| format!("blocked: {r}/{t} moved during the search, so the push was refused; run it again ({e})"))?;
    git(&m.root, &["merge", "--ff-only", "--quiet", &c])?;
    record_cost(m, &c);
    Ok(())
}

#[verifier::external]
fn append(file: &std::path::Path, line: &serde_json::Value) {
    if let Some(d) = file.parent() { let _ = std::fs::create_dir_all(d); }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(file) {
        let _ = writeln!(f, "{line}");
    }
}

/// Each push's cost: the generation and time cost of every search this bon
/// process ran to reach it (blocked attempts, reruns and counterexample
/// searches included), from its searches.jsonl, appended to pushes.jsonl.
#[verifier::external_body]
pub fn record_cost(m: &Manifest, commit: &str) {
    let d = trace_dir(&m.root);
    let searches: Vec<serde_json::Value> = std::fs::read_to_string(d.join("searches.jsonl")).unwrap_or_default()
        .lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let sum = |k: &str| searches.iter().filter_map(|s| s[k].as_f64()).sum::<f64>();
    let (generation, time) = (sum("generation_dollars"), sum("time_dollars"));
    eprintln!("bon: push {}: {} searches; generation ${generation:.4} + time ${time:.4} = ${:.4}",
              &commit[..commit.len().min(8)], searches.len(), generation + time);
    append(&d.join("pushes.jsonl"), &serde_json::json!({
        "commit": commit, "searches": searches.len(), "generation_dollars": generation, "time_dollars": time,
        "cost": generation + time,
        "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
    }));
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
/// passed.
#[verifier::external_body]
pub fn report(m: &Manifest, s: &Search, verified: usize, generation: u64, started: Clock) {
    let n = s.n;
    let search = RUNS.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
    let hours = started.at.elapsed().as_secs_f64() / 3600.0;
    let generation = generation as f64 / 1_000_000.0;
    // Background work is charged no time: no one waited on it.
    let background = BACKGROUND.load(std::sync::atomic::Ordering::SeqCst);
    let rate = if background { 0.0 } else { m.config.rate };
    let time = rate * hours;
    let per = if verified == 0 { None } else { Some((generation + time) / verified as f64) };
    let line = format!(
        "search {search}: {n} agent processes, {verified} verified; generation ${generation:.4} + time ${time:.4} ({:.0}s at ${}/h) = {}",
        hours * 3600.0, rate,
        per.map_or("no verified candidate".to_string(), |p| format!("${p:.4} per verified candidate")));
    eprintln!("bon: {line}");
    let d = trace_dir(&m.root);
    let _ = std::fs::create_dir_all(&d);
    let (kind, goal) = LATEST.lock().map(|l| l.clone()).unwrap_or_default();
    let summary = serde_json::json!({
        "search": search, "kind": kind, "goal": goal,
        "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        "agent_processes": n, "limit": s.limit as f64 / 1_000_000.0, "verified": verified, "generation_dollars": generation,
        "seconds": hours * 3600.0, "rate": rate, "background": background, "time_dollars": time,
        "cost_per_verified_candidate": per,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(d.join("searches.jsonl")) {
        let _ = writeln!(f, "{summary}");
    }
    // The search as the gates saw it, in the kernel's words (little-endian),
    // for programs to read and re-derive its selection.
    let words: Vec<u8> = <crate::exec::Kernel as crate::gates::Encoding>::encode(s).iter().flat_map(|w| w.to_le_bytes()).collect();
    let _ = std::fs::create_dir_all(d.join(search.to_string()));
    let _ = std::fs::write(d.join(search.to_string()).join("search.words"), words);
}

/// Record which candidate of the latest search was selected.
#[verifier::external_body]
pub fn record_selected(m: &Manifest, i: usize) {
    let search = RUNS.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
    record(m, &format!("selected {search} {i}"));
}

// ── the trace: each transition under its spec name, with its arguments ──
//
// A transition's recorder requires what the transition required, so Verus
// checks that each caller records the arguments it fired. The other lines
// (selected, blocked, not found, proposal, over limit) say what the bon
// process concluded; a replay skips them.

/// initialize: trunk's head as root, and the bon process's limit.
#[verifier::external_body]
pub fn record_initialize(m: &Manifest, root: &Commit, limit: u64) {
    let root: String = root.iter().collect();
    record(m, &format!("initialize {root} {limit}"));
}

/// grant: its width, when, each agent process's limit, its kind and goal. The
/// last search is the one granted.
#[verifier::external_body]
pub fn record_grant(m: &Manifest, kind: &Kind, n: usize, agent_process_limit: u64, Ghost(searches): Ghost<Seq<spec::Search>>)
    requires
        searches.len() > 0,
        searches.last().kind == kind@,
        searches.last().n == n as nat,
        searches.last().limit == agent_process_limit as nat,
{
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (k, goal) = label(kind);
    record(m, &format!("grant {n} {now} {agent_process_limit} {k} {goal}"));
}

/// wait: when, the agent process, the commit it returned (or none), and its
/// generation in microdollars. Its result is the one the search now holds.
#[verifier::external_body]
pub fn record_wait(m: &Manifest, search: usize, index: usize, result: &Option<Candidate>, generation: u64, Ghost(searches): Ghost<Seq<spec::Search>>)
    requires
        search < searches.len(),
        searches[search as int].results.contains_key(index as int),
        searches[search as int].results[index as int] == (match result { Some(c) => Some(c@), None => None }),
{
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let commit = result.as_ref().map_or("none".to_string(), |c| c.commit.iter().collect());
    record(m, &format!("wait {now} {search} {index} {commit} {generation}"));
}

/// push: the tested search's selected candidate i, cleared by the counterexample
/// search, measured against the foil search.
#[verifier::external_body]
pub fn record_push(m: &Manifest, tested_index: usize, i: usize, counterexample_index: usize, foil_index: usize, Ghost(searches): Ghost<Seq<spec::Search>>)
    requires
        tested_index < searches.len(),
        counterexample_index < searches.len(),
        foil_index < searches.len(),
        spec::selected(searches[tested_index as int], i as int),
        searches[counterexample_index as int].kind == (spec::Kind::Counterexample { goal: Some(spec::AgentProcess { search: tested_index as int, index: i as int }) }),
        searches[foil_index as int].kind == (spec::Kind::Foil { goal: spec::AgentProcess { search: tested_index as int, index: i as int } }),
        spec::not_found(searches[counterexample_index as int], searches[tested_index as int], searches[foil_index as int]),
{
    record(m, &format!("push {tested_index} {i} {counterexample_index} {foil_index}"));
}

/// land: the counterexample search's test i.
#[verifier::external_body]
pub fn record_land(m: &Manifest, counterexample_index: usize, i: usize, Ghost(searches): Ghost<Seq<spec::Search>>)
    requires spec::lands(searches, counterexample_index as int, i as int),
{
    record(m, &format!("land {counterexample_index} {i}"));
}

/// A search blocked, and why.
#[verifier::external_body]
pub fn record_blocked(m: &Manifest, reason: &str) { record(m, &format!("blocked: {reason}")); }

/// A counterexample search on trunk found none, and why.
#[verifier::external_body]
pub fn record_not_found(m: &Manifest, reason: &str) { record(m, &format!("not found: {reason}")); }

/// A queue search ended in a proposal.
#[verifier::external_body]
pub fn record_proposal(m: &Manifest) { record(m, "proposal"); }

/// An agent process passed its limit and is charged at its limit.
#[verifier::external_body]
pub fn record_over_limit(m: &Manifest) { record(m, "over limit: an agent process passed its limit and is charged at it"); }

/// Append one line to this command's trace.
#[verifier::external]
fn record(m: &Manifest, line: &str) {
    let d = trace_dir(&m.root);
    let _ = std::fs::create_dir_all(&d);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(d.join("transitions")) {
        let _ = writeln!(f, "{line}");
    }
}

/// The agree checks' outputs at a commit, hashed: a compaction search's goal.
#[verifier::external_body]
pub fn agree_outputs(m: &Manifest, commit: &Commit) -> (r: Result<Vec<Hash>, String>) {
    let c: String = commit.iter().collect();
    let dir = scratch(&format!("goal/{}", repository_name(&m.root)));
    check_directory(&m.root, &c, &dir)?;
    let build = build_directory(&m.config, "goal/build")?;
    let log = trace_dir(&m.root);
    let _ = std::fs::create_dir_all(&log);
    let mut out = Vec::new();
    for (k, a) in m.config.checks.agree.iter().enumerate() {
        out.push(Hash(hash(&run_check(&m.config, &dir, &build, a, &log.join(format!("goal-agree-{k}"))).1)));
    }
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(out)
}

} // verus!

/// bon's directory in a repository, and what it tracks there.
pub const BON: &str = ".bon";
pub const MANIFEST: &str = ".bon/bon.toml";
pub const QUEUE: &str = ".bon/queue.tsv";
pub const SBOM: &str = ".bon/sbom.json";

/// One agent process: generate, capture, observe. Its log goes under `trace`.
#[allow(clippy::too_many_arguments)]
fn agent_process(m: &Manifest, kind: &Kind, search: usize, index: usize, h: &Harness, start: &str,
                 target: Option<&Search>, foils: Option<&Search>, trace: &std::path::Path) -> (Option<Candidate>, u64) {
    let _ = std::fs::create_dir_all(trace);
    let config = &m.config;
    let dir = scratch(&format!("{search}.{index}/{}", repository_name(&m.root)));
    // What each kind may not write, made structural: code, the counterexamples' tests.
    let (writable, more) = match kind {
        Kind::Queue { .. } => (Some(QUEUE), Vec::new()),
        Kind::Code { .. } | Kind::Foil { .. } => (None, config.counterexample.tests.clone()),
        _ => (None, Vec::new()),
    };
    if let Err(e) = working_directory_except(&m.root, config, start, &dir, writable, &more) {
        let _ = std::fs::write(trace.join("error"), e);
        return (None, 0);
    }
    if let Kind::Counterexample { .. } = kind {
        if !config.counterexample.visible.is_empty() {
            let mut keep: Vec<String> = config.counterexample.visible.iter().chain(config.checks.paths.iter())
                .chain(config.counterexample.tests.iter()).cloned().collect();
            keep.push(BON.to_string());
            prune(&dir, &keep);
        }
    }
    let argv = harness_argv(h, config, &dir);
    let _ = std::fs::write(trace.join("argv"), argv.join(" "));
    let text = prompt(kind, config);
    let _ = std::fs::write(trace.join("prompt"), &text);
    let c = as_agent(config, &dir, &[], &argv);
    let (_, stdout, killed) = supervise(c, Some(text), Duration::from_secs(config.agent_process.time), &trace.join("harness"));
    // Without token counts there is no measured cost: charge the whole limit.
    let (spent, harness_cost, prices) = generation(h, config, &stdout).unwrap_or((micro(config.agent_process.limit), None, HashMap::new()));
    if killed { let _ = std::fs::write(trace.join("killed"), "time limit"); }
    let candidate = capture(m, kind, search, index, start, &dir, target, foils, trace).map_err(|e| {
        let _ = std::fs::write(trace.join("error"), &e);
    }).ok();
    let _ = Command::new("chmod").args(["-R", "-N"]).arg(&dir).stderr(Stdio::null()).status();
    let _ = std::fs::remove_dir_all(&dir);
    let build = scratch(&format!("{search}.{index}.build/build"));
    // agent empties its build directory; engineer removes the directory itself at cleanup.
    let _ = as_agent(config, std::path::Path::new("/tmp"), &[], &["rm".into(), "-rf".into(), build.to_string_lossy().into()])
        .stderr(Stdio::null()).status();
    let text = |v: &[char]| v.iter().collect::<String>();
    // Lines added and removed, apart: the kernel's diff is their sum.
    let (added, removed) = candidate.as_ref().map_or((0, 0), |c| added_removed(&m.root, &text(&c.base), &text(&c.commit)));
    let facts = serde_json::json!({
        "harness": h.name, "model": h.model, "generation_microdollars": spent, "killed": killed,
        "harness_generation_microdollars": harness_cost,
        // The prices this cost was computed at, so the trace stays true when the host's prices change.
        "prices": prices,
        // The harness's own figure differs from bon's by more than 5%: the price table or the harness is stale.
        "price_mismatch": harness_cost.is_some_and(|c| (c as f64 - spent as f64).abs() > 0.05 * (c.max(spent).max(1) as f64)),
        "over_limit": spent > micro(config.agent_process.limit),
        "candidate": candidate.as_ref().map(|c| serde_json::json!({
            "commit": text(&c.commit), "base": text(&c.base), "accepted": c.accepted, "proved": c.proved,
            "changed": c.changed.iter().map(|p| text(p)).collect::<Vec<_>>(), "diff": c.diff, "added": added, "removed": removed, "rank": c.rank,
            "out": c.out.iter().map(|h| h.0).collect::<Vec<u64>>(), "accepts": c.accepts, "accepts_foils": c.accepts_foils, "rejects_counterexamples": c.rejects_counterexamples,
            "intents": c.intents.iter().map(|(q, i)| (q, text(i))).collect::<Vec<_>>(),
        })),
    });
    let _ = std::fs::write(trace.join("facts.json"), serde_json::to_string_pretty(&facts).unwrap_or_default());
    (candidate, spent)
}

/// Record the working directory as a commit whose parent is `start`, then
/// observe it: changed paths, diff, tests, Verus, agree outputs, rank, and what
/// its test accepts.
#[allow(clippy::too_many_arguments)]
fn capture(m: &Manifest, kind: &Kind, search: usize, index: usize, start: &str, dir: &std::path::Path,
           target: Option<&Search>, foils: Option<&Search>, trace: &std::path::Path) -> Result<Candidate, String> {
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
    // A counterexample's directory may be pruned, and a queue search writes one
    // file: record only what each may write.
    match kind {
        Kind::Counterexample { .. } => {
            for t in &config.counterexample.tests { if dir.join(t.trim_end_matches('/')).exists() { with(&["add", "-A", "--", t])?; } }
        }
        Kind::Queue { .. } => { if dir.join(QUEUE).exists() { with(&["add", "--", QUEUE])?; } }
        _ => { with(&["add", "-A", "."])?; }
    }
    let tree = with(&["write-tree"])?;
    let _ = std::fs::remove_file(&index_file);
    let (name, goal) = label(kind);
    let message = format!("{name}{}\n\nTrace: {BON}/traces/{}/{search}/{index}\n",
                          if goal.is_empty() { String::new() } else { format!(": {goal}") }, std::process::id());
    let commit_of = |tree: &str| -> Result<String, String> {
        let out = Command::new("git").args(["commit-tree", tree, "-p", start, "-m", &message]).current_dir(root)
            .env("GIT_AUTHOR_NAME", "agent").env("GIT_AUTHOR_EMAIL", "agent@localhost")
            .stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).to_string()); }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let commit = commit_of(&tree)?;
    let changes = |commit: &str| -> Result<(Vec<Path>, u64), String> {
        let numstat = git(root, &["diff-tree", "-r", "--numstat", "--no-renames", start, commit])?;
        let mut changed = Vec::new();
        let mut diff = 0u64;
        for l in numstat.lines() {
            let f: Vec<&str> = l.splitn(3, '\t').collect();
            if f.len() < 3 { continue; }
            diff += f[0].parse::<u64>().unwrap_or(1) + f[1].parse::<u64>().unwrap_or(1);
            changed.push(f[2].chars().collect::<Path>());
        }
        Ok((changed, diff))
    };
    let (mut changed, mut diff) = changes(&commit)?;
    let mut commit = commit;
    let mut written: Option<Vec<u8>> = None;

    // Checks run in a read-only checkout, as agent.
    let cdir = scratch(&format!("{search}.{index}.check/{}", repository_name(root)));
    check_directory(root, &commit, &cdir)?;
    let build = build_directory(config, &format!("{search}.{index}.build/build"))?;
    let trunk_proved = TRUNK_PROVED.load(std::sync::atomic::Ordering::SeqCst);
    let mut accepted = true;
    let mut proved = true;
    let mut accepts = Vec::new();
    let mut accepts_foils = Vec::new();
    let mut rejects_counterexamples = false;
    let mut out = Vec::new();
    let mut rank = 0i64;
    match kind {
        Kind::Code { .. } | Kind::Compaction { .. } | Kind::Foil { .. } => {
            for (k, v) in config.checks.test.iter().enumerate() {
                if !run_check(config, &cdir, &build, v, &trace.join(format!("test-{k}"))).0 { accepted = false; break; }
            }
            for (k, v) in config.checks.verify.iter().enumerate() {
                if !accepted { proved = false; break; }
                if !run_check(config, &cdir, &build, v, &trace.join(format!("verify-{k}"))).0 { proved = false; break; }
            }
            if accepted && proved && !matches!(kind, Kind::Foil { .. }) {
                for (k, a) in config.checks.agree.iter().enumerate() {
                    out.push(Hash(hash(&run_check(config, &cdir, &build, a, &trace.join(format!("agree-{k}"))).1)));
                }
                let which = if matches!(kind, Kind::Compaction { .. }) { "compaction" } else { "code" };
                if let Some(r) = config.checks.rank.get(which) {
                    rank = run_check(config, &cdir, &build, r, &trace.join("rank")).1.trim().parse().unwrap_or(0);
                }
                if matches!(kind, Kind::Compaction { .. }) {
                    rejects_counterexamples = rejects_every_counterexample(m, &commit, &build, trace);
                }
            }
        }
        Kind::Counterexample { .. } => {
            // Its test is accepted when it builds on the tree it tests: trunk's own build
            // lags a spec change that adds or changes a gate. Verus's verdict is trunk's.
            let test = std::fs::read(dir.join(&config.counterexample.path)).ok();
            written = test.clone();
            accepted = match &test {
                Some(bytes) => test_on(m, &tested_tree(kind, target, start), bytes, &build, &config.counterexample.build, &trace.join("build")),
                None => false,
            };
            proved = trunk_proved;
            let mut members: Vec<(i64, String)> = Vec::new();
            match target {
                Some(t) => {
                    if let Kind::Compaction { goal, .. } = &t.kind { members.push((-1, goal.iter().collect())); }
                    for (j, r) in t.results.iter().enumerate() {
                        if let Some(c) = r { members.push((j as i64, c.commit.iter().collect())); }
                    }
                }
                None => members.push((-1, start.to_string())),
            }
            if accepted {
                for (j, mc) in members {
                    let a = match &test { Some(bytes) => test_on(m, &mc, bytes, &build, &config.counterexample.run, &trace.join(format!("accepts-{j}"))), None => false };
                    accepts.push((j, a));
                }
                // Each foil: a program trunk's tests accept and Verus rejects. The
                // spec decides which results are foils; every result is run. A test
                // that does not build on a foil has no result on it: failing to
                // build is not telling a wrong program apart.
                if let (Some(f), Some(bytes)) = (foils, &test) {
                    for (j, r) in f.results.iter().enumerate() {
                        let Some(c) = r else { continue };
                        let fc: String = c.commit.iter().collect();
                        if !test_on(m, &fc, bytes, &build, &config.counterexample.build, &trace.join(format!("builds-foil-{j}"))) { continue; }
                        let a = test_on(m, &fc, bytes, &build, &config.counterexample.run, &trace.join(format!("accepts-foil-{j}")));
                        accepts_foils.push((j as i64, a));
                    }
                }
            }
        }
        Kind::Queue { .. } => {
            // Only the queue changed: trunk's verdicts stand; the lines must parse.
            proved = trunk_proved;
        }
    }
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&cdir).status();
    let _ = std::fs::remove_dir_all(&cdir);
    // A counterexample's test keeps its own file, where it lands: its commit
    // moves the test there, so the commit that lands is the candidate itself.
    if let (Kind::Counterexample { .. }, Some(bytes)) = (kind, &written) {
        let path = landed_path(config, bytes);
        with(&["read-tree", &commit])?;
        with(&["rm", "--cached", "-q", "--", &config.counterexample.path])?;
        let mut h = Command::new("git").args(["hash-object", "-w", "--stdin"]).current_dir(root)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
        h.stdin.take().ok_or("hash-object: no stdin")?.write_all(bytes).map_err(|e| e.to_string())?;
        let blob = String::from_utf8_lossy(&h.wait_with_output().map_err(|e| e.to_string())?.stdout).trim().to_string();
        with(&["update-index", "--add", "--cacheinfo", &format!("100644,{blob},{path}")])?;
        let tree = with(&["write-tree"])?;
        let _ = std::fs::remove_file(&index_file);
        commit = commit_of(&tree)?;
        (changed, diff) = changes(&commit)?;
    }

    let intents: Vec<(Cue, Intent)> = match kind {
        Kind::Queue { .. } => queue_intents(root, start, &commit),
        _ => Vec::new(),
    };
    Ok(Candidate {
        commit: commit.chars().collect(),
        base: start.chars().collect(),
        accepted,
        proved,
        changed,
        out,
        intents,
        accepts,
        accepts_foils,
        rejects_counterexamples,
        rank,
        diff,
    })
}

/// A compaction candidate's tests still reject every counterexample: for each
/// counterexample on record, its evidence's code with this commit's tests in
/// place is rejected by the tests. Evidence that cannot be read counts as not
/// rejected.
fn rejects_every_counterexample(m: &Manifest, commit: &str, build: &std::path::Path, trace: &std::path::Path) -> bool {
    let records: Vec<serde_json::Value> = std::fs::read_to_string(m.root.join(BON).join("traces").join("counterexamples.jsonl"))
        .unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let config = &m.config;
    for (k, r) in records.iter().enumerate() {
        for (e, evidence) in r["evidence"].as_array().into_iter().flatten().enumerate() {
            let Some(evidence) = evidence.as_str() else { return false };
            // Its bundle, if git no longer has it.
            if git(&m.root, &["cat-file", "-e", &format!("{evidence}^{{commit}}")]).is_err() {
                let bundles = Command::new("find").arg(m.root.join(BON).join("traces")).args(["-name", "candidate.bundle"])
                    .output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
                for b in bundles.lines() { let _ = git(&m.root, &["bundle", "unbundle", b]); }
                if git(&m.root, &["cat-file", "-e", &format!("{evidence}^{{commit}}")]).is_err() { return false; }
            }
            let dir = scratch(&format!("evidence.{k}.{e}/{}", repository_name(&m.root)));
            if materialize(&m.root, evidence, &dir).is_err() { return false; }
            // The candidate's tests, over the evidence's code.
            for t in &config.counterexample.tests {
                let _ = std::fs::remove_dir_all(dir.join(t.trim_end_matches('/')));
                let mut archive = match Command::new("git").args(["archive", "--format=tar", commit, "--", t]).current_dir(&m.root)
                    .stdout(Stdio::piped()).stderr(Stdio::null()).spawn() { Ok(a) => a, Err(_) => return false };
                let _ = Command::new("tar").arg("-x").arg("-C").arg(&dir).stdin(archive.stdout.take().unwrap()).status();
                let _ = archive.wait();
            }
            let _ = Command::new("chgrp").args(["-R", "bon"]).arg(&dir).status();
            let _ = Command::new("chmod").args(["-R", "a-w,g+rX"]).arg(&dir).status();
            let accepted = config.checks.test.iter().enumerate()
                .all(|(c, v)| run_check(config, &dir, build, v, &trace.join(format!("counterexample-{k}-{e}-{c}"))).0);
            let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
            let _ = std::fs::remove_dir_all(&dir);
            if accepted { return false; }
        }
    }
    true
}

/// Lines added and removed from `base` to `commit`, as git counts them.
pub fn added_removed(root: &std::path::Path, base: &str, commit: &str) -> (u64, u64) {
    git(root, &["diff", "--numstat", "--no-renames", base, commit]).unwrap_or_default().lines().fold((0, 0), |(a, r), l| {
        let f: Vec<&str> = l.splitn(3, '\t').collect();
        if f.len() < 3 { return (a, r); }
        (a + f[0].parse::<u64>().unwrap_or(0), r + f[1].parse::<u64>().unwrap_or(0))
    })
}

/// Whether a test accepts `commit`: a read-only checkout of it with the test at
/// the counterexample path, run as agent.
/// The tree a counterexample's test builds on: the selected candidate it tests,
/// or trunk's head.
fn tested_tree(kind: &Kind, target: Option<&Search>, start: &str) -> String {
    match (kind, target) {
        (Kind::Counterexample { goal: Some(p) }, Some(t)) => match t.results.get(p.index) {
            Some(Some(c)) => c.commit.iter().collect(),
            _ => start.to_string(),
        },
        _ => start.to_string(),
    }
}

/// Whether command exits 0 on commit's tree with the test written at its path.
fn test_on(m: &Manifest, commit: &str, test: &[u8], build: &std::path::Path, command: &str, log: &std::path::Path) -> bool {
    let config = &m.config;
    let (path, run) = (&config.counterexample.path, command);
    let dir = scratch(&format!("test.{}/{}", hash(&format!("{commit}{log:?}")), repository_name(&m.root)));
    let accepts = match materialize(&m.root, commit, &dir) {
        Ok(()) => {
            let p = dir.join(path);
            let _ = std::fs::create_dir_all(p.parent().unwrap_or(&dir));
            let _ = std::fs::write(&p, test);
            let _ = Command::new("chmod").args(["-R", "a-w,g+rX"]).arg(&dir).status();
            run_check(config, &dir, build, run, log).0
        }
        Err(_) => false,
    };
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    accepts
}

/// Remove every file of a working directory except the paths an agent process may see.
fn prune(dir: &std::path::Path, keep: &[String]) {
    let out = Command::new("find").arg(".").args(["-type", "f"]).current_dir(dir).output();
    for f in out.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default().lines() {
        let rel = f.trim_start_matches("./");
        if !keep.iter().any(|k| rel == k.trim_end_matches('/') || rel.starts_with(&format!("{}/", k.trim_end_matches('/')))) {
            let _ = std::fs::remove_file(dir.join(rel));
        }
    }
}

/// A queue candidate's new lines, by the cue each cites:
/// `<tab>intent<tab>path#HH:MM:SS.mmm` (bon gives each its id in the proposal).
fn queue_intents(root: &std::path::Path, start: &str, commit: &str) -> Vec<(Cue, Intent)> {
    let diff = git(root, &["diff", "--unified=0", start, commit, "--", QUEUE]).unwrap_or_default();
    diff.lines().filter(|l| l.starts_with('+') && !l.starts_with("+++")).filter_map(|l| {
        let fields: Vec<&str> = l[1..].split('\t').collect();
        let (text, source) = match fields.as_slice() { [_, t, s] => (*t, *s), [t, s] => (*t, *s), _ => return None };
        let cue = source.rsplit_once('#')?.1;
        Some((parse_cue(cue)?, text.trim().chars().collect()))
    }).collect()
}

/// WebVTT timestamp to milliseconds.
pub fn parse_cue(t: &str) -> Option<u64> {
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
            checks = { paths = ["checks/"], test = ["true"], verify = ["true"] }
            harness = [{ name = "claude", model = "claude-haiku-5-5", n = [2, 4] }]
            counterexample = { harness = [{ name = "codex", model = "gpt-6.1-sol", n = [1] }], path = "tests/c.sh", build = "true", run = "sh tests/c.sh", tests = ["tests/"] }
        "#).unwrap();
        let d: Host = toml::from_str(r#"
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
    fn host_facts_are_refused_in_bon_toml() {
        assert!(toml::from_str::<Config>("limit = 1.0\nrate = 1\npath = [\"/usr/bin\"]").is_err());
        assert!(toml::from_str::<Config>("limit = 1.0\nrate = 1\n[prices]").is_err());
    }

    #[test]
    fn claude_cost_matches_its_own_on_a_real_run() {
        // The modelUsage of the first end-to-end run; Claude Code reported $0.00245213.
        let c = config();
        let out = r#"{"type":"result","total_cost_usd":0.00245213,"modelUsage":{"claude-haiku-5-5":{"inputTokens":6,"outputTokens":527,"cacheReadInputTokens":49463,"cacheCreationInputTokens":8467,"cacheCreationEphemeral5mInputTokens":0,"cacheCreationEphemeral1hInputTokens":8467,"costUSD":0.00245213}}}"#;
        let (ours, theirs, prices) = generation(&c.harness[0], &c, out).unwrap();
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
        let (ours, theirs, prices) = generation(h, &c, out).unwrap();
        assert_eq!((ours, theirs), (2_050_000, None));
        assert!(prices.contains_key("gpt-6.1-sol"));
    }

    /// A repository whose trunk is pushed to a bare remote, and a test commit on
    /// trunk's head that only exists as an object, as a counterexample's does.
    fn landing_fixture(name: &str) -> (PathBuf, PathBuf, String, String) {
        let d = std::env::temp_dir().join(format!("bon-land-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (remote, work) = (d.join("remote.git"), d.join("work"));
        let sh = |dir: &std::path::Path, args: &[&str]| -> String {
            let out = Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args)
                .current_dir(dir).output().unwrap();
            assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        std::fs::create_dir_all(&work).unwrap();
        sh(&d, &["init", "-q", "--bare", "-b", "main", "remote.git"]);
        sh(&work, &["init", "-q", "-b", "main"]);
        std::fs::write(work.join("a"), "a").unwrap();
        sh(&work, &["add", "a"]);
        sh(&work, &["commit", "-q", "-m", "base"]);
        sh(&work, &["remote", "add", "origin", remote.to_str().unwrap()]);
        sh(&work, &["push", "-q", "origin", "main"]);
        let base = sh(&work, &["rev-parse", "HEAD"]);
        std::fs::create_dir_all(work.join("tests")).unwrap();
        std::fs::write(work.join("tests/c_1.sh"), "exit 1").unwrap();
        sh(&work, &["add", "tests/c_1.sh"]);
        sh(&work, &["commit", "-q", "-m", "counterexample"]);
        let test = sh(&work, &["rev-parse", "HEAD"]);
        sh(&work, &["reset", "-q", "--hard", &base]);
        (remote, work, base, test)
    }

    fn rejecting_trunk(base: &str, test: &str) -> Search {
        fn text<T: FromIterator<char>>(s: &str) -> T { s.chars().collect() }
        Search {
            kind: Kind::Counterexample { goal: None }, base: text(base), n: 1, checks: vec![], tests: vec![text("tests/")], trusted: vec![], limit: 1,
            results: vec![Some(Candidate {
                commit: text(test), base: text(base), accepted: true, proved: false, changed: vec![text("tests/c_1.sh")],
                out: vec![], intents: vec![], accepts: vec![(-1, false)], accepts_foils: vec![], rejects_counterexamples: false, rank: 0, diff: 1,
            })],
        }
    }

    #[test]
    fn a_test_lands_on_trunk_by_itself() {
        let (remote, work, base, test) = landing_fixture("lands");
        let m = Manifest { config: config(), root: work.clone() };
        land(&m, &rejecting_trunk(&base, &test), 0, None).unwrap();
        let rev = |dir: &std::path::Path, r: &str| git(dir, &["rev-parse", r]).unwrap();
        assert_eq!(rev(&remote, "main"), test, "the remote's trunk is the test's commit");
        assert_eq!(rev(&work, "HEAD"), test, "the local trunk follows");
        let record = std::fs::read_to_string(work.join(BON).join("traces").join("counterexamples.jsonl")).unwrap();
        assert_eq!(record.trim(), serde_json::json!({ "test": "tests/c_1.sh", "evidence": [base] }).to_string());
        let _ = std::fs::remove_dir_all(work.parent().unwrap());
    }

    #[test]
    fn a_test_does_not_land_when_trunk_moved() {
        let (remote, work, base, test) = landing_fixture("moved");
        // Someone else pushes to the remote's trunk first.
        let other = remote.parent().unwrap().join("other");
        assert!(Command::new("git").args(["clone", "-q", remote.to_str().unwrap(), other.to_str().unwrap()]).status().unwrap().success());
        std::fs::write(other.join("b"), "b").unwrap();
        for args in [vec!["add", "b"], vec!["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "moved"], vec!["push", "-q", "origin", "main"]] {
            assert!(Command::new("git").args(&args).current_dir(&other).status().unwrap().success());
        }
        let moved = git(&remote, &["rev-parse", "main"]).unwrap();
        let m = Manifest { config: config(), root: work.clone() };
        let e = land(&m, &rejecting_trunk(&base, &test), 0, None).unwrap_err();
        assert!(e.contains("moved"), "{e}");
        assert_eq!(git(&remote, &["rev-parse", "main"]).unwrap(), moved, "the remote's trunk is unchanged");
        assert_eq!(git(&work, &["rev-parse", "HEAD"]).unwrap(), base, "the local trunk is unchanged");
        assert!(!work.join(BON).join("traces").join("counterexamples.jsonl").exists(), "nothing is recorded");
        let _ = std::fs::remove_dir_all(work.parent().unwrap());
    }

    #[test]
    fn landed_tests_keep_their_own_file() {
        let c = config();
        let p = landed_path(&c, b"one");
        assert!(p.starts_with("tests/c_") && p.ends_with(".sh"), "{p}");
        assert_ne!(p, landed_path(&c, b"two"));
    }

    #[test]
    fn a_test_builds_on_the_tree_it_tests() {
        fn text<T: FromIterator<char>>(s: &str) -> T { s.chars().collect() }
        let candidate = |commit: &str| Candidate {
            commit: text(commit), base: text("head"), accepted: true, proved: true, changed: vec![], out: vec![],
            intents: vec![], accepts: vec![], accepts_foils: vec![], rejects_counterexamples: false, rank: 0, diff: 1,
        };
        let tested = Search {
            kind: Kind::Code { goal: text("head") }, base: text("head"), n: 2, checks: vec![], tests: vec![], trusted: vec![], limit: 1,
            results: vec![Some(candidate("first")), Some(candidate("selected"))],
        };
        let on = |goal| Kind::Counterexample { goal };
        // On a selected candidate: its tree, which builds even while trunk's head does not.
        assert_eq!(tested_tree(&on(Some(crate::gates::AgentProcess { search: 0, index: 1 })), Some(&tested), "head"), "selected");
        // On trunk: trunk's head.
        assert_eq!(tested_tree(&on(None), None, "head"), "head");
    }

    #[test]
    fn a_blocked_search_reruns_as_wide_as_the_width_list_says() {
        // queue 16: attempt a runs n[a] agent processes, the last width after the list ends;
        // the attempts are the longest list's length.
        let m = Manifest { config: config(), root: PathBuf::from(".") };
        let code = Kind::Code { goal: Commit(vec![]) };
        assert_eq!((width(&m, &code, 0), width(&m, &code, 1), width(&m, &code, 5)), (2, 4, 4));
        assert_eq!(attempts(&m), 2);
    }

    #[test]
    fn the_host_s_jobs_caps_how_many_run_at_once() {
        // queue 26: never more than jobs at once, at least one, and width is unchanged.
        assert_eq!((workers(4, 12), workers(16, 12), workers(0, 8), workers(3, 0)), (4, 12, 1, 0));
    }

    #[test]
    fn a_counterexample_writer_sees_the_spec_and_the_checks_never_the_code() {
        // queue 24: prune keeps only what is named; everything else is gone.
        let d = std::env::temp_dir().join(format!("bon-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for f in ["src/spec.rs", "src/exec.rs", "tests/c_1.rs", "Cargo.toml", ".bon/bon.toml", "view/src/main.ts"] {
            let p = d.join(f); std::fs::create_dir_all(p.parent().unwrap()).unwrap(); std::fs::write(p, "x").unwrap();
        }
        prune(&d, &["src/spec.rs".into(), "tests/".into(), "Cargo.toml".into(), ".bon/".into()]);
        let left: Vec<bool> = ["src/spec.rs", "src/exec.rs", "tests/c_1.rs", "Cargo.toml", ".bon/bon.toml", "view/src/main.ts"].iter().map(|f| d.join(f).exists()).collect();
        assert_eq!(left, [true, false, true, true, true, false]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_harness_is_logged_in_only_when_its_status_says_so() {
        // queue 32.
        assert!(logged_in("claude", true, "{\n  \"loggedIn\": true,\n}"));
        assert!(!logged_in("claude", true, "{\n  \"loggedIn\": false\n}"));
        assert!(logged_in("codex", true, "Logged in using ChatGPT"));
        assert!(!logged_in("codex", false, "Not logged in"));
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(toml::from_str::<Config>("limit = 1.0\nbogus = 2").is_err());
    }
}
