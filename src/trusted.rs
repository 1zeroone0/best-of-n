//! Trusted code. Every function the verified code calls from here is
//! `#[verifier::external_body]`: Verus does not check it. The TCB is this file,
//! the entry points (main.rs, view.rs, wasm.rs), plus what they run: git, sudo, tar, chmod, the harnesses (`claude`, `codex`)
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
    /// PATH for agent processes and checks, from the host file. Nothing is inherited.
    #[serde(skip)]
    pub path: Vec<String>,
    pub agent_process: AgentProcessConfig,
    pub checks: Checks,
    pub harness: Vec<Harness>,
    pub counterexample: Counterexample,
    #[serde(default)]
    pub scrub: Option<Scrub>,
    /// Prices by canonical model, from the host file.
    #[serde(skip)]
    pub prices: HashMap<String, Price>,
    /// How many agent processes run at once, from the host file. (intent 24)
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
    /// The command that runs its test.
    pub run: String,
}

/// A scrub: a test written from the spec and an intent alone checks that trunk
/// still satisfies the intent. (intent 21)
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Scrub {
    pub harness: Vec<Harness>,
    /// All an agent process sees besides the checks, the map and bon.toml: the
    /// spec and the interface, never the implementation.
    pub visible: Vec<String>,
    /// Where its test goes, with `{}` filled by the intent's short name; a test
    /// that lands becomes a check, so this should be under a check path.
    pub path: String,
    /// The command that builds its test (`{}` as in path); a test that does not
    /// build is unverified.
    pub build: String,
    /// The command that runs its test (`{}` as in path); exit 0 means it passes.
    pub run: String,
}

/// An intent's short name for its scrub test: lowercase words joined by `_`.
fn short(intent: &str) -> String {
    let words: Vec<String> = intent.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase()).take(6).collect();
    words.join("_")
}

/// A scrub template with `{}` filled for an intent.
fn fill(template: &str, intent: &str) -> String { template.replace("{}", &short(intent)) }

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
/// the isolated gate checks it. (intent 8)
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
/// to it. (intent 8)
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
/// write everything except the check paths, which it may read and execute but
/// not write, rename or delete. (intent 8; TCB: POSIX ACLs)
fn working_directory(root: &std::path::Path, config: &Config, commit: &str, dir: &std::path::Path) -> Result<(), String> {
    working_directory_except(root, config, commit, dir, None)
}

/// A working directory whose protected paths exclude `writable`: the directory a
/// scrub writes its test into. Only that test is ever committed.
fn working_directory_except(root: &std::path::Path, config: &Config, commit: &str, dir: &std::path::Path,
                            writable: Option<&str>) -> Result<(), String> {
    materialize(root, commit, dir)?;
    sh(dir, "chmod", &["-R", "g+rwX", "."])?;
    sh(dir, "find", &[".", "-type", "d", "-exec", "chmod", "g+s", "{}", "+"])?;
    // The checks and the transcripts: agent may read them, never change them.
    let transcripts = config.transcripts.clone().unwrap_or("transcripts".into());
    for p in config.checks.paths.iter().chain(std::iter::once(&transcripts)) {
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
/// (intent 23)
static WARM: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
/// This bon process's runs so far: names its working directories, traces and refs.
static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// The latest run's kind and goal, for its line in searches.jsonl.
static LATEST: std::sync::Mutex<(String, String)> = std::sync::Mutex::new((String::new(), String::new()));

/// A kind's name and goal, as the trace records them.
fn label(kind: &Kind) -> (String, String) {
    let text = |v: &Vec<char>| v.iter().collect::<String>();
    match kind {
        Kind::Code { goal } => ("code".into(), text(goal)),
        Kind::Map { goal } => ("map".into(), text(goal)),
        Kind::Counterexample { goal } => ("counterexample".into(), format!("search {} candidate {}", goal.search, goal.index)),
        Kind::Compaction { .. } => ("compaction".into(), String::new()),
        Kind::Scrub { goal, .. } => ("scrub".into(), text(goal)),
    }
}
static WARMING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Start building trunk in the background, once.
fn warm(m: &Manifest, head: &str) {
    if WARMING.swap(true, std::sync::atomic::Ordering::SeqCst) { return; }
    let (config, root, head) = (m.config.clone(), m.root.clone(), head.to_string());
    std::thread::spawn(move || {
        let built = (|| -> Option<PathBuf> {
            let dir = scratch(&format!("trunk/{}", repository_name(&root)));
            check_directory(&root, &head, &dir).ok()?;
            let build = scratch("trunk/build");
            writable_dir(&build).ok()?;
            let log = root.join(".bon").join("traces").join(format!("{}", std::process::id()));
            let _ = std::fs::create_dir_all(&log);
            for (k, v) in config.checks.verify.iter().enumerate() {
                run_check(&config, &dir, &build, v, &log.join(format!("trunk-verify-{k}")));
            }
            let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
            let _ = std::fs::remove_dir_all(&dir);
            Some(build)
        })();
        let _ = WARM.set(built);
    });
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

fn prompt(kind: &Kind, config: &Config, map: &str, target: Option<&Search>) -> String {
    let goal = match kind {
        Kind::Code { goal } => format!("Change the code so this intent holds:\n\n{}\n", goal.iter().collect::<String>()),
        Kind::Compaction { .. } => "Remove or simplify as much code as you can without changing behavior: \
             dead code, duplication, needless indirection. Fewer lines is better, as long as every check \
             still passes and the program prints the same.\n".to_string(),
        Kind::Counterexample { .. } => {
            // The test comes from the spec and the intent; no candidate's code is shown.
            let intent = match target.map(|t| &t.kind) {
                Some(Kind::Code { goal }) => format!("this intent holds:\n\n{}\n", goal.iter().collect::<String>()),
                _ => "behavior is unchanged from this code.\n".to_string(),
            };
            format!(
                "Several implementations were written, separately, so that {intent}\n\
                 You will not see them. From the spec, the checks and the intent alone, write one test, \
                 at {}, that every correct implementation must pass, and that a plausible wrong reading \
                 of the intent would fail. It runs with: {}\n",
                config.counterexample.path, config.counterexample.run)
        }
        Kind::Scrub { goal, path } => {
            let s = config.scrub.as_ref();
            format!(
                "This intent should hold of this repository:\n\n{}\n\n\
                 You see only the spec, the interface and the checks, not the implementation, on purpose. \
                 From them and the intent alone, write one test, at {}, that passes exactly when the intent \
                 holds. It builds with: {}. It runs with: {}.\n",
                goal.iter().collect::<String>(), path.iter().collect::<String>(),
                s.map_or(String::new(), |s| fill(&s.build, &goal.iter().collect::<String>())),
                s.map_or(String::new(), |s| fill(&s.run, &goal.iter().collect::<String>())))
        }
        Kind::Map { goal } => format!("Read the transcript at {} and append to `map` one line per need it voices: \
             the intent, a tab, then the transcript path, '#', and the cue's start time.\n", goal.iter().collect::<String>()),
    };
    format!(
        "You are working in a copy of a repository, with no git. {goal}\n\
         The checks are {paths:?}: read and run them, never change them; you cannot.\n\
         They run with: {verify:?}\n\
         The current intents, for context:\n{map}\n\
         {scope} Reply with one line saying what you changed.",
        paths = config.checks.paths, verify = config.checks.verify,
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
    let text = git(&root, &["show", &format!("{c}:bon.toml")]).map_err(|_| "no bon.toml at trunk's head; commit one".to_string())?;
    let mut config: Config = toml::from_str(&text).map_err(|e| format!("bon.toml: {e}"))?;
    let host: Host = toml::from_str(&std::fs::read_to_string(HOST).map_err(|_| format!("no {HOST}; run bon setup"))?)
        .map_err(|e| format!("{HOST}: {e}"))?;
    config.path = host.path;
    config.prices = host.prices;
    config.jobs = host.jobs.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).max(1)));
    let scrubbers = config.scrub.as_ref().map(|s| s.harness.clone()).unwrap_or_default();
    for h in config.harness.iter().chain(config.counterexample.harness.iter()).chain(scrubbers.iter()) {
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

/// The harnesses a search of this kind draws from.
#[verifier::external]
fn harnesses(config: &Config, kind: &Kind) -> Vec<Harness> {
    match kind {
        Kind::Counterexample { .. } => config.counterexample.harness.clone(),
        Kind::Scrub { .. } => config.scrub.as_ref().map(|s| s.harness.clone()).unwrap_or_default(),
        _ => config.harness.clone(),
    }
}

/// How many agent processes one harness runs on attempt `a`.
#[verifier::external]
fn at(h: &Harness, a: usize) -> usize { h.n.get(a).or(h.n.last()).copied().unwrap_or(0) }

/// How many agent processes a search of this kind runs on attempt `a`.
#[verifier::external_body]
pub fn width(m: &Manifest, kind: &Kind, a: usize) -> usize {
    harnesses(&m.config, kind).iter().map(|h| at(h, a)).sum()
}

/// How many attempts a command makes: the longest width list. (intent 15)
#[verifier::external_body]
pub fn attempts(m: &Manifest) -> usize {
    m.config.harness.iter().chain(m.config.counterexample.harness.iter()).map(|h| h.n.len()).max().unwrap_or(1)
}

/// Tests carried from a counterexample search that did not clear: each joins the
/// agree checks of the later attempts in this command. (intent 13)
#[verifier::external_body]
pub struct Tests {
    /// Counterexample tests: each joins the agree checks.
    pub files: Vec<Vec<u8>>,
    /// Scrub tests that failed on trunk: each must pass for a candidate to be verified.
    pub required: Vec<Vec<u8>>,
}

#[verifier::external_body]
pub fn no_tests() -> Tests { Tests { files: Vec::new(), required: Vec::new() } }

/// Where an intent's scrub test goes.
#[verifier::external_body]
pub fn scrub_test_path(m: &Manifest, goal: &Intent) -> (r: Result<Path, String>) {
    let s = m.config.scrub.as_ref().ok_or("bon.toml has no [scrub]")?;
    Ok(fill(&s.path, &goal.iter().collect::<String>()).chars().collect())
}

/// How many attempts a scrub makes: the longest of its width lists.
#[verifier::external_body]
pub fn scrub_attempts(m: &Manifest) -> usize {
    m.config.scrub.as_ref().map_or(1, |s| s.harness.iter().map(|h| h.n.len()).max().unwrap_or(1))
}

/// Carry a scrub candidate's test, which failed on trunk, as a required test.
#[verifier::external_body]
pub fn require(m: &Manifest, tests: &mut Tests, x: &Search, c: &Candidate) {
    let commit: String = c.commit.iter().collect();
    if let (Some(s), Kind::Scrub { goal, .. }) = (&m.config.scrub, &x.kind) {
        let path = fill(&s.path, &goal.iter().collect::<String>());
        if let Ok(out) = Command::new("git").args(["show", &format!("{commit}:{path}")]).current_dir(&m.root).output() {
            if out.status.success() { tests.required.push(out.stdout); }
        }
    }
}

/// Record a scrub's outcome for an intent: status reads these to derive broken.
#[verifier::external_body]
pub fn record_scrub(m: &Manifest, intent: &Intent, passes: bool) {
    let line = serde_json::json!({
        "intent": intent.iter().collect::<String>(), "passes": passes,
        "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
    });
    let d = m.root.join(".bon");
    let _ = std::fs::create_dir_all(&d);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(d.join("scrubs.jsonl")) {
        let _ = writeln!(f, "{line}");
    }
}

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
/// search a counterexample attacks.
#[verifier::external_body]
pub fn run(m: &Manifest, kind: &Kind, _index: usize, a: usize, start: &Commit, target: Option<&Search>, tests: &Tests) -> Vec<(Option<Candidate>, u64)> {
    // Number runs once per bon process, so a command that runs several drivers
    // (a scrub, then a code search) never reuses a working directory, trace or ref.
    let search = RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut l) = LATEST.lock() { *l = label(kind); }
    let start: String = start.iter().collect();
    warm(m, &start);
    let hs = harnesses(&m.config, kind);
    let slots: Vec<Harness> = hs.iter().flat_map(|h| std::iter::repeat(h.clone()).take(at(h, a))).collect();
    let map = git(&m.root, &["show", &format!("{start}:map")]).unwrap_or_default();
    let traces = m.root.join(".bon").join("traces").join(format!("{}", std::process::id())).join(search.to_string());
    let _ = std::fs::create_dir_all(&traces);
    // At most `jobs` agent processes at once; each worker takes the next index.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: Vec<std::sync::Mutex<(Option<Candidate>, u64)>> = slots.iter().map(|_| std::sync::Mutex::new((None, 0))).collect();
    std::thread::scope(|scope| {
        for _ in 0..m.config.jobs.max(1).min(slots.len()) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(h) = slots.get(i) else { break };
                *out[i].lock().unwrap() = agent_process(m, kind, search, i, h, &start, &map, target, tests, &traces.join(i.to_string()));
            });
        }
    });
    out.into_iter().map(|c| c.into_inner().unwrap_or((None, 0))).collect()
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
pub fn report(m: &Manifest, _index: usize, s: &Search, verified: usize, generation: u64, started: Clock) {
    let n = s.n;
    let search = RUNS.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
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
    let (kind, goal) = LATEST.lock().map(|l| l.clone()).unwrap_or_default();
    let summary = serde_json::json!({
        "search": search, "kind": kind, "goal": goal,
        "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        "agent_processes": n, "verified": verified, "generation_dollars": generation,
        "seconds": hours * 3600.0, "rate": m.config.rate, "time_dollars": time,
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

/// Record which candidate of the latest search was selected. (intent 14)
#[verifier::external_body]
pub fn record_selected(m: &Manifest, i: usize) {
    let search = RUNS.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
    record(m, &format!("selected {search} {i}"));
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
    let dir = scratch(&format!("goal/{}", repository_name(&m.root)));
    check_directory(&m.root, &c, &dir)?;
    let build = build_directory(&m.config, "goal/build")?;
    let log = m.root.join(".bon").join("traces").join(format!("{}", std::process::id()));
    let _ = std::fs::create_dir_all(&log);
    let mut out = Vec::new();
    for (k, a) in m.config.checks.agree.iter().enumerate() {
        out.push(hash(&run_check(&m.config, &dir, &build, a, &log.join(format!("goal-agree-{k}"))).1));
    }
    for (k, t) in tests.files.iter().enumerate() {
        out.push(hash(if test_on(m, &c, t, &m.config.counterexample.path, &m.config.counterexample.run, &build, &log.join(format!("goal-carried-{k}"))) { "pass" } else { "fail" }));
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
    let dir = scratch(&format!("{search}.{index}/{}", repository_name(&m.root)));
    let writable = match (kind, &config.scrub) {
        (Kind::Scrub { path, .. }, Some(_)) => {
            let p: String = path.iter().collect();
            std::path::Path::new(&p).parent().map(|d| d.to_string_lossy().to_string())
        }
        _ => None,
    };
    if let Err(e) = working_directory_except(&m.root, config, start, &dir, writable.as_deref()) {
        let _ = std::fs::write(trace.join("error"), e);
        return (None, 0);
    }
    if let (Kind::Scrub { .. }, Some(s)) = (kind, &config.scrub) {
        let mut keep: Vec<String> = s.visible.iter().chain(config.checks.paths.iter()).cloned().collect();
        keep.extend(["bon.toml", "map", "Cargo.toml"].map(String::from));
        prune(&dir, &keep);
    }
    let argv = harness_argv(h, config, &dir);
    let _ = std::fs::write(trace.join("argv"), argv.join(" "));
    let text = prompt(kind, config, map, target);
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
    let build = scratch(&format!("{search}.{index}/build"));
    let _ = as_agent(config, std::path::Path::new("/tmp"), &[], &["rm".into(), "-rf".into(), build.to_string_lossy().into()]).status();
    let text = |v: &Vec<char>| v.iter().collect::<String>();
    let facts = serde_json::json!({
        "harness": h.name, "model": h.model, "cost_microdollars": spent, "killed": killed,
        "harness_cost_microdollars": harness_cost,
        // The prices this cost was computed at, so the trace stays true when the host's prices change.
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
    match kind {
        // A scrub's working directory holds only what it may see: record its test alone.
        Kind::Scrub { path, .. } => {
            let p: String = path.iter().collect();
            if dir.join(&p).exists() { with(&["add", "--", &p])?; }
        }
        _ => { with(&["add", "-A", "."])?; }
    }
    let tree = with(&["write-tree"])?;
    let _ = std::fs::remove_file(&index_file);
    let subject = match kind {
        Kind::Code { goal } => goal.iter().collect::<String>(),
        Kind::Compaction { .. } => "compaction".to_string(),
        Kind::Map { goal } => format!("map: {}", goal.iter().collect::<String>()),
        Kind::Counterexample { .. } => "counterexample".to_string(),
        Kind::Scrub { goal, .. } => format!("scrub: {}", goal.iter().collect::<String>()),
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
    let cdir = scratch(&format!("{search}.{index}/check"));
    check_directory(root, &commit, &cdir)?;
    let build = build_directory(config, &format!("{search}.{index}/build"))?;
    let mut checks_pass = true;
    let mut test_passes = Vec::new();
    let mut rank = 0i64;
    if let (Kind::Scrub { goal, .. }, Some(s)) = (kind, &config.scrub) {
        // Trunk is unchanged; a scrub candidate is verified when its test builds.
        let intent: String = goal.iter().collect();
        let (path, run) = (fill(&s.path, &intent), fill(&s.run, &intent));
        checks_pass = run_check(config, &cdir, &build, &fill(&s.build, &intent), &trace.join("scrub-build")).0;
        if checks_pass {
            let passes = run_check(config, &cdir, &build, &run, &trace.join("scrub-run")).0;
            test_passes.push((-1, passes));
            // Rank: how many losing candidates for this intent the test rejects.
            let test = std::fs::read(dir.join(&path)).unwrap_or_default();
            for (k, mc) in losing(root, &intent, start).iter().enumerate() {
                if !test_on(m, mc, &test, &path, &run, &build, &trace.join(format!("losing-{k}"))) { rank += 1; }
            }
        }
    } else {
        for (k, v) in config.checks.verify.iter().enumerate() {
            let (ok, _) = run_check(config, &cdir, &build, v, &trace.join(format!("verify-{k}")));
            if !ok { checks_pass = false; break; }
        }
        // A broken intent's scrub test must pass.
        if let (Some(s), Kind::Code { goal }) = (&config.scrub, kind) {
            let intent: String = goal.iter().collect();
            for (k, t) in tests.required.iter().enumerate() {
                if checks_pass && !test_on(m, &commit, t, &fill(&s.path, &intent), &fill(&s.run, &intent), &build, &trace.join(format!("required-{k}"))) {
                    checks_pass = false;
                }
            }
        }
    }
    let mut out = Vec::new();
    if let [(_, passes)] = test_passes.as_slice() { out.push(hash(if *passes { "pass" } else { "fail" })); }
    if checks_pass && !matches!(kind, Kind::Scrub { .. }) {
        for (k, a) in config.checks.agree.iter().enumerate() {
            let (_, o) = run_check(config, &cdir, &build, a, &trace.join(format!("agree-{k}")));
            out.push(hash(&o));
        }
        for (k, t) in tests.files.iter().enumerate() {
            out.push(hash(if test_on(m, &commit, t, &config.counterexample.path, &config.counterexample.run, &build, &trace.join(format!("carried-{k}"))) { "pass" } else { "fail" }));
        }
        let which = match kind { Kind::Compaction { .. } => "compaction", _ => "code" };
        if let Some(r) = config.checks.rank.get(which) {
            let (_, o) = run_check(config, &cdir, &build, r, &trace.join("rank"));
            rank = o.trim().parse().unwrap_or(0);
        }
    }
    if let (Kind::Counterexample { .. }, Some(t)) = (kind, target) {
        let test = std::fs::read(dir.join(&config.counterexample.path)).ok();
        let mut members: Vec<(i64, String)> = Vec::new();
        if let Kind::Compaction { goal, .. } = &t.kind { members.push((-1, goal.iter().collect())); }
        for (j, r) in t.results.iter().enumerate() {
            if let Some(c) = r { members.push((j as i64, c.commit.iter().collect())); }
        }
        for (j, mc) in members {
            let passes = match &test {
                Some(bytes) => test_on(m, &mc, bytes, &config.counterexample.path, &config.counterexample.run, &build, &trace.join(format!("test-{j}"))),
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

/// Whether a test passes on `commit`: a read-only checkout of it with the test at
/// `path`, run as agent with `run`.
fn test_on(m: &Manifest, commit: &str, test: &[u8], path: &str, run: &str, build: &std::path::Path, log: &std::path::Path) -> bool {
    let config = &m.config;
    let dir = scratch(&format!("test.{}/{}", hash(&format!("{commit}{log:?}")), repository_name(&m.root)));
    let passes = match materialize(&m.root, commit, &dir) {
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
    passes
}

/// Up to five of the most recent losing candidates for an intent: candidate
/// commits under refs/bon whose subject is the intent and that trunk never took.
fn losing(root: &std::path::Path, intent: &str, trunk: &str) -> Vec<String> {
    git(root, &["for-each-ref", "--sort=-committerdate", "--format=%(objectname) %(subject)", "refs/bon/"])
        .unwrap_or_default().lines()
        .filter_map(|l| l.split_once(' ')).filter(|(_, s)| *s == intent).map(|(c, _)| c.to_string())
        .filter(|c| !Command::new("git").args(["merge-base", "--is-ancestor", c, trunk]).current_dir(root)
            .status().is_ok_and(|s| s.success()))
        .take(5).collect()
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
            counterexample = { harness = [{ name = "codex", model = "gpt-6.1-sol", n = [1] }], path = "c.sh", run = "sh c.sh" }
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
