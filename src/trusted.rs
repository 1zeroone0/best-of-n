//! Trusted code. Every function the verified code calls from here is
//! `#[verifier::external_body]`: Verus does not check it. The TCB is this file,
//! the entry points (main.rs, view.rs), plus what they run: git, sudo, tar, chmod, the harnesses (`claude`, `codex`),
//! perl (bon's cargo, `CARGO`) and the checks the manifest declares.
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
    /// How many model sessions and how many checks run at once, from the host
    /// file and bon's environment.
    #[serde(skip)]
    pub pools: Pools,
    /// RUSTUP_HOME and CARGO_HOME for agent processes and checks, from the host file.
    #[serde(skip)]
    pub toolchain: Vec<(String, String)>,
}

/// Cargo reads a config.toml from every ancestor of the directory it builds in.
/// /tmp is anyone's, so bon makes /tmp/.cargo its own before agent can, and
/// refuses to run if another user made it first.
fn cargo_config_guard(root: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let d = std::path::Path::new("/tmp/.cargo");
    let _ = std::fs::create_dir(d);
    let me = std::fs::metadata(root).map_err(|e| e.to_string())?.uid();
    let it = std::fs::metadata(d).map_err(|e| format!("/tmp/.cargo: {e}"))?;
    if it.uid() != me || it.mode() & 0o022 != 0 {
        return Err("/tmp/.cargo belongs to another user or is writable by others: cargo would read a config.toml from it; remove it, then run again".into());
    }
    Ok(())
}

/// What is true of this machine rather than of a repository, written by
/// `bon setup` and owned by root: where agent's tools live, and model prices.
pub const HOST: &str = "/etc/bon/host.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    path: Vec<String>,
    prices: HashMap<String, Price>,
    /// How many model sessions run at once, host-wide; width stays what
    /// bon.toml says. Default 64 (a session waits on the model); BON_GENERATION
    /// overrides it.
    #[serde(default)]
    generation: Option<usize>,
    /// The generation pool's earlier name, read when `generation` is absent.
    #[serde(default)]
    jobs: Option<usize>,
    /// How many checks run at once, host-wide: the judge's and every cargo an
    /// agent process runs. Default: cores / check_threads, never more than
    /// free memory / 1.5 GB. BON_CHECKS overrides it.
    #[serde(default)]
    checks: Option<usize>,
    /// Threads one check may use (CARGO_BUILD_JOBS, Verus --num-threads).
    /// Default 2; BON_CHECK_THREADS overrides it.
    #[serde(default)]
    check_threads: Option<usize>,
    /// The toolchain checks judge with, where no agent process can write it
    /// (/opt/bon, root's all the way up): rustup's home, and a cargo home whose
    /// root is root's, only its caches agent's. Required.
    rustup_home: String,
    cargo_home: String,
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
    /// "claude", "codex", or "stub" (a program that costs nothing: see `command`).
    pub name: String,
    /// The canonical model id (e.g. claude-haiku-5-5, gpt-6.1-sol), never an alias:
    /// it is passed to the harness and keys the price table. A stub's needs no price.
    pub model: String,
    /// The program to run instead of the built-in one: an argv, run as agent in
    /// the working directory, the prompt on its stdin. Its cost is parsed by
    /// `name`; a stub's is zero.
    #[serde(default)]
    pub command: Option<Vec<String>>,
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

/// agent's home directory.
const AGENT_HOME: &str = "/Users/agent";

/// The PATH checks run with: the host file's, without any directory under
/// agent's home, so every tool a check runs is the toolchain's. Harness
/// processes keep the host file's whole PATH.
fn checks_path(config: &Config) -> Vec<String> {
    config.path.iter().filter(|d| !std::path::Path::new(d).starts_with(AGENT_HOME)).cloned().collect()
}

/// A command run as user agent with a cleared environment: only PATH, HOME and
/// what bon sets. (TCB: sudo)
fn as_agent(config: &Config, dir: &std::path::Path, env: &[(&str, String)], argv: &[String]) -> Command {
    as_agent_on(config, &config.path, dir, env, argv)
}

/// Whether this process already runs as agent.
fn is_agent() -> bool {
    static AGENT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AGENT.get_or_init(|| Command::new("id").arg("-un").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "agent"))
}

/// as_agent, with PATH path.
fn as_agent_on(config: &Config, path: &[String], dir: &std::path::Path, env: &[(&str, String)], argv: &[String]) -> Command {
    // Already agent (a candidate's tests run as agent): the same cleared
    // environment, without sudo, which agent may not use.
    let mut c = if is_agent() { Command::new("env") } else { let mut c = Command::new("sudo"); c.args(["-n", "-u", "agent", "env"]); c };
    c.arg("-i");
    c.arg(format!("PATH={}", path.join(":")));
    c.arg(format!("HOME={AGENT_HOME}"));
    c.arg("LANG=en_US.UTF-8");
    c.arg("TERM=dumb");
    for (k, v) in &config.toolchain { c.arg(format!("{k}={v}")); }
    for (k, v) in env { c.arg(format!("{k}={v}")); }
    c.args(argv);
    c.current_dir(dir);
    c
}

/// Run to completion or kill at `time`, with all it started. Returns (exit 0,
/// stdout, killed).
fn supervise(c: Command, stdin: Option<String>, time: Duration, log: &std::path::Path) -> (bool, String, bool) {
    let r = supervised(c, stdin, time, log);
    (r.ok, r.stdout, r.killed)
}

/// What a supervised command did: exit 0, its stdout, whether its time limit
/// stopped it, whether it exited with a code of its own (not killed, not a
/// signal, not a spawn that failed: only such a result may be cached), and its
/// log as written.
struct Run { ok: bool, stdout: String, killed: bool, exited: bool, log: String }

fn supervised(mut c: Command, stdin: Option<String>, time: Duration, log: &std::path::Path) -> Run {
    std::os::unix::process::CommandExt::process_group(&mut c, 0);
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let start = Instant::now();
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            let text = format!("spawn: {e}");
            write_trace(log, &text);
            return Run { ok: false, stdout: String::new(), killed: false, exited: false, log: text };
        }
    };
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        std::thread::spawn(move || { let _ = pipe.write_all(text.as_bytes()); });
    }
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let o = std::thread::spawn(move || { let mut s = String::new(); let _ = out.read_to_string(&mut s); s });
    let e = std::thread::spawn(move || { let mut s = String::new(); let _ = err.read_to_string(&mut s); s });
    // Done when the command has exited and nothing it started holds its output.
    let mut status = None;
    let killed = loop {
        if status.is_none() { status = child.try_wait().ok().flatten(); }
        if status.is_some() && o.is_finished() && e.is_finished() { break false; }
        if start.elapsed() >= time { break true; }
        std::thread::sleep(Duration::from_millis(200));
    };
    if killed {
        // The command is its own process group, and agent's: agent signals the
        // whole group (sudo, root's, is spared), so nothing it started outlives it.
        let group = format!("-{}", child.id());
        let signal = |s: &str| { let _ = (if is_agent() { let mut c = Command::new("/bin/kill"); c.args([s, "--", &group]); c }
                                          else { let mut c = Command::new("sudo"); c.args(["-n", "-u", "agent", "/bin/kill", s, "--", &group]); c })
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status(); };
        signal("-TERM");
        let grace = Instant::now();
        while !(o.is_finished() && e.is_finished()) && grace.elapsed() < Duration::from_secs(2) { std::thread::sleep(Duration::from_millis(100)); }
        signal("-KILL");
        let _ = child.kill();
        status = child.wait().ok();
    }
    let stdout = o.join().unwrap_or_default();
    let stderr = e.join().unwrap_or_default();
    let exit = if killed { "killed".to_string() } else { status.and_then(|s| s.code()).map_or("signal".into(), |c| c.to_string()) };
    let text = format!("exit: {exit}\nseconds: {:.1}\n--- stdout\n{stdout}\n--- stderr\n{stderr}", start.elapsed().as_secs_f64());
    write_trace(log, &text);
    Run { ok: status.is_some_and(|s| s.success()) && !killed, stdout, killed, exited: !killed && status.and_then(|s| s.code()).is_some(), log: text }
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
    // bon runs as engineer; only a candidate's tests run bon's code as agent,
    // which cannot write the host's working directories: they get agent's own.
    let base = if is_agent() { std::env::temp_dir().join("bon-agent") } else { PathBuf::from(WORKING_DIRECTORIES) };
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

/// Write `commit`'s tree into `dir`, owned by engineer, group bon. (TCB: git)
fn materialize(root: &std::path::Path, commit: &str, dir: &std::path::Path) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    extract(root, commit, &[], dir)?;
    sh(dir, "chgrp", &["-R", "bon", "."])?;
    Ok(())
}

/// One entry of a tree: its mode, object and path.
type Entry = (Vec<u8>, String, Vec<u8>);

/// Write the files of `commit`'s tree under `paths` (all of it, when empty)
/// into `dir`: exactly what `git ls-tree -r` lists, byte for byte. No attribute
/// applies (export-ignore, export-subst, eol, filters), so no candidate leaves
/// a file out of its own check directory. Each file gets the time it is
/// written, not its commit's: cargo tracks a package's own sources by path and
/// mtime, so files older than a build directory's artifacts (one shared across
/// the commits a test runs on) would read as unchanged. (TCB: git)
fn extract(root: &std::path::Path, commit: &str, paths: &[&str], dir: &std::path::Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let bad = || format!("materialize {commit}");
    let mut args = vec!["ls-tree", "-r", "-z", "--full-tree", commit, "--"];
    args.extend_from_slice(paths);
    let out = Command::new("git").args(&args).current_dir(root).stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
    if !out.status.success() { return Err(format!("{}: {}", bad(), String::from_utf8_lossy(&out.stderr).trim())); }
    let mut entries: Vec<Entry> = Vec::new();
    for e in out.stdout.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let tab = e.iter().position(|b| *b == b'\t').ok_or_else(bad)?;
        let head = String::from_utf8_lossy(&e[..tab]).to_string();
        let [mode, _, object] = head.split(' ').collect::<Vec<_>>()[..] else { return Err(bad()) };
        let path = e[tab + 1..].to_vec();
        if path.starts_with(b"/") || path.split(|b| *b == b'/').any(|c| c.is_empty() || c == b"." || c == b"..") {
            return Err(format!("{}: path {}", bad(), String::from_utf8_lossy(&path)));
        }
        entries.push((mode.as_bytes().to_vec(), object.to_string(), path));
    }
    let target = |p: &[u8]| dir.join(std::ffi::OsStr::from_bytes(p));
    // A submodule is an empty directory, as git leaves it.
    let (modules, blobs): (Vec<&Entry>, Vec<&Entry>) = entries.iter().partition(|(m, _, _)| m.as_slice() == b"160000");
    for (_, _, path) in modules { std::fs::create_dir_all(target(path)).map_err(|e| e.to_string())?; }
    let mut cat = Command::new("git").args(["cat-file", "--batch"]).current_dir(root)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    let mut input = cat.stdin.take().ok_or("cat-file: no stdin")?;
    let ids: String = blobs.iter().map(|(_, o, _)| format!("{o}\n")).collect();
    let writer = std::thread::spawn(move || input.write_all(ids.as_bytes()));
    let mut output = std::io::BufReader::new(cat.stdout.take().ok_or("cat-file: no stdout")?);
    for (mode, object, path) in blobs {
        // `<object> blob <size>\n<bytes>\n`
        let mut header = Vec::new();
        std::io::BufRead::read_until(&mut output, b'\n', &mut header).map_err(|e| e.to_string())?;
        let header = String::from_utf8_lossy(&header).to_string();
        let size: usize = header.trim_end().rsplit(' ').next().and_then(|n| n.parse().ok())
            .filter(|_| header.starts_with(&format!("{object} blob "))).ok_or_else(|| format!("{}: {}", bad(), header.trim()))?;
        let mut bytes = vec![0u8; size + 1];
        output.read_exact(&mut bytes).map_err(|e| e.to_string())?;
        bytes.truncate(size);
        let t = target(path);
        if let Some(parent) = t.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
        if mode.as_slice() == b"120000" {
            std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&bytes), &t).map_err(|e| e.to_string())?;
        } else {
            std::fs::write(&t, &bytes).map_err(|e| e.to_string())?;
            let bits = if mode.as_slice() == b"100755" { 0o755 } else { 0o644 };
            std::fs::set_permissions(&t, std::fs::Permissions::from_mode(bits)).map_err(|e| e.to_string())?;
        }
    }
    let _ = writer.join();
    if !cat.wait().map_err(|e| e.to_string())?.success() { return Err(bad()); }
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
    // The checks, their build configuration, the transcripts and .bon/: agent may read them, never change them.
    let transcripts = config.transcripts.clone().unwrap_or("transcripts".into());
    let fixed: Vec<String> = BUILD.iter().map(|p| p.to_string()).chain([transcripts, BON.to_string()]).collect();
    for p in config.checks.paths.iter().chain(fixed.iter()).chain(more.iter()) {
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
        Kind::Foil { goal: p, .. } => ("foil".into(), format!("search {} candidate {}", p.search, p.index)),
    }
}
static WARMING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// This bon process runs as background work: no one waits on it, so its time
/// is charged at rate 0 and it costs its generation alone.
static BACKGROUND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Mark this bon process as background work.
pub fn background() { BACKGROUND.store(true, std::sync::atomic::Ordering::SeqCst); }

/// This bon process's trace directory's name, claimed at its first trace write.
static TRACE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// This bon process's trace directory: its own, never an earlier run's.
fn trace_dir(root: &std::path::Path) -> PathBuf {
    let traces = root.join(BON).join("traces");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    traces.join(TRACE.get_or_init(|| claim(&traces, std::process::id(), now)))
}

/// Make a run's trace directory under `traces`, one no other run has: `<pid>`,
/// or `<pid>.<start>` (unix seconds) when an earlier bon process of the same
/// pid left `<pid>`. Making it is the claim: two runs never both make one.
fn claim(traces: &std::path::Path, pid: u32, start: u64) -> String {
    traced(traces, std::fs::create_dir_all(traces));
    let mut name = pid.to_string();
    for t in start..start + 1000 {
        match std::fs::create_dir(traces.join(&name)) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => name = format!("{pid}.{t}"),
            r => { traced(&traces.join(&name), r); break; }
        }
    }
    name
}

/// A trace directory's bon process, by its name: (pid, start); start is 0 for
/// `<pid>`, the first run of a pid.
pub fn trace_process(name: &str) -> Option<(u64, u64)> {
    let (pid, start) = name.split_once('.').unwrap_or((name, "0"));
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    if !digits(pid) || !digits(start) { return None; }
    Some((pid.parse().ok()?, start.parse().ok()?))
}

/// Whether the trace directory `name` under `traces` is another bon process's
/// that is still running: its pid is alive, is not this process's, and no later
/// run of that pid has a trace (else its pid was reused and it ended).
pub fn trace_running(traces: &std::path::Path, name: &str) -> bool {
    let Some((pid, start)) = trace_process(name) else { return false };
    if pid == u64::from(std::process::id()) { return false; }
    let later = std::fs::read_dir(traces).into_iter().flatten().flatten()
        .filter_map(|e| trace_process(&e.file_name().to_string_lossy()))
        .any(|(p, s)| p == pid && s > start);
    // ps, not kill -0: kill -0 fails on another user's live process (EPERM).
    !later && process_running(&pid.to_string())
}

/// Check liveness even when the sandbox denies ps; ps covers other users.
fn process_running(pid: &str) -> bool {
    Command::new("/bin/kill").args(["-0", pid]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
        || Command::new("ps").args(["-p", pid]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// A trace write that failed is reported; the search goes on.
fn traced(path: &std::path::Path, r: std::io::Result<()>) {
    if let Err(e) = r { eprintln!("bon: trace not written: {}: {e}", path.display()); }
}

/// Write a trace file, its directory made first.
fn write_trace(path: &std::path::Path, contents: impl AsRef<[u8]>) {
    traced(path, (|| {
        if let Some(d) = path.parent() { std::fs::create_dir_all(d)?; }
        std::fs::write(path, contents)
    })());
}

/// Append one line to a trace file, its directory made first.
fn append_line(file: &std::path::Path, line: &str) {
    traced(file, (|| {
        if let Some(d) = file.parent() { std::fs::create_dir_all(d)?; }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(file)?;
        writeln!(f, "{line}")
    })());
}

/// Where this driver's searches start in this bon process's runs: a search's
/// index in the kernel (from 0 at initialize) plus it names its trace directory.
static FIRST_RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Run trunk's checks, as agent, building trunk in the process: (every test
/// accepts trunk, Verus verifies it). Each candidate's build starts from it, so
/// the first run in a bon process runs; a later one (the next attempt) may be
/// answered by the verdict cache. It runs alone, so it takes every core.
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
        traced(&log, std::fs::create_dir_all(&log));
        let on = On { tree: tree_of(root, head), test: None, read: WARM.get().is_some() };
        let run = |v: &String, name: String| run_check_with(config, &on, cores(), &dir, &build, v, &log.join(name)).0;
        let tests = config.checks.test.iter().enumerate().all(|(k, v)| run(v, format!("trunk-test-{k}")));
        let proved = config.checks.verify.iter().enumerate().all(|(k, v)| run(v, format!("trunk-verify-{k}")));
        result = (tests, proved);
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
        let _ = std::fs::remove_dir_all(&dir);
        Some(build)
    })();
    TRUNK_PROVED.store(result.1, std::sync::atomic::Ordering::SeqCst);
    let _ = WARM.set(built);
    result
}

/// A build directory that starts as a copy-on-write clone of trunk's build:
/// an agent process's, which its judge then reuses.
fn build_directory(config: &Config, name: &str) -> Result<PathBuf, String> {
    // Once trunk's build is under way, wait for it and start from a clone of it.
    let warm = if WARMING.load(std::sync::atomic::Ordering::SeqCst) {
        let start = Instant::now();
        while WARM.get().is_none() && start.elapsed() < Duration::from_secs(config.agent_process.time) {
            std::thread::sleep(Duration::from_millis(500));
        }
        WARM.get().cloned().flatten()
    } else { None };
    clone_build(config, warm.as_deref(), name)
}

/// A build directory named `name`: empty, or a copy-on-write clone of `from`.
fn clone_build(config: &Config, from: Option<&std::path::Path>, name: &str) -> Result<PathBuf, String> {
    let d = scratch(name);
    // engineer makes the directory; agent fills it with a clone.
    writable_dir(&d)?;
    if let Some(w) = from {
        let argv: Vec<String> = vec!["cp".into(), "-cR".into(), format!("{}/", w.display()), d.to_string_lossy().into()];
        let ok = as_agent(config, std::path::Path::new("/tmp"), &[], &argv).status().map_err(|e| e.to_string())?.success();
        if !ok { return Err(format!("{} as agent", argv.join(" "))); }
    }
    Ok(d)
}

/// agent empties a build directory; engineer removes the directory itself at cleanup.
fn remove_build(config: &Config, d: &std::path::Path) {
    let _ = as_agent(config, std::path::Path::new("/tmp"), &[], &["rm".into(), "-rf".into(), d.to_string_lossy().into()])
        .stderr(Stdio::null()).status();
}

/// Remove this bon process's directories under /tmp/bon, and any left by a bon
/// process no longer running. Each holds files of two owners: engineer's check
/// files (with an ACL denying agent) and agent's build output. So: engineer
/// removes its ACLs, agent removes what it can, engineer removes the rest.
/// With BON_CLEANUP=own in bon's environment, only this process's own (a host
/// shared with other bon processes, as the benchmark's is).
pub fn cleanup(path: &[String]) {
    let me = std::process::id().to_string();
    let own = std::env::var("BON_CLEANUP").is_ok_and(|v| v == "own");
    // ps, not kill -0: kill -0 fails on another user's live process (EPERM),
    // which would read as dead.
    let running = |pid: &str| pid == me || process_running(pid);
    for e in std::fs::read_dir(WORKING_DIRECTORIES).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        // <pid>.<owner>; <pid>-<name> from before the working directories were 0711.
        let Some(pid) = name.split(['.', '-']).next() else { continue };
        if !pid.chars().all(|c| c.is_ascii_digit()) || (pid != me && (own || running(pid))) { continue; }
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

// ── pools ───────────────────────────────────────────────

/// Memory one check may need: bon's own cold `cargo verus verify` peaks near
/// 2.3 GB, a warm one near 0.7 GB.
const CHECK_GB: f64 = 1.5;

/// The host's two pools, each shared by every bon process on the host.
/// Generation: model sessions at once; a session waits on the model, so it is
/// wide. Checks: CPU-heavy commands at once, the judge's checks and every cargo
/// an agent process runs alike, each given `threads` threads.
#[derive(Clone, Debug, PartialEq)]
pub struct Pools { pub generation: usize, pub checks: usize, pub threads: usize }

impl Default for Pools { fn default() -> Self { Pools { generation: 1, checks: 1, threads: 1 } } }

impl Pools {
    /// From bon's environment, then the host file, then this machine: BON_GENERATION
    /// (default 64, or the host's older `jobs`), BON_CHECK_THREADS (default 2),
    /// BON_CHECKS (default `check_pool`). BON_CORES and BON_MEMORY_GB stand in
    /// for this machine's cores and free memory, to size the pools as another
    /// machine would.
    fn of(host: &Host, env: &dyn Fn(&str) -> Option<String>) -> Pools {
        let n = |k: &str| env(k).and_then(|v| v.trim().parse::<f64>().ok()).filter(|v| *v >= 1.0);
        let cores = n("BON_CORES").map_or_else(|| std::thread::available_parallelism().map_or(1, |c| c.get()), |c| c as usize);
        let threads = n("BON_CHECK_THREADS").map(|t| t as usize).or(host.check_threads).unwrap_or(2).max(1);
        let memory = || env("BON_MEMORY_GB").and_then(|v| v.trim().parse().ok()).unwrap_or_else(free_memory_gb);
        let checks = n("BON_CHECKS").map(|c| c as usize).or(host.checks).unwrap_or_else(|| check_pool(cores, memory(), threads)).max(1);
        let generation = n("BON_GENERATION").map(|g| g as usize).or(host.generation).or(host.jobs).unwrap_or(64).max(1);
        Pools { generation, checks, threads }
    }
}

/// The default check pool: one check per `threads` cores, never more than free
/// memory holds at CHECK_GB each, at least one.
fn check_pool(cores: usize, memory_gb: f64, threads: usize) -> usize {
    (cores / threads.max(1)).min((memory_gb / CHECK_GB) as usize).max(1)
}

/// Memory free for checks now, in GB: vm_stat's free, inactive, speculative and
/// purgeable pages; half of physical memory if vm_stat cannot say.
fn free_memory_gb() -> f64 {
    let out = Command::new("vm_stat").output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let page = out.lines().next().and_then(|l| l.split("page size of ").nth(1))
        .and_then(|r| r.split_whitespace().next()).and_then(|v| v.parse::<f64>().ok());
    let pages: f64 = out.lines().filter(|l| ["Pages free", "Pages inactive", "Pages speculative", "Pages purgeable"].iter().any(|k| l.starts_with(k)))
        .filter_map(|l| l.rsplit(':').next()?.trim().trim_end_matches('.').parse::<f64>().ok()).sum();
    match page {
        Some(p) if pages > 0.0 => pages * p / 1e9,
        _ => Command::new("sysctl").args(["-n", "hw.memsize"]).output().ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<f64>().ok()).unwrap_or(8e9) / 2e9,
    }
}

/// Where slots, bon's cargo and the verdict cache live: the working
/// directories, or agent's own when bon runs as agent (a candidate's tests).
fn base() -> PathBuf {
    if is_agent() { std::env::temp_dir().join("bon-agent") } else { PathBuf::from(WORKING_DIRECTORIES) }
}

/// The check pool's slot files: engineer's directory, which agent (through
/// group bon) may write, since bon's cargo takes slots as agent.
fn slots_dir() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let d = base().join("checks");
        if let Err(e) = writable_dir(&d) { eprintln!("bon: {}: {e}", d.display()); }
        // Made here, so agent opens them read-only (a sandboxed harness may not create files).
        for k in 0..256 {
            let p = d.join(format!("check.{k}"));
            if !p.exists() && std::fs::write(&p, "").is_ok() {
                let _ = std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644));
            }
        }
        d
    }).clone()
}

/// One slot of a host-wide pool: an flock on the file `<name>.<k>` under a
/// directory, k below the pool's size. The kernel frees a lock when its
/// holder's last descriptor closes, so a slot a dead process held is free at
/// once. bon's cargo takes check slots the same way, as agent.
struct Slot(#[allow(dead_code)] std::fs::File);

/// A pool's slot as this process holds it: first a place among the process's
/// own waiters (at most the pool's size of them look for a host-wide slot, so
/// a wide search does not poll the slot files from every thread), then the slot.
struct Held { _slot: Slot, _gate: Ticket }

/// In-process admission to a pool: how many of this process's threads hold or
/// seek one of its slots.
struct Gate { taken: std::sync::Mutex<usize>, freed: std::sync::Condvar }
static GENERATION_GATE: Gate = Gate { taken: std::sync::Mutex::new(0), freed: std::sync::Condvar::new() };
static CHECK_GATE: Gate = Gate { taken: std::sync::Mutex::new(0), freed: std::sync::Condvar::new() };

struct Ticket(&'static Gate);

impl Gate {
    fn enter(&'static self, n: usize) -> Ticket {
        let mut taken = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        while *taken >= n.max(1) { taken = self.freed.wait(taken).unwrap_or_else(|e| e.into_inner()); }
        *taken += 1;
        Ticket(self)
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        *self.0.taken.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        self.0.freed.notify_one();
    }
}

impl Slot {
    /// A model session's slot: generation.<k> in the working directories.
    fn generation(config: &Config) -> Held {
        let gate = GENERATION_GATE.enter(config.pools.generation);
        Held { _slot: Slot::take_in(&base(), "generation", config.pools.generation), _gate: gate }
    }

    /// A check's slot: check.<k> in the slots directory.
    fn check(config: &Config) -> Held {
        let gate = CHECK_GATE.enter(config.pools.checks);
        Held { _slot: Slot::take_in(&slots_dir(), "check", config.pools.checks), _gate: gate }
    }

    fn take_in(dir: &std::path::Path, name: &str, n: usize) -> Slot {
        loop {
            for k in 0..n.max(1) {
                let p = dir.join(format!("{name}.{k}"));
                // Read-only: a slot file agent made is locked the same way.
                let f = std::fs::File::open(&p).or_else(|_| {
                    let f = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(&p);
                    let _ = std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644));
                    f
                });
                if let Ok(f) = f { if f.try_lock().is_ok() { return Slot(f); } }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

/// bon's cargo: first on the PATH of agent processes and of checks. It runs the
/// toolchain's cargo (the next on PATH) holding a check slot for as long as that
/// cargo and all it starts run, unless its caller holds one (BON_CHECK_SLOT, as
/// the judge does); and it caps the threads: CARGO_BUILD_JOBS, and Verus's
/// --num-threads for `cargo verus`. Cooperative: an agent process may call the
/// toolchain's cargo by its path, or set BON_CHECK_SLOT, and go unpooled.
const CARGO: &str = r#"#!/usr/bin/perl
# bon's cargo: the toolchain's, holding one of the host's check slots, threads capped.
use strict; use warnings; use Fcntl qw(:flock O_RDONLY O_CREAT);
my ($slots, $n, $threads, $self) = ('@SLOTS@', @N@, @THREADS@, '@SELF@');
$ENV{PATH} = join ':', grep { $_ ne $self } split /:/, ($ENV{PATH} // '');
$ENV{CARGO_BUILD_JOBS} //= $threads;
my @args = @ARGV;
if (@args >= 2 && $args[0] eq 'verus' && $args[1] =~ /^(verify|focus|build|check)$/ && !grep { /^--num-threads/ } @args) {
    my ($sep) = grep { $args[$_] eq '--' } 0 .. $#args;
    if (defined $sep) { splice @args, $sep + 1, 0, '--num-threads', $threads } else { push @args, '--', '--num-threads', $threads }
}
my $held;  # open until exec, and after it: cargo, and all it starts, hold the slot
unless ($ENV{BON_CHECK_SLOT}) {
    $^F = 1023;  # the slot's descriptor survives exec
    until ($held) {
        for my $k (0 .. $n - 1) {
            my $f;
            sysopen($f, "$slots/check.$k", O_RDONLY) or sysopen($f, "$slots/check.$k", O_RDONLY | O_CREAT, 0644) or next;
            if (flock($f, LOCK_EX | LOCK_NB)) { $held = $f; last }
            close $f;
        }
        select(undef, undef, undef, 0.25) unless $held;
    }
    $ENV{BON_CHECK_SLOT} = 'held';
}
exec { 'cargo' } 'cargo', @args or die "bon's cargo: no cargo on PATH: $!\n";
"#;

/// The directory holding bon's cargo for this bon process, engineer's: agent
/// may read and run it, never write it. None if it could not be written; then
/// nothing is pooled or capped beyond what bon sets itself.
fn wrapper(config: &Config) -> Option<PathBuf> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        if is_agent() { return None; }
        let d = scratch("bin");
        let text = CARGO.replace("@SLOTS@", &slots_dir().to_string_lossy()).replace("@N@", &config.pools.checks.to_string())
            .replace("@THREADS@", &config.pools.threads.to_string()).replace("@SELF@", &d.to_string_lossy());
        let p = d.join("cargo");
        let r = std::fs::write(&p, text).and_then(|_| std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)));
        match r { Ok(()) => Some(d), Err(e) => { eprintln!("bon: bon's cargo not written: {}: {e}", p.display()); None } }
    }).clone()
}

/// PATH with bon's cargo first.
fn with_wrapper(config: &Config, path: Vec<String>) -> Vec<String> {
    wrapper(config).map(|d| d.to_string_lossy().to_string()).into_iter().chain(path).collect()
}

// ── the verdict cache ───────────────────────────────────

/// What a check's result is a function of besides its command and the
/// toolchain: the tree it runs on and the test written into it (path, bytes).
/// `read`: whether a cached result may answer; trunk's first run in a bon
/// process always runs, since candidates' builds start from the build it leaves.
struct On<'a> { tree: String, test: Option<(&'a str, &'a [u8])>, read: bool }

impl On<'_> {
    /// A commit's tree, nothing written into it.
    fn commit(root: &std::path::Path, commit: &str) -> On<'static> { On { tree: tree_of(root, commit), test: None, read: true } }
}

/// A commit's tree id; empty (never cached) if git cannot say.
fn tree_of(root: &std::path::Path, commit: &str) -> String {
    git(root, &["rev-parse", &format!("{commit}^{{tree}}")]).unwrap_or_default()
}

/// The cache of check results: engineer's alone (0700), never agent's.
/// BON_VERDICTS names another (a benchmark's own, so runs do not share).
/// None, so nothing is cached, if it cannot be made so, or another can write it.
fn cache_dir() -> Option<PathBuf> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::env::var("BON_VERDICTS").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(WORKING_DIRECTORIES).join("verdicts"));
        std::fs::create_dir_all(&d).ok()?;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).ok()?;
        // Owned by whoever owns the working directories (engineer), and by no group or other.
        let (it, base) = (std::fs::metadata(&d).ok()?, std::fs::metadata(WORKING_DIRECTORIES).ok()?);
        (it.uid() == base.uid() && it.mode() & 0o077 == 0).then_some(d)
    }).clone()
}

/// The toolchain as the checks see it: the host file, their PATH and homes, the
/// versions of rustc, cargo and Verus, and bon's cargo. Computed once per PATH.
fn identity(config: &Config) -> String {
    static MEMO: std::sync::Mutex<Option<HashMap<String, String>>> = std::sync::Mutex::new(None);
    let path = checks_path(config).join(":");
    let id = format!("{path}\0{:?}", config.toolchain);
    let mut memo = MEMO.lock().unwrap_or_else(|e| e.into_inner());
    memo.get_or_insert_with(HashMap::new).entry(id.clone()).or_insert_with(|| {
        let version = |tool: &str| Command::new(tool).arg("--version").env_clear().env("PATH", &path)
            .envs(config.toolchain.iter().map(|(k, v)| (k.as_str(), v.as_str()))).stdin(Stdio::null()).output()
            .map_or_else(|e| e.to_string(), |o| String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr));
        let host = std::fs::read(HOST).unwrap_or_default();
        format!("{id}\0{}\0{}\0{}\0{}\0{}", String::from_utf8_lossy(&host), version("rustc"), version("cargo"), version("verus"), CARGO)
    }).clone()
}

/// The cache key of a command on `on`, or None when it may not be cached: no
/// tree, or bon running as agent (which may not keep engineer's cache).
fn verdict_key(config: &Config, on: &On, command: &str) -> Option<String> {
    if on.tree.is_empty() || is_agent() { return None; }
    let mut h = Sha256::new();
    for part in [identity(config).as_bytes(), on.tree.as_bytes(), command.as_bytes()] { h.update(part); h.update([0u8]); }
    if let Some((path, bytes)) = on.test { h.update(path.as_bytes()); h.update([0u8]); h.update(bytes); }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// A cached result: (exit 0, stdout, the log it wrote when it ran).
fn cached(key: &str) -> Option<(bool, String, String)> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(cache_dir()?.join(key)).ok()?).ok()?;
    Some((v["ok"].as_bool()?, v["stdout"].as_str()?.to_string(), v["log"].as_str().unwrap_or_default().to_string()))
}

/// Keep a result: written whole, then renamed into place.
fn store(key: &str, ok: bool, stdout: &str, log: &str) {
    let Some(d) = cache_dir() else { return };
    let tmp = d.join(format!(".{key}.{}", std::process::id()));
    let text = serde_json::json!({ "ok": ok, "stdout": stdout, "log": log }).to_string();
    if std::fs::write(&tmp, text).is_ok() { let _ = std::fs::rename(&tmp, d.join(key)); }
}

/// Answer from the cache, writing the trace's log as `cached: <key>` and the
/// log the run wrote. (exit 0, stdout)
fn answer(config: &Config, on: &On, command: &str, log: &std::path::Path) -> Option<(bool, String)> {
    if !on.read { return None; }
    let key = verdict_key(config, on, command)?;
    let (ok, stdout, text) = cached(&key)?;
    write_trace(log, format!("cached: {key}\n{text}"));
    Some((ok, stdout))
}

/// One lock per key: of identical checks running at once in this bon process,
/// one runs and the rest wait for its result.
fn flight(key: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
    type Flights = HashMap<String, std::sync::Arc<std::sync::Mutex<()>>>;
    static FLIGHTS: std::sync::Mutex<Option<Flights>> = std::sync::Mutex::new(None);
    FLIGHTS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).entry(key.to_string()).or_default().clone()
}

/// Run a check as agent in a read-only checkout, holding a check slot, with the
/// pool's threads; or answer it from the cache. A check's exit (0 or not), its
/// output, and whether its time limit stopped it. Only a run that exited with
/// a code of its own is cached: never one killed, signalled or not started.
fn run_check(config: &Config, on: &On, dir: &std::path::Path, target: &std::path::Path, command: &str, log: &std::path::Path) -> (bool, String, bool) {
    run_check_with(config, on, config.pools.threads, dir, target, command, log)
}

/// run_check with `threads` threads: trunk's build, which every candidate
/// waits on, and `bon check`, which engineer waits on, take the machine.
fn run_check_with(config: &Config, on: &On, threads: usize, dir: &std::path::Path, target: &std::path::Path, command: &str,
                  log: &std::path::Path) -> (bool, String, bool) {
    let key = verdict_key(config, on, command);
    let one = key.as_deref().map(flight);
    let _one = one.as_ref().map(|f| f.lock().unwrap_or_else(|e| e.into_inner()));
    if let Some((ok, out)) = answer(config, on, command, log) { return (ok, out, false); }
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()];
    let t = target.to_string_lossy().to_string();
    let env = [("BON_BUILD", t.clone()), ("CARGO_TARGET_DIR", t), ("CARGO_BUILD_JOBS", threads.to_string()), ("BON_CHECK_SLOT", "held".to_string())];
    let c = as_agent_on(config, &with_wrapper(config, checks_path(config)), dir, &env, &argv);
    let _slot = Slot::check(config);
    let r = supervised(c, None, Duration::from_secs(config.agent_process.time), log);
    if let (Some(k), true) = (&key, r.exited) { store(k, r.ok, &r.stdout, &r.log); }
    (r.ok && !r.killed, r.stdout, r.killed)
}

/// Every core: for the checks something waits on alone.
fn cores() -> usize { std::thread::available_parallelism().map_or(1, |c| c.get()) }

// ── harnesses ───────────────────────────────────────────

/// A harness that runs no model: its cost is zero, it needs no price and no login.
fn is_stub(h: &Harness) -> bool { h.name == STUB }
const STUB: &str = "stub";

/// The harness's argv. `writable`: directories besides the working directory
/// the session writes (its build, the check slots), for a harness that
/// sandboxes its commands to the working directory (codex).
fn harness_argv(h: &Harness, config: &Config, dir: &std::path::Path, writable: &[PathBuf]) -> Vec<String> {
    if let Some(c) = &h.command { return c.clone(); }
    match h.name.as_str() {
        "claude" => vec![
            "claude", "-p", "--output-format", "stream-json", "--verbose",
            "--setting-sources", "", "--strict-mcp-config", "--no-session-persistence",
            "--permission-mode", "bypassPermissions", "--model", &h.model,
            "--max-budget-usd", &format!("{}", config.agent_process.limit),
        ].into_iter().map(String::from).collect(),
        _ => {
            let mut argv: Vec<String> = vec![
                "codex", "exec", "--json", "--ephemeral", "--ignore-rules", "--skip-git-repo-check",
                "--sandbox", "workspace-write", "--color", "never", "-m", &h.model,
                "-C", &dir.to_string_lossy(),
            ].into_iter().map(String::from).collect();
            for w in writable { argv.push("--add-dir".into()); argv.push(w.to_string_lossy().into()); }
            argv.push("-".into());
            argv
        }
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
    if is_stub(h) { return Ok((0, Some(0), HashMap::new())); }
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

/// What a push changes, for the agent processes that test it: the spec's diff
/// since bon's last push (for blind tests, which see the spec and not the code),
/// and the selected candidate's diff against its base (for foils). Capped, so a
/// large change still fits.
fn aim(m: &Manifest, kind: &Kind, target: Option<&Search>, start: &str) -> String {
    let cap = |d: String| { let lines: Vec<&str> = d.lines().collect(); if lines.len() > 400 { format!("{}\n[… {} more lines]", lines[..400].join("\n"), lines.len() - 400) } else { d } };
    let selected = |p: &crate::gates::AgentProcess| target.and_then(|t| t.results.get(p.index)).and_then(|r| r.as_ref())
        .map(|c| (c.base.iter().collect::<String>(), c.commit.iter().collect::<String>()));
    match kind {
        Kind::Counterexample { goal: Some(_) } => {
            let since = git(&m.root, &["log", "-1", "--format=%H", "--author=agent", start]).unwrap_or_default();
            let mut args = vec!["diff".to_string(), if since.is_empty() { git(&m.root, &["rev-list", "--max-parents=0", start]).unwrap_or_default() } else { since }, start.to_string(), "--".into()];
            args.extend(m.config.checks.paths.iter().cloned());
            let d = git(&m.root, &args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).unwrap_or_default();
            // No selection: the implementations behave differently, and the test decides between them.
            let differ = if target.is_some_and(|t| crate::exec::selected(t).is_none()) { "They behave differently: write the test that tells which behavior the spec requires.\n" } else { "" };
            if d.is_empty() { differ.to_string() } else { format!("{differ}The spec changed for this push; aim your test at what the change requires:\n{}\n", cap(d)) }
        }
        Kind::Foil { goal, .. } => match selected(goal) {
            Some((base, commit)) => {
                let files = git(&m.root, &["diff", "--name-only", &base, &commit]).unwrap_or_default().lines().collect::<Vec<_>>().join(", ");
                let d = git(&m.root, &["diff", &base, &commit]).unwrap_or_default();
                format!("The change under test touched {files}. Change only what it added or altered, in those files:\n{}\n", cap(d))
            }
            None => String::new(),
        },
        _ => String::new(),
    }
}

fn prompt(kind: &Kind, config: &Config, aim: &str) -> String {
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
        "You are working in a copy of a repository, with no git. {goal}{aim}\n\
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
        .map_err(|e| format!("{HOST}: {e}; run bon setup"))?;
    config.pools = Pools::of(&host, &|k| std::env::var(k).ok());
    config.path = host.path;
    config.prices = host.prices;
    config.toolchain = vec![("RUSTUP_HOME".to_string(), host.rustup_home), ("CARGO_HOME".to_string(), host.cargo_home)];
    cargo_config_guard(&root)?;
    for h in config.harness.iter().chain(config.counterexample.harness.iter()) {
        if !is_stub(h) && !config.prices.contains_key(&h.model) {
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

/// The checks' paths and the build configuration they read: no search may change them.
#[verifier::external_body]
pub fn checks(m: &Manifest) -> Vec<Path> {
    m.config.checks.paths.iter().map(|p| p.as_str()).chain(BUILD).map(|p| p.chars().collect()).collect()
}

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
    let mut names: Vec<&str> = m.config.harness.iter().chain(m.config.counterexample.harness.iter())
        .filter(|h| !is_stub(h)).map(|h| h.name.as_str()).collect();
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
    traced(trace, std::fs::create_dir_all(trace));
    // git bundles refs, never a bare commit ("empty bundle"): a ref for as long as it takes.
    let r = format!("refs/bon/evidence/{commit}");
    let ok = git(&m.root, &["update-ref", &r, commit]).is_ok()
        && Command::new("git").args(["bundle", "create", "-q"]).arg(&file).arg(&r).arg(format!("^{base}"))
            .current_dir(&m.root).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    let _ = git(&m.root, &["update-ref", "-d", &r]);
    if !ok { eprintln!("bon: trace not written: {}: git bundle of {commit}", file.display()); }
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
            // Under the tested search, whose candidates they are: its index in the
            // kernel is the counterexample search's goal.
            let Kind::Counterexample { goal: Some(p) } = &x.kind else { return Err("evidence without a tested search".into()) };
            let d = trace_dir(&m.root);
            let search = FIRST_RUN.load(std::sync::atomic::Ordering::SeqCst) + p.search;
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
    git(&m.root, &["update-ref", &format!("refs/remotes/{r}/{tr}"), &commit])?;
    append(&m.root.join(BON).join("traces").join("counterexamples.jsonl"),
           &serde_json::json!({ "test": path, "evidence": evidence }));
    Ok(())
}

/// The remote and trunk the manifest names (default origin and main), read
/// from the commit checked out: names only, so any branch will do.
#[verifier::external]
pub fn remote_trunk(root: &std::path::Path) -> (String, String) {
    let manifest: Option<toml::Value> = git(root, &["show", &format!("HEAD:{BON}/bon.toml")]).ok().and_then(|t| toml::from_str(&t).ok());
    let key = |k: &str, d: &str| manifest.as_ref().and_then(|m| m.get(k)).and_then(|v| v.as_str()).unwrap_or(d).to_string();
    (key("remote", "origin"), key("trunk", "main"))
}

/// trunk's head: the remote's trunk, just fetched. bon works on git's objects
/// and the remote's ref, never a working tree, so what is checked out, and
/// whether it has changes, does not matter.
#[verifier::external_body]
pub fn head(root: &str) -> (r: Result<Commit, String>) {
    let root = PathBuf::from(root);
    let (r, t) = remote_trunk(&root);
    git(&root, &["fetch", "--quiet", &r, &t]).map_err(|e| format!("fetch {r} {t}: {e}"))?;
    Ok(git(&root, &["rev-parse", &format!("refs/remotes/{r}/{t}")])?.chars().collect())
}

/// Nothing to check: bon works on the remote's trunk from any branch.
#[verifier::external_body]
pub fn on_trunk(m: &Manifest) -> (r: Result<(), String>) {
    let _ = m;
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
    traced(&log, std::fs::create_dir_all(&log));
    let mut out = Vec::new();
    let on = On::commit(root, &c);
    for (kind, list) in [("test", &config.checks.test), ("verify", &config.checks.verify)] {
        for (k, v) in list.iter().enumerate() {
            let path = log.join(format!("check-{kind}-{k}"));
            // engineer waits on it alone: every core.
            let ok = run_check_with(config, &on, cores(), &dir, &build, v, &path).0;
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

/// The permissions trusted code observed for agent on each object the policy
/// names, path by path, in the order of `gates::observed`: the checks, the
/// transcripts, a working directory, the repository, the working directories,
/// the toolchain. None is a path that does not exist.
pub type Observed = (Vec<Option<Permission>>, Vec<Option<Permission>>, Vec<Option<Permission>>,
                     Vec<Option<Permission>>, Vec<Option<Permission>>, Vec<Option<Permission>>);

/// agent's effective permissions on every path of each object the policy
/// names, observed by asking as agent, on a probe working directory made the
/// same way as real ones. A path that does not exist is reported as missing
/// (None), never as the policy's value. Err is an observation that could not
/// be made (agent cannot be asked, a path cannot be looked at), never a denial.
#[verifier::external_body]
pub fn observe(m: &Manifest, commit: &Commit) -> (r: Result<Observed, String>) {
    let c: String = commit.iter().collect();
    // Asking as agent must work before any answer counts as a denial.
    let asks = Command::new("sudo").args(["-n", "-u", "agent", "true"]).status().map_err(|e| format!("cannot ask as agent: {e}; run bon setup"))?;
    if !asks.success() { return Err("cannot ask as agent (sudo -n -u agent); run bon setup".into()); }
    let probe = scratch(&format!("probe/{}", repository_name(&m.root)));
    if let Err(e) = working_directory(&m.root, &m.config, &c, &probe) {
        let _ = std::fs::remove_dir_all(&probe);
        return Err(format!("agent is not set up ({e}); run bon setup"));
    }
    let r = observe_in(m, &probe);
    let _ = std::fs::remove_dir_all(&probe);
    r
}

} // verus!

fn observe_in(m: &Manifest, probe: &std::path::Path) -> Result<Observed, String> {
    // test(1) exits 0 (allowed) or 1 (denied); anything else is no answer.
    let ask = |path: &std::path::Path, flag: &str| -> Result<bool, String> {
        let s = Command::new("sudo").args(["-n", "-u", "agent", "test", flag]).arg(path).status()
            .map_err(|e| format!("cannot ask as agent about {}: {e}", path.display()))?;
        match s.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(format!("cannot ask as agent about {}: {s}", path.display())),
        }
    };
    // Whether a path exists, as bon's own process sees it: missing is reported
    // as missing; a path that cannot be looked at is an error.
    let present = |path: &std::path::Path| -> Result<bool, String> {
        match std::fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("cannot observe {}: {e}", path.display())),
        }
    };
    // A check that is a file is run by an interpreter that reads it (sh, cargo),
    // so for a file, execute is whether agent can read it.
    let perm = |object: &str, path: &std::path::Path| -> Result<Option<Permission>, String> {
        if !present(path)? {
            eprintln!("bon: missing: {object} {}", path.display());
            return Ok(None);
        }
        let p = Permission { read: ask(path, "-r")?, write: ask(path, "-w")?, execute: ask(path, "-x")? };        Ok(Some(if path.is_dir() { p } else { Permission { execute: p.read, ..p } }))
    };
    let mut checks = Vec::new();
    for p in &m.config.checks.paths { checks.push(perm("check", &probe.join(p.trim_end_matches('/')))?); }
    // The transcripts as agent meets them: in a working directory. A
    // repository without them observes them on no path.
    let transcripts = probe.join(m.config.transcripts.clone().unwrap_or("transcripts".into()));
    let transcripts = if present(&transcripts)? { vec![perm("transcripts", &transcripts)?] } else { Vec::new() };
    // The toolchain: the host file's homes, and every directory on the checks' PATH.
    let mut toolchain = Vec::new();
    for (k, v) in &m.config.toolchain { toolchain.push(perm(&format!("toolchain {k}"), std::path::Path::new(v))?); }
    for d in checks_path(&m.config) { toolchain.push(perm("toolchain", std::path::Path::new(&d))?); }
    Ok((checks, transcripts, vec![perm("working directory", probe)?],
        vec![perm("repository", &m.root.join(".git"))?], vec![perm("working directories", std::path::Path::new(WORKING_DIRECTORIES))?], toolchain))
}

verus! {

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
    traced(&traces, std::fs::create_dir_all(&traces));
    // Every agent process at once: the generation pool bounds the model
    // sessions, the check pool their checks and the judge's.
    let out: Vec<std::sync::Mutex<(Option<Candidate>, u64)>> = slots.iter().map(|_| std::sync::Mutex::new((None, 0))).collect();
    std::thread::scope(|scope| {
        for (i, h) in slots.iter().enumerate() {
            let (out, start, traces) = (&out, &start, &traces);
            scope.spawn(move || {
                *out[i].lock().unwrap() = agent_process(m, kind, search, i, h, start, target, foils, &traces.join(i.to_string()));
            });
        }
    });
    out.into_iter().map(|c| c.into_inner().unwrap_or((None, 0))).collect()
}

/// The selected candidate is pushed to the remote's trunk. The push is
/// fast-forward only: if the remote's trunk moved, it is refused and nothing
/// changes. The engineer's branch is left alone: pull to follow. (TCB: git, the remote)
#[verifier::external_body]
pub fn push(m: &Manifest, commit: &Commit) -> (r: Result<(), String>) {
    let c: String = commit.iter().collect();
    let (r, t) = (&m.config.remote, &m.config.trunk);
    git(&m.root, &["push", "--quiet", r, &format!("{c}:refs/heads/{t}")])
        .map_err(|e| format!("blocked: {r}/{t} moved during the search, so the push was refused; run it again ({e})"))?;
    git(&m.root, &["update-ref", &format!("refs/remotes/{r}/{t}"), &c])?;
    record_cost(m, &c);
    Ok(())
}

#[verifier::external]
fn append(file: &std::path::Path, line: &serde_json::Value) { append_line(file, &line.to_string()); }

/// What this bon process spent before its push: the generation and time cost
/// of every search it ran (blocked attempts, reruns, foil and counterexample
/// searches included), from its searches.jsonl, appended to pushes.jsonl as
/// `process_cost`. A push's cost, which spans bon processes, the view derives.
#[verifier::external_body]
pub fn record_cost(m: &Manifest, commit: &str) {
    let d = trace_dir(&m.root);
    let searches: Vec<serde_json::Value> = std::fs::read_to_string(d.join("searches.jsonl")).unwrap_or_default()
        .lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let sum = |k: &str| searches.iter().filter_map(|s| s[k].as_f64()).sum::<f64>();
    let (generation, time) = (sum("generation_dollars"), sum("time_dollars"));
    eprintln!("bon: push {}: this bon process ran {} searches; generation ${generation:.4} + time ${time:.4} = ${:.4}",
              &commit[..commit.len().min(8)], searches.len(), generation + time);
    append(&d.join("pushes.jsonl"), &serde_json::json!({
        "commit": commit, "searches": searches.len(), "generation_dollars": generation, "time_dollars": time,
        "process_cost": generation + time,
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
    let (kind, goal) = LATEST.lock().map(|l| l.clone()).unwrap_or_default();
    let summary = serde_json::json!({
        "search": search, "kind": kind, "goal": goal,
        "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        "agent_processes": n, "limit": s.limit as f64 / 1_000_000.0, "verified": verified, "generation_dollars": generation,
        "seconds": hours * 3600.0, "rate": rate, "background": background, "time_dollars": time,
        "cost_per_verified_candidate": per,
    });
    append(&d.join("searches.jsonl"), &summary);
    // The search as the gates saw it, in the kernel's words (little-endian),
    // for programs to read and re-derive its selection.
    let words: Vec<u8> = <crate::exec::Kernel as crate::gates::Encoding>::encode(s).iter().flat_map(|w| w.to_le_bytes()).collect();
    write_trace(&d.join(search.to_string()).join("search.words"), words);
}

/// Record which candidate of the latest search was selected.
#[verifier::external_body]
pub fn record_selected(m: &Manifest, i: usize) {
    let search = RUNS.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
    record(m, &format!("selected {search} {i}"));
}

/// Record that the latest search's verified candidates disagree: a
/// counterexample search on it follows, its tests built on its verified candidate i.
#[verifier::external_body]
pub fn record_disagreed(m: &Manifest, i: usize) {
    let search = RUNS.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
    record(m, &format!("disagreed {search} {i}"));
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
    // A new kernel instance: its search 0 is this bon process's next run.
    FIRST_RUN.store(RUNS.load(std::sync::atomic::Ordering::SeqCst), std::sync::atomic::Ordering::SeqCst);
    let root: String = root.iter().collect();
    record(m, &format!("initialize {root} {limit}"));
}

/// grant: its width, when, each agent process's limit, its kind and goal. The
/// last search is the one granted, on the trunk verdict its kind needs.
#[verifier::external_body]
pub fn record_grant(m: &Manifest, kind: &Kind, n: usize, agent_process_limit: u64, Ghost(checks_accept): Ghost<bool>, Ghost(searches): Ghost<Seq<spec::Search>>)
    requires
        searches.len() > 0,
        kind@ is Code ==> !checks_accept,
        kind@ is Compaction || kind@ == (spec::Kind::Counterexample { goal: None }) ==> checks_accept,
        searches.last().kind == kind@,
        searches.last().n == n as nat,
        searches.last().limit == agent_process_limit as nat,
{
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (k, goal) = label(kind);
    record(m, &format!("grant {n} {now} {agent_process_limit} {k} {goal}"));
}

/// wait: when, the agent process, the commit it returned (or none), what it
/// is charged against its limit (its generation, up to the agent process's
/// limit), and its generation as measured, both in
/// microdollars. Its result is the one the search now holds.
#[verifier::external_body]
pub fn record_wait(m: &Manifest, search: usize, index: usize, result: &Option<Candidate>, generation: u64, Ghost(searches): Ghost<Seq<spec::Search>>)
    requires
        search < searches.len(),
        searches[search as int].results.contains_key(index as int),
        searches[search as int].results[index as int] == (match result { Some(c) => Some(c@), None => None }),
{
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let commit = result.as_ref().map_or("none".to_string(), |c| c.commit.iter().collect());
    let charged = generation.min(micro(m.config.agent_process.limit));
    record(m, &format!("wait {now} {search} {index} {commit} {charged} {generation}"));
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
        spec::foils_on(searches[foil_index as int], tested_index as int, i as int),
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

/// An attempt blocked, and the one reason why, which Verus checks against the
/// searches it names: tested, and the counterexample and foil searches on its
/// selection (any search, for a reason that does not reach them), and the
/// remote's head, which decides trunk moved from refused.
#[verifier::external_body]
pub fn record_blocked(m: &Manifest, reason: spec::Blocked, Ghost(tested): Ghost<spec::Search>,
                      Ghost(counterexample): Ghost<spec::Search>, Ghost(foils): Ghost<spec::Search>,
                      Ghost(remote): Ghost<spec::Commit>)
    requires spec::blocked(reason, tested, counterexample, foils, remote),
{
    let (word, sentence) = match reason {
        spec::Blocked::TooFewVerified => ("too_few_verified", "fewer than two verified candidates"),
        spec::Blocked::Disagree => ("disagree", "the verified candidates disagree, two tests judged every one, and none splits them: the spec does not decide between them"),
        spec::Blocked::TooFewTests => ("too_few_tests", "fewer than two verified tests, or on candidates that disagree fewer than two that judge every one, and none splits the candidates"),
        spec::Blocked::RejectsEvery => ("rejects_every", "a verified test rejects every candidate"),
        spec::Blocked::Undiscriminating => ("undiscriminating", "fewer than two verified tests judge every candidate and reject a foil"),
        spec::Blocked::TrunkMoved => ("trunk_moved", "trunk moved during the search; run it again"),
        spec::Blocked::Refused => ("refused", "git refused what the gates allowed"),
    };
    record(m, &format!("blocked: {word}: {sentence}"));
}

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
    append_line(&trace_dir(&m.root).join("transitions"), line);
}

/// The agree checks' outputs at a commit, hashed: a compaction search's goal.
#[verifier::external_body]
pub fn agree_outputs(m: &Manifest, commit: &Commit) -> (r: Result<Vec<Hash>, String>) {
    let c: String = commit.iter().collect();
    let dir = scratch(&format!("goal/{}", repository_name(&m.root)));
    check_directory(&m.root, &c, &dir)?;
    let build = build_directory(&m.config, "goal/build")?;
    let log = trace_dir(&m.root);
    traced(&log, std::fs::create_dir_all(&log));
    let mut out = Vec::new();
    let on = On::commit(&m.root, &c);
    for (k, a) in m.config.checks.agree.iter().enumerate() {
        out.push(Hash(hash(&run_check(&m.config, &on, &dir, &build, a, &log.join(format!("goal-agree-{k}"))).1)));
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
/// The build configuration cargo reads beside Cargo.toml: a check runs what it
/// says, so it is protected like a check.
pub const BUILD: [&str; 2] = [".cargo/", "build.rs"];

/// One agent process: generate, capture, observe. Its log goes under `trace`.
#[allow(clippy::too_many_arguments)]
fn agent_process(m: &Manifest, kind: &Kind, search: usize, index: usize, h: &Harness, start: &str,
                 target: Option<&Search>, foils: Option<&Search>, trace: &std::path::Path) -> (Option<Candidate>, u64) {
    traced(trace, std::fs::create_dir_all(trace));
    let config = &m.config;
    // A generation slot for the session and its setup alone: never held while
    // its candidate is judged.
    let session = Slot::generation(config);
    let dir = scratch(&format!("{search}.{index}/{}", repository_name(&m.root)));
    // What each kind may not write, made structural: code, the counterexamples' tests.
    let (writable, more) = match kind {
        Kind::Queue { .. } => (Some(QUEUE), Vec::new()),
        Kind::Code { .. } | Kind::Foil { .. } => (None, config.counterexample.tests.clone()),
        _ => (None, Vec::new()),
    };
    if let Err(e) = working_directory_except(&m.root, config, start, &dir, writable, &more) {
        write_trace(&trace.join("error"), e);
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
    // Its own build, a clone of trunk's, which its judge reuses: its first cargo
    // is warm, and the judge builds only what changed since its last.
    let build = match build_directory(config, &format!("{search}.{index}.build/build")) {
        Ok(b) => b,
        Err(e) => { write_trace(&trace.join("error"), e); return (None, 0); }
    };
    let argv = harness_argv(h, config, &dir, &[build.clone(), slots_dir()]);
    write_trace(&trace.join("argv"), argv.join(" "));
    let text = prompt(kind, config, &aim(m, kind, target, start));
    write_trace(&trace.join("prompt"), &text);
    let b = build.to_string_lossy().to_string();
    let env = [("CARGO_TARGET_DIR", b.clone()), ("BON_BUILD", b), ("CARGO_BUILD_JOBS", config.pools.threads.to_string())];
    let c = as_agent_on(config, &with_wrapper(config, config.path.clone()), &dir, &env, &argv);
    let (_, stdout, killed) = supervise(c, Some(text), Duration::from_secs(config.agent_process.time), &trace.join("harness"));
    drop(session);
    // Without token counts there is no measured cost: charge the whole limit.
    let (spent, harness_cost, prices) = generation(h, config, &stdout).unwrap_or((micro(config.agent_process.limit), None, HashMap::new()));
    if killed { write_trace(&trace.join("killed"), "time limit"); }
    let candidate = capture(m, kind, search, index, start, &dir, &build, target, foils, trace).map_err(|e| {
        write_trace(&trace.join("error"), &e);
    }).ok();
    let _ = Command::new("chmod").args(["-R", "-N"]).arg(&dir).stderr(Stdio::null()).status();
    let _ = std::fs::remove_dir_all(&dir);
    remove_build(config, &build);
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
            "measured": c.measured, "added_paths": c.added.iter().map(|p| text(p)).collect::<Vec<_>>(),
            "intents": c.intents.iter().map(|(q, i)| (q, text(i))).collect::<Vec<_>>(),
        })),
    });
    write_trace(&trace.join("facts.json"), serde_json::to_string_pretty(&facts).unwrap_or_default());
    (candidate, spent)
}

/// Record the working directory as a commit whose parent is `start`, then
/// observe it: changed paths, diff, tests, Verus, agree outputs, rank, and what
/// its test accepts.
#[allow(clippy::too_many_arguments)]
fn capture(m: &Manifest, kind: &Kind, search: usize, index: usize, start: &str, dir: &std::path::Path, build: &std::path::Path,
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
    let run = trace_dir(root).file_name().map_or(String::new(), |n| n.to_string_lossy().to_string());
    let message = format!("{name}{}\n\nTrace: {BON}/traces/{run}/{search}/{index}\n",
                          if goal.is_empty() { String::new() } else { format!(": {goal}") });
    let commit_of = |tree: &str| -> Result<String, String> {
        let out = Command::new("git").args(["commit-tree", tree, "-p", start, "-m", &message]).current_dir(root)
            .env("GIT_AUTHOR_NAME", "agent").env("GIT_AUTHOR_EMAIL", "agent@localhost")
            .stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).to_string()); }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let commit = commit_of(&tree)?;
    let changes = |commit: &str| -> Result<(Vec<Path>, u64), String> {
        let files = numstat(root, start, commit)?;
        let diff = files.iter().map(|(a, r, _)| a + r).sum();
        Ok((files.into_iter().map(|(_, _, p)| p.chars().collect::<Path>()).collect(), diff))
    };
    let (mut changed, mut diff) = changes(&commit)?;
    let mut commit = commit;
    let mut written: Option<Vec<u8>> = None;

    // Checks run in a read-only checkout, as agent.
    let cdir = scratch(&format!("{search}.{index}.check/{}", repository_name(root)));
    check_directory(root, &commit, &cdir)?;
    // Keyed by the candidate's tree: a byte-identical sibling's checks run once.
    let on = On { tree: tree.clone(), test: None, read: true };
    let trunk_proved = TRUNK_PROVED.load(std::sync::atomic::Ordering::SeqCst);
    let mut accepted = true;
    let mut proved = true;
    let mut accepts = Vec::new();
    let mut accepts_foils = Vec::new();
    let mut rejects_counterexamples = false;
    let mut measured = false;
    let mut out = Vec::new();
    let mut rank = 0i64;
    match kind {
        Kind::Code { .. } | Kind::Compaction { .. } | Kind::Foil { .. } => {
            for (k, v) in config.checks.test.iter().enumerate() {
                if !run_check(config, &on, &cdir, build, v, &trace.join(format!("test-{k}"))).0 { accepted = false; break; }
            }
            for (k, v) in config.checks.verify.iter().enumerate() {
                if !accepted { proved = false; break; }
                if !run_check(config, &on, &cdir, build, v, &trace.join(format!("verify-{k}"))).0 { proved = false; break; }
            }
            if accepted && proved && !matches!(kind, Kind::Foil { .. }) {
                // Measured only when every agree check and the rank check exited 0, and
                // the rank parsed: a failure's output is no measurement.
                measured = true;
                for (k, a) in config.checks.agree.iter().enumerate() {
                    let (ok, text, _) = run_check(config, &on, &cdir, build, a, &trace.join(format!("agree-{k}")));
                    measured &= ok;
                    out.push(Hash(hash(&text)));
                }
                let which = if matches!(kind, Kind::Compaction { .. }) { "compaction" } else { "code" };
                if let Some(r) = config.checks.rank.get(which) {
                    let (ok, text, _) = run_check(config, &on, &cdir, build, r, &trace.join("rank"));
                    match text.trim().parse() { Ok(v) if ok => rank = v, _ => measured = false }
                }
                if matches!(kind, Kind::Compaction { .. }) {
                    rejects_counterexamples = rejects_every_counterexample(m, &commit, start, build, trace);
                }
            }
        }
        Kind::Counterexample { .. } => {
            // Its test is accepted when it builds on the tree it tests: trunk's own build
            // lags a spec change that adds or changes a gate. Verus's verdict is trunk's.
            let test = std::fs::read(dir.join(&config.counterexample.path)).ok();
            written = test.clone();
            accepted = match &test {
                Some(bytes) => test_on(m, &tested_tree(kind, target, start), bytes, build, &config.counterexample.build, &trace.join("build")),
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
            // A verdict on each member and each foil, or none: a test that does not
            // build there, or whose run times out or cannot be set up, has no result,
            // which the spec reads as saying nothing (never a split, never a rejection).
            if let (true, Some(bytes)) = (accepted, &test) {
                // (member or foil, its index, its commit, its log)
                let mut tasks: Vec<(bool, i64, String, PathBuf)> = members.into_iter()
                    .map(|(j, mc)| (false, j, mc, trace.join(format!("accepts-{j}")))).collect();
                // Each foil: a program trunk's tests accept and Verus rejects. The
                // spec decides which results are foils; every result is run.
                if let Some(f) = foils {
                    for (j, r) in f.results.iter().enumerate() {
                        let Some(c) = r else { continue };
                        tasks.push((true, j as i64, c.commit.iter().collect(), trace.join(format!("accepts-foil-{j}"))));
                    }
                }
                let on: Vec<(String, PathBuf)> = tasks.iter().map(|(_, _, c, l)| (c.clone(), l.clone())).collect();
                let results = verdicts(m, &on, bytes, build, &format!("{search}.{index}"));
                for ((foil, j, _, _), r) in tasks.into_iter().zip(results) {
                    let Some(a) = r else { continue };
                    if foil { accepts_foils.push((j, a)); } else { accepts.push((j, a)); }
                }
            }
        }
        Kind::Queue { .. } => {
            // Only the queue changed: trunk's verdicts stand; the lines must parse.
            accepted = queue_accepted(root, start, &commit);
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
        Kind::Queue { goal } => queue_intents(root, start, &commit, &goal.iter().collect::<String>()),
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
        measured,
        added: added(root, start, &commit)?,
        rejects_counterexamples,
        rank,
        diff,
    })
}

/// A compaction candidate's tests still reject every counterexample. The landed
/// tests are the files under the counterexample `tests` paths on trunk
/// (`start`); each one's evidence is the commits recorded when it landed
/// (counterexamples.jsonl, by its path). Each landed test must still be in the
/// candidate, and the candidate's version of it, alone at the counterexample
/// path, must make `counterexample.run` reject each of its evidence. A landed
/// test with no evidence on record, evidence git cannot read, or a deleted test
/// fails the check: missing evidence never passes. Why it fails is in the
/// trace's `counterexample` log.
fn rejects_every_counterexample(m: &Manifest, commit: &str, start: &str, build: &std::path::Path, trace: &std::path::Path) -> bool {
    let config = &m.config;
    let check = || -> Result<(), String> {
        let mut evidence: HashMap<String, Vec<String>> = HashMap::new();
        for l in std::fs::read_to_string(m.root.join(BON).join("traces").join("counterexamples.jsonl")).unwrap_or_default().lines() {
            let Ok(r) = serde_json::from_str::<serde_json::Value>(l) else { continue };
            let Some(test) = r["test"].as_str() else { continue };
            evidence.entry(test.to_string()).or_default()
                .extend(r["evidence"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(String::from)));
        }
        let mut args = vec!["ls-tree", "-r", "--name-only", start, "--"];
        args.extend(config.counterexample.tests.iter().map(String::as_str));
        let landed = git(&m.root, &args).map_err(|e| format!("the landed tests cannot be listed: {e}"))?;
        for (k, test) in landed.lines().enumerate() {
            let commits = evidence.get(test).filter(|e| !e.is_empty())
                .ok_or_else(|| format!("{test}: landed with no evidence on record"))?;
            let bytes = Command::new("git").args(["cat-file", "blob", &format!("{commit}:{test}")]).current_dir(&m.root)
                .stderr(Stdio::null()).output().ok().filter(|o| o.status.success()).map(|o| o.stdout)
                .ok_or_else(|| format!("{test}: the candidate deleted it"))?;
            for (e, evidence) in commits.iter().enumerate() {
                // Its bundle, if git no longer has it.
                let has = || git(&m.root, &["cat-file", "-e", &format!("{evidence}^{{commit}}")]).is_ok();
                if !has() {
                    let bundles = Command::new("find").arg(m.root.join(BON).join("traces")).args(["-name", "candidate.bundle"])
                        .output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
                    for b in bundles.lines() { let _ = git(&m.root, &["bundle", "unbundle", b]); }
                    if !has() { return Err(format!("{test}: its evidence {evidence} cannot be read")); }
                }
                // test_on materializes with fresh mtimes, so the shared build sees each tree as changed.
                // A verdict, or none: a test that cannot be set up, built or run on its
                // evidence has not shown it still rejects it, so compaction fails closed.
                match verdict(m, evidence, &bytes, build, &trace.join(format!("counterexample-{k}-{e}"))) {
                    Some(false) => {}
                    Some(true) => return Err(format!("{test}: accepts its evidence {evidence}")),
                    None => return Err(format!("{test}: no verdict on its evidence {evidence}")),
                }
            }
        }
        Ok(())
    };
    match check() {
        Ok(()) => true,
        Err(reason) => { write_trace(&trace.join("counterexample"), format!("{reason}\n")); false }
    }
}

/// Each file changed from `base` to `commit`: lines added, lines removed, and
/// its path as git stores it, never quoted. A binary file counts one line each way.
fn numstat(root: &std::path::Path, base: &str, commit: &str) -> Result<Vec<(u64, u64, String)>, String> {
    let out = git(root, &["diff-tree", "-r", "-z", "--numstat", "--no-renames", base, commit])?;
    Ok(out.split('\0').filter_map(|record| {
        let f: Vec<&str> = record.splitn(3, '\t').collect();
        if f.len() < 3 { return None; }
        Some((f[0].parse().unwrap_or(1), f[1].parse().unwrap_or(1), f[2].to_string()))
    }).collect())
}

/// Lines added and removed from `base` to `commit`, as `numstat` counts them.
pub fn added_removed(root: &std::path::Path, base: &str, commit: &str) -> (u64, u64) {
    numstat(root, base, commit).unwrap_or_default().iter().fold((0, 0), |(a, r), (x, y, _)| (a + x, r + y))
}

/// The paths `commit` adds to `base`, as git stores them (NUL-delimited).
fn added(root: &std::path::Path, base: &str, commit: &str) -> Result<Vec<Path>, String> {
    let out = git(root, &["diff-tree", "-r", "-z", "--no-renames", "--name-only", "--diff-filter=A", base, commit])?;
    Ok(out.split('\0').filter(|p| !p.is_empty()).map(|p| p.chars().collect()).collect())
}

/// A test's verdict on `commit`: whether it accepts it, or None when there is no
/// verdict: the checkout or the test could not be set up, the test does not
/// build there, or its run hit the time limit.
fn verdict(m: &Manifest, commit: &str, test: &[u8], build: &std::path::Path, log: &std::path::Path) -> Option<bool> {
    verdict_in(m, commit, test, &|| Some(build.to_path_buf()), log)
}

/// verdict, with its build directory made only when a check must run: the
/// cache answers the rest without a checkout or a build.
fn verdict_in(m: &Manifest, commit: &str, test: &[u8], build: &dyn Fn() -> Option<PathBuf>, log: &std::path::Path) -> Option<bool> {
    let config = &m.config;
    let (make, run) = (&config.counterexample.build, &config.counterexample.run);
    let on = On { tree: tree_of(&m.root, commit), test: Some((config.counterexample.path.as_str(), test)), read: true };
    match answer(config, &on, make, &log.with_extension("build")) {
        Some((false, _)) => return None,
        Some((true, _)) => if let Some((ok, _)) = answer(config, &on, run, log) { return Some(ok) },
        None => {}
    }
    let dir = scratch(&format!("test.{}/{}", hash(&format!("{commit}{log:?}")), repository_name(&m.root)));
    let result = (|| {
        materialize(&m.root, commit, &dir).ok()?;
        let p = dir.join(&config.counterexample.path);
        std::fs::create_dir_all(p.parent().unwrap_or(&dir)).ok()?;
        std::fs::write(&p, test).ok()?;
        let _ = Command::new("chmod").args(["-R", "a-w,g+rX"]).arg(&dir).status();
        let build = build()?;
        let (built, _, _) = run_check(config, &on, &dir, &build, make, &log.with_extension("build"));
        if !built { return None; }
        let (ok, _, killed) = run_check(config, &on, &dir, &build, run, log);
        (!killed).then_some(ok)
    })();
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// A test's verdict on each of `tasks` (a commit, its log), at once through the
/// check pool. Tasks on one tree run one after another, so the first's result
/// answers the rest from the cache; a verdict that must run builds in its own
/// copy-on-write clone of `build` (cargo locks a build directory: one build at
/// a time), removed after. `name` names those clones.
fn verdicts(m: &Manifest, tasks: &[(String, PathBuf)], test: &[u8], build: &std::path::Path, name: &str) -> Vec<Option<bool>> {
    let config = &m.config;
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, (commit, _)) in tasks.iter().enumerate() {
        let tree = tree_of(&m.root, commit);
        match groups.iter_mut().find(|(t, _)| !t.is_empty() && *t == tree) {
            Some((_, g)) => g.push(i),
            None => groups.push((tree, vec![i])),
        }
    }
    let out: Vec<std::sync::Mutex<Option<bool>>> = tasks.iter().map(|_| std::sync::Mutex::new(None)).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..config.pools.checks.max(1).min(groups.len()) {
            scope.spawn(|| loop {
                let g = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some((_, group)) = groups.get(g) else { break };
                for &i in group {
                    let (commit, log) = &tasks[i];
                    let made: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
                    let make = || {
                        let d = clone_build(config, Some(build), &format!("{name}.verdict.{i}/build")).ok()?;
                        *made.lock().unwrap() = Some(d.clone());
                        Some(d)
                    };
                    *out[i].lock().unwrap() = verdict_in(m, commit, test, &make, log);
                    if let Some(d) = made.into_inner().unwrap() { remove_build(config, &d); }
                }
            });
        }
    });
    out.into_iter().map(|r| r.into_inner().unwrap_or(None)).collect()
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
    let on = On { tree: tree_of(&m.root, commit), test: Some((path.as_str(), test)), read: true };
    if let Some((ok, _)) = answer(config, &on, run, log) { return ok; }
    let accepts = match materialize(&m.root, commit, &dir) {
        Ok(()) => {
            let p = dir.join(path);
            let _ = std::fs::create_dir_all(p.parent().unwrap_or(&dir));
            let _ = std::fs::write(&p, test);
            let _ = Command::new("chmod").args(["-R", "a-w,g+rX"]).arg(&dir).status();
            run_check(config, &on, &dir, build, run, log).0
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

/// The lines a queue candidate appends to trunk's queue, or None when it
/// changes or removes a line trunk's queue holds.
fn appended(root: &std::path::Path, start: &str, commit: &str) -> Option<Vec<String>> {
    let old = git(root, &["show", &format!("{start}:{QUEUE}")]).unwrap_or_default();
    let new = git(root, &["show", &format!("{commit}:{QUEUE}")]).ok()?;
    let (old, new): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    if !new.starts_with(&old) { return None; }
    Some(new[old.len()..].iter().map(|l| l.to_string()).collect())
}

/// One line as the queue prompt asks for it: an id (empty; bon gives it in the
/// proposal), a tab, the intent, a tab, the transcript path, '#', the cue's
/// start time. Returns the transcript, the cue and the intent.
fn queue_line(l: &str) -> Option<(&str, Cue, &str)> {
    let [id, intent, source] = l.split('\t').collect::<Vec<_>>()[..] else { return None };
    let (transcript, cue) = source.rsplit_once('#')?;
    if !id.chars().all(|c| c.is_ascii_digit()) || intent.trim().is_empty() || transcript.is_empty() { return None; }
    Some((transcript, parse_cue(cue)?, intent.trim()))
}

/// A queue candidate is accepted when it only appends lines and each parses.
fn queue_accepted(root: &std::path::Path, start: &str, commit: &str) -> bool {
    appended(root, start, commit).is_some_and(|a| a.iter().all(|l| queue_line(l).is_some()))
}

/// A queue candidate's new lines that cite its own transcript, by cue.
fn queue_intents(root: &std::path::Path, start: &str, commit: &str, transcript: &str) -> Vec<(Cue, Intent)> {
    appended(root, start, commit).unwrap_or_default().iter().filter_map(|l| queue_line(l))
        .filter(|(t, _, _)| *t == transcript).map(|(_, cue, intent)| (cue, intent.chars().collect())).collect()
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

    #[test]
    fn slots_are_shared_and_a_dead_holders_slot_is_free() {
        let d = std::env::temp_dir().join(format!("bon-slots-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // Another process holds slot 0, then dies without letting go: its slot is free.
        std::fs::write(d.join("check.0"), "").unwrap();
        let mut holder = Command::new("/usr/bin/perl").args(["-e", "open(F, '<', $ARGV[0]) or die; flock(F, 2) or die; sleep 60"]).arg(d.join("check.0")).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let a = Slot::take_in(&d, "check", 2);
        assert!(std::fs::File::open(d.join("check.1")).unwrap().try_lock().is_err(), "slot 1 is taken while 0 is held");
        let _ = holder.kill();
        let _ = holder.wait();
        let b = Slot::take_in(&d, "check", 2);
        // A third waits until one is dropped.
        let waiter = { let d = d.clone(); std::thread::spawn(move || { let _c = Slot::take_in(&d, "check", 2); }) };
        std::thread::sleep(Duration::from_millis(1000));
        assert!(!waiter.is_finished());
        drop(a);
        waiter.join().unwrap();
        drop(b);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_pools_are_sized_from_the_host_and_overridden_by_the_environment() {
        let host: Host = toml::from_str("path = []\nrustup_home = \"\"\ncargo_home = \"\"\n[prices]\n").unwrap();
        let env = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string());
        // queue 26: width stays what bon.toml says; the pools bound what runs at once.
        // A 24 GB, 12-core laptop with 16 GB free: 6 checks of 2 threads; 64 sessions.
        assert_eq!(Pools::of(&host, &env(&[("BON_CORES", "12"), ("BON_MEMORY_GB", "16")])), Pools { generation: 64, checks: 6, threads: 2 });
        // Memory binds before cores: 7 GB free holds 4 checks.
        assert_eq!(Pools::of(&host, &env(&[("BON_CORES", "14"), ("BON_MEMORY_GB", "7")])).checks, 4);
        // Every knob by the environment; at least one of each.
        assert_eq!(Pools::of(&host, &env(&[("BON_GENERATION", "500"), ("BON_CHECKS", "3"), ("BON_CHECK_THREADS", "4")])), Pools { generation: 500, checks: 3, threads: 4 });
        assert_eq!(Pools::of(&host, &env(&[("BON_CORES", "1"), ("BON_MEMORY_GB", "0.5"), ("BON_CHECK_THREADS", "0")])).checks, 1);
        // The host file's, where the environment says nothing; its older `jobs` is the generation pool.
        let older: Host = toml::from_str("jobs = 7\nchecks = 5\ncheck_threads = 3\npath = []\nrustup_home = \"\"\ncargo_home = \"\"\n[prices]\n").unwrap();
        assert_eq!(Pools::of(&older, &env(&[])), Pools { generation: 7, checks: 5, threads: 3 });
        assert_eq!(check_pool(14, 40.0, 2), 7);
    }

    #[test]
    fn bons_cargo_caps_threads_and_holds_a_check_slot_while_it_runs() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("bon-cargo-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (bin, toolchain, slots) = (d.join("bin"), d.join("toolchain"), d.join("slots"));
        for x in [&bin, &toolchain, &slots] { std::fs::create_dir_all(x).unwrap(); }
        let text = CARGO.replace("@SLOTS@", &slots.to_string_lossy()).replace("@N@", "1").replace("@THREADS@", "3").replace("@SELF@", &bin.to_string_lossy());
        std::fs::write(bin.join("cargo"), text).unwrap();
        // The toolchain's cargo, here: it says what it was given and whether slot 0 is held.
        std::fs::write(toolchain.join("cargo"), format!("#!/bin/sh\necho \"$CARGO_BUILD_JOBS $BON_CHECK_SLOT $*\"\n/usr/bin/lockf -k -t 0 {} /usr/bin/true && echo free || echo held\n", slots.join("check.0").display())).unwrap();
        for f in [bin.join("cargo"), toolchain.join("cargo")] { std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap(); }
        let path = format!("{}:{}:/usr/bin:/bin", bin.display(), toolchain.display());
        let run = |args: &[&str], env: &[(&str, &str)]| {
            let o = Command::new(bin.join("cargo")).args(args).env_clear().env("PATH", &path).envs(env.iter().copied()).output().unwrap();
            String::from_utf8_lossy(&o.stdout).to_string()
        };
        assert_eq!(run(&["verus", "verify"], &[]), "3 held verus verify -- --num-threads 3\nheld\n");
        assert_eq!(run(&["verus", "verify", "--", "--rlimit", "9"], &[]), "3 held verus verify -- --num-threads 3 --rlimit 9\nheld\n");
        assert_eq!(run(&["verus", "verify", "--", "--num-threads", "8"], &[]), "3 held verus verify -- --num-threads 8\nheld\n");
        // Its caller holds a slot (the judge): none taken; the threads still capped.
        assert_eq!(run(&["test", "-q"], &[("BON_CHECK_SLOT", "held"), ("CARGO_BUILD_JOBS", "2")]), "2 held test -q\nfree\n");
        // Done: the slot is free again.
        assert!(std::fs::File::open(slots.join("check.0")).unwrap().try_lock().is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_check_is_cached_by_tree_command_and_test_and_never_when_killed() {
        let mut c = config();
        c.agent_process.time = 2;
        let tree = format!("test-tree-{}-{:?}", std::process::id(), Instant::now());
        let on = On { tree: tree.clone(), test: None, read: true };
        let key = verdict_key(&c, &on, "echo hi").unwrap();
        // Each part of the key changes it; no tree, no key.
        assert_ne!(Some(key.clone()), verdict_key(&c, &on, "echo ho"));
        assert_ne!(Some(key.clone()), verdict_key(&c, &On { tree: tree.clone() + "x", test: None, read: true }, "echo hi"));
        assert_ne!(Some(key.clone()), verdict_key(&c, &On { tree: tree.clone(), test: Some(("t.rs", b"a")), read: true }, "echo hi"));
        assert_ne!(verdict_key(&c, &On { tree: tree.clone(), test: Some(("t.rs", b"a")), read: true }, "echo hi"),
                   verdict_key(&c, &On { tree: tree.clone(), test: Some(("t.rs", b"b")), read: true }, "echo hi"));
        assert_eq!(verdict_key(&c, &On { tree: String::new(), test: None, read: true }, "echo hi"), None);
        let d = std::env::temp_dir().join(format!("bon-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let here = std::path::Path::new("/tmp");
        // Runs once; the second is answered, its log saying so.
        assert_eq!(run_check(&c, &on, here, here, "echo hi", &d.join("first")), (true, "hi\n".to_string(), false));
        assert_eq!(run_check(&c, &on, here, here, "echo hi", &d.join("second")), (true, "hi\n".to_string(), false));
        assert!(std::fs::read_to_string(d.join("first")).unwrap().starts_with("exit: 0"));
        assert!(std::fs::read_to_string(d.join("second")).unwrap().starts_with(&format!("cached: {key}\nexit: 0")));
        // A failure is a result; a run its time limit stopped is not.
        assert!(!run_check(&c, &on, here, here, "exit 3", &d.join("failed")).0);
        assert!(cached(&verdict_key(&c, &on, "exit 3").unwrap()).is_some_and(|(ok, _, _)| !ok));
        let (ok, _, killed) = run_check(&c, &on, here, here, "/bin/sleep 30", &d.join("killed"));
        assert!(!ok && killed);
        assert!(cached(&verdict_key(&c, &on, "/bin/sleep 30").unwrap()).is_none());
        // Not read where reading is off: it runs again.
        let off = On { tree: tree.clone(), test: None, read: false };
        let _ = run_check(&c, &off, here, here, "echo hi", &d.join("third"));
        assert!(std::fs::read_to_string(d.join("third")).unwrap().starts_with("exit: 0"));
        for k in ["echo hi", "exit 3"] { let _ = std::fs::remove_file(cache_dir().unwrap().join(verdict_key(&c, &on, k).unwrap())); }
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(PathBuf::from(WORKING_DIRECTORIES).join(format!("{}.bin", std::process::id())));
    }

    #[test]
    fn a_materialized_commit_is_newer_than_any_build_before_it() {
        let d = std::env::temp_dir().join(format!("bon-mtime-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        git(&d, &["init", "-q"]).unwrap();
        std::fs::write(d.join("a.rs"), "fn main() {}\n").unwrap();
        git(&d, &["add", "."]).unwrap();
        let out = Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "old"])
            .env("GIT_AUTHOR_DATE", "2001-01-01T00:00:00Z").env("GIT_COMMITTER_DATE", "2001-01-01T00:00:00Z").current_dir(&d).status().unwrap();
        assert!(out.success());
        let before = std::time::SystemTime::now() - Duration::from_secs(5);
        let dir = d.join("out");
        let _ = materialize(&d, "HEAD", &dir);
        let mtime = std::fs::metadata(dir.join("a.rs")).unwrap().modified().unwrap();
        assert!(mtime > before, "a file of a 2001 commit gets the time it was extracted");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_check_directory_holds_exactly_the_commits_tree() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("bon-tree-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("tests")).unwrap();
        std::fs::create_dir_all(d.join("src")).unwrap();
        git(&d, &["init", "-q"]).unwrap();
        // The candidate's own attributes would leave its tests out and rewrite its sources.
        std::fs::write(d.join(".gitattributes"), "tests/** export-ignore\n*.rs export-subst ident\n*.txt eol=crlf\n").unwrap();
        std::fs::write(d.join("tests/trunk.rs"), "#[test] fn t() {} // $Format:%H$\n").unwrap();
        std::fs::write(d.join("src/lib.rs"), "// $Format:%H$ $Id$\n").unwrap();
        std::fs::write(d.join("notes.txt"), "a\nb\n").unwrap();
        std::fs::write(d.join("run.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(d.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("src/lib.rs", d.join("link")).unwrap();
        git(&d, &["add", "."]).unwrap();
        git(&d, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c"]).unwrap();
        let dir = d.join("out");
        // chgrp bon fails on a host without group bon; the files are written first.
        let _ = materialize(&d, "HEAD", &dir);
        let listed = git(&d, &["ls-tree", "-r", "HEAD"]).unwrap();
        assert_eq!(listed.lines().count(), 6);
        for l in listed.lines() {
            let (head, path) = l.split_once('\t').unwrap();
            let f: Vec<&str> = head.split(' ').collect();
            let blob = Command::new("git").args(["cat-file", "blob", f[2]]).current_dir(&d).output().unwrap().stdout;
            let p = dir.join(path);
            let bytes = if f[0] == "120000" { std::fs::read_link(&p).unwrap().to_string_lossy().as_bytes().to_vec() } else { std::fs::read(&p).unwrap() };
            assert_eq!(bytes, blob, "{path}");
            if f[0] == "100755" { assert!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o111 != 0); }
        }
        // Nothing beyond the tree.
        let found = Command::new("find").args([".", "-type", "f", "-o", "-type", "l"]).current_dir(&dir).output().unwrap().stdout;
        assert_eq!(String::from_utf8_lossy(&found).lines().count(), 6);
        // A candidate's tests over other code: only the paths asked for.
        let only = d.join("only");
        std::fs::create_dir_all(&only).unwrap();
        extract(&d, "HEAD", &["tests/"], &only).unwrap();
        assert!(only.join("tests/trunk.rs").exists() && !only.join("src").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    use super::*;

    #[test]
    fn changed_paths_are_read_as_git_stores_them() {
        let d = std::env::temp_dir().join(format!("bon-numstat-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("tests")).unwrap();
        let g = |args: &[&str]| git(&d, &[&["-c", "user.name=t", "-c", "user.email=t@t"], args].concat()).unwrap();
        g(&["init", "-q", "-b", "main"]);
        g(&["commit", "-q", "--allow-empty", "-m", "base"]);
        let base = g(&["rev-parse", "HEAD"]);
        std::fs::write(d.join("tests/é.rs"), "a\nb\n").unwrap();
        std::fs::write(d.join("a\tb.rs"), "c\n").unwrap();
        std::fs::write(d.join("blob"), [0u8, 1, 2]).unwrap();
        g(&["add", "-A"]);
        g(&["commit", "-q", "-m", "files"]);
        let head = g(&["rev-parse", "HEAD"]);
        let files = numstat(&d, &base, &head).unwrap();
        let paths: Vec<&str> = files.iter().map(|(_, _, p)| p.as_str()).collect();
        assert_eq!(paths, ["a\tb.rs", "blob", "tests/é.rs"]);
        // A binary file counts one line each way, here and in added_removed.
        assert_eq!(files.iter().map(|(a, r, _)| (*a, *r)).collect::<Vec<_>>(), [(1, 0), (1, 1), (2, 0)]);
        assert_eq!(added_removed(&d, &base, &head), (4, 1));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cues() {
        assert_eq!(parse_cue("00:01:02.345"), Some(62_345));
        assert_eq!(parse_cue("01:00:00.000"), Some(3_600_000));
        assert_eq!(parse_cue("nope"), None);
    }

    /// A repository whose queue is `old`, then `new`: the two commits.
    fn queues(name: &str, old: &str, new: &str) -> (PathBuf, String, String) {
        let d = std::env::temp_dir().join(format!("bon-queue-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(BON)).unwrap();
        git(&d, &["init", "-q"]).unwrap();
        let mut commits = Vec::new();
        for q in [old, new] {
            std::fs::write(d.join(QUEUE), q).unwrap();
            git(&d, &["add", "."]).unwrap();
            git(&d, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "q"]).unwrap();
            commits.push(git(&d, &["rev-parse", "HEAD"]).unwrap());
        }
        (d, commits[0].clone(), commits[1].clone())
    }

    #[test]
    fn an_intent_counts_only_when_it_cites_its_own_transcript() {
        let (d, a, b) = queues("cites", "id\tintent\n1\told\n",
            "id\tintent\n1\told\n\tmine\tt/a.vtt#00:00:01.000\n\tsomeone else's\tt/b.vtt#00:00:02.000\n");
        assert!(queue_accepted(&d, &a, &b));
        let i: Vec<(Cue, String)> = queue_intents(&d, &a, &b, "t/a.vtt").into_iter().map(|(c, i)| (c, i.iter().collect())).collect();
        assert_eq!(i, vec![(1000, "mine".to_string())]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_queue_candidate_is_accepted_only_when_its_lines_parse() {
        let old = "id\tintent\n1\told\n";
        for (new, ok) in [
            ("id\tintent\n1\told\n\tnew\tt/a.vtt#00:00:01.000\n", true),
            ("id\tintent\n1\told\n", true),
            ("id\tintent\n1\told\nnew without fields\n", false),
            ("id\tintent\n1\told\n\tnew\tt/a.vtt#soon\n", false),
            ("id\tintent\n1\told\n\t\tt/a.vtt#00:00:01.000\n", false),
            ("id\tintent\n1\told, reworded\n\tnew\tt/a.vtt#00:00:01.000\n", false),
            ("id\tintent\n\tnew\tt/a.vtt#00:00:01.000\n", false),
        ] {
            let (d, a, b) = queues("parse", old, new);
            assert_eq!(queue_accepted(&d, &a, &b), ok, "{new:?}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn the_build_configuration_a_check_reads_is_protected() {
        let m = Manifest { config: config(), root: PathBuf::from("/nonexistent") };
        let c: Vec<String> = checks(&m).iter().map(|p| p.iter().collect()).collect();
        assert_eq!(c, vec!["checks/", ".cargo/", "build.rs"]);
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
            rustup_home = "/opt/bon/rustup"
            cargo_home = "/opt/bon/cargo-home"
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
                out: vec![], intents: vec![], accepts: vec![(-1, false)], accepts_foils: vec![], measured: false, added: vec![], rejects_counterexamples: false, rank: 0, diff: 1,
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
        assert_eq!(rev(&work, "refs/remotes/origin/main"), test, "the remote's ref follows");
        assert_eq!(rev(&work, "HEAD"), base, "the engineer's branch is left alone");
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
    fn evidence_is_filed_under_the_search_it_was_tested_in() {
        // queue 47: select, foil, counterexample: the evidence is the tested search's candidate.
        fn text<T: FromIterator<char>>(s: &str) -> T { s.chars().collect() }
        let (_remote, work, base, test) = landing_fixture("evidence");
        std::fs::write(work.join("b"), "b").unwrap();
        git(&work, &["add", "b"]).unwrap();
        git(&work, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "wrong code"]).unwrap();
        let wrong = git(&work, &["rev-parse", "HEAD"]).unwrap();
        git(&work, &["reset", "-q", "--hard", &base]).unwrap();
        let candidate = |commit: &str, changed: Vec<Path>, accepts: Vec<(i64, bool)>| Candidate {
            commit: text(commit), base: text(&base), accepted: true, proved: true, changed, out: vec![], intents: vec![],
            accepts, accepts_foils: vec![], measured: false, added: vec![], rejects_counterexamples: false, rank: 0, diff: 1,
        };
        let search = |kind: Kind, c: Candidate| Search {
            kind, base: text(&base), n: 1, checks: vec![], tests: vec![text("tests/")], trusted: vec![], limit: 1, results: vec![Some(c)],
        };
        let tested = search(Kind::Code { goal: text(&base) }, candidate(&wrong, vec![], vec![]));
        let x = search(Kind::Counterexample { goal: Some(crate::gates::AgentProcess { search: 0, index: 0 }) },
                       candidate(&test, vec![text("tests/c_1.sh")], vec![(0, false)]));
        // The foil and counterexample searches ran after it.
        RUNS.store(3, std::sync::atomic::Ordering::SeqCst);
        let m = Manifest { config: config(), root: work.clone() };
        land(&m, &x, 0, Some(&tested)).unwrap();
        assert!(trace_dir(&work).join("0").join("0").join("candidate.bundle").is_file(), "under search 0, the tested one");
        assert!(!trace_dir(&work).join("1").exists(), "never under the foil search");
        let record = std::fs::read_to_string(work.join(BON).join("traces").join("counterexamples.jsonl")).unwrap();
        assert_eq!(record.trim(), serde_json::json!({ "test": "tests/c_1.sh", "evidence": [wrong] }).to_string());
        let _ = std::fs::remove_dir_all(work.parent().unwrap());
    }

    #[test]
    fn each_run_has_its_own_trace_even_on_a_reused_pid() {
        // queue 47.
        let d = std::env::temp_dir().join(format!("bon-claim-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(claim(&d, 4242, 1000), "4242", "a pid's first run is <pid>");
        assert_eq!(claim(&d, 4242, 1000), "4242.1000", "a reused pid is <pid>.<start>, never the earlier run's");
        assert_eq!(claim(&d, 4242, 1000), "4242.1001");
        assert_eq!((trace_process("4242"), trace_process("4242.1000"), trace_process("proposals"), trace_process("1.x")),
                   (Some((4242, 0)), Some((4242, 1000)), None, None));
        // Of a live pid, only its latest run is running: the earlier one ended.
        let mut live = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = live.id();
        std::fs::create_dir_all(d.join(pid.to_string())).unwrap();
        assert!(trace_running(&d, &pid.to_string()));
        std::fs::create_dir_all(d.join(format!("{pid}.5"))).unwrap();
        assert!(!trace_running(&d, &pid.to_string()) && trace_running(&d, &format!("{pid}.5")));
        let _ = live.kill();
        let _ = live.wait();
        assert!(!trace_running(&d, &format!("{pid}.5")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_failed_trace_write_is_reported_and_the_search_goes_on() {
        // queue 47: a trace under a file cannot be written; nothing panics.
        let d = std::env::temp_dir().join(format!("bon-traced-test-{}", std::process::id()));
        std::fs::write(&d, "a file").unwrap();
        write_trace(&d.join("facts.json"), "{}");
        append_line(&d.join("transitions"), "grant");
        assert!(std::fs::metadata(&d).unwrap().is_file());
        let _ = std::fs::remove_file(&d);
    }

    #[test]
    fn a_time_limit_stops_everything_the_command_started() {
        // queue 47: a grandchild holding stdout dies with its command.
        let log = std::env::temp_dir().join(format!("bon-supervise-test-{}", std::process::id()));
        let c = as_agent(&config(), std::path::Path::new("/tmp"), &[], &["/bin/sh".into(), "-c".into(), "/bin/sleep 60 & wait".into()]);
        let start = Instant::now();
        let (ok, _, killed) = supervise(c, None, Duration::from_secs(1), &log);
        assert!(!ok && killed, "{}", std::fs::read_to_string(&log).unwrap_or_default());
        assert!(start.elapsed() < Duration::from_secs(6), "{:?}", start.elapsed());
        let _ = std::fs::remove_file(&log);
    }

    /// Trunk with a landed test (accepts only good code) and its evidence (bad
    /// code), and a commit on trunk made by `change`: (manifest, trunk, commit).
    fn compaction_fixture(name: &str, record: bool, change: &dyn Fn(&std::path::Path)) -> (Manifest, String, String) {
        let d = std::env::temp_dir().join(format!("bon-compaction-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let commit = |message: &str| -> String {
            git(&d, &["add", "-A"]).unwrap();
            git(&d, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", message]).unwrap();
            git(&d, &["rev-parse", "HEAD"]).unwrap()
        };
        git(&d, &["init", "-q", "-b", "main"]).unwrap();
        std::fs::write(d.join("code"), "bad\n").unwrap();
        let bad = commit("bad code");
        std::fs::write(d.join("code"), "good\n").unwrap();
        std::fs::create_dir_all(d.join("tests")).unwrap();
        std::fs::write(d.join("tests/c_1.sh"), "grep -q good code\n").unwrap();
        let trunk = commit("good code and its test");
        change(&d);
        let candidate = commit("compaction");
        if record {
            std::fs::create_dir_all(d.join(BON).join("traces")).unwrap();
            std::fs::write(d.join(BON).join("traces").join("counterexamples.jsonl"),
                           format!("{}\n", serde_json::json!({ "test": "tests/c_1.sh", "evidence": [bad] }))).unwrap();
        }
        let mut config = config();
        config.counterexample.run = "/bin/sh tests/c.sh".into();
        (Manifest { config, root: d }, trunk, candidate)
    }

    #[test]
    fn compaction_keeps_rejecting_each_landed_test_s_evidence() {
        // queue 41: each landed test, alone, still rejects its evidence.
        let (m, trunk, candidate) = compaction_fixture("keeps", true, &|_| {});
        let trace = m.root.join("trace");
        assert!(rejects_every_counterexample(&m, &candidate, &trunk, std::path::Path::new("/tmp"), &trace),
                "{}", std::fs::read_to_string(trace.join("counterexample")).unwrap_or_default());
        let _ = std::fs::remove_dir_all(&m.root);
    }

    #[test]
    fn compaction_that_deletes_or_weakens_a_landed_test_fails() {
        // queue 41.
        let (m, trunk, deleted) = compaction_fixture("deletes", true, &|d| std::fs::remove_file(d.join("tests/c_1.sh")).unwrap());
        let trace = m.root.join("trace");
        assert!(!rejects_every_counterexample(&m, &deleted, &trunk, std::path::Path::new("/tmp"), &trace));
        assert!(std::fs::read_to_string(trace.join("counterexample")).unwrap().contains("deleted"));
        let _ = std::fs::remove_dir_all(&m.root);
        let (m, trunk, weakened) = compaction_fixture("weakens", true, &|d| std::fs::write(d.join("tests/c_1.sh"), "exit 0\n").unwrap());
        let trace = m.root.join("trace");
        assert!(!rejects_every_counterexample(&m, &weakened, &trunk, std::path::Path::new("/tmp"), &trace));
        assert!(std::fs::read_to_string(trace.join("counterexample")).unwrap().contains("accepts its evidence"));
        let _ = std::fs::remove_dir_all(&m.root);
    }

    #[test]
    fn a_landed_test_with_no_evidence_on_record_fails_closed() {
        // queue 41: a fresh clone has no record; that never passes.
        let (m, trunk, candidate) = compaction_fixture("unrecorded", false, &|_| {});
        let trace = m.root.join("trace");
        assert!(!rejects_every_counterexample(&m, &candidate, &trunk, std::path::Path::new("/tmp"), &trace));
        assert!(std::fs::read_to_string(trace.join("counterexample")).unwrap().contains("no evidence on record"));
        let _ = std::fs::remove_dir_all(&m.root);
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
            intents: vec![], accepts: vec![], accepts_foils: vec![], measured: false, added: vec![], rejects_counterexamples: false, rank: 0, diff: 1,
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
    fn a_test_on_candidates_that_disagree_is_told_they_behave_differently() {
        fn text<T: FromIterator<char>>(s: &str) -> T { s.chars().collect() }
        let candidate = |commit: &str, out: u64| Candidate {
            commit: text(commit), base: text("head"), accepted: true, proved: true, changed: vec![], out: vec![Hash(out)],
            intents: vec![], accepts: vec![], accepts_foils: vec![], measured: true, added: vec![], rejects_counterexamples: false, rank: 0, diff: 1,
        };
        let tested = |second: u64| Search {
            kind: Kind::Code { goal: text("head") }, base: text("head"), n: 2, checks: vec![], tests: vec![], trusted: vec![], limit: 1,
            results: vec![Some(candidate("first", 7)), Some(candidate("second", second))],
        };
        // No git here: the spec's diff is empty, so the aim is what the tested search shows.
        let m = Manifest { config: config(), root: PathBuf::from("/nonexistent/bon-aim") };
        let kind = Kind::Counterexample { goal: Some(crate::gates::AgentProcess { search: 0, index: 0 }) };
        assert!(aim(&m, &kind, Some(&tested(8)), "head").contains("They behave differently"));
        assert_eq!(aim(&m, &kind, Some(&tested(7)), "head"), "", "a selection's test is aimed by the spec alone");
        // Its test builds on the verified candidate the goal names.
        assert_eq!(tested_tree(&kind, Some(&tested(8)), "head"), "first");
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
    fn a_counterexample_writer_sees_the_spec_and_the_checks_never_the_code() {
        // queue 24: prune keeps only what is named; everything else is gone.
        let d = std::env::temp_dir().join(format!("bon-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for f in ["src/spec.rs", "src/exec.rs", "tests/c_1.rs", "Cargo.toml", ".bon/bon.toml", "examples/go/main.go"] {
            let p = d.join(f); std::fs::create_dir_all(p.parent().unwrap()).unwrap(); std::fs::write(p, "x").unwrap();
        }
        prune(&d, &["src/spec.rs".into(), "tests/".into(), "Cargo.toml".into(), ".bon/".into()]);
        let left: Vec<bool> = ["src/spec.rs", "src/exec.rs", "tests/c_1.rs", "Cargo.toml", ".bon/bon.toml", "examples/go/main.go"].iter().map(|f| d.join(f).exists()).collect();
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
    fn a_stub_harness_runs_its_command_and_costs_nothing() {
        let mut c = config();
        c.harness[0] = toml::from_str(r#"name = "stub"
            model = "stub"
            command = ["/bin/sh", ".bon/stub.sh"]
            n = [3]"#).unwrap();
        let h = c.harness[0].clone();
        assert_eq!(harness_argv(&h, &c, std::path::Path::new("/tmp"), &[]), ["/bin/sh", ".bon/stub.sh"]);
        // codex sandboxes to its working directory: the build and the slots are added.
        let codex = harness_argv(&c.counterexample.harness[0], &c, std::path::Path::new("/w"), &[PathBuf::from("/b")]);
        assert_eq!(codex[codex.len() - 3..], ["--add-dir", "/b", "-"]);
        assert_eq!(generation(&h, &c, "anything at all").unwrap(), (0, Some(0), HashMap::new()));
        // A built-in harness still needs its token counts.
        assert!(generation(&c.counterexample.harness[0], &c, "anything at all").is_err());
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(toml::from_str::<Config>("limit = 1.0\nbogus = 2").is_err());
    }
}
