//! Trusted code. Every function the verified code calls from here is
//! `#[verifier::external_body]`: Verus does not check it. The TCB is this file,
//! the entry points (main.rs, view.rs), plus what they run: git, sudo, tar, chmod, the programs the host file's roles name (`claude`, `codex`),
//! perl (bon's cargo, `CARGO`) and the checks the manifest declares.
//!
//! It observes and reports facts; it decides nothing. Every decision is a gate.
//!
//! Everything bon keeps in a repository is under `.bon/`: the manifest
//! (bon.toml), the queue (queue.tsv) and the account, tracked; the traces, not.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use vstd::prelude::*;

use crate::gates::{Candidate, Commit, Cue, Hash, Intent, Kind, Observation, Path, Permission, Search};
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
    /// Each search kind's role and width list.
    pub searches: Searches,
    pub counterexample: Counterexample,
    /// The account `bon account` keeps; its `trusted` list is also every search's trusted code.
    #[serde(default)]
    pub account: Option<toml::Value>,
    /// What `bon types` emits for programs: read by it alone.
    #[serde(default)]
    pub types: Option<toml::Value>,
    /// Prices by canonical model, from the host file.
    #[serde(skip)]
    pub prices: HashMap<String, Price>,
    /// How many agent processes and how many checks run at once, from the host file.
    #[serde(skip)]
    pub pools: Pools,
    /// RUSTUP_HOME and CARGO_HOME for agent processes and checks, from the host file.
    #[serde(skip)]
    pub toolchain: Vec<(String, String)>,
    /// What each role runs, from the host file.
    #[serde(skip)]
    pub roles: HashMap<String, Role>,
    /// The Messages API, from the host file: for a role whose client is `api`.
    #[serde(skip)]
    pub api: Option<Api>,
    /// The host file these facts were read from: every program is told it (BON_HOST).
    #[serde(skip)]
    pub host: PathBuf,
    /// The repository: where a tree's lockfile is read (`dependencies`).
    #[serde(skip)]
    pub root: PathBuf,
}

/// Keys bon no longer reads, each with what says it now: a manifest or host
/// file that still has one is refused with that, not a bare unknown field.
const RENAMED: [(&str, &str); 10] = [
    ("harness", "[searches]: each search kind's role and width list n; the host file's [roles] say what each role runs (queue 53)"),
    ("counterexample.harness", "[searches] counterexample and foil: each a role and its width list n (queue 53)"),
    ("programs", "[types] (queue 52)"),
    ("generation", "agent_processes (queue 54)"),
    ("jobs", "agent_processes (queue 54)"),
    ("checks", "check_processes (queue 54)"),
    ("cores", "nothing: set check_processes (queue 54)"),
    ("memory_gb", "nothing: set check_processes (queue 54)"),
    ("verdicts", "user: the verdict cache is <user>/.bon/verdicts, in the user layer's state (queue 56)"),
    ("cleanup", "nothing: a bon process removes its own working directories, and those of a bon process the process list says ended (queue 58)"),
];

/// The first key of `text` that RENAMED names, as an error naming what replaced it.
/// `host`: the host file's top level, where `checks` is the old pool's name
/// (in the manifest, `[checks]` is the checks' table).
fn renamed(text: &str, host: bool) -> Result<(), String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    for (old, now) in RENAMED {
        let manifest_key = matches!(old, "harness" | "counterexample.harness" | "programs");
        if manifest_key == host { continue; }
        let at = old.split('.').try_fold(&v, |t, part| t.get(part));
        if at.is_some() { return Err(format!("`{old}` is gone; it is {now}")); }
    }
    Ok(())
}

/// The files and directories cargo, rustup and git discover by walking the
/// working directory's ancestors, each of which decides what a check compiles
/// or which toolchain runs: cargo's Cargo.toml (a parent `[workspace]` claims
/// a checkout, a `[patch]` swaps a dependency's source, a `[profile]` changes
/// its build) and `.cargo` (its config.toml); rustup's `rust-toolchain` and
/// `rust-toolchain.toml` (which pick the cargo and rustc that run, though
/// `RUSTUP_TOOLCHAIN` in the checks' environment overrides them); git's
/// `.git` (hooks, config). A tool reads the nearest in any ancestor, so a
/// world-writable ancestor (/tmp is 1777) is a writable judge. The names are
/// the discovery rules of those tools, which have no API to enumerate.
const ANCESTOR_FILES: [&str; 5] = ["Cargo.toml", ".cargo", "rust-toolchain", "rust-toolchain.toml", ".git"];

/// The ancestors of the working directories, from WORKING_DIRECTORIES up to
/// the filesystem root, canonicalized (so /tmp is read as /private/tmp).
fn working_ancestors() -> Vec<PathBuf> {
    let start = std::fs::canonicalize(WORKING_DIRECTORIES).unwrap_or_else(|_| PathBuf::from(WORKING_DIRECTORIES));
    let mut out = Vec::new();
    let mut p: Option<&std::path::Path> = Some(start.as_path());
    while let Some(d) = p { out.push(d.to_path_buf()); p = d.parent(); }
    out
}

/// Claim the `.cargo` directory in every working ancestor as engineer's own
/// (an empty directory holds no config.toml), so no agent process can create
/// one there; once per bon process.
fn claim_ancestor_cargo() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| for a in working_ancestors() { let _ = std::fs::create_dir(a.join(".cargo")); });
}

/// A signature of the ancestor files a check would read (`ANCESTOR_FILES`),
/// and a refusal if any is one bon did not make that could decide a check:
/// owned by neither root nor engineer (`me`), or writable by others. bon
/// occupies each `.cargo` (an empty directory), but cannot occupy a Cargo.toml
/// or a toolchain file without breaking a build, so it refuses when one is
/// present. The signature (each file's inode and mtime) lets a check compare
/// the state before and after it runs: a file that appears or changes mid-run
/// voids its verdict. What stays open is a file created in a world-writable
/// ancestor between one check's signature and the next (the README's "not
/// isolated"); it closes when the working directories move off /tmp.
fn ancestor_guard(me: u32) -> Result<String, String> {
    // Confined (a candidate's checks, which run bon's own tests as a slot's
    // user): the engineer bon process already guarded the ancestors; a slot's
    // user is not engineer, so it would read engineer's own .cargo as foreign.
    if confined() { return Ok(String::new()); }
    claim_ancestor_cargo();
    ancestor_guard_over(&working_ancestors(), me)
}

/// The guard over a given ancestor list (`ancestor_guard`, without the claim).
fn ancestor_guard_over(dirs: &[PathBuf], me: u32) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let mut sig = String::new();
    for a in dirs {
        for name in ANCESTOR_FILES {
            let p = a.join(name);
            let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
            if (m.uid() != me && m.uid() != 0) || m.mode() & 0o022 != 0 {
                return Err(format!("{}: a {name} not engineer's or root's, or writable by others; a check would read it; remove it, then run again", p.display()));
            }
            sig.push_str(&format!("{}\0{}\0{}\0{}\0", p.display(), m.ino(), m.mtime(), m.mtime_nsec()));
        }
    }
    Ok(sig)
}

/// This process's own uid, by `id -u`: engineer, whom bon runs as.
fn my_uid() -> u32 {
    static UID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *UID.get_or_init(|| Command::new("id").arg("-u").output().ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok()).unwrap_or(u32::MAX))
}

/// The uid the guard reads as "mine": the repository's owner (engineer), from
/// the repository root; this process's own uid when the root cannot be read.
fn guard_uid(root: &std::path::Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(root).map(|m| m.uid()).unwrap_or_else(|_| my_uid())
}

/// The toolchain rustup's home has as its default, resolved once per home by
/// `rustup default` as engineer in the home itself, whose ancestors are root's:
/// no working-directory toolchain file influences it, so it is the name the
/// checks must run under (`RUSTUP_TOOLCHAIN`), not one a candidate's file picks.
/// None if rustup cannot say (then the toolchain files still decide, and the
/// ancestor guard and BUILD are the defense).
fn default_toolchain(rustup_home: &str, path: &str) -> Option<String> {
    static MEMO: std::sync::Mutex<Option<HashMap<String, String>>> = std::sync::Mutex::new(None);
    {
        let memo = MEMO.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tc) = memo.as_ref().and_then(|m| m.get(rustup_home)) { return Some(tc.clone()); }
    }
    let out = Command::new("rustup").arg("default").env_clear()
        .env("RUSTUP_HOME", rustup_home).env("PATH", path)
        .current_dir(rustup_home).stdin(Stdio::null()).output().ok()?;
    if !out.status.success() { return None; }
    let tc = String::from_utf8_lossy(&out.stdout).split_whitespace().next().filter(|s| !s.is_empty())?.to_string();
    MEMO.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(rustup_home.to_string(), tc.clone());
    Some(tc)
}

/// What is true of this machine rather than of a repository, written by
/// `bon setup` and owned by root: where agent's tools live, and model prices.
pub const HOST: &str = "/etc/bon/host.toml";

/// The host file bon reads: HOST, or the one BON_HOST names, which describes
/// this host otherwise (a benchmark's: its own verdict cache, another
/// machine's sizing). One file either way; nothing else stands beside it. A
/// named one must be a file only its owner can write, its owner root or the
/// user bon runs as, so no agent process can change it.
pub fn host_file() -> Result<PathBuf, String> { checked_host(std::env::var("BON_HOST").ok()) }

fn checked_host(named: Option<String>) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    let Some(p) = named else { return Ok(PathBuf::from(HOST)) };
    let m = std::fs::metadata(&p).map_err(|e| format!("BON_HOST {p}: {e}"))?;
    let me = Command::new("id").arg("-u").output().ok().and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok());
    if !m.is_file() || m.mode() & 0o022 != 0 || !(m.uid() == 0 || Some(m.uid()) == me) {
        return Err(format!("BON_HOST {p}: must be a file only its owner (root, or you) can write"));
    }
    Ok(PathBuf::from(p))
}

/// The host file's user layer root and check slots, for the code that has no manifest at hand.
static USER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
static SLOTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    path: Vec<String>,
    prices: HashMap<String, Price>,
    /// How many agent processes run at once, host-wide; width stays what
    /// bon.toml says. Default 64 (an agent process mostly waits on its model).
    #[serde(default)]
    agent_processes: Option<usize>,
    /// How many checks run at once, host-wide: the judge's and every cargo an
    /// agent process runs. Default: free memory / 1.5 GB, never more than
    /// 2 * cores / check_threads (see `check_pool`).
    #[serde(default)]
    check_processes: Option<usize>,
    /// Threads one check may use (CARGO_BUILD_JOBS, Verus --num-threads). Default 2.
    #[serde(default)]
    check_threads: Option<usize>,
    /// The user layer's root, between the host and its repositories: bon's
    /// state that outlives a bon process lives in its `.bon` (`state_dir`),
    /// engineer's alone. Required.
    user: String,
    /// The toolchain checks judge with, where no agent process can write it
    /// (/opt/bon, root's all the way up): rustup's home, and a cargo home whose
    /// root is root's, only its caches agent's. Required.
    rustup_home: String,
    cargo_home: String,
    /// What each role a manifest names runs.
    #[serde(default)]
    roles: HashMap<String, Role>,
    /// The Messages API, for a role whose client is `api`.
    #[serde(default)]
    api: Option<Api>,
    /// Where a transcript dropped in the user layer's folder goes: a pattern
    /// of its meeting title, and the repository (its root, absolute or under
    /// the user layer's root). A title matches a pattern that it contains,
    /// ignoring case.
    #[serde(default)]
    routes: std::collections::BTreeMap<String, String>,
}

/// The user layer's root the host file names (`user`), and its routes: each
/// title pattern with its repository's root, a relative one under the user
/// layer's root. None without a host file bon reads.
pub fn user_layer() -> Option<(PathBuf, Vec<(String, PathBuf)>)> {
    let host = read_host(&host_file().ok()?).ok()?;
    let root = PathBuf::from(&host.user);
    let routes = host.routes.iter().map(|(p, r)| (p.clone(), root.join(r))).collect();
    Some((root, routes))
}

/// The host's two pools as the host file sizes them (`Pools::of`); None
/// without a host file bon reads.
pub fn host_pools() -> Option<Pools> { read_host(&host_file().ok()?).ok().map(|h| Pools::of(&h)) }

/// How many slots of each pool are held now, host-wide: each slot file below
/// the pool's size that some process holds locked. Asked by taking each lock
/// without waiting and freeing it at once; a slot file that does not exist was
/// never taken. Read-only: nothing is made.
pub fn pools_held(pools: &Pools) -> (usize, usize) {
    let held = |dir: PathBuf, name: &str, n: usize| (0..n).filter(|k| {
        std::fs::File::open(dir.join(format!("{name}.{k}"))).is_ok_and(|f| match f.try_lock() {
            Ok(()) => { let _ = f.unlock(); false }
            Err(_) => true,
        })
    }).count();
    (held(base(), "agent_process", pools.agent_processes), held(base().join("checks"), "check", pools.check_processes))
}

/// Memory, in GB: this machine's physical memory, and what is free for checks
/// now (`free_memory_gb`).
pub fn memory_gb() -> (f64, f64) {
    let total = Command::new("sysctl").args(["-n", "hw.memsize"]).output().ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<f64>().ok()).unwrap_or(0.0) / 1e9;
    (total, free_memory_gb())
}

/// What a role runs: its program, the client through which it reaches a
/// model, the model, and how much of the repository a one-shot program shows
/// it. A role with no client and no model reaches none: a stub, which costs
/// nothing and needs no price or login.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Role {
    /// The argv, run as agent in the working directory with the prompt on its
    /// stdin; bon appends `--model <model>`.
    pub program: Vec<String>,
    /// How the program reaches its model: `claude` or `codex` (that CLI,
    /// logged in as agent), or `api` (the Messages API, the host's [api]).
    #[serde(default)]
    pub client: Option<String>,
    /// The canonical model id (claude-opus-5-5, gpt-6.1-sol), never an alias:
    /// passed to the program, it keys the price table and the trace.
    #[serde(default)]
    pub model: Option<String>,
    /// The largest prompt, in tokens, the program may send: a one-shot
    /// program (bon-sample) assembles no more context than that. Given to the
    /// program as BON_CONTEXT.
    #[serde(default)]
    pub context: Option<u64>,
}

/// The clients a role may name.
const CLIENTS: [&str; 3] = ["claude", "codex", "api"];

/// The Messages API: where it is, and the file holding its key, which agent reads.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Api {
    pub address: String,
    pub key_file: String,
}

/// Whether `text` is a host file bon reads (`bon setup`'s template is one).
pub fn host_shape(text: &str) -> Result<(), String> {
    renamed(text, true)?;
    toml::from_str::<Host>(text).map(|_| ()).map_err(|e| e.to_string())
}

/// The host file at `file`, read: refused with what replaced a key it still has.
fn read_host(file: &std::path::Path) -> Result<Host, String> {
    let shown = file.display().to_string();
    let text = std::fs::read_to_string(file).map_err(|_| format!("no {shown}; run bon setup"))?;
    renamed(&text, true).map_err(|e| format!("{shown}: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("{shown}: {e}; run bon setup"))
}

/// A manifest's settings with the host file's facts: its pools, PATH, prices,
/// toolchain, roles and API, and the user layer's root. Each role the
/// manifest names must be the host's, and each model priced.
fn with_host(mut config: Config, host: Host, file: &std::path::Path) -> Result<Config, String> {
    let shown = file.display().to_string();
    config.pools = Pools::of(&host);
    if !std::path::Path::new(&host.user).is_absolute() { return Err(format!("{shown}: user is the user layer's root, an absolute path")); }
    let _ = USER.set(PathBuf::from(&host.user));
    SLOTS.store(config.pools.check_processes, std::sync::atomic::Ordering::SeqCst);
    config.path = host.path;
    config.prices = host.prices;
    // The toolchain the checks run under: rustup's home and cargo home, and the
    // toolchain name that home has as its default, so no toolchain file in a
    // working ancestor (/tmp is anyone's) picks the cargo and rustc that judge.
    // It is part of what the verdict key covers (`toolchain_identity`): it is
    // what the checks see.
    let resolved = default_toolchain(&host.rustup_home, &config.path.join(":"));
    config.toolchain = vec![("RUSTUP_HOME".to_string(), host.rustup_home), ("CARGO_HOME".to_string(), host.cargo_home)];
    if let Some(tc) = resolved { config.toolchain.push(("RUSTUP_TOOLCHAIN".to_string(), tc)); }
    config.roles = host.roles;
    config.api = host.api;
    config.host = file.to_path_buf();
    for (kind, e) in config.searches.all() {
        let Some(r) = config.roles.get(&e.role) else {
            return Err(format!("{shown}: no role {}; bon.toml's [searches] {kind} names it", e.role));
        };
        match (&r.client, &r.model) {
            (None, None) => {}
            (Some(c), Some(model)) => {
                if !CLIENTS.contains(&c.as_str()) { return Err(format!("{shown}: role {}: client {c}: one of {}", e.role, CLIENTS.join(", "))); }
                if c == "api" && config.api.is_none() { return Err(format!("{shown}: role {} reaches the API: [api] needs address and key_file", e.role)); }
                if !config.prices.contains_key(model) { return Err(format!("{shown}: no price for {model}; a role names canonical model ids")); }
            }
            _ => return Err(format!("{shown}: role {}: a client and a model, or neither (a stub)", e.role)),
        }
        if r.program.is_empty() { return Err(format!("{shown}: role {}: program is an argv", e.role)); }
    }
    Ok(config)
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
    /// The expensive checks: each exits 0 on the selected candidate alone,
    /// run once, from a clean build, beside the re-check of what decided its
    /// push; a candidate is accepted and proved without them.
    #[serde(default)]
    pub staged: Vec<String>,
    /// Seconds a check may run before it is stopped: its own cutoff, apart
    /// from an agent process's time.
    pub time: u64,
}

/// Each search kind's entry: the foil's apart from the counterexample's.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Searches {
    pub code: PerKind,
    pub compaction: PerKind,
    pub queue: PerKind,
    pub counterexample: PerKind,
    pub foil: PerKind,
    /// The spec search's, which a manifest may leave out: then `bon spec
    /// <queue id>` says to add it.
    #[serde(default)]
    pub spec: Option<PerKind>,
}

/// A kind with no entry: no role, no width.
static UNSET: std::sync::LazyLock<PerKind> = std::sync::LazyLock::new(|| PerKind { role: String::new(), n: Vec::new() });

impl Searches {
    /// Every kind's entry, by the kind's name.
    fn all(&self) -> Vec<(&'static str, &PerKind)> {
        let mut all = vec![("code", &self.code), ("compaction", &self.compaction), ("queue", &self.queue),
            ("counterexample", &self.counterexample), ("foil", &self.foil)];
        if let Some(spec) = &self.spec { all.push(("spec", spec)); }
        all
    }

    /// The entry of a search of this kind.
    fn of(&self, kind: &Kind) -> &PerKind {
        match kind {
            Kind::Code { .. } => &self.code,
            Kind::Compaction { .. } => &self.compaction,
            Kind::Queue { .. } => &self.queue,
            Kind::Counterexample { .. } => &self.counterexample,
            Kind::Foil { .. } => &self.foil,
            Kind::Spec { .. } => self.spec.as_ref().unwrap_or(&UNSET),
        }
    }
}

/// A search kind's role, which the host file maps to what runs, and its width
/// list: attempt a runs n[a] agent processes; a shorter list repeats its last
/// value. The longest list sets how many attempts a command makes. A kind's
/// role, so its model, is the same on every attempt.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PerKind {
    pub role: String,
    pub n: Vec<usize>,
}

/// What one agent process runs: its kind's role, as the host file maps it.
#[derive(Clone, Debug, PartialEq)]
pub struct Program { pub role: String, pub run: Role }

impl Program {
    /// Its name: the file name of the argv's first word (`codex`, `claude`, `bon-sample`).
    fn name(&self) -> String {
        self.run.program.first().map(|p| p.rsplit('/').next().unwrap_or(p).to_string()).unwrap_or_default()
    }

    /// The argv: the role's program, then `--model <model>` when it reaches one.
    fn argv(&self) -> Vec<String> {
        let mut argv = self.run.program.clone();
        if let Some(m) = &self.run.model { argv.extend(["--model".to_string(), m.clone()]); }
        argv
    }
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Counterexample {
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
    /// The provider's higher rate for a large request, if it has one. None: one rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
}

/// A large request's prices: a request whose prompt (input, cache reads and
/// cache writes together) is more than `above` tokens is billed `multiplier`
/// times every input-side price and `output_multiplier` (default 1) times the
/// output price. Both from the provider's price list, never guessed.
#[derive(Deserialize, serde::Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Tier {
    pub above: u64,
    pub multiplier: f64,
    #[serde(default = "one")]
    pub output_multiplier: f64,
}

fn one() -> f64 { 1.0 }

impl Price {
    /// The prices one request of `prompt` tokens is billed at.
    fn at(&self, prompt: f64) -> Price {
        match &self.tier {
            Some(t) if prompt > t.above as f64 => Price {
                input: self.input * t.multiplier, cached_input: self.cached_input * t.multiplier,
                cache_write: self.cache_write * t.multiplier, cache_write_long: self.cache_write_long * t.multiplier,
                output: self.output * t.output_multiplier, tier: None,
            },
            _ => self.clone(),
        }
    }
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
/// agent's home, so every tool a check runs is the toolchain's. Agent
/// processes keep the host file's whole PATH.
fn checks_path(config: &Config) -> Vec<String> {
    config.path.iter().filter(|d| !std::path::Path::new(d).starts_with(AGENT_HOME)).cloned().collect()
}

/// The home of every check slot's user: none it may write. (bon setup makes them so.)
const CHECK_HOME: &str = "/var/empty";

/// Who a command bon confines runs as: agent, which every agent process runs
/// as, or the user of check slot k, `check<k>`, which the check that holds
/// the slot runs as (`spec::User`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
enum Who { Agent, Check(usize) }

impl Who {
    /// Its POSIX user's name.
    fn name(self) -> String { match self { Who::Agent => "agent".into(), Who::Check(k) => format!("check{k}") } }
    fn home(self) -> &'static str { match self { Who::Agent => AGENT_HOME, Who::Check(_) => CHECK_HOME } }
}

/// A command run as user agent with a cleared environment: only PATH, HOME and
/// what bon sets. (TCB: sudo)
fn as_agent(config: &Config, dir: &std::path::Path, env: &[(&str, String)], argv: &[String]) -> Command {
    as_user(config, Who::Agent, &config.path, dir, env, argv)
}

/// The user this process runs as, by name.
fn whoami() -> &'static str {
    static ME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ME.get_or_init(|| Command::new("id").arg("-un").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default())
}

/// Whether this process already runs as a user bon confines: agent, or a
/// check slot's user (bon's own tests, run as a candidate's checks).
fn confined() -> bool {
    let me = whoami();
    me == "agent" || me.strip_prefix("check").is_some_and(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_digit()))
}

/// A plain command run as `who` (with sudo, unless this process is confined
/// and so runs it as itself), its output discarded: bon's own housekeeping
/// in what `who` wrote (rm, chmod, kill).
fn run_as(who: Who, argv: &[&str]) -> Command {
    let mut c = if confined() { Command::new(argv[0]) } else { let mut c = Command::new("sudo"); c.args(["-n", "-u", &who.name(), argv[0]]); c };
    c.args(&argv[1..]).current_dir("/tmp").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

/// A command run as `who`, with PATH path and a cleared environment.
fn as_user(config: &Config, who: Who, path: &[String], dir: &std::path::Path, env: &[(&str, String)], argv: &[String]) -> Command {
    // Already confined (a candidate's tests): the same cleared environment, as
    // itself, without sudo, which no confined user may use.
    let mut c = if confined() { Command::new("env") } else { let mut c = Command::new("sudo"); c.args(["-n", "-u", &who.name(), "env"]); c };
    c.arg("-i");
    c.arg(format!("PATH={}", path.join(":")));
    c.arg(format!("HOME={}", who.home()));
    c.arg("LANG=en_US.UTF-8");
    c.arg("TERM=dumb");
    for (k, v) in &config.toolchain { c.arg(format!("{k}={v}")); }
    for (k, v) in env { c.arg(format!("{k}={v}")); }
    c.args(argv);
    c.current_dir(dir);
    c
}

/// Something that happens once, which threads wait for: a search's leading
/// agent process has spoken (see `run`).
#[derive(Default)]
struct Signal { done: std::sync::Mutex<bool>, cv: std::sync::Condvar }

impl Signal {
    fn set(&self) { *self.done.lock().unwrap_or_else(|e| e.into_inner()) = true; self.cv.notify_all(); }
    fn wait(&self) {
        let mut d = self.done.lock().unwrap_or_else(|e| e.into_inner());
        while !*d { d = self.cv.wait(d).unwrap_or_else(|e| e.into_inner()); }
    }
}

/// What a supervised command did: exit 0, its stdout, whether its time limit
/// stopped it, whether it exited with a code of its own (not killed, not a
/// signal, not a spawn that failed: only such a result may be cached), that
/// code, whether it was spawned at all, and its log as written.
struct Run { ok: bool, stdout: String, killed: bool, exited: bool, exit: Option<i32>, spawned: bool, log: String }

/// Run to completion or kill at `time`, with all it started; the command runs
/// as `who`. `spoke`, if given, is set when the command first writes to stdout.
fn supervised(mut c: Command, who: Who, stdin: Option<String>, time: Duration, log: &std::path::Path, spoke: Option<std::sync::Arc<Signal>>) -> Run {
    std::os::unix::process::CommandExt::process_group(&mut c, 0);
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let start = Instant::now();
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            let text = format!("spawn: {e}");
            write_trace(log, &text);
            return Run { ok: false, stdout: String::new(), killed: false, exited: false, exit: None, spawned: false, log: text };
        }
    };
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        std::thread::spawn(move || { let _ = pipe.write_all(text.as_bytes()); });
    }
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let o = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            match out.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => { bytes.extend_from_slice(&chunk[..n]); if let Some(s) = &spoke { s.set(); } }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    });
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
        // The command is its own process group, and its user's: that user
        // signals the whole group (sudo, root's, is spared), so nothing it
        // started outlives it.
        let group = format!("-{}", child.id());
        let signal = |s: &str| { let _ = run_as(who, &["/bin/kill", s, "--", &group]).status(); };
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
    let code = if killed { None } else { status.and_then(|s| s.code()) };
    Run { ok: status.is_some_and(|s| s.success()) && !killed, stdout, killed, exited: code.is_some(), exit: code, spawned: true, log: text }
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
    let base = base();
    if !base.exists() {
        let _ = std::fs::create_dir_all(&base);
    }
    // Its mode once per bon process (it was a fork on every call).
    static BASE: std::sync::Once = std::sync::Once::new();
    BASE.call_once(|| { let _ = Command::new("chmod").arg("0711").arg(&base).stderr(Stdio::null()).status(); });
    let (owner, rest) = name.split_once('/').unwrap_or((name, ""));
    let dir = base.join(format!("{}.{owner}", std::process::id()));
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = Command::new("chgrp").arg("bon").arg(&dir).status();
        let _ = Command::new("chmod").arg("2750").arg(&dir).status();
    }
    if rest.is_empty() { dir } else { dir.join(rest) }
}

/// Make `d`, a directory of scratch's, agent's alone of the users bon
/// confines: engineer's, mode 0700, and agent may list and search it. No
/// check slot's user reaches what is under it, whatever its modes (agent
/// writes there through group bon, and every check slot's user is in group bon).
fn agents_alone(d: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", d.display()))?;
    // Confined (a candidate's tests), there is no agent to admit: the directory is the user's own.
    if confined() { return Ok(()); }
    sh(d, "chmod", &["+a", "user:agent allow list,search,readattr,readextattr,readsecurity", &d.to_string_lossy()]).map(|_| ())
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
    working_directory_except(root, config, commit, dir, &[], &[])
}

/// A working directory whose protected paths exclude `writable` (the queue, for
/// a queue search; the spec's files, for a spec search) and also include `more` (the tests, for a code search).
fn working_directory_except(root: &std::path::Path, config: &Config, commit: &str, dir: &std::path::Path,
                            writable: &[String], more: &[String]) -> Result<(), String> {
    materialize(root, commit, dir)?;
    // Its owner's directory is agent's alone: no check slot's user reaches it.
    if let Some(owner) = dir.parent() { agents_alone(owner)?; }
    sh(dir, "chmod", &["-R", "g+rwX", "."])?;
    sh(dir, "find", &[".", "-type", "d", "-exec", "chmod", "g+s", "{}", "+"])?;
    // The checks, their build configuration, the transcripts and .bon/: agent may read them, never change them.
    let transcripts = config.transcripts.clone().unwrap_or("transcripts".into());
    let fixed: Vec<String> = BUILD.iter().map(|p| p.to_string()).chain([transcripts, BON.to_string()]).collect();
    // Every protected path at once: one chmod each, not one per path.
    let (mut targets, mut ancestors): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for p in config.checks.paths.iter().chain(fixed.iter()).chain(more.iter()) {
        if writable.iter().any(|w| w.starts_with(p.trim_end_matches('/'))) { continue; }
        let target = dir.join(p.trim_end_matches('/'));
        if !target.exists() { continue; }
        targets.push(target.to_string_lossy().to_string());
        // Its ancestors cannot be renamed or deleted out from under it.
        let mut a = target.parent();
        while let Some(d) = a {
            if d == dir || !d.starts_with(dir) { break; }
            let s = d.to_string_lossy().to_string();
            if !ancestors.contains(&s) { ancestors.push(s); }
            a = d.parent();
        }
    }
    if !targets.is_empty() {
        let t: Vec<&str> = targets.iter().map(String::as_str).collect();
        sh(dir, "chmod", &[&["-R", "g-w"][..], &t].concat())?;
        sh(dir, "chmod", &[&["-R", "+a", "user:agent deny write,append,delete,writeattr,writeextattr,writesecurity,chown,add_file,add_subdirectory,delete_child"][..], &t].concat())?;
    }
    if !ancestors.is_empty() {
        let a: Vec<&str> = ancestors.iter().map(String::as_str).collect();
        sh(dir, "chmod", &[&["+a", "user:agent deny delete"][..], &a].concat())?;
    }
    Ok(())
}

/// A read-only checkout for running checks, engineer's alone: read-only, with
/// no group or other access. The one check slot's user that runs its checks is
/// granted read while they run (`checkout_readable`), so no other slot's user,
/// and no agent process, reads this candidate's checkout (B4); the build
/// directory each check writes is already its slot's user's alone (`slots_alone`).
fn check_directory(root: &std::path::Path, commit: &str, dir: &std::path::Path) -> Result<(), String> {
    materialize(root, commit, dir)?;
    sh(dir, "chmod", &["-R", "a-w,u+rX,go-rwx", "."])?;
    Ok(())
}

/// Grant `who` read, execute and search over a read-only checkout, once per
/// checkout and user in this bon process: the slot's user reads the checkout
/// its checks run in, and no other confined user does. Idempotent; skipped
/// when bon runs confined (a candidate's tests, where there is no ACL to set).
fn checkout_readable(dir: &std::path::Path, who: Who) {
    if confined() { return; }
    static DONE: std::sync::Mutex<Option<std::collections::HashSet<(PathBuf, String)>>> = std::sync::Mutex::new(None);
    let key = (dir.to_path_buf(), who.name());
    if !DONE.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(Default::default).insert(key) { return; }
    let ace = format!("user:{} allow read,execute,search,readattr,readextattr,readsecurity", who.name());
    let _ = sh(dir, "chmod", &["-R", "+a", &ace, &dir.to_string_lossy()]);
}

/// Trunk's build: made by trunk's checks, as a check slot's user, then copied to one of
/// engineer's that no agent process can write, kept for later bon processes
/// (see `kept`). Every build directory (an agent process's own, and its
/// judge's) starts as a clone of it (see CLONE), so cargo rebuilds only what
/// the candidate changed; cargo's own change detection (TCB) keeps it correct.
/// None until trunk's build is ready, or when there is none (every build starts cold).
static WARM: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
/// This bon process's first trunk build is done (made, kept, or failed).
static WARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
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
        Kind::Spec { goal, .. } => ("spec".into(), text(goal)),
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

/// Run trunk's checks, as a check slot's user: (every test accepts trunk, Verus verifies it).
/// Each candidate's build starts from trunk's, so they build it, unless a bon
/// process before kept one for the same key (`trunk_key`): then the verdict
/// cache answers them, or they run in a clone of it. Trunk's checks run alone,
/// so they take every core.
fn warm(m: &Manifest, head: &str) -> (bool, bool) {
    WARMING.store(true, std::sync::atomic::Ordering::SeqCst);
    let (config, root) = (&m.config, &m.root);
    let tree = tree_of(root, head);
    // bon run confined (a candidate's tests) keeps nothing in engineer's directories.
    let key = if confined() { None } else { trunk_key(config, &tree) };
    let kept_build = key.as_deref().and_then(reuse);
    let mut result = (false, false);
    let dir = scratch(&format!("trunk/{}", repository_name(root)));
    let made = (|| -> Option<PathBuf> {
        check_directory(root, head, &dir).ok()?;
        // A kept build is the one the checks clone, made by the first that must run.
        if let Some(k) = &kept_build { *WARM.lock().unwrap_or_else(|e| e.into_inner()) = Some(k.clone()); }
        let build = named_build("trunk.build/build", if kept_build.is_some() { Start::Trunk } else { Start::Empty });
        let log = trace_dir(root);
        traced(&log, std::fs::create_dir_all(&log));
        let on = On { tree: tree.clone(), test: None, cache: if kept_build.is_some() { Cache::Use } else { Cache::Refresh } };
        let run = |v: &String, name: String| run_check_with(config, &on, cores(), &dir, &build, v, &log.join(name)).0;
        // One slot for them all: they build in one directory, its user's.
        result = holding(|| {
            let tests = config.checks.test.iter().enumerate().all(|(k, v)| run(v, format!("trunk-test-{k}")));
            let proved = config.checks.verify.iter().enumerate().all(|(k, v)| run(v, format!("trunk-verify-{k}")));
            (tests, proved)
        });
        if kept_build.is_some() { remove_build(config, &build); return kept_build.clone(); }
        // A check slot's user wrote that build: what every build clones is
        // engineer's copy of it, which no agent process and no check can change.
        let staging = scratch("trunk.snapshot");
        if std::fs::read_dir(&staging).is_ok_and(|mut e| e.next().is_some()) {
            let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&staging).status();
            let _ = std::fs::remove_dir_all(&staging);
            scratch("trunk.snapshot");
        }
        let snapshot = staging.join("build");
        // Its user's files there that only it may read (rustc's incremental
        // session locks are 0600) are made readable first, or the copy fails.
        // (The directory itself is engineer's, so that chmod reports failure on
        // it: the copy decides.) Never run: nothing to copy.
        let Some((_, Some(who))) = build_of(&build) else { return None };
        let _ = run_as(who, &["/bin/chmod", "-R", "a+rX", &build.to_string_lossy()]).status();
        let copy = Command::new("cp").arg("-cR").arg(format!("{}/", build.display())).arg(&snapshot).output();
        let copied = copy.as_ref().is_ok_and(|o| o.status.success());
        remove_build(config, &build);
        if !copied {
            // Every build then starts cold: say so where the run's traces are.
            let why = copy.map_or_else(|e| e.to_string(), |o| String::from_utf8_lossy(&o.stderr).to_string());
            write_trace(&log.join("trunk-build"), format!("trunk's build was not copied, so every build starts cold: {why}"));
            let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&snapshot).stderr(Stdio::null()).status();
            let _ = std::fs::remove_dir_all(&snapshot);
            return None;
        }
        // Writable by engineer alone, whatever bon's umask, and readable by
        // group bon (agent and every slot's user): the copy took the slot's
        // build directory's mode (0700), and no ACL of it stays.
        let _ = Command::new("chmod").args(["-R", "-N"]).arg(&staging).stderr(Stdio::null()).status();
        let _ = Command::new("chmod").args(["-R", "go-w,g+rX"]).arg(&staging).status();
        write_links(&snapshot, &dir);
        // No tree, no key: this process's alone, removed with its directories.
        let Some(key) = key else { return Some(snapshot) };
        Some(keep(&staging, &key).unwrap_or(snapshot))
    })();
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    TRUNK_PROVED.store(result.1, std::sync::atomic::Ordering::SeqCst);
    // A later attempt's trunk build replaces the earlier; one that failed leaves it.
    if let Some(b) = made { *WARM.lock().unwrap_or_else(|e| e.into_inner()) = Some(b); }
    WARMED.store(true, std::sync::atomic::Ordering::SeqCst);
    result
}

/// Trunk's build, if there is one.
fn warm_build() -> Option<PathBuf> { WARM.lock().unwrap_or_else(|e| e.into_inner()).clone() }

/// Trunk's build, waited for (at most an agent process's time limit) once it is under way.
fn wait_warm(config: &Config) -> Option<PathBuf> {
    if WARMING.load(std::sync::atomic::Ordering::SeqCst) {
        let start = Instant::now();
        while !WARMED.load(std::sync::atomic::Ordering::SeqCst) && start.elapsed() < Duration::from_secs(config.agent_process.time) {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    warm_build()
}

// ── trunk's builds, kept ────────────────────────────────

/// How many trunk builds the host keeps (each one trunk commit, checks and
/// toolchain): trunk's head, the one before it (a bon process still on it,
/// or a counterexample after a push), and one more. bench/sandbox's is 0.2 GB.
const TRUNK_BUILDS: usize = 3;

/// What trunk's build is a function of: trunk's tree, the commands that build
/// it (the test and verify checks), the checks' toolchain (their PATH and
/// homes, the tools' versions and bon's cargo: `toolchain_identity`), and the
/// dependency sources they compile (`dependencies`). None when git names no tree.
fn trunk_key(config: &Config, tree: &str) -> Option<String> {
    if tree.is_empty() { return None; }
    let mut h = Sha256::new();
    let (id, dependencies) = (toolchain_identity(config), dependencies(config, tree, true));
    let parts = [id.as_str(), dependencies.as_str(), tree, "test"].into_iter().chain(config.checks.test.iter().map(String::as_str))
        .chain(["verify"]).chain(config.checks.verify.iter().map(String::as_str));
    for part in parts { h.update(part.as_bytes()); h.update([0u8]); }
    Some(h.finalize().iter().take(16).map(|b| format!("{b:02x}")).collect())
}

/// A kept trunk build's directory: `trunk-<key>` under the working
/// directories, engineer's (group bon, 2750: agent reads, never writes). It
/// holds `build`, `links`, and `done`, written last: a directory without it
/// is not one. bon's `cleanup` leaves it (its name is no pid's); `keep` bounds them.
fn kept(key: &str) -> PathBuf { PathBuf::from(WORKING_DIRECTORIES).join(format!("trunk-{key}")) }

/// The kept builds this process clones from: each one's `done`, held under a
/// shared lock until the process ends, so no other process prunes it meanwhile.
static IN_USE: std::sync::Mutex<Vec<std::fs::File>> = std::sync::Mutex::new(Vec::new());

/// The kept build for `key`, if one is complete and every file in it is
/// engineer's and writable by no one else (so no agent process wrote it);
/// it is then held in use and marked the most recent.
fn reuse(key: &str) -> Option<PathBuf> {
    let d = kept(key);
    let done = std::fs::OpenOptions::new().read(true).write(true).open(d.join("done")).ok()?;
    done.lock_shared().ok()?;
    // Pruned while this process waited for the lock: gone.
    if !d.join("done").exists() || !engineers_alone(&d) { return None; }
    let _ = done.set_modified(std::time::SystemTime::now());
    IN_USE.lock().unwrap_or_else(|e| e.into_inner()).push(done);
    Some(d.join("build"))
}

/// Every file and directory under `d` (links not followed) is owned by whoever
/// owns the working directories, and none is writable by a group or others.
fn engineers_alone(d: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(owner) = std::fs::metadata(WORKING_DIRECTORIES).map(|m| m.uid()) else { return false };
    let mut stack = vec![d.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(m) = std::fs::symlink_metadata(&p) else { return false };
        if m.uid() != owner || (!m.file_type().is_symlink() && m.mode() & 0o022 != 0) { return false; }
        if m.is_dir() {
            let Ok(entries) = std::fs::read_dir(&p) else { return false };
            stack.extend(entries.flatten().map(|e| e.path()));
        }
    }
    true
}

/// Keep `staging` (this process's `build` and `links`) as `key`'s trunk build:
/// `done` written, the directory renamed into place, then the kept builds past
/// the TRUNK_BUILDS most recent that no process holds removed. Another process
/// that kept the same key first wins, and its build is used. The kept build.
fn keep(staging: &std::path::Path, key: &str) -> Option<PathBuf> {
    let done = staging.join("done");
    std::fs::write(&done, "").ok()?;
    let _ = std::fs::set_permissions(&done, std::os::unix::fs::PermissionsExt::from_mode(0o644));
    if std::fs::rename(staging, kept(key)).is_err() {
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(staging).status();
        let _ = std::fs::remove_dir_all(staging);
    }
    let kept_build = reuse(key);
    prune_kept(TRUNK_BUILDS);
    kept_build
}

/// Remove the kept trunk builds past the `keep` most recently used, each only
/// if no process holds it (an exclusive lock on its `done`, not waited for).
fn prune_kept(keep: usize) {
    let mut all: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(WORKING_DIRECTORIES).into_iter().flatten().flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("trunk-"))
        .filter_map(|e| Some((std::fs::metadata(e.path().join("done")).ok()?.modified().ok()?, e.path()))).collect();
    all.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, d) in all.into_iter().skip(keep) {
        let Ok(done) = std::fs::File::open(d.join("done")) else { continue };
        if done.try_lock().is_err() { continue; }
        // Its `done` first, so no process takes it up while it goes.
        let _ = std::fs::remove_file(d.join("done"));
        drop(done);
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&d).stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// How a build directory is made from trunk's (as the build's user: `sh -c CLONE from to`):
/// a copy-on-write clone of it, then each file `links` (beside it) names is
/// hard-linked instead. A clone is a new file to macOS, which scans every new
/// executable and library once, host-wide and one at a time, when it is first
/// loaded; a hard link is the file trunk's build already loaded. A link that
/// fails leaves the clone.
const CLONE: &str = r#"cp -cR "$1/" "$2" || exit 1
l="$(dirname "$1")/links"
[ -f "$l" ] || exit 0
while IFS= read -r f; do ln -f "$1/$f" "$2/$f" 2>/dev/null; done < "$l"
exit 0"#;

/// How many clones run at once, host-wide. Clones that run together contend
/// in the file system: one alone costs 0.1 CPU-s, each of 7 at once 0.6, of
/// 14 at once 1.2, and 14 take longer at once than two at a time.
const CLONES: usize = 2;

/// Make `to` from `from` as CLONE says, as `who`, in one of the CLONES slots.
/// A clone is a new file, so its owner is who makes it: `who`.
fn clone_into(config: &Config, from: &std::path::Path, to: &std::path::Path, who: Who) -> bool {
    let argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), CLONE.into(), "sh".into(), from.to_string_lossy().into(), to.to_string_lossy().into()];
    let _slot = Slot::take_in(&slots_dir(), "clone", CLONES);
    as_user(config, who, &config.path, std::path::Path::new("/tmp"), &[], &argv).status().is_ok_and(|s| s.success())
}

/// Name, beside trunk's build `snapshot`, the files every build may share with
/// it rather than clone: the libraries a compiler loads (proc macros) of crates
/// none of whose sources is in the repository (`checkout`), per their
/// dep-info. No candidate can change such a crate's sources, and the toolchain
/// and environment are the checks' own, so cargo never rebuilds it in place;
/// were it to, the write fails (the file is engineer's) and the check fails
/// closed. No agent process can write the shared file.
fn write_links(snapshot: &std::path::Path, checkout: &std::path::Path) {
    let mut links = Vec::new();
    let mut dirs = vec![snapshot.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if !e.file_type().is_ok_and(|t| t.is_dir()) { continue; }
            // <profile>/deps, or <triple>/<profile>/deps: never deeper.
            if p.file_name().is_some_and(|n| n == "deps") { links.extend(shared_in(snapshot, &p, checkout)); }
            else if p.strip_prefix(snapshot).map_or(0, |r| r.components().count()) < 2 { dirs.push(p); }
        }
    }
    let file = snapshot.with_file_name("links");
    let text: String = links.iter().map(|l| format!("{l}\n")).collect();
    if std::fs::write(&file, text).is_ok() {
        let _ = std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o644));
    }
}

/// In one deps directory: each `lib<stem>.dylib` (or `.so`) whose `<stem>.d`
/// lists only absolute sources outside `checkout`, relative to `snapshot`.
fn shared_in(snapshot: &std::path::Path, deps: &std::path::Path, checkout: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(deps).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(stem) = name.strip_suffix(".d") else { continue };
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        // The first rule: `<output>: <source> <source> …`, spaces in a path escaped.
        let Some((_, sources)) = text.lines().next().and_then(|l| l.split_once(": ")) else { continue };
        let sources: Vec<String> = sources.replace("\\ ", "\0").split(' ').filter(|s| !s.is_empty()).map(|s| s.replace('\0', " ")).collect();
        let outside = |s: &String| { let p = std::path::Path::new(s); p.is_absolute() && !p.starts_with(checkout) };
        if sources.is_empty() || !sources.iter().all(outside) { continue; }
        for lib in [format!("lib{stem}.dylib"), format!("lib{stem}.so")] {
            let p = deps.join(&lib);
            if p.is_file() { if let Ok(r) = p.strip_prefix(snapshot) { out.push(r.to_string_lossy().to_string()); } }
        }
    }
    out
}

/// What a build directory starts as, when the first check that runs in it makes it.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Start {
    /// A copy-on-write clone of trunk's build, if there is one yet (`warm_build`).
    Trunk,
    /// Empty: trunk's own first build, and a re-check from a clean build.
    Empty,
}

/// Every build directory this bon process names: what it starts as, and whose
/// it is once made (agent's, an agent process's own; or a check slot's
/// user's). A build directory is its user's alone: a check slot's is
/// engineer's, mode 0700, with an ACL that lets that slot's user, and no
/// other, list, add and delete in it (`Object::BuildDirectory`); what that
/// user builds there is its own.
static BUILDS: std::sync::Mutex<Option<HashMap<PathBuf, (Start, Option<Who>)>>> = std::sync::Mutex::new(None);

/// What BUILDS says of `d`, if it names it.
fn build_of(d: &std::path::Path) -> Option<(Start, Option<Who>)> {
    BUILDS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|b| b.get(d).copied())
}

fn set_build(d: &std::path::Path, entry: (Start, Option<Who>)) {
    BUILDS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(d.to_path_buf(), entry);
}

/// A build directory named `name`, not yet made: the first check that runs
/// in it makes it, as that check's slot's user (`ensure_build`), so a judge
/// whose checks the verdict cache answers costs no clone and no removal.
fn named_build(name: &str, start: Start) -> PathBuf {
    let d = scratch(name);
    set_build(&d, (start, None));
    d
}

/// A build directory that starts as a copy-on-write clone of trunk's build,
/// agent's: an agent process's own, when there is no bon's cargo to clone it
/// at its first cargo.
fn build_directory(config: &Config, name: &str) -> Result<PathBuf, String> {
    // Once trunk's build is under way, wait for it and start from a clone of it.
    let (d, warm) = session_build(config, name)?;
    if let Some(w) = warm {
        if !clone_into(config, &w, &d, Who::Agent) { return Err(format!("cannot clone {} into {} as agent", w.display(), d.display())); }
    }
    Ok(d)
}

/// A session's build directory, agent's (under a directory agent's alone),
/// empty, and trunk's build for bon's cargo to clone into it at the session's
/// first cargo (once trunk's build is ready).
fn session_build(config: &Config, name: &str) -> Result<(PathBuf, Option<PathBuf>), String> {
    let warm = wait_warm(config);
    let d = scratch(name);
    if let Some(owner) = d.parent() { agents_alone(owner)?; }
    writable_dir(&d)?;
    set_build(&d, (Start::Empty, Some(Who::Agent)));
    Ok((d, warm))
}

/// Make `d`, a build directory BUILDS names, `who`'s, as it says it starts,
/// unless it is `who`'s already; one made by another user is emptied and made
/// again. A directory BUILDS does not name is used as it is. One at a time
/// per directory.
fn ensure_build(config: &Config, d: &std::path::Path, who: Who) -> bool {
    let one = flight(&format!("build\0{}", d.display()));
    let _one = one.lock().unwrap_or_else(|e| e.into_inner());
    let Some((start, owner)) = build_of(d) else { return d.exists() };
    if owner == Some(who) { return true; }
    if owner.is_some() { remove_build(config, d); }
    let made = slots_alone(d, who).is_ok()
        && (start == Start::Empty || warm_build().is_none_or(|w| clone_into(config, &w, d, who)));
    set_build(d, (start, Some(who)));
    if !made { remove_build(config, d); }
    made
}

/// Make `d` `who`'s alone: engineer's, mode 0700, and an ACL that lets `who`
/// list, add and delete in it (`chmod +a`: one ACL entry, on the directory
/// alone; what `who` makes in it is its own).
fn slots_alone(d: &std::path::Path, who: Who) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    if confined() { return Ok(()); }
    let ace = format!("user:{} allow list,add_file,search,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity", who.name());
    sh(d, "chmod", &["+a", &ace, &d.to_string_lossy()]).map(|_| ())
}

/// Its user empties a build directory, and engineer removes it, so the next
/// check that runs in it makes it again.
fn remove_build(config: &Config, d: &std::path::Path) {
    let _ = config;
    let Some((start, owner)) = build_of(d) else { return };
    if let Some(who) = owner {
        // Empty (a session that never built): nothing of its user's to remove.
        if std::fs::read_dir(d).is_ok_and(|mut e| e.next().is_some()) {
            let _ = run_as(who, &["/bin/rm", "-rf", &d.to_string_lossy()]).status();
        }
        let _ = Command::new("chmod").arg("-N").arg(d).stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(d);
    }
    set_build(d, (start, None));
}

/// Stop every process of check slot k's user, before a check takes the slot:
/// nothing a check left running reaches the next one in the slot. Asked
/// until no process is left (`kill -1` signals every process of its sender's
/// user but itself, and fails when there is none). Never confined.
fn vacate(k: usize) {
    if confined() { return; }
    for _ in 0..10 {
        if !run_as(Who::Check(k), &["/bin/kill", "-9", "-1"]).status().is_ok_and(|s| s.success()) { break; }
    }
}

/// Remove this bon process's directories under /tmp/bon, and any of a bon
/// process the process list says ended (its entry stale, and its pid no
/// longer a live process): never another live one's, of any user layer. Each
/// holds files of several owners: engineer's check files (with an ACL
/// denying agent), agent's, and each check slot's user's build output. So:
/// each of those users removes what it can, then engineer removes the rest.
pub fn cleanup(path: &[String]) {
    let me = std::process::id().to_string();
    let ended: Vec<String> = ended_processes().into_iter().filter(|p| !process_running(p)).collect();
    let mut gone: Vec<PathBuf> = Vec::new();
    for e in std::fs::read_dir(WORKING_DIRECTORIES).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        // <pid>.<owner>
        let Some(pid) = name.split('.').next() else { continue };
        if pid == me || ended.iter().any(|p| p == pid) { gone.push(e.path()); }
    }
    // All of them at once: a few processes in all, not a few per directory.
    let users: Vec<Who> = std::iter::once(Who::Agent).chain((0..SLOTS.load(std::sync::atomic::Ordering::SeqCst)).map(Who::Check)).collect();
    for chunk in gone.chunks(200) {
        for who in &users {
            let mut c = Command::new("sudo");
            c.args(["-n", "-u", &who.name(), "env", "-i", &format!("PATH={}", path.join(":")), "rm", "-rf"]);
            let _ = c.args(chunk).current_dir("/tmp").stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
        let _ = Command::new("chmod").args(["-R", "-N"]).args(chunk).stderr(Stdio::null()).status();
        let _ = Command::new("chmod").args(["-R", "u+w"]).args(chunk).stderr(Stdio::null()).status();
        for p in chunk { let _ = std::fs::remove_dir_all(p); }
    }
}

// ── checks ──────────────────────────────────────────────

fn hash(s: &str) -> u64 {
    let d = Sha256::digest(s.as_bytes());
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

// ── pools ───────────────────────────────────────────────

/// Memory one check may need: bon's own cold `cargo verus verify` peaks near
/// 2.3 GB, a warm one (a clone of trunk's build) near 0.7 GB.
const CHECK_GB: f64 = 1.5;

/// Threads the running checks may have together, per core. A check computes
/// for part of its time only: it also starts processes, links, writes files,
/// and on macOS waits while the system scans each new binary it runs (one at
/// a time, host-wide). The kernel sandbox's checks use 1.0 CPU-s in 2.6 s
/// alone, and less of their time under load; the scheduler shares the cores
/// among those that compute.
const THREADS_PER_CORE: usize = 2;

/// The host's two pools, each shared by every bon process on the host.
/// agent_processes: agent processes at once; one mostly waits on its model,
/// so it is wide. check_processes: commands at once, the judge's checks and
/// every cargo an agent process runs alike, each given `threads` threads.
#[derive(Clone, Debug, PartialEq)]
pub struct Pools { pub agent_processes: usize, pub check_processes: usize, pub threads: usize }

impl Default for Pools { fn default() -> Self { Pools { agent_processes: 1, check_processes: 1, threads: 1 } } }

impl Pools {
    /// From the host file, then this machine: agent_processes (default 64),
    /// check_threads (default 2), check_processes (default `check_pool` of
    /// this machine's cores and free memory).
    fn of(host: &Host) -> Pools {
        let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
        let threads = host.check_threads.unwrap_or(2).max(1);
        let check_processes = host.check_processes.unwrap_or_else(|| check_pool(cores, free_memory_gb(), threads)).max(1);
        Pools { agent_processes: host.agent_processes.unwrap_or(64).max(1), check_processes, threads }
    }
}

/// The environment a check runs with on this host, as `env -i` arguments:
/// the checks' PATH (the host file's, without agent's home), the toolchain's
/// homes, and a check slot's user's home. Whoever asks with it (engineer, or
/// a check slot's user in a check) sees the tools the checks run (`bon account`).
pub fn check_environment() -> Vec<String> {
    let host = host_file().ok().and_then(|f| std::fs::read_to_string(f).ok()).and_then(|t| toml::from_str::<toml::Value>(&t).ok());
    let text = |k: &str| host.as_ref().and_then(|h| h.get(k)).and_then(|v| v.as_str()).map(String::from);
    let path: Vec<String> = host.as_ref().and_then(|h| h.get("path")).and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|d| d.as_str()).filter(|d| !std::path::Path::new(d).starts_with(AGENT_HOME)).map(String::from).collect())
        .unwrap_or_else(|| vec!["/usr/bin".into(), "/bin".into()]);
    let mut env = vec![format!("PATH={}", path.join(":")), format!("HOME={CHECK_HOME}")];
    for (k, v) in [("RUSTUP_HOME", text("rustup_home")), ("CARGO_HOME", text("cargo_home"))] { if let Some(v) = v { env.push(format!("{k}={v}")); } }
    env
}

/// How many check slots this host may have, so how many slot users `bon
/// setup` makes: the host file's check_processes; unset (or no host file
/// yet), the most the default pool can come to here, whatever memory is free.
pub fn check_slots() -> usize {
    let host = host_file().ok().and_then(|f| std::fs::read_to_string(f).ok()).and_then(|t| toml::from_str::<toml::Value>(&t).ok());
    let get = |k: &str| host.as_ref().and_then(|h| h.get(k)).and_then(|v| v.as_integer()).map(|v| v.max(1) as usize);
    let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
    get("check_processes").unwrap_or_else(|| (THREADS_PER_CORE * cores / get("check_threads").unwrap_or(2)).max(1))
}

/// The default check pool: as many checks as free memory holds at CHECK_GB
/// each, and no more than THREADS_PER_CORE threads per core among them; at
/// least one. Memory is what a check holds whether it computes or waits, so
/// it bounds them; the cores are shared, not divided.
fn check_pool(cores: usize, memory_gb: f64, threads: usize) -> usize {
    ((memory_gb / CHECK_GB) as usize).min(THREADS_PER_CORE * cores / threads.max(1)).max(1)
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

/// Where working directories, slots and bon's cargo live: the working
/// directories; or, when bon runs confined (a candidate's tests, as agent or a
/// check slot's user), which cannot write the host's, that user's own.
fn base() -> PathBuf {
    if confined() { std::env::temp_dir().join(format!("bon-{}", whoami())) } else { PathBuf::from(WORKING_DIRECTORIES) }
}

/// The check pool's slot files: engineer's directory, which no user bon
/// confines may write: bon's cargo takes slots as agent, opening the files
/// read-only. A slot's file is the slot: were it replaced, two checks could
/// hold one slot, so run as one slot's user at once.
fn slots_dir() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let d = base().join("checks");
        let made = std::fs::create_dir_all(&d).is_ok()
            && Command::new("chgrp").arg("bon").arg(&d).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
            && Command::new("chmod").arg("2755").arg(&d).status().is_ok_and(|s| s.success());
        if !made && !confined() { eprintln!("bon: {}: cannot make it engineer's, group bon, 2755", d.display()); }
        // Made here, so agent opens them read-only (a sandboxed program may not create files).
        for p in (0..256).map(|k| d.join(format!("check.{k}"))).chain((0..CLONES).map(|k| d.join(format!("clone.{k}")))) {
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
/// once. bon's cargo takes check slots the same way, as agent. Its k is the slot.
struct Slot(std::fs::File, usize);

/// A slot this process freed: its own waiters look again at once, not at
/// their next poll (another process's freed slot is found by polling).
static FREED: (std::sync::Mutex<u64>, std::sync::Condvar) = (std::sync::Mutex::new(0), std::sync::Condvar::new());

impl Drop for Slot {
    fn drop(&mut self) {
        let _ = self.0.unlock();
        *FREED.0.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        FREED.1.notify_all();
    }
}

/// A pool's slot as this process holds it: first a place among the process's
/// own waiters (at most the pool's size of them look for a host-wide slot, so
/// a wide search does not poll the slot files from every thread), then the slot.
struct Held { slot: Slot, _gate: Ticket }

impl Held {
    /// The slot's index: a check that holds check slot k runs as `check<k>`.
    fn slot(&self) -> usize { self.slot.1 }
}

/// In-process admission to a pool: how many of this process's threads hold or
/// seek one of its slots.
struct Gate { taken: std::sync::Mutex<usize>, freed: std::sync::Condvar }
static AGENT_PROCESS_GATE: Gate = Gate { taken: std::sync::Mutex::new(0), freed: std::sync::Condvar::new() };
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
    /// An agent process's slot: agent_process.<k> in the working directories.
    fn agent_process(config: &Config) -> Held {
        let gate = AGENT_PROCESS_GATE.enter(config.pools.agent_processes);
        Held { slot: Slot::take_in(&base(), "agent_process", config.pools.agent_processes), _gate: gate }
    }

    /// A check's slot: check.<k> in the slots directory, taken for a check bon
    /// runs as `check<k>`, which nothing an earlier holder ran still runs as.
    fn check(config: &Config) -> Held {
        let gate = CHECK_GATE.enter(config.pools.check_processes);
        let slot = Slot::take_in(&slots_dir(), "check", config.pools.check_processes);
        vacate(slot.1);
        Held { slot, _gate: gate }
    }

    fn take_in(dir: &std::path::Path, name: &str, n: usize) -> Slot {
        loop {
            let seen = *FREED.0.lock().unwrap_or_else(|e| e.into_inner());
            for k in 0..n.max(1) {
                let p = dir.join(format!("{name}.{k}"));
                // Read-only: a slot file agent made is locked the same way.
                let f = std::fs::File::open(&p).or_else(|_| {
                    let f = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(&p);
                    let _ = std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644));
                    f
                });
                if let Ok(f) = f { if f.try_lock().is_ok() { return Slot(f, k); } }
            }
            let freed = FREED.0.lock().unwrap_or_else(|e| e.into_inner());
            if *freed == seen { let _ = FREED.1.wait_timeout(freed, Duration::from_millis(250)); }
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
# A session's build: trunk's, cloned at its first cargo (bon sets BON_WARM for
# sessions, never for checks), so a session that never builds costs no clone.
if ($ENV{BON_WARM} && $ENV{CARGO_TARGET_DIR}) {
    my $t = $ENV{CARGO_TARGET_DIR};
    if (open(my $l, '>>', "$t/.bon-warm.lock")) {
        flock($l, LOCK_EX);
        unless (-e "$t/.bon-warm") {
            # One of the host's clone slots, as bon takes them (see CLONES).
            my ($c, $open) = (undef, 1);
            while (!$c && $open) {
                $open = 0;
                for my $k (0 .. @CLONES@ - 1) {
                    my $f;
                    sysopen($f, "$slots/clone.$k", O_RDONLY) or sysopen($f, "$slots/clone.$k", O_RDONLY | O_CREAT, 0644) or next;
                    $open = 1;
                    if (flock($f, LOCK_EX | LOCK_NB)) { $c = $f; last }
                    close $f;
                }
                select(undef, undef, undef, 0.05) unless $c;
            }
            system('/bin/sh', '-c', q{@CLONE@}, 'sh', $ENV{BON_WARM}, $t) == 0 or warn "bon's cargo: trunk's build not cloned; this build starts cold\n";
            close $c if $c;
            if (open(my $m, '>', "$t/.bon-warm")) { close $m }
        }
        close $l;
    }
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

/// bon's cargo with trunk's clone spelled in: the same CLONE every build is made by.
fn cargo_text() -> String { CARGO.replace("@CLONE@", CLONE).replace("@CLONES@", &CLONES.to_string()) }

/// The directory holding bon's cargo for this bon process, engineer's: agent
/// may read and run it, never write it. None if it could not be written; then
/// nothing is pooled or capped beyond what bon sets itself.
fn wrapper(config: &Config) -> Option<PathBuf> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        if confined() { return None; }
        let d = scratch("bin");
        let text = cargo_text().replace("@SLOTS@", &slots_dir().to_string_lossy()).replace("@N@", &config.pools.check_processes.to_string())
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

/// What a check's result is a function of besides its command, the toolchain
/// and the dependency sources: the tree it runs on and the test written into
/// it (path, bytes), and how the cache serves it.
struct On<'a> { tree: String, test: Option<(&'a str, &'a [u8])>, cache: Cache }

/// How the verdict cache serves a check.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Cache {
    /// A cached result answers it; a result is kept.
    Use,
    /// It runs, and its result is kept: trunk's first run in a bon process,
    /// whose build every candidate's starts from.
    Refresh,
    /// It runs, and nothing is read or kept: what decides a push or a landing,
    /// checked again from a clean build.
    Off,
}

impl On<'_> {
    /// A commit's tree, nothing written into it.
    fn commit(root: &std::path::Path, commit: &str) -> On<'static> { On { tree: tree_of(root, commit), test: None, cache: Cache::Use } }
}

/// A commit's tree id; empty (never cached) if git cannot say.
fn tree_of(root: &std::path::Path, commit: &str) -> String {
    git(root, &["rev-parse", &format!("{commit}^{{tree}}")]).unwrap_or_default()
}

/// bon's state that outlives a bon process: `.bon` under the user layer's
/// root the host file names (`user`), made when missing, engineer's alone
/// (0700): no agent process and no check may read or write it
/// (`Object::State`; the isolated gate observes it). It holds the verdict cache
/// and the process list. None when no host file names a root, or the
/// directory cannot be made so (bon run confined, in a candidate's tests).
pub fn state_dir() -> Option<PathBuf> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = USER.get().cloned().or_else(|| read_host(&host_file().ok()?).ok().map(|h| PathBuf::from(h.user)))?;
        let d = root.join(BON);
        std::fs::create_dir_all(&d).ok()?;
        // Only its owner may set its mode: then it is this process's user's.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).ok()?;
        (std::fs::metadata(&d).ok()?.mode() & 0o077 == 0).then_some(d)
    }).clone()
}

/// A directory of the state's, made when missing, its owner's alone.
fn state(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let d = state_dir()?.join(name);
    std::fs::create_dir_all(&d).ok()?;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).ok()?;
    Some(d)
}

/// The cache of check results: the user layer's state's `verdicts`. None, so
/// nothing is cached, when there is no state.
fn cache_dir() -> Option<PathBuf> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| state("verdicts")).clone()
}

/// The toolchain as the checks see it: their PATH and homes, the versions of
/// rustc, cargo and Verus, and bon's cargo. Computed once per PATH. Not the
/// host file: its other facts (prices, pools, roles, the user layer's root)
/// change no check's result.
fn toolchain_identity(config: &Config) -> String {
    static MEMO: std::sync::Mutex<Option<HashMap<String, String>>> = std::sync::Mutex::new(None);
    let path = checks_path(config).join(":");
    let id = format!("{path}\0{:?}", config.toolchain);
    let mut memo = MEMO.lock().unwrap_or_else(|e| e.into_inner());
    memo.get_or_insert_with(HashMap::new).entry(id.clone()).or_insert_with(|| {
        let version = |tool: &str| Command::new(tool).arg("--version").env_clear().env("PATH", &path)
            .envs(config.toolchain.iter().map(|(k, v)| (k.as_str(), v.as_str()))).stdin(Stdio::null()).output()
            .map_or_else(|e| e.to_string(), |o| String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr));
        let (rustc, cargo, verus) = (version("rustc"), version("cargo"), version("verus"));
        format!("{id}\0{rustc}\0{cargo}\0{verus}\0{}", cargo_text())
    }).clone()
}

/// Every directory the toolchain object covers, for the isolated gate to
/// observe (`observe`): the host file's homes (RUSTUP_HOME, CARGO_HOME; not
/// The directories holding the dependency sources a lockfile names, under
/// the checks' cargo home: each registry package as unpacked
/// (`registry/src/<index>/<name>-<version>`), each git package as checked out
/// (`git/checkouts/<name>-<hash>/<rev>`). A path dependency is the tree's,
/// or the toolchain's. Sorted; a package not unpacked yet is its path alone.
fn dependency_dirs(config: &Config, lockfile: &str) -> Vec<PathBuf> {
    let Some(home) = config.toolchain.iter().find(|(k, _)| k == "CARGO_HOME").map(|(_, v)| PathBuf::from(v)) else { return Vec::new() };
    let lock: toml::Value = toml::from_str(lockfile).unwrap_or(toml::Value::Table(Default::default()));
    let indexes: Vec<PathBuf> = std::fs::read_dir(home.join("registry/src")).into_iter().flatten().flatten().map(|e| e.path()).collect();
    let checkouts: Vec<PathBuf> = std::fs::read_dir(home.join("git/checkouts")).into_iter().flatten().flatten().map(|e| e.path()).collect();
    let mut dirs = Vec::new();
    for p in lock.get("package").and_then(|v| v.as_array()).into_iter().flatten() {
        let (Some(name), Some(version), Some(source)) = (p.get("name").and_then(|v| v.as_str()), p.get("version").and_then(|v| v.as_str()),
                                                         p.get("source").and_then(|v| v.as_str())) else { continue };
        if source.starts_with("registry+") || source.starts_with("sparse+") {
            dirs.extend(indexes.iter().map(|i| i.join(format!("{name}-{version}"))));
        } else if let Some((_, rev)) = source.split_once('#') {
            dirs.extend(checkouts.iter().filter(|c| c.file_name().is_some_and(|n| n.to_string_lossy().starts_with(&format!("{name}-"))))
                .map(|c| c.join(&rev[..rev.len().min(7)])));
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

/// What the checks compile besides the tree and the toolchain: the
/// dependency sources the tree's Cargo.lock names (`dependency_dirs`), as which
/// of them are unpacked (each by its `.cargo-ok`, which cargo writes last). No
/// agent process and no check can write them: they are engineer's, part of
/// the toolchain (`Object::Toolchain`, which the isolated gate observes), and
/// cargo unpacks each package once, from the bytes whose checksum the
/// lockfile pins. So the lockfile, which is the tree's, says what each holds;
/// what it cannot say is whether each is there yet. Taken again when `fresh`
/// (as a check that runs does before and after), else the last this process
/// took for the lockfile stands. A tree with no Cargo.lock compiles none: empty.
fn dependencies(config: &Config, tree: &str, fresh: bool) -> String {
    static LOCKFILES: std::sync::Mutex<Option<HashMap<String, Option<String>>>> = std::sync::Mutex::new(None);
    static PRESENT: std::sync::Mutex<Option<HashMap<String, String>>> = std::sync::Mutex::new(None);
    if tree.is_empty() { return String::new(); }
    // The tree's lockfile, once per tree: its blob.
    let blob = LOCKFILES.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).entry(tree.to_string())
        .or_insert_with(|| git(&config.root, &["rev-parse", "--verify", "-q", &format!("{tree}:Cargo.lock")]).ok()).clone();
    let Some(blob) = blob else { return String::new() };
    if !fresh {
        if let Some(p) = PRESENT.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|m| m.get(&blob)) { return p.clone(); }
    }
    let dirs = dependency_dirs(config, &git(&config.root, &["cat-file", "blob", &blob]).unwrap_or_default());
    let mut h = Sha256::new();
    h.update(blob.as_bytes());
    for d in &dirs { h.update(d.as_os_str().as_encoded_bytes()); h.update([u8::from(d.join(".cargo-ok").exists())]); }
    let present: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    PRESENT.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(blob, present.clone());
    present
}

/// The cache key of a command on `on`, or None when it may not be cached: no
/// tree, or bon running confined (which may not keep engineer's cache). What
/// the check sees: the toolchain, the dependency sources, the tree, the test
/// written into it, and the command.
fn verdict_key(config: &Config, on: &On, command: &str) -> Option<String> {
    verdict_key_with(config, on, command, &dependencies(config, &on.tree, false))
}

fn verdict_key_with(config: &Config, on: &On, command: &str, dependencies: &str) -> Option<String> {
    if on.tree.is_empty() || confined() { return None; }
    let mut h = Sha256::new();
    for part in [toolchain_identity(config).as_bytes(), dependencies.as_bytes(), on.tree.as_bytes(), command.as_bytes()] { h.update(part); h.update([0u8]); }
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
    if on.cache != Cache::Use { return None; }
    let key = verdict_key(config, on, command)?;
    let (ok, stdout, text) = cached(&key)?;
    write_trace(log, format!("cached: {key}\n{}", check_record(command, on, &text, &stdout)));
    decided(on, command, ok, &stdout, log);
    Some((ok, stdout))
}

/// One lock per key: of identical checks running at once in this bon process,
/// one runs and the rest wait for its result.
fn flight(key: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
    type Flights = HashMap<String, std::sync::Arc<std::sync::Mutex<()>>>;
    static FLIGHTS: std::sync::Mutex<Option<Flights>> = std::sync::Mutex::new(None);
    FLIGHTS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).entry(key.to_string()).or_default().clone()
}

/// Run a check in a read-only checkout, holding a check slot, as the slot's user, with the
/// pool's threads; or answer it from the cache. A check's exit (0 or not), its
/// output, and whether its cutoff (`[checks] time`) stopped it. Only a run that
/// exited with a code of its own is cached: never one killed, signalled or not
/// started, nor one during which the dependency sources changed.
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
    // No file in a working ancestor decides this check (a parent Cargo.toml,
    // a toolchain file, a .cargo or a .git). Checked before and after the run:
    // one that appears mid-run voids the verdict, so it is not cached.
    let guard = match ancestor_guard(guard_uid(&config.root)) {
        Ok(g) => g,
        Err(e) => { write_trace(log, check_record(command, on, &format!("suspect: {e}"), "")); return (false, String::new(), false); }
    };
    // The dependency sources as they are now: a run is kept under them.
    let before = dependencies(config, &on.tree, true);
    let key = verdict_key_with(config, on, command, &before);
    if let Some((ok, out)) = key.as_deref().and_then(|_| answer(config, on, command, log)) { return (ok, out, false); }
    // The slot the thread holds for its checks (see `holding`), or one for
    // this check alone: the check runs as the slot's user.
    let (_slot, k) = HOLDING.with(|h| match &mut *h.borrow_mut() {
        Some(held) => { let held = held.get_or_insert_with(|| Slot::check(config)); (None, held.slot()) }
        None => { let s = Slot::check(config); let k = s.slot(); (Some(s), k) }
    });
    let who = Who::Check(k);
    // The checkout is the slot's user's to read while its checks run; no other
    // confined user reaches it (B4).
    checkout_readable(dir, who);
    // A judge's build is made now, when a check must run in it, as the slot's user's.
    if !ensure_build(config, target, who) {
        write_trace(log, check_record(command, on, &format!("no build directory: {} could not be made {}'s", target.display(), who.name()), ""));
        return (false, String::new(), false);
    }
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()];
    let t = target.to_string_lossy().to_string();
    let env = [("BON_BUILD", t.clone()), ("CARGO_TARGET_DIR", t), ("CARGO_BUILD_JOBS", threads.to_string()), ("BON_CHECK_SLOT", "held".to_string())];
    let c = as_user(config, who, &with_wrapper(config, checks_path(config)), dir, &env, &argv);
    let started = Instant::now();
    let mut r = supervised(c, who, None, Duration::from_secs(config.checks.time), log, None);
    RAN.with(|s| s.set(started.elapsed().as_secs_f64()));
    r.log = check_record(command, on, &r.log, &r.stdout);
    write_trace(log, &r.log);
    // A working-ancestor file that appeared or changed while the check ran
    // could have decided it: the verdict is suspect, kept by nothing.
    let guard_held = ancestor_guard(guard_uid(&config.root)).map(|g| g == guard).unwrap_or(false);
    if !guard_held {
        write_trace(log, check_record(command, on, "suspect: a working-ancestor file appeared or changed while the check ran; its verdict is not kept", &r.stdout));
        return (false, r.stdout, r.killed);
    }
    if r.exited && on.cache != Cache::Off {
        if let Some(k) = &key { if dependencies(config, &on.tree, true) == before { store(k, r.ok, &r.stdout, &r.log); } }
        decided(on, command, r.ok, &r.stdout, log);
    }
    (r.ok && !r.killed, r.stdout, r.killed)
}

/// A check's log in the one trace shape (README, "The trace"): its head says
/// how it was judged (`exit:`, the verdict) and how long it ran, then what ran
/// (`program:`, the command), what it was given (`context:`, the tree, and the
/// test written into it) and which behavior its output showed (`behavior:`,
/// its stdout hashed as an agree check's is); its output follows. A log that
/// already says them (a cached run's) is left as it is.
fn check_record(command: &str, on: &On, log: &str, stdout: &str) -> String {
    if log.lines().take(5).any(|l| l.starts_with("program: ")) { return log.to_string(); }
    let context = match on.test { Some((path, _)) => format!("{} + {path}", on.tree), None => on.tree.clone() };
    let shape = format!("program: {}\ncontext: {context}\nbehavior: {}\n", command.split_whitespace().collect::<Vec<_>>().join(" "), hash(stdout));
    let lines: Vec<&str> = log.split_inclusive('\n').collect();
    let at = lines.iter().position(|l| l.starts_with("seconds: ")).map_or(0, |i| i + 1);
    format!("{}{}{shape}{}", lines[..at].concat(), if at > 0 && !lines[at - 1].ends_with('\n') { "\n" } else { "" }, lines[at..].concat())
}

// ── what decided a candidate ────────────────────────────

/// A check's result as it judged a candidate: what it ran on (a tree, and a
/// test written into it), its command, and what it said (exit 0, stdout).
#[derive(Clone, Debug, PartialEq)]
struct Decided { tree: String, test: Option<(String, Vec<u8>)>, command: String, ok: bool, stdout: String }

/// What decided each candidate this bon process judged, by its commit: every
/// check that ran or was answered while it was judged.
static DECIDED: std::sync::Mutex<Option<HashMap<String, Vec<Decided>>>> = std::sync::Mutex::new(None);

type Deciding = std::sync::Arc<std::sync::Mutex<Vec<Decided>>>;

thread_local! {
    /// While a candidate is judged on this thread: where its checks' results go.
    static DECIDING: std::cell::RefCell<Option<Deciding>> = const { std::cell::RefCell::new(None) };
}

/// A check's result, kept for the candidate being judged on this thread.
fn decided(on: &On, command: &str, ok: bool, stdout: &str, _log: &std::path::Path) {
    DECIDING.with(|d| if let Some(d) = &*d.borrow() {
        d.lock().unwrap_or_else(|e| e.into_inner()).push(Decided {
            tree: on.tree.clone(), test: on.test.map(|(p, b)| (p.to_string(), b.to_vec())), command: command.to_string(), ok, stdout: stdout.to_string() });
    });
}

/// Run `f` with the checks it runs on this thread, and on the threads it
/// hands `within`, kept for one candidate; then what they decided.
fn deciding<T>(f: impl FnOnce() -> T) -> (T, Vec<Decided>) {
    let d: Deciding = Default::default();
    let outer = DECIDING.with(|x| x.replace(Some(d.clone())));
    let r = f();
    DECIDING.with(|x| x.replace(outer));
    let out = d.lock().unwrap_or_else(|e| e.into_inner()).clone();
    (r, out)
}

/// This thread's collector, for a thread that judges on its behalf.
fn deciding_here() -> Option<Deciding> { DECIDING.with(|d| d.borrow().clone()) }

/// Run `f` on this thread with `d` as its collector.
fn within<T>(d: &Option<Deciding>, f: impl FnOnce() -> T) -> T {
    let outer = DECIDING.with(|x| x.replace(d.clone()));
    let r = f();
    DECIDING.with(|x| x.replace(outer));
    r
}

/// Keep what decided `commit`.
fn keep_decided(commit: &str, d: Vec<Decided>) {
    DECIDED.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(commit.to_string(), d);
}

/// Check again, from a clean build and never from the cache, what decided
/// `commit` (`DECIDED`): each distinct check once, at once through the check
/// pool, each in a checkout of its tree (the test written in) and a build
/// directory that starts empty. Ok when each says what it said when it
/// decided: the same exit, and for an agree or rank check the same output.
/// Err names the first that differs: a suspect check. Each run's log is
/// `recheck-<commit>-<k>` in the trace.
fn recheck(m: &Manifest, commit: &str) -> Result<(), String> {
    let config = &m.config;
    let short = &commit[..commit.len().min(12)];
    let all = DECIDED.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|d| d.get(commit)).cloned()
        .ok_or_else(|| format!("nothing this bon process judged decided {short}: it is not checked again, and not pushed"))?;
    let mut checks: Vec<Decided> = Vec::new();
    for d in all { if !checks.iter().any(|c| c.tree == d.tree && c.test == d.test && c.command == d.command) { checks.push(d); } }
    let log = trace_dir(&m.root);
    let n = RECHECKS.fetch_add(checks.len(), std::sync::atomic::Ordering::SeqCst);
    let results: Vec<std::sync::Mutex<Option<Result<(bool, String), String>>>> = checks.iter().map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for (k, d) in checks.iter().enumerate() {
            let (results, log) = (&results, &log);
            scope.spawn(move || {
                let name = format!("recheck.{}", n + k);
                let dir = scratch(&format!("{name}/{}", repository_name(&m.root)));
                let build = named_build(&format!("{name}.build/build"), Start::Empty);
                let made = materialize(&m.root, &d.tree, &dir).and_then(|_| {
                    if let Some((p, bytes)) = &d.test {
                        let p = dir.join(p);
                        std::fs::create_dir_all(p.parent().unwrap_or(&dir)).map_err(|e| e.to_string())?;
                        std::fs::write(&p, bytes).map_err(|e| e.to_string())?;
                    }
                    sh(&dir, "chmod", &["-R", "a-w,g+rX", "."]).map(|_| ())
                });
                let on = On { tree: d.tree.clone(), test: d.test.as_ref().map(|(p, b)| (p.as_str(), b.as_slice())), cache: Cache::Off };
                let r = match made {
                    Ok(()) => { let (ok, out, _) = run_check(config, &on, &dir, &build, &d.command, &log.join(format!("recheck-{short}-{k}"))); Ok((ok, out)) }
                    Err(e) => Err(format!("`{}` on tree {} could not be checked again: {e}; nothing was pushed", d.command, d.tree)),
                };
                *results[k].lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
                remove_build(config, &build);
                for p in [dir.parent(), build.parent()].into_iter().flatten() {
                    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(p).stderr(Stdio::null()).status();
                    let _ = std::fs::remove_dir_all(p);
                }
            });
        }
    });
    let output_matters = |c: &str| config.checks.agree.iter().any(|a| a == c) || config.checks.rank.values().any(|r| r == c);
    for (k, (d, r)) in checks.iter().zip(results).enumerate() {
        let Some(r) = r.into_inner().unwrap_or_else(|e| e.into_inner()) else { continue };
        let (ok, out) = r?;
        let said = |ok: bool| if ok { "exit 0" } else { "a failure" };
        if ok != d.ok {
            return Err(format!("suspect check: `{}` on tree {}: it decided {short} with {}, and from a clean build it says {}; nothing was pushed (log: {})",
                               d.command, d.tree, said(d.ok), said(ok), log.join(format!("recheck-{short}-{k}")).display()));
        }
        if output_matters(&d.command) && out.trim_end() != d.stdout.trim_end() {
            return Err(format!("suspect check: `{}` on tree {}: from a clean build it prints other than what decided {short}; nothing was pushed (log: {})",
                               d.command, d.tree, log.join(format!("recheck-{short}-{k}")).display()));
        }
    }
    Ok(())
}

/// How many re-checks this bon process has run: names their directories.
static RECHECKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The staged checks (`[checks] staged`) on `commit`, the selected candidate:
/// one after another in one checkout of its tree and one build directory that
/// starts empty, never from the cache. Ok when each exits 0; Err names the
/// first that does not, which stops the push as a suspect re-check does. Each
/// run's log is `staged-<commit>-<k>` in the trace.
fn staged(m: &Manifest, commit: &str) -> Result<(), String> {
    let config = &m.config;
    if config.checks.staged.is_empty() { return Ok(()); }
    let short = &commit[..commit.len().min(12)];
    let log = trace_dir(&m.root);
    let name = format!("recheck.{}", RECHECKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
    let dir = scratch(&format!("{name}/{}", repository_name(&m.root)));
    let build = named_build(&format!("{name}.build/build"), Start::Empty);
    let tree = tree_of(&m.root, commit);
    let made = materialize(&m.root, &tree, &dir).and_then(|_| sh(&dir, "chmod", &["-R", "a-w,g+rX", "."]).map(|_| ()));
    let on = On { tree, test: None, cache: Cache::Off };
    let mut r = made.map_err(|e| format!("the staged checks could not be set up on {short}: {e}; nothing was pushed"));
    // One slot for them all: they build in one directory, its user's.
    holding(|| for (k, command) in config.checks.staged.iter().enumerate() {
        if r.is_err() { break; }
        let path = log.join(format!("staged-{short}-{k}"));
        if !run_check(config, &on, &dir, &build, command, &path).0 {
            r = Err(format!("staged check `{command}` rejects {short}, the selected candidate, from a clean build; nothing was pushed (log: {})", path.display()));
        }
    });
    remove_build(config, &build);
    for p in [dir.parent(), build.parent()].into_iter().flatten() {
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(p).stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(p);
    }
    r
}

thread_local! {
    /// The seconds the last check this thread ran took, from its start to its
    /// exit: never a slot's wait, never a cached answer.
    static RAN: std::cell::Cell<f64> = const { std::cell::Cell::new(0.0) };
}

/// A compaction candidate's suite seconds: each test and verify check run
/// again on its tree once it judged it, in the same build, so what is timed is
/// the suite, not what its change made cargo rebuild. bon times each run; a
/// tree's time is kept in the verdict cache beside its verdict (the command's
/// key with `seconds` added), so a tree is timed once per verdict cache and
/// every bon process of the user layer ranks it alike. None if a run fails: then the
/// rank is not measured. Each run's log is `seconds-<k>` in the trace.
fn suite_seconds(config: &Config, on: &On, dir: &std::path::Path, build: &std::path::Path, trace: &std::path::Path) -> Option<f64> {
    let mut total = 0.0;
    for (k, command) in config.checks.test.iter().chain(&config.checks.verify).enumerate() {
        let log = trace.join(format!("seconds-{k}"));
        let key = verdict_key(config, on, &format!("{command}\0seconds"));
        // Of identical trees timed at once, one is timed and the rest read its figure.
        let one = key.as_deref().map(flight);
        let _one = one.as_ref().map(|f| f.lock().unwrap_or_else(|e| e.into_inner()));
        if let Some((s, k)) = key.as_ref().and_then(|k| cached(k).and_then(|(_, s, _)| s.parse::<f64>().ok()).map(|s| (s, k))) {
            write_trace(&log, format!("cached: {k}\n{}", check_record(command, on, &format!("seconds: {s:.3}\n"), "")));
            total += s;
            continue;
        }
        let off = On { tree: on.tree.clone(), test: on.test, cache: Cache::Off };
        if !run_check(config, &off, dir, build, command, &log).0 { return None; }
        // To the millisecond, as kept: a figure read back sums the same.
        let s = (RAN.with(|r| r.get()) * 1000.0).round() / 1000.0;
        if let Some(k) = &key { store(k, true, &format!("{s:.3}"), ""); }
        total += s;
    }
    Some(total)
}

thread_local! {
    /// While `holding`: Some, and the check slot this thread took at its first
    /// check that ran (None until one runs: the cache may answer them all).
    static HOLDING: std::cell::RefCell<Option<Option<Held>>> = const { std::cell::RefCell::new(None) };
}

/// Run `f`, its checks in one check slot taken at the first that runs and
/// freed when `f` returns: a candidate's checks, which run one after another,
/// wait for a slot once, not once each. Never around work that waits on other
/// threads' checks, which would hold a slot idle. Nested, the outer holds.
fn holding<T>(f: impl FnOnce() -> T) -> T {
    let outer = HOLDING.with(|h| { let mut h = h.borrow_mut(); let outer = h.is_some(); if !outer { *h = Some(None); } outer });
    let r = f();
    if !outer { HOLDING.with(|h| *h.borrow_mut() = None); }
    r
}

/// Every core: for the checks something waits on alone.
fn cores() -> usize { std::thread::available_parallelism().map_or(1, |c| c.get()) }

// ── programs ────────────────────────────────────────────

/// API-equivalent cost in microdollars, from the program's token counts and the
/// host's price table: (bon's figure, the program's own figure if it reports
/// one: a figure of 0, or none, is not reported). Read from what it printed,
/// whatever its client: a final `result` event (the claude CLI's, and
/// bon-sample's for every client) carries `modelUsage`, per model, with
/// 5-minute and 1-hour cache writes apart; else the last `turn.completed`
/// (the codex CLI's), whose usage is a running total, cached and cache-write
/// tokens part of `input_tokens`. A program that reaches no model costs nothing.
///
/// A price's tier is per request, so it applies where the output says what each
/// request's prompt was: a `result` with `"requests": 1` (bon-sample's) is one
/// request per model; otherwise each of Claude's `assistant` events carries its
/// request's usage, and a request over the threshold is charged the difference.
/// Codex's running total says nothing per request: no tier.
fn generation(p: &Program, config: &Config, stdout: &str) -> Result<(u64, Option<u64>, HashMap<String, Price>), String> {
    let price = |model: &str| config.prices.get(model).ok_or(format!("no price for model {model}"));
    let rate = |p: &Price, input: f64, cached: f64, output: f64, write: f64, write_long: f64| {
        (input * p.input + cached * p.cached_input + output * p.output + write * p.cache_write + write_long * p.cache_write_long) / 1_000_000.0
    };
    let Some(model) = &p.run.model else { return Ok((0, Some(0), HashMap::new())) };
    let reported = |theirs: f64| Some(micro(theirs)).filter(|c| *c > 0);
    let events: Vec<serde_json::Value> = stdout.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).collect();
    if let Some(r) = events.iter().rev().find(|v| v["type"] == "result") {
        let one_request = r["requests"].as_u64() == Some(1);
        let mut ours = 0.0;
        let mut theirs = 0.0;
        let mut used = HashMap::new();
        for (model, u) in r["modelUsage"].as_object().into_iter().flatten() {
            used.insert(model.clone(), price(model)?.clone());
            let n = |k: &str| u[k].as_f64().unwrap_or(0.0);
            let (w5, w1) = (n("cacheCreationEphemeral5mInputTokens"), n("cacheCreationEphemeral1hInputTokens"));
            let w5 = if w5 + w1 == 0.0 { n("cacheCreationInputTokens") } else { w5 };
            let (input, cached) = (n("inputTokens"), n("cacheReadInputTokens"));
            let p = if one_request { price(model)?.at(input + cached + w5 + w1) } else { price(model)?.clone() };
            ours += rate(&p, input, cached, n("outputTokens"), w5, w1);
            theirs += n("costUSD");
        }
        if !one_request {
            // Each request once, by message id: a message's blocks repeat its usage.
            let mut requests: HashMap<String, (String, serde_json::Value)> = HashMap::new();
            for v in events.iter().filter(|v| v["type"] == "assistant") {
                let m = &v["message"];
                if let (Some(id), Some(model)) = (m["id"].as_str(), m["model"].as_str()) { requests.insert(id.into(), (model.into(), m["usage"].clone())); }
            }
            for (model, u) in requests.values() {
                let Some(p) = config.prices.get(model).filter(|p| p.tier.is_some()) else { continue };
                let n = |k: &str| u[k].as_f64().unwrap_or(0.0);
                let c = &u["cache_creation"];
                let (w5, w1) = (c["ephemeral_5m_input_tokens"].as_f64().unwrap_or(0.0), c["ephemeral_1h_input_tokens"].as_f64().unwrap_or(0.0));
                let w5 = if w5 + w1 == 0.0 { n("cache_creation_input_tokens") } else { w5 };
                let (input, cached, output) = (n("input_tokens"), n("cache_read_input_tokens"), n("output_tokens"));
                ours += rate(&p.at(input + cached + w5 + w1), input, cached, output, w5, w1) - rate(p, input, cached, output, w5, w1);
            }
        }
        return Ok((micro(ours), reported(theirs), used));
    }
    let Some(t) = events.iter().rev().find(|v| v["type"] == "turn.completed") else { return Err("no result or turn.completed event".into()) };
    let n = |k: &str| t["usage"][k].as_f64().unwrap_or(0.0);
    let (cached, write) = (n("cached_input_tokens"), n("cache_write_input_tokens"));
    let input = (n("input_tokens") - cached - write).max(0.0);
    let p = price(model)?;
    Ok((micro(rate(p, input, cached, n("output_tokens"), write, 0.0)), None, HashMap::from([(model.clone(), p.clone())])))
}

/// How many of the program's requests sent a prompt over its model's tier
/// threshold (`Tier::above`), read as `generation` reads them: a `result`
/// with `"requests": 1` is one request per model, else each `assistant`
/// event is one. A model with no tier has no threshold to pass. With them,
/// what they cost beyond the base price, in microdollars. None where the
/// output says nothing per request (codex's running total).
fn over_tier(p: &Program, config: &Config, stdout: &str) -> Option<(u64, u64)> {
    if p.run.model.is_none() { return Some((0, 0)); }
    let events: Vec<serde_json::Value> = stdout.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).collect();
    let r = events.iter().rev().find(|v| v["type"] == "result")?;
    // Each request: its model and its tokens (input, cache reads, output, 5-minute and 1-hour cache writes).
    let mut requests: Vec<(String, [f64; 5])> = Vec::new();
    if r["requests"].as_u64() == Some(1) {
        for (model, u) in r["modelUsage"].as_object().into_iter().flatten() {
            let n = |k: &str| u[k].as_f64().unwrap_or(0.0);
            let (w5, w1) = (n("cacheCreationEphemeral5mInputTokens"), n("cacheCreationEphemeral1hInputTokens"));
            let w5 = if w5 + w1 == 0.0 { n("cacheCreationInputTokens") } else { w5 };
            requests.push((model.clone(), [n("inputTokens"), n("cacheReadInputTokens"), n("outputTokens"), w5, w1]));
        }
    } else {
        let mut by: HashMap<String, (String, serde_json::Value)> = HashMap::new();
        for v in events.iter().filter(|v| v["type"] == "assistant") {
            let m = &v["message"];
            if let (Some(id), Some(model)) = (m["id"].as_str(), m["model"].as_str()) { by.insert(id.into(), (model.into(), m["usage"].clone())); }
        }
        for (model, u) in by.into_values() {
            let n = |k: &str| u[k].as_f64().unwrap_or(0.0);
            let c = &u["cache_creation"];
            let (w5, w1) = (c["ephemeral_5m_input_tokens"].as_f64().unwrap_or(0.0), c["ephemeral_1h_input_tokens"].as_f64().unwrap_or(0.0));
            let w5 = if w5 + w1 == 0.0 { n("cache_creation_input_tokens") } else { w5 };
            requests.push((model, [n("input_tokens"), n("cache_read_input_tokens"), n("output_tokens"), w5, w1]));
        }
    }
    let rate = |p: &Price, t: &[f64; 5]| (t[0] * p.input + t[1] * p.cached_input + t[2] * p.output + t[3] * p.cache_write + t[4] * p.cache_write_long) / 1_000_000.0;
    let (mut count, mut beyond) = (0, 0.0);
    for (model, t) in &requests {
        let Some(price) = config.prices.get(model) else { continue };
        let Some(tier) = &price.tier else { continue };
        if t[0] + t[1] + t[3] + t[4] > tier.above as f64 { count += 1; beyond += rate(&price.at(f64::INFINITY), t) - rate(price, t); }
    }
    Some((count, micro(beyond)))
}

/// How many lines and bytes of a failing check's output a prompt carries.
const FAILING_LINES: usize = 150;
const FAILING_BYTES: usize = 12_000;

/// The informative part of a check's log (`supervised`'s: an exit line, then
/// its stdout and stderr): each error and each failed test first (a block from
/// a line starting `error`, or `---- ` and its first paragraph, to the next blank line), then, if there
/// is none, the output's last lines; bounded by FAILING_LINES and FAILING_BYTES.
fn informative(log: &str) -> String {
    let log = log.strip_prefix("cached: ").map_or(log, |t| t.split_once('\n').map_or("", |(_, r)| r));
    let exit = log.lines().next().unwrap_or("").to_string();
    let output: Vec<&str> = log.lines().filter(|l| !["seconds: ", "exit: ", "--- std", "program: ", "context: ", "behavior: "].iter().any(|h| l.starts_with(h))).collect();
    let mut errors: Vec<&str> = Vec::new();
    // A block ends at the first blank line after its header's first content
    // line: a failed test's block opens with a blank line before its panic.
    let (mut inside, mut content) = (false, false);
    for l in &output {
        let t = l.trim_start();
        if t.starts_with("error") || t.starts_with("---- ") { inside = true; content = t.starts_with("error"); errors.push(l); continue; }
        if inside { errors.push(l); }
        if l.trim().is_empty() { if content { inside = false; } } else { content = true; }
    }
    let lines: Vec<&str> = if errors.is_empty() { output[output.len().saturating_sub(FAILING_LINES)..].to_vec() } else { errors };
    let mut out = format!("{exit}\n");
    for (k, l) in lines.iter().enumerate() {
        if k >= FAILING_LINES || out.len() + l.len() > FAILING_BYTES {
            out.push_str(&format!("[… {} more lines]\n", lines.len() - k));
            break;
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// The checks that rejected commit, each as its command and the informative
/// part of its output: trunk's head (start) from this bon process's trunk
/// logs (`trunk-test-K`, `trunk-verify-K`); a candidate from the logs in its
/// trace, which its commit message names (`Trace:`): its test, verify, agree
/// and rank checks. Empty when none failed or none was logged.
fn rejected_by(m: &Manifest, commit: &str, start: &str, rank: Option<&String>) -> Vec<(String, String)> {
    let c = &m.config.checks;
    let mut logs: Vec<(String, String)> = Vec::new();
    let dir = if commit == start {
        for (k, v) in c.test.iter().enumerate() { logs.push((format!("trunk-test-{k}"), v.clone())); }
        for (k, v) in c.verify.iter().enumerate() { logs.push((format!("trunk-verify-{k}"), v.clone())); }
        trace_dir(&m.root)
    } else {
        let message = git(&m.root, &["log", "-1", "--format=%B", commit]).unwrap_or_default();
        let Some(trace) = message.lines().find_map(|l| l.strip_prefix("Trace: ")) else { return Vec::new() };
        for (k, v) in c.test.iter().enumerate() { logs.push((format!("test-{k}"), v.clone())); }
        for (k, v) in c.verify.iter().enumerate() { logs.push((format!("verify-{k}"), v.clone())); }
        for (k, v) in c.agree.iter().enumerate() { logs.push((format!("agree-{k}"), v.clone())); }
        if let Some(r) = rank { logs.push(("rank".into(), r.clone())); }
        m.root.join(trace.trim())
    };
    logs.into_iter().filter_map(|(file, command)| {
        let text = informative(&std::fs::read_to_string(dir.join(file)).ok()?);
        (!text.starts_with("exit: 0\n")).then_some((command, text))
    }).collect()
}

/// A search's context as its prompt carries it: for each commit in order
/// (trunk's head first), each check that rejected it and why, an output
/// identical to one already shown once, with who showed it. The whole is
/// bounded as one failing check is (FAILING_LINES, FAILING_BYTES): trunk's
/// first; what does not fit after it is left out whole, never cut, and how
/// many were is said in one line.
fn rendered(m: &Manifest, kind: &Kind, start: &str, context: &[String]) -> String {
    let rank = m.config.checks.rank.get(if matches!(kind, Kind::Compaction { .. }) { "compaction" } else { "code" });
    // (command, output, the commits it rejected so)
    let mut items: Vec<(String, String, Vec<String>)> = Vec::new();
    for commit in context {
        for (command, text) in rejected_by(m, commit, start, rank) {
            match items.iter_mut().find(|i| i.0 == command && i.1 == text) {
                Some(i) => i.2.push(commit.clone()),
                None => items.push((command, text, vec![commit.clone()])),
            }
        }
    }
    let (mut out, mut lines, mut left) = (String::new(), 0usize, 0usize);
    for (command, text, commits) in &items {
        let others: Vec<String> = commits.iter().filter(|c| *c != start).map(|c| c[..c.len().min(8)].to_string()).collect();
        let mut who: Vec<String> = Vec::new();
        if commits.iter().any(|c| c == start) { who.push("trunk".into()); }
        if !others.is_empty() {
            who.push(format!("{} {} of the previous attempt ({})", others.len(), if others.len() == 1 { "candidate" } else { "candidates" }, others.join(", ")));
        }
        let item = format!("This check fails on {}: {command}\n{text}", who.join(" and on "));
        let n = item.lines().count();
        if !out.is_empty() && (out.len() + item.len() > FAILING_BYTES || lines + n > FAILING_LINES) { left += 1; continue; }
        out.push_str(&item);
        lines += n;
    }
    if left > 0 { out.push_str(&format!("[{left} more failing {} left out whole: {} did not fit]\n", if left == 1 { "check" } else { "checks" }, if left == 1 { "it" } else { "they" })); }
    out
}

/// What a push changes, for the agent processes that test it: the spec's diff
/// since bon's last push (for blind tests, which see the spec and not the code),
/// and the selected candidate's diff against its base (for foils). Capped, so a
/// large change still fits.
fn aim(m: &Manifest, kind: &Kind, target: Option<&Search>, start: &str, context: &[String]) -> String {
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
        // Which check rejects trunk and why, and the previous attempt's
        // candidates: each command and its errors, exactly the search's
        // context, so the agent process knows what fails before it reads a file.
        Kind::Code { .. } | Kind::Compaction { .. } | Kind::Spec { .. } => rendered(m, kind, start, context),
        _ => String::new(),
    }
}

/// What a search of this kind may not change besides the checks: the build
/// configuration, bon's directory (but for a queue search, which writes the
/// queue there), the trusted code, and for code and foils the counterexamples' tests.
fn fixed(kind: &Kind, config: &Config) -> Vec<String> {
    let trusted = config.account.as_ref().and_then(|s| s.get("trusted")).and_then(|t| t.as_array()).into_iter().flatten()
        .filter_map(|p| p.as_str().map(String::from));
    let bon = (!matches!(kind, Kind::Queue { .. })).then(|| format!("{BON}/"));
    let tests = if matches!(kind, Kind::Code { .. } | Kind::Foil { .. }) { config.counterexample.tests.clone() } else { Vec::new() };
    BUILD.iter().map(|p| p.to_string()).chain(bon).chain(trusted).chain(tests).collect()
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
        Kind::Spec { goal, files } => format!(
            "engineer accepted this intent, which the spec does not state yet: \"{}\". Change the spec so that \
             it states it: you may change {:?} alone, the spec's files. Give each new type, field, variant, \
             predicate, transition or gate a /// sentence saying what it is. The spec must verify by itself \
             (Verus on those files alone); the code need not follow yet. Nothing you write is pushed: engineer \
             reads every agent process's change side by side and applies one.\n",
            goal.iter().collect::<String>(), files.iter().map(|f| f.iter().collect::<String>()).collect::<Vec<_>>()),
    };
    // A spec search writes some of the checks: the spec's files.
    let checks = match kind {
        Kind::Spec { .. } => format!("The other checks are {:?}: read and run them, never change them; you cannot.", config.checks.paths),
        _ => format!("The checks are {:?}: read and run them, never change them; you cannot.", config.checks.paths),
    };
    format!(
        "You are working in a copy of a repository, with no git. {goal}{aim}\n\
         {checks}\n\
         Never change {fixed:?} either: a change to any of them is refused or rejected.\n\
         The tests run with: {test:?}. Verus runs with: {verify:?}.{staged}\n\
         {scope} Reply with one line saying what you changed.",
        test = config.checks.test, verify = config.checks.verify, fixed = fixed(kind, config),
        staged = if config.checks.staged.is_empty() { String::new() } else { format!(" Before a push, the selected candidate must also pass: {:?}.", config.checks.staged) },
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
    renamed(&text, false).map_err(|e| format!("{MANIFEST}: {e}"))?;
    let mut config: Config = toml::from_str(&text).map_err(|e| format!("{MANIFEST}: {e}"))?;
    config.root = root.clone();
    let file = host_file()?;
    let config = with_host(config, read_host(&file)?, &file)?;
    ancestor_guard(guard_uid(&root))?;
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

/// The trusted code the manifest's account declares: no search may change it.
#[verifier::external_body]
pub fn trusted(m: &Manifest) -> Vec<Path> {
    m.config.account.as_ref().and_then(|s| s.get("trusted")).and_then(|t| t.as_array())
        .map(|a| a.iter().filter_map(|p| p.as_str()).map(|p| p.chars().collect()).collect()).unwrap_or_default()
}

/// What a search of this kind runs: its role, as the host file maps it.
#[verifier::external]
fn program(config: &Config, kind: &Kind) -> Program {
    let role = config.searches.of(kind).role.clone();
    let run = config.roles.get(&role).cloned().unwrap_or(Role { program: Vec::new(), client: None, model: None, context: None });
    Program { role, run }
}

/// How many agent processes a width list runs on attempt `a`.
#[verifier::external]
fn at(n: &[usize], a: usize) -> usize { n.get(a).or(n.last()).copied().unwrap_or(0) }

/// Whether a client's own status command says it is logged in, from its exit and output.
#[verifier::external]
fn logged_in(client: &str, ok: bool, out: &str) -> bool {
    match client {
        "claude" => out.contains("\"loggedIn\": true") || out.contains("\"loggedIn\":true"),
        _ => ok && out.contains("Logged in"),
    }
}

/// Before a search: the client of each role bon.toml names can reach its
/// model as agent, checked the way bon runs it: the claude and codex CLIs are
/// logged in, and agent can read the API's key file. If one cannot, the
/// command that fixes it. (queue 32)
#[verifier::external_body]
pub fn programs_logged_in(m: &Manifest) -> (r: Result<(), String>) {
    let mut clients: Vec<String> = m.config.searches.all().iter()
        .filter_map(|(_, e)| m.config.roles.get(&e.role).and_then(|r| r.client.clone())).collect();
    clients.sort(); clients.dedup();
    for client in clients {
        let argv: Vec<String> = match client.as_str() {
            "claude" => vec!["claude".into(), "auth".into(), "status".into()],
            "codex" => vec!["codex".into(), "login".into(), "status".into()],
            _ => {
                let key = m.config.api.as_ref().map(|a| a.key_file.clone()).unwrap_or_default();
                let readable = as_agent(&m.config, std::path::Path::new("/tmp"), &[], &["test".into(), "-s".into(), key.clone()]).status().is_ok_and(|s| s.success());
                if !readable { return Err(format!("agent cannot read the API's key file {key}; write the key there, readable by agent")); }
                continue;
            }
        };
        let (ok, out) = match as_agent(&m.config, std::path::Path::new("/tmp"), &[], &argv).output() {
            Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)),
            Err(e) => (false, e.to_string()),
        };
        if !logged_in(&client, ok, &out) {
            let fix = match client.as_str() { "claude" => "sudo -u agent -i claude", _ => "sudo -u agent -i codex login" };
            return Err(format!("{client} is not logged in as agent; run: {fix}"));
        }
    }
    Ok(())
}

/// Whether `$1` runs: a name is looked up on PATH, a path is that file; each
/// failure says why, on stdout, and exits 1.
/// A name is looked for as env looks for it, an executable file in a PATH
/// directory (a shell builtin is no answer); a relative path is the working
/// directory's, which exists only once the search runs, so it is not checked.
pub const PROBE: &'static str = "case \"$1\" in /*) p=\"$1\";; */*) exit 0;; *) p=; IFS=:; for d in $PATH; do [ -f \"$d/$1\" ] && [ -x \"$d/$1\" ] && { p=\"$d/$1\"; break; }; done
  [ -n \"$p\" ] || { echo \"not found on agent's PATH\"; exit 1; };; esac
[ -e \"$p\" ] || { echo \"$p does not exist\"; exit 1; }; [ -f \"$p\" ] && [ -x \"$p\" ] || { echo \"$p is not executable by agent\"; exit 1; }";

/// Before a search, before anything is reserved: the program of each role
/// bon.toml names is found and executable as agent, on agent's PATH, the way
/// an agent process runs it. If one is not, which role and program, and why.
#[verifier::external_body]
pub fn programs_executable(m: &Manifest) -> (r: Result<(), String>) {
    let mut roles: Vec<String> = m.config.searches.all().iter().map(|(_, e)| e.role.clone()).collect();
    roles.sort(); roles.dedup();
    for role in roles {
        let Some(program) = m.config.roles.get(&role).and_then(|r| r.program.first()).cloned() else {
            return Err(format!("role {role} has no program in the host file; give [roles.{role}] a program"));
        };
        let out = as_agent(&m.config, std::path::Path::new("/tmp"), &[], &["/bin/sh".into(), "-c".into(), PROBE.into(), "sh".into(), program.clone()]).output();
        let why = match out {
            Ok(o) if o.status.success() => continue,
            // The probe's own line; what the shell or sudo said, only when it said nothing.
            Ok(o) => Some(String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty())
                .unwrap_or_else(|| String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("").trim().to_string()),
            Err(e) => format!("bon could not run as agent: {e}"),
        };
        return Err(format!("agent cannot execute {program} (role {role}): {why}; make it executable by agent, or name another program in the host file"));
    }
    Ok(())
}

/// Whether an agent process's program never started: it wrote nothing, and
/// it could not be spawned, or `env` could not run it (126: found but not
/// executable; 127: not found). It reached no model and is charged nothing;
/// so is one that wrote nothing and exited non-zero (`silent`): there is no
/// token count to charge, and its exit is flagged, not a spent limit.
#[verifier::external]
fn never_started(run: &Run) -> bool {
    !run.killed && run.stdout.is_empty() && (!run.spawned || matches!(run.exit, Some(126 | 127)))
}

/// How many agent processes a search of this kind runs on attempt `a`.
#[verifier::external_body]
pub fn width(m: &Manifest, kind: &Kind, a: usize) -> usize {
    at(&m.config.searches.of(kind).n, a)
}

/// How many attempts a command of one kind makes: its width list's length.
#[verifier::external_body]
pub fn attempts_of(m: &Manifest, kind: &Kind) -> usize { m.config.searches.of(kind).n.len() }

/// How many attempts a command makes: the longest width list.
#[verifier::external_body]
pub fn attempts(m: &Manifest) -> usize {
    m.config.searches.all().iter().map(|(_, e)| e.n.len()).max().unwrap_or(1)
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
    // The verdicts that make it land, checked again from a clean build; a
    // differing one stops the bon process, landing nothing.
    if let Err(e) = recheck(m, &commit) { stop(&m.root, &e) }
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

/// Every test, verify and staged check on a commit, run as a check slot's user in a
/// checkout without `.git`, the way candidates are judged; each one's name,
/// whether it exited 0, and its log. All of them run, not only until one fails.
#[verifier::external]
pub fn check(m: &Manifest, commit: &Commit) -> Result<Vec<(String, bool, PathBuf)>, String> {
    let (config, root) = (&m.config, &m.root);
    let c: String = commit.iter().collect();
    let dir = scratch(&format!("check/{}", repository_name(root)));
    check_directory(root, &c, &dir)?;
    let build = named_build("check.build/build", Start::Empty);
    let log = trace_dir(root);
    traced(&log, std::fs::create_dir_all(&log));
    let mut out = Vec::new();
    let on = On::commit(root, &c);
    // One slot for them all: they build in one directory, its user's.
    holding(|| for (kind, list) in [("test", &config.checks.test), ("verify", &config.checks.verify), ("staged", &config.checks.staged)] {
        for (k, v) in list.iter().enumerate() {
            let path = log.join(format!("check-{kind}-{k}"));
            // engineer waits on it alone: every core.
            let ok = run_check_with(config, &on, cores(), &dir, &build, v, &path).0;
            out.push((v.clone(), ok, path));
        }
    });
    remove_build(config, &build);
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

/// Each confined user's effective permissions on every path of each object
/// the policy names, observed by asking as that user: agent's, and each check
/// slot's user's (`check<k>`, k below the host's check_processes), on probes
/// made the way real ones are (a working directory, a check's checkout, a
/// kept build, each slot's build directory). A path that does not exist is
/// reported as missing (None), never as the policy's value. Err is an
/// observation that could not be made (a user cannot be asked, a path cannot
/// be looked at), never a denial.
#[verifier::external_body]
pub fn observe(m: &Manifest, commit: &Commit) -> (r: Result<(Observation, Vec<Observation>), String>) {
    let c: String = commit.iter().collect();
    let name = repository_name(&m.root);
    let slots = m.config.pools.check_processes;
    let probes: Vec<PathBuf> = ["probe", "probe.check", "probe.builds"].iter().map(|p| scratch(p))
        .chain((0..slots).map(|j| scratch(&format!("probe.{j}.build")))).collect();
    let r = (|| -> Result<(Observation, Vec<Observation>), String> {
        let working = probes[0].join(&name);
        working_directory(&m.root, &m.config, &c, &working).map_err(|e| format!("agent is not set up ({e}); run bon setup"))?;
        let checkout = probes[1].join(&name);
        check_directory(&m.root, &c, &checkout)?;
        // A checkout is each slot's user's to read while its checks run (B4);
        // the policy still has every check slot's user reading the checks, so
        // the probe grants the read each slot's user would get on its own.
        for j in 0..slots { checkout_readable(&checkout, Who::Check(j)); }
        // A kept build, as `keep` leaves one: engineer's, group bon, writable by no one else.
        let builds = probes[2].join("build");
        std::fs::create_dir_all(builds.join("debug")).map_err(|e| e.to_string())?;
        std::fs::write(builds.join("debug/libkept.rlib"), "").map_err(|e| e.to_string())?;
        sh(&probes[2], "chmod", &["-R", "go-w", "."])?;
        let mut kept = vec![probes[2].clone(), builds];
        for e in std::fs::read_dir(WORKING_DIRECTORIES).into_iter().flatten().flatten() {
            if e.file_name().to_string_lossy().starts_with("trunk-") { kept.extend([e.path(), e.path().join("build")].into_iter().filter(|p| p.exists())); }
        }
        // Each slot's build directory, as `ensure_build` makes one (empty).
        let slot_builds: Vec<Vec<PathBuf>> = (0..slots).map(|j| {
            let d = probes[3 + j].join("build");
            slots_alone(&d, Who::Check(j)).map(|_| vec![d])
        }).collect::<Result<_, _>>()?;
        let state = vec![state_dir().ok_or("no state for the user layer: the host file's `user` names its root, which must be a directory bon can make its own `.bon` in")?];
        // The toolchain: the host file's homes, the dependency sources in cargo's
        // (its registry, each registry's unpacked sources, its git checkouts),
        // and every directory on the checks' PATH.
        let mut toolchain: Vec<PathBuf> = m.config.toolchain.iter().map(|(_, v)| PathBuf::from(v)).collect();
        if let Some((_, home)) = m.config.toolchain.iter().find(|(k, _)| k == "CARGO_HOME") {
            let home = PathBuf::from(home);
            toolchain.extend([home.join("registry"), home.join("registry/src"), home.join("git")]);
            toolchain.extend(std::fs::read_dir(home.join("registry/src")).into_iter().flatten().flatten().map(|e| e.path()));
        }
        toolchain.extend(checks_path(&m.config).iter().map(PathBuf::from));
        let transcripts = m.config.transcripts.clone().unwrap_or("transcripts".into());
        // The checks and the transcripts as each user meets them: agent in a
        // working directory, a check slot's user in a check's checkout. A
        // repository without transcripts observes them on no path.
        let met = |at: &std::path::Path| -> (Vec<PathBuf>, Vec<PathBuf>) {
            (m.config.checks.paths.iter().map(|p| at.join(p.trim_end_matches('/'))).collect(),
             Some(at.join(&transcripts)).filter(|t| t.exists()).into_iter().collect())
        };
        let ask = |who: Who, at: &std::path::Path| -> Result<Observation, String> {
            let (checks, transcripts) = met(at);
            let objects = [checks, transcripts, vec![working.clone()], vec![m.root.join(".git")], vec![PathBuf::from(WORKING_DIRECTORIES)],
                           toolchain.clone(), kept.clone(), state.clone()];
            let all: Vec<PathBuf> = objects.iter().chain(slot_builds.iter()).flatten().cloned().collect();
            let mut seen = permissions_as(who, &all)?.into_iter();
            let mut take = |paths: &Vec<PathBuf>| -> Vec<Option<Permission>> { paths.iter().filter_map(|_| seen.next()).collect() };
            let [a, b, c, d, e, f, g, h] = objects.each_ref().map(&mut take);
            let build_directories = slot_builds.iter().map(&mut take).collect();
            Ok(Observation { checks: a, transcripts: b, working_directory: c, repository: d, working_directories: e, toolchain: f, builds: g, state: h, build_directories })
        };
        let agent = ask(Who::Agent, &working)?;
        let checks = (0..slots).map(|k| ask(Who::Check(k), &checkout)).collect::<Result<Vec<_>, _>>()?;
        Ok((agent, checks))
    })();
    for p in &probes {
        let _ = Command::new("chmod").args(["-R", "-N"]).arg(p).stderr(Stdio::null()).status();
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(p).stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(p);
    }
    r
}

} // verus!

/// `who`'s permissions on each path, asked as `who` in one process: test(1)
/// exits 0 (allowed) or 1 (denied), anything else is no answer. A path that
/// does not exist, as bon's own process sees it, is None; one that cannot be
/// looked at is an error. A check that is a file is run by an interpreter that
/// reads it (sh, cargo), so for a file, execute is whether `who` can read it.
fn permissions_as(who: Who, paths: &[PathBuf]) -> Result<Vec<Option<Permission>>, String> {
    let present = |path: &std::path::Path| -> Result<bool, String> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("cannot observe {}: {e}", path.display())),
        }
    };
    const ASK: &str = r#"for p; do test -r "$p"; r=$?; test -w "$p"; w=$?; test -x "$p"; x=$?; echo "$r $w $x"; done"#;
    let out = Command::new("sudo").args(["-n", "-u", &who.name(), "/bin/sh", "-c", ASK, "sh"]).args(paths)
        .current_dir("/tmp").stdin(Stdio::null()).output().map_err(|e| format!("cannot ask as {}: {e}; run bon setup", who.name()))?;
    let lines: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().map(String::from).collect();
    if !out.status.success() || lines.len() != paths.len() {
        return Err(format!("cannot ask as {} (sudo -n -u {}): {}; run bon setup", who.name(), who.name(), String::from_utf8_lossy(&out.stderr).trim()));
    }
    paths.iter().zip(lines).map(|(path, line)| {
        if !present(path)? {
            eprintln!("bon: missing, as {}: {}", who.name(), path.display());
            return Ok(None);
        }
        let bit = |code: &str| match code { "0" => Ok(true), "1" => Ok(false), _ => Err(format!("cannot ask as {} about {}: {line}", who.name(), path.display())) };
        let codes: Vec<&str> = line.split(' ').collect();
        let [r, w, x] = codes[..] else { return Err(format!("cannot ask as {} about {}: {line}", who.name(), path.display())) };
        let p = Permission { read: bit(r)?, write: bit(w)?, execute: bit(x)? };
        Ok(Some(if path.is_dir() { p } else { Permission { execute: p.read, ..p } }))
    }).collect()
}

verus! {

/// Run a search's agent processes in parallel and observe each: its candidate
/// (None if it produced none) and its cost in microdollars. `target` is the
/// search a counterexample attacks; `foils`, the foil search its tests must
/// tell from correct code.
#[verifier::external_body]
pub fn run(m: &Manifest, kind: &Kind, a: usize, start: &Commit, target: Option<&Search>, foils: Option<&Search>, context: &Vec<Commit>) -> Vec<(Option<Candidate>, u64)> {
    // Number runs once per bon process, so a command that runs several drivers
    // (a counterexample on trunk, then a code search) never reuses a working directory or trace.
    let search = RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut l) = LATEST.lock() { *l = label(kind); }
    let start: String = start.iter().collect();
    let context: Vec<String> = context.iter().map(|c| c.iter().collect()).collect();
    search_started(&m.root, search, kind, a, &tree_of(&m.root, &start));
    if !WARMING.load(std::sync::atomic::Ordering::SeqCst) { warm(m, &start); }
    let p = program(&m.config, kind);
    let slots: Vec<Program> = std::iter::repeat(p).take(width(m, kind, a)).collect();
    let traces = trace_dir(&m.root).join(search.to_string());
    traced(&traces, std::fs::create_dir_all(&traces));
    // Every agent process at once: the agent_processes pool bounds them, the
    // check pool their checks and the judge's. The first leads: the rest
    // start once it has written its first output (or ended), so a program
    // whose sessions open alike (the same prompt, the same files) has its
    // prefix cached by the first, and the rest read it.
    let out: Vec<std::sync::Mutex<(Option<Candidate>, u64)>> = slots.iter().map(|_| std::sync::Mutex::new((None, 0))).collect();
    let spoke = std::sync::Arc::new(Signal::default());
    std::thread::scope(|scope| {
        for (i, h) in slots.iter().enumerate() {
            let (out, start, traces, spoke, context) = (&out, &start, &traces, &spoke, &context);
            scope.spawn(move || {
                // Whatever the leader does, the rest go on when it is done.
                struct Spoken<'a>(&'a Signal);
                impl Drop for Spoken<'_> { fn drop(&mut self) { self.0.set(); } }
                let _spoken = (i == 0).then(|| Spoken(spoke));
                if i > 0 { spoke.wait(); }
                let lead = (i == 0).then(|| spoke.clone());
                *out[i].lock().unwrap() = agent_process(m, kind, search, i, h, start, target, foils, context, &traces.join(i.to_string()), lead);
            });
        }
    });
    out.into_iter().map(|c| c.into_inner().unwrap_or((None, 0))).collect()
}

/// The selected candidate is pushed to the remote's trunk. What decided it
/// (its test and verify checks, and its agree and rank checks) is checked
/// again first, from a clean build and never from the verdict cache: a result
/// that differs stops the bon process with that check named suspect, and
/// nothing is pushed. Beside it the staged checks run on it, once: one that
/// fails stops the bon process the same way. The push is fast-forward only: if the remote's trunk
/// moved, it is refused and nothing changes. The engineer's branch is left
/// alone: pull to follow. (TCB: git, the remote)
#[verifier::external_body]
pub fn push(m: &Manifest, commit: &Commit) -> (r: Result<(), String>) {
    let c: String = commit.iter().collect();
    // The staged checks run beside the re-check, each in the one clean build they share.
    let (rechecked, passed) = std::thread::scope(|s| {
        let st = s.spawn(|| staged(m, &c));
        (recheck(m, &c), st.join().unwrap_or_else(|_| Err("a staged check could not run; nothing was pushed".into())))
    });
    if let Err(e) = rechecked.and(passed) { stop(&m.root, &e) }
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
/// rate; t is engineer's time charged to the search: each interval of its wall
/// time split equally among the searches he waits on that run in it, on the
/// process list (`search_ended`); v is how many candidates the verified gate
/// passed.
#[verifier::external_body]
pub fn report(m: &Manifest, s: &Search, verified: usize, generation: u64, started: Clock) {
    let n = s.n;
    let search = RUNS.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
    let charged = search_ended();
    let hours = started.at.elapsed().as_secs_f64() / 3600.0;
    let generation = generation as f64 / 1_000_000.0;
    // Background work is charged no time: no one waited on it.
    let background = BACKGROUND.load(std::sync::atomic::Ordering::SeqCst);
    let rate = if background { 0.0 } else { m.config.rate };
    let time = rate * charged / 3600.0;
    let per = if verified == 0 { None } else { Some((generation + time) / verified as f64) };
    let line = format!(
        "search {search}: {n} agent processes, {verified} verified; generation ${generation:.4} + time ${time:.4} ({charged:.0}s of {:.0}s at ${}/h) = {}",
        hours * 3600.0, rate,
        per.map_or("no verified candidate".to_string(), |p| format!("${p:.4} per verified candidate")));
    eprintln!("bon: {line}");
    let d = trace_dir(&m.root);
    let (kind, goal) = LATEST.lock().map(|l| l.clone()).unwrap_or_default();
    let summary = serde_json::json!({
        "search": search, "kind": kind, "goal": goal,
        "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        "agent_processes": n, "limit": s.limit as f64 / 1_000_000.0,
        // The commits whose verdicts its prompt carried (the kernel's context).
        "context": s.context.iter().map(|c| c.iter().collect::<String>()).collect::<Vec<_>>(), "verified": verified, "generation_dollars": generation,
        "seconds": hours * 3600.0, "charged_seconds": charged, "rate": rate, "background": background, "time_dollars": time,
        "cost_per_verified_candidate": per,
        // The host's semaphores in force for this search.
        "host": { "agent_processes": m.config.pools.agent_processes, "check_processes": m.config.pools.check_processes },
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

/// grant: its width, when, each agent process's limit, its kind and goal;
/// then, on a line of its own (the grant line's tail is the goal), its
/// context: `context` and each commit. The last search is the one granted,
/// on the trunk verdict its kind needs, with this context.
#[verifier::external_body]
pub fn record_grant(m: &Manifest, kind: &Kind, n: usize, agent_process_limit: u64, context: &Vec<Commit>, Ghost(checks_accept): Ghost<bool>, Ghost(searches): Ghost<Seq<spec::Search>>)
    requires
        searches.len() > 0,
        kind@ is Code ==> !checks_accept,
        kind@ is Compaction || kind@ == (spec::Kind::Counterexample { goal: None }) ==> checks_accept,
        searches.last().kind == kind@,
        searches.last().n == n as nat,
        searches.last().limit == agent_process_limit as nat,
        searches.last().context == crate::gates::commits(context@),
{
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (k, goal) = label(kind);
    record(m, &format!("grant {n} {now} {agent_process_limit} {k} {goal}"));
    record(m, &std::iter::once("context".to_string()).chain(context.iter().map(|c| c.iter().collect())).collect::<Vec<_>>().join(" "));
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
        spec::Blocked::Undecided => ("undecided", "the verified candidates disagree, two tests judged every one, and none splits them: the spec does not decide between them"),
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
    let _ = wait_warm(&m.config);
    let build = named_build("goal.build/build", Start::Trunk);
    let log = trace_dir(&m.root);
    traced(&log, std::fs::create_dir_all(&log));
    let mut out = Vec::new();
    let on = On::commit(&m.root, &c);
    holding(|| for (k, a) in m.config.checks.agree.iter().enumerate() {
        out.push(Hash(hash(&run_check(&m.config, &on, &dir, &build, a, &log.join(format!("goal-agree-{k}"))).1)));
    });
    remove_build(&m.config, &build);
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(out)
}

} // verus!

/// bon's directory in a repository, and what it tracks there.
pub const BON: &str = ".bon";

// ── how a bon process that searches ends ────────────────

/// A bon process that searches ends here: on an error it records `exited:
/// <error>` in its transitions (unless its last line, a block, already says
/// why it ended), removes its working directories, commits its traces (and
/// pushes them to the manifest's `traces` remote), takes itself off the process
/// list, and exits 1 with the error;
/// otherwise 0.
pub fn end(root: &std::path::Path, result: Result<(), String>) -> ! {
    if let Err(e) = &result { record_exited(root, e); }
    cleanup(&["/usr/bin".into(), "/bin".into()]);
    if let Err(e) = persist(root) { eprintln!("bon: traces not persisted: {e}"); }
    leave();
    let _ = std::io::stdout().flush();
    match result {
        Ok(()) => std::process::exit(0),
        // One line, whatever the error carried.
        Err(e) => { eprintln!("bon: {}", e.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; ")); std::process::exit(1) }
    }
}

/// Stop the bon process on an error found where nothing may go on (a suspect
/// check before a push): as `end` does.
pub fn stop(root: &std::path::Path, error: &str) -> ! { end(root, Err(error.to_string())) }

/// `exited: <error>`, on one line, appended to this bon process's transitions,
/// unless their last line is a block, which already says why it ended.
pub fn record_exited(root: &std::path::Path, error: &str) {
    let file = trace_dir(root).join("transitions");
    let last = std::fs::read_to_string(&file).unwrap_or_default().lines().last().unwrap_or("").to_string();
    if last.starts_with("blocked") { return; }
    append_line(&file, &format!("exited: {}", error.split_whitespace().collect::<Vec<_>>().join(" ")));
}

/// The traces are their own git repository, apart from this one's (they hold
/// prompts, arguments and outputs): commit what this command added, and push to
/// the private remote the manifest names in `traces`, if it names one.
pub fn persist(root: &std::path::Path) -> Result<(), String> {
    let d = root.join(".bon/traces");
    if !d.is_dir() { return Ok(()); }
    let manifest: toml::Value = toml::from_str(&std::fs::read_to_string(root.join(".bon/bon.toml")).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let remote = manifest.get("traces").and_then(|v| v.as_str());
    if remote.is_some_and(|r| git(root, &["remote", "get-url", "origin"]).is_ok_and(|o| o == r)) {
        return Err("traces names this repository's own remote; it must be a private one of its own".into());
    }
    if !d.join(".git").exists() {
        git(&d, &["init", "-q", "-b", "main"])?;
        std::fs::write(d.join(".gitignore"), "running\n").map_err(|e| e.to_string())?;
    }
    if let Some(r) = remote {
        if git(&d, &["remote", "get-url", "origin"]).is_ok() { git(&d, &["remote", "set-url", "origin", r])?; }
        else { git(&d, &["remote", "add", "origin", r])?; }
    }
    git(&d, &["add", "-A"])?;
    if git(&d, &["diff", "--cached", "--quiet"]).is_ok() { return Ok(()); }
    git(&d, &["-c", "user.name=bon", "-c", "user.email=bon@localhost", "commit", "-q", "-m", &format!("bon process {}", std::process::id())])?;
    if remote.is_some() { git(&d, &["push", "-q", "origin", "main"])?; }
    Ok(())
}
// ── the process list ────────────────────────────────────
//
// Each bon process that searches writes itself to the user layer's process
// list (OSTEP: a process list), by pid and start time, and takes itself off
// when it ends. An entry is a plain JSON file, `<state>/processes/<pid>.<start>.json`,
// another program can read:
//   pid, start         the process, and when it started (unix seconds)
//   repository         the repository it searches
//   trace              its trace directory's name, under the repository's .bon/traces
//   background         whether no one waits on it (bon background), so it is charged no time
//   search, kind, goal, attempt, tree, started
//                      the search it runs now: its index in this process's
//                      traces, its kind and goal, the attempt, the tree it
//                      starts from, and when it started; null between searches
// An entry whose pid and start time no longer match a live process is stale:
// it is ignored and removed.

/// This process's entry, once it has one.
static ENTRY: std::sync::Mutex<Option<(PathBuf, serde_json::Value)>> = std::sync::Mutex::new(None);

/// When each of `pids` started, by ps: unix seconds, now less its elapsed
/// time (`etime`), so to the second. A pid ps does not list is no live process.
fn started_at(pids: &[u64]) -> HashMap<u64, u64> {
    if pids.is_empty() { return HashMap::new(); }
    let list: Vec<String> = pids.iter().map(u64::to_string).collect();
    let out = Command::new("ps").args(["-o", "pid=,etime=", "-p", &list.join(",")]).stdin(Stdio::null()).stderr(Stdio::null()).output();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // [[dd-]hh:]mm:ss
    let elapsed = |t: &str| -> Option<u64> {
        let (days, rest) = match t.split_once('-') { Some((d, r)) => (d.parse::<u64>().ok()?, r), None => (0, t) };
        Some(days * 86400 + rest.split(':').try_fold(0u64, |a, p| Some(a * 60 + p.parse::<u64>().ok()?))?)
    };
    out.map(|o| String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| {
        let mut f = l.split_whitespace();
        Some((f.next()?.parse().ok()?, now.saturating_sub(elapsed(f.next()?)?)))
    }).collect()).unwrap_or_default()
}

/// Whether an entry's pid and start time match a live process: the pid is
/// one, started within a second or two of the entry's start (ps says the
/// start to the second, from the elapsed time).
fn matches_live(entry: &serde_json::Value, live: &HashMap<u64, u64>) -> bool {
    let (Some(pid), Some(start)) = (entry["pid"].as_u64(), entry["start"].as_u64()) else { return false };
    live.get(&pid).is_some_and(|s| s.abs_diff(start) <= 2)
}

/// The process list's directory, in the user layer's state.
fn process_list() -> Option<PathBuf> { state("processes") }

/// Every entry of the process list, read: those whose pid and start time
/// match a live process, and the pids of the stale ones, which are removed.
fn read_processes() -> (Vec<serde_json::Value>, Vec<u64>) {
    let Some(d) = process_list() else { return (Vec::new(), Vec::new()) };
    let entries: Vec<(PathBuf, serde_json::Value)> = std::fs::read_dir(&d).into_iter().flatten().flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .filter_map(|e| Some((e.path(), serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok()?))).collect();
    let live = started_at(&entries.iter().filter_map(|(_, v)| v["pid"].as_u64()).collect::<Vec<_>>());
    let (mut running, mut ended) = (Vec::new(), Vec::new());
    for (p, v) in entries {
        if matches_live(&v, &live) { running.push(v); } else {
            let _ = std::fs::remove_file(&p);
            if let Some(pid) = v["pid"].as_u64() { ended.push(pid); }
        }
    }
    (running, ended)
}

/// The bon processes the process list says are running, every repository's.
pub fn processes() -> Vec<serde_json::Value> { read_processes().0 }

/// The pids of the bon processes the process list says ended without taking
/// themselves off (their entries, stale, are removed).
fn ended_processes() -> Vec<String> { read_processes().1.iter().map(u64::to_string).collect() }

/// Write this process's entry, whole, then renamed into place.
fn write_entry(path: &std::path::Path, entry: &serde_json::Value) {
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, entry.to_string()).is_ok() { let _ = std::fs::rename(&tmp, path); }
}

/// This bon process, which searches in `root`, enters the process list, and
/// its time starts being charged as its searches run (`CHARGE`).
pub fn enter(root: &std::path::Path) {
    let pid = std::process::id();
    let Some(start) = started_at(&[u64::from(pid)]).get(&u64::from(pid)).copied() else { return };
    let entry = serde_json::json!({
        "pid": pid, "start": start, "repository": root.to_string_lossy(), "trace": null,
        "background": BACKGROUND.load(std::sync::atomic::Ordering::SeqCst),
        "search": null, "kind": null, "goal": null, "attempt": null, "tree": null, "started": null,
    });
    if let Some(d) = process_list() {
        let path = d.join(format!("{pid}.{start}.json"));
        write_entry(&path, &entry);
        *ENTRY.lock().unwrap_or_else(|e| e.into_inner()) = Some((path, entry));
    }
    std::thread::spawn(|| loop { std::thread::sleep(Duration::from_secs(1)); charge(); });
}

/// Change this process's entry (a search starts or ends), and write it.
fn update_entry(f: impl FnOnce(&mut serde_json::Value)) {
    if let Some((path, entry)) = ENTRY.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        f(entry);
        entry["background"] = serde_json::json!(BACKGROUND.load(std::sync::atomic::Ordering::SeqCst));
        write_entry(path, entry);
    }
}

/// This bon process takes itself off the process list.
fn leave() {
    if let Some((path, _)) = ENTRY.lock().unwrap_or_else(|e| e.into_inner()).take() { let _ = std::fs::remove_file(path); }
}

// ── engineer's time ─────────────────────────────────────
//
// Engineer's time is charged once per wall-clock interval in which a search
// he waits on runs, split equally among the searches running in it: those of
// every bon process on the process list (every repository's) that is not
// background. A background search is charged nothing, and counts in no split.

/// The running search's charge: the seconds charged to it so far, and since
/// when, split among how many waited-on searches.
struct Charge { charged: f64, since: Instant, among: f64 }

static CHARGE: std::sync::Mutex<Option<Charge>> = std::sync::Mutex::new(None);

/// How many searches someone waits on run now, by the process list, this
/// process's own counted; at least one. Whether each entry's process is live
/// is asked (one ps) every thirty seconds; between, the entries as they are.
fn waited_on() -> f64 {
    static ASKED: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let ask = { let mut a = ASKED.lock().unwrap_or_else(|e| e.into_inner());
        let due = a.is_none_or(|t| t.elapsed() >= Duration::from_secs(30)); if due { *a = Some(Instant::now()); } due };
    let entries: Vec<serde_json::Value> = if ask { processes() } else {
        process_list().map(|d| std::fs::read_dir(d).into_iter().flatten().flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
            .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok()).collect()).unwrap_or_default()
    };
    waiting(&entries)
}

/// How many of `entries`' searches someone waits on: those running (started)
/// that are not background; at least one, the search being charged.
fn waiting(entries: &[serde_json::Value]) -> f64 {
    entries.iter().filter(|p| !p["started"].is_null() && p["background"] != true).count().max(1) as f64
}

impl Charge {
    /// Charge the time since the last charge, split `among` the searches that
    /// ran in it; from now on, split among `next`.
    fn to(&mut self, now: Instant, next: f64) {
        self.charged += (now - self.since).as_secs_f64() / self.among;
        self.since = now;
        self.among = next;
    }
}

/// Charge the running search the time since the last charge, its share of it.
fn charge() {
    let among = if CHARGE.lock().unwrap_or_else(|e| e.into_inner()).is_some() { waited_on() } else { return };
    if let Some(c) = CHARGE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() { c.to(Instant::now(), among); }
}

/// A search starts: its entry says so, and its charge starts at nothing.
fn search_started(root: &std::path::Path, search: usize, kind: &Kind, a: usize, tree: &str) {
    let (k, goal) = label(kind);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let trace = trace_dir(root).file_name().map_or(String::new(), |n| n.to_string_lossy().to_string());
    update_entry(|e| {
        e["trace"] = serde_json::json!(trace);
        e["search"] = serde_json::json!(search); e["kind"] = serde_json::json!(k); e["goal"] = serde_json::json!(goal);
        e["attempt"] = serde_json::json!(a); e["tree"] = serde_json::json!(tree); e["started"] = serde_json::json!(now);
    });
    let among = waited_on();
    *CHARGE.lock().unwrap_or_else(|e| e.into_inner()) = Some(Charge { charged: 0.0, since: Instant::now(), among });
}

/// A search ends: what engineer's time it was charged, in seconds (none
/// for background work), and its entry says no search runs.
fn search_ended() -> f64 {
    charge();
    let charged = CHARGE.lock().unwrap_or_else(|e| e.into_inner()).take().map_or(0.0, |c| c.charged);
    update_entry(|e| for k in ["search", "kind", "goal", "attempt", "tree", "started"] { e[k] = serde_json::Value::Null; });
    if BACKGROUND.load(std::sync::atomic::Ordering::SeqCst) { 0.0 } else { charged }
}

pub const MANIFEST: &str = ".bon/bon.toml";
pub const QUEUE: &str = ".bon/queue.tsv";
pub const SBOM: &str = ".bon/sbom.json";
/// The build configuration cargo reads beside Cargo.toml, and the toolchain
/// files rustup reads: a check runs what they say, so a candidate may no more
/// write its own than it may write a check. Protected like a check.
pub const BUILD: [&str; 4] = [".cargo/", "build.rs", "rust-toolchain", "rust-toolchain.toml"];

/// One agent process: generate, capture, observe. Its log goes under `trace`.
/// `spoke`: the leader's signal, set at its program's first output.
#[allow(clippy::too_many_arguments)]
fn agent_process(m: &Manifest, kind: &Kind, search: usize, index: usize, p: &Program, start: &str,
                 target: Option<&Search>, foils: Option<&Search>, context: &[String], trace: &std::path::Path, spoke: Option<std::sync::Arc<Signal>>) -> (Option<Candidate>, u64) {
    traced(trace, std::fs::create_dir_all(trace));
    let config = &m.config;
    // An agent process's slot for its program and its setup alone: never
    // held while its candidate is judged.
    let session = Slot::agent_process(config);
    let dir = scratch(&format!("{search}.{index}/{}", repository_name(&m.root)));
    // What each kind may not write, made structural: code, the counterexamples' tests.
    // A queue search writes the queue, and a spec search the spec's files, among what is protected.
    let (writable, more) = match kind {
        Kind::Queue { .. } => (vec![QUEUE.to_string()], Vec::new()),
        Kind::Spec { files, .. } => (files.iter().map(|f| f.iter().collect()).collect(), Vec::new()),
        Kind::Code { .. } | Kind::Foil { .. } => (Vec::new(), config.counterexample.tests.clone()),
        _ => (Vec::new(), Vec::new()),
    };
    if let Err(e) = working_directory_except(&m.root, config, start, &dir, &writable, &more) {
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
    // Its own build, a clone of trunk's, for the session alone: its first cargo
    // is warm. The judge never reuses it (an agent process could forge cargo's
    // fingerprints there and have a planted artifact judged, and cached).
    // bon's cargo makes the clone at the session's first cargo (BON_WARM), so a
    // session that never builds (one sample) costs no clone; without bon's
    // cargo, it is made now.
    let lazy = wrapper(config).is_some();
    let made = if lazy { session_build(config, &format!("{search}.{index}.build/build")) }
               else { build_directory(config, &format!("{search}.{index}.build/build")).map(|b| (b, None)) };
    let (build, warm) = match made {
        Ok(b) => b,
        Err(e) => { write_trace(&trace.join("error"), e); return (None, 0); }
    };
    let argv = p.argv();
    write_trace(&trace.join("argv"), argv.join(" "));
    let text = prompt(kind, config, &aim(m, kind, target, start, context));
    write_trace(&trace.join("prompt"), &text);
    let b = build.to_string_lossy().to_string();
    let mut env = vec![("CARGO_TARGET_DIR", b.clone()), ("BON_BUILD", b), ("CARGO_BUILD_JOBS", config.pools.threads.to_string())];
    if let Some(w) = warm { env.push(("BON_WARM", w.to_string_lossy().to_string())); }
    // What the role says beyond its argv, for a program that reaches its model
    // itself (bon-sample): its client, its context budget, and the host file
    // that holds its client's facts.
    env.push(("BON_HOST", config.host.to_string_lossy().to_string()));
    if let Some(c) = &p.run.client { env.push(("BON_CLIENT", c.clone())); }
    if let Some(c) = p.run.context { env.push(("BON_CONTEXT", c.to_string())); }
    let c = as_user(config, Who::Agent, &with_wrapper(config, config.path.clone()), &dir, &env, &argv);
    let run = supervised(c, Who::Agent, Some(text), Duration::from_secs(config.agent_process.time), &trace.join("program"), spoke);
    let started = !never_started(&run);
    let silent = !run.killed && run.stdout.is_empty() && run.exit != Some(0);
    let (stdout, killed, exit) = (run.stdout, run.killed, run.exit);
    drop(session);
    remove_build(config, &build);
    // Without token counts there is no measured cost: charge the whole limit;
    // a program that never started reached no model, and costs nothing.
    let (spent, program_cost, prices) = generation(p, config, &stdout)
        .unwrap_or((if started && !silent { micro(config.agent_process.limit) } else { 0 }, None, HashMap::new()));
    let over = over_tier(p, config, &stdout);
    if killed { write_trace(&trace.join("killed"), "time limit"); }
    // The judge's build: a fresh clone of trunk's, which no agent process wrote,
    // made only if a check must run (the verdict cache may answer them all).
    let judge = named_build(&format!("{search}.{index}.judge/build"), Start::Trunk);
    // What its checks said is kept with it, for a push or landing to check again.
    // A program that never started wrote nothing: its untouched directory is no candidate to judge.
    let (captured, decided) = if started { deciding(|| capture(m, kind, search, index, start, &dir, &judge, target, foils, trace)) }
        else { (Err(format!("its program never started (exit {}); nothing to judge", exit.map_or("none".to_string(), |c| c.to_string()))), Default::default()) };
    if let Ok(c) = &captured { keep_decided(&c.commit.iter().collect::<String>(), decided); }
    let candidate = captured.map_err(|e| { write_trace(&trace.join("error"), &e); }).ok();
    remove_build(config, &judge);
    let _ = Command::new("chmod").args(["-R", "-N"]).arg(&dir).stderr(Stdio::null()).status();
    let _ = std::fs::remove_dir_all(&dir);
    let text = |v: &[char]| v.iter().collect::<String>();
    // Lines added and removed, apart: the kernel's diff is their sum.
    let (lines_added, lines_removed) = candidate.as_ref().map_or((0, 0), |c| added_removed(&m.root, &text(&c.base), &text(&c.commit)));
    let facts = serde_json::json!({
        // The program by its name (its argv is the trace's `argv`), its role and its client.
        "program": p.name(), "role": p.role, "client": p.run.client, "model": p.run.model,
        "generation_microdollars": spent, "killed": killed,
        // Its program's exit code (none when killed or never spawned), and whether it started at all.
        "exit": exit, "started": started,
        "program_generation_microdollars": program_cost,
        // Its requests over its model's tier threshold, where the output says each request's prompt,
        // and what they cost beyond the base price.
        "requests_over_tier": over.map(|o| o.0), "over_tier_microdollars": over.map(|o| o.1),
        // The prices this cost was computed at, so the trace stays true when the host's prices change.
        "prices": prices,
        // The program's own figure differs from bon's by more than 5%: the price table or the program is stale.
        "price_mismatch": program_cost.is_some_and(|c| (c as f64 - spent as f64).abs() > 0.05 * (c.max(spent).max(1) as f64)),
        "over_limit": spent > micro(config.agent_process.limit),
        "candidate": candidate.as_ref().map(|c| serde_json::json!({
            "commit": text(&c.commit), "base": text(&c.base), "accepted": c.accepted, "proved": c.proved,
            "changed": c.changed.iter().map(|p| text(p)).collect::<Vec<_>>(), "diff": c.diff, "lines_added": lines_added, "lines_removed": lines_removed,
            "rank": c.rank, "out": c.out.iter().map(|h| h.0).collect::<Vec<u64>>(), "accepts": c.accepts, "accepts_foils": c.accepts_foils,
            "rejects_counterexamples": c.rejects_counterexamples, "measured": c.measured, "added": c.added.iter().map(|p| text(p)).collect::<Vec<_>>(),
            "intents": c.intents.iter().map(|(q, i)| (q, text(i))).collect::<Vec<_>>(),
        })),
    });
    let facts = agent_process_record(facts, candidate.as_ref(), context, matches!(kind, Kind::Spec { .. }));
    write_trace(&trace.join("facts.json"), serde_json::to_string_pretty(&facts).unwrap_or_default());
    (candidate, spent)
}

// ── the one trace shape ─────────────────────────────────
//
// Every record a bon process writes says, under these five keys, what ran
// (program), what it was given (context), what it returned (output), how it
// was judged (verdict) and which behavior its output showed (behavior); the
// README's "The trace" says where each lives in each record.

/// An agent process's facts in the one shape: its program (already there),
/// what it was given (`context`: the trace file `prompt`, and the commits
/// whose verdicts the prompt carries, `prompt + <commit> …`), the commit it returned
/// (`output`), what its checks said (`verdict`: proved, accepted, rejected; none
/// when it returned no candidate) and its agree outputs' hashes (`behavior`).
fn agent_process_record(mut facts: serde_json::Value, candidate: Option<&Candidate>, context: &[String], spec: bool) -> serde_json::Value {
    // A spec candidate runs no tests: proved when its spec verifies alone.
    let verdict = candidate.map(|c| if spec { if c.proved { "proved" } else { "rejected" } } else if !c.accepted { "rejected" } else if c.proved { "proved" } else { "accepted" });
    let behavior = candidate.filter(|c| !c.out.is_empty()).map(|c| c.out.iter().map(|h| h.0.to_string()).collect::<Vec<_>>().join(","));
    facts["context"] = if context.is_empty() { "prompt".to_string() } else { format!("prompt + {}", context.join(" ")) }.into();
    facts["output"] = candidate.map(|c| c.commit.iter().collect::<String>()).into();
    facts["verdict"] = verdict.into();
    facts["behavior"] = behavior.into();
    facts
}

/// Where a repository's decision records are: one line each, in the one shape.
pub const DECISIONS: &str = ".bon/traces/decisions.jsonl";

/// Record an interrupt's resolution, as the view derived it (`record`, in the
/// one shape: engineer as its program, what the interrupt showed as its
/// context, the answering commit as its output, the choice it showed as its
/// behavior; what came of it, its verdict, is derived later), with a pointer to
/// the transcript of the session that answered it and the transcript's SHA-256,
/// never its content: `transcript` is the path the session gave bon pending,
/// none when engineer answered by hand. Appended to the repository's
/// decisions.jsonl.
pub fn record_decision(root: &std::path::Path, mut record: serde_json::Value, transcript: Option<&std::path::Path>) -> Result<(), String> {
    record["transcript"] = match transcript {
        Some(t) => {
            let bytes = std::fs::read(t).map_err(|e| format!("{}: {e}", t.display()))?;
            let path = std::fs::canonicalize(t).unwrap_or_else(|_| t.to_path_buf());
            serde_json::json!({ "path": path.to_string_lossy(), "sha256": Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>() })
        }
        None => serde_json::Value::Null,
    };
    record["time"] = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()).into();
    append_line(&root.join(DECISIONS), &record.to_string());
    Ok(())
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

    // Checks run in a read-only checkout, as the slot's user.
    let cdir = scratch(&format!("{search}.{index}.check/{}", repository_name(root)));
    check_directory(root, &commit, &cdir)?;
    // Keyed by the candidate's tree: a byte-identical sibling's checks run once.
    let on = On { tree: tree.clone(), test: None, cache: Cache::Use };
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
        Kind::Code { .. } | Kind::Compaction { .. } | Kind::Foil { .. } => holding(|| {
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
                    // Its suite's seconds as well as the rank command's integer: whole seconds off it.
                    match suite_seconds(config, &on, &cdir, build, trace) {
                        Some(s) => { write_trace(&trace.join("seconds"), format!("{s:.3}\n")); rank = rank.saturating_sub(s.round() as i64); }
                        None => measured = false,
                    }
                    rejects_counterexamples = rejects_every_counterexample(m, &commit, start, build, trace);
                }
            }
        }),
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
                    // The members alone: the kernel reads a test's verdict on a
                    // verified candidate (spec::member) and on no other.
                    for (j, r) in t.results.iter().enumerate() {
                        if let Some(c) = r.as_ref().filter(|c| crate::exec::verified(t, c)) { members.push((j as i64, c.commit.iter().collect())); }
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
                // spec decides which results are foils (spec::foil, which also
                // asks that it changed only what it may); a result the tests
                // reject, or Verus proves, is none, and is not run.
                if let Some(f) = foils {
                    for (j, r) in f.results.iter().enumerate() {
                        let Some(c) = r.as_ref().filter(|c| c.accepted && !c.proved) else { continue };
                        tasks.push((true, j as i64, c.commit.iter().collect(), trace.join(format!("accepts-foil-{j}"))));
                    }
                }
                let on: Vec<(String, PathBuf)> = tasks.iter().map(|(_, _, c, l)| (c.clone(), l.clone())).collect();
                let results = verdicts(m, &on, bytes, &format!("{search}.{index}"));
                for ((foil, j, _, _), r) in tasks.into_iter().zip(results) {
                    let Some(a) = r else { continue };
                    if foil { accepts_foils.push((j, a)); } else { accepts.push((j, a)); }
                }
            }
        }
        Kind::Spec { files, .. } => {
            let files: Vec<String> = files.iter().map(|f| f.iter().collect()).collect();
            // Verus on the spec's files alone: what proves a spec candidate.
            proved = stands_alone(m, &commit, &files, &format!("{search}.{index}"), trace).is_ok();
            // B3: a spec proposal may not hide an admitted proof. `assume(false)`
            // or `external_body` in a proof passes stands_alone; a skip (as the
            // account's `skips` recognises them) a changed file did not have
            // before is not proved, so the proposal does not group it with
            // honest candidates.
            if proved {
                let at = |c: &str, f: &str| git(root, &["cat-file", "blob", &format!("{c}:{f}")]).unwrap_or_default();
                if let Some(f) = files.iter().find(|f| skips(&at(&commit, f)).len() > skips(&at(start, f)).len()) {
                    write_trace(&trace.join("rules"), format!("{f}: a proof skip (assume/admit/external_body) its base did not have ({NOT_JUDGED})"));
                    proved = false;
                }
            }
            // The whole kernel's verify, as information for the proposal: what still proves with it.
            holding(|| for (k, v) in config.checks.verify.iter().enumerate() { run_check(config, &on, &cdir, build, v, &trace.join(format!("kernel-{k}"))); });
            accepted = false;
            out = surface_hashes(&surface_change(root, start, &commit, &files));
            measured = true;
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

    // The rules of queue 67-69, applied to this candidate by its own kind's
    // authority (`broken_by_candidate`): a candidate that breaks a rule its
    // base does not (a build script, a proc macro, a unit test, or plain Rust
    // outside verus! in a file it may write; a check that would then run such
    // a file) is not a clean verified candidate. `rules` reads the tree and
    // the manifest only, so it runs on the candidate's commit without
    // executing anything of the candidate's. The verdict's authority is the
    // kernel's `exec::verified`, which asks for `accepted` or `proved` by
    // kind; failing both makes it unverified whatever the kind.
    if let Some(reason) = broken_by_candidate(m, kind, start, &commit) {
        write_trace(&trace.join("rules"), &reason);
        accepted = false;
        proved = false;
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

// ── the spec search ─────────────────────────────────────

/// The spec's files at commit: the files under the check paths that are Rust
/// with a `verus!` block (as `bon account` calls a file proven), sorted.
fn spec_files_at(root: &std::path::Path, paths: &[String], commit: &str) -> Vec<String> {
    let mut args = vec!["ls-tree", "-r", "--name-only", commit, "--"];
    args.extend(paths.iter().map(|p| p.as_str()));
    let mut files: Vec<String> = git(root, &args).unwrap_or_default().lines().filter(|f| f.ends_with(".rs"))
        .filter(|f| git(root, &["show", &format!("{commit}:{f}")]).is_ok_and(|t| t.lines().any(|l| l.trim_start().starts_with("verus!"))))
        .map(String::from).collect();
    files.sort();
    files.dedup();
    files
}

/// The crate in which the spec stands alone, as a commit made of git objects
/// alone, so the same files make the same bytes: commit's Cargo.toml reduced
/// to its package's name, version, edition and metadata, its dependencies
/// (all three kinds), lints and patches, so its Cargo.lock still holds;
/// that Cargo.lock; and a src/lib.rs that declares the spec's files and
/// nothing else, each src/<name>.rs as commit holds it.
fn alone_commit(root: &std::path::Path, commit: &str, files: &[String]) -> Result<String, String> {
    let run = |args: &[&str], input: Option<&str>| -> Result<String, String> {
        let mut c = Command::new("git").args(args).current_dir(root)
            .env("GIT_AUTHOR_NAME", "bon").env("GIT_AUTHOR_EMAIL", "bon@localhost").env("GIT_AUTHOR_DATE", "1970-01-01T00:00:00Z")
            .env("GIT_COMMITTER_NAME", "bon").env("GIT_COMMITTER_EMAIL", "bon@localhost").env("GIT_COMMITTER_DATE", "1970-01-01T00:00:00Z")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
        c.stdin.take().ok_or("git: no stdin")?.write_all(input.unwrap_or("").as_bytes()).map_err(|e| e.to_string())?;
        let out = c.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(format!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim())); }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let blob = |text: &str| run(&["hash-object", "-w", "--stdin"], Some(text));
    // The blob commit holds at path, if any.
    let held = |path: &str| git(root, &["rev-parse", &format!("{commit}:{path}")]).ok();
    let manifest: toml::Table = toml::from_str(&git(root, &["show", &format!("{commit}:Cargo.toml")])?).map_err(|e| format!("Cargo.toml: {e}"))?;
    let mut package = toml::Table::new();
    for key in ["name", "version", "edition", "metadata"] {
        if let Some(v) = manifest.get("package").and_then(|p| p.get(key)) { package.insert(key.into(), v.clone()); }
    }
    let mut alone = toml::Table::new();
    alone.insert("package".into(), toml::Value::Table(package));
    for key in ["dependencies", "dev-dependencies", "build-dependencies", "lints", "patch"] {
        if let Some(v) = manifest.get(key) { alone.insert(key.into(), v.clone()); }
    }
    let cargo = toml::to_string(&alone).map_err(|e| e.to_string())?;
    let (mut lib, mut src) = (String::new(), Vec::new());
    for f in files {
        let name = f.strip_prefix("src/").and_then(|n| n.strip_suffix(".rs")).filter(|n| !n.contains('/') && !["lib", "main"].contains(n))
            .ok_or_else(|| format!("{f}: each of the spec's files must be src/<name>.rs, a module of the crate's lib"))?;
        lib.push_str(&format!("pub mod {name};\n"));
        src.push(format!("100644 blob {}\t{name}.rs", held(f).ok_or_else(|| format!("{f}: not in {commit}"))?));
    }
    src.push(format!("100644 blob {}\tlib.rs", blob(&lib)?));
    src.sort_by(|a, b| a.split('\t').nth(1).cmp(&b.split('\t').nth(1)));
    let src = run(&["mktree"], Some(&(src.join("\n") + "\n")))?;
    let mut top = vec![format!("100644 blob {}\tCargo.toml", blob(&cargo)?)];
    if let Some(lock) = held("Cargo.lock") { top.insert(0, format!("100644 blob {lock}\tCargo.lock")); }
    top.push(format!("040000 tree {src}\tsrc"));
    let tree = run(&["mktree"], Some(&(top.join("\n") + "\n")))?;
    run(&["commit-tree", &tree, "-m", "the spec alone"], None)
}

/// The crate in which commit's spec stands alone (`alone_commit`), its spec's
/// files found under paths, the check paths: for a check that a project's
/// spec does.
pub fn spec_alone_commit(root: &std::path::Path, paths: &[String], commit: &str) -> Result<String, String> {
    alone_commit(root, commit, &spec_files_at(root, paths, commit))
}

/// Whether the spec's files verify alone at commit: each `checks.verify`
/// command in the crate `alone_commit` makes, as a check slot's user, in a
/// clone of trunk's build, each logged as `verify-K` under logs. Err names
/// the file and the first error when one does not.
fn stands_alone(m: &Manifest, commit: &str, files: &[String], name: &str, logs: &std::path::Path) -> Result<(), String> {
    let (config, root) = (&m.config, &m.root);
    let alone = alone_commit(root, commit, files)?;
    let dir = scratch(&format!("{name}.alone/{}", repository_name(root)));
    check_directory(root, &alone, &dir)?;
    let build = named_build(&format!("{name}.alone.build/build"), Start::Trunk);
    let on = On::commit(root, &alone);
    traced(logs, std::fs::create_dir_all(logs));
    let failed = holding(|| config.checks.verify.iter().enumerate().find_map(|(k, v)| {
        let log = logs.join(format!("verify-{k}"));
        (!run_check(config, &on, &dir, &build, v, &log).0).then(|| (v.clone(), std::fs::read_to_string(&log).unwrap_or_default()))
    }));
    remove_build(config, &build);
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    let _ = std::fs::remove_dir_all(&dir);
    let Some((command, log)) = failed else { return Ok(()) };
    let lines: Vec<&str> = log.lines().collect();
    let at = lines.iter().position(|l| l.starts_with("error"));
    let error = at.map_or("it did not finish", |k| lines[k]);
    let file = at.and_then(|k| lines[k..].iter().find_map(|l| l.trim_start().strip_prefix("--> ")))
        .map(|w| w.split(':').next().unwrap_or(w).to_string()).unwrap_or_else(|| files.join(", "));
    Err(format!("{file}: does not verify alone ({command}): {error}"))
}

/// One surface item of a spec file: its kind and name, its text as written
/// (its /// lines first), its text as compared (no comments, no layout; a
/// proof's contract without its body), and its first doc sentence.
#[derive(Clone)]
struct Item { kind: &'static str, name: String, written: String, compared: String, doc: String }

/// Brackets opened minus closed on a line ({, ( and [), outside strings,
/// chars and a trailing comment.
fn braces(line: &str) -> i32 {
    let (mut depth, mut chars) = (0, line.chars().peekable());
    while let Some(c) = chars.next() {
        match c {
            '"' => { while let Some(d) = chars.next() { if d == '\\' { chars.next(); } else if d == '"' { break; } } }
            '\'' => {
                // A char literal ('x' or '\x'); a lifetime has no closing quote.
                let rest: Vec<char> = chars.clone().take(3).collect();
                if rest.get(1) == Some(&'\'') { chars.next(); chars.next(); }
                else if rest.first() == Some(&'\\') && rest.get(2) == Some(&'\'') { chars.next(); chars.next(); chars.next(); }
            }
            '/' if chars.peek() == Some(&'/') => break,
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// A doc's first sentence.
fn sentence(doc: &str) -> String {
    match doc.find(". ") { Some(k) => doc[..=k].to_string(), None => doc.to_string() }
}

/// The surface items of a spec file, as Verus expresses them: types (with
/// their fields and variants), predicates, proofs (their contracts),
/// transitions, init, properties, invariants, the state's fields, and the
/// methods of a trait (the gates). Proof bodies and impl blocks are not
/// surface: they are an agent's own words.
fn surface(text: &str) -> Vec<Item> {
    let lines: Vec<&str> = text.lines().collect();
    let mut items = Vec::new();
    let (mut doc, mut invariant) = (Vec::<String>::new(), false);
    let (mut trait_depth, mut fields_depth) = (None::<i32>, None::<i32>);
    let (mut depth, mut i) = (0i32, 0usize);
    let word = |rest: &str| rest.trim_start().split(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap_or("").to_string();
    let after = |t: &str, key: &str| word(t.split(key).nth(1).unwrap_or(""));
    while i < lines.len() {
        let t = lines[i].trim();
        if trait_depth.is_some_and(|d| depth <= d) { trait_depth = None; }
        if fields_depth.is_some_and(|d| depth <= d) { fields_depth = None; }
        if let Some(d) = t.strip_prefix("///") { doc.push(d.trim().to_string()); i += 1; continue; }
        if t == "#[invariant]" { invariant = true; i += 1; continue; }
        // An inductive proof or an impl block: skipped whole.
        if t.starts_with("#[inductive") || t.starts_with("impl ") || t.starts_with("impl<") {
            let (start, mut j, mut opened) = (depth, i, false);
            if t.starts_with("#[") { j += 1; }
            while j < lines.len() {
                depth += braces(lines[j]);
                opened |= lines[j].contains('{');
                if opened && depth <= start { break; }
                j += 1;
            }
            depth = start;
            doc.clear(); invariant = false; i = j + 1;
            continue;
        }
        let item: Option<(&'static str, String)> = if fields_depth.is_some() {
            t.split("pub ").nth(1).filter(|r| r.contains(':')).map(|r| ("field", word(r)))
        } else if t.starts_with("#[") {
            i += 1; continue;
        } else if let Some(r) = ["pub struct ", "pub enum ", "pub type "].iter().find_map(|k| t.strip_prefix(k)) {
            Some(("type", word(r)))
        } else if t.contains("spec fn ") && ["pub", "spec", "open", "closed"].iter().any(|k| t.starts_with(k)) {
            Some(("predicate", after(t, "spec fn ")))
        } else if trait_depth.is_some() && (t.starts_with("fn ") || t.starts_with("proof fn ")) {
            Some(("gate", after(t, "fn ")))
        } else if t.contains("proof fn ") && (t.starts_with("pub") || t.starts_with("proof")) {
            Some(("proof", after(t, "proof fn ")))
        } else if let Some(k) = ["transition!{", "init!{", "property!{"].iter().find(|k| t.starts_with(**k)) {
            Some((match *k { "transition!{" => "transition", "init!{" => "init", _ => "property" }, word(&t[k.len()..])))
        } else if invariant && t.contains("fn ") {
            Some(("invariant", after(t, "fn ")))
        } else { None };
        let Some((kind, name)) = item else {
            if t.starts_with("pub trait ") { trait_depth = Some(depth); }
            if t.starts_with("fields") && t.contains('{') { fields_depth = Some(depth); }
            depth += braces(lines[i]);
            if !t.is_empty() { doc.clear(); }
            invariant = false;
            i += 1;
            continue;
        };
        // The item: to where its brackets close, past an opened body or at its ; or ,.
        let (start, mut j, mut opened) = (depth, i, false);
        loop {
            depth += braces(lines[j]);
            opened |= lines[j].contains('{');
            let end = lines[j].trim_end();
            if kind == "field" || (depth <= start && (opened || end.ends_with(';') || end.ends_with(','))) { break; }
            if j + 1 >= lines.len() { break; }
            j += 1;
        }
        depth = start;
        let body: Vec<&str> = lines[i..=j].iter().copied().filter(|l| !l.trim_start().starts_with("//")).collect();
        let mut compared = body.join(" ").split_whitespace().collect::<Vec<_>>().join(" ");
        if kind == "proof" { if let Some(k) = compared.find('{') { compared.truncate(k); } }
        let written = doc.iter().map(|d| format!("/// {d}")).chain(lines[i..=j].iter().map(|l| l.to_string())).collect::<Vec<_>>().join("\n");
        items.push(Item { kind, name, written, compared: compared.trim().to_string(), doc: sentence(&doc.join(" ")) });
        doc.clear();
        invariant = false;
        i = j + 1;
    }
    items
}

/// The named members of a type item: each field and variant, with its doc's first sentence.
fn members(item: &Item) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut doc = Vec::new();
    for l in item.written.lines().skip_while(|l| l.trim_start().starts_with("///")).skip(1) {
        let t = l.trim();
        if let Some(d) = t.strip_prefix("///") { doc.push(d.trim().to_string()); continue; }
        let name: String = t.trim_start_matches("pub ").chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if !name.is_empty() && !t.starts_with('}') { out.push((name, sentence(&doc.join(" ")))); }
        doc.clear();
    }
    out
}

/// What a spec candidate changed at the surface: each item, by its file,
/// kind and name, that it adds, removes or changes, with its two versions as
/// compared and as written (None where absent), in key order.
fn surface_change(root: &std::path::Path, base: &str, commit: &str, files: &[String]) -> Vec<(String, &'static str, Option<Item>, Option<Item>)> {
    let read = |at: &str, f: &str| -> Vec<(String, Item)> {
        git(root, &["show", &format!("{at}:{f}")]).map(|t| surface(&t)).unwrap_or_default().into_iter()
            .map(|it| (format!("{f}: {} {}", it.kind, it.name), it)).collect()
    };
    let mut keys = std::collections::BTreeMap::<String, (Option<Item>, Option<Item>)>::new();
    for f in files {
        for (k, it) in read(base, f) { keys.entry(k).or_default().0 = Some(it); }
        for (k, it) in read(commit, f) { keys.entry(k).or_default().1 = Some(it); }
    }
    keys.into_iter().filter_map(|(k, (a, b))| {
        let how = match (&a, &b) {
            (None, Some(_)) => "adds",
            (Some(_), None) => "removes",
            (Some(x), Some(y)) if x.compared != y.compared => "changes",
            _ => return None,
        };
        Some((k, how, a, b))
    }).collect()
}

/// A spec candidate's behavior: a hash of each surface change, in key order.
fn surface_hashes(change: &[(String, &'static str, Option<Item>, Option<Item>)]) -> Vec<Hash> {
    change.iter().map(|(k, how, _, b)| Hash(hash(&format!("{k}\n{how}\n{}", b.as_ref().map_or("", |i| i.compared.as_str()))))).collect()
}

/// The kernel's functions that name one of names, by file and name, each
/// with whether Verus still proves it with this change, from the whole
/// kernel's verify log: "still proves", "fails", or, when the crate did not
/// build, "not built". The kernel's files: the proven files that are not the spec's.
fn dependents(root: &std::path::Path, commit: &str, files: &[String], names: &[String], log: &str) -> Vec<(String, String, &'static str)> {
    let built = log.contains("verification results");
    let errors: Vec<(String, usize)> = log.lines().filter_map(|l| l.trim_start().strip_prefix("--> "))
        .filter_map(|w| { let mut p = w.split(':'); Some((p.next()?.to_string(), p.next()?.parse().ok()?)) }).collect();
    let kernel: Vec<String> = git(root, &["ls-tree", "-r", "--name-only", commit]).unwrap_or_default().lines()
        .filter(|f| f.ends_with(".rs") && !files.iter().any(|s| s == f))
        .filter(|f| git(root, &["show", &format!("{commit}:{f}")]).is_ok_and(|t| t.lines().any(|l| l.trim_start().starts_with("verus!"))))
        .map(String::from).collect();
    let named = |text: &str, n: &str| text.match_indices(n).any(|(k, _)| {
        let ok = |c: Option<char>| c.is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        ok(text[..k].chars().last()) && ok(text[k + n.len()..].chars().next())
    });
    let mut out = Vec::new();
    for f in &kernel {
        let text = git(root, &["show", &format!("{commit}:{f}")]).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        // Each function, from its fn line to the next.
        let starts: Vec<(usize, String)> = lines.iter().enumerate().filter_map(|(k, l)| {
            let t = l.trim_start();
            let rest = ["pub fn ", "fn ", "pub proof fn ", "proof fn ", "pub open spec fn ", "pub closed spec fn ", "spec fn ", "open spec fn "].iter().find_map(|p| t.strip_prefix(p))?;
            Some((k, rest.split(|c: char| !(c.is_alphanumeric() || c == '_')).next()?.to_string()))
        }).collect();
        for (n, (k, name)) in starts.iter().enumerate() {
            let end = starts.get(n + 1).map_or(lines.len(), |s| s.0);
            let body = lines[*k..end].join("\n");
            if !names.iter().any(|x| named(&body, x)) { continue; }
            let status = if !built { "not built" } else if errors.iter().any(|(e, l)| e == f && (*k + 1..=end).contains(l)) { "fails" } else { "still proves" };
            out.push((f.clone(), name.clone(), status));
        }
    }
    out
}

/// A code block of item text, fenced.
fn fenced(text: &str) -> String { format!("```rust\n{text}\n```\n") }


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
    let on = On { tree: tree_of(&m.root, commit), test: Some((config.counterexample.path.as_str(), test)), cache: Cache::Use };
    match answer(config, &on, make, &log.with_extension("build")) {
        Some((false, _)) => return None,
        Some((true, _)) => if let Some((ok, _)) = answer(config, &on, run, log) { return Some(ok) },
        None => {}
    }
    let dir = scratch(&format!("test.{}/{}", hash(&format!("{commit}{log:?}")), repository_name(&m.root)));
    // The build and the run, one after another in one check slot.
    let result = holding(|| {
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
    });
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
    // Its owner's directory too: `test.<hash>` is this verdict's alone.
    if let Some(d) = dir.parent() { let _ = std::fs::remove_dir_all(d); }
    result
}

/// A test's verdict on each of `tasks` (a commit, its log), at once through the
/// check pool. Tasks on one tree run one after another, so the first's result
/// answers the rest from the cache; a verdict that must run builds in its own
/// clone of trunk's build (cargo locks a build directory: one build at a
/// time), removed after. `name` names those clones.
fn verdicts(m: &Manifest, tasks: &[(String, PathBuf)], test: &[u8], name: &str) -> Vec<Option<bool>> {
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
    // These verdicts decide the candidate whose test this is, like its own thread's.
    let deciding = deciding_here();
    std::thread::scope(|scope| {
        for _ in 0..config.pools.check_processes.max(1).min(groups.len()) {
            scope.spawn(|| within(&deciding, || loop {
                let g = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some((_, group)) = groups.get(g) else { break };
                for &i in group {
                    let (commit, log) = &tasks[i];
                    let made: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
                    let make = || {
                        // From trunk's build, whose shared files it links (a judge's
                        // build's copy of them would be new files again).
                        let d = named_build(&format!("{name}.verdict.{i}/build"), Start::Trunk);
                        *made.lock().unwrap() = Some(d.clone());
                        Some(d)
                    };
                    *out[i].lock().unwrap() = verdict_in(m, commit, test, &make, log);
                    if let Some(d) = made.into_inner().unwrap() { remove_build(config, &d); }
                }
            }));
        }
    });
    out.into_iter().map(|r| r.into_inner().unwrap_or(None)).collect()
}

/// Whether a test accepts `commit`: a read-only checkout of it with the test at
/// the counterexample path, run as a check slot's user.
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
    let on = On { tree: tree_of(&m.root, commit), test: Some((path.as_str(), test)), cache: Cache::Use };
    if let Some((ok, _)) = answer(config, &on, run, log) { return ok; }
    let dir = scratch(&format!("test.{}/{}", hash(&format!("{commit}{log:?}")), repository_name(&m.root)));
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
    if let Some(d) = dir.parent() { let _ = std::fs::remove_dir_all(d); }
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

verus! {

/// The spec's files at trunk's head, once they stand alone there: what a spec
/// search may change. Refused, before any search, without a `[searches]
/// spec` entry, without a spec file, or when they do not verify alone.
#[verifier::external_body]
pub fn spec_files(m: &Manifest, head: &Commit) -> (r: Result<Vec<Path>, String>) {
    if m.config.searches.spec.is_none() { return Err("bon.toml's [searches] has no spec entry: add spec = { role = \"…\", n = [4, 6] }".into()); }
    let h: String = head.iter().collect();
    let files = spec_files_at(&m.root, &m.config.checks.paths, &h);
    if files.is_empty() { return Err("no spec file: no check path holds a Rust file with a verus! block".into()); }
    stands_alone(m, &h, &files, "trunk", &trace_dir(&m.root).join("spec-alone"))
        .map_err(|e| format!("trunk's spec does not stand alone, so no spec search can be judged: {e}"))?;
    Ok(files.iter().map(|f| f.chars().collect()).collect())
}


} // verus!

/// bon spec's proposal for queue id, in its own directory beside the queue's
/// proposals, `spec-<id>/`: `review.md`, the review form engineer reads first
/// (new words, decisions, reach, scenarios, in plain words, no diff); one
/// patch per behavior beside it (`<k>.patch`, a plain diff `git apply` takes,
/// so the commit is engineer's); and `proposal.json`, which the proposal
/// interrupt reads. The kernel decides which candidates are verified; this
/// groups them by `out`, their surface change. Prose wraps by `wrap` and counts
/// read by `count`, the view's own formats. Returns the review's path.
pub fn spec_proposal(m: &Manifest, s: &Search, id: u64, wrap: &dyn Fn(&str, usize, usize) -> String, count: &dyn Fn(usize, &str, &str) -> String) -> Result<String, String> {
    let root = &m.root;
    let text = |v: &[char]| v.iter().collect::<String>();
    let Kind::Spec { goal, files } = &s.kind else { return Err("not a spec search".into()) };
    let (intent, files): (String, Vec<String>) = (text(goal), files.iter().map(|f| text(f)).collect());
    let base = text(&s.base);
    let verified: Vec<(usize, &Candidate)> = s.results.iter().enumerate()
        .filter_map(|(i, r)| r.as_ref().filter(|c| crate::exec::verified(s, c)).map(|c| (i, c))).collect();
    // Behaviors, in the order of their first agent process.
    let mut behaviors: Vec<(Vec<Hash>, Vec<usize>)> = Vec::new();
    for (i, c) in &verified {
        match behaviors.iter_mut().find(|(out, _)| out.iter().map(|h| h.0).eq(c.out.iter().map(|h| h.0))) {
            Some(b) => b.1.push(*i),
            None => behaviors.push((c.out.clone(), vec![*i])),
        }
    }
    let commit_of = |i: usize| s.results[i].as_ref().map_or(String::new(), |c| text(&c.commit));
    let changes: Vec<Vec<(String, &'static str, Option<Item>, Option<Item>)>> = behaviors.iter().map(|(_, is)| surface_change(root, &base, &commit_of(is[0]), &files)).collect();
    let at = format!("{BON}/traces/proposals/spec-{id}");
    let dir = root.join(&at);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let name = |k: usize| format!("{}.patch", k + 1);
    let who = |is: &[usize]| format!("{} ({})", count(is.len(), "agent process", "agent processes"), is.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
    // A paragraph, wrapped; a list item, its lines under its text.
    let para = |text: &str| wrap(text, 0, 0) + "\n";
    let item = |text: &str| wrap(&format!("- {text}"), 0, 2);
    let mut patches = Vec::new();
    for (k, (_, is)) in behaviors.iter().enumerate() {
        let mut args = vec!["diff".to_string(), base.clone(), commit_of(is[0]), "--".into()];
        args.extend(files.iter().cloned());
        let diff = git(root, &args.iter().map(String::as_str).collect::<Vec<_>>())?;
        std::fs::write(dir.join(name(k)), diff + "\n").map_err(|e| e.to_string())?;
        patches.push(format!("{at}/{}", name(k)));
    }
    let mut md = format!("# Proposal: queue {id}, a spec change\n\n> {intent}\n\n");
    md.push_str(&para(&format!("{} each proposed a spec change; {} verified (the spec verifies alone, and each changed only the spec's files, {}). \
        They group into {} by the surface items they change. Nothing was pushed.",
        count(s.n, "agent process", "agent processes"), verified.len(), files.join(", "), count(behaviors.len(), "behavior", "behaviors"))));
    md.push_str(&para(&format!("To accept behavior k: `git apply {at}/k.patch`, delete line {id} of `{QUEUE}`, \
        and commit with the trailer `Source: queue {id}`. To accept none: `git commit --allow-empty -m 'spec: not queue {id}' -m 'Source: queue {id}'`.")));

    // New words: identifiers new to the surface, each with the sentence each behavior gave it.
    md.push_str("## New words\n\n");
    // (word, each agent process's sentence for it)
    let mut words: std::collections::BTreeMap<String, Vec<(usize, String)>> = Default::default();
    for (i, _) in &verified {
        let k = *i;
        for (_, how, a, b) in &surface_change(root, &base, &commit_of(*i), &files) {
            let Some(b) = b else { continue };
            if *how == "adds" { words.entry(format!("`{}` ({})", b.name, b.kind)).or_default().push((k, b.doc.clone())); }
            if b.kind == "type" {
                let old: Vec<String> = a.as_ref().map(|a| members(a).into_iter().map(|m| m.0).collect()).unwrap_or_default();
                for (member, doc) in members(b).into_iter().filter(|m| !old.contains(&m.0)) {
                    words.entry(format!("`{}.{member}`", b.name)).or_default().push((k, doc));
                }
            }
        }
    }
    if words.is_empty() { md.push_str(&para("None: no identifier is new to the surface.")); }
    for (w, said) in &words {
        let mut sentences: Vec<(String, Vec<usize>)> = Vec::new();
        for (i, d) in said { match sentences.iter_mut().find(|x| x.0 == *d) { Some(x) => x.1.push(*i), None => sentences.push((d.clone(), vec![*i])) } }
        for (d, is) in sentences {
            md.push_str(&item(&format!("{w}, as {} wrote it: {}", who(&is), if d.is_empty() { "(no sentence given)".to_string() } else { d })));
        }
    }

    // Decisions: each item the behaviors wrote differently, or one wrote and another did not.
    md.push_str("\n## Decisions\n\n");
    md.push_str(&para("A split is an item the verified agent processes wrote differently. bon compares text, without docs, comments or layout, \
        so two sides may still mean the same: that is for you to judge."));
    let keys: std::collections::BTreeSet<String> = changes.iter().flat_map(|c| c.iter().map(|x| x.0.clone())).collect();
    let mut n = 0;
    for key in &keys {
        // Each side: what the behavior's version is (its compared text, or unchanged), and which behaviors hold it.
        let mut sides: Vec<(Option<&Item>, &'static str, Vec<usize>)> = Vec::new();
        for (k, change) in changes.iter().enumerate() {
            let mine = change.iter().find(|x| &x.0 == key);
            let (version, how) = match mine { Some((_, how, _, b)) => (b.as_ref(), *how), None => (None, "leaves") };
            match sides.iter_mut().find(|x| x.1 == how && x.0.map(|i| &i.compared) == version.map(|i| &i.compared)) {
                Some(x) => x.2.push(k),
                None => sides.push((version, how, vec![k])),
            }
        }
        if sides.len() < 2 { continue; }
        n += 1;
        md.push_str(&format!("{n}. {key}:\n"));
        for (side, (version, how, ks)) in sides.iter().enumerate() {
            let processes: usize = ks.iter().map(|k| behaviors[*k].1.len()).sum();
            let label = format!("{} — behavior{} {}, {}", if side == 0 { "either" } else { "or" },
                if ks.len() == 1 { "" } else { "s" }, ks.iter().map(|k| (k + 1).to_string()).collect::<Vec<_>>().join(", "), count(processes, "agent process", "agent processes"));
            match (how, version) {
                (&"leaves", _) => md.push_str(&format!("   - {label}: leaves it as trunk has it\n")),
                (&"removes", _) => md.push_str(&format!("   - {label}: removes it\n")),
                (_, Some(i)) => md.push_str(&format!("   - {label}: {}\n\n{}\n", if *how == "adds" { "adds it" } else { "changes it to" }, fenced(&i.written).lines().map(|l| format!("     {l}")).collect::<Vec<_>>().join("\n"))),
                _ => {}
            }
        }
        // The same words in another order: likely the same meaning.
        let tokens = |i: &Item| { let mut t: Vec<String> = i.compared.split(|c: char| !(c.is_alphanumeric() || c == '_')).filter(|w| !w.is_empty()).map(String::from).collect(); t.sort(); t };
        let versions: Vec<Vec<String>> = sides.iter().filter_map(|x| x.0.map(tokens)).collect();
        if versions.len() == sides.len() && versions.windows(2).all(|w| w[0] == w[1]) {
            md.push_str(&wrap("These sides use the same words in another order: they may well mean the same.", 3, 3));
        }
        md.push('\n');
    }
    if n == 0 { md.push_str(&para("None: every verified agent process made the same surface change.")); }

    // Reach, per behavior: what it changes in full, the kernel's functions that name it, and the rest.
    md.push_str("## Reach\n\n");
    let surface_count: usize = files.iter().map(|f| git(root, &["show", &format!("{base}:{f}")]).map(|t| surface(&t).len()).unwrap_or(0)).sum();
    for (k, (_, is)) in behaviors.iter().enumerate() {
        md.push_str(&format!("### Behavior {}: {}, `{}`\n\n", k + 1, who(is), patches[k]));
        for (key, how, _, b) in &changes[k] {
            match b {
                Some(i) => { md.push_str(&para(&format!("It {how} {key}, which reads:"))); md.push_str(&fenced(&i.written)); md.push('\n'); }
                None => md.push_str(&para(&format!("It {how} {key}."))),
            }
        }
        let names: Vec<String> = changes[k].iter().filter_map(|x| x.3.as_ref().or(x.2.as_ref()).map(|i| i.name.clone())).collect();
        let trace = git(root, &["log", "-1", "--format=%B", &commit_of(is[0])]).unwrap_or_default().lines().find_map(|l| l.strip_prefix("Trace: ").map(|t| root.join(t.trim()))).unwrap_or_default();
        let log: String = (0..m.config.checks.verify.len()).map(|v| std::fs::read_to_string(trace.join(format!("kernel-{v}"))).unwrap_or_default()).collect();
        let deps = dependents(root, &commit_of(is[0]), &files, &names, &log);
        if !log.contains("verification results") {
            let first = log.lines().find(|l| l.starts_with("error")).unwrap_or("it did not finish");
            md.push_str(&para(&format!("The kernel does not build with this change ({first}): code must follow it before anything proves.")));
        }
        let with = |st: &str| deps.iter().filter(|d| d.2 == st).count();
        md.push_str(&para(&format!("The kernel's functions that name what it changes: {} ({} still prove, {} fail, {} not built).",
            deps.len(), with("still proves"), with("fails"), with("not built"))));
        for (f, name, st) in deps.iter().filter(|d| d.2 != "still proves").take(40) { md.push_str(&item(&format!("{f}: `{name}` {st}"))); }
        // A proof's body is an agent's own words, so it is not part of the
        // surface and does not count toward a behavior (B3): a change to a
        // proof's body alone leaves the surface item unchanged. Say, for every
        // proof whose body changed, that it did, so the review never hides an
        // admitted proof behind an unchanged contract.
        let proofs = |commit: &str| -> Vec<(String, String)> {
            files.iter().flat_map(|f| surface(&git(root, &["show", &format!("{commit}:{f}")]).unwrap_or_default())
                .into_iter().filter(|it| it.kind == "proof").map(|it| (it.name, it.written))).collect::<Vec<_>>()
        };
        let (was, now_) = (proofs(&base), proofs(&commit_of(is[0])));
        let changed_names: Vec<String> = changes[k].iter().filter_map(|x| x.3.as_ref().or(x.2.as_ref()).map(|i| i.name.clone())).collect();
        let body_changed: Vec<&String> = now_.iter().filter(|(n, body)| was.iter().any(|(wn, wb)| wn == n && wb != body)
            && !changed_names.contains(n)).map(|(n, _)| n).collect();
        for n in &body_changed { md.push_str(&item(&format!("the proof `{n}`'s body changed, though its contract did not: read `{}` to see how it now proves it.", patches[k]))); }
        let rest = surface_count.saturating_sub(changes[k].iter().filter(|x| x.1 != "adds").count());
        md.push('\n');
        md.push_str(&para(&format!("The rest of the spec's surface, {}, is unchanged.", count(rest, "item", "items"))));
    }
    md.push_str("## Scenarios\n\n");
    md.push_str(&wrap("None derived: bon does not yet write the cases that tell two specs apart.", 0, 0));
    let review = dir.join("review.md");
    std::fs::write(&review, &md).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let record = serde_json::json!({
        "source": format!("queue {id}"), "intent": intent, "files": files, "raised": now, "review": format!("{at}/review.md"),
        "agent_processes": s.n, "verified": verified.len(), "decisions": n,
        "behaviors": behaviors.iter().enumerate().map(|(k, (_, is))| serde_json::json!({ "agent_processes": is, "patch": patches[k] })).collect::<Vec<_>>(),
    });
    std::fs::write(dir.join("proposal.json"), serde_json::to_string_pretty(&record).unwrap_or_default()).map_err(|e| e.to_string())?;
    Ok(format!("{at}/review.md"))
}

// ── what a search may write (queue 67, 68, 69) ──────────
//
// The rules of what a search may write and how its candidates are judged.
// `bon check` applies them to engineer's tree (every search that reaches
// trunk may write it); `capture` applies them to a candidate by its own
// kind's authority (`broken_by_candidate`). One definition, read from the
// tree, the manifest and the kernel's authority (`exec::authority_contains`);
// nothing of a candidate's runs.

pub const PROVEN_OR_CHECKED: &str = "every line a search may write is proven, or program code with declared checks";
pub const NO_CHECK_WRITABLE: &str = "no check lives in a file a search may write";
pub const NOT_JUDGED: &str = "nothing a candidate writes changes how it is judged";

/// A predicate: whether a search of any of `kinds` may write `path`, as the
/// kernel's authority decides with the manifest's checks, tests and trusted
/// code (`exec::authority_contains`, the single source).
fn writable_for<'a>(m: &'a Manifest, kinds: Vec<Kind>) -> impl Fn(&str) -> bool + 'a {
    let (c, t, tr) = (checks(m), tests(m), trusted(m));
    move |path| { let p = Path(path.chars().collect()); kinds.iter().any(|k| crate::exec::authority_contains(k, &c, &t, &tr, &p)) }
}

/// The three kinds whose candidates reach trunk and may write code: a fresh
/// value of each, its goal empty (authority does not read the goal, but for
/// a foil's `changed`, which `bon check` does not test).
fn trunk_kinds() -> Vec<Kind> {
    vec![Kind::Code { goal: Commit(vec![]) }, Kind::Compaction { goal: Commit(vec![]), out: vec![] }, Kind::Counterexample { goal: None }]
}

/// Where `commit`'s tree breaks a rule, one line each: the file, what is
/// wrong, and the rule. `writable(path)` says whether a search may write it.
/// Read from the tree, the manifest and the kernel's authority; nothing runs.
/// - every file a search may write is proven (a module of the root package's
///   library: the kernel) or program code a declared check reads (a Rust file
///   of a target a cargo check builds, or one under a path a check names);
/// - no file a check runs (by its path, its cargo target, or `cargo run`'s
///   binary) is one a search may write, but the counterexample's own `path`;
/// - no local crate has a build script or is a proc macro; no file a search
///   may write holds a unit test, but the counterexamples' tests, which are
///   judged by their evidence; and the kernel holds nothing outside `verus!`
///   but `use`, `mod` and `extern crate` declarations.
fn rules_with(root: &std::path::Path, commit: &str, m: &Manifest, writable: &dyn Fn(&str) -> bool) -> Result<Vec<String>, String> {
    let files: Vec<String> = git(root, &["ls-tree", "-r", "-z", "--name-only", commit])?.split('\0').filter(|f| !f.is_empty()).map(String::from).collect();
    let read = |p: &str| git(root, &["cat-file", "blob", &format!("{commit}:{p}")]).unwrap_or_default();
    let exists = |p: &str| files.iter().any(|f| f == p);
    let c = &m.config;
    let mut broken = Vec::new();
    // Every local crate: no build script, no proc macro.
    for manifest in files.iter().filter(|f| f.rsplit('/').next() == Some("Cargo.toml")) {
        let dir = manifest.strip_suffix("Cargo.toml").unwrap_or("");
        let Ok(t) = toml::from_str::<toml::Value>(&read(manifest)) else {
            broken.push(format!("{manifest}: not TOML cargo can read ({NOT_JUDGED})"));
            continue;
        };
        let build = match t.get("package").and_then(|p| p.get("build")) {
            Some(toml::Value::String(b)) => Some(format!("{dir}{b}")),
            Some(toml::Value::Boolean(false)) => None,
            _ => exists(&format!("{dir}build.rs")).then(|| format!("{dir}build.rs")),
        };
        if let Some(b) = build { broken.push(format!("{manifest}: a local crate with a build script, {b}, which runs when a check builds ({NOT_JUDGED})")); }
        if ["proc-macro", "proc_macro"].iter().any(|k| t.get("lib").and_then(|l| l.get(*k)).and_then(|v| v.as_bool()) == Some(true)) {
            broken.push(format!("{manifest}: a local crate that is a proc macro, which runs when a check builds ({NOT_JUDGED})"));
        }
    }
    // The root package's targets, by cargo's defaults and its [lib], [[bin]], [[test]] and [[example]].
    let package: toml::Value = toml::from_str(&read("Cargo.toml")).unwrap_or(toml::Value::Table(Default::default()));
    let declared = |key: &str| -> Vec<String> {
        package.get(key).and_then(|v| v.as_array()).into_iter().flatten().filter_map(|t| t.get("path").and_then(|p| p.as_str()).map(String::from)).collect()
    };
    let auto = |dir: &str| -> Vec<String> {
        files.iter().filter(|f| f.strip_prefix(dir).is_some_and(|r| r.ends_with(".rs") && (!r.contains('/') || r.ends_with("/main.rs")))).cloned().collect()
    };
    let lib = package.get("lib").and_then(|l| l.get("path")).and_then(|p| p.as_str()).map(String::from)
        .or_else(|| exists("src/lib.rs").then(|| "src/lib.rs".to_string()));
    let kernel: Vec<String> = lib.iter().flat_map(|r| modules(r, &read, &exists, Some(&mut broken))).collect();
    // Every check: (command, whether it is the counterexample's, which runs the test at its `path`).
    let commands: Vec<(&str, bool)> = c.checks.test.iter().chain(&c.checks.verify).chain(&c.checks.agree).chain(c.checks.rank.values())
        .chain(&c.checks.staged).map(|s| (s.as_str(), false))
        .chain([(c.counterexample.build.as_str(), true), (c.counterexample.run.as_str(), true)]).collect();
    let runs = |prefix: &str| commands.iter().any(|(w, _)| w.trim_start().starts_with(prefix));
    let mut compiled: Vec<String> = Vec::new();
    if runs("cargo ") {
        let mut roots = declared("bin");
        roots.extend(auto("src/bin/"));
        if exists("src/main.rs") { roots.push("src/main.rs".into()); }
        if runs("cargo test") { roots.extend(declared("test")); roots.extend(declared("example")); roots.extend(auto("tests/")); roots.extend(auto("examples/")); }
        for r in roots { compiled.extend(modules(&r, &read, &exists, None)); }
    }
    let bin = |name: &str| -> Option<String> {
        package.get("bin").and_then(|v| v.as_array()).into_iter().flatten().find(|b| b.get("name").and_then(|n| n.as_str()) == Some(name))
            .and_then(|b| b.get("path").and_then(|p| p.as_str()).map(String::from))
            .or_else(|| [format!("src/bin/{name}.rs"), format!("src/bin/{name}/main.rs")].into_iter().find(|p| exists(p)))
            .or_else(|| (package.get("package").and_then(|p| p.get("name")).and_then(|n| n.as_str()) == Some(name) && exists("src/main.rs")).then(|| "src/main.rs".into()))
    };
    // What each check names: a file by its path, a cargo target, `cargo run`'s binary; and the directories it reads under.
    let mut named: Vec<(String, &str)> = Vec::new();
    let mut under: Vec<String> = Vec::new();
    for (command, own) in &commands {
        let w: Vec<&str> = command.split_whitespace().map(|w| w.trim_matches(|ch: char| "\"'();&|".contains(ch))).collect();
        for (k, word) in w.iter().enumerate() {
            let target = match (k.checked_sub(1).map(|j| w[j]), *word) {
                (Some("--test"), n) => Some(format!("tests/{n}.rs")),
                (Some("--example"), n) => Some(format!("examples/{n}.rs")),
                (Some("--bench"), n) => Some(format!("benches/{n}.rs")),
                (Some("--bin"), n) => bin(n),
                (Some("cargo"), "run") if !w.contains(&"--bin") && !w.contains(&"--example") =>
                    package.get("package").and_then(|p| p.get("default-run")).and_then(|d| d.as_str()).and_then(|d| bin(d)),
                (_, p) if exists(p) => Some(p.to_string()),
                (_, p) if !p.is_empty() && files.iter().any(|f| f.starts_with(&format!("{}/", p.trim_end_matches('/')))) => {
                    under.push(p.trim_end_matches('/').to_string());
                    None
                }
                _ => None,
            };
            if let Some(t) = target.filter(|t| !(*own && *t == c.counterexample.path)) { named.push((t, command)); }
        }
    }
    for (t, command) in &named {
        if writable(t) { broken.push(format!("{t}: the check `{command}` runs it, and a search may write it ({NO_CHECK_WRITABLE})")); }
    }
    let landed = |f: &str| c.counterexample.tests.iter().any(|t| f.starts_with(t.as_str()));
    for f in files.iter().filter(|f| writable(f)) {
        let read_by_check = compiled.contains(f) || named.iter().any(|(t, _)| t == f) || under.iter().any(|d| f.starts_with(&format!("{d}/")));
        if !kernel.contains(f) && !read_by_check {
            broken.push(format!("{f}: a search may write it, and it is neither proven, in the kernel, nor read by a declared check ({PROVEN_OR_CHECKED})"));
        }
        if !f.ends_with(".rs") { continue; }
        let text = read(f);
        if !landed(f) {
            if let Some(n) = unit_test(&text) { broken.push(format!("{f}:{n}: a unit test in a file a search may write ({NOT_JUDGED})")); }
        }
        if kernel.contains(f) {
            for n in outside_verus(&text) { broken.push(format!("{f}:{n}: plain Rust outside verus! in the kernel ({NOT_JUDGED})")); }
        }
    }
    Ok(broken)
}

/// Where `commit`'s tree breaks a rule, judged for every search that reaches
/// trunk: `bon check` on engineer's tree.
pub fn rules(root: &std::path::Path, commit: &str, m: &Manifest) -> Result<Vec<String>, String> {
    rules_with(root, commit, m, &writable_for(m, trunk_kinds()))
}

/// The kernel's files at `commit`: the root package's library modules (from
/// `src/lib.rs`) that hold a `verus!` block and are not trusted, as the
/// account's proven rule reads the working tree, but at a commit from git.
/// Empty when there is no library. Used to tell a stale install from trunk's
/// kernel without a list of file names in code.
pub fn broken_by_candidate(m: &Manifest, kind: &Kind, base: &str, commit: &str) -> Option<String> {
    let mut one = Kind::Counterexample { goal: None };
    one = match kind {
        Kind::Queue { .. } => Kind::Queue { goal: Transcript(Path(vec![])) },
        Kind::Code { .. } => Kind::Code { goal: Commit(vec![]) },
        Kind::Compaction { .. } => Kind::Compaction { goal: Commit(vec![]), out: vec![] },
        Kind::Counterexample { .. } => one,
        Kind::Foil { changed, .. } => Kind::Foil { goal: crate::gates::AgentProcess { search: 0, index: 0 }, changed: changed.clone() },
        Kind::Spec { files, .. } => Kind::Spec { goal: Intent(vec![]), files: files.clone() },
    };
    let writable = writable_for(m, vec![one]);
    let at = |c: &str| rules_with(&m.root, c, m, &writable);
    match (at(base), at(commit)) {
        (Ok(b), Ok(c)) => c.into_iter().find(|x| !b.contains(x)),
        (_, Err(e)) | (Err(e), _) => Some(format!("the rules could not be read on the candidate: {e} ({NOT_JUDGED})")),
    }
}

/// A Rust file and the modules it declares (`mod name;`), each where cargo
/// looks for it, recursively. A `#[path]` module is not followed: in the
/// kernel (`broken` Some) it is broken, since its plain Rust would go unread.
fn modules(file: &str, read: &dyn Fn(&str) -> String, exists: &dyn Fn(&str) -> bool, mut broken: Option<&mut Vec<String>>) -> Vec<String> {
    let mut out = vec![file.to_string()];
    let mut k = 0;
    while k < out.len() {
        let f = out[k].clone();
        k += 1;
        let t = tokens(&read(&f));
        let at = |i: usize| t.get(i).map_or("", |(s, _)| s.as_str());
        // A crate root's or a mod.rs's modules sit beside it; another file's, in the directory of its name.
        let dir = if k == 1 || f.ends_with("/mod.rs") { f.rsplit_once('/').map_or(String::new(), |(d, _)| format!("{d}/")) }
                  else { format!("{}/", f.trim_end_matches(".rs")) };
        for i in 0..t.len() {
            if let Some(b) = broken.as_deref_mut().filter(|_| at(i) == "#" && at(i + 1) == "[" && at(i + 2) == "path") {
                b.push(format!("{f}:{}: a #[path] module, which bon does not follow ({NOT_JUDGED})", t[i].1));
            }
            if at(i) == "mod" && at(i + 2) == ";" {
                let name = at(i + 1);
                if let Some(p) = [format!("{dir}{name}.rs"), format!("{dir}{name}/mod.rs")].into_iter().find(|p| exists(p)) {
                    if !out.contains(&p) { out.push(p); }
                }
            }
        }
    }
    out
}

/// The line of the first unit test in Rust source: a `#[test]` attribute (or
/// `#[a::test]`), or a `cfg` attribute that names `test`.
fn unit_test(text: &str) -> Option<usize> {
    let t = tokens(text);
    let at = |i: usize| t.get(i).map_or("", |(s, _)| s.as_str());
    (0..t.len()).find(|&i| {
        if at(i) != "#" || at(i + 1) != "[" { return false; }
        let body: Vec<&str> = (i + 2..t.len()).map(at).take_while(|w| *w != "]").collect();
        (body.last() == Some(&"test") && body.iter().all(|w| *w == ":" || w.chars().all(|ch| ch.is_alphanumeric() || ch == '_')))
            || (body.first() == Some(&"cfg") && body.contains(&"test"))
    }).map(|i| t[i].1)
}

/// The lines of Rust source's items outside every `verus! { … }` that are not
/// a `use`, a `mod name;` or an `extern crate`, with the attributes on them.
fn outside_verus(text: &str) -> Vec<usize> {
    let t = tokens(text);
    let at = |i: usize| t.get(i).map_or("", |(s, _)| s.as_str());
    // The index past the group that opens at i ({, ( or [).
    let group = |i: usize| -> usize {
        let mut depth = 0i64;
        for j in i..t.len() {
            match at(j) {
                "{" | "(" | "[" => depth += 1,
                "}" | ")" | "]" => { depth -= 1; if depth == 0 { return j + 1; } }
                _ => {}
            }
        }
        t.len()
    };
    let mut lines = Vec::new();
    let mut i = 0;
    while i < t.len() {
        if at(i) == "#" {
            let a = if at(i + 1) == "!" { i + 2 } else { i + 1 };
            if at(a) == "[" { i = group(a); continue; }
        }
        if at(i) == "verus" && at(i + 1) == "!" { i = group(i + 2); continue; }
        let mut j = i;
        if at(j) == "pub" { j += 1; if at(j) == "(" { j = group(j); } }
        let declaration = at(j) == "use" || (at(j) == "mod" && at(j + 2) == ";") || (at(j) == "extern" && at(j + 1) == "crate");
        if !declaration { lines.push(t[i].1); }
        // To the item's end: its `;`, or its body, at depth zero.
        while j < t.len() {
            match at(j) {
                ";" => { j += 1; break; }
                "{" => { j = group(j); if at(j) == ";" { j += 1; } break; }
                "(" | "[" => j = group(j),
                _ => j += 1,
            }
        }
        i = j;
    }
    lines
}

/// Each place a Rust file outside `declared` (the trusted files and the checks)
/// skips a proof: `#[verifier::external…]`, `assume(` or `admit(`, as path:line.
pub fn holes(root: &std::path::Path, declared: &[String]) -> Vec<String> {
    fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if p.is_dir() {
                if !name.starts_with('.') && name != "target" && name != "node_modules" { walk(&p, root, out); }
            } else if name.ends_with(".rs") {
                out.push(p.strip_prefix(root).unwrap_or(&p).to_path_buf());
            }
        }
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort();
    let mut found = Vec::new();
    for f in files {
        let rel = f.to_string_lossy().to_string();
        if declared.iter().any(|d| rel == *d || rel.starts_with(&format!("{}/", d.trim_end_matches('/')))) { continue; }
        let Ok(text) = std::fs::read_to_string(root.join(&f)) else { continue };
        for n in skips(&text) { found.push(format!("{rel}:{n}")); }
    }
    found
}

/// The lines of Rust source `text` that skip a proof, read by tokens: a call of
/// `assume` or `admit`, an `assume_specification`, or a `verifier::external…`
/// or `verifier(external…)` attribute. Comments and literals are not code.
pub fn skips(text: &str) -> Vec<usize> {
    let tokens = tokens(text);
    let t = |k: usize| tokens.get(k).map_or("", |(s, _)| s.as_str());
    let mut lines = Vec::new();
    for (k, (word, n)) in tokens.iter().enumerate() {
        let call = matches!(word.as_str(), "assume" | "admit") && t(k + 1) == "(" && (k == 0 || t(k - 1) != "fn");
        let specification = word == "assume_specification";
        // #[verifier::external…] or #[verifier(external…)], also as an inner #![…].
        let attribute = word == "#" && {
            let a = if t(k + 1) == "!" { k + 2 } else { k + 1 };
            t(a) == "[" && t(a + 1) == "verifier"
                && ((t(a + 2) == ":" && t(a + 3) == ":" && t(a + 4).starts_with("external"))
                    || (t(a + 2) == "(" && t(a + 3).starts_with("external")))
        };
        if (call || specification || attribute) && lines.last() != Some(n) { lines.push(*n); }
    }
    lines
}

/// Rust source as tokens: identifiers and single punctuation, each with its
/// line. Comments and literals are not code: they make no token.
pub fn tokens(text: &str) -> Vec<(String, usize)> {
    let c: Vec<char> = text.chars().collect();
    let ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut tokens: Vec<(String, usize)> = Vec::new();
    let (mut i, mut line) = (0, 1);
    // Skips past the closing `"` of a string whose body starts at `j`; raw
    // strings (`hashes` is Some) have no escapes.
    let string_end = |mut j: usize, hashes: Option<usize>, line: &mut usize| -> usize {
        while j < c.len() {
            match (c[j], hashes) {
                ('\n', _) => { *line += 1; j += 1; }
                ('\\', None) => { if c.get(j + 1) == Some(&'\n') { *line += 1; } j += 2; }
                ('"', None) => return j + 1,
                ('"', Some(h)) if c[j + 1..].iter().take(h).filter(|&&x| x == '#').count() == h => return j + 1 + h,
                _ => j += 1,
            }
        }
        j
    };
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        if ch == '\n' { line += 1; i += 1; }
        else if ch.is_whitespace() { i += 1; }
        else if ch == '/' && next == Some('/') { while i < c.len() && c[i] != '\n' { i += 1; } }
        else if ch == '/' && next == Some('*') {
            let mut depth = 0;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') { depth += 1; i += 2; }
                else if c[i] == '*' && c.get(i + 1) == Some(&'/') { depth -= 1; i += 2; if depth == 0 { break; } }
                else { if c[i] == '\n' { line += 1; } i += 1; }
            }
        }
        else if ch == '"' { i = string_end(i + 1, None, &mut line); }
        else if ch == '\'' {
            // A char literal, or a lifetime (no closing quote right after one char).
            if next == Some('\\') { i += 3; while i < c.len() && c[i] != '\'' { i += 1; } i += 1; }
            else if c.get(i + 2) == Some(&'\'') { i += 3; }
            else { i += 1; }
        }
        else if ident(ch) {
            let start = i;
            while i < c.len() && ident(c[i]) { i += 1; }
            let word: String = c[start..i].iter().collect();
            // String prefixes: b"…", r"…", r#"…"#, br#"…"#, c"…", b'…'.
            let raw = matches!(word.as_str(), "r" | "br" | "cr");
            let hashes = c[i..].iter().take_while(|&&x| x == '#').count();
            if raw && c.get(i + hashes) == Some(&'"') { i = string_end(i + hashes + 1, Some(hashes), &mut line); }
            else if matches!(word.as_str(), "b" | "c") && c.get(i) == Some(&'"') { i = string_end(i + 1, None, &mut line); }
            else if word == "b" && c.get(i) == Some(&'\'') {
                i += 1;
                if c.get(i) == Some(&'\\') { i += 1; }
                while i < c.len() && c[i] != '\'' { i += 1; }
                i += 1;
            }
            else { tokens.push((word, line)); }
        }
        else { tokens.push((ch.to_string(), line)); i += 1; }
    }
    tokens
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_check_log_says_the_one_shape_once() {
        let on = super::On { tree: "t1".into(), test: Some(("tests/x.rs", b"")), cache: super::Cache::Off };
        let log = "exit: 0\nseconds: 1.0\n--- stdout\nok\n--- stderr\n";
        let shaped = super::check_record("cargo   test -q", &on, log, "ok\n");
        assert!(shaped.starts_with(&format!("exit: 0\nseconds: 1.0\nprogram: cargo test -q\ncontext: t1 + tests/x.rs\nbehavior: {}\n--- stdout\nok\n", super::hash("ok\n"))), "{shaped}");
        // Shaped again (a cached run's log), it is left as it is; a log with no head gets one at its top.
        assert_eq!(super::check_record("other", &on, &shaped, ""), shaped);
        assert!(super::check_record("c", &on, "no build directory", "").starts_with("program: c\ncontext: t1 + tests/x.rs\n"));
        // What reads a log's seconds reads its first two lines: they stay where they were.
        assert_eq!(shaped.lines().take(2).collect::<Vec<_>>(), ["exit: 0", "seconds: 1.0"]);
    }

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
    fn another_host_file_must_be_writable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(checked_host(None), Ok(PathBuf::from(HOST)));
        let p = std::env::temp_dir().join(format!("bon-host-test-{}.toml", std::process::id()));
        std::fs::write(&p, "path = []\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(checked_host(Some(p.to_string_lossy().into())), Ok(p.clone()));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(checked_host(Some(p.to_string_lossy().into())).is_err());
        let _ = std::fs::remove_file(&p);
        assert!(checked_host(Some(p.to_string_lossy().into())).is_err());
    }

    #[test]
    fn the_pools_are_sized_from_the_host_file() {
        let host = |keys: &str| -> Host { toml::from_str(&format!("{keys}\nuser = \"/u\"\npath = []\nrustup_home = \"\"\ncargo_home = \"\"\n[prices]\n")).unwrap() };
        // queue 26: width stays what bon.toml says; the pools bound what runs at once.
        // queue 54: the host file sets both pools directly.
        assert_eq!(Pools::of(&host("agent_processes = 500\ncheck_processes = 3\ncheck_threads = 4")), Pools { agent_processes: 500, check_processes: 3, threads: 4 });
        // At least one of each.
        assert_eq!(Pools::of(&host("agent_processes = 0\ncheck_processes = 0\ncheck_threads = 0")), Pools { agent_processes: 1, check_processes: 1, threads: 1 });
        // Unset: 64 agent processes, and as many checks as this machine's free memory and cores hold.
        let unset = Pools::of(&host(""));
        assert_eq!((unset.agent_processes, unset.threads), (64, 2));
        assert!(unset.check_processes >= 1);
        // The default pool: a 24 GB, 12-core laptop with 16 GB free holds 10 checks of 2 threads;
        // memory binds before cores (7 GB holds 4); threads before memory (14 cores take 14 of 2).
        assert_eq!((check_pool(12, 16.0, 2), check_pool(14, 7.0, 2), check_pool(14, 45.0, 2)), (10, 4, 14));
        assert_eq!(check_pool(14, 40.0, 1), 26);
        assert_eq!(check_pool(1, 0.5, 1), 1);
    }

    #[test]
    fn a_host_file_or_manifest_with_a_key_bon_no_longer_reads_names_what_replaced_it() {
        // queue 54: the pools' old names and the sizes they were computed from.
        for (old, now) in [("generation = 8", "agent_processes"), ("jobs = 8", "agent_processes"), ("checks = 8", "check_processes"),
                           ("cores = 8", "check_processes"), ("memory_gb = 8.0", "check_processes")] {
            let e = renamed(&format!("{old}\npath = []"), true).unwrap_err();
            assert!(e.contains(&format!("`{}` is gone", old.split(' ').next().unwrap())) && e.contains(now), "{e}");
        }
        // queue 52, 53: a manifest of harnesses, or of [programs].
        let e = renamed("[[harness]]\nname = \"codex\"\nmodel = \"m\"\nn = [1]\n", false).unwrap_err();
        assert!(e.contains("`harness` is gone") && e.contains("[searches]"), "{e}");
        let e = renamed("[counterexample]\nharness = [{ name = \"claude\", model = \"m\", n = [2] }]\n", false).unwrap_err();
        assert!(e.contains("`counterexample.harness` is gone") && e.contains("[searches]"), "{e}");
        assert!(renamed("[programs]\nfrom = []\n", false).unwrap_err().contains("[types]"));
        // A manifest's [checks] table is no host key.
        assert!(renamed("[checks]\npaths = []\n", false).is_ok());
        // bon's own manifest is in the new shape.
        assert!(renamed(include_str!("../.bon/bon.toml"), false).is_ok());
        assert!(toml::from_str::<Config>(include_str!("../.bon/bon.toml")).is_ok());
    }

    #[test]
    fn a_kept_trunk_build_is_reused_only_while_no_one_else_can_write_it() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("bon-kept-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("build/debug")).unwrap();
        std::fs::write(d.join("build/debug/libm.dylib"), "").unwrap();
        for p in [d.clone(), d.join("build"), d.join("build/debug")] { std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap(); }
        std::fs::set_permissions(d.join("build/debug/libm.dylib"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mine = std::fs::metadata(WORKING_DIRECTORIES).is_ok_and(|m| std::os::unix::fs::MetadataExt::uid(&m) == std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&d).unwrap()));
        if mine {
            assert!(engineers_alone(&d));
            // One file a group may write: not reused.
            std::fs::set_permissions(d.join("build/debug/libm.dylib"), std::fs::Permissions::from_mode(0o775)).unwrap();
            assert!(!engineers_alone(&d));
        }
        // The key is trunk's tree, its checks and the toolchain's identity.
        let c = config();
        assert_eq!(trunk_key(&c, "abc"), trunk_key(&c, "abc"));
        assert_ne!(trunk_key(&c, "abc"), trunk_key(&c, "abd"));
        let mut other = config();
        other.checks.verify = vec!["cargo verus verify -- --rlimit 9".into()];
        assert_ne!(trunk_key(&c, "abc"), trunk_key(&other, "abc"));
        assert_eq!(trunk_key(&c, ""), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_build_shares_only_libraries_built_from_outside_the_repository() {
        let d = std::env::temp_dir().join(format!("bon-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (snapshot, checkout) = (d.join("build"), d.join("checkout"));
        let deps = snapshot.join("debug/deps");
        std::fs::create_dir_all(&deps).unwrap();
        let file = |name: &str, text: &str| std::fs::write(deps.join(name), text).unwrap();
        // A registry proc macro: every source absolute, outside the checkout.
        file("macros-1.d", "/b/debug/deps/libmacros-1.dylib: /home/registry/macros/src/lib.rs /home/registry/macros/src/a\\ b.rs\n\n/x:\n");
        file("libmacros-1.dylib", "");
        // The repository's own proc macro (relative), and one whose source is in the checkout.
        file("own-2.d", "/b/debug/deps/libown-2.dylib: src/lib.rs\n");
        file("libown-2.dylib", "");
        file("path-3.d", &format!("/b/debug/deps/libpath-3.dylib: {}/macros/lib.rs\n", checkout.display()));
        file("libpath-3.dylib", "");
        // A registry library that is no dylib: cloned like the rest.
        file("syn-4.d", "/b/debug/deps/libsyn-4.rlib: /home/registry/syn/src/lib.rs\n");
        file("libsyn-4.rlib", "");
        write_links(&snapshot, &checkout);
        assert_eq!(std::fs::read_to_string(d.join("links")).unwrap(), "debug/deps/libmacros-1.dylib\n");
        // CLONE clones the build, then links what `links` names.
        let to = d.join("clone");
        assert!(Command::new("/bin/sh").args(["-c", CLONE, "sh"]).arg(&snapshot).arg(&to).status().unwrap().success());
        use std::os::unix::fs::MetadataExt;
        let ino = |p: &std::path::Path| std::fs::metadata(p).unwrap().ino();
        assert_eq!(ino(&to.join("debug/deps/libmacros-1.dylib")), ino(&deps.join("libmacros-1.dylib")));
        assert_ne!(ino(&to.join("debug/deps/libown-2.dylib")), ino(&deps.join("libown-2.dylib")));
        assert!(to.join("debug/deps/libsyn-4.rlib").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bons_cargo_caps_threads_and_holds_a_check_slot_while_it_runs() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("bon-cargo-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (bin, toolchain, slots) = (d.join("bin"), d.join("toolchain"), d.join("slots"));
        for x in [&bin, &toolchain, &slots] { std::fs::create_dir_all(x).unwrap(); }
        let text = cargo_text().replace("@SLOTS@", &slots.to_string_lossy()).replace("@N@", "1").replace("@THREADS@", "3").replace("@SELF@", &bin.to_string_lossy());
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
        // A session's first cargo clones trunk's build into its own; a later one leaves it alone.
        let (warm, target) = (d.join("warm"), d.join("target"));
        for x in [&warm.join("debug"), &target] { std::fs::create_dir_all(x).unwrap(); }
        std::fs::write(warm.join("debug/artifact"), "trunk").unwrap();
        let session = [("BON_WARM", warm.to_str().unwrap()), ("CARGO_TARGET_DIR", target.to_str().unwrap()), ("BON_CHECK_SLOT", "held")];
        run(&["build"], &session);
        assert_eq!(std::fs::read_to_string(target.join("debug/artifact")).unwrap(), "trunk");
        std::fs::write(target.join("debug/artifact"), "the session's").unwrap();
        run(&["build"], &session);
        assert_eq!(std::fs::read_to_string(target.join("debug/artifact")).unwrap(), "the session's");
        // A check (no BON_WARM) clones nothing.
        let other = d.join("other");
        std::fs::create_dir_all(&other).unwrap();
        run(&["build"], &[("CARGO_TARGET_DIR", other.to_str().unwrap()), ("BON_CHECK_SLOT", "held")]);
        assert!(!other.join("debug").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_check_is_cached_by_tree_command_and_test_and_never_when_killed() {
        let mut c = config();
        c.checks.time = 2;
        let tree = format!("test-tree-{}-{:?}", std::process::id(), Instant::now());
        let on = On { tree: tree.clone(), test: None, cache: Cache::Use };
        // Run confined (bon's judge runs bon's own tests as a slot's user), bon keeps no cache at all.
        if confined() { assert_eq!(verdict_key(&c, &on, "echo hi"), None); return; }
        let key = verdict_key(&c, &on, "echo hi").unwrap();
        // Each part of the key changes it; no tree, no key.
        assert_ne!(Some(key.clone()), verdict_key(&c, &on, "echo ho"));
        assert_ne!(Some(key.clone()), verdict_key(&c, &On { tree: tree.clone() + "x", test: None, cache: Cache::Use }, "echo hi"));
        assert_ne!(Some(key.clone()), verdict_key(&c, &On { tree: tree.clone(), test: Some(("t.rs", b"a")), cache: Cache::Use }, "echo hi"));
        assert_ne!(verdict_key(&c, &On { tree: tree.clone(), test: Some(("t.rs", b"a")), cache: Cache::Use }, "echo hi"),
                   verdict_key(&c, &On { tree: tree.clone(), test: Some(("t.rs", b"b")), cache: Cache::Use }, "echo hi"));
        assert_eq!(verdict_key(&c, &On { tree: String::new(), test: None, cache: Cache::Use }, "echo hi"), None);
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
        let off = On { tree: tree.clone(), test: None, cache: Cache::Refresh };
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
        // B4: a checkout is engineer's alone — read-only, no group or other
        // access — so no other slot's user and no agent process reads it.
        let co = d.join("checkout");
        check_directory(&d, "HEAD", &co).unwrap();
        for p in ["src/lib.rs", "run.sh", "tests"] {
            let m = std::fs::symlink_metadata(co.join(p)).unwrap().permissions().mode();
            assert_eq!(m & 0o077, 0, "{p} is {m:o}: no group or other access");
            assert_eq!(m & 0o222, 0, "{p} is {m:o}: read-only");
        }
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
        assert_eq!(c, vec!["checks/", ".cargo/", "build.rs", "rust-toolchain", "rust-toolchain.toml"]);
    }

    #[test]
    fn no_working_ancestor_file_may_decide_a_check() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let base = std::env::temp_dir().join(format!("bon-ancestor-{}", std::process::id()));
        let (top, mid) = (base.join("top"), base.join("top/mid"));
        std::fs::create_dir_all(&mid).unwrap();
        let me = std::fs::metadata(&mid).unwrap().uid();
        let dirs = vec![mid.clone(), top.clone(), base.clone()];
        // Nothing planted: the guard passes.
        let empty = ancestor_guard_over(&dirs, me).unwrap();
        // A parent Cargo.toml engineer owns is read as part of the signature, not refused.
        std::fs::write(top.join("Cargo.toml"), "[workspace]\n").unwrap();
        let with_toml = ancestor_guard_over(&dirs, me).unwrap();
        assert_ne!(empty, with_toml, "a Cargo.toml that appeared changes the signature, so a mid-run verdict is voided");
        // A world-writable one (anyone could replace it) is refused.
        std::fs::set_permissions(top.join("Cargo.toml"), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(ancestor_guard_over(&dirs, me).is_err(), "a Cargo.toml writable by others is a writable judge");
        // So is a toolchain file (a search's own must not pick its judge either).
        std::fs::set_permissions(top.join("Cargo.toml"), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(mid.join("rust-toolchain.toml"), "[toolchain]\npath = \"/x\"\n").unwrap();
        let with_tc = ancestor_guard_over(&dirs, me).unwrap();
        assert_ne!(with_toml, with_tc);
        std::fs::set_permissions(mid.join("rust-toolchain.toml"), std::fs::Permissions::from_mode(0o622)).unwrap();
        assert!(ancestor_guard_over(&dirs, me).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_default_toolchain_is_resolved_and_keyed() {
        // On this host rustup has a default; it is the name the checks run under.
        let tc = default_toolchain("/opt/bon/rustup", "/opt/bon/cargo/bin:/usr/bin:/bin");
        assert!(tc.as_deref().is_some_and(|t| t.contains('-')), "a toolchain name, from rustup's own default: {tc:?}");
        // It is in the toolchain the verdict key covers, so a candidate's toolchain
        // file cannot change which toolchain the key records.
        let mut c = config();
        c.toolchain.push(("RUSTUP_TOOLCHAIN".into(), tc.clone().unwrap()));
        let keyed = toolchain_identity(&c);
        assert!(keyed.contains(&tc.unwrap()));
    }

    #[test]
    fn a_candidate_that_moves_kernel_code_outside_verus_is_not_verified() {
        // queue 67-69 applied to a candidate (A2): the verify check gives exit 0
        // when a kernel function moves outside verus!, but the rules do not.
        let d = std::env::temp_dir().join(format!("bon-a2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("Cargo.toml"), "[package]\nname = \"k\"\nversion = \"0.0.0\"\nedition = \"2021\"\n").unwrap();
        std::fs::write(d.join("src/lib.rs"), "pub mod k;\n").unwrap();
        std::fs::write(d.join("src/k.rs"), "verus! {\npub fn f() -> u64 { 1 }\n} // verus!\n").unwrap();
        git(&d, &["init", "-q"]).unwrap();
        git(&d, &["add", "-A"]).unwrap();
        git(&d, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"]).unwrap();
        let base = git(&d, &["rev-parse", "HEAD"]).unwrap();
        // The candidate moves f outside verus! (its body never verified again).
        std::fs::write(d.join("src/k.rs"), "verus! {\n} // verus!\npub fn f() -> u64 { 1 }\n").unwrap();
        git(&d, &["add", "-A"]).unwrap();
        git(&d, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "cand"]).unwrap();
        let cand = git(&d, &["rev-parse", "HEAD"]).unwrap();
        let m = Manifest { config: config(), root: d.clone() };
        let code = Kind::Code { goal: Commit(vec![]) };
        assert!(broken_by_candidate(&m, &code, &base, &base).is_none(), "the base breaks no rule");
        let reason = broken_by_candidate(&m, &code, &base, &cand);
        assert!(reason.as_deref().is_some_and(|r| r.contains("src/k.rs") && r.contains("outside verus!")), "{reason:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_spec_candidate_that_adds_a_proof_skip_is_caught() {
        // B3: `assume(false)`/`admit`/`external_body` added to a changed spec
        // file verifies alone, but the skips its base did not have are seen (the
        // same `skips` the account uses). The check in capture compares them.
        let d = std::env::temp_dir().join(format!("bon-b3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("src/spec.rs"), "verus! {\npub proof fn p() ensures true { assert(true); }\n}\n").unwrap();
        git(&d, &["init", "-q"]).unwrap();
        git(&d, &["add", "-A"]).unwrap();
        git(&d, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"]).unwrap();
        let base = git(&d, &["rev-parse", "HEAD"]).unwrap();
        std::fs::write(d.join("src/spec.rs"), "verus! {\npub proof fn p() ensures true { admit(); }\n}\n").unwrap();
        git(&d, &["add", "-A"]).unwrap();
        git(&d, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "cand"]).unwrap();
        let cand = git(&d, &["rev-parse", "HEAD"]).unwrap();
        let at = |c: &str| skips(&git(&d, &["cat-file", "blob", &format!("{c}:src/spec.rs")]).unwrap()).len();
        assert_eq!(at(&base), 0);
        assert!(at(&cand) > at(&base), "a skip the base did not have");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The tests' host file: no prices beyond these, a verdict cache of their own (never /tmp/bon's).
    const TEST_HOST: &str = r#"
            user = "/the-tests-user-layer"
            path = ["/usr/bin", "/bin"]
            rustup_home = "/opt/bon/rustup"
            cargo_home = "/opt/bon/cargo-home"
            [roles.wide]
            program = ["claude", "-p"]
            client = "claude"
            model = "claude-haiku-5-5"
            [roles.deep]
            program = ["codex", "exec"]
            client = "codex"
            model = "gpt-6.1-sol"
            [roles.stub]
            program = ["/bin/sh", ".bon/stub.sh"]
            [prices]
            "claude-haiku-5-5" = { input = 0.10, cached_input = 0.01, output = 0.50, cache_write = 0.125, cache_write_long = 0.20 }
            "gpt-6.1-sol" = { input = 2.00, cached_input = 0.10, output = 10.00, cache_write = 2.50, cache_write_long = 5.00 }
        "#;

    const TEST_MANIFEST: &str = r#"
            limit = 5.0
            rate = 150
            agent_process = { limit = 0.5, time = 60 }
            checks = { paths = ["checks/"], test = ["true"], verify = ["true"], time = 60 }
            counterexample = { path = "tests/c.sh", build = "true", run = "sh tests/c.sh", tests = ["tests/"] }
            [searches]
            code = { role = "wide", n = [2, 4] }
            compaction = { role = "wide", n = [2] }
            queue = { role = "stub", n = [1] }
            counterexample = { role = "deep", n = [1] }
            foil = { role = "deep", n = [3] }
        "#;

    /// The tests' user layer (its state: their verdict cache, their process
    /// list): under the system's temporary directory, so bon's tests leave
    /// nothing in /tmp/bon (queue 86) or in the host's user layer.
    fn test_user() -> PathBuf { std::env::temp_dir().join(format!("bon-test-user-{}", std::process::id())) }

    fn config() -> Config {
        let host: Host = toml::from_str(&TEST_HOST.replace("/the-tests-user-layer", &test_user().to_string_lossy())).unwrap();
        with_host(toml::from_str(TEST_MANIFEST).unwrap(), host, std::path::Path::new("/test/host.toml")).unwrap()
    }

    fn program_of(c: &Config, role: &str) -> Program { Program { role: role.into(), run: c.roles[role].clone() } }

    #[test]
    fn each_kind_runs_its_own_role_and_the_host_says_what_runs() {
        // queue 53: one entry per kind, the foil apart from the counterexample; the host maps role to program.
        let c = config();
        let goal = Commit(vec![]);
        let p = |k: &Kind| program(&c, k);
        assert_eq!(p(&Kind::Code { goal: goal.clone() }).role, "wide");
        assert_eq!(p(&Kind::Queue { goal: "t.vtt".chars().collect() }).role, "stub");
        assert_eq!(p(&Kind::Counterexample { goal: None }).role, "deep");
        let m = Manifest { config: c.clone(), root: PathBuf::from(".") };
        let foil = Kind::Foil { goal: crate::gates::AgentProcess { search: 0, index: 0 }, changed: vec![] };
        assert_eq!((width(&m, &Kind::Counterexample { goal: None }, 0), width(&m, &foil, 0)), (1, 3));
        // The argv: the role's program, then its model; a stub's alone.
        assert_eq!(program_of(&c, "wide").argv(), ["claude", "-p", "--model", "claude-haiku-5-5"]);
        assert_eq!(program_of(&c, "stub").argv(), ["/bin/sh", ".bon/stub.sh"]);
        assert_eq!((program_of(&c, "wide").name(), program_of(&c, "stub").name()), ("claude".to_string(), "sh".to_string()));
        // A role the manifest names must be the host's; a client and a model, or neither; each model priced.
        let host = |extra: &str| -> Host { toml::from_str(&format!("{TEST_HOST}{extra}")).unwrap() };
        let manifest = |m: &str| -> Config { toml::from_str(&TEST_MANIFEST.replace("role = \"stub\"", m)).unwrap() };
        let f = std::path::Path::new("/h");
        assert!(with_host(manifest("role = \"missing\""), host(""), f).err().unwrap().contains("no role missing"));
        let odd = "[roles.odd]\nprogram = [\"x\"]\nmodel = \"claude-haiku-5-5\"\n";
        assert!(with_host(manifest("role = \"odd\""), toml::from_str(&TEST_HOST.replace("[prices]", &format!("{odd}[prices]"))).unwrap(), f).err().unwrap().contains("or neither"));
        let unpriced = "[roles.odd]\nprogram = [\"x\"]\nclient = \"claude\"\nmodel = \"claude-opus-5-5\"\n";
        assert!(with_host(manifest("role = \"odd\""), toml::from_str(&TEST_HOST.replace("[prices]", &format!("{unpriced}[prices]"))).unwrap(), f).err().unwrap().contains("no price for claude-opus-5-5"));
        let api = "[roles.odd]\nprogram = [\"bon-sample\"]\nclient = \"api\"\nmodel = \"claude-haiku-5-5\"\ncontext = 1000\n";
        assert!(with_host(manifest("role = \"odd\""), toml::from_str(&TEST_HOST.replace("[prices]", &format!("{api}[prices]"))).unwrap(), f).err().unwrap().contains("[api]"));
        let with_api = format!("[api]\naddress = \"http://127.0.0.1:1\"\nkey_file = \"/k\"\n{api}[prices]");
        assert!(with_host(manifest("role = \"odd\""), toml::from_str(&TEST_HOST.replace("[prices]", &with_api)).unwrap(), f).is_ok());
        let _ = host;
        // Unknown keys are refused in a role, as everywhere.
        assert!(toml::from_str::<Role>("program = [\"x\"]\nname = \"codex\"").is_err());
    }

    #[test]
    fn widths_repeat_their_last_value_and_set_the_attempts() {
        let c = config();
        assert_eq!((at(&c.searches.code.n, 0), at(&c.searches.code.n, 1), at(&c.searches.code.n, 5)), (2, 4, 4));
        assert_eq!(at(&c.searches.counterexample.n, 3), 1);
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
        let (ours, theirs, prices) = generation(&program_of(&c, "wide"), &c, out).unwrap();
        assert_eq!((ours, theirs), (2452, Some(2452)));
        assert_eq!(prices["claude-haiku-5-5"], c.prices["claude-haiku-5-5"]);
    }

    #[test]
    fn a_program_cost_of_zero_or_none_is_not_reported() {
        // bon-sample's usage line for the api and codex transports, which know no price.
        let c = config();
        for usage in [r#""costUSD":0.0"#, r#""costUSD":0"#, r#""x":0"#] {
            let out = format!(r#"{{"type":"result","requests":1,"modelUsage":{{"claude-haiku-5-5":{{"inputTokens":10,"outputTokens":1000,"cacheReadInputTokens":0,{usage}}}}}}}"#);
            assert_eq!(generation(&program_of(&c, "wide"), &c, &out).unwrap(), (501, None, HashMap::from([("claude-haiku-5-5".into(), c.prices["claude-haiku-5-5"].clone())])));
        }
    }

    #[test]
    fn a_large_request_is_billed_at_its_tier_where_the_output_says_each_request() {
        let mut c = config();
        // A host file without a tier still parses (config's has none); this one has one.
        let tiered: Price = toml::from_str("input = 0.10\ncached_input = 0.01\noutput = 0.50\ncache_write = 0.125\ncache_write_long = 0.20\ntier = { above = 100000, multiplier = 5 }").unwrap();
        assert_eq!(tiered.tier, Some(Tier { above: 100_000, multiplier: 5.0, output_multiplier: 1.0 }));
        c.prices.insert("claude-haiku-5-5".into(), tiered);
        let h = &program_of(&c, "wide");
        // One request (bon-sample's), 150k-token prompt: input side 5x, output 1x.
        let one = r#"{"type":"result","requests":1,"modelUsage":{"claude-haiku-5-5":{"inputTokens":10,"cacheReadInputTokens":150000,"outputTokens":1000}}}"#;
        assert_eq!(generation(h, &c, one).unwrap().0, 5 * (1 + 1500) + 500);
        // The same total over requests unknown: no tier can be told apart.
        assert_eq!(generation(h, &c, &one.replace(r#""requests":1,"#, "")).unwrap().0, 1 + 1500 + 500);
        // A session: each assistant message is one request (a repeated id once); only the large one is tiered.
        let session = r#"{"type":"assistant","message":{"id":"a","model":"claude-haiku-5-5","usage":{"input_tokens":10,"cache_read_input_tokens":150000,"output_tokens":1000}}}
{"type":"assistant","message":{"id":"a","model":"claude-haiku-5-5","usage":{"input_tokens":10,"cache_read_input_tokens":150000,"output_tokens":1000}}}
{"type":"assistant","message":{"id":"b","model":"claude-haiku-5-5","usage":{"input_tokens":6,"cache_read_input_tokens":1000,"output_tokens":100}}}
{"type":"result","modelUsage":{"claude-haiku-5-5":{"inputTokens":16,"cacheReadInputTokens":151000,"outputTokens":1100,"costUSD":0.008}}}"#;
        // Base 1.6 + 1510 + 550, and request a's input side again four times over.
        assert_eq!(generation(h, &c, session).unwrap(), (8066, Some(8000), HashMap::from([("claude-haiku-5-5".into(), c.prices["claude-haiku-5-5"].clone())])));
        // How many requests passed the threshold: one of the session's two, the one-shot's one; codex says nothing per request.
        // And what they cost beyond the base price: request a's input side four times over, the one-shot's likewise.
        assert_eq!((over_tier(h, &c, session), over_tier(h, &c, one)), (Some((1, 6004)), Some((1, 6004))));
        assert_eq!(over_tier(h, &c, &one.replace("150000", "1000")), Some((0, 0)));
        assert_eq!(over_tier(h, &c, r#"{"type":"turn.completed","usage":{"input_tokens":5}}"#), None);
    }

    #[test]
    fn codex_cost_is_the_last_running_total_with_cached_input_apart() {
        let c = config();
        let h = &program_of(&c, "deep");
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
            context: vec![],
        }
    }

    #[test]
    fn a_test_lands_on_trunk_by_itself() {
        let (remote, work, base, test) = landing_fixture("lands");
        let m = Manifest { config: config(), root: work.clone() };
        // What decided it, as capture keeps it: here, nothing to check again.
        keep_decided(&test, Vec::new());
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
        keep_decided(&test, Vec::new());
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
            kind, base: text(&base), n: 1, checks: vec![], tests: vec![text("tests/")], trusted: vec![], limit: 1, results: vec![Some(c)], context: vec![],
        };
        let tested = search(Kind::Code { goal: text(&base) }, candidate(&wrong, vec![], vec![]));
        let x = search(Kind::Counterexample { goal: Some(crate::gates::AgentProcess { search: 0, index: 0 }) },
                       candidate(&test, vec![text("tests/c_1.sh")], vec![(0, false)]));
        // The foil and counterexample searches ran after it.
        RUNS.store(3, std::sync::atomic::Ordering::SeqCst);
        let m = Manifest { config: config(), root: work.clone() };
        keep_decided(&test, Vec::new());
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
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_check_slot_s_user_writes_its_own_build_directory_alone() {
        // queue 62, 57, 56: what a candidate's check runs as (its slot's user) writes its own build directory, and
        // neither another slot's nor a kept trunk build; agent writes none of them; neither reads bon's state.
        let mut c = config();
        let asks = |who: Who| !confined() && run_as(who, &["/usr/bin/true"]).status().is_ok_and(|s| s.success());
        // Confined (a candidate's tests), there is no one to ask as; otherwise bon setup made the slot users.
        if confined() { return; }
        // Two slots held, as checks hold them: their users run nothing else meanwhile.
        c.pools.check_processes = c.pools.check_processes.max(2);
        let held = [Slot::check(&c), Slot::check(&c)];
        let (one, two) = (Who::Check(held[0].slot()), Who::Check(held[1].slot()));
        assert!(asks(one) && asks(two), "no check slot users: run bon setup");
        let can = |who: Who, argv: &[&str]| run_as(who, argv).status().is_ok_and(|s| s.success());
        let (b0, b1) = (named_build("slot-test.0/build", Start::Empty), named_build("slot-test.1/build", Start::Empty));
        assert!(ensure_build(&c, &b0, one) && ensure_build(&c, &b1, two));
        let file = |d: &PathBuf| d.join("x").to_string_lossy().to_string();
        assert!(can(one, &["/usr/bin/touch", &file(&b0)]), "a slot's user writes its own build directory");
        assert!(!can(one, &["/usr/bin/touch", &file(&b1)]), "and not another slot's");
        assert!(!can(one, &["/bin/ls", &b1.to_string_lossy()]), "nor reads it");
        assert!(!can(Who::Agent, &["/usr/bin/touch", &file(&b0)]), "agent writes no slot's build directory");
        // A slot's build is made again, empty, for another slot's user: nothing of the first stays.
        assert!(ensure_build(&c, &b0, two) && !b0.join("x").exists());
        assert!(can(two, &["/usr/bin/touch", &file(&b0)]) && !can(one, &["/usr/bin/touch", &file(&b0)]));
        remove_build(&c, &b0);
        remove_build(&c, &b1);
        assert!(!b0.exists() && !b1.exists(), "removed by its user, then engineer");
        // A kept build, as `keep` leaves one: read, never written.
        let kept = scratch("slot-test.kept");
        std::fs::create_dir_all(kept.join("build")).unwrap();
        std::fs::write(kept.join("build/lib.rlib"), "").unwrap();
        sh(&kept, "chmod", &["-R", "go-w", "."]).unwrap();
        for who in [Who::Agent, one] {
            assert!(can(who, &["/bin/cat", &kept.join("build/lib.rlib").to_string_lossy()]), "{who:?} reads a kept build");
            assert!(!can(who, &["/usr/bin/touch", &kept.join("build/lib.rlib").to_string_lossy()]), "{who:?} writes no kept build");
            assert!(!can(who, &["/usr/bin/touch", &kept.join("build/new").to_string_lossy()]), "{who:?} adds to no kept build");
        }
        // bon's state, in the user layer: no confined user reads, writes or searches it.
        let state = state_dir().unwrap();
        for who in [Who::Agent, one, two] {
            assert!(!can(who, &["/bin/ls", &state.to_string_lossy()]), "{who:?} lists no state");
            assert!(!can(who, &["/usr/bin/touch", &state.join("x").to_string_lossy()]), "{who:?} writes no state");
        }
        // What a check leaves running is stopped before the slot's next check.
        let mut left = Command::new("sudo").args(["-n", "-u", &one.name(), "/bin/sleep", "60"]).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        vacate(held[0].slot());
        let start = Instant::now();
        while left.try_wait().unwrap().is_none() && start.elapsed() < Duration::from_secs(5) { std::thread::sleep(Duration::from_millis(100)); }
        assert!(left.try_wait().unwrap().is_some(), "vacate stops what a slot's user left running");
        let _ = std::fs::remove_dir_all(&kept);
        for p in ["slot-test.0", "slot-test.1"] { let _ = std::fs::remove_dir_all(scratch(p)); }
    }

    #[test]
    fn engineers_time_is_charged_once_split_among_the_searches_he_waits_on() {
        // queue 59: every running search but a background one is waited on, across bon processes and repositories.
        let e = |started: Option<u64>, background: bool| serde_json::json!({ "started": started, "background": background });
        assert_eq!(waiting(&[e(Some(1), false), e(Some(2), false), e(Some(3), true), e(None, false)]), 2.0);
        assert_eq!(waiting(&[]), 1.0);
        // 2 s alone, then 4 s beside another, then 2 s alone again: 2 + 4/2 + 2 = 6 s charged.
        let t = Instant::now();
        let mut c = Charge { charged: 0.0, since: t, among: 1.0 };
        c.to(t + Duration::from_secs(2), 2.0);
        c.to(t + Duration::from_secs(6), 1.0);
        c.to(t + Duration::from_secs(8), 1.0);
        assert!((c.charged - 6.0).abs() < 1e-9, "{}", c.charged);
        // The other search, over the same 4 s, is charged the other half: the interval once.
        let mut d = Charge { charged: 0.0, since: t + Duration::from_secs(2), among: 2.0 };
        d.to(t + Duration::from_secs(6), 1.0);
        assert!((c.charged + d.charged - 8.0).abs() < 1e-9);
    }

    #[test]
    fn the_process_list_holds_each_running_bon_process_and_drops_a_stale_one() {
        // queue 58: an entry by pid and start time; one whose pid and start no longer match a live process is ignored and removed.
        let _ = config();
        let Some(list) = process_list() else { assert!(confined(), "the tests' user layer has a state"); return };
        let mut live = Command::new("sleep").arg("30").spawn().unwrap();
        let mut dead = Command::new("true").spawn().unwrap();
        let _ = dead.wait();
        let (pid, gone) = (u64::from(live.id()), u64::from(dead.id()));
        let start = started_at(&[pid])[&pid];
        let entry = |pid: u64, start: u64, started: Option<u64>, background: bool| serde_json::json!({ "pid": pid, "start": start,
            "repository": "/r", "trace": pid.to_string(), "background": background, "started": started });
        let files = [(pid, start, Some(1), false), (pid, start + 100, Some(1), false), (gone, start, Some(1), false)]
            .map(|(p, s, st, b)| { let f = list.join(format!("{p}.{s}.json")); write_entry(&f, &entry(p, s, st, b)); f });
        let (running, ended) = read_processes();
        // The live one is running; the same pid with another start (a reused pid), and a dead pid, ended.
        assert!(running.iter().any(|e| e["pid"] == pid && e["start"] == start));
        assert!(!running.iter().any(|e| e["start"] == start + 100 || e["pid"] == gone));
        assert!(ended.contains(&pid) && ended.contains(&gone));
        assert!(files[0].exists() && !files[1].exists() && !files[2].exists(), "a stale entry is removed");
        let _ = std::fs::remove_file(&files[0]);
        let _ = live.kill();
        let _ = live.wait();
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
    fn a_leader_has_spoken_at_its_first_output_not_at_its_end() {
        let log = std::env::temp_dir().join(format!("bon-spoke-test-{}", std::process::id()));
        let spoke = std::sync::Arc::new(Signal::default());
        let (s, start) = (spoke.clone(), Instant::now());
        let waiter = std::thread::spawn(move || { s.wait(); start.elapsed() });
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "echo replying; sleep 2; echo done"]);
        let r = supervised(c, Who::Agent, None, Duration::from_secs(10), &log, Some(spoke));
        let heard = waiter.join().unwrap();
        assert!(r.ok && r.stdout == "replying\ndone\n", "{}", r.stdout);
        assert!(heard < Duration::from_millis(1500), "{heard:?}");
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn a_time_limit_stops_everything_the_command_started() {
        // queue 47: a grandchild holding stdout dies with its command.
        let log = std::env::temp_dir().join(format!("bon-supervise-test-{}", std::process::id()));
        let c = as_agent(&config(), std::path::Path::new("/tmp"), &[], &["/bin/sh".into(), "-c".into(), "/bin/sleep 60 & wait".into()]);
        let start = Instant::now();
        let Run { ok, killed, .. } = supervised(c, Who::Agent, None, Duration::from_secs(1), &log, None);
        assert!(!ok && killed, "{}", std::fs::read_to_string(&log).unwrap_or_default());
        assert!(start.elapsed() < Duration::from_secs(6), "{:?}", start.elapsed());
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn a_program_that_never_started_is_told_apart_and_why_it_cannot_run_is_said() {
        // M3: spawn failed, or env could not run it (126, 127), with no output: never started.
        let log = std::env::temp_dir().join(format!("bon-started-test-{}", std::process::id()));
        let run = |c: Command| supervised(c, Who::Agent, None, Duration::from_secs(10), &log, None);
        assert!(never_started(&run(Command::new("/nonexistent/program"))));
        let mut c = Command::new("/usr/bin/env"); c.arg("/etc/hosts");
        let r = run(c);
        assert!(r.exit == Some(126) && never_started(&r), "{}", r.log);
        let mut c = Command::new("/usr/bin/env"); c.arg("no-such-program-anywhere");
        assert!(never_started(&run(c)));
        // A program that ran and failed, or printed anything, started.
        let mut c = Command::new("/bin/sh"); c.args(["-c", "echo token; exit 127"]);
        assert!(!never_started(&run(c)));
        let mut c = Command::new("/bin/sh"); c.args(["-c", "exit 1"]);
        assert!(!never_started(&run(c)));
        let _ = std::fs::remove_file(&log);
        // The probe says why, in one line.
        let probe = |p: &str| { let o = Command::new("/bin/sh").args(["-c", PROBE, "sh", p]).env("PATH", "/usr/bin:/bin").output().unwrap(); (o.status.success(), String::from_utf8_lossy(&o.stdout).trim().to_string()) };
        assert_eq!(probe("sh"), (true, String::new()));
        // A builtin is found only as the file env would run.
        assert_eq!(probe("true"), (true, String::new()));
        assert_eq!(probe("./relative"), (true, String::new()));
        assert_eq!(probe("/bin/sh"), (true, String::new()));
        assert_eq!(probe("no-such-program-anywhere"), (false, "not found on agent's PATH".to_string()));
        assert_eq!(probe("/etc/hosts"), (false, "/etc/hosts is not executable by agent".to_string()));
        assert_eq!(probe("/nonexistent/program"), (false, "/nonexistent/program does not exist".to_string()));
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
            results: vec![Some(candidate("first")), Some(candidate("selected"))], context: vec![],
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
            results: vec![Some(candidate("first", 7)), Some(candidate("second", second))], context: vec![],
        };
        // No git here: the spec's diff is empty, so the aim is what the tested search shows.
        let m = Manifest { config: config(), root: PathBuf::from("/nonexistent/bon-aim") };
        let kind = Kind::Counterexample { goal: Some(crate::gates::AgentProcess { search: 0, index: 0 }) };
        assert!(aim(&m, &kind, Some(&tested(8)), "head", &[]).contains("They behave differently"));
        assert_eq!(aim(&m, &kind, Some(&tested(7)), "head", &[]), "", "a selection's test is aimed by the spec alone");
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
    fn a_client_is_logged_in_only_when_its_status_says_so() {
        // queue 32.
        assert!(logged_in("claude", true, "{\n  \"loggedIn\": true,\n}"));
        assert!(!logged_in("claude", true, "{\n  \"loggedIn\": false\n}"));
        assert!(logged_in("codex", true, "Logged in using ChatGPT"));
        assert!(!logged_in("codex", false, "Not logged in"));
    }

    #[test]
    fn a_stub_program_runs_its_argv_and_costs_nothing() {
        let c = config();
        let stub = program_of(&c, "stub");
        assert_eq!(stub.argv(), ["/bin/sh", ".bon/stub.sh"]);
        assert_eq!(generation(&stub, &c, "anything at all").unwrap(), (0, Some(0), HashMap::new()));
        // A program that reaches a model still needs its token counts.
        assert!(generation(&program_of(&c, "deep"), &c, "anything at all").is_err());
        // Its cost is read from what it printed, whatever its client: bon-sample
        // reaching codex prints a result event, as the claude CLI does.
        let deep = program_of(&c, "deep");
        let result = r#"{"type":"result","requests":1,"modelUsage":{"gpt-6.1-sol":{"inputTokens":1000000,"outputTokens":0}}}"#;
        assert_eq!(generation(&deep, &c, result).unwrap().0, 2_000_000);
    }

    #[test]
    fn the_staged_checks_run_on_the_selected_candidate_from_a_clean_build_and_one_that_fails_stops_its_push() {
        // queue 70: each staged check runs once, never from the cache; the first that fails is named.
        let (_remote, work, base, _test) = landing_fixture("staged");
        let mut config = config();
        let mut m = Manifest { config: config.clone(), root: work.clone() };
        assert_eq!(staged(&m, &base), Ok(()), "no staged checks: nothing runs");
        if confined() { return; }
        config.checks.staged = vec!["test -f a".into(), "cat a".into()];
        m.config = config.clone();
        assert_eq!(staged(&m, &base), Ok(()));
        config.checks.staged = vec!["test -f a".into(), "test -f missing".into()];
        m.config = config;
        let e = staged(&m, &base).unwrap_err();
        assert!(e.starts_with("staged check `test -f missing` rejects") && e.contains("nothing was pushed"), "{e}");
        let short = &base[..12];
        for k in 0..2 {
            let log = std::fs::read_to_string(trace_dir(&work).join(format!("staged-{short}-{k}"))).unwrap();
            assert!(log.starts_with("exit: "), "ran, not answered by the cache: {log}");
        }
        let _ = std::fs::remove_dir_all(work.parent().unwrap());
    }

    #[test]
    fn a_tree_s_suite_seconds_are_timed_once_and_read_back_alike() {
        // queue 71: bon times the suite on a judged tree; the verdict cache keeps the figure, so a second ranking agrees.
        let (_remote, work, base, _test) = landing_fixture("seconds");
        if confined() { return; }
        let mut config = config();
        config.checks.test = vec!["sleep 0.3".into()];
        config.checks.verify = vec!["true".into()];
        let dir = scratch("seconds-test/work");
        let build = named_build("seconds-test.build/build", Start::Empty);
        check_directory(&work, &base, &dir).unwrap();
        let trace = std::env::temp_dir().join(format!("bon-seconds-{}", std::process::id()));
        std::fs::create_dir_all(&trace).unwrap();
        let on = On::commit(&work, &base);
        let first = suite_seconds(&config, &on, &dir, &build, &trace).unwrap();
        assert!(first >= 0.3, "{first}");
        assert!(std::fs::read_to_string(trace.join("seconds-0")).unwrap().starts_with("exit: "));
        let second = suite_seconds(&config, &on, &dir, &build, &trace).unwrap();
        assert_eq!(format!("{first:.3}"), format!("{second:.3}"), "the kept figure, not a second timing");
        assert!(std::fs::read_to_string(trace.join("seconds-0")).unwrap().starts_with("cached: "));
        // A run that fails measures nothing.
        config.checks.verify = vec!["false".into()];
        assert_eq!(suite_seconds(&config, &on, &dir, &build, &trace), None);
        remove_build(&config, &build);
        for p in [dir.parent().unwrap(), build.parent().unwrap(), &trace, work.parent().unwrap()] {
            let _ = Command::new("chmod").args(["-R", "u+w"]).arg(p).status();
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn what_decides_a_push_is_checked_again_from_a_clean_build_and_a_differing_verdict_is_suspect() {
        // queue 65: a planted verdict that a clean build does not give stops the push; a true one does not.
        let (_remote, work, base, _test) = landing_fixture("recheck");
        let mut config = config();
        config.checks.agree = vec!["cat a".into()];
        let m = Manifest { config, root: work.clone() };
        let tree = tree_of(&work, &base);
        let decided = |command: &str, ok: bool, stdout: &str, test: Option<(&str, &[u8])>| Decided {
            tree: tree.clone(), test: test.map(|(p, b)| (p.to_string(), b.to_vec())), command: command.into(), ok, stdout: stdout.into() };
        // As they were: the tree has `a`, a written test exits 3, the agree check prints `a`.
        keep_decided("true-verdicts", vec![decided("test -f a", true, "", None), decided("sh t.sh", false, "", Some(("t.sh", b"exit 3"))),
                                           decided("cat a", true, "a", None), decided("test -f a", true, "", None)]);
        if confined() { return; }
        assert_eq!(recheck(&m, "true-verdicts"), Ok(()));
        // Planted: the cache said the tests accept what a clean build rejects.
        keep_decided("planted", vec![decided("test -f a", true, "", None), decided("test -f missing", true, "", None)]);
        let e = recheck(&m, "planted").unwrap_err();
        assert!(e.starts_with("suspect check: `test -f missing`") && e.contains("from a clean build it says a failure") && e.contains("nothing was pushed"), "{e}");
        // An agree check whose output differs is suspect too; a test's is not compared.
        keep_decided("agree", vec![decided("cat a", true, "b", None)]);
        assert!(recheck(&m, "agree").unwrap_err().contains("prints other than"));
        keep_decided("output", vec![decided("echo now", true, "then", None)]);
        assert_eq!(recheck(&m, "output"), Ok(()));
        // A candidate this bon process never judged is never pushed.
        assert!(recheck(&m, "unknown").unwrap_err().contains("not pushed"));
        // Each re-check ran (never answered by the cache) and left its log; its directories are gone.
        let logs: Vec<String> = std::fs::read_dir(trace_dir(&work)).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("recheck-planted-")).collect();
        assert_eq!(logs.len(), 2);
        for l in &logs { assert!(std::fs::read_to_string(trace_dir(&work).join(l)).unwrap().starts_with("exit: ")); }
        let left = std::fs::read_dir(WORKING_DIRECTORIES).unwrap().flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(&format!("{}.recheck.", std::process::id())));
        assert!(!left, "a re-check's directories are removed");
        let _ = std::fs::remove_dir_all(work.parent().unwrap());
    }

    #[test]
    fn what_a_candidate_s_checks_said_is_kept_for_its_push() {
        // queue 65: every check run or answered while a candidate is judged, on its thread and on those it hands the work to.
        let on = On { tree: "t".into(), test: None, cache: Cache::Use };
        let (_, kept) = deciding(|| {
            decided(&on, "a", true, "x", std::path::Path::new("/l"));
            let here = deciding_here();
            std::thread::scope(|s| { s.spawn(|| within(&here, || decided(&on, "b", false, "", std::path::Path::new("/l")))); });
        });
        assert_eq!(kept.iter().map(|d| (d.command.as_str(), d.ok)).collect::<Vec<_>>(), [("a", true), ("b", false)]);
        // Outside a candidate's judging, nothing is kept.
        decided(&on, "c", true, "", std::path::Path::new("/l"));
        assert!(deciding_here().is_none());
    }

    #[test]
    fn the_verdict_key_covers_the_dependency_sources_and_not_the_host_file() {
        // queue 64, 63: which sources the lockfile names are unpacked changes the key; another file in the registry, or the host's prices, do not.
        // Run confined (bon's judge runs bon's own tests as a slot's user), bon keeps no cache, so no key.
        if confined() { return; }
        let d = std::env::temp_dir().join(format!("bon-deps-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (repo, home) = (d.join("repo"), d.join("cargo-home"));
        let source = home.join("registry/src/index.crates.io-x/foo-1.0.0/src/lib.rs");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(home.join("registry/src/index.crates.io-x/bar-2.0.0")).unwrap();
        std::fs::write(&source, "pub fn f() {}\n").unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]).unwrap();
        std::fs::write(repo.join("Cargo.lock"), "version = 4\n\n[[package]]\nname = \"foo\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"mine\"\nversion = \"0.1.0\"\n").unwrap();
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c"]).unwrap();
        let tree = tree_of(&repo, "HEAD");
        let mut c = config();
        c.root = repo.clone();
        c.toolchain = vec![("RUSTUP_HOME".into(), "/opt/bon/rustup".into()), ("CARGO_HOME".into(), home.to_string_lossy().into())];
        assert_eq!(dependency_dirs(&c, &std::fs::read_to_string(repo.join("Cargo.lock")).unwrap()), [home.join("registry/src/index.crates.io-x/foo-1.0.0")]);
        // not the RUSTUP_TOOLCHAIN name. So a host where one is writable by
        // agent or a slot user is refused.
        let mut tc = c.clone();
        tc.toolchain.push(("RUSTUP_TOOLCHAIN".into(), "some-toolchain-name".into()));
        let on = On { tree: tree.clone(), test: None, cache: Cache::Use };
        let before = dependencies(&c, &tree, true);
        assert!(!before.is_empty());
        let key = verdict_key(&c, &on, "cargo test").unwrap();
        // Another package's file, which the lockfile does not name: the same key.
        std::fs::write(home.join("registry/src/index.crates.io-x/bar-2.0.0/lib.rs"), "x").unwrap();
        assert_eq!(dependencies(&c, &tree, true), before);
        // The host file's other facts: the same key.
        let mut priced = c.clone();
        priced.prices.clear();
        priced.pools = Pools { agent_processes: 7, check_processes: 7, threads: c.pools.threads };
        assert_eq!(verdict_key(&priced, &on, "cargo test"), Some(key.clone()));
        // queue 63: the sources are engineer's, unpacked once from what the
        // lockfile pins, so their bytes are the lockfile's to say; whether a
        // package is unpacked yet (its .cargo-ok) is not: unpacking it changes the key.
        std::fs::write(source.parent().unwrap().parent().unwrap().join(".cargo-ok"), "{\"v\":1}").unwrap();
        let after = dependencies(&c, &tree, true);
        assert_ne!(after, before);
        assert_ne!(verdict_key(&c, &on, "cargo test"), Some(key.clone()));
        // An edit to its bytes, which no candidate can make: the same key.
        std::fs::write(&source, "pub fn g() {}\n").unwrap();
        assert_eq!(dependencies(&c, &tree, true), after);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_check_stops_at_its_own_cutoff_not_an_agent_process_s() {
        // queue 66.
        let mut c = config();
        c.checks.time = 1;
        c.agent_process.time = 600;
        let log = std::env::temp_dir().join(format!("bon-cutoff-test-{}", std::process::id()));
        let on = On { tree: String::new(), test: None, cache: Cache::Use };
        let here = std::path::Path::new("/tmp");
        let start = Instant::now();
        let (ok, _, killed) = run_check(&c, &on, here, here, "/bin/sleep 60", &log);
        assert!(!ok && killed, "{}", std::fs::read_to_string(&log).unwrap_or_default());
        assert!(start.elapsed() < Duration::from_secs(10), "{:?}", start.elapsed());
        let _ = std::fs::remove_file(&log);
        let _ = std::fs::remove_dir_all(PathBuf::from(WORKING_DIRECTORIES).join(format!("{}.bin", std::process::id())));
    }

    #[test]
    fn a_bon_process_that_ends_on_an_error_records_exited_and_the_error() {
        // queue 76: on one line; after a block, the block already says why.
        let root = std::env::temp_dir().join(format!("bon-exited-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let file = trace_dir(&root).join("transitions");
        append_line(&file, "grant 2 0 1 code x");
        record_exited(&root, "suspect check: `cargo test -q`\non tree t");
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().last(), Some("exited: suspect check: `cargo test -q` on tree t"));
        append_line(&file, "blocked: too_few_verified: fewer than two verified candidates");
        record_exited(&root, "blocked: no attempt was selected");
        assert!(std::fs::read_to_string(&file).unwrap().lines().last().unwrap().starts_with("blocked: too_few_verified"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_code_search_s_prompt_says_which_check_fails_and_why() {
        // queue 74: trunk's failing check, its command and its errors, for every program alike.
        let root = std::env::temp_dir().join(format!("bon-failing-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut c = config();
        c.checks.test = vec!["cargo test -q".into()];
        c.checks.verify = vec!["cargo verus verify".into()];
        let m = Manifest { config: c, root: root.clone() };
        let d = trace_dir(&root);
        write_trace(&d.join("trunk-test-0"), "exit: 0\nseconds: 1.0\n--- stdout\nok\n--- stderr\n");
        let noise: String = (0..400).map(|k| format!("   Compiling crate{k} v1.0\n")).collect();
        write_trace(&d.join("trunk-verify-0"), format!("cached: abc\nexit: 1\nseconds: 3.0\n--- stdout\n--- stderr\n{noise}\
            error: postcondition not satisfied\n    --> src/exec.rs:1300:5\n     |\n1300 |     a.len() <= b.len()\n\n\
            warning: unused\n\nverification results:: 101 verified, 1 errors\n"));
        let kind = Kind::Code { goal: Commit(vec![]) };
        let a = aim(&m, &kind, None, "head", &["head".to_string()]);
        assert!(a.starts_with("This check fails on trunk: cargo verus verify\nexit: 1\n"), "{a}");
        assert!(a.contains("error: postcondition not satisfied\n    --> src/exec.rs:1300:5\n"), "{a}");
        assert!(!a.contains("cargo test -q") && !a.contains("Compiling crate") && !a.contains("warning: unused"), "errors first, the rest left out: {a}");
        let text = prompt(&kind, &m.config, &a);
        assert!(text.contains("Trunk's checks reject this code.") && text.contains("src/exec.rs:1300:5"));
        assert!(text.contains("Never change [\".cargo/\", \"build.rs\", \"rust-toolchain\", \"rust-toolchain.toml\", \".bon/\", \"tests/\"] either"), "{text}");
        // queue 73: a second attempt carries the previous attempt's unverified
        // candidates' failing checks, from the logs their commits name, after
        // trunk's; an output two showed alike, once; what does not fit, left out whole.
        git(&root, &["init", "-q"]).unwrap();
        let commit_of = |name: &str| {
            let out = Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", name, "-m", &format!("Trace: .bon/traces/x/0/{name}")])
                .current_dir(&root).output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            git(&root, &["rev-parse", "HEAD"]).unwrap()
        };
        let (one, two, three) = (commit_of("1"), commit_of("2"), commit_of("3"));
        let logs = root.join(".bon/traces/x/0");
        let failed = |msg: &str| format!("exit: 101\nseconds: 1.0\n--- stdout\n---- t stdout ----\n\n{msg}\n\nfailures:\n");
        for k in ["1", "2"] { write_trace(&logs.join(k).join("test-0"), failed("thread 't' panicked: left 1 right 2")); }
        let long: String = (0..FAILING_LINES).map(|k| format!("---- t{k} stdout ----\npanicked\n")).collect();
        write_trace(&logs.join("3").join("test-0"), format!("exit: 101\n--- stdout\n{long}"));
        let context = ["head".to_string(), one.clone(), two.clone(), three];
        let a = aim(&m, &kind, None, "head", &context);
        assert!(a.starts_with("This check fails on trunk: cargo verus verify\n"), "trunk's first: {a}");
        assert_eq!(a.matches("left 1 right 2").count(), 1, "identical outputs once: {a}");
        assert!(a.contains(&format!("This check fails on 2 candidates of the previous attempt ({}, {}): cargo test -q\n", &one[..8], &two[..8])), "{a}");
        assert!(a.ends_with("[1 more failing check left out whole: it did not fit]\n") && !a.contains("t3 stdout"), "{a}");
        assert!(a.len() <= FAILING_BYTES + 200 && a.lines().count() <= FAILING_LINES + 1, "bounded as one failing check: {}", a.len());
        // No error block: the output's last lines, bounded.
        let tail = informative(&format!("exit: 101\n--- stdout\n{noise}test result: FAILED\n"));
        assert!(tail.contains("test result: FAILED") && tail.lines().count() <= FAILING_LINES + 2, "{}", tail.lines().count());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_spec_candidate_s_behavior_is_its_surface_change_not_its_wording() {
        // queue 83: docs, comments and layout do not split; a different text does; a proof's body is not surface.
        let base = "verus! {\n/// r is the larger.\npub open spec fn is_max(a: u64, r: u64) -> bool { r >= a }\n\npub proof fn p(a: u64)\n    ensures a >= 0,\n{\n    assert(true);\n}\n} // verus!\n";
        let one = base.replace("/// r is the larger.", "/// r is the larger one.\n// a note");
        let two = base.replace("{ r >= a }", "{\n    r >= a\n}").replace("assert(true);", "assert(a >= 0);");
        let three = base.replace("{ r >= a }", "{ a <= r }");
        let keyed = |t: &str| surface(t).into_iter().map(|i| (format!("{} {}", i.kind, i.name), i.compared)).collect::<Vec<_>>();
        assert_eq!(keyed(base).iter().map(|k| k.0.clone()).collect::<Vec<_>>(), ["predicate is_max", "proof p"]);
        assert_eq!(keyed(base), keyed(&one), "a doc and a comment are not surface");
        assert_eq!(keyed(base), keyed(&two), "nor layout, nor a proof's body");
        assert_ne!(keyed(base), keyed(&three), "another text is another behavior, even of the same meaning");
        // The state's fields, a trait's methods, types with their members, and invariants.
        let machine = "pub struct S {\n    /// The base.\n    pub base: u64,\n}\npub trait Gates {\n    fn g(x: u64) -> (r: bool)\n        ensures r == (x > 0);\n}\ntokenized_state_machine!{ m {\n    fields {\n        #[sharding(variable)] pub n: nat,\n    }\n    #[invariant]\n    pub fn ok(&self) -> bool { self.n >= 0 }\n    #[inductive(t)]\n    fn t_inductive(pre: Self, post: Self) { assert(true); }\n}}\n";
        let items = surface(machine);
        assert_eq!(items.iter().map(|i| format!("{} {}", i.kind, i.name)).collect::<Vec<_>>(), ["type S", "gate g", "field n", "invariant ok"]);
        assert_eq!(members(&items[0]), [("base".to_string(), "The base.".to_string())]);
    }

    #[test]
    fn the_spec_alone_is_one_crate_of_the_same_bytes_from_the_same_files() {
        // queue 83: from the manifest and the spec's files alone; refused for a file that is no module of the lib.
        let root = std::env::temp_dir().join(format!("bon-alone-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"k\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"k\"\npath = \"src/main.rs\"\n\n[dependencies]\nvstd = \"1\"\n\n[package.metadata.verus]\nverify = true\n").unwrap();
        std::fs::write(root.join("src/spec.rs"), "verus! {}\n").unwrap();
        std::fs::write(root.join("src/gates.rs"), "verus! {}\n").unwrap();
        std::fs::write(root.join("src/exec.rs"), "fn f() {}\n").unwrap();
        git(&root, &["init", "-q"]).unwrap();
        git(&root, &["add", "-A"]).unwrap();
        git(&root, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c"]).unwrap();
        let files = ["src/gates.rs".to_string(), "src/spec.rs".to_string()];
        let a = alone_commit(&root, "HEAD", &files).unwrap();
        assert_eq!(alone_commit(&root, "HEAD", &files).unwrap(), a, "the same files, the same commit");
        assert_eq!(git(&root, &["show", &format!("{a}:src/lib.rs")]).unwrap(), "pub mod gates;\npub mod spec;");
        let cargo = git(&root, &["show", &format!("{a}:Cargo.toml")]).unwrap();
        assert!(cargo.contains("name = \"k\"") && cargo.contains("vstd") && cargo.contains("verify = true") && !cargo.contains("[[bin]]"), "{cargo}");
        assert!(git(&root, &["show", &format!("{a}:src/exec.rs")]).is_err(), "nothing but the spec's files");
        assert!(alone_commit(&root, "HEAD", &["checks/x.rs".to_string()]).unwrap_err().contains("must be src/<name>.rs"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(toml::from_str::<Config>("limit = 1.0\nbogus = 2").is_err());
    }
}
