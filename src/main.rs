//! The bon CLI. Trusted code: it parses arguments, prints, and calls the
//! verified drivers in exec.rs, which make every decision.

use std::path::{Path, PathBuf};
use std::process::Command;

use best_of_n::process;

mod projection;
mod tui;
mod types;
mod view;

const USAGE: &str = "usage:
  bon [--since YYYY-MM-DD] [--until YYYY-MM-DD] [--find TEXT]
                          what is running, what was pushed, the queue, and what it cost, over that range
  bon code                search for code that trunk's checks accept; push it
  bon compaction          search for code and tests with what is stale removed or written cleaner; push it
  bon counterexample      search trunk for a behavior the spec forbids; if found, a code search carries its test
  bon init                create a manifest and queue in this git repository
  bon queue               turn each new transcript into a proposal for the queue
  bon view                the same in the terminal view, as `bon` opens it in a terminal
  bon background [--plist] the stalest of compaction and counterexample, on spare capacity
  bon setup [--dry-run] [--for <user>]
                          create user agent and group bon, and let <user> (default: you) run commands as agent;
                          run it as an administrator
  bon sbom [--check]      write .bon/sbom.json, or fail if it differs from this machine
  bon types [--check]     write the types programs are built on, or fail if one is stale
  bon spec [NAME]         the spec's vocabulary and how it reaches the code, or one item
  bon check               every check on the working tree, as agent, the way candidates are judged
  bon cost                write .bon/cost.toml, what reaching trunk cost (bon does after each push)";

/// The commands that grant capabilities.
const SEARCHES: [&str; 5] = ["code", "compaction", "counterexample", "queue", "background"];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = match git(Path::new("."), &["rev-parse", "--show-toplevel"]) {
        Ok(r) => r,
        // init checks for a repository itself; sbom and types also run without .git (checks).
        Err(_) if matches!(args.first().map(String::as_str), Some("init" | "setup" | "sbom" | "types" | "help" | "-h" | "--help")) => ".".into(),
        Err(e) => fail(&format!("not in a git repository: {e}")),
    };
    let command = args.first().map(String::as_str).unwrap_or("");
    // In bon's own repository the installed bon decides with the kernel it was
    // built from; trunk is what the last fetch or push left in the remote's ref.
    let (remote, branch) = best_of_n::trusted::remote_trunk(Path::new(&root));
    let at_trunk = |p: &str| git(Path::new(&root), &["show", &format!("refs/remotes/{remote}/{branch}:{p}")]).ok();
    if at_trunk("Cargo.toml").is_some_and(|t| t.contains("name = \"best-of-n\"")) {
        let differ = stale(at_trunk);
        if !differ.is_empty() {
            eprintln!("bon: this bon was built from another kernel than trunk's ({}); reinstall: cargo install --path . --locked", differ.join(", "));
        }
    }
    // Before a search: every harness it may run is logged in as agent, or the command that fixes it.
    if SEARCHES.contains(&command) {
        let checked = best_of_n::trusted::head(&root).and_then(|h| best_of_n::trusted::manifest(&root, &h)).and_then(|m| best_of_n::trusted::harnesses_logged_in(&m));
        if let Err(e) = checked { fail(&e) }
    }
    // Trunk is the remote's: what the last fetch or push left in its ref.
    let trunk = || best_of_n::trusted::head(&root).map(|h| h.iter().collect::<String>()).unwrap_or_default();
    let before = if SEARCHES.contains(&command) { trunk() } else { String::new() };
    let result = dispatch(&root, &args);
    // A push or a landed test moved trunk: the cost file follows it, as its own commit.
    if SEARCHES.contains(&command) && result.is_ok() && trunk() != before {
        if let Err(e) = record_cost(Path::new(&root)) { eprintln!("bon: .bon/cost.toml not updated: {e}"); }
    }
    // Only commands that grant capabilities make directories under /tmp/bon, so
    // only they clean up; bon run inside a check (help, sbom) never touches it.
    if SEARCHES.contains(&command) {
        best_of_n::trusted::cleanup(&["/usr/bin".into(), "/bin".into()]);
        if let Err(e) = persist(Path::new(&root)) { eprintln!("bon: traces not persisted: {e}"); }
    }
    if let Err(e) = result { fail(&e) }
}

fn dispatch(root: &str, args: &[String]) -> Result<(), String> {
    let root = root.to_string();
    match args.first().map(String::as_str) {
        Some("code") => process::to_push(&root, false).map(|_| println!("pushed")),
        Some("compaction") => process::to_push(&root, true).map(|_| println!("pushed")),
        Some("init") => init(&root),
        Some("counterexample") => counterexample(&root),
        Some("background") if args.get(1).map(String::as_str) == Some("--plist") => { plist(&root); Ok(()) }
        Some("background") => background(&root),
        Some("view") if args.iter().any(|a| a == "--frame") => {
            // bon view --frame WxH [--tab N] [--light]: one frame of the terminal view, as HTML.
            let size = args.iter().position(|a| a == "--frame").and_then(|i| args.get(i + 1)).cloned().unwrap_or("120x32".into());
            let (w, h) = size.split_once('x').and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?))).ok_or("--frame WxH")?;
            let tab = args.iter().position(|a| a == "--tab").and_then(|i| args.get(i + 1)).and_then(|t| t.parse::<usize>().ok()).unwrap_or(4);
            let focus = args.iter().position(|a| a == "--focus").and_then(|i| args.get(i + 1)).and_then(|t| t.parse::<usize>().ok()).unwrap_or(0);
            print!("{}", tui::frame(&root, w, h, tab.saturating_sub(1), focus, args.iter().any(|a| a == "--light"))?);
            Ok(())
        }
        Some("view") if args.iter().any(|a| a == "--typed") => {
            let p = projection::read(std::path::Path::new(&root), &view::Filter::args(args)?)?;
            println!("{} bon processes, {} goals, {} searches, {} agent processes, {} spec items, {} queue lines", p.processes.len(), p.groups.len(),
                p.processes.iter().map(|b| b.searches.len()).sum::<usize>(), p.processes.iter().flat_map(|b| &b.searches).map(|s| s.candidates.len()).sum::<usize>(),
                p.spec.as_ref().map_or(0, |s| s.items.len()), p.queue.as_ref().map_or(0, |q| q.len()));
            Ok(())
        }
        Some("view") if args.iter().any(|a| a == "--state") => {
            println!("{}", serde_json::to_string_pretty(&view::state(std::path::Path::new(&root), &view::Filter::args(args)?)).unwrap_or_default());
            Ok(())
        }
        Some("view") => tui::run(&root, view::Filter::args(args)?),
        Some("queue") => queue(&root),
        Some("setup") => {
            let dry_run = args.iter().any(|a| a == "--dry-run");
            let user = args.iter().position(|a| a == "--for").and_then(|i| args.get(i + 1)).cloned();
            setup(dry_run, user)
        }
        Some("sbom") => sbom(&root, args.get(1).map(String::as_str) == Some("--check")),
        Some("types") => types::run(&root, args.get(1).map(String::as_str) == Some("--check")),
        Some("spec") => { print!("{}", tui::spec_text(&root, args.get(1).map(String::as_str), 100)?); Ok(()) }
        Some("check") => check(&root),
        Some("cost") => { let p = projection::read(Path::new(&root), &view::Filter::default())?; let t = cost_toml(&p);
            std::fs::write(Path::new(&root).join(".bon/cost.toml"), &t).map_err(|e| e.to_string())?; print!("{t}"); Ok(()) }
        Some("help" | "-h" | "--help") => { println!("{USAGE}"); Ok(()) }
        None if tui::wanted() => tui::run(&root, view::Filter::args(args)?),
        None => status(&root, args),
        Some(a) if a.starts_with("--") => status(&root, args),
        Some(other) => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

/// The traces are their own git repository, apart from this one's (they hold
/// prompts, arguments and outputs): commit what this command added, and push to
/// the private remote the manifest names in `traces`, if it names one.
fn persist(root: &Path) -> Result<(), String> {
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

/// The working tree as a commit object, untracked files included and nothing
/// changed: a temporary index, `git add -A` into it, `write-tree`, `commit-tree`.
fn snapshot(root: &Path) -> Result<String, String> {
    let index = std::env::temp_dir().join(format!("bon-check-{}", std::process::id()));
    let with = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git").args(args).current_dir(root).env("GIT_INDEX_FILE", &index).output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).trim().to_string()); }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let head = git(root, &["rev-parse", "HEAD"])?;
    with(&["read-tree", &head])?;
    with(&["add", "-A"])?;
    let tree = with(&["write-tree"])?;
    let _ = std::fs::remove_file(&index);
    git(root, &["-c", "user.name=bon", "-c", "user.email=bon@localhost", "commit-tree", &tree, "-p", &head, "-m", "bon check: the working tree"])
}

/// Where an error a check printed is: each `--> path:line` and `path:line:col:`.
fn error_paths(log: &str) -> Vec<String> {
    // Only an error's location counts, not a warning's: the first `-->` after an `error` line.
    let mut out: Vec<String> = Vec::new();
    let mut in_error = false;
    for l in log.lines() {
        let t = l.trim_start();
        if t.starts_with("error") { in_error = true; }
        else if t.starts_with("warning") { in_error = false; }
        let at = if let Some(r) = t.strip_prefix("--> ") { in_error.then_some(r) } else if t.contains(": error") { Some(t) } else { None };
        if let Some(p) = at.and_then(|r| r.split(':').next()).map(str::trim).filter(|p| !p.is_empty() && !p.starts_with('/') && p.contains('.')) {
            if !out.iter().any(|o| o == p) { out.push(p.to_string()); }
            in_error = false;
        }
    }
    out
}

/// A path no search may change (bon's directory, a check, trusted code): only
/// the model, or engineer, can fix an error there.
fn protected(manifest: &toml::Value, path: &str) -> bool {
    let list = |v: Option<&toml::Value>| v.and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect::<Vec<_>>()).unwrap_or_default();
    let under = |p: &String| path == p.trim_end_matches('/') || path.starts_with(&format!("{}/", p.trim_end_matches('/')));
    path.starts_with(".bon/") || list(manifest.get("checks").and_then(|c| c.get("paths"))).iter().any(under)
        || list(manifest.get("sbom").and_then(|s| s.get("trusted"))).iter().any(under)
}

/// bon check: every check on the working tree, run as agent in a checkout
/// without `.git`, the way candidates are judged; decided by exit codes. For a
/// failure, where its errors are: in protected files the model fixes them; in
/// the rest, a code search can.
fn check(root: &str) -> Result<(), String> {
    let r = Path::new(root);
    let commit = snapshot(r)?;
    let m = best_of_n::trusted::manifest(root, &commit.chars().collect())?;
    let manifest: toml::Value = toml::from_str(&git(r, &["show", &format!("{commit}:.bon/bon.toml")])?).map_err(|e| e.to_string())?;
    let queue = std::fs::read_to_string(r.join(".bon/queue.tsv")).unwrap_or_default();
    let reused = reused_ids(&git(r, &["log", "-p", "--reverse", "--format=commit %h", "--", ".bon/queue.tsv"]).unwrap_or_default(), &queue);
    if !reused.is_empty() {
        for (id, commit) in &reused { println!("  FAIL .bon/queue.tsv: id {id} was retired in {commit}; ids are never reused"); }
        return Err(format!("renumber from {}: one more than any id the queue has held", next_id(r)));
    }
    println!("checking the working tree ({}) as agent, the way candidates are judged", &commit[..8]);
    let results = best_of_n::trusted::check(&m, &commit.chars().collect())?;
    let mut failed = false;
    for (command, ok, log) in &results {
        println!("  {} {command}", if *ok { "ok  " } else { "FAIL" });
        if *ok { continue; }
        failed = true;
        let text = std::fs::read_to_string(log).unwrap_or_default();
        let paths = error_paths(&text);
        let (mine, search): (Vec<&String>, Vec<&String>) = paths.iter().partition(|p| protected(&manifest, p));
        if !mine.is_empty() { println!("       in protected files, for the model to fix: {}", mine.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")); }
        if !search.is_empty() {
            println!("       in files a code search may change: {}", search.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            println!("       what builds after these is not checked yet: check again once they compile");
        }
        println!("       log: {}", log.strip_prefix(r).unwrap_or(log).display());
    }
    if failed { return Err("checks reject the working tree".into()); }
    println!("every check accepts the working tree");
    Ok(())
}

/// The kernel this bon was built from: the spec, the gates and their implementation.
const KERNEL: [(&str, &str); 5] = [
    ("src/spec.rs", include_str!("spec.rs")),
    ("src/gates.rs", include_str!("gates.rs")),
    ("src/exec.rs", include_str!("exec.rs")),
    ("src/encoding.rs", include_str!("encoding.rs")),
    ("src/process.rs", include_str!("process.rs")),
];

/// The kernel's files whose trunk version (read by `trunk`, None if missing)
/// differs from the one this bon was built from.
fn stale(trunk: impl Fn(&str) -> Option<String>) -> Vec<&'static str> {
    KERNEL.iter().filter(|(p, built)| trunk(p).is_none_or(|t| t.trim_end() != built.trim_end())).map(|(p, _)| *p).collect()
}

/// .bon/cost.toml: the totals at the top of bon's view, always these keys in
/// this order. Generation stands on its own beside the total, which engineer's
/// time at the rate otherwise outweighs.
fn cost_toml(p: &projection::Projection) -> String {
    let t = &p.totals;
    let pushed: Vec<&projection::GoalTrace> = p.groups.iter().filter(|g| g.outcome == "pushed").collect();
    let generation_per_push = (!pushed.is_empty()).then(|| pushed.iter().map(|g| g.generation).sum::<f64>() / pushed.len() as f64);
    let generation_per_verified = (t.verified > 0).then(|| t.generation / t.verified as f64);
    let money = |v: Option<f64>| v.map_or("nan".to_string(), |v| format!("{v:.2}"));
    format!("# What reaching this trunk cost, from bon's traces; bon rewrites it after each push.\n\
# cost = generation (what the models charged) + time (engineer's, at each search's rate).\n\
cost = {}\ngeneration = {}\ntime = {}\nper_verified_candidate = {}\nper_push = {}\n\
generation_per_verified_candidate = {}\ngeneration_per_push = {}\npushes = {}\nverified = {}\ncandidates = {}\n",
        money(Some(t.cost)), money(Some(t.generation)), money(Some(t.time_cost)), money(t.per_verified_candidate), money(t.per_push),
        money(generation_per_verified), money(generation_per_push), t.pushes, t.verified, t.candidates)
}

/// After a push: write .bon/cost.toml, commit it as engineer, and push it to
/// the remote's trunk the push went to.
fn record_cost(root: &Path) -> Result<(), String> {
    let p = projection::read(root, &view::Filter::default())?;
    let text = cost_toml(&p);
    // On the remote's trunk, with git's objects alone: no working tree is touched.
    let head = best_of_n::trusted::head(&root.to_string_lossy()).map(|h| h.iter().collect::<String>())?;
    let manifest: toml::Value = toml::from_str(&git(root, &["show", &format!("{head}:.bon/bon.toml")])?).map_err(|e| e.to_string())?;
    let remote = manifest.get("remote").and_then(|v| v.as_str()).unwrap_or("origin");
    let trunk = manifest.get("trunk").and_then(|v| v.as_str()).unwrap_or("main");
    if git(root, &["show", &format!("{head}:.bon/cost.toml")]).is_ok_and(|old| old.trim_end() == text.trim_end()) { return Ok(()); }
    let t = &p.totals;
    let message = format!("cost: ${:.2} generation + ${:.2} time = ${:.2} to reach {}", t.generation, t.time_cost, t.cost, &head[..7]);
    let commit = commit_file(root, &head, ".bon/cost.toml", &text, &message)?;
    git(root, &["push", "-q", remote, &format!("{commit}:refs/heads/{trunk}")])?;
    git(root, &["update-ref", &format!("refs/remotes/{remote}/{trunk}"), &commit])?;
    Ok(())
}

/// A commit on parent that changes only path, to text, made with a temporary
/// index: no working tree, and no branch moves.
fn commit_file(root: &Path, parent: &str, path: &str, text: &str, message: &str) -> Result<String, String> {
    use std::io::Write;
    let run = |args: &[&str], input: Option<&str>, index: Option<&Path>| -> Result<String, String> {
        let mut c = Command::new("git");
        c.args(args).current_dir(root).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        if let Some(i) = index { c.env("GIT_INDEX_FILE", i); }
        if input.is_some() { c.stdin(std::process::Stdio::piped()); }
        let mut child = c.spawn().map_err(|e| e.to_string())?;
        if let Some(t) = input { child.stdin.take().unwrap().write_all(t.as_bytes()).map_err(|e| e.to_string())?; }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).trim().to_string()); }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let index = std::env::temp_dir().join(format!("bon-index-{}", std::process::id()));
    let blob = run(&["hash-object", "-w", "--stdin"], Some(text), None)?;
    run(&["read-tree", parent], None, Some(&index))?;
    run(&["update-index", "--add", "--cacheinfo", &format!("100644,{blob},{path}")], None, Some(&index))?;
    let tree = run(&["write-tree"], None, Some(&index));
    let _ = std::fs::remove_file(&index);
    run(&["commit-tree", &tree?, "-p", parent, "-m", message], None, None)
}

/// bon counterexample: if trunk shows a behavior the spec forbids, the test that
/// shows it lands on trunk, and trunk's checks reject trunk until bon code.
fn counterexample(root: &str) -> Result<(), String> {
    if process::counterexample(root)? {
        println!("found: verified tests reject trunk; the best landed on trunk, so trunk's checks reject it: run bon code");
    } else {
        println!("not found: fewer than two verified tests reject trunk");
    }
    Ok(())
}

/// bon background: the stalest of compaction and a counterexample on trunk,
/// only on spare capacity. Staleness is trunk commits since that kind last ran.
fn background(root: &str) -> Result<(), String> {
    let r = Path::new(root);
    // Spare capacity: no bon command running here, and load below the host's jobs.
    // A bon process is running while its pid, which names its traces, is alive.
    let traces = r.join(".bon/traces");
    let busy = std::fs::read_dir(&traces).into_iter().flatten().flatten()
        .any(|e| best_of_n::trusted::trace_running(&traces, &e.file_name().to_string_lossy()));
    if busy { println!("busy: a bon command is running here"); return Ok(()); }
    let jobs = std::fs::read_to_string(best_of_n::trusted::HOST).ok()
        .and_then(|d| d.lines().find_map(|l| l.strip_prefix("jobs").and_then(|v| v.trim_start_matches([' ', '=']).trim().parse::<f64>().ok())))
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1.0, |n| (n.get() / 2).max(1) as f64));
    let load: f64 = Command::new("sysctl").args(["-n", "vm.loadavg"]).output().ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0.0);
    if load >= jobs { println!("busy: load {load:.1} is at or above jobs {jobs}"); return Ok(()); }
    // When each kind last ran, from the traces; never is staler than any.
    let last = |kind: &str, goal: Option<&str>| -> Option<u64> {
        std::fs::read_dir(r.join(".bon/traces")).ok()?.flatten()
            .flat_map(|d| std::fs::read_to_string(d.path().join("searches.jsonl")).unwrap_or_default().lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).collect::<Vec<_>>())
            .filter(|v| v["kind"] == kind && goal.is_none_or(|g| v["goal"] == g))
            .filter_map(|v| v["time"].as_u64()).max()
    };
    let total: u64 = git(r, &["rev-list", "--count", "HEAD"])?.trim().parse().unwrap_or(0);
    let since = |t: Option<u64>| t.map_or(total, |t| git(r, &["rev-list", "--count", &format!("--since={t}"), "HEAD"]).ok()
        .and_then(|c| c.trim().parse::<u64>().ok()).unwrap_or(total));
    let (compaction, counter) = (since(last("compaction", None)), since(last("counterexample", Some("trunk"))));
    if compaction == 0 && counter == 0 { println!("nothing stale"); return Ok(()); }
    // No one waits on background work: its time is charged at rate 0.
    best_of_n::trusted::background();
    if counter >= compaction {
        println!("counterexample ({counter} commits stale)");
        counterexample(root)
    } else {
        println!("compaction ({compaction} commits stale)");
        process::to_push(root, true).map(|_| println!("pushed"))
    }
}

/// A launchd job that runs bon background in this repository every five minutes.
/// The interval is only how often it looks for spare capacity.
fn plist(root: &str) {
    use sha2::{Digest, Sha256};
    let escape = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;");
    let bon = escape(&std::env::current_exe().map(|p| p.display().to_string()).unwrap_or("bon".into()));
    let name = Path::new(root).file_name().map_or("repo".into(), |n| n.to_string_lossy().to_string());
    let hash = format!("{:x}", Sha256::digest(root.as_bytes()));
    let name = escape(&format!("{name}.{}", &hash[..16]));
    let root = escape(root);
    println!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.bon.background.{name}</string>
  <key>ProgramArguments</key><array><string>{bon}</string><string>background</string></array>
  <key>WorkingDirectory</key><string>{root}</string>
  <key>StartInterval</key><integer>300</integer>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>{root}/.bon/traces/background.log</string>
  <key>StandardErrorPath</key><string>{root}/.bon/traces/background.log</string>
</dict></plist>"#);
}

fn fail(e: &str) -> ! {
    eprintln!("bon: {e}");
    std::process::exit(1)
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git").args(args).current_dir(root).output().map_err(|e| e.to_string())?;
    if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).trim().to_string()); }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Start a repository with a manifest that cannot run a search yet.
fn init(root: &str) -> Result<(), String> {
    use std::io::Write;
    let r = Path::new(root);
    git(r, &["rev-parse", "--show-toplevel"]).map_err(|e| format!("not in a git repository: {e}"))?;
    let bon = r.join(".bon");
    if std::fs::symlink_metadata(&bon).is_ok() && !bon.is_dir() {
        return Err(".bon exists but is not a directory".into());
    }
    for file in ["bon.toml", "queue.tsv"] {
        if std::fs::symlink_metadata(bon.join(file)).is_ok() {
            return Err(format!(".bon/{file} already exists; nothing written"));
        }
    }
    let ignore = r.join(".gitignore");
    let text = match std::fs::read_to_string(&ignore) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.to_string()),
    };
    let head = git(r, &["symbolic-ref", "refs/remotes/origin/HEAD"]).unwrap_or_default();
    let (remote, trunk) = head.strip_prefix("refs/remotes/").and_then(|s| s.split_once('/')).unwrap_or(("origin", "main"));
    let manifest = format!("# Configure this manifest before running a search.\ntrunk = {}\nremote = {}\n{}{}",
        toml::Value::String(trunk.into()), toml::Value::String(remote.into()), INIT_TEMPLATE, init_sbom(r));
    std::fs::create_dir_all(&bon).map_err(|e| e.to_string())?;
    for (file, contents) in [("bon.toml", manifest.as_str()), ("queue.tsv", "id\tintent\n")] {
        std::fs::OpenOptions::new().write(true).create_new(true).open(bon.join(file))
            .and_then(|mut f| f.write_all(contents.as_bytes())).map_err(|e| e.to_string())?;
    }
    if !text.lines().any(|l| l == "/.bon/traces/") {
        let line = if text.is_empty() || text.ends_with('\n') { "/.bon/traces/\n" } else { "\n/.bon/traces/\n" };
        std::fs::OpenOptions::new().append(true).create(true).open(&ignore)
            .and_then(|mut f| f.write_all(line.as_bytes())).map_err(|e| e.to_string())?;
    }
    println!("created .bon/bon.toml and .bon/queue.tsv");
    println!("next: configure .bon/bon.toml; commit and push .bon/ and .gitignore to trunk ({remote}/{trunk})");
    println!("then run bon");
    println!("bon code needs trunk's checks to reject trunk (a spec change); otherwise run bon counterexample or bon compaction");
    Ok(())
}

const INIT_TEMPLATE: &str = r#"# Replace the zero limit with the bon process's dollar limit, and set your hourly rate.
limit = 0.0
rate = 0.0
# Directory containing .vtt files for the queue.
# transcripts = "transcripts"

[agent_process]
# Replace with the dollar limit and time in seconds for each agent process.
limit = 0.0
time = 3600

[checks]
# Replace with protected spec and check paths.
paths = []
# Replace false with commands whose exit 0 means a candidate is accepted / verified.
test = ["false"]
verify = ["false"]
# Commands whose output must agree, and commands printing an integer for ranking.
agree = []
rank = {}

[[harness]]
# Replace with a harness (codex or claude), a canonical model id and counts per attempt.
name = "codex"
model = "REPLACE_ME"
n = [1]

[counterexample]
harness = [{ name = "codex", model = "REPLACE_ME", n = [1] }]
# Replace with the test path, build/run commands and test paths on trunk.
path = "tests/counterexample.rs"
build = "false"
run = "false"
tests = ["tests/"]
# Spec and interface paths an agent process sees; empty means everything.
visible = []

"#;

/// The manifest's [sbom], guessed from the repository for the owner to confirm:
/// its name, the tracked files that mark trusted code (`#[verifier::external*]`),
/// and a version command per toolchain whose lockfile is at the root.
fn init_sbom(r: &Path) -> String {
    let name = r.canonicalize().unwrap_or_else(|_| r.to_path_buf()).file_name().unwrap_or_default().to_string_lossy().to_string();
    let trusted: Vec<toml::Value> = git(r, &["grep", "-l", "-F", "#[verifier::external"]).unwrap_or_default()
        .lines().filter(|l| !l.is_empty()).map(|l| toml::Value::String(l.into())).collect();
    let mut tools = toml::Table::new();
    for (lock, names) in [("Cargo.lock", &["rustc", "cargo"][..]), ("package-lock.json", &["node", "npm"]), ("go.sum", &["go"])] {
        if r.join(lock).exists() {
            for t in names { tools.insert((*t).into(), toml::Value::String(format!("{t} --version"))); }
        }
    }
    let inline = tools.iter().map(|(k, v)| format!("{k} = {v}")).collect::<Vec<_>>().join(", ");
    format!("\n# What bon sbom lists beyond the lockfiles, guessed by bon init: confirm it.\n\
             # trusted: files of trusted code; tools: the TCB's tools and their version commands.\n\
             [sbom]\nname = {}\ntrusted = {}\ntools = {{ {inline} }}\n",
            toml::Value::String(name), toml::Value::Array(trusted))
}

/// What is running, what was pushed, and the queue: the projection bon view
/// draws, printed.
fn status(root: &str, args: &[String]) -> Result<(), String> {
    let filter = view::Filter::args(args)?;
    if git(Path::new(root), &["show", "HEAD:.bon/bon.toml"]).is_err() {
        println!("no .bon/bon.toml at trunk's head: run bon init");
        return Ok(());
    }
    print!("{}", view::text(&view::state(Path::new(root), &filter)));
    Ok(())
}

/// Each transcript not yet cited by a commit on trunk becomes a proposal: a
/// patch adding its agreed intents to the queue, each with the next id the
/// queue has never used. engineer decides by applying it, editing it, or not.
fn queue(root: &str) -> Result<(), String> {
    let r = Path::new(root);
    let config: toml::Value = toml::from_str(&git(r, &["show", "HEAD:.bon/bon.toml"])
        .map_err(|_| "no .bon/bon.toml at trunk's head; run bon init")?).map_err(|e| e.to_string())?;
    let dir = match config.get("transcripts") {
        Some(v) => v.as_str().ok_or("transcripts in .bon/bon.toml must be a directory string")?,
        None => "transcripts",
    };
    if !r.join(dir).is_dir() {
        return Err(format!("no transcripts directory '{dir}': set transcripts in .bon/bon.toml or add .vtt files"));
    }
    let cited = git(r, &["log", "--format=%(trailers:key=Source,valueonly)"])?;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(r.join(&dir)).map_err(|e| format!("{dir}: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "vtt")).collect();
    entries.sort();
    // Each transcript no commit cites yet: one search each, in one bon process.
    let new: Vec<(PathBuf, String)> = entries.into_iter()
        .map(|p| { let rel = format!("{dir}/{}", p.file_name().unwrap().to_string_lossy()); (p, rel) })
        .filter(|(_, rel)| !cited.lines().any(|l| l.trim() == rel)).collect();
    if new.is_empty() { println!("no new transcripts in {dir}"); return Ok(()); }
    for (_, rel) in &new { println!("{rel}: searching"); }
    let found = process::queue(root, &new.iter().map(|(_, rel)| rel.chars().collect()).collect())?;
    // One counter for the run: each proposal's ids follow the last one's.
    let mut id = next_id(r);
    for ((p, rel), (agreed, contested)) in new.iter().zip(found) {
        let head = git(r, &["rev-parse", "HEAD"])?;
        let mut text = git(r, &["show", "HEAD:.bon/queue.tsv"]).unwrap_or_else(|_| "id\tintent\n".into());
        let intents: Vec<(u64, String)> = agreed.iter().map(|(cue, intent)| (*cue, intent.iter().collect())).collect();
        let cues = numbered(&mut text, &mut id, &intents);
        let commit = proposal(r, &head, &text, &rel, &cues, &contested)?;
        let name = p.file_stem().unwrap().to_string_lossy().to_string();
        let file = r.join(".bon/traces/proposals").join(format!("{name}.patch"));
        std::fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&file, git(r, &["format-patch", "--stdout", "-1", &commit])? + "\n").map_err(|e| e.to_string())?;
        println!("{} agreed, {} contested", agreed.len(), contested.len());
        for c in &contested { println!("  contested cue {}", timestamp(*c)); }
        println!("  review: cat .bon/traces/proposals/{name}.patch");
        println!("  accept: git am .bon/traces/proposals/{name}.patch");
    }
    Ok(())
}

/// The ids in `queue` that an earlier commit retired: removed with no line of
/// the same id added in that commit (an edit keeps its id; a retirement does
/// not). `log` is `git log -p --reverse --format="commit %h" -- .bon/queue.tsv`.
fn reused_ids(log: &str, queue: &str) -> Vec<(u64, String)> {
    let id = |l: &str| l.split('\t').next()?.parse::<u64>().ok();
    let mut retired: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    let mut flush = |commit: &str, removed: &mut Vec<u64>, added: &mut Vec<u64>| {
        for r in removed.drain(..) { if !added.contains(&r) { retired.insert(r, commit.to_string()); } }
        added.clear();
    };
    let (mut commit, mut removed, mut added) = (String::new(), Vec::new(), Vec::new());
    for l in log.lines() {
        if let Some(c) = l.strip_prefix("commit ") { flush(&commit, &mut removed, &mut added); commit = c.to_string(); }
        else if l.starts_with("---") || l.starts_with("+++") { continue; }
        else if let Some(x) = l.strip_prefix('-').and_then(id) { removed.push(x); }
        else if let Some(x) = l.strip_prefix('+').and_then(id) { added.push(x); }
    }
    flush(&commit, &mut removed, &mut added);
    let mut out: Vec<(u64, String)> = queue.lines().filter_map(id).filter_map(|i| retired.get(&i).map(|c| (i, c.clone()))).collect();
    out.sort();
    out
}

/// Append each intent to `queue` with the next id from `id`, which it advances;
/// returns each id with the cue it came from.
fn numbered(queue: &mut String, id: &mut u64, intents: &[(u64, String)]) -> Vec<(u64, u64)> {
    if !queue.ends_with('\n') { queue.push('\n'); }
    intents.iter().map(|(cue, intent)| {
        queue.push_str(&format!("{id}\t{intent}\n"));
        *id += 1;
        (*id - 1, *cue)
    }).collect()
}

/// One more than the largest id the queue has ever held, in any commit.
fn next_id(root: &Path) -> u64 {
    git(root, &["log", "-p", "--format=", "--", ".bon/queue.tsv"]).unwrap_or_default().lines()
        .filter_map(|l| l.trim_start_matches(['+', '-', ' ']).split('\t').next()?.parse::<u64>().ok())
        .max().map_or(1, |m| m + 1)
}

/// A commit on `head` whose queue is `text`, citing the transcript and, for
/// each new intent, the cue it came from. No ref keeps it: its patch is the
/// proposal, and `git am` keeps its trailers.
fn proposal(root: &Path, head: &str, text: &str, source: &str, cues: &[(u64, u64)], contested: &[u64]) -> Result<String, String> {
    let blob = {
        let mut c = Command::new("git").args(["hash-object", "-w", "--stdin"]).current_dir(root)
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().map_err(|e| e.to_string())?;
        use std::io::Write;
        c.stdin.take().unwrap().write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        String::from_utf8_lossy(&c.wait_with_output().map_err(|e| e.to_string())?.stdout).trim().to_string()
    };
    let index = std::env::temp_dir().join(format!("bon-proposal-{}", std::process::id()));
    let with = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git").args(args).current_dir(root).env("GIT_INDEX_FILE", &index).output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).to_string()); }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    with(&["read-tree", head])?;
    with(&["update-index", "--add", "--cacheinfo", &format!("100644,{blob},.bon/queue.tsv")])?;
    let tree = with(&["write-tree"])?;
    let _ = std::fs::remove_file(&index);
    let cited: String = cues.iter().map(|(id, cue)| format!("Cue: {id} {source}#{cue}\n")).chain(contested.iter().map(|c| format!("Contested: {source}#{c}\n"))).collect();
    git(root, &["commit-tree", &tree, "-p", head, "-m", &format!("queue: {source}\n\nSource: {source}\n{cited}")])
}

/// Milliseconds to a WebVTT timestamp.
fn timestamp(ms: u64) -> String {
    format!("{:02}:{:02}:{:02}.{:03}", ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60, ms % 1000)
}

/// Create user agent and group bon, put engineer and agent in bon, let
/// engineer run commands as agent (never as root) with no password, and install
/// the toolchain checks judge with under /opt/bon. Each step runs with sudo and
/// is printed first.
fn setup(dry_run: bool, user: Option<String>) -> Result<(), String> {
    let runner = std::env::var("USER").map_err(|_| "USER is not set")?;
    let me = user.unwrap_or(runner.clone());
    let exists = |kind: &str, name: &str| Command::new("dscl").args([".", "-read", &format!("/{kind}/{name}")])
        .output().is_ok_and(|o| o.status.success());
    let mut steps: Vec<Vec<String>> = Vec::new();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    if !exists("Groups", "bon") { steps.push(s(&["dseditgroup", "-o", "create", "bon"])); }
    if !exists("Users", "agent") {
        // A random password no one keeps: agent is never logged in to, only run as.
        let out = Command::new("openssl").args(["rand", "-base64", "32"]).output().map_err(|e| e.to_string())?;
        let password = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if password.len() < 40 { return Err("could not make a password".into()); }
        steps.push(vec!["sysadminctl".into(), "-addUser".into(), "agent".into(), "-fullName".into(), "bon agent".into(),
                        "-shell".into(), "/bin/zsh".into(), "-home".into(), "/Users/agent".into(), "-password".into(), password]);
        steps.push(s(&["createhomedir", "-c", "-u", "agent"]));
        steps.push(s(&["dscl", ".", "create", "/Users/agent", "IsHidden", "1"]));
    }
    steps.push(s(&["dseditgroup", "-o", "edit", "-a", "agent", "-t", "user", "bon"]));
    // agent's primary group is bon, not staff: staff can read engineer's home.
    steps.push(s(&["sh", "-c", "dscl . -create /Users/agent PrimaryGroupID \"$(dscl . -read /Groups/bon PrimaryGroupID | awk '{print $2}')\""]));
    steps.push(s(&["dseditgroup", "-o", "edit", "-a", &me, "-t", "user", "bon"]));
    steps.push(vec!["sh".into(), "-c".into(), format!(
        "f=$(mktemp) && printf '%s ALL=(agent) NOPASSWD: ALL\\n' {me} > \"$f\" && visudo -cf \"$f\" && install -m 0440 -o root -g wheel \"$f\" /etc/sudoers.d/bon; r=$?; rm -f \"$f\"; exit $r")]);
    // The directory holding every working directory: the owner's, mode 0711, so
    // agent may pass through to a path it was given but not list or add to it.
    // bon remakes it after a reboot clears /tmp.
    steps.push(vec!["sh".into(), "-c".into(), format!(
        "mkdir -p {d} && chown {me} {d} && chmod 0711 {d}", d = best_of_n::trusted::WORKING_DIRECTORIES)]);
    // The toolchain checks judge with, where no agent process can write it: a copy
    // of the one this user runs (rustup's home, cargo's proxies, Verus), root's all
    // the way up, with a cargo home whose root is root's and only its caches agent's.
    if !std::path::Path::new("/opt/bon").exists() {
        let home = std::env::var("HOME").map_err(|_| "HOME is not set")?;
        let rustup = std::env::var("RUSTUP_HOME").unwrap_or(format!("{home}/.rustup"));
        let cargo = std::env::var("CARGO_HOME").unwrap_or(format!("{home}/.cargo"));
        let verus = Command::new("sh").args(["-c", "dirname \"$(realpath \"$(command -v verus)\")\""]).output()
            .ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|d| !d.is_empty()).ok_or("verus is not on PATH: install it first")?;
        steps.push(vec!["sh".into(), "-c".into(), format!(
            "set -e; mkdir -p /opt/bon/rustup /opt/bon/cargo/bin /opt/bon/verus /opt/bon/cargo-home/registry /opt/bon/cargo-home/git; \
             cp -cR {rustup}/settings.toml {rustup}/toolchains {rustup}/update-hashes /opt/bon/rustup/; \
             mkdir -p /opt/bon/rustup/downloads /opt/bon/rustup/tmp; cp -cR {cargo}/bin/. /opt/bon/cargo/bin/; cp -cR {verus}/. /opt/bon/verus/; \
             touch /opt/bon/cargo-home/.global-cache /opt/bon/cargo-home/.package-cache /opt/bon/cargo-home/.package-cache-mutate; \
             chown -R root:wheel /opt/bon; chmod -R go-w,a+rX /opt/bon; \
             chown -R agent:bon /opt/bon/cargo-home/registry /opt/bon/cargo-home/git /opt/bon/cargo-home/.global-cache /opt/bon/cargo-home/.package-cache /opt/bon/cargo-home/.package-cache-mutate")]);
    }
    // The host file: written once, then edited by hand (with sudo) as models and prices change.
    if !std::path::Path::new(best_of_n::trusted::HOST).exists() {
        let draft = std::env::temp_dir().join(format!("bon-host-{}.toml", std::process::id()));
        if !dry_run { std::fs::write(&draft, HOST_TEMPLATE).map_err(|e| e.to_string())?; }
        steps.push(vec!["sh".into(), "-c".into(), format!(
            "mkdir -p /etc/bon && install -m 0644 -o root -g wheel {} {}", draft.display(), best_of_n::trusted::HOST)]);
    }
    for step in &steps {
        let shown: Vec<&str> = step.iter().map(|x| if x.len() > 40 && !x.contains(' ') { "<random>" } else { x.as_str() }).collect();
        println!("sudo {}", shown.join(" "));
        if dry_run { continue; }
        let ok = Command::new("sudo").args(step).status().map_err(|e| e.to_string())?.success();
        if !ok { return Err(format!("failed: sudo {}", shown.join(" "))); }
    }
    if dry_run { println!("(dry run: nothing changed)"); return Ok(()); }
    if me == runner {
        let ok = Command::new("sudo").args(["-n", "-u", "agent", "true"]).status().is_ok_and(|s| s.success());
        if !ok { return Err(format!("{me} still cannot run commands as agent")); }
    } else {
        println!("as {me}, confirm with: sudo -n -u agent true && echo ok");
    }
    println!("done. Group membership takes effect in a new login session.");
    println!("Then log the harnesses in as agent: sudo -u agent -i claude, and sudo -u agent -i codex login");
    Ok(())
}

/// The host file `bon setup` writes: where agent's tools live, and the prices
/// of the models in use. Traces record the prices they were costed at.
const HOST_TEMPLATE: &str = r#"# bon's host file: facts about this host, not about any repository.
# Owned by root; edit with sudo. Every trace records the prices it was costed at.

# Two pools, each shared by every bon process on this host; width per search
# stays what each repository's bon.toml says. generation: model sessions at
# once (default 64; a session waits on the model). checks: CPU-heavy commands
# at once, the judge's checks and every cargo an agent process runs (default
# cores / check_threads, never more than free memory / 1.5 GB). check_threads:
# threads one check may use (default 2). BON_GENERATION, BON_CHECKS and
# BON_CHECK_THREADS in bon's environment override them.
# generation = 64
# checks = 7
# check_threads = 2

# PATH for agent processes and checks. Nothing else is inherited. Checks drop
# every entry under agent's home: they run only what no agent process can write.
path = ["/opt/bon/cargo/bin", "/opt/bon/verus", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/Users/agent/.local/bin"]

# The toolchain checks judge with, installed by bon setup: root's all the way up.
rustup_home = "/opt/bon/rustup"
cargo_home = "/opt/bon/cargo-home"

# Dollars per million tokens, API list prices, by canonical model id. Keep only
# the models in use. cache_write is the shorter TTL (Claude 5m, OpenAI 30m),
# cache_write_long the longer (Claude 1h, OpenAI 12h). As of 2026-11-03.
[prices]
"claude-haiku-5-5" = { input = 0.10, cached_input = 0.01, output = 0.50, cache_write = 0.125, cache_write_long = 0.20 }
"gpt-6.1-sol" = { input = 2.00, cached_input = 0.10, output = 10.00, cache_write = 2.50, cache_write_long = 5.00 }
"#;

/// The repository's dependencies, trusted code, tools and harness services.
/// Each place a Rust file outside `declared` (the trusted files and the checks)
/// skips a proof: `#[verifier::external…]`, `assume(` or `admit(`, as path:line.
fn holes(root: &Path, declared: &[String]) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) {
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
fn skips(text: &str) -> Vec<usize> {
    // Tokens: identifiers and single punctuation, each with its line.
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

fn sbom(root: &str, check: bool) -> Result<(), String> {
    let r = Path::new(root);
    let read = |p: &str| std::fs::read_to_string(r.join(p)).map_err(|e| format!("{p}: {e}"));
    let manifest: toml::Value = if r.join(".bon/bon.toml").exists() {
        toml::from_str(&read(".bon/bon.toml")?).map_err(|e| format!(".bon/bon.toml: {e}"))?
    } else { toml::Value::Table(Default::default()) };
    let config = manifest.get("sbom");
    if config.is_none() { eprintln!("no [sbom] in .bon/bon.toml: trusted code and tools not listed"); }
    let default_name = r.canonicalize().unwrap_or_else(|_| r.to_path_buf()).file_name()
        .unwrap_or_default().to_string_lossy().to_string();
    let name = config.and_then(|v| v.get("name")).and_then(|v| v.as_str()).unwrap_or(&default_name);
    // Keep namespace slashes, but escape reserved characters in package names and versions.
    let encode = |s: &str| -> String { s.bytes().map(|b| {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) { (b as char).to_string() }
        else { format!("%{b:02X}") }
    }).collect() };
    let library = |kind: &str, name: &str, version: &str| serde_json::json!({
        "type": "library", "name": name, "version": version,
        "purl": format!("pkg:{kind}/{}@{}", encode(name), encode(version))
    });
    let mut components = Vec::new();
    if r.join("Cargo.lock").exists() {
        let lock: toml::Value = toml::from_str(&read("Cargo.lock")?).map_err(|e| format!("Cargo.lock: {e}"))?;
        for p in lock.get("package").and_then(|v| v.as_array()).into_iter().flatten() {
            let (Some(name), Some(version)) = (p.get("name").and_then(|v| v.as_str()), p.get("version").and_then(|v| v.as_str())) else { continue; };
            let mut c = library("cargo", name, version);
            if let Some(sum) = p.get("checksum").and_then(|v| v.as_str()) {
                c["hashes"] = serde_json::json!([{ "alg": "SHA-256", "content": sum }]);
            }
            components.push(c);
        }
    }
    if r.join("package-lock.json").exists() {
        let lock: serde_json::Value = serde_json::from_str(&read("package-lock.json")?).map_err(|e| format!("package-lock.json: {e}"))?;
        for (path, p) in lock.get("packages").and_then(|v| v.as_object()).into_iter().flatten() {
            if path.is_empty() { continue; }
            let Some(version) = p.get("version").and_then(|v| v.as_str()) else { continue; };
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or_else(|| path.rsplit("node_modules/").next().unwrap_or(path));
            let c = library("npm", name, version);
            if !components.contains(&c) { components.push(c); }
        }
    }
    if r.join("go.sum").exists() {
        for l in read("go.sum")?.lines() {
            let mut fields = l.split_whitespace();
            let (Some(name), Some(version)) = (fields.next(), fields.next()) else { continue; };
            let c = library("golang", name, version.trim_end_matches("/go.mod"));
            if !components.contains(&c) { components.push(c); }
        }
    }
    // From /tmp: agent cannot enter engineer's repository, and rustup reads the current directory.
    let output = |program: &str, args: &[&str]| -> String {
        Command::new(program).args(args).current_dir("/tmp").output().ok().filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(if o.stdout.is_empty() { &o.stderr } else { &o.stdout }).trim().to_string())
            .filter(|v| !v.is_empty()).unwrap_or_else(|| "absent".into())
    };
    let first = |s: String| s.lines().next().unwrap_or("absent").trim().to_string();
    let is_agent = output("id", &["-un"]) == "agent";
    let as_agent = |command: &str| -> String {
        let a = ["env", "-i", "PATH=/Users/agent/.local/bin:/Users/agent/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin", "HOME=/Users/agent", "sh", "-c", command];
        if is_agent { output(a[0], &a[1..]) } else { output("sudo", &[&["-n", "-u", "agent"][..], &a[..]].concat()) }
    };
    if let Some(tools) = config.and_then(|v| v.get("tools")).and_then(|v| v.as_table()) {
        for (name, command) in tools {
            let text = as_agent(command.as_str().ok_or_else(|| format!("sbom.tools.{name} must be a command string"))?);
            let version = if name == "verus" {
                text.lines().find_map(|l| l.split_once("Version:").map(|(_, v)| v.trim().to_string())).unwrap_or_else(|| "absent".into())
            } else { first(text) };
            components.push(serde_json::json!({ "type": "application", "name": name, "version": version, "group": "tcb" }));
        }
    }
    // Host-level TCB, even if no tools are configured. Merge identical git entries.
    for (kind, name, version) in [
        ("application", "git", first(output("git", &["--version"]))),
        ("operating-system", "macOS", first(output("sw_vers", &["-productVersion"]))),
    ] {
        let c = serde_json::json!({ "type": kind, "name": name, "version": version, "group": "tcb" });
        if !components.contains(&c) { components.push(c); }
    }
    let mut properties = vec![serde_json::json!({ "name": "bon:version", "value": env!("CARGO_PKG_VERSION") })];
    let mut trusted = Vec::new();
    for file in config.and_then(|v| v.get("trusted")).and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| v.as_str()) {
        if !r.join(file).is_file() { continue; }
        properties.push(serde_json::json!({ "name": "bon:trusted-file", "value": file }));
        let text = read(file)?;
        let mut next = false;
        for l in text.lines().map(str::trim).filter(|l| !l.starts_with("//")) {
            if l.starts_with("#[verifier::external_body]") || l.starts_with("#[verifier::external]") { next = true; }
            if next {
                if let Some(n) = l.split("fn ").nth(1).or_else(|| l.split("struct ").nth(1)) {
                    trusted.push(n.split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("").to_string());
                    next = false;
                }
            }
        }
    }
    properties.push(serde_json::json!({ "name": "bon:trusted-functions", "value": trusted.join(",") }));
    // Outside trusted code and the checks, nothing may skip a proof.
    let declared: Vec<String> = config.and_then(|v| v.get("trusted")).and_then(|v| v.as_array()).into_iter().flatten()
        .chain(manifest.get("checks").and_then(|v| v.get("paths")).and_then(|v| v.as_array()).into_iter().flatten())
        .filter_map(|v| v.as_str().map(String::from)).collect();
    let found = holes(r, &declared);
    if !found.is_empty() {
        return Err(format!("a proof is skipped outside trusted code and the checks: {}; prove it, or declare the file trusted in [sbom]", found.join(", ")));
    }
    let harnesses: Vec<&str> = manifest.get("harness").and_then(|v| v.as_array()).into_iter().flatten()
        .chain(manifest.get("counterexample").and_then(|v| v.get("harness")).and_then(|v| v.as_array()).into_iter().flatten())
        .filter_map(|v| v.get("name").and_then(|v| v.as_str())).collect();
    let mut services = Vec::new();
    for (harness, name, endpoint) in [("claude", "Anthropic API", "https://api.anthropic.com"), ("codex", "OpenAI API", "https://api.openai.com")] {
        if harnesses.contains(&harness) { services.push(serde_json::json!({ "name": name, "endpoints": [endpoint], "group": "harness" })); }
    }
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": { "component": { "type": "application", "name": name }, "properties": properties },
        "components": components, "services": services,
    });
    let out = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
    let path = r.join(best_of_n::trusted::SBOM);
    if check {
        let current = std::fs::read_to_string(&path).map_err(|e| if e.kind() == std::io::ErrorKind::NotFound {
            format!("{} missing; run bon sbom", best_of_n::trusted::SBOM)
        } else { e.to_string() })?;
        if current != out { return Err(format!("{} differs from this machine; run bon sbom", best_of_n::trusted::SBOM)); }
        println!("{} matches", best_of_n::trusted::SBOM);
    } else {
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&path, out).map_err(|e| e.to_string())?;
        println!("wrote {}", best_of_n::trusted::SBOM);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bon_works_on_the_remotes_trunk_and_never_touches_the_working_tree() {
        let d = std::env::temp_dir().join(format!("bon-remote-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (work, remote) = (d.join("work"), d.join("remote.git"));
        std::fs::create_dir_all(&work).unwrap();
        git(&d, &["init", "-q", "--bare", "-b", "main", remote.to_str().unwrap()]).unwrap();
        git(&work, &["init", "-q", "-b", "main"]).unwrap();
        git(&work, &["remote", "add", "origin", remote.to_str().unwrap()]).unwrap();
        // Whoever runs the tests (agent, for a candidate) may have no git identity.
        git(&work, &["config", "user.name", "t"]).unwrap();
        git(&work, &["config", "user.email", "t@t"]).unwrap();
        std::fs::create_dir_all(work.join(".bon")).unwrap();
        std::fs::write(work.join(".bon/bon.toml"), "remote = \"origin\"\ntrunk = \"main\"\n").unwrap();
        git(&work, &["add", "."]).unwrap();
        git(&work, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "one"]).unwrap();
        git(&work, &["push", "-q", "origin", "main"]).unwrap();
        // The engineer is on another branch, with an uncommitted change.
        git(&work, &["checkout", "-q", "-b", "mine"]).unwrap();
        std::fs::write(work.join(".bon/bon.toml"), "remote = \"origin\"\ntrunk = \"main\"\n# editing\n").unwrap();
        let head: String = best_of_n::trusted::head(work.to_str().unwrap()).unwrap().iter().collect();
        assert_eq!(head, git(&remote, &["rev-parse", "main"]).unwrap());
        // A commit on trunk made from git's objects alone, pushed to the remote.
        let c = commit_file(&work, &head, ".bon/cost.toml", "cost = 1.00\n", "cost").unwrap();
        git(&work, &["push", "-q", "origin", &format!("{c}:refs/heads/main")]).unwrap();
        assert_eq!(git(&remote, &["rev-parse", "main"]).unwrap(), c);
        assert_eq!(git(&remote, &["show", "main:.bon/cost.toml"]).unwrap(), "cost = 1.00");
        // Nothing the engineer has moved: their branch, and their edit.
        assert_eq!(git(&work, &["symbolic-ref", "--short", "HEAD"]).unwrap(), "mine");
        assert!(std::fs::read_to_string(work.join(".bon/bon.toml")).unwrap().contains("# editing"));
        assert!(!work.join(".bon/cost.toml").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn two_transcripts_in_one_run_get_disjoint_ids() {
        let mut id = 7;
        let (mut a, mut b) = ("id\tintent\n".to_string(), "id\tintent".to_string());
        let first = numbered(&mut a, &mut id, &[(1, "one".into()), (2, "two".into())]);
        let second = numbered(&mut b, &mut id, &[(3, "three".into())]);
        assert_eq!(first, vec![(7, 1), (8, 2)]);
        assert_eq!(second, vec![(9, 3)]);
        assert_eq!(b, "id\tintent\n9\tthree\n");
    }

    #[test]
    fn a_retired_queue_id_is_never_reused_and_an_edit_keeps_its_id() {
        // 1 and 2 added; 2 reworded (an edit); 1 written into the spec (retired).
        let log = "commit a\n+++ b/.bon/queue.tsv\n+1\tone\n+2\ttwo\n\
                   commit b\n--- a/.bon/queue.tsv\n-2\ttwo\n+2\ttwo, narrowed\n\
                   commit c\n-1\tone\n";
        assert!(reused_ids(log, "id\tintent\n2\ttwo, narrowed\n3\tthree\n").is_empty());
        assert_eq!(reused_ids(log, "id\tintent\n1\tsomething else\n"), vec![(1, "c".to_string())]);
    }

    #[test]
    fn bon_check_says_whose_errors_they_are() {
        let log = "warning: unused\n   --> src/tui.rs:9:1\nerror[E0063]: missing field\n   --> src/encoding.rs:328:120\nerror: x\n  --> src/main.rs:35:9\nsrc/view.rs:12:3: error: y\nerror: z\n   --> /Users/x/.cargo/registry/serde/lib.rs:1:1";
        assert_eq!(error_paths(log), vec!["src/encoding.rs", "src/main.rs", "src/view.rs"]);
        let manifest: toml::Value = toml::from_str("[checks]\npaths = [\"src/spec.rs\"]\n[sbom]\ntrusted = [\"src/main.rs\", \"src/view.rs\"]").unwrap();
        assert!(protected(&manifest, "src/main.rs") && protected(&manifest, "src/spec.rs") && protected(&manifest, ".bon/bon.toml"));
        assert!(!protected(&manifest, "src/encoding.rs"));
    }

    #[test]
    fn the_cost_file_is_the_view_s_totals_in_a_fixed_order() {
        let p: projection::Projection = serde_json::from_value(serde_json::json!({
            "totals": { "cost": 100.0, "generation": 20.0, "time_cost": 80.0, "per_verified_candidate": 2.0, "per_push": 50.0, "pushes": 2, "verified": 50, "candidates": 60 },
            "groups": [{ "outcome": "pushed", "generation": 8.0 }, { "outcome": "pushed", "generation": 4.0 }, { "outcome": "blocked", "generation": 8.0 }]
        })).unwrap();
        let t = cost_toml(&p);
        let keys: Vec<&str> = t.lines().filter(|l| !l.starts_with('#')).map(|l| l.split(" = ").next().unwrap()).collect();
        assert_eq!(keys, ["cost", "generation", "time", "per_verified_candidate", "per_push", "generation_per_verified_candidate", "generation_per_push", "pushes", "verified", "candidates"]);
        assert!(t.contains("generation_per_verified_candidate = 0.40") && t.contains("generation_per_push = 6.00"), "{t}");
        assert!(toml::from_str::<toml::Value>(&t).is_ok());
    }

    #[test]
    fn bon_notices_its_own_kernel_is_stale() {
        let built = |p: &str| KERNEL.iter().find(|(k, _)| *k == p).map(|(_, t)| t.to_string());
        assert!(stale(built).is_empty());
        assert_eq!(stale(|p| if p == "src/exec.rs" { Some("fn f() {}".into()) } else { built(p) }), ["src/exec.rs"]);
        assert_eq!(stale(|p| if p == "src/spec.rs" { None } else { built(p) }), ["src/spec.rs"]);
        assert_eq!(stale(|_| None).len(), 5);
    }

    #[test]
    fn traces_reach_their_own_private_remote_and_never_the_code_s() {
        let d = std::env::temp_dir().join(format!("bon-traces-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (work, private, public) = (d.join("work"), d.join("traces.git"), d.join("public.git"));
        std::fs::create_dir_all(work.join(".bon/traces/123")).unwrap();
        for r in [&private, &public] { git(&d, &["init", "-q", "--bare", "-b", "main", r.to_str().unwrap()]).unwrap(); }
        git(&work, &["init", "-q", "-b", "main"]).unwrap();
        git(&work, &["remote", "add", "origin", public.to_str().unwrap()]).unwrap();
        std::fs::write(work.join(".bon/traces/123/transitions"), "initialize\n").unwrap();
        std::fs::write(work.join(".bon/traces/running"), "123").unwrap();
        // Naming the code's own remote is refused, and nothing is committed.
        std::fs::write(work.join(".bon/bon.toml"), format!("traces = {:?}\n", public.to_str().unwrap())).unwrap();
        assert!(persist(&work).unwrap_err().contains("private"));
        assert!(!work.join(".bon/traces/.git").exists());
        // A private remote of its own gets the traces, and not the running marker.
        std::fs::write(work.join(".bon/bon.toml"), format!("traces = {:?}\n", private.to_str().unwrap())).unwrap();
        persist(&work).unwrap();
        let files = git(&private, &["ls-tree", "-r", "--name-only", "main"]).unwrap();
        assert_eq!(files, ".gitignore\n123/transitions");
        // Nothing new: no commit.
        persist(&work).unwrap();
        assert_eq!(git(&private, &["rev-list", "--count", "main"]).unwrap(), "1");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_proposal_cites_each_intent_s_cue() {
        let d = std::env::temp_dir().join(format!("bon-proposal-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".bon")).unwrap();
        let sh = |args: &[&str]| { let o = Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args).current_dir(&d).output().unwrap(); assert!(o.status.success()); String::from_utf8_lossy(&o.stdout).trim().to_string() };
        sh(&["init", "-q", "-b", "main"]);
        // Checks run as agent, who may have no git identity of its own.
        sh(&["config", "user.name", "t"]);
        sh(&["config", "user.email", "t@t"]);
        std::fs::write(d.join(".bon/queue.tsv"), "id\tintent\n").unwrap();
        sh(&["add", "."]);
        sh(&["commit", "-q", "-m", "base"]);
        let head = sh(&["rev-parse", "HEAD"]);
        let c = proposal(&d, &head, "id\tintent\n7\tone\n8\ttwo\n", "transcripts/a.vtt", &[(7, 1200), (8, 64500)], &[90000]).unwrap();
        let trailers = git(&d, &["log", "-1", "--format=%(trailers)", &c]).unwrap();
        assert_eq!(trailers.trim(), "Source: transcripts/a.vtt\nCue: 7 transcripts/a.vtt#1200\nCue: 8 transcripts/a.vtt#64500\nContested: transcripts/a.vtt#90000");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_skipped_proof_outside_trusted_code_is_found() {
        let d = std::env::temp_dir().join(format!("bon-holes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("src/exec.rs"), "fn a() {}\n#[verifier::external_body]\nfn b() {}\nproof fn c() { assume(false); }\n// admit() in a comment\nfn assume_x() {}\n").unwrap();
        std::fs::write(d.join("src/trusted.rs"), "#[verifier::external_body]\nfn t() {}\n").unwrap();
        std::fs::write(d.join("src/spec.rs"), "proof fn s() { admit(); }\n").unwrap();
        let declared = vec!["src/trusted.rs".to_string(), "src/spec.rs".to_string()];
        assert_eq!(holes(&d, &declared), vec!["src/exec.rs:2", "src/exec.rs:4"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_skipped_proof_is_found_by_tokens_in_every_spelling() {
        assert_eq!(skips("proof fn a() { assume (false); }"), [1]);
        assert_eq!(skips("proof fn a() {\n    assume\n        (false);\n}"), [2]);
        assert_eq!(skips("fn a() {}\n#[verifier(external_body)]\nfn b() {}"), [2]);
        assert_eq!(skips("#![verifier::external]\n"), [1]);
        assert_eq!(skips("pub assume_specification<T> [ f ] (x: T);"), [1]);
        assert_eq!(skips("proof fn a() { admit\t(); }"), [1]);
    }

    #[test]
    fn comments_and_literals_skip_no_proof() {
        assert!(skips("// assume(false);\nfn a() {}").is_empty());
        assert!(skips("/* admit(); /* nested */ assume(x) */ fn a() {}").is_empty());
        assert!(skips("/// #[verifier::external_body]\nfn a() {}").is_empty());
        assert!(skips(r##"fn a() { let s = "assume(false)"; let r = r#"admit()"#; let b = b"assume("; }"##).is_empty());
        assert!(skips("fn a<'x>(c: char) -> bool { c == '\"' || c == '\\'' } fn assume_x() {} fn assume(b: bool) {}").is_empty());
        // Lines count across what is skipped.
        assert_eq!(skips("/* a\nb */ \"c\nd\"\n'\\n' assume(false);"), [4]);
    }
}
