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
  bon view [--port N]     one live page of the same
  bon background [--plist] the stalest of compaction and counterexample, on spare capacity
  bon setup [--dry-run] [--for <user>]
                          create user agent and group bon, and let <user> (default: you) run commands as agent;
                          run it as an administrator
  bon sbom [--check]      write .bon/sbom.json, or fail if it differs from this machine
  bon types [--check]     write the types programs are built on, or fail if one is stale
  bon spec [NAME]         the spec's vocabulary and how it reaches the code, or one item";

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
    // Before a search: every harness it may run is logged in as agent, or the command that fixes it.
    if SEARCHES.contains(&command) {
        let checked = best_of_n::trusted::head(&root).and_then(|h| best_of_n::trusted::manifest(&root, &h)).and_then(|m| best_of_n::trusted::harnesses_logged_in(&m));
        if let Err(e) = checked { fail(&e) }
    }
    if SEARCHES.contains(&command) && command != "background" { running(&root); }
    let result = dispatch(&root, &args);
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
        Some("view") => {
            let port = args.iter().position(|a| a == "--port").and_then(|i| args.get(i + 1)).and_then(|p| p.parse().ok()).unwrap_or(4747);
            view::serve(&root, port, !args.iter().any(|a| a == "--no-open"))
        }
        Some("queue") => queue(&root),
        Some("setup") => {
            let dry_run = args.iter().any(|a| a == "--dry-run");
            let user = args.iter().position(|a| a == "--for").and_then(|i| args.get(i + 1)).cloned();
            setup(dry_run, user)
        }
        Some("sbom") => sbom(&root, args.get(1).map(String::as_str) == Some("--check")),
        Some("types") => types::run(&root, args.get(1).map(String::as_str) == Some("--check")),
        Some("spec") => { print!("{}", tui::spec_text(&root, args.get(1).map(String::as_str), 100)?); Ok(()) }
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

/// Mark this repository as having a bon command running, for bon background.
fn running(root: &str) {
    let d = Path::new(root).join(".bon/traces");
    let _ = std::fs::create_dir_all(&d);
    let _ = std::fs::write(d.join("running"), std::process::id().to_string());
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
    let busy = std::fs::read_to_string(r.join(".bon/traces/running")).ok()
        .filter(|pid| Command::new("ps").args(["-p", pid.trim()]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success()));
    if busy.is_some() { println!("busy: a bon command is running here"); return Ok(()); }
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
    running(root);
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
    println!("then run bon and bon view");
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
    for ((p, rel), (agreed, contested)) in new.iter().zip(found) {
        let head = git(r, &["rev-parse", "HEAD"])?;
        let mut text = git(r, &["show", "HEAD:.bon/queue.tsv"]).unwrap_or_else(|_| "id\tintent\n".into());
        if !text.ends_with('\n') { text.push('\n'); }
        let mut id = next_id(r);
        let mut cues = Vec::new();
        for (cue, intent) in &agreed {
            text.push_str(&format!("{id}\t{}\n", intent.iter().collect::<String>()));
            cues.push((id, *cue));
            id += 1;
        }
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

/// Create user agent and group bon, put engineer and agent in bon, and let
/// engineer run commands as agent (never as root) with no password. Each step
/// runs with sudo and is printed first.
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

# How many agent processes run at once (default: half the cores). Width per
# search stays what each repository's bon.toml says.
jobs = 7

# PATH for agent processes and checks. Nothing else is inherited.
path = ["/Users/agent/.local/bin", "/Users/agent/.cargo/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]

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
    let skips = |l: &str| {
        let call = |w: &str| l.match_indices(w).any(|(i, _)| !l[..i].ends_with(|c: char| c.is_alphanumeric() || c == '_'));
        l.contains("#[verifier::external") || call("assume(") || call("admit(")
    };
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort();
    let mut found = Vec::new();
    for f in files {
        let rel = f.to_string_lossy().to_string();
        if declared.iter().any(|d| rel == *d || rel.starts_with(&format!("{}/", d.trim_end_matches('/')))) { continue; }
        let Ok(text) = std::fs::read_to_string(root.join(&f)) else { continue };
        for (n, l) in text.lines().enumerate() {
            let l = l.trim();
            if !l.starts_with("//") && skips(l) { found.push(format!("{rel}:{}", n + 1)); }
        }
    }
    found
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
}
