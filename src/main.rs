//! The bon CLI. Trusted code: it parses arguments, prints, and calls the
//! verified drivers in exec.rs, which make every decision.

use std::path::{Path, PathBuf};
use std::process::Command;

use best_of_n::exec;

const USAGE: &str = "usage:
  bon                     every intent in the map, and whether it is built
  bon code \"<intent>\"     search for code that makes this intent hold; fast-forward trunk
  bon compaction          search for code that removes or simplifies without changing behavior
  bon background [--plist] one unit of the stalest scrub or compaction, on spare capacity
  bon scrub \"<intent>\"    check an intent against trunk with tests written from the spec and the intent
  bon map                 turn each new transcript into a proposal for the map
  bon setup [--dry-run] [--for <user>]
                          create user agent and group bon, and let <user> (default: you) run commands as agent;
                          run it as an administrator
  bon sbom [--check]      write sbom.json, or fail if it differs from this machine";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = match git(Path::new("."), &["rev-parse", "--show-toplevel"]) {
        Ok(r) => r,
        // setup and help need no repository; sbom also runs in a checkout with no .git (a check).
        Err(_) if matches!(args.first().map(String::as_str), Some("setup" | "sbom" | "help" | "-h" | "--help")) => ".".into(),
        Err(e) => fail(&format!("not in a git repository: {e}")),
    };
    let result = match args.first().map(String::as_str) {
        None => status(&root),
        Some("code" | "compaction" | "map") => { running(&root); dispatch(&root, &args) }
        _ => dispatch(&root, &args),
    };
    best_of_n::trusted::cleanup(&["/usr/bin".into(), "/bin".into()]);
    if let Err(e) = result { fail(&e) }
}

fn dispatch(root: &str, args: &[String]) -> Result<(), String> {
    let root = root.to_string();
    match args.first().map(String::as_str) {
        Some("code") => {
            let intent = args[1..].join(" ");
            if intent.is_empty() { fail("which intent? bon code \"<intent>\"") }
            exec::land(&root, Some(intent.chars().collect()), best_of_n::trusted::no_tests()).map(|_| println!("trunk fast-forwarded"))
        }
        Some("compaction") => exec::land(&root, None, best_of_n::trusted::no_tests()).map(|_| println!("trunk fast-forwarded")),
        Some("scrub") => {
            let intent = args[1..].join(" ");
            if intent.is_empty() { fail("which intent? bon scrub \"<intent>\"") }
            running(&root);
            scrub(&root, &intent)
        }
        Some("background") if args.get(1).map(String::as_str) == Some("--plist") => { plist(&root); Ok(()) }
        Some("background") => background(&root),
        Some("map") => map(&root),
        Some("setup") => {
            let dry_run = args.iter().any(|a| a == "--dry-run");
            let user = args.iter().position(|a| a == "--for").and_then(|i| args.get(i + 1)).cloned();
            setup(dry_run, user)
        }
        Some("sbom") => sbom(&root, args.get(1).map(String::as_str) == Some("--check")),
        Some("help" | "-h" | "--help") => { println!("{USAGE}"); Ok(()) }
        Some(other) => Err(format!("unknown command {other}\n{USAGE}")),
        None => status(&root),
    }
}

/// Mark this repository as having a bon command running, for bon background.
fn running(root: &str) {
    let d = Path::new(root).join(".bon");
    let _ = std::fs::create_dir_all(&d);
    let _ = std::fs::write(d.join("running"), std::process::id().to_string());
}

/// bon scrub, and if the intent is broken, the code search that carries its test.
fn scrub(root: &str, intent: &str) -> Result<(), String> {
    let goal: Vec<char> = intent.chars().collect();
    match exec::scrub(root, goal.clone())? {
        None => { println!("holds: its test is retained on trunk"); Ok(()) }
        Some(carried) => {
            println!("broken: the agreed test fails on trunk; searching for code that passes it");
            exec::land(root, Some(goal.clone()), carried)?;
            println!("trunk fast-forwarded; scrubbing again on the new trunk");
            // The fix landed: a scrub of the new trunk retains a test for the intent.
            match exec::scrub(root, goal)? {
                None => { println!("holds: its test is retained on trunk"); Ok(()) }
                Some(_) => Err("still broken after the fix landed; see .bon/traces".into()),
            }
        }
    }
}

/// bon background: one unit of the stalest work, only on spare capacity. Staleness
/// is trunk commits since an intent's last scrub, or since the last compaction.
/// (intent 25)
fn background(root: &str) -> Result<(), String> {
    let r = Path::new(root);
    // Spare capacity: no bon command running here, and load below the device's jobs.
    let busy = std::fs::read_to_string(r.join(".bon/running")).ok()
        .filter(|pid| Command::new("kill").args(["-0", pid.trim()]).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success()));
    if busy.is_some() { println!("busy: a bon command is running here"); return Ok(()); }
    let jobs = std::fs::read_to_string(best_of_n::trusted::DEVICE).ok()
        .and_then(|d| d.lines().find_map(|l| l.strip_prefix("jobs").and_then(|v| v.trim_start_matches([' ', '=']).trim().parse::<f64>().ok())))
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1.0, |n| (n.get() / 2).max(1) as f64));
    let load: f64 = Command::new("sysctl").args(["-n", "vm.loadavg"]).output().ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0.0);
    if load >= jobs { println!("busy: load {load:.1} is at or above jobs {jobs}"); return Ok(()); }
    // The stalest work, in trunk commits.
    let total: u64 = git(r, &["rev-list", "--count", "HEAD"])?.trim().parse().unwrap_or(0);
    let since = |t: u64| git(r, &["rev-list", "--count", &format!("--since={t}"), "HEAD"]).ok()
        .and_then(|c| c.trim().parse::<u64>().ok()).unwrap_or(total);
    let scrubs: Vec<serde_json::Value> = std::fs::read_to_string(r.join(".bon/scrubs.jsonl")).unwrap_or_default()
        .lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let last = git(r, &["log", "-1", "--format=%H", "--fixed-strings", "--grep=compaction"]).unwrap_or_default();
    let mut stalest: (u64, Option<String>) = (
        if last.is_empty() { total } else { git(r, &["rev-list", "--count", &format!("{last}..HEAD")])?.trim().parse().unwrap_or(total) },
        None,
    );
    if git(r, &["show", "HEAD:bon.toml"]).unwrap_or_default().contains("[scrub]") {
        for line in git(r, &["show", "HEAD:map"])?.lines() {
            let intent = line.split('\t').next().unwrap_or("").trim();
            if intent.is_empty() { continue; }
            let n = scrubs.iter().filter(|v| v["intent"] == intent).last()
                .and_then(|v| v["time"].as_u64()).map_or(total, since);
            if n > stalest.0 { stalest = (n, Some(intent.to_string())); }
        }
    }
    if stalest.0 == 0 { println!("nothing stale"); return Ok(()); }
    running(root);
    match stalest.1 {
        Some(intent) => { println!("scrub ({} commits stale): {intent}", stalest.0); scrub(root, &intent) }
        None => {
            println!("compaction ({} commits stale)", stalest.0);
            exec::land(root, None, best_of_n::trusted::no_tests()).map(|_| println!("trunk fast-forwarded"))
        }
    }
}

/// A launchd job that runs bon background in this repository every five minutes.
/// The interval is only how often it looks for spare capacity.
fn plist(root: &str) {
    let bon = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or("bon".into());
    let name = Path::new(root).file_name().map_or("repo".into(), |n| n.to_string_lossy().to_string());
    println!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.bon.background.{name}</string>
  <key>ProgramArguments</key><array><string>{bon}</string><string>background</string></array>
  <key>WorkingDirectory</key><string>{root}</string>
  <key>StartInterval</key><integer>300</integer>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>{root}/.bon/background.log</string>
  <key>StandardErrorPath</key><string>{root}/.bon/background.log</string>
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

/// Status is derived, never stored: an intent is built when trunk has a commit
/// whose subject is that intent, and broken when its latest scrub failed after
/// that commit. (intents 1, 21)
fn status(root: &str) -> Result<(), String> {
    let root = Path::new(root);
    let map = git(root, &["show", "HEAD:map"]).map_err(|_| "no map at trunk's head".to_string())?;
    let log = git(root, &["log", "--format=%ct %s"])?;
    let scrubs: Vec<serde_json::Value> = std::fs::read_to_string(root.join(".bon/scrubs.jsonl")).unwrap_or_default()
        .lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    for line in map.lines() {
        let intent = line.split('\t').next().unwrap_or("").trim();
        if intent.is_empty() { continue; }
        let landed = log.lines().filter_map(|l| l.split_once(' ')).filter(|(_, s)| *s == intent)
            .filter_map(|(t, _)| t.parse::<u64>().ok()).max();
        let failed = scrubs.iter().filter(|v| v["intent"] == intent).last()
            .filter(|v| v["passes"] == false).and_then(|v| v["time"].as_u64());
        let state = match (landed, failed) {
            (_, Some(f)) if landed.is_none_or(|l| l < f) => "broken",
            (Some(_), _) => "built",
            _ => "open",
        };
        println!("{state:<6} {intent}");
    }
    Ok(())
}

/// Each transcript not yet cited by a commit on trunk becomes a proposal: a
/// commit adding its agreed intents to the map, at refs/bon/proposal/<name>.
/// engineer decides by fast-forwarding to it, editing it, or ignoring it.
fn map(root: &str) -> Result<(), String> {
    let r = Path::new(root);
    let config = git(r, &["show", "HEAD:bon.toml"])?;
    let dir = config.lines().find_map(|l| l.strip_prefix("transcripts").and_then(|v| v.split('"').nth(1)))
        .unwrap_or("transcripts").to_string();
    let cited = git(r, &["log", "--format=%(trailers:key=Source,valueonly)"])?;
    let mut any = false;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(r.join(&dir)).map_err(|e| format!("{dir}: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "vtt")).collect();
    entries.sort();
    for p in entries {
        let rel = format!("{dir}/{}", p.file_name().unwrap().to_string_lossy());
        if cited.lines().any(|l| l.trim() == rel) { continue; }
        any = true;
        println!("{rel}: searching");
        let (agreed, contested) = exec::map(root, rel.chars().collect())?;
        let head = git(r, &["rev-parse", "HEAD"])?;
        let mut text = git(r, &["show", "HEAD:map"])?;
        if !text.is_empty() && !text.ends_with('\n') { text.push('\n'); }
        for (cue, intent) in &agreed {
            text.push_str(&format!("{}\t{rel}#{}\n", intent.iter().collect::<String>(), timestamp(*cue)));
        }
        let commit = proposal(r, &head, &text, &rel)?;
        let name = p.file_stem().unwrap().to_string_lossy();
        git(r, &["update-ref", &format!("refs/bon/proposal/{name}"), &commit])?;
        println!("{} agreed, {} contested", agreed.len(), contested.len());
        for c in &contested { println!("  contested cue {}", timestamp(*c)); }
        println!("  review: git show refs/bon/proposal/{name}");
        println!("  accept: git merge --ff-only refs/bon/proposal/{name}");
    }
    if !any { println!("no new transcripts in {dir}"); }
    Ok(())
}

/// A commit on `head` whose map is `text`, citing the transcript.
fn proposal(root: &Path, head: &str, text: &str, source: &str) -> Result<String, String> {
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
    with(&["update-index", "--add", "--cacheinfo", &format!("100644,{blob},map")])?;
    let tree = with(&["write-tree"])?;
    let _ = std::fs::remove_file(&index);
    git(root, &["commit-tree", &tree, "-p", head, "-m", &format!("map: {source}\n\nSource: {source}\n")])
}

/// Milliseconds to a WebVTT timestamp.
fn timestamp(ms: u64) -> String {
    format!("{:02}:{:02}:{:02}.{:03}", ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60, ms % 1000)
}

/// Create user agent and group bon, put engineer and agent in bon, and let
/// engineer run commands as agent (never as root) with no password. Each step
/// runs with sudo and is printed first. (intents 7, 8)
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
    steps.push(s(&["sh", "-c", "mkdir -p /tmp/bon && chmod 1777 /tmp/bon"]));
    // The device file: written once, then edited by hand (with sudo) as models and prices change.
    if !std::path::Path::new(best_of_n::trusted::DEVICE).exists() {
        let draft = std::env::temp_dir().join(format!("bon-device-{}.toml", std::process::id()));
        if !dry_run { std::fs::write(&draft, DEVICE_TEMPLATE).map_err(|e| e.to_string())?; }
        steps.push(vec!["sh".into(), "-c".into(), format!(
            "mkdir -p /etc/bon && install -m 0644 -o root -g wheel {} {}", draft.display(), best_of_n::trusted::DEVICE)]);
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

/// The device file `bon setup` writes: where agent's tools live, and the prices
/// of the models in use. Traces record the prices they were costed at.
const DEVICE_TEMPLATE: &str = r#"# bon's device file: facts about this machine, not about any repository.
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

/// The SBOM, as CycloneDX: every crate in Cargo.lock, the toolchain, the TCB
/// tools, the services the harnesses call, and the trusted code. (intent 18)
fn sbom(root: &str, check: bool) -> Result<(), String> {
    let r = Path::new(root);
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(r.join("Cargo.lock")).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut components = Vec::new();
    for p in lock["package"].as_array().into_iter().flatten() {
        let (name, version) = (p["name"].as_str().unwrap_or(""), p["version"].as_str().unwrap_or(""));
        let mut c = serde_json::json!({ "type": "library", "name": name, "version": version,
            "purl": format!("pkg:cargo/{name}@{version}") });
        if let Some(sum) = p.get("checksum").and_then(|v| v.as_str()) {
            c["hashes"] = serde_json::json!([{ "alg": "SHA-256", "content": sum }]);
        }
        components.push(c);
    }
    // From /tmp: agent cannot enter engineer's repository, and rustup reads the current directory.
    let version = |program: &str, args: &[&str]| -> String {
        Command::new(program).args(args).current_dir("/tmp").output().ok()
            .filter(|o| o.status.success())
            .map(|o| { let s = if o.stdout.is_empty() { o.stderr } else { o.stdout }; String::from_utf8_lossy(&s).lines().next().unwrap_or("").trim().to_string() })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "absent".into())
    };
    // agent runs the harnesses and the checks, so the toolchain and harness
    // versions are observed as agent: the SBOM describes what candidates are judged with.
    // As a check, bon sbom already runs as agent, which cannot sudo.
    let is_agent = version("id", &["-un"]) == "agent";
    let as_agent = |program: &str, args: &[&str]| -> String {
        let mut a = vec!["env", "-i", "PATH=/Users/agent/.local/bin:/Users/agent/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin", "HOME=/Users/agent", program];
        a.extend_from_slice(args);
        if is_agent { version(a[0], &a[1..]) } else { version("sudo", &[&["-n", "-u", "agent"][..], &a[..]].concat()) }
    };
    let verus = {
        let mut a = vec!["env", "-i", "PATH=/Users/agent/.local/bin:/Users/agent/.cargo/bin:/usr/bin:/bin", "HOME=/Users/agent", "verus", "--version"];
        if !is_agent { a = [&["-n", "-u", "agent"][..], &a[..]].concat(); }
        let program = if is_agent { "env" } else { "sudo" };
        Command::new(program).args(if is_agent { &a[1..] } else { &a[..] }).current_dir("/tmp").output().ok().filter(|o| o.status.success())
            .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().find(|l| l.contains("Version:")).map(|l| l.replace("Version:", "").trim().to_string()))
            .unwrap_or_else(|| "absent".into())
    };
    for (kind, name, v) in [
        ("application", "rustc", as_agent("rustc", &["--version"])),
        ("application", "verus", verus),
        ("application", "git", version("git", &["--version"])),
        ("application", "sudo", version("sudo", &["-V"])),
        ("application", "tar", version("tar", &["--version"])),
        ("application", "claude", as_agent("claude", &["--version"])),
        ("application", "codex", as_agent("codex", &["--version"])),
        ("operating-system", "macOS", version("sw_vers", &["-productVersion"])),
    ] {
        components.push(serde_json::json!({ "type": kind, "name": name, "version": v, "group": "tcb" }));
    }
    let mut trusted = Vec::new();
    let text = std::fs::read_to_string(r.join("src/trusted.rs")).unwrap_or_default();
    let mut next = false;
    for l in text.lines() {
        if l.contains("verifier::external_body") { next = true; continue; }
        if next {
            if let Some(n) = l.split("fn ").nth(1).or_else(|| l.split("struct ").nth(1)) {
                trusted.push(n.split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("").to_string());
            }
            next = false;
        }
    }
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": { "type": "application", "name": "best-of-n", "version": env!("CARGO_PKG_VERSION") },
            "properties": [
                { "name": "bon:trusted-file", "value": "src/trusted.rs" },
                { "name": "bon:trusted-file", "value": "src/main.rs" },
                { "name": "bon:trusted-functions", "value": trusted.join(",") },
            ],
        },
        "components": components,
        "services": [
            { "name": "Anthropic API", "endpoints": ["https://api.anthropic.com"], "group": "harness" },
            { "name": "OpenAI API", "endpoints": ["https://api.openai.com"], "group": "harness" },
        ],
    });
    let out = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
    let path = r.join("sbom.json");
    if check {
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current != out { return Err("sbom.json differs from this machine; run bon sbom".into()); }
        println!("sbom.json matches");
    } else {
        std::fs::write(&path, out).map_err(|e| e.to_string())?;
        println!("wrote sbom.json");
    }
    Ok(())
}
