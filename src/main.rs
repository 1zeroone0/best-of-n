//! The bon CLI. Trusted code: it parses arguments, prints, and calls the
//! verified drivers in exec.rs, which make every decision.

use std::path::{Path, PathBuf};
use std::process::Command;

use best_of_n::exec;

const USAGE: &str = "usage:
  bon                     every intent in the map, and whether it is built
  bon code \"<intent>\"     search for code that makes this intent hold; fast-forward trunk
  bon compaction          search for code that removes or simplifies without changing behavior
  bon map                 turn each new transcript into a proposal for the map
  bon setup               create user agent and group bon, and let engineer run commands as agent
  bon sbom [--check]      write sbom.json, or fail if it differs from this machine";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = match git(Path::new("."), &["rev-parse", "--show-toplevel"]) {
        Ok(r) => r,
        Err(_) if matches!(args.first().map(String::as_str), Some("setup" | "help" | "-h" | "--help")) => ".".into(),
        Err(e) => fail(&format!("not in a git repository: {e}")),
    };
    let result = match args.first().map(String::as_str) {
        None => status(&root),
        Some("code") => {
            let intent = args[1..].join(" ");
            if intent.is_empty() { fail("which intent? bon code \"<intent>\"") }
            exec::land(&root, Some(intent.chars().collect())).map(|_| println!("trunk fast-forwarded"))
        }
        Some("compaction") => exec::land(&root, None).map(|_| println!("trunk fast-forwarded")),
        Some("map") => map(&root),
        Some("setup") => setup(),
        Some("sbom") => sbom(&root, args.get(1).map(String::as_str) == Some("--check")),
        Some("help" | "-h" | "--help") => { println!("{USAGE}"); Ok(()) }
        Some(other) => Err(format!("unknown command {other}\n{USAGE}")),
    };
    if let Err(e) = result { fail(&e) }
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
/// whose subject is that intent. (intent 1)
fn status(root: &str) -> Result<(), String> {
    let root = Path::new(root);
    let map = git(root, &["show", "HEAD:map"]).map_err(|_| "no map at trunk's head".to_string())?;
    let subjects = git(root, &["log", "--format=%s"])?;
    for line in map.lines() {
        let intent = line.split('\t').next().unwrap_or("").trim();
        if intent.is_empty() { continue; }
        let built = subjects.lines().any(|s| s == intent);
        println!("{:<6} {intent}", if built { "built" } else { "open" });
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
        let name = p.file_stem().unwrap().to_string_lossy().to_string();
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
fn setup() -> Result<(), String> {
    let me = std::env::var("USER").map_err(|_| "USER is not set")?;
    let exists = |kind: &str, name: &str| Command::new("dscl").args([".", "-read", &format!("/{kind}/{name}")])
        .output().is_ok_and(|o| o.status.success());
    let mut steps: Vec<Vec<String>> = Vec::new();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    if !exists("Groups", "bon") { steps.push(s(&["dseditgroup", "-o", "create", "bon"])); }
    if !exists("Users", "agent") {
        let password: String = std::fs::read("/dev/urandom").ok().and_then(|_| {
            let out = Command::new("openssl").args(["rand", "-base64", "32"]).output().ok()?;
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }).ok_or("could not make a password")?;
        steps.push(vec!["sysadminctl".into(), "-addUser".into(), "agent".into(), "-fullName".into(), "bon agent".into(),
                        "-shell".into(), "/bin/zsh".into(), "-home".into(), "/Users/agent".into(), "-password".into(), password]);
        steps.push(s(&["createhomedir", "-c", "-u", "agent"]));
        steps.push(s(&["dscl", ".", "create", "/Users/agent", "IsHidden", "1"]));
    }
    steps.push(s(&["dseditgroup", "-o", "edit", "-a", "agent", "-t", "user", "bon"]));
    steps.push(s(&["dseditgroup", "-o", "edit", "-a", &me, "-t", "user", "bon"]));
    steps.push(vec!["sh".into(), "-c".into(), format!(
        "printf '%s ALL=(agent) NOPASSWD: ALL\\n' {me} > /etc/sudoers.d/bon && chmod 0440 /etc/sudoers.d/bon && visudo -cf /etc/sudoers.d/bon")]);
    steps.push(s(&["sh", "-c", "mkdir -p /tmp/bon && chmod 1777 /tmp/bon"]));
    for step in &steps {
        let shown: Vec<&str> = step.iter().map(|x| if x.len() > 40 && !x.contains(' ') { "<random>" } else { x.as_str() }).collect();
        println!("sudo {}", shown.join(" "));
        let ok = Command::new("sudo").args(step).status().map_err(|e| e.to_string())?.success();
        if !ok { return Err(format!("failed: sudo {}", shown.join(" "))); }
    }
    let ok = Command::new("sudo").args(["-n", "-u", "agent", "true"]).status().is_ok_and(|s| s.success());
    if !ok { return Err("engineer still cannot run commands as agent".into()); }
    println!("done. Group membership takes effect in a new login session.");
    println!("Then log the harnesses in as agent: sudo -u agent -i claude, and sudo -u agent -i codex login");
    Ok(())
}

/// The SBOM, as CycloneDX: every crate in Cargo.lock, the toolchain, the TCB
/// tools, the services the harnesses call, and the trusted code. (intent 18)
fn sbom(root: &str, check: bool) -> Result<(), String> {
    let r = Path::new(root);
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(r.join("Cargo.lock")).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut components = Vec::new();
    for p in lock["package"].as_array().cloned().unwrap_or_default() {
        let (name, version) = (p["name"].as_str().unwrap_or(""), p["version"].as_str().unwrap_or(""));
        let mut c = serde_json::json!({ "type": "library", "name": name, "version": version,
            "purl": format!("pkg:cargo/{name}@{version}") });
        if let Some(sum) = p.get("checksum").and_then(|v| v.as_str()) {
            c["hashes"] = serde_json::json!([{ "alg": "SHA-256", "content": sum }]);
        }
        components.push(c);
    }
    let version = |program: &str, args: &[&str]| -> String {
        Command::new(program).args(args).output().ok()
            .map(|o| { let s = if o.stdout.is_empty() { o.stderr } else { o.stdout }; String::from_utf8_lossy(&s).lines().next().unwrap_or("").trim().to_string() })
            .unwrap_or_else(|| "absent".into())
    };
    let verus = Command::new("verus").arg("--version").output().ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().find(|l| l.contains("Version:")).map(|l| l.replace("Version:", "").trim().to_string()))
        .unwrap_or_else(|| "absent".into());
    for (kind, name, v) in [
        ("application", "rustc", version("rustc", &["--version"])),
        ("application", "verus", verus),
        ("application", "git", version("git", &["--version"])),
        ("application", "sudo", version("sudo", &["-V"])),
        ("application", "tar", version("tar", &["--version"])),
        ("application", "claude", version("claude", &["--version"])),
        ("application", "codex", version("codex", &["--version"])),
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
