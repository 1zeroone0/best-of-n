//! The bon CLI. Trusted code: it parses arguments, prints, and calls the
//! verified drivers in exec.rs, which make every decision.

use std::path::{Path, PathBuf};
use std::process::Command;

use best_of_n::process;

mod account;
mod host;
mod interrupt;
mod new;
mod projection;
mod route;
mod tui;
mod types;
mod view;

// ── commands ────────────────────────────────────────────

/// Every command: its name, its arguments as the usage writes them, and its
/// one sentence. The usage, each command's `--help`, every argument error and
/// the README's table come from here (a test holds the README to it).
/// Two lines may share a name: `bon spec` reads, `bon spec <queue-id>` searches.
pub(crate) const COMMANDS: [(&str, &str, &str); 18] = [
    ("", "[--since YYYY-MM-DD] [--until YYYY-MM-DD] [--find TEXT]",
        "the view: Project, Spec, Queue, Traces, over that range (piped, plain text); outside every repository, the host: what waits on you across repositories, the pools, memory, each bon process, a journal"),
    ("code", "", "search for code that trunk's checks accept; push it"),
    ("counterexample", "", "look for a behavior on trunk the spec forbids, with tests written blind"),
    ("compaction", "", "remove what is stale, behavior unchanged"),
    ("queue", "", "turn each new transcript into a proposal for the queue"),
    ("background", "[--plist]", "the stalest of compaction and counterexample, on spare capacity; --plist, a launchd job that runs it every five minutes"),
    ("spec", "[NAME]", "the spec's vocabulary and how it reaches the code, or one item"),
    ("spec", "<queue-id>", "a search, so it spends money: agent processes each propose a spec change that states that queue line; nothing is pushed, and it ends in a proposal you read as new words, decisions, reach and scenarios, and apply one of, or none"),
    ("types", "[--check]", "write the types programs are built on, in TypeScript, Go and Python, or fail if one is stale"),
    ("account", "[--check]", "write what is proven, trusted, configured and tested, as OSCAL with its SBOM, or fail if it is stale"),
    ("check", "", "every check on the working tree, as candidates are judged; whose fix a failure is; each file that breaks a rule on what a search may write"),
    ("pending", "[--transcript FILE]", "what only you can answer, oldest first: what happened, the choices and what each costs; outside every repository, the host's; first, each transcript dropped in the user layer's folder goes where the host file routes it"),
    ("new", "<name>", "set up a project: a spec with the core nouns, its gates, an empty implementation, the manifest and the queue"),
    ("init", "", "create a manifest and queue in this git repository"),
    ("setup", "[--dry-run] [--for USER]", "create users agent and check0, check1, … (one per check slot) and group bon, and let USER (default: you) run commands as each; run it as an administrator"),
    ("cost", "", "write .bon/cost.toml, what reaching trunk cost (bon does after each push)"),
    ("view", "[--state | --frame WxH [--tab N] [--focus K] [--light]]", "the view, as bon opens it in a terminal; --state, its projection as JSON; --frame, one frame of it as HTML"),
    ("help", "", "every command, its arguments and what it does"),
];

/// How bon exits, said once, under the usage.
const EXIT: &str = "exit: 0 done; 1 an error (one line on stderr); 2 something pending (bon pending)";

/// The commands that grant capabilities.
const SEARCHES: [&str; 5] = ["code", "compaction", "counterexample", "queue", "background"];

/// A command's head as the usage writes it: `bon account [--check]`.
fn signature(c: &(&str, &str, &str)) -> String {
    ["bon", c.0, c.1].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" ")
}

/// One command's lines of the usage: its signature, and its sentence from
/// column 26, wrapped to 80 columns; a signature too long for the gap puts the
/// sentence on the next line.
fn usage_of(c: &(&str, &str, &str)) -> String {
    const AT: usize = 26;
    let head = format!("  {}", signature(c));
    let mut lines: Vec<String> = Vec::new();
    let mut line = if head.chars().count() < AT - 1 { format!("{head:<AT$}") } else { lines.push(head); " ".repeat(AT) };
    for word in c.2.split_whitespace() {
        if line.chars().count() > AT && line.chars().count() + 1 + word.chars().count() > 80 {
            lines.push(std::mem::replace(&mut line, " ".repeat(AT)));
        }
        if line.chars().count() > AT { line.push(' '); }
        line.push_str(word);
    }
    lines.push(line);
    lines.join("\n")
}

/// The whole usage: every command, then how bon exits.
fn usage() -> String {
    format!("usage:\n{}\n\n{EXIT}", COMMANDS.iter().map(usage_of).collect::<Vec<_>>().join("\n"))
}

/// What a command's arguments are, read from its signature: each `--option`,
/// with the word for its value if it takes one; and each positional word,
/// required when it is not in brackets.
fn grammar(sig: &str) -> (Vec<(String, Option<String>)>, Vec<(String, bool)>) {
    let (mut options, mut words) = (Vec::new(), Vec::new());
    let mut depth = 0;
    let mut tokens: Vec<(String, bool)> = Vec::new();
    for t in sig.split_whitespace() {
        let bracketed = depth > 0 || t.starts_with('[');
        depth += t.matches('[').count() as i32 - t.matches(']').count() as i32;
        let w = t.trim_matches(|c| c == '[' || c == ']');
        if !w.is_empty() && w != "|" { tokens.push((w.to_string(), bracketed)); }
    }
    let mut i = 0;
    while i < tokens.len() {
        let (t, bracketed) = &tokens[i];
        if t.starts_with("--") {
            let value = tokens.get(i + 1).filter(|(n, _)| !n.starts_with("--")).map(|(n, _)| n.clone());
            if value.is_some() { i += 1; }
            options.push((t.clone(), value));
        } else { words.push((t.clone(), !bracketed)); }
        i += 1;
    }
    (options, words)
}

/// A command's arguments, parsed against its signature.
#[derive(Default)]
struct Parsed { options: Vec<(String, Option<String>)>, words: Vec<String> }

impl Parsed {
    fn has(&self, o: &str) -> bool { self.options.iter().any(|(k, _)| k == o) }
    fn value(&self, o: &str) -> Option<String> { self.options.iter().find(|(k, _)| k == o).and_then(|(_, v)| v.clone()) }
}

/// Parse `args` against command `c`'s signature: an option it does not name,
/// a value missing, a word too many or one missing is an error.
fn parse(c: &(&str, &str, &str), args: &[String]) -> Result<Parsed, String> {
    let (options, words) = grammar(c.1);
    // What to do about it: the command's own usage, which fits a line where its signature might not.
    let usage = format!("{} --help shows its usage", signature(&(c.0, "", "")));
    let name = if c.0.is_empty() { "bon" } else { c.0 };
    let mut out = Parsed::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') && a.len() > 1 {
            let Some((o, value)) = options.iter().find(|(o, _)| o == a) else {
                return Err(format!("{a} is not an option of {name}; {usage}"));
            };
            let v = match value {
                // A value is what follows, and it is something: --find "" finds nothing to find.
                Some(word) => { i += 1; Some(args.get(i).filter(|v| !v.starts_with("--") && !v.trim().is_empty()).cloned().ok_or(format!("{o} needs {word}; {usage}"))?) }
                None => None,
            };
            if out.has(o) { return Err(format!("{o} given twice; {usage}")); }
            out.options.push((o.clone(), v));
        } else {
            if out.words.len() == words.len() { return Err(format!("{a} is not an argument of {name}; {usage}")); }
            out.words.push(a.clone());
        }
        i += 1;
    }
    if let Some((w, _)) = words.iter().skip(out.words.len()).find(|(_, required)| *required) { return Err(format!("{name} needs {w}; {usage}")); }
    Ok(out)
}

/// The line of the command table a name and its arguments are: the name's
/// first, but for bon spec with a number, a queue line's id (no spec item's
/// name is a number), its searching line.
fn entry(name: &str, rest: &[String]) -> Option<&'static (&'static str, &'static str, &'static str)> {
    let numbered = name == "spec" && rest.first().is_some_and(|w| w.parse::<u64>().is_ok());
    COMMANDS.iter().filter(|c| c.0 == name).find(|c| (c.1 == "<queue-id>") == numbered)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // The command, and its arguments; bare bon is the command with no name.
    let (name, rest) = match args.first() { Some(a) if !a.starts_with('-') => (a.as_str(), &args[1..]), _ => ("", &args[..]) };
    if name.is_empty() && matches!(rest, [v] if v == "--version" || v == "-V") {
        println!("bon {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let Some(command) = entry(name, rest) else { fail(&format!("unknown command {name}; bon help lists every command")) };
    // Help has no effect: it is answered before anything else is read; a name's every line.
    if rest.iter().any(|a| a == "-h" || a == "--help") || (name == "help" && rest.is_empty()) {
        println!("{}", if name.is_empty() || name == "help" { usage() }
            else { format!("usage:\n{}", COMMANDS.iter().filter(|c| c.0 == name).map(usage_of).collect::<Vec<_>>().join("\n")) });
        return;
    }
    let parsed = parse(command, rest).unwrap_or_else(|e| fail(&e));
    // What the arguments say is refused before anything else is said or read.
    let filter = view::Filter::new(parsed.value("--since").as_deref(), parsed.value("--until").as_deref(), parsed.value("--find")).unwrap_or_else(|e| fail(&e));
    let narrowed = filter.since.is_some() || filter.until.is_some() || filter.find.is_some();
    let root = match git(Path::new("."), &["rev-parse", "--show-toplevel"]) {
        Ok(r) => r,
        // These read no repository: account and types run in a checkout without .git (checks).
        Err(_) if matches!(name, "new" | "setup") || (matches!(name, "account" | "types") && Path::new(".bon/bon.toml").is_file()) => ".".into(),
        // Outside every repository, the view and bon pending show the host: no root.
        // Outside every repository, the view and bon pending show the host: no root; it has one tab, and no range to narrow.
        Err(_) if matches!(name, "" | "view" | "pending") => {
            if narrowed { fail("--since, --until and --find narrow a repository's bon processes; run bon in one"); }
            if parsed.value("--tab").is_some_and(|t| t != "1") { fail("outside every repository the view is the host, one tab; give no --tab"); }
            String::new()
        }
        Err(_) => fail("not in a git repository; run bon in one, or start one with bon new <name>"),
    };
    // What a command reads its settings from: trunk's manifest, or the working tree's.
    let r = Path::new(&root);
    if !root.is_empty() && matches!(name, "" | "view" | "spec" | "pending" | "cost" | "code" | "compaction" | "counterexample" | "queue" | "background") {
        match git(r, &["show", "HEAD:.bon/bon.toml"]) {
            Err(_) if r.join(".bon/bon.toml").is_file() => fail("no .bon/bon.toml at trunk's head: it is not committed; commit .bon/"),
            Err(_) => fail("no .bon/bon.toml at trunk's head; run bon init"),
            Ok(t) => if let Err(e) = toml::from_str::<toml::Value>(&t) {
                fail(&format!(".bon/bon.toml at trunk's head is not TOML ({}); correct it and commit .bon/", e.message()));
            },
        }
    }
    if matches!(name, "account" | "types" | "check") && !r.join(".bon/bon.toml").is_file() { fail("no .bon/bon.toml; run bon init"); }
    // In bon's own repository the installed bon decides with the kernel it was
    // built from; trunk is what the last fetch or push left in the remote's ref.
    let (remote, branch) = best_of_n::trusted::remote_trunk(r);
    let at_trunk = |p: &str| git(r, &["show", &format!("refs/remotes/{remote}/{branch}:{p}")]).ok();
    // Said before a search only, where the kernel decides: other commands' own lines stay one.
    if (SEARCHES.contains(&name) || command.1 == "<queue-id>") && at_trunk("Cargo.toml").is_some_and(|t| t.contains("name = \"best-of-n\"")) {
        let differ = stale(at_trunk);
        if !differ.is_empty() {
            eprintln!("bon: this bon was built from another kernel than trunk's ({}); reinstall: cargo install --path . --locked", differ.join(", "));
        }
    }
    // bon spec reads; bon spec <queue-id> is a search.
    let searching = SEARCHES.contains(&name) || command.1 == "<queue-id>";
    if !searching || (name == "background" && parsed.has("--plist")) {
        if let Err(e) = dispatch(&root, name, &parsed, &filter) { fail(&e) }
        return;
    }
    // Before a search, before anything is reserved: every role it may run
    // starts as agent, and its client reaches its model; or what fixes it.
    let checked = best_of_n::trusted::head(&root).and_then(|h| best_of_n::trusted::manifest(&root, &h))
        .and_then(|m| best_of_n::trusted::programs_executable(&m).and_then(|_| best_of_n::trusted::programs_logged_in(&m)));
    // Trunk is the remote's: what the last fetch or push left in its ref.
    let trunk = || best_of_n::trusted::head(&root).map(|h| h.iter().collect::<String>()).unwrap_or_default();
    let before = trunk();
    // On the user layer's process list until it ends (`end` takes it off).
    best_of_n::trusted::enter(Path::new(&root));
    let result = checked.and_then(|_| dispatch(&root, name, &parsed, &filter));
    // A push or a landed test moved trunk: the cost file follows it, as its own commit.
    if result.is_ok() && trunk() != before {
        if let Err(e) = record_cost(r) { eprintln!("bon: .bon/cost.toml not updated: {e}"); }
    }
    // Only commands that grant capabilities make directories under /tmp/bon, so
    // only they clean up and record how they ended; bon run inside a check
    // (help, account) never touches it.
    best_of_n::trusted::end(r, result)
}

fn dispatch(root: &str, name: &str, a: &Parsed, filter: &view::Filter) -> Result<(), String> {
    let root = root.to_string();
    match name {
        "code" => process::to_push(&root, false).map(|_| println!("pushed")),
        "compaction" => process::to_push(&root, true).map(|_| println!("pushed")),
        "init" => init(&root),
        "new" => new::run(&a.words[0]),
        "counterexample" => counterexample(&root),
        "background" if a.has("--plist") => { plist(&root); Ok(()) }
        "background" => background(&root),
        "view" if a.has("--state") && (a.has("--frame") || a.has("--tab") || a.has("--focus") || a.has("--light")) =>
            Err("--state goes alone; bon view --help shows its usage".into()),
        "view" if a.has("--frame") => {
            let size = a.value("--frame").unwrap_or_default();
            let (w, h) = size.split_once('x').and_then(|(w, h)| Some((w.parse::<u16>().ok()?, h.parse::<u16>().ok()?)))
                .filter(|(w, h)| *w > 0 && *h > 0).ok_or(format!("--frame {size} is not WxH; write it as 120x40"))?;
            let number = |o: &str, of: std::ops::RangeInclusive<usize>, what: &str| -> Result<usize, String> {
                a.value(o).map_or(Ok(*of.start()), |v| v.parse::<usize>().ok().filter(|n| of.contains(n)).ok_or(format!("{o} {v} is not {what}")))
            };
            let tab = number("--tab", 1..=4, "a tab; write 1 to 4")?;
            let focus = number("--focus", 0..=usize::MAX, "a row; write 0 or more")?;
            print!("{}", tui::frame(&root, w, h, tab - 1, focus, a.has("--light"))?);
            Ok(())
        }
        "view" if a.has("--state") && root.is_empty() => { println!("{}", serde_json::to_string_pretty(&host::state(None)).unwrap_or_default()); Ok(()) }
        "view" if a.has("--state") => { println!("{}", serde_json::to_string_pretty(&view::state(Path::new(&root), &view::Filter::default())).unwrap_or_default()); Ok(()) }
        "view" if a.has("--tab") || a.has("--focus") || a.has("--light") => Err("--tab, --focus and --light go with --frame; bon view --help shows its usage".into()),
        "view" => tui::run(&root, view::Filter::default()),
        "queue" => queue(&root),
        // A user's name reaches sudo and dscl: letters, digits, . _ - only.
        "setup" if a.value("--for").is_some_and(|u| !u.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))) =>
            Err(format!("--for {} is no user's name; name a user with letters, digits, . _ or -", a.value("--for").unwrap_or_default())),
        "setup" => setup(a.has("--dry-run"), a.value("--for")),
        "account" => account::run(&root, a.has("--check")),
        "types" => types::run(&root, a.has("--check")),
        "spec" if a.words.first().is_some_and(|w| w.parse::<u64>().is_ok()) => spec_search(&root, a.words[0].parse().unwrap_or(0)),
        "spec" => { print!("{}", tui::spec_text(&root, a.words.first().map(String::as_str), 100)?); Ok(()) }
        "check" => check(&root),
        "pending" => interrupt::run(&root, a.value("--transcript").as_deref()),
        "cost" => { let p = projection::read(Path::new(&root), &view::Filter::default())?; let t = cost_toml(&p);
            std::fs::write(Path::new(&root).join(".bon/cost.toml"), &t).map_err(|e| format!(".bon/cost.toml not written ({e}); make .bon/ writable"))?; print!("{t}"); Ok(()) }
        _ if tui::wanted() => tui::run(&root, filter.clone()),
        _ => status(&root, filter),
    }
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
        || list(manifest.get("account").and_then(|s| s.get("trusted"))).iter().any(under)
}

/// bon check: every check on the working tree, run as a check slot's user in a checkout
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
        return Err(format!("a queue id is reused; renumber from {}, one more than any id the queue has held", next_id(r)));
    }
    let broken = best_of_n::trusted::rules(r, &commit, &m)?;
    if !broken.is_empty() { println!("what a search may write, and how its candidates are judged:"); }
    for b in &broken { println!("  FAIL {b}"); }
    println!("checking the working tree ({}) as a check slot's user, the way candidates are judged", &commit[..8]);
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
    if failed { return Err("checks reject the working tree; each FAIL above says where".into()); }
    println!("every check accepts the working tree");
    if !broken.is_empty() { return Err(format!("the working tree breaks a rule in {} places; each FAIL above names the file and the rule", broken.len())); }
    Ok(())
}

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

/// bon counterexample: if trunk does what the spec forbids, the test that
/// shows it lands on trunk, and trunk's checks reject trunk until bon code.
/// bon spec <queue id>: the spec search for trunk's queue line id.
fn spec_search(root: &str, id: u64) -> Result<(), String> {
    let head: String = best_of_n::trusted::head(root)?.iter().collect();
    let queue = git(Path::new(root), &["show", &format!("{head}:.bon/queue.tsv")]).map_err(|_| "no .bon/queue.tsv at trunk's head")?;
    let intent = queue.lines().find_map(|l| { let (n, rest) = l.split_once('\t')?; (n.parse::<u64>().ok()? == id).then(|| rest.split('\t').next().unwrap_or("").to_string()) })
        .ok_or_else(|| format!("no line {id} in trunk's queue"))?;
    let s = process::spec(root, best_of_n::gates::Intent(intent.chars().collect()))?;
    let m = best_of_n::trusted::manifest(root, &best_of_n::trusted::head(root)?)?;
    let review = best_of_n::trusted::spec_proposal(&m, &s, id, &view::wrap, &view::count)?;
    println!("proposed: read {review}; accept one behavior with the git apply it names, or none");
    Ok(())
}

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
    // Spare capacity: no other bon command running here, by the process list,
    // and load below half the cores.
    let busy = best_of_n::trusted::processes().iter()
        .any(|p| p["repository"].as_str() == Some(root) && p["pid"].as_u64() != Some(u64::from(std::process::id())));
    if busy { println!("busy: a bon command is running here"); return Ok(()); }
    let half = std::thread::available_parallelism().map_or(1.0, |n| (n.get() / 2).max(1) as f64);
    let load: f64 = Command::new("sysctl").args(["-n", "vm.loadavg"]).output().ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0.0);
    if load >= half { println!("busy: load {load:.1} is at or above half the cores, {half}"); return Ok(()); }
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

/// An error, in one line on stderr, and exit 1.
fn fail(e: &str) -> ! {
    eprintln!("bon: {}", e.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; "));
    std::process::exit(1)
}

/// A git command's output; or, failing, what bon ran and git's first line.
fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git").args(args).current_dir(root).output().map_err(|e| format!("git {}: {e}", args[0]))?;
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git {}: {}", args[0], said.lines().find(|l| !l.trim().is_empty()).unwrap_or("failed").trim().trim_start_matches("fatal: ")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Start a repository with a manifest that cannot run a search yet.
fn init(root: &str) -> Result<(), String> {
    use std::io::Write;
    let r = Path::new(root);
    let bon = r.join(".bon");
    if std::fs::symlink_metadata(&bon).is_ok() && !bon.is_dir() {
        return Err(".bon exists and is not a directory; move it aside".into());
    }
    for file in ["bon.toml", "queue.tsv"] {
        if std::fs::symlink_metadata(bon.join(file)).is_ok() {
            return Err(format!(".bon/{file} already exists, so nothing is written; configure it, or move it aside and run bon init again"));
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
        toml::Value::String(trunk.into()), toml::Value::String(remote.into()), INIT_TEMPLATE, init_account(r));
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
# Seconds a check may run before it is stopped.
time = 1800

# Each search kind's role, and its width list: attempt a runs n[a] agent
# processes. The host file's [roles] say what each role runs (its program,
# client and model). Replace with the roles your host file names.
[searches]
code = { role = "REPLACE_ME", n = [1] }
compaction = { role = "REPLACE_ME", n = [1] }
queue = { role = "REPLACE_ME", n = [1] }
counterexample = { role = "REPLACE_ME", n = [1] }
foil = { role = "REPLACE_ME", n = [1] }

[counterexample]
# Replace with the test path, build/run commands and test paths on trunk.
path = "tests/counterexample.rs"
build = "false"
run = "false"
tests = ["tests/"]
# Spec and interface paths an agent process sees; empty means everything.
visible = []

"#;

/// The manifest's [account], guessed from the repository for the owner to confirm:
/// its name, the tracked files that mark trusted code (`#[verifier::external*]`),
/// and a version command per toolchain whose lockfile is at the root.
fn init_account(r: &Path) -> String {
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
    format!("\n# The account bon account keeps, guessed by bon init: confirm it.\n\
             # trusted: files of trusted code; tools: the TCB's tools and their version commands.\n\
             # A claimed control: [account.controls.<id>] with a claim, and its evidence by status\n\
             # (proven, trusted, configured, tested); catalog names the catalog the ids are from.\n\
             [account]\nname = {}\ntrusted = {}\ntools = {{ {inline} }}\n",
            toml::Value::String(name), toml::Value::Array(trusted))
}

/// What is running, what was pushed, and the queue: the projection bon view
/// draws, printed.
fn status(root: &str, filter: &view::Filter) -> Result<(), String> {
    // Outside every repository: the host.
    if root.is_empty() { print!("{}", host::text(&host::state(None))); return Ok(()); }
    print!("{}", view::text(&view::state(Path::new(root), filter)));
    Ok(())
}

/// Each transcript not yet cited by a commit on trunk becomes a proposal: a
/// patch adding its agreed intents to the queue, each with the next id the
/// queue has never used. engineer decides by applying it, editing it, or not.
fn queue(root: &str) -> Result<(), String> {
    let r = Path::new(root);
    let config: toml::Value = toml::from_str(&git(r, &["show", "HEAD:.bon/bon.toml"])
        .map_err(|_| "no .bon/bon.toml at trunk's head; run bon init")?).map_err(|e| format!(".bon/bon.toml at trunk's head: {e}"))?;
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

/// Create user agent, a user per check slot (`check0`, `check1`, …, as many
/// as the host's check_processes) and group bon, put engineer, agent and
/// each slot's user in bon, let engineer run commands as agent and as each
/// slot's user (never as root) with no password, install the toolchain
/// checks judge with under /opt/bon, its dependency sources engineer's, and
/// write the host file. Each step runs with sudo and is printed first.
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
    // Each check slot's user: a check that holds slot k runs as check<k>, so it
    // writes only its own build directory. Hidden, never logged in to, its home
    // one it cannot write, its primary group bon (it reads what bon makes for
    // the checks); as many as the host's check_processes, or as many as it may
    // come to by default on this machine.
    let slots = best_of_n::trusted::check_slots();
    for k in 0..slots {
        let u = format!("check{k}");
        if !exists("Users", &u) {
            let out = Command::new("openssl").args(["rand", "-base64", "32"]).output().map_err(|e| e.to_string())?;
            let password = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if password.len() < 40 { return Err("could not make a password".into()); }
            steps.push(vec!["sysadminctl".into(), "-addUser".into(), u.clone(), "-fullName".into(), format!("bon check {k}"),
                            "-shell".into(), "/bin/zsh".into(), "-home".into(), "/var/empty".into(), "-password".into(), password]);
            steps.push(s(&["dscl", ".", "create", &format!("/Users/{u}"), "IsHidden", "1"]));
        }
        steps.push(vec!["sh".into(), "-c".into(), format!("dscl . -create /Users/{u} PrimaryGroupID \"$(dscl . -read /Groups/bon PrimaryGroupID | awk '{{print $2}}')\"")]);
        steps.push(s(&["dseditgroup", "-o", "edit", "-a", &u, "-t", "user", "bon"]));
    }
    steps.push(s(&["dseditgroup", "-o", "edit", "-a", &me, "-t", "user", "bon"]));
    let runs_as: Vec<String> = std::iter::once("agent".to_string()).chain((0..slots).map(|k| format!("check{k}"))).collect();
    steps.push(vec!["sh".into(), "-c".into(), format!(
        "f=$(mktemp) && printf '%s ALL=(%s) NOPASSWD: ALL\\n' {me} '{}' > \"$f\" && visudo -cf \"$f\" && install -m 0440 -o root -g wheel \"$f\" /etc/sudoers.d/bon; r=$?; rm -f \"$f\"; exit $r",
        runs_as.join(", "))]);
    // The directory holding every working directory: the owner's, mode 0711, so
    // agent may pass through to a path it was given but not list or add to it.
    // bon remakes it after a reboot clears /tmp.
    steps.push(vec!["sh".into(), "-c".into(), format!(
        "mkdir -p {d} && chown {me} {d} && chmod 0711 {d}", d = best_of_n::trusted::WORKING_DIRECTORIES)]);
    // The toolchain checks judge with, where no agent process and no check can
    // write it: a copy of the one this user runs (rustup's home, cargo's
    // proxies, Verus), root's all the way up, with a cargo home whose root is
    // root's and whose dependency sources are this user's.
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
             chown -R root:wheel /opt/bon; chmod -R go-w,a+rX /opt/bon")]);
    }
    // The dependency sources the checks compile, and cargo's caches and locks
    // beside them: this user's, writable by no one else, so no agent process
    // and no check changes what a check compiles. Cargo writes nothing there to
    // build from sources already unpacked: they are fetched as this user.
    steps.push(vec!["sh".into(), "-c".into(), format!(
        "set -e; c=/opt/bon/cargo-home; for p in $c/registry $c/git $c/.global-cache $c/.package-cache $c/.package-cache-mutate; do [ -e $p ] && chown -R {me}:bon $p; done; \
         chmod -R go-w,a+rX $c/registry $c/git")]);
    // The host file: written once, then edited by hand (with sudo) as models and
    // prices change. Its user layer is the directory holding the repository
    // setup runs in (`user`): edit it to name another.
    if !std::path::Path::new(best_of_n::trusted::HOST).exists() {
        let draft = std::env::temp_dir().join(format!("bon-host-{}.toml", std::process::id()));
        let layer = std::fs::canonicalize(".").ok().and_then(|d| d.parent().map(Path::to_path_buf))
            .ok_or("the user layer: run bon setup in a repository, whose directory's parent is the user layer's root")?;
        if !dry_run { std::fs::write(&draft, HOST_TEMPLATE.replace("@USER@", &layer.to_string_lossy())).map_err(|e| e.to_string())?; }
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
    println!("Then log the clients your roles name in as agent: sudo -u agent -i claude, and sudo -u agent -i codex login");
    println!("A repository's dependencies are fetched as {me}, never by a check: in it, CARGO_HOME=/opt/bon/cargo-home cargo fetch");
    Ok(())
}

/// The host file `bon setup` writes: where agent's tools live, what each role
/// runs, and the prices of the models in use. Traces record the prices they
/// were costed at.
const HOST_TEMPLATE: &str = r#"# bon's host file: facts about this host, not about any repository.
# Owned by root; edit with sudo. Every trace records the prices it was costed at.

# Two pools, each shared by every bon process on this host; width per search
# stays what each repository's bon.toml says. agent_processes: agent
# processes at once (default 64; one mostly waits on its model).
# check_processes: commands at once, the judge's checks and every cargo an
# agent process runs. A check slot is a share of memory: by default as many
# checks run as free memory holds at 1.5 GB each, and no more than 2 threads
# per core among them, since a check computes only part of its time (it also
# starts processes, links, writes files, and on macOS waits while the system
# scans each new binary); the cores are shared among the checks that compute,
# not divided. check_threads: threads one check may use (default 2). Each
# check runs as its slot's user, check0, check1, …: bon setup makes as many
# as check_processes. Another host file (a benchmark's, sized as another
# machine) is named by BON_HOST: it must be writable by its owner alone, root
# or the user bon runs as.
# agent_processes = 64
# check_processes = 14
# check_threads = 2

# The user layer's root, between this host and its repositories: bon's state
# that outlives a bon process (the verdict cache, the process list) is in its
# .bon, engineer's alone. `bon` outside every repository shows the host: the
# repositories under this root with a .bon/bon.toml, and any a bon process
# searches.
user = "@USER@"

# PATH for agent processes and checks. Nothing else is inherited. Checks drop
# every entry under agent's home: they run only what no agent process can write.
path = ["/opt/bon/cargo/bin", "/opt/bon/verus", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/Users/agent/.local/bin"]

# The toolchain checks judge with, installed by bon setup: root's all the way up.
rustup_home = "/opt/bon/rustup"
cargo_home = "/opt/bon/cargo-home"

# Where a transcript dropped in the user layer's folder (<user>/transcripts)
# goes: a pattern of its meeting title (its WebVTT header's text, else its
# file name), and the repository, its path under the user layer's root or
# absolute. A title matches a pattern it contains, ignoring case; a transcript
# goes where its matching routes name one repository, into that repository's
# transcripts directory (moved, not committed), when bon pending runs. One no
# route names, or whose routes name two repositories, stays in the folder,
# pending, until a route names it or you move it.
[routes]
# "Acme" = "acme"
# "weekly sync" = "bon"

# What each role a repository's [searches] names runs. program: the argv, run
# as agent in the working directory with the prompt on its stdin; bon appends
# `--model <model>`. client: how it reaches its model: claude or codex (that
# CLI, logged in as agent: sudo -u agent -i claude, sudo -u agent -i codex
# login), or api (the Messages API, [api] below). model: the canonical id,
# which keys [prices]. context: the largest prompt, in tokens, the program
# may send: a one-shot program (bon-sample) assembles no more context than
# that (the files the task names first, the rest dropped to fit); bon gives
# it as BON_CONTEXT. Of the agentic CLIs, claude offers a compaction
# threshold (--autocompact, 100k-1M tokens) in its argv; codex exec offers
# none. A role with no client and no model reaches none: a stub, which costs
# nothing.
[roles.wide]
program = ["codex", "exec", "--json", "--ephemeral", "--ignore-rules", "--skip-git-repo-check", "--sandbox", "workspace-write", "--add-dir", "/tmp/bon", "--color", "never"]
client = "codex"
model = "gpt-6.1-sol"

[roles.deep]
program = ["claude", "-p", "--output-format", "stream-json", "--verbose", "--setting-sources", "", "--strict-mcp-config", "--no-session-persistence", "--permission-mode", "bypassPermissions", "--max-budget-usd", "5"]
client = "claude"
model = "claude-opus-5-5"

# A one-shot program: bon-sample makes one model call, through its client.
# [roles.one-shot]
# program = ["/Users/agent/.local/bin/bon-sample"]
# client = "api"
# model = "claude-haiku-5-5"
# context = 80000

# The Messages API, for a role whose client is api: where it is, and the file
# holding its key, which agent reads.
# [api]
# address = "https://api.anthropic.com"
# key_file = "/Users/agent/.config/bon/anthropic.key"

# Dollars per million tokens, API list prices, by canonical model id. Keep only
# the models in use. cache_write is the shorter TTL (Claude 5m, OpenAI 30m),
# cache_write_long the longer (Claude 1h, OpenAI 12h). As of 2026-11-03.
#
# A model whose provider bills a large prompt at a higher rate takes a tier,
# which is per prompt, each request on its own:
#   tier = { above = <prompt tokens>, multiplier = <x>, output_multiplier = <x> }
# A request whose prompt (input, cache reads and cache writes together) is over
# `above` tokens is billed `multiplier` times every input-side price and
# `output_multiplier` (default 1) times output. Each agent process's trace
# records how many of its requests were over (`requests_over_tier`). Copy both from the provider's
# price list; without a tier, every request is billed at the one rate. bon
# applies it per request where the program says what each request was (Claude's
# events, bon-sample); codex's running total cannot say, so it never applies there.
[prices]
"claude-haiku-5-5" = { input = 0.10, cached_input = 0.01, output = 0.50, cache_write = 0.125, cache_write_long = 0.20, tier = { above = 100000, multiplier = 5, output_multiplier = 5 } }
"claude-opus-5-5" = { input = 4.00, cached_input = 0.20, output = 20.00, cache_write = 5.00, cache_write_long = 8.00 }
"gpt-6.1-sol" = { input = 2.00, cached_input = 0.10, output = 10.00, cache_write = 2.50, cache_write_long = 5.00 }
"#;


#[cfg(test)]
mod tests {
    use super::*;
    use best_of_n::trusted::{rules, holes, skips, PROVEN_OR_CHECKED, NO_CHECK_WRITABLE, NOT_JUDGED};

    #[test]

    #[test]
    fn the_readmes_command_table_is_the_usage_word_for_word() {
        let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
        // Each row: `signature` | sentence, a pipe in code written \|.
        let rows: Vec<(String, String)> = readme.lines().filter(|l| l.starts_with("| `bon")).map(|l| {
            let (code, rest) = l[3..].split_once("` | ").unwrap();
            (code.replace("\\|", "|"), rest.trim_end_matches(" |").to_string())
        }).collect();
        let table: Vec<(String, String)> = COMMANDS.iter().map(|c| (signature(c), c.2.to_string())).collect();
        assert_eq!(rows, table);
        assert!(readme.contains(EXIT), "the README says how bon exits, as the usage does");
        // Every line of the usage fits 80 columns, and each command starts one line of it.
        let text = usage();
        assert!(text.lines().all(|l| l.chars().count() <= 80), "{text}");
        for c in COMMANDS { assert_eq!(text.lines().filter(|l| l.starts_with(&format!("  {}", signature(&c))) && l[2 + signature(&c).len()..].starts_with([' ', '\n']) || *l == format!("  {}", signature(&c))).count(), 1, "{}", c.0); }
    }

    #[test]
    fn a_commands_arguments_are_read_from_its_signature_and_nothing_else_is_taken() {
        let c = |n: &str| *COMMANDS.iter().find(|c| c.0 == n).unwrap();
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let ok = parse(&c(""), &args(&["--since", "2026-11-01", "--find", "Code"])).unwrap();
        assert_eq!((ok.value("--since").as_deref(), ok.value("--find").as_deref(), ok.has("--until")), (Some("2026-11-01"), Some("Code"), false));
        // An unknown option, a value missing, a word too many, a word missing, an option twice: each an error that says the usage.
        assert_eq!(parse(&c(""), &args(&["--version", "x"])).err().unwrap(), "--version is not an option of bon; bon --help shows its usage");
        assert_eq!(parse(&c(""), &args(&["--since"])).err().unwrap(), "--since needs YYYY-MM-DD; bon --help shows its usage");
        assert_eq!(parse(&c("code"), &args(&["now"])).err().unwrap(), "now is not an argument of code; bon code --help shows its usage");
        assert_eq!(parse(&c("new"), &[]).err().unwrap(), "new needs <name>; bon new --help shows its usage");
        assert!(parse(&c("help"), &args(&["code"])).is_err());
        assert!(parse(&c("account"), &args(&["--check", "--check"])).is_err());
        assert!(parse(&c("account"), &args(&["--bogus"])).err().unwrap().starts_with("--bogus is not an option of account;"));
        // Optional words, and an option's value that is another option.
        assert_eq!(parse(&c("spec"), &args(&["verified"])).unwrap().words, ["verified"]);
        assert!(parse(&c("spec"), &[]).is_ok());
        assert!(parse(&c("pending"), &args(&["--transcript", "--x"])).is_err());
        let v = parse(&c("view"), &args(&["--frame", "80x24", "--tab", "2", "--light"])).unwrap();
        assert_eq!((v.value("--frame").as_deref(), v.value("--tab").as_deref(), v.has("--light"), v.has("--state")), (Some("80x24"), Some("2"), true, false));
        assert_eq!(grammar("[--dry-run] [--for USER]"), (vec![("--dry-run".into(), None), ("--for".into(), Some("USER".into()))], vec![]));
        assert_eq!(grammar("<name>").1, vec![("<name>".to_string(), true)]);
    }

    #[test]
    fn an_error_is_one_line_and_says_what_git_was_asked() {
        let e = git(Path::new("/"), &["rev-parse", "--show-toplevel"]).unwrap_err();
        assert!(e.starts_with("git rev-parse: ") && !e.contains('\n') && !e.contains("fatal:"), "{e}");
    }

    #[test]
    fn bon_check_names_each_file_that_breaks_a_rule_on_what_a_search_may_write() {
        // queue 67, 68, 69: read from the tree, the manifest and the kernel's authority.
        let d = std::env::temp_dir().join(format!("bon-rules-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let manifest = r#"
            limit = 1.0
            rate = 0
            agent_process = { limit = 0.5, time = 60 }
            checks = { paths = ["src/spec.rs", "tests/engineer.rs"], test = ["cargo test -q", "sh scripts/check.sh", "cargo run -q -- lint"], verify = ["true"], time = 60 }
            counterexample = { path = "tests/counterexample.rs", build = "cargo test --no-run --test counterexample", run = "cargo test --test counterexample", tests = ["tests/counterexample"] }
            account = { trusted = ["src/main.rs"] }
            [searches]
            code = { role = "r", n = [1] }
            compaction = { role = "r", n = [1] }
            queue = { role = "r", n = [1] }
            counterexample = { role = "r", n = [1] }
            foil = { role = "r", n = [1] }
        "#;
        let files: &[(&str, &str)] = &[
            (".bon/bon.toml", manifest),
            ("Cargo.toml", "[package]\nname = \"k\"\ndefault-run = \"k\"\n[[bin]]\nname = \"k\"\npath = \"src/main.rs\"\n"),
            ("src/lib.rs", "//! k\npub mod spec;\npub mod exec;\n"),
            ("src/spec.rs", "verus! { pub open spec fn s() -> bool { true } }\n#[cfg(test)]\nmod t {}\n"),
            ("src/exec.rs", "use vstd::prelude::*;\nverus! {\nfn a() {}\nmod inner;\n}\n#[allow(dead_code)]\npub fn plain() -> bool { true }\nimpl X {}\n"),
            ("src/exec/inner.rs", "fn unproven() {}\n"),
            ("src/main.rs", "mod view;\nfn main() {}\n#[test]\nfn t() {}\n"),
            ("src/view.rs", "pub fn v() {}\n"),
            ("src/bin/tool.rs", "fn main() {}\n#[cfg(test)]\nmod tests { #[test] fn t() {} }\n"),
            ("tests/counterexample_1.rs", "#[test]\nfn landed() {}\n"),
            ("tests/engineer.rs", "#[test]\nfn mine() {}\n"),
            ("scripts/check.sh", "exit 0\n"),
            ("README.md", "k\n"),
            ("crates/m/Cargo.toml", "[package]\nname = \"m\"\n[lib]\nproc-macro = true\n"),
            ("crates/b/Cargo.toml", "[package]\nname = \"b\"\n"),
            ("crates/b/build.rs", "fn main() {}\n"),
        ];
        for (p, text) in files {
            std::fs::create_dir_all(d.join(p).parent().unwrap()).unwrap();
            std::fs::write(d.join(p), text).unwrap();
        }
        git(&d, &["init", "-q"]).unwrap();
        git(&d, &["add", "-A"]).unwrap();
        git(&d, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "k"]).unwrap();
        let commit = git(&d, &["rev-parse", "HEAD"]).unwrap();
        let m = best_of_n::trusted::Manifest { config: toml::from_str(manifest).unwrap(), root: d.clone() };
        let broken = rules(&d, &commit, &m).unwrap();
        // Each line: where, then the rule it breaks.
        let found: Vec<(&str, &str)> = broken.iter().map(|b| {
            let rule = [PROVEN_OR_CHECKED, NO_CHECK_WRITABLE, NOT_JUDGED].into_iter().find(|r| b.ends_with(&format!("({r})"))).unwrap();
            (b.split(": ").next().unwrap(), rule)
        }).collect();
        assert_eq!(found, [
            ("crates/b/Cargo.toml", NOT_JUDGED), ("crates/m/Cargo.toml", NOT_JUDGED),
            ("scripts/check.sh", NO_CHECK_WRITABLE),
            ("Cargo.toml", PROVEN_OR_CHECKED), ("README.md", PROVEN_OR_CHECKED), ("crates/b/Cargo.toml", PROVEN_OR_CHECKED),
            ("crates/b/build.rs", PROVEN_OR_CHECKED), ("crates/m/Cargo.toml", PROVEN_OR_CHECKED),
            ("src/bin/tool.rs:2", NOT_JUDGED),
            ("src/exec.rs:7", NOT_JUDGED), ("src/exec.rs:8", NOT_JUDGED), ("src/exec/inner.rs:1", NOT_JUDGED),
        ], "{broken:#?}");
        // Not broken: the protected spec's and trusted main's tests, the landed and engineer's tests, the program's code.
        assert!(broken[1].starts_with("crates/m/Cargo.toml: a local crate that is a proc macro"));
        let _ = std::fs::remove_dir_all(&d);
    }

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
    fn bon_setup_writes_a_host_file_bon_reads() {
        // queue 53, 54: the template is the new shape, its roles those bon's own manifest names.
        assert_eq!(best_of_n::trusted::host_shape(HOST_TEMPLATE), Ok(()));
        let host: toml::Value = toml::from_str(HOST_TEMPLATE).unwrap();
        // queue 56: one key names the user layer's root; setup fills it in.
        assert_eq!(host["user"].as_str(), Some("@USER@"));
        assert!(host["roles"].get("wide").is_some() && host["roles"].get("deep").is_some());
        assert_eq!(host["prices"]["claude-haiku-5-5"]["tier"]["above"].as_integer(), Some(100_000));
        // queue 80: the routes are a table of the host's own, empty until the owner names one; every top-level key stays top-level.
        assert!(host["routes"].as_table().is_some_and(|r| r.is_empty()) && host.get("path").is_some() && host["routes"].get("path").is_none());
        let routed = HOST_TEMPLATE.replace("# \"Acme\" = \"acme\"", "\"Acme\" = \"acme\"");
        assert_eq!(best_of_n::trusted::host_shape(&routed), Ok(()));
        assert_eq!(toml::from_str::<toml::Value>(&routed).unwrap()["routes"]["Acme"].as_str(), Some("acme"));
        // The old shape is refused, naming what replaced it.
        assert!(best_of_n::trusted::host_shape("generation = 8\npath = []").unwrap_err().contains("agent_processes"));
        // queue 56, 58: the verdict cache's place and cleanup are no host keys now.
        assert!(best_of_n::trusted::host_shape("verdicts = \"/v\"\npath = []").unwrap_err().contains("user"));
        assert!(best_of_n::trusted::host_shape("cleanup = \"own\"\npath = []").unwrap_err().contains("process list"));
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
        let manifest: toml::Value = toml::from_str("[checks]\npaths = [\"src/spec.rs\"]\n[account]\ntrusted = [\"src/main.rs\", \"src/view.rs\"]").unwrap();
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
        assert!(best_of_n::trusted::persist(&work).unwrap_err().contains("private"));
        assert!(!work.join(".bon/traces/.git").exists());
        // A private remote of its own gets the traces, and not the running marker.
        std::fs::write(work.join(".bon/bon.toml"), format!("traces = {:?}\n", private.to_str().unwrap())).unwrap();
        best_of_n::trusted::persist(&work).unwrap();
        let files = git(&private, &["ls-tree", "-r", "--name-only", "main"]).unwrap();
        assert_eq!(files, ".gitignore\n123/transitions");
        // Nothing new: no commit.
        best_of_n::trusted::persist(&work).unwrap();
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
