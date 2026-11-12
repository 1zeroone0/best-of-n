//! bon-sample: an agent process that is one sample. Context in, edits out:
//! it reads the task on stdin, sends the working directory's files and the task
//! to a model in one request, applies the edit blocks of the one reply, and
//! prints the reply and a usage line. bon does all the checking.
//!
//! usage: bon-sample --via api|claude|codex --model <id>
//!                   [--max-context-bytes N] [--max-file-bytes N] [--max-output-tokens N] [--effort LEVEL]
//!
//! Environment: BON_ANTHROPIC_KEY_FILE (default /Users/agent/.config/bon/anthropic.key),
//! BON_ANTHROPIC_BASE_URL (default https://api.anthropic.com), and, for tests,
//! BON_SAMPLE_CLAUDE / BON_SAMPLE_CODEX (the program to run for those transports).
//!
//! Unverified edge code, like the harness CLIs it stands in for: what it
//! writes is judged by bon's checks, never trusted.

// Nothing here is verified, but `cargo verus verify` builds every target of
// the package, and Verus refuses a crate that does not import its builtins.
#[allow(unused_imports)]
use vstd::prelude::*;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const USAGE: &str = "usage: bon-sample --via api|claude|codex --model <id> [--max-context-bytes N] [--max-file-bytes N] [--max-output-tokens N] [--effort LEVEL]";
const API_VERSION: &str = "2026-10-21";
const DEFAULT_KEY_FILE: &str = "/Users/agent/.config/bon/anthropic.key";
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// Under 100k tokens of code (about 2.4 bytes a token, measured on this
/// repository): past that, Haiku 5.5's input price steps up fivefold.
const DEFAULT_CONTEXT_BYTES: usize = 220_000;
const DEFAULT_FILE_BYTES: usize = 160_000;
const DEFAULT_OUTPUT_TOKENS: u64 = 16_000;
/// Where codex runs: empty, and the same for every sample.
const CODEX_DIR: &str = "/var/empty";
/// Directories never sent: build output, dependencies, version control.
const SKIP_DIRS: [&str; 6] = [".git", "target", "node_modules", ".venv", "__pycache__", ".cargo"];
const LOCKFILES: [&str; 10] = ["Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum",
                               "poetry.lock", "uv.lock", "Gemfile.lock", "composer.lock", "flake.lock"];

/// The output format, first in the stable prefix.
const INSTRUCTIONS: &str = "You are one sample among many. You see a repository's files and a task, and you reply once, \
with edits. You cannot run commands, open other files or ask questions: whatever the task says about reading or \
running the checks, they run on your edits after you reply.

Reply with edit blocks in exactly this format, and after them one line saying what you changed:

@@@ FILE <path relative to the repository root>
@@@ SEARCH
<lines copied exactly from the file as shown, enough of them to occur exactly once>
@@@ REPLACE
<the lines that take their place>
@@@ END

- SEARCH must match the file byte for byte, whitespace included, and occur exactly once in it.
- An empty SEARCH writes the whole file: it creates a new file, or replaces an existing one with exactly the REPLACE text.
- Several blocks may name one file; they apply in order, each to the result of the one before.
- If any block does not apply, none does, and the sample counts for nothing.
- Paths are relative, never absolute, and never contain `..`.
- Marker lines start with `@@@ ` at the start of a line. Do not put the blocks in code fences.
- Keep each SEARCH short: a few lines around the change.
";

#[derive(Debug, Clone, Copy, PartialEq)]
enum Via { Api, Claude, Codex }

#[derive(Debug)]
struct Args { via: Via, model: String, max_context: usize, max_file: usize, max_output: u64, effort: Option<String> }

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args { via: Via::Api, model: String::new(), max_context: DEFAULT_CONTEXT_BYTES, max_file: DEFAULT_FILE_BYTES,
                       max_output: DEFAULT_OUTPUT_TOKENS, effort: None };
    let mut via = None;
    let mut it = argv.iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().cloned().ok_or(format!("{flag} needs a value"));
        let number = |v: String| v.parse::<u64>().map_err(|_| format!("{flag}: not a number: {v}"));
        match flag.as_str() {
            "--via" => via = Some(match value()?.as_str() {
                "api" => Via::Api, "claude" => Via::Claude, "codex" => Via::Codex,
                v => return Err(format!("--via: unknown transport {v}")),
            }),
            "--model" => a.model = value()?,
            "--max-context-bytes" => a.max_context = number(value()?)? as usize,
            "--max-file-bytes" => a.max_file = number(value()?)? as usize,
            "--max-output-tokens" => a.max_output = number(value()?)?,
            "--effort" => a.effort = Some(value()?),
            "-h" | "--help" => return Err(USAGE.into()),
            f => return Err(format!("unknown argument {f}\n{USAGE}")),
        }
    }
    a.via = via.ok_or(format!("--via is required\n{USAGE}"))?;
    if a.model.is_empty() { return Err(format!("--model is required\n{USAGE}")); }
    Ok(a)
}

// ── context ─────────────────────────────────────────────

/// The request's stable part: the format, then the files. A function of the
/// tree and the paths the task names, so the N samples of a search send it
/// byte for byte the same.
#[derive(Debug, PartialEq)]
struct Context { repository: String, included: Vec<String>, omitted: Vec<(String, &'static str)> }

/// Every file under `root`, relative, '/'-separated, sorted by bytes. Symlinks
/// and the skipped directories are not followed.
fn tree(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(t) = e.file_type() else { continue };
            let path = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            if t.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) { walk(&e.path(), &path, out); }
            } else if t.is_file() {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out.sort();
    out
}

/// The files the task names (a file, or a directory's files), in the order the
/// task first names them. Only path-like tokens count, with a `/` or a `.`, so
/// a word such as "checks" does not pull in a directory of that name.
fn named(prompt: &str, files: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let path_char = |c: char| c.is_ascii_alphanumeric() || "_./-".contains(c);
    for token in prompt.split(|c: char| !path_char(c)) {
        let t = token.trim_start_matches("./").trim_end_matches('.');
        if t.is_empty() || !t.contains(['/', '.']) { continue; }
        let dir = format!("{}/", t.trim_end_matches('/'));
        for f in files {
            if (f == t || f.starts_with(&dir)) && !out.contains(f) { out.push(f.clone()); }
        }
    }
    out
}

fn context(root: &Path, prompt: &str, max_context: usize, max_file: usize) -> Context {
    let files = tree(root);
    let first = named(prompt, &files);
    let order = first.iter().chain(files.iter().filter(|f| !first.contains(f)));
    let (mut included, mut omitted, mut body, mut total) = (Vec::new(), Vec::new(), String::new(), 0usize);
    for f in order {
        let name = f.rsplit('/').next().unwrap_or(f);
        if LOCKFILES.contains(&name) { omitted.push((f.clone(), "lockfile")); continue; }
        let size = std::fs::metadata(root.join(f)).map(|m| m.len() as usize).unwrap_or(usize::MAX);
        if size > max_file { omitted.push((f.clone(), "over the per-file cap")); continue; }
        let Ok(bytes) = std::fs::read(root.join(f)) else { omitted.push((f.clone(), "unreadable")); continue };
        let Ok(text) = String::from_utf8(bytes) else { omitted.push((f.clone(), "binary")); continue };
        if text.contains('\0') { omitted.push((f.clone(), "binary")); continue; }
        if total + text.len() > max_context { omitted.push((f.clone(), "over the context budget")); continue; }
        total += text.len();
        body.push_str(&format!("<file path=\"{f}\">\n{text}{}</file>\n", if text.ends_with('\n') || text.is_empty() { "" } else { "\n" }));
        included.push(f.clone());
    }
    let mut repository = format!("<repository>\nThe working directory's files, each in full ({} shown, {total} bytes).\n{body}", included.len());
    if !omitted.is_empty() {
        repository.push_str("Files not shown: ");
        repository.push_str(&omitted.iter().map(|(f, why)| format!("{f} ({why})")).collect::<Vec<_>>().join(", "));
        repository.push('\n');
    }
    repository.push_str("</repository>\n");
    Context { repository, included, omitted }
}

// ── edits ───────────────────────────────────────────────

#[derive(Debug, PartialEq)]
struct Edit { path: String, search: String, replace: String }

/// The edit blocks of a reply. Text outside blocks is ignored; a block left
/// open or out of order is an error.
fn parse(reply: &str) -> Result<Vec<Edit>, String> {
    #[derive(PartialEq)]
    enum At { Outside, Search, Replace }
    let mut at = At::Outside;
    let mut edits = Vec::new();
    let (mut path, mut search, mut replace) = (String::new(), String::new(), String::new());
    for (n, line) in reply.split_inclusive('\n').enumerate() {
        let marker = line.trim_end_matches(['\n', '\r']);
        let n = n + 1;
        match (&at, marker) {
            (At::Outside, m) if m.starts_with("@@@ FILE ") => {
                path = m["@@@ FILE ".len()..].trim().to_string();
                if path.is_empty() { return Err(format!("line {n}: FILE without a path")); }
            }
            (At::Outside, "@@@ SEARCH") if !path.is_empty() => { at = At::Search; search.clear(); }
            (At::Search, "@@@ REPLACE") => { at = At::Replace; replace.clear(); }
            (At::Replace, "@@@ END") => {
                edits.push(Edit { path: std::mem::take(&mut path), search: std::mem::take(&mut search), replace: std::mem::take(&mut replace) });
                at = At::Outside;
            }
            (_, m) if m.starts_with("@@@ FILE ") || ["@@@ SEARCH", "@@@ REPLACE", "@@@ END"].contains(&m) => {
                return Err(format!("line {n}: {m} out of order"));
            }
            (At::Search, _) => search.push_str(line),
            (At::Replace, _) => replace.push_str(line),
            (At::Outside, _) => {}
        }
    }
    if at != At::Outside { return Err("the reply ends inside an edit block".into()); }
    if edits.is_empty() { return Err("the reply has no edit blocks".into()); }
    Ok(edits)
}

/// A path the reply may write: relative, plain components only, and no
/// symlink on the way (none could lead out of the working directory).
fn checked(root: &Path, path: &str) -> Result<PathBuf, String> {
    let p = Path::new(path);
    if path.contains('\0') || path.contains('\\') { return Err(format!("{path}: refused")); }
    if p.is_absolute() { return Err(format!("{path}: absolute paths are refused")); }
    let mut at = root.to_path_buf();
    for c in p.components() {
        match c {
            Component::Normal(s) => {
                at.push(s);
                if std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink()) {
                    return Err(format!("{path}: refused, it passes through a symlink"));
                }
            }
            Component::ParentDir => return Err(format!("{path}: paths with .. are refused")),
            _ => return Err(format!("{path}: refused")),
        }
    }
    if at == root { return Err(format!("{path}: refused")); }
    if at.is_dir() { return Err(format!("{path}: is a directory")); }
    Ok(at)
}

/// Apply every edit or none. Returns the paths written.
fn apply(root: &Path, edits: &[Edit]) -> Result<Vec<String>, String> {
    let mut files: BTreeMap<String, (PathBuf, Option<String>, String)> = BTreeMap::new();
    for (i, e) in edits.iter().enumerate() {
        let block = i + 1;
        if !files.contains_key(&e.path) {
            let full = checked(root, &e.path)?;
            let old = match std::fs::read(&full) {
                Ok(b) => Some(String::from_utf8(b).map_err(|_| format!("block {block}: {} is not text", e.path))?),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(format!("block {block}: {}: {err}", e.path)),
            };
            let now = old.clone().unwrap_or_default();
            files.insert(e.path.clone(), (full, old, now));
        }
        let entry = files.get_mut(&e.path).unwrap();
        if e.search.is_empty() { entry.2 = e.replace.clone(); continue; }
        if entry.1.is_none() && entry.2.is_empty() { return Err(format!("block {block}: {} does not exist; an empty SEARCH creates it", e.path)); }
        let text = &entry.2;
        let count = text.matches(e.search.as_str()).count();
        entry.2 = match count {
            1 => text.replacen(e.search.as_str(), &e.replace, 1),
            // The file's last line has no newline: match it without the reply's.
            0 if e.search.ends_with('\n') && text.ends_with(e.search.trim_end_matches('\n'))
                && text.matches(e.search.trim_end_matches('\n')).count() == 1 => {
                let s = e.search.trim_end_matches('\n');
                format!("{}{}", &text[..text.len() - s.len()], e.replace.strip_suffix('\n').unwrap_or(&e.replace))
            }
            0 => return Err(format!("block {block}: SEARCH not found in {}", e.path)),
            n => return Err(format!("block {block}: SEARCH occurs {n} times in {}", e.path)),
        };
    }
    // Write each changed file beside itself, then rename: a failed write leaves nothing.
    let changed: Vec<(&String, &PathBuf, &String)> = files.iter()
        .filter(|(_, (_, old, now))| old.as_ref() != Some(now)).map(|(p, (full, _, now))| (p, full, now)).collect();
    let mut staged: Vec<(PathBuf, &PathBuf)> = Vec::new();
    let mut made: Vec<PathBuf> = Vec::new();
    let undo = |staged: &[(PathBuf, &PathBuf)], made: &[PathBuf]| {
        for (t, _) in staged { let _ = std::fs::remove_file(t); }
        for d in made.iter().rev() { let _ = std::fs::remove_dir(d); }
    };
    for (path, full, now) in &changed {
        let parent = full.parent().unwrap();
        let mut missing = Vec::new();
        let mut p = parent.to_path_buf();
        while !p.exists() { missing.push(p.clone()); if !p.pop() { break; } }
        for d in missing.into_iter().rev() {
            if let Err(err) = std::fs::create_dir(&d) { undo(&staged, &made); return Err(format!("{path}: {err}")); }
            made.push(d);
        }
        let tmp = parent.join(format!(".{}.bon-sample", full.file_name().unwrap().to_string_lossy()));
        if let Err(err) = std::fs::write(&tmp, now.as_bytes()) {
            undo(&staged, &made);
            return Err(format!("{path}: {err}"));
        }
        if let Ok(m) = std::fs::metadata(full) { let _ = std::fs::set_permissions(&tmp, m.permissions()); }
        staged.push((tmp, full));
    }
    for (tmp, full) in &staged {
        if let Err(err) = std::fs::rename(tmp, full) { undo(&staged, &made); return Err(format!("{}: {err}", full.display())); }
    }
    Ok(changed.iter().map(|(p, _, _)| (*p).clone()).collect())
}

// ── transports ──────────────────────────────────────────

/// A model's reply and the usage line for bon.
struct Reply { text: String, usage: serde_json::Value }

/// Why a transport gave no usable reply, and the reply when tokens were spent anyway.
struct Failure { why: String, spent: Option<Reply> }

impl From<String> for Failure { fn from(why: String) -> Self { Failure { why, spent: None } } }

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The usage line, shaped like the Claude CLI's final `result` event.
fn usage_line(model: &str, input: u64, cache_read: u64, cache_write_5m: u64, cache_write_1h: u64, output: u64) -> serde_json::Value {
    serde_json::json!({ "type": "result", "modelUsage": { model: {
        "inputTokens": input, "cacheReadInputTokens": cache_read, "outputTokens": output,
        "cacheCreationInputTokens": cache_write_5m + cache_write_1h,
        "cacheCreationEphemeral5mInputTokens": cache_write_5m, "cacheCreationEphemeral1hInputTokens": cache_write_1h,
        "costUSD": 0.0,
    } } })
}

/// A quoted value in a curl config file.
fn curl_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c { '\\' => out.push_str("\\\\"), '"' => out.push_str("\\\""), '\n' => out.push_str("\\n"), '\r' => out.push_str("\\r"), c => out.push(c) }
    }
    out.push('"');
    out
}

/// Run a program with `stdin`; (exit 0, stdout, stderr).
fn run_with_stdin(mut c: Command, stdin: &str) -> Result<(bool, String, String), String> {
    let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|e| format!("spawn {:?}: {e}", c.get_program()))?;
    let mut pipe = child.stdin.take().unwrap();
    let text = stdin.to_string();
    let writer = std::thread::spawn(move || { let _ = pipe.write_all(text.as_bytes()); });
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let _ = writer.join();
    Ok((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned()))
}

/// The Messages API through curl: the key and the body go on curl's stdin as
/// its config, never in argv. The stable prefix is the system prompt, with a
/// cache breakpoint at its end; the task is the user turn.
fn via_api(a: &Args, ctx: &Context, prompt: &str, env: Env) -> Result<Reply, Failure> {
    let key_file = env("BON_ANTHROPIC_KEY_FILE").unwrap_or_else(|| DEFAULT_KEY_FILE.into());
    let key = std::fs::read_to_string(&key_file).map_err(|e| format!("{key_file}: {e}"))?.trim().to_string();
    if key.is_empty() { return Err(format!("{key_file} is empty").into()); }
    let base = env("BON_ANTHROPIC_BASE_URL").unwrap_or_else(|| DEFAULT_BASE_URL.into());
    let mut body = serde_json::json!({
        "model": a.model, "max_tokens": a.max_output,
        "system": [{ "type": "text", "text": format!("{INSTRUCTIONS}\n{}", ctx.repository), "cache_control": { "type": "ephemeral" } }],
        "messages": [{ "role": "user", "content": prompt }],
    });
    if let Some(e) = &a.effort { body["output_config"] = serde_json::json!({ "effort": e }); }
    let config = format!(
        "url = {}\nrequest = \"POST\"\nheader = {}\nheader = \"anthropic-version: {API_VERSION}\"\nheader = \"content-type: application/json\"\n\
         header = \"Expect:\"\ndata-binary = {}\nsilent\nshow-error\nmax-time = 900\nwrite-out = \"\\n%{{http_code}}\"\n",
        curl_quote(&format!("{}/v1/messages", base.trim_end_matches('/'))), curl_quote(&format!("x-api-key: {key}")),
        curl_quote(&body.to_string()));
    let mut last = String::new();
    for attempt in 0..4u32 {
        if attempt > 0 { std::thread::sleep(std::time::Duration::from_secs(2u64 << attempt)); }
        let mut c = Command::new("curl");
        c.args(["-K", "-"]);
        let (ok, out, err) = run_with_stdin(c, &config)?;
        if !ok { last = format!("curl: {}", err.trim()); continue; }
        let (response, status) = out.rsplit_once('\n').unwrap_or(("", out.as_str()));
        let status: u16 = status.trim().parse().unwrap_or(0);
        if status == 429 || status >= 500 { last = format!("HTTP {status}: {}", response.trim()); continue; }
        if status != 200 { return Err(format!("HTTP {status}: {}", response.trim()).into()); }
        let v: serde_json::Value = serde_json::from_str(response).map_err(|e| format!("response is not JSON: {e}"))?;
        let text: String = v["content"].as_array().into_iter().flatten()
            .filter(|b| b["type"] == "text").filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("");
        let u = &v["usage"];
        let n = |x: &serde_json::Value| x.as_u64().unwrap_or(0);
        let (w5, w1) = (n(&u["cache_creation"]["ephemeral_5m_input_tokens"]), n(&u["cache_creation"]["ephemeral_1h_input_tokens"]));
        let w5 = if w5 + w1 == 0 { n(&u["cache_creation_input_tokens"]) } else { w5 };
        let usage = usage_line(&a.model, n(&u["input_tokens"]), n(&u["cache_read_input_tokens"]), w5, w1, n(&u["output_tokens"]));
        return match v["stop_reason"].as_str() {
            Some("end_turn") | Some("stop_sequence") => Ok(Reply { text, usage }),
            other => Err(Failure { why: format!("stop_reason {}", other.unwrap_or("missing")), spent: Some(Reply { text, usage }) }),
        };
    }
    Err(last.into())
}

/// The Claude CLI, one shot: no tools, no settings, MCP, slash commands or
/// session on disk. The format is the system prompt; the files then the task
/// are the one user turn, so the prefix is the same for every sample.
fn via_claude(a: &Args, ctx: &Context, prompt: &str, env: Env) -> Result<Reply, Failure> {
    let program = env("BON_SAMPLE_CLAUDE").unwrap_or_else(|| "claude".into());
    let mut c = Command::new(program);
    c.args(["-p", "--output-format", "json", "--model", &a.model, "--tools", "", "--system-prompt", INSTRUCTIONS,
            "--setting-sources", "", "--strict-mcp-config", "--no-session-persistence", "--disable-slash-commands"]);
    if let Some(e) = &a.effort { c.args(["--effort", e]); }
    let (ok, out, err) = run_with_stdin(c, &format!("{}\n{prompt}", ctx.repository))?;
    let v = out.lines().rev().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).find(|v| v["type"] == "result")
        .ok_or(format!("claude printed no result{}: {}", if ok { "" } else { " and failed" }, err.trim()))?;
    let usage = serde_json::json!({ "type": "result", "modelUsage": v["modelUsage"], "total_cost_usd": v["total_cost_usd"] });
    let text = v["result"].as_str().unwrap_or("").to_string();
    if v["is_error"] == true || !ok {
        return Err(Failure { why: format!("claude: {}", v["subtype"].as_str().unwrap_or("error")), spent: Some(Reply { text, usage }) });
    }
    Ok(Reply { text, usage })
}

/// `codex exec`, read-only, no session or user config; the last agent message
/// is the reply. Codex keeps its own system prompt and tools, so it runs in an
/// empty directory: it has nothing to look at or write, and its environment
/// context (which names the directory) is the same for every sample, so the
/// prefix caches. The edits are applied here, in the working directory.
fn via_codex(a: &Args, ctx: &Context, prompt: &str, env: Env) -> Result<Reply, Failure> {
    let program = env("BON_SAMPLE_CODEX").unwrap_or_else(|| "codex".into());
    let mut c = Command::new(program);
    c.args(["exec", "--json", "--ephemeral", "--ignore-rules", "--ignore-user-config", "--skip-git-repo-check",
            "--sandbox", "read-only", "--color", "never", "-m", &a.model]);
    if let Some(e) = &a.effort { c.args(["-c", &format!("model_reasoning_effort=\"{e}\"")]); }
    c.args(["-C", CODEX_DIR, "-"]).current_dir(CODEX_DIR);
    let (ok, out, err) = run_with_stdin(c, &format!("{INSTRUCTIONS}\n{}\n{prompt}", ctx.repository))?;
    let events: Vec<serde_json::Value> = out.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let text = events.iter().rev().find(|v| v["type"] == "item.completed" && v["item"]["type"] == "agent_message")
        .and_then(|v| v["item"]["text"].as_str()).unwrap_or("").to_string();
    // Read-only, codex may still run commands to look around: say how many.
    let commands = events.iter().filter(|v| v["type"] == "item.completed" && v["item"]["type"] == "command_execution").count();
    if commands > 0 { eprintln!("bon-sample: codex ran {commands} commands"); }
    let turn = events.iter().rev().find(|v| v["type"] == "turn.completed");
    let Some(t) = turn else { return Err(format!("codex printed no turn.completed{}: {}", if ok { "" } else { " and failed" }, err.trim()).into()) };
    let n = |k: &str| t["usage"][k].as_u64().unwrap_or(0);
    let (input, cached, write) = (n("input_tokens"), n("cached_input_tokens"), n("cache_write_input_tokens"));
    let usage = usage_line(&a.model, input.saturating_sub(cached + write), cached, write, 0, n("output_tokens"));
    if !ok { return Err(Failure { why: format!("codex failed: {}", err.trim()), spent: Some(Reply { text, usage }) }); }
    Ok(Reply { text, usage })
}

// ── one sample ──────────────────────────────────────────

/// What the process prints and whether it succeeded: stdout (the reply, then
/// the usage line last) and the reason on failure.
struct Outcome { stdout: String, error: Option<String> }

fn run(argv: &[String], prompt: &str, root: &Path, env: Env) -> Outcome {
    let fail = |e: String| Outcome { stdout: String::new(), error: Some(e) };
    let a = match parse_args(argv) { Ok(a) => a, Err(e) => return fail(e) };
    let ctx = context(root, prompt, a.max_context, a.max_file);
    eprintln!("bon-sample: context: {} files shown; not shown: {}", ctx.included.len(),
              if ctx.omitted.is_empty() { "none".to_string() } else { ctx.omitted.iter().map(|(f, why)| format!("{f} ({why})")).collect::<Vec<_>>().join(", ") });
    let reply = match a.via {
        Via::Api => via_api(&a, &ctx, prompt, env),
        Via::Claude => via_claude(&a, &ctx, prompt, env),
        Via::Codex => via_codex(&a, &ctx, prompt, env),
    };
    let (text, usage) = match reply {
        Ok(r) => (r.text, r.usage),
        // Tokens were spent: print the reply and usage, change nothing.
        Err(Failure { why, spent: Some(r) }) => return Outcome { stdout: format!("{}\n{}\n", r.text, r.usage), error: Some(why) },
        Err(Failure { why, spent: None }) => return fail(why),
    };
    let stdout = format!("{text}\n{usage}\n");
    match parse(&text).and_then(|edits| apply(root, &edits)) {
        Ok(written) => { eprintln!("bon-sample: wrote {}", written.join(", ")); Outcome { stdout, error: None } }
        Err(e) => Outcome { stdout, error: Some(e) },
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut prompt = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut prompt) { eprintln!("bon-sample: stdin: {e}"); std::process::exit(2); }
    let root = match std::env::current_dir() { Ok(d) => d, Err(e) => { eprintln!("bon-sample: {e}"); std::process::exit(2) } };
    let o = run(&argv, &prompt, &root, &|k| std::env::var(k).ok());
    print!("{}", o.stdout);
    let _ = std::io::stdout().flush();
    if let Some(e) = o.error { eprintln!("bon-sample: {e}"); std::process::exit(1); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn scratch() -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!("bon-sample-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn write(root: &Path, p: &str, s: &[u8]) {
        let f = root.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, s).unwrap();
    }
    fn read(root: &Path, p: &str) -> String { std::fs::read_to_string(root.join(p)).unwrap() }
    fn block(path: &str, search: &str, replace: &str) -> String {
        format!("@@@ FILE {path}\n@@@ SEARCH\n{search}@@@ REPLACE\n{replace}@@@ END\n")
    }

    #[test]
    fn parses_blocks_and_ignores_prose() {
        let reply = format!("Here:\n{}{}Changed a and created b.\n", block("src/a.rs", "x\n", "y\n"), block("b.txt", "", "new\n"));
        let e = parse(&reply).unwrap();
        assert_eq!(e, vec![Edit { path: "src/a.rs".into(), search: "x\n".into(), replace: "y\n".into() },
                           Edit { path: "b.txt".into(), search: "".into(), replace: "new\n".into() }]);
    }

    #[test]
    fn malformed_replies_are_errors() {
        assert!(parse("no blocks here\n").is_err());
        assert!(parse("@@@ FILE a\n@@@ SEARCH\nx\n@@@ REPLACE\ny\n").is_err(), "unterminated");
        assert!(parse("@@@ FILE a\n@@@ REPLACE\ny\n@@@ END\n").is_err(), "out of order");
        assert!(parse("@@@ SEARCH\nx\n@@@ REPLACE\ny\n@@@ END\n").is_err(), "no FILE");
    }

    #[test]
    fn applies_in_order_and_creates_files() {
        let d = scratch();
        write(&d, "a.txt", b"one\ntwo\nthree\n");
        let reply = format!("{}{}{}", block("a.txt", "two\n", "2\n"), block("a.txt", "2\nthree\n", "2\n3\n"), block("new/dir/b.txt", "", "b\n"));
        let written = apply(&d, &parse(&reply).unwrap()).unwrap();
        assert_eq!(written, vec!["a.txt".to_string(), "new/dir/b.txt".to_string()]);
        assert_eq!(read(&d, "a.txt"), "one\n2\n3\n");
        assert_eq!(read(&d, "new/dir/b.txt"), "b\n");
    }

    #[test]
    fn a_last_line_without_newline_matches() {
        let d = scratch();
        write(&d, "a.txt", b"one\ntwo");
        apply(&d, &parse(&block("a.txt", "two\n", "2\n")).unwrap()).unwrap();
        assert_eq!(read(&d, "a.txt"), "one\n2");
    }

    #[test]
    fn nothing_applies_unless_everything_does() {
        let d = scratch();
        write(&d, "a.txt", b"x\nx\n");
        write(&d, "b.txt", b"b\n");
        for bad in [block("b.txt", "b\n", "B\n") + &block("a.txt", "x\n", "y\n"),   // ambiguous
                    block("b.txt", "b\n", "B\n") + &block("a.txt", "z\n", "y\n"),   // not found
                    block("b.txt", "b\n", "B\n") + &block("c.txt", "z\n", "y\n"),   // no such file
                    block("b.txt", "b\n", "B\n") + &block("../c.txt", "", "y\n")] { // refused
            assert!(apply(&d, &parse(&bad).unwrap()).is_err(), "{bad}");
            assert_eq!(read(&d, "a.txt"), "x\nx\n");
            assert_eq!(read(&d, "b.txt"), "b\n");
        }
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 2, "no temporary files left");
    }

    #[test]
    fn paths_outside_are_refused() {
        let d = scratch();
        std::os::unix::fs::symlink("/tmp", d.join("link")).unwrap();
        for p in ["/etc/passwd", "../x", "a/../../x", "a/..", "link/x", "./", "", "a\\b"] {
            assert!(checked(&d, p).is_err(), "{p}");
        }
        assert!(checked(&d, "src/new.rs").is_ok());
        assert!(checked(&d, "./a.txt").is_err(), "a CurDir component is refused");
    }

    #[test]
    fn context_is_deterministic_named_first_and_skips() {
        let d = scratch();
        write(&d, "src/z.rs", b"fn z() {}\n");
        write(&d, "src/a.rs", b"fn a() {}\n");
        write(&d, "checks/spec.rs", b"spec\n");
        write(&d, "README.md", b"readme");
        write(&d, "Cargo.lock", b"lock\n");
        write(&d, "target/debug/x", b"build\n");
        write(&d, ".git/HEAD", b"ref\n");
        write(&d, "logo.png", b"\x89PNG\r\n\x1a\n\0\0\xff");
        write(&d, "big.txt", &vec![b'a'; 2000]);
        let prompt = "The checks are [\"src/z.rs\", \"checks/\"]: read them.";
        let c = context(&d, prompt, 10_000, 1000);
        assert_eq!(c, context(&d, prompt, 10_000, 1000), "the same tree and task give the same bytes");
        assert_eq!(c.included, vec!["src/z.rs", "checks/spec.rs", "README.md", "src/a.rs"]);
        assert_eq!(c.omitted, vec![("Cargo.lock".to_string(), "lockfile"), ("big.txt".to_string(), "over the per-file cap"),
                                   ("logo.png".to_string(), "binary")]);
        assert!(c.repository.contains("<file path=\"README.md\">\nreadme\n</file>\n"));
        // Over the budget: skipped, and later files that fit still come.
        let small = context(&d, prompt, 25, 1000);
        assert_eq!(small.included, vec!["src/z.rs", "checks/spec.rs", "README.md"]);
        assert!(small.omitted.contains(&("src/a.rs".to_string(), "over the context budget")));
    }

    #[test]
    fn arguments() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse_args(&s(&["--via", "claude", "--model", "m", "--max-context-bytes", "10"])).unwrap();
        assert_eq!((a.via, a.model.as_str(), a.max_context), (Via::Claude, "m", 10));
        assert!(parse_args(&s(&["--model", "m"])).is_err());
        assert!(parse_args(&s(&["--via", "x", "--model", "m"])).is_err());
        assert!(parse_args(&s(&["--via", "api"])).is_err());
    }

    /// One HTTP exchange on a local port: returns the base URL and a handle
    /// yielding the request's head and body.
    fn mock(status: &str, body: String) -> (String, std::thread::JoinHandle<(String, String)>) {
        use std::io::BufRead;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let status = status.to_string();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = std::io::BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            loop { let mut line = String::new(); r.read_line(&mut line).unwrap(); if line == "\r\n" || line.is_empty() { break; } head.push_str(&line); }
            let len: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
            let mut b = vec![0; len];
            r.read_exact(&mut b).unwrap();
            let mut s = s;
            write!(s, "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
            (head, String::from_utf8(b).unwrap())
        });
        (url, h)
    }

    #[test]
    fn api_transport_against_a_local_server() {
        let d = scratch();
        write(&d, "src/lib.rs", b"pub fn f() -> u32 { 1 }\n");
        write(&d, "checks.rs", b"// the check\n");
        let key = scratch().join("key");
        std::fs::write(&key, "sk-test-key\n").unwrap();
        let reply = block("src/lib.rs", "pub fn f() -> u32 { 1 }\n", "pub fn f() -> u32 { 2 }\n") + "f returns 2.\n";
        let response = serde_json::json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-haiku-5-5", "stop_reason": "end_turn",
            "content": [{ "type": "thinking", "thinking": "" }, { "type": "text", "text": reply }],
            "usage": { "input_tokens": 12, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 700, "output_tokens": 40,
                       "cache_creation": { "ephemeral_5m_input_tokens": 700, "ephemeral_1h_input_tokens": 0 } },
        });
        let (url, server) = mock("200 OK", response.to_string());
        let key_path = key.to_string_lossy().to_string();
        let env = move |k: &str| match k { "BON_ANTHROPIC_BASE_URL" => Some(url.clone()), "BON_ANTHROPIC_KEY_FILE" => Some(key_path.clone()), _ => None };
        let argv: Vec<String> = ["--via", "api", "--model", "claude-haiku-5-5", "--max-output-tokens", "1000"].iter().map(|s| s.to_string()).collect();
        let prompt = "Make f return 2. The checks are [\"checks.rs\"].";
        let o = run(&argv, prompt, &d, &env);
        assert_eq!(o.error, None);
        assert_eq!(read(&d, "src/lib.rs"), "pub fn f() -> u32 { 2 }\n");
        let (head, body) = server.join().unwrap();
        let head = head.to_ascii_lowercase();
        assert!(head.starts_with("post /v1/messages "), "{head}");
        assert!(head.contains("x-api-key: sk-test-key\r\n") && head.contains(&format!("anthropic-version: {API_VERSION}")), "{head}");
        let req: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(req["model"], "claude-haiku-5-5");
        assert_eq!(req["max_tokens"], 1000);
        assert_eq!(req["system"][0]["cache_control"]["type"], "ephemeral");
        let system = req["system"][0]["text"].as_str().unwrap();
        assert!(system.starts_with(INSTRUCTIONS));
        assert!(system.find("checks.rs").unwrap() < system.find("src/lib.rs").unwrap(), "the named check comes first");
        assert_eq!(req["messages"][0]["content"], prompt);
        // The reply, then the usage line, last.
        let last: serde_json::Value = serde_json::from_str(o.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(last["type"], "result");
        let u = &last["modelUsage"]["claude-haiku-5-5"];
        assert_eq!((u["inputTokens"].as_u64(), u["cacheCreationInputTokens"].as_u64(), u["outputTokens"].as_u64()), (Some(12), Some(700), Some(40)));
        assert!(o.stdout.starts_with("@@@ FILE src/lib.rs"));
    }

    #[test]
    fn api_errors_change_nothing() {
        let d = scratch();
        write(&d, "a.txt", b"a\n");
        let key = scratch().join("key");
        std::fs::write(&key, "k").unwrap();
        let (url, server) = mock("400 Bad Request", r#"{"type":"error","error":{"type":"invalid_request_error","message":"no"}}"#.into());
        let key_path = key.to_string_lossy().to_string();
        let env = move |k: &str| match k { "BON_ANTHROPIC_BASE_URL" => Some(url.clone()), "BON_ANTHROPIC_KEY_FILE" => Some(key_path.clone()), _ => None };
        let argv: Vec<String> = ["--via", "api", "--model", "m"].iter().map(|s| s.to_string()).collect();
        let o = run(&argv, "task", &d, &env);
        server.join().unwrap();
        assert!(o.error.unwrap().contains("HTTP 400"));
        assert_eq!(read(&d, "a.txt"), "a\n");
    }

    #[test]
    fn a_reply_that_does_not_apply_still_reports_usage() {
        let d = scratch();
        write(&d, "a.txt", b"a\n");
        let fake = scratch().join("claude");
        let result = serde_json::json!({ "type": "result", "subtype": "success", "is_error": false, "result": block("a.txt", "nope\n", "b\n"),
                                         "modelUsage": { "claude-haiku-5-5": { "inputTokens": 3, "outputTokens": 5, "costUSD": 0.001 } } });
        std::fs::write(&fake, format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{result}'\n")).unwrap();
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let program = fake.to_string_lossy().to_string();
        let env = move |k: &str| (k == "BON_SAMPLE_CLAUDE").then(|| program.clone());
        let argv: Vec<String> = ["--via", "claude", "--model", "claude-haiku-5-5"].iter().map(|s| s.to_string()).collect();
        let o = run(&argv, "task", &d, &env);
        assert!(o.error.unwrap().contains("SEARCH not found"));
        assert_eq!(read(&d, "a.txt"), "a\n");
        let last: serde_json::Value = serde_json::from_str(o.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(last["modelUsage"]["claude-haiku-5-5"]["outputTokens"], 5);
    }

    #[test]
    fn codex_events_are_read() {
        let d = scratch();
        write(&d, "a.txt", b"a\n");
        let fake = scratch().join("codex");
        let msg = serde_json::json!({ "type": "item.completed", "item": { "type": "agent_message", "text": block("a.txt", "a\n", "b\n") } });
        let turn = serde_json::json!({ "type": "turn.completed", "usage": { "input_tokens": 100, "cached_input_tokens": 60, "output_tokens": 7 } });
        std::fs::write(&fake, format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{msg}' '{turn}'\n")).unwrap();
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let program = fake.to_string_lossy().to_string();
        let env = move |k: &str| (k == "BON_SAMPLE_CODEX").then(|| program.clone());
        let argv: Vec<String> = ["--via", "codex", "--model", "gpt-6.1-sol"].iter().map(|s| s.to_string()).collect();
        let o = run(&argv, "task", &d, &env);
        assert_eq!(o.error, None);
        assert_eq!(read(&d, "a.txt"), "b\n");
        let last: serde_json::Value = serde_json::from_str(o.stdout.lines().last().unwrap()).unwrap();
        let u = &last["modelUsage"]["gpt-6.1-sol"];
        assert_eq!((u["inputTokens"].as_u64(), u["cacheReadInputTokens"].as_u64()), (Some(40), Some(60)));
    }
}
