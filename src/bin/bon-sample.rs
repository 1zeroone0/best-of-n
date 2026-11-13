//! bon-sample: a program that makes one model call. Context in, edits out:
//! it reads the task on stdin, sends the working directory's files and the task
//! to a model in one request, applies the edit blocks of the one reply, and
//! prints the reply and a usage line. bon does all the checking.
//!
//! usage: bon-sample --model <id> [--max-file-bytes N] [--max-output-tokens N] [--effort LEVEL]
//!
//! What its role says beyond its argv, bon gives it in its environment:
//! BON_CLIENT, how it reaches the model (api, claude or codex: each through
//! the program of that name on PATH, curl for the api); BON_CONTEXT, the
//! largest prompt in tokens its one request may be (the instructions, the
//! files and the task together); and BON_HOST, the host file, whose
//! [api] says where the Messages API is and which file holds its key.
//!
//! Unverified edge code, like the CLIs it stands in for: what it
//! writes is judged by bon's checks, never trusted.

// Nothing here is verified, but `cargo verus verify` builds every target of
// the package, and Verus refuses a crate that does not import its builtins.
#[allow(unused_imports)]
use vstd::prelude::*;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

pub(crate) const USAGE: &str = "usage: bon-sample --model <id> [--max-file-bytes N] [--max-output-tokens N] [--effort LEVEL] (BON_CLIENT, BON_CONTEXT and BON_HOST from bon)";
pub(crate) const API_VERSION: &str = "2026-10-21";
/// The host file when BON_HOST names none.
pub(crate) const HOST: &str = "/etc/bon/host.toml";
/// The largest prompt, in tokens, when the role names no context: under
/// Haiku 5.5's tier line (100,000 tokens, past which every price is five
/// times) with margin.
pub(crate) const DEFAULT_CONTEXT_TOKENS: usize = 80_000;
/// Bytes counted per token of the budget: fewer than the 2.4 measured on this
/// repository's code, so a prompt held to the budget in bytes stays under it
/// in tokens (80,000 tokens are 160,000 bytes, about 67,000 measured tokens).
pub(crate) const BYTES_PER_TOKEN: usize = 2;
pub(crate) const DEFAULT_FILE_BYTES: usize = 160_000;
pub(crate) const DEFAULT_OUTPUT_TOKENS: u64 = 16_000;
/// Where codex runs: empty, and the same for every agent process.
pub(crate) const CODEX_DIR: &str = "/var/empty";
/// Directories never sent: build output, dependencies, version control.
pub(crate) const SKIP_DIRS: [&str; 6] = [".git", "target", "node_modules", ".venv", "__pycache__", ".cargo"];
pub(crate) const LOCKFILES: [&str; 10] = ["Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum",
                               "poetry.lock", "uv.lock", "Gemfile.lock", "composer.lock", "flake.lock"];

/// The output format, first in the stable prefix.
pub(crate) const INSTRUCTIONS: &str = "You see a repository's files and a task, and you reply once, \
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
- If any block does not apply, none does, and your reply changes nothing.
- Paths are relative, never absolute, and never contain `..`.
- Marker lines start with `@@@ ` at the start of a line. Do not put the blocks in code fences.
- Keep each SEARCH short: a few lines around the change.
";

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Client { Api, Claude, Codex }

#[derive(Debug)]
pub(crate) struct Args { pub(crate) client: Client, pub(crate) model: String, pub(crate) max_context: usize, pub(crate) max_file: usize, pub(crate) max_output: u64, pub(crate) effort: Option<String> }

pub(crate) type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The arguments, and what bon gave in the environment: the client and the context budget.
pub(crate) fn parse_args(argv: &[String], env: Env) -> Result<Args, String> {
    let client = match env("BON_CLIENT").as_deref() {
        Some("api") => Client::Api, Some("claude") => Client::Claude, Some("codex") => Client::Codex,
        Some(c) => return Err(format!("BON_CLIENT: unknown client {c}; api, claude or codex")),
        None => return Err(format!("BON_CLIENT is not set: bon sets it from the role's client\n{USAGE}")),
    };
    let tokens = match env("BON_CONTEXT") {
        Some(v) => v.parse::<usize>().map_err(|_| format!("BON_CONTEXT: not a number: {v}"))?,
        None => DEFAULT_CONTEXT_TOKENS,
    };
    let max_context = tokens.saturating_mul(BYTES_PER_TOKEN);
    let mut a = Args { client, model: String::new(), max_context, max_file: DEFAULT_FILE_BYTES, max_output: DEFAULT_OUTPUT_TOKENS, effort: None };
    let mut it = argv.iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().cloned().ok_or(format!("{flag} needs a value"));
        let number = |v: String| v.parse::<u64>().map_err(|_| format!("{flag}: not a number: {v}"));
        match flag.as_str() {
            "--model" => a.model = value()?,
            "--max-file-bytes" => a.max_file = number(value()?)? as usize,
            "--max-output-tokens" => a.max_output = number(value()?)?,
            "--effort" => a.effort = Some(value()?),
            "-h" | "--help" => return Err(USAGE.into()),
            f => return Err(format!("unknown argument {f}\n{USAGE}")),
        }
    }
    if a.model.is_empty() { return Err(format!("--model is required\n{USAGE}")); }
    Ok(a)
}

/// The host file's [api]: (address, key file).
pub(crate) fn api(env: Env) -> Result<(String, String), String> {
    let file = env("BON_HOST").unwrap_or_else(|| HOST.into());
    let host: toml::Value = toml::from_str(&std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?).map_err(|e| format!("{file}: {e}"))?;
    let key = |k: &str| host.get("api").and_then(|a| a.get(k)).and_then(|v| v.as_str()).map(String::from)
        .ok_or(format!("{file}: [api] has no {k}"));
    Ok((key("address")?, key("key_file")?))
}

// ── context ─────────────────────────────────────────────

/// The request's stable part: the format, then the files. A function of the
/// tree and the paths the task names, so the agent processes of a search send
/// it byte for byte the same.
#[derive(Debug, PartialEq)]
pub(crate) struct Context { pub(crate) repository: String, pub(crate) included: Vec<String>, pub(crate) omitted: Vec<(String, &'static str)>, pub(crate) fixed: Vec<String> }

/// Every file under `root`, relative, '/'-separated, sorted by bytes. Symlinks
/// and the skipped directories are not followed.
pub(crate) fn tree(root: &Path) -> Vec<String> {
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
/// a word such as "checks" does not pull in a directory of that name; a
/// location a compiler or Verus prints (`src/exec.rs:1300:5`) names its file.
pub(crate) fn named(prompt: &str, files: &[String]) -> Vec<String> {
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

/// Whether this process may write `p`: the checks and what else bon protects
/// are read-only to agent in its working directory. Opened for writing, never written.
pub(crate) fn writable(p: &Path) -> bool { std::fs::OpenOptions::new().write(true).open(p).is_ok() }

/// The files in the request: the ones the task names first, each in full,
/// then the rest that fit. A named file is never dropped for the budget while
/// an unnamed one is kept: once a named file does not fit, no unnamed file
/// comes; nor does the per-file cap apply to a named file. It says which files
/// may not be changed.
pub(crate) fn context(root: &Path, prompt: &str, max_context: usize, max_file: usize) -> Context {
    let files = tree(root);
    let first = named(prompt, &files);
    let order = first.iter().map(|f| (f, true)).chain(files.iter().filter(|f| !first.contains(f)).map(|f| (f, false)));
    let (mut included, mut omitted, mut body, mut total) = (Vec::new(), Vec::new(), String::new(), 0usize);
    let mut named_dropped = false;
    for (f, is_named) in order {
        let name = f.rsplit('/').next().unwrap_or(f);
        if LOCKFILES.contains(&name) { omitted.push((f.clone(), "lockfile")); continue; }
        let size = std::fs::metadata(root.join(f)).map(|m| m.len() as usize).unwrap_or(usize::MAX);
        if !is_named && size > max_file { omitted.push((f.clone(), "over the per-file cap")); continue; }
        let Ok(bytes) = std::fs::read(root.join(f)) else { omitted.push((f.clone(), "unreadable")); continue };
        let Ok(text) = String::from_utf8(bytes) else { omitted.push((f.clone(), "binary")); continue };
        if text.contains('\0') { omitted.push((f.clone(), "binary")); continue; }
        if total + text.len() > max_context || (!is_named && named_dropped) {
            named_dropped |= is_named;
            omitted.push((f.clone(), "over the context budget"));
            continue;
        }
        total += text.len();
        body.push_str(&format!("<file path=\"{f}\">\n{text}{}</file>\n", if text.ends_with('\n') || text.is_empty() { "" } else { "\n" }));
        included.push(f.clone());
    }
    let fixed: Vec<String> = files.iter().filter(|f| !writable(&root.join(f))).cloned().collect();
    let mut repository = format!("<repository>\nThe working directory's files, each in full ({} shown, {total} bytes).\n{body}", included.len());
    if !omitted.is_empty() {
        repository.push_str("Files not shown: ");
        repository.push_str(&omitted.iter().map(|(f, why)| format!("{f} ({why})")).collect::<Vec<_>>().join(", "));
        repository.push('\n');
    }
    if !fixed.is_empty() {
        repository.push_str("You cannot change these files (the checks, and what else bon protects): an edit to any of them is refused: ");
        repository.push_str(&fixed.join(", "));
        repository.push('\n');
    }
    repository.push_str("</repository>\n");
    Context { repository, included, omitted, fixed }
}

// ── edits ───────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub(crate) struct Edit { pub(crate) path: String, pub(crate) search: String, pub(crate) replace: String }

/// The edit blocks of a reply. Text outside blocks is ignored; a block left
/// open or out of order is an error.
pub(crate) fn parse(reply: &str) -> Result<Vec<Edit>, String> {
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
pub(crate) fn checked(root: &Path, path: &str) -> Result<PathBuf, String> {
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
pub(crate) fn apply(root: &Path, edits: &[Edit]) -> Result<Vec<String>, String> {
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
pub(crate) struct Reply { pub(crate) text: String, pub(crate) usage: serde_json::Value }

/// Why a transport gave no usable reply, and the reply when tokens were spent anyway.
pub(crate) struct Failure { pub(crate) why: String, pub(crate) spent: Option<Reply> }

impl From<String> for Failure { fn from(why: String) -> Self { Failure { why, spent: None } } }

/// The usage line, shaped like the Claude CLI's final `result` event. No
/// `costUSD`: this transport knows no price, and bon prices the tokens itself.
/// `requests`: one, so bon can apply a price's tier for a large prompt.
pub(crate) fn usage_line(model: &str, input: u64, cache_read: u64, cache_write_5m: u64, cache_write_1h: u64, output: u64) -> serde_json::Value {
    serde_json::json!({ "type": "result", "requests": 1, "modelUsage": { model: {
        "inputTokens": input, "cacheReadInputTokens": cache_read, "outputTokens": output,
        "cacheCreationInputTokens": cache_write_5m + cache_write_1h,
        "cacheCreationEphemeral5mInputTokens": cache_write_5m, "cacheCreationEphemeral1hInputTokens": cache_write_1h,
    } } })
}

/// A quoted value in a curl config file.
pub(crate) fn curl_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c { '\\' => out.push_str("\\\\"), '"' => out.push_str("\\\""), '\n' => out.push_str("\\n"), '\r' => out.push_str("\\r"), c => out.push(c) }
    }
    out.push('"');
    out
}

/// Run a program with `stdin`; (exit 0, stdout, stderr).
pub(crate) fn run_with_stdin(mut c: Command, stdin: &str) -> Result<(bool, String, String), String> {
    let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|e| format!("spawn {:?}: {e}", c.get_program()))?;
    let mut pipe = child.stdin.take().unwrap();
    let text = stdin.to_string();
    let writer = std::thread::spawn(move || { let _ = pipe.write_all(text.as_bytes()); });
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let _ = writer.join();
    Ok((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned()))
}

/// Run a program with `stdin`, `line` called on each line of its stdout as it
/// comes; (exit 0, stdout, stderr).
pub(crate) fn run_streaming(mut c: Command, stdin: &str, line: &mut dyn FnMut(&str)) -> Result<(bool, String, String), String> {
    let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|e| format!("spawn {:?}: {e}", c.get_program()))?;
    let mut pipe = child.stdin.take().unwrap();
    let text = stdin.to_string();
    let writer = std::thread::spawn(move || { let _ = pipe.write_all(text.as_bytes()); });
    let mut err_pipe = child.stderr.take().unwrap();
    let errors = std::thread::spawn(move || { let mut e = String::new(); let _ = err_pipe.read_to_string(&mut e); e });
    let mut out = String::new();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut l = String::new();
    while std::io::BufRead::read_line(&mut reader, &mut l).map_err(|e| e.to_string())? > 0 {
        line(l.trim_end());
        out.push_str(&l);
        l.clear();
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = writer.join();
    Ok((status.success(), out, errors.join().unwrap_or_default()))
}

/// A program on the PATH the environment gives (bon's, or a test's).
pub(crate) fn on_path(program: &str, env: Env) -> Command {
    let mut c = Command::new(program);
    if let Some(p) = env("PATH") { c.env("PATH", p); }
    c
}

/// The Messages API through curl: the key and the body go on curl's stdin as
/// its config, never in argv. The stable prefix is the system prompt, with a
/// cache breakpoint at its end; the task is the user turn. Where the API is
/// and the key's file are the host file's [api].
pub(crate) fn via_api(a: &Args, ctx: &Context, prompt: &str, env: Env) -> Result<Reply, Failure> {
    let (base, key_file) = api(env)?;
    let key = std::fs::read_to_string(&key_file).map_err(|e| format!("{key_file}: {e}"))?.trim().to_string();
    if key.is_empty() { return Err(format!("{key_file} is empty").into()); }
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
        let mut c = on_path("curl", env);
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

/// The line bon-sample prints the moment its model's reply begins: the
/// request was taken, so its prompt is in the provider's cache for the next
/// agent process (bon starts a search's other agent processes at its leader's
/// first output).
pub(crate) const REPLYING: &str = "bon-sample: replying";

/// The Claude CLI, one shot: no tools, no settings, MCP, slash commands or
/// session on disk. The format is the system prompt; the files then the task
/// are the one user turn, so the prefix is the same for every agent process.
/// Its events stream, so REPLYING goes out when the reply starts.
pub(crate) fn via_claude(a: &Args, ctx: &Context, prompt: &str, env: Env) -> Result<Reply, Failure> {
    let mut c = on_path("claude", env);
    c.args(["-p", "--output-format", "stream-json", "--verbose", "--include-partial-messages", "--model", &a.model, "--tools", "",
            "--system-prompt", INSTRUCTIONS, "--setting-sources", "", "--strict-mcp-config", "--no-session-persistence", "--disable-slash-commands"]);
    if let Some(e) = &a.effort { c.args(["--effort", e]); }
    let mut replying = false;
    let (ok, out, err) = run_streaming(c, &format!("{}\n{prompt}", ctx.repository), &mut |line: &str| {
        if !replying && serde_json::from_str::<serde_json::Value>(line).is_ok_and(|v| v["type"] == "stream_event" || v["type"] == "assistant") {
            replying = true;
            let mut o = std::io::stdout();
            let _ = writeln!(o, "{REPLYING}");
            let _ = o.flush();
        }
    })?;
    let v = out.lines().rev().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).find(|v| v["type"] == "result")
        .ok_or(format!("claude printed no result{}: {}", if ok { "" } else { " and failed" }, err.trim()))?;
    // One prompt, no tools: one request (bon applies a price's tier per request).
    let usage = serde_json::json!({ "type": "result", "requests": 1, "modelUsage": v["modelUsage"], "total_cost_usd": v["total_cost_usd"] });
    let text = v["result"].as_str().unwrap_or("").to_string();
    if v["is_error"] == true || !ok {
        return Err(Failure { why: format!("claude: {}", v["subtype"].as_str().unwrap_or("error")), spent: Some(Reply { text, usage }) });
    }
    Ok(Reply { text, usage })
}

/// `codex exec`, read-only, no session or user config; the last agent message
/// is the reply. Codex keeps its own system prompt and tools, so it runs in an
/// empty directory: it has nothing to look at or write, and its environment
/// context (which names the directory) is the same for every agent process,
/// so the prefix caches. The edits are applied here, in the working directory.
pub(crate) fn via_codex(a: &Args, ctx: &Context, prompt: &str, env: Env) -> Result<Reply, Failure> {
    let mut c = on_path("codex", env);
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

// ── one call ────────────────────────────────────────────

/// What the process prints and whether it succeeded: stdout (the reply, then
/// the usage line last) and the reason on failure.
pub(crate) struct Outcome { pub(crate) stdout: String, pub(crate) error: Option<String> }

pub(crate) fn run(argv: &[String], prompt: &str, root: &Path, env: Env) -> Outcome {
    let fail = |e: String| Outcome { stdout: String::new(), error: Some(e) };
    let a = match parse_args(argv, env) { Ok(a) => a, Err(e) => return fail(e) };
    // The files get what the budget leaves after the instructions and the task.
    let ctx = context(root, prompt, a.max_context.saturating_sub(INSTRUCTIONS.len() + prompt.len()), a.max_file);
    eprintln!("bon-sample: context: {} files shown; not shown: {}", ctx.included.len(),
              if ctx.omitted.is_empty() { "none".to_string() } else { ctx.omitted.iter().map(|(f, why)| format!("{f} ({why})")).collect::<Vec<_>>().join(", ") });
    let reply = match a.client {
        Client::Api => via_api(&a, &ctx, prompt, env),
        Client::Claude => via_claude(&a, &ctx, prompt, env),
        Client::Codex => via_codex(&a, &ctx, prompt, env),
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

pub(crate) fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut prompt = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut prompt) { eprintln!("bon-sample: stdin: {e}"); std::process::exit(2); }
    let root = match std::env::current_dir() { Ok(d) => d, Err(e) => { eprintln!("bon-sample: {e}"); std::process::exit(2) } };
    let o = run(&argv, &prompt, &root, &|k| std::env::var(k).ok());
    print!("{}", o.stdout);
    let _ = std::io::stdout().flush();
    if let Some(e) = o.error { eprintln!("bon-sample: {e}"); std::process::exit(1); }
}
