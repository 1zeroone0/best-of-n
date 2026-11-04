//! bon view: one read-only page on localhost over what is already on disk: the
//! map, the spec, the searches (live and past), trunk, and reports. Trusted code;
//! it decides nothing and stores nothing. The interface is TypeScript in
//! view/src, compiled into view/dist and embedded here.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

use best_of_n::exec::Kernel;
use best_of_n::gates::{Encoding, Gates};
use serde_json::{json, Value};

const INDEX: &str = include_str!("../view/dist/index.html");
const APP: &str = include_str!("../view/dist/app.js");
const STYLE: &str = include_str!("../view/dist/app.css");
/// The verified gates, compiled to WebAssembly (`npm run gates` in view/ builds it).
const GATES: &[u8] = include_bytes!("../view/dist/gates.wasm");

pub fn serve(root: &str, port: u16, open: bool) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("port {port}: {e}"))?;
    let url = format!("http://localhost:{port}");
    println!("bon view: {url}");
    if open { let _ = Command::new("open").arg(&url).status(); }
    let root = PathBuf::from(root);
    for stream in listener.incoming().flatten() {
        let root = root.clone();
        std::thread::spawn(move || { let _ = respond(&root, stream); });
    }
    Ok(())
}

fn respond(root: &Path, mut stream: TcpStream) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    let target = line.split_whitespace().nth(1).unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (status, kind, body) = match path {
        "/gates.wasm" => ("200 OK", "application/wasm", GATES.to_vec()),
        "/api/words" => match words(root, query) {
            Some(b) => ("200 OK", "application/octet-stream", b),
            None => ("404 Not Found", "text/plain", b"no such search".to_vec()),
        },
        _ => { let (status, kind, body) = match path {
        "/" => ("200 OK", "text/html; charset=utf-8", INDEX.to_string()),
        "/app.js" => ("200 OK", "text/javascript; charset=utf-8", APP.to_string()),
        "/app.css" => ("200 OK", "text/css; charset=utf-8", STYLE.to_string()),
        "/api/state" => ("200 OK", "application/json", state(root).to_string()),
        "/api/log" => match log(root, query) {
            Some(text) => ("200 OK", "text/plain; charset=utf-8", text),
            None => ("404 Not Found", "text/plain", "no such log".into()),
        },
        _ => ("404 Not Found", "text/plain", "not found".into()),
        }; (status, kind, body.into_bytes()) }
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len())?;
    stream.write_all(&body)
}

fn git(root: &Path, args: &[&str]) -> String {
    Command::new("git").args(args).current_dir(root).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim_end().to_string()).unwrap_or_default()
}

fn jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// A search's words, as the trace records them (little-endian u64).
fn read_words(p: &Path) -> Option<Vec<u64>> {
    let b = std::fs::read(p).ok()?;
    if b.len() % 8 != 0 { return None; }
    Some(b.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
}

/// A search's words for the gates in WebAssembly, only from under .bon/traces:
/// path=<pid>/<search>.
fn words(root: &Path, query: &str) -> Option<Vec<u8>> {
    let rel = query.strip_prefix("path=")?.replace("%2F", "/");
    if rel.contains("..") { return None; }
    std::fs::read(root.join(".bon/traces").join(rel).join("search.words")).ok()
}

/// A trace log, only from under .bon/traces.
fn log(root: &Path, query: &str) -> Option<String> {
    let rel = query.strip_prefix("path=")?.replace("%2F", "/");
    if rel.contains("..") { return None; }
    let p = root.join(".bon/traces").join(rel);
    std::fs::read_to_string(p).ok()
}

/// Everything the page shows, assembled from disk on every request.
pub fn state(root: &Path) -> Value {
    let toml_text = git(root, &["show", "HEAD:bon.toml"]);
    let manifest: toml::Value = toml::from_str(&toml_text).unwrap_or(toml::Value::Table(Default::default()));
    let trunk_name = manifest.get("trunk").and_then(|v| v.as_str()).unwrap_or("main").to_string();
    let remote = manifest.get("remote").and_then(|v| v.as_str()).unwrap_or("origin").to_string();
    let head = git(root, &["rev-parse", "HEAD"]);
    let remote_head = git(root, &["rev-parse", &format!("{remote}/{trunk_name}")]);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());

    // Trunk: recent commits, who authored them, and whether the remote has them.
    let mut trunk = Vec::new();
    for l in git(root, &["log", "-200", "--format=%H\x1f%an\x1f%ct\x1f%s\x1f%(trailers:key=Trace,valueonly,separator=)"]).lines() {
        let f: Vec<&str> = l.split('\x1f').collect();
        if f.len() < 4 { continue; }
        let pushed = !remote_head.is_empty() && git(root, &["merge-base", "--is-ancestor", f[0], &remote_head]).is_empty()
            && Command::new("git").args(["merge-base", "--is-ancestor", f[0], &remote_head]).current_dir(root)
                .status().is_ok_and(|s| s.success());
        trunk.push(json!({
            "commit": f[0], "author": f[1], "time": f[2].parse::<u64>().unwrap_or(0), "subject": f[3],
            "trace": f.get(4).map(|t| t.trim()).unwrap_or(""), "pushed": pushed,
            "by_agent": f[1] == "agent",
        }));
    }

    // Map: each intent's status, derived as `bon` derives it.
    let scrubs = jsonl(&root.join(".bon/scrubs.jsonl"));
    let mut map = Vec::new();
    for line in git(root, &["show", "HEAD:map"]).lines() {
        let intent = line.split('\t').next().unwrap_or("").trim();
        if intent.is_empty() { continue; }
        let source = line.split_once('\t').map(|(_, s)| s.trim()).unwrap_or("");
        let landed = trunk.iter().find(|c| c["subject"] == intent);
        let scrub = scrubs.iter().filter(|v| v["intent"] == intent).last().cloned();
        let landed_time = landed.and_then(|c| c["time"].as_u64());
        let failed = scrub.as_ref().filter(|v| v["passes"] == false).and_then(|v| v["time"].as_u64());
        let status = match (landed_time, failed) {
            (_, Some(f)) if landed_time.is_none_or(|l| l < f) => "broken",
            (Some(_), _) => "built",
            _ => "open",
        };
        map.push(json!({
            "intent": intent, "source": source, "status": status,
            "landed": landed.map(|c| json!({ "commit": c["commit"], "time": c["time"], "pushed": c["pushed"] })),
            "scrub": scrub,
        }));
    }

    // Searches: every bon process's trace, newest first.
    let mut searches = Vec::new();
    let traces = root.join(".bon/traces");
    let mut pids: Vec<(u64, PathBuf)> = std::fs::read_dir(&traces).into_iter().flatten().flatten()
        .filter_map(|e| Some((e.file_name().to_string_lossy().parse::<u64>().ok()?, e.path()))).collect();
    pids.sort_by_key(|(_, p)| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    pids.reverse();
    for (pid, dir) in pids.into_iter().take(40) {
        let running = Command::new("kill").args(["-0", &pid.to_string()]).stderr(std::process::Stdio::null())
            .status().is_ok_and(|s| s.success());
        let transitions: Vec<String> = std::fs::read_to_string(dir.join("transitions")).unwrap_or_default()
            .lines().map(String::from).collect();
        let summaries = jsonl(&dir.join("searches.jsonl"));
        let mut runs: Vec<(usize, PathBuf)> = std::fs::read_dir(&dir).into_iter().flatten().flatten()
            .filter_map(|e| Some((e.file_name().to_string_lossy().parse::<usize>().ok()?, e.path()))).collect();
        runs.sort_by_key(|(n, _)| *n);
        let mut list = Vec::new();
        for (n, rdir) in runs {
            let mut candidates: Vec<(usize, Value)> = std::fs::read_dir(&rdir).into_iter().flatten().flatten()
                .filter_map(|e| {
                    let i = e.file_name().to_string_lossy().parse::<usize>().ok()?;
                    let facts: Value = serde_json::from_str(&std::fs::read_to_string(e.path().join("facts.json")).ok()?).ok()?;
                    let logs: Vec<String> = std::fs::read_dir(e.path()).into_iter().flatten().flatten()
                        .map(|f| f.file_name().to_string_lossy().to_string()).filter(|f| f != "index").collect();
                    Some((i, json!({ "index": i, "facts": facts, "logs": logs })))
                }).collect();
            candidates.sort_by_key(|(i, _)| *i);
            let summary = summaries.iter().find(|s| s["search"] == n).cloned();
            let selected = transitions.iter().find_map(|t| {
                let rest = t.strip_prefix("selected ")?;
                let (s, i) = rest.split_once(' ')?;
                (s.parse::<usize>().ok()? == n).then(|| i.parse::<usize>().ok()).flatten()
            });
            let kernel = read_words(&rdir.join("search.words")).as_ref().and_then(|w| Kernel::decode(w));
            for (i, candidate) in &mut candidates {
                // The kernel's verdict when the trace has its words; otherwise what the trace recorded.
                let recorded = candidate["facts"]["candidate"]["checks_pass"].as_bool().unwrap_or(false);
                candidate["verified"] = json!(match &kernel {
                    Some(k) => k.results.get(*i).and_then(|r| r.as_ref()).is_some_and(|c| Kernel::verified(k, c)),
                    None => recorded,
                });
            }
            list.push(json!({
                "search": n, "summary": summary, "selected": selected,
                // The search as the gates saw it, emitted by the kernel in the
                // spec's names; null in traces recorded before the kernel wrote words.
                "kernel": kernel.as_ref().and_then(|k| serde_json::from_str::<Value>(&Kernel::emit(&k).into_iter().collect::<String>()).ok()),
                "candidates": candidates.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
            }));
        }
        let modified = std::fs::metadata(&dir).and_then(|m| m.modified()).ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
        // Each fast-forward's cost, as bon recorded it; for a bon process from before
        // it recorded them, the same sum over its searches.jsonl.
        let mut fast_forwards = jsonl(&dir.join("fast_forwards.jsonl"));
        if fast_forwards.is_empty() && transitions.iter().any(|t| t.starts_with("fast_forward")) {
            let sum = |k: &str| summaries.iter().filter_map(|s| s[k].as_f64()).sum::<f64>();
            let (generation, time) = (sum("generation_dollars"), sum("time_dollars"));
            fast_forwards.push(json!({ "searches": summaries.len(), "generation_dollars": generation,
                "time_dollars": time, "cost": generation + time, "derived": true }));
        }
        searches.push(json!({ "pid": pid, "running": running, "modified": modified, "transitions": transitions,
            "searches": list, "fast_forwards": fast_forwards }));
    }

    json!({
        "repo": {
            "name": root.file_name().map(|n| n.to_string_lossy().to_string()),
            "head": head, "trunk": trunk_name, "remote": remote, "remote_head": remote_head,
            "pushed": !head.is_empty() && head == remote_head, "now": now,
        },
        "map": map,
        "spec": spec(root, &manifest),
        "processes": searches,
        "trunk": trunk,
        "host": host(),
        "manifest": serde_json::to_value(&manifest).unwrap_or(Value::Null),
    })
}

fn host() -> Value {
    let text = std::fs::read_to_string(best_of_n::trusted::HOST).unwrap_or_default();
    toml::from_str::<toml::Value>(&text).ok().and_then(|v| serde_json::to_value(v).ok()).unwrap_or(Value::Null)
}

/// The spec module, read as it is written: types, predicates, transitions,
/// properties and invariants, each with its `///` lines; transitions with the
/// state they read and update; the state's fields.
fn spec(root: &Path, manifest: &toml::Value) -> Value {
    let paths: Vec<String> = manifest.get("checks").and_then(|c| c.get("paths")).and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    let file = paths.iter().filter(|p| p.ends_with(".rs"))
        .find(|p| git(root, &["show", &format!("HEAD:{p}")]).contains("state_machine!"));
    let Some(file) = file else { return Value::Null };
    let text = git(root, &["show", &format!("HEAD:{file}")]);
    let lines: Vec<&str> = text.lines().collect();
    let mut items = Vec::new();
    let mut fields = Vec::new();
    let mut doc: Vec<String> = Vec::new();
    let mut in_fields = false;
    let name_after = |l: &str, key: &str| -> Option<String> {
        let rest = l.split(key).nth(1)?;
        Some(rest.trim_start().split(|c: char| !(c.is_alphanumeric() || c == '_')).next()?.to_string())
    };
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        if let Some(d) = l.strip_prefix("///") { doc.push(d.trim().to_string()); i += 1; continue; }
        if l.starts_with("fields {") { in_fields = true; doc.clear(); i += 1; continue; }
        if in_fields {
            if l.starts_with('}') { in_fields = false; }
            else if let Some(rest) = l.split("pub ").nth(1) {
                if let Some((name, ty)) = rest.split_once(':') {
                    let sharding = l.split("sharding(").nth(1).and_then(|s| s.split(')').next()).unwrap_or("");
                    fields.push(json!({ "name": name.trim(), "type": ty.trim().trim_end_matches(','), "sharding": sharding, "doc": doc.join(" ") }));
                }
                doc.clear();
            }
            i += 1; continue;
        }
        let item = |kind: &str, name: String, doc: &[String]| json!({ "kind": kind, "name": name, "doc": doc.join(" ") });
        if l.starts_with("pub struct ") || l.starts_with("pub enum ") || l.starts_with("pub type ") {
            let key = if l.starts_with("pub struct ") { "struct" } else if l.starts_with("pub enum ") { "enum" } else { "type" };
            if let Some(n) = name_after(l, key) { items.push(item("type", n, &doc)); }
        } else if l.contains("spec fn ") && l.starts_with("pub") {
            if let Some(n) = name_after(l, "spec fn") { items.push(item("predicate", n, &doc)); }
        } else if l.starts_with("transition!{") || l.starts_with("init!{") || l.starts_with("property!{") {
            let kind = if l.starts_with("transition!") { "transition" } else if l.starts_with("init!") { "init" } else { "property" };
            let name = l.split('{').nth(1).unwrap_or("").trim().split('(').next().unwrap_or("").trim().to_string();
            // The body, to the matching close of the macro.
            let mut body = String::new();
            let mut depth = 0i32;
            let mut j = i;
            while j < lines.len() {
                for ch in lines[j].chars() { if ch == '{' { depth += 1 } else if ch == '}' { depth -= 1 } }
                body.push_str(lines[j]); body.push('\n');
                if depth <= 0 && j > i { break; }
                j += 1;
            }
            let mut updates = Vec::new();
            let mut reads = Vec::new();
            for b in body.lines() {
                let t = b.trim();
                for key in ["update ", "init ", "add ", "remove "] {
                    if let Some(f) = t.strip_prefix(key).and_then(|r| r.split_whitespace().next()) {
                        if !updates.contains(&f.to_string()) { updates.push(f.to_string()); }
                    }
                }
                for part in t.split("pre.").skip(1) {
                    let f: String = part.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !f.is_empty() && !reads.contains(&f) { reads.push(f); }
                }
            }
            let mut v = item(kind, name, &doc);
            v["updates"] = json!(updates);
            v["reads"] = json!(reads);
            items.push(v);
            doc.clear();
            i = j + 1; continue;
        } else if l.starts_with("#[invariant]") {
            if let Some(n) = lines.get(i + 1).and_then(|n| name_after(n, "fn")) { items.push(item("invariant", n, &doc)); }
            doc.clear();
            i += 2; continue;
        }
        if !l.starts_with("#[") { doc.clear(); }
        i += 1;
    }
    json!({ "path": file, "fields": fields, "items": items })
}
