//! Transcripts dropped in the user layer's folder, routed to the repository
//! the host file names for their meeting title (queue 80). Trusted code: it
//! moves files and records what it did; it decides nothing a search reads.
//!
//! - The folder is `<user>/transcripts`, under the user layer's root.
//! - The host file's `[routes]` maps a title pattern to a repository: a title
//!   matches a pattern it contains, ignoring case. A transcript goes where its
//!   matching routes all name one repository; none, or more than one, and it
//!   is routed nowhere.
//! - A transcript's meeting title is its WebVTT header's text (`WEBVTT -
//!   Acme weekly`), else its file name without `.vtt` (a Teams export's name).
//! - Going to a repository is a move into its transcripts directory (the
//!   manifest's `transcripts`, default `transcripts`, at trunk's head), in the
//!   working tree, committed by no one: `bon queue` reads a transcript once it
//!   is on trunk, so the owner (or the model) commits and pushes it, as with
//!   any transcript.
//! - Each route is a line of `<user>/.bon/traces/routes.jsonl`, in the one
//!   shape: `{program: "route", context: <its path in the folder>, sha256,
//!   title, output: <repository root, or null>, verdict: <why it went
//!   nowhere, "moved" when it left the folder by hand, else null>, behavior:
//!   null, time}`. A line routed nowhere raises an interrupt; the transcript
//!   stays in the folder, pending, until a route moves it or the owner does.
//! - `bon pending` routes, before it lists: no daemon, no command of its own.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The folder, under the user layer's root, where transcripts are dropped.
pub const FOLDER: &str = "transcripts";

/// Where the user layer's routes are recorded, under its root.
pub const ROUTES: &str = ".bon/traces/routes.jsonl";

/// A meeting title: the text after `WEBVTT` on a WebVTT file's first line
/// (a space or tab, then the text; a leading `-` is a separator), else the
/// file's name without its extension.
pub fn title(path: &Path, text: &str) -> String {
    let header = text.trim_start_matches('\u{feff}').lines().next().unwrap_or("");
    let said = header.strip_prefix("WEBVTT").filter(|r| r.is_empty() || r.starts_with([' ', '\t']))
        .map(|r| r.trim().trim_start_matches('-').trim().to_string()).unwrap_or_default();
    if said.is_empty() { path.file_stem().map_or(String::new(), |s| s.to_string_lossy().to_string()) } else { said }
}

/// The repositories the routes whose pattern `title` contains (ignoring
/// case) name, each once, in the order of the routes.
pub fn matching(title: &str, routes: &[(String, PathBuf)]) -> Vec<PathBuf> {
    let t = title.to_lowercase();
    let mut out: Vec<PathBuf> = Vec::new();
    for (pattern, repo) in routes {
        if !pattern.is_empty() && t.contains(&pattern.to_lowercase()) && !out.contains(repo) { out.push(repo.clone()); }
    }
    out
}

/// Every route recorded in the user layer, oldest first.
pub fn records(user: &Path) -> Vec<Value> {
    std::fs::read_to_string(user.join(ROUTES)).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// A transcript's hash, as the records hold it.
fn sha256(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }

/// The hashes routed nowhere and not since resolved, by the records: each with
/// the path its last line named.
fn pending(records: &[Value]) -> Vec<(String, String)> {
    let mut open: Vec<(String, String)> = Vec::new();
    for r in records {
        let hash = r["sha256"].as_str().unwrap_or("").to_string();
        let stays = r["output"].is_null() && r["verdict"] != "moved";
        open.retain(|(h, _)| *h != hash);
        if stays { open.push((hash, r["context"].as_str().unwrap_or("").to_string())); }
    }
    open
}

/// The transcripts directory a repository's manifest names at trunk's head
/// (default `transcripts`); none where trunk's head has no manifest.
fn transcripts_of(repo: &Path) -> Option<PathBuf> {
    let text = super::git(repo, &["show", "HEAD:.bon/bon.toml"]).ok()?;
    let m: toml::Value = toml::from_str(&text).ok()?;
    Some(repo.join(m.get("transcripts").and_then(|v| v.as_str()).unwrap_or("transcripts")))
}

/// What one routing did to one transcript, for the owner to read.
pub struct Routed { pub file: String, pub to: Option<PathBuf>, pub why: Option<String> }

/// Route every transcript in the user layer's folder at `user` by `routes`,
/// at `now`: each that one repository's routes name moves into that
/// repository's transcripts directory; each other one stays, recorded once as
/// routed nowhere; each recorded nowhere that is no longer in the folder (the
/// owner moved it) is recorded moved. The folder is made when missing, so it
/// is there to drop into. Returns what changed.
pub fn route(user: &Path, routes: &[(String, PathBuf)], now: i64) -> Result<Vec<Routed>, String> {
    let folder = user.join(FOLDER);
    std::fs::create_dir_all(&folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    let mut recorded = records(user);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&folder).map_err(|e| format!("{}: {e}", folder.display()))?.flatten()
        .map(|e| e.path()).filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "vtt")).collect();
    files.sort();
    let mut out = Vec::new();
    let mut lines: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for path in files {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let hash = sha256(&bytes);
        seen.push(hash.clone());
        let name = path.file_name().map_or(String::new(), |n| n.to_string_lossy().to_string());
        let title = title(&path, &String::from_utf8_lossy(&bytes));
        let line = |output: Value, verdict: Value| json!({ "program": "route", "context": path.to_string_lossy(), "sha256": hash, "title": title,
            "output": output, "verdict": verdict, "behavior": null, "time": now });
        let to = matching(&title, routes);
        // A repository by its path under the user layer's root, else in full.
        let shown = |r: &Path| r.strip_prefix(user).map_or(r.display().to_string(), |p| p.display().to_string());
        // Where it goes, or why nowhere.
        let why = match to.as_slice() {
            [] => Err(format!("no route matches \"{title}\"")),
            [repo] => match transcripts_of(repo) {
                None => Err(format!("its route names {}, which has no .bon/bon.toml at trunk's head", shown(repo))),
                Some(dir) => {
                    let dest = dir.join(&name);
                    match std::fs::read(&dest) {
                        Ok(there) if there != bytes => Err(format!("{} already holds another file of that name", dest.display())),
                        _ => Ok((repo.clone(), dir, dest)),
                    }
                }
            },
            many => Err(format!("\"{title}\" matches routes to {} repositories: {}", many.len(), many.iter().map(|r| shown(r)).collect::<Vec<_>>().join(", "))),
        };
        match why {
            Ok((repo, dir, dest)) => {
                std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                if !dest.exists() && std::fs::rename(&path, &dest).is_err() {
                    std::fs::copy(&path, &dest).map_err(|e| format!("{} to {}: {e}", path.display(), dest.display()))?;
                }
                let _ = std::fs::remove_file(&path);
                lines.push(line(json!(repo.to_string_lossy()), Value::Null));
                out.push(Routed { file: name, to: Some(dest), why: None });
            }
            // Recorded once: a transcript already pending stays so.
            Err(why) if !pending(&recorded).iter().any(|(h, _)| *h == hash) => {
                lines.push(line(Value::Null, json!(why)));
                out.push(Routed { file: name, to: None, why: Some(why) });
            }
            Err(_) => {}
        }
        recorded.extend(lines.last().cloned().filter(|l| l["sha256"] == hash.as_str()));
    }
    // Pending ones no longer in the folder: the owner moved them.
    for (hash, context) in pending(&recorded) {
        if seen.contains(&hash) { continue; }
        let gone = json!({ "program": "route", "context": context, "sha256": hash, "title": recorded.iter().rev().find(|r| r["sha256"] == hash.as_str()).map_or(Value::Null, |r| r["title"].clone()),
            "output": null, "verdict": "moved", "behavior": null, "time": now });
        out.push(Routed { file: Path::new(&context).file_name().map_or(context.clone(), |n| n.to_string_lossy().to_string()), to: None, why: Some("moved".into()) });
        lines.push(gone);
    }
    if !lines.is_empty() {
        let file = user.join(ROUTES);
        if let Some(d) = file.parent() { std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?; }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        for l in &lines { writeln!(f, "{l}").map_err(|e| format!("{}: {e}", file.display()))?; }
    }
    Ok(out)
}

/// The routing as lines for the owner: where each transcript went, or why it
/// stayed. Empty when nothing changed.
pub fn text(routed: &[Routed]) -> String {
    routed.iter().map(|r| match (&r.to, r.why.as_deref()) {
        (Some(dest), _) => format!("routed {} to {}: commit it to trunk, then bon queue\n", r.file, dest.display()),
        (None, Some("moved")) => format!("{} left the folder\n", r.file),
        (None, why) => format!("{} stays in the folder: {}\n", r.file, why.unwrap_or("")),
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bon-route-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A repository whose trunk's manifest names `dir` as its transcripts.
    fn repository(at: &Path, dir: Option<&str>) {
        std::fs::create_dir_all(at.join(".bon")).unwrap();
        let g = |a: &[&str]| assert!(std::process::Command::new("git").args(a).current_dir(at).output().unwrap().status.success(), "{a:?}");
        g(&["init", "-q", "-b", "main"]);
        std::fs::write(at.join(".bon/bon.toml"), dir.map_or(String::new(), |d| format!("transcripts = \"{d}\"\n"))).unwrap();
        g(&["add", "-A"]);
        g(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "manifest"]);
    }

    #[test]
    fn a_title_is_the_header_text_else_the_file_name() {
        assert_eq!(title(Path::new("/x/Acme weekly.vtt"), "WEBVTT\n\n00:00.000 --> 00:01.000\nhi\n"), "Acme weekly");
        assert_eq!(title(Path::new("/x/a.vtt"), "\u{feff}WEBVTT - Acme sync\n"), "Acme sync");
        assert_eq!(title(Path::new("/x/a.vtt"), "WEBVTTX\n"), "a");
    }

    #[test]
    fn a_title_matches_a_pattern_it_contains_ignoring_case_and_goes_only_where_one_repository_is_named() {
        let routes = vec![("acme".to_string(), PathBuf::from("/r/acme")), ("Weekly".to_string(), PathBuf::from("/r/acme")), ("beta".to_string(), PathBuf::from("/r/beta"))];
        assert_eq!(matching("ACME Weekly sync", &routes), vec![PathBuf::from("/r/acme")]);
        assert_eq!(matching("Acme and Beta", &routes).len(), 2);
        assert!(matching("Gamma", &routes).is_empty());
    }

    #[test]
    fn a_transcript_moves_to_its_repository_or_stays_pending_until_routed_or_moved() {
        let user = tmp("user");
        repository(&user.join("acme"), Some("calls"));
        let routes = vec![("acme".to_string(), user.join("acme"))];
        let folder = user.join(FOLDER);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("Acme weekly.vtt"), "WEBVTT\n").unwrap();
        std::fs::write(folder.join("Gamma intro.vtt"), "WEBVTT\n\nx\n").unwrap();
        std::fs::write(folder.join("notes.txt"), "not a transcript").unwrap();
        let r = route(&user, &routes, 100).unwrap();
        assert_eq!(r.len(), 2);
        // Moved into the transcripts directory the manifest names; the other stays, recorded nowhere.
        assert!(user.join("acme/calls/Acme weekly.vtt").is_file() && !folder.join("Acme weekly.vtt").exists());
        assert!(folder.join("Gamma intro.vtt").is_file() && folder.join("notes.txt").is_file());
        let rec = records(&user);
        assert_eq!(rec.len(), 2);
        for k in ["program", "context", "output", "verdict", "behavior", "sha256", "title", "time"] { assert!(rec.iter().all(|l| l.get(k).is_some()), "{k}"); }
        assert_eq!(rec[0]["output"].as_str(), user.join("acme").to_str());
        assert!(rec[1]["output"].is_null() && rec[1]["title"] == "Gamma intro");
        // Run again: nothing new is recorded; the pending one stays pending.
        assert!(route(&user, &routes, 200).unwrap().is_empty());
        assert_eq!(records(&user).len(), 2);
        // A route for it: it moves (here, to the default transcripts directory), and the line resolves it.
        repository(&user.join("gamma"), None);
        let more = vec![routes[0].clone(), ("gamma".to_string(), user.join("gamma"))];
        assert!(route(&user, &more, 300).unwrap()[0].to.is_some());
        assert!(user.join("gamma/transcripts/Gamma intro.vtt").is_file());
        // Dropped again, unrouted, then moved out by hand: recorded moved.
        std::fs::write(folder.join("Delta.vtt"), "WEBVTT\n\nd\n").unwrap();
        route(&user, &more, 400).unwrap();
        std::fs::rename(folder.join("Delta.vtt"), user.join("Delta.vtt")).unwrap();
        let r = route(&user, &more, 500).unwrap();
        assert_eq!(r[0].why.as_deref(), Some("moved"));
        let last = records(&user).pop().unwrap();
        assert!(last["output"].is_null() && last["verdict"] == "moved" && last["time"] == 500);
        assert!(pending(&records(&user)).is_empty());
        let _ = std::fs::remove_dir_all(&user);
    }

    #[test]
    fn a_name_taken_by_another_file_keeps_the_transcript_in_the_folder() {
        let user = tmp("taken");
        repository(&user.join("acme"), None);
        std::fs::create_dir_all(user.join("acme/transcripts")).unwrap();
        std::fs::write(user.join("acme/transcripts/Acme.vtt"), "WEBVTT\n\nolder\n").unwrap();
        std::fs::create_dir_all(user.join(FOLDER)).unwrap();
        std::fs::write(user.join(FOLDER).join("Acme.vtt"), "WEBVTT\n\nnewer\n").unwrap();
        let r = route(&user, &[("acme".to_string(), user.join("acme"))], 1).unwrap();
        assert!(r[0].to.is_none() && r[0].why.as_deref().unwrap().contains("already holds"), "{:?}", r[0].why);
        assert!(user.join(FOLDER).join("Acme.vtt").is_file());
        let _ = std::fs::remove_dir_all(&user);
    }
}
