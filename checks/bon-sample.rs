//! bon-sample's tests: program code's declared checks, engineer's, so no
//! search that may change bon-sample may change them. They include its source
//! as a module.

#[path = "../src/bin/bon-sample.rs"]
#[allow(dead_code)]
mod bon_sample;

use bon_sample::*;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
    // queue 55: the client and the context budget come from the role, through bon's environment.
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let role = |k: &str| match k { "BON_CLIENT" => Some("claude".to_string()), "BON_CONTEXT" => Some("10".to_string()), _ => None };
    let a = parse_args(&s(&["--model", "m"]), &role).unwrap();
    assert_eq!((a.client, a.model.as_str(), a.max_context), (Client::Claude, "m", 10 * BYTES_PER_TOKEN));
    let api = |k: &str| (k == "BON_CLIENT").then(|| "api".to_string());
    assert_eq!(parse_args(&s(&["--model", "m"]), &api).unwrap().max_context, DEFAULT_CONTEXT_TOKENS * BYTES_PER_TOKEN);
    // The default, at the 2.4 bytes a token measured, is under Haiku's 100,000-token tier line.
    assert!(DEFAULT_CONTEXT_TOKENS * BYTES_PER_TOKEN * 10 / 24 < 100_000);
    assert!(parse_args(&s(&["--model", "m"]), &|_| None).unwrap_err().contains("BON_CLIENT"));
    assert!(parse_args(&s(&["--model", "m"]), &|k| (k == "BON_CLIENT").then(|| "x".to_string())).is_err());
    assert!(parse_args(&s(&[]), &role).is_err());
    assert!(parse_args(&s(&["--via", "api", "--model", "m"]), &role).is_err(), "no --via: the role says the client");
}

/// A host file whose [api] is `address`, its key in a file of its own: the file.
fn host_with_api(address: &str, key: &str) -> String {
    let d = scratch();
    std::fs::write(d.join("key"), key).unwrap();
    let host = d.join("host.toml");
    std::fs::write(&host, format!("path = []\n[api]\naddress = {address:?}\nkey_file = {:?}\n", d.join("key").to_string_lossy())).unwrap();
    host.to_string_lossy().to_string()
}

/// A directory holding `name`, a program that reads its stdin and prints `lines`:
/// a PATH on which it is that client, the system's tools after it.
fn client_on_path(name: &str, lines: &[String]) -> String {
    let d = scratch();
    let quoted: Vec<String> = lines.iter().map(|l| format!("'{l}'")).collect();
    std::fs::write(d.join(name), format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' {}\n", quoted.join(" "))).unwrap();
    std::fs::set_permissions(d.join(name), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    format!("{}:/usr/bin:/bin", d.display())
}

#[test]
fn a_failing_check_s_locations_name_their_files_and_a_named_file_is_never_dropped_for_another() {
    // queue 74: `src/exec.rs:1300:5` in a check's output names src/exec.rs.
    let d = scratch();
    write(&d, "src/a.rs", b"fn a() {}\n");
    write(&d, "src/exec.rs", &vec![b'x'; 3000]);
    write(&d, "src/z.rs", b"fn z() {}\n");
    let prompt = "This check fails on trunk: cargo verus verify\nerror: postcondition not satisfied\n   --> src/exec.rs:1300:5\n";
    let files = tree(&d);
    assert_eq!(named(prompt, &files), ["src/exec.rs"]);
    // Named, it comes first, past the per-file cap.
    let c = context(&d, prompt, 10_000, 1000);
    assert_eq!(c.included, ["src/exec.rs", "src/a.rs", "src/z.rs"]);
    // Over the budget, it is not shown, and then neither is any file the task does not name.
    let c = context(&d, prompt, 100, 1000);
    assert!(c.included.is_empty(), "{:?}", c.included);
    assert!(c.omitted.contains(&("src/exec.rs".to_string(), "over the context budget")));
    assert!(c.omitted.contains(&("src/a.rs".to_string(), "over the context budget")));
}

#[test]
fn the_context_says_which_files_cannot_be_changed() {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch();
    write(&d, "src/spec.rs", b"spec\n");
    write(&d, "src/lib.rs", b"lib\n");
    std::fs::set_permissions(d.join("src/spec.rs"), std::fs::Permissions::from_mode(0o444)).unwrap();
    let c = context(&d, "task", 10_000, 1000);
    assert_eq!(c.fixed, ["src/spec.rs"]);
    assert!(c.repository.contains("You cannot change these files (the checks, and what else bon protects): an edit to any of them is refused: src/spec.rs\n"));
    std::fs::set_permissions(d.join("src/spec.rs"), std::fs::Permissions::from_mode(0o644)).unwrap();
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
    let _ = key;
    // queue 55: the address and the key's file are the host file's [api].
    let host = host_with_api(&url, "sk-test-key\n");
    let env = move |k: &str| match k { "BON_HOST" => Some(host.clone()), "BON_CLIENT" => Some("api".into()), _ => None };
    let argv: Vec<String> = ["--model", "claude-haiku-5-5", "--max-output-tokens", "1000"].iter().map(|s| s.to_string()).collect();
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
    // No price here: no cost figure, so bon's own stands alone; one request.
    assert!(u.get("costUSD").is_none());
    assert_eq!(last["requests"], 1);
    assert!(o.stdout.starts_with("@@@ FILE src/lib.rs"));
}

#[test]
fn api_errors_change_nothing() {
    let d = scratch();
    write(&d, "a.txt", b"a\n");
    let key = scratch().join("key");
    std::fs::write(&key, "k").unwrap();
    let (url, server) = mock("400 Bad Request", r#"{"type":"error","error":{"type":"invalid_request_error","message":"no"}}"#.into());
    let _ = key;
    let host = host_with_api(&url, "k");
    let env = move |k: &str| match k { "BON_HOST" => Some(host.clone()), "BON_CLIENT" => Some("api".into()), _ => None };
    let argv: Vec<String> = ["--model", "m"].iter().map(|s| s.to_string()).collect();
    let o = run(&argv, "task", &d, &env);
    server.join().unwrap();
    assert!(o.error.unwrap().contains("HTTP 400"));
    assert_eq!(read(&d, "a.txt"), "a\n");
}

#[test]
fn a_reply_that_does_not_apply_still_reports_usage() {
    let d = scratch();
    write(&d, "a.txt", b"a\n");
    let result = serde_json::json!({ "type": "result", "subtype": "success", "is_error": false, "result": block("a.txt", "nope\n", "b\n"),
                                     "modelUsage": { "claude-haiku-5-5": { "inputTokens": 3, "outputTokens": 5, "costUSD": 0.001 } } });
    // queue 55: the claude client is whatever `claude` the PATH finds.
    let path = client_on_path("claude", &[result.to_string()]);
    let env = move |k: &str| match k { "PATH" => Some(path.clone()), "BON_CLIENT" => Some("claude".into()), _ => None };
    let argv: Vec<String> = ["--model", "claude-haiku-5-5"].iter().map(|s| s.to_string()).collect();
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
    let msg = serde_json::json!({ "type": "item.completed", "item": { "type": "agent_message", "text": block("a.txt", "a\n", "b\n") } });
    let turn = serde_json::json!({ "type": "turn.completed", "usage": { "input_tokens": 100, "cached_input_tokens": 60, "output_tokens": 7 } });
    let path = client_on_path("codex", &[msg.to_string(), turn.to_string()]);
    let env = move |k: &str| match k { "PATH" => Some(path.clone()), "BON_CLIENT" => Some("codex".into()), _ => None };
    let argv: Vec<String> = ["--model", "gpt-6.1-sol"].iter().map(|s| s.to_string()).collect();
    let o = run(&argv, "task", &d, &env);
    assert_eq!(o.error, None);
    assert_eq!(read(&d, "a.txt"), "b\n");
    let last: serde_json::Value = serde_json::from_str(o.stdout.lines().last().unwrap()).unwrap();
    let u = &last["modelUsage"]["gpt-6.1-sol"];
    assert_eq!((u["inputTokens"].as_u64(), u["cacheReadInputTokens"].as_u64()), (Some(40), Some(60)));
}
