//! bon account: one account of what is true of the code. Every file, tool,
//! dependency and claimed control is proven (in the kernel, verified by
//! Verus), trusted (reviewed by the owner, not verified), configured (a fact of
//! the manifest) or tested (judged by the checks). It is read from the
//! manifest's `[account]`, the spec and gates as Verus expresses them, the
//! trusted files, the lockfiles and each tool's version, and written as an OSCAL
//! component definition with a CycloneDX SBOM beside it. Trusted code.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The OSCAL version the document follows.
const OSCAL: &str = "1.2.3";
/// The OSCAL document; the SBOM is `best_of_n::trusted::SBOM`.
pub const DOCUMENT: &str = ".bon/account.json";
const STATUSES: [&str; 4] = ["proven", "trusted", "configured", "tested"];
/// What each status means, as the document says it.
const MEANING: &str = "proven: in the kernel, verified by Verus. trusted: reviewed by the owner, not verified. \
configured: a fact of the manifest. tested: program code and every other file, judged by the checks. \
Every control claim is proposed and awaits GRC review.";

/// bon's own property namespace: OSCAL's admits only the names NIST lists.
fn ns() -> String { format!("{}/account", env!("CARGO_PKG_REPOSITORY")) }

/// One thing a claim may name as evidence: its status, its kind, its name.
#[derive(Clone)]
struct Item { status: &'static str, class: &'static str, name: String }

struct Control { id: String, claim: String, evidence: Vec<Item> }

struct Account {
    name: String,
    description: String,
    catalog: Option<String>,
    /// Every item a claim may name, gates first so a gate wins over its predicate.
    items: Vec<Item>,
    /// The commands that judge tested files.
    tests: Vec<String>,
    controls: Vec<Control>,
    /// name, version command, version.
    tools: Vec<(String, String, String)>,
    services: Vec<(String, String)>,
    /// The lockfiles the dependencies come from, and the dependencies as CycloneDX components.
    lockfiles: Vec<String>,
    dependencies: Vec<Value>,
}

/// `bon account [--check]`.
pub fn run(root: &str, check: bool) -> Result<(), String> {
    let r = Path::new(root);
    let account = read(r)?;
    let sbom = text(&cyclonedx(&account)?);
    let committed = |p: &str| std::fs::read_to_string(r.join(p)).ok();
    let (old_doc, old_sbom) = (committed(DOCUMENT), committed(best_of_n::trusted::SBOM));
    let doc = text(&oscal(&account, &sbom, old_doc.as_deref()));
    if check {
        if old_doc.as_deref() == Some(doc.as_str()) && old_sbom.as_deref() == Some(sbom.as_str()) {
            println!("{DOCUMENT} and {} match", best_of_n::trusted::SBOM);
            return Ok(());
        }
        let parse = |t: Option<&String>| t.and_then(|t| serde_json::from_str::<Value>(t).ok()).unwrap_or(Value::Null);
        let was = facts(&parse(old_doc.as_ref()), &parse(old_sbom.as_ref()));
        let is = facts(&parse(Some(&doc)), &parse(Some(&sbom)));
        for line in changes(&was, &is) { println!("{line}"); }
        return Err("the account is stale; run bon account and commit .bon/".into());
    }
    let unchanged = old_doc.as_deref() == Some(doc.as_str()) && old_sbom.as_deref() == Some(sbom.as_str());
    if !unchanged {
        std::fs::create_dir_all(r.join(".bon")).map_err(|e| e.to_string())?;
        std::fs::write(r.join(DOCUMENT), &doc).map_err(|e| format!("{DOCUMENT}: {e}"))?;
        std::fs::write(r.join(best_of_n::trusted::SBOM), &sbom).map_err(|e| format!("{}: {e}", best_of_n::trusted::SBOM))?;
    }
    print!("{}", summary(&account));
    println!("{} {DOCUMENT} and {}", if unchanged { "unchanged:" } else { "wrote" }, best_of_n::trusted::SBOM);
    Ok(())
}

fn text(v: &Value) -> String { serde_json::to_string_pretty(v).unwrap_or_default() + "\n" }

fn strings(v: Option<&toml::Value>) -> Vec<String> {
    v.and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// path is p, or under p when p is a directory.
fn under(p: &str, path: &str) -> bool {
    let d = p.trim_end_matches('/');
    path == d || path.starts_with(&format!("{d}/"))
}

/// The account, from the working tree.
fn read(r: &Path) -> Result<Account, String> {
    let file = |p: &str| std::fs::read_to_string(r.join(p)).map_err(|e| format!("{p}: {e}"));
    let manifest: toml::Value = toml::from_str(&file(best_of_n::trusted::MANIFEST)?).map_err(|e| format!("{}: {e}", best_of_n::trusted::MANIFEST))?;
    let table = manifest.get("account").ok_or("no [account] in .bon/bon.toml; add one, as bon init writes it in a new repository (name, trusted, tools)")?;
    let key = |k: &str| table.get(k).and_then(|v| v.as_str()).map(String::from);
    let default_name = r.canonicalize().unwrap_or_else(|_| r.to_path_buf()).file_name().unwrap_or_default().to_string_lossy().to_string();
    let name = key("name").unwrap_or(default_name);
    let checks = strings(manifest.get("checks").and_then(|c| c.get("paths")));
    let listed = strings(table.get("trusted"));
    for p in listed.iter().chain(&checks) {
        if !r.join(p).exists() { return Err(format!("{} names {p}, which does not exist", if listed.contains(p) { "account.trusted" } else { "checks.paths" })); }
    }
    // Outside trusted code and the checks, nothing may skip a proof.
    let declared: Vec<String> = listed.iter().chain(&checks).cloned().collect();
    let skipped = best_of_n::trusted::holes(r, &declared);
    if !skipped.is_empty() {
        return Err(format!("a proof is skipped outside trusted code and the checks: {}; prove it, or add the file to account.trusted", skipped.join(", ")));
    }
    // proven: a Rust file with a verus! block in the package the root builds, outside the trusted list.
    let proven: Vec<String> = rust_files(r).into_iter()
        .filter(|f| !listed.iter().any(|t| under(t, f)) && in_root_package(r, f))
        .filter(|f| std::fs::read_to_string(r.join(f)).is_ok_and(|t| t.lines().any(|l| l.trim_start().starts_with("verus!"))))
        .collect();
    // trusted: the list, and every check that is not proven (the owner's, which nothing verifies).
    let mut trusted = listed.clone();
    for c in &checks { if !proven.contains(c) && !trusted.contains(c) { trusted.push(c.clone()); } }

    let mut items: Vec<Item> = Vec::new();
    let mut add = |status: &'static str, class: &'static str, name: String| items.push(Item { status, class, name });
    // proven: the gates, then the spec's items, then the files.
    let spec_file = checks.iter().find(|p| p.ends_with(".rs") && file(p).is_ok_and(|t| t.contains("state_machine!")));
    if let Some(sf) = spec_file {
        let system = crate::view::system(r, "HEAD", &manifest);
        for n in system["nodes"].as_array().into_iter().flatten().filter(|n| n["id"].as_str().is_some_and(|i| i.starts_with("gate:"))) {
            add("proven", "gate", n["name"].as_str().unwrap_or_default().to_string());
        }
        let outline = crate::view::outline(sf, &file(sf)?);
        for kind in ["invariant", "property", "transition", "init", "predicate", "type"] {
            for i in outline["items"].as_array().into_iter().flatten().filter(|i| i["kind"] == kind) {
                let class = match kind { "init" => "transition", "invariant" => "invariant", "property" => "property", "transition" => "transition", "predicate" => "predicate", _ => "type" };
                add("proven", class, i["name"].as_str().unwrap_or_default().to_string());
            }
        }
    }
    for f in &proven { add("proven", "file", f.clone()); }
    // trusted: the files, and the functions in them Verus does not check.
    for f in &trusted { add("trusted", "file", f.clone()); }
    for f in trusted.iter().filter(|f| f.ends_with(".rs")) {
        for n in unchecked(&file(f)?) { add("trusted", "trusted-function", n); }
    }
    // configured: bon's directory, and every key of the manifest.
    add("configured", "file", ".bon/".into());
    fn keys(prefix: &str, v: &toml::Value, out: &mut Vec<String>) {
        if let Some(t) = v.as_table() {
            for (k, x) in t {
                let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                out.push(path.clone());
                keys(&path, x, out);
            }
        }
    }
    let mut manifest_keys = Vec::new();
    keys("", &manifest, &mut manifest_keys);
    for k in manifest_keys { add("configured", "manifest-key", k); }

    let tests = strings(manifest.get("checks").and_then(|c| c.get("test")));
    let mut controls = Vec::new();
    for (id, c) in table.get("controls").and_then(|c| c.as_table()).into_iter().flatten() {
        if !id.chars().next().is_some_and(|c| c.is_alphabetic()) || !id.chars().all(|c| c.is_alphanumeric() || ".-_".contains(c)) {
            return Err(format!("account.controls.{id}: a control id is a catalog's id, such as ac-3"));
        }
        let claim = c.get("claim").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())
            .ok_or_else(|| format!("account.controls.{id}: no claim"))?.to_string();
        if let Some(k) = c.as_table().and_then(|t| t.keys().find(|k| *k != "claim" && !STATUSES.contains(&k.as_str()))) {
            return Err(format!("account.controls.{id}: {k} is not claim or a status"));
        }
        let mut evidence = Vec::new();
        for status in STATUSES {
            for name in strings(c.get(status)) {
                evidence.push(resolve(r, &items, status, &name).map_err(|e| format!("account.controls.{id}: {e}"))?);
            }
        }
        if evidence.is_empty() { return Err(format!("account.controls.{id}: no evidence; name what is proven, trusted, configured or tested")); }
        controls.push(Control { id: id.clone(), claim, evidence });
    }
    let catalog = key("catalog");
    if !controls.is_empty() && catalog.is_none() { return Err("account.catalog: name the catalog the controls are from".into()); }

    // The tools, at the version each reports, as a check runs them; then the host's own.
    let mut tools = Vec::new();
    for (n, command) in table.get("tools").and_then(|v| v.as_table()).into_iter().flatten() {
        let command = command.as_str().ok_or_else(|| format!("account.tools.{n} must be a command string"))?;
        let out = as_check(command);
        let version = if n == "verus" { out.lines().find_map(|l| l.split_once("Version:").map(|(_, v)| v.trim().to_string())) } else { out.lines().next().map(|l| l.trim().to_string()) };
        tools.push((n.clone(), command.to_string(), version.filter(|v| !v.is_empty()).unwrap_or_else(|| "absent".into())));
    }
    for (n, program, args) in [("git", "git", &["--version"][..]), ("macOS", "sw_vers", &["-productVersion"][..])] {
        if !tools.iter().any(|t| t.0 == n) { tools.push((n.into(), format!("{program} {}", args.join(" ")), first(&output(program, args)))); }
    }
    let mut services = Vec::new();
    for (n, endpoint) in table.get("services").and_then(|v| v.as_table()).into_iter().flatten() {
        services.push((n.clone(), endpoint.as_str().ok_or_else(|| format!("account.services.{n} must be an endpoint string"))?.to_string()));
    }
    let (lockfiles, dependencies) = dependencies(r)?;
    Ok(Account { name, description: key("description").unwrap_or_default(), catalog, items, tests, controls, tools, services, lockfiles, dependencies })
}

/// The item a claim names under status: it must exist with that status.
fn resolve(r: &Path, items: &[Item], status: &'static str, name: &str) -> Result<Item, String> {
    if let Some(i) = items.iter().find(|i| i.status == status && i.name == name) { return Ok(i.clone()); }
    if let Some(i) = items.iter().find(|i| i.name == name) { return Err(format!("{status} {name} is {}, not {status}", i.status)); }
    // tested: a file that exists and has no other status.
    if status == "tested" && r.join(name).is_file() && !items.iter().any(|i| i.class == "file" && under(&i.name, name)) {
        return Ok(Item { status, class: "file", name: name.into() });
    }
    Err(format!("{status} {name} does not exist"))
}

/// The names of the functions and types in `text` that Verus does not check.
fn unchecked(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut next = false;
    for l in text.lines().map(str::trim).filter(|l| !l.starts_with("//")) {
        if l.starts_with("#[verifier::external_body]") || l.starts_with("#[verifier::external]") { next = true; }
        if next {
            if let Some(n) = l.split("fn ").nth(1).or_else(|| l.split("struct ").nth(1)) {
                out.push(n.split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("").to_string());
                next = false;
            }
        }
    }
    out.retain(|n| !n.is_empty());
    out.dedup();
    out
}

/// Every Rust file under r, but in dot-directories, target and node_modules, sorted.
fn rust_files(r: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let (p, name) = (e.path(), e.file_name().to_string_lossy().to_string());
            if p.is_dir() { if !name.starts_with('.') && name != "target" && name != "node_modules" { walk(&p, root, out); } }
            else if name.ends_with(".rs") { out.push(p.strip_prefix(root).unwrap_or(&p).to_string_lossy().to_string()); }
        }
    }
    let mut out = Vec::new();
    walk(r, r, &mut out);
    out.sort();
    out
}

/// No Cargo.toml lies between f and the root: f is the root package's, which the checks verify.
fn in_root_package(r: &Path, f: &str) -> bool {
    r.join("Cargo.toml").is_file() && Path::new(f).ancestors().skip(1).filter(|a| !a.as_os_str().is_empty()).all(|a| !r.join(a).join("Cargo.toml").exists())
}

fn output(program: &str, args: &[&str]) -> String {
    // From /tmp: a check slot's user cannot enter engineer's repository, and rustup reads the current directory.
    Command::new(program).args(args).current_dir("/tmp").output().ok().filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(if o.stdout.is_empty() { &o.stderr } else { &o.stdout }).trim().to_string())
        .filter(|v| !v.is_empty()).unwrap_or_else(|| "absent".into())
}

fn first(s: &str) -> String { s.lines().next().unwrap_or("absent").trim().to_string() }

/// A tool's version command, as this process's user, in the environment a
/// check runs with (the checks' PATH and the toolchain's homes, from the host
/// file): what the checks judge with, the same whether engineer asks or a
/// check slot's user does, in one of bon's own checks. A tool no check can
/// run (one under agent's home) is absent.
fn as_check(command: &str) -> String {
    let env = best_of_n::trusted::check_environment();
    let mut a: Vec<&str> = vec!["-i"];
    a.extend(env.iter().map(String::as_str));
    a.extend(["sh", "-c", command]);
    output("env", &a)
}

/// The dependencies the lockfiles at the root pin, as CycloneDX components.
fn dependencies(r: &Path) -> Result<(Vec<String>, Vec<Value>), String> {
    let read = |p: &str| std::fs::read_to_string(r.join(p)).map_err(|e| format!("{p}: {e}"));
    // Keep namespace slashes, but escape reserved characters in package names and versions.
    let encode = |s: &str| -> String { s.bytes().map(|b| {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }
    }).collect() };
    let library = |kind: &str, name: &str, version: &str| json!({
        "type": "library", "name": name, "version": version, "purl": format!("pkg:{kind}/{}@{}", encode(name), encode(version))
    });
    let (mut lockfiles, mut components) = (Vec::new(), Vec::new());
    if r.join("Cargo.lock").exists() {
        lockfiles.push("Cargo.lock".to_string());
        let lock: toml::Value = toml::from_str(&read("Cargo.lock")?).map_err(|e| format!("Cargo.lock: {e}"))?;
        for p in lock.get("package").and_then(|v| v.as_array()).into_iter().flatten() {
            let (Some(name), Some(version)) = (p.get("name").and_then(|v| v.as_str()), p.get("version").and_then(|v| v.as_str())) else { continue };
            let mut c = library("cargo", name, version);
            if let Some(sum) = p.get("checksum").and_then(|v| v.as_str()) { c["hashes"] = json!([{ "alg": "SHA-256", "content": sum }]); }
            components.push(c);
        }
    }
    if r.join("package-lock.json").exists() {
        lockfiles.push("package-lock.json".to_string());
        let lock: Value = serde_json::from_str(&read("package-lock.json")?).map_err(|e| format!("package-lock.json: {e}"))?;
        for (path, p) in lock.get("packages").and_then(|v| v.as_object()).into_iter().flatten() {
            if path.is_empty() { continue; }
            let Some(version) = p.get("version").and_then(|v| v.as_str()) else { continue };
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or_else(|| path.rsplit("node_modules/").next().unwrap_or(path));
            let c = library("npm", name, version);
            if !components.contains(&c) { components.push(c); }
        }
    }
    if r.join("go.sum").exists() {
        lockfiles.push("go.sum".to_string());
        for l in read("go.sum")?.lines() {
            let mut fields = l.split_whitespace();
            let (Some(name), Some(version)) = (fields.next(), fields.next()) else { continue };
            let c = library("golang", name, version.trim_end_matches("/go.mod"));
            if !components.contains(&c) { components.push(c); }
        }
    }
    Ok((lockfiles, components))
}

/// The SBOM: the dependencies, the tools and the services, in CycloneDX 1.5.
fn cyclonedx(a: &Account) -> Result<Value, String> {
    let mut components = a.dependencies.clone();
    for (n, _, version) in &a.tools {
        let kind = if n == "macOS" { "operating-system" } else { "application" };
        components.push(json!({ "type": kind, "name": n, "version": version, "group": "tcb" }));
    }
    let mut properties = vec![json!({ "name": "bon:version", "value": env!("CARGO_PKG_VERSION") })];
    for i in a.items.iter().filter(|i| i.status == "trusted" && i.class == "file") { properties.push(json!({ "name": "bon:trusted-file", "value": i.name })); }
    let functions: Vec<&str> = a.items.iter().filter(|i| i.class == "trusted-function").map(|i| i.name.as_str()).collect();
    properties.push(json!({ "name": "bon:trusted-functions", "value": functions.join(",") }));
    let services: Vec<Value> = a.services.iter().map(|(n, e)| json!({ "name": n, "endpoints": [e], "group": "program" })).collect();
    Ok(json!({
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": { "component": { "type": "application", "name": a.name }, "properties": properties },
        "components": components, "services": services,
    }))
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// A UUID from SHA-256 of `key`, in version 4's form (OSCAL admits 4 or 5): the same key, the same id.
fn uuid(key: &str) -> String {
    let mut b: Vec<u8> = Sha256::digest(key.as_bytes())[..16].to_vec();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Now, as an OSCAL date-time in UTC.
fn now() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    format!("{}T{:02}:{:02}:{:02}Z", crate::view::date(t), t / 3600 % 24, t / 60 % 60, t % 60)
}

/// The OSCAL component definition. Its version is its content's hash; its
/// last-modified is kept from `old` while that hash is unchanged.
fn oscal(a: &Account, sbom: &str, old: Option<&str>) -> Value {
    let ns = ns();
    let id = |subject: &str| uuid(&format!("{}:{subject}", a.name));
    let prop = |name: &str, class: &str, value: &str| json!({ "ns": ns, "name": name, "class": class, "value": value });
    let mut props: Vec<Value> = a.items.iter().filter(|i| i.class == "file").map(|i| prop(i.status, "file", &i.name)).collect();
    props.push(prop("tested", "rule", "every other file"));
    for t in &a.tests { props.push(prop("tested", "check", t)); }
    let sbom_id = id("sbom");
    let mut root = json!({ "uuid": id("component"), "type": "software", "title": a.name,
        "description": if a.description.is_empty() { a.name.clone() } else { a.description.clone() },
        "props": props, "links": [{ "href": format!("#{sbom_id}"), "rel": "sbom" }] });
    if !a.controls.is_empty() {
        let requirements: Vec<Value> = a.controls.iter().map(|c| {
            let mut p = vec![prop("review", "claim", "proposed")];
            p.extend(c.evidence.iter().map(|e| prop(e.status, e.class, &e.name)));
            json!({ "uuid": id(&format!("control:{}", c.id)), "control-id": c.id, "description": c.claim, "props": p, "remarks": "Proposed; awaiting GRC review." })
        }).collect();
        root["control-implementations"] = json!([{ "uuid": id("controls"), "source": a.catalog,
            "description": "Claims proposed for review, each naming its evidence by status.", "implemented-requirements": requirements }]);
    }
    let mut components = vec![root];
    for (n, command, version) in &a.tools {
        components.push(json!({ "uuid": id(&format!("tool:{n}")), "type": "software", "title": n, "description": command,
            "props": [{ "name": "version", "value": version }, prop("configured", "tool", n)] }));
    }
    for (n, endpoint) in &a.services {
        components.push(json!({ "uuid": id(&format!("service:{n}")), "type": "service", "title": n, "description": endpoint,
            "links": [{ "href": endpoint }], "props": [prop("configured", "service", n)] }));
    }
    let mut resource = json!({ "uuid": sbom_id, "title": "Software bill of materials (CycloneDX 1.5)",
        "rlinks": [{ "href": "sbom.json", "media-type": "application/vnd.cyclonedx+json",
                     "hashes": [{ "algorithm": "SHA-256", "value": hex(&Sha256::digest(sbom.as_bytes())) }] }] });
    if !a.lockfiles.is_empty() { resource["props"] = json!(a.lockfiles.iter().map(|l| prop("configured", "dependencies", l)).collect::<Vec<_>>()); }
    let mut doc = json!({ "component-definition": { "uuid": "", "metadata": {
            "title": a.name, "last-modified": "", "version": "", "oscal-version": OSCAL, "remarks": MEANING },
        "components": components, "back-matter": { "resources": [resource] } } });
    let hash = hex(&Sha256::digest(text(&doc).as_bytes()));
    let version = hash[..12].to_string();
    let old: Option<Value> = old.and_then(|t| serde_json::from_str(t).ok());
    let kept = old.as_ref().filter(|o| o["component-definition"]["metadata"]["version"] == version.as_str())
        .and_then(|o| o["component-definition"]["metadata"]["last-modified"].as_str().map(String::from));
    let d = &mut doc["component-definition"];
    d["uuid"] = json!(uuid(&hash));
    d["metadata"]["version"] = json!(version);
    d["metadata"]["last-modified"] = json!(kept.unwrap_or_else(now));
    doc
}

/// What the documents say, item by item: a name, and what it is.
fn facts(doc: &Value, sbom: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let d = &doc["component-definition"];
    let components = d["components"].as_array().cloned().unwrap_or_default();
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    for c in &components {
        for p in c["props"].as_array().into_iter().flatten() {
            match (s(&p["class"]).as_str(), c["type"].as_str()) {
                ("file", _) => { out.insert(format!("file {}", s(&p["value"])), s(&p["name"])); }
                ("check", _) => { out.insert(format!("check {}", s(&p["value"])), s(&p["name"])); }
                _ => {}
            }
        }
        if let Some(n) = c["title"].as_str() {
            let kind = c["props"].as_array().into_iter().flatten().find(|p| p["name"] == "configured").map(|p| s(&p["class"])).unwrap_or_default();
            match kind.as_str() {
                "tool" => { out.insert(format!("tool {n}"), c["props"].as_array().into_iter().flatten().find(|p| p["name"] == "version").map(|p| s(&p["value"])).unwrap_or_default()); }
                "service" => { out.insert(format!("service {n}"), s(&c["description"])); }
                _ => {}
            }
        }
        for imp in c["control-implementations"].as_array().into_iter().flatten() {
            for q in imp["implemented-requirements"].as_array().into_iter().flatten() {
                let cid = s(&q["control-id"]);
                let claim = s(&q["description"]);
                out.insert(format!("control {cid}"), if claim.chars().count() > 40 { format!("{}…", claim.chars().take(40).collect::<String>()) } else { claim });
                for p in q["props"].as_array().into_iter().flatten().filter(|p| p["name"] != "review") {
                    out.insert(format!("control {cid} {} {}", s(&p["name"]), s(&p["value"])), s(&p["class"]));
                }
            }
        }
    }
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in sbom["components"].as_array().into_iter().flatten().filter(|c| c["type"] == "library") {
        versions.entry(s(&c["name"])).or_default().push(s(&c["version"]));
    }
    for (n, v) in versions { out.insert(format!("dependency {n}"), v.join(", ")); }
    if doc.is_object() { out.insert("document".into(), s(&d["metadata"]["version"])); }
    out
}

/// Each item whose fact changed, in the facts' order: its name, what it was, what it is.
fn changes(was: &BTreeMap<String, String>, is: &BTreeMap<String, String>) -> Vec<String> {
    let mut keys: Vec<&String> = was.keys().chain(is.keys()).collect();
    keys.sort();
    keys.dedup();
    let changed: Vec<(&String, &str, &str)> = keys.into_iter()
        .map(|k| (k, was.get(k).map_or("absent", |v| v.as_str()), is.get(k).map_or("absent", |v| v.as_str())))
        .filter(|(_, a, b)| a != b).collect();
    let w = changed.iter().map(|(k, _, _)| k.chars().count()).max().unwrap_or(0);
    changed.iter().map(|(k, a, b)| format!("  {k:<w$}  {a} → {b}")).collect()
}

fn count(n: usize, one: &str, many: &str) -> String { format!("{n} {}", if n == 1 { one } else { many }) }

/// What `bon account` prints: each document, each status's items, each claim's evidence.
fn summary(a: &Account) -> String {
    let n = |status: &str, class: &str| a.items.iter().filter(|i| i.status == status && i.class == class).count();
    let join = |parts: Vec<String>| parts.into_iter().filter(|p| !p.starts_with("0 ")).collect::<Vec<_>>().join(" · ");
    let mut rows: Vec<(String, String)> = Vec::new();
    let claims = if a.controls.is_empty() { String::new() } else { format!(" · {}, proposed for review", count(a.controls.len(), "control", "controls")) };
    rows.push((DOCUMENT.into(), format!("OSCAL {OSCAL} component definition{claims}")));
    rows.push((best_of_n::trusted::SBOM.into(), join(vec!["CycloneDX 1.5".into(), count(a.dependencies.len(), "dependency", "dependencies"),
        count(a.tools.len(), "tool", "tools"), count(a.services.len(), "service", "services")])));
    rows.push((String::new(), String::new()));
    let proven = join(vec![count(n("proven", "file"), "file", "files"), count(n("proven", "type"), "type", "types"),
        count(n("proven", "predicate"), "predicate", "predicates"), count(n("proven", "transition"), "transition", "transitions"),
        count(n("proven", "invariant"), "invariant", "invariants"), count(n("proven", "property"), "property", "properties"),
        count(n("proven", "gate"), "gate", "gates")]);
    let trusted = join(vec![count(n("trusted", "file"), "file", "files"), count(n("trusted", "trusted-function"), "trusted function", "trusted functions")]);
    let configured = join(vec![".bon/".into(), count(a.dependencies.len(), "dependency", "dependencies"),
        count(a.tools.len(), "tool", "tools"), count(a.services.len(), "service", "services")]);
    let tested = if a.tests.is_empty() { "every other file".to_string() } else { format!("every other file, judged by {}", a.tests.join(" · ")) };
    for (s, v) in [("proven", proven), ("trusted", trusted), ("configured", configured), ("tested", tested)] {
        if !v.is_empty() { rows.push((s.into(), v)); }
    }
    if !a.controls.is_empty() { rows.push((String::new(), String::new())); }
    // Each claim's evidence by status, one column per status any claim names, counts right-aligned.
    let by = |c: &Control, s: &str| c.evidence.iter().filter(|e| e.status == s).count();
    let columns: Vec<(&str, usize)> = STATUSES.iter().filter(|s| a.controls.iter().any(|c| by(c, s) > 0))
        .map(|s| (*s, a.controls.iter().map(|c| by(c, s).to_string().len()).max().unwrap_or(1))).collect();
    for c in &a.controls {
        let cells: Vec<String> = columns.iter().map(|(s, w)| match by(c, s) {
            0 => " ".repeat(w + 1 + s.len()),
            k => format!("{k:>w$} {s}"),
        }).collect();
        rows.push((c.id.clone(), cells.join("   ").trim_end().to_string()));
    }
    // Each block, between blank rows, aligns on its own widest name.
    rows.split(|(k, v)| k.is_empty() && v.is_empty()).map(|block| {
        let w = block.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
        block.iter().map(|(k, v)| format!("{k:<w$}  {v}\n")).collect::<String>()
    }).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uuid_is_version_4_in_form_and_the_same_for_the_same_key() {
        let u = uuid("a:component");
        assert_eq!(u, uuid("a:component"));
        assert_ne!(u, uuid("a:controls"));
        let b: Vec<char> = u.chars().collect();
        assert_eq!((u.len(), b[14], b[8], b[13]), (36, '4', '-', '-'));
        assert!("89ab".contains(b[19]));
    }

    #[test]
    fn a_claim_s_evidence_must_exist_with_the_status_it_names() {
        let items = vec![Item { status: "proven", class: "gate", name: "isolated".into() }, Item { status: "trusted", class: "trusted-function", name: "observe".into() }];
        let r = Path::new("/nonexistent");
        assert_eq!(resolve(r, &items, "proven", "isolated").unwrap().class, "gate");
        assert_eq!(resolve(r, &items, "proven", "observe").err().unwrap(), "proven observe is trusted, not proven");
        assert_eq!(resolve(r, &items, "proven", "gone").err().unwrap(), "proven gone does not exist");
    }

    #[test]
    fn each_changed_item_says_what_it_was_and_what_it_is_in_one_order() {
        let m = |v: &[(&str, &str)]| v.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect::<BTreeMap<_, _>>();
        let was = m(&[("tool verus", "1"), ("file src/a.rs", "proven"), ("control ac-6 proven isolated", "gate")]);
        let is = m(&[("tool verus", "2"), ("file src/a.rs", "tested")]);
        assert_eq!(changes(&was, &is), vec![
            "  control ac-6 proven isolated  gate → absent",
            "  file src/a.rs                 proven → tested",
            "  tool verus                    1 → 2"]);
        assert!(changes(&was, &was).is_empty());
    }

    #[test]
    fn trusted_functions_are_those_verus_does_not_check() {
        assert_eq!(unchecked("#[verifier::external_body]\npub fn a() {}\nfn b() {}\n// #[verifier::external]\n#[verifier::external]\nstruct C;\n"), ["a", "C"]);
    }
}
