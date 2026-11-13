//! bon new <name>: a project, set up from the template in `template/` with no
//! model call: a spec with the core nouns, its gates, an empty implementation,
//! the manifest (with the account's table) and the queue, then the types the
//! gates emit, committed as its first commit. The same name gives the same
//! bytes. Trusted code.

use std::path::Path;
use std::process::Command;

/// Each file of the template, by its path in the project; `{{name}}` is the project's name.
const TEMPLATE: [(&str, &str); 9] = [
    (".gitignore", include_str!("../template/.gitignore")),
    (".bon/bon.toml", include_str!("../template/.bon/bon.toml")),
    (".bon/queue.tsv", include_str!("../template/.bon/queue.tsv")),
    ("Cargo.toml", include_str!("../template/Cargo.toml")),
    ("Cargo.lock", include_str!("../template/Cargo.lock")),
    ("src/lib.rs", include_str!("../template/src/lib.rs")),
    ("src/spec.rs", include_str!("../template/src/spec.rs")),
    ("src/gates.rs", include_str!("../template/src/gates.rs")),
    ("src/exec.rs", include_str!("../template/src/exec.rs")),
];

/// `bon new <name>`, in the current directory.
pub fn run(name: &str) -> Result<(), String> {
    // A Cargo package name, and a directory: a letter, then letters, digits, - or _.
    if !name.starts_with(|c: char| c.is_ascii_lowercase()) || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err(format!("{name} is no project's name; start it with a-z, then use a-z, 0-9, - or _"));
    }
    let dir = Path::new(name);
    if std::fs::symlink_metadata(dir).is_ok() { return Err(format!("{name} already exists; nothing written: choose another name, or move it aside")); }
    for (path, text) in TEMPLATE {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).map_err(|e| format!("{name}/{path}: {e}"))?;
        std::fs::write(&file, text.replace("{{name}}", name)).map_err(|e| format!("{name}/{path}: {e}"))?;
    }
    // The types programs are built on, as bon types writes them.
    let manifest: toml::Value = toml::from_str(&TEMPLATE[1].1.replace("{{name}}", name)).map_err(|e| e.to_string())?;
    for (path, text) in crate::types::targets(dir, &manifest)? {
        let file = dir.join(&path);
        std::fs::create_dir_all(file.parent().unwrap()).map_err(|e| format!("{name}/{path}: {e}"))?;
        std::fs::write(&file, text).map_err(|e| format!("{name}/{path}: {e}"))?;
    }
    let git = |args: &[&str]| -> Result<(), String> {
        let out = Command::new("git").args(args).current_dir(dir).output().map_err(|e| format!("git: {e}"))?;
        if out.status.success() { Ok(()) } else { Err(format!("git {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim())) }
    };
    git(&["init", "-q", "-b", "main"])?;
    git(&["add", "-A"])?;
    git(&["commit", "-q", "-m", &format!("bon new {name}")])?;
    println!("created {name}: a spec, its gates, an empty implementation, the manifest and the queue, as its first commit");
    println!("next: cd {name}; bon account, and commit .bon/; bon check");
    println!("before a search: set the limits and the rate in .bon/bon.toml, and push to a remote");
    Ok(())
}
