//! `bon new`: the same name gives the same bytes, and the project it sets up
//! passes its own checks as created (Verus verifies it, its tests pass), its
//! types emit, and its account generates.

use std::path::Path;
use std::process::Command;

fn bon(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bon")).args(args).current_dir(dir)
        .env("GIT_AUTHOR_NAME", "bon").env("GIT_AUTHOR_EMAIL", "bon@localhost")
        .env("GIT_COMMITTER_NAME", "bon").env("GIT_COMMITTER_EMAIL", "bon@localhost")
        .output().unwrap()
}

fn ok(o: &std::process::Output, what: &str) {
    assert!(o.status.success(), "{what}: {}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
}

fn tree(dir: &Path) -> String {
    let o = Command::new("git").args(["rev-parse", "HEAD^{tree}"]).current_dir(dir).output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn a_new_project_is_the_same_bytes_and_passes_its_checks() {
    // Kept between runs: the project's build (Verus's vstd) is the slow part.
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let d = tmp.join(format!("bon-new-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for run in ["a", "b"] {
        std::fs::create_dir_all(d.join(run)).unwrap();
        ok(&bon(&d.join(run), &["new", "demo"]), "bon new");
    }
    let p = d.join("a/demo");
    assert_eq!(tree(&p), tree(&d.join("b/demo")));
    assert!(!bon(&d.join("a"), &["new", "demo"]).status.success(), "bon new over an existing directory");
    assert!(!bon(&d.join("a"), &["new", "Demo"]).status.success(), "a name that is not a package name");

    // Each check the manifest declares, as written, in the project.
    let manifest: toml::Value = toml::from_str(&std::fs::read_to_string(p.join(".bon/bon.toml")).unwrap()).unwrap();
    let checks = &manifest["checks"];
    for key in ["verify", "test"] {
        for c in checks[key].as_array().unwrap().iter().filter_map(|c| c.as_str()) {
            let o = Command::new("sh").args(["-c", c]).current_dir(&p)
                .env("CARGO_TARGET_DIR", tmp.join("bon-new-target")).env("CARGO_NET_OFFLINE", "true").output().unwrap();
            ok(&o, c);
        }
    }
    ok(&bon(&p, &["types", "--check"]), "bon types --check");
    ok(&bon(&p, &["account"]), "bon account");
    ok(&bon(&p, &["account", "--check"]), "bon account --check");
    let _ = std::fs::remove_dir_all(&d);
}
