//! engineer's tests of bon's command line, run on the built binary: `--help`
//! has no effect and prints the command's line; the version is one line; a
//! mistake is one line on stderr, nothing on stdout, and exit 1.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// bon with `args`, in `dir`, with a PATH where nothing is found: a command
/// that did more than print would fail, not act.
fn bon(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bon")).args(args).current_dir(dir).env("PATH", "/nonexistent").env_remove("BON_HOST").output().unwrap()
}

/// A directory of its own for one test, removed when it is dropped.
struct Scratch(PathBuf);
impl Scratch {
    fn new(name: &str) -> Scratch {
        let d = std::env::temp_dir().join(format!("bon-cli-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }
    fn is_empty(&self) -> bool { std::fs::read_dir(&self.0).unwrap().next().is_none() }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

const COMMANDS: [&str; 16] = ["code", "counterexample", "compaction", "queue", "background", "spec", "types", "account", "check",
    "pending", "new", "init", "setup", "cost", "view", "help"];

#[test]
fn help_for_every_command_prints_its_line_and_does_nothing_else() {
    let d = Scratch::new("help");
    for c in COMMANDS {
        for flag in ["--help", "-h"] {
            let o = bon(&d.0, &[c, flag]);
            let out = String::from_utf8_lossy(&o.stdout);
            assert!(o.status.success() && o.stderr.is_empty(), "{c} {flag}: {o:?}");
            if c == "help" { assert!(out.contains("  bon code ") && out.contains("exit: 0"), "{out}"); continue; }
            assert!(out.starts_with(&format!("usage:\n  bon {c}")), "{c} {flag}: {out}");
            // Its lines only: one signature (bon spec's two: it reads, and with a queue line's id it searches), every line within 80 columns.
            assert_eq!(out.matches("\n  bon ").count(), if c == "spec" { 2 } else { 1 }, "{out}");
            assert!(out.lines().all(|l| l.chars().count() <= 80), "{out}");
        }
        // After the words a command takes, too; bon spec's searching form, with no effect either.
        assert!(bon(&d.0, &[c, "x", "--help"]).status.success());
        if c == "spec" { assert!(bon(&d.0, &[c, "83", "--help"]).status.success()); }
        assert!(d.is_empty(), "bon {c} --help wrote something");
    }
    let all = bon(&d.0, &["--help"]);
    assert!(all.status.success() && String::from_utf8_lossy(&all.stdout).lines().count() > COMMANDS.len());
    assert!(d.is_empty());
}

#[test]
fn the_version_is_one_line_in_either_spelling() {
    let d = Scratch::new("version");
    for v in ["--version", "-V"] {
        let o = bon(&d.0, &[v]);
        assert!(o.status.success() && o.stderr.is_empty(), "{o:?}");
        assert_eq!(String::from_utf8_lossy(&o.stdout), format!("bon {}\n", env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn a_mistake_is_one_line_on_stderr_and_exit_1() {
    let d = Scratch::new("mistakes");
    let cases: [(&[&str], &str); 11] = [
        (&["frobnicate"], "bon: unknown command frobnicate; bon help lists every command\n"),
        (&["--bogus"], "bon: --bogus is not an option of bon; bon --help shows its usage\n"),
        (&["--since"], "bon: --since needs YYYY-MM-DD; bon --help shows its usage\n"),
        (&["--find"], "bon: --find needs TEXT; bon --help shows its usage\n"),
        (&["account", "--bogus"], "bon: --bogus is not an option of account; bon account --help shows its usage\n"),
        (&["new"], "bon: new needs <name>; bon new --help shows its usage\n"),
        (&["help", "code"], "bon: code is not an argument of help; bon help --help shows its usage\n"),
        (&["code", "now"],"bon: now is not an argument of code; bon code --help shows its usage\n"),
        (&["view", "--frame"], "bon: --frame needs WxH; bon view --help shows its usage\n"),
        // Outside a repository, before anything is read (bare bon, view and pending show the host there).
        (&["--find", "x"], "bon: --since, --until and --find narrow a repository's bon processes; run bon in one\n"),
        (&["spec"], "bon: not in a git repository; run bon in one, or start one with bon new <name>\n"),
    ];
    for (args, said) in cases {
        let o = bon(&d.0, args);
        assert_eq!(o.status.code(), Some(1), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}: {o:?}");
        assert_eq!(String::from_utf8_lossy(&o.stderr), said, "{args:?}");
    }
    assert!(d.is_empty());
}
