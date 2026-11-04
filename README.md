# bon

best-of-N: bon generates candidate changes with agent processes, verifies them
against checks they cannot change, requires agreement, ranks them, runs a
counterexample search, and fast-forwards trunk to the selected candidate.

What bon must do is the [map](map). What it is, formally, is the
[spec](src/spec.rs), which Verus proves. This file only says how to use it.

## Install

```sh
cargo verus build          # verify, then build target/debug/bon
```

`bon setup`, run once as an administrator, creates user `agent` and group
`bon`, lets you run commands as agent (never as root), and makes `/tmp/bon`,
the directory holding the working directories: yours, mode 0711, so an agent
process can reach only the working directory it was given.

```sh
su admin -c "/path/to/bon setup --for $USER"   # --dry-run prints each step
sudo -u agent -i bash -c 'curl -fsSL https://claude.ai/install.sh | bash'
sudo -u agent -i /Users/agent/.local/bin/claude   # log in
sudo -u agent -i codex login
```

## Commands

| command | does |
|---|---|
| `bon` | every intent in the map: built or open |
| `bon code "<intent>"` | search for code that makes the intent hold; fast-forward trunk |
| `bon compaction` | search for code that removes or simplifies without changing behavior |
| `bon map` | turn each new transcript into a proposal at `refs/bon/proposal/<name>` |
| `bon sbom [--check]` | write `sbom.json`, or fail if it differs from this machine |
| `bon setup [--dry-run] [--for <user>]` | create agent and group bon |

## Configuration

Two files, by what they are about.

**`/etc/bon/device.toml`, about this machine.** `bon setup` writes it once and
you edit it with sudo afterwards. It holds `path`, where agent's tools live,
and `[prices]`: dollars per million tokens, keyed by canonical model id
(`claude-haiku-5-5`, `gpt-6.1-sol`), with `input`, `cached_input`, `output`,
`cache_write` and `cache_write_long`. Keep only the models in use. bon
computes every cost from token counts and these prices, as an API-equivalent
figure (on a subscription nothing is billed per token). Each trace records the
prices it was costed at, so changing them never rewrites history. A run where
Claude Code's own figure differs by more than 5% is flagged.

**`bon.toml`, about one repository,** committed at its root and read from
trunk's head, never the working tree: the checks, harnesses and widths, limits,
rate, and `remote` (default `origin`) and `trunk` (default `main`). The
remote's trunk is the golden trunk: bon refuses to start unless local trunk
matches it, and pushes every fast-forward to it (fast-forward only; refused if
it moved). It may not contain `path` or `prices`.

Each harness's `n` is a list of widths, one per attempt: `n = [2, 4, 8]` runs
2 agent processes, and if that attempt is blocked (fewer than two verified, a
disagreement, or a counterexample that splits them), 4, then 8. The longest
list sets the number of attempts; the bon process's cost limit bounds them all.
A counterexample's tests join the agree checks of the later attempts.

## SBOM

`sbom.json` is a [CycloneDX 1.5](https://cyclonedx.org) document listing
everything bon depends on or trusts:

| layer | from |
|---|---|
| crates | `Cargo.lock`: name, version, SHA-256 checksum, purl |
| toolchain | `rustc`, `verus` |
| TCB tools | `git`, `sudo`, `tar`, macOS; `claude` and `codex` as agent runs them |
| services | the Anthropic and OpenAI APIs the harnesses call |
| trusted code | `src/trusted.rs` and `src/main.rs`, and every `external_body` function |

It has no timestamp, so the same machine always produces the same file.
`bon sbom` writes it; `bon sbom --check` exits non-zero when anything differs,
so it belongs in a repository's `verify` checks. Regenerate and commit it when
a dependency, tool or trusted function changes.

## Trust

The kernel is the spec, the gates and their implementation (`src/spec.rs`,
`src/gates.rs`, `src/exec.rs`), proven by Verus. Programs (the terminal, the
view, the gates in WebAssembly) are built from it. Everything else is trusted
and listed in the SBOM: `src/trusted.rs` and the entry points (`main.rs`,
`view.rs`, `wasm.rs`), plus git, sudo, tar, POSIX ACLs, the harnesses and the
checks.

Each agent process works in `/tmp/bon/<pid>.<search>.<index>/<repository>`.
`/tmp/bon` is searchable but not listable by agent, so no agent process can
find another's working directory by looking. Every agent process is the same
POSIX user, so one that set out to (guessing a path, or `ps` and `lsof`)
could still reach a sibling's.
