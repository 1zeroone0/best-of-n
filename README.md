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
`bon` and lets you run commands as agent (never as root):

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

## bon.toml

Each repository that uses bon commits a `bon.toml` at its root. bon reads it
from trunk's head, never the working tree. Two parts worth knowing:

- `remote` (default `origin`) and `trunk` (default `main`): the remote's trunk
  is the golden trunk. bon refuses to start unless local trunk matches it, and
  pushes every fast-forward to it (fast-forward only; refused if it moved).
- `[prices]`: dollars per million tokens, keyed by the canonical model id each
  harness runs (`claude-haiku-5-5`, `gpt-6.1-sol`), with `input`,
  `cached_input`, `output`, `cache_write` and `cache_write_long`. bon computes
  every cost from token counts and these prices, as an API-equivalent figure
  (on a subscription nothing is billed per token), and flags any run where
  Claude Code's own figure differs by more than 5%.

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

Verus proves the spec and the gates (`src/spec.rs`, `src/gates.rs`,
`src/exec.rs`). Everything else is trusted and listed in the SBOM.
