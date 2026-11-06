# bon

You write what the software must do. bon searches for the code.

Several agent processes each write a candidate. The tests accept or reject
each one; Verus proves the accepted ones. Two verified candidates must agree.
The highest rank is selected, and pushed to trunk once no counterexample
splits them.

<img src="readme/loop.svg" width="880" alt="One iteration, transcript to transcript: a queue search turns a transcript into intents; the owner writes them into the spec and checks; code and counterexample searches write and test the code; it is pushed to trunk; counterexample searches on trunk and compaction keep trunk true and small; people try it and talk again.">

<img src="readme/search.svg" width="880" alt="Inside one search: generate, verify, agree, counterexample, select. Four kinds share it: queue, code, compaction, counterexample.">

## Who decides

You decide the [spec](src/spec.rs) and the checks. The
[queue](.bon/queue.tsv) holds what was asked for and is not in the spec yet;
writing an intent into the spec takes it off the queue. Search decides the
rest. Only a search that runs out of width or limit comes back to you.

The kernel is the spec, the [gates](src/gates.rs) and their
[implementation](src/exec.rs), proven by Verus. The terminal, `bon view` and
the gates in WebAssembly are built from it.

<img src="readme/kernel.svg" width="880" alt="The kernel at the center: spec, gates and their Rust implementation, proven by Verus. Programs around it, the terminal, the web view and WebAssembly, use what it emits and decide nothing.">

## Start

macOS, Rust, [Verus](https://github.com/verus-lang/verus).

```sh
cargo verus build
su admin -c "target/debug/bon setup --for $USER"   # --dry-run shows each step
sudo -u agent -i codex login                         # or claude
bon code      # after a spec change: code that trunk's checks accept
bon view
```

| | |
|---|---|
| `bon` | what is running, what was pushed, the queue |
| `bon code` | search for code that trunk's checks accept; push it |
| `bon compaction` | remove what is stale in code and tests, behavior unchanged |
| `bon counterexample` | look for a behavior on trunk the spec forbids, with tests written blind; if found, its test lands on trunk: then `bon code` |
| `bon queue` | turn each new transcript into a proposal for the queue |
| `bon background` | the stalest of compaction and counterexample, on spare capacity |
| `bon view` | the same, live, on localhost |
| `bon sbom --check` | fail when what bon trusts changed |

## Host, repository, agent

- **Host: `/etc/bon/host.toml`.** Where agent's tools are, model prices,
  and `jobs`, how many agent processes run at once. `bon setup` writes it.
- **Repository: `.bon/`.** Tracked: `bon.toml`, the manifest (the checks,
  the harnesses and their widths, `n = [8, 12]`: 8 agent processes, 12 if
  blocked, limits, trunk), `queue.tsv` and `sbom.json`. Not tracked:
  `traces/`, every search's record. Trunk is the remote's; every selected
  candidate is pushed to it.
- **agent: the POSIX user every agent process runs as.** Each works in
  `/tmp/bon/<pid>.<search>.<index>/<repository>`. It can read the checks,
  write its own working directory, and nothing else; it cannot list
  `/tmp/bon` to find another's. bon confirms this before every search.
  That copy is thrown away after the search.

## Where things are

| | |
|---|---|
| [`.bon/queue.tsv`](.bon/queue.tsv) | what was asked for, not yet in the spec |
| [`src/spec.rs`](src/spec.rs) | what bon is |
| [`src/gates.rs`](src/gates.rs) | each decision's contract |
| [`src/exec.rs`](src/exec.rs) | the decisions, proven |
| [`src/trusted.rs`](src/trusted.rs) | what Verus doesn't check |
| [`view/`](view/) | `bon view` |
| [`skills/bon/`](skills/bon/SKILL.md) | how your model runs bon |
| [`.bon/sbom.json`](.bon/sbom.json) | everything bon trusts |
| `.bon/traces/` | every search, every candidate, every cost; a counterexample's evidence as a git bundle |
