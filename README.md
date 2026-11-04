# bon

You write what the software must do. bon searches for the code.

Several agent processes each write a candidate. Checks they cannot change
verify each one. Two must agree. The highest rank is selected, and trunk
fast-forwards to it.

<img src="readme/search.svg" width="880" alt="One search: agent processes fan out from trunk, checks verify their candidates, two agree, the highest rank is selected, trunk fast-forwards. Code, counterexample, compaction, scrub and map searches run the same path toward different goals.">

## Who decides

You decide the [map](map) (one intent per line), the [spec](src/spec.rs) and
the checks. Search decides the rest. Only a search that runs out of width or
limit comes back to you.

The kernel is the spec, the [gates](src/gates.rs) and their
[implementation](src/exec.rs), proven by Verus. The terminal, `bon view` and
the gates in WebAssembly are built from it.

<img src="readme/levels.svg" width="880" alt="The owner's level above: map, spec, checks. Search below: searches, trunk, scrub and compaction in the background. The kernel at the center, its programs around it.">

## Start

macOS, Rust, [Verus](https://github.com/verus-lang/verus).

```sh
cargo verus build
su admin -c "target/debug/bon setup --for $USER"   # --dry-run shows each step
sudo -u agent -i codex login                         # or claude
bon code "<an intent, exactly as in the map>"
bon view
```

| | |
|---|---|
| `bon` | the map: open, built, broken |
| `bon code "<intent>"` | search for code that makes it hold |
| `bon scrub "<intent>"` | check it still holds, with tests written blind |
| `bon compaction` | remove code, behavior unchanged |
| `bon map` | turn a transcript into a proposal |
| `bon background` | the stalest scrub or compaction, on spare capacity |
| `bon view` | everything, live, on localhost |
| `bon sbom --check` | fail when what bon trusts changed |

## Host, repository, agent

- **Host: `/etc/bon/host.toml`.** Where agent's tools are, model prices,
  and `jobs`, how many agent processes run at once. `bon setup` writes it.
- **Repository: `bon.toml`, the manifest.** The checks, the harnesses and
  their widths (`n = [8, 12]`: 8 agent processes, 12 if blocked), limits,
  and trunk. Trunk is the remote's; every fast-forward is pushed.
- **agent: the POSIX user every agent process runs as.** Each works in
  `/tmp/bon/<pid>.<search>.<index>/<repository>`. It can read the checks,
  write its own working directory, and nothing else; it cannot list
  `/tmp/bon` to find another's. bon confirms this before every search.

## Where things are

| | |
|---|---|
| [`map`](map) | what bon must do |
| [`src/spec.rs`](src/spec.rs) | what bon is |
| [`src/gates.rs`](src/gates.rs) | each decision's contract |
| [`src/exec.rs`](src/exec.rs) | the decisions, proven |
| [`src/trusted.rs`](src/trusted.rs) | what Verus doesn't check |
| [`view/`](view/) | `bon view` |
| [`skills/bon/`](skills/bon/SKILL.md) | how your model runs bon |
| [`sbom.json`](sbom.json) | everything bon trusts |
| `.bon/traces/` | every search, every candidate, every cost |
