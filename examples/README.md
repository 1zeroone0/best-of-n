# Examples

One pattern: **the kernel decides; programs do effects.**

1. **The kernel** is Rust under Verus: the spec (`src/spec.rs`), each gate's
   contract (`src/gates.rs`) and the code that meets it (`src/exec.rs`),
   proven. It chooses, validates and schedules, and does no I/O.
2. **It emits types and data.** `[types]` in `.bon/bon.toml` names the Rust
   files to emit from (`from`) and one types file per language (`types`);
   `bon types` writes them, each type with its `///` sentence; `bon types
   --check` is a test check, so a types file never lags the kernel. The data is
   JSON, one object per line.
3. **A program**, in its own language, imports its types file, reads that data
   with its own toolchain, and does the effects: files, network, UI, tensors.
   It decides nothing the kernel decides. bon embeds and runs nothing of it.

Types files are generated: never edit them; change the Rust and run `bon types`.

| | types file | how shapes come out | run | types checked by |
|---|---|---|---|---|
| Go | `go/kernel/kernel.go` | structs with JSON tags; an enum is a struct of optional pointers | `go run .` | the Go compiler |
| Python | `python/kernel.py` | `TypedDict`s; an enum is a `TypedDict` with one key set | `python main.py` | mypy (optional) |
| TypeScript | `typescript/kernel.ts` | interfaces; an enum is a union of one-key objects | `node main.ts` | `tsc --noEmit` (optional: Node only strips types) |

In all three, a single-field Rust type (`Commit`, `Path`, `Intent`,
`Transcript`) is an alias of its field, and `Hash` is a decimal string: an
identity, not a number.

## The source: `kernel.rs`

```sh
cargo run -q --example kernel
```

Builds fixed searches, one of each kind, and prints for each its JSON (from the
kernel's `emit`), its words, whether they round-trip, and what the gates
`selected` and `found_on_trunk` return. It is also an agree check: the
contracts fix this output exactly, so every verified candidate prints the same.
Each program below reads its JSON lines and skips the rest.

## Go: `go/`

```sh
cargo run -q --example kernel | (cd examples/go && go run .)
```

Reads each line into `kernel.Search` with `encoding/json`, names its kind by
which pointer in `kernel.Kind` is set, and counts the candidates returned and
accepted.

## Python: `python/`, with PyTorch

```sh
python3 -m venv examples/python/.venv && examples/python/.venv/bin/pip install torch
cargo run -q --example kernel | examples/python/.venv/bin/python examples/python/main.py
```

Reads each line as a `kernel.Search`, holds its candidates as a tensor (one row
each: accepted, proved, rank, diff) and reports how many were accepted and their
mean diff.

## TypeScript: `typescript/`

```sh
cargo run -q --example kernel | node examples/typescript/main.ts
```

Node (22.18 or later) runs `.ts` by stripping its types, so `main.ts` uses only
erasable TypeScript and imports its types with `import type`. Reads each line as
a `Search`, names its kind by which key `Kind` has, and counts the candidates
returned and accepted. To check its types, with `typescript` and `@types/node`
installed: `tsc --noEmit --strict --allowImportingTsExtensions --module nodenext
--types node examples/typescript/main.ts`.
