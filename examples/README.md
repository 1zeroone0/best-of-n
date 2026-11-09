# Examples

These show one pattern: **the kernel decides, programs do effects.** They stand
in until real programs exist in each language, and then they go away.

## The pattern

1. **The kernel** is Rust under Verus: the spec (`src/spec.rs`), each gate's
   contract (`src/gates.rs`) and the code that meets it (`src/exec.rs`),
   proven. It chooses, validates and schedules. It does no I/O.
2. **Its types are emitted.** `[programs] from` in `.bon/bon.toml` names the
   Rust files whose types programs use; `[programs] types` names one output
   file per language. `bon types` writes them, with each type's `///` sentence
   as its comment; `bon types --check` is a test check, so an emitted file never
   lags the kernel.
3. **A program reads what the kernel emits** (one JSON object per value) as
   those types, and does the effects: files, network, UI, tensors. It decides
   nothing the kernel decides.

The emitted files are generated: never edit them; change the Rust and run
`bon types`.

| | emitted to | how the shapes come out |
|---|---|---|
| TypeScript | `view/src/kernel.ts` | interfaces; an enum is a union of one-key objects |
| Go | `examples/go/kernel/kernel.go` | structs with JSON tags; an enum is a struct of optional pointers |
| Python | `examples/python/kernel.py` | `TypedDict`s; an enum is a `TypedDict` with one key set |

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

## TypeScript

The same program, against `kernel.ts`:

```ts
import type { Kind, Search } from './kernel';

declare const input: string; // what the kernel printed

const kind = (k: Kind): string =>
  'queue' in k ? `queue ${k.queue.goal}`
  : 'code' in k ? `code ${k.code.goal}`
  : 'compaction' in k ? `compaction ${k.compaction.goal}`
  : k.counterexample.goal ? `counterexample on search ${k.counterexample.goal.search} candidate ${k.counterexample.goal.index}`
  : 'counterexample on trunk';

for (const line of input.split('\n').filter(l => l.startsWith('{'))) {
  const s: Search = JSON.parse(line);
  const returned = s.results.filter(c => c !== null);
  console.log(`${kind(s.kind)}: ${returned.length} of ${s.n} returned, ${returned.filter(c => c.accepted).length} accepted`);
}
```

`kernel.ts` also carries the gates' named answers (`NONE`, `NOT_A_SEARCH`) for
a program that runs the gates as WebAssembly.

## Not yet

Go and Python use the types only. Running the gates compiled in, as a
TypeScript program can through WebAssembly, is queue 28.
