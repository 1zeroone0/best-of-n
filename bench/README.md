# bench

How bon scales with width, measured on stub agents: what a search costs
besides the model.

```sh
export BENCH=/path/to/scratch            # sandboxes and results go here
sh bench/run.sh 32                       # width 32; results in $BENCH/results-w32
SLEEP=10 K=2 sh bench/run.sh 128 w128k2  # a tag names the run
```

`run.sh WIDTH [TAG]` builds bon, then a throwaway **sandbox** under
`$BENCH/sandbox-TAG`: a small Verus crate (`bench/sandbox/`) in a git
repository whose `origin` is a bare repository beside it, and whose trunk
commits a `.bon/bon.toml` with no `traces` key. It refuses to run if either
is otherwise. On that trunk Verus rejects `max` (its body returns `a` where
the spec says the larger), so `bon code` has work to do. The run then:

1. `bon code`: a code search of WIDTH stubs, a foil search and a
   counterexample search of `CX_WIDTH` each, and the push;
2. `bon counterexample` on the trunk that push made.

Each is measured as a process tree by `measure.py`: wall time, CPU time
(`cpu_rusage`, every waited-for descendant's user+system; `cpu_sampled`, from
ps each second), and peak resident memory summed over the tree (bon, git,
sudo, and everything agent runs under them) at one sample. `checks_executed`
counts the judge's check logs that ran a command; `checks_cached`, those its
verdict cache answered. Each result is a JSON file in `$BENCH/results-TAG/`,
beside the command's stdout, stderr and traces.

## The stub

`bench/stub.sh` is the harness (`name = "stub"`, `command = ["/bin/sh",
".bon/stub.sh"]`: a stub costs nothing and needs no login or price). It reads
the prompt on stdin, sleeps `SLEEP` seconds (the model), then by the prompt's
kind:

- **code**: fixes `max`, one of `VARIANTS` ways by its index, so stubs whose
  indices agree modulo `VARIANTS` write byte-identical trees;
- **foil**: puts the wrong body back: the tests accept it, Verus does not;
- **counterexample**: writes a test that the right `max` passes and the
  foil fails, one of `TEST_VARIANTS` ways.

A code or foil stub then runs `cargo test` and `cargo verus verify` itself `K`
times, as an agent iterating does.

## Why a crate of its own

bon's own `cargo verus verify` is ~190 CPU-s warm; at width 32 with the
foils, a baseline would be hours. The sandbox crate depends on the same vstd,
so an agent's first, cold build re-verifies vstd (~50 CPU-s, 2.3 GB, 18 s on
14 cores), the same shape of cost, at a quarter of the price; its own proof is
small, so a warm check is seconds.

## Settings

| env | default | |
|---|---|---|
| `CX_WIDTH` | 4 | counterexample and foil searches' width |
| `SLEEP` | 30 | seconds each stub waits |
| `K` | 1 | times each stub runs the checks itself |
| `VARIANTS` | 4 | distinct code edits |
| `TEST_VARIANTS` | 2 | distinct counterexample tests |
| `TIME` | 1800 | each agent process's time limit |
| `BON` | `target/debug/bon` | the binary (built first when unset) |

bon's pool knobs pass through the environment (see `src/trusted.rs`, `Pools`).
