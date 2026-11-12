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

- **code**: fixes `max`, one of `VARIANTS` ways by its index (past four, the
  same fix with its own comment), so stubs whose indices agree modulo
  `VARIANTS` write byte-identical trees;
- **foil**: puts the wrong body back: the tests accept it, Verus does not;
- **counterexample**: writes a test that the right `max` passes and the
  foil fails, one of `TEST_VARIANTS` ways.

A code or foil stub then runs `cargo test` and `cargo verus verify` itself `K`
times, as an agent iterating does.

## bon itself

`PROJECT=bon` makes the sandbox bon's own source at HEAD instead: its
`.bon/` replaced by the benchmark's (the stub harness, the local bare origin,
no `traces` key), and on its trunk `exec::eq` broken to say a strict prefix
equals the longer text: bon's tests miss it, Verus does not. A code stub
copies the right file back from `.bon/fix/` (variant v > 0 appends
`// variant v`, so `VARIANTS` sets how many distinct trees); a foil copies
trunk's wrong one from `.bon/foil/`; a counterexample tests
`best_of_n::exec::eq` on a prefix. The checks are `cargo test -q`,
`cargo verus verify` and the kernel example: a real check's cost and memory.

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
| `PROJECT` | `kernel` | `kernel` (bench/sandbox) or `bon` (bon's own source) |
| `BON` | `target/debug/bon` | the binary (built first when unset) |

bon's pool knobs pass through the environment (see `src/trusted.rs`, `Pools`).

## Results

This Mac mini (14 cores, 64 GB), `SLEEP=30 K=1 CX_WIDTH=4 VARIANTS=4
TEST_VARIANTS=2`, 2026-11-12, other sessions sharing the host. `bon code`
(code, foil and counterexample searches, push). CPU is `cpu_rusage`; checks
are the judge's logs, executed / answered by the cache. Baseline is 03d9da4
(one `jobs` slot pool of 7, cold agent builds, no cache, serial verdicts).

| width | build | wall s | CPU s | peak RSS MB | checks run / cached |
|---|---|---|---|---|---|
| 8 | baseline | 290 | 984 | 13344 | 142 / 0 |
| 8 | after | 161 | 126 | 1990 | 38 / 104 |
| 32 | baseline | 527 | 2758 | 6252 | 430 / 0 |
| 32 | after | 200 | 204 | 1998 | 38 / 392 |
| 128 | after | 357 | 399 | 2027 | 38 / 1544 |
| 500 | after | 986 | 1007 | 1994 | 38 / 6008 |
| 32 | after, 24 GB / 12-core pools | 206 | 206 | 2051 | 38 / 392 |
| 128 | after, 24 GB / 12-core pools | 356 | 401 | 1977 | 38 / 1544 |
| 32, every tree distinct | baseline | 517 | 2712 | 6330 | 430 / 0 |
| 32, every tree distinct | after | 310 | 289 | 1944 | 394 / 36 |
| 128 | after, `BON_CHECKS=14 BON_CHECK_THREADS=1` | 356 | 399 | 2293 | 38 / 1544 |

"24 GB / 12-core pools" is `BON_CORES=12 BON_MEMORY_GB=16`: 6 checks of 2
threads, 64 sessions. "Every tree distinct" is `VARIANTS=32 TEST_VARIANTS=4`:
the warm builds and pools without the cache's help. `bon counterexample` on
the pushed trunk: 59 s / 70 CPU-s / 2.3 GB before, 69 s / 65 CPU-s / 2.0 GB
after (its few checks now get 2 threads each, not the machine).
