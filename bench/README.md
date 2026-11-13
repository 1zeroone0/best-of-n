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

| `GENERATION`, `CHECKS`, `CHECK_THREADS`, `CORES`, `MEMORY_GB` | unset | the host file's pool keys for this run |

bon reads a host file of the run's own (`BON_HOST`, in the sandbox):
`/etc/bon/host.toml` with the run's verdict cache, `cleanup = "own"`, and
those keys, so a run can size the pools as another machine's (`CORES=12
MEMORY_GB=16`: a 24 GB, 12-core laptop with 16 GB free). The rows below that
name `BON_*` variables are from before, when bon read them from its environment.

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

## Results on the merged branch

Same host and settings, later the same day. "merged" is c9578f5 (the judge's
fresh build); "lazy" is d93cd48 (builds cloned only when a cargo runs). K=0
is a stub that never runs cargo itself: the one-shot sample's shape. `bon
code` row; CPU is `cpu_rusage`; checks are executed / cached.

| config | width | K | build | wall s | CPU s | peak RSS MB | checks |
|---|---|---|---|---|---|---|---|
| kernel | 8 | 1 | merged | 167 | 131 | 1985 | 38 / 104 |
| kernel | 32 | 1 | merged | 207 | 209 | 2017 | 38 / 392 |
| kernel | 128 | 1 | merged | 361 | 436 | 1990 | 38 / 1544 |
| kernel | 500 | 1 | merged | 957 | 1085 | 1975 | 38 / 6008 |
| kernel | 32 | 0 | merged | 155 | 231 | 2046 | 38 / 392 |
| kernel | 128 | 0 | merged | 214 | 633 | 1971 | 38 / 1544 |
| kernel | 500 | 0 | merged | 453 | 1567 | 1944 | 38 / 6008 |
| kernel | 32 | 1 | lazy | 206 | 156 | 2010 | 38 / 392 |
| kernel | 500 | 0 | lazy | 426 | 369 | 1918 | 38 / 6008 |
| kernel | 500 | 0 | lazy, generation 500 | 252 | 392 | 5254 | 38 / 6008 |
| kernel, every tree distinct | 500 | 0 | lazy, generation 500 | 2895 | 3502 | 5790 | 6010 / 36 |
| bon | 8 | 1 | lazy | 337 | 1047 | 4283 | 38 / 104 |
| bon | 32 | 1 | lazy | 495 | 1780 | 4672 | 38 / 392 |
| bon | 128 | 1 | lazy | 1104 | 4981 | 5551 | 38 / 1544 |

Where width 500 K=1's time goes (`timeline.py`): of its 798 s code search,
the median agent process waits 333 s for one of the 64 generation slots and
spends 52 s (p90 137 s) in its own two cargo runs, mostly queued for one of
7 check slots; its judge, answered by the cache, takes 0.3 s.

Every tree distinct (500 one-shot samples, generation 500): the check pool was
full 81% of the code search and 93% of the counterexample search (whose
verdict matrix is 4 tests × 500 candidates), yet 1.9 of 14 cores were busy on
average: the checks' 3502 CPU-s over 14 cores is 250 s, against 2895 s of
wall. These checks are latency, not compute (0.6 CPU-s each): a pool sized
`cores / check_threads` is the bottleneck, not the machine.

What an agent process costs bon itself (`forks.py`, K=0 width 32, per agent
process): merged, 98 processes and 7.8 s, of which 2.5 build clones (`cp -cR`
as agent) 5.5 s and 8 `rm -rf` 1.1 s; lazy, 87 processes and 1.9 s, the rest
chmod/chgrp/git/ps forks of ~0.02–0.1 s each.

Simulated memory (`BON_CORES=12`, `BON_MEMORY_GB` what was free): with 40 GB
wired by a ballast, 6–7 GB stayed free (other sessions held the rest) and every
row matched the full machine's within noise, no swap, pressure normal; with
49.75 GB wired the kernel's pressure went critical and the level was stopped.
