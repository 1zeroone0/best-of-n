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
  foil fails, one of `TEST_VARIANTS` ways (`CX_MODE` says which tests).

Its reply begins at once: it prints a line before it sleeps, as a model's
first token comes before its last (bon starts a search's other agent
processes at its first one's first output).

The sandbox's `pick(a, b)` may return either (its spec says so); trunk's
returns `a`, and with `BEHAVIORS=2` half the code stubs make it `b`: two
behaviors, both verified, for the disagreement path.

A code or foil stub then runs `cargo test` and `cargo verus verify` itself `K`
times, as an agent iterating does.

## bon itself

`PROJECT=bon` makes the sandbox bon's own source at HEAD instead: its
`.bon/` replaced by the benchmark's (the stub harness, the local bare origin,
no `traces` key), `bench/` left out (it says how trunk is broken), and on its
trunk `exec::eq` broken to say a strict prefix equals the longer text: bon's
tests miss it, Verus does not. A code stub copies the right file back from
`.bon/fix/` (variant v > 0 appends `// variant v`, so `VARIANTS` sets how
many distinct trees), which is in the tree only when stubs write the code (a
real harness would read the answer there); a foil undoes the diff its prompt
shows it; a counterexample tests
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
| `BEHAVIORS` | 1 | kernel: code stubs set `pick` to `b` at every index ≡ 1 (mod it): verified candidates that behave differently |
| `CX_MODE` | `blind` | kernel: counterexample stubs' tests: `blind` (max only), `split` (pick 1 2 = 2; variant 0 that alone), `few` (only index 0's builds) |
| `ATTEMPTS` | 1 | attempts `bon code` may make, each WIDTH wide |
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

## Results: what a check waits on (bench3)

Same host, later the same evening, every tree distinct (`VARIANTS=WIDTH
TEST_VARIANTS=4 K=0 GENERATION=500`) unless noted. "Scan" is the CPU that
macOS's `XprotectService` and `syspolicyd` used over the run (`ps`): it is no
descendant of bon, so `CPU s` leaves it out.

**What a check waits on.** One judged candidate of the kernel sandbox, alone:
materialize, permissions, build clone, sudo and env are 0.01–0.07 s each;
`cargo test` 1.2 s wall for 0.6 CPU-s, `cargo verus verify` 1.0 s for 0.4,
the agree check 0.3 s for 0.02. The rest of each is macOS scanning every new
executable and library when it is first loaded, one at a time host-wide
(`XprotectService`, single-threaded, ~0.15 s each; a hard link to a file it
already scanned is not scanned again, a copy or clone is): 1.3 CPU-s per
candidate, more than its checks' own. Seven at once, `cargo test` took 6.3 s;
14 at once, 12.3 s; 28, 24 s: the queue for the scanner, not the cores.
Clones of trunk's build contend in the file system: one alone costs 0.1
CPU-s, each of 7 at once 0.6, of 14 at once 1.2.

What changed: trunk's proc-macro libraries are hard-linked into every build
(they are engineer's, so no agent process can change them; a library whose
sources are the repository's is cloned as before), clones run two at a time
host-wide, a candidate's checks wait for one slot, and the pool is sized by
memory (`checks = min(free GB / 1.5, 2 × cores / check_threads)`).

| width | build | wall s | CPU s | peak RSS MB | scan CPU s | code search s | counterexample search s | pool full |
|---|---|---|---|---|---|---|---|---|
| 128 | 732dbc4 | 777 | 757 | 2221 | 443 | 272 | 436 | 84% / 88% |
| 128 | links | 354 | 711 | 3243 | 162 | 136 | 150 | 67% / 64% |
| 128 | links, 14 checks | 363 | 799 | 4009 | 158 | | | |
| 128 | links, 28 checks | 362 | 838 | 3974 | 161 | | | |
| 128 | links, clones two at a time (7 checks) | 334 | 549 | 1922 | 162 | 122 | 146 | 63% / 65% |
| 500 | lazy (above) | 2895 | 3502 | 5790 | | 1177 | 1571 | 81% / 93% |
| 500 | links, clones two at a time (7 checks) | 945 | 1974 | 6567 | 617 | 368 | 498 | 81% / 79% |

Cores busy (CPU ÷ wall), width 500: 1.2 before, 2.1 after, plus 0.65 of the
scanner. More check slots than seven do not help on this Mac: the scanner,
one core, is the bottleneck (617 CPU-s over a 945 s run), not bon and not the
pool. The counterexample search's matrix (4 tests × 500 candidates) is 498 s
of it; each verdict is still a build of its own (a test's code runs there, so
it may not be shared), one new test binary for the scanner, and one clone.

**Trunk's build kept across bon processes**, width 4, `SLEEP=5 K=0`, the
same trunk twice (`bon code`, then `bon counterexample` on the trunk it pushed):

| project | build | code wall s, 1st / 2nd | counterexample wall s, 1st / 2nd |
|---|---|---|---|
| kernel | before | 62.7 / 62.7 | 42.1 / 43.1 |
| kernel | kept | 63.7 / 27.9 | 42.1 / 10.3 |
| bon | before | 130.4 / 124.4 | 73.8 / 76.0 |
| bon | kept | 126.4 / 86.4 | 72.8 / 29.7 |

The key is trunk's tree, its test and verify checks, and the toolchain the
checks see, so a sandbox whose `.bon/bon.toml` differs (another harness) is
another key. The kernel's kept build is 0.2 GB, bon's 0.8 GB; three are kept.

**Samples that read the prompt cache**, kernel sandbox, width 32, real Haiku
samples (`bon-sample --via claude`), the code search only:

| build | cache reads | cache writes | output | generation | code search s |
|---|---|---|---|---|---|
| before | 53,625 | 89,031 | 7,199 | $0.0220 | 6.9 |
| first leads | 127,875 | 14,781 | 7,585 | $0.0080 | 6.2 |

The others started 1.1 s after the first (its reply's first event).

**Real samples on bon's own source** (`PROJECT=bon`, Haiku one-shot, foil and
counterexample stubs), after the sandbox stopped carrying the answer
(`.bon/fix/`, `bench/`):

| width | applied | tests accept | Verus proves | distinct trees applied | pushed | code search s | generation | cache reads / writes |
|---|---|---|---|---|---|---|---|---|
| 16 | 10 | 0 | 0 | 10 | no (too few verified) | 49 | $0.066 | 1.33M / 94k |
| 64 | 34 | 0 | 0 | 32 | no (too few verified) | 81 | $0.225 | 5.57M / 110k |

At width 64: 13 replies had no edit blocks, 16 tried to write a check path
(src/gates.rs, src/spec.rs, examples/kernel.rs) and were refused, 1 SEARCH
did not match; of the 34 that applied, every one failed to compile (32:
`conflicting implementations of trait FromIterator<char>`, impls bon already
has in src/trusted.rs). The broken file, src/exec.rs, is past bon-sample's
220 KB context (14 files fit, in path order), and the prompt does not say
which check fails or why: the samples guessed. Peak RSS 14.1 GB (64 Claude
CLIs at once).

Before that, the sandbox carried the right file (`.bon/fix/src/exec.rs`, for
the code stub) and bon-sample showed it to the model: 4 of 16 and 39 of 64
samples were proved, and the search pushed. Those runs measured the bench's
leak, not the samples.
