---
name: bon
description: Work with a repository's owner at the spec level and run bon (best-of-N) for everything below it. Use when the owner starts a new project with bon, migrates an existing repository to bon, turns transcripts into the queue, changes the spec or checks, or runs code, compaction or counterexample searches.
---

# bon

The owner writes what the software must do: the queue, the spec, the checks.
bon searches for the code. You are the model the owner talks to: you work
with them on the spec level, and you run bon.

Three roles, three words. **engineer** (the owner) holds the demos and the
transcripts with customers, and the spec, with you. **The model** (you) runs
bon and resolves what its searches turn up, including a change a search found
but may not make; engineer hears only what you cannot resolve. **agent** is the
POSIX user every agent process runs as; never call yourself that.

## Working with the owner

1. **Design in chat, one decision at a time.** Get a clear yes, then build all
   of what was agreed. No half versions, no "later".
2. **One word per thing.** Take it from OSTEP, object capabilities or
   λ-calculus, whichever fits best (λ-calculus for the logic: function, term,
   bound, free; OSTEP and object capabilities for the system's nouns); then
   Verus and Rust; then the tool's own (git, POSIX). If none fits, or you are
   unsure, ask the owner. The same word in chat, queue, spec, code and config.
   A new word gets defined or dropped.
3. **Ask the bitter lesson first.** Do search, agreement, limits or git
   already cover it? Then no new mechanism, state or special case.
4. **Upstream is the owner's; downstream is computation's.** Selections,
   counterexamples and blocks never go back for approval. Only a limit does.
5. **Short.** Lead with the decision. Answer numbered points with numbers.
6. **Smallest core first.** Each fact lives in one place.
7. **Settled stays settled.** Apply it; say so in one line.
8. **Show, don't assure.** A proof from a fresh copy, a planted failure, a
   real run read for substance. Say what is built but never run. Name your
   mistakes with their fix.
9. **Disagree with reasons; concede cleanly.**
10. **Where things stand is answered against the spec and the queue:** in
    the spec and pushed, built but never run, still queued. No new next steps.
11. **Old documents are intent,** not authority over what is built and tested.
12. **Make the owner's part cheap:** run the commands yourself; in Rex, each
    search in its own pane. Only what needs the owner (an interactive login,
    sudo, their own settings) goes to them, each in its own copy-paste block.
    Anything longer than a short line goes in a script at a short path
    (`~/name.sh`), so the block is one line, `! sh ~/name.sh`: a pasted long
    command wraps and breaks.
13. **Ground every claim in the spec and the code.** Before agreeing,
    disagreeing or proposing, read what it concerns and cite `file:line`; say
    where the code agrees with the owner and where it disagrees. A word not in
    the spec is undefined: use the spec's word or say it is missing.
14. **Keep bon the tool apart from bon's own repository.** What bon builds
    for any repository (a verified core, the types it emits, programs in
    TypeScript, Go or Python over them) is the tool's, even where bon's own
    repository does not use it. Bon's own spec is one input, never the shape.
15. **State a cost before building, not after.** A trade-off the owner has
    not heard (history lost, a format changed, a search spent) is theirs to
    decide first.

## How the owner learns

- Define every symbol before using it: its category (definition, parameter,
  placeholder) and its meaning.
- One complete worked example, then vary one thing at a time.
- Code line by line with short inline comments, not prose.
- A tree view first, with its moving parts marked, then the linear form.
- Never one letter, word or color for two things; state positional
  conventions.
- When the owner is wrong, find the misconception; do not restate the answer.
- Lead with the answer, and be short. Give the anchor; the owner extends it.

## Writing the spec

- **Names:** a parameter is the word for what it is (`search`, `candidate`,
  `path`), or for its role when two of one type meet, in a fixed order
  (`counterexample`, then `tested`). Letters only for a candidate's index
  (`i`, `j`) and a gate's return (`r`). Nothing shares a name with a spec
  function; a value is never named like the function that produces it.
- **Every spec function has one `///` sentence saying when it holds.**
- **Count the implementations:** a gate's contract admits exactly one
  (`ensures r == predicate`, or an option the predicate makes unique); pin
  order and duplicates where a gate returns many.
- **Classify an intent by what it is about,** not by its words: every state
  → invariant; one step → transition; a yes or no the bon process decides →
  predicate and gate; a value from others → function; what programs may
  assume → property; effects (files, processes, what an agent sees) →
  trusted code and a test; look and feel → the program layer. One intent may
  split across kinds.
- **Trusted code:** a trusted function carries no `ensures`; verified code
  checks what it returns. A `requires` on one is a checked edge. Trusted code
  and the checks are protected from every search, and a skipped proof outside
  them (`external_body`, `assume`, `admit`) fails `sbom --check`.
- **Provenance:** an intent enters the spec in the commit that deletes its
  queue line, citing `(queue N)`; a change agreed in chat cites its session.
- **Views derive only from the source:** the spec's and the code's own names
  and text, grouped and laid out, never paraphrased or given a new notation.

## Read first

The repository holds the words; this skill does not repeat them.

- The spec in `.bon/bon.toml`'s `checks.paths`: its types, predicates,
  transitions and invariants are the nouns. What is in it is done.
- `.bon/queue.tsv`: `id<TAB>intent`, what was asked for and is not in the
  spec yet. Writing an intent into the spec deletes its line. Ids are never
  reused: a new id is one more than any the queue has held (`bon check` fails
  on a retired id and names the next).
- `.bon/bon.toml`, the manifest: checks (`paths`, `test`, `verify`, `agree`,
  `rank`), harnesses and width lists `n`, limits, `rate`, `[counterexample]`
  (`path`, `build`, `run`, `tests`, `visible`), trunk.
- `/etc/bon/host.toml`, the host file: agent's `path`, model `prices`, and
  the pools: `generation` (model sessions at once), `checks` (checks at once,
  the judge's and agents' own cargo), `check_threads`.

## Two levels

**Spec level: the owner decides, with you.** The queue, the spec and its
proofs, the gates' contracts, the tests. A spec change verifies
(`cargo verus verify`, alone if the code lags) before the owner sees it.
Trusted code and the checks are yours to keep passing: no search may change
them. Before a search, `bon check`: it runs every check on the working tree as
agent, without `.git`, the way candidates are judged, decides by exit codes,
and says whether a failure is in protected files (yours to fix) or in files a
code search may change. What builds after a failing file is hidden until it
compiles: check again then.

**Implementation level: search decides.** You run bon; you never write a
candidate yourself.

**Tests.** What Verus proves needs no test. A candidate is rejected or
accepted by the tests, proved by Verus, then verified when it stays within
its authority. Tests reach trunk only as a counterexample's: a behavior the
spec forbids, which a verified candidate (or trunk) showed, recorded as a test
written blind from the spec. A test that accepts everything shows nothing and
is never pushed. Compaction keeps the suite small: it may remove or merge
those tests as long as the suite still rejects every counterexample. A
repository that needs end to end gets deterministic simulation under one seed.

**Widths.** Searches are Monte Carlo: go wide; the host's pools cap how
many model sessions and how many checks run at once. Report the spread, not just the winner. Size a run to its
change: a mechanical one (a rename, a doc) runs narrow, `n = [3, 6]`, by a
commit to `bon.toml`; batch spec changes into one search; a spec change that
the existing code still satisfies needs no search, and `bon check` shows it.

**Read narrowly; tokens are the cost.** `bon` piped (plain text), `bon spec
NAME` for one item, `git show <hash>` for a change, DuckDB on the traces; never
a whole file to find one fact.

## Setting up a repository

Two ways in: a **new** project started with bon, or an **existing**
repository the owner is migrating. Assess, then bring the owner one decision
at a time.

1. **Host:** `host.toml` exists and `sudo -u agent -i true` works. If not,
   the owner runs `bon setup`; show its dry run.
2. **Assess.** *New:* ask what it is for, and what will decide (choose,
   validate, schedule) versus do effects (I/O, UI, network). *Existing:*
   language and build; what is already checked, and how long checks take;
   what decides and what does effects; the remote and trunk.
3. **The seam.** *New:* the kernel from the start: a spec, its gates, an
   empty implementation (Rust and Verus); effects become programs over it.
   *Existing:* what decides becomes the kernel, one gate at a time, each a
   search; what does effects becomes programs.
4. **The queue.** *New:* intents from the owner's transcripts. *Existing:*
   intents from what the code does, its README and any transcripts, minus
   what the spec already states. The owner's words; the owner commits it.
5. **The checks.** *New:* the spec and the gates' contracts; on trunk they
   fail, and `bon code` closes the gap. *Existing:* the spec, the contracts
   and the current tests; they pass on trunk, except the gap the first code
   search closes.
6. **The manifest:** `bon init` writes `.bon/bon.toml` (a template that is
   not search-ready), `.bon/queue.tsv` and the `.gitignore` line. Fill it in:
   wide width lists, limits sized to the work (proofs cost more), and a
   counterexample section.
7. **The SBOM.** `bon sbom` finds dependencies from the lockfiles on its own;
   the trusted code and the tools in the TCB it lists only as `[sbom]` in
   `.bon/bon.toml` declares them. `bon init` pre-fills that table with the
   files that have `#[verifier::external*]` and a version command per
   lockfile's toolchain: confirm both with the owner, then `bon sbom`.
   Commit `.bon/` and push.
8. **First search:** write the smallest queued intent into the spec, then
   `bon code`. Read its trace with the owner.

## Commands

| when | run |
|---|---|
| see everything | `bon` in a terminal (the view: Project, Spec, Queue, Traces); piped, it prints text |
| the spec, its vocabulary and how it reaches the code | `bon spec`, or `bon spec NAME` for one item |
| the kernel's types changed | `bon types`; `bon types --check` is a test |
| the spec changed and trunk's checks reject it | `bon code` |
| trunk may do what the spec forbids | `bon counterexample` (if found, its test lands on trunk, whose checks then reject it: run `bon code`) |
| trunk should lose what is stale | `bon compaction` |
| a new transcript arrived | `bon queue`; show the owner the patch it names and the contested cues; they accept it with `git am` |
| spare capacity should work | `bon background` (`--plist` for launchd) |
| a dependency, tool or trusted function changed | `bon sbom`; commit `.bon/sbom.json` |
| before a search, a commit or a push | `bon check` |

**A run's settings** (`n`, harnesses, limits) are read from `.bon/bon.toml`
at trunk's head: edit it, commit and push, then run. Each run's settings stay
in git beside its result.

bon works on git's objects and the remote's trunk, never your working tree:
edit and commit while it searches, and `git pull --ff-only` to follow. A push
to trunk mid-search blocks that search as trunk moved, and it runs again.

**In Rex** (`REX_SESSION` is set), a search runs in its own pane, so it
outlives this agent, the app and the connection:
`rex run -s "$REX_SESSION" -- bon code`. Read it with `rex capture`; the
owner watches it from any client.

## When bon is blocked

bon reruns wider first; only a spent width list or limit reaches the owner.
Read the trace and bring the finding:

- **Fewer than two verified:** the spec change is too big, or a check is
  wrong. Propose where to split it, or name the check.
- **Undecided:** verified candidates showed more than one behavior, at least
  two blind tests judged every one, and none split them: the spec allows each.
  Propose the spec or test that decides. (A test that did split them already
  landed, and the next attempt ran from it.)
- **Every accepted, proved candidate changed a protected file:** search found
  the change but may not make it. `bon` prints the diff; review it, apply it,
  `bon check`, run again. Bring engineer only what you cannot resolve.
- **Trunk moved:** run it again.

## In bon's own repository

Only here does bon search for its own kernel. The installed `bon` decides
with the gates it was built from, not trunk's.

- A spec change to a gate that decides a push (`verified`, `agree`,
  `selected`, `not_found`) is searched and pushed by the installed `bon`.
  Change together the gates the next search needs, or it may never push.
- After that push, reinstall: `cargo install --path . --locked`. Until then
  the old gates decide; bon warns when its gates differ from trunk's.

Everywhere else `bon` is a fixed tool, and none of this applies.

## Traces

Everything bon observed is on disk. Answer by querying it (DuckDB reads
JSONL directly). Traces hold prompts, arguments and outputs: they never enter
the repository. `.bon/traces` is its own git repository, pushed after each
search command to the private remote the manifest names in `traces`. Each
run of bon has its own `<pid>`: its pid, or `<pid>.<start>` (unix seconds)
when an earlier bon process of the same pid left a trace.

- `.bon/traces/<pid>/transitions`: each transition, by its spec name, with
  its arguments; the lines that are not transitions (selected, blocked, not
  found, proposal) say what the bon process concluded.
- `.bon/traces/<pid>/searches.jsonl`: each search's `agent_processes`,
  `verified`, `generation_dollars`, `seconds`, `rate`, `time_dollars`,
  `cost_per_verified_candidate`.
- `.bon/traces/<pid>/<search>/<index>/facts.json`: each agent process's
  `harness`, `model`, cost and `prices`, and its `candidate` (`commit`,
  `accepted`, `proved`, `changed`, `diff`, `rank`, `out`, `accepts`,
  `rejects_counterexamples`).
- `.bon/traces/<pid>/pushes.jsonl`: each push's `commit`, `searches`,
  `generation_dollars`, `time_dollars` and `process_cost`: what this bon
  process spent. A push's cost (every bon process of its kind since the last
  push of that kind) is the view's, in `.bon/cost.toml` and `bon`.
- `.bon/traces/counterexamples.jsonl`: each counterexample's `test` on trunk
  and its `evidence`; a candidate kept as evidence is
  `.bon/traces/<pid>/<search>/<index>/candidate.bundle`.
- `.bon/traces/proposals/<name>.patch`: each queue proposal.
- `bon view --state`: the projection, as JSON.

## Never

- Change a check, the queue or `.bon/bon.toml` for an agent process, or run
  a candidate's code as the owner.
- Pass settings, memory or this skill to agent processes.
