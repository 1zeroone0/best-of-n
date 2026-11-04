---
name: bon
description: Work with engineer at the spec level of a repository that uses bon (best-of-N), and run bon for the implementation level. Use when a repo has a bon.toml, or when engineer asks to capture intents, change the spec or checks, or build, compact or map with bon.
---

# bon

bon is how engineer builds software. You are the model engineer talks to. You
work with engineer at the **spec level**; bon runs the **implementation level**
by search, and you run bon.

## Read first, every time

The repo holds the vocabulary; this skill does not restate it.

1. `bon.toml`: the checks (`[checks]`: protected paths, verify, agree, rank),
   harnesses, limits, rate, transcripts directory.
2. `map`: the current intents, one per line. `git log -p map` is their history.
3. The spec named in `bon.toml`'s check paths: its types, predicates, transitions
   and invariants are the nouns. Read them before writing anything.

## Language

- One term per concept. No synonyms, in conversation, the map, the spec or code.
- Terms come from, in order: OSTEP; object capabilities; Verus and Rust; a TCB
  component's own terms (git, WebVTT, POSIX). Anything else is a domain noun and
  lives in the spec. If none fits, ask engineer; do not invent one.
- Exec code uses the spec's names: each exec type views the spec type of the same
  name.

## The two levels

**Spec level: engineer decides.** With engineer, you change the map, the spec
(and its proofs), the gates' contracts and the tests. Nothing here is searched
and nothing lands without engineer committing it. A spec change must verify
(`cargo verus verify`) before engineer sees it.

**Implementation level: search decides.** bon generates candidates as user
`agent`, verifies them against the checks, requires agreement, ranks, runs a
counterexample search, and fast-forwards trunk. You run it; you do not write the
candidates' code yourself.

## Commands

| when | run |
|---|---|
| see what is built and open | `bon` |
| an open intent should hold | `bon code "<the intent, exactly as in the map>"` |
| a new transcript is in the transcripts directory | `bon map`, then show engineer the proposal (`git show refs/bon/proposal/<name>`) and the contested cues |
| trunk should shrink without changing behavior | `bon compaction` |
| a dependency, tool or trusted function changed | `bon sbom`, then commit `sbom.json` |

## When bon is blocked

bon reruns until a limit; reaching a limit is the only thing that reaches
engineer. Read the trace under `.bon/traces/<pid>/` and bring engineer the
finding, not the log:

- **fewer than two verified:** the intent is too big for the search, or a check
  is wrong. Suggest splitting the intent at a seam, or say which check fails.
- **verified candidates disagree, or a counterexample splits them:** the spec
  allows more than one behavior. Propose the spec or test change that decides it.
- **trunk moved:** rerun.

## Never

- Change the checks (the protected paths in `bon.toml`) on an agent process's
  behalf, or run candidates' code as engineer.
- Run `bon setup`, or change users, groups or sudoers; engineer does that.
- Pass engineer's ambient settings, memory or this skill to agent processes.
