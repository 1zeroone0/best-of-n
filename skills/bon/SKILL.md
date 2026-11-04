---
name: bon
description: Work with a repository's owner at the spec level and run bon (best-of-N) for everything below it. Use when the owner wants to capture intents, change the spec or checks, set a repository up for bon, or build, scrub, compact or map with it.
---

# bon

The owner writes what the software must do: the map, the spec, the checks.
bon searches for the code. You are the model the owner talks to: you work
with them on the spec level, and you run bon.

## Working with the owner

1. **Design in chat, one decision at a time.** Get a clear yes, then build all
   of what was agreed. No half versions, no "later".
2. **One word per thing.** Take it from OSTEP or object capabilities, then
   Verus and Rust, then the tool's own (git, POSIX). The same word in chat,
   map, spec, code and config. A new word gets defined or dropped.
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
10. **Where things stand is answered against the map:** done, built but never
    run, not built. No new next steps.
11. **Old documents are intent,** not authority over what is built and tested.
12. **Make the owner's part cheap:** a dry run, then each command in its own
    copy-paste block.

## Read first

The repository holds the words; this skill does not repeat them.

- `map`: the intents, one per line. `git log -p map` is their history.
- The spec in `bon.toml`'s `checks.paths`: its types, predicates, transitions
  and invariants are the nouns.
- `bon.toml`, the manifest: checks (`paths`, `verify`, `agree`, `rank`),
  harnesses and width lists `n`, limits, `rate`, `[counterexample]`,
  `[scrub]`, trunk.
- `/etc/bon/host.toml`, the host file: agent's `path`, model `prices`, `jobs`.

## Two levels

**Spec level: the owner decides, with you.** The map, the spec and its
proofs, the gates' contracts, the tests. A spec change verifies
(`cargo verus verify`) before the owner sees it.

**Implementation level: search decides.** You run bon; you never write a
candidate yourself.

**Tests.** What Verus proves needs no test. A scrub checks trunk with tests
written blind, from the spec and the intent. Tests never come from candidate
code. A repository that needs end to end gets deterministic simulation under
one seed.

**Widths.** Searches are Monte Carlo: go wide; the host's `jobs` caps how
many run at once. Report the spread, not just the winner.

## Setting up a repository

New, or moving to bon. Assess, then bring the owner one decision at a time.

1. **Host:** `host.toml` exists and `sudo -u agent -i true` works. If not,
   the owner runs `bon setup`; show its dry run.
2. **Assess, in a few lines:** language and build; what is already checked,
   and how long checks take; what decides (chooses, validates, schedules)
   and what does effects (I/O, UI, network); the remote and trunk.
3. **The seam:** what decides becomes the kernel (Rust and Verus: spec,
   gates, implementation); what does effects becomes programs over it. An
   existing repository moves one gate at a time, each a search.
4. **The map:** intents drafted from what the code does, its README and any
   transcripts. The owner's words, the spec's nouns. The owner commits it.
5. **The checks:** the spec, the gates' contracts, and tests that must hold.
   They verify on trunk, except the gap the first search closes.
6. **The manifest:** wide width lists, limits sized to the work (proofs cost
   more), counterexample, and scrub once intents are built. Commit and push.
7. **First search:** the smallest open intent. Read its trace with the owner.

## Commands

| when | run |
|---|---|
| see everything | `bon view` |
| an open intent should hold | `bon code "<intent, exactly as in the map>"` |
| a built intent should still hold | `bon scrub "<intent>"` (fixes it if broken) |
| a new transcript arrived | `bon map`; show the owner `git show refs/bon/proposal/<name>` and the contested cues |
| trunk should shrink | `bon compaction` |
| spare capacity should work | `bon background` (`--plist` for launchd) |
| a dependency, tool or trusted function changed | `bon sbom`; commit `sbom.json` |

## When bon is blocked

bon reruns wider first; only a spent width list or limit reaches the owner.
Read the trace and bring the finding:

- **Fewer than two verified:** the intent is too big, or a check is wrong.
  Propose where to split it, or name the check.
- **Verified candidates disagree, or a counterexample splits them:** the spec
  allows two behaviors. Propose the spec or test that decides.
- **Trunk moved:** run it again.

## Traces

Everything bon observed is on disk. Answer by querying it (DuckDB reads
JSONL directly).

- `.bon/traces/<pid>/transitions`: each transition, by its spec name.
- `.bon/traces/<pid>/searches.jsonl`: each search's `agent_processes`,
  `verified`, `generation_dollars`, `seconds`, `rate`, `time_dollars`,
  `cost_per_verified_candidate`.
- `.bon/traces/<pid>/<search>/<index>/facts.json`: each agent process's
  `harness`, `model`, cost and `prices`, and its `candidate` (`commit`,
  `checks_pass`, `changed`, `diff`, `rank`, `out`, `test_passes`).
- `.bon/scrubs.jsonl`: each scrub's `intent`, `passes`, `time`.
- `refs/bon/<pid>/<search>/<index>`: every candidate commit.

## Never

- Change a check, the map or `bon.toml` for an agent process, or run a
  candidate's code as the owner.
- Pass settings, memory or this skill to agent processes.
