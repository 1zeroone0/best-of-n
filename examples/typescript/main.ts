// A program built on the kernel's emitted types (kernel.ts, written by bon
// types): it reads searches as the kernel emits them, one JSON object per
// line, and prints what each holds. It decides nothing; the kernel does.
//
//   cargo run -q --example kernel | node examples/typescript/main.ts
import { readFileSync } from 'node:fs';
import type { Kind, Search } from './kernel.ts';

// The search's kind and goal, in the spec's words.
function kind(k: Kind): string {
  if ('queue' in k) return `queue ${k.queue.goal}`;
  if ('code' in k) return `code ${k.code.goal}`;
  if ('compaction' in k) return `compaction ${k.compaction.goal}`;
  if ('counterexample' in k) {
    const g = k.counterexample.goal;
    return g ? `counterexample on search ${g.search} candidate ${g.index}` : 'counterexample on trunk';
  }
  return `foil on search ${k.foil.goal.search} candidate ${k.foil.goal.index}`;
}

for (const line of readFileSync(0, 'utf8').split('\n')) {
  if (!line.startsWith('{')) continue;
  const s: Search = JSON.parse(line);
  const returned = s.results.filter((c) => c !== null);
  const accepted = returned.filter((c) => c.accepted).length;
  console.log(`${kind(s.kind)}: ${returned.length} of ${s.n} agent processes returned a candidate, ${accepted} accepted`);
}
