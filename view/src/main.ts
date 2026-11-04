export {};
type Tone = 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'indigo' | 'violet' | 'neutral';
interface MapIntent {
    intent: string;
    source?: string;
    status?: string;
    landed?: {
        commit?: string;
        time?: number;
        pushed?: boolean;
    } | null;
    scrub?: {
        time?: number;
        passes?: boolean;
    } | null;
}
interface Candidate {
    index: number;
    facts?: {
        harness?: string;
        model?: string;
        cost_microdollars?: number;
        killed?: boolean;
        over_limit?: boolean;
        price_mismatch?: boolean;
        prices?: unknown;
        candidate?: {
            commit?: string;
            base?: string;
            checks_pass?: boolean;
            changed?: string[];
            diff?: number;
            rank?: number;
            out?: unknown[];
            test_passes?: [
                number,
                boolean
            ][];
        };
    };
    logs?: string[];
}
interface Summary {
    kind?: string;
    goal?: string;
    time?: number;
    agent_processes?: number;
    verified?: number;
    generation_dollars?: number;
    seconds?: number;
    rate?: number;
    time_dollars?: number;
    cost_per_verified_candidate?: number | null;
}
interface Search {
    search: number;
    summary?: Summary | null;
    selected?: number | null;
    candidates?: Candidate[];
}
interface Process {
    pid: number;
    running?: boolean;
    modified?: number;
    transitions?: string[];
    searches?: Search[];
}
interface SpecItem {
    kind: string;
    name: string;
    doc?: string;
    reads?: string[];
    updates?: string[];
}
interface SpecField {
    name: string;
    type?: string;
    sharding?: string;
    doc?: string;
}
interface Trunk {
    commit: string;
    author?: string;
    time?: number;
    subject?: string;
    trace?: string;
    pushed?: boolean;
    by_agent?: boolean;
}
interface Harness {
    model?: string;
    name?: string;
    n?: number[];
}
interface State {
    repo?: {
        name?: string;
        head?: string;
        remote_head?: string;
        remote?: string;
        trunk?: string;
        pushed?: boolean;
        now?: number;
    };
    map?: MapIntent[];
    spec?: {
        path?: string;
        fields?: SpecField[];
        items?: SpecItem[];
    } | null;
    processes?: Process[];
    trunk?: Trunk[];
    device?: {
        jobs?: number;
        path?: string[];
        prices?: unknown;
    } | null;
    manifest?: {
        harness?: Harness[];
        counterexample?: {
            harness?: Harness[];
        };
        scrub?: {
            harness?: Harness[];
        };
        rate?: number;
        [key: string]: unknown;
    } | null;
}
const app = document.querySelector<HTMLDivElement>('#app')!;
let data: State = {};
let ready = false;
let connection = true;
let pending = false;
let lastPayload = '';
let filter: number | null = null;
let visibleCount = 12;
const opened = new Set<string>();
const openCandidates = new Set<string>();
const e = (v: unknown): string => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const nf = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });
const n = (v?: number): string => v == null ? '—' : nf.format(v);
const money = (v?: number | null): string => v == null || !Number.isFinite(v) ? '—' : '$' + v.toFixed(v !== 0 && v < .01 ? 4 : 2);
const short = (v?: string): string => v ? v.slice(0, 8) : '—';
const intentArg = (value: string): string => '"' + value.replace(/["\\$`]/g, '\\$&') + '"';
const verified = (c: Candidate): boolean => c.facts?.candidate?.checks_pass === true;
const keyOf = (p: Process, s: Search): string => `${p.pid}/${s.search}`;
function relative(time?: number): string {
    if (!time) return 'not recorded';
    const diff = Math.max(0, (data.repo?.now ?? Date.now() / 1000) - time);
    return diff < 60 ? 'just now' : diff < 3600 ? `${Math.floor(diff / 60)}m ago` : diff < 86400 ? `${Math.floor(diff / 3600)}h ago` : `${Math.floor(diff / 86400)}d ago`;
}
function timestamp(time?: number): string {
    return `<time ${time ? `datetime="${new Date(time * 1000).toISOString()}" title="${e(new Date(time * 1000).toLocaleString())}"` : ''}>${relative(time)}</time>`;
}
function icon(name: string, size = 16): string {
    const paths: Record<string, string> = {
        branch: '<circle cx="6" cy="4" r="2"/><circle cx="6" cy="20" r="2"/><circle cx="18" cy="5" r="2"/><path d="M6 6v12m0-3c0-7 12-2 12-8"/>',
        search: '<circle cx="6" cy="5" r="2"/><circle cx="18" cy="12" r="2"/><circle cx="6" cy="19" r="2"/><path d="M6 7v10m2-12h3a7 7 0 0 1 7 5M8 19h3a7 7 0 0 0 7-5"/>',
        arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
        chevron: '<path d="m9 5 7 7-7 7"/>',
        copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M15 8V3H3v13h5"/>'
    };
    return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] ?? paths.search}</svg>`;
}
const aliases: Record<string, string> = { granted: 'grant', returned: 'wait', 'agent processes returned': 'wait', retained: 'retain', landed: 'fast_forward', built: 'map', open: 'map', broken: 'broken', candidate: 'Candidate', candidates: 'Candidate', intent: 'Intent', selected: 'selected', verified: 'verified', agreed: 'agreed', checks_pass: 'verified' };
function word(name: string, label = name): string {
    return `<span class="word" tabindex="0" data-word="${e(name)}" aria-describedby="spec-tip">${e(label)}</span>`;
}
function pill(label: string, tone: Tone): string { return `<span class="pill ${tone}"><i></i>${word(label)}</span>`; }
function command(value: string): string {
    return `<button class="command" data-copy="${e(value)}" title="Copy command"><code>${e(value)}</code>${icon('copy', 14)}<span class="sr-only">Copy command</span></button>`;
}
interface Entry {
    key: string; p: Process; s: Search; trace: string[]; children: Entry[]; parent?: Entry;
    landed?: Trunk; selected?: number; count: number; v: number; cost?: number;
    outcome: string; tone: Tone; reason: string; time: number;
}
interface Line { key: string; entry?: Entry; commit?: Trunk; time: number }
let entries = new Map<string, Entry>();
let lines: Line[] = [];
let totals = { count: 0, verified: 0, cost: 0 };
let revision = 0;
let projected = -1;
function project(): void {
    entries = new Map();
    totals = { count: 0, verified: 0, cost: 0 };
    const commitByHash = new Map((data.trunk ?? []).map(t => [t.commit, t]));
    const matched = new Set<string>();
    for (const p of data.processes ?? []) {
        const segments: string[][] = [];
        for (const t of p.transitions ?? []) {
            if (/^grant(?: |$)/.test(t)) segments.push([]);
            segments.at(-1)?.push(t);
        }
        for (const [i, s] of (p.searches ?? []).entries()) {
            const cs = s.candidates ?? [];
            const trace = segments.length === p.searches?.length ? segments[i] ?? [] : [];
            const v = cs.filter(verified).length;
            const generation = s.summary?.generation_dollars ?? (cs.some(c => c.facts?.cost_microdollars != null) ? cs.reduce((a, c) => a + (c.facts?.cost_microdollars ?? 0) / 1e6, 0) : undefined);
            const cost = generation == null && s.summary?.time_dollars == null ? undefined : (generation ?? 0) + (s.summary?.time_dollars ?? 0);
            const exact = (data.trunk ?? []).find(t => t.trace?.replace(/^\.bon\/traces\//, '').startsWith(`${p.pid}/${s.search}/`));
            // The commit is also useful when older traces have no selected index.
            const landed = exact ?? cs.map(c => commitByHash.get(c.facts?.candidate?.commit ?? '')).find(Boolean);
            if (landed) matched.add(landed.commit);
            const entry: Entry = { key: keyOf(p, s), p, s, trace, children: [], landed, selected: s.selected ?? cs.find(c => c.facts?.candidate?.commit === landed?.commit && landed)?.index, count: cs.length, v, cost, outcome: 'returned', tone: 'neutral', reason: 'Agent processes returned. No further transition recorded.', time: s.summary?.time ?? p.modified ?? 0 };
            entries.set(entry.key, entry);
            totals.count += cs.length; totals.verified += v; totals.cost += cost ?? 0;
        }
    }
    for (const entry of entries.values()) {
        if (entry.s.summary?.kind === 'counterexample') {
            const target = /^search (\d+) candidate/.exec(entry.s.summary.goal ?? '')?.[1];
            const parent = entries.get(`${entry.p.pid}/${target}`);
            if (parent && parent !== entry) { parent.children.push(entry); entry.parent = parent; }
        }
    }
    for (const entry of entries.values()) resolve(entry);
    lines = [...entries.values()].filter(en => !en.parent).map(en => ({ key: en.key, entry: en, time: Math.max(en.time, ...en.children.map(c => c.time)) }));
    for (const commit of data.trunk ?? []) {
        if (!commit.by_agent || !matched.has(commit.commit)) lines.push({ key: `commit-${commit.commit}`, commit, time: commit.time ?? 0 });
    }
    lines.sort((a, b) => b.time - a.time || (b.entry?.s.search ?? -1) - (a.entry?.s.search ?? -1));
    projected = revision;
}
function resolve(en: Entry): void {
    const { s, p, trace } = en;
    const terminal = trace.find(t => /^(blocked|broken)/.test(t));
    if (terminal) {
        en.outcome = terminal.startsWith('broken') ? 'broken' : 'blocked';
        en.tone = en.outcome === 'broken' ? 'red' : 'yellow';
        en.reason = terminal.replace(/^(blocked|broken):?\s*/, '') + '. ' + (en.outcome === 'broken' ? 'bon starts a code search carrying the test.' : 'bon reruns wider, as the width list allows.');
    } else if (s.summary?.kind === 'counterexample') {
        const members = (en.parent?.s.candidates ?? []).filter(verified).map(c => c.index);
        if (en.parent?.s.summary?.kind === 'compaction') members.push(-1);
        const split = (s.candidates ?? []).filter(verified).some(c => {
            const tests = new Map(c.facts?.candidate?.test_passes ?? []);
            const targets = members.length ? members : [...tests.keys()];
            return targets.some(i => !tests.has(i)) || new Set(targets.map(i => tests.get(i))).size > 1;
        });
        const complete = s.summary?.seconds != null || trace.some(t => /^(fast_forward|retain)/.test(t));
        en.outcome = complete ? split ? 'split' : 'cleared' : p.running ? 'running' : 'returned';
        en.tone = split ? 'red' : complete ? 'green' : 'orange';
        en.reason = complete ? split ? 'A verified counterexample test splits the agreed candidates.' : 'No verified counterexample test splits the agreed candidates.' : `${en.count} agent processes returned; ${en.v} candidates verified.`;
    } else if (trace.some(t => /^retain/.test(t)) || en.landed?.subject?.startsWith('scrub:')) {
        en.outcome = 'retained'; en.tone = 'violet'; en.reason = 'The agreed scrub test passes on trunk and is retained.';
    } else if (en.landed || trace.some(t => /^fast_forward/.test(t)) || en.children.some(c => c.trace.some(t => /^fast_forward/.test(t)))) {
        en.outcome = 'fast_forward'; en.tone = 'indigo'; en.reason = 'Trunk fast-forwarded to the selected candidate.';
    } else if (p.running && s === p.searches?.at(-1)) {
        en.outcome = 'running'; en.tone = 'orange'; en.reason = `${en.count} agent processes returned; ${en.v} candidates verified.`;
    }
}
interface Stage { label: string; value: string; tone: Tone; done: boolean }
function stages(en: Entry): Stage[] {
    const { s } = en;
    const cs = s.candidates ?? [];
    const v = cs.filter(verified);
    const outs = v.map(c => JSON.stringify(c.facts?.candidate?.out));
    const hasOut = v.every(c => c.facts?.candidate?.out != null);
    const agreed = en.selected != null || (v.length >= 2 && hasOut && new Set(outs).size === 1);
    const differs = hasOut && new Set(outs).size > 1;
    const ce = en.children.at(-1);
    const counter = s.summary?.kind === 'counterexample';
    const ceOutcome = counter ? en.outcome : ce?.outcome ?? (en.outcome === 'fast_forward' ? 'cleared' : undefined);
    const end = ['fast_forward', 'retained', 'blocked', 'broken'].includes(en.outcome);
    const width = Math.max(s.summary?.agent_processes ?? 0, en.count);
    return [
        { label: 'granted', value: width ? n(width) : '—', tone: 'orange', done: width > 0 || en.trace.some(t => t.startsWith('grant')) },
        { label: 'agent processes returned', value: width ? `${en.count} / ${width}` : n(en.count), tone: en.count >= width && width > 0 ? 'yellow' : 'orange', done: en.count > 0 },
        { label: 'verified', value: n(en.v), tone: en.v ? 'green' : 'red', done: en.count > 0 },
        { label: differs ? 'not agreed' : 'agreed', value: agreed ? n(en.v) : differs ? 'different output' : en.v < 2 && en.count ? 'fewer than 2' : 'not recorded', tone: agreed ? 'green' : differs ? 'red' : 'yellow', done: agreed || differs },
        { label: 'selected', value: en.selected == null ? '—' : `#${en.selected}`, tone: 'blue', done: en.selected != null },
        { label: 'counterexample', value: ceOutcome ?? '—', tone: ceOutcome === 'split' ? 'red' : ceOutcome === 'cleared' ? 'green' : 'yellow', done: ceOutcome != null },
        { label: en.outcome === 'retained' ? 'retain' : end ? en.outcome : 'fast_forward / retain / blocked', value: end ? '✓' : '—', tone: end ? en.tone : 'neutral', done: end }
    ];
}
function diagram(en: Entry): string {
    return `<div class="state-path" aria-label="Search path">${stages(en).map((a, i) => `${i ? `<span class="state-arrow">${icon('arrow', 16)}</span>` : ''}<div class="state-node ${a.tone} ${a.done ? 'filled' : 'waiting'}"><span class="state-value">${e(a.value)}</span><span class="state-label">${word(a.label)}</span></div>`).join('')}</div>`;
}
function dots(en: Entry): string {
    const ss = stages(en);
    return `<span class="path-dots" aria-label="${e(ss.map(a => a.label + ': ' + a.value).join(' → '))}">${ss.map(a => `<i class="${a.tone} ${a.done ? 'filled' : ''}" title="${e(a.label + ': ' + a.value)}"></i>`).join('')}</span>`;
}
function headerHTML(): string {
    return `<div class="repository">${icon('branch')}<strong>${e(data.repo?.name ?? 'repository')}</strong><span class="head">${word('trunk', data.repo?.trunk ?? 'main')} <code>${e(short(data.repo?.head))}</code></span>${pill(data.repo?.pushed ? 'pushed' : 'not pushed', data.repo?.pushed ? 'indigo' : 'blue')}</div><div class="header-cost">${totals.verified ? money(totals.cost / totals.verified) : '—'} per ${word('verified', 'verified candidate')} <span>·</span> ${totals.count ? Math.round(totals.verified / totals.count * 100) : 0}% of candidates verified</div><span class="live ${connection ? '' : 'offline'}"><i class="dot ${connection ? 'violet' : 'red'}"></i>${connection ? 'live' : 'waiting'}</span>`;
}
function nowHTML(): string {
    const running = (data.processes ?? []).filter(p => p.running);
    const activeP = running[0];
    const active = activeP ? entries.get(`${activeP.pid}/${activeP.searches?.at(-1)?.search}`) : undefined;
    if (active) {
        const parent = active.parent ?? active;
        const completed = active.outcome !== 'running' && active.s.summary?.seconds != null;
        return `<div class="now-heading"><h1>Now</h1><span class="running orange"><i class="dot orange"></i>${running.length === 1 ? 'bon process running' : `${running.length} bon processes running`}</span></div><div class="now-card"><div class="now-title"><span class="search-symbol orange">${icon('search', 21)}</span><div><div class="eyebrow">${word(parent.s.summary?.kind ?? 'search')} <span> / ${e(parent.key)}</span></div><h2>${e(parent.s.summary?.goal ?? 'Goal not recorded')}</h2></div><a class="text-link" href="#${e(parent.key)}">Open search ${icon('arrow', 15)}</a></div>${diagram(parent)}<p class="now-note">${completed ? 'Last recorded path: ' : ''}${e(active.reason)}${completed ? ' The bon process is still running.' : ''}</p></div>`;
    }
    const latest = lines[0];
    const next = data.map?.find(i => i.status === 'open');
    let sentence = 'No search has run yet.';
    if (latest?.commit) sentence = `The owner committed “${latest.commit.subject ?? short(latest.commit.commit)}” to trunk.`;
    else if (latest?.entry) {
        const en = latest.entry;
        sentence = en.outcome === 'fast_forward' ? `Trunk fast-forwarded${en.s.summary?.goal ? `: ${en.s.summary.goal}` : '. Goal not recorded.'}` : en.outcome === 'retained' ? `The last scrub was retained${en.s.summary?.goal ? `: ${en.s.summary.goal}` : '. Goal not recorded.'}` : `The last search ${en.outcome}. ${en.reason}`;
    }
    return `<div class="now-heading"><h1>Now</h1><span class="muted">No searches running</span></div><div class="now-calm"><p>${e(sentence)} <span class="muted">${latest ? relative(latest.time) : ''}</span></p>${next ? `<div class="next-command"><span class="eyebrow">NEXT OPEN INTENT</span>${command(`bon code ${intentArg(next.intent)}`)}</div>` : '<p class="settled">No open intents on the map.</p>'}</div>`;
}
function mapHTML(): string {
    const intents = data.map ?? [];
    return `<div class="section-heading"><h2>${word('map', 'Map')}</h2><span>${intents.length} intents</span></div><div class="map-list">${intents.map((item, index) => {
        const scrubbed = item.scrub?.passes && (item.scrub.time ?? 0) >= (item.landed?.time ?? 0);
        const tone: Tone = item.status === 'broken' ? 'red' : item.status === 'open' ? 'orange' : scrubbed ? 'violet' : 'blue';
        return `<a id="intent-${index}" class="map-intent ${filter === index ? 'active' : ''}" href="#intent/${index}" aria-label="Filter timeline to ${e(item.intent)}" ${filter === index ? 'aria-current="true"' : ''}><div class="map-intent-title"><span class="dot ${tone}"></span><span>${e(item.intent)}</span></div><div class="map-meta"><span class="status-text ${tone}">${word(item.status ?? 'open')}</span><span>${word('scrub')} ${item.scrub ? timestamp(item.scrub.time) : '—'}</span><span>${word('landed')} ${item.landed ? timestamp(item.landed.time) : '—'}</span></div></a>`;
    }).join('') || '<p class="empty">The map holds intents, one per line. None are recorded yet.</p>'}</div><p class="map-note">An intent shows its searches here.<br><span class="key-hint">Hover or focus a word for its <code>///</code> line.</span></p>`;
}
function searchSummary(en: Entry, child = false): string {
    const { s } = en;
    return `<summary class="timeline-summary"><span class="line-chevron">${icon('chevron', 12)}</span><span class="line-goal">${child ? '<span class="counter-label">counterexample</span> ' : ''}${e(s.summary?.goal ?? 'not recorded')}<span class="line-record"><span class="line-kind">${e(s.summary?.kind ?? 'kind not recorded')}</span>${en.landed ? `<span class="landed-commit" title="${e(en.landed.commit)}">${word('trunk')} <code>${short(en.landed.commit)}</code></span>` : ''}</span></span>${dots(en)}<span class="outcome ${en.tone}">${word(en.outcome)}</span><span class="line-cost">${money(en.cost)}</span><span class="line-time">${timestamp(s.summary?.time ?? en.p.modified)}</span></summary>`;
}
function candidateSummary(c: Candidate, en: Entry): string {
    const f = c.facts ?? {}; const v = f.candidate;
    return `<summary><span class="candidate-index">#${c.index}${en.selected === c.index ? '<span class="selected-mark" title="selected">◆</span>' : ''}</span><span class="candidate-model"><strong>${e(f.model ?? 'not recorded')}</strong><small>${e(f.harness ?? 'not recorded')} · <code>${short(v?.commit)}</code></small></span><span class="checks ${verified(c) ? 'green' : 'orange'}">${word(verified(c) ? 'verified' : v?.checks_pass === false ? 'not verified' : 'checks', verified(c) ? 'verified' : v?.checks_pass === false ? 'not verified' : 'not recorded')}</span><span class="numeric">${money(f.cost_microdollars == null ? undefined : f.cost_microdollars / 1e6)}</span><span class="numeric">${n(v?.rank)}</span><span class="numeric">${n(v?.diff)}</span><span class="candidate-log-count">${c.logs?.length ?? 0} logs ${icon('chevron', 12)}</span></summary>`;
}
function candidateContent(c: Candidate, en: Entry): string {
    const f = c.facts ?? {}; const v = f.candidate;
    return `<div class="candidate-facts"><div><div class="eyebrow">${word('checks')}</div><p>${verified(c) ? 'Every check passes.' : v?.checks_pass === false ? 'The candidate is not verified. The logs record the checks.' : 'No checks recorded yet.'}</p>${['killed', 'over_limit', 'price_mismatch'].filter(k => f[k as keyof typeof f]).map(k => `<span class="fact-flag">${word(k)}</span>`).join('')}</div><div><div class="eyebrow">${word('changed')} / ${word('diff')}</div><p>${(v?.changed ?? []).map(path => `<code>${e(path)}</code>`).join('<br>') || 'No changed paths recorded.'}</p><p class="muted">diff: ${n(v?.diff)} · ${v?.base ? `base ${short(v.base)}` : 'base not recorded'}</p></div><div><div class="eyebrow">${word('out')} / ${word('test_passes')}</div><pre>${e(JSON.stringify(v?.out ?? []))}</pre><p>${v?.test_passes?.length ? v.test_passes.map(([i, pass]) => `#${i}: ${pass ? 'passes' : 'does not pass'}`).join(' · ') : 'No test_passes recorded.'}</p></div></div><div class="log-list"><span class="eyebrow">logs</span>${(c.logs ?? []).map(file => `<button class="log-button" data-log="${e(`${en.key}/${c.index}/${file}`)}">${e(file)}</button>`).join('') || '<span class="muted">No logs recorded.</span>'}</div><div class="inline-log" hidden><div class="log-heading"><code></code><button data-close-log aria-label="Close log">×</button></div><pre></pre></div>`;
}
function searchBodyHTML(en: Entry): string {
    return `<div class="search-context"><code>${e(en.key)}</code><span>${en.s.summary?.kind ? word(en.s.summary.kind) : 'kind not recorded'}</span><span>${en.s.summary?.time ? timestamp(en.s.summary.time) : 'time not recorded; using process modified'}</span><span class="push-right">${en.count} candidates · rank ↓, diff ↑</span></div>${diagram(en)}<p class="search-explanation ${en.tone}"><i class="dot ${en.tone}"></i>${e(en.reason)}</p><div class="candidate-table"><div class="candidate-head"><span>${word('candidate', 'index')}</span><span>model / commit</span><span>${word('checks')}</span><span class="numeric">cost</span><span class="numeric">${word('rank')}</span><span class="numeric">${word('diff')}</span><span>logs</span></div><div class="candidate-rows"></div></div><div class="search-foot"><span>${en.v} of ${en.count} candidates ${word('verified')}</span><span>${en.selected == null ? 'selected not recorded' : `selected #${en.selected}`}</span></div><details class="transitions"><summary>Recorded transitions <span>${en.trace.length ? 'search' : 'bon process'}</span>${icon('chevron', 12)}</summary><div class="trace-list">${(en.trace.length ? en.trace : en.p.transitions ?? []).map(t => { const [name, ...rest] = t.split(' '); return `<code>${word(name ?? '')} ${e(rest.join(' '))}</code>`; }).join('') || '<span class="muted">No transitions recorded.</span>'}</div></details>`;
}
// Each stable island compares its markup before touching the DOM. Search and
// candidate bodies are separate islands, so polling cannot close or replace them.
const markup = new WeakMap<Element, string>();
function attr(el: Element, name: string, value: string): void { if (el.getAttribute(name) !== value) el.setAttribute(name, value); }
function hidden(el: HTMLElement, value: boolean): void { if (el.hidden !== value) el.hidden = value; }
function put(el: Element, html: string): void { if (markup.get(el) !== html) { el.innerHTML = html; markup.set(el, html); } }
function syncCandidates(body: Element, en: Entry): void {
    const list = body.querySelector('.candidate-rows')!;
    if (list.querySelector('.empty') && en.count) { list.replaceChildren(); markup.delete(list); }
    const candidates = [...(en.s.candidates ?? [])].sort((a, b) => (b.facts?.candidate?.rank ?? -Infinity) - (a.facts?.candidate?.rank ?? -Infinity) || (a.facts?.candidate?.diff ?? Infinity) - (b.facts?.candidate?.diff ?? Infinity) || a.index - b.index);
    const existing = new Map([...list.children].map(el => [(el as HTMLElement).dataset.key, el]));
    const keep = new Set<Element>();
    let cursor = list.firstElementChild;
    for (const c of candidates) {
        const key = `${en.key}/${c.index}`;
        let row = existing.get(key) as HTMLDetailsElement | undefined;
        if (!row) { row = document.createElement('details'); row.dataset.key = key; row.dataset.candidate = key; row.innerHTML = '<summary></summary><div class="candidate-details"></div>'; }
        attr(row, 'class', `candidate ${c.index === en.selected ? 'is-selected' : ''}`);
        const summary = row.firstElementChild!;
        const template = document.createElement('template'); template.innerHTML = candidateSummary(c, en);
        const html = template.content.firstElementChild!.innerHTML;
        put(summary, html);
        if (row.open !== openCandidates.has(key)) row.open = openCandidates.has(key);
        if (row.open) {
            const detail = row.lastElementChild!;
            const content = candidateContent(c, en);
            if (markup.get(detail) !== content) {
                const log = detail.querySelector('.inline-log'); put(detail, content);
                if (log) detail.querySelector('.inline-log')!.replaceWith(log);
            }
        }
        if (row !== cursor) list.insertBefore(row, cursor);
        cursor = row.nextElementSibling; keep.add(row);
    }
    for (const el of [...list.children]) if (!keep.has(el)) el.remove();
    if (!candidates.length) put(list, '<p class="empty">No agent processes have returned yet.</p>');
}
function syncSearch(container: HTMLElement, en: Entry, child = false): void {
    attr(container, 'class', 'search-group');
    attr(container, 'data-group-search', en.key);
    if (!container.firstElementChild) container.innerHTML = '<details><summary></summary><div class="search-body"></div></details><div class="counter-searches"></div>';
    const row = container.firstElementChild as HTMLDetailsElement;
    attr(row, 'class', `timeline-search ${child ? 'counter-search' : ''}`);
    attr(row, 'id', `search-${en.key.replace('/', '-')}`);
    attr(row, 'data-search', en.key);
    attr(row.firstElementChild!, 'class', 'timeline-summary');
    const html = searchSummary(en, child);
    const start = html.indexOf('>') + 1;
    put(row.firstElementChild!, html.slice(start, -10));
    if (row.open !== opened.has(en.key)) row.open = opened.has(en.key);
    const body = row.children[1]!;
    if (row.open) {
        // Preserve candidate islands on updates, including a fetched inline log.
        const shell = searchBodyHTML(en);
        if (markup.get(body) !== shell) {
            const oldList = body.querySelector('.candidate-rows');
            const oldTransitions = body.querySelector<HTMLDetailsElement>('.transitions')?.open;
            put(body, shell);
            if (oldList) body.querySelector('.candidate-rows')!.replaceWith(oldList);
            const trace = body.querySelector<HTMLDetailsElement>('.transitions'); if (trace) trace.open = oldTransitions ?? false;
        }
        syncCandidates(body, en);
    }
    // Counterexample lines belong to the search they tested, never a second view.
    const nested = container.children[1]!;
    const old = new Map([...nested.children].map(c => [(c as HTMLElement).dataset.groupSearch, c]));
    let cursor = nested.firstElementChild;
    for (const c of en.children) {
        const el = old.get(c.key) as HTMLElement | undefined ?? document.createElement('div');
        syncSearch(el, c, true);
        if (el !== cursor) nested.insertBefore(el, cursor);
        cursor = el.nextElementSibling; old.delete(c.key);
    }
    for (const el of old.values()) el.remove();
}
function filteredLines(): Line[] {
    if (filter == null) return lines;
    const intent = data.map?.[filter];
    if (!intent) return [];
    return lines.filter(l => l.entry ? l.entry.s.summary?.goal === intent.intent || l.entry.landed?.subject === intent.intent || l.entry.landed?.subject === `scrub: ${intent.intent}` || l.entry.landed?.commit === intent.landed?.commit : l.commit?.commit === intent.landed?.commit);
}
const rowNodes = new Map<string, HTMLElement>();
function syncTimeline(): void {
    const list = document.querySelector('#timeline-lines')!;
    const all = filteredLines();
    const visible = all.slice(0, visibleCount);
    const wanted = new Set(visible.map(l => l.key));
    let cursor = list.firstElementChild;
    for (const line of visible) {
        let row = rowNodes.get(line.key);
        if (!row) { row = document.createElement('div'); rowNodes.set(line.key, row); }
        if (line.entry) syncSearch(row, line.entry);
        else {
            const t = line.commit!;
            attr(row, 'class', 'owner-line');
            put(row, `<span class="commit-dot ${t.pushed ? 'indigo' : 'blue'}"></span><span class="owner-subject">${e(t.subject ?? 'not recorded')}<span class="owner-label">${t.by_agent ? 'agent · trace not recorded here' : 'owner'}</span></span><code>${short(t.commit)}</code><span class="outcome ${t.pushed ? 'indigo' : 'blue'}">${word(t.pushed ? 'pushed' : 'landed')}</span><span class="line-time">${timestamp(t.time)}</span>`);
        }
        attr(row, 'data-line-key', line.key);
        if (row !== cursor) list.insertBefore(row, cursor);
        cursor = row.nextElementSibling;
    }
    for (const row of [...list.children]) if (!wanted.has((row as HTMLElement).dataset.lineKey ?? '')) row.remove();
    put(document.querySelector('#timeline-count')!, `${all.reduce((count, l) => count + 1 + (l.entry?.children.length ?? 0), 0)} ${filter == null ? 'searches & commits' : 'matching lines'}`);
    const filterEl = document.querySelector('#intent-filter')!;
    put(filterEl, filter == null ? '' : `<span><span class="dot orange"></span>${e(data.map?.[filter]?.intent ?? 'Intent not recorded')}</span><a href="#" data-clear-filter>Clear filter ×</a>`);
    hidden(filterEl as HTMLElement, filter == null);
    const more = document.querySelector<HTMLButtonElement>('#load-more')!;
    hidden(more, visibleCount >= all.length);
    const moreLabel = `Earlier · ${Math.max(0, all.length - visibleCount)} more`;
    if (more.textContent !== moreLabel) more.textContent = moreLabel;
    const empty = document.querySelector<HTMLElement>('#timeline-empty')!;
    hidden(empty, all.length > 0);
    put(empty, filter == null ? 'No search has run yet. A code search writes candidates for an intent.' : 'No searches recorded for this intent. Older searches may not record a goal.');
}
app.innerHTML = `<div class="page"><header class="topbar" id="header"></header><main><p id="connection-note" hidden role="status"></p><section id="now" aria-label="Now"></section><div class="reading-layout"><section id="timeline" aria-labelledby="timeline-title"><div class="section-heading"><h2 id="timeline-title">Timeline</h2><span id="timeline-count"></span></div><div id="intent-filter" hidden></div><div id="timeline-lines"></div><p id="timeline-empty" class="empty" hidden></p><button id="load-more" hidden>Earlier</button></section><aside id="map" aria-label="Map"></aside></div><footer><span class="footer-brand"><strong>bon</strong> view</span><span>The owner writes intents. bon searches.</span></footer></main></div>`;
const renderTimes: { reason: string; ms: number }[] = [];
Object.assign(window, { bonRenderTimes: renderTimes });
function render(reason = 'state'): void {
    const start = performance.now();
    if (projected !== revision) project();
    put(document.querySelector('#header')!, headerHTML());
    put(document.querySelector('#now')!, ready ? nowHTML() : '<h1>Now</h1><p class="empty">Reading the repository…</p>');
    put(document.querySelector('#map')!, mapHTML());
    syncTimeline();
    const note = document.querySelector<HTMLElement>('#connection-note')!;
    hidden(note, connection);
    if (!connection && !note.textContent) note.textContent = '/api/state is not available. The last state stays here. Reading again every 2 seconds.';
    const title = `${data.repo?.name ?? 'bon'} — bon view`;
    if (document.title !== title) document.title = title;
    const ms = performance.now() - start;
    renderTimes.push({ reason, ms });
    if (renderTimes.length > 200) renderTimes.shift();
    console.info(`[bon view] render ${reason}: ${ms.toFixed(2)} ms`);
}
function address(scroll = true): void {
    if (!ready) return;
    const hash = decodeURIComponent(location.hash.slice(1));
    const matchIntent = /^intent\/(\d+)$/.exec(hash);
    filter = matchIntent && data.map?.[Number(matchIntent[1])] ? Number(matchIntent[1]) : null;
    const search = entries.get(hash);
    if (search) {
        opened.add(search.key); if (search.parent) opened.add(search.parent.key);
        const root = search.parent ?? search;
        visibleCount = Math.max(visibleCount, lines.findIndex(l => l.key === root.key) + 1);
    }
    render('address');
    if (scroll && (search || matchIntent)) requestAnimationFrame(() => {
        const el = search ? document.getElementById(`search-${search.key.replace('/', '-')}`) : document.querySelector('#timeline');
        el?.scrollIntoView({ block: 'start' });
    });
}
function pushHash(hash: string): void { history.pushState(null, '', hash ? `#${hash}` : location.pathname + location.search); }
function measureAction(reason: string, action: () => void): void {
    const start = performance.now(); action();
    const ms = performance.now() - start; renderTimes.push({ reason, ms });
    console.info(`[bon view] render ${reason}: ${ms.toFixed(2)} ms`);
}
app.addEventListener('toggle', event => {
    const el = event.target as HTMLDetailsElement;
    if (el.dataset.search) {
        const key = el.dataset.search;
        if (el.open === opened.has(key)) return;
        if (el.open) { opened.add(key); pushHash(key); }
        else { opened.delete(key); if (location.hash === `#${key}`) pushHash(filter == null ? '' : `intent/${filter}`); }
        const en = entries.get(key);
        if (en && el.open) measureAction('open search', () => syncSearch(el.parentElement!, en, !!en.parent));
    } else if (el.dataset.candidate) {
        const key = el.dataset.candidate;
        if (el.open) {
            openCandidates.add(key);
            const parts = key.split('/'); const en = entries.get(parts.slice(0, 2).join('/'));
            const c = en?.s.candidates?.find(c => String(c.index) === parts[2]);
            if (en && c) measureAction('open candidate', () => put(el.lastElementChild!, candidateContent(c, en)));
        } else openCandidates.delete(key);
    }
}, true);
app.addEventListener('click', event => {
    const target = (event.target as Element).closest<HTMLElement>('[data-copy],[data-log],[data-close-log],[data-clear-filter],a[href^="#"],#load-more');
    if (!target) return;
    if (target.dataset.copy) void copy(target.dataset.copy);
    else if (target.dataset.log) void openLog(target.dataset.log, target);
    else if (target.hasAttribute('data-close-log')) target.closest<HTMLElement>('.inline-log')!.hidden = true;
    else if (target.id === 'load-more') { visibleCount += 12; render('scroll'); }
    else if (target instanceof HTMLAnchorElement) {
        event.preventDefault();
        const hash = target.getAttribute('href')!.slice(1);
        pushHash(hash === `intent/${filter}` ? '' : hash);
        visibleCount = 12; address();
    }
});
let scrollingDown = false;
let previousY = 0;
let scrollQueued = false;
window.addEventListener('scroll', () => {
    scrollingDown = window.scrollY > previousY; previousY = window.scrollY;
    if (scrollQueued || !scrollingDown) return;
    scrollQueued = true;
    requestAnimationFrame(() => {
        scrollQueued = false;
        const more = document.querySelector<HTMLElement>('#load-more')!;
        if (!more.hidden && more.getBoundingClientRect().top < innerHeight + 160) { visibleCount += 12; render('scroll'); }
    });
}, { passive: true });
window.addEventListener('popstate', () => {
    // A search address represents the open line; leave unrelated open lines intact.
    const hash = location.hash.slice(1);
    for (const key of opened) if (key !== hash && document.querySelector<HTMLDetailsElement>(`[data-search="${key}"]`)?.open) opened.delete(key);
    address();
});
// Hash edits (and native links from outside the page) use the same in-place route.
window.addEventListener('hashchange', () => address());
function toast(message: string): void { const el = document.querySelector<HTMLElement>('#toast')!; el.textContent = message; el.classList.add('visible'); setTimeout(() => el.classList.remove('visible'), 2000); }
async function copy(text: string): Promise<void> {
    try { await navigator.clipboard.writeText(text); toast('Command copied'); }
    catch { const box = document.createElement('textarea'); box.value = text; document.body.append(box); box.select(); const ok = document.execCommand('copy'); box.remove(); toast(ok ? 'Command copied' : 'Select the command to copy'); }
}
const logCache = new Map<string, string>();
async function openLog(path: string, button: HTMLElement): Promise<void> {
    const panel = button.closest('.candidate-details')?.querySelector<HTMLElement>('.inline-log');
    if (!panel) return;
    panel.hidden = false; panel.dataset.path = path;
    panel.querySelector('code')!.textContent = path;
    const pre = panel.querySelector('pre')!; pre.textContent = 'Reading log…';
    try {
        let text = logCache.get(path);
        if (text == null || entries.get(path.split('/').slice(0, 2).join('/'))?.p.running) {
            const response = await fetch(`/api/log?path=${encodeURIComponent(path)}`);
            if (!response.ok) throw new Error();
            text = await response.text(); logCache.set(path, text);
        }
        if (panel.dataset.path === path) pre.textContent = text;
    } catch { if (panel.dataset.path === path) pre.textContent = 'This log is not available. The recorded file may no longer be on the device.'; }
}
const tip = document.querySelector<HTMLElement>('#spec-tip')!;
let tipTarget: HTMLElement | null = null;
function showTip(target: HTMLElement): void {
    const name = target.dataset.word ?? '';
    const lookup = aliases[name] ?? name;
    const item = data.spec?.items?.find(i => i.name.toLowerCase() === lookup.toLowerCase());
    const field = data.spec?.fields?.find(f => f.name === lookup);
    const doc = item?.doc || field?.doc;
    const readers = field ? (data.spec?.items ?? []).filter(i => i.reads?.includes(field.name)).map(i => i.name) : [];
    const writers = field ? (data.spec?.items ?? []).filter(i => i.updates?.includes(field.name)).map(i => i.name) : [];
    put(tip, `<div class="tip-heading"><code>${e(item?.name ?? field?.name ?? name)}</code><span>${e(item?.kind ?? (field ? 'field' : ''))}</span></div><p>${doc ? `<span class="doc-slash">///</span> ${e(doc)}` : `No /// doc line recorded for “${e(name)}”.`}</p>${field ? `<div class="tip-type"><code>${e(field.type)}</code> · ${e(field.sharding)}</div><dl><dt>read by</dt><dd>${e(readers.join(', ') || 'none recorded')}</dd><dt>updated by</dt><dd>${e(writers.join(', ') || 'none recorded')}</dd></dl>` : `<dl><dt>reads</dt><dd>${e(item?.reads?.join(', ') || 'none recorded')}</dd><dt>updates</dt><dd>${e(item?.updates?.join(', ') || 'none recorded')}</dd></dl>`}`);
    tipTarget = target; tip.hidden = false;
    const rect = target.getBoundingClientRect();
    tip.style.left = `${Math.max(12, Math.min(innerWidth - tip.offsetWidth - 12, rect.left))}px`;
    tip.style.top = `${Math.min(innerHeight - tip.offsetHeight - 12, rect.bottom + 9)}px`;
}
function hideTip(): void { tip.hidden = true; tipTarget = null; }
app.addEventListener('pointerover', event => { const target = (event.target as Element).closest<HTMLElement>('[data-word]'); if (target) showTip(target); });
app.addEventListener('pointerout', event => { if (!(event.relatedTarget instanceof Node) || !tipTarget?.contains(event.relatedTarget)) hideTip(); });
app.addEventListener('focusin', event => { const target = (event.target as Element).closest<HTMLElement>('[data-word]'); if (target) showTip(target); });
app.addEventListener('focusout', hideTip);
window.addEventListener('scroll', hideTip, { passive: true });
window.addEventListener('keydown', event => { if (event.key === 'Escape') hideTip(); });
async function refresh(): Promise<void> {
    if (pending) return; pending = true;
    try {
        const response = await fetch('/api/state', { cache: 'no-store', signal: AbortSignal.timeout(8000) });
        if (!response.ok) throw new Error();
        const next = await response.json() as State;
        if (!next || typeof next !== 'object' || Array.isArray(next)) throw new Error();
        const payload = JSON.stringify({ ...next, repo: { ...next.repo, now: Math.floor((next.repo?.now ?? Date.now() / 1000) / 60) } });
        const first = !ready; const changed = payload !== lastPayload;
        data = next; ready = true;
        const recovered = !connection; connection = true;
        if (changed) { revision++; lastPayload = payload; }
        // Unchanged polls still get a measured render; put() leaves every DOM node alone.
        render(changed ? 'state' : recovered ? 'reconnected' : 'unchanged');
        if (first && location.hash !== '#page' && location.hash !== '') address();
    } catch {
        if (connection || !ready) { connection = false; render('connection'); }
    } finally { pending = false; }
}
render('initial');
void refresh();
setInterval(() => void refresh(), 2000);
