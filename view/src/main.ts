// bon view draws the projection bon prints (src/view.rs): what is running,
// what was pushed, the queue, and what it cost. It decides nothing; the one
// thing it computes is each selection again, with the kernel's gates in
// WebAssembly, to mark any disagreement with the trace.
//
// Color is one scale, red to violet: red is early, unstable, or needs you;
// violet is settled. A search's steps run the same scale in order.

// The projection's types, emitted from src/projection.rs by bon types.
import type { Projection as State, GoalTrace as Group, BonProcess as Process, SearchTrace as Search, Facts as Candidate,
    About, SpecItem, SpecField, SpecNode as SysNode, SpecGraph as System, Sbom, Component as SbomComponent } from './kernel';
import type { Search as KernelSearch } from './kernel';
import { NONE, NOT_A_SEARCH } from './kernel';
const app = document.querySelector<HTMLDivElement>('#app')!;
let data: State | null = null;
let connection = true;
let lastPayload = '';
/** What the owner opened: rows (g), bon processes (p), candidates' logs (l), and each log pane by path. */
const opened = new Set<string>();
const logs = new Map<string, string | null>();
let recentCount = 12;
let tracesOpen = true;
let sbomOpen = false;
let queueOpen = true;
let systemOpen = true;
/** The node the owner points at, or pinned with a click: its chain lights up. */
let sysFocus: string | null = null;
let sysPinned = false;
/** The search whose candidates' changes the System view shows: 'pid/search', '' for none, null to follow the running (or latest) one. */
let sysSearch: string | null = null;
/** What each candidate commit changed against its base; a commit never changes, so this is kept. */
const itemsOf = new Map<string, { files: string[]; items: [string, string][] } | null>();
let sbomFind = '';
/** The open drill-down under the results card: verified candidates, or pushes. */
let drill: 'verified' | 'pushes' | null = null;
const mismatches = new Map<string, string>();
const range: { since?: number; until?: number; find?: string; preset: string } = { preset: 'all' };
/** Light or dark: the system's until the owner picks; the pick is kept in this browser. */
type Theme = 'light' | 'dark';
const systemTheme = (): Theme => matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
let theme: Theme = (() => { try { const t = localStorage.getItem('bon-theme'); return t === 'light' || t === 'dark' ? t : systemTheme(); } catch { return systemTheme(); } })();
document.documentElement.dataset.theme = theme;

// ── formatting ──
const e = (v: unknown): string => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const money = (v?: number | null): string => v == null || !Number.isFinite(v) ? '—' : '$' + v.toFixed(2);
const short = (v?: string | null): string => v ? v.slice(0, 7) : '';
const day = (t: number): string => new Date(t * 1000).toISOString().slice(0, 10);
const cap = (t: string): string => t.charAt(0).toUpperCase() + t.slice(1);
function ago(t?: number | null): string {
    if (!t || !data) return '';
    const d = Math.max(0, data.repo.now - t);
    return d < 60 ? 'just now' : d < 3600 ? `${Math.floor(d / 60)}m ago` : d < 86400 ? `${Math.floor(d / 3600)}h ago` : `${Math.floor(d / 86400)}d ago`;
}
const minutes = (s?: number | null): string => s == null ? '' : s < 90 ? `${Math.round(s)}s` : `${Math.round(s / 60)} min`;

// ── the color scale ──
type Tone = 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'indigo' | 'violet' | 'neutral';
const outcomeTone: Record<string, Tone> = { exited: 'red', found: 'red', running: 'orange', blocked: 'yellow', proposal: 'yellow', 'not found': 'indigo', pushed: 'violet' };
const toneOf = (o: string): Tone => outcomeTone[o] ?? 'neutral';
/** An outcome as the page says it; the spec word stays on hover. */
const outcomeLabel = (o: string): string => ({ 'not found': 'Counterexample not found', found: 'Counterexample found' } as Record<string, string>)[o] ?? cap(o);

// ── components ──
/** A spec word: its /// line on hover. */
const NOTES: Record<string, string> = {
    generation: 'What the models charged. Cost = generation + time.',
    time: 'Your time while it ran, at your rate. Cost = generation + time.',
    cost: 'Generation + time.',
    to_selection: 'Cost to get a selected candidate. To push = this + counterexample.',
    counterexample: 'Cost of trying to break the selection. To push = to selection + this.',
    to_push: 'Everything spent since the last push of this kind. To selection + counterexample.',
    per_verified: 'Cost ÷ verified candidates.',
    per_push: 'Cost that reached a push ÷ pushes.',
    pushed: 'Cost of bon processes that reached a push.',
    not_pushed: 'Cost of finished bon processes that did not.',
    in_flight: 'Cost so far of what is still running.',
};
/** A money term, its note on hover. */
const note = (key: string, label: string): string => `<span class="word" tabindex="0" data-note="${e(NOTES[key] ?? '')}">${e(label)}</span>`;
const word = (name: string, label = name): string => `<span class="word" tabindex="0" data-word="${e(name)}">${e(label)}</span>`;
const chip = (label: string, tone: Tone = 'neutral', specWord?: string): string =>
    `<span class="chip ${tone}">${specWord ? word(specWord, label) : e(label)}</span>`;
const mono = (t: string, title: string | null = ''): string => `<code class="hash" ${title ? `title="${e(title)}"` : ''}>${e(t)}</code>`;
/** A labelled value: the label above, small; the value below. */
const field = (label: string, value: string, tone: Tone = 'neutral'): string =>
    `<div class="field ${tone}"><span class="label">${label}</span><span class="value">${value}</span></div>`;
const sectionHead = (title: string, count?: string, tone: Tone = 'neutral'): string =>
    `<header class="section-head ${tone}"><h2>${title}</h2>${count != null ? `<span class="count">${count}</span>` : ''}</header>`;
/** A cost as one sum: each row is a way the same total breaks down (terms joined by +),
 *  and the total stands once, on the right, after =. Read left to right. */
function sum(rows: [string, string, Tone][][], total: [string, string, Tone]): string {
    const line = (terms: [string, string, Tone][], r: number): string => terms.map(([l, v, t], i) =>
        `${i ? `<span class="op" style="grid-row:${r}">+</span>` : ''}<div class="field ${t}" style="grid-row:${r}"><span class="label">${l}</span><span class="value">${v}</span></div>`).join('');
    return `<div class="sum" style="--rows:${rows.length}">${rows.map((t, i) => line(t, i + 1)).join('')}<span class="op eq" style="grid-row:1 / span ${rows.length}">=</span><div class="field total ${total[2]}" style="grid-row:1 / span ${rows.length}"><span class="label">${total[0]}</span><span class="value">${total[1]}</span></div></div>`;
}
/** Time, with the rate it was charged at. */
const timeValue = (time?: number | null, rate?: number | null): string => `${money(time)}${rate != null ? ` <small>at $${Math.round(rate)}/h</small>` : ''}`;

/** A cost as labelled fields: generation + time = cost, the time with its rate when known. */
function costFields(total: number | null | undefined, generation?: number | null, time?: number | null, label = note('cost', 'Cost'), rate?: number | null, seconds?: number | null): string {
    const t = rate != null && seconds != null ? `${money(time)} <small>${money(rate)}/h × ${minutes(seconds)}</small>` : money(time);
    return `${field(note('generation', 'Generation'), money(generation), 'yellow')}${field(note('time', 'Time'), t, 'orange')}${field(label, `<b>${money(total)}</b>`)}`;
}
const chevron = '<svg class="chev" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>';

// ── the kernel, compiled to WebAssembly ──
let gatesWarning = false;
function warnGates(error: unknown): void {
    if (!gatesWarning) { console.warn('Could not check selections with WebAssembly', error); gatesWarning = true; }
}
const gates = Promise.resolve().then(() => WebAssembly.instantiateStreaming(fetch('/gates.wasm'))).catch(error => { warnGates(error); return null; });
/** Every gate again, in WebAssembly, on each search's words as the trace recorded them:
 *  the search read in the kernel's types, each candidate's verified, the selection, and a
 *  counterexample's verdict (not_found against the search it tested; found_on_trunk on
 *  trunk). Any disagreement with the trace is marked on the search. */
async function rederive(s: State): Promise<void> {
    const loaded = await gates;
    if (!loaded) return;
    const x = loaded.instance.exports;
    const memory = x.memory as WebAssembly.Memory;
    const call = (n: string, ...a: number[]): number => (x[n] as (...a: number[]) => number)(...a);
    const words = new Map<string, ArrayBuffer>();
    const read = async (pid: number, search: number): Promise<ArrayBuffer | null> => {
        const key = `${pid}/${search}`;
        if (!words.has(key)) {
            const res = await fetch(`/api/words?path=${pid}%2F${search}`, { cache: 'no-store' });
            if (!res.ok) return null;
            words.set(key, await res.arrayBuffer());
        }
        return words.get(key)!;
    };
    /** Copy words into the kernel's memory for f; free them after. */
    const withWords = <T>(bytes: ArrayBuffer, f: (ptr: number, len: number) => T): T => {
        const len = bytes.byteLength / 8, ptr = call('alloc', len);
        try { new Uint8Array(memory.buffer, ptr, bytes.byteLength).set(new Uint8Array(bytes)); return f(ptr, len); }
        finally { call('dealloc', ptr, len); }
    };
    const emit = (ptr: number, len: number): KernelSearch | null => {
        const q = call('emit', ptr, len);
        if (!q) return null;
        const n = call('emitted');
        try { return JSON.parse(new TextDecoder().decode(new Uint8Array(memory.buffer, q, n))) as KernelSearch; }
        finally { call('dealloc_bytes', q, n); }
    };
    mismatches.clear();
    for (const p of s.processes) for (const r of p.searches) {
        if (r.kernel !== 'derived') continue;
        const key = `${p.pid}/${r.search}`;
        const bytes = await read(p.pid, r.search);
        if (!bytes) continue;
        const said: string[] = [];
        const k = withWords(bytes, (ptr, len) => {
            const k = emit(ptr, len);
            if (!k) return null;
            const got = call('selected', ptr, len);
            const kernel = got === NONE ? null : got;
            if (r.recorded_selected != null && kernel !== r.recorded_selected) said.push(`kernel selected ${kernel ?? 'none'}, trace recorded ${r.recorded_selected}`);
            for (const c of r.candidates) {
                const v = call('verified', ptr, len, c.index);
                if (v !== NOT_A_SEARCH && (v === 1) !== c.verified) said.push(`kernel says #${c.index} is ${v === 1 ? '' : 'not '}verified`);
                const kc = k.results[c.index];
                if (kc && c.commit && kc.commit !== c.commit) said.push(`kernel has #${c.index} at ${short(kc.commit)}`);
            }
            if ('counterexample' in k.kind && k.kind.counterexample.goal === null) {
                // On trunk: two verified tests that reject it, or not found.
                const onTrunk = call('found_on_trunk', ptr, len);
                const found = onTrunk !== NONE && onTrunk !== NOT_A_SEARCH;
                const last = p.transitions.at(-1) ?? '';
                const traced = last.startsWith('found') ? true : last.startsWith('not found') ? false : null;
                if (traced !== null && traced !== found) said.push(`kernel: counterexample ${found ? 'found' : 'not found'}, trace says otherwise`);
            }
            return k;
        });
        if (!k) { mismatches.set(key, 'The kernel cannot read this search'); continue; }
        // A counterexample on a selection: not_found against the search it tested.
        if ('counterexample' in k.kind && k.kind.counterexample.goal !== null) {
            const tested = await read(p.pid, k.kind.counterexample.goal.search);
            // The foil search on the same candidate: the last one before this search.
            const foil = p.searches.filter(o => o.kind === 'foil' && o.search < r.search).at(-1);
            const foils = foil ? await read(p.pid, foil.search) : null;
            const later = p.searches.some(o => o.search > r.search);
            const traced = later ? false : p.outcome === 'pushed' ? true : null;
            if (tested && foils && traced !== null) {
                const nf = withWords(bytes, (xp, xl) => withWords(tested, (tp, tl) => withWords(foils, (fp, fl) => call('not_found', xp, xl, tp, tl, fp, fl))));
                if (nf !== NOT_A_SEARCH && (nf === 1) !== traced) said.push(`kernel: counterexample ${nf === 1 ? 'not found' : 'found'}, trace says otherwise`);
            }
        }
        if (said.length) mismatches.set(key, cap(said.join('; ')));
    }
}

// ── header ──
/** The rates searches ran at, as recorded: one value, or several, or none. */
function rates(searches: Search[]): string {
    const seen = [...new Set(searches.map(r => r.rate).filter((r): r is number => r != null))];
    return seen.length ? seen.map(r => `$${Math.round(r)}/h`).join(', ') : '—';
}

function header(s: State): string {
    const t = s.totals;
    const button = (key: 'verified' | 'pushes', label: string, value: string, sub: string, tone: Tone, parts: [string, number, Tone][]): string => {
        const total = parts.reduce((a, [, n]) => a + n, 0) || 1;
        const bar = `<span class="split">${parts.map(([, n, t]) => `<i class="${t}" style="width:${(n / total) * 100}%"></i>`).join('')}</span>`;
        const legend = `<span class="legend">${parts.map(([l, n, t]) => `<span class="${t}"><i></i>${n} ${e(l)}</span>`).join('')}</span>`;
        return `<button class="result ${tone} ${drill === key ? 'on' : ''}" data-drill="${key}"><span class="label">${label}</span><b>${value}</b><span class="sub">${sub}</span>${bar}${legend}${chevron}</button>`;
    };
    // Candidates by how far they got; pushes by kind, and the bon processes that did not.
    const cands = s.processes.flatMap(p => p.searches.flatMap(r => r.candidates));
    const accepted = cands.filter(c => c.accepted && !c.verified).length, rejected = cands.filter(c => !c.accepted).length;
    const byKind = new Map<string, number>();
    for (const g of s.groups) if (g.outcome === 'pushed') byKind.set(g.kind, (byKind.get(g.kind) ?? 0) + 1);
    const unpushed = s.groups.filter(g => g.outcome !== 'pushed' && !g.running).length;
    const kindTone: Record<string, Tone> = { code: 'violet', compaction: 'indigo', queue: 'yellow', counterexample: 'blue' };
    const share = (x: number): string => `${(x / (t.cost || 1)) * 100}%`;
    const pct = (x: number): string => `${Math.round((x / (t.cost || 1)) * 100)}%`;
    return `<div class="bar-top"><div class="widget"><span class="label">${word('Repository', 'Repository')}</span><span class="value name">${e(s.repo.name)}</span></div><div class="widget violet" title="${e(`${s.repo.remote ?? 'origin'}/${s.repo.trunk ?? 'main'} ${s.repo.remote_head ?? ''} ${s.repo.subject ?? ''}`)}"><span class="label">${word('trunk', 'Trunk')}</span><span class="value toned">${e(ago(s.repo.remote_time ?? undefined))} · <code>${e(short(s.repo.remote_head))}</code></span>${s.repo.since_push?.commits ? `<span class="sub" title="${e(`Committed to trunk without bon, by ${s.repo.since_push.authors.join(', ')}`)}">+${s.repo.since_push.commits} since last push</span>` : s.repo.since_push ? '<span class="sub">At the last push</span>' : ''}</div>${topWidgets(s)}<div class="widget theme-widget"><span class="label">Theme</span><span class="theme" role="group" aria-label="Theme"><button class="${theme === 'light' ? 'on' : ''}" data-theme-pick="light">Light</button><button class="${theme === 'dark' ? 'on' : ''}" data-theme-pick="dark">Dark</button></span></div></div>
<div class="cards"><div class="card money">
<div class="equation">
<span class="label">${note('cost', 'Cost')}</span><span></span><span class="label">${note('generation', 'Generation')}</span><span></span><span class="label">${note('time', 'Time')}</span>
<b class="total">${money(t.cost)}</b><span class="op">=</span><b class="term yellow">${money(t.generation)}</b><span class="op">+</span><b class="term orange">${money(t.time_cost)}</b>
<span></span><span></span><span class="sub">Model tokens × prices</span><span></span><span class="sub">Your time at the set rate</span></div>
<div class="rates"><div class="green"><span class="label">${note('per_verified', 'Per verified candidate')}</span><b>${money(t.per_verified_candidate)}</b></div><div class="violet"><span class="label">${note('per_push', 'Per push')}</span><b>${money(t.per_push)}</b></div></div>
<div class="went"><span class="label">Where it went</span><div class="split wide"><i class="violet" style="width:${share(t.pushed)}"></i><i class="red" style="width:${share(t.not_pushed)}"></i><i class="orange" style="width:${share(t.in_flight)}"></i></div>
<div class="legend row"><span class="violet"><i></i>${note('pushed', 'Reached a push')} <b>${money(t.pushed)}</b> ${pct(t.pushed)}</span><span class="red"><i></i>${note('not_pushed', 'Did not')} <b>${money(t.not_pushed)}</b> ${pct(t.not_pushed)}</span>${t.in_flight ? `<span class="orange"><i></i>${note('in_flight', 'In flight')} <b>${money(t.in_flight)}</b> ${pct(t.in_flight)}</span>` : ''}</div></div></div>
<div class="card results">${button('verified', 'Verified', `${t.verified}`, `of ${t.candidates} candidates`, 'green', [['verified', t.verified, 'green'], ['accepted, not verified', accepted, 'yellow'], ['rejected', rejected, 'red']])}${button('pushes', 'Pushed', String(t.pushes), t.pushes === 1 ? 'push' : 'pushes', 'violet', [...[...byKind].map(([k, n]): [string, number, Tone] => [k, n, kindTone[k] ?? 'neutral']), ...(unpushed ? [['not pushed', unpushed, 'red'] as [string, number, Tone]] : [])])}</div></div>
${drill ? `<div class="card drill">${drill === 'verified' ? verifiedList(s) : pushList(s)}</div>` : ''}`;
}

/** The top bar's glance widgets: the queue (a link to it), the last push, and what runs now. */
function topWidgets(s: State): string {
    const last = s.repo.last_push;
    const running = s.processes.filter(p => p.running).length;
    const q = s.queue ? `${s.queue.length} not in the spec` : 'None';
    return `<div class="widget violet"><span class="label">Last ${word('push')}</span><span class="value toned">${last ? `${e(ago(last.time))} · <code>${e(short(last.commit ?? ''))}</code>` : '—'}</span></div>`
        + `<a class="widget yellow" href="#queue"><span class="label">${word('queue', 'Queue')}</span><span class="value toned">${q}</span></a>`
        + `<div class="widget ${running ? 'orange' : 'neutral'}"><span class="label">Now</span><span class="value toned">${running ? `Running ${running}` : 'Idle'}</span></div>`;
}

/** Every verified candidate in range, with the effort and search it came from. */
function verifiedList(s: State): string {
    const rows: string[] = [];
    for (const g of s.groups) for (const p of g.processes) for (const r of p.searches) for (const c of r.candidates) {
        if (!c.verified) continue;
        const key = `l${p.pid}/${r.search}/${c.index}`;
        rows.push(`<tr><td>${chip(cap(g.kind))} <span class="cell-title">${e(g.title)}</span></td><td>${mono(`${p.pid}/${r.search}`)}</td><td><span class="index">#${c.index}</span>${r.selected === c.index ? chip('Selected', 'blue', 'selected') : ''}</td><td class="num">${money(c.generation)}</td><td class="num lines">${c.added != null ? `<span class="add">+${c.added}</span><span class="del">−${c.removed ?? 0}</span>` : ''}</td><td>${c.logs?.length ? `<button class="toggle ${opened.has(key) ? 'on' : ''}" data-toggle="${key}">${chevron}${c.logs.length} logs</button>` : ''}</td></tr>${opened.has(key) ? logRow(p, r, c, 6) : ''}`);
    }
    return `<table class="candidates"><thead><tr><th>Bon processes</th><th>Search</th><th>Candidate</th><th class="num">Generation</th><th class="num">Lines</th><th>Logs</th></tr></thead><tbody>${rows.join('') || '<tr><td colspan="6" class="muted">None in this range</td></tr>'}</tbody></table>`;
}

/** Every push in range: the commit, and everything it took to reach it. */
function pushList(s: State): string {
    const rows = s.groups.filter(g => g.outcome === 'pushed').map(g => `<tr><td>${mono(short(g.push?.commit ?? ''), g.push?.commit ?? '')}</td><td>${chip(cap(g.kind))} <span class="cell-title">${e(g.title)}</span></td><td class="num">${g.processes.length}</td><td class="num">${money(g.generation)}</td><td class="num">${money(g.time_cost)}</td><td class="num"><b>${money(g.push?.cost)}</b></td><td class="muted">${ago(g.time)}</td></tr>`);
    return `<table class="candidates"><thead><tr><th>Commit</th><th>Bon processes</th><th class="num">${word('bon process', 'Bon processes')}</th><th class="num">${note('generation', 'Generation')}</th><th class="num">${note('time', 'Time')}</th><th class="num">${note('to_push', 'Push cost')}</th><th>When</th></tr></thead><tbody>${rows.join('') || '<tr><td colspan="7" class="muted">None in this range</td></tr>'}</tbody></table>`;
}

// ── filter toolbar ──
function controls(s: State): string {
    const preset = (key: string, label: string): string => `<button class="${range.preset === key ? 'on' : ''}" data-preset="${key}">${label}</button>`;
    const lo = s.bounds.earliest ? day(s.bounds.earliest) : '', hi = s.bounds.latest ? day(s.bounds.latest) : '';
    return `<div class="segmented" role="group" aria-label="Time range">${preset('day', '24 hours')}${preset('week', '7 days')}${preset('month', '30 days')}${preset('all', 'All time')}</div>
<div class="dates"><label class="input"><span>Ran from</span><input type="date" data-range="since" min="${lo}" max="${hi}" value="${range.since != null ? day(range.since) : ''}"></label><span class="arrow">→</span><label class="input"><span>To</span><input type="date" data-range="until" min="${lo}" max="${hi}" value="${range.until != null ? day(range.until) : ''}"></label></div>
<label class="input find"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg><input type="search" data-range="find" placeholder="Find a bon process, commit, goal or outcome" value="${e(range.find ?? '')}"></label>`;
}

// ── live ──
/** Elapsed time that ticks on the page between polls: a running search's, from its grant. */
const since = (started: number, seconds?: number | null): string => `<span data-since="${started}">${minutes(seconds ?? 0)}</span>`;
/** Rows, bon processes and searches that were running when first seen open on their own, once. */
const autoOpened = new Set<string>();

// ── a search ──
/** The steps, in order: red to violet. */
function steps(p: Process, r: Search): string {
    const items: [Tone, string, string, string][] = [
        ['red', 'grant', r.width != null ? String(r.width) : '—', 'Started'],
        ['orange', 'wait', String(r.returned), 'Returned'],
        ['yellow', 'accepted', String(r.accepted), 'Accepted'],
        ['green', 'verified', String(r.verified), 'Verified'],
    ];
    const later = p.searches.indexOf(r) < p.searches.length - 1;
    const last = p.transitions.at(-1) ?? '';
    if (r.kind === 'counterexample') {
        if (last.startsWith('found')) items.push(['red', 'found', 'Found', 'Counterexample']);
        else if (last.startsWith('not found') || (p.outcome === 'pushed' && !later)) items.push(['indigo', 'not_found', 'Not found', 'Counterexample']);
    } else if (r.selected != null) items.push(['blue', 'selected', `#${r.selected}`, 'Selected']);
    else if (r.blocked) items.push(['yellow', 'blocked', 'Blocked', 'Outcome']);
    return `<ol class="steps">${items.map(([t, w, v, label]) => `<li class="${t}"><span class="label">${word(w, label)}</span><b>${e(v)}</b></li>`).join('')}</ol>`;
}

function logRow(p: Process, r: Search, c: Candidate, cols: number): string {
    const base = `${p.pid}/${r.search}/${c.index}`;
    const names = c.logs ?? [];
    const open = names.filter(n => logs.has(`${base}/${n}`));
    return `<tr class="logs-row"><td colspan="${cols}"><div class="log-tabs">${names.map(n => `<button class="tab ${logs.has(`${base}/${n}`) ? 'on' : ''}" data-log="${e(`${base}/${n}`)}">${e(n)}</button>`).join('')}</div>
${open.length ? `<div class="log-panes">${open.map(n => { const path = `${base}/${n}`; const text = logs.get(path);
        return `<div class="pane"><div class="pane-head">${mono(n)}<span class="muted">${e(path)}</span><button class="close" data-log="${e(path)}" aria-label="Close ${e(n)}">×</button></div><pre>${text == null ? 'Reading…' : e(text)}</pre></div>`; }).join('')}</div>` : ''}</td></tr>`;
}

function candidates(p: Process, r: Search): string {
    if (!r.candidates.length) return '';
    const models = new Set(r.candidates.map(c => `${c.harness ?? '?'} · ${c.model ?? '?'}`));
    const one = models.size === 1;
    const cols = one ? 8 : 9;
    const sorted = [...r.candidates].sort((a, b) => Number(b.verified) - Number(a.verified) || (b.rank ?? 0) - (a.rank ?? 0) || (a.diff ?? 0) - (b.diff ?? 0));
    const yes = (ok: boolean, no: string, tone: Tone): string => ok ? `<span class="chip soft ${tone}">Yes</span>` : chip(no, 'red');
    return `<table class="candidates"><thead><tr><th>Candidate</th>${one ? '' : '<th>Harness · model</th>'}<th>Commit</th><th>${word('accepted', 'Accepted')}</th><th>${word('verified', 'Verified')}</th><th class="num">Generation</th><th class="num">${word('rank', 'Rank')}</th><th class="num" title="Lines added and removed; the kernel breaks a rank tie by their sum, the smaller first">Lines</th><th>Logs</th></tr></thead><tbody>${sorted.map(c => {
        const sel = r.selected === c.index;
        const key = `l${p.pid}/${r.search}/${c.index}`;
        const n = c.logs?.length ?? 0;
        return `<tr class="${sel ? 'sel' : ''}"><td><span class="index">#${c.index}</span>${sel ? chip('Selected', 'blue', 'selected') : ''}</td>${one ? '' : `<td>${e(c.harness)} · ${e(c.model)}</td>`}<td>${mono(short(c.commit), c.commit)}</td><td>${yes(c.accepted, 'Rejected', 'yellow')}</td><td>${yes(c.verified, 'No', 'green')}${(c.flags ?? []).map(f => chip(f.replace('_', ' '), 'red', f)).join('')}</td><td class="num">${money(c.generation)}</td><td class="num">${c.rank ?? '—'}</td><td class="num lines">${c.added != null ? `<span class="add">+${c.added}</span><span class="del">−${c.removed ?? 0}</span>` : (c.diff ?? '—')}</td><td>${n ? `<button class="toggle ${opened.has(key) ? 'on' : ''}" data-toggle="${key}">${chevron}${n} logs</button>` : ''}</td></tr>${opened.has(key) ? logRow(p, r, c, cols) : ''}`;
    }).join('')}</tbody></table>`;
}

/** A search's parameters in the spec's shape: Search { kind(goal), base, n, authority, limit }.
 *  Kind is shown separately; goal is the kind's goal. */
function params(r: Search, kind: string): string {
    const g = r.params.goal;
    const slot = (label: string, value: string, cls = ''): string => `<div class="slot ${cls}"><span class="label">${label}</span><span class="value">${value}</span></div>`;
    const goal = g.transcript != null ? `Transcript ${mono(g.transcript)}`
        : g.candidate != null ? `Selected candidate · ${e(g.candidate.replace(' candidate ', ', #'))}`
        : `Trunk ${mono(short(g.trunk ?? ''), g.trunk ?? '')}`;
    const models = [...new Set(r.candidates.map(c => `${c.harness ?? '?'} · ${c.model ?? '?'}`))].join(', ');
    return `<div class="signature"><div class="slots">${slot(word('Kind', 'Kind'), e(cap(kind)))}${slot(word('Kind', 'Goal'), goal, 'wide')}${slot(word('base', 'Base'), mono(short(r.params.base), r.params.base))}${slot('Width', String(r.params.n ?? '—'))}${r.params.limit != null ? slot(word('limit', 'Limit'), money(r.params.limit)) : ''}${r.params.limit != null ? slot(word('authority', 'Authority'), e(cap(r.params.authority))) : ''}${models ? slot('Harness', e(models), 'wide') : ''}</div></div>`;
}

function search(p: Process, r: Search): string {
    const i = p.searches.indexOf(r);
    const kind = r.kind === 'counterexample' ? 'counterexample' : p.kind;
    const rerun = r.kind !== 'counterexample' && p.searches.slice(0, i).some(x => x.kind !== 'counterexample');
    const mismatch = mismatches.get(`${p.pid}/${r.search}`);
    const key = `s${p.pid}/${r.search}`;
    const last = p.transitions.at(-1) ?? '';
    const later = i < p.searches.length - 1;
    // What the search came to: a selection, a counterexample's verdict, or blocked.
    const result = r.kind === 'counterexample'
        ? (last.startsWith('found') ? field(word('found', 'Counterexample'), 'Found', 'red')
            : last.startsWith('not found') || (p.outcome === 'pushed' && !later) ? field(word('not_found', 'Counterexample'), 'Not found', 'indigo') : field('Counterexample', '—'))
        : r.selected != null ? field(word('selected', 'Selected'), `#${r.selected}`, 'blue')
        : r.blocked ? field(word('blocked', 'Outcome'), 'Blocked', 'yellow') : field('Outcome', '—');
    const stage: Tone = r.running ? 'orange' : r.kind === 'counterexample' ? 'indigo' : r.selected != null ? 'blue' : r.blocked ? 'yellow' : 'neutral';
    const summary = `<summary><div class="line1">${chevron}<h4>${word('Search', `Search ${r.search}`)}</h4>${chip(cap(kind), r.running ? 'neutral' : stage)}${r.running ? chip('Running', 'orange', 'running') : ''}${rerun ? chip('Rerun wider', 'yellow') : ''}${r.background ? chip('Background', 'violet') : ''}${r.kernel === 'derived' ? chip('Kernel checked', 'green') : ''}</div>
<div class="glance-row"><div class="facts">${r.running ? field(word('wait', 'Returned'), `${r.returned} / ${r.width ?? '—'}`, 'orange') : ''}${field(word('verified', 'Verified'), `${r.verified} / ${r.returned}`, r.verified >= 2 ? 'green' : 'red')}${r.running ? '' : result}${field(r.running ? 'Elapsed' : 'Took', r.running && r.started ? since(r.started, r.seconds) : r.seconds != null ? minutes(r.seconds) : '—')}</div>${sum([[[note('generation', 'Generation'), money(r.generation), 'yellow'], [note('time', 'Time'), timeValue(r.time_cost, r.rate), 'orange']]], [note('cost', 'Cost'), `<b>${money(r.cost)}</b>`, 'neutral'])}</div></summary>`;
    const inner = `<div class="search-body">${params(r, kind)}${steps(p, r)}${r.blocked ? `<div class="notice yellow">${e(cap(r.blocked.replace(/^blocked:\s*/, '')))}</div>` : ''}${mismatch ? `<div class="notice red">${e(mismatch)}</div>` : ''}${candidates(p, r)}</div>`;
    return `<details class="search ${stage}" data-open="${key}" ${opened.has(key) ? 'open' : ''}>${summary}${opened.has(key) ? inner : ''}</details>`;
}

// ── rows ──
function processBlock(p: Process, several: boolean): string {
    const inner = p.searches.map(r => search(p, r)).join('');
    if (!several) return `<div class="process">${inner}</div>`;
    const key = `p${p.pid}`;
    return `<details class="process ${toneOf(p.outcome)}" data-open="${key}" ${opened.has(key) ? 'open' : ''}><summary><div class="line1">${chevron}<span class="pid">${word('bon process', 'Bon process')} ${mono(String(p.pid))}</span>${chip(outcomeLabel(p.outcome), toneOf(p.outcome), p.outcome)}${p.searches.some(r => r.background) ? chip('Background', 'violet') : ''}</div><div class="glance-row"><div class="facts">${field(word('Search', 'Searches'), String(p.searches.length))}${field('Ran', e(ago(p.time)))}</div>${sum([[[note('generation', 'Generation'), money(p.generation), 'yellow'], [note('time', 'Time'), timeValue(p.time_cost, p.searches.find(r => r.rate != null)?.rate), 'orange']]], [note('cost', 'Cost'), `<b>${money(p.cost)}</b>`, 'neutral'])}</div></summary>${opened.has(key) ? inner : ''}</details>`;
}

function body(g: Group): string { return `<div class="body">${g.processes.map(p => processBlock(p, g.processes.length > 1)).join('')}</div>`; }

/** At a glance, read left to right: what the effort came to, then what it cost
 *  as one sum: by stage (to selection + counterexample) and by source (generation + time),
 *  both equal to the push. */
function glance(g: Group): string {
    const p = g.processes[0]!;
    const main = p.searches.find(s => s.kind !== 'counterexample') ?? p.searches[0];
    const ce = p.searches.find(s => s.kind === 'counterexample');
    const found = p.transitions.at(-1)?.startsWith('found');
    const none = g.outcome === 'pushed' || g.outcome === 'not found';
    const dash = '—';
    const pushed = g.push?.cost != null;
    const searches = g.processes.flatMap(x => x.searches);
    const agents = searches.reduce((a, r) => a + r.returned, 0);
    const seconds = searches.reduce((a, r) => a + (r.seconds ?? 0), 0);
    const took = seconds >= 3600 ? `${Math.floor(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m` : minutes(seconds) || dash;
    const rate = [...new Set(searches.map(r => r.rate).filter((r): r is number => r != null))];
    const facts = [
        field(word('verified', 'Verified'), main ? `${main.verified} / ${main.returned}` : dash, main && main.verified >= 2 ? 'green' : 'red'),
        field(word('selected', 'Selected'), main?.selected != null ? `#${main.selected}` : dash, main?.selected != null ? 'blue' : 'neutral'),
        field(word(none ? 'not_found' : 'found', 'Counterexample'), ce ? (none ? `Not found · ${ce.verified}` : found ? 'Found' : dash) : dash, ce ? (none ? 'indigo' : 'red') : 'neutral'),
        field(word('bon process', 'Bon processes'), String(g.processes.length)),
        field(word('agent_processes', 'Agent processes'), String(agents)),
        field(g.running ? 'Elapsed' : 'Took', took),
    ];
    const total: [string, string, Tone] = [pushed ? note('to_push', 'To push') : note('cost', 'Cost'), `<b>${money(pushed ? g.push!.cost : g.cost)}</b>`, pushed ? 'violet' : 'neutral'];
    const rows: [string, string, Tone][][] = [
        ...(pushed ? [[[note('to_selection', 'To selection'), money(g.push!.to_selection), 'blue'], [note('counterexample', 'Counterexample'), money(g.push!.counterexample), 'indigo']] as [string, string, Tone][]] : []),
        [[note('generation', 'Generation'), money(g.generation), 'yellow'], [note('time', 'Time'), timeValue(g.time_cost, rate.length === 1 ? rate[0] : null), 'orange']],
    ];
    return `<div class="glance-row"><div class="facts">${facts.join('')}</div>${sum(rows, total)}</div>`;
}

function row(g: Group): string {
    const key = `g${g.processes.at(-1)!.pid}`;
    const full = [g.about.goal, g.about.from && `${g.about.from} · ${g.about.subject}`].filter(Boolean).join('\n');
    return `<details class="group ${toneOf(g.outcome)}" data-open="${key}" ${opened.has(key) ? 'open' : ''}><summary>
<div class="line1">${chevron}${chip(cap(g.kind), 'neutral', g.kind)}${chip(`${outcomeLabel(g.outcome)} · ${ago(g.time)}${g.push?.commit ? ` · ${short(g.push.commit)}` : ''}`, toneOf(g.outcome), g.outcome)}</div>
<div class="row-title" title="${e(full)}">${e(g.title)}</div>
<div class="line2">${glance(g)}</div></summary>${opened.has(key) ? body(g) : ''}</details>`;
}

function recent(s: State): string {
    const done = [...s.groups.filter(g => g.running), ...s.groups.filter(g => !g.running)];
    const filtered = range.since != null || range.until != null || !!range.find;
    const head = `<summary class="section-head">${chevron}<h2>${word('traces', 'Traces')}</h2><span class="count">${done.length}${filtered ? ' in range' : ''}</span></summary>`;
    const rows = done.slice(0, recentCount).map(row).join('') || '<div class="empty">No search in this range</div>';
    const more = done.length > recentCount ? `<button class="more" data-more>Show ${Math.min(12, done.length - recentCount)} more of ${done.length - recentCount}</button>` : '';
    return `<details class="traces violet" ${tracesOpen ? 'open' : ''} data-section="traces">${head}${tracesOpen ? rows + more : ''}</details>`;
}

/** What bon trusts, from the SBOM: its trusted code, the tools in its TCB, the services, then the crates. */
function sbomSection(s: State): string {
    const d = s.sbom?.document;
    const comps = d?.components ?? [];
    const crates = comps.filter(c => c.type === 'library');
    const tcb = comps.filter(c => c.group === 'tcb');
    const props = d?.metadata?.properties ?? [];
    const files = props.filter(p => p.name === 'bon:trusted-file').map(p => p.value);
    const fns = (props.find(p => p.name === 'bon:trusted-functions')?.value ?? '').split(',').filter(Boolean);
    const count = d ? `${crates.length} crates · ${tcb.length} tools · ${fns.length} trusted functions` : 'None';
    const head = `<summary class="section-head">${chevron}<h2>${word('sbom', 'SBOM')}</h2>${s.sbom ? chip(s.sbom.source === 'trunk' ? 'On trunk' : 'Working tree, not on trunk', s.sbom.source === 'trunk' ? 'violet' : 'yellow') : ''}<span class="count">${count}</span></summary>`;
    if (!sbomOpen || !d) return `<details class="sbom red" data-section="sbom" ${sbomOpen ? 'open' : ''}>${head}${sbomOpen ? '<div class="empty">No .bon/sbom.json</div>' : ''}</details>`;
    const q = sbomFind.toLowerCase();
    const shown = crates.filter(c => !q || `${c.name} ${c.version}`.toLowerCase().includes(q));
    return `<details class="sbom red" data-section="sbom" open>${head}<div class="sbom-body">
<div class="sbom-grid"><div class="slot"><span class="label">Trusted files</span><span class="value">${files.map(f => mono(f)).join(' ')}</span></div>
<div class="slot"><span class="label">Services</span><span class="value">${(d.services ?? []).map(v => `${e(v.name)} <span class="muted">${e((v.endpoints ?? []).join(', '))}</span>`).join('<br>')}</span></div></div>
<div class="slot full"><span class="label">Trusted functions</span><span class="value fns">${fns.map(f => `<code>${e(f)}</code>`).join('')}</span></div>
<table class="candidates"><thead><tr><th>Tool in the TCB</th><th>Version</th></tr></thead><tbody>${tcb.map(c => `<tr><td>${e(c.name)}</td><td><code>${e(c.version)}</code></td></tr>`).join('')}</tbody></table>
<label class="input find"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg><input type="search" data-sbom-find placeholder="Find a crate (${crates.length})" value="${e(sbomFind)}"></label>
<table class="candidates"><thead><tr><th>Crate</th><th>Version</th><th>Checksum</th></tr></thead><tbody>${shown.map(c => `<tr><td>${e(c.name)}</td><td><code>${e(c.version)}</code></td><td>${(c as SbomComponent & { hashes?: { content: string }[] }).hashes?.[0] ? mono(((c as SbomComponent & { hashes?: { content: string }[] }).hashes![0]!.content).slice(0, 12)) : ''}</td></tr>`).join('') || '<tr><td colspan="3" class="muted">No crate matches</td></tr>'}</tbody></table>
</div></details>`;
}

// ── the system: the kernel (spec, gates, implementation), the bon process, the entry points
//    and the programs, each named from the next by the source's own syntax ──
const LAYERS: { key: SysNode['layer']; title: string; tone: Tone; sub: string; kernel?: boolean; groups: [string, string][] }[] = [
    { key: 'spec', title: 'Spec', tone: 'indigo', sub: 'src/spec.rs', kernel: true, groups: [['init', 'init!'], ['transition', 'Transitions'], ['predicate', 'Predicates a gate ensures'], ['property', 'Properties'], ['invariant', 'Invariants']] },
    { key: 'gates', title: 'Gates', tone: 'blue', sub: 'src/gates.rs', kernel: true, groups: [['Gates', 'trait Gates'], ['Encoding', 'trait Encoding'], ['Commands', 'trait Commands'], ['types', 'Types emitted for programs']] },
    { key: 'implementation', title: 'Implementation', tone: 'violet', sub: 'src/exec.rs, src/encoding.rs', kernel: true, groups: [['gate', 'impl Gates for Kernel'], ['encoding', 'impl Encoding for Kernel'], ['process', 'Called by the bon process']] },
    { key: 'process', title: 'bon process', tone: 'green', sub: 'src/process.rs · holds the tokens', groups: [['function', 'Functions']] },
    { key: 'entry', title: 'Entry points', tone: 'red', sub: 'trusted code', groups: [['main', 'src/main.rs'], ['view', 'src/view.rs']] },
    { key: 'program', title: 'Programs', tone: 'orange', sub: 'built from the types the kernel emits', groups: [['typescript', 'view/src · TypeScript']] },
];
/** The transitions running bon processes have fired. */
function operating(s: State): Set<string> {
    const out = new Set<string>();
    for (const p of s.processes.filter(p => p.running)) for (const t of p.transitions) out.add(t.split(/[: ]/)[0]!);
    return out;
}
function sysNode(n: SysNode, live: Set<string>, by?: Touch): string {
    const sub: string[] = [];
    if (n.guards?.length) sub.push(`<span class="g">requires ${n.guards.map(g => e(g)).join(', ')}</span>`);
    for (const a of n.adds ?? []) sub.push(`<span class="tok add">+ ${e(a)}</span>`);
    for (const r of n.removes ?? []) sub.push(`<span class="tok rm">− ${e(r)}</span>`);
    if (n.uses?.length) sub.push(`<span class="g">${e(n.uses.slice(0, 3).join(', '))}${n.uses.length > 3 ? ` +${n.uses.length - 3}` : ''}</span>`);
    if (n.trusted?.length) sub.push(`<span class="g tr">calls ${n.trusted.length} in trusted code</span>`);
    if (n.proof) sub.push('<span class="g">proof</span>');
    const on = n.layer === 'spec' && live.has(n.name);
    const t = by?.get(n.id);
    const note = `${n.file}${n.line && n.line > 1 ? `:${n.line}` : ''}${n.doc ? ` — ${n.doc}` : ''}${t ? ` · changed by candidate${t.who.length > 1 ? 's' : ''} ${t.who.map(i => `#${i}`).join(', ')}` : ''}`;
    return `<div class="sys-node${n.changed ? ' changed' : ''}${on ? ' live' : ''}${t ? ' touched' : ''}" data-node="${e(n.id)}" data-src="${e(srcUrl(n.file, n.line, n.end))}" tabindex="0" data-note="${e(note)}"><span class="nm">${e(n.name)}</span>${on ? '<i class="pulse" title="A running search fired it"></i>' : ''}${n.changed ? '<i class="dot" title="Differs from trunk"></i>' : ''}${t ? `<span class="by${t.selected ? ' sel' : ''}">${t.who.length}/${t.of}</span>` : ''}${sub.length ? `<span class="sub">${sub.join('')}</span>` : ''}</div>`;
}
type Touch = Map<string, { who: number[]; of: number; selected: boolean }>;
/** Every search on the page, running first, then latest first. */
function allSearches(s: State): { key: string; pid: number; r: Search }[] {
    const seen = new Set<number>();
    const out: { key: string; pid: number; r: Search }[] = [];
    for (const p of [...s.processes, ...s.groups.flatMap(g => g.processes)]) {
        if (seen.has(p.pid)) continue; seen.add(p.pid);
        for (const r of p.searches) out.push({ key: `${p.pid}/${r.search}`, pid: p.pid, r });
    }
    return out.sort((a, b) => Number(!!b.r.running) - Number(!!a.r.running) || (b.r.started ?? b.r.time ?? 0) - (a.r.started ?? a.r.time ?? 0));
}
/** The chosen search's candidates' changes, by item: who changed it, of how many, and whether the selected one did.
 *  Fetches what is not yet known and redraws when it arrives. */
function touched(sys: System, pick: { r: Search } | undefined): { by: Touch; other: string[]; pending: number } {
    const by: Touch = new Map();
    const other = new Set<string>();
    let pending = 0;
    if (!pick) return { by, other: [], pending };
    const base = pick.r.params?.base;
    const cands = pick.r.candidates.filter(c => c.commit);
    const of = pick.r.width ?? pick.r.params?.n ?? cands.length;
    const shown = new Set(sys.nodes.map(n => n.file));
    for (const c of cands) {
        const got = itemsOf.get(c.commit!);
        if (got === undefined && base) {
            itemsOf.set(c.commit!, null); pending++;
            fetch(`/api/items?base=${base}&commit=${c.commit}`).then(r => r.ok ? r.json() : null)
                .then(v => { itemsOf.set(c.commit!, v ?? { files: [], items: [] }); soon(); })
                .catch(() => { itemsOf.set(c.commit!, { files: [], items: [] }); });
            continue;
        }
        if (!got) { pending++; continue; }
        const hit = new Set<string>();
        for (const [file, name] of got.items) for (const n of sys.nodes) if (n.file === file && n.name === name) hit.add(n.id);
        for (const n of sys.nodes) if ((n.line ?? 1) <= 1 && got.files.includes(n.file)) hit.add(n.id);
        for (const f of got.files) if (!shown.has(f)) other.add(f);
        for (const id of hit) {
            const t = by.get(id) ?? { who: [], of, selected: false };
            t.who.push(c.index);
            if (pick.r.selected === c.index) t.selected = true;
            by.set(id, t);
        }
    }
    return { by, other: [...other].sort(), pending };
}
/** Where an item is written: the file, its lines marked, from the working tree. */
const srcUrl = (file: string, line?: number | null, end?: number | null): string =>
    `/source?path=${encodeURIComponent(file)}${line && line > 1 ? `&from=${line}&to=${end ?? line}#L${line}` : ''}`;
function systemSection(s: State): string {
    const sys = s.system;
    const changed = sys ? sys.nodes.filter(n => n.changed).length + sys.trusted.filter(t => t.changed).length : 0;
    const live = operating(s);
    const searches = sys ? allSearches(s) : [];
    const pick = sysSearch === '' ? undefined : searches.find(x => x.key === sysSearch) ?? (sysSearch == null ? searches[0] : undefined);
    const { by, other, pending } = sys ? touched(sys, pick) : { by: new Map() as Touch, other: [] as string[], pending: 0 };
    const count = sys ? `${sys.nodes.length} items · ${sys.edges.length} references` : 'None';
    const head = `<summary class="section-head">${chevron}<h2>System</h2>${changed ? chip(`${changed} differ from trunk`, 'yellow') : ''}${live.size ? chip(`Running: ${[...live].join(', ')}`, 'orange') : ''}<span class="count">${count}</span></summary>`;
    if (!systemOpen || !sys) return `<details class="system-section indigo" data-section="system" ${systemOpen ? 'open' : ''}>${head}${systemOpen ? '<div class="empty">No state machine in src/spec.rs</div>' : ''}</details>`;
    const cols = LAYERS.map(L => {
        const mine = sys.nodes.filter(n => n.layer === L.key);
        const groups = L.groups.map(([g, label]) => {
            const ns = mine.filter(n => n.group === g);
            return ns.length ? `<div class="sys-group">${/^(init!|trait |impl |src\/|view\/)/.test(label) ? `<code class="glabel">${e(label)}</code>` : `<span class="label">${e(label)}</span>`}${ns.map(n => sysNode(n, live, by)).join('')}</div>` : '';
        }).join('');
        return `<div class="sys-col ${L.tone}"><header><b>${L.title}</b><span>${e(L.sub)}</span></header>${groups}</div>`;
    }).join('');
    const wasm = sys.nodes.filter(n => n.layer === 'target');
    const target = wasm.length ? `<div class="sys-target"><header><b>wasm32</b><span>the kernel, compiled · <code>gates.wasm</code> · entry points in <code>src/wasm.rs</code>, trusted code</span></header><div class="row">${wasm.map(n => sysNode(n, live, by)).join('')}</div></div>` : '';
    const kernel = `<div class="sys-kernel"><span>Kernel</span><small>the spec, the gates and their implementation · proven by Verus</small></div>`;
    const legend = `<div class="sys-legend"><span><i class="ln ensures"></i>ensures</span><span><i class="ln implements"></i>implements</span><span><i class="ln calls"></i>calls</span><span><i class="ln transition"></i>calls a transition</span><span><i class="ln types"></i>uses an emitted type</span><span><i class="dot"></i>differs from trunk</span><span class="muted">Hover an item for what it reaches and what reaches it; click to open it in its file; shift-click to pin.</span></div>`;
    const trusted = `<div class="sys-trusted red"><span class="label">Trusted code · src/trusted.rs · ${sys.trusted.length} of its ${sys.counts.trusted} functions the bon process calls; Verus does not check them</span><div>${sys.trusted.map(t => `<code class="${t.changed ? 'changed' : ''}" data-trusted="${e(t.name)}" data-src="${e(srcUrl('src/trusted.rs', t.line))}" data-note="${e(`src/trusted.rs:${t.line}${t.doc ? ` — ${t.doc}` : ''}`)}">${e(t.name)}</code>`).join('')}</div></div>`;
    const label = (x: { pid: number; r: Search }): string => `bon process ${x.pid} · search ${x.r.search} · ${x.r.kind} · ${x.r.candidates.length}/${x.r.width ?? x.r.params?.n ?? '?'} returned${x.r.running ? ' · running' : ''}${x.r.selected != null ? ` · selected #${x.r.selected}` : ''}`;
    const picker = `<div class="sys-pick"><label><span class="label">${word('search', 'Search')}</span><select data-sys-search>`
        + `<option value="" ${!pick ? 'selected' : ''}>None</option>`
        + searches.slice(0, 40).map(x => `<option value="${e(x.key)}" ${pick?.key === x.key ? 'selected' : ''}>${e(label(x))}</option>`).join('')
        + `</select></label>${pick ? `<span class="muted">${by.size} item${by.size === 1 ? '' : 's'} changed by its candidates${pending ? ` · reading ${pending}…` : ''}; <span class="by">2/8</span> two of eight changed it, <span class="by sel">bold</span> the selected one did</span>` : '<span class="muted">Pick a search to see what its candidates changed, item by item.</span>'}`
        + (other.length ? `<span class="muted">Also changed: ${other.map(f => `<code>${e(f)}</code>`).join(' ')}</span>` : '') + `</div>`;
    return `<details class="system-section indigo" data-section="system" open>${head}<div class="sys-body">${picker}${legend}<div class="sys-grid">${kernel}<svg class="sys-edges" aria-hidden="true"></svg>${cols}${target}</div>${trusted}</div></details>`;
}
/** Draw each link between columns as a curve, from the caller's left edge to the callee's right. */
function drawSystem(): void {
    const grid = document.querySelector<HTMLElement>('.sys-grid');
    const svg = grid?.querySelector<SVGSVGElement>('svg.sys-edges');
    const sys = data?.system;
    if (!grid || !svg || !sys) return;
    const box = grid.getBoundingClientRect();
    svg.setAttribute('width', String(box.width)); svg.setAttribute('height', String(box.height));
    const at = new Map<string, DOMRect>();
    for (const el of grid.querySelectorAll<HTMLElement>('[data-node]')) at.set(el.dataset.node!, el.getBoundingClientRect());
    const order = { spec: 0, gates: 1, implementation: 2, target: 3, process: 4, entry: 5, program: 6 } as const;
    const layer = new Map(sys.nodes.map(n => [n.id, order[n.layer as keyof typeof order]]));
    svg.innerHTML = sys.edges.map(([from, to, kind]) => {
        const a = at.get(from), b = at.get(to);
        if (!a || !b || layer.get(from) === layer.get(to)) return '';
        const L = box.left, T = box.top;
        let d: string;
        if (b.right <= a.left) {        // the callee is left of the caller: left edge to right edge
            const x1 = a.left - L, y1 = a.top + a.height / 2 - T, x2 = b.right - L, y2 = b.top + b.height / 2 - T, dx = Math.max(24, (x1 - x2) / 2);
            d = `M${x1},${y1} C${x1 - dx},${y1} ${x2 + dx},${y2} ${x2},${y2}`;
        } else if (a.right <= b.left) { // right of it
            const x1 = a.right - L, y1 = a.top + a.height / 2 - T, x2 = b.left - L, y2 = b.top + b.height / 2 - T, dx = Math.max(24, (x2 - x1) / 2);
            d = `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
        } else {                        // above or below it
            const down = b.top > a.bottom;
            const x1 = a.left + a.width / 2 - L, y1 = (down ? a.bottom : a.top) - T, x2 = b.left + b.width / 2 - L, y2 = (down ? b.top : b.bottom) - T, dy = Math.max(24, Math.abs(y2 - y1) / 2) * (down ? 1 : -1);
            d = `M${x1},${y1} C${x1},${y1 + dy} ${x2},${y2 - dy} ${x2},${y2}`;
        }
        return `<path class="${kind}" data-from="${e(from)}" data-to="${e(to)}" d="${d}"/>`;
    }).join('');
    lightSystem();
}
/** Light the focused part's chain: everything it reaches (down to the spec) and everything that reaches it. */
function lightSystem(): void {
    const sys = data?.system;
    const grid = document.querySelector<HTMLElement>('.sys-grid');
    if (!sys || !grid) return;
    grid.classList.toggle('focused', sysFocus != null);
    const lit = new Set<string>();
    if (sysFocus) {
        const walk = (start: string, next: (id: string) => string[]) => { const todo = [start]; while (todo.length) { const id = todo.pop()!; if (lit.has(id) && id !== start) continue; lit.add(id); todo.push(...next(id).filter(x => !lit.has(x))); } };
        walk(sysFocus, id => sys.edges.filter(x => x[0] === id).map(x => x[1]));
        walk(sysFocus, id => sys.edges.filter(x => x[1] === id).map(x => x[0]));
    }
    for (const el of grid.querySelectorAll<HTMLElement>('[data-node]')) { el.classList.toggle('lit', lit.has(el.dataset.node!)); el.classList.toggle('focus', el.dataset.node === sysFocus); }
    for (const el of grid.querySelectorAll<SVGPathElement>('path')) el.classList.toggle('lit', lit.has(el.dataset.from!) && lit.has(el.dataset.to!));
    const used = new Set(sys.nodes.filter(n => lit.has(n.id)).flatMap(n => n.trusted ?? []));
    for (const el of document.querySelectorAll<HTMLElement>('[data-trusted]')) el.classList.toggle('lit', used.has(el.dataset.trusted!));
}
app.addEventListener('pointerover', ev => {
    if (sysPinned) return;
    const t = (ev.target as Element).closest<HTMLElement>('[data-node]');
    const next = t?.dataset.node ?? null;
    if (next !== sysFocus) { sysFocus = next; lightSystem(); }
});
app.addEventListener('click', ev => {
    const src = (ev.target as Element).closest<HTMLElement>('[data-src]');
    const t = (ev.target as Element).closest<HTMLElement>('[data-node]');
    if (src && !ev.shiftKey) { window.open(src.dataset.src!, 'bon-source'); return; }
    if (t) { sysPinned = !(sysPinned && sysFocus === t.dataset.node); sysFocus = t.dataset.node!; lightSystem(); }
    else if (sysPinned && !(ev.target as Element).closest('.sys-grid')) { sysPinned = false; sysFocus = null; lightSystem(); }
});
window.addEventListener('resize', () => drawSystem());


function queue(s: State): string {
    const head = `<summary class="section-head">${chevron}<h2>${word('queue', 'Queue')}</h2><span class="count">${s.queue ? `${s.queue.length} not in the spec` : 'None'}</span></summary>`;
    const body = !s.queue ? `<div class="empty">No <code>.bon/queue.tsv</code> at trunk's head</div>`
        : s.queue.length ? `<ol class="queue">${s.queue.map(q => `<li><span class="qid">${q.id}</span><span>${e(q.intent)}</span></li>`).join('')}</ol>` : '<div class="empty">Queue is empty</div>';
    return `<details class="queue-section yellow" data-section="queue" ${queueOpen ? 'open' : ''}>${head}${queueOpen ? body : ''}</details>`;
}

// ── rendering ──
const markup = new WeakMap<Element, string>();
function put(el: Element, html: string): void { if (markup.get(el) !== html) { el.innerHTML = html; markup.set(el, html); } }
app.innerHTML = '<header id="header" class="top"></header><section id="sbom"></section><div id="controls" class="toolbar"></div><main><section id="now"></section><section id="system"></section><section id="queue" tabindex="-1"></section><section id="recent"></section></main>';
let controlsDrawn = false;
function render(): void {
    if (!data) { put(document.querySelector('#now')!, '<div class="empty">Reading the repository…</div>'); return; }
    document.title = `${data.repo.name ?? 'bon'} · bon view`;
    for (const id of ['header', 'controls', 'sbom', 'system', 'queue', 'recent']) document.querySelector<HTMLElement>(`#${id}`)!.hidden = !data.configured;
    const nowEl = document.querySelector<HTMLElement>('#now')!;
    if (!data.configured) {
        put(nowEl, '<div class="card empty">No .bon/bon.toml at trunk&#39;s head — run bon init</div>'); nowEl.hidden = false; return;
    }
    put(document.querySelector('#header')!, header(data));
    // Redraw on preset changes; update date bounds without replacing focused inputs.
    if (!controlsDrawn) { document.querySelector('#controls')!.innerHTML = controls(data); controlsDrawn = true; }
    for (const input of document.querySelectorAll<HTMLInputElement>('#controls input[type="date"]')) {
        input.min = data.bounds.earliest != null ? day(data.bounds.earliest) : '';
        input.max = data.bounds.latest != null ? day(data.bounds.latest) : '';
    }
    put(nowEl, ''); nowEl.hidden = true;
    // What is running opens on its own, once: its row, its bon process, its running search.
    for (const g of data.groups.filter(x => x.running)) for (const p of g.processes) {
        const keys = [`g${g.processes.at(-1)!.pid}`, `p${p.pid}`, ...p.searches.filter(r => r.running).map(r => `s${p.pid}/${r.search}`)];
        for (const k of keys) if (!autoOpened.has(k)) { autoOpened.add(k); opened.add(k); }
    }
    put(document.querySelector('#recent')!, recent(data));
    if (!document.activeElement?.matches('[data-sys-search]')) put(document.querySelector('#system')!, systemSection(data));
    drawSystem();
    put(document.querySelector('#queue')!, queue(data));
    // The SBOM's filter keeps its focus: while it is typed in, its input handler redraws.
    const sb = document.querySelector('#sbom')!;
    if (!document.activeElement?.matches('[data-sbom-find]')) put(sb, sbomSection(data));
}
const soon = (): void => { requestAnimationFrame(render); };

app.addEventListener('change', ev => {
    const el = ev.target as HTMLSelectElement;
    if (el.matches('[data-sys-search]')) { sysSearch = el.value; el.blur(); render(); }
});
app.addEventListener('toggle', ev => {
    const el = ev.target as HTMLDetailsElement;
    if (el.dataset.section === 'traces') { if (el.open !== tracesOpen) { tracesOpen = el.open; soon(); } return; }
    if (el.dataset.section === 'sbom') { if (el.open !== sbomOpen) { sbomOpen = el.open; soon(); } return; }
    if (el.dataset.section === 'system') { if (el.open !== systemOpen) { systemOpen = el.open; soon(); } return; }
    if (el.dataset.section === 'queue') { if (el.open !== queueOpen) { queueOpen = el.open; soon(); } return; }
    const key = el.dataset.open; if (!key || el.open === opened.has(key)) return;
    if (el.open) opened.add(key); else opened.delete(key);
    soon();
}, true);
app.addEventListener('change', ev => {
    const t = ev.target as HTMLInputElement;
    const key = t.dataset.range; if (!key || key === 'find') return;
    const v = t.value ? Math.floor(Date.parse(`${t.value}T00:00:00Z`) / 1000) : undefined;
    if (key === 'since') range.since = v; else range.until = v == null ? undefined : v + 86399;
    range.preset = 'custom'; controlsDrawn = false; lastPayload = ''; void refresh();
});
let typing: number | undefined;
app.addEventListener('input', ev => {
    const t = ev.target as HTMLInputElement;
    if (t.hasAttribute('data-sbom-find')) {
        sbomFind = t.value;
        const sb = document.querySelector('#sbom')!; const at = t.selectionStart;
        sb.innerHTML = data ? sbomSection(data) : ''; const again = sb.querySelector<HTMLInputElement>('[data-sbom-find]');
        if (again) { again.focus(); again.setSelectionRange(at, at); }
        return;
    }
    if (t.dataset.range !== 'find') return;
    clearTimeout(typing);
    typing = window.setTimeout(() => { range.find = t.value.trim() || undefined; lastPayload = ''; void refresh(); }, 250);
});
app.addEventListener('click', ev => {
    const el = ev.target as Element;
    const preset = el.closest<HTMLElement>('[data-preset]');
    if (preset) {
        const k = preset.dataset.preset!, n = Math.floor(Date.now() / 1000);
        range.preset = k; range.until = undefined;
        range.since = k === 'day' ? n - 86400 : k === 'week' ? n - 7 * 86400 : k === 'month' ? n - 30 * 86400 : undefined;
        controlsDrawn = false; lastPayload = ''; void refresh(); return;
    }
    const pick = el.closest<HTMLElement>('[data-theme-pick]');
    if (pick) {
        theme = pick.dataset.themePick as Theme; document.documentElement.dataset.theme = theme;
        try { localStorage.setItem('bon-theme', theme); } catch { /* the pick lasts this visit */ }
        soon(); return;
    }
    const d = el.closest<HTMLElement>('[data-drill]');
    if (d) { const k = d.dataset.drill as 'verified' | 'pushes'; drill = drill === k ? null : k; soon(); return; }
    const toggle = el.closest<HTMLElement>('[data-toggle]');
    if (toggle) { const k = toggle.dataset.toggle!; if (opened.has(k)) opened.delete(k); else opened.add(k); soon(); return; }
    const log = el.closest<HTMLElement>('[data-log]');
    if (log) { void toggleLog(log.dataset.log!); return; }
    if (el.closest('[data-more]')) { recentCount += 12; soon(); return; }
    // The queue widget jumps to the queue.
    if (el.closest('a[href="#queue"]')) { ev.preventDefault(); if (!queueOpen) { queueOpen = true; render(); } document.querySelector<HTMLElement>('#queue')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
});
async function toggleLog(path: string): Promise<void> {
    if (logs.has(path)) { logs.delete(path); soon(); return; }
    logs.set(path, null); soon();
    try { const r = await fetch(`/api/log?path=${encodeURIComponent(path)}`); if (!r.ok) throw 0; logs.set(path, await r.text()); }
    catch { logs.set(path, 'This log is no longer on disk.'); }
    soon();
}

// Hover or focus a word for its /// line in the spec.
const tip = document.querySelector<HTMLElement>('#spec-tip')!;
const aliases: Record<string, string> = { generation: 'wait', blocked: 'selected', exited: 'wait', pushed: 'push', 'not found': 'not_found', running: 'wait', found: 'found_on_trunk', proposal: 'proposed', code: 'Kind', compaction: 'Kind', counterexample: 'Kind', queue: 'Kind', limit: 'within_limit', 'bon process': 'initialize' };
function showTip(target: HTMLElement): void {
    if (target.dataset.note) { tip.innerHTML = `<p>${e(target.dataset.note)}</p>`; tip.hidden = false; place(target); return; }
    const name = target.dataset.word ?? '';
    const look = (aliases[name] ?? name).toLowerCase();
    const item = data?.spec?.items?.find(i => i.name.toLowerCase() === look);
    if (!item?.doc) { tip.hidden = true; return; }
    tip.innerHTML = `<code>${e(item.name)}</code> <span class="muted">${e(item.kind)}</span><p>/// ${e(item.doc)}</p>`;
    tip.hidden = false;
    place(target);
}
function place(target: HTMLElement): void {
    const rect = target.getBoundingClientRect();
    tip.style.left = `${Math.max(12, Math.min(innerWidth - tip.offsetWidth - 12, rect.left))}px`;
    tip.style.top = `${Math.min(innerHeight - tip.offsetHeight - 12, rect.bottom + 8)}px`;
}
app.addEventListener('pointerover', ev => { const t = (ev.target as Element).closest<HTMLElement>('[data-word],[data-note]'); if (t) showTip(t); else tip.hidden = true; });
app.addEventListener('focusin', ev => { const t = (ev.target as Element).closest<HTMLElement>('[data-word],[data-note]'); if (t) showTip(t); });
window.addEventListener('scroll', () => { tip.hidden = true; }, { passive: true });

function query(): string {
    const q = new URLSearchParams();
    if (range.since != null) q.set('since', String(range.since));
    if (range.until != null) q.set('until', String(range.until));
    if (range.find) q.set('find', range.find);
    const t = q.toString(); return t ? `?${t}` : '';
}
let pending = false;
async function refresh(): Promise<void> {
    if (pending) return; pending = true;
    try {
        const r = await fetch(`/api/state${query()}`, { cache: 'no-store', signal: AbortSignal.timeout(8000) });
        if (!r.ok) throw 0;
        const next = await r.json() as State;
        const payload = JSON.stringify({ ...next, repo: { ...next.repo, now: Math.floor(next.repo.now / 60) } });
        if (payload !== lastPayload || !connection) {
            data = next; lastPayload = payload; connection = true; render();
            void rederive(next).then(() => { if (data === next) render(); }).catch(warnGates);
        } else data = next;
    } catch { if (connection) { connection = false; render(); } }
    finally { pending = false; }
}
render();
void refresh();
setInterval(() => void refresh(), 2000);
setInterval(() => { for (const el of document.querySelectorAll<HTMLElement>('[data-since]')) el.textContent = minutes(Date.now() / 1000 - Number(el.dataset.since)); }, 1000);
