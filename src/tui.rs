//! `bon` in a terminal: the projection as four tabs, Project, Spec, Queue and
//! Traces, each a list with the focused item's detail beside it (or, under
//! 100 columns, opened on ⏎). Trusted code. It reads only the projection and
//! the files it names; it decides nothing.
//!
//! Color has one meaning, position on the chain: red needs attention, violet
//! is settled. Everything else is ink, muted or faint. The palette is the
//! page's (view/src/app.css), light and dark.

use std::io::IsTerminal;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::projection::{self, BonProcess, Facts, GoalTrace, Projection, SearchTrace};
use crate::view;

// ── palette ─────────────────────────────────────────────

fn rgb(hex: u32) -> Color { Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8) }

/// The page's tokens. A tone is shown mixed toward ink, as the page lifts it.
#[derive(Clone, Copy)]
struct Palette { ink: u32, muted: u32, faint: u32, line: u32, hover: u32, lift: f32, tones: [u32; 7] }

const DARK: Palette = Palette {
    ink: 0xEDEAE5, muted: 0xA8A39B, faint: 0x6E6A64, line: 0x2E2E35, hover: 0x1C1C20, lift: 0.62,
    tones: [0xC62828, 0xD45500, 0xD4A017, 0x1D5A2A, 0x1B3D8A, 0x4534B0, 0x4A1E86],
};
const LIGHT: Palette = Palette {
    ink: 0x1B1A18, muted: 0x5C574F, faint: 0x8F887C, line: 0xDDD3C1, hover: 0xE8E0CF, lift: 0.88,
    tones: [0xA61E1E, 0xB34A06, 0x93680A, 0x173D20, 0x122C61, 0x33258A, 0x35165C],
};

/// Position on the chain, red to violet.
#[derive(Clone, Copy)]
enum Tone { Red, Orange, Yellow, Green, Blue, Indigo, Violet }

impl Palette {
    fn mix(&self, tone: u32) -> Color {
        let ch = |c: u32, s: u32| ((c & 0xFF) as f32 * self.lift + (s & 0xFF) as f32 * (1.0 - self.lift)) as u32;
        let (t, i) = (tone, self.ink);
        rgb(ch(t >> 16, i >> 16) << 16 | ch(t >> 8, i >> 8) << 8 | ch(t, i))
    }
    fn tone(&self, t: Tone) -> Style { Style::new().fg(self.mix(self.tones[t as usize])) }
    fn ink(&self) -> Style { Style::new().fg(rgb(self.ink)) }
    fn strong(&self) -> Style { self.ink().add_modifier(Modifier::BOLD) }
    fn muted(&self) -> Style { Style::new().fg(rgb(self.muted)) }
    fn faint(&self) -> Style { Style::new().fg(rgb(self.faint)) }
    fn rule(&self) -> Style { Style::new().fg(rgb(self.line)) }
    fn selected(&self) -> Style { Style::new().bg(rgb(self.hover)) }
}

/// An outcome's place on the chain.
fn outcome_tone(outcome: &str) -> Tone {
    match outcome {
        "exited" | "found" => Tone::Red,
        "running" => Tone::Orange,
        "blocked" | "proposal" => Tone::Yellow,
        "not found" => Tone::Indigo,
        "pushed" => Tone::Violet,
        _ => Tone::Yellow,
    }
}

// ── formatting ──────────────────────────────────────────

fn money(v: Option<f64>) -> String { v.filter(|v| v.is_finite()).map_or("—".into(), |v| format!("${v:.2}")) }
fn short(v: &str) -> String { v.chars().take(7).collect() }

fn ago(now: i64, t: i64) -> String {
    let s = (now - t).max(0);
    match s { 0..=59 => "now".into(), 60..=3599 => format!("{}m ago", s / 60), 3600..=86399 => format!("{}h ago", s / 3600), _ => format!("{}d ago", s / 86400) }
}

fn took(s: f64) -> String { if s < 90.0 { format!("{}s", s.round()) } else if s < 5400.0 { format!("{}m", (s / 60.0).round()) } else { format!("{}h {}m", (s / 3600.0) as u64, ((s % 3600.0) / 60.0) as u64) } }

/// The local offset from UTC, in seconds, read once.
fn local_offset() -> i64 {
    std::process::Command::new("date").arg("+%z").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|z| { let z = z.trim(); let sign = if z.starts_with('-') { -1 } else { 1 }; let d: i64 = z.trim_start_matches(['+', '-']).parse().ok()?; Some(sign * ((d / 100) * 3600 + (d % 100) * 60)) })
        .unwrap_or(0)
}

fn clock(t: i64, off: i64) -> String { let s = (t + off).rem_euclid(86400); format!("{:02}:{:02}", s / 3600, (s / 60) % 60) }

/// Days since the epoch, locally; and a day's label.
fn day(t: i64, off: i64) -> i64 { (t + off).div_euclid(86400) }
fn day_label(d: i64, today: i64) -> String {
    if d == today { return "today".into(); }
    if d == today - 1 { return "yesterday".into(); }
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = d + 719468; let era = z.div_euclid(146097); let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); let mp = (5 * doy + 2) / 153;
    let dd = doy - (153 * mp + 2) / 5 + 1; let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, dd)
}

/// Pad or cut to exactly `w` columns.
fn fit(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n > w { let mut t: String = s.chars().take(w.saturating_sub(1)).collect(); t.push('…'); t } else { format!("{s}{}", " ".repeat(w - n)) }
}

// ── the model ───────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Tab { Project, Spec, Queue, Traces }
const TABS: [Tab; 4] = [Tab::Project, Tab::Spec, Tab::Queue, Tab::Traces];

/// What a focusable row stands for, so its detail is found by key, not by position.
#[derive(Clone, PartialEq)]
enum Key { Goal(usize), Queue(usize), Proposal(usize), Item(usize), Grid, Trusted(usize), Sbom(&'static str) }

/// One row of a list: what it shows, and the item it stands for, if it can be focused.
struct Row { line: Line<'static>, key: Option<Key> }
impl Row {
    fn text(line: Line<'static>) -> Row { Row { line, key: None } }
    fn focusable(&self) -> bool { self.key.is_some() }
}

/// What covers the body: a list of logs, one log, or two outputs side by side.
enum Overlay {
    None,
    Logs { items: Vec<(String, std::path::PathBuf)>, sel: usize },
    Text { title: String, lines: Vec<String>, top: usize },
    Compare { titles: (String, String), left: Vec<String>, right: Vec<String>, top: usize },
}

/// The time ranges r cycles through, as the page offers them.
const RANGES: [(&str, i64); 4] = [("all time", 0), ("24 hours", 86400), ("7 days", 7 * 86400), ("30 days", 30 * 86400)];

struct App {
    p: Projection,
    root: std::path::PathBuf,
    overlay: Overlay,
    /// Text being typed after /, for find.
    input: Option<String>,
    range: usize,
    filter: std::sync::Arc<std::sync::Mutex<view::Filter>>,
    error: Option<String>,
    tab: Tab,
    /// Focused row and first visible row, per tab.
    focus: [usize; 4],
    top: [usize; 4],
    /// Scroll of the detail pane.
    detail_top: u16,
    /// Under 100 columns the detail is a full screen of its own.
    detail_open: bool,
    keys: bool,
    palette: Palette,
    dark: bool,
    off: i64,
    loaded: Option<Instant>,
}

impl App {
    fn new() -> App {
        let dark = std::env::var("BON_THEME").map_or(true, |t| t != "light");
        App { p: Projection::default(), root: ".".into(), overlay: Overlay::None, input: None, range: 0, filter: Default::default(),
              error: None, tab: Tab::Traces, focus: [0; 4], top: [0; 4], detail_top: 0, detail_open: false,
              keys: false, palette: if dark { DARK } else { LIGHT }, dark, off: local_offset(), loaded: None }
    }
    fn ti(&self) -> usize { TABS.iter().position(|t| *t == self.tab).unwrap_or(0) }
}

// ── rows per tab ────────────────────────────────────────

/// Who started a bon process: you, through the agent, or bon on spare capacity.
fn who(g: &GoalTrace) -> &'static str {
    if g.processes.iter().flat_map(|p| &p.searches).any(|s| s.background) { "bon" } else { "you" }
}

/// The main search of a bon process: its first that is not a counterexample.
fn main_search(p: &BonProcess) -> Option<&SearchTrace> { p.searches.iter().find(|s| s.kind != "counterexample") }

/// A goal's steps, compressed: width → verified → selected → counterexample → push.
fn steps(g: &GoalTrace, tight: bool) -> String {
    let Some(last) = g.processes.first() else { return String::new() };
    // A counterexample on trunk: how many of its tests were verified.
    if g.kind == "counterexample" {
        let v = last.searches.iter().map(|s| s.verified).sum::<u64>();
        return format!("{v} verified test{}", if v == 1 { "" } else { "s" });
    }
    let mut out = Vec::new();
    if let Some(m) = main_search(last) {
        out.push(format!("{}", m.width.max(m.returned)));
        out.push(format!("{}", m.verified));
        if let Some(i) = m.selected { out.push(format!("#{i}")); }
    }
    if let Some(ce) = last.searches.iter().rev().find(|s| s.kind == "counterexample") {
        out.push(match g.outcome.as_str() { "found" => "found".into(), _ if ce.verified >= 2 => "none found".into(), _ => format!("{} of 2 tests", ce.verified) });
    }
    if let Some(c) = g.push.as_ref().and_then(|p| p.commit.as_deref()) { out.push(short(c)); }
    if tight {
        // Tight: width→verified, then the rest spaced: 8→7 #1 none found b2579d5.
        let mut it = out.into_iter();
        let head = [it.next(), it.next()].into_iter().flatten().collect::<Vec<_>>().join("→");
        std::iter::once(head).chain(it).collect::<Vec<_>>().join(" ")
    } else { out.join(" → ") }
}

fn rows(app: &App, width: u16) -> Vec<Row> {
    let pal = &app.palette;
    let p = &app.p;
    let w = width as usize;
    let mut out = Vec::new();
    let header = |t: &str| Row::text(Line::from(Span::styled(format!(" {t}"), pal.faint().add_modifier(Modifier::BOLD))));
    match app.tab {
        Tab::Traces => {
            let today = day(p.repo.now, app.off);
            let mut last_day = None;
            let mut groups: Vec<&GoalTrace> = p.groups.iter().collect();
            groups.sort_by_key(|g| (!g.running, -g.time));
            for (gi, g) in groups.into_iter().enumerate() {
                let d = if g.running { today } else { day(g.time, app.off) };
                if last_day != Some(d) { if last_day.is_some() { out.push(Row::text(Line::default())); } out.push(header(&day_label(d, today))); last_day = Some(d); }
                let tone = pal.tone(outcome_tone(&g.outcome));
                let cost = money(g.push.as_ref().and_then(|p| p.cost).or(Some(g.cost)));
                let label = if g.outcome == "not found" { "none found".to_string() } else { g.outcome.clone() };
                // Three forms by width: 96+ everything; 76+ without "who", arrows tight;
                // under 76 (beside the detail, or a phone) no steps, which the detail shows.
                let (who_col, with_steps) = (w >= 96, w >= 76);
                // The kind and the commit it started from; the title is in the detail.
                let commit = g.title.split_whitespace().last().unwrap_or("");
                let what = format!("{} {}", if g.kind == "counterexample" { "trunk" } else { g.kind.as_str() }, commit);
                let what_w = if with_steps { 19 } else { w.saturating_sub(1 + 7 + 2 + 11 + 8).clamp(8, 22) };
                let fixed = 1 + 7 + if who_col { 4 } else { 0 } + 2 + 11 + what_w + 8;
                let rest = w.saturating_sub(fixed + 1);
                let mut spans = vec![Span::raw(" "), Span::styled(format!("{}  ", clock(g.time, app.off)), pal.muted())];
                if who_col { spans.push(Span::styled(format!("{} ", who(g)), pal.faint())); }
                spans.extend([
                    Span::styled("● ", tone),
                    Span::styled(fit(&label, 11), tone),
                    Span::styled(format!("{} ", fit(&what, what_w - 1)), pal.ink()),
                ]);
                if with_steps { spans.push(Span::styled(fit(&steps(g, !who_col), rest), pal.muted())); }
                spans.push(Span::styled(format!("{:>8}", cost), pal.ink()));
                out.push(Row { line: Line::from(spans), key: Some(Key::Goal(gi)) });
            }
            if p.groups.is_empty() { out.push(Row::text(Line::from(Span::styled(" No bon process yet.", pal.muted())))); }
        }
        Tab::Queue => {
            if !p.proposals.is_empty() {
                out.push(header(&format!("proposed  {}", p.proposals.len())));
                for (pi, pr) in p.proposals.iter().enumerate() {
                    out.push(Row { line: Line::from(vec![Span::styled("  ● ", pal.tone(Tone::Yellow)), Span::styled(fit(&pr.source, w.saturating_sub(24)), pal.ink()),
                        Span::styled(format!("  {} new{}", pr.intents.len(), if pr.contested.is_empty() { String::new() } else { format!(", {} contested", pr.contested.len()) }), pal.muted())]), key: Some(Key::Proposal(pi)) });
                }
                out.push(Row::text(Line::default()));
                out.push(header(&format!("queued  {}", p.queue.as_ref().map_or(0, |q| q.len()))));
            }
            for (qi, q) in p.queue.iter().flatten().enumerate() {
                out.push(Row { line: Line::from(vec![Span::styled(format!(" {:>3}  ", q.id), pal.faint()), Span::styled(fit(&q.intent, w.saturating_sub(7)), pal.ink())]), key: Some(Key::Queue(qi)) });
            }
            if p.queue.as_ref().is_none_or(|q| q.is_empty()) { out.push(Row::text(Line::from(Span::styled(" Nothing queued: every intent is in the spec.", pal.muted())))); }
        }
        Tab::Spec => {
            let Some(spec) = &p.spec else { out.push(Row::text(Line::from(Span::styled(" No spec found.", pal.muted())))); return out };
            let g = p.system.clone().unwrap_or_default();
            // Names as wide as the longest, but never more than a third of the width (a phone).
            let nw = (spec.items.iter().map(|i| i.name.chars().count()).chain(spec.fields.iter().map(|f| f.name.chars().count())).max().unwrap_or(10).min(24) + 2).min((w / 3).max(10));
            let item = |i: usize, rest: Vec<Span<'static>>| { let mut v = vec![Span::styled(format!("   {}", fit(&spec.items[i].name, nw)), pal.ink())]; v.extend(rest); Row { line: Line::from(v), key: Some(Key::Item(i)) } };
            let doc_of = |i: usize, room: usize| Span::styled(fit(&spec.items[i].doc.clone().unwrap_or_default(), room), pal.muted());
            let of = |kind: &str| spec.items.iter().enumerate().filter(|(_, x)| x.kind == kind).map(|(i, _)| i).collect::<Vec<_>>();
            let room = w.saturating_sub(nw + 4);
            let summary = format!(" {} · {} types · {} predicates · {} transitions · {} invariants{}", spec.path, of("type").len(), of("predicate").len(), of("transition").len() + of("init").len(), of("invariant").len(),
                { let d = g.nodes.iter().filter(|n| n.changed).count(); if d > 0 { format!(" · {d} differ from trunk") } else { String::new() } });
            out.push(Row::text(Line::from(Span::styled(fit(&summary, w), pal.muted()))));
            out.push(Row::text(Line::default()));

            out.push(header(&format!("vocabulary  {}", of("type").len())));
            for i in of("type") { out.push(item(i, vec![doc_of(i, room)])); }

            out.push(Row::text(Line::default()));
            let ts: Vec<usize> = of("init").into_iter().chain(of("transition")).collect();
            out.push(header(&format!("state machine  {} fields · {} transitions", spec.fields.len(), ts.len())));
            if !spec.fields.is_empty() {
                let names = spec.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(" · ");
                out.push(Row { line: Line::from(vec![Span::styled(format!("   {}", fit("fields", nw)), pal.ink()), Span::styled(fit(&names, room), pal.muted())]), key: Some(Key::Grid) });
            }
            for i in ts { out.push(item(i, vec![doc_of(i, room)])); }

            out.push(Row::text(Line::default()));
            out.push(header("spec → code"));
            // For a predicate a gate decides, which layers reach it: gate · implementation · target · program.
            let layers = |name: &str| -> Option<[Option<String>; 4]> {
                let gate = format!("gate:{name}");
                if !g.edges.iter().any(|e| e.0 == gate && e.1 == format!("spec:{name}")) { return None; }
                let kernel = format!("kernel:{name}");
                let imp = g.edges.iter().any(|e| e.0 == kernel && e.1 == gate);
                let target = g.edges.iter().find(|e| e.1 == kernel && e.0.starts_with("target:")).and_then(|e| g.nodes.iter().find(|n| n.id == e.0)).map(|n| n.group.clone());
                let program = g.edges.iter().find(|e| e.0.starts_with("program:") && g.edges.iter().any(|t| t.0 == e.1 && t.1 == kernel && e.1.starts_with("target:"))).and_then(|e| g.nodes.iter().find(|n| n.id == e.0))
                    .map(|n| std::path::Path::new(&n.file).file_name().map_or(n.file.clone(), |f| f.to_string_lossy().to_string()));
                Some([Some("gate".into()), imp.then(|| "impl".into()), target, program])
            };
            let mut decided: Vec<usize> = of("predicate").into_iter().filter(|i| layers(&spec.items[*i].name).is_some()).collect();
            decided.sort_by_key(|i| spec.items[*i].name.clone());
            for i in &decided {
                let ls = layers(&spec.items[*i].name).unwrap();
                let cells: Vec<Span<'static>> = ls.iter().zip([5usize, 5, 7, 10]).map(|(c, cw)| match c {
                    Some(x) => Span::styled(fit(x, cw), pal.ink()),
                    None => Span::styled(fit("·", cw), pal.faint()),
                }).collect();
                let mut row = vec![];
                if w >= nw + 4 + 27 { row.extend(cells); } else { row.push(Span::styled(ls.iter().map(|c| if c.is_some() { '●' } else { '·' }).collect::<String>(), pal.ink())); }
                out.push(item(*i, row));
            }
            let rest: Vec<usize> = of("predicate").into_iter().filter(|i| !decided.contains(i)).collect();
            if !rest.is_empty() {
                out.push(Row::text(Line::from(Span::styled(format!("   {} more predicates, defined in the spec", rest.len()), pal.faint()))));
                for i in rest { out.push(item(i, vec![doc_of(i, room)])); }
            }

            let rules: Vec<usize> = of("invariant").into_iter().chain(of("property")).collect();
            if !rules.is_empty() {
                out.push(Row::text(Line::default()));
                out.push(header(&format!("invariants and properties  {}", rules.len())));
                for i in rules { out.push(item(i, vec![doc_of(i, room)])); }
            }

            out.push(Row::text(Line::default()));
            out.push(header("rests on"));
            for (ti, t) in g.trusted.iter().enumerate() {
                out.push(Row { line: Line::from(vec![Span::styled("  ┆", pal.faint()), Span::styled(format!("{}", fit(&t.name, nw)), pal.ink()), Span::styled(fit(&format!("{}:{}  {}", t.file, t.line, t.doc.clone().unwrap_or_default()), room), pal.muted())]), key: Some(Key::Trusted(ti)) });
            }
            if let Some(sb) = &p.sbom {
                let comps = &sb.document.components;
                let tools: Vec<String> = comps.iter().filter(|c| c.group.as_deref() == Some("tcb")).map(|c| c.name.clone()).collect();
                let crates = comps.iter().filter(|c| c.r#type == "library").count();
                let services: Vec<String> = sb.document.services.iter().map(|s| s.name.clone()).collect();
                for (k, label, v) in [("tools", "tools", tools.join(" · ")), ("services", "services", services.join(" · ")), ("crates", "crates", format!("{crates}"))] {
                    out.push(Row { line: Line::from(vec![Span::styled(format!("   {}", fit(label, nw)), pal.ink()), Span::styled(fit(&v, room), pal.muted())]), key: Some(Key::Sbom(k)) });
                }
            }
        }
        Tab::Project => {
            let t = &p.totals;
            let line = |label: &str, value: Vec<Span<'static>>| { let mut v = vec![Span::styled(format!(" {} ", fit(label, 16)), pal.muted())]; v.extend(value); Row::text(Line::from(v)) };
            out.push(header("cost"));
            out.push(line("total", vec![Span::styled(money(Some(t.cost)), pal.strong()), Span::styled("  =  ", pal.faint()), Span::styled(money(Some(t.generation)), pal.ink()), Span::styled(" generation  +  ", pal.muted()), Span::styled(money(Some(t.time_cost)), pal.ink()), Span::styled(format!(" time{}", t.rate.map_or(String::new(), |r| format!(" at ${r:.0}/h"))), pal.muted())]));
            out.push(line("per verified", vec![Span::styled(money(t.per_verified_candidate), pal.ink()), Span::styled("   per push  ", pal.muted()), Span::styled(money(t.per_push), pal.ink())]));
            let share = |v: f64| if t.cost > 0.0 { v / t.cost } else { 0.0 };
            let bar = |v: f64, tone: Tone| { let n = (share(v) * 30.0).round() as usize; Span::styled("█".repeat(n), pal.tone(tone)) };
            out.push(line("where it went", vec![bar(t.pushed, Tone::Violet), bar(t.not_pushed, Tone::Red), bar(t.in_flight, Tone::Orange)]));
            out.push(line("", vec![Span::styled(format!("{} reached a push  {:.0}%", money(Some(t.pushed)), share(t.pushed) * 100.0), pal.tone(Tone::Violet))]));
            out.push(line("", vec![Span::styled(format!("{} did not  {:.0}%", money(Some(t.not_pushed)), share(t.not_pushed) * 100.0), pal.tone(Tone::Red))]));
            if t.in_flight > 0.0 { out.push(line("", vec![Span::styled(format!("{} in flight  {:.0}%", money(Some(t.in_flight)), share(t.in_flight) * 100.0), pal.tone(Tone::Orange))])); }
            out.push(Row::text(Line::default()));
            out.push(header("results"));
            let cands: Vec<&Facts> = p.processes.iter().flat_map(|b| &b.searches).flat_map(|s| &s.candidates).collect();
            let (v, a, r) = (cands.iter().filter(|c| c.verified).count(), cands.iter().filter(|c| c.accepted && !c.verified).count(), cands.iter().filter(|c| !c.accepted).count());
            out.push(line("candidates", vec![Span::styled(format!("{}", cands.len()), pal.strong()), Span::styled(format!("   {v} verified", ), pal.tone(Tone::Green)), Span::styled(format!("   {a} accepted, not verified"), pal.tone(Tone::Yellow)), Span::styled(format!("   {r} rejected"), pal.tone(Tone::Red))]));
            let mut kinds: Vec<(String, usize)> = Vec::new();
            for g in p.groups.iter().filter(|g| g.outcome == "pushed") { match kinds.iter_mut().find(|(k, _)| *k == g.kind) { Some(e) => e.1 += 1, None => kinds.push((g.kind.clone(), 1)) } }
            out.push(line("pushes", vec![Span::styled(format!("{}", t.pushes), pal.strong()), Span::styled(format!("   {}", kinds.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(" · ")), pal.muted())]));
            out.push(Row::text(Line::default()));
            out.push(header("trunk"));
            let repo = &p.repo;
            out.push(line("head", vec![Span::styled(short(repo.remote_head.as_deref().or(repo.head.as_deref()).unwrap_or("")), pal.ink()), Span::styled(format!("  {}", repo.subject.clone().unwrap_or_default()), pal.muted())]));
            if let Some(lp) = &repo.last_push { out.push(line("last push", vec![Span::styled(short(lp.commit.as_deref().unwrap_or("")), pal.ink()), Span::styled(format!("  {}", lp.time.map_or(String::new(), |t| ago(repo.now, t))), pal.muted())])); }
            if let Some(sp) = &repo.since_push { out.push(line("since push", vec![Span::styled(format!("{} commits", sp.commits), pal.ink()), Span::styled(if sp.authors.is_empty() { String::new() } else { format!("  by {}", sp.authors.join(", ")) }, pal.muted())])); }
        }
    }
    out
}

// ── detail ──────────────────────────────────────────────

/// The focused row's key.
fn focused(app: &App) -> Option<Key> { rows(app, 200).into_iter().nth(app.focus[app.ti()]).and_then(|r| r.key) }

/// The goals in the order Traces lists them.
fn sorted_groups(p: &Projection) -> Vec<&GoalTrace> {
    let mut groups: Vec<&GoalTrace> = p.groups.iter().collect();
    groups.sort_by_key(|g| (!g.running, -g.time));
    groups
}

/// Each edge into (`up`) or out of an item, followed `depth` steps: its call graph, as indented lines.
fn chain(g: &projection::SpecGraph, id: &str, up: bool, depth: usize, indent: usize, seen: &mut Vec<String>, pal: Palette, out: &mut Vec<Line<'static>>) {
    if depth == 0 { return; }
    for e in g.edges.iter().filter(|e| if up { e.1 == id } else { e.0 == id }) {
        let other = if up { &e.0 } else { &e.1 };
        if seen.contains(other) { continue; }
        seen.push(other.clone());
        let (name, at) = g.nodes.iter().find(|n| n.id == *other).map_or((other.clone(), String::new()), |n| (n.name.clone(), if n.name == n.file { String::new() } else { format!("{}:{}", n.file, n.line.unwrap_or(0)) }));
        let trusted = g.nodes.iter().find(|n| n.id == *other).map_or(false, |n| n.layer == "entry" || n.layer == "target");
        out.push(Line::from(vec![
            Span::styled(format!("{}{} ", " ".repeat(indent), if trusted { "┆" } else { "│" }), pal.faint()),
            Span::styled(format!("{} ", fit(&e.2, 11)), pal.muted()),
            Span::styled(format!("{name}  "), pal.ink()),
            Span::styled(at, pal.faint()),
        ]));
        chain(g, other, up, depth - 1, indent + 2, seen, pal, out);
    }
}

fn detail(app: &App, width: u16) -> Text<'static> {
    let pal = app.palette;
    let mut t: Vec<Line<'static>> = Vec::new();
    let head = |s: String| Line::from(Span::styled(s, pal.strong()));
    let sub = |s: &str| Line::from(Span::styled(s.to_string(), pal.faint().add_modifier(Modifier::BOLD)));
    let kv = |k: &str, v: Vec<Span<'static>>| { let mut x = vec![Span::styled(format!("{} ", fit(k, 12)), pal.muted())]; x.extend(v); Line::from(x) };
    match app.tab {
        Tab::Traces => {
            let Some(Key::Goal(gi)) = focused(app) else { return Text::default() };
            let Some(g) = sorted_groups(&app.p).get(gi).copied() else { return Text::default() };
            let tone = pal.tone(outcome_tone(&g.outcome));
            t.push(Line::from(vec![Span::styled(format!("{} ", g.kind), pal.strong()), Span::styled(g.title.clone(), pal.strong()), Span::raw("   "), Span::styled(format!("● {}", g.outcome), tone)]));
            t.extend(hanging(&g.sentence, 0, width as usize, pal.muted()));
            if !g.about.subject.is_empty() { t.extend(hanging(&format!("{} · {}", short(&g.about.from), g.about.subject), 0, width as usize, pal.faint())); }
            t.push(Line::default());
            let total = g.push.as_ref().and_then(|p| p.cost).unwrap_or(g.cost);
            t.push(kv(if g.push.is_some() { "to push" } else { "cost" }, vec![Span::styled(money(Some(total)), pal.strong()), Span::styled(" = ", pal.faint()), Span::styled(money(Some(g.generation)), pal.ink()), Span::styled(" gen + ", pal.muted()), Span::styled(money(Some(g.time_cost)), pal.ink()), Span::styled(" time", pal.muted())]));
            if let Some(p) = &g.push {
                if let (Some(a), Some(b)) = (p.to_selection, p.counterexample) { t.push(kv("", vec![Span::styled(format!("{} to selection + {} counterexample", money(Some(a)), money(Some(b))), pal.muted())])); }
                if let Some(c) = &p.commit { t.push(kv("pushed", vec![Span::styled(c.clone(), pal.ink())])); }
            }
            for b in &g.processes {
                t.push(Line::default());
                t.push(Line::from(vec![Span::styled(format!("bon process {}", b.pid), pal.ink()), Span::styled(format!("   {}   {}", b.outcome, ago(app.p.repo.now, b.time)), pal.muted())]));
                for s in &b.searches {
                    let stone = if s.running { Tone::Orange } else if s.blocked.is_some() { Tone::Yellow } else if s.kind == "counterexample" { Tone::Indigo } else if s.selected.is_some() { Tone::Blue } else { Tone::Yellow };
                    let kernel = match s.kernel.as_str() { "derived" => "kernel checked", "unreadable" => "kernel cannot read", _ => "" };
                    // Fit the pane: duration and cost right-aligned at its edge.
                    let what = format!("{} ", fit(&format!("search {}  {}", s.search, s.kind), 24));
                    let how_w = (width as usize).saturating_sub(4 + 25 + 5 + 9).max(10);
                    let how = fit(&format!("{} → {} verified{}", s.width.max(s.returned), s.verified, s.selected.map_or(String::new(), |i| format!(" → #{i}"))), how_w);
                    t.push(Line::from(vec![
                        Span::styled("  ● ", pal.tone(stone)),
                        Span::styled(what, pal.ink()),
                        Span::styled(how, pal.muted()),
                        Span::styled(format!("{:>5}", s.seconds.map_or(String::new(), took)), pal.faint()),
                        Span::styled(format!("{:>9}", s.cost.map_or(String::new(), |c| money(Some(c)))), pal.ink()),
                    ]));
                    let facts: Vec<String> = [(!s.params.base.is_empty()).then(|| format!("base {}", short(&s.params.base))), s.params.limit.map(|l| format!("limit {}", money(Some(l)))), (!kernel.is_empty()).then(|| kernel.to_string())].into_iter().flatten().collect();
                    if !facts.is_empty() { t.push(Line::from(Span::styled(format!("    {}", facts.join(" · ")), pal.faint()))); }
                    if !s.params.authority.is_empty() { t.extend(hanging(&format!("may change {}", s.params.authority), 4, width as usize, pal.faint())); }
                    if s.blocked.is_some() { for l in why_blocked(s) { t.extend(hanging(&l, 4, width as usize, pal.tone(Tone::Yellow))); } }
                    if !s.candidates.is_empty() {
                        t.push(Line::from(Span::styled(format!("    {}  {}  {}  {}  {}  {}", fit("#", 4), fit("commit", 8), fit("verified", 9), fit("rank", 5), fit("lines", 10), "gen"), pal.faint())));
                        let mut cs: Vec<&Facts> = s.candidates.iter().collect();
                        cs.sort_by_key(|c| (!c.verified, -(c.rank.unwrap_or(0)), c.diff.unwrap_or(0)));
                        for c in cs {
                            let sel = s.selected == Some(c.index);
                            let v = if c.verified { ("yes", Tone::Green) } else if c.accepted { ("no", Tone::Yellow) } else { ("rejected", Tone::Red) };
                            t.push(Line::from(vec![
                                Span::styled(format!("    {}  ", fit(&format!("{}{}", c.index, if sel { "★" } else { "" }), 4)), if sel { pal.tone(Tone::Blue) } else { pal.muted() }),
                                Span::styled(format!("{}  ", fit(&short(c.commit.as_deref().unwrap_or("")), 8)), pal.ink()),
                                Span::styled(format!("{}  ", fit(v.0, 9)), pal.tone(v.1)),
                                Span::styled(format!("{}  ", fit(&c.rank.map_or("—".into(), |r| r.to_string()), 5)), pal.muted()),
                                Span::styled(format!("{}  ", fit(&match (c.added, c.removed) { (Some(a), Some(r)) => format!("+{a} −{r}"), _ => c.diff.map_or("—".into(), |d| d.to_string()) }, 10)), pal.muted()),
                                Span::styled(money(c.generation), pal.muted()),
                                Span::styled(if c.flags.is_empty() { String::new() } else { format!("  {}", c.flags.join(" · ")) }, pal.tone(Tone::Red)),
                            ]));
                        }
                    }
                }
            }
        }
        Tab::Queue => {
            match focused(app) {
                Some(Key::Queue(qi)) => {
                    let Some(q) = app.p.queue.as_ref().and_then(|q| q.get(qi)) else { return Text::default() };
                    t.push(head(format!("queue {}", q.id)));
                    t.push(Line::from(Span::styled("wanted, and not yet in the spec", pal.muted())));
                    t.push(Line::default());
                    t.extend(hanging(&q.intent, 0, width as usize, pal.ink()));
                }
                Some(Key::Proposal(pi)) => {
                    let Some(pr) = app.p.proposals.get(pi) else { return Text::default() };
                    t.push(Line::from(vec![Span::styled("proposal  ", pal.strong()), Span::styled(pr.source.clone(), pal.ink()), Span::styled("   ● waiting for you", pal.tone(Tone::Yellow))]));
                    t.push(Line::from(Span::styled(pr.path.clone(), pal.faint())));
                    for i in &pr.intents {
                        t.push(Line::default());
                        t.push(Line::from(vec![Span::styled(format!("{} ", i.id.map_or("—".into(), |n| n.to_string())), pal.muted()), Span::styled(i.cue.clone().map_or(String::new(), |c| format!("cue {c}")), pal.faint())]));
                        t.extend(hanging(&i.intent, 2, width as usize, pal.ink()));
                    }
                    if !pr.contested.is_empty() { t.push(Line::default()); t.push(sub("contested: one candidate only")); for c in &pr.contested { t.push(Line::from(Span::styled(format!("  {c}"), pal.ink()))); } }
                    t.push(Line::default());
                    t.push(kv("accept", vec![Span::styled(format!("git am {}", pr.path), pal.ink())]));
                }
                _ => {}
            }
        }
        Tab::Spec => {
            let Some(spec) = &app.p.spec else { return Text::default() };
            let g = app.p.system.clone().unwrap_or_default();
            let wide = width as usize;
            let node = |id: &str| g.nodes.iter().find(|n| n.id == id).cloned();
            let at = |n: &projection::SpecNode| format!("{}:{}", n.file, n.line.unwrap_or(0));
            let verbatim = |t: &mut Vec<Line<'static>>, title: &str, list: &[String]| {
                if list.is_empty() { return; }
                t.push(Line::default()); t.push(sub(title));
                for r in list { t.extend(hanging(r, 2, wide, pal.ink())); }
            };
            let graph = |t: &mut Vec<Line<'static>>, id: &str| {
                let mut up = Vec::new(); chain(&g, id, true, 4, 0, &mut vec![id.to_string()], pal, &mut up);
                if !up.is_empty() { t.push(Line::default()); t.push(sub("reached from")); t.extend(up); }
                let mut down = Vec::new(); chain(&g, id, false, 3, 0, &mut vec![id.to_string()], pal, &mut down);
                if !down.is_empty() { t.push(Line::default()); t.push(sub("reaches")); t.extend(down); }
            };
            match focused(app) {
                Some(Key::Item(i)) => {
                    let it = &spec.items[i];
                    t.push(Line::from(vec![Span::styled(it.name.clone(), pal.strong()), Span::styled(format!("   {}", it.kind), pal.muted())]));
                    if let Some(d) = &it.doc { t.extend(hanging(d, 0, wide, pal.ink())); }
                    let sid = format!("spec:{}", it.name);
                    if let Some(n) = node(&sid) { t.push(Line::from(Span::styled(format!("{}{}", at(&n), if n.changed { "  · differs from trunk" } else { "" }), pal.faint()))); }
                    verbatim(&mut t, "requires", &it.requires);
                    let list = |t: &mut Vec<Line<'static>>, k: &str, v: &[String]| {
                        let mut ls = hanging(&v.join(" · "), 13, wide, pal.ink());
                        if let Some(first) = ls.first_mut() { let rest: String = first.spans[0].content.chars().skip(13).collect(); *first = Line::from(vec![Span::styled(format!("{} ", fit(k, 12)), pal.muted()), Span::styled(rest, pal.ink())]); }
                        t.extend(ls);
                    };
                    if !it.reads.is_empty() { t.push(Line::default()); list(&mut t, "reads", &it.reads); }
                    if !it.updates.is_empty() { list(&mut t, "writes", &it.updates); }
                    if let Some(n) = node(&sid) {
                        if !n.adds.is_empty() { t.push(kv("adds", vec![Span::styled(n.adds.join(" · "), pal.ink())])); }
                        if !n.removes.is_empty() { t.push(kv("removes", vec![Span::styled(n.removes.join(" · "), pal.ink())])); }
                    }
                    // A predicate a gate decides: the gate's contract, as written.
                    if let Some(gate) = node(&format!("gate:{}", it.name)) {
                        t.push(Line::default());
                        t.push(Line::from(vec![Span::styled(format!("gate {}", gate.name), pal.ink()), Span::styled(format!("   trait {} · {}{}", gate.group, at(&gate), if gate.changed { " · differs from trunk" } else { "" }), pal.faint())]));
                        verbatim(&mut t, "requires", &gate.requires);
                        verbatim(&mut t, "ensures", &gate.ensures);
                        if let Some(k) = node(&format!("kernel:{}", it.name)) {
                            t.push(Line::default());
                            t.push(Line::from(vec![Span::styled(format!("implementation {}", k.name), pal.ink()), Span::styled(format!("   {}{}", at(&k), if k.uses.is_empty() { String::new() } else { format!(" · uses {}", k.uses.join(", ")) }), pal.faint())]));
                        }
                    }
                    // Where it is a guard.
                    let guards: Vec<String> = g.nodes.iter().filter(|n| n.guards.contains(&it.name)).map(|n| n.name.clone()).collect();
                    if !guards.is_empty() { t.push(Line::default()); t.push(kv("guards", vec![Span::styled(guards.join(" · "), pal.ink())])); }
                    // The emitted type of the same name, and who reads it.
                    if let Some(ty) = node(&format!("type:{}", it.name)) { t.push(Line::default()); t.push(kv("emitted", vec![Span::styled(format!("for programs, from {}", at(&ty)), pal.ink())])); }
                    graph(&mut t, &sid);
                }
                Some(Key::Grid) => {
                    t.push(Line::from(vec![Span::styled("state machine", pal.strong()), Span::styled(format!("   {} fields", spec.fields.len()), pal.muted())]));
                    t.push(Line::from(Span::styled("r reads · w writes · + adds · − removes", pal.faint())));
                    t.push(Line::default());
                    let ts: Vec<&projection::SpecItem> = spec.items.iter().filter(|x| x.kind == "transition" || x.kind == "init").collect();
                    let nw = ts.iter().map(|x| x.name.chars().count()).max().unwrap_or(8) + 2;
                    // Columns: one per field, as wide as its name, or its first letters when narrow.
                    let cw = |f: &str| f.chars().count().min(((wide.saturating_sub(nw)) / spec.fields.len().max(1)).saturating_sub(1).max(2)) + 1;
                    let mut header = vec![Span::raw(" ".repeat(nw))];
                    for f in &spec.fields { header.push(Span::styled(format!("{} ", fit(&f.name, cw(&f.name) - 1)), pal.muted())); }
                    t.push(Line::from(header));
                    for x in ts {
                        let n = node(&format!("spec:{}", x.name));
                        let mut row = vec![Span::styled(fit(&x.name, nw), pal.ink())];
                        for f in &spec.fields {
                            let mut m = String::new();
                            if x.reads.contains(&f.name) { m.push('r'); }
                            if x.updates.contains(&f.name) { m.push('w'); }
                            if n.as_ref().is_some_and(|n| n.adds.contains(&f.name)) { m.push('+'); }
                            if n.as_ref().is_some_and(|n| n.removes.contains(&f.name)) { m.push('−'); }
                            row.push(Span::styled(format!("{} ", fit(if m.is_empty() { "·" } else { &m }, cw(&f.name) - 1)), if m.is_empty() { pal.faint() } else { pal.ink() }));
                        }
                        t.push(Line::from(row));
                    }
                    t.push(Line::default());
                    t.push(sub("fields"));
                    for f in &spec.fields {
                        t.push(Line::from(vec![Span::styled(format!("{} ", fit(&f.name, nw)), pal.ink()), Span::styled(f.r#type.clone(), pal.muted())]));
                        if let Some(d) = f.doc.as_ref().filter(|d| !d.is_empty()) { t.extend(hanging(d, nw + 1, wide, pal.faint())); }
                    }
                }
                Some(Key::Trusted(ti)) => {
                    let Some(tf) = g.trusted.get(ti) else { return Text::default() };
                    t.push(Line::from(vec![Span::styled(tf.name.clone(), pal.strong()), Span::styled("   trusted: Verus does not check it", pal.muted())]));
                    if let Some(d) = &tf.doc { t.extend(hanging(d, 0, wide, pal.ink())); }
                    t.push(Line::from(Span::styled(format!("{}:{}{}", tf.file, tf.line, if tf.changed { "  · differs from trunk" } else { "" }), pal.faint())));
                    let callers: Vec<&projection::SpecNode> = g.nodes.iter().filter(|n| n.trusted.contains(&tf.name)).collect();
                    if !callers.is_empty() { t.push(Line::default()); t.push(sub("called by")); for c in callers { t.push(Line::from(vec![Span::styled(format!("  {}  ", c.name), pal.ink()), Span::styled(at(c), pal.faint())])); } }
                }
                Some(Key::Sbom(k)) => {
                    let Some(sb) = &app.p.sbom else { return Text::default() };
                    t.push(Line::from(vec![Span::styled(k.to_string(), pal.strong()), Span::styled(format!("   .bon/sbom.json · {}", if sb.source == "trunk" { "on trunk" } else { "working tree, not on trunk" }), pal.muted())]));
                    t.push(Line::default());
                    match k {
                        "tools" => for c in sb.document.components.iter().filter(|c| c.group.as_deref() == Some("tcb")) { t.push(Line::from(vec![Span::styled(format!("{} ", fit(&c.name, 14)), pal.ink()), Span::styled(c.version.clone(), pal.muted())])); },
                        "services" => for sv in &sb.document.services { t.push(Line::from(vec![Span::styled(format!("{} ", fit(&sv.name, 14)), pal.ink()), Span::styled(sv.endpoints.join(", "), pal.muted())])); },
                        _ => for c in sb.document.components.iter().filter(|c| c.r#type == "library") {
                            t.push(Line::from(vec![Span::styled(format!("{} ", fit(&c.name, 26)), pal.ink()), Span::styled(format!("{} ", fit(&c.version, 12)), pal.muted()), Span::styled(c.hashes.first().map_or(String::new(), |h| h.content.chars().take(12).collect()), pal.faint())]));
                        },
                    }
                }
                _ => {}
            }
        }
        Tab::Project => {}
    }
    Text::from(t)
}

/// The verified candidates of a search, grouped by their agree output.
fn groups(s: &SearchTrace) -> Vec<Vec<&Facts>> {
    let mut out: Vec<Vec<&Facts>> = Vec::new();
    for c in s.candidates.iter().filter(|c| c.verified) {
        match out.iter_mut().find(|g| g[0].out == c.out) { Some(g) => g.push(c), None => out.push(vec![c]) }
    }
    out
}

/// Why a search blocked, from what its candidates show: too few verified, or
/// verified candidates that disagree, each group of agreeing ones by index.
fn why_blocked(s: &SearchTrace) -> Vec<String> {
    let v = s.candidates.iter().filter(|c| c.verified).count();
    let mut out = Vec::new();
    if s.kind == "counterexample" {
        out.push(format!("{v} of its {} tests verified; two are needed to say a counterexample was found or not, so neither", s.candidates.len()));
    } else if v < 2 {
        out.push(format!("too few verified: {v} of {}", s.candidates.len()));
    } else {
        let gs = groups(s);
        if gs.len() > 1 {
            out.push(format!("the verified candidates disagree: {} groups by their agree output", gs.len()));
            for g in &gs { out.push(format!("  {}", g.iter().map(|c| format!("#{}", c.index)).collect::<Vec<_>>().join(" "))); }
            out.push("d shows two groups' agree output side by side".into());
        }
    }
    if let Some(b) = &s.blocked { out.push(format!("trace: {}", b.trim_start_matches("blocked: "))); }
    out
}

/// Text wrapped at `width`, every line after the first indented like the first.
fn hanging(text: &str, indent: usize, width: usize, style: Style) -> Vec<Line<'static>> {
    let room = width.saturating_sub(indent).max(12);
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > room { lines.push(std::mem::take(&mut cur)); }
        if !cur.is_empty() { cur.push(' '); }
        cur.push_str(word);
    }
    if !cur.is_empty() { lines.push(cur); }
    lines.into_iter().map(|l| Line::from(Span::styled(format!("{}{l}", " ".repeat(indent)), style))).collect()
}

// ── drawing ─────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let pal = app.palette;
    let area = f.area();
    let [top, tabs, rule, body, foot] = Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)]).areas(area);
    let p = &app.p;

    // Header: the repository, trunk and what is running; the money equation at the right.
    let running = p.processes.iter().filter(|b| b.running).count();
    let repo = &p.repo;
    let mut left_spans = vec![
        Span::styled(" bon", pal.faint().add_modifier(Modifier::BOLD)),
        Span::styled(" / ", pal.faint()),
        Span::styled(format!("{} ", repo.name.clone().unwrap_or_default()), pal.strong()),
        Span::styled(format!("· {} {} ", repo.trunk.clone().unwrap_or("main".into()), short(repo.remote_head.as_deref().or(repo.head.as_deref()).unwrap_or(""))), pal.muted()),
        Span::styled(if top.width < 64 { String::new() } else { repo.last_push.as_ref().and_then(|l| l.time).map_or(String::new(), |t| format!("· pushed {} ", ago(repo.now, t))) }, pal.muted()),
        if running > 0 { Span::styled(format!("· ● running {running}"), pal.tone(Tone::Orange)) } else { Span::styled("· idle", pal.faint()) },
    ];
    let t = &p.totals;
    let right = Line::from(vec![
        Span::styled(money(Some(t.cost)), pal.strong()), Span::styled(" = ", pal.faint()),
        Span::styled(money(Some(t.generation)), pal.ink()), Span::styled(" gen + ", pal.muted()),
        Span::styled(money(Some(t.time_cost)), pal.ink()), Span::styled(" time ", pal.muted()),
    ]);
    // The money at the right: the equation when it fits, the total when it does not.
    let left_w: usize = left_spans.iter().map(|s| s.content.chars().count()).sum();
    let right_w: usize = right.spans.iter().map(|s| s.content.chars().count()).sum();
    let money_spans = if left_w + right_w + 2 <= top.width as usize { right.spans } else { vec![Span::styled(format!("{} ", money(Some(t.cost))), pal.strong())] };
    let pad = (top.width as usize).saturating_sub(left_w + money_spans.iter().map(|s| s.content.chars().count()).sum::<usize>());
    left_spans.push(Span::raw(" ".repeat(pad)));
    left_spans.extend(money_spans);
    f.render_widget(Paragraph::new(Line::from(left_spans)), top);

    // Tabs, with counts where a count says something.
    let label = |tab: Tab| match tab {
        Tab::Project => "Project".to_string(),
        Tab::Spec => "Spec".to_string(),
        Tab::Queue => format!("Queue {}", p.queue.as_ref().map_or(0, |q| q.len())),
        Tab::Traces => format!("Traces {}", p.groups.len()),
    };
    let mut spans = vec![Span::raw(" ")];
    for tab in TABS {
        let on = tab == app.tab;
        spans.push(Span::styled(format!(" {} ", label(tab)), if on { pal.strong().add_modifier(Modifier::UNDERLINED) } else { pal.muted() }));
        spans.push(Span::raw("  "));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), tabs);
    f.render_widget(Paragraph::new(Line::from(Span::styled("─".repeat(rule.width as usize), pal.rule()))), rule);

    // Body: the list, and the focused item's detail beside it or over it.
    let wide = body.width >= 100;
    let detail_tab = app.tab != Tab::Project;
    let (list_area, detail_area) = if !detail_tab { (body, None) }
        else if wide {
            // Beside the detail the list is compact (its steps are in the detail), so the detail has room.
            let list_w = (body.width * 9 / 20).clamp(54, 66).min(body.width.saturating_sub(40));
            let [l, _, d] = Layout::horizontal([Constraint::Length(list_w), Constraint::Length(1), Constraint::Min(30)]).areas(body); (l, Some(d))
        }
        else if app.detail_open { (Rect::default(), Some(body)) } else { (body, None) };
    if wide && detail_tab {
        let x = list_area.right();
        for y in body.top()..body.bottom() { f.buffer_mut()[(x, y)].set_symbol("│").set_style(pal.rule()); }
    }
    let list = rows(app, list_area.width);
    let ti = app.ti();
    // Keep the focus on a focusable row, and in view.
    if !list.is_empty() {
        let mut i = app.focus[ti].min(list.len() - 1);
        if !list[i].focusable() { if let Some(j) = (i..list.len()).chain((0..i).rev()).find(|&j| list[j].focusable()) { i = j; } }
        app.focus[ti] = i;
        let h = list_area.height as usize;
        if h > 0 {
            if i < app.top[ti] { app.top[ti] = i.saturating_sub(1); }
            if i >= app.top[ti] + h { app.top[ti] = i + 1 - h; }
        }
    }
    if list_area.width > 0 {
        let lines: Vec<Line> = list.into_iter().enumerate().skip(app.top[ti]).take(list_area.height as usize).map(|(i, r)| {
            if r.focusable() && i == app.focus[ti] && detail_tab {
                let mut l = r.line.patch_style(pal.selected());
                if let Some(first) = l.spans.first_mut() { if first.content.starts_with(' ') { *first = Span::styled(format!("▎{}", &first.content[1..]), pal.tone(Tone::Blue).patch(pal.selected())); } }
                l
            } else { r.line }
        }).collect();
        f.render_widget(Paragraph::new(lines), list_area);
    }
    if let Some(d) = detail_area {
        let inner = Rect { x: d.x + 1, width: d.width.saturating_sub(2), ..d };
        f.render_widget(Paragraph::new(detail(app, inner.width)).wrap(Wrap { trim: false }).scroll((app.detail_top, 0)), inner);
    }
    // An overlay covers the body.
    match &app.overlay {
        Overlay::None => {}
        Overlay::Logs { items, sel } => {
            f.render_widget(ratatui::widgets::Clear, body);
            let mut lines = vec![Line::from(Span::styled(" logs  ⏎ open · esc back", pal.faint().add_modifier(Modifier::BOLD))), Line::default()];
            let h = body.height.saturating_sub(2) as usize;
            let first = sel.saturating_sub(h.saturating_sub(1));
            for (i, (label, _)) in items.iter().enumerate().skip(first).take(h) {
                let l = Line::from(Span::styled(format!(" {}", fit(label, body.width as usize - 1)), if i == *sel { pal.ink().patch(pal.selected()) } else { pal.muted() }));
                lines.push(l);
            }
            f.render_widget(Paragraph::new(lines), body);
        }
        Overlay::Text { title, lines, top } => {
            f.render_widget(ratatui::widgets::Clear, body);
            let [head, text] = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).areas(body);
            f.render_widget(Paragraph::new(Line::from(vec![Span::styled(format!(" {title}"), pal.strong()), Span::styled(format!("   line {} of {} · esc back", top + 1, lines.len()), pal.faint())])), head);
            // Long lines wrap, so nothing is cut at the edge.
            let shown: Vec<Line> = lines.iter().skip(*top).take(text.height as usize * 2).map(|l| Line::from(Span::styled(l.clone(), pal.ink()))).collect();
            f.render_widget(Paragraph::new(shown).wrap(Wrap { trim: false }), Rect { x: text.x + 1, width: text.width.saturating_sub(2), ..text });
        }
        Overlay::Compare { titles, left, right, top } => {
            f.render_widget(ratatui::widgets::Clear, body);
            let [l, _, r] = Layout::horizontal([Constraint::Percentage(50), Constraint::Length(1), Constraint::Percentage(50)]).areas(body);
            for (area, title, text) in [(l, &titles.0, left), (r, &titles.1, right)] {
                let mut out = vec![Line::from(Span::styled(format!(" {title}"), pal.strong())), Line::default()];
                out.extend(text.iter().enumerate().skip(*top).take(area.height as usize).map(|(i, line)| {
                    let other = if std::ptr::eq(text, left) { right.get(i) } else { left.get(i) };
                    Line::from(Span::styled(format!(" {line}"), if other == Some(line) { pal.muted() } else { pal.ink() }))
                }));
                f.render_widget(Paragraph::new(out), area);
            }
            for y in body.top()..body.bottom() { f.buffer_mut()[(l.right(), y)].set_symbol("│").set_style(pal.rule()); }
        }
    }

    // Footer: the keys, or an error reading the projection.
    let filter = app.filter.lock().map(|f| f.clone()).unwrap_or_default();
    let foot_line = if let Some(e) = &app.error { Line::from(Span::styled(format!(" {e}"), pal.tone(Tone::Red))) }
    else if let Some(buf) = &app.input { Line::from(vec![Span::styled(" find ", pal.muted()), Span::styled(format!("{buf}▏"), pal.ink()), Span::styled("   ⏎ apply · esc cancel", pal.faint())]) }
    else {
        let k = |key: &str, what: &str| vec![Span::styled(format!(" {key} "), pal.ink()), Span::styled(format!("{what}  "), pal.faint())];
        let mut items: Vec<Vec<Span>> = vec![k("↑↓", "move"), k("⇥", "tab")];
        if app.tab == Tab::Traces { items.push(k("l", "logs")); }
        let find_label = filter.find.as_deref().map_or("find".to_string(), |f| format!("find: {f}"));
        items.push(k("/", &find_label));
        items.push(k("r", RANGES[app.range].0));
        if detail_tab && !wide { items.push(if app.detail_open { k("esc", "back") } else { k("⏎", "open") }); }
        if detail_tab { items.push(k("⇧↑↓", "scroll")); }
        items.push(k("t", if app.dark { "light" } else { "dark" }));
        items.push(k("?", "keys"));
        items.push(k("q", "quit"));
        // Keep what fits, dropping from the middle: move, tab and quit stay.
        let width = |v: &Vec<Vec<Span>>| v.iter().flatten().map(|s| s.content.chars().count()).sum::<usize>();
        while width(&items) > foot.width as usize && items.len() > 3 { items.remove(items.len() - 2); }
        Line::from(items.into_iter().flatten().collect::<Vec<_>>())
    };
    f.render_widget(Paragraph::new(foot_line), foot);

    if app.keys {
        let w = 50.min(area.width); let h = 16.min(area.height);
        let r = Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h };
        f.render_widget(ratatui::widgets::Clear, r);
        let lines: Vec<Line> = [("↑ ↓  j k", "move"), ("⇥  1 2 3 4", "tab"), ("⏎", "open the detail (narrow)"), ("esc", "close it"), ("⇧↑ ⇧↓  pgup pgdn", "scroll the detail"),
            ("l", "a goal's logs"), ("d", "disagreeing outputs side by side"), ("/", "find"), ("r", "time range"), ("g G", "top, bottom"), ("t", "light or dark"), ("q", "quit")]
            .iter().map(|(k, w)| Line::from(vec![Span::styled(format!("  {} ", fit(k, 18)), pal.ink()), Span::styled(w.to_string(), pal.muted())])).collect();
        let mut all = vec![Line::from(Span::styled("  keys", pal.strong())), Line::default()]; all.extend(lines);
        f.render_widget(Paragraph::new(all).block(ratatui::widgets::Block::bordered().border_style(pal.rule())), r);
    }
}

// ── a frame as HTML ─────────────────────────────────────

fn css(c: Color) -> Option<String> { match c { Color::Rgb(r, g, b) => Some(format!("#{r:02x}{g:02x}{b:02x}")), _ => None } }

/// One frame of the view at w×h, on a given tab, as a self-contained HTML page:
/// the same cells a terminal would show, for a preview anywhere.
pub fn frame(root: &str, w: u16, h: u16, tab: usize, focus: usize, light: bool) -> Result<String, String> {
    use ratatui::backend::TestBackend;
    let mut app = App::new();
    app.root = root.into();
    app.p = projection::read(std::path::Path::new(root), &view::Filter::default())?;
    app.tab = TABS[tab.min(3)];
    if light { app.dark = false; app.palette = LIGHT; }
    // Focus the focus-th focusable row.
    if let Some((i, _)) = rows(&app, w).iter().enumerate().filter(|(_, r)| r.focusable()).nth(focus) { app.focus[app.ti()] = i; }
    let mut t = ratatui::Terminal::new(TestBackend::new(w, h)).map_err(|e| e.to_string())?;
    t.draw(|f| draw(f, &mut app)).map_err(|e| e.to_string())?;
    let b = t.backend().buffer().clone();
    let (bg, ink) = if light { ("#F3EDE0", "#1B1A18") } else { ("#09090A", "#EDEAE5") };
    let mut out = format!("<!doctype html><meta charset=utf-8><body style=\"margin:0;background:{bg};color:{ink};padding:14px 16px\"><pre style=\"margin:0;font:14px/1.45 Menlo,SFMono-Regular,monospace\">");
    for y in 0..h {
        for x in 0..w {
            let c = &b[(x, y)];
            let mut style = String::new();
            if let Some(fg) = css(c.fg) { style += &format!("color:{fg};"); }
            if let Some(bgc) = css(c.bg) { style += &format!("background:{bgc};"); }
            if c.modifier.contains(Modifier::BOLD) { style += "font-weight:700;"; }
            if c.modifier.contains(Modifier::UNDERLINED) { style += "text-decoration:underline;"; }
            let sym = c.symbol().replace('&', "&amp;").replace('<', "&lt;");
            if style.is_empty() { out += &sym; } else { out += &format!("<span style=\"{style}\">{sym}</span>"); }
        }
        out.push('\n');
    }
    out += "</pre></body>";
    Ok(out)
}

// ── bon spec ────────────────────────────────────────────

/// Lines of styled text as plain text.
fn plain(t: Text) -> String { t.lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>().trim_end().to_string()).collect::<Vec<_>>().join("\n") }

/// `bon spec`: the Spec tab as text; `bon spec NAME`: one item's detail, as the view shows it.
pub fn spec_text(root: &str, name: Option<&str>, width: u16) -> Result<String, String> {
    let mut app = App::new();
    app.root = root.into();
    app.p = projection::read(std::path::Path::new(root), &view::Filter::default())?;
    app.tab = Tab::Spec;
    let list = rows(&app, width);
    let Some(name) = name else { return Ok(list.into_iter().map(|r| plain(Text::from(r.line))).collect::<Vec<_>>().join("\n") + "\n") };
    let spec = app.p.spec.clone().unwrap_or_default();
    let key = spec.items.iter().position(|i| i.name == name).map(Key::Item).or_else(|| (name == "fields" || name == "state").then_some(Key::Grid))
        .ok_or_else(|| format!("no {name} in the spec; bon spec lists every item"))?;
    let at = list.iter().position(|r| r.key.as_ref() == Some(&key)).ok_or("not listed")?;
    app.focus[app.ti()] = at;
    Ok(plain(detail(&app, width)) + "\n")
}

// ── input ───────────────────────────────────────────────

/// Handle one key; false to quit.
fn key(app: &mut App, k: KeyEvent) -> bool {
    let ti = app.ti();
    let step = |app: &mut App, down: bool| {
        let list = rows(app, 200);
        let mut i = app.focus[ti] as isize;
        loop { i += if down { 1 } else { -1 }; if i < 0 || i as usize >= list.len() { break; } if list[i as usize].focusable() { app.focus[ti] = i as usize; app.detail_top = 0; break; } }
    };
    if app.keys { app.keys = false; return true; }
    // Typing after /: find, as the page's find box.
    if let Some(buf) = app.input.as_mut() {
        match k.code {
            KeyCode::Esc => app.input = None,
            KeyCode::Enter => { let f = app.input.take().filter(|s| !s.is_empty()); app.filter.lock().map(|mut x| x.find = f).ok(); app.focus = [0; 4]; }
            KeyCode::Backspace => { buf.pop(); }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        return true;
    }
    // An overlay takes the keys until esc.
    match &mut app.overlay {
        Overlay::None => {}
        Overlay::Logs { items, sel } => {
            match k.code {
                KeyCode::Esc | KeyCode::Char('q') => app.overlay = Overlay::None,
                KeyCode::Up | KeyCode::Char('k') => *sel = sel.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *sel = (*sel + 1).min(items.len().saturating_sub(1)),
                KeyCode::Enter => if let Some((label, path)) = items.get(*sel).cloned() {
                    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| "This log is no longer on disk.".into());
                    app.overlay = Overlay::Text { title: label, lines: text.lines().map(String::from).collect(), top: 0 };
                },
                _ => {}
            }
            return true;
        }
        Overlay::Text { top, lines, .. } => {
            match k.code {
                KeyCode::Esc | KeyCode::Char('q') => app.overlay = Overlay::None,
                KeyCode::Up | KeyCode::Char('k') => *top = top.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *top = (*top + 1).min(lines.len().saturating_sub(1)),
                KeyCode::PageUp => *top = top.saturating_sub(20),
                KeyCode::PageDown | KeyCode::Char(' ') => *top = (*top + 20).min(lines.len().saturating_sub(1)),
                KeyCode::Char('g') => *top = 0,
                KeyCode::Char('G') => *top = lines.len().saturating_sub(1),
                _ => {}
            }
            return true;
        }
        Overlay::Compare { top, left, right, .. } => {
            let n = left.len().max(right.len());
            match k.code {
                KeyCode::Esc | KeyCode::Char('q') => app.overlay = Overlay::None,
                KeyCode::Up | KeyCode::Char('k') => *top = top.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *top = (*top + 1).min(n.saturating_sub(1)),
                KeyCode::PageUp => *top = top.saturating_sub(20),
                KeyCode::PageDown | KeyCode::Char(' ') => *top = (*top + 20).min(n.saturating_sub(1)),
                _ => {}
            }
            return true;
        }
    }
    match (k.code, k.modifiers) {
        (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => return false,
        (KeyCode::Esc, _) => app.detail_open = false,
        (KeyCode::Char('?'), _) => app.keys = true,
        (KeyCode::Tab, _) => { app.tab = TABS[(ti + 1) % 4]; app.detail_top = 0; }
        (KeyCode::BackTab, _) => { app.tab = TABS[(ti + 3) % 4]; app.detail_top = 0; }
        (KeyCode::Char(c @ '1'..='4'), _) => { app.tab = TABS[c as usize - '1' as usize]; app.detail_top = 0; }
        (KeyCode::Up, KeyModifiers::SHIFT) | (KeyCode::PageUp, _) => app.detail_top = app.detail_top.saturating_sub(if k.code == KeyCode::PageUp { 10 } else { 1 }),
        (KeyCode::Down, KeyModifiers::SHIFT) | (KeyCode::PageDown, _) => app.detail_top = app.detail_top.saturating_add(if k.code == KeyCode::PageDown { 10 } else { 1 }),
        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => step(app, false),
        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => step(app, true),
        (KeyCode::Char('g'), _) => { app.focus[ti] = 0; app.top[ti] = 0; }
        (KeyCode::Char('G'), _) => { app.focus[ti] = usize::MAX; }
        (KeyCode::Enter, _) => app.detail_open = true,
        (KeyCode::Char('t'), _) => { app.dark = !app.dark; app.palette = if app.dark { DARK } else { LIGHT }; }
        (KeyCode::Char('/'), _) => app.input = Some(app.filter.lock().ok().and_then(|f| f.find.clone()).unwrap_or_default()),
        (KeyCode::Char('r'), _) => {
            app.range = (app.range + 1) % RANGES.len();
            let since = (RANGES[app.range].1 > 0).then(|| (app.p.repo.now - RANGES[app.range].1).max(0) as u64);
            app.filter.lock().map(|mut f| f.since = since).ok();
        }
        // Traces: every log of the focused goal's agent processes.
        (KeyCode::Char('l'), _) if app.tab == Tab::Traces => {
            if let Some(Key::Goal(gi)) = focused(app) {
                if let Some(g) = sorted_groups(&app.p).get(gi) {
                    let mut items = Vec::new();
                    for b in &g.processes { for s in &b.searches { for c in &s.candidates { for l in &c.logs {
                        items.push((format!("bon process {} · search {} · #{} · {l}", b.pid, s.search, c.index), app.root.join(".bon/traces").join(b.pid.to_string()).join(s.search.to_string()).join(c.index.to_string()).join(l)));
                    } } } }
                    if !items.is_empty() { app.overlay = Overlay::Logs { items, sel: 0 }; }
                }
            }
        }
        // Traces: two groups of disagreeing candidates, their agree output side by side.
        (KeyCode::Char('d'), _) if app.tab == Tab::Traces => {
            if let Some(Key::Goal(gi)) = focused(app) {
                if let Some(g) = sorted_groups(&app.p).get(gi) {
                    'find: for b in &g.processes { for s in &b.searches {
                        let gs = groups(s);
                        if gs.len() < 2 { continue; }
                        let side = |c: &Facts| { let dir = app.root.join(".bon/traces").join(b.pid.to_string()).join(s.search.to_string()).join(c.index.to_string());
                            let name = c.logs.iter().find(|l| l.starts_with("agree")).cloned().unwrap_or("agree-0".into());
                            (format!("#{} {name}", c.index), std::fs::read_to_string(dir.join(&name)).unwrap_or_default().lines().map(String::from).collect::<Vec<_>>()) };
                        let ((lt, l), (rt, r)) = (side(gs[0][0]), side(gs[1][0]));
                        app.overlay = Overlay::Compare { titles: (lt, rt), left: l, right: r, top: 0 };
                        break 'find;
                    } }
                }
            }
        }
        _ => {}
    }
    true
}

// ── the loop ────────────────────────────────────────────

/// Whether `bon` with these arguments should be the terminal view.
pub fn wanted() -> bool { std::io::stdout().is_terminal() && std::io::stdin().is_terminal() }

/// Run the terminal view until q. The projection is read every 2 s on a thread
/// of its own, so input never waits on the traces.
pub fn run(root: &str, filter: view::Filter) -> Result<(), String> {
    let (tx, rx) = mpsc::channel::<Result<Projection, String>>();
    let mut app = App::new();
    app.root = root.into();
    app.filter = std::sync::Arc::new(std::sync::Mutex::new(filter));
    let (root_t, shared) = (app.root.clone(), app.filter.clone());
    // Read the projection every 2 s, or as soon as find or the range changes.
    std::thread::spawn(move || {
        let mut last: Option<(Option<u64>, Option<String>)> = None;
        let mut at = Instant::now() - Duration::from_secs(10);
        loop {
            let f = shared.lock().map(|f| f.clone()).unwrap_or_default();
            let now_key = (f.since, f.find.clone());
            if last.as_ref() != Some(&now_key) || at.elapsed() >= Duration::from_secs(2) {
                if tx.send(projection::read(&root_t, &f)).is_err() { break; }
                last = Some(now_key); at = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let mut terminal: DefaultTerminal = ratatui::init();
    let result = (|| -> Result<(), String> {
        loop {
            while let Ok(p) = rx.try_recv() {
                match p { Ok(p) => { app.p = p; app.error = None; app.loaded = Some(Instant::now()); } Err(e) => app.error = Some(e) }
            }
            terminal.draw(|f| draw(f, &mut app)).map_err(|e| e.to_string())?;
            if event::poll(Duration::from_millis(200)).map_err(|e| e.to_string())? {
                match event::read().map_err(|e| e.to_string())? {
                    Event::Key(k) if k.kind == KeyEventKind::Press => if !key(&mut app, k) { return Ok(()) },
                    _ => {}
                }
            }
        }
    })();
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn screen(p: Projection, tab: Tab, w: u16, h: u16) -> String {
        let mut app = App::new();
        app.p = p; app.tab = tab;
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let b = t.backend().buffer().clone();
        (0..h).map(|y| (0..w).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().trim_end().to_string()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn every_tab_draws_at_80_and_120_columns() {
        let p: Projection = serde_json::from_value(serde_json::json!({
            "configured": true, "repo": { "name": "r", "trunk": "main", "head": "abcdef1234", "now": 100000 },
            "totals": { "cost": 10.0, "generation": 2.0, "time_cost": 8.0, "pushes": 1 },
            "queue": [{ "id": 7, "intent": "Each trace records every transition." }],
            "groups": [{ "kind": "code", "title": "from abcdef1", "outcome": "pushed", "time": 99000, "cost": 10.0,
                "push": { "commit": "fedcba9876", "cost": 10.0 },
                "processes": [{ "pid": 1, "outcome": "pushed", "searches": [
                    { "search": 0, "kind": "code", "width": 8, "returned": 8, "verified": 7, "selected": 1, "kernel": "derived",
                      "candidates": [{ "index": 1, "commit": "1111111", "accepted": true, "verified": true, "rank": 0, "diff": 9 }] },
                    { "search": 1, "kind": "counterexample", "width": 2, "returned": 2, "verified": 2 }] }] }],
            "spec": { "path": "src/spec.rs", "items": [{ "kind": "predicate", "name": "verified", "doc": "Passed the vertical bottleneck." }], "fields": [] }
        })).unwrap();
        for (w, h) in [(80, 24), (120, 30)] {
            let traces = screen(p.clone(), Tab::Traces, w, h);
            // Full width (80): the steps on the row. Beside the detail (120): the steps in the detail.
            let steps_shown = if w < 100 { "8→7 #1 none found fedcba9" } else { "8 → 7 verified → #1" };
            assert!(traces.contains("pushed") && traces.contains(steps_shown), "{traces}");
            assert!(screen(p.clone(), Tab::Queue, w, h).contains("Each trace records"));
            assert!(screen(p.clone(), Tab::Spec, w, h).contains("verified"));
            assert!(screen(p.clone(), Tab::Project, w, h).contains("$10.00"));
            // Nothing is drawn past the last column.
            assert!(traces.lines().all(|l| l.chars().count() <= w as usize));
        }
        // Wide: the selected group's candidates show beside the list.
        assert!(screen(p.clone(), Tab::Traces, 120, 30).contains("1111111"));
    }

    fn search(kind: &str, outs: &[(bool, u64)]) -> SearchTrace {
        serde_json::from_value(serde_json::json!({ "kind": kind, "blocked": "blocked: fewer than two verified candidates, or they disagree",
            "candidates": outs.iter().enumerate().map(|(i, (v, o))| serde_json::json!({ "index": i, "accepted": true, "verified": v, "out": [o] })).collect::<Vec<_>>() })).unwrap()
    }

    #[test]
    fn a_blocked_search_says_why() {
        // Disagreeing: two groups by agree output, each by index.
        let w = why_blocked(&search("code", &[(true, 1), (true, 2), (true, 1), (false, 3)]));
        assert!(w[0].contains("disagree: 2 groups") && w[1].trim() == "#0 #2" && w[2].trim() == "#1", "{w:?}");
        // Too few verified.
        assert!(why_blocked(&search("code", &[(true, 1), (false, 1)]))[0].contains("too few verified: 1 of 2"));
        // A counterexample with fewer than two verified tests: neither found nor not found.
        assert!(why_blocked(&search("counterexample", &[(true, 1), (false, 1)]))[0].contains("so neither"));
    }

    #[test]
    fn proposals_wait_above_the_queue_and_spec_shows_what_reaches_a_predicate() {
        let p: Projection = serde_json::from_value(serde_json::json!({
            "configured": true, "repo": { "now": 1 },
            "queue": [{ "id": 7, "intent": "queued" }],
            "proposals": [{ "name": "a", "path": ".bon/traces/proposals/a.patch", "source": "transcripts/a.vtt",
                "intents": [{ "id": 8, "intent": "new one", "cue": "transcripts/a.vtt#1200" }], "contested": ["transcripts/a.vtt#900"] }],
            "spec": { "path": "k/model.rs", "items": [{ "kind": "predicate", "name": "may_open", "doc": "A door opens when unlocked." }] },
            "system": { "nodes": [{ "id": "spec:may_open", "layer": "spec", "name": "may_open", "file": "k/model.rs" },
                                  { "id": "gate:may_open", "layer": "gates", "group": "Policy", "name": "may_open", "file": "k/rules.rs", "ensures": ["r == spec::may_open(locked)"] },
                                  { "id": "kernel:may_open", "layer": "implementation", "name": "may_open", "file": "k/impl.rs" }],
                        "edges": [["gate:may_open", "spec:may_open", "ensures"], ["kernel:may_open", "gate:may_open", "implements"]] }
        })).unwrap();
        let q = screen(p.clone(), Tab::Queue, 120, 20);
        assert!(q.find("proposed").unwrap() < q.find("queued").unwrap() && q.contains("1 new, 1 contested"), "{q}");
        let sp = screen(p.clone(), Tab::Spec, 120, 30);
        assert!(sp.contains("may_open") && sp.contains("gate impl"), "{sp}");
    }
}
