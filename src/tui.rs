//! `bon` in a terminal: the projection as four tabs, Project, Spec, Queue and
//! Traces, each a list with the focused item's detail beside it (or, under
//! 100 columns, opened on ⏎). Trusted code. It reads only the projection and
//! the files it names; it decides nothing.
//!
//! Color has one meaning, position on the chain: red needs attention, violet
//! is settled. Everything else is ink, muted or faint, light and dark.

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

/// The view's tokens. A tone is shown mixed toward ink, lifted by `lift`.
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

/// Position on the chain, red to violet. Green has its place on the chain but no use yet.
#[derive(Clone, Copy)]
#[allow(dead_code)]
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

/// An outcome as a value: sentence case.
fn outcome_label(outcome: &str) -> String { if outcome == "not found" { "None found".into() } else { cap(outcome) } }

/// A word shown as a value: its first letter upper case.
fn cap(s: &str) -> String { let mut c = s.chars(); c.next().map_or(String::new(), |f| f.to_uppercase().chain(c).collect()) }

// ── formatting ──────────────────────────────────────────

/// Dollars to the cent; never `$-0.00`.
fn money(v: Option<f64>) -> String { v.filter(|v| v.is_finite()).map_or("—".into(), |v| format!("${:.2}", if v.abs() < 0.005 { 0.0 } else { v })) }
fn short(v: &str) -> String { v.chars().take(7).collect() }
/// The rate time is charged at, next to time.
fn at_rate(r: Option<f64>) -> String { r.map_or(String::new(), |r| format!("at ${r:.0}/h")) }
fn plural(n: usize, one: &str, many: &str) -> String { format!("{n} {}", if n == 1 { one } else { many }) }

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
    if d == today { return "Today".into(); }
    if d == today - 1 { return "Yesterday".into(); }
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
    if n > w { let mut t: String = s.chars().take(w.saturating_sub(1)).collect(); if w > 0 { t.push('…'); } t } else { format!("{s}{}", " ".repeat(w - n)) }
}
/// Right-aligned in exactly `w` columns.
fn right(s: &str, w: usize) -> String { let n = s.chars().count(); if n >= w { s.into() } else { format!("{}{s}", " ".repeat(w - n)) } }

fn width_of(spans: &[Span]) -> usize { spans.iter().map(|s| s.content.chars().count()).sum() }

/// `left` at the start of a line `w` wide and `right` at its end.
fn spread(mut left: Vec<Span<'static>>, right: Vec<Span<'static>>, w: usize) -> Line<'static> {
    let pad = w.saturating_sub(width_of(&left) + width_of(&right)).max(1);
    left.push(Span::raw(" ".repeat(pad)));
    left.extend(right);
    Line::from(left)
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

/// The time ranges r cycles through.
const RANGES: [(&str, i64); 4] = [("All time", 0), ("24 hours", 86400), ("7 days", 7 * 86400), ("30 days", 30 * 86400)];

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
    /// Switch tab; an open detail closes, so a tab opens on its list.
    fn switch(&mut self, tab: Tab) { self.tab = tab; self.detail_top = 0; self.detail_open = false; }
}

// ── the visual hierarchy ────────────────────────────────
//
// Three kinds of text, one style each: a section header (Title Case, strong),
// a label (sentence case, muted) and a value (the data, ink). Faint is for
// what only locates a value (a path, a line number).

/// A section header, with a count when it has one.
fn section(pal: &Palette, indent: usize, title: &str, count: Option<usize>) -> Line<'static> {
    let mut v = vec![Span::styled(format!("{}{title}", " ".repeat(indent)), pal.strong())];
    if let Some(n) = count { v.push(Span::styled(format!("  {n}"), pal.muted())); }
    Line::from(v)
}

/// A label in a column `w` wide, then its value.
fn kv(pal: &Palette, indent: usize, w: usize, label: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let mut v = vec![Span::styled(format!("{}{}", " ".repeat(indent), fit(label, w)), pal.muted())];
    v.extend(value);
    Line::from(v)
}

/// Labeled values on one line, `Base 9bb8a5b   Limit $5.00`, onto the next
/// where the line is full.
fn pairs(pal: &Palette, indent: usize, items: &[(&str, String)], w: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut v = vec![Span::raw(" ".repeat(indent))];
    for (k, val) in items {
        let n = k.chars().count() + 1 + val.chars().count();
        if v.len() > 1 && width_of(&v) + 3 + n > w { out.push(Line::from(std::mem::replace(&mut v, vec![Span::raw(" ".repeat(indent))]))); }
        if v.len() > 1 { v.push(Span::raw("   ")); }
        v.push(Span::styled(format!("{k} "), pal.muted()));
        v.push(Span::styled(val.clone(), pal.ink()));
    }
    out.push(Line::from(v));
    out
}

/// A label, then a value that wraps under itself.
fn kv_wrap(pal: &Palette, w: usize, label: &str, value: &str, style: Style) -> Vec<Line<'static>> {
    let mut ls = hanging(value, 14, w, style);
    if let Some(first) = ls.first_mut() { let text: String = first.spans[0].content.chars().skip(14).collect(); *first = kv(pal, 0, 14, label, vec![Span::styled(text, style)]); }
    ls
}

/// Generation and time side by side, then the total, as three aligned rows.
fn cost_rows(pal: &Palette, indent: usize, generation: Option<f64>, time: Option<f64>, rate: Option<f64>) -> Vec<Line<'static>> {
    let total = match (generation, time) { (None, None) => None, (g, t) => Some(g.unwrap_or(0.0) + t.unwrap_or(0.0)) };
    vec![
        kv(pal, indent, 12, "Generation", vec![Span::styled(right(&money(generation), 9), pal.ink())]),
        kv(pal, indent, 12, "Time", vec![Span::styled(right(&money(time), 9), pal.ink()), Span::styled(format!("  {}", at_rate(rate)), pal.muted())]),
        kv(pal, indent, 12, "Total", vec![Span::styled(right(&money(total), 9), pal.muted())]),
    ]
}

// ── rows per tab ────────────────────────────────────────

/// Who started a bon process: you, through the agent, or bon on spare capacity.
fn who(g: &GoalTrace) -> &'static str {
    if g.processes.iter().flat_map(|p| &p.searches).any(|s| s.background) { "bon" } else { "You" }
}

/// The main search of a bon process: its first that is not a counterexample.
fn main_search(p: &BonProcess) -> Option<&SearchTrace> { p.searches.iter().find(|s| !clears(&s.kind)) }

/// A search that clears or blocks another's push, rather than writing what is pushed.
fn clears(kind: &str) -> bool { kind == "counterexample" || kind == "foil" }

/// A foil search's foils, by index: programs trunk's tests accept and Verus
/// rejects (the spec's `foil`).
fn foil_indices(f: &SearchTrace) -> Vec<u64> {
    f.candidates.iter().filter(|c| c.accepted && !c.proved).map(|c| c.index).collect()
}

/// The verified tests of a counterexample search that reject a foil (the
/// spec's `discriminates`), each with the foils it rejects.
fn telling(ce: &SearchTrace, f: &SearchTrace) -> Vec<(u64, Vec<i64>)> {
    let foils = foil_indices(f);
    ce.candidates.iter().filter(|c| c.verified).filter_map(|c| {
        let rejected: Vec<i64> = c.accepts_foils.iter().filter(|(j, a)| !a && foils.contains(&(*j as u64))).map(|(j, _)| *j).collect();
        (!rejected.is_empty()).then_some((c.index, rejected))
    }).collect()
}

/// A recorded reason: its word and sentence, from `blocked: word: sentence`.
/// A trace from before reasons were words has only a sentence.
fn reason(blocked: &str) -> (Option<&str>, &str) {
    let rest = blocked.trim_start_matches("blocked: ");
    match rest.split_once(": ") {
        Some((w, s)) if w.chars().all(|c| c.is_ascii_lowercase() || c == '_') => (Some(w), s),
        _ => (None, rest),
    }
}

/// A goal's steps: width → verified → selected → foils → counterexample.
/// Tight, for a list row, with the commit pushed: `8→8→#2 · 2 foils · none found · 0b1e1a5`.
fn steps(g: &GoalTrace, tight: bool) -> String {
    let Some(last) = g.processes.first() else { return String::new() };
    // A counterexample on trunk: how many of its tests were verified.
    if g.kind == "counterexample" {
        let v = last.searches.iter().map(|s| s.verified).sum::<u64>();
        return plural(v as usize, "verified test", "verified tests");
    }
    let mut head = Vec::new();
    if let Some(m) = main_search(last) {
        head.push(format!("{}", m.width.max(m.returned)));
        head.push(format!("{}", m.verified));
        if let Some(i) = m.selected { head.push(format!("#{i}")); }
    }
    let mut rest = Vec::new();
    let foils = last.searches.iter().rev().find(|s| s.kind == "foil");
    if let Some(f) = foils { rest.push(plural(foil_indices(f).len(), "foil", "foils")); }
    if let Some(ce) = last.searches.iter().rev().find(|s| s.kind == "counterexample") {
        let telling = foils.map(|f| telling(ce, f).len());
        rest.push(match (g.outcome.as_str(), telling) {
            ("found", _) => "found".into(),
            ("pushed", _) => "none found".into(),
            _ if ce.verified < 2 => format!("{} of 2 tests", ce.verified),
            (_, Some(d)) if d < 2 => format!("{d} of 2 tests reject a foil"),
            _ => "none found".into(),
        });
    }
    if let Some(c) = g.push.as_ref().and_then(|p| p.commit.as_deref()).filter(|_| tight) { rest.push(short(c)); }
    if tight { std::iter::once(head.join("→")).chain(rest).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" · ") }
    else { head.into_iter().chain(rest).collect::<Vec<_>>().join(" → ") }
}

/// What a goal cost: to its push when it pushed, else its own bon processes.
fn goal_cost(g: &GoalTrace) -> (Option<f64>, Option<f64>) {
    match &g.push {
        Some(p) if p.generation.is_some() || p.time_cost.is_some() => (p.generation, p.time_cost),
        // Time is charged when a search reports: a running one has none yet, not $0.00.
        _ => (Some(g.generation), (!g.running || g.time_cost != 0.0).then_some(g.time_cost)),
    }
}

/// The two cost columns of a list: generation, then time.
const GEN_W: usize = 9;
const TIME_W: usize = 10;
fn cost_cells(pal: &Palette, generation: Option<f64>, time: Option<f64>) -> Vec<Span<'static>> {
    vec![Span::styled(right(&money(generation), GEN_W), pal.ink()), Span::styled(right(&money(time), TIME_W), pal.ink())]
}
fn cost_heads(pal: &Palette) -> Vec<Span<'static>> {
    vec![Span::styled(right("Gen", GEN_W), pal.muted()), Span::styled(right("Time", TIME_W), pal.muted())]
}

/// The outcomes table, at the head of Traces: columns that do not fit drop from the right.
fn outcome_rows(pal: &Palette, t: &projection::Totals, w: usize) -> Vec<Row> {
    let rows = view::outcome_table(t);
    if rows.is_empty() { return Vec::new(); }
    let head = view::OUTCOME_COLUMNS;
    let cw: Vec<usize> = (0..7).map(|i| rows.iter().map(|r| r[i].chars().count()).chain([head[i].chars().count()]).max().unwrap_or(0)).collect();
    let mut n = 7;
    while n > 2 && 1 + cw[0] + (1..n).map(|i| cw[i] + 2).sum::<usize>() > w { n -= 1; }
    let line = |cells: &[String], first: Style, rest: Style| {
        let mut v = vec![Span::styled(format!(" {}", fit(&cells[0], cw[0])), first)];
        for i in 1..n { v.push(Span::styled(format!("  {}", right(&cells[i], cw[i])), rest)); }
        Row::text(Line::from(v))
    };
    let mut out = vec![line(&head.map(String::from), pal.strong(), pal.muted())];
    for r in &rows { out.push(line(r, if r[0].starts_with(' ') { pal.muted() } else { pal.ink() }, pal.ink())); }
    if !t.reasons.is_empty() {
        let reasons = t.reasons.iter().map(|r| format!("{} {}", r.reason, r.count)).collect::<Vec<_>>().join(" · ");
        out.push(Row::text(Line::from(vec![Span::styled(format!(" {}", fit("Blocked by", cw[0])), pal.muted()), Span::styled(format!("  {}", fit(&reasons, w.saturating_sub(cw[0] + 3))), pal.ink())])));
    }
    out
}

fn rows(app: &App, width: u16) -> Vec<Row> {
    let pal = &app.palette;
    let p = &app.p;
    let w = width as usize;
    let mut out = Vec::new();
    let blank = || Row::text(Line::default());
    let header = |t: &str, n: Option<usize>| Row::text(section(pal, 1, t, n));
    match app.tab {
        Tab::Traces => {
            // How attempts and bon processes ended, measured, above the goals themselves.
            out.extend(outcome_rows(pal, &p.totals, w));
            let today = day(p.repo.now, app.off);
            let mut last_day = None;
            // Three forms by width: 96+ everything; 76+ without who; under 76
            // (beside the detail, or a phone) no steps, which the detail shows.
            let (who_col, with_steps) = (w >= 96, w >= 76);
            let fixed = 1 + 7 + if who_col { 5 } else { 0 } + 2 + 11 + GEN_W + TIME_W;
            let what_w = if with_steps { 20 } else { w.saturating_sub(fixed).clamp(8, 22) };
            let rest = w.saturating_sub(fixed + what_w);
            for (gi, g) in sorted_groups(p).into_iter().enumerate() {
                let d = if g.running { today } else { day(g.time, app.off) };
                if last_day != Some(d) {
                    if !out.is_empty() { out.push(blank()); }
                    // The first day carries the cost columns' labels.
                    let title = vec![Span::styled(format!(" {}", day_label(d, today)), pal.strong())];
                    out.push(Row::text(if last_day.is_none() { spread(title, cost_heads(pal), w) } else { Line::from(title) }));
                    last_day = Some(d);
                }
                // A row where the kernel disagrees with the trace needs attention: red.
                let differs = g.processes.iter().flat_map(|b| &b.searches).any(|s| disagreement(s).is_some());
                let tone = pal.tone(if differs { Tone::Red } else { outcome_tone(&g.outcome) });
                // The kind and the commit it started from; the title is in the detail.
                let commit = g.title.split_whitespace().last().unwrap_or("");
                let what = format!("{} {}", if g.kind == "counterexample" { "Trunk".into() } else { cap(&g.kind) }, commit);
                let mut spans = vec![Span::raw(" "), Span::styled(format!("{}  ", clock(g.time, app.off)), pal.muted())];
                if who_col { spans.push(Span::styled(fit(who(g), 5), pal.muted())); }
                spans.extend([
                    Span::styled("● ", tone),
                    Span::styled(fit(&outcome_label(&g.outcome), 11), tone),
                    Span::styled(fit(&what, what_w), pal.ink()),
                ]);
                spans.push(if with_steps { Span::styled(fit(&steps(g, true), rest), pal.muted()) } else { Span::raw(" ".repeat(rest)) });
                let (gen, time) = goal_cost(g);
                spans.extend(cost_cells(pal, gen, time));
                out.push(Row { line: Line::from(spans), key: Some(Key::Goal(gi)) });
            }
            if p.groups.is_empty() { out.push(Row::text(Line::from(Span::styled(" No bon process yet", pal.muted())))); }
        }
        Tab::Queue => {
            if !p.proposals.is_empty() {
                out.push(header("Proposed", Some(p.proposals.len())));
                for (pi, pr) in p.proposals.iter().enumerate() {
                    let counts = vec![Span::styled("New ", pal.muted()), Span::styled(format!("{:<3}", pr.intents.len()), pal.ink()),
                        Span::styled("Contested ", pal.muted()), Span::styled(format!("{:<2}", pr.contested.len()), pal.ink())];
                    let room = w.saturating_sub(5 + width_of(&counts) + 1);
                    out.push(Row { line: spread(vec![Span::styled("  ● ", pal.tone(Tone::Yellow)), Span::styled(fit(&pr.source, room), pal.ink())], counts, w), key: Some(Key::Proposal(pi)) });
                }
                out.push(blank());
                out.push(header("Queued", Some(p.queue.as_ref().map_or(0, |q| q.len()))));
            }
            for (qi, q) in p.queue.iter().flatten().enumerate() {
                out.push(Row { line: Line::from(vec![Span::styled(format!(" {:>3}  ", q.id), pal.muted()), Span::styled(fit(&q.intent, w.saturating_sub(7)), pal.ink())]), key: Some(Key::Queue(qi)) });
            }
            if p.queue.as_ref().is_none_or(|q| q.is_empty()) { out.push(Row::text(Line::from(Span::styled(" Nothing queued", pal.muted())))); }
        }
        Tab::Spec => {
            let Some(spec) = &p.spec else { out.push(Row::text(Line::from(Span::styled(" No spec found", pal.muted())))); return out };
            let g = p.system.clone().unwrap_or_default();
            // Names as wide as the longest, but never more than a third of the width (a phone).
            let nw = (spec.items.iter().map(|i| i.name.chars().count()).chain(spec.fields.iter().map(|f| f.name.chars().count())).max().unwrap_or(10).min(24) + 2).min((w / 3).max(10));
            let item = |i: usize, rest: Vec<Span<'static>>| { let mut v = vec![Span::styled(format!("   {}", fit(&spec.items[i].name, nw)), pal.ink())]; v.extend(rest); Row { line: Line::from(v), key: Some(Key::Item(i)) } };
            let room = w.saturating_sub(nw + 4);
            let doc_of = |i: usize| Span::styled(fit(&spec.items[i].doc.clone().unwrap_or_default(), room), pal.muted());
            let of = |kind: &str| spec.items.iter().enumerate().filter(|(_, x)| x.kind == kind).map(|(i, _)| i).collect::<Vec<_>>();
            // Where the spec is, and how much of it differs from trunk.
            let differ = g.nodes.iter().filter(|n| n.changed).count();
            let mut file = vec![(" File", spec.path.clone())];
            if differ > 0 { file.push(("Differs from trunk", differ.to_string())); }
            out.extend(pairs(pal, 0, &file, w).into_iter().map(Row::text));
            out.push(blank());

            out.push(header("Vocabulary", Some(of("type").len())));
            for i in of("type") { out.push(item(i, vec![doc_of(i)])); }

            out.push(blank());
            let ts: Vec<usize> = of("init").into_iter().chain(of("transition")).collect();
            out.push(header("State Machine", Some(ts.len())));
            if !spec.fields.is_empty() {
                let names = spec.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(" · ");
                out.push(Row { line: Line::from(vec![Span::styled(format!("   {}", fit("Fields", nw)), pal.ink()), Span::styled(fit(&names, room), pal.muted())]), key: Some(Key::Grid) });
            }
            for i in ts { out.push(item(i, vec![doc_of(i)])); }

            // For a predicate a gate decides, which layers reach it: gate · implementation · target · program.
            let layers = |name: &str| -> Option<[Option<String>; 4]> {
                let gate = format!("gate:{name}");
                if !g.edges.iter().any(|e| e.0 == gate && e.1 == format!("spec:{name}")) { return None; }
                let kernel = format!("kernel:{name}");
                let imp = g.edges.iter().any(|e| e.0 == kernel && e.1 == gate);
                let target = g.edges.iter().find(|e| e.1 == kernel && e.0.starts_with("target:")).and_then(|e| g.nodes.iter().find(|n| n.id == e.0)).map(|n| n.group.clone());
                let program = g.edges.iter().find(|e| e.0.starts_with("program:") && g.edges.iter().any(|t| t.0 == e.1 && t.1 == kernel && e.1.starts_with("target:"))).and_then(|e| g.nodes.iter().find(|n| n.id == e.0))
                    .map(|n| std::path::Path::new(&n.file).file_name().map_or(n.file.clone(), |f| f.to_string_lossy().to_string()));
                Some([Some("●".into()), imp.then(|| "●".into()), target, program])
            };
            let mut decided: Vec<usize> = of("predicate").into_iter().filter(|i| layers(&spec.items[*i].name).is_some()).collect();
            decided.sort_by_key(|i| spec.items[*i].name.clone());
            let cws = [6usize, 6, 8, 10];
            let full = w >= nw + 4 + cws.iter().sum::<usize>();
            if !decided.is_empty() {
                out.push(blank());
                let mut h = vec![Span::styled(format!(" {}", fit("Spec → Code", nw + 2)), pal.strong())];
                if full { for (l, cw) in ["Gate", "Impl", "Target", "Program"].iter().zip(cws) { h.push(Span::styled(fit(l, cw), pal.muted())); } }
                out.push(Row::text(Line::from(h)));
            }
            for i in &decided {
                let ls = layers(&spec.items[*i].name).unwrap();
                let row = if full {
                    ls.iter().zip(cws).map(|(c, cw)| match c { Some(x) => Span::styled(fit(x, cw), pal.ink()), None => Span::styled(fit("·", cw), pal.faint()) }).collect()
                } else { vec![Span::styled(ls.iter().map(|c| if c.is_some() { '●' } else { '·' }).collect::<String>(), pal.ink())] };
                out.push(item(*i, row));
            }
            let rest: Vec<usize> = of("predicate").into_iter().filter(|i| !decided.contains(i)).collect();
            if !rest.is_empty() {
                out.push(blank());
                out.push(header("Predicates", Some(rest.len())));
                for i in rest { out.push(item(i, vec![doc_of(i)])); }
            }

            let rules: Vec<usize> = of("invariant").into_iter().chain(of("property")).collect();
            if !rules.is_empty() {
                out.push(blank());
                out.push(header("Invariants and Properties", Some(rules.len())));
                for i in rules { out.push(item(i, vec![doc_of(i)])); }
            }

            out.push(blank());
            out.push(header("Trusted", Some(g.trusted.len())));
            for (ti, t) in g.trusted.iter().enumerate() {
                out.push(Row { line: Line::from(vec![Span::styled(format!("   {}", fit(&t.name, nw)), pal.ink()), Span::styled(fit(&t.doc.clone().unwrap_or_default(), room), pal.muted())]), key: Some(Key::Trusted(ti)) });
            }
            if let Some(sb) = &p.sbom {
                let comps = &sb.document.components;
                let tools: Vec<String> = comps.iter().filter(|c| c.group.as_deref() == Some("tcb")).map(|c| c.name.clone()).collect();
                let crates = comps.iter().filter(|c| c.r#type == "library").count();
                let services: Vec<String> = sb.document.services.iter().map(|s| s.name.clone()).collect();
                for (k, label, v) in [("tools", "Tools", tools.join(" · ")), ("services", "Services", services.join(" · ")), ("crates", "Crates", format!("{crates}"))] {
                    out.push(Row { line: Line::from(vec![Span::styled(format!("   {}", fit(label, nw)), pal.ink()), Span::styled(fit(&v, room), pal.muted())]), key: Some(Key::Sbom(k)) });
                }
            }
        }
        Tab::Project => {
            let t = &p.totals;
            let lw = 16;
            let num = |s: String| Span::styled(right(&s, 9), pal.ink());
            let line = |label: &str, value: Vec<Span<'static>>| Row::text(kv(pal, 3, lw, label, value));
            out.push(header("Cost", None));
            for l in cost_rows(pal, 3, Some(t.generation), Some(t.time_cost), t.rate) {
                // Project's labels are as wide as its others.
                let mut s = l.spans; s[0] = Span::styled(format!("   {}", fit(s[0].content.trim(), lw)), pal.muted()); out.push(Row::text(Line::from(s)));
            }
            out.push(line("Per verified", vec![num(money(t.per_verified_candidate))]));
            out.push(line("Per push", vec![num(money(t.per_push))]));

            // Where it went: what reached a push, what did not, what is running; each split
            // into generation (█) and time (▒) by its share of the total.
            let pushed = p.groups.iter().filter(|g| g.outcome == "pushed");
            let sum = |gs: &mut dyn Iterator<Item = (Option<f64>, Option<f64>)>| gs.fold((0.0, 0.0), |(a, b), (g, t)| (a + g.unwrap_or(0.0), b + t.unwrap_or(0.0)));
            let parts = [
                ("Reached a push", Tone::Violet, sum(&mut pushed.map(goal_cost))),
                ("Did not", Tone::Red, sum(&mut p.groups.iter().filter(|g| g.outcome != "pushed" && !g.running).map(|g| (Some(g.generation), Some(g.time_cost))))),
                ("In flight", Tone::Orange, sum(&mut p.groups.iter().filter(|g| g.running).map(goal_cost))),
            ];
            let whole: f64 = parts.iter().map(|(_, _, (g, t))| g + t).sum::<f64>().max(1e-9);
            let bw = w.saturating_sub(3 + lw + GEN_W + TIME_W + 2 + 5).min(30);
            out.push(blank());
            let mut h = vec![Span::styled(format!(" {}", fit("Where It Went", lw + 2)), pal.strong())];
            h.extend(cost_heads(pal));
            if bw >= 10 { h.extend([Span::raw("  "), Span::styled("█ ", pal.muted()), Span::styled("Gen  ", pal.muted()), Span::styled("▒ ", pal.muted()), Span::styled("Time", pal.muted())]); }
            out.push(Row::text(Line::from(h)));
            for (label, tone, (g, tm)) in parts {
                if label == "In flight" && g + tm == 0.0 { continue; }
                let (ng, nt) = ((g / whole * bw as f64).round() as usize, ((g + tm) / whole * bw as f64).round() as usize);
                let mut v = cost_cells(pal, Some(g), Some(tm));
                v.push(Span::raw("  "));
                v.push(Span::styled("█".repeat(ng), pal.tone(tone)));
                v.push(Span::styled("▒".repeat(nt.saturating_sub(ng)), pal.tone(tone)));
                v.push(Span::raw(" ".repeat(bw.saturating_sub(nt.max(ng)))));
                v.push(Span::styled(right(&format!("{:.0}%", (g + tm) / whole * 100.0), 5), pal.muted()));
                out.push(line(label, v));
            }

            out.push(blank());
            out.push(header("Results", None));
            let cands: Vec<&Facts> = p.processes.iter().flat_map(|b| &b.searches).flat_map(|s| &s.candidates).collect();
            let (v, a, r) = (cands.iter().filter(|c| c.verified).count(), cands.iter().filter(|c| c.accepted && !c.verified).count(), cands.iter().filter(|c| !c.accepted).count());
            out.push(line("Candidates", vec![num(cands.len().to_string())]));
            out.push(line("Verified", vec![num(v.to_string())]));
            out.push(line("Not verified", vec![num(a.to_string())]));
            out.push(line("Rejected", vec![num(r.to_string())]));
            let mut kinds: Vec<(String, usize)> = Vec::new();
            for g in p.groups.iter().filter(|g| g.outcome == "pushed") { match kinds.iter_mut().find(|(k, _)| *k == g.kind) { Some(e) => e.1 += 1, None => kinds.push((g.kind.clone(), 1)) } }
            out.push(line("Pushes", vec![num(t.pushes.to_string()), Span::styled(format!("   {}", kinds.iter().map(|(k, n)| format!("{} {n}", cap(k))).collect::<Vec<_>>().join(" · ")), pal.muted())]));
            // Spec strength, measured by search: searches whose verified candidates all printed the same.
            let measured: Vec<usize> = p.processes.iter().flat_map(|b| &b.searches).filter(|s| !clears(&s.kind) && s.verified >= 2).map(|s| groups(s).len()).collect();
            if !measured.is_empty() {
                let pinned = measured.iter().filter(|n| **n == 1).count();
                out.push(line("One output", vec![num(pinned.to_string()), Span::styled(format!("   of {} searches", measured.len()), pal.muted())]));
            }

            out.push(blank());
            out.push(header("Trunk", None));
            let repo = &p.repo;
            let room = w.saturating_sub(3 + lw + 9);
            out.push(line("Head", vec![Span::styled(fit(&short(repo.remote_head.as_deref().or(repo.head.as_deref()).unwrap_or("")), 9), pal.ink()), Span::styled(fit(&repo.subject.clone().unwrap_or_default(), room), pal.muted())]));
            if let Some(lp) = &repo.last_push { out.push(line("Last push", vec![Span::styled(fit(&short(lp.commit.as_deref().unwrap_or("")), 9), pal.ink()), Span::styled(lp.time.map_or(String::new(), |t| ago(repo.now, t)), pal.muted())])); }
            if let Some(sp) = &repo.since_push { out.push(line("Since push", vec![num(sp.commits.to_string()), Span::styled(format!("   {}{}", if sp.commits == 1 { "commit" } else { "commits" }, if sp.authors.is_empty() { String::new() } else { format!(" by {}", sp.authors.join(", ")) }), pal.muted())])); }
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
            Span::styled(format!("{} ", fit(&cap(&e.2), 11)), pal.muted()),
            Span::styled(format!("{name}  "), pal.ink()),
            Span::styled(at, pal.faint()),
        ]));
        chain(g, other, up, depth - 1, indent + 2, seen, pal, out);
    }
}

/// A test's verdicts, by member (trunk is -1) or foil: `#0 ✓`.
fn verdicts(on: &[(i64, bool)]) -> Vec<String> {
    on.iter().map(|(j, a)| format!("{} {}", if *j < 0 { "trunk".into() } else { format!("#{j}") }, if *a { "✓" } else { "✗" })).collect()
}

/// Items two spaces apart, wrapped between items at `w`.
fn wrap_items(items: &[String], w: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for it in items {
        match out.last_mut() {
            Some(l) if l.chars().count() + 2 + it.chars().count() <= w => { l.push_str("  "); l.push_str(it); }
            _ => out.push(it.clone()),
        }
    }
    out
}

fn detail(app: &App, width: u16) -> Text<'static> {
    let pal = app.palette;
    let wd = width as usize;
    let mut t: Vec<Line<'static>> = Vec::new();
    let blank = Line::default;
    let title = |s: String| Line::from(Span::styled(s, pal.strong()));
    let sec = |t: &mut Vec<Line<'static>>, s: &str| { t.push(Line::default()); t.push(section(&pal, 0, s, None)); };
    let kv = |k: &str, v: Vec<Span<'static>>| kv(&pal, 0, 14, k, v);
    match app.tab {
        Tab::Traces => {
            let Some(Key::Goal(gi)) = focused(app) else { return Text::default() };
            let Some(g) = sorted_groups(&app.p).get(gi).copied() else { return Text::default() };
            let tone = pal.tone(outcome_tone(&g.outcome));
            t.push(spread(vec![Span::styled(format!("{} {}", cap(&g.kind), g.title), pal.strong())], vec![Span::styled(format!("● {}", outcome_label(&g.outcome)), tone)], wd));
            if !g.about.subject.is_empty() { t.push(Line::from(Span::styled(fit(&g.about.subject, wd), pal.muted()))); }
            t.push(blank());
            t.extend(kv_wrap(&pal, wd, "Steps", &steps(g, false), pal.ink()));
            if let Some(c) = g.push.as_ref().and_then(|p| p.commit.as_deref()) { t.push(kv("Pushed", vec![Span::styled(short(c), pal.ink())])); }
            sec(&mut t, if g.push.is_some() { "Cost to Push" } else { "Cost" });
            let (gen, time) = goal_cost(g);
            t.extend(cost_rows(&pal, 0, gen, time, app.p.totals.rate));
            // Each bon process: its searches as a table, each search's candidates under it.
            // Narrow, Took gives way so the steps fit.
            let (kw, tw) = (17usize, if wd >= 60 { 5usize } else { 0 });
            let sw = wd.saturating_sub(2 + kw + tw + GEN_W + TIME_W).max(6);
            for b in &g.processes {
                t.push(blank());
                t.push(spread(vec![Span::styled(format!("Process {}", b.pid), pal.strong())], vec![Span::styled(format!("{} · {}", outcome_label(&b.outcome), ago(app.p.repo.now, b.time)), pal.muted())], wd));
                let mut h = vec![Span::styled(format!("  {}{}{}", fit("Search", kw), fit("Steps", sw), if tw == 0 { String::new() } else { right("Took", tw) }), pal.muted())];
                h.extend(cost_heads(&pal));
                t.push(Line::from(h));
                for (k, s) in b.searches.iter().enumerate() {
                    if k > 0 && !b.searches[k - 1].candidates.is_empty() { t.push(blank()); }
                    let stone = if s.running { Tone::Orange } else if s.blocked.is_some() { Tone::Yellow } else if clears(&s.kind) { Tone::Indigo } else if s.selected.is_some() { Tone::Blue } else { Tone::Yellow };
                    let how = match s.kind.as_str() {
                        "foil" => format!("{} → {}", s.width.max(s.returned), plural(foil_indices(s).len(), "foil", "foils")),
                        "counterexample" => format!("{} → {}", s.width.max(s.returned), s.verified),
                        _ => format!("{} → {}{}", s.width.max(s.returned), s.verified, s.selected.map_or(String::new(), |i| format!(" → #{i}"))),
                    };
                    let mut row = vec![
                        Span::styled("● ", pal.tone(stone)),
                        Span::styled(fit(&format!("{} {}", s.search, cap(&s.kind)), kw), pal.ink()),
                        Span::styled(fit(&how, sw), pal.ink()),
                        Span::styled(if tw == 0 { String::new() } else { right(&s.seconds.map_or(String::new(), took), tw) }, pal.muted()),
                    ];
                    row.extend(cost_cells(&pal, s.generation, s.time_cost));
                    t.push(Line::from(row));
                    let mut facts: Vec<(&str, String)> = Vec::new();
                    if !s.params.base.is_empty() { facts.push(("Base", short(&s.params.base))); }
                    if let Some(l) = s.params.limit { facts.push(("Limit", money(Some(l)))); }
                    match s.kernel.as_str() { "derived" => facts.push(("Kernel", "Checked".into())), "unreadable" => facts.push(("Kernel", "Unreadable".into())), _ => {} }
                    // Spec strength, measured: how many distinct agree outputs the verified candidates had.
                    if !clears(&s.kind) && s.verified > 0 { facts.push(("Outputs", groups(s).len().to_string())); }
                    if !facts.is_empty() { t.extend(pairs(&pal, 2, &facts, wd)); }
                    if let Some(d) = disagreement(s) { t.extend(hanging(&d, 2, wd, pal.tone(Tone::Red))); }
                    if s.blocked.is_some() { for l in why_blocked_in(s, &app.p.protected) { t.extend(hanging(&l, 2, wd, pal.tone(Tone::Yellow))); } }
                    if s.candidates.is_empty() { continue; }
                    let foil = s.kind == "foil";
                    t.push(Line::from(Span::styled(format!("  {}{}{}{}{}{}", fit("#", 4), fit("Commit", 9), fit(if foil { "Foil?" } else { "Verified" }, 11), right("Rank", 4), right("Lines", 11), right("Gen", 8)), pal.muted())));
                    let mut cs: Vec<&Facts> = s.candidates.iter().collect();
                    cs.sort_by_key(|c| (!c.verified, -(c.rank.unwrap_or(0)), c.diff.unwrap_or(0)));
                    for c in cs {
                        let sel = s.selected == Some(c.index);
                        // A foil is meant to fail Verus: accepted and not proved is what it is for.
                        let (v, vs) = if foil {
                            if c.accepted && !c.proved { ("Foil", pal.ink()) } else if c.accepted { ("Not a foil", pal.muted()) } else { ("Rejected", pal.faint()) }
                        } else if c.verified { ("Yes", pal.ink()) } else if c.accepted { ("No", pal.muted()) } else { ("Rejected", pal.faint()) };
                        let lines = match (c.added, c.removed) { (Some(a), Some(r)) => format!("+{a} −{r}"), _ => c.diff.map_or("—".into(), |d| d.to_string()) };
                        t.push(Line::from(vec![
                            Span::styled(format!("  {}", fit(&format!("{}{}", c.index, if sel { "★" } else { "" }), 4)), if sel { pal.tone(Tone::Blue) } else { pal.muted() }),
                            Span::styled(fit(&short(c.commit.as_deref().unwrap_or("")), 9), pal.ink()),
                            Span::styled(fit(v, 11), vs),
                            Span::styled(right(&c.rank.map_or("—".into(), |r| r.to_string()), 4), pal.ink()),
                            Span::styled(right(&lines, 11), pal.ink()),
                            Span::styled(right(&money(c.generation), 8), pal.ink()),
                            Span::styled(if c.flags.is_empty() { String::new() } else { format!("  {}", c.flags.iter().map(|f| cap(&f.replace('_', " "))).collect::<Vec<_>>().join(" · ")) }, pal.tone(Tone::Red)),
                        ]));
                        // A test: its verdict on each member and trunk, then on each foil.
                        if s.kind == "counterexample" {
                            // Each verdict list wraps under itself, between verdicts.
                            let labeled = |t: &mut Vec<Line<'static>>, k: &str, items: Vec<String>| {
                                for (n, l) in wrap_items(&items, wd.saturating_sub(15)).into_iter().enumerate() {
                                    t.push(Line::from(vec![Span::styled(format!("      {}", fit(if n == 0 { k } else { "" }, 9)), pal.muted()), Span::styled(l, pal.ink())]));
                                }
                            };
                            if !c.accepts.is_empty() { labeled(&mut t, "Members", verdicts(&c.accepts)); }
                            if !c.accepts_foils.is_empty() {
                                labeled(&mut t, "Foils", verdicts(&c.accepts_foils));
                                // Accepting every foil too means it tells nothing apart; without foils, it cannot be said.
                                if c.accepts_foils.iter().all(|(_, a)| *a) { t.push(Line::from(vec![Span::raw(" ".repeat(15)), Span::styled("Accepts every foil", pal.tone(Tone::Yellow))])); }
                            }
                        }
                    }
                }
            }
        }
        Tab::Queue => {
            match focused(app) {
                Some(Key::Queue(qi)) => {
                    let Some(q) = app.p.queue.as_ref().and_then(|q| q.get(qi)) else { return Text::default() };
                    t.push(title(format!("Queue {}", q.id)));
                    t.push(blank());
                    t.extend(hanging(&q.intent, 0, wd, pal.ink()));
                }
                Some(Key::Proposal(pi)) => {
                    let Some(pr) = app.p.proposals.get(pi) else { return Text::default() };
                    t.push(spread(vec![Span::styled("Proposal", pal.strong())], vec![Span::styled("● Waiting", pal.tone(Tone::Yellow))], wd));
                    t.push(blank());
                    t.push(kv("Source", vec![Span::styled(pr.source.clone(), pal.ink())]));
                    t.push(kv("Patch", vec![Span::styled(pr.path.clone(), pal.ink())]));
                    t.push(kv("Accept", vec![Span::styled(format!("git am {}", pr.path), pal.ink())]));
                    sec(&mut t, "Intents");
                    for i in &pr.intents {
                        let id = i.id.map_or("—".into(), |n| n.to_string());
                        let mut ls = hanging(&i.intent, 6, wd, pal.ink());
                        if let Some(first) = ls.first_mut() { let text: String = first.spans[0].content.chars().skip(6).collect(); *first = Line::from(vec![Span::styled(format!("{:>4}  ", id), pal.muted()), Span::styled(text, pal.ink())]); }
                        t.extend(ls);
                        if let Some(c) = &i.cue { t.push(Line::from(vec![Span::styled("      Cue ", pal.muted()), Span::styled(c.clone(), pal.faint())])); }
                    }
                    if !pr.contested.is_empty() {
                        sec(&mut t, "Contested");
                        for c in &pr.contested { t.push(Line::from(Span::styled(format!("      {c}"), pal.ink()))); }
                    }
                }
                _ => {}
            }
        }
        Tab::Spec => {
            let Some(spec) = &app.p.spec else { return Text::default() };
            let g = app.p.system.clone().unwrap_or_default();
            let node = |id: &str| g.nodes.iter().find(|n| n.id == id).cloned();
            let at = |n: &projection::SpecNode| format!("{}:{}", n.file, n.line.unwrap_or(0));
            // A location, and whether it differs from trunk.
            let place = |n: &projection::SpecNode| { let mut v = vec![Span::styled(at(n), pal.faint())]; if n.changed { v.push(Span::styled("   Differs from trunk", pal.tone(Tone::Yellow))); } v };
            let clauses = |t: &mut Vec<Line<'static>>, label: &str, list: &[String]| {
                for (k, r) in list.iter().enumerate() {
                    let mut ls = hanging(r, 14, wd, pal.ink());
                    if k == 0 { if let Some(first) = ls.first_mut() { let text: String = first.spans[0].content.chars().skip(14).collect(); *first = kv(label, vec![Span::styled(text, pal.ink())]); } }
                    t.extend(ls);
                }
            };
            let list = |t: &mut Vec<Line<'static>>, k: &str, v: &[String]| { if !v.is_empty() { clauses(t, k, &[v.join(" · ")]); } };
            let graph = |t: &mut Vec<Line<'static>>, id: &str| {
                let mut up = Vec::new(); chain(&g, id, true, 4, 0, &mut vec![id.to_string()], pal, &mut up);
                if !up.is_empty() { t.push(Line::default()); t.push(section(&pal, 0, "Reached From", None)); t.extend(up); }
                let mut down = Vec::new(); chain(&g, id, false, 3, 0, &mut vec![id.to_string()], pal, &mut down);
                if !down.is_empty() { t.push(Line::default()); t.push(section(&pal, 0, "Reaches", None)); t.extend(down); }
            };
            match focused(app) {
                Some(Key::Item(i)) => {
                    let it = &spec.items[i];
                    t.push(spread(vec![Span::styled(it.name.clone(), pal.strong())], vec![Span::styled(cap(&it.kind), pal.muted())], wd));
                    if let Some(d) = &it.doc { t.extend(hanging(d, 0, wd, pal.ink())); }
                    t.push(blank());
                    let sid = format!("spec:{}", it.name);
                    if let Some(n) = node(&sid) { t.push(kv("Defined", place(&n))); }
                    clauses(&mut t, "Requires", &it.requires);
                    list(&mut t, "Reads", &it.reads);
                    list(&mut t, "Writes", &it.updates);
                    if let Some(n) = node(&sid) { list(&mut t, "Adds", &n.adds); list(&mut t, "Removes", &n.removes); }
                    // Where it is a guard.
                    let guards: Vec<String> = g.nodes.iter().filter(|n| n.guards.contains(&it.name)).map(|n| n.name.clone()).collect();
                    list(&mut t, "Guards", &guards);
                    // The emitted type of the same name.
                    if let Some(ty) = node(&format!("type:{}", it.name)) { t.push(kv("Emitted", vec![Span::styled(at(&ty), pal.faint())])); }
                    // A predicate a gate decides: the gate's contract, as written, and its implementation.
                    if let Some(gate) = node(&format!("gate:{}", it.name)) {
                        sec(&mut t, "Gate");
                        t.push(kv("Name", vec![Span::styled(gate.name.clone(), pal.ink())]));
                        t.push(kv("Trait", vec![Span::styled(gate.group.clone(), pal.ink())]));
                        t.push(kv("Defined", place(&gate)));
                        clauses(&mut t, "Requires", &gate.requires);
                        clauses(&mut t, "Ensures", &gate.ensures);
                        if let Some(k) = node(&format!("kernel:{}", it.name)) {
                            sec(&mut t, "Implementation");
                            t.push(kv("Name", vec![Span::styled(k.name.clone(), pal.ink())]));
                            t.push(kv("Defined", place(&k)));
                            list(&mut t, "Uses", &k.uses);
                        }
                    }
                    graph(&mut t, &sid);
                }
                Some(Key::Grid) => {
                    t.push(spread(vec![Span::styled("State Machine", pal.strong())], vec![Span::styled(plural(spec.fields.len(), "field", "fields"), pal.muted())], wd));
                    // The marks, as the key bar shows keys.
                    let mut legend = Vec::new();
                    for (m, w) in [("r", "Reads"), ("w", "Writes"), ("+", "Adds"), ("−", "Removes")] { legend.push(Span::styled(format!("{m} "), pal.ink())); legend.push(Span::styled(format!("{w}   "), pal.muted())); }
                    t.push(Line::from(legend));
                    t.push(blank());
                    let ts: Vec<&projection::SpecItem> = spec.items.iter().filter(|x| x.kind == "transition" || x.kind == "init").collect();
                    let nw = ts.iter().map(|x| x.name.chars().count()).max().unwrap_or(8) + 2;
                    // Columns: one per field, as wide as its name, or its first letters when narrow.
                    let cw = |f: &str| f.chars().count().min(((wd.saturating_sub(nw)) / spec.fields.len().max(1)).saturating_sub(1).max(2)) + 1;
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
                    sec(&mut t, "Fields");
                    for f in &spec.fields {
                        t.push(Line::from(vec![Span::styled(format!("{} ", fit(&f.name, nw)), pal.ink()), Span::styled(f.r#type.clone(), pal.muted())]));
                        if let Some(d) = f.doc.as_ref().filter(|d| !d.is_empty()) { t.extend(hanging(d, nw + 1, wd, pal.faint())); }
                    }
                }
                Some(Key::Trusted(ti)) => {
                    let Some(tf) = g.trusted.get(ti) else { return Text::default() };
                    t.push(spread(vec![Span::styled(tf.name.clone(), pal.strong())], vec![Span::styled("Trusted", pal.muted())], wd));
                    if let Some(d) = &tf.doc { t.extend(hanging(d, 0, wd, pal.ink())); }
                    t.push(blank());
                    let mut place = vec![Span::styled(format!("{}:{}", tf.file, tf.line), pal.faint())];
                    if tf.changed { place.push(Span::styled("   Differs from trunk", pal.tone(Tone::Yellow))); }
                    t.push(kv("Defined", place));
                    let callers: Vec<&projection::SpecNode> = g.nodes.iter().filter(|n| n.trusted.contains(&tf.name)).collect();
                    if !callers.is_empty() { sec(&mut t, "Called By"); for c in callers { t.push(Line::from(vec![Span::styled(format!("{}  ", fit(&c.name, 24)), pal.ink()), Span::styled(at(c), pal.faint())])); } }
                }
                Some(Key::Sbom(k)) => {
                    let Some(sb) = &app.p.sbom else { return Text::default() };
                    t.push(title(cap(k)));
                    t.push(blank());
                    t.push(kv("Source", vec![Span::styled(".bon/sbom.json", pal.ink()), Span::styled(format!("   {}", if sb.source == "trunk" { "On trunk" } else { "Working tree" }), pal.muted())]));
                    t.push(blank());
                    let row = |cells: Vec<(String, usize)>, style: Style| Line::from(cells.into_iter().map(|(c, w)| Span::styled(fit(&c, w), style)).collect::<Vec<_>>());
                    match k {
                        "tools" => { t.push(row(vec![("Name".into(), 16), ("Version".into(), 20)], pal.muted()));
                            for c in sb.document.components.iter().filter(|c| c.group.as_deref() == Some("tcb")) { t.push(row(vec![(c.name.clone(), 16), (c.version.clone(), wd.saturating_sub(16))], pal.ink())); } }
                        "services" => { t.push(row(vec![("Name".into(), 16), ("Endpoints".into(), 20)], pal.muted()));
                            for sv in &sb.document.services { t.push(row(vec![(sv.name.clone(), 16), (sv.endpoints.join(", "), wd.saturating_sub(16))], pal.ink())); } }
                        _ => { t.push(row(vec![("Name".into(), 26), ("Version".into(), 13), ("Hash".into(), 12)], pal.muted()));
                            for c in sb.document.components.iter().filter(|c| c.r#type == "library") {
                                t.push(Line::from(vec![Span::styled(fit(&c.name, 26), pal.ink()), Span::styled(fit(&c.version, 13), pal.ink()), Span::styled(c.hashes.first().map_or(String::new(), |h| h.content.chars().take(12).collect()), pal.faint())]));
                            } }
                    }
                }
                _ => {}
            }
        }
        Tab::Project => {}
    }
    Text::from(t)
}

/// Where the kernel, re-deriving a search from its words, disagrees with what the trace recorded.
fn disagreement(s: &SearchTrace) -> Option<String> {
    if s.kernel != "derived" { return None; }
    match (s.selected, s.recorded_selected) {
        (k, Some(t)) if k != Some(t) => Some(format!("Kernel selects {}, trace recorded #{t}", k.map_or("none".to_string(), |k| format!("#{k}")))),
        _ => None,
    }
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
#[cfg(test)]
fn why_blocked(s: &SearchTrace) -> Vec<String> { why_blocked_in(s, &[]) }

/// The protected paths every accepted, proved, unverified candidate changed:
/// the change search found but may not make, for the model to review and apply.
pub(crate) fn needed(s: &SearchTrace, protected: &[String]) -> Option<(Vec<String>, String)> {
    let under = |p: &String| protected.iter().any(|q| p == q.trim_end_matches('/') || p.starts_with(&format!("{}/", q.trim_end_matches('/'))));
    let outside: Vec<&Facts> = s.candidates.iter().filter(|c| c.accepted && c.proved && !c.verified).collect();
    let first = outside.first()?;
    let mut files: Vec<String> = first.changed.iter().filter(|p| under(p)).cloned().collect();
    files.retain(|f| outside.iter().all(|c| c.changed.contains(f)));
    if files.is_empty() { return None; }
    Some((files.clone(), format!("git diff {} {} -- {}", short(&s.params.base), short(first.commit.as_deref().unwrap_or("")), files.join(" "))))
}

/// Why a search blocked: the trace's recorded reason first, as written; then
/// what the candidates show.
fn why_blocked_in(s: &SearchTrace, protected: &[String]) -> Vec<String> {
    let v = s.candidates.iter().filter(|c| c.verified).count();
    let mut out = Vec::new();
    if let Some(b) = s.blocked.as_deref() {
        let (word, sentence) = reason(b);
        out.push(match word { Some(w) => format!("blocked: {w}: {sentence}"), None => format!("blocked: {sentence}") });
        // Tests that did not tell the selection from its foils, or rejected every member: what each rejects.
        if matches!(word, Some("undiscriminating" | "rejects_every")) {
            for c in s.candidates.iter().filter(|c| c.verified) {
                let rejects: Vec<String> = c.accepts.iter().filter(|(_, a)| !a).map(|(j, _)| if *j < 0 { "trunk".into() } else { format!("#{j}") })
                    .chain(c.accepts_foils.iter().filter(|(_, a)| !a).map(|(j, _)| format!("foil #{j}"))).collect();
                out.push(format!("Test #{}: Rejects {}", c.index, if rejects.is_empty() { "nothing".into() } else { rejects.join(", ") }));
            }
        }
    }
    if let Some((files, diff)) = needed(s, protected) {
        out.push(format!("Needs protected {}: {diff}", files.join(", ")));
    }
    if s.kind == "counterexample" {
        if v < 2 { out.push(format!("Too few verified tests: {v} of {}", s.candidates.len())); }
    } else if s.kind == "foil" {
    } else if v < 2 {
        out.push(format!("Too few verified: {v} of {}", s.candidates.len()));
    } else {
        let gs = groups(s);
        if gs.len() > 1 {
            out.push(format!("Disagree: {} groups by agree output", gs.len()));
            for g in &gs { out.push(format!("  {}", g.iter().map(|c| format!("#{}", c.index)).collect::<Vec<_>>().join(" "))); }
            out.push("d  Compare two groups".into());
        }
    }
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

/// The key reference `?` opens: every key, by where it applies.
const KEYS: [(&str, &[(&str, &str)]); 2] = [
    ("Everywhere", &[("↑ ↓   j k", "Move"), ("g  G", "First, last"), ("⇥  ⇧⇥  1–4", "Switch tab"), ("⏎", "Open detail"), ("esc", "Back"),
        ("PgUp PgDn  ⇧↑ ⇧↓", "Scroll detail"), ("/", "Find"), ("r", "Time range"), ("t", "Light or dark"), ("q", "Quit")]),
    ("Traces", &[("l", "Logs"), ("d", "Compare outputs")]),
];

/// A key bar: each key in ink, what it does muted.
fn key_bar(pal: &Palette, items: &[(&str, String)], w: usize) -> Line<'static> {
    let mut items: Vec<(String, String)> = items.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    let len = |v: &Vec<(String, String)>| v.iter().map(|(k, d)| k.chars().count() + d.chars().count() + 3).sum::<usize>() + 1;
    // Drop from the end of the middle until it fits: the first and the last two stay.
    while len(&items) > w && items.len() > 3 { items.remove(items.len() - 3); }
    let mut v = vec![Span::raw(" ")];
    for (k, d) in items { v.push(Span::styled(format!("{k} "), pal.ink().add_modifier(Modifier::BOLD))); v.push(Span::styled(format!("{d}  "), pal.muted())); }
    Line::from(v)
}

fn draw(f: &mut Frame, app: &mut App) {
    let pal = app.palette;
    let area = f.area();
    let [top, tabs, rule, body, foot] = Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)]).areas(area);
    let p = &app.p;

    // Header: the repository, trunk and what is running; cost at the right:
    // generation and time, the same weight, then their total, muted.
    let running = p.processes.iter().filter(|b| b.running).count();
    let repo = &p.repo;
    let state = if running > 0 { Span::styled(format!("● Running {running}"), pal.tone(Tone::Orange)) } else { Span::styled("Idle", pal.muted()) };
    let trunk = format!("{} {}", repo.trunk.clone().unwrap_or("main".into()), short(repo.remote_head.as_deref().or(repo.head.as_deref()).unwrap_or("")));
    // 2: repository, trunk and state; 1: repository and state; 0: state.
    let left = |level: u8| {
        let mut v = vec![Span::raw(" ")];
        if level >= 1 { v.extend([Span::styled("bon", pal.muted()), Span::styled(" / ", pal.faint()), Span::styled(repo.name.clone().unwrap_or_default(), pal.strong()), Span::raw("   ")]); }
        if level >= 2 { v.extend([Span::styled(trunk.clone(), pal.muted()), Span::raw("   ")]); }
        v.push(state.clone());
        v
    };
    let t = &p.totals;
    let cost = |gw: &str, rate: bool| {
        let mut v = vec![Span::styled(money(Some(t.generation)), pal.ink()), Span::styled(format!(" {gw} + "), pal.muted()),
            Span::styled(money(Some(t.time_cost)), pal.ink()), Span::styled(" time", pal.muted())];
        if rate && t.rate.is_some() { v.push(Span::styled(format!(" {}", at_rate(t.rate)), pal.muted())); }
        v.push(Span::styled(format!(" = {} ", money(Some(t.cost))), pal.muted()));
        v
    };
    let w = top.width as usize;
    let header = [(2, "generation", true), (2, "generation", false), (1, "generation", false), (1, "gen", false), (0, "gen", false)].into_iter()
        .map(|(tr, gw, rate)| (left(tr), cost(gw, rate)))
        .find(|(l, r)| width_of(l) + width_of(r) + 2 <= w)
        .unwrap_or_else(|| (vec![Span::styled(" ", pal.muted())], cost("gen", false)));
    f.render_widget(Paragraph::new(spread(header.0, header.1, w)), top);

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
            let mut lines = vec![section(&pal, 1, "Logs", Some(items.len())), Line::default()];
            let h = body.height.saturating_sub(2) as usize;
            let first = sel.saturating_sub(h.saturating_sub(1));
            for (i, (label, _)) in items.iter().enumerate().skip(first).take(h) {
                lines.push(Line::from(Span::styled(format!(" {}", fit(label, body.width as usize - 1)), if i == *sel { pal.ink().patch(pal.selected()) } else { pal.ink() })));
            }
            f.render_widget(Paragraph::new(lines), body);
        }
        Overlay::Text { title, lines, top } => {
            f.render_widget(ratatui::widgets::Clear, body);
            let [head, text] = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).areas(body);
            f.render_widget(Paragraph::new(spread(vec![Span::styled(format!(" {title}"), pal.strong())], vec![Span::styled(format!("Line {} of {} ", top + 1, lines.len()), pal.muted())], head.width as usize)), head);
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

    // Footer: the keys, the same on every tab, or an error reading the projection.
    let filter = app.filter.lock().map(|f| f.clone()).unwrap_or_default();
    let fw = foot.width as usize;
    let foot_line = if let Some(e) = &app.error { Line::from(Span::styled(format!(" {e}"), pal.tone(Tone::Red))) }
    else if let Some(buf) = &app.input { let mut l = vec![Span::styled(" Find  ", pal.muted()), Span::styled(format!("{buf}▏   "), pal.ink())]; l.extend(key_bar(&pal, &[("⏎", "Apply".into()), ("esc", "Cancel".into())], fw).spans); Line::from(l) }
    else {
        let items: Vec<(&str, String)> = match &app.overlay {
            Overlay::Logs { .. } => vec![("↑↓", "Move".into()), ("⏎", "Open".into()), ("esc", "Back".into())],
            Overlay::Text { .. } | Overlay::Compare { .. } => vec![("↑↓", "Scroll".into()), ("PgUp PgDn", "Page".into()), ("esc", "Back".into())],
            Overlay::None => {
                let mut v: Vec<(&str, String)> = vec![("↑↓", "Move".into())];
                if detail_tab && !wide { v.push(if app.detail_open { ("esc", "Back".into()) } else { ("⏎", "Open".into()) }); }
                v.push(("⇥", "Tab".into()));
                v.push(("/", filter.find.as_deref().map_or("Find".to_string(), |f| format!("Find: {f}"))));
                v.push(("r", RANGES[app.range].0.to_string()));
                v.push(("?", "Keys".into()));
                v.push(("q", "Quit".into()));
                v
            }
        };
        key_bar(&pal, &items, fw)
    };
    f.render_widget(Paragraph::new(foot_line), foot);

    if app.keys {
        let kw = 20;
        let n: usize = KEYS.iter().map(|(_, ks)| ks.len() + 2).sum::<usize>() + 1;
        let w = 44.min(area.width); let h = (n as u16 + 2).min(area.height);
        let r = Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h };
        f.render_widget(ratatui::widgets::Clear, r);
        let mut all = vec![];
        for (i, (where_, ks)) in KEYS.iter().enumerate() {
            if i > 0 { all.push(Line::default()); }
            all.push(section(&pal, 1, where_, None));
            for (k, what) in ks.iter() { all.push(Line::from(vec![Span::styled(format!("   {}", fit(k, kw)), pal.ink().add_modifier(Modifier::BOLD)), Span::styled(what.to_string(), pal.muted())])); }
        }
        f.render_widget(Paragraph::new(all).block(ratatui::widgets::Block::bordered().border_style(pal.rule()).title(Span::styled(" Keys ", pal.strong()))), r);
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
    // Typing after /: find.
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
        (KeyCode::Tab, _) => app.switch(TABS[(ti + 1) % 4]),
        (KeyCode::BackTab, _) => app.switch(TABS[(ti + 3) % 4]),
        (KeyCode::Char(c @ '1'..='4'), _) => app.switch(TABS[c as usize - '1' as usize]),
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
                        items.push((format!("bon process {} · search {} · #{} · {l}", b.pid, s.search, c.index), app.root.join(".bon/traces").join(&b.trace).join(s.search.to_string()).join(c.index.to_string()).join(l)));
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
                        let side = |c: &Facts| { let dir = app.root.join(".bon/traces").join(&b.trace).join(s.search.to_string()).join(c.index.to_string());
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
            "groups": [{ "kind": "code", "title": "from abcdef1", "outcome": "pushed", "time": 99000, "cost": 10.0, "generation": 2.0, "time_cost": 8.0,
                "push": { "commit": "fedcba9876", "cost": 10.0, "generation": 2.0, "time_cost": 8.0 },
                "processes": [{ "pid": 1, "outcome": "pushed", "searches": [
                    { "search": 0, "kind": "code", "width": 8, "returned": 8, "verified": 7, "selected": 1, "kernel": "derived",
                      "candidates": [{ "index": 1, "commit": "1111111", "accepted": true, "verified": true, "rank": 0, "diff": 9 }] },
                    { "search": 1, "kind": "counterexample", "width": 2, "returned": 2, "verified": 2 }] }] }],
            "spec": { "path": "src/spec.rs", "items": [{ "kind": "predicate", "name": "verified", "doc": "Passed the vertical bottleneck." }], "fields": [] }
        })).unwrap();
        for (w, h) in [(80, 24), (120, 30)] {
            let traces = screen(p.clone(), Tab::Traces, w, h);
            // Full width (80): the steps on the row. Beside the detail (120): the steps in the detail.
            let steps_shown = if w < 100 { "8→7→#1 · none found" } else { "8 → 7 → #1 → none found" };
            assert!(traces.contains("Pushed") && traces.contains(steps_shown), "{traces}");
            assert!(screen(p.clone(), Tab::Queue, w, h).contains("Each trace records"));
            assert!(screen(p.clone(), Tab::Spec, w, h).contains("verified"));
            // Cost is generation and time side by side, then the total; never a lone total.
            let project = screen(p.clone(), Tab::Project, w, h);
            assert!(project.contains("$2.00") && project.contains("$8.00") && project.contains("$10.00"), "{project}");
            assert!(traces.lines().next().unwrap().contains("$2.00 gen") && traces.lines().next().unwrap().contains("= $10.00"), "{traces}");
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
    fn the_view_marks_where_the_kernel_disagrees_with_the_trace() {
        // queue 29: the kernel re-derives the selection from the words; the trace recorded its own.
        let s = |kernel: &str, sel: Option<u64>, rec: Option<u64>| -> SearchTrace { serde_json::from_value(serde_json::json!({ "kernel": kernel, "selected": sel, "recorded_selected": rec })).unwrap() };
        assert_eq!(disagreement(&s("derived", Some(1), Some(2))).as_deref(), Some("Kernel selects #1, trace recorded #2"));
        assert!(disagreement(&s("derived", Some(1), Some(1))).is_none());
        assert!(disagreement(&s("unreadable", Some(1), Some(2))).is_none());
    }

    #[test]
    fn every_search_shows_how_many_outputs_its_verified_candidates_had() {
        // Spec strength, measured: one output, the spec pinned the behavior down.
        let s = |outs: &[u64]| -> SearchTrace { serde_json::from_value(serde_json::json!({ "kind": "code",
            "candidates": outs.iter().enumerate().map(|(i, o)| serde_json::json!({ "index": i, "accepted": true, "verified": true, "out": [o] })).collect::<Vec<_>>() })).unwrap() };
        assert_eq!(groups(&s(&[7, 7, 7])).len(), 1);
        assert_eq!(groups(&s(&[7, 8, 7])).len(), 2);
    }

    #[test]
    fn a_search_blocked_by_protected_files_shows_the_change_it_needed() {
        // The afternoon of 4f492c6: every candidate changed src/main.rs, which is trusted.
        let s: SearchTrace = serde_json::from_value(serde_json::json!({ "kind": "code", "blocked": "blocked: fewer than two verified candidates, or they disagree",
            "params": { "base": "4f492c64b3" },
            "candidates": ([0, 1].iter().map(|i| serde_json::json!({ "index": i, "accepted": true, "proved": true, "verified": false, "commit": format!("c9638503{i}"),
                "changed": ["src/encoding.rs", "src/exec.rs", "src/main.rs"] })).collect::<Vec<_>>()) })).unwrap();
        let protected = vec!["src/main.rs".to_string(), "src/spec.rs".to_string(), ".bon/".to_string()];
        let (files, diff) = needed(&s, &protected).unwrap();
        assert_eq!(files, vec!["src/main.rs"]);
        assert_eq!(diff, "git diff 4f492c6 c963850 -- src/main.rs");
        assert_eq!(why_blocked_in(&s, &protected)[1], "Needs protected src/main.rs: git diff 4f492c6 c963850 -- src/main.rs");
        assert!(needed(&s, &[]).is_none());
    }

    #[test]
    fn a_blocked_search_says_why() {
        // Disagreeing: two groups by agree output, each by index.
        // The trace's recorded reason leads, as written.
        let w = why_blocked(&search("code", &[(true, 1), (true, 2), (true, 1), (false, 3)]));
        assert_eq!(w[0], "blocked: fewer than two verified candidates, or they disagree");
        assert!(w[1] == "Disagree: 2 groups by agree output" && w[2].trim() == "#0 #2" && w[3].trim() == "#1", "{w:?}");
        // Too few verified.
        assert_eq!(why_blocked(&search("code", &[(true, 1), (false, 1)]))[1], "Too few verified: 1 of 2");
        // A counterexample with fewer than two verified tests: neither found nor not found.
        assert_eq!(why_blocked(&search("counterexample", &[(true, 1), (false, 1)]))[1], "Too few verified tests: 1 of 2");
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
        assert!(q.find("Proposed").unwrap() < q.find("Queued").unwrap() && q.contains("New 1  Contested 1"), "{q}");
        let sp = screen(p.clone(), Tab::Spec, 120, 30);
        assert!(sp.contains("may_open") && sp.contains("Gate  Impl") && sp.contains("●     ●"), "{sp}");
    }

    /// A pushed code goal whose first selection did not survive its foils: search 0 code,
    /// 1 foil (both foils), 2 counterexample (test 1 rejects both foils, test 0 none).
    fn foiled() -> GoalTrace {
        serde_json::from_value(serde_json::json!({ "kind": "code", "title": "from 9bb8a5b", "outcome": "blocked", "time": 1,
            "processes": [{ "pid": 7, "outcome": "blocked", "searches": [
                { "search": 0, "kind": "code", "width": 2, "returned": 2, "verified": 2, "selected": 1,
                  "candidates": [{ "index": 0, "accepted": true, "proved": true, "verified": true }, { "index": 1, "accepted": true, "proved": true, "verified": true }] },
                { "search": 1, "kind": "foil", "width": 3, "returned": 3,
                  "candidates": [{ "index": 0, "accepted": true }, { "index": 1, "accepted": true }, { "index": 2, "accepted": true, "proved": true }] },
                { "search": 2, "kind": "counterexample", "width": 2, "returned": 2, "verified": 2,
                  "blocked": "blocked: undiscriminating: fewer than two verified tests reject a foil",
                  "candidates": [
                    { "index": 0, "accepted": true, "verified": true, "accepts": [[-1, false], [0, true], [1, true]], "accepts_foils": [[0, true], [1, true]] },
                    { "index": 1, "accepted": true, "verified": true, "accepts": [[-1, false], [0, true], [1, true]], "accepts_foils": [[0, false], [1, false]] }] }] }] })).unwrap()
    }

    #[test]
    fn foils_show_in_the_steps_and_tests_that_tell_them_apart_in_why_blocked() {
        let g = foiled();
        // Accepted and not proved is a foil: 2 of the 3; one test of 2 rejects one.
        assert_eq!(steps(&g, false), "2 → 2 → #1 → 2 foils → 1 of 2 tests reject a foil");
        let w = why_blocked(&g.processes[0].searches[2]);
        assert_eq!(w[0], "blocked: undiscriminating: fewer than two verified tests reject a foil");
        assert_eq!(&w[1..3], ["Test #0: Rejects trunk", "Test #1: Rejects trunk, foil #0, foil #1"]);
    }

    #[test]
    fn a_tests_verdicts_show_under_it_and_accepting_every_foil_is_flagged() {
        let p: Projection = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        let mut p = p; p.groups = vec![foiled()];
        let d = screen(p, Tab::Traces, 140, 80);
        assert!(d.contains("Foil?") && d.contains("Not a foil"), "{d}");
        assert!(d.contains("Members  trunk ✗  #0 ✓  #1 ✓"), "{d}");
        // Test 0 accepts both foils: flagged; test 1 rejects them: not.
        assert_eq!(d.matches("Accepts every foil").count(), 1, "{d}");
        // A test with no foil verdicts is not flagged.
        let mut g = foiled(); for c in &mut g.processes[0].searches[2].candidates { c.accepts_foils.clear(); }
        let mut p: Projection = serde_json::from_value(serde_json::json!({ "repo": { "now": 10 } })).unwrap(); p.groups = vec![g];
        assert!(!screen(p, Tab::Traces, 140, 80).contains("Accepts every foil"));
    }

    #[test]
    fn money_never_prints_negative_zero() {
        assert_eq!(money(Some(-0.001)), "$0.00");
        assert_eq!(money(Some(-0.0)), "$0.00");
        assert_eq!(money(Some(-1.5)), "$-1.50");
        assert_eq!(money(None), "—");
    }

    #[test]
    fn switching_tabs_closes_an_open_detail() {
        let mut app = App::new();
        let k = |c: KeyCode| KeyEvent::new(c, KeyModifiers::NONE);
        for c in [KeyCode::Tab, KeyCode::BackTab, KeyCode::Char('2')] {
            app.detail_open = true;
            key(&mut app, k(c));
            assert!(!app.detail_open);
        }
    }
}
