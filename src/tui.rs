//! `bon` in a terminal: the projection as four tabs, Project, Spec, Queue and
//! Traces, each a list with the focused item's detail beside it (or, under
//! 100 columns, opened on ⏎). Trusted code. It reads only the projection and
//! the files it names; it decides nothing.
//!
//! Color has one meaning, position on the chain: red needs attention, violet
//! is settled. Everything else is ink, muted or faint, light and dark. `Tone`
//! holds the legend: what each color means where it is used. The cursor is
//! reverse video, and a mark (≠) says an item differs from trunk: neither is
//! a color.

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
use crate::view::{self, dur};

// ── palette ─────────────────────────────────────────────

fn rgb(hex: u32) -> Color { Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8) }

/// The view's tokens. A tone is shown mixed toward ink, lifted by `lift`.
#[derive(Clone, Copy)]
struct Palette { ink: u32, muted: u32, faint: u32, line: u32, lift: f32, tones: [u32; 7] }

const DARK: Palette = Palette {
    ink: 0xEDEAE5, muted: 0xA8A39B, faint: 0x6E6A64, line: 0x2E2E35, lift: 0.62,
    tones: [0xC62828, 0xD45500, 0xD4A017, 0x1D5A2A, 0x1B3D8A, 0x4534B0, 0x4A1E86],
};
const LIGHT: Palette = Palette {
    ink: 0x1B1A18, muted: 0x5C574F, faint: 0x8F887C, line: 0xDDD3C1, lift: 0.88,
    tones: [0xA61E1E, 0xB34A06, 0x93680A, 0x173D20, 0x122C61, 0x33258A, 0x35165C],
};

/// Position on the chain, red to violet. Green has its place on the chain but no use yet.
///
/// The legend: what each tone means where the view uses it. Everything not
/// listed is ink (a value), muted (a label), faint (what only locates a value:
/// a path, a line, a commit beside an intent), or the rule's line. Two things
/// are no color: the cursor, the focused row of a list (and of the logs), in
/// reverse video; and an item that differs from trunk, in Spec, marked ≠.
///
/// - Red, needs attention: a bon process that exited (on an error, or with no
///   final transition), the line saying so on its attempt, and Exited in
///   Where It Went; a counterexample found on trunk (outcome `found`); a goal
///   where the kernel's selection differs from the trace's (its list dot and
///   its detail's title) and that disagreement's line; an agent process's flags
///   (killed, over limit, price mismatch); an error reading the projection, in
///   the footer.
/// - Orange, under way: a running bon process or search; Running N in the
///   header; In flight in Where It Went.
/// - Yellow, stopped short and waiting on someone: a blocked goal or search,
///   why it blocked and a reason inferred for it, and Blocked in Where It Went;
///   a proposal waiting for engineer (its dot and ● Waiting); a pending
///   interrupt (its dot in Project's Pending, and ● Pending N in the header); a code or
///   compaction search that neither selected nor blocked nor runs; any outcome
///   without a tone of its own.
/// - Blue, selected: the selected candidate (its index and ★), a search that
///   selected.
/// - Indigo, cleared: a foil or counterexample search that did not block; a
///   counterexample search on trunk that found none (outcome `not found`),
///   and None found in Where It Went.
/// - Violet, settled: a pushed goal; Reached a push in Where It Went.
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
    /// The cursor: the row in reverse video, ink on the background, whatever its colors.
    fn cursor(&self) -> Style { self.ink().add_modifier(Modifier::REVERSED) }
}

/// The mark of an item that differs from trunk, and its words.
const DIFFERS: &str = "≠";

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

/// A goal's tone, the same on its list dot and its detail's title: red where
/// the kernel's selection differs from the trace's in any of its searches,
/// else its outcome's.
fn goal_tone(g: &GoalTrace) -> Tone {
    if g.processes.iter().flat_map(|b| &b.searches).any(|s| disagreement(s).is_some()) { Tone::Red } else { outcome_tone(&g.outcome) }
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
    match s { 0..=59 => "Now".into(), 60..=3599 => format!("{}m ago", s / 60), 3600..=86399 => format!("{}h ago", s / 3600), _ => format!("{}d ago", s / 86400) }
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
enum Key { Goal(usize), Queue(usize), Retired(usize), Proposal(usize), Item(usize), Grid, Trusted(usize), Sbom(&'static str) }

/// One row of a list: what it shows, and the item it stands for, if it can be
/// focused; `more` when it continues the focusable row above it (the cursor
/// covers both).
struct Row { line: Line<'static>, key: Option<Key>, more: bool }
impl Row {
    fn text(line: Line<'static>) -> Row { Row { line, key: None, more: false } }
    fn item(line: Line<'static>, key: Key) -> Row { Row { line, key: Some(key), more: false } }
    fn more(line: Line<'static>) -> Row { Row { line, key: None, more: true } }
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
    /// The list's width when last drawn: rows wrap by width, so a focus is a row at this width.
    list_w: u16,
}

impl App {
    fn new() -> App {
        let dark = std::env::var("BON_THEME").map_or(true, |t| t != "light");
        App { p: Projection::default(), root: ".".into(), overlay: Overlay::None, input: None, range: 0, filter: Default::default(),
              error: None, tab: Tab::Traces, focus: [0; 4], top: [0; 4], detail_top: 0, detail_open: false,
              keys: false, palette: if dark { DARK } else { LIGHT }, dark, off: local_offset(), loaded: None, list_w: 200 }
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

/// Labeled values on one line, `Base 9bb8a5b · Limit $5.00`, onto the next
/// where the line is full.
fn pairs(pal: &Palette, indent: usize, items: &[(&str, String)], w: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut v = vec![Span::raw(" ".repeat(indent))];
    for (k, val) in items {
        let n = k.chars().count() + 1 + val.chars().count();
        if v.len() > 1 && width_of(&v) + 3 + n > w { out.push(Line::from(std::mem::replace(&mut v, vec![Span::raw(" ".repeat(indent))]))); }
        if v.len() > 1 { v.push(Span::styled(" · ", pal.faint())); }
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

/// The attempt that ended a bon process: its last code or compaction search,
/// and the foil and counterexample searches after it.
fn last_attempt(p: &BonProcess) -> Option<(&SearchTrace, &[SearchTrace])> {
    let i = p.searches.iter().rposition(|s| !clears(&s.kind))?;
    Some((&p.searches[i], &p.searches[i + 1..]))
}

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

/// A goal's steps, each labeled, from the attempt that ended it: how many
/// candidates, how many verified, the selection, the foils, and what the
/// counterexample search found.
fn step_parts(g: &GoalTrace) -> Vec<(&'static str, String)> {
    let Some(last) = g.processes.first() else { return Vec::new() };
    // A counterexample on trunk: how many of its tests were verified.
    if g.kind == "counterexample" {
        return vec![("Verified tests", last.searches.iter().map(|s| s.verified).sum::<u64>().to_string())];
    }
    let mut out = Vec::new();
    let Some((m, after)) = last_attempt(last) else { return out };
    // Which attempt these are, where the goal made more than one: its last, the
    // last search but its foils and counterexamples of the process listed first.
    let n: usize = g.processes.iter().map(|p| p.searches.iter().filter(|s| !clears(&s.kind)).count()).sum();
    if n > 1 {
        let at = if g.processes.len() > 1 { format!("process {}, search {}", last.pid, m.search) } else { format!("search {}", m.search) };
        out.push(("Attempt", format!("{n} of {n} ({at})")));
    }
    out.push(("Candidates", m.width.max(m.returned).to_string()));
    out.push(("Verified", m.verified.to_string()));
    if let Some(i) = m.selected { out.push(("Selected", format!("#{i}"))); }
    let foils = after.iter().rev().find(|s| s.kind == "foil");
    if let Some(f) = foils { out.push(("Foils", foil_indices(f).len().to_string())); }
    if let Some(ce) = after.iter().rev().find(|s| s.kind == "counterexample") {
        let telling = foils.map(|f| telling(ce, f).len());
        out.push(("Counterexample", match (g.outcome.as_str(), telling) {
            ("found", _) => "Found".into(),
            ("pushed", _) => "None found".into(),
            // How many ran, and how many the spec's two needs.
            _ if ce.verified < 2 => format!("{} of {} verified, 2 needed", ce.verified, plural(ce.width.max(ce.returned) as usize, "test", "tests")),
            (_, Some(d)) if d < 2 => format!("{d} of {} reject a foil, 2 needed", plural(ce.verified as usize, "verified test", "verified tests")),
            // Candidates that disagree, and tests that judged them all without telling them apart.
            _ if m.reason.as_deref() == Some("undecided") => "None splits them".into(),
            _ => "None found".into(),
        }));
    }
    out
}

/// A goal's steps on one line. Tight, for a list row, with the commit pushed:
/// `8→8→#2 · 2 foils · None found · 0b1e1a5`.
fn steps(g: &GoalTrace, tight: bool) -> String {
    let parts = step_parts(g);
    if !tight { return parts.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(" · "); }
    let get = |k: &str| parts.iter().find(|(l, _)| *l == k).map(|(_, v)| v.clone());
    if g.kind == "counterexample" { return get("Verified tests").map_or(String::new(), |v| plural(v.parse().unwrap_or(0), "verified test", "verified tests")); }
    let head = ["Candidates", "Verified", "Selected"].iter().filter_map(|k| get(k)).collect::<Vec<_>>().join("→");
    let mut out = vec![head];
    if let Some(f) = get("Foils") { out.push(plural(f.parse().unwrap_or(0), "foil", "foils")); }
    if let Some(c) = get("Counterexample") { out.push(c); }
    if let Some(c) = g.push.as_ref().and_then(|p| p.commit.as_deref()) { out.push(short(c)); }
    out.into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" · ")
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

/// The outcome tables, at the head of Traces: attempts, each kind's reasons
/// (which sum to its Blocked), then bon processes. Both tables share their
/// columns' widths; columns that do not fit drop from the right.
fn outcome_rows(pal: &Palette, t: &projection::Totals, w: usize) -> Vec<Row> {
    let (attempts, processes) = (view::attempt_table(t), view::process_table(t));
    if attempts.is_empty() && processes.is_empty() { return Vec::new(); }
    // The first column as wide in both tables; the rest each as its own.
    let w0 = attempts.iter().chain(&processes).map(|r| r[0].chars().count()).max().unwrap_or(0);
    let mut out = table_rows(pal, &attempts, w0, w);
    // Each kind's blocked attempts by reason, wrapped under itself.
    for (label, items) in view::reason_rows(t) {
        let mut lw = label.chars().count() + 2;
        if items.join(" · ").chars().count() > w.saturating_sub(1 + lw) {
            out.push(Row::text(Line::from(Span::styled(format!(" {label}"), pal.muted()))));
            lw = 2;
        }
        for (k, l) in wrap_items(&items, " · ", w.saturating_sub(1 + lw)).into_iter().enumerate() {
            out.push(Row::text(Line::from(vec![Span::styled(format!(" {}", fit(if k == 0 && lw > 2 { &label } else { "" }, lw)), pal.muted()), Span::styled(l, pal.ink())])));
        }
    }
    if !processes.is_empty() { out.push(Row::text(Line::default())); out.extend(table_rows(pal, &processes, w0, w)); }
    out
}

/// A table, its header first (strong, then muted), as rows `w` wide: the first
/// column `w0` wide and left, the rest each as wide as its widest and right;
/// a row whose label is indented is a sub-row (muted label). Columns that do
/// not fit drop from the right.
fn table_rows(pal: &Palette, rows: &[Vec<String>], w0: usize, w: usize) -> Vec<Row> {
    let cw: Vec<usize> = (0..rows.first().map_or(0, |r| r.len())).map(|i| if i == 0 { w0 } else { rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0) }).collect();
    let mut n = cw.len();
    while n > 2 && 1 + cw[0] + (1..n).map(|i| cw[i] + 2).sum::<usize>() > w { n -= 1; }
    rows.iter().enumerate().map(|(k, r)| {
        let (first, rest) = if k == 0 { (pal.strong(), pal.muted()) } else if r[0].starts_with(' ') { (pal.muted(), pal.ink()) } else { (pal.ink(), pal.ink()) };
        let mut v = vec![Span::styled(format!(" {}", fit(&r[0], cw[0])), first)];
        for i in 1..n { v.push(Span::styled(format!("  {}", right(&r[i], cw[i])), rest)); }
        Row::text(Line::from(v))
    }).collect()
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
                let tone = pal.tone(goal_tone(g));
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
                out.push(Row::item(Line::from(spans), Key::Goal(gi)));
            }
            if p.groups.is_empty() { out.push(Row::text(Line::from(Span::styled(" No bon process yet", pal.muted())))); }
        }
        Tab::Queue => {
            // Every item in full, full width: its label, then its text wrapped under itself.
            let entry = |out: &mut Vec<Row>, key: Key, label: String, text: &str, style: Style| {
                for (k, l) in hanging(text, 7, w, style).into_iter().enumerate() {
                    let body: String = l.spans[0].content.chars().skip(7).collect();
                    let line = Line::from(vec![Span::styled(format!(" {}", fit(if k == 0 { &label } else { "" }, 6)), pal.muted()), Span::styled(body, style)]);
                    out.push(if k == 0 { Row::item(line, key.clone()) } else { Row::more(line) });
                }
            };
            // A labeled line under an item, part of it.
            let under = |out: &mut Vec<Row>, label: &str, value: &str, style: Style| {
                for (k, l) in hanging(value, 7 + 13, w, style).into_iter().enumerate() {
                    let body: String = l.spans[0].content.chars().skip(20).collect();
                    out.push(Row::more(Line::from(vec![Span::raw(" ".repeat(7)), Span::styled(fit(if k == 0 { label } else { "" }, 13), pal.muted()), Span::styled(body, style)])));
                }
            };
            if !p.proposals.is_empty() {
                out.push(header("Proposed", Some(p.proposals.len())));
                for (pi, pr) in p.proposals.iter().enumerate() {
                    let counts = vec![Span::styled("New ", pal.muted()), Span::styled(format!("{:<3}", pr.intents.len()), pal.ink()),
                        Span::styled("Contested ", pal.muted()), Span::styled(format!("{:<2}", pr.contested.len()), pal.ink())];
                    let room = w.saturating_sub(5 + width_of(&counts) + 1);
                    out.push(Row::item(spread(vec![Span::styled("  ● ", pal.tone(Tone::Yellow)), Span::styled(fit(&pr.source, room), pal.ink())], counts, w), Key::Proposal(pi)));
                    under(&mut out, "Accept", &format!("git am {}", pr.path), pal.ink());
                    for i in &pr.intents {
                        under(&mut out, &format!("New {}", i.id.map_or("—".into(), |n| n.to_string())), &i.intent, pal.ink());
                        if let Some(c) = &i.cue { under(&mut out, "Cue", c, pal.faint()); }
                    }
                    for c in &pr.contested { under(&mut out, "Contested", c, pal.ink()); }
                }
                out.push(blank());
            }
            if !p.proposals.is_empty() || !p.retired.is_empty() { out.push(header("Queued", Some(p.queue.as_ref().map_or(0, |q| q.len())))); }
            for (qi, q) in p.queue.iter().flatten().enumerate() { entry(&mut out, Key::Queue(qi), format!("#{}", q.id), &q.intent, pal.ink()); }
            if p.queue.as_ref().is_none_or(|q| q.is_empty()) { out.push(Row::text(Line::from(Span::styled(" Nothing queued", pal.muted())))); }
            // Intents taken off the queue, newest first, each with the commit that took it off.
            if !p.retired.is_empty() {
                out.push(blank());
                out.push(header("Retired", Some(p.retired.len())));
                for (ri, r) in p.retired.iter().enumerate() {
                    entry(&mut out, Key::Retired(ri), format!("#{}", r.id), &r.intent, pal.muted());
                    let when = r.time.map_or(String::new(), |x| format!(" · {}", ago(p.repo.now, x)));
                    under(&mut out, "Taken off by", &format!("{}{when} · {}", short(&r.commit), r.subject), pal.faint());
                }
            }
        }
        Tab::Spec => {
            let Some(spec) = &p.spec else { out.push(Row::text(Line::from(Span::styled(" No spec found", pal.muted())))); return out };
            let g = p.system.clone().unwrap_or_default();
            // Names as wide as the longest, but never more than a third of the width (a phone).
            let nw = (spec.items.iter().map(|i| i.name.chars().count()).chain(spec.fields.iter().map(|f| f.name.chars().count())).max().unwrap_or(10).min(24) + 2).min((w / 3).max(10));
            // An item whose detail shows something that differs from trunk is marked in the gutter.
            let changed = |name: &str| ["spec", "gate", "kernel"].iter().any(|l| g.nodes.iter().any(|n| n.changed && n.id == format!("{l}:{name}")));
            let gutter = |c: bool| Span::styled(format!(" {} ", if c { DIFFERS } else { " " }), pal.ink());
            let item = |i: usize, rest: Vec<Span<'static>>| { let mut v = vec![gutter(changed(&spec.items[i].name)), Span::styled(fit(&spec.items[i].name, nw), pal.ink())]; v.extend(rest); Row::item(Line::from(v), Key::Item(i)) };
            let room = w.saturating_sub(nw + 4);
            let doc_of = |i: usize| Span::styled(fit(&spec.items[i].doc.clone().unwrap_or_default(), room), pal.muted());
            let of = |kind: &str| spec.items.iter().enumerate().filter(|(_, x)| x.kind == kind).map(|(i, _)| i).collect::<Vec<_>>();
            // Where the spec is, and how much of it differs from trunk.
            let differ = g.nodes.iter().filter(|n| n.changed).count();
            let mut file = vec![(" File", spec.path.clone())];
            let label = format!("{DIFFERS} Differs from trunk");
            if differ > 0 { file.push((label.as_str(), differ.to_string())); }
            out.extend(pairs(pal, 0, &file, w).into_iter().map(Row::text));
            out.push(blank());

            out.push(header("Vocabulary", Some(of("type").len())));
            for i in of("type") { out.push(item(i, vec![doc_of(i)])); }

            out.push(blank());
            let ts: Vec<usize> = of("init").into_iter().chain(of("transition")).collect();
            out.push(header("State Machine", Some(ts.len())));
            if !spec.fields.is_empty() {
                let names = spec.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(" · ");
                out.push(Row::item(Line::from(vec![Span::styled(format!("   {}", fit("Fields", nw)), pal.ink()), Span::styled(fit(&names, room), pal.muted())]), Key::Grid));
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
                Some([Some("✓".into()), imp.then(|| "✓".into()), target, program])
            };
            let mut decided: Vec<usize> = of("predicate").into_iter().filter(|i| layers(&spec.items[*i].name).is_some()).collect();
            decided.sort_by_key(|i| spec.items[*i].name.clone());
            // A layer absent for every predicate is said once, under the legend, not as a column of —.
            // Columns drop from the right where they do not fit: Program, then Target.
            let heads = ["Gate", "Implementation", "Target", "Program"];
            let cws = [6usize, 16, 8, 10];
            let present: Vec<usize> = (0..4).filter(|&k| decided.iter().any(|i| layers(&spec.items[*i].name).is_some_and(|l| l[k].is_some()))).collect();
            let absent: Vec<&str> = (0..4).filter(|k| !present.contains(k)).map(|k| heads[k]).collect();
            let mut ncols = present.len();
            while ncols > 2 && w < nw + 3 + present[..ncols].iter().map(|&k| cws[k]).sum::<usize>() { ncols -= 1; }
            let cols = &present[..ncols];
            if !decided.is_empty() {
                out.push(blank());
                let mut h = vec![Span::styled(format!(" {}", fit("Spec → Code", nw + 2)), pal.strong())];
                for &k in cols { h.push(Span::styled(fit(heads[k], cws[k]), pal.muted())); }
                out.push(Row::text(Line::from(h)));
                out.push(Row::text(Line::from(vec![Span::raw(format!("   {}", " ".repeat(nw))), Span::styled("✓ ", pal.ink()), Span::styled("Present   ", pal.muted()), Span::styled("— ", pal.faint()), Span::styled("Absent", pal.muted())])));
                if !absent.is_empty() { out.push(Row::text(Line::from(vec![Span::raw(format!("   {}", " ".repeat(nw))), Span::styled(fit(&format!("{}: absent for every one", absent.join(", ")), room), pal.muted())]))); }
            }
            for i in &decided {
                let ls = layers(&spec.items[*i].name).unwrap();
                let row = cols.iter().map(|&k| match &ls[k] { Some(x) => Span::styled(fit(x, cws[k]), pal.ink()), None => Span::styled(fit("—", cws[k]), pal.faint()) }).collect();
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
                out.push(Row::item(Line::from(vec![gutter(t.changed), Span::styled(fit(&t.name, nw), pal.ink()), Span::styled(fit(&t.doc.clone().unwrap_or_default(), room), pal.muted())]), Key::Trusted(ti)));
            }
            if let Some(sb) = &p.sbom {
                let comps = &sb.document.components;
                let tools: Vec<String> = comps.iter().filter(|c| c.group.as_deref() == Some("tcb")).map(|c| c.name.clone()).collect();
                let crates = comps.iter().filter(|c| c.r#type == "library").count();
                let services: Vec<String> = sb.document.services.iter().map(|s| s.name.clone()).collect();
                for (k, label, v) in [("tools", "Tools", tools.join(" · ")), ("services", "Services", services.join(" · ")), ("crates", "Crates", format!("{crates}"))] {
                    out.push(Row::item(Line::from(vec![Span::styled(format!("   {}", fit(label, nw)), pal.ink()), Span::styled(fit(&v, room), pal.muted())]), Key::Sbom(k)));
                }
            }
        }
        Tab::Project => {
            let t = &p.totals;
            // What waits on engineer comes first: each pending interrupt, oldest
            // first, what happened, and each choice with its cost and how it is made.
            let pending: Vec<&projection::Interrupt> = p.interrupts.iter().filter(|i| i.resolved.is_none()).collect();
            if !pending.is_empty() {
                out.push(header("Pending", Some(pending.len())));
                let names = pending.iter().flat_map(|i| i.choices.iter().map(|c| c.choice.chars().count() + 4).chain([i.kind.chars().count() + 4])).max().unwrap_or(0) + 2;
                let at = names.min(w / 3).max(6);
                let labeled = |out: &mut Vec<Row>, label: Vec<Span<'static>>, text: &str, style: Style| {
                    let first = width_of(&label) < at;
                    if !first { out.push(Row::text(Line::from(label.clone()))); }
                    for (k, l) in hanging(text, at, w, style).into_iter().enumerate() {
                        let mut v = if k == 0 && first { label.clone() } else { Vec::new() };
                        let used = width_of(&v);
                        v.push(Span::raw(" ".repeat(at.saturating_sub(used))));
                        v.push(Span::styled(l.spans[0].content.chars().skip(at).collect::<String>(), style));
                        out.push(Row::text(Line::from(v)));
                    }
                };
                for (k, i) in pending.iter().enumerate() {
                    if k > 0 { out.push(blank()); }
                    let repo = if i.repository.is_empty() || p.repo.name.as_deref() == Some(i.repository.as_str()) { String::new() } else { format!(" · {}", i.repository) };
                    labeled(&mut out, vec![Span::styled("  ● ", pal.tone(Tone::Yellow)), Span::styled(cap(&i.kind), pal.ink())],
                        &format!("{} · raised {}{repo}", i.about, ago(p.repo.now, i.raised).to_lowercase()), pal.ink());
                    for line in &i.what { labeled(&mut out, Vec::new(), line, pal.muted()); }
                    for c in &i.choices {
                        labeled(&mut out, vec![Span::styled(format!("    {}", cap(&c.choice)), pal.ink())], &c.cost, pal.ink());
                        labeled(&mut out, Vec::new(), &c.how, pal.faint());
                    }
                }
                out.push(blank());
            }
            let lw = 18;
            let num = |s: String| Span::styled(right(&s, 9), pal.ink());
            let line = |label: &str, value: Vec<Span<'static>>| Row::text(kv(pal, 3, lw, label, value));
            out.push(header("Cost", None));
            for l in cost_rows(pal, 3, Some(t.generation), Some(t.time_cost), t.rate) {
                // Project's labels are as wide as its others.
                let mut s = l.spans; s[0] = Span::styled(format!("   {}", fit(s[0].content.trim(), lw)), pal.muted()); out.push(Row::text(Line::from(s)));
            }
            out.push(line("Per verified", vec![num(money(t.per_verified_candidate))]));
            // Per push, with its basis: what reached a push, over how many pushes.
            out.push(Row::text(Line::default()));
            out.push(line("Reached a push", vec![num(money(Some(t.pushed)))]));
            out.push(line("Pushes", vec![num(t.pushes.to_string())]));
            out.push(line("Per push", vec![num(money(t.per_push)), Span::styled(format!("   {} / {}", money(Some(t.pushed)), t.pushes), pal.muted())]));

            // Where it went: what reached a push, what ended each other way, what is running;
            // each in its outcome's tone, split into generation (█) and time (▒) by its share of the total.
            let sum = |gs: &mut dyn Iterator<Item = (Option<f64>, Option<f64>)>| gs.fold((0.0, 0.0), |(a, b), (g, t)| (a + g.unwrap_or(0.0), b + t.unwrap_or(0.0)));
            let mut parts = vec![("Reached a push".to_string(), Tone::Violet, sum(&mut p.groups.iter().filter(|g| g.outcome == "pushed").map(goal_cost)))];
            let mut others: Vec<&str> = p.groups.iter().filter(|g| g.outcome != "pushed" && !g.running).map(|g| g.outcome.as_str()).collect();
            others.sort(); others.dedup();
            for o in others {
                parts.push((outcome_label(o), outcome_tone(o), sum(&mut p.groups.iter().filter(|g| g.outcome == o && !g.running).map(|g| (Some(g.generation), Some(g.time_cost))))));
            }
            parts.push(("In flight".to_string(), Tone::Orange, sum(&mut p.groups.iter().filter(|g| g.running).map(goal_cost))));
            let whole: f64 = parts.iter().map(|(_, _, (g, t))| g + t).sum::<f64>().max(1e-9);
            let share_w = 14;
            let bw = w.saturating_sub(3 + lw + GEN_W + TIME_W + 2 + share_w).min(30);
            out.push(blank());
            let mut h = vec![Span::styled(format!(" {}", fit("Where It Went", lw + 2)), pal.strong())];
            h.extend(cost_heads(pal));
            let legend = vec![Span::styled("█ ", pal.muted()), Span::styled("Gen  ", pal.muted()), Span::styled("▒ ", pal.muted()), Span::styled("Time", pal.muted())];
            h.push(Span::raw("  "));
            if bw >= 12 { let lw = width_of(&legend); h.extend(legend); h.push(Span::raw(" ".repeat(bw - lw))); } else { h.push(Span::raw(" ".repeat(bw))); }
            h.push(Span::styled(right("Share of total", share_w), pal.muted()));
            out.push(Row::text(Line::from(h)));
            for (label, tone, (g, tm)) in parts {
                if label == "In flight" && g + tm == 0.0 { continue; }
                let label = label.as_str();
                let (ng, nt) = ((g / whole * bw as f64).round() as usize, ((g + tm) / whole * bw as f64).round() as usize);
                let mut v = cost_cells(pal, Some(g), Some(tm));
                v.push(Span::raw("  "));
                v.push(Span::styled("█".repeat(ng), pal.tone(tone)));
                v.push(Span::styled("▒".repeat(nt.saturating_sub(ng)), pal.tone(tone)));
                v.push(Span::raw(" ".repeat(bw.saturating_sub(nt.max(ng)))));
                let share = (g + tm) / whole * 100.0;
                v.push(Span::styled(right(&if share > 0.0 && share < 1.0 { "<1%".to_string() } else { format!("{share:.0}%") }, share_w), pal.ink()));
                out.push(line(label, v));
            }

            // Where the wall time went: each search's split by its slowest agent process, summed,
            // with the time cost each part carries. Trunk's checks before a search are charged nothing.
            let (parts, trunk) = time_split(p);
            let wall: f64 = parts.iter().map(|x| x.0).sum();
            if wall > 0.0 {
                out.push(blank());
                out.push(Row::text(Line::from(vec![Span::styled(format!(" {}", fit("Where The Time Went", lw + 2)), pal.strong()),
                    Span::styled(right("Wall", 9), pal.muted()), Span::styled(right("Time", TIME_W), pal.muted()), Span::styled(right("Share", 7), pal.muted())])));
                for (label, (secs, dollars)) in ["Model session", "Checks", "Other"].into_iter().zip(parts) {
                    out.push(line(label, vec![num(dur(secs)), Span::styled(right(&money(Some(dollars)), TIME_W), pal.ink()), Span::styled(right(&format!("{:.0}%", 100.0 * secs / wall), 7), pal.ink())]));
                }
                out.push(line("Searches", vec![num(dur(wall)), Span::styled(right(&money(Some(parts.iter().map(|x| x.1).sum())), TIME_W), pal.muted())]));
                if trunk > 0.0 { out.push(line("Trunk checks", vec![num(dur(trunk)), Span::styled("   before each first search; no time charged", pal.muted())])); }
                out.push(Row::text(Line::from(Span::styled(fit("   By each search's slowest agent process; other is waiting on a slot and setup (inferred)", w), pal.faint()))));
            }

            // The measures, each table with its formulas under it, said once.
            let notes = |out: &mut Vec<Row>, names: &[&str]| for (k, v) in view::MEASURE_NOTES.iter().filter(|(k, _)| names.contains(k)) {
                out.extend(hanging(&format!("{k}: {v}"), 3, w, pal.faint()).into_iter().map(Row::text));
            };
            let (run, fits) = view::run_time_table(t);
            let tables = [
                (view::utilization_table(t), vec!["Utilization"]),
                (view::success_table(t), vec!["Success probability per agent process", "Success probability per attempt", "Attempt a"]),
                (run, vec!["Time, cost to a push", "Median, 90th percentile"]),
                (view::per_verified_table(t), vec!["Cost per verified candidate"]),
                (view::turnaround_table(t), vec!["Turnaround"]),
            ];
            for (k, (rows, names)) in tables.into_iter().enumerate() {
                // The run-time distribution's fits stand under its table, or alone where nothing pushed.
                if rows.is_empty() && !(k == 2 && !fits.is_empty()) { continue; }
                out.push(blank());
                if rows.is_empty() { out.push(header("Run-Time Distribution", None)); }
                out.extend(table_rows(pal, &rows, rows.iter().map(|r| r[0].chars().count()).max().unwrap_or(0), w));
                if k == 2 {
                    for f in &fits { out.extend(hanging(f, 3, w, pal.ink()).into_iter().map(Row::text)); }
                    notes(&mut out, &["Per search (inferred)"]);
                }
                notes(&mut out, &names);
                if k == 0 && t.utilization.agent_processes.size.is_none() {
                    out.extend(hanging("Size: no trace records the semaphores' sizes yet, so utilization is held ÷ wall alone", 3, w, pal.faint()).into_iter().map(Row::text));
                }
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
            for (k, n) in &kinds { out.push(line(&format!("{} pushes", cap(k)), vec![num(n.to_string())])); }
            // Spec strength, measured by search: searches whose verified candidates show one behavior.
            let measured: Vec<usize> = p.processes.iter().flat_map(|b| &b.searches).filter(|s| !clears(&s.kind) && s.verified >= 2).map(|s| groups(s).len()).collect();
            if !measured.is_empty() {
                let pinned = measured.iter().filter(|n| **n == 1).count();
                // Every search one behavior: agree has never told verified candidates apart.
                let always = if pinned == measured.len() { " · every one: agree split none" } else { "" };
                out.push(line("One behavior", vec![num(pinned.to_string()), Span::styled(format!("   of {} searches with two verified{always}", measured.len()), pal.muted())]));
            }
            // A kind's rank every candidate in range shares: it selects nothing.
            for kind in ["code", "compaction"] {
                let ranks: Vec<Option<i64>> = p.processes.iter().flat_map(|b| &b.searches).filter(|s| s.kind == kind).flat_map(|s| &s.candidates).map(|c| c.rank).collect();
                if ranks.len() > 1 && ranks.windows(2).all(|w| w[0] == w[1]) {
                    out.push(line(&format!("{} rank", cap(kind)), vec![num(ranks[0].map_or("—".to_string(), |r| r.to_string())),
                        Span::styled(format!("   for all {} candidates: the smallest diff, then the earliest, selects", ranks.len()), pal.muted())]));
                }
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
fn focused(app: &App) -> Option<Key> { rows(app, app.list_w).into_iter().nth(app.focus[app.ti()]).and_then(|r| r.key) }

/// The goals in the order Traces lists them.
fn sorted_groups(p: &Projection) -> Vec<&GoalTrace> {
    let mut groups: Vec<&GoalTrace> = p.groups.iter().collect();
    groups.sort_by_key(|g| (!g.running, -g.time));
    groups
}

/// Each edge into (`up`) or out of an item, followed `depth` steps: how, what, and where.
fn chain(g: &projection::SpecGraph, id: &str, up: bool, depth: usize, seen: &mut Vec<String>, out: &mut Vec<(String, String, String)>) {
    if depth == 0 { return; }
    for e in g.edges.iter().filter(|e| if up { e.1 == id } else { e.0 == id }) {
        let other = if up { &e.0 } else { &e.1 };
        if seen.contains(other) { continue; }
        seen.push(other.clone());
        let (name, at) = g.nodes.iter().find(|n| n.id == *other).map_or((other.clone(), String::new()), |n| (n.name.clone(), if n.name == n.file { String::new() } else { format!("{}:{}", n.file, n.line.unwrap_or(0)) }));
        out.push((e.2.clone(), name, at));
        chain(g, other, up, depth - 1, seen, out);
    }
}

/// Items `sep` apart, wrapped between items at `w`.
fn wrap_items(items: &[String], sep: &str, w: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for it in items {
        match out.last_mut() {
            Some(l) if l.chars().count() + sep.chars().count() + it.chars().count() <= w => { l.push_str(sep); l.push_str(it); }
            _ => out.push(it.clone()),
        }
    }
    out
}

/// What a line of the detail is, for what stays pinned when it scrolls: the
/// title, a process, a search's heading, a table's header, or the notes that end them.
#[derive(Clone, Copy, PartialEq)]
enum Mark { Title, Process, Search, Header, Notes }

fn detail(app: &App, width: u16) -> Text<'static> { detail_marked(app, width).0 }

/// The detail's lines, and the marked ones by index.
fn detail_marked(app: &App, width: u16) -> (Text<'static>, Vec<(usize, Mark)>) {
    let pal = app.palette;
    let wd = width as usize;
    let mut marks: Vec<(usize, Mark)> = Vec::new();
    let mut t: Vec<Line<'static>> = Vec::new();
    let blank = Line::default;
    let title = |s: String| Line::from(Span::styled(s, pal.strong()));
    let sec = |t: &mut Vec<Line<'static>>, s: &str| { t.push(Line::default()); t.push(section(&pal, 0, s, None)); };
    let kv = |k: &str, v: Vec<Span<'static>>| kv(&pal, 0, 14, k, v);
    match app.tab {
        Tab::Traces => {
            let Some(Key::Goal(gi)) = focused(app) else { return (Text::default(), marks) };
            let Some(g) = sorted_groups(&app.p).get(gi).copied() else { return (Text::default(), marks) };
            let tone = pal.tone(goal_tone(g));
            marks.push((t.len(), Mark::Title));
            t.push(spread(vec![Span::styled(format!("{} {}", cap(&g.kind), g.title), pal.strong())], vec![Span::styled(format!("● {}", outcome_label(&g.outcome)), tone)], wd));
            if !g.about.subject.is_empty() { t.push(Line::from(Span::styled(fit(&g.about.subject, wd), pal.muted()))); }
            t.push(blank());
            t.extend(pairs(&pal, 0, &step_parts(g), wd));
            if let Some(c) = g.push.as_ref().and_then(|p| p.commit.as_deref()) { t.push(kv("Pushed commit", vec![Span::styled(short(c), pal.ink())])); }
            sec(&mut t, if g.push.is_some() { "Cost to Push" } else { "Cost" });
            let (gen, time) = goal_cost(g);
            t.extend(cost_rows(&pal, 0, gen, time, app.p.totals.rate));
            // Each bon process: its searches as a table, each search's candidates under it.
            // Narrow, Elapsed moves to the search's line below it, so the steps fit.
            let (kw, tw) = (17usize, if wd >= 60 { 8usize } else { 0 });
            let sw = wd.saturating_sub(2 + kw + tw + GEN_W + TIME_W).max(6);
            // Kernel's value: why it is unreadable, said once.
            let mut explained = false;
            let mut kernel = |k: &str| match k {
                "derived" => Some("Checked".to_string()),
                "unreadable" => Some(if std::mem::replace(&mut explained, true) { "Unreadable".into() } else { "Unreadable (older encoding)".into() }),
                _ => None,
            };
            for b in &g.processes {
                t.push(blank());
                marks.push((t.len(), Mark::Process));
                t.push(spread(vec![Span::styled(format!("Process {}", b.pid), pal.strong())], vec![Span::styled(format!("{} · {}", outcome_label(&b.outcome), ago(app.p.repo.now, b.time)), pal.muted())], wd));
                // What every search of the process shares is said once, on the process.
                let same = |f: &dyn Fn(&SearchTrace) -> String| b.searches.first().map(f).filter(|v| b.searches.iter().all(|s| f(s) == *v));
                let limit_of = |s: &SearchTrace| s.params.limit.map_or(String::new(), |l| money(Some(l)));
                let kernel_of = |s: &SearchTrace| s.kernel.clone();
                let (shared_limit, shared_kernel) = (same(&limit_of).filter(|v| !v.is_empty()), same(&kernel_of));
                let mut shared: Vec<(&str, String)> = Vec::new();
                if let Some(l) = &shared_limit { shared.push(("Limit", l.clone())); }
                if let Some(k) = shared_kernel.as_deref().and_then(&mut kernel) { shared.push(("Kernel", k)); }
                if !shared.is_empty() { t.extend(pairs(&pal, 0, &shared, wd)); }
                let mut h = vec![Span::styled(format!("  {}{}{}", fit("Search", kw), fit("Steps", sw), if tw == 0 { String::new() } else { right("Elapsed", tw) }), pal.muted())];
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
                    let elapsed = s.seconds.map_or(String::new(), took);
                    marks.push((t.len(), Mark::Search));
                    let mut row = vec![
                        Span::styled("● ", pal.tone(stone)),
                        Span::styled(fit(&format!("{} {}", s.search, cap(&s.kind)), kw), pal.ink()),
                        Span::styled(fit(&how, sw), pal.ink()),
                        Span::styled(if tw == 0 { String::new() } else { right(&elapsed, tw) }, pal.muted()),
                    ];
                    row.extend(cost_cells(&pal, s.generation, s.time_cost));
                    t.push(Line::from(row));
                    let mut facts: Vec<(&str, String)> = Vec::new();
                    if !s.params.base.is_empty() { facts.push(("Base", short(&s.params.base))); }
                    if shared_limit.is_none() { if let Some(l) = s.params.limit { facts.push(("Limit", money(Some(l)))); } }
                    if shared_kernel.is_none() { if let Some(k) = kernel(&s.kernel) { facts.push(("Kernel", k)); } }
                    if tw == 0 && !elapsed.is_empty() { facts.push(("Elapsed", elapsed.clone())); }
                    if s.running { let now = view::now_counts(s.in_flight, s.in_checks, s.waiting); if !now.is_empty() { facts.push(("Agent processes", now)); } }
                    // The search's measures: success, its spread over behaviors, its trees, its cost per verified candidate.
                    if s.time.is_some() && s.width > 0 {
                        let k = if s.kind == "foil" { foil_indices(s).len() as u64 } else { s.verified };
                        facts.push(("Success probability per agent process", format!("{:.0}% ({k} of {})", 100.0 * k as f64 / s.width as f64, s.width)));
                    }
                    if !s.behaviors.is_empty() { facts.push(("Agent processes per behavior", s.behaviors.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" · "))); }
                    if let Some(n) = s.trees.filter(|_| !s.candidates.is_empty()) { facts.push(("Distinct trees", n.to_string())); }
                    if let (Some(c), true) = (s.cost, s.verified > 0 && s.time.is_some()) { facts.push(("Cost per verified candidate", money(Some(c / s.verified as f64)))); }
                    if !facts.is_empty() { t.extend(pairs(&pal, 2, &facts, wd)); }
                    // Where its wall time went, by its slowest agent process; and summed over all of them.
                    if let Some(x) = split(s).filter(|x| x.n > 0) {
                        t.extend(pairs(&pal, 2, &[("Wall", dur(x.wall)), ("Model", dur(x.model)), ("Checks", dur(x.checks)), ("Other", dur(x.rest))], wd));
                        t.extend(hanging(&format!("By its slowest agent process, #{}; other is waiting on a slot and setup (inferred). Summed over {}: model {} · checks {}",
                            x.slowest.unwrap_or(0), plural(x.n, "agent process", "agent processes"), dur(x.model_all), dur(x.checks_all)), 2, wd, pal.faint()));
                    }
                    if let Some(d) = disagreement(s) { t.extend(hanging(&d, 2, wd, pal.tone(Tone::Red))); }
                    if s.blocked.is_some() { for l in why_blocked_in(s, &app.p.protected) { t.extend(hanging(&l, 2, wd, pal.tone(Tone::Yellow))); } }
                    // A reason the trace has no word for, on its attempt's code or compaction search:
                    // where it was inferred from, under the line it was inferred from (or the last search of the attempt).
                    let attempt = b.searches[..=k].iter().rposition(|x| !clears(&x.kind)).map(|i| &b.searches[i]);
                    let closes = s.blocked.is_some() || b.searches.get(k + 1).is_none_or(|n| !clears(&n.kind));
                    if let Some(a) = attempt.filter(|_| closes) {
                        if let (Some(r), Some(from @ ("kernel" | "sentence"))) = (a.reason.as_deref(), a.reason_from.as_deref()) {
                            let line = format!("Reason: {}, inferred from {}", r.replace('_', " "), if from == "kernel" { "the searches' words by the kernel" } else { "the trace's sentence" });
                            t.extend(hanging(&line, 2, wd, pal.tone(Tone::Yellow)));
                        }
                    }
                    // An attempt its bon process stopped in, with nothing recorded after: at its last search.
                    let last_of_attempt = b.searches.get(k + 1).is_none_or(|n| !clears(&n.kind));
                    if let Some(a) = attempt.filter(|a| last_of_attempt && a.end.as_deref() == Some("exited")) {
                        let when = if a.reason.as_deref() == Some("after_its_searches") { "after its searches reported" } else { "during this search" };
                        t.extend(hanging(&format!("Exited {when}: no transition and no error in the trace"), 2, wd, pal.tone(outcome_tone("exited"))));
                    }
                    if s.candidates.is_empty() { continue; }
                    let mut cs: Vec<&Facts> = s.candidates.iter().collect();
                    cs.sort_by_key(|c| (!c.verified, -(c.rank.unwrap_or(0)), c.diff.unwrap_or(0)));
                    if s.kind == "counterexample" {
                        // One table of every test's verdicts: trunk, the members, each foil.
                        let verdict = |v: Option<bool>| match v { Some(true) => ("Accepts", pal.ink()), Some(false) => ("Rejects", pal.ink()), None => ("—", pal.faint()) };
                        let trunk = cs.iter().any(|c| c.accepts.iter().any(|(j, _)| *j < 0));
                        let mut foils: Vec<i64> = cs.iter().flat_map(|c| c.accepts_foils.iter().map(|(j, _)| *j)).collect();
                        foils.sort(); foils.dedup();
                        let mw = 14;
                        let mut h = format!("  {}{}", fit("Test", 6), fit("Verified", 10));
                        if trunk { h += &fit("Trunk", 9); }
                        h += &fit("Members", mw);
                        for j in &foils { h += &fit(&format!("Foil #{j}"), 9); }
                        marks.push((t.len(), Mark::Header));
                        t.push(Line::from(Span::styled(h, pal.muted())));
                        for c in cs {
                            let sel = s.selected == Some(c.index);
                            let mut row = vec![
                                Span::styled(format!("  {}", fit(&format!("#{}{}", c.index, if sel { "★" } else { "" }), 6)), if sel { pal.tone(Tone::Blue) } else { pal.muted() }),
                                Span::styled(fit(if c.verified { "Yes" } else if c.accepted { "No" } else { "Rejected" }, 10), if c.verified { pal.ink() } else { pal.muted() }),
                            ];
                            if trunk { let (v, st) = verdict(c.accepts.iter().find(|(j, _)| *j < 0).map(|(_, a)| *a)); row.push(Span::styled(fit(v, 9), st)); }
                            // The members: Accepts or Rejects when all agree, else the ones it rejects.
                            let members: Vec<&(i64, bool)> = c.accepts.iter().filter(|(j, _)| *j >= 0).collect();
                            let rejected: Vec<String> = members.iter().filter(|(_, a)| !a).map(|(j, _)| format!("#{j}")).collect();
                            let (m, st) = if members.is_empty() { ("—".to_string(), pal.faint()) } else if rejected.is_empty() { ("Accepts".into(), pal.ink()) }
                                else if rejected.len() == members.len() { ("Rejects".into(), pal.ink()) } else { (format!("Rejects {}", rejected.join(" ")), pal.ink()) };
                            row.push(Span::styled(fit(&m, mw), st));
                            for j in &foils { let (v, st) = verdict(c.accepts_foils.iter().find(|(k, _)| k == j).map(|(_, a)| *a)); row.push(Span::styled(fit(v, 9), st)); }
                            t.push(Line::from(row));
                        }
                        continue;
                    }
                    let foil = s.kind == "foil";
                    // A rank every candidate shares selects nothing: said once, its column left out.
                    // Compaction's rank is −lines: shown against the base.
                    let shown = rank_shown(s);
                    if let Some(n) = rank_note(s, &shown) { t.extend(hanging(&n, 2, wd, pal.muted())); }
                    let rank_cell = |c: &Facts| match shown {
                        RankShown::Constant(_) => String::new(),
                        RankShown::Lines { base } => c.rank.map_or("—".into(), |r| signed(-r - base)),
                        RankShown::Raw => c.rank.map_or("—".into(), |r| r.to_string()),
                    };
                    let rw = if matches!(shown, RankShown::Constant(_)) { 0 } else { s.candidates.iter().map(|c| rank_cell(c).chars().count()).max().unwrap_or(0).max(4) + 2 };
                    marks.push((t.len(), Mark::Header));
                    t.push(Line::from(Span::styled(format!("  {}{}{}{}{}{}", fit("#", 4), fit("Commit", 9), fit(if foil { "Foil?" } else { "Verified" }, 11), if rw == 0 { String::new() } else { right("Rank", rw) }, right("Lines", 11), right("Gen", 8)), pal.muted())));
                    for c in cs {
                        let sel = s.selected == Some(c.index);
                        // A foil is meant to fail Verus: accepted and not proved is what it is for.
                        let (v, vs) = if foil {
                            if c.accepted && !c.proved { ("Foil", pal.ink()) } else if c.accepted { ("Not a foil", pal.muted()) } else { ("Rejected", pal.faint()) }
                        } else if c.verified { ("Yes", pal.ink()) } else if c.accepted { ("No", pal.muted()) } else { ("Rejected", pal.faint()) };
                        let lines = match (c.lines_added, c.lines_removed) { (Some(a), Some(r)) => format!("+{a} −{r}"), _ => c.diff.map_or("—".into(), |d| d.to_string()) };
                        t.push(Line::from(vec![
                            Span::styled(format!("  {}", fit(&format!("{}{}", c.index, if sel { "★" } else { "" }), 4)), if sel { pal.tone(Tone::Blue) } else { pal.muted() }),
                            Span::styled(fit(&short(c.commit.as_deref().unwrap_or("")), 9), pal.ink()),
                            Span::styled(fit(v, 11), vs),
                            Span::styled(if rw == 0 { String::new() } else { right(&rank_cell(c), rw) }, pal.ink()),
                            Span::styled(right(&lines, 11), pal.ink()),
                            Span::styled(right(&money(c.generation), 8), pal.ink()),
                            Span::styled(if c.flags.is_empty() { String::new() } else { format!("  {}", c.flags.iter().map(|f| cap(&f.replace('_', " "))).collect::<Vec<_>>().join(" · ")) }, pal.tone(Tone::Red)),
                        ]));
                    }
                }
            }
            // The searches' measures, each formula once: no search's heading or table header stays pinned over them.
            marks.push((t.len(), Mark::Notes));
            t.push(blank());
            for (k, v) in view::MEASURE_NOTES.iter().filter(|(k, _)| ["Success probability per agent process", "Agent processes per behavior", "Cost per verified candidate"].contains(k)) {
                t.extend(hanging(&format!("{k}: {v}"), 0, wd, pal.faint()));
            }
        }
        Tab::Spec => {
            let Some(spec) = &app.p.spec else { return (Text::default(), marks) };
            let g = app.p.system.clone().unwrap_or_default();
            let node = |id: &str| g.nodes.iter().find(|n| n.id == id).cloned();
            let at = |n: &projection::SpecNode| format!("{}:{}", n.file, n.line.unwrap_or(0));
            // A location, and whether it differs from trunk.
            let place = |n: &projection::SpecNode| { let mut v = vec![Span::styled(at(n), pal.faint())]; if n.changed { v.push(Span::styled(format!("   {DIFFERS} Differs from trunk"), pal.ink())); } v };
            // An expression: its label above, the expression full width under it.
            let clauses = |t: &mut Vec<Line<'static>>, label: &str, list: &[String]| {
                if list.is_empty() { return; }
                t.push(Line::from(Span::styled(label.to_string(), pal.muted())));
                for r in list { t.extend(hanging(r, 2, wd, pal.ink())); }
            };
            // A list of names: label and names on one line, wrapping under the names.
            let list = |t: &mut Vec<Line<'static>>, k: &str, v: &[String]| { if !v.is_empty() { t.extend(kv_wrap(&pal, wd, k, &v.join(" · "), pal.ink())); } };
            // A section header that says where the thing is: `Gate · src/gates.rs:458`.
            let placed = |t: &mut Vec<Line<'static>>, title: &str, n: &projection::SpecNode| {
                t.push(Line::default());
                let mut v = vec![Span::styled(title.to_string(), pal.strong()), Span::styled(format!(" · {}", at(n)), pal.faint())];
                if n.changed { v.push(Span::styled(format!("   {DIFFERS} Differs from trunk"), pal.ink())); }
                t.push(Line::from(v));
            };
            // The call graph, flat: how, what, where, in aligned columns.
            let graph = |t: &mut Vec<Line<'static>>, id: &str| {
                for (up, title, depth) in [(true, "Reached From", 4), (false, "Reaches", 3)] {
                    let mut edges = Vec::new(); chain(&g, id, up, depth, &mut vec![id.to_string()], &mut edges);
                    if edges.is_empty() { continue; }
                    t.push(Line::default()); t.push(section(&pal, 0, title, None));
                    let nw = edges.iter().map(|(_, n, _)| n.chars().count()).max().unwrap_or(0).min(28) + 2;
                    for (how, name, at) in edges { t.push(Line::from(vec![Span::styled(fit(&cap(&how), 12), pal.muted()), Span::styled(fit(&name, nw), pal.ink()), Span::styled(at, pal.faint())])); }
                }
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
                        placed(&mut t, "Gate", &gate);
                        t.push(kv("Trait", vec![Span::styled(gate.group.clone(), pal.ink())]));
                        clauses(&mut t, "Requires", &gate.requires);
                        clauses(&mut t, "Ensures", &gate.ensures);
                        if let Some(k) = node(&format!("kernel:{}", it.name)) {
                            placed(&mut t, "Implementation", &k);
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
                    let Some(tf) = g.trusted.get(ti) else { return (Text::default(), marks) };
                    t.push(spread(vec![Span::styled(tf.name.clone(), pal.strong())], vec![Span::styled("Trusted", pal.muted())], wd));
                    if let Some(d) = &tf.doc { t.extend(hanging(d, 0, wd, pal.ink())); }
                    t.push(blank());
                    let mut place = vec![Span::styled(format!("{}:{}", tf.file, tf.line), pal.faint())];
                    if tf.changed { place.push(Span::styled(format!("   {DIFFERS} Differs from trunk"), pal.ink())); }
                    t.push(kv("Defined", place));
                    let callers: Vec<&projection::SpecNode> = g.nodes.iter().filter(|n| n.trusted.contains(&tf.name)).collect();
                    if !callers.is_empty() { sec(&mut t, "Called By"); for c in callers { t.push(Line::from(vec![Span::styled(format!("{}  ", fit(&c.name, 24)), pal.ink()), Span::styled(at(c), pal.faint())])); } }
                }
                Some(Key::Sbom(k)) => {
                    let Some(sb) = &app.p.sbom else { return (Text::default(), marks) };
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
        // Project and Queue show everything in their lists: no detail.
        Tab::Project | Tab::Queue => {}
    }
    (Text::from(t), marks)
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

/// A reported search's wall time, split by its slowest agent process (the one
/// whose model session and checks took longest, inferred to be the one the
/// search waited on): that one's model session, its checks, and the rest
/// (waiting on a slot, setup, the selection; inferred), the three summing to
/// the wall time. Each from the logs' `seconds:` heads and the search's
/// recorded seconds. Also each summed over every agent process.
#[derive(Debug, PartialEq)]
struct Split { wall: f64, model: f64, checks: f64, rest: f64, slowest: Option<u64>, model_all: f64, checks_all: f64, n: usize }

fn split(s: &SearchTrace) -> Option<Split> {
    if s.time.is_none() { return None; }
    let wall = s.seconds?;
    let timed: Vec<(&Facts, f64, f64)> = s.candidates.iter().filter(|c| c.program_seconds.is_some() || c.check_seconds.is_some())
        .map(|c| (c, c.program_seconds.unwrap_or(0.0), c.check_seconds.unwrap_or(0.0))).collect();
    let slowest = timed.iter().max_by(|a, b| (a.1 + a.2).total_cmp(&(b.1 + b.2)));
    let (model, checks) = slowest.map_or((0.0, 0.0), |(_, h, c)| { let h = h.min(wall); (h, c.min(wall - h)) });
    Some(Split { wall, model, checks, rest: wall - model - checks, slowest: slowest.map(|(c, _, _)| c.index),
        model_all: timed.iter().map(|t| t.1).sum(), checks_all: timed.iter().map(|t| t.2).sum(), n: timed.len() })
}

/// The wall time of every reported search in range, split as `split` does,
/// with the time cost each part carries (each search's time cost shared by
/// its parts' seconds): [model, checks, rest] as (seconds, dollars); and the
/// bon processes' checks of trunk before their first search, which no time is
/// charged for.
fn time_split(p: &Projection) -> ([(f64, f64); 3], f64) {
    let mut out = [(0.0, 0.0); 3];
    for s in p.processes.iter().flat_map(|b| &b.searches) {
        let Some(x) = split(s) else { continue };
        let cost = s.time_cost.unwrap_or(0.0);
        for (k, part) in [x.model, x.checks, x.rest].into_iter().enumerate() {
            out[k].0 += part;
            if x.wall > 0.0 { out[k].1 += cost * part / x.wall; }
        }
    }
    (out, p.processes.iter().filter_map(|b| b.check_seconds).sum())
}

/// How a search's ranks are shown: one value every candidate has (or none
/// has), so its column is left out; compaction's, as lines against the base,
/// where every candidate's rank is −(the base's lines + added − removed), the
/// manifest's compaction rank being minus the line count; otherwise as recorded.
#[derive(Debug, PartialEq, Clone, Copy)]
enum RankShown { Constant(Option<i64>), Lines { base: i64 }, Raw }

fn rank_shown(s: &SearchTrace) -> RankShown {
    let ranks: Vec<Option<i64>> = s.candidates.iter().map(|c| c.rank).collect();
    if ranks.windows(2).all(|w| w[0] == w[1]) { return RankShown::Constant(ranks.first().copied().flatten()); }
    if s.kind == "compaction" {
        let bases: Option<Vec<i64>> = s.candidates.iter().filter(|c| c.rank.is_some())
            .map(|c| Some(-c.rank? - c.lines_added? as i64 + c.lines_removed? as i64)).collect();
        if let Some(b) = bases.filter(|b| !b.is_empty() && b.windows(2).all(|w| w[0] == w[1])) { return RankShown::Lines { base: b[0] }; }
    }
    RankShown::Raw
}

/// A count of lines with its sign: +3, −19, ±0.
fn signed(n: i64) -> String { if n > 0 { format!("+{n}") } else if n < 0 { format!("−{}", -n) } else { "±0".into() } }

/// What decided a code or compaction search's selection, against the verified
/// candidate that came next (the spec's `beats`): rank, then the smaller diff,
/// then the earlier index.
fn decided(s: &SearchTrace, shown: RankShown) -> Option<String> {
    let i = s.selected?;
    let sel = s.candidates.iter().find(|c| c.index == i)?;
    let (r, d) = (|c: &Facts| c.rank.unwrap_or(0), |c: &Facts| c.diff.unwrap_or(0));
    let next = s.candidates.iter().filter(|c| c.verified && c.index != i).min_by_key(|c| (-r(c), d(c), c.index))?;
    Some(if r(sel) != r(next) {
        match shown {
            RankShown::Lines { base } => format!("selected #{i} by fewest lines: {} against #{}'s {}", signed(-r(sel) - base), next.index, signed(-r(next) - base)),
            _ => format!("selected #{i} by rank: {} against #{}'s {}", r(sel), next.index, r(next)),
        }
    } else if d(sel) != d(next) {
        format!("selected #{i} by smallest diff: {} lines against #{}'s {}", d(sel), next.index, d(next))
    } else {
        format!("selected #{i} as the earliest: rank and diff tied with #{}", next.index)
    })
}

/// The line over a candidate table that says what its rank is and what
/// selected: `Rank 0 for every candidate; selected #2 by smallest diff: …`.
fn rank_note(s: &SearchTrace, shown: &RankShown) -> Option<String> {
    if clears(&s.kind) { return None; }
    let how = decided(s, *shown);
    let rank = match shown {
        RankShown::Constant(Some(r)) => Some(format!("Rank {r} for every candidate")),
        RankShown::Constant(None) => Some("No rank".to_string()),
        RankShown::Lines { base } => Some(format!("Rank is −lines, shown against the base's {base}{}", s.selected
            .and_then(|i| s.candidates.iter().find(|c| c.index == i)).and_then(|c| c.rank).map_or(String::new(), |r| format!(" (#{}★ raw {})", s.selected.unwrap_or(0), signed(r))))),
        RankShown::Raw => None,
    };
    match (rank, how) {
        (Some(r), Some(h)) => Some(format!("{r}; {h}")),
        (Some(r), None) => Some(r),
        (None, Some(h)) => Some(cap(&h)),
        (None, None) => None,
    }
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

/// Why a search blocked: the trace's recorded reason first; then what the
/// candidates show.
fn why_blocked_in(s: &SearchTrace, protected: &[String]) -> Vec<String> {
    let v = s.candidates.iter().filter(|c| c.verified).count();
    let mut out = Vec::new();
    if let Some(b) = s.blocked.as_deref() {
        let (word, sentence) = reason(b);
        // The trace's line as written; each test's verdicts are in the table under it.
        out.push(match word { Some(w) => format!("Blocked: {w}: {sentence}"), None => format!("Blocked: {sentence}") });
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
            out.push(format!("Disagree: {} behaviors, by agree output", gs.len()));
            for g in &gs { out.push(format!("  {}", g.iter().map(|c| format!("#{}", c.index)).collect::<Vec<_>>().join(" "))); }
            out.push("d  Compare two behaviors".into());
        }
    }
    out
}

/// Text wrapped at `width`, every line indented: at the last space that
/// fits, or inside a word longer than the line. Only the space a line breaks
/// at is dropped; every other character stays.
fn hanging(text: &str, indent: usize, width: usize, style: Style) -> Vec<Line<'static>> {
    let room = width.saturating_sub(indent).max(12);
    let mut lines = Vec::new();
    let mut rest: Vec<char> = text.trim().chars().collect();
    while rest.len() > room {
        let cut = rest[..=room].iter().rposition(|c| *c == ' ').filter(|&i| i > 0);
        let (line, skip) = match cut { Some(i) => (rest[..i].iter().collect::<String>(), i + 1), None => (rest[..room].iter().collect(), room) };
        lines.push(line);
        rest.drain(..skip);
    }
    if !rest.is_empty() { lines.push(rest.into_iter().collect()); }
    lines.into_iter().map(|l| Line::from(Span::styled(format!("{}{l}", " ".repeat(indent)), style))).collect()
}

// ── drawing ─────────────────────────────────────────────

/// The key reference `?` opens: every key, by where it applies, in the
/// key bar's words.
const KEYS: [(&str, &[(&str, &str)]); 3] = [
    ("Everywhere", &[("↑ ↓   j k", "Move"), ("g  G", "First, last"), ("⇥  ⇧⇥  1–4", "Tab"), ("⏎", "Open"), ("esc", "Close"),
        ("⇧↑ ⇧↓  PgUp PgDn", "Scroll"), ("/", "Find"), ("r", "Range"), ("t", "Light or dark"), ("?", "Keys"), ("q", "Quit")]),
    ("Traces", &[("l", "Logs"), ("d", "Compare")]),
    // Not keys: what the words of the outcome tables at the head of Traces mean.
    ("Outcomes", &view::OUTCOME_NOTES),
];

/// A key bar: each key in ink, what it does muted. Where it does not fit,
/// the lowest priority goes first.
fn key_bar(pal: &Palette, items: &[(&str, String, u8)], w: usize) -> Line<'static> {
    let mut items: Vec<(String, String, u8)> = items.iter().map(|(k, v, p)| (k.to_string(), v.clone(), *p)).collect();
    let len = |v: &Vec<(String, String, u8)>| v.iter().map(|(k, d, _)| k.chars().count() + d.chars().count() + 3).sum::<usize>() + 1;
    while len(&items) > w && items.len() > 1 {
        let low = items.iter().map(|i| i.2).min().unwrap_or(0);
        let at = items.iter().rposition(|i| i.2 == low).unwrap_or(0);
        items.remove(at);
    }
    let mut v = vec![Span::raw(" ")];
    for (k, d, _) in items { v.push(Span::styled(format!("{k} "), pal.ink().add_modifier(Modifier::BOLD))); v.push(Span::styled(format!("{d}  "), pal.muted())); }
    Line::from(v)
}

/// The overflow cue a pane shows on its first row once scrolled, and on its last
/// while rows run past the bottom.
fn more_line(pal: &Palette, up: bool) -> Line<'static> { Line::from(Span::styled(if up { " ↑ more" } else { " ↓ more" }, pal.muted())) }

/// For `len` rows in a pane `h` high from row `top`: whether the first row is
/// the up cue, and how many rows of content fit, the down cue's row left free
/// when there are more.
fn more(len: usize, h: usize, top: usize) -> (bool, usize) {
    let up = top > 0;
    let avail = h.saturating_sub(up as usize);
    (up, if top + avail < len { avail.saturating_sub(1) } else { avail })
}

/// Whether a tab shows the focused item's detail: Spec and Traces. Project and
/// Queue show everything in their lists.
fn has_detail(tab: Tab) -> bool { matches!(tab, Tab::Spec | Tab::Traces) }

/// A row under the cursor: its text in reverse video, one style, padded to `w`.
fn cursor_line(pal: &Palette, line: Line<'static>, w: usize) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = line.spans.into_iter().map(|s| Span::styled(s.content, pal.cursor())).collect();
    let n = width_of(&spans);
    if n < w { spans.push(Span::styled(" ".repeat(w - n), pal.cursor())); }
    Line::from(spans)
}

fn draw(f: &mut Frame, app: &mut App) {
    let pal = app.palette;
    let area = f.area();
    let p = &app.p;

    // Header: the repository, trunk and what is running; cost at the right:
    // generation and time, the same weight, then their total, muted. Where
    // both do not fit on one row, cost has a row of its own.
    // What runs now: the bon processes, and their running searches' agent processes by where each is.
    let running = p.processes.iter().filter(|b| b.running).count();
    let live: Vec<&SearchTrace> = p.processes.iter().filter(|b| b.running).flat_map(|b| &b.searches).filter(|s| s.running).collect();
    let sum = |f: fn(&SearchTrace) -> u64| live.iter().map(|s| f(s)).sum::<u64>();
    let now = view::now_counts(sum(|s| s.in_flight), sum(|s| s.in_checks), sum(|s| s.waiting));
    let repo = &p.repo;
    let mut left = vec![
        Span::styled(format!(" {}", repo.name.clone().unwrap_or_default()), pal.strong()),
        // Trunk as bon works on it: the remote's ref.
        Span::styled(format!(" · {}/{} · {}", repo.remote.clone().unwrap_or("origin".into()), repo.trunk.clone().unwrap_or("main".into()), short(repo.remote_head.as_deref().unwrap_or(""))), pal.muted()),
        Span::raw("   "),
    ];
    if running > 0 {
        left.push(Span::styled(format!("● Running {running}"), pal.tone(Tone::Orange)));
        if !now.is_empty() { left.push(Span::styled(format!(" · agent processes {now}"), pal.ink())); }
    } else { left.push(Span::styled("Idle", pal.muted())); }
    // What waits on engineer: the pending interrupts, which Project lists first.
    let pending = p.interrupts.iter().filter(|i| i.resolved.is_none()).count();
    if pending > 0 { left.push(Span::styled(format!("   ● Pending {pending}"), pal.tone(Tone::Yellow))); }
    let t = &p.totals;
    let cost = |gw: &str, rate: bool| {
        let mut v = vec![Span::styled(money(Some(t.generation)), pal.ink()), Span::styled(format!(" {gw} + "), pal.muted()),
            Span::styled(money(Some(t.time_cost)), pal.ink()), Span::styled(" time", pal.muted())];
        if rate && t.rate.is_some() { v.push(Span::styled(format!(" {}", at_rate(t.rate)), pal.muted())); }
        v.push(Span::styled(format!(" = {} ", money(Some(t.cost))), pal.muted()));
        v
    };
    let w = area.width as usize;
    let fits = |l: usize, r: &Vec<Span>| l + width_of(r) + 2 <= w;
    let head: Vec<Line> = match [cost("generation", true), cost("generation", false)].into_iter().find(|c| fits(width_of(&left), c)) {
        Some(c) => vec![spread(left, c, w)],
        None => {
            let c = [cost("generation", true), cost("generation", false), cost("gen", false)].into_iter().find(|c| fits(1, c)).unwrap_or_else(|| cost("gen", false));
            let mut row = vec![Span::raw(" ")]; row.extend(c);
            vec![Line::from(left), Line::from(row)]
        }
    };
    let [top, tabs, rule, body, foot] = Layout::vertical([Constraint::Length(head.len() as u16), Constraint::Length(1), Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)]).areas(area);
    f.render_widget(Paragraph::new(head), top);

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
    let detail_tab = has_detail(app.tab);
    let (list_area, detail_area) = if !detail_tab { (body, None) }
        else if wide {
            // Beside the detail the list is compact (its steps are in the detail), so the detail has room.
            let list_w = (body.width * 9 / 20).clamp(60, 66).min(body.width.saturating_sub(40));
            let [l, _, d] = Layout::horizontal([Constraint::Length(list_w), Constraint::Length(1), Constraint::Min(30)]).areas(body); (l, Some(d))
        }
        else if app.detail_open { (Rect::default(), Some(body)) } else { (body, None) };
    if wide && detail_tab {
        let x = list_area.right();
        for y in body.top()..body.bottom() { f.buffer_mut()[(x, y)].set_symbol("│").set_style(pal.rule()); }
    }
    if list_area.width > 0 { app.list_w = list_area.width; }
    let list = rows(app, app.list_w);
    let scrolls = !list.iter().any(|r| r.focusable());
    let ti = app.ti();
    // Keep the focus on a focusable row, and in view: rows below a cue it
    // shares the pane with. A list with nothing to focus scrolls, no further
    // than its last row.
    if !list.iter().any(|r| r.focusable()) {
        let h = list_area.height as usize;
        app.top[ti] = if list.len() > h { app.top[ti].min(list.len() + 1 - h) } else { 0 };
    } else {
        let mut i = app.focus[ti].min(list.len() - 1);
        if !list[i].focusable() { if let Some(j) = (i..list.len()).chain((0..i).rev()).find(|&j| list[j].focusable()) { i = j; } }
        app.focus[ti] = i;
        let h = list_area.height as usize;
        if h > 2 {
            if i < app.top[ti] { app.top[ti] = i.saturating_sub(1); }
            for _ in 0..3 {
                let (_, avail) = more(list.len(), h, app.top[ti]);
                if i >= app.top[ti] + avail { app.top[ti] = i + 1 - avail; } else { break; }
            }
        }
    }
    if list_area.width > 0 {
        let (up, avail) = more(list.len(), list_area.height as usize, app.top[ti]);
        let down = app.top[ti] + avail < list.len();
        // The cursor: the focused row and the rows that continue it, in reverse video, the list's width.
        let lw = list_area.width as usize;
        let focus = app.focus[ti];
        let covered: Vec<bool> = list.iter().enumerate().scan(false, |on, (i, r)| { *on = if r.focusable() { i == focus } else { *on && r.more }; Some(*on) }).collect();
        let mut lines: Vec<Line> = list.into_iter().enumerate().skip(app.top[ti]).take(avail).map(|(i, r)| {
            if covered[i] { cursor_line(&pal, r.line, lw) } else { r.line }
        }).collect();
        if up { lines.insert(0, more_line(&pal, true)); }
        if down { lines.push(more_line(&pal, false)); }
        f.render_widget(Paragraph::new(lines), list_area);
    }
    if let Some(d) = detail_area {
        let inner = Rect { x: d.x + 1, width: d.width.saturating_sub(2), ..d };
        let (text, marks) = detail_marked(app, inner.width);
        let lines = text.lines;
        let h = inner.height as usize;
        // Its lines are cut to the pane, so a line is a row; it scrolls no further than its last line.
        let s = (app.detail_top as usize).min(lines.len().saturating_sub(1));
        if !lines.is_empty() { app.detail_top = s as u16; }
        // Scrolled, the title, the process above, its search and a table's header whose
        // rows continue stay at the top: each while what it heads is on screen.
        let last = |m: Mark| marks.iter().rev().find(|(i, k)| *k == m && *i < s).map(|(i, _)| *i);
        let open = |at: usize, ends: &[Mark]| !marks.iter().any(|(i, k)| *i > at && *i <= s && ends.contains(k));
        let mut pins: Vec<usize> = Vec::new();
        if s > 0 {
            if let Some(i) = last(Mark::Title) { pins.push(i); }
            if let Some(i) = last(Mark::Process) { pins.push(i); }
            if let Some(i) = last(Mark::Search).filter(|&i| open(i, &[Mark::Process, Mark::Search, Mark::Notes])) { pins.push(i); }
            if let Some(i) = last(Mark::Header).filter(|&i| open(i, &[Mark::Process, Mark::Search, Mark::Notes])) { pins.push(i); }
            pins.retain(|i| *i < s);
            pins.dedup();
        }
        let up = s > 0;
        let room = h.saturating_sub(pins.len() + up as usize);
        let down = s + room < lines.len();
        let room = room.saturating_sub(down as usize);
        let mut shown: Vec<Line> = Vec::new();
        if up { shown.push(more_line(&pal, true)); }
        shown.extend(pins.iter().map(|i| lines[*i].clone()));
        shown.extend(lines.into_iter().skip(s).take(room));
        if down { shown.push(more_line(&pal, false)); }
        f.render_widget(Paragraph::new(shown), inner);
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
                let l = Line::from(Span::styled(format!(" {}", fit(label, body.width as usize - 1)), pal.ink()));
                lines.push(if i == *sel { cursor_line(&pal, l, body.width as usize) } else { l });
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
    else if let Some(buf) = &app.input { let mut l = vec![Span::styled(" Find  ", pal.muted()), Span::styled(format!("{buf}▏   "), pal.ink())]; l.extend(key_bar(&pal, &[("⏎", "Apply".into(), 1), ("esc", "Cancel".into(), 1)], fw).spans); Line::from(l) }
    else {
        // The same words as the key reference; the detail's keys where a detail shows.
        let shown = detail_tab && (wide || app.detail_open);
        let items: Vec<(&str, String, u8)> = match &app.overlay {
            Overlay::Logs { .. } => vec![("↑↓", "Move".into(), 3), ("⏎", "Open".into(), 3), ("esc", "Close".into(), 3)],
            Overlay::Text { .. } | Overlay::Compare { .. } => vec![("↑↓", "Scroll".into(), 3), ("PgUp PgDn", "Scroll".into(), 2), ("esc", "Close".into(), 3)],
            Overlay::None => {
                // Narrow, what the open detail binds outranks what ? lists anyway.
                let mut v: Vec<(&str, String, u8)> = vec![("↑↓", if scrolls { "Scroll" } else { "Move" }.into(), 5)];
                if detail_tab && !wide { v.push(if app.detail_open { ("esc", "Close".into(), 9) } else { ("⏎", "Open".into(), 9) }); }
                if shown { v.push(("⇧↑↓", "Scroll".into(), 8)); }
                if shown && app.tab == Tab::Traces { v.push(("l", "Logs".into(), 7)); v.push(("d", "Compare".into(), 7)); }
                v.push(("⇥", "Tab".into(), 3));
                v.push(("/", filter.find.as_deref().map_or("Find".to_string(), |f| format!("Find: {f}")), 4));
                v.push(("r", if app.range == 0 { "Range".to_string() } else { format!("Range: {}", RANGES[app.range].0) }, 2));
                v.push(("?", "Keys".into(), 6));
                v.push(("q", "Quit".into(), 9));
                v
            }
        };
        key_bar(&pal, &items, fw)
    };
    f.render_widget(Paragraph::new(foot_line), foot);

    if app.keys {
        let kw = 20;
        let n: usize = KEYS.iter().map(|(_, ks)| ks.len() + 2).sum::<usize>() + 1;
        let w = 72.min(area.width); let h = (n as u16 + 2).min(area.height);
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
    let mut t = ratatui::Terminal::new(TestBackend::new(w, h)).map_err(|e| e.to_string())?;
    // A first draw sets the list's width; the focus is a row at that width.
    t.draw(|f| draw(f, &mut app)).map_err(|e| e.to_string())?;
    if let Some((i, _)) = rows(&app, app.list_w).iter().enumerate().filter(|(_, r)| r.focusable()).nth(focus) { app.focus[app.ti()] = i; }
    t.draw(|f| draw(f, &mut app)).map_err(|e| e.to_string())?;
    Ok(frame_html(t.backend().buffer(), light))
}

/// A drawn buffer as a self-contained HTML page.
fn frame_html(b: &ratatui::buffer::Buffer, light: bool) -> String {
    let (w, h) = (b.area.width, b.area.height);
    let (bg, ink) = if light { ("#F3EDE0", "#1B1A18") } else { ("#09090A", "#EDEAE5") };
    let mut out = format!("<!doctype html><meta charset=utf-8><body style=\"margin:0;background:{bg};color:{ink};padding:14px 16px\"><pre style=\"margin:0;font:14px/1.45 Menlo,SFMono-Regular,monospace\">");
    for y in 0..h {
        for x in 0..w {
            let c = &b[(x, y)];
            let mut style = String::new();
            // Reverse video swaps the cell's colors; an unset one is the page's.
            let (fg, bgc) = if c.modifier.contains(Modifier::REVERSED) { (css(c.bg).or(Some(bg.to_string())), css(c.fg).or(Some(ink.to_string()))) } else { (css(c.fg), css(c.bg)) };
            if let Some(fg) = fg { style += &format!("color:{fg};"); }
            if let Some(bgc) = bgc { style += &format!("background:{bgc};"); }
            if c.modifier.contains(Modifier::BOLD) { style += "font-weight:700;"; }
            if c.modifier.contains(Modifier::UNDERLINED) { style += "text-decoration:underline;"; }
            let sym = c.symbol().replace('&', "&amp;").replace('<', "&lt;");
            if style.is_empty() { out += &sym; } else { out += &format!("<span style=\"{style}\">{sym}</span>"); }
        }
        out.push('\n');
    }
    out += "</pre></body>";
    out
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
        let list = rows(app, app.list_w);
        // A list with nothing to focus (Project) scrolls instead.
        if !list.iter().any(|r| r.focusable()) { app.top[ti] = if down { app.top[ti] + 1 } else { app.top[ti].saturating_sub(1) }; return; }
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
                        items.push((format!("Process {} · Search {} · #{} · {l}", b.pid, s.search, c.index), app.root.join(".bon/traces").join(&b.trace).join(s.search.to_string()).join(c.index.to_string()).join(l)));
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
            let steps_shown = if w < 100 { "8→7→#1 · None found" } else { "Candidates 8 · Verified 7 · Selected #1" };
            assert!(traces.contains("Pushed") && traces.contains(steps_shown), "{traces}");
            assert!(screen(p.clone(), Tab::Queue, w, h).contains("Each trace records"));
            assert!(screen(p.clone(), Tab::Spec, w, h).contains("verified"));
            // Cost is generation and time side by side, then the total; never a lone total.
            let project = screen(p.clone(), Tab::Project, w, h);
            assert!(project.contains("$2.00") && project.contains("$8.00") && project.contains("$10.00"), "{project}");
            // Per push shows its basis: what reached a push, over how many.
            assert!(project.contains("Reached a push") && project.contains("Pushes") && project.contains("Per push"), "{project}");
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
        assert_eq!(w[0], "Blocked: fewer than two verified candidates, or they disagree");
        assert!(w[1] == "Disagree: 2 behaviors, by agree output" && w[2].trim() == "#0 #2" && w[3].trim() == "#1", "{w:?}");
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
        assert!(q.find("Proposed").unwrap() < q.find("Queued").unwrap() && q.contains("New 1  Contested 1") && q.contains("#7"), "{q}");
        let sp = screen(p.clone(), Tab::Spec, 140, 30);
        assert!(sp.contains("may_open") && sp.contains("Gate  Implementation") && sp.contains("✓     ✓") && sp.contains("✓ Present"), "{sp}");
        // The gate's section says where it is; its expression sits under its label.
        assert!(sp.contains("Gate · k/rules.rs:0") && sp.contains("Ensures") && sp.contains("  r == spec::may_open(locked)"), "{sp}");
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
    fn foils_show_in_the_steps_and_why_blocked_leads_with_the_trace() {
        let g = foiled();
        // Accepted and not proved is a foil: 2 of the 3; one test of 2 rejects one.
        assert_eq!(steps(&g, false), "Candidates 2 · Verified 2 · Selected #1 · Foils 2 · Counterexample 1 of 2 verified tests reject a foil, 2 needed");
        assert_eq!(why_blocked(&g.processes[0].searches[2]), ["Blocked: undiscriminating: fewer than two verified tests reject a foil"]);
    }

    fn traces_of(g: GoalTrace) -> String {
        let mut p: Projection = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        p.groups = vec![g];
        screen(p, Tab::Traces, 140, 80)
    }

    #[test]
    fn a_counterexample_search_shows_one_table_of_its_tests_verdicts() {
        let d = traces_of(foiled());
        assert!(d.contains("Foil?") && d.contains("Not a foil"), "{d}");
        // Trunk, the members, then each foil: Accepts or Rejects.
        assert!(d.contains("Test  Verified  Trunk    Members       Foil #0  Foil #1"), "{d}");
        assert!(d.contains("#0    Yes       Rejects  Accepts       Accepts  Accepts"), "{d}");
        assert!(d.contains("#1    Yes       Rejects  Accepts       Rejects  Rejects"), "{d}");
        // No verdict is —; members it rejects are named.
        let mut g = foiled();
        let tests = &mut g.processes[0].searches[2].candidates;
        tests[0].accepts_foils.clear();
        tests[1].accepts = vec![(0, true), (1, false)];
        let d = traces_of(g);
        assert!(d.contains("#0    Yes       Rejects  Accepts       —        —"), "{d}");
        assert!(d.contains("#1    Yes       —        Rejects #1    Rejects  Rejects"), "{d}");
    }

    #[test]
    fn a_scrolled_detail_keeps_the_title_and_process_at_the_top() {
        let mut app = App::new();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        app.p.groups = vec![foiled()];
        // Scrolled into the counterexample search's table: the cue, the title, the process,
        // the search's heading and the table's header, then its rows.
        let mut t = Terminal::new(TestBackend::new(140, 30)).unwrap();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let lines = detail_marked(&app, 140 - 63 - 1 - 2).0.lines;
        let at = lines.iter().position(|l| l.spans.iter().any(|s| s.content.starts_with("  #1 "))).unwrap();
        app.detail_top = at as u16;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let b = t.backend().buffer().clone();
        let row = |y: u16| (63..140).map(|x| b[(x, y)].symbol().to_string()).collect::<String>();
        let top: Vec<String> = (3..9).map(row).collect();
        assert!(top[0].contains("↑ more") && top[1].contains("Code from 9bb8a5b") && top[2].contains("Process 7")
            && top[3].contains("2 Counterexample") && top[4].contains("Test  Verified") && top[5].contains("#1"), "{top:#?}");
        // Scrolled past it to the end, no search is pinned whose rows are gone.
        app.detail_top = u16::MAX;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let b = t.backend().buffer().clone();
        let all: String = (3..29).map(|y| (63..140).map(|x| b[(x, y)].symbol().to_string()).collect::<String>() + "\n").collect();
        assert!(!all.contains("Test  Verified") || all.contains("#1    Yes"), "{all}");
    }

    #[test]
    fn a_pane_says_when_it_has_more() {
        let mut p: Projection = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        p.queue = Some((1..40).map(|i| serde_json::from_value(serde_json::json!({ "id": i, "intent": "x" })).unwrap()).collect());
        let q = screen(p, Tab::Queue, 80, 20);
        assert!(q.contains("↓ more") && !q.contains("↑ more"), "{q}");
    }

    #[test]
    fn the_steps_are_the_attempt_that_ended_the_goal() {
        // Two attempts: the first blocked on its foils, the second pushed #6.
        let ce = |blocked: bool| serde_json::json!({ "kind": "counterexample", "width": 2, "returned": 2, "verified": 2,
            "blocked": if blocked { serde_json::json!("blocked: undiscriminating: fewer than two verified tests reject a foil") } else { serde_json::Value::Null } });
        let foil = serde_json::json!({ "kind": "foil", "width": 2, "returned": 2, "candidates": [{ "index": 0, "accepted": true }, { "index": 1, "accepted": true }] });
        let g: GoalTrace = serde_json::from_value(serde_json::json!({ "kind": "code", "title": "from 9bb8a5b", "outcome": "pushed",
            "push": { "commit": "0b1e1a5aa9" },
            "processes": [{ "pid": 1, "outcome": "pushed", "searches": [
                { "search": 0, "kind": "code", "width": 8, "returned": 8, "verified": 8, "selected": 2 }, foil, ce(true),
                { "search": 3, "kind": "code", "width": 12, "returned": 12, "verified": 12, "selected": 6 }, foil, ce(false)] }] })).unwrap();
        // The detail's steps say which attempt they are; the list's are short.
        assert_eq!(steps(&g, false), "Attempt 2 of 2 (search 3) · Candidates 12 · Verified 12 · Selected #6 · Foils 2 · Counterexample None found");
        assert_eq!(steps(&g, true), "12→12→#6 · 2 foils · None found · 0b1e1a5");
    }

    fn ranked(kind: &str, selected: u64, cs: &[(i64, u64, u64, u64)]) -> SearchTrace {
        serde_json::from_value(serde_json::json!({ "kind": kind, "selected": selected, "candidates": cs.iter().enumerate().map(|(i, (rank, diff, added, removed))|
            serde_json::json!({ "index": i, "accepted": true, "verified": true, "rank": rank, "diff": diff, "lines_added": added, "lines_removed": removed })).collect::<Vec<_>>() })).unwrap()
    }

    #[test]
    fn a_rank_every_candidate_shares_is_said_once_with_what_selected() {
        // Code's rank is echo 0: the smallest diff selects.
        let s = ranked("code", 1, &[(0, 159, 150, 9), (0, 154, 150, 4), (0, 155, 150, 5)]);
        assert_eq!(rank_shown(&s), RankShown::Constant(Some(0)));
        assert_eq!(rank_note(&s, &rank_shown(&s)).unwrap(), "Rank 0 for every candidate; selected #1 by smallest diff: 154 lines against #2's 155");
        // Tied on both: the earliest.
        let s = ranked("code", 0, &[(0, 9, 5, 4), (0, 9, 5, 4)]);
        assert!(rank_note(&s, &rank_shown(&s)).unwrap().ends_with("selected #0 as the earliest: rank and diff tied with #1"));
        // A foil's rank selects nothing and is not noted.
        assert!(rank_note(&ranked("foil", 0, &[(0, 2, 1, 1), (0, 2, 1, 1)]), &RankShown::Constant(Some(0))).is_none());
    }

    #[test]
    fn a_compaction_rank_reads_as_lines_against_the_base() {
        // Rank is −(lines): 11376 at the base, −19 for +28 −47.
        let s = ranked("compaction", 0, &[(-11357, 75, 28, 47), (-11372, 14, 5, 9)]);
        assert_eq!(rank_shown(&s), RankShown::Lines { base: 11376 });
        assert_eq!(rank_note(&s, &rank_shown(&s)).unwrap(), "Rank is −lines, shown against the base's 11376 (#0★ raw −11357); selected #0 by fewest lines: −19 against #1's −4");
        // Ranks that are not −lines of one base stay as recorded.
        assert_eq!(rank_shown(&ranked("compaction", 0, &[(-5, 1, 1, 0), (-100, 1, 1, 0)])), RankShown::Raw);
    }

    #[test]
    fn a_searchs_wall_time_splits_by_its_slowest_agent_process() {
        let s: SearchTrace = serde_json::from_value(serde_json::json!({ "kind": "code", "time": 1, "seconds": 600.0, "time_cost": 20.0, "candidates": [
            { "index": 0, "program_seconds": 300.0, "check_seconds": 100.0 }, { "index": 1, "program_seconds": 420.0, "check_seconds": 120.0 }, { "index": 2 }] })).unwrap();
        let x = split(&s).unwrap();
        assert_eq!((x.model, x.checks, x.rest, x.slowest, x.model_all, x.checks_all, x.n), (420.0, 120.0, 60.0, Some(1), 720.0, 220.0, 2));
        // The parts sum to the wall time, never past it; a search that has not reported has none.
        let mut long = s.clone(); long.seconds = Some(500.0);
        let y = split(&long).unwrap();
        assert_eq!(y.model + y.checks + y.rest, 500.0);
        assert!(y.rest >= 0.0);
        let mut running = s.clone(); running.time = None;
        assert!(split(&running).is_none());
        // Summed over a projection, each part carries its share of the time cost.
        let mut p = Projection::default();
        p.processes = vec![serde_json::from_value(serde_json::json!({ "pid": 1, "check_seconds": 30.0 })).unwrap()];
        p.processes[0].searches = vec![s];
        let (parts, trunk) = time_split(&p);
        assert_eq!((parts[0], parts[1], parts[2], trunk), ((420.0, 14.0), (120.0, 4.0), (60.0, 2.0), 30.0));
        assert_eq!(dur(468.0), "7m48s");
        assert_eq!(dur(31.0 * 3600.0 + 300.0), "31h05m");
    }

    #[test]
    fn an_expression_wraps_and_keeps_every_character() {
        let e = "r matches Some(i) ==> spec::found_on_trunk(counterexample@, i as int)&&a_very_long_word_with_no_space_at_all";
        let ls = hanging(e, 2, 30, Style::new());
        let text: Vec<String> = ls.iter().map(|l| l.spans[0].content.to_string()).collect();
        assert!(text.iter().all(|l| l.chars().count() <= 30 && l.starts_with("  ")), "{text:?}");
        assert_eq!(text.iter().map(|l| l[2..].to_string()).collect::<Vec<_>>().join(" ").replace(' ', ""), e.replace(' ', ""));
    }

    #[test]
    fn reasons_are_words_with_their_counts() {
        assert_eq!(view::reason_count(&projection::Reason { reason: "too_few_verified".into(), count: 1, ..Default::default() }), "Too few verified (1)");
        assert_eq!(view::reason_count(&projection::Reason { reason: "too_few_tests".into(), count: 5, inferred: 5, ..Default::default() }), "Too few tests (5, 5 inferred)");
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

    /// The buffer of one draw of `app` at w×h.
    fn buffer(app: &mut App, w: u16, h: u16) -> ratatui::buffer::Buffer {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        t.backend().buffer().clone()
    }

    /// Every color a tone can be drawn in, light and dark.
    fn tone_colors(tone: Tone) -> [Color; 2] { [DARK.mix(DARK.tones[tone as usize]), LIGHT.mix(LIGHT.tones[tone as usize])] }

    #[test]
    fn the_cursor_is_reverse_video_and_no_color() {
        let mut app = App::new();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        app.p.groups = vec![foiled()];
        app.tab = Tab::Traces;
        let b = buffer(&mut app, 140, 30);
        // The focused goal's row, the list's width, in reverse video; no cell anywhere is blue but a selection's.
        let row = (0..30).find(|&y| b[(1, y)].modifier.contains(Modifier::REVERSED)).expect("a reversed row");
        assert!((0..60).all(|x| b[(x, row)].modifier.contains(Modifier::REVERSED)));
        assert!((0..63).all(|x| b[(x, row)].fg == rgb(DARK.ink)), "one style under the cursor");
        assert!(!(0..30).any(|y| (0..140).any(|x| b[(x, y)].symbol() == "▎")));
        // Queue's focused intent and its continuation lines are under it too.
        let mut q = App::new();
        q.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 },
            "queue": [{ "id": 7, "intent": "word ".repeat(40) }, { "id": 8, "intent": "next" }] })).unwrap();
        q.tab = Tab::Queue;
        let b = buffer(&mut q, 80, 20);
        let reversed: Vec<u16> = (0..20).filter(|&y| b[(0, y)].modifier.contains(Modifier::REVERSED)).collect();
        assert_eq!(reversed, vec![3, 4, 5], "#7's three lines");
        // The frame's HTML draws reverse video as swapped colors.
        assert!(frame_html(&b, false).contains("color:#09090A;background:#edeae5"));
    }

    #[test]
    fn a_goal_the_kernel_disagrees_on_is_red_in_its_list_and_its_detail() {
        let mut g = foiled();
        g.processes[0].searches[0].kernel = "derived".into();
        g.processes[0].searches[0].recorded_selected = Some(0);
        assert!(matches!(goal_tone(&g), Tone::Red));
        let mut app = App::new();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        app.p.groups = vec![g];
        app.tab = Tab::Traces;
        let b = buffer(&mut app, 140, 30);
        // The detail's title line: its ● outcome in red, as the list's dot (under the cursor) would be.
        let title = (0..30).find(|&y| (63..140).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().contains("Code from 9bb8a5b")).unwrap();
        let dot = (63..140).find(|&x| b[(x, title)].symbol() == "●").unwrap();
        assert!(tone_colors(Tone::Red).contains(&b[(dot, title)].fg));
    }

    #[test]
    fn where_it_went_shows_each_outcome_in_its_own_tone() {
        let mut app = App::new();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 },
            "groups": [{ "kind": "code", "outcome": "blocked", "generation": 1.0, "time_cost": 1.0 },
                       { "kind": "code", "outcome": "exited", "generation": 1.0, "time_cost": 1.0 },
                       { "kind": "counterexample", "outcome": "not found", "generation": 1.0, "time_cost": 1.0 }] })).unwrap();
        app.tab = Tab::Project;
        let b = buffer(&mut app, 120, 60);
        let line = |label: &str| (0..60).find(|&y| (0..120).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().starts_with(&format!("   {label} "))).unwrap();
        let bar = |y: u16| (0..120).find(|&x| matches!(b[(x, y)].symbol(), "█" | "▒")).map(|x| b[(x, y)].fg).unwrap();
        // Blocked is yellow, as everywhere else; exited red; none found indigo. No row says No push.
        assert!(tone_colors(Tone::Yellow).contains(&bar(line("Blocked"))));
        assert!(tone_colors(Tone::Red).contains(&bar(line("Exited"))));
        assert!(tone_colors(Tone::Indigo).contains(&bar(line("None found"))));
        assert!(!(0..60).any(|y| (0..120).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().contains("No push")));
    }

    #[test]
    fn an_item_that_differs_from_trunk_is_marked_not_colored() {
        let p: Projection = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 1 },
            "spec": { "path": "k/model.rs", "items": [{ "kind": "predicate", "name": "may_open", "doc": "A door opens." }, { "kind": "predicate", "name": "may_close", "doc": "It closes." }] },
            "system": { "nodes": [{ "id": "spec:may_open", "name": "may_open", "file": "k/model.rs", "changed": true }, { "id": "spec:may_close", "name": "may_close", "file": "k/model.rs" }] }
        })).unwrap();
        let sp = screen(p.clone(), Tab::Spec, 140, 30);
        assert!(sp.contains("≠ Differs from trunk 1") && sp.contains(" ≠ may_open") && sp.contains("   may_close"), "{sp}");
        // The detail says so in ink, with the mark.
        let mut app = App::new();
        app.p = p; app.tab = Tab::Spec;
        let b = buffer(&mut app, 140, 30);
        let y = (0..30).find(|&y| (63..140).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().contains("≠ Differs from trunk")).unwrap();
        let x = (63..140).find(|&x| b[(x, y)].symbol() == "≠").unwrap();
        assert_eq!(b[(x, y)].fg, rgb(DARK.ink));
    }

    #[test]
    fn the_header_says_what_runs_now_and_trunk_as_the_remotes() {
        let mut app = App::new();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true,
            "repo": { "name": "r", "trunk": "main", "remote": "origin", "head": "1111111aaa", "remote_head": "2222222bbb", "now": 10 },
            "processes": [{ "pid": 1, "running": true, "searches": [{ "kind": "code", "running": true, "in_flight": 5, "in_checks": 2, "waiting": 1 }] }] })).unwrap();
        let b = buffer(&mut app, 160, 10);
        let head: String = (0..160).map(|x| b[(x, 0)].symbol().to_string()).collect();
        assert!(head.contains("origin/main · 2222222") && head.contains("● Running 1 · agent processes 5 in flight, 2 in checks, 1 waiting"), "{head}");
        assert!(!head.contains("1111111"));
    }

    #[test]
    fn project_scrolls_and_a_counterexample_says_how_many_tests_ran() {
        let mut app = App::new();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        app.tab = Tab::Project;
        let k = |c: KeyCode| KeyEvent::new(c, KeyModifiers::NONE);
        key(&mut app, k(KeyCode::Down));
        assert_eq!(app.top[0], 1);
        // Drawn, it is held to the last row: nothing past it.
        buffer(&mut app, 80, 200);
        assert_eq!(app.top[0], 0);
        let ce: SearchTrace = serde_json::from_value(serde_json::json!({ "kind": "counterexample", "width": 4, "returned": 4, "verified": 1 })).unwrap();
        let mut g = foiled();
        g.processes[0].searches[2] = ce;
        assert!(steps(&g, false).ends_with("Counterexample 1 of 4 tests verified, 2 needed"), "{}", steps(&g, false));
    }
}
