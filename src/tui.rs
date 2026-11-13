//! `bon` in a terminal: the projection as four tabs, Project, Spec, Queue and
//! Traces, each a list with the focused item's detail beside it (or, under
//! 100 columns, opened on ⏎). Outside every repository it is the host
//! (`host.rs`): what is pending across repositories, what runs against the
//! host's pools, memory, the journal and each repository; in a repository,
//! Project shows that repository's part of the same. Trusted code. It reads
//! only the projections and the files they name; it decides nothing.
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
use ratatui::widgets::Paragraph;
use ratatui::{DefaultTerminal, Frame};

use crate::projection::{self, BonProcess, Facts, GoalTrace, Projection, SearchTrace};
use crate::view::{self, ago, cap, count, dur, money_or as money, outcome_label, short, signed, size};

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
///   (killed, over limit, price mismatch, and the exit of a program that never
///   started); an error reading the projection, in the footer.
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

// ── layout ──────────────────────────────────────────────
//
// Every value is written by `view`'s formats; these only place it: in a
// column (fit, right), at both ends of a line (spread), wrapped under itself
// (hanging), or as labeled pairs that wrap (pairs). Nothing is cut without …,
// and text that matters wraps.

/// The rate time is charged at, next to time; nothing when there is none.
fn at_rate(r: Option<f64>) -> String { r.filter(|r| *r > 0.0).map_or(String::new(), |r| format!("at ${r:.0}/h")) }

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
    view::date(d.max(0) as u64 * 86400)
}

/// Pad or cut to exactly `w` columns.
fn fit(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n > w { let mut t: String = s.chars().take(w.saturating_sub(1)).collect(); if w > 0 { t.push('…'); } t } else { format!("{s}{}", " ".repeat(w - n)) }
}
/// Cut to at most `w` columns, with … where it is cut.
fn cut(s: &str, w: usize) -> String { if s.chars().count() > w { fit(s, w) } else { s.to_string() } }

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

/// The tabs of a repository; outside every repository, the host is the one
/// tab (queue 60), and no repository's tabs show.
#[derive(Clone, Copy, PartialEq)]
enum Tab { Project, Spec, Queue, Traces, Host }
const TABS: [Tab; 4] = [Tab::Project, Tab::Spec, Tab::Queue, Tab::Traces];

/// What a focusable row stands for, by the item's identity, never its
/// position: the cursor stays on it when rows come, go or rewrap. A goal is
/// its first bon process's trace; an intent its id; a spec item, a trusted
/// function or a proposal its name.
#[derive(Clone, PartialEq, Debug)]
enum Key { Goal(String), Queue(u64), Retired(u64), Proposal(String), Item(String), Grid, Trusted(String), Sbom(&'static str) }

/// A goal's identity: its bon processes' traces, first first; it is the same
/// goal while any of them is (`same`), so a filter that leaves one out keeps it.
fn goal_key(g: &GoalTrace) -> Key { Key::Goal(g.processes.iter().rev().map(|p| p.trace.as_str()).collect::<Vec<_>>().join(" ")) }

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
    /// When the projection was first read: before it, nothing is shown as if read.
    loaded: Option<Instant>,
    /// The host as it shows here: this repository's part of it, or, outside
    /// every repository (`root` empty), all of it.
    host: projection::Host,
    root: std::path::PathBuf,
    overlay: Overlay,
    /// Text being typed after /, for find.
    input: Option<String>,
    range: usize,
    filter: std::sync::Arc<std::sync::Mutex<view::Filter>>,
    error: Option<String>,
    tab: Tab,
    /// Per tab: the focused item, the row it was last drawn on, and the first visible row.
    held: [Option<Key>; 4],
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
    /// The list's width and the panes' heights when last drawn: rows wrap by
    /// width, and a page is a pane's height.
    list_w: u16,
    list_h: u16,
    detail_h: u16,
    /// Whether a detail showed when last drawn: ⇧↑↓ and PgUp PgDn scroll it, else the list.
    detail_shown: bool,
    /// Rows a page of the detail shows, and of an overlay, when last drawn; an overlay's rows once wrapped.
    detail_page: u16,
    body_h: u16,
    /// The first row of the key reference shown, where it does not fit.
    keys_top: usize,
    /// Whether the list was last scrolled through its rows rather than moved between items.
    scrolled: bool,
    overlay_rows: usize,
    /// The host drawn as two panes (100 columns and wider): what happened on the right.
    split: bool,
}

impl App {
    fn new() -> App {
        let dark = std::env::var("BON_THEME").map_or(true, |t| t != "light");
        App { p: Projection::default(), loaded: None, host: Default::default(), root: ".".into(), overlay: Overlay::None, input: None, range: 0, filter: Default::default(),
              error: None, tab: Tab::Traces, held: Default::default(), focus: [0; 4], top: [0; 4], detail_top: 0, detail_open: false,
              keys: false, palette: if dark { DARK } else { LIGHT }, dark, off: local_offset(), list_w: 200, list_h: 20, detail_h: 20, detail_shown: false, detail_page: 18, body_h: 20, keys_top: 0, scrolled: false, overlay_rows: 0, split: false }
    }
    fn ti(&self) -> usize { TABS.iter().position(|t| *t == self.tab).unwrap_or(0) }
    /// Focus row `i` of `list`, and its item; a new focus opens its detail at the top.
    fn focus_on(&mut self, list: &[Row], i: usize) {
        let ti = self.ti();
        let key = list.get(i).and_then(|r| r.key.clone());
        // Another item opens at its top; the same one (a goal that gained a bon process) stays where it was read to.
        if !matches!((&key, &self.held[ti]), (Some(a), Some(b)) if same(&self.p, a, b)) { self.detail_top = 0; }
        self.focus[ti] = i;
        self.held[ti] = key;
    }
    /// Switch tab; an open detail closes, so a tab opens on its list. The
    /// host has one tab: there is nothing to switch to.
    fn switch(&mut self, tab: Tab) { if self.tab == Tab::Host { return; } self.tab = tab; self.detail_top = 0; self.detail_open = false; }
}

// ── the visual hierarchy ────────────────────────────────
//
// Three kinds of text, one style each: a section header (Title Case, strong),
// a label (sentence case, muted; what a measure's words mean is a label too)
// and a value (the data, ink). Faint is for what only locates a value (a
// path, a line number, a commit beside an intent).

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
/// where the line is full; a pair longer than a line wraps at its words, under
/// its value.
fn pairs(pal: &Palette, indent: usize, items: &[(&str, String)], w: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut v = vec![Span::raw(" ".repeat(indent))];
    for (k, val) in items {
        let n = k.chars().count() + 1 + val.chars().count();
        if v.len() > 1 && width_of(&v) + 3 + n > w { out.push(Line::from(std::mem::replace(&mut v, vec![Span::raw(" ".repeat(indent))]))); }
        if v.len() > 1 { v.push(Span::styled(" · ", pal.faint())); }
        let at = width_of(&v) + k.chars().count() + 1;
        if at + val.chars().count().min(8) > w {
            // Its label leaves no room: label and value wrap together, under the label.
            if v.len() > 1 { v.pop(); out.push(Line::from(std::mem::replace(&mut v, vec![Span::raw(" ".repeat(indent))]))); }
            // How much of the label is left to show, line by line, so all of it stays muted.
            let mut label_left = k.chars().count();
            for (j, l) in hanging(&format!("{k} {val}"), indent + 2, w, pal.ink()).into_iter().enumerate() {
                let body: String = l.spans[0].content.chars().skip(indent + 2).collect();
                let kn = label_left.min(body.chars().count());
                label_left = label_left.saturating_sub(kn + 1);
                let (label, value): (String, String) = (body.chars().take(kn).collect(), body.chars().skip(kn).collect());
                out.push(Line::from(vec![Span::raw(" ".repeat(if j == 0 { indent } else { indent + 2 })), Span::styled(label, pal.muted()), Span::styled(value, pal.ink())]));
            }
            continue;
        }
        v.push(Span::styled(format!("{k} "), pal.muted()));
        if at + val.chars().count() <= w { v.push(Span::styled(val.clone(), pal.ink())); continue; }
        // Too long for what is left of the line: its value wraps under itself.
        let hang = if w.saturating_sub(at) >= 16 { at } else { indent + 2 };
        let lines = hanging(val, hang, w, pal.ink());
        let mut lines = lines.into_iter();
        if hang == at {
            if let Some(first) = lines.next() { v.push(Span::styled(first.spans[0].content.chars().skip(hang).collect::<String>(), pal.ink())); }
        }
        out.push(Line::from(std::mem::replace(&mut v, vec![Span::raw(" ".repeat(indent))])));
        out.extend(lines);
    }
    if v.len() > 1 { out.push(Line::from(v)); }
    out
}

/// A line no wider than `w`: one that is wider is cut, and ends in ….
fn clip(line: Line<'static>, w: usize) -> Line<'static> {
    if width_of(&line.spans) <= w { return line; }
    let mut left = w.saturating_sub(1);
    let mut spans = Vec::new();
    for s in line.spans {
        if left == 0 { break; }
        let n = s.content.chars().count();
        let text: String = s.content.chars().take(left).collect();
        left -= n.min(left);
        spans.push(Span::styled(text, s.style));
    }
    let style = spans.last().map_or(Style::new(), |s: &Span| s.style);
    spans.push(Span::styled("…", style));
    Line::from(spans)
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
            _ if ce.verified < 2 => format!("{} of {} verified, 2 needed", ce.verified, count(ce.width.max(ce.returned) as usize, "test", "tests")),
            (_, Some(d)) if d < 2 => format!("{d} of {} reject a foil, 2 needed", count(ce.verified as usize, "verified test", "verified tests")),
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
    if g.kind == "counterexample" { return get("Verified tests").map_or(String::new(), |v| count(v.parse().unwrap_or(0), "verified test", "verified tests")); }
    let head = ["Candidates", "Verified", "Selected"].iter().filter_map(|k| get(k)).collect::<Vec<_>>().join("→");
    let mut out = vec![head];
    if let Some(f) = get("Foils") { out.push(count(f.parse().unwrap_or(0), "foil", "foils")); }
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

/// The outcome tables, on Project with the other aggregates: attempts, each
/// kind's reasons (which sum to its Blocked), then bon processes. Both tables
/// share their columns' widths; columns that do not fit drop from the right.
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
            out.push(Row::text(Line::from(vec![Span::styled(format!(" {}", fit(if k == 0 && lw > 2 { &label } else { "" }, lw)), pal.muted()), Span::styled(fit(&l, w.saturating_sub(1 + lw)), pal.ink())])));
        }
    }
    if !processes.is_empty() { out.push(Row::text(Line::default())); out.extend(table_rows(pal, &processes, w0, w)); }
    out
}

/// A table, its header first (strong, then muted), as rows `w` wide: the first
/// column `w0` wide and left, the rest each as wide as its widest and right;
/// a row whose label is indented is a sub-row (muted label). Columns that do
/// not fit drop from the right; a first column that does not fit is cut with ….
fn table_rows(pal: &Palette, rows: &[Vec<String>], w0: usize, w: usize) -> Vec<Row> {
    let cw: Vec<usize> = (0..rows.first().map_or(0, |r| r.len())).map(|i| if i == 0 { w0 } else { rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0) }).collect();
    let mut n = cw.len();
    // A column that does not fit drops, and the header ends in … to say so.
    while n > 2 && 1 + cw[0] + (1..n).map(|i| cw[i] + 2).sum::<usize>() + if n < cw.len() { 3 } else { 0 } > w { n -= 1; }
    let first = cw.first().copied().unwrap_or(0).min(w.saturating_sub(1 + (1..n).map(|i| cw[i] + 2).sum::<usize>()));
    rows.iter().enumerate().map(|(k, r)| {
        let (lead, rest) = if k == 0 { (pal.strong(), pal.muted()) } else if r[0].starts_with(' ') { (pal.muted(), pal.ink()) } else { (pal.ink(), pal.ink()) };
        let mut v = vec![Span::styled(format!(" {}", fit(&r[0], first)), lead)];
        for i in 1..n { v.push(Span::styled(format!("  {}", right(&r[i], cw[i])), rest)); }
        if k == 0 && n < cw.len() { v.push(Span::styled("  …", pal.muted())); }
        Row::text(Line::from(v))
    }).collect()
}

/// What each measure's and outcome's words mean, under its table: once, muted, wrapped.
fn notes(pal: &Palette, out: &mut Vec<Row>, w: usize, all: &[(&str, &str)], names: &[&str]) {
    for (k, v) in all.iter().filter(|(k, _)| names.contains(k)) {
        out.extend(hanging(&format!("{k}: {v}"), 3, w, pal.muted()).into_iter().map(Row::text));
    }
}

fn rows(app: &App, width: u16) -> Vec<Row> {
    let pal = &app.palette;
    let p = &app.p;
    let w = width as usize;
    let mut out = Vec::new();
    // Before the first read there is nothing to show as read.
    if app.loaded.is_none() { return out; }
    let blank = || Row::text(Line::default());
    let header = |t: &str, n: Option<usize>| Row::text(section(pal, 1, t, n));
    let empty = |s: &str| Row::text(Line::from(Span::styled(format!(" {s}"), pal.muted())));
    match app.tab {
        // Outside every repository: the host, its only tab.
        Tab::Host => {
            // Beside the right pane, one blank column before its rule.
            let pending: Vec<&projection::Interrupt> = app.host.interrupts.iter().filter(|i| i.resolved.is_none()).collect();
            if pending.is_empty() { out.push(header("Pending", None)); out.push(Row::text(Line::from(Span::styled("   Nothing waits on you", pal.muted())))); }
            else { out.extend(pending_rows(pal, &pending, app.host.now, None, w)); }
            // Wide, what happened is the right pane (the detail); each section keeps its side.
            out.push(blank());
            out.extend(if app.split { host_now(app, w, true) } else { host_rows(app, w, true) });
        }
        Tab::Traces => {
            let today = day(p.repo.now, app.off);
            let mut last_day = None;
            // Three forms by width: 96+ everything; 76+ without who; under 76
            // (beside the detail, or a phone) no steps, which the detail shows.
            let (who_col, with_steps) = (w >= 96, w >= 76);
            let fixed = 1 + 7 + if who_col { 5 } else { 0 } + 2 + 11 + GEN_W + TIME_W;
            // The kind and its commit, as wide as the widest of them.
            let what = |g: &GoalTrace| format!("{} {}", cap(&g.kind), g.title.split_whitespace().last().unwrap_or(""));
            let widest = p.groups.iter().map(|g| what(g).chars().count() + 1).max().unwrap_or(12).clamp(12, 23);
            let what_w = if with_steps { widest } else { w.saturating_sub(fixed).clamp(8, widest) };
            let rest = w.saturating_sub(fixed + what_w);
            for g in sorted_groups(p) {
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
                let what = what(g);
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
                out.push(Row::item(Line::from(spans), goal_key(g)));
            }
            if p.groups.is_empty() { out.push(empty(none_yet(p))); }
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
                for pr in &p.proposals {
                    let counts = vec![Span::styled("New ", pal.muted()), Span::styled(format!("{:<3}", pr.intents.len()), pal.ink()),
                        Span::styled("Contested ", pal.muted()), Span::styled(format!("{:<2}", pr.contested.len()), pal.ink())];
                    let room = w.saturating_sub(5 + width_of(&counts) + 1);
                    out.push(Row::item(spread(vec![Span::styled("  ● ", pal.tone(Tone::Yellow)), Span::styled(fit(&pr.source, room), pal.ink())], counts, w), Key::Proposal(pr.name.clone())));
                    under(&mut out, "Accept", &format!("git am {}", pr.path), pal.ink());
                    for i in &pr.intents {
                        under(&mut out, &format!("New {}", i.id.map_or("—".into(), |n| format!("#{n}"))), &i.intent, pal.ink());
                        if let Some(c) = &i.cue { under(&mut out, "Cue", c, pal.faint()); }
                    }
                    for c in &pr.contested { under(&mut out, "Contested", c, pal.ink()); }
                }
                out.push(blank());
            }
            if !p.proposals.is_empty() || !p.retired.is_empty() { out.push(header("Queued", Some(p.queue.as_ref().map_or(0, |q| q.len())))); }
            for q in p.queue.iter().flatten() { entry(&mut out, Key::Queue(q.id), format!("#{}", q.id), &q.intent, pal.ink()); }
            if p.queue.as_ref().is_none_or(|q| q.is_empty()) { out.push(empty("Nothing queued")); }
            // Intents taken off the queue, newest first, each with the commit that
            // took it off; the commit's subject once, under the first it took off.
            if !p.retired.is_empty() {
                out.push(blank());
                out.push(header("Retired", Some(p.retired.len())));
                for (k, r) in p.retired.iter().enumerate() {
                    entry(&mut out, Key::Retired(r.id), format!("#{}", r.id), &r.intent, pal.muted());
                    let when = r.time.map_or(String::new(), |x| format!(" · {}", ago(p.repo.now, x)));
                    let first = k == 0 || p.retired[k - 1].commit != r.commit;
                    let subject = if first && !r.subject.is_empty() { format!(" · {}", r.subject) } else { String::new() };
                    let at = out.len();
                    under(&mut out, "Taken off by", &format!("{}{when}{subject}", short(&r.commit)), pal.muted());
                    // The commit only locates it: faint.
                    if let Some(row) = out.get_mut(at) {
                        let body = row.line.spans.pop().map(|s| s.content.to_string()).unwrap_or_default();
                        let (commit, rest): (String, String) = (body.chars().take(7).collect(), body.chars().skip(7).collect());
                        row.line.spans.extend([Span::styled(commit, pal.faint()), Span::styled(rest, pal.muted())]);
                    }
                }
            }
        }
        Tab::Spec => {
            let Some(spec) = &p.spec else { out.push(empty("No spec found")); return out };
            let g = p.system.clone().unwrap_or_default();
            // Names as wide as the longest, but never more than a third of the width (a phone).
            let nw = (spec.items.iter().map(|i| i.name.chars().count()).chain(spec.fields.iter().map(|f| f.name.chars().count())).max().unwrap_or(10).min(24) + 2).min((w / 3).max(10));
            // An item whose detail shows something that differs from trunk is marked in the gutter.
            let changed = |name: &str| ["spec", "gate", "kernel"].iter().any(|l| g.nodes.iter().any(|n| n.changed && n.id == format!("{l}:{name}")));
            let gutter = |c: bool| Span::styled(format!(" {} ", if c { DIFFERS } else { " " }), pal.ink());
            let item = |i: usize, rest: Vec<Span<'static>>| { let mut v = vec![gutter(changed(&spec.items[i].name)), Span::styled(fit(&spec.items[i].name, nw), pal.ink())]; v.extend(rest); Row::item(Line::from(v), Key::Item(spec.items[i].name.clone())) };
            let room = w.saturating_sub(nw + 4);
            let doc_of = |i: usize| Span::styled(fit(&spec.items[i].doc.clone().unwrap_or_default(), room), pal.muted());
            let of = |kind: &str| spec.items.iter().enumerate().filter(|(_, x)| x.kind == kind).map(|(i, _)| i).collect::<Vec<_>>();
            // Where the spec is (a path: faint), and how much of it differs from trunk.
            let differ = g.nodes.iter().filter(|n| n.changed).count();
            let mut file = vec![Span::styled(" File ", pal.muted()), Span::styled(cut(&spec.path, w.saturating_sub(7)), pal.faint())];
            if differ > 0 && width_of(&file) + 24 <= w { file.extend([Span::styled(" · ", pal.faint()), Span::styled(format!("{DIFFERS} Differs from trunk "), pal.muted()), Span::styled(differ.to_string(), pal.ink())]); }
            out.push(Row::text(Line::from(file)));
            out.push(blank());

            out.push(header("Vocabulary", Some(of("type").len())));
            for i in of("type") { out.push(item(i, vec![doc_of(i)])); }

            out.push(blank());
            let ts: Vec<usize> = of("init").into_iter().chain(of("transition")).collect();
            out.push(header("State Machine", Some(ts.len())));
            if !spec.fields.is_empty() {
                let names = spec.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(" · ");
                out.push(Row::item(Line::from(vec![Span::styled(format!("   {}", fit("Fields", nw)), pal.muted()), Span::styled(fit(&names, room), pal.ink())]), Key::Grid));
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
                // The legend, for what a cell can show: — only where some cell is absent.
                let some_absent = decided.iter().any(|i| layers(&spec.items[*i].name).is_some_and(|l| cols.iter().any(|&k| l[k].is_none())));
                if some_absent { out.push(Row::text(Line::from(vec![Span::raw(format!("   {}", " ".repeat(nw))), Span::styled("✓ ", pal.ink()), Span::styled("Present", pal.muted()),
                    Span::styled("   — ", pal.faint()), Span::styled("Absent", pal.muted())]))); }
                if !absent.is_empty() { out.extend(hanging(&format!("{}: absent for every one", absent.join(", ")), 3 + nw, w, pal.muted()).into_iter().map(Row::text)); }
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
            for t in &g.trusted {
                out.push(Row::item(Line::from(vec![gutter(t.changed), Span::styled(fit(&t.name, nw), pal.ink()), Span::styled(fit(&t.doc.clone().unwrap_or_default(), room), pal.muted())]), Key::Trusted(t.name.clone())));
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
                out.extend(pending_rows(pal, &pending, p.repo.now, p.repo.name.as_deref(), w));
                out.push(blank());
            }
            // Then what runs now in this repository, against the host's pools, and what happened (queue 60).
            out.extend(host_rows(app, w, false));
            out.push(blank());
            let lw = 23;
            let num = |s: String| Span::styled(right(&s, 9), pal.ink());
            let line = |label: &str, value: Vec<Span<'static>>| Row::text(kv(pal, 3, lw, label, value));
            // Nothing has run: nothing to measure; trunk is all there is.
            if p.groups.is_empty() { out.push(empty(none_yet(p))); }
            else {
                // Cost: generation, time and their total are the header's, on every tab;
                // here what each verified candidate and each push cost.
                out.push(header("Cost", None));
                out.push(line("Per verified candidate", vec![num(money(t.per_verified_candidate))]));
                out.push(line("Reached a push", vec![num(money(Some(t.pushed)))]));
                out.push(line("Pushes", vec![num(t.pushes.to_string())]));
                out.push(line("Per push", vec![num(money(t.per_push))]));

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
                // The share's heading in full where it fits.
                let (share_w, share_head) = if w >= 3 + lw + GEN_W + TIME_W + 2 + 14 { (14, "Share of total") } else { (7, "Share") };
                let bw = w.saturating_sub(3 + lw + GEN_W + TIME_W + 2 + share_w).min(30);
                out.push(blank());
                let mut h = vec![Span::styled(format!(" {}", fit("Where It Went", lw + 2)), pal.strong())];
                h.extend(cost_heads(pal));
                let legend = vec![Span::styled("█ ", pal.muted()), Span::styled("Gen  ", pal.muted()), Span::styled("▒ ", pal.muted()), Span::styled("Time", pal.muted())];
                h.push(Span::raw("  "));
                if bw >= 12 { let lw = width_of(&legend); h.extend(legend); h.push(Span::raw(" ".repeat(bw - lw))); } else { h.push(Span::raw(" ".repeat(bw))); }
                h.push(Span::styled(right(share_head, share_w), pal.muted()));
                out.push(Row::text(Line::from(h)));
                for (label, tone, (g, tm)) in parts {
                    if g + tm == 0.0 && label != "Reached a push" { continue; }
                    let (ng, nt) = ((g / whole * bw as f64).round() as usize, ((g + tm) / whole * bw as f64).round() as usize);
                    // The label carries its outcome's tone, so it holds where the bar is too small to draw.
                    let mut v = vec![Span::styled(format!("   {}", fit(&label, lw)), pal.tone(tone))];
                    v.extend(cost_cells(pal, Some(g), Some(tm)));
                    v.push(Span::raw("  "));
                    v.push(Span::styled("█".repeat(ng), pal.tone(tone)));
                    v.push(Span::styled("▒".repeat(nt.saturating_sub(ng)), pal.tone(tone)));
                    v.push(Span::raw(" ".repeat(bw.saturating_sub(nt.max(ng)))));
                    v.push(Span::styled(right(&view::percent((g + tm) / whole), share_w), pal.ink()));
                    out.push(Row::text(Line::from(v)));
                }

                // Where the wall time went: each search's split by its slowest agent process, summed,
                // with the time cost each part carries. Trunk's checks before a search are charged nothing.
                let (parts, trunk) = time_split(p);
                let wall: f64 = parts.iter().map(|x| x.0).sum();
                if wall > 0.0 {
                    out.push(blank());
                    out.push(Row::text(Line::from(vec![Span::styled(format!(" {}", fit("Where The Time Went", lw + 2)), pal.strong()),
                        Span::styled(right("Wall", 9), pal.muted()), Span::styled(right("Time", TIME_W), pal.muted()), Span::styled(right("Share", 7), pal.muted())])));
                    for (label, (secs, dollars)) in ["Model", "Checks", "Other"].into_iter().zip(parts) {
                        out.push(line(label, vec![num(dur(secs)), Span::styled(right(&money(Some(dollars)), TIME_W), pal.ink()), Span::styled(right(&view::percent(secs / wall), 7), pal.ink())]));
                    }
                    out.push(line("Searches", vec![num(dur(wall)), Span::styled(right(&money(Some(parts.iter().map(|x| x.1).sum())), TIME_W), pal.muted())]));
                    if trunk > 0.0 { out.push(line("Trunk checks", vec![num(dur(trunk)), Span::styled(fit("   before each first search; no time charged", w.saturating_sub(3 + lw + 9)), pal.muted())])); }
                    out.extend(hanging("By each search's slowest agent process; other is waiting on a slot and setup (inferred)", 3, w, pal.muted()).into_iter().map(Row::text));
                }

                // How attempts and bon processes ended, measured; what their words mean under them.
                let outcomes = outcome_rows(pal, t, w);
                if !outcomes.is_empty() {
                    out.push(blank());
                    out.extend(outcomes);
                    notes(pal, &mut out, w, &view::OUTCOME_NOTES, &["All", "Exited", "Expected", "Inferred"]);
                }

                // The measures, each table with its formulas under it, said once.
                let (run, fits) = view::run_time_table(t);
                let tables = [
                    (view::success_table(t), vec!["Success probability per agent process", "Success probability per attempt", "Attempt a"]),
                    (run, vec!["Time, cost to a push", "Median, 90th percentile"]),
                    (view::per_verified_table(t), vec!["Cost per verified candidate"]),
                    (view::over_tier_table(t), vec!["Over tier"]),
                    (view::utilization_table(t), vec!["Utilization"]),
                    (view::turnaround_table(t), vec!["Turnaround"]),
                ];
                for (k, (rows, names)) in tables.into_iter().enumerate() {
                    // The run-time distribution's fits stand under its table, or alone where nothing pushed.
                    if rows.is_empty() && !(k == 1 && !fits.is_empty()) { continue; }
                    out.push(blank());
                    if rows.is_empty() { out.push(header("Run-Time Distribution", None)); }
                    out.extend(table_rows(pal, &rows, rows.iter().map(|r| r[0].chars().count()).max().unwrap_or(0), w));
                    if k == 1 {
                        for f in &fits { out.extend(hanging(f, 3, w, pal.ink()).into_iter().map(Row::text)); }
                        notes(pal, &mut out, w, &view::MEASURE_NOTES, &["Per search (inferred)"]);
                    }
                    notes(pal, &mut out, w, &view::MEASURE_NOTES, &names);
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
                let room = w.saturating_sub(3 + lw + 9);
                if !measured.is_empty() {
                    let pinned = measured.iter().filter(|n| **n == 1).count();
                    // Every search one behavior: agree has never told verified candidates apart.
                    let always = if pinned == measured.len() { " · every one: agree split none" } else { "" };
                    out.push(line("One behavior", vec![num(pinned.to_string()), Span::styled(fit(&format!("   of {} searches with two verified{always}", measured.len()), room), pal.muted())]));
                }
                // A kind's rank every candidate in range shares: it selects nothing.
                for kind in ["code", "compaction"] {
                    let ranks: Vec<Option<i64>> = p.processes.iter().flat_map(|b| &b.searches).filter(|s| s.kind == kind).flat_map(|s| &s.candidates).map(|c| c.rank).collect();
                    if ranks.len() > 1 && ranks.windows(2).all(|w| w[0] == w[1]) {
                        out.push(line(&format!("{} rank", cap(kind)), vec![num(ranks[0].map_or("—".to_string(), |r| r.to_string())),
                            Span::styled(fit(&format!("   for all {} candidates: the smallest diff, then the earliest, selects", ranks.len()), room), pal.muted())]));
                    }
                }
            }

            out.push(blank());
            out.push(header("Trunk", None));
            let repo = &p.repo;
            let room = w.saturating_sub(3 + lw + 9);
            match repo.remote_head.as_deref() {
                Some(h) => out.push(line("Head", vec![Span::styled(fit(&short(h), 9), pal.ink()), Span::styled(fit(&repo.subject.clone().unwrap_or_default(), room), pal.muted())])),
                None => out.push(line("Head", vec![Span::styled("—", pal.faint())])),
            }
            if let Some(lp) = &repo.last_push { out.push(line("Last push", vec![Span::styled(fit(&short(lp.commit.as_deref().unwrap_or("")), 9), pal.ink()), Span::styled(lp.time.map_or(String::new(), |t| cap(&ago(repo.now, t))), pal.muted())])); }
            if let Some(sp) = &repo.since_push { out.push(line("Since push", vec![num(sp.commits.to_string()), Span::styled(fit(&format!("   {}{}", if sp.commits == 1 { "commit" } else { "commits" }, if sp.authors.is_empty() { String::new() } else { format!(" by {}", sp.authors.join(", ")) }), room), pal.muted())])); }
        }
    }
    out
}

// ── the host (queue 60) ─────────────────────────────────

/// The pending interrupts, oldest first, under their header: each one's kind,
/// what it is about and when it was raised (with its repository where it is
/// not `here`'s), what happened, then each choice with what it costs and,
/// under it, how it is made.
fn pending_rows(pal: &Palette, pending: &[&projection::Interrupt], now: i64, here: Option<&str>, w: usize) -> Vec<Row> {
    let mut out = vec![Row::text(section(pal, 1, "Pending", Some(pending.len())))];
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
        if k > 0 { out.push(Row::text(Line::default())); }
        let repo = if i.repository.is_empty() || here == Some(i.repository.as_str()) { String::new() } else { format!(" · {}", i.repository) };
        labeled(&mut out, vec![Span::styled("  ● ", pal.tone(Tone::Yellow)), Span::styled(cap(&i.kind), pal.ink())],
            &format!("{} · raised {}{repo}", i.about, ago(now, i.raised).to_lowercase()), pal.ink());
        for line in &i.what { labeled(&mut out, Vec::new(), line, pal.muted()); }
        for c in &i.choices {
            labeled(&mut out, vec![Span::styled(format!("    {}", cap(&c.choice)), pal.ink())], &c.cost, pal.ink());
            labeled(&mut out, Vec::new(), &c.how, pal.faint());
        }
    }
    out
}

/// A gauge `w` cells wide: `part` of `whole` as ink cells, the rest faint.
fn gauge(pal: &Palette, part: f64, whole: f64, w: usize) -> Vec<Span<'static>> {
    let n = if whole > 0.0 { ((part / whole).clamp(0.0, 1.0) * w as f64).round() as usize } else { 0 };
    // Something held shows at least a cell; nothing held, none.
    let n = if part > 0.0 { n.max(1) } else { n };
    vec![Span::styled("█".repeat(n), pal.ink()), Span::styled("░".repeat(w - n), pal.faint())]
}


/// How many journal lines show: in a repository's Project, its latest; on the host, more.
const JOURNAL_HERE: usize = 8;
const JOURNAL_HOST: usize = 40;

/// The host's panes after what is pending: what waiting on searches costs
/// engineer, the two pools and memory (the host's, which a repository shares),
/// each running bon process (those of one tree together), the journal and,
/// for the whole host, each repository. In a repository (`whole` false), its
/// own processes and journal only. Nothing before the first read.
fn host_rows(app: &App, w: usize, whole: bool) -> Vec<Row> {
    let mut out = host_now(app, w, whole);
    out.push(Row::text(Line::default()));
    out.extend(host_record(app, w, whole));
    out
}

/// The host's journal and, for the whole host, each repository: the right
/// pane at 100 columns and wider, under what runs below that.
fn host_record(app: &App, w: usize, whole: bool) -> Vec<Row> {
    let mut out: Vec<Line<'static>> = Vec::new();
    if app.loaded.is_none() { return Vec::new(); }
    host_journal(app, whole, w, &mut out);
    if whole { host_repositories(app, w, &mut out); }
    out.into_iter().map(|l| Row::text(clip(l, w))).collect()
}

/// What engineer's waiting costs, the pools and memory, and each running bon process.
fn host_now(app: &App, w: usize, whole: bool) -> Vec<Row> {
    let (pal, h) = (&app.palette, &app.host);
    let mut out: Vec<Line<'static>> = Vec::new();
    if app.loaded.is_none() { return Vec::new(); }
    let lw = 18;
    let line = |label: &str, value: Vec<Span<'static>>| kv(pal, 3, lw, label, value);
    let ink = |s: String| Span::styled(s, pal.ink());
    let muted = |s: &str| Span::styled(s.to_string(), pal.muted());

    // Now: what engineer's waiting costs, and what the host holds.
    out.push(section(pal, 1, "Now", None));
    let wt = &h.waiting;
    if wt.searches > 0 {
        let mut v = vec![ink(count(wt.searches as usize, "search", "searches")), muted(" · "), ink(format!("{}/h", money(Some(wt.per_hour)))), muted(" of your time")];
        if wt.host > wt.searches && !whole { v.push(muted(&format!(" · {} on the host", wt.host))); }
        out.push(line("You wait on", v));
    }
    out.push(line("Your time today", vec![ink(money(Some(wt.today)))]));
    // A gauge where the line has room for one of at least 8 cells, up to 16.
    let gw = match w.saturating_sub(3 + lw + 2 + 32) { n if n >= 8 => n.min(16), _ => 0 };
    for (name, s, what) in [("agent_processes", &h.pools.agent_processes, "in flight"), ("check_processes", &h.pools.check_processes, "in checks")] {
        let mut v = Vec::new();
        match s.size {
            Some(n) => {
                if gw > 0 { v.extend(gauge(pal, s.held as f64, n as f64, gw)); v.push(Span::raw("  ")); }
                v.push(ink(format!("{} of {n} held", s.held)));
                if !whole && s.shown > 0 { v.push(muted(&format!(" · {} {what} here", s.shown))); }
                if name == "check_processes" { if let Some(t) = h.pools.check_threads { v.push(muted(&format!(" · {t} threads each"))); } }
            }
            None => v.push(muted("unsized: no host file")),
        }
        out.push(line(name, v));
    }
    let m = &h.memory;
    if m.total > 0.0 {
        let mut v = Vec::new();
        if gw > 0 { v.extend(gauge(pal, m.total - m.free, m.total, gw)); v.push(Span::raw("  ")); }
        v.push(ink(format!("{:.1} of {:.1} GB free", m.free, m.total)));
        if !h.trees.is_empty() { v.push(muted(" · bon ")); v.push(ink(size(m.bon))); }
        out.push(line("Memory", v));
    }

    // Each running bon process, those of one tree together.
    out.push(Line::default());
    let n: usize = h.trees.iter().map(|g| g.processes.len()).sum();
    out.push(section(pal, 1, "bon Processes", (n > 0).then_some(n)));
    if n == 0 { out.push(Line::from(Span::styled("   No bon process is running", pal.muted()))); }
    for g in &h.trees {
        let grouped = g.processes.len() > 1;
        if grouped {
            out.push(Line::from(vec![Span::styled("   Tree ", pal.muted()), Span::styled(short(g.tree.as_deref().unwrap_or("")), pal.faint()),
                Span::styled(format!(" · {} bon processes from one tree", g.processes.len()), pal.muted())]));
        }
        let ind = if grouped { 5 } else { 3 };
        for r in &g.processes {
            let what = match (r.kind.as_deref(), r.goal.as_deref()) {
                (Some(k), Some(goal)) => format!("{k} {}", if goal.len() == 40 && goal.chars().all(|c| c.is_ascii_hexdigit()) { format!("from {}", short(goal)) } else { goal.to_string() }),
                (Some(k), None) => k.to_string(),
                _ => "between searches".to_string(),
            };
            let mut left = vec![Span::raw(" ".repeat(ind)), Span::styled("● ", pal.tone(Tone::Orange))];
            if whole { left.push(Span::styled(format!("{} · ", r.repository), pal.muted())); }
            left.push(ink(what));
            if r.background { left.push(muted(" · background")); }
            // Its age at the right where it fits; its pid and memory after what it does.
            let age = vec![Span::styled(format!("{} ", ago(h.now, r.start).to_lowercase()), pal.muted())];
            if width_of(&left) + width_of(&age) + 2 <= w { out.push(spread(left, age, w)); } else { out.push(Line::from(left)); }
            let counts = view::now_counts(r.in_flight, r.in_checks, r.waiting);
            let detail = match r.width {
                Some(n) if r.search.is_some() => format!("{} of {n} returned{}, {} verified so far", r.returned, if counts.is_empty() { String::new() } else { format!(" ({counts})") }, r.verified),
                _ => r.sentence.clone(),
            };
            for l in hanging(&format!("{detail} · pid {} · {}", r.pid, size(r.memory)), ind + 2, w, pal.muted()) { out.push(l); }
        }
    }

    out.into_iter().map(|l| Row::text(clip(l, w))).collect()
}

/// The journal: what happened, in the order it happened, by day; the latest.
fn host_journal(app: &App, whole: bool, w: usize, out: &mut Vec<Line<'static>>) {
    let (pal, h) = (&app.palette, &app.host);
    out.push(section(pal, 1, "Journal", None));
    let take = if whole { JOURNAL_HOST } else { JOURNAL_HERE };
    let shown: Vec<&projection::Event> = h.journal.iter().rev().take(take).collect::<Vec<_>>().into_iter().rev().collect();
    if shown.is_empty() { out.push(Line::from(Span::styled("   No push, block or interrupt yet", pal.muted()))); }
    let today = day(h.now, app.off);
    let mut last_day = None;
    for e in shown {
        let d = day(e.time, app.off);
        if last_day != Some(d) { out.push(Line::from(Span::styled(format!("   {}", day_label(d, today)), pal.muted()))); last_day = Some(d); }
        let tone = match e.kind.as_str() { "pushed" => pal.tone(Tone::Violet), "blocked" => pal.tone(Tone::Yellow), _ => pal.ink() };
        let mut v = vec![Span::styled(format!("   {}  ", clock(e.time, app.off)), pal.muted()), Span::styled(fit(&cap(&e.kind), 10), tone)];
        if whole && !e.repository.is_empty() { v.push(Span::styled(format!("{} · ", e.repository), pal.muted())); }
        // What happened wraps under itself, after its time and kind.
        let at = width_of(&v);
        for (k, l) in hanging(&e.text, at, w.max(at + 12), pal.ink()).into_iter().enumerate() {
            let body: String = l.spans[0].content.chars().skip(at).collect();
            if k == 0 { v.push(Span::styled(body, pal.ink())); out.push(Line::from(std::mem::take(&mut v))); }
            else { out.push(Line::from(vec![Span::raw(" ".repeat(at)), Span::styled(body, pal.ink())])); }
        }
    }
}

/// Each repository the host reaches: what is pending in it, what runs, what it cost today.
fn host_repositories(app: &App, w: usize, out: &mut Vec<Line<'static>>) {
    let (pal, h) = (&app.palette, &app.host);
    let muted = |s: &str| Span::styled(s.to_string(), pal.muted());
    out.push(Line::default());
    out.push(section(pal, 1, "Repositories", (!h.repositories.is_empty()).then_some(h.repositories.len())));
    if h.repositories.is_empty() {
        let why = match &h.user { None => "No host file names the user layer: bon setup writes one".to_string(),
            Some(u) => format!("No repository under {u} has a .bon/bon.toml: bon init makes one") };
        for l in hanging(&why, 3, w, pal.muted()) { out.push(l); }
    }
    let nw = h.repositories.iter().map(|r| r.name.chars().count()).max().unwrap_or(0).min(w / 3).max(4);
    let under = |r: &str| h.user.as_deref().is_some_and(|u| std::path::Path::new(r).parent() == Some(std::path::Path::new(u)));
    for r in &h.repositories {
        let mut v = vec![Span::styled(format!("   {}  ", fit(&r.name, nw)), pal.ink())];
        if !r.configured { v.push(muted("no .bon/bon.toml at trunk's head")); }
        else {
            let mut parts: Vec<Span<'static>> = Vec::new();
            if r.pending > 0 { parts.push(Span::styled(format!("{} pending", r.pending), pal.tone(Tone::Yellow))); }
            if r.running > 0 { parts.push(Span::styled(format!("{} running", r.running), pal.tone(Tone::Orange))); }
            parts.push(Span::styled(format!("{} today", money(Some(r.today))), pal.ink()));
            if let Some(t) = r.latest { parts.push(muted(&format!("last ran {}", ago(h.now, t).to_lowercase()))); }
            for (k, s) in parts.into_iter().enumerate() { if k > 0 { v.push(muted(" · ")); } v.push(s); }
        }
        out.push(Line::from(v));
        // A repository outside the user layer (a benchmark's sandbox): where it is, under its name.
        if !under(&r.root) { for l in hanging(&r.root, 5 + nw, w, pal.faint()) { out.push(l); } }
    }
}

// ── detail ──────────────────────────────────────────────

/// The focused item.
fn focused(app: &App) -> Option<Key> { app.held[app.ti()].clone() }

/// The goal a key stands for.
fn goal<'a>(p: &'a Projection, k: &Key) -> Option<&'a GoalTrace> { p.groups.iter().find(|g| goal_key(g) == *k) }

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
        // The host's right pane: what happened, and each repository.
        Tab::Host => { t.extend(host_record(app, width as usize, true).into_iter().map(|r| r.line)); }
        Tab::Traces => {
            let Some(g) = focused(app).and_then(|k| goal(&app.p, &k)) else { return (Text::default(), marks) };
            let tone = pal.tone(goal_tone(g));
            marks.push((t.len(), Mark::Title));
            t.push(spread(vec![Span::styled(format!("{} {}", cap(&g.kind), g.title), pal.strong())], vec![Span::styled(format!("● {}", outcome_label(&g.outcome)), tone)], wd));
            if !g.about.subject.is_empty() { t.extend(hanging(&g.about.subject, 0, wd, pal.muted())); }
            t.push(blank());
            t.extend(pairs(&pal, 0, &step_parts(g), wd));
            if let Some(c) = g.push.as_ref().and_then(|p| p.commit.as_deref()) { t.push(kv("Pushed commit", vec![Span::styled(short(c), pal.ink())])); }
            sec(&mut t, if g.push.is_some() { "Cost to Push" } else { "Cost" });
            let (gen, time) = goal_cost(g);
            t.extend(cost_rows(&pal, 0, gen, time, app.p.totals.rate));
            // Each bon process: its searches as a table, each search's candidates under it.
            // Narrow, Elapsed and then the costs move to the search's lines below it, so the steps fit.
            let (kw, tw) = (17usize, if wd >= 60 { 8usize } else { 0 });
            let costs = wd >= 2 + kw + 10 + GEN_W + TIME_W;
            let sw = wd.saturating_sub(2 + kw + tw + if costs { GEN_W + TIME_W } else { 0 }).max(6);
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
                if costs { h.extend(cost_heads(&pal)); }
                t.push(Line::from(h));
                for (k, s) in b.searches.iter().enumerate() {
                    if k > 0 && !b.searches[k - 1].candidates.is_empty() { t.push(blank()); }
                    let stone = if s.running { Tone::Orange } else if s.blocked.is_some() { Tone::Yellow } else if clears(&s.kind) { Tone::Indigo } else if s.selected.is_some() { Tone::Blue } else { Tone::Yellow };
                    let how = match s.kind.as_str() {
                        "foil" => format!("{} → {}", s.width.max(s.returned), count(foil_indices(s).len(), "foil", "foils")),
                        "counterexample" => format!("{} → {}", s.width.max(s.returned), s.verified),
                        _ => format!("{} → {}{}", s.width.max(s.returned), s.verified, s.selected.map_or(String::new(), |i| format!(" → #{i}"))),
                    };
                    let elapsed = s.seconds.map_or(String::new(), dur);
                    marks.push((t.len(), Mark::Search));
                    let mut row = vec![
                        Span::styled("● ", pal.tone(stone)),
                        Span::styled(fit(&format!("{} {}", s.search, cap(&s.kind)), kw), pal.ink()),
                        Span::styled(fit(&how, sw), pal.ink()),
                        Span::styled(if tw == 0 { String::new() } else { right(&elapsed, tw) }, pal.ink()),
                    ];
                    if costs { row.extend(cost_cells(&pal, s.generation, s.time_cost)); }
                    t.push(Line::from(row));
                    let mut facts: Vec<(&str, String)> = Vec::new();
                    if !s.params.base.is_empty() { facts.push(("Base", short(&s.params.base))); }
                    if shared_limit.is_none() { if let Some(l) = s.params.limit { facts.push(("Limit", money(Some(l)))); } }
                    if shared_kernel.is_none() { if let Some(k) = kernel(&s.kernel) { facts.push(("Kernel", k)); } }
                    if tw == 0 && !elapsed.is_empty() { facts.push(("Elapsed", elapsed.clone())); }
                    if !costs { facts.push(("Gen", money(s.generation))); facts.push(("Time", money(s.time_cost))); }
                    if s.running { let now = view::now_counts(s.in_flight, s.in_checks, s.waiting); if !now.is_empty() { facts.push(("Agent processes", now)); } }
                    // The search's measures: success, its spread over behaviors, its trees, its cost per verified candidate.
                    if s.time.is_some() && s.width > 0 {
                        let k = if s.kind == "foil" { foil_indices(s).len() as u64 } else { s.verified };
                        facts.push(("Success probability per agent process", view::share(k, s.width)));
                    }
                    if !s.behaviors.is_empty() { facts.push(("Agent processes per behavior", s.behaviors.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" · "))); }
                    if let Some(n) = s.trees.filter(|_| !s.candidates.is_empty()) { facts.push(("Distinct trees", n.to_string())); }
                    if let (Some(c), true) = (s.cost, s.verified > 0 && s.time.is_some()) { facts.push(("Cost per verified candidate", money(Some(c / s.verified as f64)))); }
                    // Its requests over a model's tier threshold, where any crossed it, and what they cost beyond the base price (queue 82).
                    if s.requests_over_tier > 0 { facts.push(("Over tier", format!("{} · {} beyond the base price", count(s.requests_over_tier as usize, "request", "requests"), money(Some(s.over_tier))))); }
                    if !facts.is_empty() { t.extend(pairs(&pal, 2, &facts, wd)); }
                    // Where its elapsed time went, by its slowest agent process; and summed over all of them.
                    if let Some(x) = split(s).filter(|x| x.n > 0) {
                        t.extend(pairs(&pal, 2, &[("Model", dur(x.model)), ("Checks", dur(x.checks)), ("Other", dur(x.rest))], wd));
                        t.extend(hanging(&format!("By its slowest agent process, #{}; other is waiting on a slot and setup (inferred). Summed over {}: model {} · checks {}",
                            x.slowest.unwrap_or(0), count(x.n, "agent process", "agent processes"), dur(x.model_all), dur(x.checks_all)), 2, wd, pal.muted()));
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
                            // Its flags beside it where they fit, else under it: never cut.
                            let flags = c.flags.iter().map(|f| cap(&f.replace('_', " "))).collect::<Vec<_>>().join(" · ");
                            let beside = !flags.is_empty() && width_of(&row) + flags.chars().count() + 2 <= wd;
                            if beside { row.push(Span::styled(format!("  {flags}"), pal.tone(Tone::Red))); }
                            t.push(Line::from(row));
                            if !flags.is_empty() && !beside { t.extend(hanging(&flags, 8, wd, pal.tone(Tone::Red))); }
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
                        let flags = c.flags.iter().map(|f| cap(&f.replace('_', " "))).collect::<Vec<_>>().join(" · ");
                        let beside = 2 + 4 + 9 + 11 + rw + 11 + 8 + 2 + flags.chars().count() <= wd;
                        t.push(Line::from(vec![
                            Span::styled(format!("  {}", fit(&format!("{}{}", c.index, if sel { "★" } else { "" }), 4)), if sel { pal.tone(Tone::Blue) } else { pal.muted() }),
                            Span::styled(fit(&short(c.commit.as_deref().unwrap_or("")), 9), pal.ink()),
                            Span::styled(fit(v, 11), vs),
                            Span::styled(if rw == 0 { String::new() } else { right(&rank_cell(c), rw) }, pal.ink()),
                            Span::styled(right(&lines, 11), pal.ink()),
                            Span::styled(right(&money(c.generation), 8), pal.ink()),
                            Span::styled(if flags.is_empty() || !beside { String::new() } else { format!("  {flags}") }, pal.tone(Tone::Red)),
                        ]));
                        if !flags.is_empty() && !beside { t.extend(hanging(&flags, 6, wd, pal.tone(Tone::Red))); }
                    }
                }
            }
            // The searches' measures, each formula once: no search's heading or table header stays pinned over them.
            marks.push((t.len(), Mark::Notes));
            t.push(blank());
            for (k, v) in view::MEASURE_NOTES.iter().filter(|(k, _)| ["Success probability per agent process", "Agent processes per behavior", "Cost per verified candidate"].contains(k)) {
                t.extend(hanging(&format!("{k}: {v}"), 0, wd, pal.muted()));
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
                Some(Key::Item(name)) => {
                    let Some(it) = spec.items.iter().find(|i| i.name == name) else { return (Text::default(), marks) };
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
                    t.push(spread(vec![Span::styled("State Machine", pal.strong())], vec![Span::styled(count(spec.fields.len(), "field", "fields"), pal.muted())], wd));
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
                Some(Key::Trusted(name)) => {
                    let Some(tf) = g.trusted.iter().find(|t| t.name == name) else { return (Text::default(), marks) };
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
    // Text wraps; a table row too wide for the pane says it is cut.
    (Text::from(t.into_iter().map(|l| clip(l, wd)).collect::<Vec<_>>()), marks)
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
        // Lines against the base: what selected says it.
        RankShown::Lines { .. } => None,
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
/// key bar's words. Each works everywhere its heading says.
const KEYS: [(&str, &[(&str, &str)]); 4] = [
    ("Everywhere", &[("↑ ↓   j k", "Move; scroll where nothing is focused"), ("g  G", "First, last"), ("⇧↑ ⇧↓  PgUp PgDn", "Scroll"),
        ("⇥  ⇧⇥  1–4", "Tab"), ("t", "Light or dark"), ("?", "Keys"), ("q  ⌃C", "Quit")]),
    ("Spec and Traces", &[("⏎", "Open, under 100 columns"), ("esc", "Close")]),
    ("Project and Traces", &[("/", "Find"), ("r", "Range")]),
    ("Traces", &[("l", "Logs"), ("d", "Compare two behaviors")]),
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
    clip(Line::from(v), w)
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

/// The first row from which the last of `len` rows shows in a pane `h` high.
fn last_top(len: usize, h: usize) -> usize { if len > h { len + 1 - h } else { 0 } }

/// Whether a tab shows the focused item's detail: Spec and Traces. Project and
/// Queue show everything in their lists.
fn has_detail(tab: Tab) -> bool { matches!(tab, Tab::Spec | Tab::Traces) }

/// Whether a tab's list is what Find and Range filter: the bon processes, on
/// Project (its totals) and Traces.
fn filtered(tab: Tab) -> bool { matches!(tab, Tab::Project | Tab::Traces) }

/// A row under the cursor: its text in reverse video, one style, padded to `w`.
fn cursor_line(pal: &Palette, line: Line<'static>, w: usize) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = line.spans.into_iter().map(|s| Span::styled(s.content, pal.cursor())).collect();
    let n = width_of(&spans);
    if n < w { spans.push(Span::styled(" ".repeat(w - n), pal.cursor())); }
    Line::from(spans)
}

/// Where the body's panes are: the list, and the detail beside it (100
/// columns and wider, a gutter and a rule between them) or over it (opened
/// with ⏎ under 100). Project and Queue are a list alone.
struct Panes { list: Rect, rows_w: u16, detail: Option<Rect>, beside: bool }

fn panes(app: &App, body: Rect) -> Panes {
    // The host, 100 columns and wider: what waits and runs │ what happened, half each.
    if app.tab == Tab::Host && body.width >= 100 {
        let [l, _, d] = Layout::horizontal([Constraint::Length(body.width / 2), Constraint::Length(1), Constraint::Min(30)]).areas(body);
        return Panes { list: l, rows_w: (body.width / 2).saturating_sub(1), detail: Some(d), beside: true };
    }
    let beside = has_detail(app.tab) && body.width >= 100;
    if beside {
        // Beside the detail the list is compact (its steps are in the detail), so the detail has room.
        let list_w = (body.width * 9 / 20).clamp(60, 66).min(body.width.saturating_sub(40));
        let [l, _, d] = Layout::horizontal([Constraint::Length(list_w), Constraint::Length(1), Constraint::Min(30)]).areas(body);
        // One blank column between the list's last column and the rule.
        return Panes { list: l, rows_w: list_w.saturating_sub(1), detail: Some(d), beside };
    }
    if has_detail(app.tab) && app.detail_open { return Panes { list: Rect::default(), rows_w: app.list_w, detail: Some(body), beside }; }
    Panes { list: body, rows_w: body.width, detail: None, beside }
}

/// Whether a row's key is the held item: the same key; or the same intent,
/// queued then and retired now (or back); or the goal one of whose bon
/// processes the held goal began with, when a filter left that one out.
fn same(p: &Projection, row: &Key, held: &Key) -> bool {
    match (row, held) {
        (Key::Queue(a) | Key::Retired(a), Key::Queue(b) | Key::Retired(b)) => a == b,
        (Key::Goal(a), Key::Goal(b)) => { let _ = p; a.split(' ').any(|t| b.split(' ').any(|u| t == u)) }
        _ => row == held,
    }
}

/// What a list with no bon process says: none yet, or none the find or range matches.
fn none_yet(p: &Projection) -> &'static str {
    if p.filter.find.is_some() { "No bon process matches" } else if p.filter.since.is_some() || p.filter.until.is_some() { "No bon process in this range" } else { "No bon process yet" }
}

/// The rows that continue row `i` (its wrapped lines), and it: the cursor covers them all.
fn block_end(list: &[Row], i: usize) -> usize { (i + 1..list.len()).take_while(|&j| list[j].more).last().unwrap_or(i) }

/// After the rows changed (a refresh, a resize, a find, a key), put the focus
/// back on its item, or, where the item is gone, on the nearest row; keep it as
/// far from the pane's top as it was, and in view with the rows that continue
/// it. A list with nothing to focus scrolls, no further than its last row.
fn place(app: &mut App, list: &[Row], h: usize) {
    let ti = app.ti();
    if !list.iter().any(|r| r.focusable()) { app.top[ti] = app.top[ti].min(last_top(list.len(), h)); return; }
    let was = app.focus[ti];
    let found = app.held[ti].as_ref().and_then(|k| list.iter().position(|r| r.key.as_ref().is_some_and(|r| same(&app.p, r, k))));
    let i = found.unwrap_or_else(|| {
        let from = was.min(list.len() - 1);
        (0..list.len()).filter(|&j| list[j].focusable()).min_by_key(|&j| j.abs_diff(from)).unwrap_or(from)
    });
    // Its item moved to another row: the pane moves with it.
    if found.is_some_and(|i| i != was) { app.top[ti] = (app.top[ti] + i).saturating_sub(was); }
    app.focus_on(list, i);
    let end = block_end(list, i);
    // Scrolled through an item's lines (⇧↑↓, PgUp PgDn): left where it is while any of the item shows.
    let (_, avail) = more(list.len(), h, app.top[ti]);
    if app.scrolled && end >= app.top[ti] && i < app.top[ti] + avail { app.top[ti] = app.top[ti].min(last_top(list.len(), h)); return; }
    app.scrolled = false;
    if h > 2 {
        if i < app.top[ti] { app.top[ti] = i.saturating_sub(1); }
        for _ in 0..3 {
            let (_, avail) = more(list.len(), h, app.top[ti]);
            if end >= app.top[ti] + avail { app.top[ti] = (end + 1 - avail).min(i); } else { break; }
        }
    }
    // A list that got shorter shows its last rows, not space under them.
    app.top[ti] = app.top[ti].min(last_top(list.len(), h));
}

/// Every log of a goal's agent processes, by where it is.
fn logs_of(app: &App, g: &GoalTrace) -> Vec<(String, std::path::PathBuf)> {
    let mut items = Vec::new();
    for b in &g.processes { for s in &b.searches { for c in &s.candidates { for l in &c.logs {
        items.push((format!("Process {} · Search {} · #{} · {l}", b.pid, s.search, c.index), app.root.join(".bon/traces").join(&b.trace).join(s.search.to_string()).join(c.index.to_string()).join(l)));
    } } } }
    items
}

/// The first search of a goal whose verified candidates show two behaviors, and one candidate of each.
fn two_behaviors(g: &GoalTrace) -> Option<(&BonProcess, &SearchTrace, &Facts, &Facts)> {
    g.processes.iter().flat_map(|b| b.searches.iter().map(move |s| (b, s))).find_map(|(b, s)| {
        let gs = groups(s);
        (gs.len() >= 2).then(|| (b, s, gs[0][0], gs[1][0]))
    })
}

/// The width from which the header is one row, cost beside what runs.
const HEAD_ONE_ROW: usize = 140;

/// What a line says when the file it would show is gone.
const GONE: &str = "This log is no longer on disk.";

fn draw(f: &mut Frame, app: &mut App) {
    let pal = app.palette;
    let area = f.area();
    let w = area.width as usize;
    let loaded = app.loaded.is_some();

    // Header: the repository, trunk and what is running; cost at the right:
    // generation and time, the same weight, then their total, muted. Its rows
    // depend on the width alone (one from HEAD_ONE_ROW columns, else two, the
    // cost on its own), so nothing moves when a read or a bon process arrives.
    // Before the first read, only the repository's name and that it is being
    // read, where trunk will be.
    let p = &app.p;
    let repo = &p.repo;
    let host = app.tab == Tab::Host;
    let name = if host { "Host".to_string() } else { repo.name.clone().unwrap_or_else(|| app.root.canonicalize().ok().and_then(|r| r.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_default()) };
    let mut left = vec![Span::styled(format!(" {name}"), pal.strong())];
    let head: Vec<Line> = if !loaded {
        left.push(Span::styled(" · Reading", pal.muted()));
        let mut rows = vec![clip(Line::from(left), w)];
        if w < HEAD_ONE_ROW { rows.push(Line::default()); }
        rows
    } else {
        // What runs now: the bon processes (on the host, across its repositories), and their running searches' agent processes by where each is.
        let (running, now) = if host {
            let ps = || app.host.trees.iter().flat_map(|g| &g.processes);
            (ps().count(), view::now_counts(ps().map(|r| r.in_flight).sum(), ps().map(|r| r.in_checks).sum(), ps().map(|r| r.waiting).sum()))
        } else {
            let live: Vec<&SearchTrace> = p.processes.iter().filter(|b| b.running).flat_map(|b| &b.searches).filter(|s| s.running).collect();
            let sum = |f: fn(&SearchTrace) -> u64| live.iter().map(|s| f(s)).sum::<u64>();
            (p.processes.iter().filter(|b| b.running).count(), view::now_counts(sum(|s| s.in_flight), sum(|s| s.in_checks), sum(|s| s.waiting)))
        };
        // Where: on the host, how many repositories it reaches; in one, trunk as bon works on it, the remote's ref.
        let at = if host { count(app.host.repositories.len(), "repository", "repositories") } else { view::trunk(repo.remote.as_deref(), repo.trunk.as_deref(), repo.remote_head.as_deref()) };
        if !at.is_empty() { left.push(Span::styled(format!(" · {at}"), pal.muted())); }
        left.push(Span::raw("   "));
        if running > 0 {
            left.push(Span::styled(format!("● Running {running}"), pal.tone(Tone::Orange)));
            if !now.is_empty() { left.push(Span::styled(format!(" · agent processes {now}"), pal.ink())); }
        } else { left.push(Span::styled("Idle", pal.muted())); }
        // What waits on engineer: the pending interrupts, which Project (or the host) lists first.
        let pending = if host { &app.host.interrupts } else { &p.interrupts }.iter().filter(|i| i.resolved.is_none()).count();
        if pending > 0 { left.push(Span::styled(format!("   ● Pending {pending}"), pal.tone(Tone::Yellow))); }
        let t = &p.totals;
        let cost = |gw: &str, rate: bool| {
            // The host's: engineer's time charged today, across its repositories.
            if host { return vec![Span::styled(money(Some(app.host.waiting.today)), pal.ink()), Span::styled(if rate { " of your time today " } else { " today " }, pal.muted())]; }
            let mut v = vec![Span::styled(money(Some(t.generation)), pal.ink()), Span::styled(format!(" {gw} + "), pal.muted()),
                Span::styled(money(Some(t.time_cost)), pal.ink()), Span::styled(" time", pal.muted())];
            if rate && !at_rate(t.rate).is_empty() { v.push(Span::styled(format!(" {}", at_rate(t.rate)), pal.muted())); }
            v.push(Span::styled(format!(" = {} ", money(Some(t.cost))), pal.muted()));
            v
        };
        // Too narrow for what runs in words: its counts go first, so Pending still shows.
        if width_of(&left) >= w { left.retain(|s| !s.content.starts_with(" · agent processes")); }
        let fits = |l: usize, r: &Vec<Span>| l + width_of(r) + 2 <= w;
        if w >= HEAD_ONE_ROW {
            // The shortest cost that fits beside what runs; what runs is cut, with …, before cost is.
            let c = [cost("generation", true), cost("generation", false), cost("gen", false)].into_iter().find(|c| fits(width_of(&left), c)).unwrap_or_else(|| cost("gen", false));
            let room = w.saturating_sub(width_of(&c) + 2);
            vec![spread(clip(Line::from(left), room).spans, c, w)]
        } else {
            let c = [cost("generation", true), cost("generation", false), cost("gen", false)].into_iter().find(|c| fits(1, c)).unwrap_or_else(|| cost("gen", false));
            let mut row = vec![Span::raw(" ")]; row.extend(c);
            vec![clip(Line::from(left), w), clip(Line::from(row), w)]
        }
    };
    let [top, tabs, rule, body, foot] = Layout::vertical([Constraint::Length(head.len() as u16), Constraint::Length(if host { 0 } else { 1 }), Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)]).areas(area);
    f.render_widget(Paragraph::new(head), top);

    // Tabs, with counts where a count says something, once read.
    let label = |tab: Tab| match tab {
        Tab::Project => "Project".to_string(),
        Tab::Spec => "Spec".to_string(),
        Tab::Queue if loaded => format!("Queue {}", p.queue.as_ref().map_or(0, |q| q.len())),
        Tab::Traces if loaded => format!("Traces {}", p.groups.len()),
        Tab::Queue => "Queue".into(),
        Tab::Traces => "Traces".into(),
        Tab::Host => "Host".into(),
    };
    let mut spans = vec![Span::raw(" ")];
    for tab in if host { &[Tab::Host][..] } else { &TABS[..] }.iter().copied() {
        let on = tab == app.tab;
        spans.push(Span::styled(format!(" {} ", label(tab)), if on { pal.strong().add_modifier(Modifier::UNDERLINED) } else { pal.muted() }));
        spans.push(Span::raw("  "));
    }
    f.render_widget(Paragraph::new(clip(Line::from(spans), w)), tabs);
    f.render_widget(Paragraph::new(Line::from(Span::styled("─".repeat(rule.width as usize), pal.rule()))), rule);

    // Body: the list, and the focused item's detail beside it or over it.
    let panes = panes(app, body);
    app.split = app.tab == Tab::Host && panes.beside;
    if panes.beside {
        let x = panes.list.right();
        for y in body.top()..body.bottom() { f.buffer_mut()[(x, y)].set_symbol("│").set_style(pal.rule()); }
    }
    if panes.list.width > 0 { app.list_w = panes.rows_w; app.list_h = panes.list.height; }
    let list = rows(app, app.list_w);
    let focusable = list.iter().filter(|r| r.focusable()).count();
    let ti = app.ti();
    place(app, &list, if panes.list.width > 0 { panes.list.height as usize } else { app.list_h as usize });
    // A detail opened over a list that has since emptied (a find that matched nothing) closes onto it.
    if app.detail_open && focusable == 0 { app.detail_open = false; }
    let list_len = list.len();
    if panes.list.width > 0 {
        let (up, avail) = more(list.len(), panes.list.height as usize, app.top[ti]);
        let down = app.top[ti] + avail < list.len();
        // The cursor: the focused row and the rows that continue it, in reverse video, the list's width.
        let lw = app.list_w as usize;
        let (focus, end) = (app.focus[ti], block_end(&list, app.focus[ti]));
        let mut lines: Vec<Line> = list.into_iter().enumerate().skip(app.top[ti]).take(avail).map(|(i, r)| {
            let l = clip(r.line, lw);
            if focusable > 0 && (focus..=end).contains(&i) { cursor_line(&pal, l, lw) } else { l }
        }).collect();
        if up { lines.insert(0, more_line(&pal, true)); }
        if down { lines.push(more_line(&pal, false)); }
        f.render_widget(Paragraph::new(lines), panes.list);
    }
    let mut detail_more = false;
    app.detail_shown = panes.detail.is_some();
    if let Some(d) = panes.detail {
        let inner = Rect { x: d.x + 1, width: d.width.saturating_sub(2), ..d };
        app.detail_h = inner.height;
        let (text, marks) = detail_marked(app, inner.width);
        let lines = text.lines;
        let h = inner.height as usize;
        // Its lines fit the pane, so a line is a row.
        detail_more = lines.len() > h;
        // Scrolled to line s: the title, the process above, its search and a table's header
        // whose rows continue stay at the top, each while what it heads is on screen (and
        // only where at least three rows of what scrolls remain under them); then the cues.
        let layout = |s: usize| -> (Vec<usize>, bool, bool, usize) {
            let last = |m: Mark| marks.iter().rev().find(|(i, k)| *k == m && *i < s).map(|(i, _)| *i);
            let open = |at: usize, ends: &[Mark]| !marks.iter().any(|(i, k)| *i > at && *i <= s && ends.contains(k));
            let mut pins: Vec<usize> = Vec::new();
            if s > 0 && h >= 8 {
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
            (pins, up, down, room.saturating_sub(down as usize))
        };
        // It scrolls no further than the first line from which its last line shows.
        let end = (0..lines.len().max(1)).find(|&s| !layout(s).2).unwrap_or(0);
        let s = (app.detail_top as usize).min(end);
        if !lines.is_empty() { app.detail_top = s as u16; }
        let (pins, up, down, room) = layout(s);
        // A page of the detail is what it shows under its pinned lines and cues.
        app.detail_page = room.max(1) as u16;
        let mut shown: Vec<Line> = Vec::new();
        if up { shown.push(more_line(&pal, true)); }
        shown.extend(pins.iter().map(|i| lines[*i].clone()));
        shown.extend(lines.into_iter().skip(s).take(room));
        if down { shown.push(more_line(&pal, false)); }
        f.render_widget(Paragraph::new(shown), inner);
    }
    // An overlay covers the body. Its long lines wrap, and it scrolls by the rows they wrap to.
    let bw = body.width as usize;
    app.body_h = body.height;
    // A text as the rows it wraps to at `w`: no character is cut off, none is lost.
    let rows_of = |text: &[String], w: usize| -> Vec<String> {
        text.iter().flat_map(|l| {
            let c: Vec<char> = l.chars().collect();
            if c.is_empty() { vec![String::new()] } else { c.chunks(w.max(1)).map(|p| p.iter().collect()).collect::<Vec<String>>() }
        }).collect()
    };
    match &mut app.overlay {
        Overlay::None => {}
        Overlay::Logs { items, sel } => {
            f.render_widget(ratatui::widgets::Clear, body);
            let mut lines = vec![section(&pal, 1, "Logs", Some(items.len())), Line::default()];
            let h = body.height.saturating_sub(2) as usize;
            let first = sel.saturating_sub(h.saturating_sub(1));
            for (i, (label, _)) in items.iter().enumerate().skip(first).take(h) {
                let l = Line::from(Span::styled(format!(" {}", fit(label, bw.saturating_sub(1))), pal.ink()));
                lines.push(if i == *sel { cursor_line(&pal, l, bw) } else { l });
            }
            f.render_widget(Paragraph::new(lines), body);
        }
        Overlay::Text { title, lines, top } => {
            f.render_widget(ratatui::widgets::Clear, body);
            let [head, text] = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).areas(body);
            let rows = rows_of(lines, text.width.saturating_sub(2) as usize);
            *top = (*top).min(rows.len().saturating_sub(text.height as usize));
            app.overlay_rows = rows.len().saturating_sub(text.height as usize) + 1;
            let at = vec![Span::styled(format!("Row {} of {} ", *top + 1, rows.len()), pal.muted())];
            f.render_widget(Paragraph::new(spread(vec![Span::styled(format!(" {}", fit(title, bw.saturating_sub(width_of(&at) + 2))), pal.strong())], at, bw)), head);
            let shown: Vec<Line> = rows.into_iter().skip(*top).take(text.height as usize).map(|l| Line::from(Span::styled(l, pal.ink()))).collect();
            f.render_widget(Paragraph::new(shown), Rect { x: text.x + 1, width: text.width.saturating_sub(2), ..text });
        }
        Overlay::Compare { titles, left, right, top } => {
            f.render_widget(ratatui::widgets::Clear, body);
            let [l, _, r] = Layout::horizontal([Constraint::Percentage(50), Constraint::Length(1), Constraint::Percentage(50)]).areas(body);
            // Each output wraps in its pane; a row the other side has too is muted.
            let pane_w = l.width.min(r.width).saturating_sub(1) as usize;
            let (lr, rr) = (rows_of(left, pane_w), rows_of(right, pane_w));
            let h = body.height.saturating_sub(2) as usize;
            *top = (*top).min(lr.len().max(rr.len()).saturating_sub(h));
            app.overlay_rows = lr.len().max(rr.len()).saturating_sub(h) + 1;
            for (area, title, rows, other) in [(l, &titles.0, &lr, &rr), (r, &titles.1, &rr, &lr)] {
                let [head, rest] = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).areas(area);
                f.render_widget(Paragraph::new(Line::from(Span::styled(format!(" {}", fit(title, area.width.saturating_sub(1) as usize)), pal.strong()))), head);
                let out: Vec<Line> = rows.iter().enumerate().skip(*top).take(rest.height as usize)
                    .map(|(i, row)| Line::from(Span::styled(row.clone(), if other.get(i) == Some(row) { pal.muted() } else { pal.ink() }))).collect();
                f.render_widget(Paragraph::new(out), Rect { x: rest.x + 1, width: rest.width.saturating_sub(1), ..rest });
            }
            for y in body.top()..body.bottom() { f.buffer_mut()[(l.right(), y)].set_symbol("│").set_style(pal.rule()); }
        }
    }

    // Footer: what each key does now, and only the keys that would change
    // something; or an error reading the projection.
    // Find and Range as the shown projection was read, so the footer and the rows agree.
    let pf = &app.p.filter;
    let filter = view::Filter { since: pf.since.map(|t| t as u64), until: pf.until.map(|t| t as u64), find: pf.find.clone() };
    let fw = foot.width as usize;
    // What is being typed shows over an error: the error is still there when it is done.
    let foot_line = if let Some(buf) = &app.input { let mut l = vec![Span::styled(" Find  ", pal.muted()), Span::styled(format!("{buf}▏   "), pal.ink())]; l.extend(key_bar(&pal, &[("⏎", "Apply".into(), 1), ("esc", "Cancel".into(), 1)], fw).spans); clip(Line::from(l), fw) }
    else if let Some(e) = &app.error { clip(Line::from(Span::styled(format!(" {e}"), pal.tone(Tone::Red))), fw) }
    else {
        let shown = panes.detail.is_some();
        let items: Vec<(&str, String, u8)> = match &app.overlay {
            Overlay::Logs { items, .. } => { let mut v = vec![("⏎", "Open".into(), 3), ("esc", "Close".into(), 3)]; if items.len() > 1 { v.insert(0, ("↑↓", "Move".into(), 3)); } v }
            Overlay::Text { .. } | Overlay::Compare { .. } => vec![("↑↓ PgUp PgDn", "Scroll".into(), 3), ("esc", "Close".into(), 3)],
            Overlay::None if !loaded => vec![("⇥", "Tab".into(), 3), ("?", "Keys".into(), 6), ("q", "Quit".into(), 9)],
            Overlay::None => {
                let goal_now = (app.tab == Tab::Traces).then(|| focused(app).and_then(|k| goal(&app.p, &k))).flatten();
                // Narrow, what the open detail binds outranks what ? lists anyway.
                let mut v: Vec<(&str, String, u8)> = Vec::new();
                if focusable > 1 && panes.list.width > 0 { v.push(("↑↓", "Move".into(), 5)); }
                else if focusable == 0 && list_len > panes.list.height as usize { v.push(("↑↓", "Scroll".into(), 5)); }
                if has_detail(app.tab) && !panes.beside {
                    if app.detail_open { v.push(("esc", "Close".into(), 9)); } else if focusable > 0 { v.push(("⏎", "Open".into(), 9)); }
                }
                if shown && detail_more { v.push(("⇧↑↓", "Scroll".into(), 8)); }
                if shown { if let Some(g) = goal_now {
                    if !logs_of(app, g).is_empty() { v.push(("l", "Logs".into(), 7)); }
                    if two_behaviors(g).is_some() { v.push(("d", "Compare".into(), 7)); }
                } }
                // The host is one tab.
                if app.tab != Tab::Host { v.push(("⇥", "Tab".into(), 3)); }
                // Find and Range only where there are bon processes to filter, or a filter to undo.
                let narrowed = filter.find.is_some() || filter.since.is_some() || filter.until.is_some();
                if filtered(app.tab) && (!app.p.groups.is_empty() || narrowed) {
                    v.push(("/", filter.find.as_deref().map_or("Find".to_string(), |f| format!("Find: {f}")), 4));
                    v.push(("r", range_label(app, &filter), 2));
                }
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
        // Its rows: each group's heading and keys, and a blank row between groups where they fit.
        let content: usize = KEYS.iter().map(|(_, ks)| ks.len() + 1).sum();
        let spaced = (content + KEYS.len() - 1 + 2) as u16 <= area.height;
        let n = content + if spaced { KEYS.len() - 1 } else { 0 };
        let w = 72.min(area.width); let h = (n as u16 + 2).min(area.height);
        let r = Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h };
        f.render_widget(ratatui::widgets::Clear, r);
        let mut all = vec![];
        for (i, (where_, ks)) in KEYS.iter().enumerate() {
            if i > 0 && spaced { all.push(Line::default()); }
            all.push(section(&pal, 1, where_, None));
            for (k, what) in ks.iter() { all.push(clip(Line::from(vec![Span::styled(format!("   {}", fit(k, kw)), pal.ink().add_modifier(Modifier::BOLD)), Span::styled(what.to_string(), pal.muted())]), w.saturating_sub(2) as usize)); }
        }
        // Too short for every key: it scrolls, with the panes' cues.
        let inner = h.saturating_sub(2) as usize;
        app.keys_top = app.keys_top.min(last_top(all.len(), inner));
        let (up, avail) = more(all.len(), inner, app.keys_top);
        let down = app.keys_top + avail < all.len();
        let mut shown: Vec<Line> = all.into_iter().skip(app.keys_top).take(avail).collect();
        if up { shown.insert(0, more_line(&pal, true)); }
        if down { shown.push(more_line(&pal, false)); }
        f.render_widget(Paragraph::new(shown).block(ratatui::widgets::Block::bordered().border_style(pal.rule()).title(Span::styled(" Keys ", pal.strong()))), r);
    }
}

/// The range r has set, or the one bon was started with: what the footer says.
fn range_label(app: &App, f: &view::Filter) -> String {
    // r's range once the read for it is shown; until then, what is shown.
    let asked = app.filter.lock().map(|x| x.since).unwrap_or(None);
    if app.range > 0 && f.since == asked { return format!("Range: {}", RANGES[app.range].0); }
    match (f.since, f.until) {
        (None, None) => "Range".into(),
        (s, u) => format!("Range:{}{}", s.map_or(String::new(), |t| format!(" since {}", view::date(t))), u.map_or(String::new(), |t| format!(" until {}", view::date(t)))),
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
    (app.p, app.host) = read(std::path::Path::new(root), &view::Filter::default())?;
    app.loaded = Some(Instant::now());
    // Outside every repository, the host is the one tab.
    app.tab = if root.is_empty() { Tab::Host } else { TABS[tab.min(3)] };
    if light { app.dark = false; app.palette = LIGHT; }
    let mut t = ratatui::Terminal::new(TestBackend::new(w, h)).map_err(|e| e.to_string())?;
    // A first draw sets the list's width; then focus the focus-th focusable row at that width.
    t.draw(|f| draw(f, &mut app)).map_err(|e| e.to_string())?;
    let list = rows(&app, app.list_w);
    let rows_n = list.iter().filter(|r| r.focusable()).count();
    match list.iter().enumerate().filter(|(_, r)| r.focusable()).nth(focus) {
        Some((i, _)) => app.focus_on(&list, i),
        None if focus > 0 => return Err(format!("--focus {focus} is not a row; this tab has {}", count(rows_n, "row to focus, 0", &format!("rows to focus, 0 to {}", rows_n.saturating_sub(1))))),
        None => {}
    }
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
    app.loaded = Some(Instant::now());
    app.tab = Tab::Spec;
    let list = rows(&app, width);
    let Some(name) = name else { return Ok(list.into_iter().map(|r| plain(Text::from(r.line))).collect::<Vec<_>>().join("\n") + "\n") };
    let spec = app.p.spec.clone().unwrap_or_default();
    let key = spec.items.iter().any(|i| i.name == name).then(|| Key::Item(name.to_string())).or_else(|| (name == "fields" || name == "state").then_some(Key::Grid))
        .ok_or_else(|| format!("no {name} in the spec; bon spec lists every item"))?;
    let at = list.iter().position(|r| r.key.as_ref() == Some(&key)).ok_or("not listed")?;
    app.focus_on(&list, at);
    Ok(plain(detail(&app, width)) + "\n")
}

// ── input ───────────────────────────────────────────────

/// Handle one key; false to quit.
fn key(app: &mut App, k: KeyEvent) -> bool {
    // Ctrl-C quits, whatever is open: in raw mode it is a key like any other.
    if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) { return false; }
    // Keys: ↑↓ and PgUp PgDn scroll it where it does not fit; any other key closes it.
    if app.keys {
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => app.keys_top = app.keys_top.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => app.keys_top += 1,
            KeyCode::PageUp => app.keys_top = app.keys_top.saturating_sub(app.body_h as usize / 2),
            KeyCode::PageDown => app.keys_top += app.body_h as usize / 2,
            KeyCode::Char('g') => app.keys_top = 0,
            KeyCode::Char('G') => app.keys_top = usize::MAX,
            KeyCode::Char('q') => return false,
            _ => { app.keys = false; app.keys_top = 0; }
        }
        return true;
    }
    // Typing after /: find, in any case (the filter compares without case).
    if let Some(buf) = app.input.as_mut() {
        match k.code {
            KeyCode::Esc => app.input = None,
            KeyCode::Enter => { let f = app.input.take().filter(|s| !s.is_empty()); app.filter.lock().map(|mut x| x.find = f).ok(); }
            KeyCode::Backspace => { buf.pop(); }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        return true;
    }
    // An overlay's page: the body under its two heading rows.
    let body_page = (app.body_h as usize).saturating_sub(2).max(1);
    let overlay_rows = app.overlay_rows;
    match &mut app.overlay {
        Overlay::None => {}
        Overlay::Logs { items, sel } => {
            match k.code {
                KeyCode::Esc => app.overlay = Overlay::None,
                KeyCode::Char('q') => return false,
                KeyCode::Up | KeyCode::Char('k') => *sel = sel.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *sel = (*sel + 1).min(items.len().saturating_sub(1)),
                KeyCode::PageUp => *sel = sel.saturating_sub(body_page),
                KeyCode::PageDown => *sel = (*sel + body_page).min(items.len().saturating_sub(1)),
                KeyCode::Char('g') => *sel = 0,
                KeyCode::Char('G') => *sel = items.len().saturating_sub(1),
                KeyCode::Enter => if let Some((label, path)) = items.get(*sel).cloned() {
                    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| GONE.into());
                    app.overlay = Overlay::Text { title: label, lines: text.lines().map(String::from).collect(), top: 0 };
                },
                _ => {}
            }
            return true;
        }
        Overlay::Text { top, .. } => {
            scroll(top, overlay_rows, k, body_page);
            if k.code == KeyCode::Esc { app.overlay = Overlay::None; }
            return k.code != KeyCode::Char('q');
        }
        Overlay::Compare { top, .. } => {
            scroll(top, overlay_rows, k, body_page);
            if k.code == KeyCode::Esc { app.overlay = Overlay::None; }
            return k.code != KeyCode::Char('q');
        }
    }
    let ti = app.ti();
    let list = rows(app, app.list_w);
    let focusable: Vec<usize> = (0..list.len()).filter(|&i| list[i].focusable()).collect();
    // Whether ⇧↑↓ and PgUp PgDn scroll the detail: only where one shows.
    let detail_shown = app.detail_shown;
    // The list moves its focus by `by` rows (down when positive), or, with nothing to focus, scrolls.
    let mv = |app: &mut App, by: isize| {
        if focusable.is_empty() {
            app.top[ti] = if by > 0 { app.top[ti].saturating_add(by as usize) } else { app.top[ti].saturating_sub(by.unsigned_abs()) };
            return;
        }
        let at = app.focus[ti] as isize + by;
        let i = if by > 0 { focusable.iter().copied().find(|&j| j as isize >= at).or(focusable.last().copied()) }
                else { focusable.iter().rev().copied().find(|&j| j as isize <= at).or(focusable.first().copied()) };
        if let Some(i) = i { app.focus_on(&list, i); app.scrolled = false; }
    };
    let detail_page = app.detail_page.max(1);
    // A page of the list: its rows between the cues.
    let list_page = (app.list_h as isize - 2).max(1);
    match (k.code, k.modifiers) {
        (KeyCode::Char('q'), _) => return false,
        (KeyCode::Esc, _) => app.detail_open = false,
        (KeyCode::Char('?'), _) => app.keys = true,
        (KeyCode::Tab, _) => app.switch(TABS[(ti + 1) % 4]),
        (KeyCode::BackTab, _) => app.switch(TABS[(ti + 3) % 4]),
        (KeyCode::Char(c @ '1'..='4'), _) => app.switch(TABS[c as usize - '1' as usize]),
        // The detail scrolls where one shows; otherwise the list does.
        (KeyCode::Up, KeyModifiers::SHIFT) if detail_shown => app.detail_top = app.detail_top.saturating_sub(1),
        (KeyCode::Down, KeyModifiers::SHIFT) if detail_shown => app.detail_top = app.detail_top.saturating_add(1),
        (KeyCode::PageUp, _) if detail_shown => app.detail_top = app.detail_top.saturating_sub(detail_page),
        (KeyCode::PageDown, _) if detail_shown => app.detail_top = app.detail_top.saturating_add(detail_page),
        // A list of items with no detail beside it scrolls through its rows, an item's wrapped lines
        // included; the focus follows to an item that shows.
        (KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown, m) if !focusable.is_empty() && (m.contains(KeyModifiers::SHIFT) || matches!(k.code, KeyCode::PageUp | KeyCode::PageDown)) => {
            let by = match k.code { KeyCode::Up => -1, KeyCode::Down => 1, KeyCode::PageUp => -list_page, _ => list_page };
            let h = app.list_h as usize;
            app.top[ti] = (app.top[ti] as isize + by).clamp(0, last_top(list.len(), h) as isize) as usize;
            let (_, avail) = more(list.len(), h, app.top[ti]);
            let (top, i) = (app.top[ti], app.focus[ti]);
            if block_end(&list, i) < top || i >= top + avail {
                if let Some(&j) = focusable.iter().find(|&&j| block_end(&list, j) >= top) { app.focus_on(&list, j); }
            }
            app.scrolled = true;
        }
        (KeyCode::PageUp, _) => mv(app, -list_page),
        (KeyCode::PageDown, _) => mv(app, list_page),
        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => mv(app, -1),
        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => mv(app, 1),
        (KeyCode::Char('g'), _) => { app.top[ti] = 0; if let Some(&i) = focusable.first() { app.focus_on(&list, i); } }
        // The last item, and its last line.
        (KeyCode::Char('G'), _) => match focusable.last() {
            Some(&i) => { app.focus_on(&list, i); app.top[ti] = last_top(list.len(), app.list_h as usize); app.scrolled = true; }
            None => app.top[ti] = usize::MAX,
        },
        // Under 100 columns the detail opens over the list; beside it, it is already open.
        (KeyCode::Enter, _) if has_detail(app.tab) && !focusable.is_empty() && !app.detail_shown => app.detail_open = true,
        (KeyCode::Char('t'), _) => { app.dark = !app.dark; app.palette = if app.dark { DARK } else { LIGHT }; }
        (KeyCode::Char('/'), _) if filtered(app.tab) && app.loaded.is_some() => app.input = Some(app.filter.lock().ok().and_then(|f| f.find.clone()).unwrap_or_default()),
        // The next range; All time clears both bounds, whatever bon was started with.
        (KeyCode::Char('r'), _) if filtered(app.tab) && app.loaded.is_some() => {
            app.range = (app.range + 1) % RANGES.len();
            let since = (RANGES[app.range].1 > 0).then(|| (app.p.repo.now - RANGES[app.range].1).max(0) as u64);
            app.filter.lock().map(|mut f| { f.since = since; f.until = None; }).ok();
        }
        // Traces: every log of the focused goal's agent processes.
        (KeyCode::Char('l'), _) if app.tab == Tab::Traces => {
            if let Some(g) = focused(app).and_then(|k| goal(&app.p, &k)) {
                let items = logs_of(app, g);
                if !items.is_empty() { app.overlay = Overlay::Logs { items, sel: 0 }; }
            }
        }
        // Traces: two groups of disagreeing candidates, their agree output side by side.
        (KeyCode::Char('d'), _) if app.tab == Tab::Traces => {
            if let Some((b, s, x, y)) = focused(app).and_then(|k| goal(&app.p, &k)).and_then(two_behaviors) {
                let side = |c: &Facts| {
                    let dir = app.root.join(".bon/traces").join(&b.trace).join(s.search.to_string()).join(c.index.to_string());
                    let name = c.logs.iter().find(|l| l.starts_with("agree")).cloned().unwrap_or("agree-0".into());
                    (format!("#{} {name}", c.index), std::fs::read_to_string(dir.join(&name)).unwrap_or_else(|_| GONE.into()).lines().map(String::from).collect::<Vec<_>>())
                };
                let ((lt, l), (rt, r)) = (side(x), side(y));
                app.overlay = Overlay::Compare { titles: (lt, rt), left: l, right: r, top: 0 };
            }
        }
        _ => {}
    }
    true
}

/// One key's scroll of a text `n` lines long, a page at a time with PgUp PgDn.
fn scroll(top: &mut usize, n: usize, k: KeyEvent, page: usize) {
    let last = n.saturating_sub(1);
    match k.code {
        KeyCode::Up | KeyCode::Char('k') => *top = top.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => *top = (*top + 1).min(last),
        KeyCode::PageUp => *top = top.saturating_sub(page),
        KeyCode::PageDown | KeyCode::Char(' ') => *top = (*top + page).min(last),
        KeyCode::Char('g') => *top = 0,
        KeyCode::Char('G') => *top = last,
        _ => {}
    }
}

// ── the loop ────────────────────────────────────────────

/// Whether `bon` with these arguments should be the terminal view.
pub fn wanted() -> bool { std::io::stdout().is_terminal() && std::io::stdin().is_terminal() }

/// Run the terminal view until q. The projection is read every 2 s on a thread
/// of its own, so input never waits on the traces.
/// What the view draws, read once: a repository's projection and its part of
/// the host; outside every repository (`root` empty), the host alone.
fn read(root: &std::path::Path, filter: &view::Filter) -> Result<(Projection, projection::Host), String> {
    let host = |v: serde_json::Value| serde_json::from_value::<projection::Host>(v).map_err(|e| format!("the host's projection does not match its types: {e}"));
    if root.as_os_str().is_empty() { return Ok((Projection::default(), host(crate::host::state(None))?)); }
    let v = view::state(root, filter);
    let h = host(crate::host::slice(root, &v))?;
    Ok((serde_json::from_value(v).map_err(|e| format!("the projection does not match its types: {e}"))?, h))
}

pub fn run(root: &str, filter: view::Filter) -> Result<(), String> {
    let (tx, rx) = mpsc::channel::<Result<(Projection, projection::Host), String>>();
    let mut app = App::new();
    app.root = root.into();
    if root.is_empty() { app.tab = Tab::Host; }
    app.filter = std::sync::Arc::new(std::sync::Mutex::new(filter));
    let (root_t, shared) = (app.root.clone(), app.filter.clone());
    // Read the projection every 2 s, or as soon as find or the range changes.
    std::thread::spawn(move || {
        let mut last: Option<(Option<u64>, Option<u64>, Option<String>)> = None;
        let mut at = Instant::now() - Duration::from_secs(10);
        loop {
            let f = shared.lock().map(|f| f.clone()).unwrap_or_default();
            let now_key = (f.since, f.until, f.find.clone());
            if last.as_ref() != Some(&now_key) || at.elapsed() >= Duration::from_secs(2) {
                if tx.send(read(&root_t, &f)).is_err() { break; }
                last = Some(now_key); at = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    // ratatui draws into a buffer and writes only the cells that changed since the last frame.
    let mut terminal: DefaultTerminal = ratatui::init();
    let result = (|| -> Result<(), String> {
        loop {
            while let Ok(p) = rx.try_recv() {
                // A read made for a find or range since changed is not shown: the read for the new one follows.
                let asked = app.filter.lock().map(|f| (f.since, f.until, f.find.clone())).unwrap_or_default();
                match p {
                    Ok((p, _)) if (p.filter.since.map(|t| t as u64), p.filter.until.map(|t| t as u64), p.filter.find.clone()) != asked => {}
                    Ok((p, h)) => { app.p = p; app.host = h; app.error = None; app.loaded = Some(Instant::now()); }
                    Err(e) => app.error = Some(e),
                }
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

    /// The view once the projection has been read.
    fn ready() -> App { let mut a = App::new(); a.loaded = Some(Instant::now()); a }

    fn screen(p: Projection, tab: Tab, w: u16, h: u16) -> String {
        let mut app = ready();
        app.p = p; app.tab = tab;
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let b = t.backend().buffer().clone();
        (0..h).map(|y| (0..w).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().trim_end().to_string()).collect::<Vec<_>>().join("\n")
    }

    /// A host with something pending, two bon processes from one tree and one between searches, a journal and repositories.
    fn host() -> projection::Host {
        let now = 1_800_000_000;
        let running = |pid: u64, repo: &str| serde_json::json!({ "pid": pid, "repository": repo, "root": format!("/u/{repo}"), "kind": "code", "goal": "a".repeat(40),
            "search": 0, "start": now - 300, "memory": 1.4, "sentence": "code: 3 of 8 returned", "width": 8, "returned": 3, "verified": 1, "in_flight": 5, "in_checks": 0, "waiting": 0 });
        serde_json::from_value(serde_json::json!({
            "user": "/u", "now": now,
            "repositories": [{ "name": "alpha", "root": "/u/alpha", "configured": true, "pending": 1, "running": 2, "latest": now - 300, "today": 3.2 },
                             { "name": "sandbox", "root": format!("/far/away/{}/sandbox", "deep".repeat(20)), "configured": true, "running": 1, "today": 0.0 },
                             { "name": "plain", "root": "/u/plain", "configured": false }],
            "interrupts": [{ "kind": "transcript", "id": "transcript x", "root": "/u", "about": "call-17.vtt", "raised": now - 240,
                "what": ["meeting title \"Gamma intro\": no route matches its title"],
                "choices": [{ "choice": "route", "how": format!("add \"Gamma intro\" = \"<repository>\" to [routes] in /etc/bon/{}host.toml, then bon pending", "x".repeat(90)), "cost": "a queue search" }] }],
            "waiting": { "searches": 2, "host": 3, "per_hour": 103.33, "today": 12.4 },
            "pools": { "agent_processes": { "size": 64, "held": 12, "shown": 10 }, "check_processes": { "size": 14, "held": 3, "shown": 1 }, "check_threads": 2 },
            "memory": { "total": 64.0, "free": 41.2, "bon": 6.1 },
            "trees": [{ "tree": "b".repeat(40), "processes": [running(11, "alpha"), running(12, "alpha")] }, { "tree": null, "processes": [{ "pid": 13, "repository": "sandbox", "start": now - 30, "sentence": "starting", "background": true }] }],
            "journal": [{ "time": now - 90000, "repository": "alpha", "kind": "pushed", "text": "code from abc1234: pushed 5ebac2f · $1.20" },
                        { "time": now - 240, "repository": "", "kind": "raised", "text": format!("transcript call-17.vtt: waits on you {}", "y".repeat(200)) }],
        })).unwrap()
    }

    #[test]
    fn the_host_draws_at_every_width_with_nothing_past_its_pane() {
        for (w, h) in [(60, 24), (80, 50), (100, 30), (120, 12), (200, 50), (60, 8)] {
            let mut app = App::new();
            app.host = host(); app.tab = Tab::Host; app.loaded = Some(Instant::now());
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
            // Every row of both panes fits its pane.
            let left = rows(&app, app.list_w);
            assert!(left.iter().all(|r| width_of(&r.line.spans) <= app.list_w as usize), "{w}: a left row is wider than {}", app.list_w);
            let pane = if app.split { (w - app.list_w - 3) as usize } else { w as usize };
            assert!(detail(&app, pane as u16).lines.iter().all(|l| width_of(&l.spans) <= pane), "{w}: a right line is wider than {pane}");
            let b = t.backend().buffer().clone();
            let s = (0..h).map(|y| (0..w).map(|x| b[(x, y)].symbol().to_string()).collect::<String>()).collect::<Vec<_>>().join("\n");
            // What waits on engineer leads; the host has no tab row and no find or range.
            let first = s.lines().skip_while(|l| !l.starts_with('─')).nth(1).unwrap_or("");
            assert!(s.contains("Host · 3 repositories") && s.contains("● Pending 1") && first.contains("Pending  1"), "{w}x{h}:\n{s}");
            // The header's line fits, cut with … where it must be.
            assert!(s.lines().next().is_some_and(|l| l.contains("Running 3")), "{w}x{h}:\n{s}");
            assert!(!s.contains("Find") && !s.contains("Range") && !s.contains("Traces"), "{w}x{h}:\n{s}");
            if h >= 40 {
                assert!(s.contains("Tree bbbbbbb · 2 bon processes from one tree") && s.contains("12 of 64 held") && s.contains("background"), "{w}x{h}:\n{s}");
                assert!(s.contains("Pushed") && s.contains("Yesterday") && s.contains("no .bon/bon.toml at trunk's head"), "{w}x{h}:\n{s}");
            }
            assert_eq!(app.split, w >= 100);
        }
    }

    #[test]
    fn the_host_says_what_is_empty_and_nothing_before_its_first_read() {
        let mut app = App::new();
        app.tab = Tab::Host;
        let mut t = Terminal::new(TestBackend::new(80, 30)).unwrap();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let b = t.backend().buffer().clone();
        let s: String = (0..30).map(|y| (0..80).map(|x| b[(x, y)].symbol().to_string()).collect::<String>() + "\n").collect();
        // Before the first read: no counts, no zeros.
        assert!(s.contains("Host · Reading") && !s.contains("$0.00") && !s.contains("Idle"), "{s}");
        app.loaded = Some(Instant::now());
        t.draw(|f| draw(f, &mut app)).unwrap();
        let b = t.backend().buffer().clone();
        let s: String = (0..30).map(|y| (0..80).map(|x| b[(x, y)].symbol().to_string()).collect::<String>() + "\n").collect();
        for empty in ["Nothing waits on you", "No bon process is running", "No push, block or interrupt yet", "No host file names the user layer"] {
            assert!(s.contains(empty), "{empty}:\n{s}");
        }
        // A pool the host file does not size says so; nothing pretends to a size.
        assert!(s.contains("unsized: no host file"), "{s}");
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
            // Under 140 columns the cost has the header's second row, whatever runs.
            assert!(traces.lines().nth(1).unwrap().contains("$2.00 gen") && traces.lines().nth(1).unwrap().contains("= $10.00"), "{traces}");
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
        assert!(sp.contains("may_open") && sp.contains("Gate  Implementation") && sp.contains("✓     ✓") && !sp.contains("✓ Present"), "{sp}");
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
        let mut app = ready();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        app.p.groups = vec![foiled()];
        // Scrolled into the counterexample search's table: the cue, the title, the process,
        // the search's heading and the table's header, then its rows.
        let mut t = Terminal::new(TestBackend::new(140, 16)).unwrap();
        t.draw(|f| draw(f, &mut app)).unwrap();
        // Scrolled as far as it goes (its last page): the cue, the title, the process,
        // and the counterexample search's heading over its table.
        app.detail_top = u16::MAX;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let b = t.backend().buffer().clone();
        let row = |y: u16| (63..140).map(|x| b[(x, y)].symbol().to_string()).collect::<String>();
        let top: Vec<String> = (3..8).map(row).collect();
        assert!(top[0].contains("↑ more") && top[1].contains("Code from 9bb8a5b") && top[2].contains("Process 7"), "{top:#?}");
        // No further than its last page: its last line is on the pane's last row.
        let last = detail_marked(&app, 140 - 63 - 1 - 2).0.lines.last().map(|l| l.spans.iter().map(|s| s.content.to_string()).collect::<String>()).unwrap();
        let pane: Vec<String> = (3..15).map(row).collect();
        assert!(pane.iter().any(|r| r.trim_end().ends_with(last.trim_end())) && !pane.iter().any(|r| r.contains("↓ more")), "{pane:#?}");
        // Scrolled past it to the end, no search is pinned whose rows are gone.
        app.detail_top = u16::MAX;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let b = t.backend().buffer().clone();
        let all: String = (4..15).map(|y| (63..140).map(|x| b[(x, y)].symbol().to_string()).collect::<String>() + "\n").collect();
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
        assert_eq!(rank_note(&s, &rank_shown(&s)).unwrap(), "Selected #0 by fewest lines: −19 against #1's −4");
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
        assert_eq!(money(Some(-1.5)), "−$1.50");
        assert_eq!(money(Some(-12.444)), "−$12.44");
        assert_eq!(view::money(-0.004), "$0.00");
        assert_eq!(money(None), "—");
    }

    #[test]
    fn switching_tabs_closes_an_open_detail() {
        let mut app = ready();
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
        let mut app = ready();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 } })).unwrap();
        app.p.groups = vec![foiled()];
        app.tab = Tab::Traces;
        let b = buffer(&mut app, 140, 30);
        // The focused goal's row, the list's width, in reverse video; no cell anywhere is blue but a selection's.
        let row = (0..30).find(|&y| b[(1, y)].modifier.contains(Modifier::REVERSED)).expect("a reversed row");
        assert!((0..60).all(|x| b[(x, row)].modifier.contains(Modifier::REVERSED)));
        assert!((0..62).all(|x| b[(x, row)].fg == rgb(DARK.ink)), "one style under the cursor");
        // One blank column between the list and the rule.
        assert!(!b[(62, row)].modifier.contains(Modifier::REVERSED) && b[(63, row)].symbol() == "│");
        assert!(!(0..30).any(|y| (0..140).any(|x| b[(x, y)].symbol() == "▎")));
        // Queue's focused intent and its continuation lines are under it too.
        let mut q = ready();
        q.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 10 },
            "queue": [{ "id": 7, "intent": "word ".repeat(40) }, { "id": 8, "intent": "next" }] })).unwrap();
        q.tab = Tab::Queue;
        let b = buffer(&mut q, 80, 20);
        let reversed: Vec<u16> = (0..20).filter(|&y| b[(0, y)].modifier.contains(Modifier::REVERSED)).collect();
        assert_eq!(reversed, vec![4, 5, 6], "#7's three lines, under the header's two rows");
        // The frame's HTML draws reverse video as swapped colors.
        assert!(frame_html(&b, false).contains("color:#09090A;background:#edeae5"));
    }

    #[test]
    fn a_goal_the_kernel_disagrees_on_is_red_in_its_list_and_its_detail() {
        let mut g = foiled();
        g.processes[0].searches[0].kernel = "derived".into();
        g.processes[0].searches[0].recorded_selected = Some(0);
        assert!(matches!(goal_tone(&g), Tone::Red));
        let mut app = ready();
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
        let mut app = ready();
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
        assert!(!(0..60).any(|y| (0..120).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().contains("No push ")));
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
        let mut app = ready();
        app.p = p; app.tab = Tab::Spec;
        let b = buffer(&mut app, 140, 30);
        let y = (0..30).find(|&y| (63..140).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().contains("≠ Differs from trunk")).unwrap();
        let x = (63..140).find(|&x| b[(x, y)].symbol() == "≠").unwrap();
        assert_eq!(b[(x, y)].fg, rgb(DARK.ink));
    }

    #[test]
    fn the_header_says_what_runs_now_and_trunk_as_the_remotes() {
        let mut app = ready();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true,
            "repo": { "name": "r", "trunk": "main", "remote": "origin", "head": "1111111aaa", "remote_head": "2222222bbb", "now": 10 },
            "processes": [{ "pid": 1, "running": true, "searches": [{ "kind": "code", "running": true, "in_flight": 5, "in_checks": 2, "waiting": 1 }] }] })).unwrap();
        let b = buffer(&mut app, 160, 10);
        let head: String = (0..160).map(|x| b[(x, 0)].symbol().to_string()).collect();
        assert!(head.contains("r · trunk origin/main 2222222   ● Running 1 · agent processes 5 in flight, 2 in checks, 1 waiting"), "{head}");
        assert!(!head.contains("1111111"));
    }

    #[test]
    fn project_scrolls_and_a_counterexample_says_how_many_tests_ran() {
        let mut app = ready();
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

    /// A goal of `kind` from `commit`, its one bon process `trace`, at `time`.
    fn goal_at(trace: &str, kind: &str, commit: &str, time: i64, outcome: &str) -> GoalTrace {
        let candidate = serde_json::json!({ "index": 1, "commit": "1111111", "accepted": true, "proved": true, "verified": true, "rank": -11357, "diff": 75,
            "lines_added": 28, "lines_removed": 47, "program_seconds": 489.0, "check_seconds": 139.0, "flags": ["exit 126"] });
        let search = serde_json::json!({ "search": 0, "kind": kind, "width": 8, "returned": 8, "verified": 7, "selected": 1, "time": 1, "seconds": 630.0,
            "generation": 1.25, "time_cost": 12.5, "params": { "base": "9b68b05aa", "limit": 5.0 }, "behaviors": [7], "trees": 8, "candidates": [candidate] });
        let process = serde_json::json!({ "pid": 1, "trace": trace, "outcome": outcome, "time": time, "searches": [search] });
        serde_json::from_value(serde_json::json!({ "kind": kind, "title": format!("from {commit}"), "outcome": outcome, "time": time, "generation": 1.25, "time_cost": 12.5,
            "processes": [process] })).unwrap()
    }

    /// A projection with something in every tab: goals, a pending interrupt, the queue, retired intents, the spec.
    fn full() -> Projection {
        let totals = serde_json::json!({ "cost": 1514.97, "generation": 181.66, "time_cost": 1333.31, "rate": 155.0, "per_verified_candidate": 5.12, "per_push": 85.86, "pushes": 16, "pushed": 1373.81,
                "attempts": [{ "kind": "code", "width": 8, "attempts": 25, "pushed": 13, "blocked": 9, "exited": 3 }, { "kind": "code", "width": 12, "attempts": 9, "pushed": 2, "exited": 7 }],
                "reasons": [{ "kind": "code", "reason": "none_splits", "count": 4, "inferred": 4 }, { "kind": "code", "reason": "too_few_verified", "count": 3, "inferred": 1 }, { "kind": "code", "reason": "undiscriminating", "count": 2 }],
                "ended": [{ "kind": "code", "pushed": 15, "exited": 10, "expected": 0.2 }],
                "success": [{ "kind": "code", "agent_processes": 216, "successes": 205, "ended": 24, "pushed": 15 }],
                "per_verified": [{ "kind": "counterexample", "program": "claude", "model": "claude-opus-5-5", "agent_processes": 60, "verified": 54, "generation": 18.66, "time_cost": 87.75 }],
                "run_time": [{ "kind": "code", "pushes": 15, "time": { "median": 653.0, "p90": 7500.0 }, "cost": { "median": 26.89, "p90": 363.75 }, "searches": 26,
                    "fit": { "time": { "fixed": -198.0, "per_tree": 157.0 }, "cost": { "fixed": -12.44, "per_tree": 7.78 } } }],
                "utilization": { "wall": 32460.0, "searches": 40, "agent_processes": { "held": 125000.0 }, "check_processes": { "held": 18000.0 } },
                "turnaround": [{ "kind": "blocked", "resolved": 1, "pending": 1, "time": { "median": 646.0, "p90": 646.0 } }] });
        let mut p: Projection = serde_json::from_value(serde_json::json!({ "configured": true, "totals": totals,
            "repo": { "name": "bon", "remote": "origin", "trunk": "main", "remote_head": "499a245c0", "now": 1_000_000, "subject": "view: every trace record has one shape and a long subject that runs on" },
            "interrupts": [{ "kind": "blocked", "id": "blocked 1", "about": "code from 365e522", "raised": 990000, "what": ["8 of 8 candidates verified; too_few_verified: fewer than two verified candidates", "2 attempts at width 8, 12 · $164.44"],
                "choices": [{ "choice": "widen", "how": "raise n of [searches] code in .bon/bon.toml (it ran at [8, 12])", "cost": "$0.71 per agent process (the last code search, width 12)" }] }],
            "queue": (1..30).map(|i| serde_json::json!({ "id": i, "intent": "Each trace records, for every agent process, its program, model, tokens, cost and time, and for every check its time and exit status." })).collect::<Vec<_>>(),
            "retired": [{ "id": 77, "intent": "Every trace record has one shape.", "commit": "499a245c0", "subject": "view: every trace record has one shape", "time": 999000 },
                        { "id": 78, "intent": "What only engineer can answer is an interrupt.", "commit": "499a245c0", "subject": "view: every trace record has one shape", "time": 999000 }],
            "spec": { "path": "src/spec.rs", "items": [{ "kind": "type", "name": "Commit", "doc": "A git commit, by its hash." }, { "kind": "predicate", "name": "verified", "doc": "Passed the vertical bottleneck, and stayed within its authority." }], "fields": [] }
        })).unwrap();
        p.groups = vec![goal_at("300", "compaction", "9b68b05", 999_500, "blocked"), goal_at("200", "counterexample", "14444a0", 999_000, "not found"), goal_at("100", "code", "365e522", 998_000, "pushed")];
        p
    }

    #[test]
    fn nothing_runs_past_the_edge_at_any_width_and_nothing_is_cut_without_an_ellipsis() {
        for (w, h) in [(60, 20), (80, 24), (100, 30), (120, 40), (200, 60), (80, 12)] {
            for tab in TABS {
                let mut app = ready();
                app.p = full();
                app.tab = tab;
                buffer(&mut app, w, h);
                // Every row of the list and every line of the detail fits the pane it is drawn in.
                let rows_w = app.list_w as usize;
                for r in rows(&app, app.list_w) { assert!(width_of(&r.line.spans) <= rows_w, "{w}x{h} {:?}: {:?}", tab as u8, plain(Text::from(r.line))); }
                if app.detail_shown {
                    let dw = if w >= 100 { w - app.list_w - 1 - 1 - 2 } else { w - 2 };
                    let d = detail(&app, dw);
                    for l in d.lines { assert!(width_of(&l.spans) <= dw as usize, "{w}x{h} detail: {}", plain(Text::from(l))); }
                }
                let s = screen_of(&mut app, w, h);
                assert!(s.lines().all(|l| l.chars().count() <= w as usize), "{w}x{h}:\n{s}");
            }
        }
    }

    /// What `app` draws at w×h, as text.
    fn screen_of(app: &mut App, w: u16, h: u16) -> String {
        let b = buffer(app, w, h);
        (0..h).map(|y| (0..w).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().trim_end().to_string()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn the_cursor_stays_on_its_item_when_rows_come_and_go() {
        let mut app = ready();
        app.p = full();
        app.tab = Tab::Traces;
        let k = |c: KeyCode| KeyEvent::new(c, KeyModifiers::NONE);
        buffer(&mut app, 120, 30);
        key(&mut app, k(KeyCode::Down));
        buffer(&mut app, 120, 30);
        assert_eq!(app.held[3], Some(Key::Goal("200".into())));
        app.detail_top = 3;
        // A bon process starts: its goal comes first, and every row moves down.
        let mut p = full();
        p.groups.insert(0, goal_at("400", "code", "aaaaaaa", 999_900, "running"));
        p.groups[0].running = true;
        app.p = p;
        buffer(&mut app, 120, 30);
        assert_eq!(app.held[3], Some(Key::Goal("200".into())), "the same goal, on another row");
        assert!(screen_of(&mut app, 120, 30).contains("Counterexample from 14444a0"), "its detail is still shown");
        assert_eq!(app.detail_top, 3, "and where it was read to");
        // Resized narrow, it wraps differently; still the same goal.
        buffer(&mut app, 80, 24);
        assert_eq!(app.held[3], Some(Key::Goal("200".into())));
        // Its goal gone, the nearest row; g and G move to the first and last, each opening its detail at the top.
        app.p = full(); app.p.groups.remove(1);
        buffer(&mut app, 120, 30);
        assert!(matches!(app.held[3], Some(Key::Goal(_))) && app.held[3] != Some(Key::Goal("200".into())));
        app.detail_top = 5;
        key(&mut app, k(KeyCode::Char('g')));
        assert_eq!((app.held[3].clone(), app.detail_top), (Some(Key::Goal("300".into())), 0));
        app.detail_top = 5;
        key(&mut app, k(KeyCode::Char('G')));
        assert_eq!((app.held[3].clone(), app.detail_top), (Some(Key::Goal("100".into())), 0));
        // Queue's intents by id.
        app.tab = Tab::Queue;
        buffer(&mut app, 80, 24);
        key(&mut app, k(KeyCode::Down));
        assert_eq!(app.held[2], Some(Key::Queue(2)));
        app.p.queue.as_mut().unwrap().remove(0);
        buffer(&mut app, 80, 24);
        assert_eq!(app.held[2], Some(Key::Queue(2)));
    }

    #[test]
    fn before_the_first_read_the_view_shows_that_it_is_reading_and_nothing_else() {
        let mut app = App::new();
        app.root = std::env::temp_dir();
        for tab in TABS {
            app.tab = tab;
            let s = screen_of(&mut app, 80, 24);
            for absent in ["Idle", "$0.00", "Queue 0", "Traces 0", "Nothing queued", "No bon process yet", "/ Find", "↑↓"] { assert!(!s.contains(absent), "{absent}:\n{s}"); }
            assert!(s.lines().next().unwrap().contains("· Reading") && s.contains("Queue") && s.contains("q Quit"), "{s}");
        }
        // Under 100 columns it holds the header's second row, where the cost will be: nothing moves when it arrives.
        let before = buffer(&mut app, 80, 24);
        app.p = full(); app.loaded = Some(Instant::now());
        let after = buffer(&mut app, 80, 24);
        let rule = |b: &ratatui::buffer::Buffer| (0..24).find(|&y| b[(0, y)].symbol() == "─").unwrap();
        assert_eq!(rule(&before), rule(&after));
    }

    #[test]
    fn ctrl_c_quits_whatever_is_open() {
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        let mut app = ready();
        app.input = Some(String::new());
        assert!(!key(&mut app, ctrl_c), "in Find");
        assert_eq!(app.input.as_deref(), Some(""), "and types nothing");
        let mut app = ready(); app.keys = true;
        assert!(!key(&mut app, ctrl_c), "with Keys open");
        let mut app = ready(); app.overlay = Overlay::Logs { items: vec![], sel: 0 };
        assert!(!key(&mut app, ctrl_c), "in Logs");
        let mut app = ready(); app.overlay = Overlay::Compare { titles: Default::default(), left: vec![], right: vec![], top: 0 };
        assert!(!key(&mut app, ctrl_c), "in Compare");
        // Find keeps what was typed as typed; the filter compares without case.
        let mut app = ready();
        app.input = Some("Code".into());
        key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.filter.lock().unwrap().find.as_deref(), Some("Code"));
    }

    #[test]
    fn a_pane_with_nothing_to_focus_scrolls_with_every_key_keys_lists() {
        let k = |c: KeyCode, m: KeyModifiers| KeyEvent::new(c, m);
        let mut app = ready();
        app.p = full();
        app.tab = Tab::Project;
        buffer(&mut app, 80, 24);
        let len = rows(&app, app.list_w).len();
        key(&mut app, k(KeyCode::Char('G'), KeyModifiers::NONE));
        buffer(&mut app, 80, 24);
        assert_eq!(app.top[0], last_top(len, app.list_h as usize), "G shows the last row");
        key(&mut app, k(KeyCode::Char('g'), KeyModifiers::NONE));
        key(&mut app, k(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.top[0], app.list_h as usize - 2, "a page is the rows between the pane's cues");
        key(&mut app, k(KeyCode::Down, KeyModifiers::SHIFT));
        assert_eq!(app.top[0], app.list_h as usize - 1, "⇧↓ scrolls the list where no detail shows");
        // Queue: the last intent's every line can be reached.
        app.tab = Tab::Queue;
        buffer(&mut app, 80, 24);
        key(&mut app, k(KeyCode::Char('G'), KeyModifiers::NONE));
        let s = screen_of(&mut app, 80, 24);
        assert!(s.contains("Taken off by 499a245") && !s.contains("↓ more"), "{s}");
        // The commit's subject once, under the first intent it took off.
        assert_eq!(s.matches("view: every trace record").count(), 1, "{s}");
        // An intent taller than its pane: ⇧↓ scrolls through its lines, the focus staying on it.
        let mut q = ready();
        q.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 1 },
            "queue": [{ "id": 7, "intent": format!("{} the end.", "word ".repeat(80)) }, { "id": 8, "intent": "next" }] })).unwrap();
        q.tab = Tab::Queue;
        buffer(&mut q, 60, 10);
        for _ in 0..12 { key(&mut q, k(KeyCode::Down, KeyModifiers::SHIFT)); buffer(&mut q, 60, 10); }
        let s = screen_of(&mut q, 60, 10);
        assert!(s.contains("the end."), "{s}");
    }

    #[test]
    fn the_footer_offers_only_what_a_key_would_do_now() {
        let foot = |app: &mut App, w: u16, h: u16| screen_of(app, w, h).lines().last().unwrap().to_string();
        // An empty project: nothing to move, open, find or range over.
        let mut app = ready();
        app.p = serde_json::from_value(serde_json::json!({ "configured": true, "repo": { "now": 1 } })).unwrap();
        for tab in TABS { app.tab = tab; let f = foot(&mut app, 80, 24); assert!(!f.contains("↑↓") && !f.contains("⏎") && !f.contains("/ Find") && !f.contains("r Range"), "{f}"); }
        // Spec and Queue filter nothing; Compare only where two behaviors are.
        let mut app = ready();
        app.p = full();
        for tab in [Tab::Spec, Tab::Queue] { app.tab = tab; let f = foot(&mut app, 120, 30); assert!(!f.contains("/ Find") && !f.contains("r Range"), "{f}"); }
        app.tab = Tab::Traces;
        let f = foot(&mut app, 120, 30);
        assert!(f.contains("/ Find") && !f.contains("d Compare"), "{f}");
        // The range bon was started with is the range shown; All time clears both bounds.
        *app.filter.lock().unwrap() = view::Filter::new(Some("2026-11-01"), Some("2026-11-02"), None).unwrap();
        // The footer says the range the shown projection was read over.
        app.p.filter.since = Some(1_793_491_200); app.p.filter.until = Some(1_793_577_600 + 86399);
        assert!(foot(&mut app, 200, 30).contains("Range: since 2026-11-01 until 2026-11-02"));
        for _ in 0..RANGES.len() { key(&mut app, KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)); }
        let f = app.filter.lock().unwrap().clone();
        assert_eq!((f.since, f.until, app.range), (None, None, 0));
    }

    #[test]
    fn an_agent_process_whose_program_never_started_says_so_in_red() {
        let mut app = ready();
        app.p = full();
        app.tab = Tab::Traces;
        let b = buffer(&mut app, 140, 40);
        let y = (0..40).find(|&y| (0..140).map(|x| b[(x, y)].symbol().to_string()).collect::<String>().contains("Exit 126")).expect("the flag");
        let x = (0..140).find(|&x| b[(x, y)].symbol() == "E" && b[(x + 1, y)].symbol() == "x").unwrap();
        assert!(tone_colors(Tone::Red).contains(&b[(x, y)].fg));
    }
}
