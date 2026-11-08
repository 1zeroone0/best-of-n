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

/// One row of a list: what it shows, and whether it can be focused.
struct Row { line: Line<'static>, focusable: bool }

struct App {
    p: Projection,
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
        App { p: Projection::default(), error: None, tab: Tab::Traces, focus: [0; 4], top: [0; 4], detail_top: 0, detail_open: false,
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
        out.push(match g.outcome.as_str() { "found" => "found".into(), _ if ce.verified >= 2 => "none found".into(), _ => format!("{} tests", ce.verified) });
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
    let header = |t: &str| Row { line: Line::from(Span::styled(format!(" {t}"), pal.faint().add_modifier(Modifier::BOLD))), focusable: false };
    match app.tab {
        Tab::Traces => {
            let today = day(p.repo.now, app.off);
            let mut last_day = None;
            let mut groups: Vec<&GoalTrace> = p.groups.iter().collect();
            groups.sort_by_key(|g| (!g.running, -g.time));
            for g in groups {
                let d = if g.running { today } else { day(g.time, app.off) };
                if last_day != Some(d) { if last_day.is_some() { out.push(Row { line: Line::default(), focusable: false }); } out.push(header(&day_label(d, today))); last_day = Some(d); }
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
                out.push(Row { line: Line::from(spans), focusable: true });
            }
            if p.groups.is_empty() { out.push(Row { line: Line::from(Span::styled(" No bon process yet.", pal.muted())), focusable: false }); }
        }
        Tab::Queue => {
            for q in p.queue.iter().flatten() {
                out.push(Row { line: Line::from(vec![Span::styled(format!(" {:>3}  ", q.id), pal.faint()), Span::styled(fit(&q.intent, w.saturating_sub(7)), pal.ink())]), focusable: true });
            }
            if p.queue.as_ref().is_none_or(|q| q.is_empty()) { out.push(Row { line: Line::from(Span::styled(" Nothing queued: every intent is in the spec.", pal.muted())), focusable: false }); }
        }
        Tab::Spec => {
            let Some(spec) = &p.spec else { out.push(Row { line: Line::from(Span::styled(" No spec found.", pal.muted())), focusable: false }); return out };
            let nw = spec.items.iter().map(|i| i.name.chars().count()).chain(spec.fields.iter().map(|f| f.name.chars().count())).max().unwrap_or(10).min(24) + 2;
            for (kind, title) in [("type", "types"), ("init", "init"), ("transition", "transitions"), ("predicate", "predicates"), ("property", "properties"), ("invariant", "invariants")] {
                let items: Vec<_> = spec.items.iter().filter(|i| i.kind == kind).collect();
                if items.is_empty() { continue; }
                if !out.is_empty() { out.push(Row { line: Line::default(), focusable: false }); }
                out.push(header(&format!("{title}  {}", items.len())));
                for i in items {
                    let doc = i.doc.clone().unwrap_or_default();
                    out.push(Row { line: Line::from(vec![Span::styled(format!("   {}", fit(&i.name, nw)), pal.ink()), Span::styled(fit(&doc, w.saturating_sub(nw + 4)), pal.muted())]), focusable: true });
                }
            }
            if !spec.fields.is_empty() {
                out.push(Row { line: Line::default(), focusable: false });
                out.push(header(&format!("state  {}", spec.fields.len())));
                for f in &spec.fields {
                    out.push(Row { line: Line::from(vec![Span::styled(format!("   {}", fit(&f.name, nw)), pal.ink()), Span::styled(fit(&f.r#type, w.saturating_sub(nw + 4)), pal.muted())]), focusable: true });
                }
            }
        }
        Tab::Project => {
            let t = &p.totals;
            let line = |label: &str, value: Vec<Span<'static>>| { let mut v = vec![Span::styled(format!(" {} ", fit(label, 16)), pal.muted())]; v.extend(value); Row { line: Line::from(v), focusable: false } };
            out.push(header("cost"));
            out.push(line("total", vec![Span::styled(money(Some(t.cost)), pal.strong()), Span::styled("  =  ", pal.faint()), Span::styled(money(Some(t.generation)), pal.ink()), Span::styled(" generation  +  ", pal.muted()), Span::styled(money(Some(t.time_cost)), pal.ink()), Span::styled(format!(" time{}", t.rate.map_or(String::new(), |r| format!(" at ${r:.0}/h"))), pal.muted())]));
            out.push(line("per verified", vec![Span::styled(money(t.per_verified_candidate), pal.ink()), Span::styled("   per push  ", pal.muted()), Span::styled(money(t.per_push), pal.ink())]));
            let share = |v: f64| if t.cost > 0.0 { v / t.cost } else { 0.0 };
            let bar = |v: f64, tone: Tone| { let n = (share(v) * 30.0).round() as usize; Span::styled("█".repeat(n), pal.tone(tone)) };
            out.push(line("where it went", vec![bar(t.pushed, Tone::Violet), bar(t.not_pushed, Tone::Red), bar(t.in_flight, Tone::Orange)]));
            out.push(line("", vec![Span::styled(format!("{} reached a push  {:.0}%", money(Some(t.pushed)), share(t.pushed) * 100.0), pal.tone(Tone::Violet))]));
            out.push(line("", vec![Span::styled(format!("{} did not  {:.0}%", money(Some(t.not_pushed)), share(t.not_pushed) * 100.0), pal.tone(Tone::Red))]));
            if t.in_flight > 0.0 { out.push(line("", vec![Span::styled(format!("{} in flight  {:.0}%", money(Some(t.in_flight)), share(t.in_flight) * 100.0), pal.tone(Tone::Orange))])); }
            out.push(Row { line: Line::default(), focusable: false });
            out.push(header("results"));
            let cands: Vec<&Facts> = p.processes.iter().flat_map(|b| &b.searches).flat_map(|s| &s.candidates).collect();
            let (v, a, r) = (cands.iter().filter(|c| c.verified).count(), cands.iter().filter(|c| c.accepted && !c.verified).count(), cands.iter().filter(|c| !c.accepted).count());
            out.push(line("candidates", vec![Span::styled(format!("{}", cands.len()), pal.strong()), Span::styled(format!("   {v} verified", ), pal.tone(Tone::Green)), Span::styled(format!("   {a} accepted, not verified"), pal.tone(Tone::Yellow)), Span::styled(format!("   {r} rejected"), pal.tone(Tone::Red))]));
            let mut kinds: Vec<(String, usize)> = Vec::new();
            for g in p.groups.iter().filter(|g| g.outcome == "pushed") { match kinds.iter_mut().find(|(k, _)| *k == g.kind) { Some(e) => e.1 += 1, None => kinds.push((g.kind.clone(), 1)) } }
            out.push(line("pushes", vec![Span::styled(format!("{}", t.pushes), pal.strong()), Span::styled(format!("   {}", kinds.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(" · ")), pal.muted())]));
            out.push(Row { line: Line::default(), focusable: false });
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

/// The focused row's item, in the order rows() lists them.
fn focused_group(app: &App) -> Option<&GoalTrace> {
    let mut groups: Vec<&GoalTrace> = app.p.groups.iter().collect();
    groups.sort_by_key(|g| (!g.running, -g.time));
    let n = rows(app, 200).iter().take(app.focus[app.ti()] + 1).filter(|r| r.focusable).count();
    groups.get(n.checked_sub(1)?).copied()
}

fn nth_focusable(app: &App) -> usize { rows(app, 200).iter().take(app.focus[app.ti()] + 1).filter(|r| r.focusable).count().saturating_sub(1) }

fn detail(app: &App, width: u16) -> Text<'static> {
    let pal = app.palette;
    let mut t: Vec<Line<'static>> = Vec::new();
    let head = |s: String| Line::from(Span::styled(s, pal.strong()));
    let sub = |s: &str| Line::from(Span::styled(s.to_string(), pal.faint().add_modifier(Modifier::BOLD)));
    let kv = |k: &str, v: Vec<Span<'static>>| { let mut x = vec![Span::styled(format!("{} ", fit(k, 12)), pal.muted())]; x.extend(v); Line::from(x) };
    match app.tab {
        Tab::Traces => {
            let Some(g) = focused_group(app) else { return Text::default() };
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
                    if let Some(bl) = &s.blocked { t.push(Line::from(Span::styled(format!("    {}", bl.trim_start_matches("blocked: ")), pal.tone(Tone::Yellow)))); }
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
            let Some(q) = app.p.queue.as_ref().and_then(|q| q.get(nth_focusable(app))) else { return Text::default() };
            t.push(head(format!("queue {}", q.id)));
            t.push(Line::default());
            t.push(Line::from(Span::styled(q.intent.clone(), pal.ink())));
        }
        Tab::Spec => {
            let Some(spec) = &app.p.spec else { return Text::default() };
            let order = ["type", "init", "transition", "predicate", "property", "invariant"];
            let mut items: Vec<_> = spec.items.iter().collect();
            items.sort_by_key(|i| order.iter().position(|k| *k == i.kind).unwrap_or(9));
            let n = nth_focusable(app);
            if let Some(i) = items.get(n) {
                t.push(Line::from(vec![Span::styled(i.name.clone(), pal.strong()), Span::styled(format!("   {}", i.kind), pal.muted())]));
                if let Some(d) = &i.doc { t.extend(hanging(d, 0, width as usize, pal.ink())); }
                for (title, list) in [("requires", &i.requires), ("reads", &i.reads), ("updates", &i.updates)] {
                    if list.is_empty() { continue; }
                    t.push(Line::default()); t.push(sub(title));
                    for r in list { t.push(Line::from(Span::styled(format!("  {r}"), pal.ink()))); }
                }
                // How it reaches the code: the spec graph's edges into and out of it.
                if let Some(g) = &app.p.system {
                    let id = format!("spec:{}", i.name);
                    let name = |id: &str| g.nodes.iter().find(|n| n.id == id).map_or(id.to_string(), |n| format!("{}  {}:{}", n.name, n.file, n.line.unwrap_or(0)));
                    let into: Vec<_> = g.edges.iter().filter(|e| e.1 == id).collect();
                    if !into.is_empty() { t.push(Line::default()); t.push(sub("reached from")); for e in into { t.push(Line::from(vec![Span::styled(format!("  {} ", fit(&e.2, 11)), pal.muted()), Span::styled(name(&e.0), pal.ink())])); } }
                }
            } else if let Some(f) = spec.fields.get(n.saturating_sub(items.len())) {
                t.push(Line::from(vec![Span::styled(f.name.clone(), pal.strong()), Span::styled(format!("   {}", f.r#type), pal.muted())]));
                if let Some(d) = &f.doc { t.push(Line::default()); t.push(Line::from(Span::styled(d.clone(), pal.ink()))); }
                if let Some(s) = &f.sharding { t.push(Line::default()); t.push(kv("sharding", vec![Span::styled(s.clone(), pal.muted())])); }
            }
        }
        Tab::Project => {}
    }
    Text::from(t)
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
        if !list[i].focusable { if let Some(j) = (i..list.len()).chain((0..i).rev()).find(|&j| list[j].focusable) { i = j; } }
        app.focus[ti] = i;
        let h = list_area.height as usize;
        if h > 0 {
            if i < app.top[ti] { app.top[ti] = i.saturating_sub(1); }
            if i >= app.top[ti] + h { app.top[ti] = i + 1 - h; }
        }
    }
    if list_area.width > 0 {
        let lines: Vec<Line> = list.into_iter().enumerate().skip(app.top[ti]).take(list_area.height as usize).map(|(i, r)| {
            if r.focusable && i == app.focus[ti] && detail_tab {
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

    // Footer: the keys, or an error reading the projection.
    let foot_line = if let Some(e) = &app.error { Line::from(Span::styled(format!(" {e}"), pal.tone(Tone::Red))) } else {
        let k = |key: &str, what: &str| vec![Span::styled(format!(" {key} "), pal.ink()), Span::styled(format!("{what}  "), pal.faint())];
        let mut items: Vec<Vec<Span>> = vec![k("↑↓", "move"), k("⇥", "tab")];
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
        let w = 46.min(area.width); let h = 12.min(area.height);
        let r = Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h };
        f.render_widget(ratatui::widgets::Clear, r);
        let lines: Vec<Line> = [("↑ ↓  j k", "move"), ("⇥  1 2 3 4", "tab"), ("⏎", "open the detail (narrow)"), ("esc", "close it"), ("⇧↑ ⇧↓  pgup pgdn", "scroll the detail"), ("g G", "top, bottom"), ("t", "light or dark"), ("q", "quit")]
            .iter().map(|(k, w)| Line::from(vec![Span::styled(format!("  {} ", fit(k, 18)), pal.ink()), Span::styled(w.to_string(), pal.muted())])).collect();
        let mut all = vec![Line::from(Span::styled("  keys", pal.strong())), Line::default()]; all.extend(lines);
        f.render_widget(Paragraph::new(all).block(ratatui::widgets::Block::bordered().border_style(pal.rule())), r);
    }
}

// ── a frame as HTML ─────────────────────────────────────

fn css(c: Color) -> Option<String> { match c { Color::Rgb(r, g, b) => Some(format!("#{r:02x}{g:02x}{b:02x}")), _ => None } }

/// One frame of the view at w×h, on a given tab, as a self-contained HTML page:
/// the same cells a terminal would show, for a preview anywhere.
pub fn frame(root: &str, w: u16, h: u16, tab: usize, light: bool) -> Result<String, String> {
    use ratatui::backend::TestBackend;
    let mut app = App::new();
    app.p = projection::read(std::path::Path::new(root), &view::Filter::default())?;
    app.tab = TABS[tab.min(3)];
    if light { app.dark = false; app.palette = LIGHT; }
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

// ── input ───────────────────────────────────────────────

/// Handle one key; false to quit.
fn key(app: &mut App, k: KeyEvent) -> bool {
    let ti = app.ti();
    let step = |app: &mut App, down: bool| {
        let list = rows(app, 200);
        let mut i = app.focus[ti] as isize;
        loop { i += if down { 1 } else { -1 }; if i < 0 || i as usize >= list.len() { break; } if list[i as usize].focusable { app.focus[ti] = i as usize; app.detail_top = 0; break; } }
    };
    if app.keys { app.keys = false; return true; }
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
    let root_t = std::path::PathBuf::from(root);
    std::thread::spawn(move || loop {
        if tx.send(projection::read(&root_t, &filter)).is_err() { break; }
        std::thread::sleep(Duration::from_secs(2));
    });
    let mut terminal: DefaultTerminal = ratatui::init();
    let mut app = App::new();
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
}
