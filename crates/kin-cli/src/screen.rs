// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The short form the first-run commands print on a terminal.
//!
//! `kin setup`, `kin clone`, `kin init` and `kin daemon sweep` print a short,
//! sectioned summary when a person is watching, and the full record otherwise.
//! This module owns that decision and the pieces all four draw with, so they
//! read as one product: section headers, check rows with aligned labels and
//! right-aligned timings, one status glyph per row, and one live line per phase
//! that the finished row replaces.
//!
//! The decision is [`short_form`]: stdout is a terminal, `--verbose` was not
//! passed, and `CI` is not set. Anything else, a pipe, a file or a CI log, gets
//! the full record that scripts and acceptance checks already read.
//!
//! Colour. Words are never painted a fixed colour, because no single colour
//! reads at 4.5:1 on both a dark and a light background. Text takes the
//! terminal's own foreground, bold for emphasis and faint for detail. Status
//! glyphs take the theme's green, yellow and red, which every theme tunes for
//! its own background. The brand lilac marks shapes only: the progress bar, the
//! spinner and the question marker.

use std::io::{IsTerminal, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::mark::{Glyphs, Paint};

/// The outer indent of every short-form line.
pub const INDENT: &str = "  ";

/// The columns a row's label is padded to.
pub const LABEL_WIDTH: usize = 17;

/// The column a row's timing ends on at its widest, which keeps every row
/// inside 80 columns on a wide terminal.
pub const RIGHT_EDGE: usize = 78;

/// The narrowest right edge the short form lays out for.
const MIN_RIGHT_EDGE: usize = 40;

/// Columns the live line's bar takes at its widest.
const BAR_WIDTH: usize = 30;

/// This terminal's width in columns, or 80 when it cannot be read.
///
/// Read on every call, so a resize between two lines is honoured by the next.
pub fn terminal_width() -> usize {
    console::Term::stdout()
        .size_checked()
        .map(|(_, columns)| usize::from(columns))
        .filter(|columns| *columns > 0)
        .unwrap_or(80)
}

/// The column a row ends on for a terminal `width` columns wide.
///
/// Two columns short of the edge, so a line never reaches the last column,
/// where some terminals wrap it and leave the next redraw a row out.
pub fn right_edge_for(width: usize) -> usize {
    width.saturating_sub(2).clamp(MIN_RIGHT_EDGE, RIGHT_EDGE)
}

/// The column a row ends on for this terminal.
pub fn right_edge() -> usize {
    right_edge_for(terminal_width())
}

/// What to call this computer in a sentence: "this Mac" on macOS, and "this
/// machine" everywhere else.
pub fn this_machine() -> &'static str {
    if cfg!(target_os = "macos") {
        "this Mac"
    } else {
        "this machine"
    }
}

/// Greedy word wrap of plain text to `width` columns.
///
/// A word longer than the width keeps its own line whole rather than being
/// cut, because the long words here are paths and commands a person copies.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// How often the live line redraws.
const TICK: Duration = Duration::from_millis(100);

/// The brand lilac, `#A993FF`, and its nearest 256-colour index.
const LILAC_TRUECOLOR: &str = "\u{1b}[38;2;169;147;255m";
const LILAC_INDEXED: &str = "\u{1b}[38;5;141m";
const LILAC_BASIC: &str = "\u{1b}[35m";

const RESET: &str = "\u{1b}[0m";
const ERASE_LINE: &str = "\u{1b}[2K\r";

/// Whether this command prints the short form.
///
/// `verbose` is the command's `--verbose` flag. Everything else is read here.
pub fn short_form(verbose: bool) -> bool {
    decide(
        verbose,
        std::io::stdout().is_terminal(),
        std::env::var("CI").ok().as_deref(),
    )
}

/// The rule behind [`short_form`], with its inputs taken as arguments.
fn decide(verbose: bool, stdout_is_terminal: bool, ci: Option<&str>) -> bool {
    let in_ci = ci.is_some_and(|value| {
        let value = value.trim().to_ascii_lowercase();
        !value.is_empty() && !matches!(value.as_str(), "0" | "false" | "no" | "off")
    });
    !verbose && stdout_is_terminal && !in_ci
}

/// Animation needs both streams on a supported terminal. A plain colour
/// preference is independent: `NO_COLOR` changes the style, not this rule.
fn live_line_allowed(
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
    term: Option<&str>,
    ci: Option<&str>,
    windows_terminal: bool,
) -> bool {
    decide(false, stdout_is_terminal, ci)
        && stderr_is_terminal
        && term.map_or(windows_terminal, |term| {
            let term = term.trim();
            !term.is_empty() && !term.eq_ignore_ascii_case("dumb")
        })
}

/// Whether progress may overwrite a terminal row in this process. Both live
/// lines and daemon startup notices use this admission rule.
pub(crate) fn animation_allowed() -> bool {
    live_line_allowed(
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
        std::env::var("TERM").ok().as_deref(),
        std::env::var("CI").ok().as_deref(),
        // Windows Terminal advertises itself without necessarily setting TERM,
        // the same capability signal Style::for_stdout already recognizes.
        std::env::var_os("WT_SESSION").is_some_and(|value| !value.is_empty()),
    )
}

/// What a row reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Done and healthy.
    Ok,
    /// Done, with something the reader should know.
    Warn,
    /// Failed.
    Fail,
    /// Deliberately not done, such as a question answered no.
    Off,
    /// Chosen, and not done yet: an answer before setup applies it.
    Chosen,
}

/// How this terminal draws the short form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    glyphs: Glyphs,
    paint: Paint,
}

impl Style {
    /// A style named outright, for tests and callers that already know.
    pub fn new(glyphs: Glyphs, paint: Paint) -> Self {
        Self { glyphs, paint }
    }

    /// No colour, Unicode glyphs.
    pub fn plain() -> Self {
        Self::new(Glyphs::Unicode, Paint::None)
    }

    /// The style for this process's stdout.
    pub fn for_stdout() -> Self {
        let locale: Vec<Option<String>> = ["LC_ALL", "LC_CTYPE", "LANG"]
            .into_iter()
            .map(|name| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned()))
            .collect();
        let paint = crate::mark::paint_for(
            crate::output_style::enabled(),
            std::env::var("COLORTERM").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
            std::env::var_os("WT_SESSION").is_some_and(|value| !value.is_empty()),
        );
        Self::new(crate::mark::glyphs_for_locale(&locale), paint)
    }

    fn coloured(self) -> bool {
        self.paint != Paint::None
    }

    fn unicode(self) -> bool {
        self.glyphs == Glyphs::Unicode
    }

    fn wrap(self, escape: &str, text: &str) -> String {
        if self.coloured() {
            format!("{escape}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    /// Bold, in the terminal's own foreground.
    pub fn bold(self, text: &str) -> String {
        self.wrap("\u{1b}[1m", text)
    }

    /// Faint, in the terminal's own foreground.
    pub fn faint(self, text: &str) -> String {
        self.wrap("\u{1b}[2m", text)
    }

    /// The brand lilac, for shapes only, never for words a reader must read.
    pub fn lilac(self, text: &str) -> String {
        match self.paint {
            Paint::Truecolor => format!("{LILAC_TRUECOLOR}{text}{RESET}"),
            Paint::Indexed => format!("{LILAC_INDEXED}{text}{RESET}"),
            Paint::Basic => format!("{LILAC_BASIC}{text}{RESET}"),
            Paint::None => text.to_string(),
        }
    }

    /// The glyph a row opens with.
    pub fn glyph(self, status: Status) -> String {
        if status == Status::Chosen {
            return self.lilac(if self.unicode() { "•" } else { "*" });
        }
        let (unicode, ascii, escape) = match status {
            Status::Chosen => unreachable!("drawn above"),
            Status::Ok => ("✓", "+", "\u{1b}[32m"),
            Status::Warn => ("!", "!", "\u{1b}[33m"),
            Status::Fail => ("✗", "x", "\u{1b}[31m"),
            Status::Off => ("○", "-", "\u{1b}[2m"),
        };
        let glyph = if self.unicode() { unicode } else { ascii };
        self.wrap(escape, glyph)
    }

    /// The marker a question opens with.
    pub fn marker(self) -> String {
        self.lilac(if self.unicode() { "›" } else { ">" })
    }

    /// The separator between parts of a row's value.
    pub fn dot(self) -> String {
        self.faint(self.separator())
    }

    /// The same separator unpainted, for text that is painted as a whole.
    pub fn separator(self) -> &'static str {
        if self.unicode() {
            "·"
        } else {
            "-"
        }
    }

    /// One frame of the live line's spinner.
    pub fn spinner(self, tick: usize) -> String {
        const UNICODE: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        const ASCII: [&str; 4] = ["|", "/", "-", "\\"];
        let frame = if self.unicode() {
            UNICODE[tick % UNICODE.len()]
        } else {
            ASCII[tick % ASCII.len()]
        };
        self.lilac(frame)
    }

    /// A progress bar `width` columns wide.
    pub fn bar(self, done: u64, total: u64, width: usize) -> String {
        let filled = if total == 0 {
            0
        } else {
            ((done.min(total) as f64 / total as f64) * width as f64).round() as usize
        };
        let (full, empty) = if self.unicode() {
            ("━", "─")
        } else {
            ("#", "-")
        };
        format!(
            "{}{}",
            self.lilac(&full.repeat(filled)),
            self.faint(&empty.repeat(width - filled))
        )
    }
}

/// A section header.
pub fn section(style: Style, title: &str) -> String {
    format!("{INDENT}{}", style.bold(title))
}

/// One check row: glyph, padded label, value, and the timing right-aligned to
/// this terminal's [`right_edge`].
///
/// `indent` is the row's own indent: [`INDENT`] for a command's result rows,
/// twice that for rows under a section header. `value` may carry escapes; its
/// visible width is what is measured.
pub fn row(
    style: Style,
    indent: &str,
    status: Status,
    label: &str,
    value: &str,
    elapsed: Option<Duration>,
) -> String {
    row_to(style, indent, status, label, value, elapsed, right_edge())
}

/// [`row`], ending on a given column.
pub fn row_to(
    style: Style,
    indent: &str,
    status: Status,
    label: &str,
    value: &str,
    elapsed: Option<Duration>,
    right_edge: usize,
) -> String {
    let head = format!("{indent}{} {label:<LABEL_WIDTH$} ", style.glyph(status));
    let mut line = format!("{head}{value}");
    if let Some(elapsed) = elapsed {
        let timing = format_elapsed(elapsed);
        let used = console::measure_text_width(&line);
        let pad = right_edge.saturating_sub(used + timing.len()).max(2);
        line.push_str(&" ".repeat(pad));
        line.push_str(&style.faint(&timing));
    }
    line.trim_end().to_string()
}

/// A duration the way a row prints it: `0.4s`, `31.7s`, `1m 12s`, `1h 3m`.
pub fn format_elapsed(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if seconds < 60.0 {
        return format!("{seconds:.1}s");
    }
    let whole = elapsed.as_secs();
    if whole < 3600 {
        return format!("{}m {}s", whole / 60, whole % 60);
    }
    format!("{}h {}m", whole / 3600, (whole % 3600) / 60)
}

/// A count with thousands separators.
pub fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// `text` shortened to `max` columns by removing its middle, so both the start
/// and the end of a path survive.
///
/// For plain text: the width is measured in characters.
pub fn fit(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max || max < 5 {
        return text.to_string();
    }
    let keep = max - 1;
    let head = keep / 2;
    let tail = keep - head;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// A path with the home directory written as `~`.
pub fn home_relative(path: &std::path::Path) -> String {
    let home = crate::commands::setup::home_dir().ok();
    match home
        .as_deref()
        .and_then(|home| path.strip_prefix(home).ok())
    {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// What the live line shows besides its label and timing.
#[derive(Clone, Debug, Default)]
struct LiveState {
    label: String,
    progress: Option<(u64, u64, String)>,
    note: Option<String>,
}

/// One line on stderr that redraws in place while a phase runs, and is erased
/// when it ends so the phase's finished row can take its place.
///
/// Drawn only when stderr is a terminal; [`LiveLine::start`] returns `None`
/// otherwise, and every caller treats that as "print nothing while working".
pub struct LiveLine {
    state: Arc<Mutex<LiveState>>,
    stop: Arc<AtomicBool>,
    /// Set once the line has been drawn, so a line that never appeared is
    /// never erased either.
    drawn: Arc<AtomicBool>,
    ticker: Option<std::thread::JoinHandle<()>>,
    started: Instant,
}

impl LiveLine {
    /// Start a live line for a phase called `label`.
    pub fn start(style: Style, label: &str) -> Option<Self> {
        Self::start_after(style, label, Duration::ZERO)
    }

    /// Start a live line that first draws only once `delay` has passed.
    ///
    /// For a wait that is usually short: a warm command that answers inside
    /// the delay never shows the line, so it cannot flash, and one that does
    /// not says what it is waiting on instead of leaving a blank terminal.
    pub fn start_after(style: Style, label: &str, delay: Duration) -> Option<Self> {
        if !animation_allowed() {
            return None;
        }
        let state = Arc::new(Mutex::new(LiveState {
            label: label.to_string(),
            ..LiveState::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let drawn = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let ticker = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            let drawn = Arc::clone(&drawn);
            std::thread::Builder::new()
                .name("kin-live-line".to_string())
                .spawn(move || {
                    while started.elapsed() < delay && !stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    let mut tick = 0usize;
                    while !stop.load(Ordering::SeqCst) {
                        drawn.store(true, Ordering::SeqCst);
                        let line = {
                            let state = state.lock().map(|s| s.clone()).unwrap_or_default();
                            live_text(style, &state, tick, started.elapsed(), right_edge())
                        };
                        let mut err = std::io::stderr().lock();
                        let _ = write!(err, "{ERASE_LINE}{line}");
                        let _ = err.flush();
                        drop(err);
                        tick += 1;
                        std::thread::sleep(TICK);
                    }
                })
                .ok()
        };
        Some(Self {
            state,
            stop,
            drawn,
            ticker,
            started,
        })
    }

    /// Show `done` of `total` `unit` and a bar.
    pub fn progress(&self, done: u64, total: u64, unit: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.progress = Some((done, total, unit.to_string()));
        }
    }

    /// Show a short note in place of the bar, such as what the phase is doing.
    pub fn note(&self, note: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.note = Some(note.to_string());
        }
    }

    /// Rename the phase, for a phase that moves through named steps.
    pub fn label(&self, label: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.label = label.to_string();
        }
    }

    /// How long this line has been live.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Stop redrawing and erase the line.
    pub fn finish(mut self) -> Duration {
        self.stop_and_erase();
        self.started.elapsed()
    }

    fn stop_and_erase(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(ticker) = self.ticker.take() {
            let _ = ticker.join();
            if self.drawn.load(Ordering::SeqCst) {
                let mut err = std::io::stderr().lock();
                let _ = write!(err, "{ERASE_LINE}");
                let _ = err.flush();
            }
        }
    }
}

impl Drop for LiveLine {
    fn drop(&mut self) {
        self.stop_and_erase();
    }
}

/// The live line's text for one frame.
fn live_text(
    style: Style,
    state: &LiveState,
    tick: usize,
    elapsed: Duration,
    right_edge: usize,
) -> String {
    // The bar gives up columns first on a narrow terminal, and goes entirely
    // below the width that leaves it none.
    let bar_width = BAR_WIDTH.min(right_edge.saturating_sub(48));
    let mut line = format!(
        "{INDENT}{} {:<LABEL_WIDTH$} ",
        style.spinner(tick),
        fit(&state.label, LABEL_WIDTH)
    );
    match (&state.progress, &state.note) {
        (Some((done, total, unit)), _) if *total > 0 => {
            if bar_width >= 8 {
                line.push_str(&style.bar(*done, *total, bar_width));
                line.push_str("  ");
            }
            line.push_str(&format!("{}/{} {unit}", count(*done), count(*total)));
        }
        (_, Some(note)) => {
            let room = right_edge.saturating_sub(console::measure_text_width(&line) + 10);
            line.push_str(&style.faint(&fit(note, room.clamp(8, 40))));
        }
        _ => {}
    }
    let timing = format_elapsed(elapsed);
    let used = console::measure_text_width(&line);
    let pad = right_edge.saturating_sub(used + timing.len()).max(2);
    line.push_str(&" ".repeat(pad));
    line.push_str(&style.faint(&timing));
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_short_form_is_for_a_person_at_a_terminal() {
        assert!(decide(false, true, None));
        assert!(
            !decide(true, true, None),
            "--verbose asks for the full record"
        );
        assert!(!decide(false, false, None), "a pipe keeps the full record");
        assert!(!decide(false, true, Some("true")), "a CI log keeps it too");
        assert!(decide(false, true, Some("false")), "CI=false is not CI");
        assert!(decide(false, true, Some("")), "an empty CI is not CI");
    }

    #[test]
    fn live_lines_require_both_streams_and_a_supported_terminal() {
        for (stdout_tty, stderr_tty) in [(false, false), (false, true), (true, false)] {
            assert!(
                !live_line_allowed(stdout_tty, stderr_tty, Some("xterm-256color"), None, false),
                "redirecting either stream disables animation"
            );
        }
        for term in [None, Some(""), Some("  "), Some("dumb"), Some(" DUMB ")] {
            assert!(
                !live_line_allowed(true, true, term, None, false),
                "unsupported terminal {term:?} must not receive cursor controls"
            );
        }
        for term in ["xterm-256color", "screen", "vt100"] {
            assert!(live_line_allowed(true, true, Some(term), None, false));
        }
        assert!(live_line_allowed(
            true,
            true,
            Some("xterm-256color"),
            None,
            false
        ));
        assert!(
            !crate::output_style::wanted(true, true, Some("xterm-256color")),
            "NO_COLOR disables colour independently of animation"
        );
    }

    #[test]
    fn live_lines_use_the_existing_ci_opt_out_semantics() {
        for ci in ["1", "true", "yes", "anything", " TRUE "] {
            assert!(
                !live_line_allowed(true, true, Some("xterm"), Some(ci), false),
                "CI={ci:?} must disable animation even in a pseudo-terminal"
            );
        }
        for ci in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("no"),
            Some(" off "),
        ] {
            assert!(live_line_allowed(true, true, Some("xterm"), ci, false));
        }
    }

    #[test]
    fn windows_terminal_without_term_still_honors_plain_output_controls() {
        assert!(live_line_allowed(true, true, None, None, true));
        assert!(!live_line_allowed(true, true, None, None, false));
        for term in ["dumb", " DUMB ", "", "  "] {
            assert!(
                !live_line_allowed(true, true, Some(term), None, true),
                "an explicit unsupported TERM wins over WT_SESSION"
            );
        }
        assert!(!live_line_allowed(true, true, None, Some("true"), true));
        assert!(live_line_allowed(true, true, None, Some("false"), true));
        for (stdout_tty, stderr_tty) in [(false, false), (false, true), (true, false)] {
            assert!(!live_line_allowed(stdout_tty, stderr_tty, None, None, true));
        }
    }

    #[test]
    fn a_row_aligns_its_label_and_right_aligns_its_timing() {
        let line = row(
            Style::plain(),
            INDENT,
            Status::Ok,
            "Read history",
            "678 commits · 197 entities",
            Some(Duration::from_millis(31_700)),
        );
        assert_eq!(
            line,
            "  ✓ Read history      678 commits · 197 entities                         31.7s"
        );
        assert_eq!(console::measure_text_width(&line), RIGHT_EDGE);
    }

    #[test]
    fn a_row_without_timing_ends_at_its_value() {
        let line = row(
            Style::plain(),
            "    ",
            Status::Off,
            "Codex CLI",
            "connects at clone or init",
            None,
        );
        assert_eq!(line, "    ○ Codex CLI         connects at clone or init");
    }

    #[test]
    fn colour_is_escapes_and_nothing_else() {
        let coloured = Style::new(Glyphs::Unicode, Paint::Truecolor);
        let line = row(
            coloured,
            INDENT,
            Status::Warn,
            "Linked",
            &format!("9 of 15 files {} pyright", coloured.dot()),
            Some(Duration::from_secs(41)),
        );
        let plain = row(
            Style::plain(),
            INDENT,
            Status::Warn,
            "Linked",
            &format!("9 of 15 files {} pyright", Style::plain().dot()),
            Some(Duration::from_secs(41)),
        );
        assert_eq!(console::strip_ansi_codes(&line), plain);
        assert!(!plain.contains('\u{1b}'));
    }

    /// Words keep the terminal's own foreground: the only colours a row writes
    /// are bold, faint, the theme's status colours and, on shapes, lilac.
    #[test]
    fn no_word_is_painted_a_fixed_colour() {
        let style = Style::new(Glyphs::Unicode, Paint::Truecolor);
        assert_eq!(style.bold("Ready."), "\u{1b}[1mReady.\u{1b}[0m");
        assert_eq!(style.faint("~/.zshrc"), "\u{1b}[2m~/.zshrc\u{1b}[0m");
        assert!(style.glyph(Status::Ok).starts_with("\u{1b}[32m"));
        assert!(style.marker().starts_with(LILAC_TRUECOLOR));
    }

    #[test]
    fn an_ascii_terminal_gets_ascii_glyphs() {
        let ascii = Style::new(Glyphs::Ascii, Paint::None);
        assert_eq!(ascii.glyph(Status::Ok), "+");
        assert_eq!(ascii.glyph(Status::Off), "-");
        assert_eq!(ascii.marker(), ">");
        assert_eq!(ascii.bar(1, 2, 4), "##--");
        assert!(ascii.spinner(3).is_ascii());
    }

    #[test]
    fn elapsed_times_read_like_a_person_would_say_them() {
        assert_eq!(format_elapsed(Duration::from_millis(400)), "0.4s");
        assert_eq!(format_elapsed(Duration::from_millis(31_700)), "31.7s");
        assert_eq!(format_elapsed(Duration::from_secs(72)), "1m 12s");
        assert_eq!(format_elapsed(Duration::from_secs(3_780)), "1h 3m");
    }

    #[test]
    fn counts_carry_thousands_separators() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(2_795), "2,795");
        assert_eq!(count(1_234_567), "1,234,567");
    }

    #[test]
    fn a_long_path_loses_its_middle_not_its_ends() {
        let fitted = fit("~/Library/Application Support/Cursor/User/mcp.json", 24);
        assert_eq!(fitted.chars().count(), 24);
        assert!(fitted.starts_with("~/Library/"), "{fitted}");
        assert!(fitted.ends_with("mcp.json"), "{fitted}");
        assert_eq!(fit("short", 24), "short");
    }

    /// At 60 columns every line still ends inside the terminal, the bar
    /// narrowing first, and a copyable word is never cut by the wrap.
    #[test]
    fn a_narrow_terminal_narrows_the_line_and_never_cuts_a_command() {
        assert_eq!(right_edge_for(60), 58);
        assert_eq!(right_edge_for(120), RIGHT_EDGE);
        assert_eq!(right_edge_for(20), 40);
        let state = LiveState {
            label: "Linking".to_string(),
            progress: Some((11, 15, "files".to_string())),
            note: None,
        };
        let line = live_text(Style::plain(), &state, 4, Duration::from_millis(28_300), 58);
        assert_eq!(console::measure_text_width(&line), 58, "{line}");
        let line = row_to(
            Style::plain(),
            INDENT,
            Status::Ok,
            "Read history",
            "678 commits · 197 entities",
            Some(Duration::from_millis(31_700)),
            58,
        );
        assert!(console::measure_text_width(&line) <= 58, "{line}");
        let wrapped = wrap(
            "run kin doctor --fix --install-language-servers inside the repository",
            24,
        );
        assert!(
            wrapped.contains(&"--install-language-servers".to_string()),
            "{wrapped:?}"
        );
        assert!(wrapped.iter().all(|line| !line.contains('…')));
    }

    #[test]
    fn the_live_line_fits_the_row_budget() {
        let state = LiveState {
            label: "Linking".to_string(),
            progress: Some((11, 15, "files".to_string())),
            note: None,
        };
        let line = live_text(
            Style::plain(),
            &state,
            4,
            Duration::from_millis(28_300),
            RIGHT_EDGE,
        );
        assert_eq!(
            line,
            "  ⠼ Linking           ━━━━━━━━━━━━━━━━━━━━━━────────  11/15 files        28.3s"
        );
        assert_eq!(console::measure_text_width(&line), RIGHT_EDGE);

        let noted = LiveState {
            label: "Downloading".to_string(),
            progress: None,
            note: Some("pallets/itsdangerous".to_string()),
        };
        let line = live_text(
            Style::plain(),
            &noted,
            0,
            Duration::from_millis(900),
            RIGHT_EDGE,
        );
        assert!(line.contains("pallets/itsdangerous"), "{line}");
        assert_eq!(console::measure_text_width(&line), RIGHT_EDGE);
    }
}
