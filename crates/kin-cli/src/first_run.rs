// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What `kin clone`, `kin init` and `kin daemon sweep` show a person at a
//! terminal.
//!
//! The short form is one live line per phase, replaced by one row with its
//! timing when the phase ends, and then a closing block: what is not linked
//! and why, one "Ready" sentence, and a real command to try. Every piece here
//! draws with [`crate::screen`], so the three commands read as one product.
//!
//! The commands still decide what happened. This module only turns what they
//! observed into lines, which is why most of it is pure: a row, the unlinked
//! explanation and the closing block are functions of a struct, and each is
//! tested without a daemon, a terminal or a repository. Nothing here reads a
//! file or starts a process.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use crate::screen::{self, LiveLine, Status, Style, INDENT, LABEL_WIDTH};

/// Widest line the short form prints on a wide terminal.
const MAX_COLUMNS: usize = 80;

/// Widest line the short form prints on this terminal: [`MAX_COLUMNS`], or
/// less on a narrower one, so no line reaches the edge and wraps.
fn max_columns() -> usize {
    screen::right_edge().min(MAX_COLUMNS)
}

/// The column a row's value starts at: the indent, the glyph and its space, the
/// padded label and its space.
const VALUE_COLUMN: usize = INDENT.len() + 2 + LABEL_WIDTH + 1;

/// Owed files the closing block names before it counts the rest.
const OWED_FILES_NAMED: usize = 3;

/// The command that installs a missing language server, as every row names it.
pub const INSTALL_SERVERS: &str = "kin doctor --fix --install-language-servers";

static QUIET_DAEMON_START: AtomicBool = AtomicBool::new(false);

/// Keep the daemon's start notice ("kin daemon ready in 3.0s") off stderr for
/// the rest of this process.
///
/// `kin clone` and `kin init` start a daemon inside a phase that already has a
/// live line, and the notice would be written through it. The phase's own row
/// says how long it took.
pub fn quiet_daemon_start() {
    QUIET_DAEMON_START.store(true, Ordering::Relaxed);
}

/// Whether a daemon this process starts should start without its notice.
pub fn daemon_start_is_quiet() -> bool {
    QUIET_DAEMON_START.load(Ordering::Relaxed)
}

/// The short form's screen for one command: the live line of the phase that
/// is running, and what the command learned on the way for its closing block.
///
/// Shared between the command and the tasks its phases run on, so every
/// method takes `&self`.
pub struct Screen {
    style: Style,
    live: Mutex<Option<LiveLine>>,
    facts: Mutex<Facts>,
}

/// What a command learned while its phases ran, for its rows and closing
/// block.
#[derive(Debug, Default, Clone)]
pub struct Facts {
    /// The repository's languages Kin has a language server for, by name.
    pub languages: Vec<String>,
    /// The language servers that serve them, by name.
    pub servers: Vec<String>,
    /// What linking came to.
    pub linking: Option<Linking>,
    /// A function worth asking about first, read from the graph.
    pub suggestion: Option<String>,
    /// Whether the Linked row has been printed.
    pub linked_shown: bool,
    /// Whether the Search index row has been printed.
    pub search_shown: bool,
}

impl Screen {
    /// A screen drawing in `style`.
    pub fn new(style: Style) -> Self {
        Self {
            style,
            live: Mutex::new(None),
            facts: Mutex::new(Facts::default()),
        }
    }

    /// How this screen draws.
    pub fn style(&self) -> Style {
        self.style
    }

    /// What the command has learned so far.
    pub fn facts(&self) -> MutexGuard<'_, Facts> {
        self.facts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn live(&self) -> MutexGuard<'_, Option<LiveLine>> {
        self.live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Start the live line for a phase called `label`, ending any other.
    pub fn start(&self, label: &str) {
        let mut live = self.live();
        if let Some(previous) = live.take() {
            previous.finish();
        }
        *live = LiveLine::start(self.style, label);
    }

    /// Show `done` of `total` `unit` on the live line.
    pub fn progress(&self, done: u64, total: u64, unit: &str) {
        if let Some(live) = self.live().as_ref() {
            live.progress(done, total, unit);
        }
    }

    /// Show a short note on the live line in place of a bar.
    pub fn note(&self, note: &str) {
        if let Some(live) = self.live().as_ref() {
            live.note(note);
        }
    }

    /// End the live line, and say how long its phase ran.
    pub fn finish(&self) -> Option<Duration> {
        self.live().take().map(LiveLine::finish)
    }

    /// End the live line and print a phase's row with the phase's timing.
    pub fn finish_row(&self, status: Status, label: &str, value: &str) {
        let elapsed = self.finish();
        self.row(status, label, value, elapsed);
    }

    /// Print one row, ending any live line first.
    pub fn row(&self, status: Status, label: &str, value: &str, elapsed: Option<Duration>) {
        self.finish();
        self.print(&fitted_row(self.style, status, label, value, elapsed));
    }

    /// Print a line under a row's value, such as the command that fixes it.
    pub fn hint(&self, text: &str) {
        self.finish();
        for line in hint_lines(self.style, text) {
            self.print(&line);
        }
    }

    /// Print lines as they are.
    pub fn lines(&self, lines: &[String]) {
        self.finish();
        for line in lines {
            self.print(line);
        }
    }

    fn print(&self, line: &str) {
        use std::io::Write as _;
        println!("{line}");
        let _ = std::io::stdout().flush();
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        self.finish();
    }
}

/// One row, kept inside [`MAX_COLUMNS`].
///
/// A value too long for its row continues under its own column, never cut: a
/// row's value often ends in the command that fixes it, and a value shortened
/// in the middle lost exactly that at 60 columns. The timing stays on the first
/// line when the value leaves it room. `value` is plain text; its ` · `
/// separators are drawn in the style's own separator here. Several lines come
/// back joined by newlines.
pub fn fitted_row(
    style: Style,
    status: Status,
    label: &str,
    value: &str,
    elapsed: Option<Duration>,
) -> String {
    let room = max_columns().saturating_sub(VALUE_COLUMN).max(12);
    let mut parts = wrap_value(value, room);
    let fits = |parts: &[String], elapsed: Duration| {
        let first = parts.first().map_or(0, |line| line.chars().count());
        VALUE_COLUMN + first + 2 + screen::format_elapsed(elapsed).len() <= max_columns()
    };
    let elapsed = elapsed.filter(|elapsed| {
        if fits(&parts, *elapsed) {
            return true;
        }
        // Give the timing its room on the first line, if the value can still
        // wrap sensibly around it.
        let timing = screen::format_elapsed(*elapsed).len() + 2;
        let narrower = wrap_value(value, room.saturating_sub(timing).max(12));
        if fits(&narrower, *elapsed) {
            parts = narrower;
            true
        } else {
            false
        }
    });
    let mut lines = vec![screen::row(
        style,
        INDENT,
        status,
        label,
        &separated(style, parts.first().map_or("", String::as_str)),
        elapsed,
    )];
    for part in parts.iter().skip(1) {
        lines.push(format!(
            "{}{}",
            " ".repeat(VALUE_COLUMN),
            separated(style, part)
        ));
    }
    lines.join("\n")
}

/// A row's value in lines of at most `room` columns, breaking at its ` · `
/// separators first, so each part of the value stays whole on its line, and
/// between words only inside a part too long for one line.
fn wrap_value(value: &str, room: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for part in value.split(" · ") {
        let joined = if current.is_empty() {
            part.to_string()
        } else {
            format!("{current} · {part}")
        };
        if joined.chars().count() <= room {
            current = joined;
            continue;
        }
        if !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }
        if part.chars().count() <= room {
            current = part.to_string();
        } else {
            let mut wrapped = screen::wrap(part, room);
            current = wrapped.pop().unwrap_or_default();
            lines.extend(wrapped);
        }
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

/// The lines that sit under a row's value, such as the command that fixes it.
///
/// Full contrast, because a person reads or copies them, and wrapped at word
/// boundaries rather than cut, so a command is never shortened.
pub fn hint_lines(style: Style, text: &str) -> Vec<String> {
    let _ = style;
    screen::wrap(text, max_columns().saturating_sub(VALUE_COLUMN).max(20))
        .into_iter()
        .map(|line| format!("{}{line}", " ".repeat(VALUE_COLUMN)))
        .collect()
}

/// `text` with each ` · ` drawn as the style's separator.
fn separated(style: Style, text: &str) -> String {
    text.replace(" · ", &format!(" {} ", style.dot()))
}

/// A language's name as a reader writes it.
pub fn language_name(language: kin_model::LanguageId) -> String {
    use kin_model::LanguageId;
    match language {
        LanguageId::Rust => "Rust".to_string(),
        LanguageId::Python => "Python".to_string(),
        LanguageId::TypeScript => "TypeScript".to_string(),
        LanguageId::JavaScript => "JavaScript".to_string(),
        LanguageId::Go => "Go".to_string(),
        other => {
            let name = other.to_string();
            let mut chars = name.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => name,
            }
        }
    }
}

/// A language server's name as a reader knows it: `pyright`, not the
/// `pyright-langserver` binary the daemon starts.
pub fn server_name(binary: &str) -> String {
    binary.trim_end_matches("-langserver").to_string()
}

/// `a`, `a and b`, `a, b and c`.
pub fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// What a clone or init does about the language servers its repository needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerInstall {
    /// Nothing is missing, or the command runs no linking at all.
    Nothing,
    /// `kin setup` recorded yes: install exactly these.
    Install(Vec<kin_model::LanguageId>),
    /// Missing, and nobody said yes: install nothing and name the command.
    Offer(Vec<kin_model::LanguageId>),
}

/// Decide what to do about `missing`, the repository's languages whose server
/// this host lacks.
///
/// Only a recorded yes installs. No answer is not consent, and `--no-enrich`
/// runs no linking, so a server installed for it would serve nothing this
/// command does.
pub fn server_install(
    consent: Option<bool>,
    no_enrich: bool,
    missing: &[kin_model::LanguageId],
) -> ServerInstall {
    if no_enrich || missing.is_empty() {
        return ServerInstall::Nothing;
    }
    match consent {
        Some(true) => ServerInstall::Install(missing.to_vec()),
        Some(false) | None => ServerInstall::Offer(missing.to_vec()),
    }
}

/// What a finished sweep reported, as the short form reads it off
/// `/lsp/sweep/status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepTally {
    pub done: u64,
    pub total: u64,
    pub blocked: u64,
    /// Languages it could not serve: the language, its files, and the reason
    /// the daemon observed.
    pub skipped: Vec<(String, u64, String)>,
    /// Whether each skip is a missing server, as the daemon's reason says.
    pub skipped_missing_server: Vec<bool>,
    /// How many files it still owes.
    pub owed: u64,
    /// The owed files it named.
    pub owed_files: Vec<String>,
}

impl SweepTally {
    /// Read a sweep status payload. A field the daemon did not send reads as
    /// nothing, which is what it reported before the field existed.
    pub fn from_status(status: &serde_json::Value) -> Self {
        let number = |key: &str| status.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
        let skipped: Vec<(String, u64, String)> = status
            .get("languages_skipped")
            .and_then(|v| v.as_array())
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        let language = row.get("language")?.as_str()?.to_string();
                        let reason = row.get("reason")?.as_str()?.to_string();
                        (!language.is_empty() && !reason.is_empty()).then(|| {
                            (
                                language,
                                row.get("files").and_then(|v| v.as_u64()).unwrap_or(0),
                                reason,
                            )
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let skipped_missing_server = skipped
            .iter()
            .map(|(_, _, reason)| {
                kin_core::reference_coverage::skip_reason_is_missing_server(reason)
            })
            .collect();
        let owed_files: Vec<String> = status
            .get("owed_files")
            .and_then(|v| v.as_array())
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row.get("file")?.as_str().map(str::to_string))
                    .filter(|file| !file.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            done: number("files_done"),
            total: number("files_total"),
            blocked: number("files_blocked"),
            skipped,
            skipped_missing_server,
            owed: number("files_owed").max(owed_files.len() as u64),
            owed_files,
        }
    }

    /// Whether every file the sweep did not serve went unserved only because
    /// no server for its language is installed.
    fn unserved_for_want_of_a_server(&self) -> bool {
        !self.skipped.is_empty() && self.skipped_missing_server.iter().all(|missing| *missing)
    }

    /// Blocked files the daemon did not attribute to a language.
    fn unattributed(&self) -> u64 {
        let named: u64 = self.skipped.iter().map(|(_, files, _)| files).sum();
        self.blocked.saturating_sub(named)
    }
}

/// What linking came to, as the rows and the closing block say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Linking {
    /// A sweep ran to its end.
    Finished(SweepTally),
    /// This command stopped waiting, and the daemon finishes the sweep.
    BudgetSpent { done: u64, total: u64 },
    /// No language server could serve this repository.
    NoServer,
    /// `--no-enrich` asked for none.
    Skipped,
    /// It did not run, for this reason.
    NotRun(String),
}

/// The Linked row: its status, its value, and a line under it when a reader
/// has something to do.
pub fn linked_row(
    linking: &Linking,
    languages: &[String],
    servers: &[String],
) -> (Status, String, Option<String>) {
    let language = match languages {
        [one] => format!("{one} "),
        _ => String::new(),
    };
    match linking {
        Linking::Finished(tally) if tally.total == 0 => (
            Status::Off,
            "nothing here for a language server to read".to_string(),
            None,
        ),
        Linking::Finished(tally) if tally.done == 0 && tally.unserved_for_want_of_a_server() => (
            Status::Off,
            no_server_value(languages),
            Some(format!("{INSTALL_SERVERS} adds it")),
        ),
        Linking::Finished(tally) if tally.done == 0 => (
            Status::Warn,
            format!("0 of {} {language}files", screen::count(tally.total)),
            None,
        ),
        Linking::Finished(tally) => {
            let mut value = format!(
                "{} of {} {language}files",
                screen::count(tally.done),
                screen::count(tally.total)
            );
            if !servers.is_empty() {
                value.push_str(&format!(" · {}", servers.join(", ")));
            }
            (Status::Ok, value, None)
        }
        Linking::BudgetSpent { done, total } => (
            Status::Warn,
            format!(
                "{} of {} files so far · finishing in the background",
                screen::count(*done),
                screen::count(*total)
            ),
            None,
        ),
        Linking::NoServer => (
            Status::Off,
            no_server_value(languages),
            Some(format!("{INSTALL_SERVERS} adds it")),
        ),
        Linking::Skipped => (
            Status::Off,
            "skipped (--no-enrich) · kin daemon sweep links them".to_string(),
            None,
        ),
        Linking::NotRun(cause) => (
            Status::Warn,
            format!("not run · {cause}"),
            Some("kin doctor says why; kin daemon sweep retries".to_string()),
        ),
    }
}

fn no_server_value(languages: &[String]) -> String {
    match languages {
        [] => "no language server".to_string(),
        languages => format!("no {} language server", and_list(languages)),
    }
}

/// The lines explaining what a finished sweep left unlinked, or nothing.
///
/// Counts and names, never a claim of completeness: a file the language
/// server could not answer for is named, and so is every language it could not
/// serve. `detail` adds the sentence about retries that `kin clone` and
/// `kin init` close on; `kin daemon sweep` keeps it to one line.
pub fn unlinked_lines(
    style: Style,
    linking: &Linking,
    servers: &[String],
    detail: bool,
) -> Vec<String> {
    let Linking::Finished(tally) = linking else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    let warn = style.glyph(Status::Warn);
    if tally.owed > 0 {
        // One file fits beside its count. More than one each get a line of
        // their own, so no path is cut to fit another beside it.
        let name_room = max_columns().saturating_sub(INDENT.len() + 2).max(20);
        match tally.owed_files.as_slice() {
            [only] if tally.owed == 1 => {
                let head = "1 file isn't linked yet: ";
                lines.push(format!(
                    "{INDENT}{warn} {head}{}",
                    screen::fit(only, name_room - head.len())
                ));
            }
            named => {
                lines.push(format!(
                    "{INDENT}{warn} {} linked yet:",
                    plural(tally.owed, "file isn't", "files aren't")
                ));
                for file in named.iter().take(OWED_FILES_NAMED) {
                    lines.push(format!("{INDENT}  {}", screen::fit(file, name_room)));
                }
                let unnamed = tally
                    .owed
                    .saturating_sub(named.len().min(OWED_FILES_NAMED) as u64);
                if unnamed > 0 {
                    lines.push(format!("{INDENT}  and {} more", screen::count(unnamed)));
                }
            }
        }
        let who = match servers {
            [one] => one.clone(),
            _ => "The language server".to_string(),
        };
        let them = if tally.owed == 1 { "it" } else { "them" };
        if detail {
            lines.push(format!(
                "{INDENT}  {who} couldn't answer for {them}. Kin keeps retrying in the background,"
            ));
            lines.push(format!(
                "{INDENT}  and kin refs says so when an answer depends on {them}."
            ));
        } else {
            lines.push(format!("{INDENT}  {who} couldn't answer for {them}."));
        }
    }
    let unserved_row_says_it = tally.done == 0 && tally.unserved_for_want_of_a_server();
    if !unserved_row_says_it {
        for ((language, files, reason), missing) in
            tally.skipped.iter().zip(&tally.skipped_missing_server)
        {
            let name = display_language(language);
            let count = plural(*files, "file isn't", "files aren't");
            if *missing {
                lines.push(format!(
                    "{INDENT}{warn} {count} linked: no {name} language server"
                ));
                lines.push(format!("{INDENT}  {INSTALL_SERVERS} adds it"));
            } else {
                lines.push(format!(
                    "{INDENT}{warn} {count} linked: the {name} language server didn't start"
                ));
                for line in screen::wrap(reason, max_columns().saturating_sub(INDENT.len() + 2)) {
                    lines.push(format!("{INDENT}  {line}"));
                }
            }
        }
    }
    let unattributed = tally.unattributed();
    if unattributed > 0 {
        lines.push(format!(
            "{INDENT}{warn} {} linked: no language server here reads them",
            plural(unattributed, "file isn't", "files aren't")
        ));
    }
    lines
}

fn plural(count: u64, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{} {many}", screen::count(count))
    }
}

/// A language the daemon named in lowercase, as a reader writes it.
fn display_language(name: &str) -> String {
    match name {
        "rust" => "Rust".to_string(),
        "python" => "Python".to_string(),
        "typescript" => "TypeScript".to_string(),
        "javascript" => "JavaScript".to_string(),
        "go" => "Go".to_string(),
        other => other.to_string(),
    }
}

/// Everything the closing block of a clone or init says.
#[derive(Debug, Clone)]
pub struct Closing {
    /// The repository's name, as its directory is called.
    pub name: String,
    /// Its languages, by name.
    pub languages: Vec<String>,
    pub entities: u64,
    pub relations: u64,
    pub linking: Linking,
    /// The language servers that linked it, by name.
    pub servers: Vec<String>,
    /// Where to `cd` first, for a clone.
    pub cd: Option<String>,
    /// A function worth asking about, from the graph.
    pub suggestion: Option<String>,
}

/// The closing block: the unlinked explanation, the Ready sentence and the one
/// next action, each after a blank line.
pub fn closing_lines(style: Style, closing: &Closing) -> Vec<String> {
    let mut lines = Vec::new();
    let unlinked = unlinked_lines(style, &closing.linking, &closing.servers, true);
    if !unlinked.is_empty() {
        lines.push(String::new());
        lines.extend(unlinked);
    }
    lines.push(String::new());
    let counts = format!(
        "{} entities, {} relations",
        screen::count(closing.entities),
        screen::count(closing.relations)
    );
    let summary = if closing.languages.is_empty() {
        format!("{}: {counts}.", closing.name)
    } else {
        format!(
            "{}: {}, {counts}.",
            closing.name,
            and_list(&closing.languages)
        )
    };
    // Each sentence wrapped at the terminal's width, so none reaches the edge
    // and breaks mid-word, with its opening words in bold.
    let width = max_columns().saturating_sub(INDENT.len()).max(20);
    let mut sentence = |lead: &str, rest: &str| {
        let text = if rest.is_empty() {
            lead.to_string()
        } else {
            format!("{lead} {rest}")
        };
        for (index, line) in screen::wrap(&text, width).into_iter().enumerate() {
            let line = match line.strip_prefix(lead) {
                Some(after) if index == 0 && !lead.is_empty() => {
                    format!("{}{after}", style.bold(lead))
                }
                _ => line,
            };
            lines.push(format!("{INDENT}{line}"));
        }
    };
    match &closing.linking {
        Linking::BudgetSpent { .. } => {
            sentence("Ready to query.", "Linking finishes in the background;");
            sentence("", "kin refs says when an answer is incomplete.");
        }
        Linking::Finished(tally) if tally.done > 0 => {
            sentence("Ready.", &summary);
        }
        _ => {
            sentence("Ready.", &summary);
            sentence(
                "",
                "Calls across files are matched by name until they're linked.",
            );
        }
    }
    lines.push(String::new());
    let ask = format!(
        "kin refs {}",
        closing.suggestion.as_deref().unwrap_or("<function>")
    );
    let next = match &closing.cd {
        Some(dir) => format!("cd {} && {ask}", shell_word(dir)),
        None => ask,
    };
    lines.push(format!(
        "{INDENT}{}  {}",
        style.lilac("Next"),
        style.bold(&next)
    ));
    lines
}

/// `word` as a shell would take it: quoted only when it has to be.
fn shell_word(word: &str) -> String {
    let plain = word
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./~+@%:,".contains(c));
    if plain && !word.is_empty() {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// One entity a graph read ranked, as the suggestion picks among them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedEntity {
    pub name: String,
    pub kind: String,
    pub file_path: Option<String>,
    pub dependents: usize,
}

/// The function to suggest first: the one most of the repository depends on.
///
/// `ranked` is the graph's own importance order. A function beats a method,
/// since `kin refs` on a method name can match every class that has one; a
/// test, a private helper and a name the list holds twice are passed over,
/// because each makes a worse first question than the next candidate.
pub fn suggestion(ranked: &[RankedEntity]) -> Option<String> {
    let usable = |entity: &&RankedEntity| {
        let name = entity.name.as_str();
        let in_tests = entity.file_path.as_deref().is_some_and(|path| {
            path.split('/').any(|part| {
                part == "test"
                    || part == "tests"
                    || part.starts_with("test_")
                    || part.ends_with("_test.go")
            })
        });
        entity.dependents > 0
            && !name.is_empty()
            && !name.starts_with('_')
            && !name.starts_with("test")
            && name.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !in_tests
            && ranked
                .iter()
                .filter(|other| other.name == entity.name)
                .count()
                == 1
    };
    let best_of = |kinds: &[&str]| {
        ranked
            .iter()
            .filter(|entity| kinds.contains(&entity.kind.as_str()))
            .filter(usable)
            .max_by(|left, right| {
                left.dependents
                    .cmp(&right.dependents)
                    .then_with(|| right.name.cmp(&left.name))
            })
            .map(|entity| entity.name.clone())
    };
    best_of(&["Function"]).or_else(|| best_of(&["Method"]))
}

/// One line of `git clone --progress`, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitProgress {
    /// The phase, such as `Receiving objects`.
    pub phase: String,
    pub done: u64,
    pub total: u64,
    /// What has arrived so far, such as `807.79 KiB`, when the line says.
    pub size: Option<String>,
}

/// Read one line of Git's clone progress, or `None` for any other line.
///
/// Git writes `Receiving objects:  45% (1258/2795), 400.00 KiB | 1.20 MiB/s`,
/// redrawn with carriage returns, and a `remote: ` prefix on what the server
/// counts.
pub fn parse_git_progress(line: &str) -> Option<GitProgress> {
    let line = line.trim();
    let line = line.strip_prefix("remote:").map(str::trim).unwrap_or(line);
    let (phase, rest) = line.split_once(':')?;
    let open = rest.find('(')?;
    let close = open + rest[open..].find(')')?;
    let (done, total) = rest[open + 1..close].split_once('/')?;
    let done = done.trim().parse().ok()?;
    let total = total.trim().parse().ok()?;
    let after = rest[close + 1..].trim_start_matches(',').trim();
    let size = after
        .split(['|', ','])
        .next()
        .map(str::trim)
        .filter(|size| size.ends_with("iB") || size.ends_with("bytes"))
        .map(str::to_string);
    Some(GitProgress {
        phase: phase.trim().to_string(),
        done,
        total,
        size,
    })
}

/// A size from Git's progress, rounded the way a row prints it: `808 KiB`,
/// `47.1 MiB`.
pub fn rounded_size(size: &str) -> String {
    let Some((number, unit)) = size.trim().split_once(' ') else {
        return size.to_string();
    };
    match number.parse::<f64>() {
        Ok(value) if value >= 100.0 => format!("{value:.0} {unit}"),
        Ok(value) => format!("{value:.1} {unit}"),
        Err(_) => size.to_string(),
    }
}

/// The Downloaded row's value.
pub fn downloaded_value(objects: Option<u64>, size: Option<&str>) -> String {
    match (objects, size) {
        (Some(objects), Some(size)) => {
            format!(
                "{} objects · {}",
                screen::count(objects),
                rounded_size(size)
            )
        }
        (Some(objects), None) => format!("{} objects", screen::count(objects)),
        _ => "Git history copied".to_string(),
    }
}

/// The repository a clone URL names, as a reader writes it:
/// `pallets/itsdangerous` for a hosted URL, the last component for a path.
pub fn clone_slug(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let hosted = trimmed.contains("://")
        || trimmed
            .split_once(':')
            .is_some_and(|(host, _)| host.contains('@') || host.contains('.'));
    let parts: Vec<&str> = trimmed
        .rsplit(['/', ':'])
        .filter(|part| !part.is_empty())
        .take(if hosted { 2 } else { 1 })
        .collect();
    let slug: Vec<&str> = parts.into_iter().rev().collect();
    if slug.is_empty() {
        url.to_string()
    } else {
        slug.join("/")
    }
}

/// The Read history row's value.
pub fn read_history_value(commits: u64, entities: u64) -> String {
    format!(
        "{} {} · {} entities",
        screen::count(commits),
        if commits == 1 { "commit" } else { "commits" },
        screen::count(entities)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::LanguageId;

    fn plain() -> Style {
        Style::plain()
    }

    fn tally(done: u64, total: u64) -> SweepTally {
        SweepTally {
            done,
            total,
            ..SweepTally::default()
        }
    }

    #[test]
    fn only_a_recorded_yes_installs_and_never_under_no_enrich() {
        let missing = [LanguageId::Python];
        assert_eq!(
            server_install(Some(true), false, &missing),
            ServerInstall::Install(vec![LanguageId::Python])
        );
        assert_eq!(
            server_install(None, false, &missing),
            ServerInstall::Offer(vec![LanguageId::Python]),
            "no answer is not consent"
        );
        assert_eq!(
            server_install(Some(false), false, &missing),
            ServerInstall::Offer(vec![LanguageId::Python])
        );
        assert_eq!(
            server_install(Some(true), true, &missing),
            ServerInstall::Nothing,
            "--no-enrich links nothing, so nothing is installed for it"
        );
        assert_eq!(
            server_install(Some(true), false, &[]),
            ServerInstall::Nothing
        );
    }

    #[test]
    fn the_result_block_reads_like_the_design() {
        let mut finished = tally(14, 15);
        finished.owed = 1;
        finished.owed_files = vec!["tests/test_itsdangerous/test_serializer.py".to_string()];
        let closing = Closing {
            name: "itsdangerous".to_string(),
            languages: vec!["Python".to_string()],
            entities: 197,
            relations: 1726,
            linking: Linking::Finished(finished),
            servers: vec!["pyright".to_string()],
            cd: Some("itsdangerous".to_string()),
            suggestion: Some("want_bytes".to_string()),
        };
        let lines = closing_lines(plain(), &closing);
        assert_eq!(
            lines,
            vec![
                "",
                "  ! 1 file isn't linked yet: tests/test_itsdangerous/test_serializer.py",
                "    pyright couldn't answer for it. Kin keeps retrying in the background,",
                "    and kin refs says so when an answer depends on it.",
                "",
                "  Ready. itsdangerous: Python, 197 entities, 1,726 relations.",
                "",
                "  Next  cd itsdangerous && kin refs want_bytes",
            ]
        );
        for line in &lines {
            assert!(line.chars().count() <= MAX_COLUMNS, "{line}");
        }
    }

    #[test]
    fn a_spent_budget_says_ready_to_query_and_never_claims_completeness() {
        let closing = Closing {
            name: "flask".to_string(),
            languages: vec!["Python".to_string()],
            entities: 1,
            relations: 1,
            linking: Linking::BudgetSpent { done: 9, total: 15 },
            servers: vec!["pyright".to_string()],
            cd: None,
            suggestion: None,
        };
        let lines = closing_lines(plain(), &closing);
        assert!(
            lines.contains(&"  Ready to query. Linking finishes in the background;".to_string())
        );
        assert!(lines.contains(&"  kin refs says when an answer is incomplete.".to_string()));
        assert_eq!(lines.last().unwrap(), "  Next  kin refs <function>");
        let (status, value, _) = linked_row(&closing.linking, &closing.languages, &[]);
        assert_eq!(status, Status::Warn);
        assert_eq!(value, "9 of 15 files so far · finishing in the background");
    }

    #[test]
    fn no_server_says_the_answers_are_matched_by_name_and_names_the_fix() {
        let (status, value, hint) = linked_row(&Linking::NoServer, &["Python".to_string()], &[]);
        assert_eq!(status, Status::Off);
        assert_eq!(value, "no Python language server");
        assert_eq!(
            hint.as_deref(),
            Some(&*format!("{INSTALL_SERVERS} adds it"))
        );
        let closing = Closing {
            name: "x".to_string(),
            languages: vec!["Python".to_string()],
            entities: 2,
            relations: 3,
            linking: Linking::NoServer,
            servers: Vec::new(),
            cd: None,
            suggestion: None,
        };
        let lines = closing_lines(plain(), &closing);
        assert!(lines
            .iter()
            .any(|line| line.contains("matched by name until they're linked")));
    }

    #[test]
    fn a_linked_row_names_the_language_and_the_server() {
        let (status, value, hint) = linked_row(
            &Linking::Finished(tally(14, 15)),
            &["Python".to_string()],
            &["pyright".to_string()],
        );
        assert_eq!(status, Status::Ok);
        assert_eq!(value, "14 of 15 Python files · pyright");
        assert!(hint.is_none());
        let row = fitted_row(
            plain(),
            status,
            "Linked",
            &value,
            Some(Duration::from_millis(41_200)),
        );
        assert_eq!(
            row,
            "  ✓ Linked            14 of 15 Python files · pyright                    41.2s"
        );
    }

    #[test]
    fn several_owed_files_are_counted_and_each_named_on_its_own_line() {
        let mut finished = tally(10, 15);
        finished.owed = 5;
        finished.owed_files = vec![
            "src/app/one.py".to_string(),
            "src/app/two.py".to_string(),
            "src/app/three.py".to_string(),
            "src/app/four.py".to_string(),
            "src/app/five.py".to_string(),
        ];
        let lines = unlinked_lines(plain(), &Linking::Finished(finished), &[], false);
        assert_eq!(
            lines,
            vec![
                "  ! 5 files aren't linked yet:",
                "    src/app/one.py",
                "    src/app/two.py",
                "    src/app/three.py",
                "    and 2 more",
                "    The language server couldn't answer for them.",
            ]
        );
    }

    #[test]
    fn an_unserved_language_is_named_with_its_fix() {
        let mut finished = tally(10, 13);
        finished.blocked = 3;
        finished.skipped = vec![("go".to_string(), 3, "no language server found".to_string())];
        finished.skipped_missing_server = vec![true];
        let lines = unlinked_lines(plain(), &Linking::Finished(finished), &[], true);
        assert_eq!(
            lines,
            vec![
                "  ! 3 files aren't linked: no Go language server".to_string(),
                format!("    {INSTALL_SERVERS} adds it"),
            ]
        );
    }

    #[test]
    fn a_long_row_drops_its_timing_rather_than_pass_eighty_columns() {
        let row = fitted_row(
            plain(),
            Status::Warn,
            "Linked",
            "1,603 of 3,590 files so far · finishing in the background",
            Some(Duration::from_secs(900)),
        );
        for line in row.lines() {
            assert!(line.chars().count() <= MAX_COLUMNS, "{row}");
        }
        assert!(!row.contains('…'), "a value is wrapped, never cut: {row}");
    }

    /// A value that ends in a command keeps the whole command at any width,
    /// broken at its separators rather than cut in the middle.
    #[test]
    fn a_long_value_wraps_at_its_separators_and_keeps_its_command() {
        let lines = wrap_value("waits for the search model · kin embed downloads it", 36);
        assert_eq!(
            lines,
            vec![
                "waits for the search model".to_string(),
                "kin embed downloads it".to_string()
            ]
        );
        let lines = wrap_value("pyright needs npm, which isn't installed", 36);
        assert_eq!(lines.join(" "), "pyright needs npm, which isn't installed");
        assert!(
            lines.iter().all(|line| line.chars().count() <= 36),
            "{lines:?}"
        );
        assert_eq!(
            wrap_value("2,795 objects · 808 KiB", 36),
            vec!["2,795 objects · 808 KiB"]
        );
    }

    #[test]
    fn the_suggestion_is_the_function_most_of_the_repository_depends_on() {
        let entity = |name: &str, kind: &str, path: &str, dependents| RankedEntity {
            name: name.to_string(),
            kind: kind.to_string(),
            file_path: Some(path.to_string()),
            dependents,
        };
        let ranked = vec![
            entity("itsdangerous", "Module", "src/itsdangerous/__init__.py", 40),
            entity("loads", "Method", "src/itsdangerous/serializer.py", 30),
            entity("want_bytes", "Function", "src/itsdangerous/encoding.py", 23),
            entity(
                "_make_keys_list",
                "Function",
                "src/itsdangerous/signer.py",
                25,
            ),
            entity("test_want_bytes", "Function", "tests/test_encoding.py", 50),
            entity(
                "base64_decode",
                "Function",
                "src/itsdangerous/encoding.py",
                9,
            ),
        ];
        assert_eq!(suggestion(&ranked).as_deref(), Some("want_bytes"));
        let methods_only = vec![entity("sign", "Method", "src/signer.py", 3)];
        assert_eq!(suggestion(&methods_only).as_deref(), Some("sign"));
        assert_eq!(suggestion(&[]), None);
        let twice = vec![
            entity("dumps", "Function", "a.py", 9),
            entity("dumps", "Function", "b.py", 8),
        ];
        assert_eq!(
            suggestion(&twice),
            None,
            "an ambiguous name is a bad first question"
        );
    }

    #[test]
    fn git_progress_lines_are_read_and_other_lines_are_not() {
        assert_eq!(
            parse_git_progress("Receiving objects:  45% (1258/2795), 400.00 KiB | 1.20 MiB/s"),
            Some(GitProgress {
                phase: "Receiving objects".to_string(),
                done: 1258,
                total: 2795,
                size: Some("400.00 KiB".to_string()),
            })
        );
        assert_eq!(
            parse_git_progress(
                "Receiving objects: 100% (2795/2795), 807.79 KiB | 4.92 MiB/s, done."
            )
            .and_then(|progress| progress.size),
            Some("807.79 KiB".to_string())
        );
        let counting = parse_git_progress("remote: Counting objects: 100% (579/579), done.")
            .expect("a remote line");
        assert_eq!(counting.phase, "Counting objects");
        assert_eq!(counting.size, None);
        assert_eq!(parse_git_progress("Cloning into 'itsdangerous'..."), None);
        assert_eq!(
            parse_git_progress("remote: Total 2795 (delta 512), reused 393 (delta 393)"),
            None
        );
    }

    #[test]
    fn the_downloaded_row_reads_count_and_rounded_size() {
        assert_eq!(
            downloaded_value(Some(2795), Some("807.79 KiB")),
            "2,795 objects · 808 KiB"
        );
        assert_eq!(rounded_size("47.12 MiB"), "47.1 MiB");
        assert_eq!(downloaded_value(None, None), "Git history copied");
    }

    #[test]
    fn a_clone_url_names_its_repository_the_way_a_reader_does() {
        assert_eq!(
            clone_slug("https://github.com/pallets/itsdangerous"),
            "pallets/itsdangerous"
        );
        assert_eq!(
            clone_slug("https://github.com/pallets/itsdangerous.git/"),
            "pallets/itsdangerous"
        );
        assert_eq!(
            clone_slug("git@github.com:pallets/flask.git"),
            "pallets/flask"
        );
        assert_eq!(clone_slug("/tmp/work/source"), "source");
    }

    #[test]
    fn a_path_is_quoted_only_when_a_shell_needs_it() {
        assert_eq!(shell_word("itsdangerous"), "itsdangerous");
        assert_eq!(shell_word("my repo"), "'my repo'");
    }

    #[test]
    fn the_sweep_tally_reads_the_daemons_own_fields() {
        let status = serde_json::json!({
            "files_done": 14,
            "files_total": 15,
            "files_blocked": 0,
            "files_owed": 1,
            "owed_files": [{"file": "tests/test_x.py", "reason": "JSON-RPC error"}],
            "languages_skipped": [],
        });
        let tally = SweepTally::from_status(&status);
        assert_eq!(tally.done, 14);
        assert_eq!(tally.total, 15);
        assert_eq!(tally.owed, 1);
        assert_eq!(tally.owed_files, vec!["tests/test_x.py".to_string()]);
    }
}
