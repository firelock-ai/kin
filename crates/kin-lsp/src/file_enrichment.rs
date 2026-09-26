// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! File-level LSP enrichment — extracts maximum relationships from a single file.
//!
//! Strategy: query textDocument/definition at the identifier positions in the
//! file. Each resolved definition creates a relationship from the containing
//! entity to the target entity. This captures references of every kind:
//! function calls, type usage, field access, method calls, trait references,
//! imports — everything the type system can resolve. A definite answer at a
//! call's callee token is also the proof of that call (see
//! [`crate::call_sites`]).
//!
//! This file-level pass then supplements them with call-hierarchy relations
//! for every entity in the file, which keeps the sweep broad while still
//! emitting `Calls` edges.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use crate::enrichment::{deterministic_relation_id, enrich_entity_calls, EntityIndex, EntityRef};
use crate::error::{LspError, QueryErrorClass, Result};
use crate::lifecycle::LspServer;
use crate::protocol;
use kin_model::{EntityId, GraphNodeId, Relation, RelationKind, RelationOrigin};

/// Result of enriching a single file.
#[derive(Debug, Default)]
pub struct FileEnrichmentResult {
    pub relations: Vec<Relation>,
    pub definitions_resolved: usize,
    pub positions_queried: usize,
    /// Queries in this pass that got no answer: one that timed out (it was
    /// skipped), an error the server returned itself, or a server that stopped
    /// answering (the pass stopped where it was). Each may answer if asked
    /// again. Every relation in `relations` stands on its own answer. Nonzero
    /// means the pass did not finish the file, so the caller must not record
    /// the file as enriched.
    pub failed_queries: usize,
    /// Questions the server settled for good, which asking again would only
    /// repeat: an answer this build cannot prove or decode
    /// ([`LspError::is_refusal`]), a caller whose call hierarchy reported calls
    /// with no site inside it (see `unproven_calls`), and a member join
    /// candidate whose own name could not be located. None holds the file
    /// back or names its `first_failure`; `unprovable` names each.
    pub refused_queries: usize,
    /// The entity each refusal was about, with what was refused.
    pub unprovable: Vec<(EntityId, String)>,
    /// Whether the call hierarchy of every entity the pass's [`FileScope`]
    /// asks it of was asked and answered, so `relations` carries every
    /// `Calls` edge and `site_answers` every call range a per-entity call
    /// hierarchy query about those entities would. False when the pass
    /// stopped before the loop, stopped inside it, or any such entity's call
    /// hierarchy got no answer.
    pub call_hierarchy_complete: bool,
    /// Queries the server declined as not applying where they were asked. An
    /// answer with nothing in it: counted, and never a reason to hold the file.
    pub declined_queries: usize,
    /// What the first failed query was, for the record of files still owed.
    pub first_failure: Option<String>,
    /// Outgoing calls a caller's call hierarchy reported with no site inside
    /// that caller. None became an edge, and every caller that reported any is
    /// one of `refused_queries`: the same server reports them again. The
    /// caller's other calls stand.
    pub unproven_calls: usize,
    /// Every identifier whose definition answer was definite: every location
    /// it named is the declaration of one graph entity, or every location lies
    /// outside the workspace in a file the graph holds no twin of. A caller
    /// holding the linker's call candidates reads these to tell which
    /// candidates the server contradicted. Identifiers with no answer, a
    /// declined or timed-out query, or an answer this pass cannot place
    /// contribute nothing.
    pub site_answers: Vec<crate::call_sites::SiteAnswer>,
    /// The external symbols the outside answers in `site_answers` name, by the
    /// place each answer landed. A place the server's own symbols and the
    /// package holding it could not name is absent: its answers still prove
    /// the call leaves the repository, and name nothing.
    pub external_names: crate::call_sites::ExternalNames,
    /// `textDocument/definition` requests this pass sent at identifiers,
    /// counting a receiver's and an alias hop's, and not a member join's.
    pub definition_queries: usize,
    /// Definition requests the pass would once have sent and did not: an
    /// identifier that can name no declaration, and a value receiver's
    /// second ask at the same position.
    pub definition_queries_saved: usize,
    /// Identifiers asked first because they open a call.
    pub call_site_queries: usize,
    /// Call sites proven through one alias hop.
    pub alias_hops: usize,
    /// Site answers proven from a TypeScript overload signature.
    pub overload_answers: usize,
    /// Every identifier the pass asked about and could not prove, with what
    /// the question came to, so a call site the pass asked at and that proved
    /// nothing is told apart from one it never asked at.
    pub unproven_sites: Vec<crate::call_sites::UnprovenSite>,
    /// Whether the pass stopped before asking about every identifier it
    /// planned to, because its server stopped answering in time. Identifiers
    /// it did not reach are neither answered nor in `unproven_sites`.
    pub stopped_early: bool,
}

/// Record that the identifier at `(line, col)` in `source` got no proof
/// because its query failed with `error`.
fn record_unproven(
    unproven: &mut Vec<crate::call_sites::UnprovenSite>,
    positions: &crate::source_positions::SourcePositions<'_>,
    source: EntityId,
    (line, col): (u32, u32),
    error: &LspError,
) {
    if let Ok(site) = positions.token(line, col) {
        unproven.push(crate::call_sites::UnprovenSite {
            source,
            start_byte: site.start_byte,
            end_byte: site.end_byte,
            answer: unproven_by_error(error),
        });
    }
}

/// What a query error says about the identifier it was asked at.
fn unproven_by_error(error: &LspError) -> crate::call_sites::UnprovenAnswer {
    use crate::call_sites::UnprovenAnswer;
    match error.class() {
        QueryErrorClass::SessionEnded => UnprovenAnswer::Crash,
        QueryErrorClass::TimedOut => UnprovenAnswer::Timeout,
        QueryErrorClass::Declined => UnprovenAnswer::Refused,
        QueryErrorClass::Failed if error.is_refusal() => UnprovenAnswer::Refused,
        QueryErrorClass::Failed => UnprovenAnswer::ProtocolError,
    }
}

/// What every location of one definition answer says about the identifier.
#[derive(Default)]
struct DefinitionVerdict {
    target: Option<crate::call_sites::SiteTarget>,
    /// Every further place an answer outside the workspace landed. Two such
    /// places agree that the call leaves the repository; whether they name one
    /// symbol is for the namer to say.
    also_outside: Vec<crate::call_sites::OutsideLocation>,
    undecided: bool,
}

impl DefinitionVerdict {
    fn observe(&mut self, target: Option<crate::call_sites::SiteTarget>) {
        use crate::call_sites::SiteTarget;
        match (target, &self.target) {
            (None, _) => self.undecided = true,
            (Some(target), None) => self.target = Some(target),
            (Some(target), Some(held)) if &target == held => {}
            (Some(SiteTarget::Outside(location)), Some(SiteTarget::Outside(_))) => {
                if !self.also_outside.contains(&location) {
                    self.also_outside.push(location);
                }
            }
            (Some(_), Some(_)) => self.undecided = true,
        }
    }

    /// The decided target, and every further outside place the answer named.
    fn decided(&self) -> Option<Vec<crate::call_sites::SiteTarget>> {
        if self.undecided {
            return None;
        }
        let target = self.target.clone()?;
        let mut targets = vec![target];
        targets.extend(
            self.also_outside
                .iter()
                .cloned()
                .map(crate::call_sites::SiteTarget::Outside),
        );
        Some(targets)
    }
}

/// Whether a definition location is the declaration of `dst` itself: on its
/// name line, and, when the column can be read, on its name token.
///
/// A module or file surface declares no name, so no location is its
/// declaration. Its name line is the file's first, and an import written
/// there would otherwise prove a call to the module that holds it.
fn names_declaration_of(dst: &EntityRef, target_line: u32, name_col: Option<(u32, u32)>) -> bool {
    if !dst.declares_name || target_line != dst.name_line {
        return false;
    }
    let Some((dst_name_col, target_col)) = name_col else {
        return true;
    };
    let simple_name = dst
        .name
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(dst.name.as_str());
    let width = simple_name.len() as u32;
    target_col >= dst_name_col && target_col < dst_name_col.saturating_add(width)
}

/// How many language-server queries in a row may time out before a file pass
/// stops asking. One slow answer is load; several in a row is a server that is
/// not answering, and every further question would only spend the pass's
/// budget.
const TIMEOUTS_BEFORE_STOPPING: usize = 3;

/// What a file pass does after a query that produced no answer.
enum AfterRefusal {
    /// Skip that position or declaration and keep going.
    Skip,
    /// Several timeouts in a row: stop asking and keep what was proven.
    Stop,
    /// The server can answer nothing more: the pass ends with this error.
    End(LspError),
}

/// A file pass's count of the queries that produced no answer, kept by the
/// one classification in [`LspError::class`].
#[derive(Default)]
struct Refusals {
    failed: usize,
    refused: usize,
    declined: usize,
    consecutive_timeouts: usize,
    first_failure: Option<String>,
    unproven_calls: usize,
    unprovable: Vec<(EntityId, String)>,
}

impl Refusals {
    fn answered(&mut self) {
        self.consecutive_timeouts = 0;
    }

    fn refused(&mut self, about: EntityId, asked: &str, error: LspError) -> AfterRefusal {
        match error.class() {
            QueryErrorClass::SessionEnded => AfterRefusal::End(error),
            QueryErrorClass::TimedOut => {
                self.fail(asked, &error);
                self.consecutive_timeouts += 1;
                if self.consecutive_timeouts >= TIMEOUTS_BEFORE_STOPPING {
                    AfterRefusal::Stop
                } else {
                    AfterRefusal::Skip
                }
            }
            QueryErrorClass::Declined => {
                self.declined += 1;
                self.consecutive_timeouts = 0;
                AfterRefusal::Skip
            }
            // The server answered with something this build cannot prove or
            // decode, and it answers the same bytes the same way every time.
            QueryErrorClass::Failed if error.is_refusal() => {
                tracing::debug!(asked, %error, "a query in the file pass was refused; it is settled, not owed");
                self.refuse(about, format!("{asked} was refused: {error}"));
                self.consecutive_timeouts = 0;
                AfterRefusal::Skip
            }
            QueryErrorClass::Failed => {
                tracing::debug!(asked, %error, "a query in the file pass failed; the file's other relations stand");
                self.fail(asked, &error);
                self.consecutive_timeouts = 0;
                AfterRefusal::Skip
            }
        }
    }

    fn fail(&mut self, asked: &str, error: &LspError) {
        self.failed += 1;
        self.first_failure
            .get_or_insert_with(|| format!("{asked} got no answer: {error}"));
    }

    fn refuse(&mut self, about: EntityId, what: String) {
        self.refused += 1;
        self.unprovable.push((about, what));
    }

    /// An answer that proved some of what it reported and not the rest. What
    /// it proved stands, and its calls without a site in the caller are
    /// counted and refused: the same server reports them again.
    fn unproven_calls(&mut self, about: EntityId, asked: &str, calls: usize) {
        self.unproven_calls += calls;
        self.refuse(
            about,
            format!("{asked} reported {calls} call(s) with no site inside the caller"),
        );
    }
}

/// Return the starting columns for identifier-like tokens in a single line.
///
/// This skips obvious comments and string literals at the token-scan level and
/// returns word starts so callers can probe LSP features at real symbol
/// positions instead of line 0.
pub(crate) fn identifier_positions_in_line(line_text: &str) -> Vec<u32> {
    let trimmed = line_text.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
        return Vec::new();
    }

    let chars: Vec<char> = line_text.chars().collect();
    let mut positions = Vec::new();
    let mut col = 0usize;
    let mut in_string = false;

    while col < chars.len() {
        let ch = chars[col];

        if ch == '"' && (col == 0 || chars[col - 1] != '\\') {
            in_string = !in_string;
            col += 1;
            continue;
        }
        if in_string {
            col += 1;
            continue;
        }

        if ch.is_alphabetic() || ch == '_' {
            let is_word_start =
                col == 0 || (!chars[col - 1].is_alphanumeric() && chars[col - 1] != '_');
            if is_word_start {
                positions.push(col as u32);
            }

            while col < chars.len() && (chars[col].is_alphanumeric() || chars[col] == '_') {
                col += 1;
            }
            continue;
        }

        col += 1;
    }

    positions
}

/// The identifier token that starts at `col`, as a string.
///
/// `col` is a character offset, the same unit `identifier_positions_in_line`
/// hands out, so the scan is over characters and not bytes.
fn identifier_at(line_text: &str, col: u32) -> String {
    line_text
        .chars()
        .skip(col as usize)
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Whether an identifier inside an entity resolved to that entity's own
/// container without naming it, so no edge should be minted for it.
///
/// An entity nested inside another refers to its container by writing the
/// container's name. Two things that are not the container's name resolved to
/// it anyway, because a definition location is matched to an entity by LINE and
/// a container's declaration line carries more than its name.
///
/// A generic declaration's type parameters sit on that line: `class
/// SmartRouter<T>` owns line 3, so every member that writes `T` (`#routers:
/// Router<T>[]`, `add(handler: T)`, `match(): Result<T>`) resolved `T` there.
/// And `this` resolves to the class's own name token, so the first `this` in
/// every method body resolved to the class as well. Between them, six of the
/// eleven references `find_references` returned for `SmartRouter` were its own
/// members, and ten of fifteen for `EventProcessor<E>`. The TypeScript compiler
/// counts none of them, because none of them writes the name.
///
/// So the identifier has to spell the container's name AND resolve to the
/// container's own name token. `this` and `T` fail the first test, a type
/// parameter fails the second, and a member that really does name its class
/// (`static create() { return new Foo() }`) passes both and keeps its edge. The
/// rule is applied only when the destination CONTAINS the source, so the only
/// edges it can remove are a member's edges to its own container, which the
/// container's own `Contains` edge already carries in the other direction.
/// Every edge between entities that do not contain one another is left exactly
/// as it was.
///
/// `dst_name_col` is the byte column the destination's name starts at on
/// `dst.name_line`, read from the source when the caller holds it, since the
/// signature-derived `dst.name_col` misses it on a decorated declaration.
fn lands_inside_container_without_naming_it(
    source: &EntityRef,
    dst: &EntityRef,
    dst_name_col: u32,
    queried: &str,
    target_line: u32,
    target_col: u32,
) -> bool {
    let contains = dst.file_path == source.file_path
        && dst.start_line <= source.start_line
        && dst.end_line >= source.end_line;
    if !contains {
        return false;
    }
    // A dotted entity name (`Owner.member`) is spelled in the source as its
    // final segment alone, which is both what a call site writes and what
    // `name_col` points at.
    let simple_name = dst.name.rsplit('.').next().unwrap_or(dst.name.as_str());
    if queried != simple_name {
        return true;
    }
    if target_line != dst.name_line {
        return true;
    }
    // `dst_name_col` is where the name STARTS; the token runs its own length.
    let width = simple_name.len() as u32;
    target_col < dst_name_col || target_col >= dst_name_col.saturating_add(width)
}

/// How a file's identifiers are read: which words are keywords, and in Python
/// which stretches of a line are comments or docstrings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lexicon {
    Python,
    Rust,
    Script,
    Other,
}

impl Lexicon {
    fn of(path: &str) -> Self {
        match path.rsplit_once('.').map(|(_, extension)| extension) {
            Some("py" | "pyi") => Self::Python,
            Some("rs") => Self::Rust,
            Some("ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs") => Self::Script,
            _ => Self::Other,
        }
    }
}

/// Whether `path` is TypeScript or JavaScript source.
pub(crate) fn is_script_source(path: &str) -> bool {
    Lexicon::of(path) == Lexicon::Script
}

/// Python's hard keywords. None of them can be a name or an attribute, so a
/// definition asked at one answers nothing the graph holds.
const PYTHON_KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

/// Rust's strict keywords, less the ones whose definition can land in the
/// repository: `self`, `Self`, `super` and `crate` name a value, a type or a
/// module, and rust-analyzer answers `.await` with the `IntoFuture` impl that
/// runs, which on axum is the repository's own.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "break", "const", "continue", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "static", "struct", "trait", "true", "type", "unsafe", "use", "where", "while",
];

/// JavaScript's reserved words that nothing in a module can be bound to.
/// Each can still be a property name, after a `.` or written as a key, a
/// method or a field (typeorm's `QueryBuilder.delete()`), and then it can
/// name a declaration. So only a word followed by whitespace, and not
/// reached through a member access, is read as the keyword.
///
/// `export` is not among them. The server answers a declaration's modifier
/// with the declaration's symbol, and where a type and a value share a name,
/// as in `export declare type AuthMechanism = (typeof AuthMechanism)[...]`,
/// that answer lands on the other one: 41 of typeorm's recorded definition
/// edges were first proven at an `export`.
const SCRIPT_KEYWORDS: &[&str] = &[
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "let",
    "null",
    "return",
    "switch",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
];

/// Whether a definition asked at the identifier starting at `col` can name
/// no declaration, so the pass does not ask it.
///
/// `non_code` holds the line's comment and docstring ranges, in the same
/// character columns. Measured on the integration baselines, no recorded
/// definition edge on axum, fastapi or typeorm sits at a position this skips.
fn names_nothing(lexicon: Lexicon, line_text: &str, col: u32, non_code: &[(u32, u32)]) -> bool {
    if non_code
        .iter()
        .any(|&(start, end)| col >= start && col < end)
    {
        return true;
    }
    let word = identifier_at(line_text, col);
    let chars: Vec<char> = line_text.chars().collect();
    let at = col as usize;
    let previous = at
        .checked_sub(1)
        .and_then(|index| chars.get(index))
        .copied();
    match lexicon {
        Lexicon::Python => PYTHON_KEYWORDS.contains(&word.as_str()),
        // `r#type` is an identifier spelled with a keyword.
        Lexicon::Rust => RUST_KEYWORDS.contains(&word.as_str()) && previous != Some('#'),
        Lexicon::Script => {
            let before = chars[..at.min(chars.len())]
                .iter()
                .rev()
                .find(|character| !character.is_whitespace())
                .copied();
            let after = chars.get(at + word.chars().count()).copied();
            SCRIPT_KEYWORDS.contains(&word.as_str())
                && !matches!(before, Some('.' | '#'))
                && after.is_none_or(char::is_whitespace)
        }
        Lexicon::Other => false,
    }
}

/// For each line of a Python file, the character ranges that hold no code:
/// comments, and the insides of triple-quoted strings that are not
/// formatted. An f-string's replacement fields are code, so an f-string is
/// never skipped, and a one-line string is left to the identifier scan as it
/// always was, because a forward reference such as `"Widget"` is a string the
/// server resolves.
fn python_non_code(text: &str) -> Vec<Vec<(u32, u32)>> {
    let mut lines = Vec::new();
    // A triple-quoted string left open at the end of the line before: its
    // quote character, and whether it is formatted.
    let mut open: Option<(char, bool)> = None;
    for line in text.lines() {
        let chars: Vec<char> = line.chars().collect();
        let mut ranges = Vec::new();
        let mut run = match open {
            Some((_, false)) => Some(0usize),
            _ => None,
        };
        let mut at = 0usize;
        while at < chars.len() {
            if let Some((quote, _)) = open {
                if chars[at] == '\\' {
                    at += 2;
                    continue;
                }
                if chars[at..].starts_with(&[quote, quote, quote]) {
                    if let Some(start) = run.take() {
                        ranges.push((start as u32, at as u32));
                    }
                    open = None;
                    at += 3;
                    continue;
                }
                at += 1;
                continue;
            }
            match chars[at] {
                '#' => {
                    ranges.push((at as u32, chars.len() as u32));
                    at = chars.len();
                }
                quote @ ('\'' | '"') => {
                    let formatted = string_prefix_formats(&chars[..at]);
                    if chars[at..].starts_with(&[quote, quote, quote]) {
                        at += 3;
                        open = Some((quote, formatted));
                        if !formatted {
                            run = Some(at);
                        }
                        continue;
                    }
                    // A one-line string ends at its closing quote or, left
                    // unterminated, at the end of the line.
                    at += 1;
                    while at < chars.len() && chars[at] != quote {
                        at += if chars[at] == '\\' { 2 } else { 1 };
                    }
                    at += 1;
                }
                _ => at += 1,
            }
        }
        if let (Some(_), Some(start)) = (open, run) {
            ranges.push((start as u32, chars.len() as u32));
        }
        lines.push(ranges);
    }
    lines
}

/// Whether the string prefix written just before a quote makes it a
/// formatted string (`f`, or a template string's `t`).
fn string_prefix_formats(before: &[char]) -> bool {
    let prefix: Vec<char> = before
        .iter()
        .rev()
        .take_while(|character| character.is_alphanumeric() || **character == '_')
        .copied()
        .collect();
    prefix.len() <= 2 && prefix.iter().any(|c| matches!(c, 'f' | 'F' | 't' | 'T'))
}

/// Whether the identifier starting at `col` is the callee of a call written
/// on this line: followed by an argument list, perhaps after generic
/// arguments, `?.` or a non-null `!`, or applied as a decorator.
fn opens_a_call(line_text: &str, col: u32) -> bool {
    let chars: Vec<char> = line_text.chars().collect();
    let start = col as usize;
    if start > 0 && chars.get(start - 1) == Some(&'@') {
        return true;
    }
    let mut at = start;
    while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
        at += 1;
    }
    let skip_spaces = |mut at: usize| {
        while at < chars.len() && chars[at].is_whitespace() {
            at += 1;
        }
        at
    };
    at = skip_spaces(at);
    if chars[at.min(chars.len())..].starts_with(&['?', '.']) {
        at += 2;
    } else if chars.get(at) == Some(&'!') && chars.get(at + 1) != Some(&'=') {
        at += 1;
    }
    at = skip_spaces(at);
    if chars[at.min(chars.len())..].starts_with(&[':', ':', '<']) {
        at += 2;
    }
    if chars.get(at) == Some(&'<') {
        let mut depth = 0usize;
        let mut closed = None;
        for (offset, character) in chars[at..].iter().enumerate() {
            match character {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        closed = Some(at + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(after) = closed else {
            return false;
        };
        at = skip_spaces(after);
    }
    chars.get(at) == Some(&'(')
}

/// The name a TypeScript or JavaScript declaration line declares, when it
/// declares a function, a method or one of their signatures.
fn declared_callable(line: &str) -> Option<&str> {
    const MODIFIERS: &[&str] = &[
        "export",
        "public",
        "private",
        "protected",
        "static",
        "async",
        "abstract",
        "readonly",
        "override",
        "declare",
        "function",
        "get",
        "set",
        "default",
    ];
    let mut rest = line.trim_start();
    loop {
        let end = rest
            .char_indices()
            .find(|(_, c)| !(c.is_alphanumeric() || *c == '_' || *c == '$'))
            .map_or(rest.len(), |(offset, _)| offset);
        if end == 0 {
            return None;
        }
        let word = &rest[..end];
        let after = &rest[end..];
        if MODIFIERS.contains(&word) && after.starts_with(char::is_whitespace) {
            rest = after.trim_start();
            continue;
        }
        let tail = after.trim_start();
        let tail = tail.strip_prefix(['?', '!']).unwrap_or(tail).trim_start();
        return (tail.starts_with('(') || tail.starts_with('<')).then_some(word);
    }
}

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The entity a definition answer on a TypeScript overload signature
/// belongs to.
///
/// Kin keeps one entity for an overloaded function or method, spanning its
/// implementation, and the server answers a call with the signature it
/// matched, which lies above that span inside `container`. The signature
/// belongs to the entity of its own name that starts below it, when nothing
/// else is declared between the two: every declaration at the signature's
/// own depth in between declares the same name, and no other entity starts
/// there. Anything else maps nothing.
pub(crate) fn overload_implementation<'i>(
    index: &'i EntityIndex,
    container: &EntityRef,
    text: &str,
    location: &protocol::Location,
) -> Option<&'i EntityRef> {
    let positions = crate::source_positions::SourcePositions::new(&container.file_path, text);
    let line = location.range.start.line;
    let signature = positions.line_text(line).ok()?;
    let column = positions.byte_column(&location.range.start).ok()? as usize;
    let name: String = signature
        .get(column..)?
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    if name.is_empty() || declared_callable(signature) != Some(name.as_str()) {
        return None;
    }
    let in_file = index.entities_in_file(&container.file_path);
    let implementation = in_file
        .iter()
        .filter(|entity| {
            entity.start_line > line && entity.name.rsplit(['.', ':']).next() == Some(name.as_str())
        })
        .min_by_key(|entity| entity.start_line)?;
    if implementation.start_line < container.start_line
        || implementation.end_line > container.end_line
        || in_file
            .iter()
            .any(|entity| entity.start_line > line && entity.start_line < implementation.start_line)
    {
        return None;
    }
    let depth = indentation(signature);
    for between in line..implementation.start_line {
        let text = positions.line_text(between).ok()?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        if indentation(text) < depth {
            return None;
        }
        if trimmed.starts_with(['*', '@']) || trimmed.starts_with("//") || trimmed.starts_with("/*")
        {
            continue;
        }
        if indentation(text) == depth
            && declared_callable(text).is_some_and(|declared| declared != name)
        {
            return None;
        }
    }
    let declaration = positions.line_text(implementation.name_line).ok()?;
    let spelled = declaration.match_indices(name.as_str()).any(|(at, _)| {
        let before = declaration[..at].chars().next_back();
        let after = declaration[at + name.len()..].chars().next();
        let boundary =
            |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '$');
        boundary(before) && boundary(after)
    });
    spelled.then_some(*implementation)
}

/// Text of the files a definition answer lands in, from repository
/// authority, fetched once each.
struct TargetTexts<'a> {
    provider: Option<crate::enrichment::DocumentProvider<'a>>,
    own_path: &'a str,
    own_text: &'a str,
    held: HashMap<String, Option<String>>,
}

impl<'a> TargetTexts<'a> {
    fn get(&mut self, file: &str) -> Option<&str> {
        if file == self.own_path {
            return Some(self.own_text);
        }
        let provider = self.provider;
        self.held
            .entry(file.to_owned())
            .or_insert_with(|| provider.and_then(|provider| provider(file)))
            .as_deref()
    }
}

/// What one definition location says: the declaration it proves the
/// identifier names, if it proves one, and the entity it records a reference
/// to.
struct Placed<'i> {
    target: Option<crate::call_sites::SiteTarget>,
    /// The entity and edge key a `References` edge goes to.
    reference: Option<(&'i EntityRef, &'static str)>,
    /// Whether `target` came from an overload signature.
    overload: bool,
}

/// Everything about the asked identifier that placing one of its answers
/// reads.
struct Asked<'p, 'i> {
    source: &'i EntityRef,
    positions: &'p crate::source_positions::SourcePositions<'p>,
    index: &'i EntityIndex,
    workspace_root: &'p Path,
    rel_path: &'p str,
    /// The identifier as written where it was asked.
    queried: &'p str,
}

impl<'i> Asked<'_, 'i> {
    /// Place one definition location. The reference rules are the ones this
    /// pass has always minted `References` edges by; the site target is the
    /// declaration proven, with an overload signature read as the
    /// implementation Kin keeps for it.
    fn place(
        &self,
        location: &protocol::Location,
        texts: &mut TargetTexts<'_>,
    ) -> Result<Placed<'i>> {
        let target_line = location.range.start.line;
        let target_uri = &location.uri;
        let Some(dst) = self.index.find_at(target_uri, target_line) else {
            // Outside the repository, in no file the graph holds or could
            // hold a twin of: a declaration the repository does not own.
            // Otherwise the answer names something the graph has no entity
            // for, a local, a parameter or the repository's own build output,
            // which places nothing.
            return Ok(Placed {
                target: self.index.outside_repository(target_uri).then(|| {
                    crate::call_sites::SiteTarget::Outside(crate::call_sites::OutsideLocation {
                        uri: target_uri.clone(),
                        range: crate::call_sites::LocationRange::from(&location.range),
                    })
                }),
                reference: None,
                overload: false,
            });
        };
        let mut placed = Placed {
            target: None,
            reference: None,
            overload: false,
        };
        if self.source.id == dst.id {
            // A call that names its own caller is recursion, but only when
            // the answer is the caller's name token. A parameter declared on
            // the caller's own line lands here too.
            let columns =
                self.positions
                    .byte_column(&location.range.start)
                    .ok()
                    .map(|target_col| {
                        let name_col = self
                            .positions
                            .name_column(dst)
                            .ok()
                            .flatten()
                            .unwrap_or(dst.name_col);
                        (name_col, target_col)
                    });
            placed.target = (columns.is_some()
                && crate::enrichment::answer_names_entity(dst, &location.range)
                && names_declaration_of(dst, target_line, columns))
            .then_some(crate::call_sites::SiteTarget::Entity(dst.id));
        } else if crate::enrichment::answer_names_entity(dst, &location.range) {
            // A Python answer inside an entity's body, or an empty one naming
            // a module, is not about the entity `find_at` placed it in.
            let (dst_name_col, target_col) = if self.source.file_path == dst.file_path {
                (
                    self.positions
                        .name_column(dst)
                        .ok()
                        .flatten()
                        .unwrap_or(dst.name_col),
                    self.positions.byte_column(&location.range.start)?,
                )
            } else {
                (dst.name_col, 0)
            };
            if !lands_inside_container_without_naming_it(
                self.source,
                dst,
                dst_name_col,
                self.queried,
                target_line,
                target_col,
            ) {
                // The declaration itself, not merely a line inside the
                // entity `find_at` chose: its name line, and its name token
                // wherever this file's text can show it.
                placed.target = names_declaration_of(
                    dst,
                    target_line,
                    (self.source.file_path == dst.file_path).then_some((dst_name_col, target_col)),
                )
                .then_some(crate::call_sites::SiteTarget::Entity(dst.id));
                let kind = if target_uri.contains(self.rel_path) {
                    "same_file"
                } else {
                    "cross_file"
                };
                placed.reference = Some((dst, kind));
            }
        }
        if placed.target.is_none() && Lexicon::of(&dst.file_path) == Lexicon::Script {
            if let Some(implementation) = texts
                .get(&dst.file_path)
                .and_then(|text| overload_implementation(self.index, dst, text, location))
            {
                placed.target = Some(crate::call_sites::SiteTarget::Entity(implementation.id));
                placed.overload = true;
            }
        }
        Ok(placed)
    }
}

/// One identifier the pass will ask about.
struct Planned {
    line: u32,
    col: u32,
    /// Whether it opens a call, which puts it ahead of the others.
    call: bool,
}

/// A `References` edge the pass minted, with the earliest position that
/// proved it and the order it was minted in there.
struct Minted {
    at: (u32, u32, usize),
    relation: Relation,
}

/// Record a `References` edge proved at `(line, col)`, keeping for each key
/// the edge from the earliest position that proved it. The pass used to ask
/// in source order and keep the first, so this is what it recorded then,
/// whatever order the identifiers are asked in now.
#[allow(clippy::too_many_arguments)]
fn mint(
    minted: &mut HashMap<(EntityId, EntityId, &'static str), Minted>,
    order: &mut usize,
    key: (EntityId, EntityId, &'static str),
    (line, col): (u32, u32),
    confidence: f32,
    rule: &'static str,
    site: kin_model::SourceSpan,
) {
    *order += 1;
    let at = (line, col, *order);
    if minted
        .get(&key)
        .is_some_and(|held| (held.at.0, held.at.1) <= (line, col))
    {
        return;
    }
    let (source, target, _) = key;
    minted.insert(
        key,
        Minted {
            at,
            relation: Relation {
                id: deterministic_relation_id(RelationKind::References, source, target),
                kind: RelationKind::References,
                src: GraphNodeId::Entity(source),
                dst: GraphNodeId::Entity(target),
                confidence,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                // The identifier position this pass ASKED about, which is the
                // reference site in the source file: for `adapter.send(...)`
                // inside `Session.send` that is the call line itself. The
                // position is already in hand, so this costs no extra round
                // trip.
                evidence: crate::enrichment::query_position_evidence(rule, site),
            },
        },
    );
}

/// Which of a file's identifiers and callers one file pass asks about.
///
/// The sweep asks about all of them. A pass after an edit asks about the
/// declarations the edit re-derived whole, every identifier inside them and
/// their call hierarchy, and, for other callers whose settlement the edit
/// undid, the callee tokens of those calls and the callers' call hierarchy.
/// Every question it does ask is asked exactly as the sweep asks it, so what
/// a site's answers prove does not depend on the scope they were asked in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileScope {
    /// The callers asked whole. `None` asks every entity in the file.
    callers: Option<HashSet<EntityId>>,
    /// Further identifiers asked for their definition, by the byte offset
    /// their token starts at in the file.
    call_tokens: BTreeSet<usize>,
    /// The callers of `call_tokens`, whose call hierarchy is asked too.
    hierarchy: HashSet<EntityId>,
}

impl FileScope {
    /// Every identifier and every caller in the file, as the sweep asks.
    pub fn whole_file() -> Self {
        Self::default()
    }

    /// `callers` whole, and each of `calls`: the callee token starting at
    /// that byte, and its caller's call hierarchy.
    pub fn callers(
        callers: impl IntoIterator<Item = EntityId>,
        calls: impl IntoIterator<Item = (EntityId, usize)>,
    ) -> Self {
        let mut scope = Self {
            callers: Some(callers.into_iter().collect()),
            ..Self::default()
        };
        for (caller, token) in calls {
            scope.call_tokens.insert(token);
            scope.hierarchy.insert(caller);
        }
        scope
    }

    /// Whether this scope asks about the whole file.
    pub fn is_whole_file(&self) -> bool {
        self.callers.is_none()
    }

    /// Whether `caller` is asked whole: its identifiers and its call
    /// hierarchy.
    pub fn holds_caller(&self, caller: EntityId) -> bool {
        self.callers
            .as_ref()
            .is_none_or(|callers| callers.contains(&caller))
    }

    /// Whether `caller`'s call hierarchy is asked.
    pub fn asks_hierarchy(&self, caller: EntityId) -> bool {
        self.holds_caller(caller) || self.hierarchy.contains(&caller)
    }

    /// Whether the identifier inside `source` whose token starts at the byte
    /// `start` gives is asked. `start` is read only when `source` is not
    /// asked whole.
    fn asks(&self, source: EntityId, start: impl FnOnce() -> Option<usize>) -> bool {
        self.holds_caller(source) || start().is_some_and(|start| self.call_tokens.contains(&start))
    }
}

/// The counts a file pass reports about the definition queries it asked.
#[derive(Default)]
struct QueryCounts {
    asked: usize,
    saved: usize,
    call_sites: usize,
    /// Second asks at a call site's binding, whether or not they proved it.
    hops_asked: usize,
    hops: usize,
    /// Hops that landed on a slot a value flows into, and so proved nothing.
    hop_slots: usize,
    overloads: usize,
    /// Receiver types asked at TypeScript member calls, and the calls whose
    /// receiver may be a union and so prove no single declaration.
    receiver_types_asked: usize,
    union_receivers: usize,
}

/// Enrich a file by asking `textDocument/definition` at its identifiers.
///
/// Every identifier inside an entity's lines is asked, except one whose
/// answer can name no declaration: a keyword, and in Python a comment or the
/// inside of a docstring. Identifiers that open a call are asked first, so a
/// pass that has to stop early still holds the proofs of its calls, and a
/// reference edge records the earliest site that proved it whatever order
/// the identifiers were asked in. Each answer that lands on a graph entity
/// becomes a `References` edge, and each definite answer a
/// [`crate::call_sites::SiteAnswer`]. At a call site whose answer is a
/// binding that names no entity, such as a destructured or imported name,
/// the definition of that binding is asked once more.
pub async fn enrich_file_definitions(
    server: &LspServer,
    file_path: &Path,
    file_content: &str,
    entity_index: &EntityIndex,
    workspace_root: &Path,
    documents: Option<crate::enrichment::DocumentProvider<'_>>,
) -> Result<FileEnrichmentResult> {
    enrich_file_definitions_in(
        server,
        file_path,
        file_content,
        entity_index,
        workspace_root,
        documents,
        &FileScope::whole_file(),
    )
    .await
}

/// [`enrich_file_definitions`] over the identifiers and callers `scope`
/// holds. Each identifier asked is asked as the whole-file pass asks it, and
/// `call_hierarchy_complete` speaks for the callers `scope` holds whole.
pub async fn enrich_file_definitions_in(
    server: &LspServer,
    file_path: &Path,
    file_content: &str,
    entity_index: &EntityIndex,
    workspace_root: &Path,
    documents: Option<crate::enrichment::DocumentProvider<'_>>,
    scope: &FileScope,
) -> Result<FileEnrichmentResult> {
    let uri = protocol::path_to_uri(file_path);
    let rel_path = file_path
        .strip_prefix(workspace_root)
        .unwrap_or(file_path)
        .to_string_lossy()
        .to_string();

    let positions = crate::source_positions::SourcePositions::new(&rel_path, file_content);
    let lexicon = Lexicon::of(&rel_path);
    let non_code = if lexicon == Lexicon::Python {
        python_non_code(file_content)
    } else {
        Vec::new()
    };

    let mut minted = HashMap::new();
    let mut order = 0usize;
    let mut hierarchy_relations = Vec::new();
    let mut definitions_resolved = 0usize;
    let mut positions_queried = 0usize;
    let mut site_answers = Vec::new();
    let mut unproven_sites: Vec<crate::call_sites::UnprovenSite> = Vec::new();
    let mut refusals = Refusals::default();
    let mut counts = QueryCounts::default();
    let mut scoped_documents = crate::enrichment::ScopedDocuments::new(server, documents);
    scoped_documents.remember(&rel_path, file_content);
    let mut texts = TargetTexts {
        provider: documents,
        own_path: &rel_path,
        own_text: file_content,
        held: HashMap::new(),
    };

    // A server that stops answering inside this pass ends it with what was
    // already proven rather than with nothing. The budget around the pass
    // abandons a pass that runs over it, and an abandoned pass keeps no
    // relation at all, so waiting out every remaining identifier on a slow
    // server throws away the ones that did answer. One slow answer skips its
    // identifier; several in a row stop the pass.
    let mut timed_out = false;

    let result = async {
        // Unsupported definition queries contribute no positions; independent
        // call hierarchy support still runs below.
        if server.has_definition() {
            let lines: Vec<&str> = file_content.lines().collect();
            let mut plan = Vec::new();
            for (line_num, line_text) in lines.iter().enumerate() {
                let line = line_num as u32;
                let identifiers = identifier_positions_in_line(line_text);
                positions_queried += identifiers.len();
                // The relation source depends only on the line (never the
                // column), and every relation emitted below requires it to be
                // Some. Lines outside any known entity span can therefore
                // never contribute a relation, so their identifiers are not
                // asked about.
                let Some(source) = entity_index.find_at(&uri, line) else {
                    continue;
                };
                let skipped = non_code.get(line_num).map_or(&[][..], Vec::as_slice);
                for col in identifiers {
                    if names_nothing(lexicon, line_text, col, skipped) {
                        counts.saved += 1;
                        continue;
                    }
                    if !scope.asks(source.id, || {
                        positions.token(line, col).ok().map(|token| token.start_byte)
                    }) {
                        continue;
                    }
                    plan.push(Planned {
                        line,
                        col,
                        call: opens_a_call(line_text, col),
                    });
                }
            }
            plan.sort_by_key(|planned| (!planned.call, planned.line, planned.col));
            counts.call_sites = plan.iter().filter(|planned| planned.call).count();

            'plan: for planned in &plan {
                let (line, col) = (planned.line, planned.col);
                let line_text = lines[line as usize];
                let Some(source) = entity_index.find_at(&uri, line) else {
                    continue;
                };
                let queried = identifier_at(line_text, col);
                let asked_at = positions.scalar_position(line, col)?;

                // A member expression on a MODULE receiver is answered by its
                // member. Asked at the receiver, the server returns the
                // module, and `find_at` turns that into whichever entity holds
                // the line, so every file that names `express` was recorded as
                // referencing express's default export: 50 inbound edges on
                // `createApplication` against 32 real reference sites on
                // `Router`, which had none.
                //
                // Value receivers keep their edges. `res` in `res.send(...)`
                // resolves to its own parameter in this file and says
                // something true about the enclosing function. The two are
                // told apart by where the server puts the receiver's
                // definition, which is the server answering rather than this
                // code guessing. A value receiver's answer is also its answer
                // as an identifier, so it is not asked a second time.
                let mut receiver_answer = None;
                if let Some((_receiver, member_col, member_name)) =
                    crate::enrichment::member_expression_at(line_text, col)
                {
                    counts.asked += 1;
                    let receiver_definitions = match crate::enrichment::locations_at(
                        server,
                        "textDocument/definition",
                        &uri,
                        line,
                        asked_at.character,
                    )
                    .await
                    {
                        Ok(locations) => {
                            refusals.answered();
                            locations
                        }
                        Err(error) => {
                            record_unproven(
                                &mut unproven_sites,
                                &positions,
                                source.id,
                                (line, col),
                                &error,
                            );
                            match refusals.refused(source.id, "a receiver's definition", error) {
                                AfterRefusal::Skip => continue,
                                AfterRefusal::Stop => {
                                    timed_out = true;
                                    break 'plan;
                                }
                                AfterRefusal::End(error) => return Err(error),
                            }
                        }
                    };
                    if crate::enrichment::receiver_names_a_module(
                        &receiver_definitions,
                        entity_index,
                        &rel_path,
                    ) {
                        // An imported value (`current_app` in
                        // `current_app.config`) also answers from another
                        // file, at its own declaration. That answer is the
                        // reference, minted here from the answer just proven
                        // rather than from a second request, and the member is
                        // left to its own turn of this loop.
                        if let Some(values) = crate::enrichment::receiver_declared_values(
                            &receiver_definitions,
                            entity_index,
                            &queried,
                        ) {
                            for value in values {
                                if source.id == value.id {
                                    continue;
                                }
                                definitions_resolved += 1;
                                mint(
                                    &mut minted,
                                    &mut order,
                                    (source.id, value.id, "cross_file"),
                                    (line, col),
                                    0.95,
                                    crate::call_sites::DEFINITION_RULE,
                                    positions.token(line, col)?,
                                );
                            }
                            continue;
                        }
                        // Declining alone was not enough, and assuming
                        // otherwise is what left a named export unreferenced.
                        // On express the member answers `node_modules/router`,
                        // outside the ingested tree, so no edge is minted from
                        // its own turn. The same equivalence join the UsesType
                        // arm uses supplies the right edge: two independently
                        // proven server answers naming the same place, never a
                        // name match.
                        let bindings = match crate::enrichment::member_export_bindings(
                            server,
                            entity_index,
                            workspace_root,
                            &mut scoped_documents,
                            &rel_path,
                            &uri,
                            line,
                            asked_at.character,
                            positions.scalar_position(line, member_col)?.character,
                            &member_name,
                        )
                        .await
                        {
                            Ok(bindings) => {
                                refusals.answered();
                                // A candidate whose declaration line does not
                                // spell its name cannot be asked about, and
                                // never will be from the same bytes.
                                for _ in 0..bindings.unasked {
                                    refusals.refuse(
                                        source.id,
                                        format!(
                                            "a member's export binding could not locate a candidate declaration of `{member_name}`"
                                        ),
                                    );
                                }
                                bindings.bound
                            }
                            Err(error) => {
                                match refusals.refused(source.id, "a member's export binding", error) {
                                    AfterRefusal::Skip => continue,
                                    AfterRefusal::Stop => {
                                        timed_out = true;
                                        break 'plan;
                                    }
                                    AfterRefusal::End(error) => return Err(error),
                                }
                            }
                        };
                        for candidate in bindings {
                            if source.id == candidate.id {
                                continue;
                            }
                            definitions_resolved += 1;
                            mint(
                                &mut minted,
                                &mut order,
                                (source.id, candidate.id, "member_on_module"),
                                (line, col),
                                0.85,
                                "lsp_member_on_module",
                                positions.token(line, member_col)?,
                            );
                            tracing::debug!(
                                entity = %source.name,
                                member = %member_name,
                                references = %candidate.name,
                                "bound a member on a module receiver to its export"
                            );
                        }
                        // The receiver's own resolution is still not this
                        // entity's fact, whether or not the member bound to
                        // anything.
                        continue;
                    }
                    receiver_answer = Some(receiver_definitions);
                }

                let locations = match receiver_answer {
                    Some(locations) => {
                        counts.saved += 1;
                        locations
                    }
                    None => {
                        counts.asked += 1;
                        let def_result = tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            server.client.request(
                                "textDocument/definition",
                                protocol::TextDocumentPositionParams {
                                    text_document: protocol::TextDocumentIdentifier {
                                        uri: uri.clone(),
                                    },
                                    position: asked_at.clone(),
                                },
                            ),
                        )
                        .await;
                        // The pass's own two-second bound is a timeout like
                        // the client's, and both go through the one
                        // classification.
                        let value = match def_result.unwrap_or(Err(LspError::Timeout)) {
                            Ok(value) => {
                                refusals.answered();
                                value
                            }
                            Err(error) => {
                                record_unproven(
                                    &mut unproven_sites,
                                    &positions,
                                    source.id,
                                    (line, col),
                                    &error,
                                );
                                match refusals.refused(source.id, "a definition", error) {
                                    AfterRefusal::Skip => continue,
                                    AfterRefusal::Stop => {
                                        timed_out = true;
                                        break 'plan;
                                    }
                                    AfterRefusal::End(error) => return Err(error),
                                }
                            }
                        };
                        crate::enrichment::decode_locations(value)?
                    }
                };

                // What the answer as a whole says about this identifier. Each
                // location votes, and only a unanimous, placeable answer
                // becomes a site answer.
                let asked = Asked {
                    source,
                    positions: &positions,
                    index: entity_index,
                    workspace_root,
                    rel_path: &rel_path,
                    queried: &queried,
                };
                let mut verdict = DefinitionVerdict::default();
                let mut overload = false;
                let mut placed_any = false;
                for location in &locations {
                    let placed = asked.place(location, &mut texts)?;
                    placed_any |= placed.target.is_some();
                    verdict.observe(placed.target);
                    overload |= placed.overload;
                    if let Some((dst, kind)) = placed.reference {
                        definitions_resolved += 1;
                        mint(
                            &mut minted,
                            &mut order,
                            (source.id, dst.id, kind),
                            (line, col),
                            0.95,
                            crate::call_sites::DEFINITION_RULE,
                            positions.token(line, col)?,
                        );
                    }
                }
                let mut decided = verdict.decided().map(|target| (target, crate::call_sites::DEFINITION_RULE));
                let hop_slots_before = counts.hop_slots;
                let mut union_receiver = false;
                if decided.is_none() && planned.call {
                    decided = alias_hop(
                        server,
                        &asked,
                        &locations,
                        (&uri, &asked_at),
                        &mut scoped_documents,
                        &mut texts,
                        &mut counts,
                    )
                    .await?
                    .map(|target| (target, crate::call_sites::DEFINITION_ALIAS_RULE));
                } else if decided.is_some() && overload {
                    counts.overloads += 1;
                }
                // TypeScript answers a call with the declaration of the
                // signature the call resolved to. Through a receiver whose
                // type is a union of classes that is one constituent's
                // method, chosen by the order the checker created the types
                // in, and the call may run any of them: typeorm's
                // `(driver as AbstractSqliteDriver | ReactNativeDriver)
                // .wrapWithJsonFunction(..)` answered with one class's method
                // in one session and the other's in the next. Such a call
                // proves no single declaration.
                if planned.call
                    && lexicon == Lexicon::Script
                    && decided.as_ref().is_some_and(|(targets, _)| {
                        matches!(targets.first(), Some(crate::call_sites::SiteTarget::Entity(_)))
                    })
                    && receiver_may_be_a_union(server, &uri, &positions, &lines, (line, col), &mut counts)
                        .await?
                {
                    counts.union_receivers += 1;
                    union_receiver = true;
                    decided = None;
                }
                if decided.is_none() {
                    // What the question came to, for the call site's state.
                    use crate::call_sites::UnprovenAnswer;
                    let answer = if locations.is_empty() {
                        UnprovenAnswer::NoAnswer
                    } else if union_receiver || placed_any {
                        UnprovenAnswer::AnswersDisagree
                    } else if counts.hop_slots > hop_slots_before
                        || locations.iter().all(|location| {
                            // A local or a parameter: a value the caller
                            // binds in its own body or signature.
                            protocol::same_file_uri(&location.uri, &uri)
                                && (source.start_line..=source.end_line)
                                    .contains(&location.range.start.line)
                        })
                    {
                        UnprovenAnswer::Binding
                    } else {
                        // A declaration inside the repository the graph holds
                        // no entity for: build output, a generated or local
                        // declaration elsewhere, or an import binding the
                        // alias hop could not follow.
                        UnprovenAnswer::OutsideTheGraph
                    };
                    if let Ok(site) = positions.token(line, col) {
                        unproven_sites.push(crate::call_sites::UnprovenSite {
                            source: source.id,
                            start_byte: site.start_byte,
                            end_byte: site.end_byte,
                            answer,
                        });
                    }
                }
                if let Some((targets, rule)) = decided {
                    if let Ok(site) = positions.token(line, col) {
                        // Every place an outside answer landed is its own
                        // answer at the site: they agree the call leaves the
                        // repository, and the settlement asks whether they
                        // name one symbol.
                        for target in targets {
                            site_answers.push(crate::call_sites::SiteAnswer {
                                source: source.id,
                                site: site.clone(),
                                target,
                                rule,
                            });
                        }
                    }
                }
            }
        }

        // Add entity-level call hierarchy for every entity in this file. The
        // daemon already performs a per-entity pass, so we keep the relation IDs
        // deterministic to make repeated discovery idempotent.
        //
        // One entity's call hierarchy that fails, or whose answer cannot be
        // proven, is that entity's failure and not the file's. It used to end
        // the pass with `?`, which threw away every definition relation the
        // loop above had already proven. On Flask 67 of 83 files lost their
        // definitions pass that way: a decorated method or the module surface
        // was asked at a column its own line does not have, and the file's
        // imports, calls and references went with it. The failure is counted,
        // so the file is still not recorded as enriched.
        let mut call_hierarchy_complete = !timed_out;
        if server.has_call_hierarchy() && !timed_out {
            refusals.answered();
            for entity in entity_index
                .entities_in_file(&rel_path)
                .into_iter()
                .filter(|entity| scope.asks_hierarchy(entity.id))
            {
                match enrich_entity_calls(
                    server,
                    entity,
                    entity_index,
                    workspace_root,
                    Some(&|file| {
                        if file == rel_path {
                            Some(file_content.to_owned())
                        } else {
                            documents.and_then(|provider| provider(file))
                        }
                    }),
                )
                .await
                {
                    Ok(calls) => {
                        refusals.answered();
                        if calls.unproven_calls > 0 {
                            refusals.unproven_calls(
                                entity.id,
                                &format!("the call hierarchy of {}", entity.name),
                                calls.unproven_calls,
                            );
                        }
                        hierarchy_relations.extend(calls.relations);
                        // A call the server resolved outside the repository
                        // refutes the in-repository guesses at its range.
                        site_answers.extend(calls.outside_sites);
                    }
                    // One declaration's call hierarchy is that declaration's,
                    // not the file's: a decline is skipped, a failure is
                    // counted and the file's other relations stand, several
                    // timeouts in a row stop asking and keep what was proven,
                    // and only a server that can answer nothing ends the pass.
                    Err(error) => {
                        // A refusal or a decline settles this entity; anything
                        // else leaves its calls unasked.
                        if !(error.is_declined() || error.is_refusal()) {
                            call_hierarchy_complete = false;
                        }
                        match refusals.refused(
                            entity.id,
                            &format!("the call hierarchy of {}", entity.name),
                            error,
                        ) {
                            AfterRefusal::Skip => {}
                            AfterRefusal::Stop => {
                                call_hierarchy_complete = false;
                                break;
                            }
                            AfterRefusal::End(error) => return Err(error),
                        }
                    }
                }
            }
        }

        let mut references: Vec<Minted> = std::mem::take(&mut minted).into_values().collect();
        references.sort_by_key(|reference| reference.at);
        let mut relations: Vec<Relation> =
            references.into_iter().map(|reference| reference.relation).collect();
        relations.append(&mut hierarchy_relations);
        site_answers.sort_by_key(|answer: &crate::call_sites::SiteAnswer| {
            (answer.site.start_byte, answer.site.end_byte, answer.rule)
        });
        let outside: Vec<crate::call_sites::OutsideLocation> = site_answers
            .iter()
            .filter_map(|answer| match &answer.target {
                crate::call_sites::SiteTarget::Outside(location) => Some(location.clone()),
                crate::call_sites::SiteTarget::Entity(_) => None,
            })
            .collect();
        let external_names = server.external_symbols().name_all(server, &outside).await;
        tracing::debug!(
            file = %rel_path,
            positions = positions_queried,
            definition_queries = counts.asked,
            definition_queries_saved = counts.saved,
            call_sites = counts.call_sites,
            alias_hops_asked = counts.hops_asked,
            alias_hops = counts.hops,
            alias_hop_slots = counts.hop_slots,
            overload_answers = counts.overloads,
            receiver_types_asked = counts.receiver_types_asked,
            union_receivers = counts.union_receivers,
            site_answers = site_answers.len(),
            "file definitions pass"
        );
        Ok(FileEnrichmentResult {
            relations,
            definitions_resolved,
            positions_queried,
            failed_queries: refusals.failed,
            refused_queries: refusals.refused,
            unprovable: std::mem::take(&mut refusals.unprovable),
            call_hierarchy_complete,
            declined_queries: refusals.declined,
            first_failure: refusals.first_failure.take(),
            unproven_calls: refusals.unproven_calls,
            site_answers: std::mem::take(&mut site_answers),
            external_names,
            definition_queries: counts.asked,
            definition_queries_saved: counts.saved,
            call_site_queries: counts.call_sites,
            alias_hops: counts.hops,
            overload_answers: counts.overloads,
            unproven_sites: std::mem::take(&mut unproven_sites),
            stopped_early: timed_out,
        })
    }
    .await;
    let closed = scoped_documents.close_all().await;
    match result {
        Ok(answer) => {
            closed?;
            Ok(answer)
        }
        Err(error) => Err(error),
    }
}

/// The receiver of the member call whose callee starts at `(line, col)`: the
/// line it ends on and that line's text up to its end, with the member
/// access and any non-null assertion taken off. `None` when the callee is not
/// reached through a member access. A chain broken across lines
/// (`builder\n    .where(..)`) ends its receiver on the line before.
fn receiver_before(lines: &[&str], (line, col): (u32, u32)) -> Option<(u32, String)> {
    let text: String = lines
        .get(line as usize)?
        .chars()
        .take(col as usize)
        .collect();
    let before = text.trim_end();
    let before = before
        .strip_suffix("?.")
        .or_else(|| before.strip_suffix('.'))?
        .trim_end();
    let (line, before) = if before.is_empty() {
        let previous = line.checked_sub(1)?;
        (
            previous,
            lines.get(previous as usize)?.trim_end().to_owned(),
        )
    } else {
        (line, before.to_owned())
    };
    let before = before
        .strip_suffix('!')
        .unwrap_or(&before)
        .trim_end()
        .to_owned();
    (!before.is_empty()).then_some((line, before))
}

/// Whether a receiver that ends with `)` on `line` is a parenthesized `as`
/// cast to a union: `(driver as AbstractSqliteDriver | ReactNativeDriver)`.
/// A call's argument list, `make(x as A | B)`, is not one.
fn casts_to_a_union(lines: &[&str], line: u32, receiver: &str) -> bool {
    let mut written: Vec<char> = Vec::new();
    for previous in line.saturating_sub(20)..line {
        if let Some(text) = lines.get(previous as usize) {
            written.extend(text.chars());
            written.push('\n');
        }
    }
    written.extend(receiver.chars());
    let mut depth = 0usize;
    for at in (0..written.len()).rev() {
        match written[at] {
            ')' => depth += 1,
            '(' => {
                depth = depth.saturating_sub(1);
                if depth > 0 {
                    continue;
                }
                // What precedes the group: a name, a generic argument list, a
                // call or an index calls it, unless the name is a keyword.
                let before: Vec<char> = written[..at]
                    .iter()
                    .rev()
                    .skip_while(|c| c.is_whitespace())
                    .copied()
                    .collect();
                let word: String = before
                    .iter()
                    .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '$'))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let called = if word.is_empty() {
                    before.first().is_some_and(|c| matches!(c, '>' | ')' | ']'))
                } else {
                    !matches!(
                        word.as_str(),
                        "return"
                            | "await"
                            | "yield"
                            | "typeof"
                            | "void"
                            | "case"
                            | "in"
                            | "of"
                            | "else"
                            | "do"
                            | "throw"
                            | "delete"
                    )
                };
                let group: String = written[at + 1..].iter().collect();
                return !called
                    && group.split_whitespace().any(|word| word == "as")
                    && group.contains('|');
            }
            _ => {}
        }
    }
    false
}

/// Whether the receiver of the TypeScript member call whose callee starts at
/// `(line, col)` may have a union type, so the call may run another
/// constituent's method than the one its definition answer names.
///
/// A receiver written as an identifier is asked `textDocument/typeDefinition`,
/// which the TypeScript server answers with the declaration of each object
/// type in a union, and a primitive in it with none. Two declarations or
/// more may be a union, and so may an answer that could not be had. A
/// parenthesized receiver is a union when it casts to one. A receiver of any
/// other shape, such as a call's result, is taken as the answer names it.
async fn receiver_may_be_a_union(
    server: &LspServer,
    uri: &str,
    positions: &crate::source_positions::SourcePositions<'_>,
    lines: &[&str],
    (line, col): (u32, u32),
    counts: &mut QueryCounts,
) -> Result<bool> {
    let Some((receiver_line, receiver)) = receiver_before(lines, (line, col)) else {
        return Ok(false);
    };
    let chars: Vec<char> = receiver.chars().collect();
    let identifier = |c: &char| c.is_alphanumeric() || *c == '_' || *c == '$';
    match chars.last() {
        Some(')') => return Ok(casts_to_a_union(lines, receiver_line, &receiver)),
        Some(last) if identifier(last) => {}
        _ => return Ok(false),
    }
    if !server.has_type_definition() {
        return Ok(true);
    }
    let start = chars
        .iter()
        .rposition(|c| !identifier(c))
        .map_or(0, |at| at + 1);
    let position = positions.scalar_position(receiver_line, start as u32)?;
    counts.receiver_types_asked += 1;
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        crate::enrichment::locations_at(
            server,
            "textDocument/typeDefinition",
            uri,
            receiver_line,
            position.character,
        ),
    )
    .await
    .unwrap_or(Err(LspError::Timeout));
    match answer {
        Ok(types) => Ok(types
            .iter()
            .map(|location| (location.uri.as_str(), location.range.start.line))
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            >= 2),
        Err(error) if error.ends_the_session() => Err(error),
        Err(_) => Ok(true),
    }
}

/// What a call site's callee names when its definition answer is a binding
/// the graph holds no entity for.
///
/// `const { reject } = make()` binds `reject` locally, and so does an import
/// the server does not follow: the answer is that binding, which names
/// nothing. Asked once more, at the binding, the server answers where the
/// binding takes its value from. A definite second answer is the proof; one
/// that is the binding again, as a plain local or a parameter answers,
/// proves nothing. Only a single answer inside the workspace is followed,
/// never one hop further, and a second ask that fails ends nothing but the
/// hop.
async fn alias_hop(
    server: &LspServer,
    asked: &Asked<'_, '_>,
    locations: &[protocol::Location],
    (uri, asked_at): (&str, &protocol::Position),
    documents: &mut crate::enrichment::ScopedDocuments<'_>,
    texts: &mut TargetTexts<'_>,
    counts: &mut QueryCounts,
) -> Result<Option<Vec<crate::call_sites::SiteTarget>>> {
    let [binding] = locations else {
        return Ok(None);
    };
    if asked.index.outside_repository(&binding.uri)
        || (protocol::same_file_uri(&binding.uri, uri)
            && (binding.range.start.line, binding.range.start.character)
                == (asked_at.line, asked_at.character))
    {
        return Ok(None);
    }
    // The file the graph holds there, through a workspace package's link
    // when the server named it that way, else the path below the root.
    let Some(file) = asked.index.held_file(&binding.uri).or_else(|| {
        protocol::uri_to_path(&binding.uri)
            .and_then(|path| {
                path.strip_prefix(asked.workspace_root)
                    .ok()
                    .map(Path::to_path_buf)
            })
            .and_then(|relative| relative.to_str().map(|file| file.replace('\\', "/")))
    }) else {
        return Ok(None);
    };
    let binding_uri = protocol::path_to_uri(&asked.workspace_root.join(&file));
    if file != asked.rel_path && !documents.ensure_open(&file, &binding_uri).await? {
        return Ok(None);
    }
    counts.asked += 1;
    counts.hops_asked += 1;
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        crate::enrichment::locations_at(
            server,
            "textDocument/definition",
            &binding_uri,
            binding.range.start.line,
            binding.range.start.character,
        ),
    )
    .await
    .unwrap_or(Err(LspError::Timeout));
    let second = match answer {
        Ok(second) => second,
        Err(error) if error.ends_the_session() => return Err(error),
        Err(error) => {
            tracing::debug!(%error, "a call site's alias hop got no answer; the site stays unproven");
            return Ok(None);
        }
    };
    let mut verdict = DefinitionVerdict::default();
    for location in &second {
        let target = match asked.place(location, texts) {
            // A slot is not what the call runs: it proves nothing and so
            // refutes nothing (see `declares_value_slot`).
            Ok(placed)
                if matches!(
                    placed.target,
                    Some(crate::call_sites::SiteTarget::Entity(_))
                ) && !placed.overload
                    && asked
                        .index
                        .find_at(&location.uri, location.range.start.line)
                        .is_some_and(|dst| {
                            declares_value_slot(asked.index, dst, texts.get(&dst.file_path))
                        }) =>
            {
                counts.hop_slots += 1;
                None
            }
            Ok(placed) => placed.target,
            Err(_) => None,
        };
        verdict.observe(target);
    }
    let decided = verdict.decided();
    if decided.is_some() {
        counts.hops += 1;
    }
    Ok(decided)
}

/// Whether the declaration an alias hop landed on is a slot a value flows
/// into rather than a body that runs.
///
/// `const { prepareTyping } = config; prepareTyping(chunk.encoder)` binds a
/// property, and the hop lands on its declaration in `BuildQueryConfig`. What
/// the call runs is whichever implementation was stored there, `PgDialect`'s
/// or `GelDialect`'s, so the declaration is no callee, and a proof of it would
/// contradict the guesses that name what actually runs. Slots are:
///
/// - an interface, a type alias or a trait, and any member of one;
/// - a property, field or variable, unless its initializer is a function:
///   an arrow, a function expression, a lambda or a closure;
/// - an abstract method, which has no body.
///
/// A function, a class, a method with a body, and anything whose declaration
/// this cannot read are not slots, and keep the proof they had.
fn declares_value_slot(index: &EntityIndex, dst: &EntityRef, text: Option<&str>) -> bool {
    use kin_model::EntityKind;
    let declaration = || text.and_then(|text| declaration_after_name(dst, text));
    match dst.kind {
        EntityKind::Interface | EntityKind::TypeAlias | EntityKind::TraitDef => true,
        _ if member_of_a_type(index, dst) => true,
        EntityKind::Field | EntityKind::Constant | EntityKind::StaticVar => !declaration()
            .is_some_and(|(_, after)| initializer(&after).is_some_and(initializer_is_function)),
        EntityKind::Method => declaration().is_some_and(|(before, after)| {
            let after = after
                .trim_start()
                .trim_start_matches(['?', '!'])
                .trim_start();
            if after.starts_with('(') || after.starts_with('<') {
                // A signature. It has a body unless it is declared abstract.
                before.split_whitespace().any(|word| word == "abstract")
            } else {
                !initializer(after).is_some_and(initializer_is_function)
            }
        }),
        _ => false,
    }
}

/// Whether the innermost entity holding `dst` declares a type rather than a
/// body: an interface, a type alias or a trait.
fn member_of_a_type(index: &EntityIndex, dst: &EntityRef) -> bool {
    use kin_model::EntityKind;
    index
        .entities_in_file(&dst.file_path)
        .into_iter()
        .filter(|held| {
            held.id != dst.id
                && held.start_line <= dst.start_line
                && held.end_line >= dst.end_line
                && (held.start_line, held.end_line) != (dst.start_line, dst.end_line)
        })
        .min_by_key(|held| held.end_line - held.start_line)
        .is_some_and(|holder| {
            matches!(
                holder.kind,
                EntityKind::Interface | EntityKind::TypeAlias | EntityKind::TraitDef
            )
        })
}

/// What `dst`'s declaration line holds before its name, and what follows the
/// name to the end of its declaration, as the graph's text spells them.
fn declaration_after_name(dst: &EntityRef, text: &str) -> Option<(String, String)> {
    let name = dst
        .name
        .rsplit(['.', ':'])
        .next()
        .filter(|name| !name.is_empty())?;
    let lines: Vec<&str> = text
        .lines()
        .skip(dst.name_line as usize)
        .take((dst.end_line.saturating_sub(dst.name_line) as usize + 1).min(40))
        .collect();
    let line = lines.first()?;
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '$');
    let at = line
        .match_indices(name)
        .map(|(at, _)| at)
        .filter(|&at| {
            !word(line[..at].chars().next_back()) && !word(line[at + name.len()..].chars().next())
        })
        .min_by_key(|&at| at.abs_diff(dst.name_col as usize))?;
    let mut after = line[at + name.len()..].to_string();
    for more in &lines[1..] {
        after.push('\n');
        after.push_str(more);
    }
    Some((line[..at].to_string(), after))
}

/// The initializer a declaration's text after its name assigns, if any: what
/// follows its top-level `=`, past a type annotation.
fn initializer(after: &str) -> Option<&str> {
    let mut depth = 0i32;
    let bytes = after.as_bytes();
    for (at, &byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth == 0 => return None,
            b'=' if depth == 0 => {
                let next = bytes.get(at + 1).copied();
                let previous = at.checked_sub(1).map(|before| bytes[before]);
                if next != Some(b'>')
                    && next != Some(b'=')
                    && !matches!(previous, Some(b'=' | b'!' | b'<' | b'>'))
                {
                    return Some(&after[at + 1..]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether an initializer is a function: an arrow function, a function
/// expression, a Python lambda or a Rust closure.
fn initializer_is_function(initializer: &str) -> bool {
    let text = initializer.trim_start();
    let text = text
        .strip_prefix("async")
        .filter(|rest| rest.starts_with(|c: char| c.is_whitespace() || c == '('))
        .map_or(text, str::trim_start);
    let text = text
        .strip_prefix("move")
        .filter(|rest| rest.trim_start().starts_with('|'))
        .map_or(text, str::trim_start);
    let keyword = |word: &str| {
        text.strip_prefix(word)
            .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
    };
    if keyword("function") || keyword("lambda") || text.starts_with('|') {
        return true;
    }
    // `<T>(x: T) => x`, `(x) => x`, `(x): T => x` and `x => x`.
    let arrow_after = |rest: &str| {
        let rest = rest.trim_start();
        rest.starts_with("=>")
            || (rest.starts_with(':')
                && rest.lines().next().is_some_and(|line| line.contains("=>")))
    };
    if text.starts_with('<') || text.starts_with('(') {
        let open = if text.starts_with('<') {
            text.find('(')
        } else {
            Some(0)
        };
        let Some(open) = open else {
            return false;
        };
        let mut depth = 0i32;
        for (at, c) in text[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return arrow_after(&text[open + at + 1..]);
                    }
                }
                _ => {}
            }
        }
        return false;
    }
    let identifier = text
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        .unwrap_or(text.len());
    identifier > 0 && text[identifier..].trim_start().starts_with("=>")
}

#[cfg(test)]
mod tests {
    use super::identifier_positions_in_line;
    use crate::enrichment::{EntityIndex, EntityRef};
    use kin_model::EntityId;

    /// The source-line gate in `enrich_file_definitions` skips a line's LSP
    /// round-trips iff `entity_index.find_at(uri, line)` is None. This proves
    /// the gate fires only on lines outside every entity span — exactly the
    /// lines on which the source half of `(source, target)` is None and so no
    /// relation could ever be emitted. That makes the skip output-identical.
    #[test]
    fn source_line_gate_skips_only_lines_outside_entity_spans() {
        let uri = "file:///project/src/lib.rs";
        let entities = vec![
            EntityRef {
                id: EntityId::new(),
                name: "alpha".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 0,
                start_col: 0,
                end_line: 5,
                name_line: 0,
                name_col: 3,
                declares_name: true,
                kind: kin_model::EntityKind::Function,
            },
            EntityRef {
                id: EntityId::new(),
                name: "beta".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 20,
                start_col: 0,
                end_line: 25,
                name_line: 20,
                name_col: 3,
                declares_name: true,
                kind: kin_model::EntityKind::Function,
            },
        ];
        let index = EntityIndex::new(entities, std::path::Path::new("/project"));

        // Inside an entity span → queried (find_at is Some).
        for line in [0u32, 3, 5, 20, 25] {
            assert!(
                index.find_at(uri, line).is_some(),
                "line {line} is inside an entity span and must be queried"
            );
        }
        // Outside any span (imports, blank lines, inter-entity gap, tail) →
        // gated out (find_at is None). These can never produce a relation.
        for line in [6u32, 12, 19, 26, 9_999] {
            assert!(
                index.find_at(uri, line).is_none(),
                "line {line} is outside every entity span and is safe to skip"
            );
        }
    }

    /// A class's own members are not references to the class.
    ///
    /// `textDocument/definition` answers with a POSITION, and this pass matches
    /// a position to an entity by line alone. A generic class declares its type
    /// parameters on the same line as its name, so every member of
    /// `SmartRouter<T>` that writes `T` resolved to line 3; and `this` resolves
    /// to the class's own name token, so the first `this` in every method body
    /// resolved there too. Both were recorded as referencing `SmartRouter`: six
    /// of the eleven rows `find_references` returned for it were its own
    /// members, and the TypeScript compiler counts none of them.
    ///
    /// The columns below are read out of the source text rather than written
    /// down, so the test pins the geometry of the declaration and not the
    /// arithmetic of the guard.
    #[test]
    fn a_members_use_of_its_owners_type_parameter_is_not_a_reference_to_the_owner() {
        // hono, src/router/smart-router/router.ts, lines 4 and 13 (1-based).
        let header = "export class SmartRouter<T> implements Router<T> {";
        let name_col = header.find("SmartRouter").expect("class name") as u32;
        let type_param_col = header.find("<T>").expect("type parameter") as u32 + 1;

        let class = EntityRef {
            id: EntityId::new(),
            name: "SmartRouter".to_string(),
            file_path: "src/router/smart-router/router.ts".to_string(),
            start_line: 3,
            start_col: 7,
            end_line: 70,
            name_line: 3,
            name_col,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        };
        let member = EntityRef {
            id: EntityId::new(),
            name: "SmartRouter.add".to_string(),
            file_path: "src/router/smart-router/router.ts".to_string(),
            start_line: 12,
            start_col: 2,
            end_line: 18,
            name_line: 12,
            name_col: 2,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        };

        // `add(method: string, path: string, handler: T)` resolves `T` to the
        // class header, one column past the end of the class name. No edge.
        assert!(
            super::lands_inside_container_without_naming_it(
                &member,
                &class,
                class.name_col,
                "T",
                class.name_line,
                type_param_col,
            ),
            "a use of the owner's type parameter must not become a reference to the owner"
        );

        // `this.#routes` resolves `this` to the class's own NAME token, so the
        // position test alone lets it through. `this` names no declaration.
        assert!(
            super::lands_inside_container_without_naming_it(
                &member,
                &class,
                class.name_col,
                "this",
                class.name_line,
                name_col,
            ),
            "`this` must not become a reference to the class that encloses it"
        );

        // `static create() { return new SmartRouter(...) }` writes the class
        // name and resolves to it. That is a real reference and keeps its edge.
        assert!(
            !super::lands_inside_container_without_naming_it(
                &member,
                &class,
                class.name_col,
                "SmartRouter",
                class.name_line,
                name_col,
            ),
            "a member that really names its class must keep its edge"
        );
        // The last column of the name is still inside the name.
        assert!(!super::lands_inside_container_without_naming_it(
            &member,
            &class,
            class.name_col,
            "SmartRouter",
            class.name_line,
            name_col + "SmartRouter".len() as u32 - 1,
        ));

        // The guard is scoped to containment: two entities that do not contain
        // one another are untouched whatever the identifier or the column.
        let sibling = EntityRef {
            id: EntityId::new(),
            name: "Hono".to_string(),
            file_path: "src/hono.ts".to_string(),
            start_line: 15,
            start_col: 7,
            end_line: 40,
            name_line: 15,
            name_col: 13,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        };
        assert!(
            !super::lands_inside_container_without_naming_it(
                &member,
                &sibling,
                sibling.name_col,
                "this",
                15,
                99
            ),
            "an edge between entities that do not contain one another must be left alone"
        );
    }

    /// A member call's receiver is found on its own line, or on the line
    /// before when the chain breaks at the dot, and a call reached without a
    /// member access has none.
    #[test]
    fn a_member_calls_receiver_is_read_before_its_dot() {
        let lines = [
            "    this.driver.wrap(x)",
            "    builder",
            "        .where(y)",
            "    wrap(z)",
            "    a?.b!.wrap(w)",
        ];
        let at = |line: usize, token: &str| (line as u32, lines[line].find(token).unwrap() as u32);
        assert_eq!(
            super::receiver_before(&lines, at(0, "wrap")),
            Some((0, "    this.driver".to_owned()))
        );
        assert_eq!(
            super::receiver_before(&lines, at(2, "where")),
            Some((1, "    builder".to_owned()))
        );
        assert_eq!(super::receiver_before(&lines, at(3, "wrap")), None);
        assert_eq!(
            super::receiver_before(&lines, at(4, "wrap")),
            Some((4, "    a?.b".to_owned()))
        );
    }

    /// Only a parenthesized cast to a union is one, across lines as typeorm
    /// writes it; a call's arguments and a cast to one type are not.
    #[test]
    fn a_parenthesized_cast_to_a_union_is_read_as_one() {
        let typeorm = [
            "expression = (",
            "    this.dataSource.driver as",
            "        AbstractSqliteDriver | ReactNativeDriver",
            ")",
        ];
        assert!(super::casts_to_a_union(&typeorm, 3, ")"));
        assert!(super::casts_to_a_union(&[], 0, "return (d as A | B)"));
        assert!(!super::casts_to_a_union(&[], 0, "make(d as A | B)"));
        assert!(!super::casts_to_a_union(&[], 0, "(d as A)"));
        assert!(!super::casts_to_a_union(&[], 0, "(a || b)"));
    }

    /// The token the pass asked about, read back from the line it asked on.
    #[test]
    fn the_queried_identifier_is_read_back_from_its_column() {
        let line = "    this.#routers = init.routers";
        assert_eq!(super::identifier_at(line, 4), "this");
        assert_eq!(super::identifier_at(line, 20), "init");
        let generic = "  add(method: string, path: string, handler: T) {";
        let t_col = generic.find("T)").expect("type parameter") as u32;
        assert_eq!(super::identifier_at(generic, t_col), "T");
    }

    #[test]
    fn identifier_positions_include_real_tokens_not_line_zero() {
        let positions = identifier_positions_in_line("    let foo_bar = Baz::new();");
        assert!(positions.contains(&4));
        assert!(positions.contains(&8));
        assert!(positions.contains(&18));
        assert!(!positions.contains(&0));
    }

    /// Build a large, adversarial source string: several thousand lines,
    /// periodic very-long lines, unicode identifiers/strings/comments, and
    /// comment/string lines to exercise every branch of the scanner.
    fn synth_large_file(lines: usize) -> String {
        let mut out = String::with_capacity(lines * 80);
        for i in 0..lines {
            match i % 10 {
                0 => {
                    // Long line (~500 cols) packed with identifiers + a string.
                    out.push_str("    let ");
                    for j in 0..40 {
                        out.push_str(&format!(
                            "ident_{i}_{j} = compute_naïve_café(α_{j}, β_{j}); "
                        ));
                    }
                    out.push_str("\"a string with spaces and symbols !@#\"\n");
                }
                3 => out.push_str("    // a comment line with λμβδα and words galore\n"),
                6 => out
                    .push_str("    let msg = \"unicode 日本語 строка with many words inside\";\n"),
                _ => out.push_str(&format!(
                    "    let value_{i} = SomeType::method_call(arg_one, arg_two);\n"
                )),
            }
        }
        out
    }

    /// Honest local-CPU measurement of the per-identifier scanner that the
    /// enrichment loops (`enrich_file_definitions`, `enrich_entity_uses_type`)
    /// run before each LSP request. The LSP round-trip itself is not measured
    /// here — that is the dominant cost and cannot be batched output-identically
    /// (definition resolution is position-dependent). This isolates the only
    /// work a "single-pass / batch" refactor could remove.
    #[test]
    #[ignore = "wall-clock microbench; run explicitly with --ignored on a quiet machine"]
    fn measure_identifier_scan_throughput_on_large_unicode_file() {
        let lines = 5_000usize;
        let content = synth_large_file(lines);
        let bytes = content.len();

        // Warm up so we measure steady-state, not first-touch allocation.
        let mut warm = 0usize;
        for line in content.lines() {
            warm += identifier_positions_in_line(line).len();
        }
        assert!(warm > 0, "scanner must find identifiers");

        let reps = 50u32;
        let start = std::time::Instant::now();
        let mut total_idents = 0usize;
        for _ in 0..reps {
            for line in content.lines() {
                total_idents += identifier_positions_in_line(line).len();
            }
        }
        let elapsed = start.elapsed();

        let idents_per_rep = total_idents / reps as usize;
        let per_rep = elapsed / reps;
        let ns_per_ident = elapsed.as_nanos() as f64 / total_idents as f64;
        let mb_per_s = (bytes as f64 * reps as f64) / elapsed.as_secs_f64() / 1.0e6;

        println!(
            "[scan-bench] {lines} lines, {bytes} bytes, {idents_per_rep} idents/file | \
             per-file {:?} | {ns_per_ident:.1} ns/ident | {mb_per_s:.0} MB/s",
            per_rep
        );

        // Sanity ceiling: scanning one whole large file must stay far under a
        // single LSP round-trip (which carries a 2s per-request timeout and
        // tens-of-ms typical latency). If a refactor ever made this O(n^2),
        // this guard would catch it. Generous bound to avoid CI flakiness.
        assert!(
            per_rep < std::time::Duration::from_millis(50),
            "per-file identifier scan should be sub-50ms (was {per_rep:?}); \
             the loop is LSP-RPC-bound, not scan-bound"
        );
    }
}

#[cfg(test)]
mod slot_tests {
    use super::{initializer, initializer_is_function};

    /// A declaration's initializer is what follows its top-level `=`, past
    /// a type annotation that may itself hold an arrow.
    #[test]
    fn the_initializer_follows_the_top_level_assignment() {
        assert_eq!(
            initializer(": Handler = defaultHandler;"),
            Some(" defaultHandler;")
        );
        assert_eq!(initializer(" = (x) => x;"), Some(" (x) => x;"));
        assert_eq!(
            initializer(": (x: number) => number = (x) => x;"),
            Some(" (x) => x;")
        );
        assert_eq!(initializer("?: (encoder: string) => string;"), None);
        assert_eq!(initializer(": { a: number };"), None);
        assert_eq!(initializer("(a = 1): void {"), None);
    }

    #[test]
    fn only_a_function_literal_initializes_a_callable() {
        for function in [
            " (x) => x + 1;",
            " async (x: number): Promise<number> => x;",
            " x => x;",
            " <T>(x: T) => x;",
            " function (x) { return x; };",
            " async function named() {}",
            " lambda request: request.url",
            " |x| x + 1;",
            " move || work();",
        ] {
            assert!(initializer_is_function(function), "{function}");
        }
        for value in [
            " defaultHandler;",
            " (a || b);",
            " make();",
            " new Handler();",
            " functional;",
            " lambdas[0]",
            " 42;",
        ] {
            assert!(!initializer_is_function(value), "{value}");
        }
    }
}

#[cfg(test)]
mod scope_tests {
    use super::{enrich_file_definitions_in, FileScope};
    use crate::enrichment::{EntityIndex, EntityRef};
    use crate::lifecycle::LspServer;
    use kin_model::EntityId;
    use serde_json::{json, Value};

    /// Where the pass asked `method`, as (line, character), in asking order.
    async fn asked(server: &LspServer, method: &str) -> Vec<(u64, u64)> {
        let seen: Vec<Value> = serde_json::from_value(
            server
                .client
                .request("test/seen", Value::Null)
                .await
                .unwrap(),
        )
        .unwrap();
        seen.iter()
            .filter(|request| request["method"] == method)
            .map(|request| {
                let position = &request["params"]["position"];
                (
                    position["line"].as_u64().unwrap(),
                    position["character"].as_u64().unwrap(),
                )
            })
            .collect()
    }

    /// A scoped pass asks every identifier of the callers it holds whole, and
    /// their call hierarchy. Of another caller it asks only the callee token it
    /// was handed, and that caller's call hierarchy, and the answer there is a
    /// site answer exactly as the whole-file pass makes it.
    #[tokio::test]
    async fn a_scoped_pass_asks_its_callers_whole_and_other_calls_at_their_token() {
        let root = std::env::temp_dir().join(format!("kin-lsp-scope-{}", EntityId::new()));
        std::fs::create_dir(&root).unwrap();
        let text = "def a():\n    one()\n\ndef b():\n    two()\n    three()\n";
        let entity = |name: &str, file: &str, start: u32, end: u32| EntityRef {
            id: EntityId::new(),
            name: name.into(),
            file_path: file.into(),
            start_line: start,
            start_col: 0,
            end_line: end,
            name_line: start,
            name_col: 4,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        };
        let a = entity("a", "source.py", 0, 1);
        let b = entity("b", "source.py", 3, 5);
        let two = entity("two", "lib.py", 0, 1);
        let index = EntityIndex::new(vec![a.clone(), b.clone(), two.clone()], &root);
        let lib = crate::protocol::path_to_uri(&root.join("lib.py"));
        let responses = json!({"textDocument/definition": {"result": [{"uri": lib, "range": {
            "start": {"line": 0, "character": 4}, "end": {"line": 0, "character": 7}}}]}});
        let provider = |path: &str| (path == "source.py").then(|| text.to_string());
        let token = text.find("two").unwrap();

        let run = |scope: FileScope| {
            let (root, index, responses) = (&root, &index, responses.clone());
            async move {
                let server = LspServer::scripted_for_tests(
                    include_str!("enrichment_test_peer.py"),
                    responses,
                );
                let result = enrich_file_definitions_in(
                    &server,
                    &root.join("source.py"),
                    text,
                    index,
                    root,
                    Some(&provider),
                    &scope,
                )
                .await
                .unwrap();
                let definitions = asked(&server, "textDocument/definition").await;
                (result, definitions)
            }
        };

        let (scoped, mut definitions) = run(FileScope::callers([a.id], [(b.id, token)])).await;
        definitions.sort();
        assert_eq!(
            definitions,
            [(0, 4), (1, 4), (4, 4)],
            "a's identifiers and b's call at its token; never b's others"
        );
        assert!(scoped
            .site_answers
            .iter()
            .any(|answer| answer.source == b.id
                && answer.site.start_byte == token
                && answer.target == crate::call_sites::SiteTarget::Entity(two.id)));
        assert!(scoped
            .site_answers
            .iter()
            .all(|answer| answer.source != b.id || answer.site.start_byte == token));
        assert!(!FileScope::callers([a.id], [(b.id, token)]).is_whole_file());
        assert!(FileScope::callers([a.id], [(b.id, token)]).asks_hierarchy(b.id));

        let (whole, mut definitions) = run(FileScope::whole_file()).await;
        definitions.sort();
        assert_eq!(
            definitions,
            [(0, 4), (1, 4), (3, 4), (4, 4), (5, 4)],
            "the whole-file scope asks every identifier, as the sweep does"
        );
        let at_token = |result: &super::FileEnrichmentResult| {
            result
                .site_answers
                .iter()
                .filter(|answer| answer.site.start_byte == token)
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            at_token(&scoped),
            at_token(&whole),
            "the answer at a site does not depend on the scope it was asked in"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
