// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a language server proved about the callee one call site names.
//!
//! The linker binds many calls by the callee's bare name, and when several
//! declarations share that name it keeps them all as candidates. A language
//! server asked for the definition at the callee token answers which one the
//! call names, or that it names a declaration outside the repository
//! altogether. [`SiteAnswer`] is that answer, pinned to the token it was asked
//! at, so a caller holding the linker's candidates for the same site can tell
//! which of them the answer contradicts.
//!
//! A site answer is only ever built from a definite answer. A query that timed
//! out, was declined, or came back empty produces no answer at all, and an
//! answer this module cannot place (a local variable, a parameter, a file inside
//! the repository that the graph does not hold) produces none either. Absence
//! is never evidence here.
//!
//! The answer does not depend on which entity Kin takes the caller to be, so it
//! proves a call whatever the linker bound there, confidently or by name, and
//! whether or not call hierarchy listed the call.

use std::path::Path;

use kin_model::{
    EntityId, GraphNodeId, Relation, RelationEvidence, RelationKind, RelationOrigin, SourceSpan,
};

/// Evidence rule of a definition answer asked at an identifier.
pub const DEFINITION_RULE: &str = "lsp_definition";

/// Evidence rule of a definition answer reached through one alias hop: the
/// identifier's own answer was a binding the graph holds no entity for, a
/// destructured or imported name, and the binding's definition is the
/// declaration it takes its value from.
pub const DEFINITION_ALIAS_RULE: &str = "lsp_definition_alias";

/// Evidence rule of a call-hierarchy answer, one record per call range.
pub const CALL_HIERARCHY_RULE: &str = "lsp_call_hierarchy";

/// A zero-based line and UTF-16 character range, as a server reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocationRange {
    pub start_line: u32,
    pub start_character: u32,
    pub end_line: u32,
    pub end_character: u32,
}

impl From<&crate::protocol::Range> for LocationRange {
    fn from(range: &crate::protocol::Range) -> Self {
        Self {
            start_line: range.start.line,
            start_character: range.start.character,
            end_line: range.end.line,
            end_character: range.end.character,
        }
    }
}

impl LocationRange {
    /// Whether the start of `other` lies inside this range: at or after its
    /// start, and before its end or at its start when it is empty.
    pub fn holds_start_of(&self, other: &LocationRange) -> bool {
        let point = (other.start_line, other.start_character);
        let start = (self.start_line, self.start_character);
        let end = (self.end_line, self.end_character);
        point == start || (start <= point && point < end)
    }
}

/// Where an answer outside the workspace landed: the file and the range the
/// server gave.
///
/// Used only to name the declaration there (see
/// [`crate::external_symbols`]). A location is never stored or served, so no
/// local path reaches the graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutsideLocation {
    pub uri: String,
    pub range: LocationRange,
}

/// Where a definite answer at a callee token puts the declaration it names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SiteTarget {
    /// The declaration of this graph entity, named at its own name token.
    Entity(EntityId),
    /// A declaration outside the workspace root, in a file the graph holds no
    /// twin of: a standard library, an installed dependency, a toolchain.
    Outside(OutsideLocation),
}

impl SiteTarget {
    /// The graph entity this target names, when it names one.
    pub fn entity(&self) -> Option<EntityId> {
        match self {
            Self::Entity(entity) => Some(*entity),
            Self::Outside(_) => None,
        }
    }

    /// Whether the target lies outside the workspace.
    pub fn is_outside(&self) -> bool {
        matches!(self, Self::Outside(_))
    }
}

/// The external symbols the declarations at outside locations were named as.
/// A location the namer could not name is absent.
pub type ExternalNames = std::collections::HashMap<OutsideLocation, kin_model::ExternalSymbol>;

/// What asking about one identifier came to, when it proved no declaration.
///
/// Every identifier a file pass asked about and could not prove is recorded
/// with one of these, so a caller holding the call sites can give each one
/// its state instead of reading silence as nothing asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnprovenAnswer {
    /// The server answered with no location.
    NoAnswer,
    /// The answer names a value binding: a local or a parameter of the
    /// caller itself, or a slot a value flows into that an alias hop landed
    /// on, which says nothing about the body that runs.
    Binding,
    /// The answer lands inside the repository at a declaration the graph
    /// holds no entity for, in a file it holds or one it does not.
    OutsideTheGraph,
    /// The answer names more than one declaration, or the call's receiver may
    /// be any of several types.
    AnswersDisagree,
    /// The server answered in a way this build cannot prove, and answers the
    /// same bytes the same way every time, or declined the question.
    Refused,
    /// The query timed out.
    Timeout,
    /// The server stopped answering.
    Crash,
    /// The server returned an error of its own.
    ProtocolError,
}

/// One identifier a file pass asked about and could not prove, keyed like a
/// [`SiteAnswer`]: the entity whose body holds it and its byte range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnprovenSite {
    pub source: EntityId,
    pub start_byte: usize,
    pub end_byte: usize,
    pub answer: UnprovenAnswer,
}

/// A language server's definite answer about the identifier at `site`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteAnswer {
    /// The entity whose body holds the identifier.
    pub source: EntityId,
    /// The identifier token the server was asked about, in the source file.
    pub site: SourceSpan,
    pub target: SiteTarget,
    /// Which query answered: [`DEFINITION_RULE`], [`DEFINITION_ALIAS_RULE`] or
    /// [`CALL_HIERARCHY_RULE`].
    pub rule: &'static str,
}

/// The site answers a set of call-hierarchy relations carries.
///
/// Every call range an outgoing-calls answer reported is recorded on its
/// `Calls` edge as an evidence span under [`CALL_HIERARCHY_RULE`]. The range is
/// the one the server reported for the call, which is the callee token for the
/// servers Kin drives. A range that is not exactly a callee token matches no
/// call site downstream and so settles nothing.
pub fn call_hierarchy_answers(relations: &[Relation]) -> Vec<SiteAnswer> {
    let mut answers = Vec::new();
    for relation in relations {
        if relation.kind != RelationKind::Calls || relation.origin != RelationOrigin::Lsp {
            continue;
        }
        let (GraphNodeId::Entity(source), GraphNodeId::Entity(target)) =
            (relation.src, relation.dst)
        else {
            continue;
        };
        for evidence in &relation.evidence {
            if evidence.parser_rule.as_deref() != Some(CALL_HIERARCHY_RULE) {
                continue;
            }
            let Some(site) = evidence.source_span.clone() else {
                continue;
            };
            answers.push(SiteAnswer {
                source,
                site,
                target: SiteTarget::Entity(target),
                rule: CALL_HIERARCHY_RULE,
            });
        }
    }
    answers
}

/// A `Calls` edge a language server proved to a symbol outside the repository,
/// keyed by [`RelationId::resolver`](kin_model::RelationId::resolver) so a
/// second proof of the same pair merges into it instead of beside it.
pub fn proven_external_call(
    caller: EntityId,
    target: kin_model::ExternalReferenceId,
    evidence: Vec<RelationEvidence>,
) -> Relation {
    let src = GraphNodeId::Entity(caller);
    let dst = GraphNodeId::ExternalReference(target);
    Relation {
        id: kin_model::RelationId::resolver(RelationKind::Calls, &src, &dst),
        kind: RelationKind::Calls,
        src,
        dst,
        confidence: 0.95,
        origin: RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence,
    }
}

/// A `Calls` edge a language server proved, keyed like every other enrichment
/// edge so a second proof of the same pair merges into it instead of beside it.
pub fn proven_call(
    caller: EntityId,
    target: EntityId,
    evidence: Vec<RelationEvidence>,
) -> Relation {
    Relation {
        id: crate::enrichment::deterministic_relation_id(RelationKind::Calls, caller, target),
        kind: RelationKind::Calls,
        src: GraphNodeId::Entity(caller),
        dst: GraphNodeId::Entity(target),
        confidence: 0.95,
        origin: RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence,
    }
}

/// One evidence record naming `site` under `rule`.
pub fn site_evidence(rule: &str, site: SourceSpan) -> RelationEvidence {
    RelationEvidence {
        source_span: Some(site),
        parser_rule: Some(rule.to_string()),
        occurrence_count: 1,
        ..Default::default()
    }
}

/// The directories of `path` below `root`, lower-cased, or `None` when the
/// path lies outside the root. The file's own name is not among them.
///
/// The comparison ignores case and a leading `/private`, so the two
/// spellings macOS gives one temporary directory, and a server that
/// lower-cases a path on a case-insensitive disk, both read as inside. Every
/// normalization here can only move a path inside, never out.
pub(crate) fn directories_below(path: &Path, root: &Path) -> Option<Vec<String>> {
    fn normalized(path: &Path) -> String {
        let text = path.to_string_lossy().replace('\\', "/").to_lowercase();
        let text = text
            .strip_prefix("/private/")
            .map_or(text.clone(), |rest| format!("/{rest}"));
        text.trim_end_matches('/').to_string()
    }
    let path = normalized(path);
    let root = normalized(root);
    if root.is_empty() {
        return None;
    }
    if path == root {
        return Some(Vec::new());
    }
    let rest = path.strip_prefix(&format!("{root}/"))?;
    let mut parts: Vec<String> = rest.split('/').map(str::to_string).collect();
    parts.pop();
    Some(parts)
}

/// Directories that hold installed dependencies and never a repository's
/// own source: JavaScript's package directories, pnpm's store among them,
/// and Python's installation directories, in a virtual environment or a
/// system interpreter.
const DEPENDENCY_DIRECTORIES: &[&str] = &[
    "node_modules",
    "bower_components",
    "jspm_packages",
    "site-packages",
    "dist-packages",
    "__pypackages__",
];

/// Pairs of directories that, one inside the other, hold a toolchain or a
/// package manager's cache: Cargo's registry and git checkouts, rustup's
/// toolchains, and Kin's own analysis environments under `KIN_HOME/cache`.
const DEPENDENCY_CACHES: &[(&str, &str)] = &[
    (".cargo", "registry"),
    (".cargo", "git"),
    (".rustup", "toolchains"),
    ("cache", "analysis-environments"),
];

/// Whether the directories of a path below the workspace root, as
/// [`directories_below`] spells them, put it in a dependency or toolchain
/// location rather than the repository's own tree.
///
/// Go's module cache is `pkg/mod` with a versioned module directory,
/// `github.com/gin-gonic/gin@v1.10.0`, below it, which a repository's own
/// `pkg/mod` package never has.
pub(crate) fn in_dependency_directory(directories: &[String]) -> bool {
    directories
        .iter()
        .any(|directory| DEPENDENCY_DIRECTORIES.contains(&directory.as_str()))
        || directories.windows(2).enumerate().any(|(at, pair)| {
            DEPENDENCY_CACHES.contains(&(pair[0].as_str(), pair[1].as_str()))
                || (pair[0] == "pkg"
                    && pair[1] == "mod"
                    && directories[at + 2..]
                        .iter()
                        .any(|directory| directory.contains('@')))
        })
}

/// The real path of `path`, with every symbolic link in it resolved, or
/// `None` when no file is there.
///
/// A package manager links a workspace package into `node_modules` by a
/// link to its directory, so a server can name a repository file by a path
/// through a dependency directory, and only the file system knows the file
/// it is.
pub(crate) fn real_path(path: &Path) -> Option<std::path::PathBuf> {
    std::fs::canonicalize(path).ok()
}

/// The callee token of a call expression, read from the admitted source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalleeToken {
    /// Byte offsets of the token in the whole file.
    pub start_byte: usize,
    pub end_byte: usize,
    /// The token as written.
    pub name: String,
    /// Whether the callee is reached through a member access (`recv.name(...)`),
    /// where the receiver's runtime type can choose the body that runs.
    pub through_member: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Syntax {
    Python,
    CLike { rust: bool },
}

fn syntax_of(file: &str) -> Syntax {
    if file.ends_with(".py") || file.ends_with(".pyi") {
        Syntax::Python
    } else {
        Syntax::CLike {
            rust: file.ends_with(".rs"),
        }
    }
}

/// The identifier a call expression calls, when the text says so plainly.
///
/// A call expression ends with its argument list, so the callee is the
/// identifier written immediately before the `(` that opens the last top-level
/// group: `send` in `self.adapter.send(request)`, `get` in `@app.get("/")`,
/// `method` in `a.b(c).method(d)`, `Foo` in `new Foo(x)`. Whitespace, an
/// optional call's `?.`, and generic arguments (`f<T>(x)`, `f::<T>(x)`) may sit
/// between the two.
///
/// A decorator applied without an argument list, `@workdir_lock` or
/// `@pytest.fixture`, calls the decorator it names, so its last name is the
/// callee.
///
/// `None` whenever the text does not say: an expression that does not end with
/// an argument list (`raise E`, a Rust macro `m!(..)`, a tagged template), a
/// callee that is itself an expression (`handlers[k](x)`, `make()(x)`), or
/// brackets this scan cannot balance. Strings and comments are skipped with the
/// rules of the file's language family, and any construct those rules misread
/// leaves the brackets unbalanced, which also answers `None`.
pub fn callee_token(file: &str, text: &str, call: &SourceSpan) -> Option<CalleeToken> {
    let expression = text.get(call.start_byte..call.end_byte)?;
    let syntax = syntax_of(file);
    let Some(open) = argument_list_open(expression, syntax) else {
        return bare_decorator(expression, syntax, call.start_byte);
    };
    let before = &expression[..open];
    let mut end = before.trim_end().len();
    if before[..end].ends_with("?.") {
        end = before[..end - 2].trim_end().len();
    }
    if before[..end].ends_with('>') {
        end = generic_arguments_start(&before[..end])?;
        if before[..end].ends_with("::") {
            end -= 2;
        }
        end = before[..end].trim_end().len();
    }
    let head = &before[..end];
    let start = head
        .char_indices()
        .rev()
        .take_while(|(_, character)| is_identifier_char(*character))
        .last()
        .map(|(offset, _)| offset)?;
    let name = &head[start..];
    if !name
        .chars()
        .next()
        .is_some_and(|first| first.is_alphabetic() || first == '_' || first == '$')
    {
        return None;
    }
    let prefix = head[..start].trim_end();
    let through_member =
        (prefix.ends_with('.') && !prefix.ends_with("..")) || prefix.ends_with("->");
    Some(CalleeToken {
        start_byte: call.start_byte + start,
        end_byte: call.start_byte + end,
        name: name.to_string(),
        through_member,
    })
}

/// The decorator a bare decorator expression applies: the last name of the
/// dotted path after `@`, with nothing else in the expression.
fn bare_decorator(expression: &str, syntax: Syntax, offset: usize) -> Option<CalleeToken> {
    if syntax == (Syntax::CLike { rust: true }) {
        return None;
    }
    let trimmed = expression.trim_end();
    let path_start = trimmed.find('@')? + 1;
    if !trimmed[..path_start - 1].trim().is_empty() {
        return None;
    }
    let path = &trimmed[path_start..];
    let segments: Vec<&str> = path.split('.').collect();
    let valid = |segment: &str| {
        segment
            .chars()
            .next()
            .is_some_and(|first| first.is_alphabetic() || first == '_' || first == '$')
            && segment.chars().all(is_identifier_char)
    };
    if !segments.iter().all(|segment| valid(segment)) {
        return None;
    }
    let name = *segments.last()?;
    let end = offset + path_start + path.len();
    Some(CalleeToken {
        start_byte: end - name.len(),
        end_byte: end,
        name: name.to_string(),
        through_member: segments.len() > 1,
    })
}

fn is_identifier_char(character: char) -> bool {
    character.is_alphanumeric() || character == '_' || character == '$'
}

/// Where the `<` of the generic argument list that `text` ends with starts.
fn generic_arguments_start(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in text.bytes().enumerate().rev() {
        match byte {
            b'>' => depth += 1,
            b'<' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// The byte offset of the `(` whose group closes the expression, when that
/// group is at the top level of the expression.
fn argument_list_open(expression: &str, syntax: Syntax) -> Option<usize> {
    let bytes = expression.as_bytes();
    let last = expression.trim_end().len().checked_sub(1)?;
    if bytes[last] != b')' {
        return None;
    }
    let mut stack: Vec<(u8, usize)> = Vec::new();
    let mut at = 0usize;
    while at <= last {
        let byte = bytes[at];
        match (syntax, byte) {
            (Syntax::Python, b'#') => {
                at = line_end(bytes, at);
                continue;
            }
            (Syntax::CLike { .. }, b'/') if bytes.get(at + 1) == Some(&b'/') => {
                at = line_end(bytes, at);
                continue;
            }
            (Syntax::CLike { .. }, b'/') if bytes.get(at + 1) == Some(&b'*') => {
                at = find(bytes, at + 2, b"*/")? + 2;
                continue;
            }
            (Syntax::Python, b'"' | b'\'') => {
                at = python_string_end(bytes, at)?;
                continue;
            }
            (Syntax::CLike { rust: true }, b'\'') => {
                // A lifetime or loop label is a lone quote; a char literal is
                // one character (or one escape) closed by another.
                at = rust_char_end(expression, at).unwrap_or(at + 1);
                continue;
            }
            (Syntax::CLike { .. }, b'"' | b'\'' | b'`') => {
                at = quoted_end(bytes, at, byte, true)?;
                continue;
            }
            (_, b'(' | b'[' | b'{') => stack.push((byte, at)),
            (_, b')' | b']' | b'}') => {
                let (opened, position) = stack.pop()?;
                let expected = match byte {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                if opened != expected {
                    return None;
                }
                if at == last {
                    return stack.is_empty().then_some(position);
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

fn line_end(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| from + offset)
}

fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

/// One past the closing quote of the string opened at `at`.
fn quoted_end(bytes: &[u8], at: usize, quote: u8, multiline: bool) -> Option<usize> {
    let mut index = at + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'\n' if !multiline => return None,
            byte if byte == quote => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

fn python_string_end(bytes: &[u8], at: usize) -> Option<usize> {
    let quote = bytes[at];
    let triple = [quote, quote, quote];
    if bytes.get(at..at + 3) == Some(&triple[..]) {
        let mut index = at + 3;
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                index += 2;
                continue;
            }
            if bytes.get(index..index + 3) == Some(&triple[..]) {
                return Some(index + 3);
            }
            index += 1;
        }
        return None;
    }
    quoted_end(bytes, at, quote, false)
}

fn rust_char_end(text: &str, at: usize) -> Option<usize> {
    let rest = text.get(at + 1..)?;
    let mut characters = rest.char_indices();
    let (_, first) = characters.next()?;
    if first == '\\' {
        let close = rest.find('\'')?;
        // An escape is short: `\n`, `\x7f`, `\u{10FFFF}`.
        return (close <= 10).then_some(at + 1 + close + 1);
    }
    let (offset, second) = characters.next()?;
    (second == '\'').then_some(at + 1 + offset + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::FilePathId;

    fn span_of(text: &str, expression: &str) -> SourceSpan {
        let start = text
            .find(expression)
            .expect("the expression is in the text");
        SourceSpan {
            file: FilePathId::new("f"),
            start_byte: start,
            end_byte: start + expression.len(),
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 0,
        }
    }

    fn callee(file: &str, text: &str, expression: &str) -> Option<(String, bool, usize)> {
        callee_token(file, text, &span_of(text, expression))
            .map(|token| (token.name, token.through_member, token.start_byte))
    }

    #[test]
    fn the_callee_is_the_name_before_the_last_argument_list() {
        let text = "    self.adapter.send(request, **kwargs)\n";
        let (name, member, start) = callee("a.py", text, "self.adapter.send(request, **kwargs)")
            .expect("a member call names its callee");
        assert_eq!((name.as_str(), member), ("send", true));
        assert_eq!(start, text.find("send").unwrap());

        let text = "x = helper(a, b)";
        assert_eq!(
            callee("a.py", text, "helper(a, b)"),
            Some(("helper".into(), false, 4))
        );
    }

    #[test]
    fn a_nested_or_chained_call_names_its_own_callee() {
        let text = "a.get(b.get(k)).items()";
        assert_eq!(
            callee("a.py", text, "a.get(b.get(k))").map(|(name, _, start)| (name, start)),
            Some(("get".into(), 2)),
            "the outer call's callee precedes its arguments, not the inner call's"
        );
        assert_eq!(
            callee("a.py", text, "b.get(k)").map(|(name, _, start)| (name, start)),
            Some(("get".into(), 8))
        );
        assert_eq!(
            callee("a.py", text, "a.get(b.get(k)).items()").map(|(name, _, _)| name),
            Some("items".into())
        );
        let text = "get(x).get(y)";
        assert_eq!(
            callee("a.py", text, "get(x).get(y)").map(|(_, _, start)| start),
            Some(7)
        );
    }

    #[test]
    fn strings_and_comments_do_not_move_the_argument_list() {
        let text = "log.info(\"(\", ')' )";
        assert_eq!(
            callee("a.py", text, text).map(|(name, ..)| name),
            Some("info".into())
        );
        let text = "run(\n    a,  # a comment with ( in it\n    b,\n)";
        assert_eq!(
            callee("a.py", text, text).map(|(name, ..)| name),
            Some("run".into())
        );
        let text = "fetch(`/api/${id(x)}`, /* ( */ opts)";
        assert_eq!(
            callee("a.ts", text, text).map(|(name, ..)| name),
            Some("fetch".into())
        );
        let text = "f('''a ( b''', \"\")";
        assert_eq!(
            callee("a.py", text, text).map(|(name, ..)| name),
            Some("f".into())
        );
    }

    #[test]
    fn generic_arguments_and_optional_calls_are_stepped_over() {
        let text = "parse::<Vec<u8>>(input)";
        assert_eq!(
            callee("a.rs", text, text).map(|(name, member, _)| (name, member)),
            Some(("parse".into(), false))
        );
        let text = "client.request<Reply>(url)";
        assert_eq!(
            callee("a.ts", text, text).map(|(name, member, _)| (name, member)),
            Some(("request".into(), true))
        );
        let text = "handler?.(event)";
        assert_eq!(
            callee("a.ts", text, text).map(|(name, ..)| name),
            Some("handler".into())
        );
        let text = "Vec::<&'static str>::with_capacity(n)";
        assert_eq!(
            callee("a.rs", text, text).map(|(name, member, _)| (name, member)),
            Some(("with_capacity".into(), false)),
            "a lifetime is not a char literal"
        );
    }

    #[test]
    fn an_expression_callee_or_a_macro_names_nothing() {
        for (file, text) in [
            ("a.py", "handlers[kind](event)"),
            ("a.py", "make()(event)"),
            ("a.rs", "println!(\"{}\", x)"),
            ("a.py", "raise Error"),
            ("a.py", "f(a"),
            ("a.ts", "tag`x`"),
        ] {
            assert_eq!(callee(file, text, text), None, "{text}");
        }
    }

    #[test]
    fn a_decorator_names_the_call_it_makes() {
        let text = "@app.get(\"/items\")\ndef items(): ...";
        assert_eq!(
            callee("a.py", text, "@app.get(\"/items\")").map(|(name, member, _)| (name, member)),
            Some(("get".into(), true))
        );
    }

    #[test]
    fn a_bare_decorator_names_the_decorator_it_applies() {
        let text = "@workdir_lock\ndef test_main(): ...";
        assert_eq!(
            callee("a.py", text, "@workdir_lock"),
            Some(("workdir_lock".into(), false, 1))
        );
        let text = "    @pytest.fixture\n    def client(): ...";
        assert_eq!(
            callee("a.py", text, "@pytest.fixture"),
            Some(("fixture".into(), true, text.find("fixture").unwrap()))
        );
        let text = "@Entity\nexport class Post {}";
        assert_eq!(
            callee("a.ts", text, "@Entity").map(|(name, ..)| name),
            Some("Entity".into())
        );
        for (file, text) in [
            ("a.py", "@handlers[kind]"),
            ("a.py", "x @ y"),
            ("a.rs", "@attr"),
            ("a.py", "@"),
        ] {
            assert_eq!(callee(file, text, text), None, "{text}");
        }
    }

    #[test]
    fn directories_below_the_root_ignore_its_spelling() {
        let root = Path::new("/work/repo");
        let below = |path: &str| directories_below(Path::new(path), root);
        assert_eq!(below("/usr/lib/python3.12/json/__init__.py"), None);
        assert_eq!(
            below("/work/repo/pkg/mod.py"),
            Some(vec!["pkg".to_string()])
        );
        assert_eq!(below("/work/repo"), Some(vec![]));
        assert_eq!(below("/work/repository/x.py"), None);
        assert_eq!(
            below("/Work/Repo/pkg/mod.py"),
            Some(vec!["pkg".to_string()]),
            "a lower-cased spelling of the root is still the root"
        );
        assert_eq!(
            below("/private/work/repo/Pkg/mod.py"),
            Some(vec!["pkg".to_string()]),
            "macOS spells one temporary directory two ways"
        );
    }

    #[test]
    fn dependency_directories_are_named_by_what_installs_them() {
        let dependency = |path: &str| {
            let directories: Vec<String> = path.split('/').map(str::to_string).collect();
            in_dependency_directory(&directories)
        };
        for installed in [
            "node_modules/typescript/lib",
            "packages/web/node_modules/@types/node",
            ".venv/lib/python3.12/site-packages/httpx",
            "usr/lib/python3/dist-packages/yaml",
            ".cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.219/src",
            "go/pkg/mod/github.com/gin-gonic/gin@v1.10.0",
            ".rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src",
            ".kin/cache/analysis-environments/python/cp311",
        ] {
            assert!(dependency(installed), "{installed}");
        }
        for source in [
            "src",
            "packages/pkg/dist",
            "pkg/mod",
            "internal/pkg/mod/v2",
            "cache/lsp",
            "vendor/github.com/x/y",
        ] {
            assert!(!dependency(source), "{source}");
        }
    }

    #[test]
    fn call_hierarchy_edges_answer_at_each_call_range() {
        let caller = EntityId::new();
        let target = EntityId::new();
        let site = span_of("a.send(x); a.send(y)", "send");
        let relation = proven_call(
            caller,
            target,
            vec![
                site_evidence(CALL_HIERARCHY_RULE, site.clone()),
                RelationEvidence::default(),
            ],
        );
        assert_eq!(
            call_hierarchy_answers(&[relation]),
            vec![SiteAnswer {
                source: caller,
                site,
                target: SiteTarget::Entity(target),
                rule: CALL_HIERARCHY_RULE,
            }]
        );
    }
}
