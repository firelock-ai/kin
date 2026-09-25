// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact coordinates in the caller-supplied admitted document. LSP uses UTF-16
//! code units; Kin's parser spans use UTF-8 byte offsets and byte columns.
//! No filesystem reads, cursor clamping, or synthetic occurrence lengths.

use kin_model::{FilePathId, SourceSpan};

use crate::error::{LspError, Result};
use crate::protocol::{Position, Range};

pub(crate) struct SourcePositions<'a> {
    file: &'a str,
    text: &'a str,
    starts: Vec<usize>,
}

impl<'a> SourcePositions<'a> {
    pub(crate) fn new(file: &'a str, text: &'a str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(offset, _)| offset + 1));
        Self { file, text, starts }
    }

    fn invalid(&self) -> LspError {
        LspError::Protocol(format!(
            "unproven source position in admitted document {}",
            self.file
        ))
    }

    fn line(&self, line: u32) -> Result<(usize, &'a str)> {
        let start = *self
            .starts
            .get(line as usize)
            .ok_or_else(|| self.invalid())?;
        let end = self
            .starts
            .get(line as usize + 1)
            .copied()
            .unwrap_or(self.text.len());
        let raw = &self.text[start..end];
        let content = raw.strip_suffix('\n').unwrap_or(raw);
        let content = content.strip_suffix('\r').unwrap_or(content);
        Ok((start, content))
    }

    fn utf16_byte(&self, position: &Position) -> Result<(usize, u32)> {
        let (start, line) = self.line(position.line)?;
        let mut units = 0;
        for (offset, character) in line.char_indices() {
            if units == position.character {
                return Ok((start + offset, offset as u32));
            }
            units += character.len_utf16() as u32;
            if units > position.character {
                return Err(self.invalid());
            }
        }
        if units == position.character {
            Ok((start + line.len(), line.len() as u32))
        } else {
            Err(self.invalid())
        }
    }

    /// The text of `line`, without its line ending.
    pub(crate) fn line_text(&self, line: u32) -> Result<&'a str> {
        self.line(line).map(|(_, content)| content)
    }

    pub(crate) fn byte_column(&self, position: &Position) -> Result<u32> {
        self.utf16_byte(position).map(|(_, column)| column)
    }

    /// Convert parser byte columns to protocol UTF-16, without changing lines.
    pub(crate) fn byte_position(&self, line: u32, column: u32) -> Result<Position> {
        let (_, content) = self.line(line)?;
        let prefix = content
            .get(..column as usize)
            .ok_or_else(|| self.invalid())?;
        Ok(Position {
            line,
            character: prefix.encode_utf16().count() as u32,
        })
    }

    /// Where a per-entity query about `entity` is asked: the token that spells
    /// its name on its declaration line.
    ///
    /// The caller's `name_col` is a hint derived from the signature, and a
    /// signature is not always the source. A decorated Python function's
    /// signature reads `@command @option def routes_command(sort: str,
    /// all_methods: bool)`, so the name's offset in it landed on `bool` in the
    /// real line, and every use of `bool` was recorded as a reference to
    /// `routes_command`. A module surface's signature is its file path, so its
    /// hint ran past the end of the file's first line and the whole file's
    /// enrichment failed with it.
    ///
    /// The name is the entity's last `.` or `::` segment. Python `def`,
    /// `async def`, and `class` lines must spell it immediately after the
    /// declaration keyword: a matching hint can instead name a parameter or
    /// base class. Other lines keep the hint when the source spells the name
    /// there. Otherwise the first whole-token
    /// occurrence of the name on the declaration line, at or after the
    /// declaration's start column, answers. A name the line does not spell is
    /// an error rather than a query at the hint, which that line has already
    /// disproven: every answer about the token under the hint would be pinned
    /// on this entity. A name that is not one identifier cannot be searched for
    /// and keeps the hint. `None` means the entity declares no name of its own,
    /// so there is nothing to ask about.
    pub(crate) fn name_position(
        &self,
        entity: &crate::enrichment::EntityRef,
    ) -> Result<Option<Position>> {
        match self.name_column(entity)? {
            Some(column) => self.byte_position(entity.name_line, column).map(Some),
            None => Ok(None),
        }
    }

    /// The byte column [`Self::name_position`] asks at, on `entity.name_line`.
    pub(crate) fn name_column(&self, entity: &crate::enrichment::EntityRef) -> Result<Option<u32>> {
        if !entity.declares_name {
            return Ok(None);
        }
        let (_, content) = self.line(entity.name_line)?;
        let hint = || {
            content
                .get(..entity.name_col as usize)
                .map(|_| Some(entity.name_col))
                .ok_or_else(|| self.invalid())
        };
        // `Owner.member` and `Type::method` are spelled as their last segment.
        let name = entity
            .name
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(entity.name.as_str());
        if self.file.ends_with(".py") || self.file.ends_with(".pyi") {
            if let Some(column) = python_declaration_name_column(content) {
                // The Python adapter preserves the raw name, including XID
                // continuations (combining marks and connector punctuation)
                // outside the generic identifier approximation below. Match
                // those exact bytes at the declaration slot and require a
                // header separator, so a shorter prefix is never authority.
                let boundary = content[column..].strip_prefix(name).is_some_and(|tail| {
                    tail.starts_with([' ', '\t', '\x0c', '(', '[', ':'])
                        || (tail == "\\"
                            && self.starts.get(entity.name_line as usize + 1).is_some())
                });
                return if !name.is_empty() && boundary {
                    Ok(Some(column as u32))
                } else {
                    // A name later in the parameter/base list cannot repair
                    // a disagreement with the declaration's own identity.
                    Err(self.invalid())
                };
            }
        }
        if !is_identifier(name) || spells_at(content, entity.name_col as usize, name) {
            return hint();
        }
        let from = if entity.name_line == entity.start_line {
            entity.start_col as usize
        } else {
            0
        };
        content
            .match_indices(name)
            .map(|(column, _)| column)
            .find(|&column| column >= from && spells_at(content, column, name))
            .map(|column| Some(column as u32))
            .ok_or_else(|| self.invalid())
    }

    /// Local identifier scans currently return scalar-character columns.
    pub(crate) fn scalar_position(&self, line: u32, column: u32) -> Result<Position> {
        let (_, content) = self.line(line)?;
        let byte = content
            .char_indices()
            .map(|(offset, _)| offset)
            .chain(std::iter::once(content.len()))
            .nth(column as usize)
            .ok_or_else(|| self.invalid())?;
        self.byte_position(line, byte as u32)
    }

    pub(crate) fn range(&self, range: &Range) -> Result<SourceSpan> {
        let (start_byte, start_col) = self.utf16_byte(&range.start)?;
        let (end_byte, end_col) = self.utf16_byte(&range.end)?;
        if start_byte >= end_byte {
            return Err(self.invalid());
        }
        Ok(SourceSpan {
            file: FilePathId::new(self.file),
            start_byte,
            end_byte,
            start_line: range.start.line,
            start_col,
            end_line: range.end.line,
            end_col,
        })
    }

    /// The real identifier asked about by a local scalar-column probe. This is
    /// the caller occurrence, not the definition range returned in another file.
    pub(crate) fn token(&self, line: u32, scalar_column: u32) -> Result<SourceSpan> {
        let position = self.scalar_position(line, scalar_column)?;
        let (start_byte, start_col) = self.utf16_byte(&position)?;
        let (_, content) = self.line(line)?;
        let tail = &content[start_col as usize..];
        let mut chars = tail.chars();
        if !chars.next().is_some_and(|c| c.is_alphabetic() || c == '_') {
            return Err(self.invalid());
        }
        let length: usize = tail
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .map(char::len_utf8)
            .sum();
        Ok(SourceSpan {
            file: FilePathId::new(self.file),
            start_byte,
            end_byte: start_byte + length,
            start_line: line,
            start_col,
            end_line: line,
            end_col: start_col + length as u32,
        })
    }
}

/// Locate only the name slot of a Python declaration on its recorded line.
/// This does not search the body, parameters, bases, or decorator text.
fn python_declaration_name_column(line: &str) -> Option<usize> {
    fn after_keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
        let rest = text.strip_prefix(keyword)?;
        rest.starts_with([' ', '\t', '\x0c'])
            .then(|| rest.trim_start_matches([' ', '\t', '\x0c']))
    }

    let declaration = line.trim_start_matches([' ', '\t', '\x0c']);
    let name = if let Some(function) = after_keyword(declaration, "async") {
        after_keyword(function, "def")?
    } else {
        after_keyword(declaration, "def").or_else(|| after_keyword(declaration, "class"))?
    };
    Some(line.len() - name.len())
}

fn is_identifier_char(character: char) -> bool {
    character.is_alphanumeric() || character == '_' || character == '$'
}

/// Whether `name` is one identifier token, the only shape a line can be
/// searched for without guessing where it starts.
fn is_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_alphabetic() || first == '_' || first == '$')
        && characters.all(is_identifier_char)
}

/// Whether `line` holds exactly the token `name` at byte `column`: the text
/// starts there, and no identifier character runs into it on either side.
fn spells_at(line: &str, column: usize, name: &str) -> bool {
    let (Some(before), Some(rest)) = (line.get(..column), line.get(column..)) else {
        return false;
    };
    rest.starts_with(name)
        && !before.chars().next_back().is_some_and(is_identifier_char)
        && !rest[name.len()..]
            .chars()
            .next()
            .is_some_and(is_identifier_char)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn range(line: u32, start: u32, end: u32) -> Range {
        Range {
            start: Position {
                line,
                character: start,
            },
            end: Position {
                line,
                character: end,
            },
        }
    }

    #[test]
    fn unicode_crlf_and_trailing_line_preserve_exact_bytes() {
        let text = "é😀 name\r\n\tλ()\n";
        let source = SourcePositions::new("src/a.py", text);
        let name = source.range(&range(0, 4, 8)).unwrap();
        assert_eq!(&text[name.start_byte..name.end_byte], "name");
        assert_eq!(
            (name.start_byte, name.end_byte, name.start_col, name.end_col),
            (7, 11, 7, 11)
        );
        assert_eq!(source.byte_position(0, 7).unwrap().character, 4);
        assert_eq!(source.scalar_position(0, 3).unwrap().character, 4);
        let token = source.token(1, 1).unwrap();
        assert_eq!(&text[token.start_byte..token.end_byte], "λ");
        assert_eq!((token.start_byte, token.end_byte), (14, 16));
        assert_eq!(source.byte_position(2, 0).unwrap().character, 0);
    }

    #[test]
    fn invalid_positions_never_clamp_or_invent_occurrences() {
        let source = SourcePositions::new("src/a.py", "😀x\r\n");
        for range in [
            range(0, 1, 2),
            range(0, 0, 1),
            range(0, 2, 2),
            range(0, 3, 2),
            range(0, 2, 20),
            range(2, 0, 1),
        ] {
            assert!(source.range(&range).is_err());
        }
        assert!(source.byte_position(0, 1).is_err());
        assert!(source.scalar_position(0, 3).is_err());
        assert!(source.token(0, 0).is_err());
        assert!(source.token(1, 0).is_err());
    }

    fn declared(name: &str, line: u32, start_col: u32, hint: u32) -> crate::EntityRef {
        crate::EntityRef {
            id: kin_model::EntityId::new(),
            name: name.into(),
            file_path: "src/a.py".into(),
            start_line: line,
            start_col,
            end_line: line + 1,
            name_line: line,
            name_col: hint,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        }
    }

    /// Flask's `routes_command`: the signature leads with four decorators, so
    /// the name's offset in it lands inside `bool` on the real `def` line.
    #[test]
    fn a_decorated_definition_is_asked_at_its_name_not_at_its_signature_offset() {
        let text = "@with_appcontext\ndef routes_command(sort: str, all_methods: bool) -> None:\n";
        let signature =
            "@command @option @option @with_appcontext def routes_command(sort: str, all_methods: bool) -> None";
        let hint = signature.find("routes_command").unwrap() as u32;
        let line = text.lines().nth(1).unwrap();
        assert_eq!(
            &line[43..47],
            "bool",
            "the fixture reproduces the offset landing in another token"
        );
        assert!((43..47).contains(&hint));
        let source = SourcePositions::new("src/flask/cli.py", text);
        let asked = source
            .name_position(&declared("routes_command", 1, 0, hint))
            .unwrap()
            .unwrap();
        assert_eq!((asked.line, asked.character), (1, 4));
    }

    #[test]
    fn decorated_python_same_spelling_hints_never_select_parameters_or_bases() {
        for (line, signature, name, expected) in [
            ("def foo(foo):", "@de def foo(foo)", "foo", 4),
            ("class Foo(Foo):", "@de class Foo(Foo)", "Foo", 6),
        ] {
            let text = format!("@de\n{line}\n    pass\n");
            let hint = signature.find(name).unwrap() as u32;
            assert!(spells_at(line, hint as usize, name));
            assert_ne!(hint, expected, "the hint spells a different symbol");
            let mut entity = declared(name, 0, 0, hint);
            entity.name_line = 1;
            entity.end_line = 2;
            let source = SourcePositions::new("src/a.py", &text);
            let asked = source.name_position(&entity).unwrap().unwrap();
            assert_eq!((asked.line, asked.character), (1, expected), "{text}");
        }
    }

    #[test]
    fn python_declaration_identity_handles_async_stubs_and_refuses_other_names() {
        let text = "\tasync\tdef\tλ(λ): ...\n";
        let source = SourcePositions::new("src/a.pyi", text);
        let entity = declared("Owner.λ", 0, 1, text.rfind('λ').unwrap() as u32);
        assert_eq!(
            source.name_position(&entity).unwrap().unwrap().character,
            11
        );

        for text in ["def other(foo):\n", "class Other(Foo):\n"] {
            let name = if text.starts_with("def") {
                "foo"
            } else {
                "Foo"
            };
            let source = SourcePositions::new("src/a.py", text);
            let entity = declared(name, 0, 0, text.find(name).unwrap() as u32);
            assert!(source.name_position(&entity).is_err(), "{text}");
        }
    }

    #[test]
    fn python_declaration_identity_preserves_raw_combining_and_connector_names() {
        for name in ["cafe\u{0301}", "a\u{203f}b"] {
            let text = format!("def {name}(): ...\n");
            let source = SourcePositions::new("src/a.py", &text);
            let asked = source
                .name_position(&declared(name, 0, 0, 4))
                .unwrap()
                .unwrap();
            assert_eq!((asked.line, asked.character), (0, 4));
        }
    }

    #[test]
    fn python_declaration_raw_name_requires_the_complete_token_without_normalizing() {
        for (text, wrong_name) in [
            ("def cafe\u{0301}(): ...\n", "cafe"),
            ("def cafe\u{0301}(): ...\n", "café"),
            ("class a\u{203f}b: ...\n", "a"),
        ] {
            let source = SourcePositions::new("src/a.py", text);
            assert!(source
                .name_position(&declared(wrong_name, 0, 0, 4))
                .is_err());
        }
        for suffix in [
            "(): ...\n",
            "[T](): ...\n",
            " (): ...\n",
            "\\\n(): ...\n",
            "\\\r\n(): ...\r\n",
        ] {
            let text = format!("def cafe\u{0301}{suffix}");
            let source = SourcePositions::new("src/a.py", &text);
            assert_eq!(
                source
                    .name_column(&declared("cafe\u{0301}", 0, 0, 4))
                    .unwrap(),
                Some(4)
            );
        }
        for suffix in ["\\junk\n", "\\"] {
            let text = format!("def cafe\u{0301}{suffix}");
            let source = SourcePositions::new("src/a.py", &text);
            assert!(source
                .name_position(&declared("cafe\u{0301}", 0, 0, 4))
                .is_err());
        }
    }

    #[test]
    fn python_keyword_prefixes_and_other_languages_keep_existing_name_positions() {
        for text in ["define = foo\n", "classify = foo\n", "async_task = foo\n"] {
            let source = SourcePositions::new("src/a.py", text);
            let column = text.find("foo").unwrap() as u32;
            assert_eq!(
                source.name_column(&declared("foo", 0, 0, column)).unwrap(),
                Some(column)
            );
        }
        // Groovy-like syntax must not be interpreted as a Python declaration.
        let source = SourcePositions::new("src/a.groovy", "def foo = foo\n");
        assert_eq!(
            source.name_column(&declared("foo", 0, 0, 10)).unwrap(),
            Some(10)
        );
    }

    /// A property setter's signature opens with `@static_url_path.setter`, so
    /// the name's first occurrence is inside the decorator.
    #[test]
    fn a_setter_is_asked_at_its_own_def_line_name() {
        let text = "    @static_url_path.setter\n    def static_url_path(self, value: str | None) -> None:\n";
        let signature =
            "@static_url_path.setter def static_url_path(self, value: str | None) -> None";
        let hint = 4 + signature.find("static_url_path").unwrap() as u32;
        let source = SourcePositions::new("src/flask/sansio/scaffold.py", text);
        let asked = source
            .name_position(&declared("Scaffold.static_url_path", 1, 4, hint))
            .unwrap()
            .unwrap();
        assert_eq!((asked.line, asked.character), (1, 8));
    }

    /// A module surface's signature is its path, so its hint ran past the end of
    /// the first line. Asked, it failed the whole file; it is now not asked.
    #[test]
    fn a_module_surface_is_not_asked_about() {
        let text = "import functools\n\nfrom flask import Blueprint\n";
        let hint = "module examples/tutorial/flaskr/auth.py"
            .find("auth")
            .unwrap() as u32;
        let mut module = declared("auth", 0, 0, hint);
        let source = SourcePositions::new("examples/tutorial/flaskr/auth.py", text);
        assert!(
            source.name_position(&module).is_err(),
            "the hint is off the line, which is the failure the flag avoids"
        );
        module.declares_name = false;
        assert!(source.name_position(&module).unwrap().is_none());
    }

    /// Where the hint already sits on the name, nothing changes, including for
    /// a dotted name addressed by its last segment.
    #[test]
    fn a_hint_on_the_name_is_kept() {
        let text = "app.handle = function handle(req) {\n";
        let source = SourcePositions::new("lib/application.js", text);
        let asked = source
            .name_position(&declared("app.handle", 0, 0, 4))
            .unwrap()
            .unwrap();
        assert_eq!((asked.line, asked.character), (0, 4));
    }

    /// Only a whole token matches: `send` inside `resend` is not the name, and
    /// the search starts at the declaration's own column.
    #[test]
    fn a_name_inside_a_longer_token_is_not_the_name() {
        let text = "resend = 1; send = 2\n";
        let source = SourcePositions::new("src/a.py", text);
        let asked = source
            .name_position(&declared("send", 0, 0, 0))
            .unwrap()
            .unwrap();
        assert_eq!(asked.character, 12);
    }

    /// The search answers in UTF-16 units, like every other request position.
    #[test]
    fn a_located_name_is_converted_to_utf16() {
        let text = "é = 1; name = 2\n";
        let source = SourcePositions::new("src/a.py", text);
        let asked = source
            .name_position(&declared("name", 0, 0, 0))
            .unwrap()
            .unwrap();
        assert_eq!(asked.character, 7);
    }

    /// A name that is not one identifier cannot be searched for and keeps the
    /// hint. A name its declaration line does not spell is an error: the hint
    /// is on some other token, and asking there would pin that token's answers
    /// on this entity.
    #[test]
    fn a_malformed_name_keeps_the_hint_and_an_unspelled_one_fails() {
        let source = SourcePositions::new("src/lib.rs", "    pub fn run(&self) {}\n");
        let asked = source
            .name_position(&declared("not an identifier", 0, 4, 4))
            .unwrap()
            .unwrap();
        assert_eq!(asked.character, 4);
        assert!(source.name_position(&declared("absent", 0, 4, 4)).is_err());
    }

    /// A Rust or C++ member is named `Type::method` and spelled `method`.
    #[test]
    fn a_path_qualified_member_is_asked_at_its_last_segment() {
        let source = SourcePositions::new("src/lib.rs", "    pub fn run(&self) {}\n");
        let asked = source
            .name_position(&declared("Worker::run", 0, 4, 4))
            .unwrap()
            .unwrap();
        assert_eq!(asked.character, 11);
    }

    /// A decorated Python definition's span opens on its first decorator, so
    /// its name is found on the declaration line the parser recorded, which is
    /// where `name_line` points.
    #[test]
    fn a_declaration_line_below_the_span_start_is_searched_from_its_start() {
        let text = "    @t.overload\n    def template_global(self, name: T_template_global) -> T_template_global: ...\n";
        let source = SourcePositions::new("src/flask/sansio/app.py", text);
        let mut entity = declared("App.template_global", 0, 4, 14);
        entity.name_line = 1;
        entity.end_line = 1;
        let asked = source.name_position(&entity).unwrap().unwrap();
        assert_eq!((asked.line, asked.character), (1, 8));
    }
}
