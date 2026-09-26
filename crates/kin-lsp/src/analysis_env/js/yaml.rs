// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The subset of YAML that pnpm and Yarn lockfiles are written in.
//!
//! pnpm writes `pnpm-lock.yaml`, and Yarn Berry writes `yarn.lock`, with ordinary YAML emitters,
//! but only a small part of YAML ever appears in them: block mappings and sequences, flow mappings
//! and sequences such as `{integrity: sha512-..., tarball: x}` or `[arm64]`, single and double
//! quoted scalars, plain scalars, comments and `---` document separators. This reader covers that
//! part, so no YAML library is needed.
//!
//! Every scalar stays text. Nothing is converted to a number or a boolean, so
//! `lockfileVersion: 5.4` reads as the text `5.4` and `optional: true` as the text `true`. Only a
//! plain `null` or `~`, or a key with no value, reads as [`Yaml::Null`]. Anchors, aliases and tags
//! are refused with an error rather than read wrongly. Block scalars (`|` and `>`) are accepted and
//! kept as text, though blank lines and lines that begin with `#` inside one are dropped, since no
//! lockfile field depends on them.

/// One YAML value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Yaml {
    /// A key with no value, or a plain `null` or `~`.
    Null,
    /// A scalar as text, with its quotes removed and its escapes applied.
    Scalar(String),
    /// A sequence.
    Seq(Vec<Yaml>),
    /// A mapping, with its keys in document order.
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    /// The value of `key` when this is a mapping that holds it. A key written twice gives its
    /// first value.
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        self.entries()
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// The text of a scalar.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Yaml::Scalar(text) => Some(text),
            _ => None,
        }
    }

    /// The entries of a mapping.
    pub fn as_map(&self) -> Option<&[(String, Yaml)]> {
        match self {
            Yaml::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// The items of a sequence.
    pub fn as_seq(&self) -> Option<&[Yaml]> {
        match self {
            Yaml::Seq(items) => Some(items),
            _ => None,
        }
    }

    /// The entries of a mapping, or none when this is not a mapping. A key with no value
    /// (`dependencies:` followed by nothing) reads as an empty mapping this way.
    pub fn entries(&self) -> &[(String, Yaml)] {
        self.as_map().unwrap_or(&[])
    }

    /// The text of the scalar at `key`.
    pub fn str_at(&self, key: &str) -> Option<&str> {
        self.get(key)?.as_str()
    }
}

/// Parses a YAML stream into its documents, one entry per document. Documents are separated by
/// `---` lines; an empty stream has no documents, and a `---` line with nothing after it holds a
/// [`Yaml::Null`] document. Errors name the line, counted from 1.
pub fn parse(text: &str) -> Result<Vec<Yaml>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut documents = Vec::new();
    let mut lines: Vec<Line> = Vec::new();
    let mut opened = false;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let content = raw.trim_end();
        if content == "---" || content.starts_with("--- ") || content.starts_with("---\t") {
            if opened || !lines.is_empty() {
                documents.push(std::mem::take(&mut lines));
            }
            opened = true;
            let rest = content[3..].trim_start();
            if !rest.is_empty() && !rest.starts_with('#') {
                lines.push(Line {
                    indent: 0,
                    text: rest,
                    number,
                });
            }
            continue;
        }
        if content == "..." {
            if opened || !lines.is_empty() {
                documents.push(std::mem::take(&mut lines));
            }
            opened = false;
            continue;
        }
        let body = content.trim_start_matches(' ');
        let indent = content.len() - body.len();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        if indent == 0 && body.starts_with('%') && !opened && lines.is_empty() {
            // A directive such as `%YAML 1.2`, which says nothing this reader needs.
            continue;
        }
        if body.starts_with('\t') {
            return Err(format!("line {number}: is indented with a tab"));
        }
        lines.push(Line {
            indent,
            text: body,
            number,
        });
    }
    if opened || !lines.is_empty() {
        documents.push(lines);
    }
    documents
        .into_iter()
        .map(|lines| Parser { lines, pos: 0 }.document())
        .collect()
}

/// One line that holds content: its indentation in spaces, its text after the indentation with
/// trailing whitespace removed, and its line number.
#[derive(Debug, Clone, Copy)]
struct Line<'a> {
    indent: usize,
    text: &'a str,
    number: usize,
}

struct Parser<'a> {
    lines: Vec<Line<'a>>,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn document(mut self) -> Result<Yaml, String> {
        let Some(first) = self.lines.first().copied() else {
            return Ok(Yaml::Null);
        };
        let value = self.node(first.indent)?;
        match self.lines.get(self.pos) {
            None => Ok(value),
            Some(line) => Err(format!(
                "line {}: does not fit the structure of the lines before it",
                line.number
            )),
        }
    }

    /// Reads the block node that starts on the current line, which is indented by `indent`.
    fn node(&mut self, indent: usize) -> Result<Yaml, String> {
        let line = self.lines[self.pos];
        if is_item(line.text) {
            return self.sequence(indent);
        }
        if split_key(line.text).is_some() {
            return self.mapping(indent);
        }
        self.pos += 1;
        self.inline(line.text, indent as isize - 1, line)
    }

    fn mapping(&mut self, indent: usize) -> Result<Yaml, String> {
        let mut entries = Vec::new();
        while let Some(line) = self.lines.get(self.pos).copied() {
            if line.indent < indent || (line.indent == indent && is_item(line.text)) {
                break;
            }
            if line.indent > indent {
                return Err(format!(
                    "line {}: is indented more than the mapping it belongs to",
                    line.number
                ));
            }
            let Some((key, rest)) = split_key(line.text) else {
                return Err(format!("line {}: expected `key: value`", line.number));
            };
            self.pos += 1;
            let value = self.value(rest, indent, line, true)?;
            entries.push((key, value));
        }
        Ok(Yaml::Map(entries))
    }

    fn sequence(&mut self, indent: usize) -> Result<Yaml, String> {
        let mut items = Vec::new();
        while let Some(line) = self.lines.get(self.pos).copied() {
            if line.indent < indent || (line.indent == indent && !is_item(line.text)) {
                break;
            }
            if line.indent > indent {
                return Err(format!(
                    "line {}: is indented more than the sequence it belongs to",
                    line.number
                ));
            }
            let after = &line.text[1..];
            let rest = after.trim_start_matches(' ');
            let nested = !rest.is_empty()
                && !rest.starts_with('#')
                && (is_item(rest) || split_key(rest).is_some());
            if nested {
                // `- key: value` or `- - item`: the item is a block node whose first line starts
                // after the dash, at the column of its first character.
                let column = indent + 1 + (after.len() - rest.len());
                self.lines[self.pos] = Line {
                    indent: column,
                    text: rest,
                    number: line.number,
                };
                items.push(self.node(column)?);
            } else {
                self.pos += 1;
                items.push(self.value(rest, indent, line, false)?);
            }
        }
        Ok(Yaml::Seq(items))
    }

    /// Reads the value that follows `key:` or `- ` on `line`. `parent` is the indentation of that
    /// key or dash; lines indented deeper than it belong to the value. After a key, a sequence
    /// may also sit at the key's own indentation.
    fn value(
        &mut self,
        rest: &'a str,
        parent: usize,
        line: Line<'a>,
        after_key: bool,
    ) -> Result<Yaml, String> {
        if rest.is_empty() || rest.starts_with('#') {
            return match self.lines.get(self.pos).copied() {
                Some(next) if next.indent > parent => self.node(next.indent),
                Some(next) if after_key && next.indent == parent && is_item(next.text) => {
                    self.sequence(parent)
                }
                _ => Ok(Yaml::Null),
            };
        }
        self.inline(rest, parent as isize, line)
    }

    /// Reads a scalar or flow collection that starts in `text`, taking the lines that follow and
    /// are indented deeper than `parent` as its continuation.
    fn inline(&mut self, text: &'a str, parent: isize, line: Line<'a>) -> Result<Yaml, String> {
        match text.as_bytes()[0] {
            b'|' | b'>' => Ok(Yaml::Scalar(self.block_scalar(text, parent))),
            b'{' | b'[' => {
                let mut joined = strip_comment(text).to_owned();
                while !flow_closed(&joined) {
                    let Some(next) = self.continuation(parent) else {
                        return Err(format!(
                            "line {}: a flow collection is not closed",
                            line.number
                        ));
                    };
                    joined.push(' ');
                    joined.push_str(strip_comment(next.text));
                }
                parse_flow(&joined).map_err(|why| format!("line {}: {why}", line.number))
            }
            b'"' | b'\'' => {
                let mut joined = text.to_owned();
                loop {
                    if let Some((value, end)) = quoted(&joined, 0) {
                        let tail = joined[end..].trim_start();
                        if !tail.is_empty() && !tail.starts_with('#') {
                            return Err(format!(
                                "line {}: has text after a quoted scalar",
                                line.number
                            ));
                        }
                        return Ok(Yaml::Scalar(value));
                    }
                    let Some(next) = self.continuation(parent) else {
                        return Err(format!(
                            "line {}: a quoted scalar is not closed",
                            line.number
                        ));
                    };
                    joined.push(' ');
                    joined.push_str(next.text);
                }
            }
            b'&' | b'*' | b'!' => Err(format!(
                "line {}: anchors, aliases and tags are not supported",
                line.number
            )),
            _ => {
                let mut value = strip_comment(text).to_owned();
                while let Some(next) = self.continuation(parent) {
                    value.push(' ');
                    value.push_str(strip_comment(next.text));
                }
                Ok(plain(value))
            }
        }
    }

    /// Reads the lines of a `|` or `>` block scalar. `|` keeps line breaks and `>` folds them
    /// into spaces; a `-` in the header drops the final line break.
    fn block_scalar(&mut self, header: &str, parent: isize) -> String {
        let mut lines = Vec::new();
        while let Some(next) = self.continuation(parent) {
            lines.push(next);
        }
        let Some(base) = lines.iter().map(|line| line.indent).min() else {
            return String::new();
        };
        let separator = if header.starts_with('|') { "\n" } else { " " };
        let mut text = lines
            .iter()
            .map(|line| format!("{}{}", " ".repeat(line.indent - base), line.text))
            .collect::<Vec<_>>()
            .join(separator);
        if !header.contains('-') {
            text.push('\n');
        }
        text
    }

    /// Takes the next line when it is indented deeper than `parent`.
    fn continuation(&mut self, parent: isize) -> Option<Line<'a>> {
        let next = self.lines.get(self.pos).copied()?;
        if next.indent as isize > parent {
            self.pos += 1;
            Some(next)
        } else {
            None
        }
    }
}

/// Whether a line's text starts a block sequence item.
fn is_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

/// Splits `key: rest` into the key and the text after the colon, or `None` when the text is not
/// a mapping entry. A quoted key may hold any character; a plain key ends at the first colon that
/// is followed by a space or ends the line, so `acorn-jsx@5.3.2(acorn@8.18.0):` is a key while
/// `https://example.com` is not.
fn split_key(text: &str) -> Option<(String, &str)> {
    let bytes = text.as_bytes();
    match bytes.first()? {
        b'"' | b'\'' => {
            let (key, end) = quoted(text, 0)?;
            let rest = text[end..].trim_start_matches(' ').strip_prefix(':')?;
            if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') {
                Some((key, rest.trim_start()))
            } else {
                None
            }
        }
        b'{' | b'[' | b'#' | b'&' | b'*' | b'!' | b'|' | b'>' => None,
        _ if is_item(text) => None,
        _ => {
            let mut from = 0;
            while let Some(offset) = text[from..].find(':') {
                let at = from + offset;
                if matches!(bytes.get(at + 1), None | Some(b' ' | b'\t')) {
                    let key = text[..at].trim_end();
                    if key.contains(" #") {
                        return None;
                    }
                    return Some((key.to_owned(), text[at + 1..].trim_start()));
                }
                from = at + 1;
            }
            None
        }
    }
}

/// A plain scalar's value: `null`, `~` and nothing read as [`Yaml::Null`], anything else as text.
fn plain(text: String) -> Yaml {
    match text.as_str() {
        "" | "~" | "null" | "Null" | "NULL" => Yaml::Null,
        _ => Yaml::Scalar(text),
    }
}

/// Removes a trailing comment: a `#` at the start or after whitespace, outside quotes. A quote
/// opens a quoted scalar only where one can start (at the start, or after whitespace, `[`, `{` or
/// `,`), so the apostrophe in `it's` opens nothing.
fn strip_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut quote: Option<u8> = None;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(b'"') => {
                if byte == b'\\' {
                    index += 1;
                } else if byte == b'"' {
                    quote = None;
                }
            }
            Some(_) => {
                if byte == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') {
                        index += 1;
                    } else {
                        quote = None;
                    }
                }
            }
            None => {
                let after_space = index == 0 || matches!(bytes[index - 1], b' ' | b'\t');
                if byte == b'#' && after_space {
                    return text[..index].trim_end();
                }
                let can_open = after_space || matches!(bytes[index - 1], b'[' | b'{' | b',');
                if (byte == b'"' || byte == b'\'') && can_open {
                    quote = Some(byte);
                }
            }
        }
        index += 1;
    }
    text.trim_end()
}

/// Whether every bracket a flow collection opens is closed, outside quotes.
fn flow_closed(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' | b'\'' => match quoted(text, index) {
                Some((_, end)) => {
                    index = end;
                    continue;
                }
                None => return false,
            },
            b'[' | b'{' => depth += 1,
            b']' | b'}' => depth -= 1,
            _ => {}
        }
        index += 1;
    }
    depth <= 0
}

/// Reads a single or double quoted scalar that starts at byte `start` of `text`, returning its
/// value and the byte just past the closing quote, or `None` when it is not closed. Single quotes
/// escape a quote by doubling it; double quotes take backslash escapes, and an escape this reader
/// does not know is kept as written.
pub(super) fn quoted(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut index = start + 1;
    if bytes[start] == b'\'' {
        loop {
            let offset = text[index..].find('\'')?;
            out.push_str(&text[index..index + offset]);
            index += offset + 1;
            if bytes.get(index) == Some(&b'\'') {
                out.push('\'');
                index += 1;
            } else {
                return Some((out, index));
            }
        }
    }
    loop {
        let offset = text[index..].find(['"', '\\'])?;
        out.push_str(&text[index..index + offset]);
        index += offset;
        if bytes[index] == b'"' {
            return Some((out, index + 1));
        }
        let escape = text[index + 1..].chars().next()?;
        index += 1 + escape.len_utf8();
        let simple = match escape {
            'n' => Some('\n'),
            't' | '\t' => Some('\t'),
            'r' => Some('\r'),
            '0' => Some('\0'),
            'a' => Some('\u{7}'),
            'b' => Some('\u{8}'),
            'e' => Some('\u{1b}'),
            'f' => Some('\u{c}'),
            'v' => Some('\u{b}'),
            ' ' => Some(' '),
            '"' => Some('"'),
            '/' => Some('/'),
            '\\' => Some('\\'),
            'N' => Some('\u{85}'),
            '_' => Some('\u{a0}'),
            'L' => Some('\u{2028}'),
            'P' => Some('\u{2029}'),
            _ => None,
        };
        if let Some(character) = simple {
            out.push(character);
            continue;
        }
        let width = match escape {
            'x' => 2,
            'u' => 4,
            'U' => 8,
            _ => 0,
        };
        let code = text
            .get(index..index + width)
            .filter(|_| width > 0)
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .and_then(char::from_u32);
        match code {
            Some(character) => {
                out.push(character);
                index += width;
            }
            None => {
                out.push('\\');
                out.push(escape);
            }
        }
    }
}

/// Parses one flow collection or scalar that fills `text`.
fn parse_flow(text: &str) -> Result<Yaml, String> {
    let mut flow = Flow {
        text,
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = flow.value()?;
    flow.skip_space();
    if flow.at < flow.bytes.len() {
        return Err("has text after a flow collection".into());
    }
    Ok(value)
}

struct Flow<'s> {
    text: &'s str,
    bytes: &'s [u8],
    at: usize,
}

impl Flow<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.at += 1;
        }
    }

    fn value(&mut self) -> Result<Yaml, String> {
        self.skip_space();
        match self.peek() {
            Some(b'{') => self.mapping(),
            Some(b'[') => self.sequence(),
            Some(b'"' | b'\'') => Ok(Yaml::Scalar(self.quoted()?)),
            Some(b'&' | b'*' | b'!') => Err("anchors, aliases and tags are not supported".into()),
            _ => Ok(plain(self.plain(false).to_owned())),
        }
    }

    fn quoted(&mut self) -> Result<String, String> {
        let (value, end) = quoted(self.text, self.at)
            .ok_or("a quoted scalar in a flow collection is not closed")?;
        self.at = end;
        Ok(value)
    }

    /// Reads a plain scalar up to `,`, `]` or `}`; a key also ends at a colon followed by a space
    /// or a flow indicator.
    fn plain(&mut self, key: bool) -> &str {
        let start = self.at;
        while let Some(byte) = self.peek() {
            if matches!(byte, b',' | b']' | b'}') {
                break;
            }
            if key
                && byte == b':'
                && matches!(
                    self.bytes.get(self.at + 1),
                    None | Some(b' ' | b'\t' | b',' | b']' | b'}')
                )
            {
                break;
            }
            self.at += 1;
        }
        self.text[start..self.at].trim()
    }

    fn mapping(&mut self) -> Result<Yaml, String> {
        self.at += 1;
        let mut entries = Vec::new();
        loop {
            self.skip_space();
            match self.peek() {
                None => return Err("a flow mapping is not closed".into()),
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Yaml::Map(entries));
                }
                _ => {}
            }
            let key = match self.peek() {
                Some(b'"' | b'\'') => self.quoted()?,
                _ => self.plain(true).to_owned(),
            };
            self.skip_space();
            let value = if self.peek() == Some(b':') {
                self.at += 1;
                self.skip_space();
                if matches!(self.peek(), Some(b',' | b'}')) {
                    Yaml::Null
                } else {
                    self.value()?
                }
            } else {
                Yaml::Null
            };
            entries.push((key, value));
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {}
                _ => return Err("expected `,` or `}` in a flow mapping".into()),
            }
        }
    }

    fn sequence(&mut self) -> Result<Yaml, String> {
        self.at += 1;
        let mut items = Vec::new();
        loop {
            self.skip_space();
            match self.peek() {
                None => return Err("a flow sequence is not closed".into()),
                Some(b']') => {
                    self.at += 1;
                    return Ok(Yaml::Seq(items));
                }
                _ => {}
            }
            items.push(self.value()?);
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {}
                _ => return Err("expected `,` or `]` in a flow sequence".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(text: &str) -> Yaml {
        Yaml::Scalar(text.to_owned())
    }

    fn map(entries: &[(&str, Yaml)]) -> Yaml {
        Yaml::Map(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    fn one(text: &str) -> Yaml {
        let mut documents = parse(text).unwrap();
        assert_eq!(documents.len(), 1, "{documents:?}");
        documents.remove(0)
    }

    #[test]
    fn block_mappings_nest_and_keep_document_order() {
        let doc = one("b: 1\na:\n  c: x\n  d:\n    e: y\nz: '9.0'\n");
        assert_eq!(
            doc,
            map(&[
                ("b", scalar("1")),
                (
                    "a",
                    map(&[("c", scalar("x")), ("d", map(&[("e", scalar("y"))]))])
                ),
                ("z", scalar("9.0")),
            ])
        );
        assert_eq!(doc.get("a").and_then(|a| a.str_at("c")), Some("x"));
        assert_eq!(doc.str_at("missing"), None);
    }

    #[test]
    fn flow_collections_read_on_one_line() {
        let doc = one(concat!(
            "resolution: {integrity: sha512-AAA+/b==, tarball: https://r.example/a/-/a-1.0.0.tgz}\n",
            "cpu: [arm64]\n",
            "os: [darwin, '!win32']\n",
            "empty: {}\n",
            "none: []\n",
            "engines: {node: '>=18.*', npm: ^20.19.0 || >=22.12.0}\n",
            "nested: {a: [1, {b: c}], 'd:e': \"f\"}\n",
        ));
        assert_eq!(
            doc.get("resolution"),
            Some(&map(&[
                ("integrity", scalar("sha512-AAA+/b==")),
                ("tarball", scalar("https://r.example/a/-/a-1.0.0.tgz")),
            ]))
        );
        assert_eq!(doc.get("cpu"), Some(&Yaml::Seq(vec![scalar("arm64")])));
        assert_eq!(
            doc.get("os"),
            Some(&Yaml::Seq(vec![scalar("darwin"), scalar("!win32")]))
        );
        assert_eq!(doc.get("empty"), Some(&Yaml::Map(vec![])));
        assert_eq!(doc.get("none"), Some(&Yaml::Seq(vec![])));
        assert_eq!(
            doc.get("engines").and_then(|e| e.str_at("npm")),
            Some("^20.19.0 || >=22.12.0")
        );
        assert_eq!(
            doc.get("nested"),
            Some(&map(&[
                (
                    "a",
                    Yaml::Seq(vec![scalar("1"), map(&[("b", scalar("c"))])])
                ),
                ("d:e", scalar("f")),
            ]))
        );
    }

    #[test]
    fn a_flow_collection_may_continue_on_deeper_lines() {
        let doc = one("a: {x: 1,\n  y: [2,\n    3]}\nb: 4\n");
        assert_eq!(
            doc.get("a"),
            Some(&map(&[
                ("x", scalar("1")),
                ("y", Yaml::Seq(vec![scalar("2"), scalar("3")])),
            ]))
        );
        assert_eq!(doc.str_at("b"), Some("4"));
    }

    #[test]
    fn quoted_keys_may_hold_colons_ats_commas_and_parentheses() {
        let doc = one(concat!(
            "'@babel/core@7.0.0(supports-color@8.1.1)':\n",
            "  x: 1\n",
            "\"lodash@npm:^4.17.21, lodash@npm:^4.17.4\":\n",
            "  resolution: \"lodash@npm:4.17.21\"\n",
            "acorn-jsx@5.3.2(acorn@8.18.0):\n",
            "  y: 2\n",
            "'it''s': \"tab\\there \\\"q\\\" \\u00e9 \\x41\"\n",
        ));
        let keys: Vec<&str> = doc.entries().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "@babel/core@7.0.0(supports-color@8.1.1)",
                "lodash@npm:^4.17.21, lodash@npm:^4.17.4",
                "acorn-jsx@5.3.2(acorn@8.18.0)",
                "it's",
            ]
        );
        assert_eq!(
            doc.get("lodash@npm:^4.17.21, lodash@npm:^4.17.4")
                .and_then(|e| e.str_at("resolution")),
            Some("lodash@npm:4.17.21")
        );
        assert_eq!(doc.str_at("it's"), Some("tab\there \"q\" \u{e9} A"));
    }

    #[test]
    fn comments_are_dropped_but_hashes_inside_values_stay() {
        let doc = one(concat!(
            "# a leading comment\n",
            "a: 1 # trailing\n",
            "  # an indented comment line\n",
            "b: \"x # not a comment\" # a comment\n",
            "c: it's here # gone\n",
            "d: https://h.example/p#frag\n",
            "e: 'a''b # still quoted' # gone\n",
        ));
        assert_eq!(doc.str_at("a"), Some("1"));
        assert_eq!(doc.str_at("b"), Some("x # not a comment"));
        assert_eq!(doc.str_at("c"), Some("it's here"));
        assert_eq!(doc.str_at("d"), Some("https://h.example/p#frag"));
        assert_eq!(doc.str_at("e"), Some("a'b # still quoted"));
    }

    #[test]
    fn documents_split_on_separators() {
        let documents = parse("---\na: 1\n\n---\nb: 2\n...\n").unwrap();
        assert_eq!(
            documents,
            vec![map(&[("a", scalar("1"))]), map(&[("b", scalar("2"))])]
        );
        assert_eq!(parse("a: 1\n---\n").unwrap().len(), 2);
        assert_eq!(parse("a: 1\n---\n").unwrap()[1], Yaml::Null);
        assert!(parse("").unwrap().is_empty());
        assert!(parse("# only a comment\n").unwrap().is_empty());
    }

    #[test]
    fn block_sequences_hold_scalars_and_mappings() {
        let doc = one(concat!(
            "list:\n",
            "  - a\n",
            "  - k: v\n",
            "    j: w\n",
            "  - - inner\n",
            "    - more\n",
            "same:\n",
            "- x\n",
            "- y\n",
            "after: z\n",
        ));
        assert_eq!(
            doc.get("list"),
            Some(&Yaml::Seq(vec![
                scalar("a"),
                map(&[("k", scalar("v")), ("j", scalar("w"))]),
                Yaml::Seq(vec![scalar("inner"), scalar("more")]),
            ]))
        );
        assert_eq!(
            doc.get("same"),
            Some(&Yaml::Seq(vec![scalar("x"), scalar("y")]))
        );
        assert_eq!(doc.str_at("after"), Some("z"));
    }

    #[test]
    fn empty_values_and_nulls() {
        let doc = one("a:\nb: ~\nc: null\nd: 'null'\ne:\n");
        assert_eq!(doc.get("a"), Some(&Yaml::Null));
        assert_eq!(doc.get("b"), Some(&Yaml::Null));
        assert_eq!(doc.get("c"), Some(&Yaml::Null));
        assert_eq!(doc.str_at("d"), Some("null"));
        assert_eq!(doc.get("e"), Some(&Yaml::Null));
        assert!(doc.get("a").unwrap().entries().is_empty());
    }

    #[test]
    fn block_scalars_are_tolerated() {
        let doc = one("a: |\n  line one\n    indented\nb: >-\n  folded\n  text\nc: 1\n");
        assert_eq!(doc.str_at("a"), Some("line one\n  indented\n"));
        assert_eq!(doc.str_at("b"), Some("folded text"));
        assert_eq!(doc.str_at("c"), Some("1"));
    }

    #[test]
    fn plain_scalars_fold_onto_deeper_lines() {
        let doc = one("deprecated: this package is\n  no longer supported\nnext: 1\n");
        assert_eq!(
            doc.str_at("deprecated"),
            Some("this package is no longer supported")
        );
        assert_eq!(doc.str_at("next"), Some("1"));
    }

    #[test]
    fn malformed_input_is_an_error_naming_the_line() {
        let err = parse("a:\n  b: 1\n c: 2\n").unwrap_err();
        assert!(err.starts_with("line 3:"), "{err}");
        let err = parse("a: {b: 1\n").unwrap_err();
        assert!(err.contains("not closed"), "{err}");
        let err = parse("a: 'open\n").unwrap_err();
        assert!(err.contains("not closed"), "{err}");
        let err = parse("a: &anchor 1\n").unwrap_err();
        assert!(err.contains("anchors"), "{err}");
        let err = parse("a: 1\n\tb: 2\n").unwrap_err();
        assert!(err.contains("tab"), "{err}");
        let err = parse("key: value\njust text\n").unwrap_err();
        assert!(err.starts_with("line 2:"), "{err}");
    }

    #[test]
    fn a_large_lock_shaped_document_parses_quickly() {
        let mut text = String::from("lockfileVersion: '9.0'\n\npackages:\n\n");
        for index in 0..20_000 {
            text.push_str(&format!(
                "  '@scope/pkg-{index}@1.0.{index}':\n    resolution: {{integrity: sha512-abc{index}==}}\n    cpu: [x64]\n\n"
            ));
        }
        let started = std::time::Instant::now();
        let doc = one(&text);
        assert_eq!(doc.get("packages").unwrap().entries().len(), 20_000);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
