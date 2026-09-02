// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A one-token spelling of the qualifiers `kin impact` and `kin trace` take as
//! flags.
//!
//! `kin context A B C` takes several entities on one line, so it has nowhere to
//! put a per-entity `--file`. This module is the suffix form of the same thing:
//! the name, then any of `@path`, `@path:line` and `#Kind`, parsed into the
//! [`IdentityQualifiers`] the flags fill. One resolver serves both spellings,
//! and a pin means the same thing whichever way it was typed.
//!
//! `line` is not an [`IdentityQualifiers`] field, because a line is not an
//! identity: two entities in one file are told apart by their spans rather than
//! by a value the graph stores. It is applied after the qualifiers, and only
//! when it selects something, so a line that lands between entities narrows
//! nothing rather than emptying the answer.

use kin_model::Entity;

use crate::entity_identity::IdentityQualifiers;

/// A parsed entity reference: the bare name, its qualifiers, and any line.
///
/// No `PartialEq`: [`IdentityQualifiers`] carries none, and adding one there to
/// satisfy a test here would widen a shared type for this module's convenience.
/// The tests compare the fields they are about.
#[derive(Debug, Clone, Default)]
pub struct EntityRef {
    /// The symbol as typed, with every suffix removed.
    pub name: String,
    pub qualifiers: IdentityQualifiers,
    /// The line from `@path:line`, applied to spans rather than to identity.
    pub line: Option<u32>,
}

impl EntityRef {
    /// Whether the caller pinned anything.
    pub fn is_pinned(&self) -> bool {
        !self.qualifiers.is_empty() || self.line.is_some()
    }

    /// How the pin reads back, in the spelling that was typed.
    ///
    /// The values come from the qualifiers themselves, which
    /// [`crate::entity_identity::apply_qualifiers`] compares against
    /// `StableEntityIdentity`, so a pin printed here is a pin that resolves.
    pub fn pin_note(&self) -> Option<String> {
        if !self.is_pinned() {
            return None;
        }
        let mut note = String::new();
        if let Some(kind) = self.qualifiers.kind.as_deref() {
            note.push_str(&format!("kind {kind}"));
        }
        if let Some(file) = self.qualifiers.file.as_deref() {
            if !note.is_empty() {
                note.push_str(" in ");
            }
            note.push_str(file);
            if let Some(line) = self.line {
                note.push_str(&format!(":{line}"));
            }
        }
        Some(note)
    }
}

/// Split `Name#Kind@path:line` into its parts.
///
/// Only a trailing run of digits after the last colon reads as a line, so a path
/// carrying a colon of its own is not silently truncated. Nothing here touches
/// the filesystem: every part is matched against graph-owned entity records.
pub fn parse_entity_ref(token: &str) -> EntityRef {
    let token = token.trim();
    let (head, location) = match token.split_once('@') {
        Some((head, location)) => (head, Some(location)),
        None => (token, None),
    };
    let (name, kind) = match head.split_once('#') {
        Some((name, kind)) if !kind.is_empty() => (name, Some(kind.to_string())),
        _ => (head, None),
    };
    let (file, line) = match location {
        None => (None, None),
        Some(location) => match location.rsplit_once(':') {
            Some((file, digits))
                if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) =>
            {
                (Some(file.to_string()), digits.parse::<u32>().ok())
            }
            _ => (Some(location.to_string()), None),
        },
    };
    EntityRef {
        name: name.to_string(),
        qualifiers: IdentityQualifiers {
            file,
            kind,
            signature: None,
        },
        line,
    }
}

/// Narrow `matches` to the entity whose span contains `line`.
///
/// A no-op when nothing contains it. A line is a convenience for pointing at a
/// twin, not a claim about identity, so one that lands between two entities, or
/// in a file whose spans the graph does not carry, leaves the caller with the
/// answer the rest of the pin already earned rather than with nothing.
pub fn apply_line(matches: &mut Vec<Entity>, line: Option<u32>) {
    let Some(line) = line else { return };
    let containing: Vec<Entity> = matches
        .iter()
        .filter(|entity| {
            entity
                .span
                .as_ref()
                .is_some_and(|span| line >= span.start_line && line <= span.end_line)
        })
        .cloned()
        .collect();
    if !containing.is_empty() {
        *matches = containing;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_name_pins_nothing() {
        let reference = parse_entity_ref("TextModel");
        assert_eq!(reference.name, "TextModel");
        assert!(!reference.is_pinned());
        assert!(reference.qualifiers.is_empty());
    }

    #[test]
    fn a_file_pin_fills_the_file_qualifier() {
        let reference = parse_entity_ref("TextModel@src/model.ts");
        assert_eq!(reference.name, "TextModel");
        assert_eq!(reference.qualifiers.file.as_deref(), Some("src/model.ts"));
        assert_eq!(reference.line, None);
    }

    #[test]
    fn a_line_pin_is_kept_apart_from_the_qualifiers() {
        let reference = parse_entity_ref("TextModel@src/model.ts:41");
        assert_eq!(reference.qualifiers.file.as_deref(), Some("src/model.ts"));
        assert_eq!(reference.line, Some(41));
    }

    #[test]
    fn a_kind_pin_fills_the_kind_qualifier_beside_a_file() {
        let reference = parse_entity_ref("TextModel#class@src/model.ts:41");
        assert_eq!(reference.name, "TextModel");
        assert_eq!(reference.qualifiers.kind.as_deref(), Some("class"));
        assert_eq!(reference.qualifiers.file.as_deref(), Some("src/model.ts"));
        assert_eq!(reference.line, Some(41));
    }

    /// A colon that is not a line number belongs to the path.
    #[test]
    fn a_path_colon_is_not_read_as_a_line() {
        let reference = parse_entity_ref("Model@weird:dir/model.ts");
        assert_eq!(
            reference.qualifiers.file.as_deref(),
            Some("weird:dir/model.ts")
        );
        assert_eq!(reference.line, None);
    }

    #[test]
    fn a_qualified_name_without_pins_is_left_alone() {
        let reference = parse_entity_ref("std::collections::HashMap");
        assert_eq!(reference.name, "std::collections::HashMap");
        assert!(!reference.is_pinned());
    }

    /// The pin reads back in the spelling that resolves it, because the values
    /// are the qualifier values `apply_qualifiers` compares.
    #[test]
    fn the_pin_note_names_what_was_pinned() {
        assert_eq!(parse_entity_ref("A").pin_note(), None);
        assert_eq!(
            parse_entity_ref("A@src/a.rs").pin_note().as_deref(),
            Some("src/a.rs")
        );
        assert_eq!(
            parse_entity_ref("A@src/a.rs:9").pin_note().as_deref(),
            Some("src/a.rs:9")
        );
        assert_eq!(
            parse_entity_ref("A#function@src/a.rs")
                .pin_note()
                .as_deref(),
            Some("kind function in src/a.rs")
        );
    }
}
