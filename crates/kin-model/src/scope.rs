// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The namespace an entity lives in.
//!
//! A file path is where an entity's bytes happen to sit. A namespace is what
//! the language calls the region the entity belongs to, and it is what another
//! entity writes when it names this one. `queue/models.py` is a path;
//! `queue.models` is what an importer types. The two agree today only because
//! nothing has moved yet.
//!
//! This is the type that lets a query group by region without grouping by path.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An entity's namespace, as the ordered segments that name it.
///
/// Segments, not a rendered string, because the separator is a language's
/// spelling and not part of the identity: `queue.models`, `queue::models` and
/// `queue\models` are one value here. Holding the string instead makes a prefix
/// test textual, and a textual prefix answers `queue` with everything in
/// `queue_internal`, which is a wrong answer that looks right.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
#[schemars(with = "Vec<String>")]
pub struct ScopePath {
    segments: Vec<String>,
}

/// Why a `Vec<String>` is not a scope path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopePathError {
    /// A scope with no segments names nothing, and would be a prefix of every
    /// other scope, so every query would answer with the whole repository.
    Empty,
    /// A segment that is empty or blank comes from a separator run such as
    /// `a..b`, and keeping it would make `a..b` and `a.b` different scopes for
    /// the same region.
    BlankSegment,
}

impl fmt::Display for ScopePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "a scope path needs at least one segment"),
            Self::BlankSegment => write!(f, "a scope path segment cannot be blank"),
        }
    }
}

impl std::error::Error for ScopePathError {}

impl ScopePath {
    /// The scope naming these segments, or why they do not name one.
    pub fn new<I, S>(segments: I) -> Result<Self, ScopePathError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let segments: Vec<String> = segments.into_iter().map(Into::into).collect();
        if segments.is_empty() {
            return Err(ScopePathError::Empty);
        }
        if segments.iter().any(|segment| segment.trim().is_empty()) {
            return Err(ScopePathError::BlankSegment);
        }
        Ok(Self { segments })
    }

    /// The scope a written path names, taking `.`, `::`, `/` and `\` as
    /// separators and dropping empty runs between them.
    ///
    /// All four appear in the languages Kin reads: Python and Java write `.`,
    /// Rust and C++ write `::`, PHP writes `\`, and a module specifier written
    /// in an import writes `/`. They are spellings of one structure, so they
    /// parse to one value, and a caller that has segments already should call
    /// [`ScopePath::new`] rather than render and reparse them.
    pub fn parse(text: &str) -> Result<Self, ScopePathError> {
        let segments: Vec<String> = text
            .replace("::", ".")
            .split(['.', '/', '\\'])
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(str::to_string)
            .collect();
        Self::new(segments)
    }

    /// The ordered segments, outermost first.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// How many segments deep this scope is. Never zero.
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// Whether this scope is `prefix` or lives inside it.
    ///
    /// Segment-wise, so `queue` holds `queue.models` and does not hold
    /// `queue_internal.models`.
    pub fn is_within(&self, prefix: &Self) -> bool {
        self.segments.len() >= prefix.segments.len()
            && self
                .segments
                .iter()
                .zip(prefix.segments.iter())
                .all(|(mine, theirs)| mine == theirs)
    }

    /// This scope with one more segment inside it.
    pub fn child(&self, segment: impl Into<String>) -> Result<Self, ScopePathError> {
        let mut segments = self.segments.clone();
        segments.push(segment.into());
        Self::new(segments)
    }
}

impl TryFrom<Vec<String>> for ScopePath {
    type Error = ScopePathError;

    fn try_from(segments: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(segments)
    }
}

impl From<ScopePath> for Vec<String> {
    fn from(path: ScopePath) -> Self {
        path.segments
    }
}

/// Rendered with `.`, which is the spelling most of the languages use and the
/// one every surface already prints. The value is the segments; this is display.
impl fmt::Display for ScopePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.segments.join("."))
    }
}

/// Why an entity has no namespace, when it genuinely has none.
///
/// Separate from [`EntityScope::NotComputed`] on purpose. "This language has no
/// namespaces" and "nobody has looked yet" are different facts, and a query that
/// treats them alike either hides a gap or refuses forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeAbsence {
    /// The language has no namespace at this level. C, HCL and Swift: C has
    /// none, HCL has blocks rather than namespaces, and a Swift module is a
    /// build-target property that no source file declares.
    LanguageHasNone,
    /// The entity has no file origin, so no layout can name a region for it.
    /// Graph-created entities before placement are the case.
    NoFileOrigin,
    /// The file's path carries no segment that names a module. A root-level
    /// `index.ts` is the case: `require('.')` names the repository, not a module.
    PathNamesNoModule,
}

impl fmt::Display for ScopeAbsence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LanguageHasNone => write!(f, "the language has no namespace at this level"),
            Self::NoFileOrigin => write!(f, "the entity has no file origin"),
            Self::PathNamesNoModule => write!(f, "the path names no module"),
        }
    }
}

/// The namespace an entity lives in, or the reason it has none, or the fact
/// that nobody has computed one.
///
/// Three states rather than an `Option`, and the third is the one that matters.
/// A store written before scopes existed holds entities with no scope, and an
/// `Option` would report those as "no namespace", which is the same answer a C
/// file gives. A query would then narrow silently on a store nobody has
/// backfilled and report an empty region as an empty region. `NotComputed` makes
/// that state nameable, so the query refuses instead and says how many entities
/// it is waiting on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityScope {
    /// The namespace this entity lives in.
    Known(ScopePath),
    /// The entity has no namespace, for the reason given.
    None(ScopeAbsence),
    /// Nobody has computed a scope for this entity yet.
    NotComputed,
}

/// `NotComputed`, so a record written before this field existed reads as
/// uncomputed rather than as scopeless.
impl Default for EntityScope {
    fn default() -> Self {
        Self::NotComputed
    }
}

impl EntityScope {
    /// The scope path, when one is known.
    pub fn path(&self) -> Option<&ScopePath> {
        match self {
            Self::Known(path) => Some(path),
            Self::None(_) | Self::NotComputed => std::option::Option::None,
        }
    }

    /// Whether a query may rely on this entity's scope being settled.
    pub fn is_computed(&self) -> bool {
        !matches!(self, Self::NotComputed)
    }
}

impl fmt::Display for EntityScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(path) => write!(f, "{path}"),
            Self::None(reason) => write!(f, "none ({reason})"),
            Self::NotComputed => write!(f, "not computed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_match_is_segment_wise_and_not_textual() {
        let queue = ScopePath::parse("queue").unwrap();
        let models = ScopePath::parse("queue.models").unwrap();
        let internal = ScopePath::parse("queue_internal.models").unwrap();

        assert!(models.is_within(&queue), "queue.models lives in queue");
        assert!(queue.is_within(&queue), "a scope is within itself");
        assert!(
            !internal.is_within(&queue),
            "queue_internal is a different region, and a textual prefix would say otherwise"
        );
        assert!(
            !queue.is_within(&models),
            "a parent does not live inside its child"
        );
    }

    #[test]
    fn the_four_separators_parse_to_one_value() {
        let expected = ScopePath::new(["queue", "models"]).unwrap();
        for spelling in [
            "queue.models",
            "queue::models",
            "queue/models",
            "queue\\models",
        ] {
            assert_eq!(
                ScopePath::parse(spelling).unwrap(),
                expected,
                "{spelling} names the same region"
            );
        }
    }

    #[test]
    fn a_path_that_names_nothing_is_refused() {
        assert_eq!(ScopePath::parse(""), Err(ScopePathError::Empty));
        assert_eq!(ScopePath::parse("..."), Err(ScopePathError::Empty));
        assert_eq!(
            ScopePath::new(Vec::<String>::new()),
            Err(ScopePathError::Empty)
        );
        assert_eq!(
            ScopePath::new(["queue", " "]),
            Err(ScopePathError::BlankSegment)
        );
    }

    #[test]
    fn a_separator_run_does_not_make_a_second_region() {
        assert_eq!(
            ScopePath::parse("queue..models").unwrap(),
            ScopePath::parse("queue.models").unwrap()
        );
        assert_eq!(
            ScopePath::parse("/queue/models/").unwrap(),
            ScopePath::parse("queue.models").unwrap()
        );
    }

    #[test]
    fn display_renders_with_dots_whatever_it_was_parsed_from() {
        assert_eq!(
            ScopePath::parse("queue::models").unwrap().to_string(),
            "queue.models"
        );
        assert_eq!(
            ScopePath::parse("App\\Http").unwrap().to_string(),
            "App.Http"
        );
    }

    #[test]
    fn an_unwritten_scope_reads_as_uncomputed_and_not_as_scopeless() {
        let default = EntityScope::default();
        assert_eq!(default, EntityScope::NotComputed);
        assert!(!default.is_computed());
        assert!(default.path().is_none());
        assert!(
            EntityScope::None(ScopeAbsence::LanguageHasNone).is_computed(),
            "a language with no namespaces has a settled answer"
        );
    }

    #[test]
    fn a_scope_round_trips_through_its_persisted_shape() {
        let scope = EntityScope::Known(ScopePath::parse("queue::models").unwrap());
        let json = serde_json::to_string(&scope).unwrap();
        assert_eq!(
            serde_json::from_str::<EntityScope>(&json).unwrap(),
            scope,
            "the persisted shape is the segments, not the rendering"
        );
        assert!(
            json.contains("[\"queue\",\"models\"]"),
            "segments are persisted, got {json}"
        );
    }

    #[test]
    fn a_persisted_scope_with_a_blank_segment_is_refused_rather_than_loaded() {
        let refused = serde_json::from_str::<ScopePath>("[\"queue\",\"\"]");
        assert!(
            refused.is_err(),
            "a blank segment would make two spellings of one region"
        );
    }

    #[test]
    fn a_child_extends_the_region_it_was_built_from() {
        let queue = ScopePath::parse("queue").unwrap();
        let models = queue.child("models").unwrap();
        assert_eq!(models.segments(), ["queue", "models"]);
        assert_eq!(models.depth(), 2);
        assert!(models.is_within(&queue));
        assert_eq!(queue.child(" "), Err(ScopePathError::BlankSegment));
    }
}
