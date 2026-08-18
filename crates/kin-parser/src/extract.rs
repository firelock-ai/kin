// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, LanguageId, ParseState,
    RelationKind, SemanticFingerprint, SourceSpan, Visibility,
};
use serde::{Deserialize, Serialize};

pub const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";
pub const COMMAND_EFFECT_CONTRACT_KEY: &str = "command_effect_contract";
pub const FILE_IMPORT_CONTEXT_KEY: &str = "file_import_context";
pub const FILE_SURFACE_CONTEXT_KEY: &str = "file_surface_context";

/// Call sites the parser read in this entity's file, before any resolution.
///
/// The denominator of reference-edge completeness. Extraction already knows it
/// and previously dropped it, so a graph could hold a fifth of its call edges
/// with no surface able to say so.
pub const FILE_PARSED_CALL_SITES_KEY: &str = "file_parsed_call_sites";

/// Import statements the parser read in this entity's file, before resolution.
pub const FILE_PARSED_IMPORT_STATEMENTS_KEY: &str = "file_parsed_import_statements";

/// Of those import statements, how many name a module this repository cannot
/// own, so no resolver could have produced an in-repo target for them.
///
/// Recorded only for the languages where the specifier alone settles it. In
/// ECMAScript a specifier that does not begin with `.`, `/` or `#` is a bare
/// package specifier, which names a dependency rather than a path. Everywhere
/// else the same syntax can name an in-repo module, so the key is absent and a
/// reader treats it as unmeasured rather than as zero.
pub const FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY: &str = "file_parsed_external_module_imports";

/// Reserved parser-to-linker control record: at least one source-level call in
/// this file could not be represented with a statically proven named target.
/// This includes wholly unrepresentable callees and receiver calls whose leaf
/// name is retained for recall but whose owning type is unknown. The record is
/// carried through the existing raw-relation seam so published `ParseOutput`
/// and linker input structs remain source compatible. Linkers consume it as
/// negative call-coverage evidence and never materialize it as a graph relation.
pub const CALL_EXTRACTION_INCOMPLETE_MARKER_V1: &str =
    "kin-internal://call-extraction-coverage/incomplete-v1";

/// Raw extracted entity before ID assignment.
#[derive(Debug, Clone)]
pub struct ExtractedEntity {
    pub kind: EntityKind,
    pub name: String,
    pub signature: String,
    pub visibility: Visibility,
    pub doc_summary: Option<String>,
    pub fingerprint: SemanticFingerprint,
    pub span: SourceSpan,
}

impl ExtractedEntity {
    /// Convert to a full Entity with a new ID.
    pub fn into_entity(self, language: LanguageId, file_id: &FilePathId) -> Entity {
        self.into_entity_with_source(language, file_id, None)
    }

    /// Convert to a full Entity with optional source bytes for richer metadata.
    pub fn into_entity_with_source(
        self,
        language: LanguageId,
        file_id: &FilePathId,
        source: Option<&[u8]>,
    ) -> Entity {
        let mut metadata = EntityMetadata::default();
        if let Some(preview) = source.and_then(|src| embedding_body_preview(src, &self.span)) {
            metadata.extra.insert(
                EMBEDDING_BODY_PREVIEW_KEY.into(),
                serde_json::Value::String(preview),
            );
        }
        let entity_id = EntityId::from_content(
            &file_id.0,
            &self.name,
            &format!("{:?}", self.kind),
            self.span.start_line,
        );
        Entity {
            id: entity_id,
            kind: self.kind,
            name: self.name,
            language,
            fingerprint: self.fingerprint,
            file_origin: Some(file_id.clone()),
            span: Some(self.span),
            signature: self.signature,
            visibility: self.visibility,
            role: EntityRole::Source,
            doc_summary: self.doc_summary,
            metadata,
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }
}

fn embedding_body_preview(source: &[u8], span: &SourceSpan) -> Option<String> {
    let start = span.start_byte.min(source.len());
    let end = span.end_byte.min(source.len());
    if start >= end {
        return None;
    }

    let raw = String::from_utf8_lossy(&source[start..end]);
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    const MAX_CHARS: usize = 8000;
    let total_chars = collapsed.chars().count();
    let preview = if total_chars > MAX_CHARS {
        summarize_long_body(&collapsed, total_chars)
    } else {
        collapsed
    };

    Some(preview)
}

fn summarize_long_body(text: &str, total_chars: usize) -> String {
    const HEAD_CHARS: usize = 3000;
    const MID_CHARS: usize = 2000;
    const TAIL_CHARS: usize = 3000;
    const GAP: &str = " ... ";

    if total_chars <= HEAD_CHARS + TAIL_CHARS + 40 {
        let head = take_prefix_chars(text, HEAD_CHARS);
        let tail = take_suffix_chars(text, TAIL_CHARS);
        return format!("{head}{GAP}{tail}");
    }

    let head = take_prefix_chars(text, HEAD_CHARS);
    let mid_start = total_chars.saturating_sub(MID_CHARS) / 2;
    let middle = take_char_range(text, mid_start, mid_start + MID_CHARS);
    let tail = take_suffix_chars(text, TAIL_CHARS);
    format!("{head}{GAP}{middle}{GAP}{tail}")
}

fn take_prefix_chars(text: &str, count: usize) -> String {
    text.chars().take(count).collect()
}

fn take_suffix_chars(text: &str, count: usize) -> String {
    let total = text.chars().count();
    let start = total.saturating_sub(count);
    take_char_range(text, start, total)
}

fn take_char_range(text: &str, start: usize, end: usize) -> String {
    text.chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

/// The argument shape written at a call site, letting the linker bind an
/// overloaded callee by how it is called. Shared across language adapters: C++
/// records positional arity; Python-style adapters additionally record keyword
/// and splat shape. This is the canonical type for the parser -> linker seam; a
/// mirror is materialized at the storage boundary when a call edge is persisted.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallArgShape {
    /// Positional arguments at the call site (`f(a, b)` -> 2).
    pub positional: u32,
    /// Named-argument names used at the call site, sorted and deduped at
    /// construction. Always empty for C++ (no keyword arguments).
    pub keywords: Vec<String>,
    /// A positional pack/splat expansion is present (C++ `args...`, Python
    /// `*args`), so the positional count is a lower bound, not exact.
    pub has_var_positional: bool,
    /// A keyword splat is present (Python `**kwargs`); always false for C++.
    pub has_var_keyword: bool,
}

/// Where in the caller's file the syntax that produced a relation sits.
///
/// Byte offsets and 0-based line/column, exactly as tree-sitter reports them,
/// which is the same convention [`ExtractedEntity::span`] already carries. The
/// file is deliberately absent: a relation's site is always inside the file
/// being parsed, and the consumer that turns this into a
/// [`kin_model::SourceSpan`] is the one holding that path, so there is no way
/// for an adapter to attribute a site to the wrong file.
///
/// Adapters that do not record sites leave [`ExtractedRelation::site`] `None`,
/// and the edge is stored exactly as it was before, without a span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationSite {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

impl RelationSite {
    /// Pair this site with the file it was read from, giving the graph-model
    /// span the relation's evidence carries.
    pub fn to_source_span(&self, file: &FilePathId) -> SourceSpan {
        SourceSpan {
            file: file.clone(),
            start_byte: self.start_byte,
            end_byte: self.end_byte,
            start_line: self.start_line,
            start_col: self.start_col,
            end_line: self.end_line,
            end_col: self.end_col,
        }
    }
}

/// Raw extracted relation between two named entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractedRelation {
    pub kind: RelationKind,
    pub src_name: String,
    pub dst_name: String,
    /// For Calls/References edges, the module/package the target was imported from.
    /// e.g., `Some("requests")` for `from requests import get`,
    ///        `Some("kin_db")` for `use kin_db::InMemoryGraph`
    pub import_source: Option<String>,
    /// For a `Calls` edge, the call site's argument shape when the adapter
    /// records it. `None` means the adapter does not track it, so the linker
    /// binds shape-blind as before. Lets the linker keep an overloaded callee's
    /// argument-incompatible candidates out of the call's binding set instead of
    /// fanning out to every same-named overload.
    pub call_shape: Option<CallArgShape>,
    /// For a `Calls` edge written as an attribute/member call, the receiver
    /// expression exactly as it appears in source: `adapter` for
    /// `adapter.send(...)`, `os.environ` for `os.environ.get(...)`. `None`
    /// means the callee was a bare identifier (`helper(...)`), the receiver was
    /// pinned into `dst_name` already (`self.m()` arrives as `Class.m`), or the
    /// adapter does not record receivers.
    ///
    /// The linker needs this to tell a call through an object from a call
    /// through a module. Both arrive with the same bare leaf name, but only the
    /// module form can reach a module-level function, so discarding the
    /// receiver is what let a `proxies.get(...)` call site bind to the public
    /// `requests.get`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    /// Where in the file this relation's syntax sits, when the adapter records
    /// it. A `Calls` edge's site is its call expression; a `References` edge's
    /// is the identifier that read the name.
    ///
    /// This is what lets `find_references` answer "who calls this, and WHERE"
    /// instead of only "who calls this". Every producer of a relation's
    /// evidence sits downstream of the parser, so a site the adapter drops here
    /// cannot be recovered later: the seam carried no span field at all until
    /// FIR-1825, which is why `RelationEvidence::source_span` was populated by
    /// nothing in the fleet and every reference row came back with an empty
    /// `reference_lines`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<RelationSite>,
}

/// Construct the reserved negative call-extraction coverage record.
pub fn call_extraction_incomplete_marker() -> ExtractedRelation {
    ExtractedRelation {
        site: None,
        receiver: None,
        kind: RelationKind::DependsOn,
        src_name: String::new(),
        dst_name: CALL_EXTRACTION_INCOMPLETE_MARKER_V1.to_string(),
        import_source: None,
        call_shape: None,
    }
}

/// Whether a raw parser relation is the reserved negative call-coverage record.
pub fn is_call_extraction_incomplete_marker(relation: &ExtractedRelation) -> bool {
    relation.kind == RelationKind::DependsOn
        && relation.src_name.is_empty()
        && relation.dst_name == CALL_EXTRACTION_INCOMPLETE_MARKER_V1
        && relation.import_source.is_none()
        && relation.call_shape.is_none()
        && relation.receiver.is_none()
}

/// A single import declaration from source code.
///
/// Represents `import { foo, bar as baz } from './utils'` or
/// `from utils import foo` etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileImport {
    /// The module path as written in source (e.g., `"./utils"`, `"lodash"`, `"../lib"`).
    pub module_path: String,
    /// Individual names imported from this module.
    pub specifiers: Vec<ImportedName>,
}

/// A single imported name within an import declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedName {
    /// The name as used locally in this file.
    pub local_name: String,
    /// The original exported name if renamed (e.g., `foo` in `import { foo as bar }`).
    /// `None` if not renamed.
    pub original_name: Option<String>,
    /// Whether this is the default import.
    pub is_default: bool,
}

/// Attach file-level retrieval context to every entity emitted from the file.
///
/// This keeps retrieval graph-native: the graph still ranks entities, but those
/// entities carry normalized file-surface and import-surface context that would
/// otherwise be lost after parsing.
pub fn attach_file_context_metadata(
    entities: &mut [Entity],
    file_id: &FilePathId,
    imports: &[FileImport],
) {
    if entities.is_empty() {
        return;
    }

    let import_context = build_file_import_context(imports);
    let surface_context = build_file_surface_context(file_id);
    if import_context.is_none() && surface_context.is_none() {
        return;
    }

    for entity in entities {
        if let Some(ref import_context) = import_context {
            entity.metadata.extra.insert(
                FILE_IMPORT_CONTEXT_KEY.into(),
                serde_json::Value::String(import_context.clone()),
            );
        }
        if let Some(ref surface_context) = surface_context {
            entity.metadata.extra.insert(
                FILE_SURFACE_CONTEXT_KEY.into(),
                serde_json::Value::String(surface_context.clone()),
            );
        }
    }
}

/// Record, on every entity of the file, how many call sites and import
/// statements the parser read there.
///
/// This is the parse side of reference-edge completeness. It is written where
/// extraction already holds both numbers, so no surface has to re-parse to say
/// how much of the relation graph resolved. A file whose parser recovery
/// omitted calls records no call-site count rather than a count it cannot
/// stand behind, and a reader treats an absent count as unmeasured rather than
/// as zero.
pub fn attach_file_reference_parse_counts(
    entities: &mut [Entity],
    relations: &[ExtractedRelation],
    imports: &[FileImport],
) {
    if entities.is_empty() {
        return;
    }

    let call_extraction_complete = !relations.iter().any(is_call_extraction_incomplete_marker);
    let call_sites = relations
        .iter()
        .filter(|relation| relation.kind == RelationKind::Calls)
        .count();
    let import_statements = imports.len();
    let external_module_imports = imports
        .iter()
        .filter(|import| is_bare_package_specifier(&import.module_path))
        .count();

    for entity in entities {
        if call_extraction_complete {
            entity.metadata.extra.insert(
                FILE_PARSED_CALL_SITES_KEY.into(),
                serde_json::Value::from(call_sites),
            );
        } else {
            entity.metadata.extra.remove(FILE_PARSED_CALL_SITES_KEY);
        }
        entity.metadata.extra.insert(
            FILE_PARSED_IMPORT_STATEMENTS_KEY.into(),
            serde_json::Value::from(import_statements),
        );
        if specifier_syntax_settles_externality(entity.language) {
            entity.metadata.extra.insert(
                FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY.into(),
                serde_json::Value::from(external_module_imports),
            );
        } else {
            entity
                .metadata
                .extra
                .remove(FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY);
        }
    }
}

/// Whether a module specifier's own syntax says the module is outside the
/// repository, with no resolver run.
///
/// True only for the ECMAScript family. A Python `import os` and a Go
/// `import "fmt"` look exactly like an in-repo module of the same name, so
/// counting them would report a gap the specifier does not establish.
fn specifier_syntax_settles_externality(language: LanguageId) -> bool {
    matches!(language, LanguageId::JavaScript | LanguageId::TypeScript)
}

/// Whether an ECMAScript specifier names a package rather than a path.
///
/// `#`-prefixed subpath imports resolve through the importing package's own
/// manifest, so they name something the repository owns and are not bare.
fn is_bare_package_specifier(module_path: &str) -> bool {
    let specifier = module_path.trim();
    !specifier.is_empty()
        && !specifier.starts_with('.')
        && !specifier.starts_with('/')
        && !specifier.starts_with('#')
}

fn build_file_import_context(imports: &[FileImport]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for import in imports.iter().take(12) {
        let module_path = import.module_path.trim();
        if !module_path.is_empty() {
            push_context_part(&mut parts, &mut seen, format!("module {module_path}"));
            for form in expanded_search_forms(module_path) {
                push_context_part(&mut parts, &mut seen, format!("module {form}"));
            }
        }

        let mut names = Vec::new();
        let mut name_seen = std::collections::HashSet::new();
        for spec in import.specifiers.iter().take(8) {
            for candidate in
                std::iter::once(spec.local_name.as_str()).chain(spec.original_name.as_deref())
            {
                for form in expanded_search_forms(candidate) {
                    if name_seen.insert(form.clone()) {
                        names.push(form);
                    }
                }
            }
        }
        if !names.is_empty() {
            push_context_part(&mut parts, &mut seen, format!("names {}", names.join(" ")));
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn build_file_surface_context(file_id: &FilePathId) -> Option<String> {
    let path = file_id.to_string();
    let mut parts = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for component in meaningful_surface_components(&path) {
        for form in expanded_search_forms(component) {
            push_context_part(&mut parts, &mut seen, format!("surface {form}"));
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn meaningful_surface_components(path: &str) -> Vec<&str> {
    const NOISE: &[&str] = &[
        "src",
        "lib",
        "internal",
        "packages",
        "pkg",
        "crates",
        "cmd",
        "docs",
        "doc",
        "examples",
        "example",
        "tests",
        "test",
        "__tests__",
    ];

    let components: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if components.is_empty() {
        return Vec::new();
    }

    let filename = components.last().copied().unwrap_or(path);
    let stem = filename.split('.').next().unwrap_or(filename);
    let mut out = Vec::new();

    if stem != "index" && !NOISE.contains(&stem) {
        out.push(stem);
    }

    for component in components.iter().rev().skip(1) {
        if !NOISE.contains(component) {
            out.push(component);
        }
        if out.len() >= 4 {
            break;
        }
    }

    out
}

fn expanded_search_forms(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let normalized = trimmed
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
        .trim();
    if normalized.is_empty() {
        return out;
    }

    if seen.insert(normalized.to_string()) {
        out.push(normalized.to_string());
    }

    let de_path = normalized.replace(['@', '/', '-', '_', '.'], " ");
    let de_camel = decamelize(&de_path);
    let collapsed = de_camel.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() >= 3 && seen.insert(collapsed.clone()) {
        out.push(collapsed);
    }

    out
}

fn decamelize(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    let mut prev_is_lower_or_digit = false;
    for ch in input.chars() {
        let is_upper = ch.is_ascii_uppercase();
        if is_upper && prev_is_lower_or_digit && !out.ends_with(' ') {
            out.push(' ');
        }
        out.push(ch);
        prev_is_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    out
}

fn push_context_part(
    parts: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
    value: String,
) {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.len() >= 3 && seen.insert(normalized.clone()) {
        parts.push(normalized);
    }
}

/// A test function discovered during parsing.
#[derive(Debug, Clone)]
pub struct ExtractedTest {
    /// Name of the test function.
    pub name: String,
    /// The kind of test (unit, integration, etc.).
    pub kind: ExtractedTestKind,
    /// The runner framework (cargo, jest, pytest, go, junit).
    pub runner: String,
}

/// Classification of a discovered test function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractedTestKind {
    Unit,
    Integration,
}

/// Output of parsing a single file.
#[derive(Debug, Clone)]
pub struct ParseOutput {
    pub entities: Vec<ExtractedEntity>,
    pub relations: Vec<ExtractedRelation>,
    /// Detailed import declarations for cross-file resolution.
    pub imports: Vec<FileImport>,
    /// Test functions discovered in this file.
    pub tests: Vec<ExtractedTest>,
    pub parse_state: ParseState,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview_for(text: &str) -> String {
        let file = FilePathId::new("src/example.ts");
        let span = SourceSpan {
            file,
            start_byte: 0,
            end_byte: text.len(),
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: text.len() as u32,
        };
        embedding_body_preview(text.as_bytes(), &span).unwrap()
    }

    fn test_entity(path: &str) -> Entity {
        let file = FilePathId::new(path);
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "hydrate".into(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: kin_model::Hash256::from_bytes([0; 32]),
                signature_hash: kin_model::Hash256::from_bytes([1; 32]),
                behavior_hash: kin_model::Hash256::from_bytes([2; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file.clone()),
            span: Some(SourceSpan {
                file,
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: 1,
            }),
            signature: "function hydrate()".into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn body_preview_keeps_short_entity_bodies_intact() {
        let body = "function hydrate() { return mount(container); }";
        assert_eq!(preview_for(body), body);
    }

    #[test]
    fn body_preview_preserves_tail_signal_for_long_entities() {
        let long = format!(
            "{} TARGET_tail_marker {}",
            "prefix ".repeat(1500),
            "suffix ".repeat(1500)
        );
        let preview = preview_for(&long);
        assert!(preview.contains("prefix"));
        assert!(preview.contains("TARGET_tail_marker"));
        assert!(preview.contains("suffix"));
    }

    #[test]
    fn body_preview_preserves_middle_signal_for_long_entities() {
        let long = format!(
            "{} middle_marker {}",
            "alpha ".repeat(1500),
            "omega ".repeat(1500)
        );
        let preview = preview_for(&long);
        assert!(preview.contains("alpha"));
        assert!(preview.contains("middle_marker"));
        assert!(preview.contains("omega"));
    }

    #[test]
    fn attach_file_context_metadata_adds_import_and_surface_context() {
        let file_id = FilePathId::new("packages/runtime-dom/src/index.ts");
        let mut entities = vec![test_entity(&file_id.to_string())];
        let imports = vec![FileImport {
            module_path: "@vue/runtime-core".into(),
            specifiers: vec![ImportedName {
                local_name: "createHydrationRenderer".into(),
                original_name: None,
                is_default: false,
            }],
        }];

        attach_file_context_metadata(&mut entities, &file_id, &imports);

        let metadata = &entities[0].metadata.extra;
        let import_context = metadata
            .get(FILE_IMPORT_CONTEXT_KEY)
            .and_then(|value| value.as_str())
            .unwrap();
        let surface_context = metadata
            .get(FILE_SURFACE_CONTEXT_KEY)
            .and_then(|value| value.as_str())
            .unwrap();

        assert!(import_context.contains("@vue/runtime-core"));
        assert!(import_context.contains("create Hydration Renderer"));
        assert!(surface_context.contains("runtime-dom"));
        assert!(surface_context.contains("runtime dom"));
    }

    fn import(module_path: &str) -> FileImport {
        FileImport {
            module_path: module_path.to_string(),
            specifiers: Vec::new(),
        }
    }

    /// FIR-2440. Most of an ECMAScript repository's imports name packages it
    /// does not hold, so a resolved-over-parsed ratio reads as a defect unless
    /// the report says how many could never have resolved. The specifier alone
    /// settles it there: anything not starting with `.`, `/` or `#` is a bare
    /// package specifier.
    #[test]
    fn a_javascript_file_records_how_many_imports_name_a_package() {
        let mut entity = test_entity("lib/express.js");
        entity.language = LanguageId::JavaScript;
        let mut entities = vec![entity];
        let imports = [
            import("./application"),
            import("./router"),
            import("merge-descriptors"),
            import("body-parser"),
            import("@scope/thing"),
            import("#internal/shim"),
        ];
        attach_file_reference_parse_counts(&mut entities, &[], &imports);

        let extra = &entities[0].metadata.extra;
        assert_eq!(
            extra
                .get(FILE_PARSED_IMPORT_STATEMENTS_KEY)
                .and_then(|v| v.as_u64()),
            Some(6)
        );
        assert_eq!(
            extra
                .get(FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY)
                .and_then(|v| v.as_u64()),
            Some(3),
            "the two relative specifiers and the `#` subpath import name modules \
             this repository owns"
        );
    }

    /// A Python `import os` and a Go `import "fmt"` look exactly like an
    /// in-repo module of the same name, so the count is absent rather than
    /// zero: nothing looked, so nothing was found missing.
    #[test]
    fn a_language_whose_specifier_syntax_settles_nothing_records_no_external_count() {
        let mut entity = test_entity("app/parsing.py");
        entity.language = LanguageId::Python;
        let mut entities = vec![entity];
        attach_file_reference_parse_counts(&mut entities, &[], &[import("os"), import("helpers")]);

        let extra = &entities[0].metadata.extra;
        assert_eq!(
            extra
                .get(FILE_PARSED_IMPORT_STATEMENTS_KEY)
                .and_then(|v| v.as_u64()),
            Some(2)
        );
        assert!(
            !extra.contains_key(FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY),
            "an absent count is unmeasured, and must not be read as zero"
        );
    }
}
