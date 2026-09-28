// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whether a focal escapes as a value: the census behind
//! [`kin_model::FocalEscape`].
//!
//! A call that never spells a focal's name can still reach it when the focal
//! is held as a value: `handler = target`, then `handler()`. Whether any
//! unsettled call site that does not spell the name could be such a call
//! turns on whether the focal escapes, and nothing recorded answers that. A
//! reference edge is no proof either way: a references pass can fail and
//! leave none, a call-site ledger censuses only call expressions, and a stale
//! reference can be retracted because a pass did not reproduce it.
//!
//! So [`focal_escape_evidence_batch`] takes a census of each focal's call
//! names over the text of every file of its calling languages, and a focal
//! is contained only when every occurrence is accounted for and no text in
//! that domain reaches a value through a name computed at run time. What the
//! census cannot read or account for reads as unknown, which every consumer
//! treats as escaping.
//!
//! The census reads files, entities and ledgers through the graph it is
//! handed, so a reader of a selected or replayed generation gets that
//! generation's answer. Exact file bytes are an internal boundary of the
//! census: nothing it reads reaches an answer's payload.

use std::collections::{BTreeMap, HashSet};

use kin_model::graph::GraphStore;
use kin_model::{
    calling_languages, holds_dynamic_access, is_file_module_surface, language_of_path,
    read_caller_sites, CallSiteFacts, CallSiteLedger, CallerSites, ContextValidation, Entity,
    EntityFilter, EntityId, EntityKind, FilePathId, FocalEscape, Hash256, LanguageId,
    RelationEvidence, RelationKind, ResolutionRecordId, TreeEntry,
};

/// Files the census examines, including preview-only reads, before it answers
/// [`FocalEscape::Unknown`].
pub const ESCAPE_CENSUS_FILES_MAX: usize = 400;
/// Aggregate exact/preview source allowance, matching the semantic source ceiling.
pub const ESCAPE_CENSUS_BYTES_MAX: usize = 8 * 1024 * 1024;
/// Source-scan work across all focal names, so a large batch cannot multiply
/// the byte allowance into unbounded repeated scans.
const ESCAPE_CENSUS_WORK_MAX: usize = ESCAPE_CENSUS_BYTES_MAX * 8;

/// The entity metadata key under which the parser keeps an entity's body
/// preview: its text with whitespace collapsed, whole up to
/// [`WHOLE_BODY_PREVIEW_CHARS`] characters, and with its middle removed past
/// them.
const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";

/// The longest preview the parser keeps whole, in characters. A span of at
/// most this many bytes cannot collapse to more, so its preview is whole.
const WHOLE_BODY_PREVIEW_CHARS: usize = 8000;

/// Why the census found a focal escaping.
pub const ESCAPE_NON_CALL_OCCURRENCE: &str =
    "an occurrence of its name is not a declaration, a plain import or a recorded call";
/// Why the census cannot prove a focal contained: some text in its domain
/// reaches a value through a name computed at run time.
pub const ESCAPE_DYNAMIC_ACCESS: &str = "dynamic reflective access in the domain";

/// One file of the census's domain, as the selected tree records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CensusFile {
    pub path: FilePathId,
    /// The language the file is parsed as.
    pub language: LanguageId,
    /// The content identity of its bytes in the tree.
    pub blob: Hash256,
    /// Its length in bytes, when the graph records one: the census refuses
    /// bytes of any other length, and rules a small file out by its preview
    /// only when the length is known.
    pub len: Option<usize>,
}

/// What the census reads from a graph, and nothing more, so a reader of a
/// replayed or selected generation that is not a [`GraphStore`] can answer
/// from that generation.
pub trait EscapeCensusGraph {
    /// Every file of `languages` in the selected tree, including files with
    /// no entities, or `None` when the tree or any in-domain source path cannot
    /// be read. Unreadable source paths must never be omitted from this inventory.
    fn census_files(&self, languages: &[LanguageId]) -> Option<Vec<CensusFile>>;
    /// The file's exact bytes, verified against its content identity, or
    /// `None` when they cannot be read within `max_bytes`. Providers must
    /// enforce this allowance before allocating the blob, even without `len`.
    fn file_bytes(&self, file: &CensusFile, max_bytes: usize) -> Option<Vec<u8>>;
    /// Every entity of the file, or `None` when the entity index cannot be
    /// read.
    fn entities_in(&self, path: &FilePathId) -> Option<Vec<Entity>>;
    /// The call-site ledger the graph records for `caller`, when it holds one.
    fn call_site_ledger(&self, caller: EntityId) -> Option<CallSiteLedger>;
    /// The proof-context validation the graph records for `language`, when it
    /// holds one.
    fn context_validation(&self, language: LanguageId) -> Option<ContextValidation>;
    /// The evidence of every `Imports` edge that lands on `target`, or `None`
    /// when its relations cannot be read.
    fn import_evidence_into(&self, target: EntityId) -> Option<Vec<RelationEvidence>>;
}

/// A [`GraphStore`] read as an [`EscapeCensusGraph`]: its resolved tree, its
/// entities, ledgers and relations, and the exact bytes `bytes` reads for a
/// file of the tree.
pub struct StoreCensus<'s, G: GraphStore + ?Sized> {
    pub store: &'s G,
    pub bytes: &'s dyn Fn(&CensusFile, usize) -> Option<Vec<u8>>,
}

impl<G: GraphStore + ?Sized> EscapeCensusGraph for StoreCensus<'_, G> {
    fn census_files(&self, languages: &[LanguageId]) -> Option<Vec<CensusFile>> {
        let tree = self.store.resolved_tree_snapshot().ok()??;
        let mut files = Vec::new();
        for artifact in tree.artifacts() {
            let TreeEntry::Blob { hash, .. } = artifact.entry else {
                continue;
            };
            // Classify the extension before decoding the entire path. A
            // raw-byte asset is outside the domain; a raw-byte source path
            // makes its inventory unreadable rather than silently smaller.
            let bytes = artifact.path.as_bytes();
            let language = bytes
                .iter()
                .rposition(|byte| *byte == b'.')
                .and_then(|at| std::str::from_utf8(&bytes[at..]).ok())
                .and_then(language_of_path)
                .filter(|language| languages.contains(language));
            let Some(language) = language else { continue };
            let path = FilePathId::new(artifact.path.as_utf8()?);
            let len = self
                .store
                .get_file_layout(&path)
                .ok()
                .flatten()
                .and_then(|layout| layout_len(&layout));
            files.push(CensusFile {
                path,
                language,
                blob: hash,
                len,
            });
        }
        Some(files)
    }

    fn file_bytes(&self, file: &CensusFile, max_bytes: usize) -> Option<Vec<u8>> {
        (self.bytes)(file, max_bytes)
    }

    fn entities_in(&self, path: &FilePathId) -> Option<Vec<Entity>> {
        self.store
            .query_entities(&EntityFilter {
                file_path: Some(path.clone()),
                ..Default::default()
            })
            .ok()
    }

    fn call_site_ledger(&self, caller: EntityId) -> Option<CallSiteLedger> {
        self.store
            .lookup_resolution_record(&ResolutionRecordId::call_sites(caller))
            .ok()
            .flatten()
            .and_then(|record| record.as_call_sites().cloned())
    }

    fn context_validation(&self, language: LanguageId) -> Option<ContextValidation> {
        self.store
            .lookup_resolution_record(&ResolutionRecordId::context_validation(language))
            .ok()
            .flatten()
            .and_then(|record| record.as_context_validation().cloned())
    }

    fn import_evidence_into(&self, target: EntityId) -> Option<Vec<RelationEvidence>> {
        let relations = self.store.get_all_relations_for_entity(&target).ok()?;
        Some(
            relations
                .into_iter()
                .filter(|relation| {
                    relation.kind == RelationKind::Imports
                        && relation.dst.as_entity() == Some(target)
                })
                .flat_map(|relation| relation.evidence)
                .collect(),
        )
    }
}

/// The length a file's layout records: the end of its last region, which
/// covers the file's trivia as well as its entities.
fn layout_len(layout: &kin_model::layout::FileLayout) -> Option<usize> {
    layout
        .regions
        .iter()
        .map(|region| match region {
            kin_model::layout::SourceRegion::EntityRef { byte_range, .. }
            | kin_model::layout::SourceRegion::Trivia { byte_range } => byte_range.end,
        })
        .chain(std::iter::once(layout.imports.byte_range.end))
        .max()
}

/// The ledger reading's facts, answered from a census graph alone: its
/// ledgers, and the proof context its own validation record holds for each
/// language.
struct CensusFacts<'g>(&'g dyn EscapeCensusGraph);

impl CallSiteFacts for CensusFacts<'_> {
    fn ledger(&self, caller: EntityId) -> Option<CallSiteLedger> {
        self.0.call_site_ledger(caller)
    }

    fn current_context(&self, language: LanguageId) -> Option<ResolutionRecordId> {
        self.0
            .context_validation(language)
            .and_then(|validation| validation.current_context())
    }
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// Every byte offset in `text` where `name` stands as a whole identifier.
/// Strings and comments count, so `getattr(ctx, "pop")` spells `pop`. A byte
/// outside ASCII never joins an identifier here, which can only find more
/// occurrences, never fewer.
fn identifier_occurrences(text: &str, name: &str) -> Vec<usize> {
    if name.is_empty() {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    text.match_indices(name)
        .filter(|(at, _)| {
            let before = at.checked_sub(1).map(|index| bytes[index]);
            let after = bytes.get(at + name.len()).copied();
            !before.is_some_and(is_identifier_byte) && !after.is_some_and(is_identifier_byte)
        })
        .map(|(at, _)| at)
        .collect()
}

/// Kinds whose entity declares a name a call could spell.
const DECLARING_KINDS: [EntityKind; 13] = [
    EntityKind::Function,
    EntityKind::Method,
    EntityKind::Test,
    EntityKind::Class,
    EntityKind::Interface,
    EntityKind::TraitDef,
    EntityKind::TypeAlias,
    EntityKind::EnumDef,
    EntityKind::EnumVariant,
    EntityKind::Constant,
    EntityKind::StaticVar,
    EntityKind::Field,
    EntityKind::Macro,
];

/// Words that introduce a declared name.
const DECLARATION_KEYWORDS: [&str; 24] = [
    "def",
    "class",
    "function",
    "fn",
    "func",
    "fun",
    "const",
    "let",
    "var",
    "val",
    "struct",
    "enum",
    "interface",
    "trait",
    "type",
    "union",
    "static",
    "get",
    "set",
    "record",
    "object",
    "protocol",
    "typealias",
    "macro_rules!",
];

/// Whether the occurrence at `at` in `text` is the name token of a
/// declaration whose entity starts at `start`: the word before it introduces
/// a declared name (`def target`, `class target`, `const target =`), it is
/// the entity's first token (`target = 1`), it is the first name of a
/// signature with no argument list or assignment before it and one after it
/// (`public void target(`), or it follows a Go receiver (`func (r T) target(`).
fn is_declaration_at(text: &str, start: usize, at: usize, length: usize) -> bool {
    if at == start {
        return true;
    }
    let before = &text[start..at];
    let trimmed = before.trim_end().trim_end_matches('*').trim_end();
    let word_start = trimmed
        .bytes()
        .rposition(|byte| !(is_identifier_byte(byte) || byte == b'!'))
        .map_or(0, |index| index + 1);
    if DECLARATION_KEYWORDS.contains(&&trimmed[word_start..]) {
        return true;
    }
    let after = text[at + length..].trim_start();
    let opens = after.starts_with('(') || after.starts_with('<');
    if opens && !before.contains('(') && !before.contains('=') {
        return true;
    }
    opens && before.trim_start().starts_with("func") && trimmed.ends_with(')')
}

/// Whether `span_text`, the bytes an import edge's evidence cites, is a
/// strictly plain import binding `name` as itself: `import name`,
/// `from pkg import a, name` (parenthesised over lines too) or
/// `import { a, name } from "pkg"`, with nothing but names, commas and
/// whitespace in the list. Any `as`, comment, `*` or other text rules it out.
fn plain_import_binds(span_text: &str, name: &str) -> bool {
    let words_only = |list: &str| {
        let items: Vec<&str> = list
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .collect();
        items
            .iter()
            .all(|item| item.bytes().all(is_identifier_byte) && *item != "as")
            && items.contains(&name)
    };
    let text = span_text.trim().trim_end_matches(';').trim_end();
    if let Some(rest) = text.strip_prefix("from ") {
        let Some((module, list)) = rest.split_once(" import ") else {
            return false;
        };
        if !module
            .trim()
            .bytes()
            .all(|byte| is_identifier_byte(byte) || byte == b'.')
        {
            return false;
        }
        let list = list.trim();
        let list = list
            .strip_prefix('(')
            .and_then(|inner| inner.strip_suffix(')'))
            .unwrap_or(list);
        return words_only(list);
    }
    let Some(rest) = text.strip_prefix("import ") else {
        return false;
    };
    let rest = rest.trim();
    if let Some(braced) = rest.strip_prefix('{') {
        let Some((list, tail)) = braced.split_once('}') else {
            return false;
        };
        let Some(source) = tail.trim().strip_prefix("from ") else {
            return false;
        };
        let source = source.trim();
        let quoted = (source.starts_with('"') && source.ends_with('"'))
            || (source.starts_with('\'') && source.ends_with('\''));
        return quoted && source.len() >= 2 && words_only(list);
    }
    rest == name
}

/// One focal's census, taken along with the others of a batch.
struct Focal {
    names: Vec<String>,
    languages: Vec<LanguageId>,
    imports: Vec<RelationEvidence>,
    answer: Option<FocalEscape>,
    entities_checked: usize,
}

/// [`focal_escape_evidence_batch`] for one focal of a [`GraphStore`], with
/// `bytes` reading a file's exact bytes from the content store.
pub fn focal_escape_evidence<G: GraphStore + ?Sized>(
    store: &G,
    focal: &Entity,
    names: &[String],
    bytes: &dyn Fn(&CensusFile, usize) -> Option<Vec<u8>>,
) -> FocalEscape {
    focal_escape_evidence_in(&StoreCensus { store, bytes }, focal, names)
}

/// [`focal_escape_evidence_batch`] for one focal of any census graph.
pub fn focal_escape_evidence_in(
    graph: &dyn EscapeCensusGraph,
    focal: &Entity,
    names: &[String],
) -> FocalEscape {
    focal_escape_evidence_batch(graph, &[(focal, names.to_vec())])
        .pop()
        .unwrap_or(FocalEscape::Unknown {
            reason: "the census answered no focal",
        })
}

/// Whether each focal, spelled by its call names
/// ([`kin_model::focal_call_names`]), escapes as a value, one answer per
/// focal in order. Every file is read at most once for the whole batch.
///
/// A focal's domain is every file of its calling languages in the selected
/// tree, whether or not it holds entities. Each file's text is read whole:
///
/// - from its file or module surface's preview, when that entity spans the
///   file's whole recorded length from its first byte and the length fits
///   the preview limit and its source digest matches the selected blob,
///   since collapsing whitespace keeps every token;
/// - otherwise from its exact bytes, which must match its recorded length
///   when it has one.
///
/// A file whose whole preview spells none of a focal's names needs no exact
/// read for that focal. Text that reaches a value through a name computed at
/// run time (see [`kin_model::holds_dynamic_access`]) makes every focal whose
/// domain holds it [`FocalEscape::Unknown`], since the focal may escape
/// through it unspelled. Otherwise each whole-identifier occurrence of a
/// name in the exact text is accounted for as:
///
/// - the callee token of a site a current ledger records, in any state;
/// - the name token of a declaration (a function, method, class, type,
///   constant or field entity named after it), and never a module's text;
/// - an import edge into the focal that binds the name as itself: its
///   evidence cites exactly the name with the name as its token, or cites a
///   strictly plain import statement listing it.
///
/// An occurrence left over escapes, unless the innermost entity holding it
/// makes calls and has no current ledger to account for them, which is
/// unknown. So is a tree, an entity index, a relation index or a file's bytes
/// that cannot be read, bytes of the wrong length, and a census past
/// [`ESCAPE_CENSUS_FILES_MAX`] files or [`ESCAPE_CENSUS_BYTES_MAX`] source
/// bytes. Repeated scans across focal names have a separate work allowance.
/// A focal with no call name is
/// unknown.
pub fn focal_escape_evidence_batch(
    graph: &dyn EscapeCensusGraph,
    focals: &[(&Entity, Vec<String>)],
) -> Vec<FocalEscape> {
    let mut census: Vec<Focal> = focals
        .iter()
        .map(|(entity, names)| {
            let names: Vec<String> = names
                .iter()
                .filter(|name| !name.is_empty())
                .cloned()
                .collect();
            let mut focal = Focal {
                languages: calling_languages(entity.language),
                imports: Vec::new(),
                answer: None,
                entities_checked: 0,
                names,
            };
            if let Some(proof) = non_callable_binding(graph, entity) {
                focal.answer = Some(proof);
            } else if focal.names.is_empty() {
                focal.answer = Some(FocalEscape::Unknown {
                    reason: "the focal has no name a call spells",
                });
            } else {
                match graph.import_evidence_into(entity.id) {
                    Some(imports) => focal.imports = imports,
                    None => {
                        focal.answer = Some(FocalEscape::Unknown {
                            reason: "the focal's relations could not be read",
                        })
                    }
                }
            }
            focal
        })
        .collect();
    let mut languages: Vec<LanguageId> = Vec::new();
    for focal in census.iter().filter(|focal| focal.answer.is_none()) {
        for language in &focal.languages {
            if !languages.contains(language) {
                languages.push(*language);
            }
        }
    }
    if !languages.is_empty() {
        take_census(graph, &languages, &mut census);
    }
    census
        .into_iter()
        .map(|focal| {
            focal.answer.unwrap_or(FocalEscape::Contained {
                entities_checked: focal.entities_checked,
            })
        })
        .collect()
}

/// Read parser-produced binding evidence from the exact selected tree. This
/// never reparses source or trusts a Constant label or a signature heuristic.
fn non_callable_binding(graph: &dyn EscapeCensusGraph, focal: &Entity) -> Option<FocalEscape> {
    let binding = focal.metadata.extra.get("scalar_binding_v1")?;
    if binding.get("version")?.as_u64()? != 1
        || binding.get("language")?.as_str()? != focal.language.to_string()
    {
        return None;
    }
    let immutable = binding.get("immutable")?.as_bool()?;
    if !immutable && focal.language != LanguageId::Python {
        return None;
    }
    if immutable
        && !matches!(
            focal.language,
            LanguageId::Rust
                | LanguageId::Go
                | LanguageId::JavaScript
                | LanguageId::TypeScript
                | LanguageId::Java
        )
    {
        return None;
    }
    let name = binding.get("name")?.as_str()?;
    if name != focal.name.rsplit(['.', ':']).next()? {
        return None;
    }
    let file = focal.file_origin.as_ref()?;
    let files = graph.census_files(&calling_languages(focal.language))?;
    if files.len() > ESCAPE_CENSUS_FILES_MAX {
        return None;
    }
    let selected = files.iter().find(|selected| &selected.path == file)?;
    let digest_matches = |entity: &Entity, blob: Hash256| {
        entity
            .metadata
            .extra
            .get("blob_hash")
            .and_then(serde_json::Value::as_str)
            .and_then(|hex| Hash256::from_hex(hex).ok())
            == Some(blob)
    };
    if !digest_matches(focal, selected.blob) {
        return None;
    }
    let held = graph.entities_in(file)?;
    if !held.iter().any(|entity| {
        entity.id == focal.id
            && entity.metadata.extra.get("scalar_binding_v1") == Some(binding)
            && digest_matches(entity, selected.blob)
    }) {
        return None;
    }
    if immutable {
        return Some(FocalEscape::NonCallable {
            reason: "the parser records an immutable scalar literal binding",
            entities_checked: 1,
        });
    }
    let mut writes = 0u64;
    let mut entities_checked = 0usize;
    for file in files {
        let entities = graph.entities_in(&file.path)?;
        entities_checked = entities_checked.checked_add(entities.len())?;
        if entities_checked > ESCAPE_CENSUS_WORK_MAX {
            return None;
        }
        let evidence = entities.iter().find_map(|entity| {
            digest_matches(entity, file.blob)
                .then(|| entity.metadata.extra.get("python_binding_census_v1"))
                .flatten()
        })?;
        if evidence.get("version")?.as_u64()? != 1 || evidence.get("blocked")?.as_bool()? {
            return None;
        }
        let counts = evidence.get("writes")?.as_object()?;
        writes = writes.checked_add(match counts.get(name) {
            Some(value) => value.as_u64()?,
            None => 0,
        })?;
        if writes > 1 {
            return None;
        }
    }
    (writes == 1).then_some(FocalEscape::NonCallable {
        reason: "one scalar assignment and no rebinding or reflective writes in the parsed domain",
        entities_checked,
    })
}

fn span_of(entity: &Entity) -> (usize, usize) {
    entity
        .span
        .as_ref()
        .map_or((0, 0), |span| (span.start_byte, span.end_byte))
}

fn mark_unknown(census: &mut [Focal], targets: &[usize], reason: &'static str) {
    for index in targets {
        census[*index].answer = Some(FocalEscape::Unknown { reason });
    }
}

fn undecided(census: &[Focal]) -> Vec<usize> {
    (0..census.len())
        .filter(|index| census[*index].answer.is_none())
        .collect()
}

fn take_census(graph: &dyn EscapeCensusGraph, languages: &[LanguageId], census: &mut [Focal]) {
    let Some(mut files) = graph.census_files(languages) else {
        let all = undecided(census);
        mark_unknown(census, &all, "the selected tree could not be read");
        return;
    };
    files.sort_by(|left, right| left.path.0.cmp(&right.path.0));
    let facts = CensusFacts(graph);
    let mut remaining_bytes = ESCAPE_CENSUS_BYTES_MAX;
    let mut remaining_work = ESCAPE_CENSUS_WORK_MAX;
    for (examined, file) in files.into_iter().enumerate() {
        let in_domain: Vec<usize> = undecided(census)
            .into_iter()
            .filter(|index| census[*index].languages.contains(&file.language))
            .collect();
        if in_domain.is_empty() {
            if census.iter().all(|focal| focal.answer.is_some()) {
                return;
            }
            continue;
        }
        if examined >= ESCAPE_CENSUS_FILES_MAX {
            let all = undecided(census);
            mark_unknown(census, &all, "the census file allowance was spent");
            return;
        }
        let scan_weight = in_domain.iter().fold(1usize, |weight, index| {
            weight.saturating_add(census[*index].names.len().saturating_mul(2))
        });
        let max_bytes = remaining_bytes.min(remaining_work / scan_weight);
        if max_bytes == 0 || file.len.is_some_and(|len| len > max_bytes) {
            let all = undecided(census);
            mark_unknown(census, &all, "the census byte or scan allowance was spent");
            return;
        }
        let Some(entities) = graph.entities_in(&file.path) else {
            mark_unknown(census, &in_domain, "the entity index could not be read");
            continue;
        };
        let entity_work = entities.len().saturating_mul(scan_weight);
        if entity_work > remaining_work {
            let all = undecided(census);
            mark_unknown(census, &all, "the census entity scan allowance was spent");
            return;
        }
        remaining_work -= entity_work;
        let max_bytes = remaining_bytes.min(remaining_work / scan_weight);
        // The whole file's text from its surface's preview, when the preview
        // provably holds every token of the file.
        let whole_preview = file
            .len
            .filter(|len| *len <= WHOLE_BODY_PREVIEW_CHARS)
            .and_then(|len| {
                entities
                    .iter()
                    .find(|entity| {
                        is_file_module_surface(entity)
                            && span_of(entity) == (0, len)
                            && entity
                                .metadata
                                .extra
                                .get("blob_hash")
                                .and_then(serde_json::Value::as_str)
                                .and_then(|hex| Hash256::from_hex(hex).ok())
                                == Some(file.blob)
                    })
                    .and_then(|surface| {
                        surface
                            .metadata
                            .extra
                            .get(EMBEDDING_BODY_PREVIEW_KEY)
                            .and_then(serde_json::Value::as_str)
                    })
            });
        let targets: Vec<usize> = match whole_preview {
            Some(preview) => {
                if preview.len() > max_bytes {
                    let all = undecided(census);
                    mark_unknown(census, &all, "the census byte or scan allowance was spent");
                    return;
                }
                remaining_bytes -= preview.len();
                remaining_work -= preview.len().saturating_mul(scan_weight);
                if holds_dynamic_access(preview) {
                    mark_unknown(census, &in_domain, ESCAPE_DYNAMIC_ACCESS);
                    continue;
                }
                let (spelling, ruled_out): (Vec<usize>, Vec<usize>) =
                    in_domain.iter().partition(|index| {
                        census[**index]
                            .names
                            .iter()
                            .any(|name| !identifier_occurrences(preview, name).is_empty())
                    });
                for index in ruled_out {
                    census[index].entities_checked += entities.len();
                }
                spelling
            }
            None => in_domain,
        };
        if targets.is_empty() {
            continue;
        }
        let max_bytes = remaining_bytes.min(remaining_work / scan_weight);
        if max_bytes == 0 || file.len.is_some_and(|len| len > max_bytes) {
            let all = undecided(census);
            mark_unknown(census, &all, "the census byte or scan allowance was spent");
            return;
        }
        let Some(bytes) = graph.file_bytes(&file, max_bytes) else {
            // A failed integrity/read check may already have consumed the
            // whole permitted body. Reserve that cost rather than retrying
            // another language's files with an unchanged aggregate allowance.
            remaining_bytes -= max_bytes;
            remaining_work -= max_bytes.saturating_mul(scan_weight);
            mark_unknown(
                census,
                &targets,
                "the exact bytes of a file in the domain could not be read within the allowance",
            );
            continue;
        };
        if bytes.len() > max_bytes {
            let all = undecided(census);
            mark_unknown(census, &all, "the census byte or scan allowance was spent");
            return;
        }
        remaining_bytes -= bytes.len();
        remaining_work -= bytes.len().saturating_mul(scan_weight);
        if file.len.is_some_and(|len| len != bytes.len()) {
            mark_unknown(
                census,
                &targets,
                "a file's bytes differ from the length its graph records",
            );
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            mark_unknown(census, &targets, "a file in the domain is not UTF-8 text");
            continue;
        };
        if holds_dynamic_access(text) {
            mark_unknown(census, &targets, ESCAPE_DYNAMIC_ACCESS);
            continue;
        }
        let readings: Vec<CallerSites> = entities
            .iter()
            .map(|entity| read_caller_sites(&facts, entity))
            .collect();
        for index in targets {
            let answer = account(&file, text, &entities, &readings, &census[index]);
            census[index].entities_checked += entities.len();
            if answer.is_some() {
                census[index].answer = answer;
            }
        }
    }
}

/// Account for every occurrence of `focal`'s names in one file's exact text,
/// or the answer an unaccounted one gives.
fn account(
    file: &CensusFile,
    text: &str,
    entities: &[Entity],
    readings: &[CallerSites],
    focal: &Focal,
) -> Option<FocalEscape> {
    let mut occurrences: BTreeMap<usize, &str> = BTreeMap::new();
    for name in &focal.names {
        for at in identifier_occurrences(text, name) {
            occurrences.insert(at, name.as_str());
        }
    }
    if occurrences.is_empty() {
        return None;
    }
    let mut accounted: HashSet<usize> = HashSet::new();
    for (entity, reading) in entities.iter().zip(readings) {
        let (start, end) = span_of(entity);
        if let CallerSites::Current(ledger) = reading {
            for site in &ledger.sites {
                let at = start + site.offset as usize;
                if occurrences
                    .get(&at)
                    .is_some_and(|name| name.len() == site.length as usize)
                {
                    accounted.insert(at);
                }
            }
        }
        if !DECLARING_KINDS.contains(&entity.kind) || is_file_module_surface(entity) {
            continue;
        }
        let leaf = entity.name.rsplit(['.', ':']).next().unwrap_or("");
        if let Some((at, _)) = occurrences
            .range(start..end)
            .find(|(at, name)| **name == leaf && is_declaration_at(text, start, **at, leaf.len()))
        {
            accounted.insert(*at);
        }
    }
    for evidence in &focal.imports {
        let Some(span) = evidence
            .source_span
            .as_ref()
            .filter(|span| span.file == file.path)
        else {
            continue;
        };
        let Some(cited) = text.get(span.start_byte..span.end_byte) else {
            continue;
        };
        for (at, name) in occurrences.range(span.start_byte..span.end_byte) {
            let exact = cited == *name && evidence.token.as_deref() == Some(*name);
            if exact || plain_import_binds(cited, name) {
                accounted.insert(*at);
            }
        }
    }
    let at = occurrences.keys().find(|at| !accounted.contains(at))?;
    let holder = entities
        .iter()
        .zip(readings)
        .filter(|(entity, _)| {
            let (start, end) = span_of(entity);
            start <= *at && *at < end
        })
        .min_by_key(|(entity, _)| {
            let (start, end) = span_of(entity);
            end - start
        });
    let unaccountable_calls = holder.is_some_and(|(_, reading)| {
        !matches!(reading, CallerSites::Current(_) | CallerSites::NoSites)
    });
    Some(if unaccountable_calls {
        FocalEscape::Unknown {
            reason: "an entity holding the name has no current ledger to account for its calls",
        }
    } else {
        FocalEscape::Escapes {
            reason: ESCAPE_NON_CALL_OCCURRENCE,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        CallSite, CallSiteState, ContextValidationState, EntityMetadata, EntityRole,
        FingerprintAlgorithm, ProofContext, ResolutionRecord, SemanticFingerprint, SourceSpan,
        UnresolvedReason, Visibility,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;

    fn context() -> ProofContext {
        ProofContext {
            language: LanguageId::Python,
            resolver: "lsp:pyright".to_string(),
            resolver_version: "1.1.400".to_string(),
            configuration_hash: Hash256::from_bytes([0x41; 32]),
            environment_hash: Hash256::from_bytes([0x42; 32]),
            environment_summary: "python 3.12".to_string(),
        }
    }

    /// A census graph over files held in memory.
    #[derive(Default)]
    struct Fixture {
        files: BTreeMap<String, String>,
        unreadable: HashSet<String>,
        lengths: HashMap<String, usize>,
        entities: Vec<Entity>,
        ledgers: HashMap<EntityId, CallSiteLedger>,
        imports: Vec<RelationEvidence>,
        reads: RefCell<Vec<String>>,
    }

    impl Fixture {
        fn file(mut self, path: &str, text: &str) -> Self {
            self.files.insert(path.to_string(), text.to_string());
            self
        }

        /// An entity of `path` spanning the first `text` in its file, with
        /// a whole-body preview and, when `calls` is given, a current ledger
        /// with one unresolved site per token.
        fn entity(
            mut self,
            path: &str,
            name: &str,
            kind: EntityKind,
            text: &str,
            calls: Option<&[&str]>,
        ) -> Self {
            let source = self.files[path].clone();
            let start = source.find(text).expect("text in file");
            let signature = if kind == EntityKind::Module {
                format!("module {path}")
            } else {
                String::new()
            };
            let entity = Entity {
                id: EntityId::from_content(path, name, &format!("{kind:?}"), start as u32),
                kind,
                name: name.to_string(),
                language: LanguageId::Python,
                fingerprint: SemanticFingerprint {
                    algorithm: FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: Hash256::from_bytes([0; 32]),
                    signature_hash: Hash256::from_bytes([0; 32]),
                    behavior_hash: Hash256::from_bytes([5; 32]),
                    equivalence_hash: Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(path)),
                span: Some(SourceSpan {
                    file: FilePathId::new(path),
                    start_byte: start,
                    end_byte: start + text.len(),
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 0,
                }),
                signature,
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata {
                    extra: [
                        (
                            EMBEDDING_BODY_PREVIEW_KEY.to_string(),
                            serde_json::json!(text
                                .split_whitespace()
                                .collect::<Vec<_>>()
                                .join(" ")),
                        ),
                        (
                            "blob_hash".to_string(),
                            serde_json::json!(Hash256::from_bytes([1; 32]).to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                },
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            };
            if let Some(tokens) = calls {
                let mut from = 0;
                let sites = tokens
                    .iter()
                    .map(|token| {
                        let offset = from + text[from..].find(token).expect("token in entity");
                        from = offset + token.len();
                        CallSite {
                            offset: offset as u32,
                            length: token.len() as u32,
                            state: CallSiteState::Unresolved {
                                reason: UnresolvedReason::NoAnswer,
                            },
                        }
                    })
                    .collect::<Vec<_>>();
                self.ledgers.insert(
                    entity.id,
                    CallSiteLedger {
                        caller: entity.id,
                        behavior_hash: entity.fingerprint.behavior_hash,
                        body_hash: Hash256::from_bytes([6; 32]),
                        context: ResolutionRecord::ProofContext(context()).id(),
                        census: sites.len() as u32,
                        sites,
                    },
                );
            }
            self.entities.push(entity);
            self
        }

        fn entity_named(&self, name: &str) -> &Entity {
            self.entities
                .iter()
                .find(|entity| entity.name == name)
                .expect("an entity of that name")
        }

        fn census(&self, focal: &str) -> FocalEscape {
            let focal = self.entity_named(focal);
            focal_escape_evidence_in(self, focal, &kin_model::focal_call_names(focal))
        }
    }

    #[test]
    fn scalar_binding_requires_current_evidence_from_every_python_file() {
        let source = "VALUE = 'value'\ndef render(): return 'prefix' + VALUE\n";
        let other = "def use(): return helper()\n";
        let mut fixture = Fixture::default()
            .file("a.py", source)
            .entity(
                "a.py",
                "VALUE",
                EntityKind::Constant,
                "VALUE = 'value'",
                None,
            )
            .file("b.py", other)
            .entity("b.py", "use", EntityKind::Function, other, None);
        fixture.entities[0].metadata.extra.insert("scalar_binding_v1".into(), serde_json::json!({
            "version":1,"language":LanguageId::Python.to_string(),"name":"VALUE","immutable":false,
        }));
        for (index, writes) in [
            (0, serde_json::json!({"VALUE":1})),
            (1, serde_json::json!({"use":1})),
        ] {
            fixture.entities[index].metadata.extra.insert(
                "python_binding_census_v1".into(),
                serde_json::json!({
                    "version":1,"blocked":false,"writes":writes,
                }),
            );
        }
        assert!(matches!(
            fixture.census("VALUE"),
            FocalEscape::NonCallable { .. }
        ));
        assert!(
            fixture.reads.borrow().is_empty(),
            "binding proof reads persisted metadata only"
        );
        let baseline = fixture.entities.clone();
        for failure in [
            "missing",
            "stale",
            "rebound",
            "reflective",
            "zero_assignments",
        ] {
            fixture.entities = baseline.clone();
            match failure {
                "missing" => {
                    fixture.entities[1]
                        .metadata
                        .extra
                        .remove("python_binding_census_v1");
                }
                "stale" => {
                    fixture.entities[1].metadata.extra.insert(
                        "blob_hash".into(),
                        serde_json::json!(Hash256::from_bytes([9; 32]).to_string()),
                    );
                }
                "rebound" => {
                    fixture.entities[1]
                        .metadata
                        .extra
                        .get_mut("python_binding_census_v1")
                        .unwrap()["writes"]["VALUE"] = serde_json::json!(1);
                }
                "reflective" => {
                    fixture.entities[1]
                        .metadata
                        .extra
                        .get_mut("python_binding_census_v1")
                        .unwrap()["blocked"] = serde_json::json!(true);
                }
                "zero_assignments" => {
                    fixture.entities[0]
                        .metadata
                        .extra
                        .get_mut("python_binding_census_v1")
                        .unwrap()["writes"]["VALUE"] = serde_json::json!(0);
                }
                _ => unreachable!(),
            }
            assert!(
                !matches!(fixture.census("VALUE"), FocalEscape::NonCallable { .. }),
                "{failure}"
            );
        }
        fixture.entities = baseline;
        fixture.entities[0].metadata.extra.insert(
            "blob_hash".into(),
            serde_json::json!(Hash256::from_bytes([9; 32]).to_string()),
        );
        assert!(!matches!(
            fixture.census("VALUE"),
            FocalEscape::NonCallable { .. }
        ));
    }

    impl EscapeCensusGraph for Fixture {
        fn census_files(&self, languages: &[LanguageId]) -> Option<Vec<CensusFile>> {
            Some(
                self.files
                    .keys()
                    .filter(|path| {
                        language_of_path(path).is_some_and(|language| languages.contains(&language))
                    })
                    .map(|path| CensusFile {
                        path: FilePathId::new(path),
                        language: LanguageId::Python,
                        blob: Hash256::from_bytes([1; 32]),
                        len: self.lengths.get(path).copied(),
                    })
                    .collect(),
            )
        }

        fn file_bytes(&self, file: &CensusFile, max_bytes: usize) -> Option<Vec<u8>> {
            self.reads.borrow_mut().push(file.path.0.clone());
            if self.unreadable.contains(&file.path.0) {
                return None;
            }
            self.files
                .get(&file.path.0)
                .filter(|text| text.len() <= max_bytes)
                .map(|text| text.as_bytes().to_vec())
        }

        fn entities_in(&self, path: &FilePathId) -> Option<Vec<Entity>> {
            Some(
                self.entities
                    .iter()
                    .filter(|entity| entity.file_origin.as_ref() == Some(path))
                    .cloned()
                    .collect(),
            )
        }

        fn call_site_ledger(&self, caller: EntityId) -> Option<CallSiteLedger> {
            self.ledgers.get(&caller).cloned()
        }

        fn context_validation(&self, language: LanguageId) -> Option<ContextValidation> {
            Some(ContextValidation {
                language,
                state: ContextValidationState::Validated { context: context() },
            })
        }

        fn import_evidence_into(&self, _target: EntityId) -> Option<Vec<RelationEvidence>> {
            Some(self.imports.clone())
        }
    }

    const APP: &str = "pkg/app.py";
    const TARGET: &str = "def target(x):\n    return x\n";
    const USER: &str = "def user(y):\n    return target(y)\n";
    const CALLED: &str = "def target(x):\n    return x\n\ndef user(y):\n    return target(y)\n";

    fn called() -> Fixture {
        Fixture::default()
            .file(APP, CALLED)
            .entity(APP, "app", EntityKind::Module, CALLED, Some(&[]))
            .entity(APP, "target", EntityKind::Function, TARGET, Some(&[]))
            .entity(APP, "user", EntityKind::Function, USER, Some(&["target"]))
    }

    /// A reflection-free fixture whose every occurrence is a declaration or
    /// a recorded call is contained.
    #[test]
    fn a_reflection_free_focal_whose_occurrences_are_declarations_and_calls_is_contained() {
        let fixture = called();
        assert_eq!(
            fixture.census("target"),
            FocalEscape::Contained {
                entities_checked: 3
            }
        );
        assert!(!fixture.census("target").may_escape());
    }

    /// `handler = target` holds the focal as a value, and no reference edge
    /// records it: the census finds it anyway.
    #[test]
    fn a_non_call_occurrence_with_no_reference_edge_escapes() {
        let factory = "def factory():\n    handler = target\n    return handler\n";
        let source = format!("{TARGET}\n{factory}");
        let fixture = Fixture::default()
            .file(APP, &source)
            .entity(APP, "app", EntityKind::Module, &source, Some(&[]))
            .entity(APP, "target", EntityKind::Function, TARGET, Some(&[]))
            .entity(APP, "factory", EntityKind::Function, factory, Some(&[]));
        assert_eq!(
            fixture.census("target"),
            FocalEscape::Escapes {
                reason: ESCAPE_NON_CALL_OCCURRENCE
            }
        );
    }

    /// Text outside every entity is read: a trailing top-level assignment,
    /// and a file that holds no entity at all.
    #[test]
    fn top_level_text_and_files_without_entities_are_read() {
        let trailing = format!("{CALLED}handler = target\n");
        let fixture = Fixture::default()
            .file(APP, &trailing)
            .entity(APP, "target", EntityKind::Function, TARGET, Some(&[]))
            .entity(APP, "user", EntityKind::Function, USER, Some(&["target"]));
        assert_eq!(
            fixture.census("target"),
            FocalEscape::Escapes {
                reason: ESCAPE_NON_CALL_OCCURRENCE
            }
        );
        let bare = called().file("pkg/bare.py", "x = target\n");
        assert_eq!(
            bare.census("target"),
            FocalEscape::Escapes {
                reason: ESCAPE_NON_CALL_OCCURRENCE
            }
        );
    }

    /// A module named like the focal holding `register(target)` does not
    /// declare it: only a declaration's name token does. And an entity that
    /// makes calls with no ledger cannot account for its occurrences.
    #[test]
    fn only_a_declaration_s_name_token_is_its_declaration() {
        let registry = "register(target)\n";
        let fixture = called().file("pkg/target.py", registry).entity(
            "pkg/target.py",
            "target",
            EntityKind::Module,
            registry,
            Some(&["register"]),
        );
        let focal = fixture
            .entities
            .iter()
            .find(|entity| entity.name == "target" && entity.kind == EntityKind::Function)
            .expect("the focal");
        assert_eq!(
            focal_escape_evidence_in(&fixture, focal, &kin_model::focal_call_names(focal)),
            FocalEscape::Escapes {
                reason: ESCAPE_NON_CALL_OCCURRENCE
            },
            "the module's register(target) argument is not the declaration"
        );
        let unledgered = Fixture::default()
            .file(APP, CALLED)
            .entity(APP, "app", EntityKind::Module, CALLED, Some(&[]))
            .entity(APP, "target", EntityKind::Function, TARGET, Some(&[]))
            .entity(APP, "user", EntityKind::Function, USER, None);
        assert!(matches!(
            unledgered.census("target"),
            FocalEscape::Unknown { .. }
        ));
    }

    /// Dynamic access anywhere in the domain, even in text that makes no
    /// call, may hold the focal unspelled.
    #[test]
    fn dynamic_access_in_the_domain_is_unknown() {
        for access in [
            "handler = obj[key]\n",
            "h = getattr(ctx, 'po' + 'p')\n",
            "getattr(ctx, 'po' + 'p')()\n",
        ] {
            let fixture = called().file("pkg/dyn.py", access);
            assert_eq!(
                fixture.census("target"),
                FocalEscape::Unknown {
                    reason: ESCAPE_DYNAMIC_ACCESS
                },
                "{access}"
            );
        }
    }

    /// Bytes that are not the length the graph records, or that cannot be
    /// read, prove nothing.
    #[test]
    fn a_length_mismatch_or_an_unreadable_file_is_unknown() {
        let mut fixture = called();
        fixture.lengths.insert(APP.to_string(), CALLED.len() + 1);
        assert!(matches!(
            fixture.census("target"),
            FocalEscape::Unknown { .. }
        ));
        let mut unreadable = called().file("pkg/lost.py", "");
        unreadable.unreadable.insert("pkg/lost.py".to_string());
        assert!(matches!(
            unreadable.census("target"),
            FocalEscape::Unknown { .. }
        ));
    }

    /// A body past the preview limit loses its middle from the preview, so
    /// the census reads the exact text and finds the occurrence there. A
    /// small file whose surface preview spells no name and holds no dynamic
    /// access is not read.
    #[test]
    fn a_long_body_is_read_exactly_and_a_small_clean_file_is_not_read() {
        let filler = format!("    # {}\n", "x".repeat(70)).repeat(80);
        let long_fn =
            format!("def long():\n{filler}    handler = target\n{filler}    return handler\n");
        let source = format!("{TARGET}\n{long_fn}");
        // Sorted before the file that decides the answer, so it is weighed.
        let other = "def other():\n    pass\n";
        let mut fixture = Fixture::default()
            .file(APP, &source)
            .file("pkg/aaa.py", other)
            .entity(APP, "app", EntityKind::Module, &source, Some(&[]))
            .entity(APP, "target", EntityKind::Function, TARGET, Some(&[]))
            .entity(APP, "long", EntityKind::Function, &long_fn, Some(&[]))
            .entity("pkg/aaa.py", "aaa", EntityKind::Module, other, Some(&[]));
        fixture.lengths.insert("pkg/aaa.py".into(), other.len());
        assert_eq!(
            fixture.census("target"),
            FocalEscape::Escapes {
                reason: ESCAPE_NON_CALL_OCCURRENCE
            }
        );
        assert_eq!(*fixture.reads.borrow(), [APP.to_string()]);
    }

    #[test]
    fn a_stale_same_length_preview_cannot_hide_changed_source() {
        let before = "handler = object\n";
        let after = "handler = target\n";
        assert_eq!(before.len(), after.len());
        for stamp in [None, Some(Hash256::from_bytes([2; 32]).to_string())] {
            let mut fixture = called().file("pkg/aaa.py", before).entity(
                "pkg/aaa.py",
                "aaa",
                EntityKind::Module,
                before,
                Some(&[]),
            );
            fixture.lengths.insert("pkg/aaa.py".into(), before.len());
            let surface = fixture
                .entities
                .iter_mut()
                .find(|entity| entity.name == "aaa")
                .unwrap();
            match stamp {
                Some(stamp) => {
                    surface
                        .metadata
                        .extra
                        .insert("blob_hash".into(), serde_json::json!(stamp));
                }
                None => {
                    surface.metadata.extra.remove("blob_hash");
                }
            }
            fixture.files.insert("pkg/aaa.py".into(), after.into());
            assert_eq!(
                fixture.census("target"),
                FocalEscape::Escapes {
                    reason: ESCAPE_NON_CALL_OCCURRENCE
                }
            );
            assert_eq!(*fixture.reads.borrow(), ["pkg/aaa.py".to_string()]);
        }
    }

    #[test]
    fn oversized_known_source_is_refused_before_the_byte_provider() {
        let mut fixture = called().file("pkg/aaa.py", "unread oversized body");
        fixture
            .lengths
            .insert("pkg/aaa.py".into(), ESCAPE_CENSUS_BYTES_MAX + 1);
        assert!(matches!(
            fixture.census("target"),
            FocalEscape::Unknown { .. }
        ));
        assert!(fixture.reads.borrow().is_empty());
    }

    #[test]
    fn aggregate_source_and_name_scan_allowances_bound_the_batch() {
        let large = " ".repeat(ESCAPE_CENSUS_BYTES_MAX / 2 + 1);
        let mut fixture = called()
            .file("pkg/aaa.py", &large)
            .file("pkg/aab.py", &large);
        fixture.lengths.insert("pkg/aaa.py".into(), large.len());
        fixture.lengths.insert("pkg/aab.py".into(), large.len());
        assert!(matches!(
            fixture.census("target"),
            FocalEscape::Unknown { .. }
        ));
        assert_eq!(*fixture.reads.borrow(), ["pkg/aaa.py".to_string()]);

        let fixture = called().file("pkg/aaa.py", &large);
        let target = fixture.entity_named("target");
        let names = (0..16)
            .map(|index| format!("alias_{index}"))
            .collect::<Vec<_>>();
        assert!(matches!(
            focal_escape_evidence_in(&fixture, target, &names),
            FocalEscape::Unknown { .. }
        ));
        assert_eq!(
            *fixture.reads.borrow(),
            ["pkg/aaa.py".to_string()],
            "the provider receives the reduced scan allowance and refuses before cloning"
        );
    }

    #[test]
    fn preview_only_files_share_the_file_work_limit() {
        let source = "unrelated = 1\n";
        let mut fixture = called();
        for index in 0..ESCAPE_CENSUS_FILES_MAX + 1 {
            let path = format!("aaa/{index:04}.py");
            fixture = fixture.file(&path, source).entity(
                &path,
                "surface",
                EntityKind::Module,
                source,
                Some(&[]),
            );
            fixture.lengths.insert(path, source.len());
        }
        assert!(matches!(
            fixture.census("target"),
            FocalEscape::Unknown { .. }
        ));
        assert!(fixture.reads.borrow().is_empty());
    }

    fn import_at(text: &str, cited: &str, token: &str) -> RelationEvidence {
        let at = text.find(cited).expect("cited text in file");
        RelationEvidence {
            source_span: Some(SourceSpan {
                file: FilePathId::new(APP),
                start_byte: at,
                end_byte: at + cited.len(),
                start_line: 0,
                start_col: 0,
                end_line: 0,
                end_col: 0,
            }),
            token: Some(token.to_string()),
            ..RelationEvidence::default()
        }
    }

    /// An import edge binding the focal as itself is accounted, by its
    /// token or by a strictly plain statement, and a renaming one is not.
    #[test]
    fn a_plain_import_is_accounted_and_a_renaming_one_is_not() {
        let lib = "def target():\n    pass\n";
        let with = |text: &str, evidence: Vec<RelationEvidence>| {
            let mut fixture = Fixture::default()
                .file("pkg/lib.py", lib)
                .entity("pkg/lib.py", "target", EntityKind::Function, lib, Some(&[]))
                .file(APP, text)
                .entity(APP, "app", EntityKind::Module, text, Some(&[]));
            fixture.imports = evidence;
            fixture.census("target")
        };
        let plain = "from pkg.lib import target\n";
        assert!(matches!(
            with(plain, vec![import_at(plain, "target", "target")]),
            FocalEscape::Contained { .. }
        ));
        let listed = "from pkg.lib import (\n    other,\n    target,\n)\n";
        assert!(matches!(
            with(listed, vec![import_at(listed, listed.trim_end(), "target")]),
            FocalEscape::Contained { .. }
        ));
        for renamed in [
            "from pkg import (target\n as alias)\n",
            "import { target /* c */ as alias } from \"pkg\"\n",
        ] {
            let cited = renamed.trim_end();
            assert_eq!(
                with(renamed, vec![import_at(renamed, cited, "alias")]),
                FocalEscape::Escapes {
                    reason: ESCAPE_NON_CALL_OCCURRENCE
                },
                "{renamed}"
            );
        }
    }

    /// A batch reads each file once for every focal.
    #[test]
    fn a_batch_reads_each_file_once() {
        let fixture = called();
        let target = fixture.entity_named("target");
        let user = fixture.entity_named("user");
        let answers = focal_escape_evidence_batch(
            &fixture,
            &[
                (target, kin_model::focal_call_names(target)),
                (user, kin_model::focal_call_names(user)),
            ],
        );
        assert_eq!(answers.len(), 2);
        assert!(matches!(answers[0], FocalEscape::Contained { .. }));
        assert!(matches!(answers[1], FocalEscape::Contained { .. }));
        assert_eq!(
            *fixture.reads.borrow(),
            [APP.to_string()],
            "one read for the batch"
        );
    }
}
