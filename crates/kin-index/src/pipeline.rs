// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::Path;

use tracing::debug;

use kin_blobs::BlobStore;
use kin_model::{
    Entity, EntityRole, FileLayout, FilePathId, GraphStore, Hash256, LanguageId, OpaqueArtifact,
    ParseCompleteness, ParseState, Relation, RelationId, RelationOrigin, StructuredArtifact,
};
use kin_parser::{
    attach_file_context_metadata, attach_file_reference_parse_counts, parse_shallow_file,
    AdapterRegistry, ShallowFile,
};
use kin_projection::build_layout;

use tree_sitter::Tree;

use crate::artifacts;
use crate::classifier::{FileClassification, FileClassifier};
use crate::error::{IndexError, Result};
use crate::fingerprint::{behavior_equivalence_hash, language_supports_equivalence};
use crate::linker::UnresolvedRelation;

/// Result of indexing a single file.
#[derive(Debug)]
pub struct IndexedFile {
    pub file_id: FilePathId,
    pub language: LanguageId,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    /// Cross-file relations that couldn't be fully resolved.
    /// These are collected for later linking by CrossFileLinker.
    pub unresolved_relations: Vec<UnresolvedRelation>,
    pub file_layout: FileLayout,
    pub parse_state: ParseState,
    pub blob_hash: kin_blobs::Hash256,
    /// Raw extracted relations preserved for cross-file linking.
    pub extracted_relations: Vec<kin_parser::ExtractedRelation>,
    /// Import declarations preserved for cross-file linking.
    pub imports: Vec<kin_parser::FileImport>,
}

/// Indexed file plus parser-emitted tests.
///
/// This keeps test metadata available to ingestion callers without widening the
/// existing `IndexedFile` struct yet.
#[derive(Debug)]
pub struct IndexedFileWithTests {
    pub indexed_file: IndexedFile,
    pub tests: Vec<kin_parser::ExtractedTest>,
}

/// Result of indexing any file through the classifier.
#[derive(Debug)]
pub enum IndexedAny {
    /// File was parsed for entities (source code).
    EntitySource(IndexedFile),
    /// File was recognized as a structured artifact.
    StructuredArtifact(StructuredArtifact),
    /// File was parsed at C2 shallow syntax tier.
    ShallowSyntax(ShallowFile),
    /// File was tracked as an opaque blob.
    OpaqueArtifact(OpaqueArtifact),
}

/// The indexing pipeline: parses files, stores blobs, and updates the graph.
pub struct IndexPipeline {
    registry: AdapterRegistry,
}

impl IndexPipeline {
    pub fn new() -> Self {
        Self {
            registry: AdapterRegistry::new(),
        }
    }

    /// Index a single file: parse it, store the blob, and return extracted entities/relations.
    pub fn index_file(&self, path: &Path, blob_store: &BlobStore) -> Result<IndexedFile> {
        let _span = tracing::info_span!(
            "kin.index.index_file",
            path = %path.display()
        )
        .entered();
        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");
        let file_id = FilePathId::new(path.display().to_string());
        Ok(self
            .index_file_content_with_tests(&file_id, &source, blob_hash)?
            .indexed_file)
    }

    /// Index a single file and retain parser-emitted tests alongside the file result.
    pub fn index_file_with_tests(
        &self,
        path: &Path,
        blob_store: &BlobStore,
    ) -> Result<IndexedFileWithTests> {
        let _span = tracing::info_span!(
            "kin.index.index_file_with_tests",
            path = %path.display()
        )
        .entered();
        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");
        let file_id = FilePathId::new(path.display().to_string());
        self.index_file_content_with_tests(&file_id, &source, blob_hash)
    }

    /// Index source content already loaded from blob storage.
    ///
    /// This is used by historical/ref-scoped views that need to rebuild an
    /// entity graph from stored blobs without materializing files to disk.
    pub fn index_file_content_with_tests(
        &self,
        file_id: &FilePathId,
        source: &[u8],
        blob_hash: kin_blobs::Hash256,
    ) -> Result<IndexedFileWithTests> {
        let path = Path::new(&file_id.0);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| IndexError::UnsupportedFile(file_id.0.clone()))?;

        let adapter = self
            .registry
            .get_by_extension_and_content(ext, source)
            .ok_or_else(|| IndexError::UnsupportedFile(ext.to_string()))?;
        let language = adapter.language_id();

        let tree = adapter.parse(source)?;
        let output = adapter.extract(&tree, source, file_id)?;
        let kin_parser::ParseOutput {
            entities: extracted_entities,
            relations: extracted_relations,
            imports,
            tests,
            parse_state,
        } = output;

        let role = classify_file_role(&file_id.0);
        // A test declared inside a production file is invisible to a classifier
        // that only reads the path, and the harness that runs it leaves no edge
        // for the graph to record, so it reads as unreferenced to everything
        // downstream. The parser already recognized these by their attribute or
        // framework convention, so that finding becomes the entity's role.
        // Matching is by name within the file: a production declaration sharing
        // a name with a test in the same file is read as the test.
        let test_names: std::collections::HashSet<&str> =
            tests.iter().map(|test| test.name.as_str()).collect();
        let mut entities: Vec<Entity> = extracted_entities
            .into_iter()
            .map(|entity| {
                let mut ent = entity.into_entity_with_source(language, file_id, Some(source));
                ent.role = if role == EntityRole::Source && test_names.contains(ent.name.as_str()) {
                    EntityRole::Test
                } else {
                    role
                };
                ent
            })
            .collect();
        attach_file_context_metadata(&mut entities, file_id, &imports);
        attach_file_reference_parse_counts(&mut entities, &extracted_relations, &imports);
        attach_equivalence_class(&mut entities, &tree, source, language);
        if language == LanguageId::Go {
            kin_parser::attach_go_command_effect_contract_metadata(&tree, source, &mut entities);
        }

        let parse_completeness = ParseCompleteness::from_parse_state(&parse_state);
        let (relations, unresolved_relations) = resolve_relations(
            &extracted_relations,
            &entities,
            file_id,
            &parse_completeness,
        );
        let file_layout = build_layout(file_id, &entities, source.len(), &[], parse_completeness);

        debug!(
            path = %file_id,
            entities = entities.len(),
            resolved_relations = relations.len(),
            unresolved_relations = unresolved_relations.len(),
            "indexed source content"
        );

        Ok(IndexedFileWithTests {
            indexed_file: IndexedFile {
                file_id: file_id.clone(),
                language,
                entities,
                relations,
                unresolved_relations,
                file_layout,
                extracted_relations,
                imports,
                parse_state,
                blob_hash,
            },
            tests,
        })
    }

    /// Index a single file with an optional incremental parse hint.
    ///
    /// When `old_tree` and `edit_hint` are both provided, uses tree-sitter's
    /// incremental parse for speed (<5ms vs 50-100ms on large files).
    /// Falls back to a full parse when hints are missing.
    ///
    /// Returns the indexed file together with the resulting tree-sitter Tree,
    /// which the caller should cache for future incremental parses.
    pub fn index_file_with_hint(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFile, tree_sitter::Tree)> {
        let _span = tracing::info_span!(
            "kin.index.index_file_with_hint",
            path = %path.display(),
            incremental = old_tree.is_some() && edit_hint.is_some()
        )
        .entered();
        let file_id = FilePathId::new(path.display().to_string());
        let (indexed, tree) =
            self.index_file_hint_with_id(path, blob_store, &file_id, old_tree, edit_hint)?;
        Ok((indexed.indexed_file, tree))
    }

    /// Index a file for incremental reconcile using an explicit logical
    /// `file_id` for all content-addressed identity, while reading source from
    /// `path` on disk.
    ///
    /// This is the single source of truth for the incremental parse/extract
    /// path. Because `EntityId` and `RelationId` are derived from the supplied
    /// `file_id`, absolute-path and normalized (relative) callers produce
    /// identical entity and relation IDs for identical content — the graph-first
    /// content-addressed contract that keeps init and reconcile in agreement.
    fn index_file_hint_with_id(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        file_id: &FilePathId,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFileWithTests, tree_sitter::Tree)> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| IndexError::UnsupportedFile(path.display().to_string()))?;

        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;

        let adapter = self
            .registry
            .get_by_extension_and_content(ext, &source)
            .ok_or_else(|| IndexError::UnsupportedFile(ext.to_string()))?;

        // Store the raw source as a blob
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");

        let language = adapter.language_id();

        // Parse: incremental when hints are available, full otherwise. An
        // edit can flip a content-disambiguated extension to another
        // adapter, and an old tree from the other grammar must never seed an
        // incremental parse — those files always take the full parse.
        let content_disambiguated = ext == "h";
        let tree = match (old_tree, edit_hint) {
            (Some(old), Some(hint)) if !content_disambiguated => {
                debug!(
                    path = %path.display(),
                    start = hint.start_byte,
                    old_end = hint.old_end_byte,
                    new_end = hint.new_end_byte,
                    "incremental parse"
                );
                adapter.parse_incremental(&source, old, hint)?
            }
            _ => adapter.parse(&source)?,
        };
        let output = adapter.extract(&tree, &source, file_id)?;
        let kin_parser::ParseOutput {
            entities: extracted_entities,
            relations: extracted_relations,
            imports,
            tests,
            parse_state,
        } = output;

        // Convert extracted entities to model entities
        let role = classify_file_role(&file_id.0);
        let mut entities: Vec<Entity> = extracted_entities
            .into_iter()
            .map(|e| {
                let mut ent = e.into_entity_with_source(language, file_id, Some(&source));
                ent.role = role;
                ent
            })
            .collect();
        attach_file_context_metadata(&mut entities, file_id, &imports);
        attach_file_reference_parse_counts(&mut entities, &extracted_relations, &imports);
        attach_equivalence_class(&mut entities, &tree, &source, language);
        if language == LanguageId::Go {
            kin_parser::attach_go_command_effect_contract_metadata(&tree, &source, &mut entities);
        }

        // Resolve extracted relations to model relations using entity name mapping
        let parse_completeness = ParseCompleteness::from_parse_state(&parse_state);
        let (relations, unresolved_relations) = resolve_relations(
            &extracted_relations,
            &entities,
            file_id,
            &parse_completeness,
        );
        let file_layout = build_layout(file_id, &entities, source.len(), &[], parse_completeness);

        debug!(
            path = %path.display(),
            entities = entities.len(),
            resolved_relations = relations.len(),
            unresolved_relations = unresolved_relations.len(),
            incremental = old_tree.is_some(),
            "indexed file"
        );

        Ok((
            IndexedFileWithTests {
                indexed_file: IndexedFile {
                    file_id: file_id.clone(),
                    language,
                    entities,
                    relations,
                    unresolved_relations,
                    file_layout,
                    extracted_relations,
                    imports,
                    parse_state,
                    blob_hash,
                },
                tests,
            },
            tree,
        ))
    }

    /// Index a single file with an optional incremental parse hint and retain parser tests.
    pub fn index_file_with_hint_with_tests(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFileWithTests, tree_sitter::Tree)> {
        let _span = tracing::info_span!(
            "kin.index.index_file_with_hint_with_tests",
            path = %path.display(),
            incremental = old_tree.is_some() && edit_hint.is_some()
        )
        .entered();
        let file_id = FilePathId::new(path.display().to_string());
        self.index_file_hint_with_id(path, blob_store, &file_id, old_tree, edit_hint)
    }

    /// Index a file with hint, normalizing its `FilePathId` relative to the given root.
    ///
    /// Same as `index_file_with_hint` but derives all identity from the
    /// root-relative path. `EntityId` and `RelationId` are computed from the
    /// normalized path, so a repo indexed at different absolute locations yields
    /// identical IDs and reconcile agrees with init.
    pub fn index_file_relative_with_hint(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFile, tree_sitter::Tree)> {
        let file_id = normalize_file_path_id(path, root);
        let (indexed, tree) =
            self.index_file_hint_with_id(path, blob_store, &file_id, old_tree, edit_hint)?;
        Ok((indexed.indexed_file, tree))
    }

    /// Index a file with hint, deriving identity from the root-relative path
    /// while retaining parser-emitted tests.
    pub fn index_file_relative_with_hint_with_tests(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFileWithTests, tree_sitter::Tree)> {
        let file_id = normalize_file_path_id(path, root);
        self.index_file_hint_with_id(path, blob_store, &file_id, old_tree, edit_hint)
    }

    /// Index a file, deriving all identity from the root-relative path.
    ///
    /// The `root` prefix is stripped and path separators normalized to forward
    /// slashes, producing a stable cross-platform `FilePathId` regardless of
    /// whether the caller passes an absolute or relative path. Entity and
    /// relation IDs are content-addressed from this normalized path, so the same
    /// repo content produces identical IDs across machines and across the
    /// init/reconcile paths.
    pub fn index_file_relative(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
    ) -> Result<IndexedFile> {
        let _span = tracing::info_span!(
            "kin.index.index_file_relative",
            path = %path.display(),
            root = %root.display()
        )
        .entered();
        Ok(self
            .index_file_relative_with_tests(path, blob_store, root)?
            .indexed_file)
    }

    /// Index a file, deriving identity from the root-relative path and retaining
    /// parser-emitted tests.
    pub fn index_file_relative_with_tests(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
    ) -> Result<IndexedFileWithTests> {
        let _span = tracing::info_span!(
            "kin.index.index_file_relative_with_tests",
            path = %path.display(),
            root = %root.display()
        )
        .entered();
        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");
        let file_id = normalize_file_path_id(path, root);
        self.index_file_content_with_tests(&file_id, &source, blob_hash)
    }

    /// Enrich exact bytes that have already been admitted into repository tree
    /// truth.
    ///
    /// The caller supplies the blob hash for those exact bytes. Parser and
    /// artifact support only select an enrichment facet; they never decide
    /// whether the file exists in the repository.
    pub fn index_any_content(
        &self,
        file_id: &FilePathId,
        content: &[u8],
        blob_hash: kin_blobs::Hash256,
    ) -> Result<IndexedAny> {
        let path = Path::new(&file_id.0);
        let classification = FileClassifier::classify_with_content(path, content);

        match classification {
            FileClassification::EntitySource => Ok(IndexedAny::EntitySource(
                self.index_file_content_with_tests(file_id, content, blob_hash)?
                    .indexed_file,
            )),
            FileClassification::StructuredArtifact(kind) => {
                let artifact = artifacts::extract_artifact(kind, content, file_id)
                    .map_err(|e| IndexError::Graph(e.to_string()))?;

                debug!(
                    path = %file_id,
                    kind = ?kind,
                    hash = %blob_hash,
                    "enriched structured artifact"
                );

                Ok(IndexedAny::StructuredArtifact(artifact))
            }
            FileClassification::ShallowSyntax { language_hint } => {
                if let Some(shallow) = parse_shallow_file(content, file_id, &language_hint) {
                    debug!(
                        path = %file_id,
                        lang = %language_hint,
                        decls = shallow.declarations.len(),
                        imports = shallow.imports.len(),
                        "enriched shallow syntax file (C2)"
                    );
                    return Ok(IndexedAny::ShallowSyntax(shallow));
                }

                debug!(
                    path = %file_id,
                    lang = %language_hint,
                    "C2 grammar unavailable; retaining opaque enrichment"
                );
                Ok(IndexedAny::OpaqueArtifact(OpaqueArtifact {
                    file_id: file_id.clone(),
                    content_hash: Hash256::from_bytes(blob_hash.0),
                    mime_type: None,
                    text_preview: artifacts::opaque_text_preview(content, None),
                }))
            }
            FileClassification::OpaqueArtifact { mime_hint } => {
                debug!(
                    path = %file_id,
                    mime = ?mime_hint,
                    hash = %blob_hash,
                    "enriched opaque artifact"
                );

                let text_preview = artifacts::opaque_text_preview(content, mime_hint.as_deref());
                Ok(IndexedAny::OpaqueArtifact(OpaqueArtifact {
                    file_id: file_id.clone(),
                    content_hash: Hash256::from_bytes(blob_hash.0),
                    mime_type: mime_hint,
                    text_preview,
                }))
            }
        }
    }

    /// Index any file by storing its exact bytes once, then routing those same
    /// bytes through optional semantic enrichment.
    ///
    /// - EntitySource files go through the tree-sitter parser pipeline.
    /// - StructuredArtifact files go through the artifact extractor.
    /// - OpaqueArtifact files are stored as blobs with an optional MIME hint.
    pub fn index_any_file(&self, path: &Path, blob_store: &BlobStore) -> Result<IndexedAny> {
        let _span = tracing::info_span!(
            "kin.index.index_any_file",
            path = %path.display()
        )
        .entered();
        let content =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;
        let blob_hash = blob_store.write(&content)?;
        let file_id = FilePathId::new(path.display().to_string());
        self.index_any_content(&file_id, &content, blob_hash)
    }

    /// Index a file and upsert results into the graph store.
    pub fn index_and_store<G: GraphStore>(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        graph: &G,
    ) -> Result<IndexedFile> {
        let _span = tracing::info_span!(
            "kin.index.index_and_store",
            path = %path.display()
        )
        .entered();
        let indexed = self.index_file(path, blob_store)?;

        for entity in &indexed.entities {
            graph
                .upsert_entity(entity)
                .map_err(|e| IndexError::Graph(e.to_string()))?;
        }
        for relation in &indexed.relations {
            graph
                .upsert_relation(relation)
                .map_err(|e| IndexError::Graph(e.to_string()))?;
        }

        debug!(
            path = %path.display(),
            "upserted {} entities and {} relations",
            indexed.entities.len(),
            indexed.relations.len()
        );

        Ok(indexed)
    }

    /// Resolve cross-file relations given parse data from all files.
    pub fn resolve_cross_file(
        &self,
        files: &[crate::linker::FileParseData],
        artifact_ids: &crate::linker::ArtifactIdentityMap,
    ) -> Result<Vec<Relation>> {
        let _span =
            tracing::info_span!("kin.index.resolve_cross_file", files = files.len()).entered();
        crate::linker::link_cross_file(files, artifact_ids)
    }

    /// Get the adapter registry for direct access.
    pub fn registry(&self) -> &AdapterRegistry {
        &self.registry
    }
}

impl Default for IndexPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize a file path into a stable `FilePathId` by stripping the working
/// directory prefix and converting backslashes to forward slashes.
///
/// If `path` does not start with `root`, it is used as-is (already relative).
pub fn normalize_file_path_id(path: &Path, root: &Path) -> FilePathId {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let normalized = relative.to_string_lossy().replace('\\', "/");
    FilePathId::new(normalized)
}

/// Attach the behavior-equivalence class to each entity of a participating
/// language. Written graph-side onto `fingerprint.equivalence_hash` and consumed
/// at review time to tell behavior-preserving body edits (docstring / comment /
/// formatting) apart from real behavior changes.
///
/// Languages that do not participate keep the zero-hash sentinel; the review
/// layer never downgrades on the sentinel — the safe default. The digest keys
/// only on the entity's own AST node, so it is a pure, deterministic function of
/// that node's tokens.
fn attach_equivalence_class(
    entities: &mut [Entity],
    tree: &Tree,
    source: &[u8],
    language: LanguageId,
) {
    if !language_supports_equivalence(language) {
        return;
    }
    let root = tree.root_node();
    for ent in entities.iter_mut() {
        let Some(span) = ent.span.as_ref() else {
            continue;
        };
        let end = span.end_byte.saturating_sub(1).max(span.start_byte);
        if let Some(node) = root.descendant_for_byte_range(span.start_byte, end) {
            ent.fingerprint.equivalence_hash = behavior_equivalence_hash(&node, source, language);
        }
    }
}

/// Key under which language adapters attach command-effect contracts to
/// entity metadata.
pub const COMMAND_EFFECT_CONTRACT_KEY: &str = "command_effect_contract";

/// Whether a single path component names a test directory: one of its
/// `[_-.]`-delimited words is an exact test keyword. Word-level matching (never a
/// raw substring) keeps a testing tool's shipped product package — `_pytest`,
/// `pytest`, `contest`, `latest` — out of the test role, while still catching
/// compound test dirs such as `unit_tests`, `acceptance_test`, and `__tests__`.
fn is_test_dir_component(component: &str) -> bool {
    const TEST_DIR_WORDS: [&str; 5] = ["test", "tests", "testing", "spec", "specs"];
    component
        .split(['_', '-', '.'])
        .any(|word| TEST_DIR_WORDS.contains(&word))
}

/// Classify a file path into an [`EntityRole`] based on directory and filename patterns.
///
/// Entities from the same file share the same role. The classifier checks path
/// components against well-known patterns (test dirs, vendor dirs, docs, generated
/// markers) and falls back to `Source` for everything else.
///
/// Test-directory detection matches whole path components (via
/// [`is_test_dir_component`]) rather than raw substrings, so a testing tool's own
/// product package — e.g. pytest's `_pytest/` — classifies as source and keeps its
/// signature/breaking changes on the contract surface. A repo's actual test tree
/// (`tests/`, `__tests__/`, or any `test_*`/`*_test` file) still resolves to the
/// test role.
pub fn classify_file_role(path: &str) -> EntityRole {
    let lower = path.to_ascii_lowercase();
    let components: Vec<&str> = lower.split('/').filter(|c| !c.is_empty()).collect();
    let file_name = components.last().copied().unwrap_or("");
    let dir_len = components.len().saturating_sub(1);

    // Test paths. A directory is a test tree only when one of its words is an
    // exact test keyword (component match, never a substring), so `_pytest/` and
    // peers are not swept in. Test *files* are recognized by filename convention
    // regardless of the directory they live in.
    let in_test_dir = components
        .iter()
        .take(dir_len)
        .any(|c| is_test_dir_component(c));
    let is_test_file = file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
        || file_name.ends_with("_test.rs")
        || file_name.ends_with("_test.go")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".test.js")
        || file_name.ends_with(".spec.ts")
        || file_name.ends_with(".spec.js");
    if in_test_dir || is_test_file {
        return EntityRole::Test;
    }

    // Vendored paths (copied dependencies)
    if lower.starts_with("vendor/")
        || lower.contains("/vendor/")
        || lower.starts_with("_vendor/")
        || lower.contains("/_vendor/")
        || lower.starts_with("node_modules/")
        || lower.contains("/node_modules/")
    {
        return EntityRole::Vendored;
    }

    // External paths (foreign code not vendored)
    if lower.starts_with("cextern/")
        || lower.contains("/cextern/")
        || lower.starts_with("extern/")
        || lower.contains("/extern/")
        || lower.starts_with("external/")
        || lower.contains("/external/")
        || lower.starts_with("third_party/")
        || lower.contains("/third_party/")
        || lower.starts_with("thirdparty/")
        || lower.contains("/thirdparty/")
    {
        return EntityRole::External;
    }

    // Generated paths. Amalgamated single-header bundles are byte-copies of
    // real sources regenerated out-of-band: their entities must never read as
    // independent consumers of the sources they were copied from.
    if lower.starts_with("generated/")
        || lower.contains("/generated/")
        || lower.starts_with("__generated__/")
        || lower.contains("/__generated__/")
        || lower.starts_with("single_include/")
        || lower.contains("/single_include/")
        || lower.contains("amalgamated")
        || lower.ends_with(".pb.go")
        || lower.ends_with("_pb2.py")
        || lower.ends_with(".generated.ts")
        || lower.ends_with(".generated.rs")
    {
        return EntityRole::Generated;
    }

    // Docs paths
    if lower.starts_with("docs/")
        || lower.contains("/docs/")
        || lower.starts_with("doc/")
        || lower.contains("/doc/")
        || lower.ends_with(".md")
        || lower.ends_with(".rst")
        || lower.ends_with(".txt")
    {
        return EntityRole::Docs;
    }

    EntityRole::Source
}

/// Resolve extracted name-based relations to entity-ID-based relations.
///
/// Returns both same-file resolved relations and cross-file unresolved ones.
/// Unresolved relations have the source entity ID but target name for deferred linking.
fn resolve_relations(
    extracted: &[kin_parser::ExtractedRelation],
    entities: &[Entity],
    file_id: &FilePathId,
    parse_completeness: &ParseCompleteness,
) -> (Vec<Relation>, Vec<UnresolvedRelation>) {
    let mut resolved = Vec::new();
    let mut relation_indices = HashMap::new();
    let mut unresolved = Vec::new();
    let call_extraction_complete = !extracted
        .iter()
        .any(kin_parser::is_call_extraction_incomplete_marker);

    for rel in extracted {
        if kin_parser::is_call_extraction_incomplete_marker(rel) {
            continue;
        }
        let src = entities.iter().find(|e| e.name == rel.src_name);
        let dst = entities.iter().find(|e| e.name == rel.dst_name);

        match (src, dst) {
            (Some(s), Some(d)) => {
                // Same-file relation: fully resolved
                crate::linker::accumulate_relation(
                    &mut resolved,
                    &mut relation_indices,
                    Relation {
                        id: RelationId::from_content(
                            &s.id.0.to_string(),
                            &d.id.0.to_string(),
                            &format!("{:?}", rel.kind),
                        ),
                        kind: rel.kind,
                        src: kin_model::GraphNodeId::Entity(s.id),
                        dst: kin_model::GraphNodeId::Entity(d.id),
                        confidence: 1.0,
                        origin: RelationOrigin::Parsed,
                        created_in: None,
                        import_source: rel.import_source.clone(),
                        evidence: crate::linker::relation_evidence(
                            rel,
                            file_id,
                            parse_completeness,
                            call_extraction_complete,
                        ),
                    },
                );
            }
            (Some(s), None) => {
                // Partial resolution: src found, dst is cross-file
                debug!(
                    src = %rel.src_name,
                    dst = %rel.dst_name,
                    kind = ?rel.kind,
                    "unresolved cross-file relation, deferring to linker"
                );
                unresolved.push(UnresolvedRelation {
                    kind: rel.kind,
                    src_entity_id: s.id,
                    dst_name: rel.dst_name.clone(),
                });
            }
            _ => {
                // Both unresolved: skip entirely for now
                debug!(
                    src = %rel.src_name,
                    dst = %rel.dst_name,
                    kind = ?rel.kind,
                    "both src and dst unresolved, skipping"
                );
            }
        }
    }
    (resolved, unresolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_pipeline_creates() {
        let pipeline = IndexPipeline::new();
        let langs = pipeline.registry().supported_languages();
        assert_eq!(langs.len(), 14);
    }

    #[test]
    fn index_typescript_file() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let ts_file = dir.path().join("test.ts");
        std::fs::write(
            &ts_file,
            b"export function hello(name: string): string { return `Hello ${name}`; }",
        )
        .unwrap();

        let result = pipeline.index_file(&ts_file, &blob_store).unwrap();
        assert_eq!(result.language, LanguageId::TypeScript);
        assert!(!result.entities.is_empty());
        // By kind and name, the way `index_python_file` below already does it.
        // Since FIR-2675 every TypeScript file carries a Module entity and it is
        // emitted first, so `entities[0]` is the module: this assertion read
        // "test" for the file stem rather than the function it names.
        assert!(
            result
                .entities
                .iter()
                .any(|entity| entity.kind == kin_model::EntityKind::Function
                    && entity.name == "hello"),
            "expected the exported function, got {:?}",
            result
                .entities
                .iter()
                .map(|e| (e.kind, e.name.as_str()))
                .collect::<Vec<_>>()
        );
        assert!(matches!(result.parse_state, ParseState::Valid));
    }

    #[test]
    fn index_python_file() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let py_file = dir.path().join("test.py");
        std::fs::write(&py_file, b"def greet(name):\n    return f'Hello {name}'").unwrap();

        let result = pipeline.index_file(&py_file, &blob_store).unwrap();
        assert_eq!(result.language, LanguageId::Python);
        assert!(
            result
                .entities
                .iter()
                .any(|entity| entity.kind == kin_model::EntityKind::Function
                    && entity.name == "greet")
        );
    }

    #[test]
    fn index_python_repeated_calls_aggregate_shape_evidence_order_independently() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();
        let py_file = dir.path().join("test.py");
        let forward = b"def target(ext, args):\n    return ext, args\n\n\ndef caller():\n    target(1, 2)\n    return target(3, args=4)\n";
        let reversed = b"def target(ext, args):\n    return ext, args\n\n\ndef caller():\n    target(3, args=4)\n    return target(1, 2)\n";
        let evidence_for = |source: &[u8]| {
            std::fs::write(&py_file, source).unwrap();
            let indexed = pipeline.index_file(&py_file, &blob_store).unwrap();
            let caller = indexed
                .entities
                .iter()
                .find(|entity| entity.name == "caller")
                .expect("caller entity");
            let target = indexed
                .entities
                .iter()
                .find(|entity| entity.name == "target")
                .expect("target entity");
            indexed
                .relations
                .iter()
                .find(|relation| {
                    relation.kind == kin_model::RelationKind::Calls
                        && relation.src == kin_model::GraphNodeId::Entity(caller.id)
                        && relation.dst == kin_model::GraphNodeId::Entity(target.id)
                })
                .expect("one logical Calls edge")
                .evidence
                .clone()
        };

        let shapes = |evidence: &[kin_model::RelationEvidence]| {
            let mut shapes: Vec<String> = evidence
                .iter()
                .map(|record| format!("{:?}x{}", record.call_shape, record.occurrence_count))
                .collect();
            shapes.sort();
            shapes
        };

        let forward_evidence = evidence_for(forward);
        let reversed_evidence = evidence_for(reversed);
        // Evidence carries the call SITE now, and the two sources put their
        // calls at different offsets, so byte equality across the reversal is
        // not the invariant any more. What must hold is that the shapes reaching
        // the callee, which is what the merge gate reads, do not depend on which
        // call was written first.
        assert_eq!(shapes(&forward_evidence), shapes(&reversed_evidence));
        assert_eq!(forward_evidence.len(), 2);
        assert!(forward_evidence.iter().any(|evidence| {
            evidence
                .call_shape
                .as_ref()
                .is_some_and(|shape| shape.keywords == ["args"])
        }));
        assert!(
            forward_evidence
                .iter()
                .all(|record| record.source_span.is_some()),
            "the same-file arm must carry each call's site: {forward_evidence:?}"
        );
    }

    #[test]
    fn incomplete_python_parse_marks_same_file_call_shape_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();
        let py_file = dir.path().join("test.py");
        std::fs::write(
            &py_file,
            b"def target(ext, args):\n    return ext, args\n\n\ndef caller():\n    target(1, 2)\n    return target(3, args=4\n",
        )
        .unwrap();

        let indexed = pipeline.index_file(&py_file, &blob_store).unwrap();
        assert!(matches!(indexed.parse_state, ParseState::Incomplete { .. }));
        let caller = indexed
            .entities
            .iter()
            .find(|entity| entity.name == "caller")
            .expect("caller entity");
        let target = indexed
            .entities
            .iter()
            .find(|entity| entity.name == "target")
            .expect("target entity");
        let edge = indexed
            .relations
            .iter()
            .find(|relation| {
                relation.kind == kin_model::RelationKind::Calls
                    && relation.src == kin_model::GraphNodeId::Entity(caller.id)
                    && relation.dst == kin_model::GraphNodeId::Entity(target.id)
            })
            .expect("surviving positional call edge");
        assert_eq!(edge.evidence.len(), 1);
        assert_eq!(
            edge.evidence[0].parser_rule.as_deref(),
            Some(crate::linker::CALL_SHAPE_EVIDENCE_INCOMPLETE_PARSE_V1)
        );
        assert!(edge.evidence[0].call_shape.is_none());
    }

    #[test]
    fn incomplete_python_call_extraction_downgrades_same_file_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let py_file = dir.path().join("test.py");
        std::fs::write(
            &py_file,
            b"def target(ext, args):\n    return ext, args\n\ndef other(ext, args):\n    return ext, args\n\ndef caller(flag):\n    target(1, 2)\n    return (target if flag else other)(ext=1, args=2)\n",
        )
        .unwrap();

        let indexed = IndexPipeline::new()
            .index_file(&py_file, &blob_store)
            .expect("index syntax-valid Python source");
        assert!(matches!(indexed.parse_state, ParseState::Valid));
        assert!(matches!(
            indexed.file_layout.parse_completeness,
            ParseCompleteness::Full
        ));
        assert!(
            indexed
                .extracted_relations
                .iter()
                .any(kin_parser::is_call_extraction_incomplete_marker),
            "raw parser marker must survive for later linking and history"
        );
        assert!(
            indexed.unresolved_relations.iter().all(|relation| {
                relation.dst_name != kin_parser::CALL_EXTRACTION_INCOMPLETE_MARKER_V1
            }),
            "the control record must never become an unresolved semantic relation"
        );
        let caller = indexed
            .entities
            .iter()
            .find(|entity| entity.name == "caller")
            .expect("caller entity");
        let target = indexed
            .entities
            .iter()
            .find(|entity| entity.name == "target")
            .expect("target entity");
        let edge = indexed
            .relations
            .iter()
            .find(|relation| {
                relation.kind == kin_model::RelationKind::Calls
                    && relation.src == kin_model::GraphNodeId::Entity(caller.id)
                    && relation.dst == kin_model::GraphNodeId::Entity(target.id)
            })
            .expect("surviving same-file target edge");
        assert_eq!(edge.evidence.len(), 1);
        assert_eq!(
            edge.evidence[0].parser_rule.as_deref(),
            Some(crate::linker::CALL_SHAPE_EVIDENCE_INCOMPLETE_EXTRACTION_V1)
        );
        assert!(edge.evidence[0].call_shape.is_none());
    }

    #[test]
    fn index_unsupported_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let txt_file = dir.path().join("readme.txt");
        std::fs::write(&txt_file, b"just some text").unwrap();

        let result = pipeline.index_file(&txt_file, &blob_store);
        assert!(result.is_err());
    }

    #[test]
    fn index_c_file_entity_source() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let c_file = dir.path().join("hello.c");
        std::fs::write(
            &c_file,
            b"#include <stdio.h>\n\nvoid hello(void) {\n    printf(\"hi\\n\");\n}\n\nint add(int a, int b) {\n    return a + b;\n}\n",
        )
        .unwrap();

        let result = pipeline.index_file(&c_file, &blob_store).unwrap();
        let names: Vec<&str> = result.entities.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(result.language, LanguageId::C);
        assert!(names.contains(&"hello"), "Expected 'hello' in {:?}", names);
        assert!(names.contains(&"add"), "Expected 'add' in {:?}", names);
    }

    #[test]
    fn index_rust_file() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let rs_file = dir.path().join("lib.rs");
        std::fs::write(
            &rs_file,
            b"pub fn add(a: i32, b: i32) -> i32 { a + b }\npub struct Point { x: f64, y: f64 }",
        )
        .unwrap();

        let result = pipeline.index_file(&rs_file, &blob_store).unwrap();
        assert_eq!(result.language, LanguageId::Rust);
        assert!(result.entities.len() >= 2);
    }

    #[test]
    fn classify_source_files() {
        assert_eq!(classify_file_role("src/lib.rs"), EntityRole::Source);
        assert_eq!(classify_file_role("pkg/api/handler.go"), EntityRole::Source);
        assert_eq!(classify_file_role("internal/core.go"), EntityRole::Source);
    }

    #[test]
    fn classify_test_files() {
        assert_eq!(classify_file_role("tests/unit_test.py"), EntityRole::Test);
        assert_eq!(classify_file_role("src/foo_test.rs"), EntityRole::Test);
        assert_eq!(classify_file_role("src/foo_test.go"), EntityRole::Test);
        assert_eq!(classify_file_role("src/foo.test.ts"), EntityRole::Test);
        assert_eq!(classify_file_role("src/foo.spec.js"), EntityRole::Test);
        assert_eq!(classify_file_role("test/helpers.py"), EntityRole::Test);
        assert_eq!(
            classify_file_role("__tests__/App.test.ts"),
            EntityRole::Test
        );
    }

    /// A testing tool ships product code whose package name embeds "test"
    /// (pytest's `_pytest/`). That code is the framework's own public API — its
    /// signature/breaking changes are a contract surface — so it must classify
    /// as source, never test, even though a naive substring match on "test/"
    /// would sweep it into the test role and suppress those findings. The tool's
    /// actual test tree (`testing/`) still classifies as test.
    #[test]
    fn classify_test_named_product_package_as_source() {
        // pytest's shipped product package, in both `src/` layout and bare form.
        assert_eq!(
            classify_file_role("src/_pytest/python.py"),
            EntityRole::Source
        );
        assert_eq!(classify_file_role("_pytest/main.py"), EntityRole::Source);
        assert_eq!(classify_file_role("_pytest/nodes.py"), EntityRole::Source);
        assert_eq!(
            classify_file_role("src/_pytest/__init__.py"),
            EntityRole::Source
        );
        assert_eq!(
            classify_file_role("src/pytest/__init__.py"),
            EntityRole::Source
        );
        // Other product packages whose names merely embed a test keyword.
        assert_eq!(
            classify_file_role("src/contest/round.py"),
            EntityRole::Source
        );
        assert_eq!(classify_file_role("latest/release.rs"), EntityRole::Source);

        // pytest's own test tree stays test-role: a `test_*` file is a test
        // wherever it lives, and compound / underscore-prefixed test dirs still
        // resolve to a `test` word.
        assert_eq!(
            classify_file_role("testing/test_collection.py"),
            EntityRole::Test
        );
        assert_eq!(
            classify_file_role("integration_tests/api.py"),
            EntityRole::Test
        );
        assert_eq!(
            classify_file_role("acceptance_test/flow.py"),
            EntityRole::Test
        );
        assert_eq!(classify_file_role("_tests/helper.py"), EntityRole::Test);
        // A bare helper in a `testing/` tree is still test infrastructure even
        // without a `test_*` filename — `testing` is a test word, while
        // `_pytest`/`contest`/`latest` embed `test` only as a substring.
        assert_eq!(
            classify_file_role("testing/util_helper.py"),
            EntityRole::Test
        );
        assert_eq!(classify_file_role("testing/conftest.py"), EntityRole::Test);
    }

    #[test]
    fn classify_external_files() {
        assert_eq!(
            classify_file_role("cextern/wcslib/wcs.c"),
            EntityRole::External
        );
        assert_eq!(
            classify_file_role("third_party/zlib/zlib.h"),
            EntityRole::External
        );
    }

    #[test]
    fn classify_vendored_files() {
        assert_eq!(
            classify_file_role("vendor/github.com/pkg/errors/errors.go"),
            EntityRole::Vendored
        );
        assert_eq!(
            classify_file_role("node_modules/react/index.js"),
            EntityRole::Vendored
        );
    }

    #[test]
    fn classify_generated_files() {
        assert_eq!(classify_file_role("proto/api.pb.go"), EntityRole::Generated);
        assert_eq!(
            classify_file_role("gen/schema_pb2.py"),
            EntityRole::Generated
        );
        assert_eq!(
            classify_file_role("src/generated/types.ts"),
            EntityRole::Generated
        );
    }

    #[test]
    fn classify_docs_files() {
        assert_eq!(classify_file_role("docs/guide.md"), EntityRole::Docs);
        assert_eq!(classify_file_role("README.md"), EntityRole::Docs);
        assert_eq!(classify_file_role("doc/api.rst"), EntityRole::Docs);
    }

    // Relative indexing must derive entity/relation identity from the
    // root-relative path, never the machine-absolute path, so that the init and
    // reconcile paths agree and identical content produces identical IDs across
    // machines and checkout locations.

    const REL_RUST_SRC: &[u8] = b"pub struct Point { x: f64, y: f64 }\n\
impl Point { pub fn origin() -> Point { Point { x: 0.0, y: 0.0 } } }\n\
pub fn add(a: i32, b: i32) -> i32 { a + b }\n";

    fn write_repo_file(root: &Path, rel: &str, content: &[u8]) -> std::path::PathBuf {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, content).unwrap();
        abs
    }

    fn entity_id_set(indexed: &IndexedFile) -> std::collections::HashSet<kin_model::EntityId> {
        indexed.entities.iter().map(|e| e.id).collect()
    }

    fn relation_id_set(indexed: &IndexedFile) -> std::collections::HashSet<kin_model::RelationId> {
        indexed.relations.iter().map(|r| r.id).collect()
    }

    #[test]
    fn relative_index_derives_entity_ids_from_relative_path_not_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blob_store = BlobStore::new(root.join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs = write_repo_file(root, "src/geo/point.rs", REL_RUST_SRC);
        let indexed = pipeline
            .index_file_relative(&abs, &blob_store, root)
            .unwrap();

        assert_eq!(indexed.file_id.0, "src/geo/point.rs");

        let mut checked = 0;
        for entity in &indexed.entities {
            let Some(span) = entity.span.as_ref() else {
                continue;
            };
            let relative = kin_model::EntityId::from_content(
                "src/geo/point.rs",
                &entity.name,
                &format!("{:?}", entity.kind),
                span.start_line,
            );
            let absolute = kin_model::EntityId::from_content(
                &abs.display().to_string(),
                &entity.name,
                &format!("{:?}", entity.kind),
                span.start_line,
            );
            assert_eq!(
                entity.id, relative,
                "entity {} is not addressed by its relative path",
                entity.name
            );
            assert_ne!(
                entity.id, absolute,
                "entity {} still bakes the machine-absolute path",
                entity.name
            );
            assert_eq!(entity.file_origin.as_ref().unwrap().0, "src/geo/point.rs");
            checked += 1;
        }
        assert!(checked >= 2, "expected at least two spanned entities");
    }

    #[test]
    fn relative_index_is_invariant_across_absolute_roots() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let blob_a = BlobStore::new(dir_a.path().join("blobs")).unwrap();
        let blob_b = BlobStore::new(dir_b.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs_a = write_repo_file(dir_a.path(), "src/foo.rs", REL_RUST_SRC);
        let abs_b = write_repo_file(dir_b.path(), "src/foo.rs", REL_RUST_SRC);

        let a = pipeline
            .index_file_relative(&abs_a, &blob_a, dir_a.path())
            .unwrap();
        let b = pipeline
            .index_file_relative(&abs_b, &blob_b, dir_b.path())
            .unwrap();

        assert!(!a.entities.is_empty());
        assert_eq!(
            entity_id_set(&a),
            entity_id_set(&b),
            "entity IDs must not depend on the absolute checkout location"
        );
        assert_eq!(
            relation_id_set(&a),
            relation_id_set(&b),
            "relation IDs must not depend on the absolute checkout location"
        );
    }

    #[test]
    fn reconcile_relative_matches_init_content_ids() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blob_store = BlobStore::new(root.join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs = write_repo_file(root, "src/foo.rs", REL_RUST_SRC);

        // reconcile path: absolute path on disk, normalized against the root.
        let reconcile = pipeline
            .index_file_relative(&abs, &blob_store, root)
            .unwrap();

        // init path: already-loaded content addressed by the relative file_id.
        let content = std::fs::read(&abs).unwrap();
        let blob_hash = blob_store.write(&content).unwrap();
        let init = pipeline
            .index_file_content_with_tests(&FilePathId::new("src/foo.rs"), &content, blob_hash)
            .unwrap()
            .indexed_file;

        assert_eq!(
            entity_id_set(&reconcile),
            entity_id_set(&init),
            "reconcile must produce the same entity IDs as init"
        );
        assert_eq!(
            relation_id_set(&reconcile),
            relation_id_set(&init),
            "reconcile must produce the same relation IDs as init"
        );
    }

    #[test]
    fn relative_index_relations_reference_local_entities() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blob_store = BlobStore::new(root.join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs = write_repo_file(root, "src/foo.rs", REL_RUST_SRC);
        let indexed = pipeline
            .index_file_relative(&abs, &blob_store, root)
            .unwrap();

        let ids = entity_id_set(&indexed);
        for rel in &indexed.relations {
            if let kin_model::GraphNodeId::Entity(src) = &rel.src {
                assert!(
                    ids.contains(src),
                    "relation src {src:?} is not a local entity"
                );
            }
            if let kin_model::GraphNodeId::Entity(dst) = &rel.dst {
                assert!(
                    ids.contains(dst),
                    "relation dst {dst:?} is not a local entity"
                );
            }
        }
        for unresolved in &indexed.unresolved_relations {
            assert!(
                ids.contains(&unresolved.src_entity_id),
                "unresolved relation src {:?} is not a local entity",
                unresolved.src_entity_id
            );
        }
    }

    #[test]
    fn relative_hint_index_matches_non_hint_relative_ids() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blob_store = BlobStore::new(root.join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs = write_repo_file(root, "src/foo.rs", REL_RUST_SRC);

        let full = pipeline
            .index_file_relative(&abs, &blob_store, root)
            .unwrap();
        let (hinted, _tree) = pipeline
            .index_file_relative_with_hint(&abs, &blob_store, root, None, None)
            .unwrap();

        assert_eq!(hinted.file_id.0, "src/foo.rs");
        assert_eq!(
            entity_id_set(&full),
            entity_id_set(&hinted),
            "incremental and full relative indexing must agree on entity IDs"
        );
    }

    #[test]
    fn admitted_binary_with_source_extension_gets_only_opaque_enrichment() {
        let bytes = b"\0\xff\x10not-rust";
        let hash = kin_blobs::digest(bytes);
        let indexed = IndexPipeline::new()
            .index_any_content(&FilePathId::new("src/payload.rs"), bytes, hash)
            .unwrap();

        let IndexedAny::OpaqueArtifact(artifact) = indexed else {
            panic!("binary bytes must not be forced through the Rust parser");
        };
        assert_eq!(artifact.file_id, FilePathId::new("src/payload.rs"));
        assert_eq!(artifact.content_hash, Hash256::from_bytes(hash.0));
        assert_eq!(
            artifact.mime_type.as_deref(),
            Some("application/octet-stream")
        );
        assert!(
            artifact.text_preview.is_none(),
            "binary bytes must not enter the text index"
        );
    }

    /// The FIR-2183 mechanism: real ingest stored every opaque artifact with no
    /// text at all, so the text index and the artifact embedding saw only a
    /// path and a MIME type, and a docs store could not answer for its own
    /// content. The deep marker sits past any head-sized preview, so this test
    /// fails against head-only retention too, not just against `None`.
    #[test]
    fn admitted_markdown_keeps_deep_text_in_its_retrieval_preview() {
        let mut body =
            String::from("# Field Notes\n\nHead marker: zebrafish lantern protocol.\n\n");
        for index in 0..40 {
            body.push_str(&format!(
                "Routine paragraph {index} about ordinary upkeep of the greenhouse ledger and \
                 irrigation schedule, nothing remarkable here.\n\n"
            ));
        }
        body.push_str(
            "## Deep Doctrine\n\nThe quokka semaphore doctrine states that a docs store must \
             answer for its own content.\n",
        );
        assert!(
            body.find("quokka").unwrap() > 2_000,
            "the deep marker must sit beyond any head-sized preview"
        );

        let bytes = body.as_bytes();
        let hash = kin_blobs::digest(bytes);
        let indexed = IndexPipeline::new()
            .index_any_content(&FilePathId::new("AGENTS.md"), bytes, hash)
            .unwrap();

        let IndexedAny::OpaqueArtifact(artifact) = indexed else {
            panic!("markdown must take the opaque enrichment facet");
        };
        let preview = artifact
            .text_preview
            .expect("a textual artifact must retain its text for retrieval");
        assert!(preview.contains("zebrafish lantern protocol"));
        assert!(preview.contains("quokka semaphore doctrine"));
    }

    /// The retention bound holds, and an extensionless text file qualifies by
    /// content rather than by MIME hint.
    #[test]
    fn artifact_text_retention_is_bounded_and_content_qualified() {
        let body = "word ".repeat(60_000);
        let bytes = body.as_bytes();
        let hash = kin_blobs::digest(bytes);
        let indexed = IndexPipeline::new()
            .index_any_content(&FilePathId::new("NOTICE"), bytes, hash)
            .unwrap();

        let IndexedAny::OpaqueArtifact(artifact) = indexed else {
            panic!("extensionless text must take the opaque enrichment facet");
        };
        assert_eq!(artifact.mime_type, None);
        let preview = artifact
            .text_preview
            .expect("printable extensionless bytes must qualify as text");
        assert_eq!(
            preview.chars().count(),
            crate::artifacts::ARTIFACT_TEXT_RETENTION_CHARS
        );
    }

    #[test]
    fn admitted_compose_bytes_get_structured_enrichment_without_changing_blob_identity() {
        let bytes = b"services:\n  api:\n    image: example/api\n";
        let hash = kin_blobs::digest(bytes);
        let indexed = IndexPipeline::new()
            .index_any_content(&FilePathId::new("compose.yaml"), bytes, hash)
            .unwrap();

        let IndexedAny::StructuredArtifact(artifact) = indexed else {
            panic!("Compose content must receive its structured facet");
        };
        assert_eq!(artifact.file_id, FilePathId::new("compose.yaml"));
        assert_eq!(artifact.kind, kin_model::ArtifactKind::ComposeFile);
        assert_ne!(
            artifact.content_hash,
            Hash256::from_bytes(hash.0),
            "structured hash is an enrichment fingerprint, not exact tree identity"
        );
    }

    #[test]
    fn test_functions_in_a_production_file_carry_the_test_role() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();
        let source = br#"
pub fn shipped() -> u32 { 1 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_returns_one() {
        assert_eq!(shipped(), 1);
    }
}
"#;
        let blob_hash = blob_store.write(source).unwrap();
        let indexed = pipeline
            .index_file_content_with_tests(&FilePathId::new("src/shipped.rs"), source, blob_hash)
            .unwrap();

        let role_of = |name: &str| {
            indexed
                .indexed_file
                .entities
                .iter()
                .find(|entity| entity.name == name)
                .unwrap_or_else(|| {
                    panic!(
                        "{name} missing from {:?}",
                        indexed
                            .indexed_file
                            .entities
                            .iter()
                            .map(|e| e.name.as_str())
                            .collect::<Vec<_>>()
                    )
                })
                .role
        };

        assert_eq!(
            role_of("shipped_returns_one"),
            EntityRole::Test,
            "a test in a production path is still a test"
        );
        assert_eq!(
            role_of("shipped"),
            EntityRole::Source,
            "the production function beside it keeps its role"
        );
    }
}
