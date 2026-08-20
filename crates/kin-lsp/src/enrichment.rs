// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Convert LSP responses into graph relations.
//!
//! The enrichment pipeline:
//! 1. For each entity in the graph, prepare a call hierarchy request
//! 2. Send to LSP server, get outgoing/incoming calls
//! 3. Match call targets against existing graph entities by file + position
//! 4. Produce Relations with RelationOrigin::Lsp

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::Path;

use tracing::debug;

use crate::error::Result;
use crate::file_enrichment::identifier_positions_in_line;
use crate::lifecycle::LspServer;
use crate::protocol::{
    self, CallHierarchyItem, Position, TextDocumentIdentifier, TypeHierarchyItem,
    TypeHierarchyPrepareParams, TypeHierarchySupertypesParams,
};
use kin_model::{
    EntityId, FilePathId, GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind,
    RelationOrigin, SourceSpan,
};

/// Result of enriching a single file via LSP.
#[derive(Debug, Default)]
pub struct EnrichmentResult {
    /// New relations discovered by LSP (type-resolved calls, references, etc.)
    pub relations: Vec<Relation>,
    /// Entities that LSP couldn't resolve (for diagnostics).
    pub unresolved: Vec<String>,
    /// Number of call hierarchy items processed.
    pub items_processed: usize,
}

/// Lightweight entity reference for matching LSP locations to graph entities.
#[derive(Debug, Clone)]
pub struct EntityRef {
    pub id: EntityId,
    pub name: String,
    pub file_path: String,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    /// Position of the entity NAME (not declaration start).
    /// LSP prepareCallHierarchy needs cursor on the name, not the fn keyword.
    pub name_line: u32,
    pub name_col: u32,
}

/// Spatial index: given a file URI and line number, find the matching entity.
pub struct EntityIndex {
    /// Map from file path → sorted list of (start_line, end_line, EntityRef)
    by_file: HashMap<String, Vec<EntityRef>>,
}

impl EntityIndex {
    /// Build an index from entity refs.
    pub fn new(entities: Vec<EntityRef>) -> Self {
        let mut by_file: HashMap<String, Vec<EntityRef>> = HashMap::new();
        for entity in entities {
            by_file
                .entry(entity.file_path.clone())
                .or_default()
                .push(entity);
        }
        // Sort each file's entities by start line for binary search.
        for entries in by_file.values_mut() {
            entries.sort_by_key(|e| e.start_line);
        }
        Self { by_file }
    }

    fn entries_for_path(&self, path: &str) -> Option<&Vec<EntityRef>> {
        self.by_file.get(path).or_else(|| {
            self.by_file
                .iter()
                .find(|(k, _)| path.ends_with(k.as_str()) || k.ends_with(path))
                .map(|(_, v)| v)
        })
    }

    /// Find the entity at the given file URI and position.
    ///
    /// Returns the INNERMOST entity whose span contains the line: the method
    /// rather than the class that holds it, and the class rather than the module
    /// that holds them both.
    ///
    /// This returned the FIRST containing span, and a module entity carries a
    /// whole-file span and sorts first, so every position in a file resolved to
    /// its module. The consequences were total rather than partial. Same-file
    /// targets resolved to the same module as their source, making `source ==
    /// dst`, and 954 edges were silently dropped that way in one file of the
    /// requests corpus. Cross-file targets resolved to the target file's module,
    /// so the whole file-level definitions pass emitted only module-to-module
    /// edges and produced no entity-level edge at all. The pass answered
    /// correctly and the mapping threw the answer away.
    ///
    /// Line bases: LSP positions are 0-based, and kin graph spans are 0-based
    /// too (`kin_mcp`'s `presentation_line` adds one for display, which is what
    /// makes the graph's own base visible). They agree, so no conversion happens
    /// here. That agreement is asserted in the tests rather than assumed,
    /// because it currently holds by convention on both sides and a one-line
    /// change to either would silently shift every lookup by a line, which on
    /// `def` lines means resolving the enclosing scope instead of the method.
    pub fn find_at(&self, uri: &str, line: u32) -> Option<&EntityRef> {
        let path = protocol::uri_to_path(uri)?;
        let path_str = path.to_string_lossy();
        let entries = self.entries_for_path(path_str.as_ref())?;

        entries
            .iter()
            .filter(|e| line >= e.start_line && line <= e.end_line)
            // Smallest span wins. Ties break on the later start, which is the
            // more deeply nested of two spans that begin together, so a method
            // whose body is its whole parent still beats the parent.
            .min_by_key(|e| {
                (
                    e.end_line.saturating_sub(e.start_line),
                    u32::MAX - e.start_line,
                )
            })
    }

    /// Return every entity known to live in a file path.
    pub fn entities_in_file(&self, file_path: &str) -> Vec<&EntityRef> {
        self.entries_for_path(file_path)
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }

    /// Find entity by name match (fallback when position doesn't match).
    pub fn find_by_name(&self, name: &str) -> Option<&EntityRef> {
        self.by_file
            .values()
            .flat_map(|entries| entries.iter())
            .find(|e| e.name == name || e.name.ends_with(&format!(".{}", name)))
    }
}

/// Evidence naming the position the server was asked about.
///
/// The call site, not the definition. Enrichment relations carried
/// `evidence: Vec::new()`, so an edge a language server proved arrived with no
/// reference site and every consuming surface reported `no_evidence_span` for
/// it. The position is already in hand at every call below, so this costs no
/// extra round trip: it is the range the server itself reported the reference
/// at.
///
/// Lines are 0-based on both sides, matching LSP and kin graph spans, and the
/// display surfaces add one.
pub(crate) fn query_position_evidence(
    rule: &'static str,
    file: &str,
    range: &protocol::Range,
) -> Vec<RelationEvidence> {
    vec![RelationEvidence {
        source_span: Some(SourceSpan {
            file: FilePathId::new(file),
            start_byte: 0,
            end_byte: 0,
            start_line: range.start.line,
            start_col: range.start.character,
            end_line: range.end.line,
            end_col: range.end.character,
        }),
        parser_rule: Some(rule.to_string()),
        token: None,
        source_path: None,
        resolved_path: None,
        occurrence_count: 1,
        call_shape: None,
    }]
}

pub(crate) fn deterministic_relation_id(
    kind: RelationKind,
    src: EntityId,
    dst: EntityId,
) -> RelationId {
    let mut first = std::collections::hash_map::DefaultHasher::new();
    kind.hash(&mut first);
    src.hash(&mut first);
    dst.hash(&mut first);
    "kin-lsp".hash(&mut first);

    let mut second = std::collections::hash_map::DefaultHasher::new();
    "kin-lsp".hash(&mut second);
    dst.hash(&mut second);
    src.hash(&mut second);
    kind.hash(&mut second);

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    RelationId::from_bytes(bytes)
}

/// Query outgoing calls from a specific entity and produce Relations.
pub async fn enrich_entity_calls(
    server: &LspServer,
    caller: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
) -> Result<Vec<Relation>> {
    if !server.has_call_hierarchy() {
        return Ok(Vec::new());
    }

    let file_path = workspace_root.join(&caller.file_path);
    let uri = protocol::path_to_uri(&file_path);

    // Step 1: Prepare call hierarchy at the entity's position.
    let prepare_result = server
        .client
        .request(
            "textDocument/prepareCallHierarchy",
            protocol::CallHierarchyPrepareParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position: Position {
                    line: caller.name_line,
                    character: caller.name_col,
                },
            },
        )
        .await;

    let items: Vec<CallHierarchyItem> = match prepare_result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %caller.name, error = %e, "prepareCallHierarchy failed");
            return Ok(Vec::new());
        }
    };

    if items.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Query outgoing calls for the first item (the entity itself).
    let item = &items[0];
    let outgoing_result = server
        .client
        .request(
            "callHierarchy/outgoingCalls",
            protocol::CallHierarchyOutgoingCallsParams { item: item.clone() },
        )
        .await;

    let outgoing: Vec<protocol::CallHierarchyOutgoingCall> = match outgoing_result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %caller.name, error = %e, "outgoingCalls failed");
            return Ok(Vec::new());
        }
    };

    // Step 3: Match each outgoing call target to a graph entity.
    let mut relations = Vec::new();
    for call in &outgoing {
        let target_line = call.to.selection_range.start.line;
        let target_uri = &call.to.uri;

        // Position only. The name fallback matched the FIRST entity whose name
        // ended with the target's, which for `send` was the caller itself, so
        // the edge became a self-loop and was dropped: a proven answer thrown
        // away and reported as nothing found. Worse, when it did not self-loop
        // it stamped an arbitrary same-named entity with `RelationOrigin::Lsp`,
        // which reads `type_resolved`, a fabricated edge wearing the strongest
        // resolution there is. A position that maps to nothing now produces no
        // edge, which is the honest answer and a reportable gap.
        let target = index.find_at(target_uri, target_line);

        match target {
            Some(target_ref) => {
                relations.push(Relation {
                    id: deterministic_relation_id(RelationKind::Calls, caller.id, target_ref.id),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(target_ref.id),
                    confidence: 0.95,
                    origin: RelationOrigin::Lsp,
                    created_in: None,
                    import_source: None,
                    // The call SITE inside the caller, which is what a reader
                    // needs and what `reference_lines` publishes.
                    evidence: call
                        .from_ranges
                        .first()
                        .map(|range| {
                            query_position_evidence("lsp_call_hierarchy", &caller.file_path, range)
                        })
                        .unwrap_or_default(),
                });
            }
            None => {
                debug!(
                    caller = %caller.name,
                    target = %call.to.name,
                    "LSP call target not found in graph"
                );
            }
        }
    }

    Ok(relations)
}

/// Query type hierarchy supertypes for a method entity to detect Overrides relations.
/// If the method exists on a parent trait/type, emit an Overrides relation.
pub async fn enrich_entity_overrides(
    server: &LspServer,
    method: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
) -> Result<Vec<Relation>> {
    if !server.has_type_hierarchy() {
        return Ok(Vec::new());
    }

    // Only query methods (names containing '.'), not standalone functions.
    if !method.name.contains('.') {
        return Ok(Vec::new());
    }

    let method_short_name = method.name.rsplit('.').next().unwrap_or(&method.name);

    let file_path = workspace_root.join(&method.file_path);
    let uri = protocol::path_to_uri(&file_path);

    // Step 1: Prepare type hierarchy at the method's position.
    let prepare_result = server
        .client
        .request(
            "textDocument/prepareTypeHierarchy",
            TypeHierarchyPrepareParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position: Position {
                    line: method.name_line,
                    character: method.start_col,
                },
            },
        )
        .await;

    let items: Vec<TypeHierarchyItem> = match prepare_result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %method.name, error = %e, "prepareTypeHierarchy failed");
            return Ok(Vec::new());
        }
    };

    if items.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Query supertypes for the first item.
    let item = &items[0];
    let supertypes_result = server
        .client
        .request(
            "typeHierarchy/supertypes",
            TypeHierarchySupertypesParams { item: item.clone() },
        )
        .await;

    let supertypes: Vec<TypeHierarchyItem> = match supertypes_result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %method.name, error = %e, "typeHierarchy/supertypes failed");
            return Ok(Vec::new());
        }
    };

    // Step 3: For each supertype, check if a method with the same name exists in the graph.
    let mut relations = Vec::new();
    for supertype in &supertypes {
        // Look for "SupertypeName.method_name" in the graph index.
        let candidate_name = format!("{}.{}", supertype.name, method_short_name);
        // Position only, for the same reason as the call mapping: a name match
        // here would pick some other class's method of the same name and stamp
        // it as a proven override.
        let _ = &candidate_name;
        let target = index.find_at(&supertype.uri, supertype.selection_range.start.line);

        if let Some(target_ref) = target {
            relations.push(Relation {
                id: deterministic_relation_id(RelationKind::Overrides, method.id, target_ref.id),
                kind: RelationKind::Overrides,
                src: GraphNodeId::Entity(method.id),
                dst: GraphNodeId::Entity(target_ref.id),
                confidence: 0.90,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            });
            debug!(
                method = %method.name,
                overrides = %target_ref.name,
                "discovered Overrides relation"
            );
        }
    }

    Ok(relations)
}

/// The member expression an identifier position opens, when it opens one.
///
/// Returns the receiver text, the member's column, and the member's text for
/// `express.Router` asked at `express`. Returns `None` for a bare identifier,
/// for the member half of an expression (which is not itself a receiver), and
/// for a dot followed by anything that is not an identifier.
pub(crate) fn member_expression_at(line_text: &str, col: u32) -> Option<(String, u32, String)> {
    let chars: Vec<char> = line_text.chars().collect();
    let start = col as usize;
    if start >= chars.len() {
        return None;
    }
    // Both halves must START like an identifier rather than merely contain
    // identifier characters, so `1.5` is a number and not a member expression.
    // The caller only offers identifier starts today, but a predicate that
    // depends on its caller's filtering is one refactor from being wrong.
    if !(chars[start].is_alphabetic() || chars[start] == '_') {
        return None;
    }
    let mut end = start;
    while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
        end += 1;
    }
    if chars.get(end) != Some(&'.') {
        return None;
    }
    let member_start = end + 1;
    if !chars
        .get(member_start)
        .is_some_and(|ch| ch.is_alphabetic() || *ch == '_')
    {
        return None;
    }
    let mut member_end = member_start;
    while member_end < chars.len()
        && (chars[member_end].is_alphanumeric() || chars[member_end] == '_')
    {
        member_end += 1;
    }
    Some((
        chars[start..end].iter().collect(),
        member_start as u32,
        chars[member_start..member_end].iter().collect(),
    ))
}

/// One location answer for a request at a position, flattened out of the two
/// shapes a server may reply with.
pub(crate) async fn locations_at(
    server: &LspServer,
    method: &'static str,
    uri: &str,
    line: u32,
    character: u32,
) -> Vec<protocol::Location> {
    let result = server
        .client
        .request(
            method,
            protocol::TextDocumentPositionParams {
                text_document: TextDocumentIdentifier {
                    uri: uri.to_string(),
                },
                position: Position { line, character },
            },
        )
        .await;
    let Ok(value) = result else {
        return Vec::new();
    };
    serde_json::from_value::<Vec<protocol::Location>>(value.clone()).unwrap_or_else(|_| {
        serde_json::from_value::<protocol::Location>(value)
            .map(|one| vec![one])
            .unwrap_or_default()
    })
}

/// Whether this receiver names a module rather than a value in this file.
///
/// Measured on express with typescript-language-server: `express` in
/// `express.Router()` answers `definition` with `./index.js:10`, another file
/// entirely, because the server follows the require through to the module it
/// resolves. The value receivers on the same page stay home: `res` answers with
/// its own parameter at `api_v1.js:6` and `apiv1` with its declaration at
/// `api_v1.js:4`.
///
/// So the question "is this a module" is answered by where its definition
/// lives, and it is the server answering rather than this code guessing. A
/// receiver whose definition is a declaration in the file being enriched is a
/// value in that file; one whose definition is another file's module entry is a
/// reference to that module.
pub(crate) fn receiver_names_a_module(
    definitions: &[protocol::Location],
    enriched_path: &str,
) -> bool {
    definitions.iter().any(|location| {
        protocol::uri_to_path(&location.uri)
            .map(|path| {
                let path = path.to_string_lossy().to_string();
                !(path.ends_with(enriched_path) || enriched_path.ends_with(path.as_str()))
            })
            .unwrap_or(false)
    })
}

/// Whether two answers name the same place.
fn same_location(left: &protocol::Location, right: &protocol::Location) -> bool {
    left.uri == right.uri && left.range.start.line == right.range.start.line
}

/// Graph-owned text for a repository-relative path, supplied by the caller.
///
/// The join below has to ask the server about a token in a file OTHER than the
/// one being enriched, and a language server answers only about documents it
/// has been handed. The daemon opens exactly the file it is enriching, so that
/// second document does not exist as far as the server is concerned and every
/// query against it comes back empty.
///
/// Reading the second file off disk here would answer the question and break
/// the rule that matters more: after graph truth exists, a runtime query path
/// does not get its answer from raw filesystem contents. So the content arrives
/// from the caller, which holds repository authority: the daemon passes its
/// graph/CAS source view, exactly the bytes it already opens the enriched file
/// with. A caller that supplies no provider, or a provider that has nothing for
/// a path, leaves the join declining precisely as it does today.
pub type DocumentProvider<'a> = &'a (dyn Fn(&str) -> Option<String> + Send + Sync);

/// The LSP language id for a path, by extension.
///
/// `None` means this code cannot name the language, and the caller declines
/// rather than opening the document under a guess: a document opened as the
/// wrong language answers nothing, which is indistinguishable at the call site
/// from a document that was never opened, and only one of those is honest.
fn lsp_language_id(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.').map(|(_, ext)| ext)?;
    Some(match extension {
        "js" | "mjs" | "cjs" => "javascript",
        "jsx" => "javascriptreact",
        "ts" | "mts" | "cts" => "typescript",
        "tsx" => "typescriptreact",
        "py" | "pyi" => "python",
        "rs" => "rust",
        "go" => "go",
        "java" => "java",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "rb" => "ruby",
        "php" => "php",
        "swift" => "swift",
        "kt" | "kts" => "kotlin",
        "cs" => "csharp",
        _ => return None,
    })
}

/// Documents this pass handed to the server itself, closed when it is done.
///
/// Scoped to one entity's enrichment. Opening is lazy and each path is opened
/// at most once, because the join reaches the same module file for every
/// candidate export it considers and a per-candidate open would be both slower
/// and a lifecycle the server has no reason to expect.
///
/// The file being enriched is never opened here. Its caller already holds that
/// document open, and re-opening a live document is a change notification this
/// pass has no business sending.
struct ScopedDocuments<'a> {
    server: &'a LspServer,
    provider: Option<DocumentProvider<'a>>,
    open: std::collections::HashSet<String>,
}

impl<'a> ScopedDocuments<'a> {
    fn new(server: &'a LspServer, provider: Option<DocumentProvider<'a>>) -> Self {
        Self {
            server,
            provider,
            open: std::collections::HashSet::new(),
        }
    }

    /// Hand `rel_path` to the server if it is not already open, and report
    /// whether the server now holds it.
    async fn ensure_open(&mut self, rel_path: &str, uri: &str) -> bool {
        if self.open.contains(uri) {
            return true;
        }
        let Some(provider) = self.provider else {
            debug!(
                path = %rel_path,
                "declined a cross-file query: no document provider was supplied"
            );
            return false;
        };
        let Some(language_id) = lsp_language_id(rel_path) else {
            debug!(path = %rel_path, "declined a cross-file query: unknown language for this path");
            return false;
        };
        let Some(text) = provider(rel_path) else {
            debug!(
                path = %rel_path,
                "declined a cross-file query: repository authority has no text for this path"
            );
            return false;
        };
        let notified = self
            .server
            .client
            .notify(
                "textDocument/didOpen",
                serde_json::json!({
                    "textDocument": {
                        "uri": uri,
                        "languageId": language_id,
                        "version": 1,
                        "text": text,
                    }
                }),
            )
            .await;
        if let Err(error) = notified {
            debug!(path = %rel_path, error = %error, "failed to open a document for a cross-file query");
            return false;
        }
        debug!(path = %rel_path, "opened a graph-owned document for a cross-file query");
        self.open.insert(uri.to_string());
        true
    }

    /// Close every document this pass opened.
    async fn close_all(&mut self) {
        for uri in self.open.drain() {
            let _ = self
                .server
                .client
                .notify(
                    "textDocument/didClose",
                    serde_json::json!({ "textDocument": { "uri": uri } }),
                )
                .await;
        }
    }
}

/// Query type definitions for entities referenced in a function's signature/body.
/// For each resolved type, find it in the graph index and emit UsesType relations.
///
/// `documents` supplies graph-owned text for files this pass needs the server
/// to hold besides the one being enriched. It is optional: without it the
/// member-on-module join declines rather than binding, which is the behavior
/// this pass had before a provider existed.
pub async fn enrich_entity_uses_type(
    server: &LspServer,
    entity: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
    documents: Option<DocumentProvider<'_>>,
) -> Result<Vec<Relation>> {
    if !server.has_type_definition() {
        return Ok(Vec::new());
    }

    let file_path = workspace_root.join(&entity.file_path);
    let uri = protocol::path_to_uri(&file_path);
    let file_content = match std::fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(error) => {
            debug!(entity = %entity.name, error = %error, "failed to read file for UsesType sampling");
            return Ok(Vec::new());
        }
    };
    let lines: Vec<&str> = file_content.lines().collect();

    // Sample positions within the entity's span to discover type usages.
    // We query real identifier starts within the entity span to catch parameter
    // types, return types, and type references in the body.
    let mut relations = Vec::new();
    let mut seen_targets = std::collections::HashSet::new();
    let mut scoped_documents = ScopedDocuments::new(server, documents);

    for line in entity.start_line..=entity.end_line {
        let Some(line_text) = lines.get(line as usize) else {
            continue;
        };

        for col in identifier_positions_in_line(line_text) {
            // A member expression on a MODULE receiver is answered by its
            // member, never by the receiver. `express.Router()` asked at
            // `express` returns the module's own type, `lib/express.js:35`,
            // which `find_at` reads as `createApplication`, so every file that
            // so much as names `express` was recorded as using that one
            // function: 50 inbound edges on express's default export and zero
            // on `Router`, which has 32 real reference sites.
            //
            // Value receivers are untouched. `res` in `res.send(...)` genuinely
            // tells the enclosing function it uses the Response type, and that
            // edge is not this pass's mistake.
            if let Some((_receiver, member_col, member_name)) = member_expression_at(line_text, col)
            {
                let receiver_definitions =
                    locations_at(server, "textDocument/definition", &uri, line, col).await;
                if receiver_names_a_module(&receiver_definitions, &entity.file_path) {
                    let module_locations =
                        locations_at(server, "textDocument/typeDefinition", &uri, line, col).await;
                    let member_definitions =
                        locations_at(server, "textDocument/definition", &uri, line, member_col)
                            .await;
                    for module_location in &module_locations {
                        let Some(module_path) = protocol::uri_to_path(&module_location.uri) else {
                            continue;
                        };
                        let module_path = module_path.to_string_lossy().to_string();
                        for candidate in index.entities_in_file(&module_path) {
                            if candidate.name != member_name {
                                continue;
                            }
                            // The join, and the reason this is not the bare-name
                            // fallback this pass deleted. The server proved
                            // where the member resolves; it proves separately
                            // where this export's own token resolves. Binding
                            // requires those two answers to be the same place,
                            // so a same-named export of something else does not
                            // qualify: `exports.Route` resolves to
                            // `router/lib/route.js`, a different target, and is
                            // refused. Nothing is matched on the name alone.
                            let candidate_uri =
                                protocol::path_to_uri(&workspace_root.join(&candidate.file_path));
                            // The export's own token lives in the module file,
                            // which is not the file being enriched, and a server
                            // answers only about documents it holds. The caller
                            // opens the enriched file and nothing else, so this
                            // second leg queried a document the server had never
                            // seen, came back empty, and declined every join:
                            // `Router` stayed at zero references while the
                            // misattribution it was meant to replace was already
                            // gone. Hand the server that document first, from
                            // repository authority, and close it below.
                            if candidate.file_path != entity.file_path
                                && !scoped_documents
                                    .ensure_open(&candidate.file_path, &candidate_uri)
                                    .await
                            {
                                continue;
                            }
                            let candidate_definitions = locations_at(
                                server,
                                "textDocument/definition",
                                &candidate_uri,
                                candidate.name_line,
                                candidate.name_col,
                            )
                            .await;
                            if !candidate_definitions.iter().any(|proven| {
                                member_definitions
                                    .iter()
                                    .any(|member| same_location(proven, member))
                            }) {
                                continue;
                            }
                            if candidate.id == entity.id || !seen_targets.insert(candidate.id) {
                                continue;
                            }
                            relations.push(Relation {
                                id: deterministic_relation_id(
                                    RelationKind::UsesType,
                                    entity.id,
                                    candidate.id,
                                ),
                                kind: RelationKind::UsesType,
                                src: GraphNodeId::Entity(entity.id),
                                dst: GraphNodeId::Entity(candidate.id),
                                confidence: 0.85,
                                origin: RelationOrigin::Lsp,
                                created_in: None,
                                import_source: None,
                                evidence: query_position_evidence(
                                    "lsp_member_on_module",
                                    &entity.file_path,
                                    &protocol::Range {
                                        start: Position {
                                            line,
                                            character: member_col,
                                        },
                                        end: Position {
                                            line,
                                            character: member_col,
                                        },
                                    },
                                ),
                            });
                            debug!(
                                entity = %entity.name,
                                member = %member_name,
                                uses_type = %candidate.name,
                                "bound a member on a module receiver to its export"
                            );
                        }
                    }
                    // The receiver's own type is not this entity's fact, whether
                    // or not the member bound to anything. Declining here is
                    // what makes the inflated attribution stop.
                    continue;
                }
            }

            let type_def_result = server
                .client
                .request(
                    "textDocument/typeDefinition",
                    protocol::TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier { uri: uri.clone() },
                        position: Position {
                            line,
                            character: col,
                        },
                    },
                )
                .await;

            let locations: Vec<protocol::Location> = match type_def_result {
                Ok(value) => {
                    // Response may be a single Location or an array of Locations.
                    if let Ok(locs) =
                        serde_json::from_value::<Vec<protocol::Location>>(value.clone())
                    {
                        locs
                    } else if let Ok(loc) = serde_json::from_value::<protocol::Location>(value) {
                        vec![loc]
                    } else {
                        continue;
                    }
                }
                Err(_) => continue,
            };

            for loc in &locations {
                let target_line = loc.range.start.line;
                // Position only. The old fallback took the FILE STEM and looked
                // that up by name, so a reference in `sessions.py` could be
                // attributed to whatever entity happened to be called
                // `sessions`, which is a guess wearing a proven label.
                let target = index.find_at(&loc.uri, target_line);

                if let Some(target_ref) = target {
                    // Skip self-references and duplicates.
                    if target_ref.id == entity.id || !seen_targets.insert(target_ref.id) {
                        continue;
                    }

                    relations.push(Relation {
                        id: deterministic_relation_id(
                            RelationKind::UsesType,
                            entity.id,
                            target_ref.id,
                        ),
                        kind: RelationKind::UsesType,
                        src: GraphNodeId::Entity(entity.id),
                        dst: GraphNodeId::Entity(target_ref.id),
                        confidence: 0.85,
                        origin: RelationOrigin::Lsp,
                        created_in: None,
                        import_source: None,
                        // The reference SITE the server reported, which is the
                        // line a reader needs and what `reference_lines`
                        // publishes.
                        evidence: query_position_evidence(
                            "lsp_references",
                            &entity.file_path,
                            &loc.range,
                        ),
                    });
                    debug!(
                        entity = %entity.name,
                        uses_type = %target_ref.name,
                        "discovered UsesType relation"
                    );
                }
            }
        }
    }

    scoped_documents.close_all().await;

    Ok(relations)
}

/// Query textDocument/references for an entity to find all references to it.
/// Returns References relations from the referencing entity to this entity.
pub async fn enrich_entity_references(
    server: &LspServer,
    entity: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
) -> Result<Vec<Relation>> {
    if !server.has_references() {
        return Ok(Vec::new());
    }

    let file_path = workspace_root.join(&entity.file_path);
    let uri = protocol::path_to_uri(&file_path);

    // Query references at the entity's name position.
    let result = server
        .client
        .request(
            "textDocument/references",
            serde_json::json!({
                "textDocument": { "uri": uri },
                "position": {
                    "line": entity.name_line,
                    "character": entity.name_col,
                },
                "context": { "includeDeclaration": false }
            }),
        )
        .await;

    let locations: Vec<protocol::Location> = match result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %entity.name, error = %e, "references query failed");
            return Ok(Vec::new());
        }
    };

    let mut relations = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for location in &locations {
        // Find the entity that contains this reference location.
        let ref_line = location.range.start.line;
        if let Some(referencing) = index.find_at(&location.uri, ref_line) {
            // Skip self-references.
            if referencing.id == entity.id {
                continue;
            }
            // Deduplicate.
            if !seen.insert(referencing.id) {
                continue;
            }
            relations.push(Relation {
                id: deterministic_relation_id(RelationKind::References, referencing.id, entity.id),
                kind: RelationKind::References,
                src: GraphNodeId::Entity(referencing.id),
                dst: GraphNodeId::Entity(entity.id),
                confidence: 0.95,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            });
        }
    }

    Ok(relations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_index_finds_by_position() {
        let entities = vec![
            EntityRef {
                id: EntityId::new(),
                name: "foo".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 10,
                start_col: 0,
                end_line: 20,
                name_line: 10,
                name_col: 3,
            },
            EntityRef {
                id: EntityId::new(),
                name: "bar".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 25,
                start_col: 0,
                end_line: 35,
                name_line: 25,
                name_col: 3,
            },
        ];
        let index = EntityIndex::new(entities);

        let found = index.find_at("file:///project/src/lib.rs", 15);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "foo");

        let found = index.find_at("file:///project/src/lib.rs", 30);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "bar");

        // Outside any entity
        let found = index.find_at("file:///project/src/lib.rs", 22);
        assert!(found.is_none());
    }

    #[test]
    fn entity_index_finds_by_name() {
        let entities = vec![EntityRef {
            id: EntityId::new(),
            name: "Config.new".to_string(),
            file_path: "src/config.rs".to_string(),
            start_line: 5,
            start_col: 0,
            end_line: 10,
            name_line: 5,
            name_col: 7,
        }];
        let index = EntityIndex::new(entities);

        assert!(index.find_by_name("Config.new").is_some());
        assert!(index.find_by_name("new").is_some()); // suffix match
        assert!(index.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn deterministic_relation_ids_are_stable_for_same_edge() {
        let src = EntityId::new();
        let dst = EntityId::new();
        let first = deterministic_relation_id(RelationKind::Calls, src, dst);
        let second = deterministic_relation_id(RelationKind::Calls, src, dst);
        let different = deterministic_relation_id(RelationKind::References, src, dst);

        assert_eq!(first, second);
        assert_ne!(first, different);
    }
}

#[cfg(test)]
mod innermost_span_tests {
    use super::*;

    fn at(name: &str, start: u32, end: u32) -> EntityRef {
        EntityRef {
            id: EntityId::new(),
            name: name.to_string(),
            file_path: "src/requests/adapters.py".to_string(),
            start_line: start,
            start_col: 0,
            end_line: end,
            name_line: start,
            name_col: 4,
        }
    }

    /// The requests shape, in the order the index actually holds it: the module
    /// spans the whole file and sorts first, the class sits inside it, and the
    /// method inside that.
    fn adapters_file() -> EntityIndex {
        EntityIndex::new(vec![
            at("adapters", 0, 400),
            at("BaseAdapter", 121, 155),
            at("BaseAdapter.send", 127, 140),
            at("HTTPAdapter", 157, 399),
            at("HTTPAdapter.send", 633, 700),
        ])
    }

    /// The defect, as a test. A position inside a method must resolve to the
    /// METHOD, not to the class or the module that contain it.
    ///
    /// Returning the first containing span returned the module for every
    /// position in the file, which made same-file targets equal their own source
    /// and be dropped as self-loops (954 of them in one file of the requests
    /// corpus) and made cross-file targets resolve to the target file's module,
    /// so the whole definitions pass emitted only module-to-module edges.
    #[test]
    fn a_position_inside_a_method_resolves_to_the_method() {
        let index = adapters_file();
        let found = index
            .find_at("file:///repo/src/requests/adapters.py", 127)
            .expect("line 127 is inside BaseAdapter.send");
        assert_eq!(
            found.name, "BaseAdapter.send",
            "the innermost containing span wins; got the enclosing scope instead"
        );
    }

    /// The other rungs, so this is a rule about nesting rather than one lucky
    /// case: inside the class but outside any method resolves to the class, and
    /// outside every class resolves to the module.
    #[test]
    fn nesting_resolves_rung_by_rung() {
        let index = adapters_file();
        let uri = "file:///repo/src/requests/adapters.py";
        assert_eq!(
            index.find_at(uri, 150).map(|e| e.name.as_str()),
            Some("BaseAdapter"),
            "inside the class, outside its methods"
        );
        assert_eq!(
            index.find_at(uri, 10).map(|e| e.name.as_str()),
            Some("adapters"),
            "outside every class, the module is the innermost thing there is"
        );
        assert_eq!(
            index.find_at(uri, 500).map(|e| e.name.as_str()),
            None,
            "past the end of the file nothing contains the line"
        );
    }

    /// Line bases: LSP positions are 0-based and kin graph spans are 0-based, so
    /// `find_at` converts nothing. Asserted rather than assumed, because it
    /// holds by convention on both sides and a one-line change to either would
    /// shift every lookup silently.
    ///
    /// Stated in both directions: the first line of a method's span is INSIDE
    /// it, and the line before is not. Under a base mismatch a `def` line lands
    /// one short and resolves to the enclosing scope, which is exactly the
    /// failure this file is fixing, so an off-by-one here is indistinguishable
    /// from the bug.
    #[test]
    fn the_zero_based_line_convention_holds_in_both_directions() {
        let index = adapters_file();
        let uri = "file:///repo/src/requests/adapters.py";
        assert_eq!(
            index.find_at(uri, 127).map(|e| e.name.as_str()),
            Some("BaseAdapter.send"),
            "a span's own first line is inside it"
        );
        assert_eq!(
            index.find_at(uri, 126).map(|e| e.name.as_str()),
            Some("BaseAdapter"),
            "the line before it is not, and falls to the enclosing scope"
        );
        assert_eq!(
            index.find_at(uri, 140).map(|e| e.name.as_str()),
            Some("BaseAdapter.send"),
            "a span's own last line is inside it"
        );
    }

    /// Two spans that begin on the same line: the smaller one wins, so a class
    /// whose only member starts with it does not swallow that member.
    #[test]
    fn a_tie_on_the_start_line_prefers_the_smaller_span() {
        let index = EntityIndex::new(vec![at("Outer", 5, 40), at("Outer.only", 5, 12)]);
        assert_eq!(
            index
                .find_at("file:///repo/src/requests/adapters.py", 6)
                .map(|e| e.name.as_str()),
            Some("Outer.only")
        );
    }
}

#[cfg(test)]
mod member_on_module_tests {
    use super::{member_expression_at, receiver_names_a_module, same_location};
    use crate::protocol::{Location, Position, Range};

    fn location(uri: &str, line: u32) -> Location {
        Location {
            uri: uri.to_string(),
            range: Range {
                start: Position { line, character: 0 },
                end: Position { line, character: 0 },
            },
        }
    }

    /// The express case: asked at the receiver, the member is what matters.
    #[test]
    fn a_receiver_reports_the_member_it_opens() {
        let (receiver, col, member) =
            member_expression_at("var apiv1 = express.Router();", 12).expect("a member expression");
        assert_eq!(receiver, "express");
        assert_eq!(member, "Router");
        assert_eq!(col, 20);
    }

    /// Asked at the member half, there is no further member to bind, so the
    /// position falls through to the ordinary type query rather than recursing.
    #[test]
    fn the_member_half_is_not_itself_a_receiver() {
        assert!(member_expression_at("var apiv1 = express.Router();", 20).is_none());
    }

    /// A bare call has no receiver at all.
    #[test]
    fn a_bare_identifier_opens_nothing() {
        assert!(member_expression_at("finalhandler(req, res);", 0).is_none());
    }

    /// A dot that opens no identifier is not a member expression, so a numeric
    /// literal or a trailing dot cannot be read as one.
    #[test]
    fn a_dot_without_a_member_opens_nothing() {
        assert!(member_expression_at("value.", 0).is_none());
        assert!(member_expression_at("wait 1.5 seconds", 5).is_none());
    }

    /// The module-versus-value rule, as measured. `express` answers with
    /// another file; `res` and `apiv1` answer with their own declarations in
    /// the file being enriched.
    #[test]
    fn a_definition_in_another_file_names_a_module() {
        assert!(receiver_names_a_module(
            &[location("file:///w/index.js", 10)],
            "examples/multi-router/controllers/api_v1.js"
        ));
    }

    #[test]
    fn a_definition_in_this_file_names_a_value() {
        let here = "examples/multi-router/controllers/api_v1.js";
        assert!(!receiver_names_a_module(
            &[location(&format!("file:///w/{here}"), 6)],
            here
        ));
        assert!(
            !receiver_names_a_module(&[], here),
            "a receiver the server said nothing about is not promoted to a module"
        );
    }

    /// The document this pass opens is named by its own extension. A path it
    /// cannot classify is declined rather than opened under a guess.
    #[test]
    fn a_document_is_opened_under_the_language_its_extension_names() {
        use super::lsp_language_id;
        assert_eq!(lsp_language_id("lib/express.js"), Some("javascript"));
        assert_eq!(lsp_language_id("src/app.mjs"), Some("javascript"));
        assert_eq!(lsp_language_id("src/app.tsx"), Some("typescriptreact"));
        assert_eq!(lsp_language_id("requests/sessions.py"), Some("python"));
        assert_eq!(lsp_language_id("src/enrichment.rs"), Some("rust"));
        assert_eq!(
            lsp_language_id("LICENSE"),
            None,
            "a path with no extension names no language"
        );
        assert_eq!(
            lsp_language_id("docs/readme.md"),
            None,
            "an extension this map does not carry is declined, never guessed"
        );
    }

    /// A provider is what makes the second leg answerable, and its absence is
    /// what makes the join decline. Both are the same code path, so both are
    /// asserted against the same helper the join calls.
    #[tokio::test]
    async fn a_missing_provider_declines_and_a_present_one_opens() {
        use super::{DocumentProvider, ScopedDocuments};

        let server = crate::lifecycle::LspServer::offline_for_tests();

        let mut without = ScopedDocuments::new(&server, None);
        assert!(
            !without
                .ensure_open("lib/express.js", "file:///w/lib/express.js")
                .await,
            "no provider means the join keeps declining, never a disk read"
        );
        assert!(without.open.is_empty());

        // The provider counts its calls, so "opened at most once" is observable
        // rather than merely consistent with a set that cannot hold duplicates.
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let provider: &(dyn Fn(&str) -> Option<String> + Send + Sync) = &|path: &str| {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (path == "lib/express.js").then(|| "exports.Router = Router;".to_string())
        };
        let mut with = ScopedDocuments::new(&server, Some(provider as DocumentProvider<'_>));
        assert!(
            with.ensure_open("lib/express.js", "file:///w/lib/express.js")
                .await,
            "a provider that answers hands the document to the server"
        );
        assert_eq!(with.open.len(), 1);
        assert!(
            with.ensure_open("lib/express.js", "file:///w/lib/express.js")
                .await,
            "a document already open stays open"
        );
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the same document is opened at most once per entity"
        );

        assert!(
            !with
                .ensure_open("lib/other.js", "file:///w/lib/other.js")
                .await,
            "a path repository authority has nothing for declines"
        );
        assert!(
            !with.ensure_open("NOTICE", "file:///w/NOTICE").await,
            "a path whose language cannot be named declines"
        );
        assert_eq!(with.open.len(), 1);

        with.close_all().await;
        assert!(
            with.open.is_empty(),
            "every document this pass opened is closed with it"
        );
    }

    /// The join compares a place, not a name, which is what keeps this apart
    /// from the bare-name fallback this pass deleted.
    #[test]
    fn the_join_compares_the_place_two_answers_name() {
        let member = location("file:///w/node_modules/router/index.js", 51);
        let router_export = location("file:///w/node_modules/router/index.js", 51);
        let route_export = location("file:///w/node_modules/router/lib/route.js", 40);
        assert!(same_location(&router_export, &member));
        assert!(
            !same_location(&route_export, &member),
            "a same-shaped export of something else must not join"
        );
    }
}
