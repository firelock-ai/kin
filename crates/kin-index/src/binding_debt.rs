// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Source-owned obligations left by withdrawing a previously local binding.
//! These facts are independent of the parser's whole-file coverage certificate.

use crate::{IndexedFile, RelationResolution};
use kin_model::{
    ArtifactId, Entity, EntityId, FilePathId, GraphNodeId, GraphStore, Hash256, Relation,
    RelationEvidence, RelationId, RelationKind, RelationOrigin,
};
use kin_parser::ExtractedRelation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LOCAL_BINDING_DEBT_V1: &str = "local_binding_debt_v1";
pub const LOCAL_BINDING_DEBT_V2: &str = "local_binding_debt_v2";

/// Includes unknown versions so claimed binding evidence cannot silently become
/// an ordinary relation when its version is unsupported or malformed.
pub fn claims_local_binding_debt(relation: &Relation) -> bool {
    relation.evidence.iter().any(|e| {
        e.parser_rule
            .as_deref()
            .is_some_and(|rule| rule.starts_with("local_binding_debt_"))
    })
}
const MAX_DEBT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBindingObligation {
    pub retired_relation: Relation,
    pub source_name: String,
    /// Immutable body whose real relation established this prior local binding.
    pub source_digest: Hash256,
    /// Original occurrence location. V1 omits this because its current and
    /// original locations coincide; every V2 obligation carries it explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_source_file: Option<FilePathId>,
    pub target_artifact: ArtifactId,
    pub target_file: FilePathId,
    pub target_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBindingDebt {
    pub source_file: FilePathId,
    /// Latest complete source observation that explicitly retained these debts.
    pub observed_source_digest: Hash256,
    pub obligations: Vec<LocalBindingObligation>,
}

pub fn local_binding_debt_id(artifact: ArtifactId) -> RelationId {
    let mut digest = Sha256::new();
    digest.update(b"kin-local-binding-debt-v1:");
    digest.update(artifact.0.as_bytes());
    let hash = digest.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    RelationId::from_bytes(bytes)
}

pub fn build_local_binding_debt(
    artifact: ArtifactId,
    mut debt: LocalBindingDebt,
) -> Result<Relation, String> {
    if debt.source_file.0.is_empty() || debt.obligations.is_empty() {
        return Err("binding debt requires a source and at least one obligation".into());
    }
    let explicit_prior_locations = debt
        .obligations
        .iter()
        .any(|o| o.prior_source_file.is_some());
    if explicit_prior_locations {
        for obligation in &mut debt.obligations {
            obligation
                .prior_source_file
                .get_or_insert_with(|| debt.source_file.clone());
        }
    }
    debt.obligations
        .sort_by_key(|obligation| obligation.retired_relation.id);
    let mut previous = None;
    for obligation in &debt.obligations {
        let relation = &obligation.retired_relation;
        let prior_file = obligation
            .prior_source_file
            .as_ref()
            .unwrap_or(&debt.source_file);
        if prior_file.0.is_empty()
            || previous == Some(relation.id)
            || relation.src.as_entity().is_none()
            || relation.dst.as_entity().is_none()
            || relation.src == relation.dst
            || obligation.source_name.is_empty()
            || obligation.target_name.is_empty()
            || obligation.target_file.0.is_empty()
            || obligation.target_file == *prior_file
            || obligation.target_artifact == artifact
            || relation
                .evidence
                .iter()
                .filter_map(|e| e.source_span.as_ref())
                .any(|span| span.file != *prior_file || span.start_byte >= span.end_byte)
        {
            return Err(
                "binding debt contains an invalid or duplicated prior local binding".into(),
            );
        }
        previous = Some(relation.id);
    }
    let token = serde_json::to_string(&debt).map_err(|error| error.to_string())?;
    if token.len() > MAX_DEBT_BYTES {
        return Err("binding debt exceeds its bounded representation".into());
    }
    let node = GraphNodeId::Artifact(artifact);
    Ok(Relation {
        id: local_binding_debt_id(artifact),
        kind: RelationKind::DependsOn,
        src: node,
        dst: node,
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: None,
        evidence: vec![RelationEvidence {
            parser_rule: Some(
                if explicit_prior_locations {
                    LOCAL_BINDING_DEBT_V2
                } else {
                    LOCAL_BINDING_DEBT_V1
                }
                .into(),
            ),
            source_path: Some(debt.source_file.0),
            token: Some(token),
            occurrence_count: 1,
            ..RelationEvidence::default()
        }],
    })
}

/// Decode only the exact owned representation; its reserved ID cannot hide a
/// missing marker, and a marker cannot enroll a different ID or endpoint.
pub fn decode_local_binding_debt(
    file: &FilePathId,
    artifact: ArtifactId,
    relation: &Relation,
) -> Result<Option<LocalBindingDebt>, String> {
    let claims = claims_local_binding_debt(relation);
    if !claims && relation.id != local_binding_debt_id(artifact) {
        return Ok(None);
    }
    let [evidence] = relation.evidence.as_slice() else {
        return Err("malformed binding debt evidence".into());
    };
    let version = evidence.parser_rule.as_deref();
    if !matches!(version, Some(LOCAL_BINDING_DEBT_V1 | LOCAL_BINDING_DEBT_V2)) {
        return Err("unsupported binding debt version".into());
    }
    let token = evidence
        .token
        .as_deref()
        .filter(|token| token.len() <= MAX_DEBT_BYTES)
        .ok_or("missing or oversized binding debt payload")?;
    let debt: LocalBindingDebt =
        serde_json::from_str(token).map_err(|error| format!("malformed binding debt: {error}"))?;
    if debt
        .obligations
        .iter()
        .any(|o| o.prior_source_file.is_some() != (version == Some(LOCAL_BINDING_DEBT_V2)))
    {
        return Err("binding debt version and prior source locations disagree".into());
    }
    if &debt.source_file != file {
        return Err("binding debt source path mismatch".into());
    }
    let mut expected = build_local_binding_debt(artifact, debt.clone())?;
    expected.created_in = relation.created_in;
    if expected != *relation {
        return Err("binding debt is not the canonical owned payload".into());
    }
    Ok(Some(debt))
}

/// Move the current location while retaining every historical occurrence byte.
/// The caller publishes the returned replacement with the exact artifact move.
pub fn relocate_local_binding_debt(
    from: &FilePathId,
    to: &FilePathId,
    artifact: ArtifactId,
    current_digest: Hash256,
    relation: &Relation,
) -> Result<Option<Relation>, String> {
    let Some(mut debt) = decode_local_binding_debt(from, artifact, relation)? else {
        return Ok(None);
    };
    if debt.observed_source_digest != current_digest {
        return Err("binding debt source digest differs from relocation source".into());
    }
    for obligation in &mut debt.obligations {
        obligation
            .prior_source_file
            .get_or_insert_with(|| from.clone());
    }
    debt.source_file = to.clone();
    let mut relocated = build_local_binding_debt(artifact, debt)?;
    relocated.created_in = relation.created_in;
    Ok(Some(relocated))
}

/// A consumer must treat Some and Err as incomplete binding knowledge. This
/// does not change the independent body, parse, or extraction observations.
pub fn inspect_local_binding_debt(
    file: &FilePathId,
    artifact: ArtifactId,
    current_digest: Hash256,
    relations: &[&Relation],
) -> Result<Option<LocalBindingDebt>, String> {
    let mut found = None;
    for relation in relations {
        if let Some(debt) = decode_local_binding_debt(file, artifact, relation)? {
            if found.is_some() {
                return Err("multiple binding debt records claim one source".into());
            }
            if debt.observed_source_digest != current_digest {
                return Err("binding debt requires revalidation against current source".into());
            }
            found = Some(debt);
        }
    }
    Ok(found)
}

/// Normalize a local import spelling to its exported binding. Moving an alias
/// does not remove the dependency, while changing the module/export actually
/// replaces it. Ambiguous local import maps cannot prove removal.
fn reference_identity(
    raw: &ExtractedRelation,
    file: &IndexedFile,
) -> Option<(RelationKind, String, Option<String>, Option<String>)> {
    let normalize = |name: &str| -> Option<String> {
        let (root, tail) = name.split_once('.').unwrap_or((name, ""));
        let mut bindings = std::collections::BTreeSet::new();
        for import in &file.imports {
            if raw
                .import_source
                .as_deref()
                .is_some_and(|module| module != import.module_path)
            {
                continue;
            }
            for specifier in &import.specifiers {
                if specifier.local_name == root {
                    bindings.insert((
                        import.module_path.as_str(),
                        specifier
                            .original_name
                            .as_deref()
                            .unwrap_or(&specifier.local_name),
                        specifier.is_default,
                    ));
                }
            }
        }
        if bindings.len() > 1 {
            return None;
        }
        let Some((_, exported, default)) = bindings.into_iter().next() else {
            return Some(name.to_owned());
        };
        let exported = if default { "default" } else { exported };
        Some(if tail.is_empty() {
            exported.to_owned()
        } else {
            format!("{exported}.{tail}")
        })
    };
    Some((
        raw.kind,
        normalize(&raw.dst_name)?,
        raw.import_source.clone(),
        match &raw.receiver {
            Some(receiver) => Some(normalize(receiver)?),
            None => None,
        },
    ))
}

fn import_binding<'a>(
    import: &'a kin_parser::FileImport,
    specifier: &'a kin_parser::ImportedName,
) -> (&'a str, &'a str, bool) {
    (
        &import.module_path,
        if specifier.is_default {
            "default"
        } else {
            specifier
                .original_name
                .as_deref()
                .unwrap_or(&specifier.local_name)
        },
        specifier.is_default,
    )
}

/// Whether a relation is one the parser owns. Its evidence then cites the
/// parser's own record of the occurrence, and the proof below compares that
/// record directly.
pub fn parser_owns_binding(relation: &Relation) -> bool {
    matches!(
        relation.origin,
        RelationOrigin::Parsed | RelationOrigin::Inferred
    )
}

/// `old_source` is the prior body `old` was parsed from. A language-server or
/// manual relation cites a name token rather than a site the parser records,
/// and the token's text is what places it inside a parser occurrence.
pub fn obligation_is_satisfied<G: GraphStore>(
    graph: &G,
    source_artifact: kin_model::ArtifactId,
    obligation: &LocalBindingObligation,
    old: &IndexedFile,
    old_source: &[u8],
    current: &IndexedFile,
    current_entities: &[Entity],
    produced: &[Relation],
    target: &mut impl FnMut(EntityId) -> std::result::Result<Option<Entity>, String>,
) -> std::result::Result<bool, String> {
    let held = &obligation.retired_relation;
    if !parser_owns_binding(held) {
        return annotated_occurrence_is_settled(
            graph,
            source_artifact,
            obligation,
            old,
            old_source,
            current,
            current_entities,
            produced,
            target,
        );
    }
    let source_file = &current.file_id;
    let prior_source_file = &old.file_id;
    if held.kind == RelationKind::Imports {
        let Some(module) = held.import_source.as_deref() else {
            return Ok(false);
        };
        let names: Vec<_> = held
            .evidence
            .iter()
            .filter_map(|e| e.token.as_deref())
            .collect();
        if names.is_empty() {
            return Ok(false);
        }
        // Matched per SPECIFIER first, then per statement. An entity-level
        // import edge cites the specifier's own bytes, so the span that
        // identifies the import this obligation was minted from is
        // `FileImport::evidence_site`. Comparing against `FileImport::site`
        // outright matched nothing once an edge started naming the line that
        // carries the name, and an obligation that matches nothing is never
        // discharged: the caller keeps binding debt forever.
        //
        // The statement fallback is the UPGRADE path, and it is not optional.
        // `held` comes out of the store, where an edge minted by an older
        // binary carries the statement's span, while `old` is re-parsed here
        // and now by the new one. Without the fallback every obligation a
        // pre-upgrade store already holds stops matching on the first
        // reconcile after the upgrade, on single-line imports as much as on
        // multi-line ones, and that debt never clears. Matching the statement
        // reproduces the older binary's own behaviour exactly: it admits every
        // named specifier under that statement, which is the set the older
        // binary would have admitted.
        let matches_held = |import: &kin_parser::FileImport,
                            specifier: &kin_parser::ImportedName| {
            held.evidence.iter().any(|e| {
                e.source_span.as_ref()
                    == Some(
                        &import
                            .evidence_site(specifier)
                            .to_source_span(prior_source_file),
                    )
                    || e.source_span.as_ref()
                        == Some(&import.site.to_source_span(prior_source_file))
            })
        };
        let prior: std::collections::BTreeSet<_> = old
            .imports
            .iter()
            .filter(|import| import.module_path == module)
            .flat_map(|import| {
                import
                    .specifiers
                    .iter()
                    .filter(|specifier| names.contains(&specifier.local_name.as_str()))
                    .filter(|specifier| matches_held(import, specifier))
                    .map(move |specifier| import_binding(import, specifier))
            })
            .collect();
        if prior.is_empty() {
            return Ok(false);
        }
        for binding in prior {
            let current_names: Vec<_> = current
                .imports
                .iter()
                .flat_map(|import| {
                    import
                        .specifiers
                        .iter()
                        .filter(move |specifier| import_binding(import, specifier) == binding)
                        .map(|specifier| specifier.local_name.as_str())
                })
                .collect();
            if current_names.is_empty() {
                continue;
            }
            let mut resolved = false;
            for relation in produced.iter().filter(|relation| {
                relation.kind == held.kind
                    && relation.import_source.as_deref() == Some(module)
                    && relation.evidence.iter().any(|e| {
                        e.token
                            .as_deref()
                            .is_some_and(|token| current_names.contains(&token))
                    })
                    && current_entities
                        .iter()
                        .any(|e| relation.src.as_entity() == Some(e.id))
            }) {
                if matches_target(
                    graph,
                    relation,
                    obligation,
                    source_artifact,
                    Some(module),
                    produced,
                    target,
                )? {
                    resolved = true;
                    break;
                }
            }
            if !resolved {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    let sites: Vec<_> = held
        .evidence
        .iter()
        .filter_map(|e| e.source_span.as_ref())
        .collect();
    if sites.is_empty() {
        return Ok(false);
    }
    let prior: Vec<_> =
        old.extracted_relations
            .iter()
            .filter(|raw| {
                raw.kind == held.kind
                    && raw.src_name == obligation.source_name
                    && raw.site.as_ref().is_some_and(|site| {
                        sites.contains(&&site.to_source_span(prior_source_file))
                    })
            })
            .collect();
    if prior.is_empty()
        || sites.iter().any(|site| {
            !prior.iter().any(|raw| {
                raw.site
                    .as_ref()
                    .is_some_and(|raw_site| raw_site.to_source_span(prior_source_file) == **site)
            })
        })
    {
        return Ok(false);
    }
    let Some(prior_keys) = prior
        .iter()
        .map(|raw| reference_identity(raw, old))
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(false);
    };
    let mut matching = Vec::new();
    for raw in current
        .extracted_relations
        .iter()
        .filter(|raw| raw.kind == held.kind)
    {
        let Some(key) = reference_identity(raw, current) else {
            return Ok(false);
        };
        if prior_keys.contains(&key) {
            matching.push(raw);
        }
    }
    if matching.is_empty() {
        return Ok(!current
            .extracted_relations
            .iter()
            .any(kin_parser::is_call_extraction_incomplete_marker));
    }
    for raw in matching {
        let Some(site) = raw
            .site
            .as_ref()
            .map(|site| site.to_source_span(source_file))
        else {
            return Ok(false);
        };
        let sources: Vec<_> = current_entities
            .iter()
            .filter(|entity| entity.name == raw.src_name)
            .collect();
        let [source] = sources.as_slice() else {
            return Ok(false);
        };
        if kin_model::is_derived_member(source) {
            return Ok(false);
        }
        let mut resolved = false;
        for relation in produced.iter().filter(|relation| {
            relation.kind == held.kind
                && relation.src.as_entity() == Some(source.id)
                && relation
                    .evidence
                    .iter()
                    .any(|e| e.source_span.as_ref() == Some(&site))
        }) {
            if matches_target(
                graph,
                relation,
                obligation,
                source_artifact,
                import_module(raw, current).as_deref(),
                produced,
                target,
            )? {
                resolved = true;
                break;
            }
        }
        if !resolved {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Where a language-server or manual relation's cited token sits in the
/// parser's record of the prior body.
enum AnnotatedOccurrence<'a> {
    /// The imported binding a specifier token names, as `import_binding`
    /// identifies it.
    Binding((&'a str, &'a str, bool)),
    /// The module an import statement names, cited at its module token.
    Module(&'a str),
    /// An extracted relation whose site is the token, or a call whose callee
    /// the token names.
    Extracted(&'a ExtractedRelation),
}

fn within(outer: &kin_model::SourceSpan, inner: &kin_model::SourceSpan) -> bool {
    outer.file == inner.file
        && outer.start_byte <= inner.start_byte
        && inner.end_byte <= outer.end_byte
}

/// The parser occurrences a cited token belongs to. Empty when the token is
/// not one the parser recorded, and then nothing can prove the obligation
/// either way.
fn annotated_occurrences<'a>(
    obligation: &LocalBindingObligation,
    old: &'a IndexedFile,
    old_source: &[u8],
    cited: &kin_model::SourceSpan,
) -> Vec<AnnotatedOccurrence<'a>> {
    let file = &old.file_id;
    let Some(token) = old_source
        .get(cited.start_byte..cited.end_byte)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    else {
        return vec![];
    };
    if cited.file != *file || token.is_empty() {
        return vec![];
    }
    let mut found = Vec::new();
    for import in &old.imports {
        if !within(&import.site.to_source_span(file), cited) {
            continue;
        }
        let named: Vec<_> = import
            .specifiers
            .iter()
            .filter(|specifier| match &specifier.site {
                Some(site) => within(&site.to_source_span(file), cited),
                None => {
                    specifier.local_name == token
                        || specifier.original_name.as_deref() == Some(token)
                }
            })
            .collect();
        let module = import
            .module_path
            .trim_matches(|c| matches!(c, '"' | '\'' | '`'));
        let unquoted = token.trim_matches(|c| matches!(c, '"' | '\'' | '`'));
        if !named.is_empty() {
            found.extend(
                named.into_iter().map(|specifier| {
                    AnnotatedOccurrence::Binding(import_binding(import, specifier))
                }),
            );
        } else if module == unquoted || module.rsplit(['.', '/']).next() == Some(unquoted) {
            found.push(AnnotatedOccurrence::Module(&import.module_path));
        }
    }
    for raw in &old.extracted_relations {
        if raw.src_name != obligation.source_name {
            continue;
        }
        let Some(site) = raw.site.as_ref().map(|site| site.to_source_span(file)) else {
            continue;
        };
        // A call's site is its whole expression, arguments included, so the
        // token has to be the callee: the called name, ahead of the argument
        // list. A name read inside the arguments is not this call.
        let names_callee = || {
            raw.kind == RelationKind::Calls
                && within(&site, cited)
                && raw.dst_name.rsplit(['.', ':']).next() == Some(token)
                && old_source
                    .get(site.start_byte..cited.start_byte)
                    .is_some_and(|ahead| !ahead.contains(&b'('))
        };
        let same_bytes = within(&site, cited) && within(cited, &site);
        if same_bytes || names_callee() {
            found.push(AnnotatedOccurrence::Extracted(raw));
        }
    }
    found
}

/// Settles an obligation minted from a language-server or manual relation.
///
/// Its evidence cites a name token, and the proof runs through the parser
/// occurrence that token belongs to: an imported binding, the module an import
/// names, or an extracted relation. The obligation settles only when the
/// current body no longer has any such occurrence, by the same identities the
/// parser proof uses, or when a relation of the obligation's own kind at the
/// retained occurrence resolves to the same target, which is what an accepted
/// language-server pass supplies. A token the parser never recorded, or
/// evidence with no span, proves nothing, and the obligation stays.
#[allow(clippy::too_many_arguments)]
fn annotated_occurrence_is_settled<G: GraphStore>(
    graph: &G,
    source_artifact: kin_model::ArtifactId,
    obligation: &LocalBindingObligation,
    old: &IndexedFile,
    old_source: &[u8],
    current: &IndexedFile,
    current_entities: &[Entity],
    produced: &[Relation],
    target: &mut impl FnMut(EntityId) -> std::result::Result<Option<Entity>, String>,
) -> std::result::Result<bool, String> {
    let cited: Vec<_> = obligation
        .retired_relation
        .evidence
        .iter()
        .filter_map(|e| e.source_span.as_ref())
        .collect();
    if cited.is_empty() {
        return Ok(false);
    }
    let source_file = &current.file_id;
    for span in cited {
        let occurrences = annotated_occurrences(obligation, old, old_source, span);
        if occurrences.is_empty() {
            return Ok(false);
        }
        for occurrence in occurrences {
            let settled = match occurrence {
                AnnotatedOccurrence::Binding(binding) => {
                    let statements: Vec<_> = current
                        .imports
                        .iter()
                        .filter(|import| {
                            import
                                .specifiers
                                .iter()
                                .any(|specifier| import_binding(import, specifier) == binding)
                        })
                        .map(|import| import.site.to_source_span(source_file))
                        .collect();
                    statements.is_empty()
                        || re_resolved_at(
                            graph,
                            source_artifact,
                            obligation,
                            &obligation.source_name,
                            &statements,
                            Some(binding.0),
                            current_entities,
                            produced,
                            target,
                        )?
                }
                AnnotatedOccurrence::Module(module) => {
                    let statements: Vec<_> = current
                        .imports
                        .iter()
                        .filter(|import| import.module_path == module)
                        .map(|import| import.site.to_source_span(source_file))
                        .collect();
                    statements.is_empty()
                        || re_resolved_at(
                            graph,
                            source_artifact,
                            obligation,
                            &obligation.source_name,
                            &statements,
                            Some(module),
                            current_entities,
                            produced,
                            target,
                        )?
                }
                AnnotatedOccurrence::Extracted(raw) => {
                    let Some(key) = reference_identity(raw, old) else {
                        return Ok(false);
                    };
                    let mut matching = Vec::new();
                    for candidate in current
                        .extracted_relations
                        .iter()
                        .filter(|candidate| candidate.kind == raw.kind)
                    {
                        let Some(candidate_key) = reference_identity(candidate, current) else {
                            return Ok(false);
                        };
                        if candidate_key == key {
                            matching.push(candidate);
                        }
                    }
                    if matching.is_empty() {
                        !current
                            .extracted_relations
                            .iter()
                            .any(kin_parser::is_call_extraction_incomplete_marker)
                    } else {
                        let mut every = true;
                        for candidate in matching {
                            let Some(site) = candidate
                                .site
                                .as_ref()
                                .map(|site| site.to_source_span(source_file))
                            else {
                                return Ok(false);
                            };
                            if !re_resolved_at(
                                graph,
                                source_artifact,
                                obligation,
                                &candidate.src_name,
                                &[site],
                                import_module(candidate, current).as_deref(),
                                current_entities,
                                produced,
                                target,
                            )? {
                                every = false;
                                break;
                            }
                        }
                        every
                    }
                }
            };
            if !settled {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Whether a relation of the obligation's own kind, from the retained
/// occurrence's source and cited inside one of `regions`, resolves to the
/// obligation's target again.
#[allow(clippy::too_many_arguments)]
fn re_resolved_at<G: GraphStore>(
    graph: &G,
    source_artifact: kin_model::ArtifactId,
    obligation: &LocalBindingObligation,
    source_name: &str,
    regions: &[kin_model::SourceSpan],
    module: Option<&str>,
    current_entities: &[Entity],
    produced: &[Relation],
    target: &mut impl FnMut(EntityId) -> std::result::Result<Option<Entity>, String>,
) -> std::result::Result<bool, String> {
    let sources: Vec<_> = current_entities
        .iter()
        .filter(|entity| entity.name == source_name)
        .collect();
    let [source] = sources.as_slice() else {
        return Ok(false);
    };
    if kin_model::is_derived_member(source) {
        return Ok(false);
    }
    for relation in produced.iter().filter(|relation| {
        relation.kind == obligation.retired_relation.kind
            && relation.src.as_entity() == Some(source.id)
            && relation.evidence.iter().any(|e| {
                e.source_span
                    .as_ref()
                    .is_some_and(|span| regions.iter().any(|region| within(region, span)))
            })
    }) {
        if matches_target(
            graph,
            relation,
            obligation,
            source_artifact,
            module,
            produced,
            target,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A parser-recorded module wins. Otherwise only one exact imported local
/// binding may identify the module; an ambiguous spelling supplies no proof.
fn import_module(raw: &ExtractedRelation, file: &IndexedFile) -> Option<String> {
    if let Some(module) = raw.import_source.as_ref() {
        return file
            .imports
            .iter()
            .any(|i| &i.module_path == module)
            .then(|| module.clone());
    }
    let roots: Vec<_> = std::iter::once(raw.dst_name.as_str())
        .chain(raw.receiver.as_deref())
        .map(|name| name.split('.').next().unwrap_or(name))
        .collect();
    let modules: std::collections::BTreeSet<_> = file
        .imports
        .iter()
        .filter(|i| {
            i.specifiers
                .iter()
                .any(|s| roots.contains(&s.local_name.as_str()))
        })
        .map(|i| i.module_path.as_str())
        .collect();
    (modules.len() == 1).then(|| modules.into_iter().next().unwrap().to_owned())
}

fn matches_target<G: GraphStore>(
    graph: &G,
    relation: &Relation,
    obligation: &LocalBindingObligation,
    source_artifact: kin_model::ArtifactId,
    current_module: Option<&str>,
    produced: &[Relation],
    target: &mut impl FnMut(EntityId) -> std::result::Result<Option<Entity>, String>,
) -> std::result::Result<bool, String> {
    if !RelationResolution::of(relation).is_proven() {
        return Ok(false);
    }
    let Some(id) = relation.dst.as_entity() else {
        return Ok(false);
    };
    let Some(entity) = target(id)? else {
        return Ok(false);
    };
    let Some(file) = entity.file_origin.as_ref() else {
        return Ok(false);
    };
    if entity.name != obligation.target_name || kin_model::is_derived_member(&entity) {
        return Ok(false);
    }
    if obligation.prior_source_file.is_none() {
        return Ok(file == &obligation.target_file);
    }
    // A relocated relative import may now reach a different admitted artifact.
    // The old location stays immutable provenance; current module authority is
    // a separate exact fact, never a same-name target shortcut.
    let Some(module) = current_module else {
        return Ok(false);
    };
    let path = kin_model::RepoPath::from_utf8(file.0.clone()).map_err(|error| error.to_string())?;
    let Some(artifact) = graph.artifact_id_at_path(&path) else {
        return Ok(false);
    };
    Ok(produced.iter().any(|import| {
        import.src == GraphNodeId::Artifact(source_artifact)
            && import.dst == GraphNodeId::Artifact(artifact)
            && matches!(import.kind, RelationKind::Imports | RelationKind::Includes)
            && import.origin == kin_model::RelationOrigin::Parsed
            && import.confidence.to_bits() == 1.0_f32.to_bits()
            && RelationResolution::of(import).is_proven()
            && import.import_source.as_deref() == Some(module)
            && import.evidence.iter().any(|e| {
                matches!(
                    e.parser_rule.as_deref(),
                    Some("import_declaration" | "include_directive")
                ) && e.source_path.as_deref() == Some(module)
                    && e.resolved_path.as_deref() == Some(file.0.as_str())
            })
    }))
}
