// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Census of import-edge resolution over a real corpus, driven through the real
//! parser and the real linker as a pure library computation.
//!
//! This is a measurement harness, not a product path. It reads a corpus
//! directory as an explicit ingestion input boundary, exactly as admission
//! does, and reports which import specifiers produced an artifact-level
//! `Imports` edge and which produced nothing. Point it at a corpus with
//! `KIN_IMPORT_CENSUS_ROOT`; with the variable unset every test here is inert,
//! so the default suite never depends on a corpus being present.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityKind, FilePathId, GraphNodeId, RelationKind};
use kin_parser::{JavaScriptAdapter, LanguageAdapter, PythonAdapter, TypeScriptAdapter};

fn adapter_for(path: &Path) -> Option<Box<dyn LanguageAdapter>> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py") => Some(Box::new(PythonAdapter)),
        Some("js") | Some("mjs") | Some("cjs") => Some(Box::new(JavaScriptAdapter)),
        Some("ts") | Some("tsx") => Some(Box::new(TypeScriptAdapter)),
        _ => None,
    }
}

fn collect_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name == "node_modules" || name == "__pycache__" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if adapter_for(&path).is_some() {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

struct Corpus {
    files: Vec<FileParseData>,
    artifact_ids: HashMap<String, ArtifactId>,
}

fn parse_corpus(root: &Path) -> Corpus {
    let mut files = Vec::new();
    for path in collect_sources(root) {
        let Some(adapter) = adapter_for(&path) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let file_id = FilePathId::new(&rel);
        let Ok(tree) = adapter.parse(&bytes) else {
            continue;
        };
        let Ok(output) = adapter.extract(&tree, &bytes, &file_id) else {
            continue;
        };
        let entities: Vec<Entity> = output
            .entities
            .into_iter()
            .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(&bytes)))
            .collect();
        files.push(FileParseData {
            file_path: rel,
            entities,
            relations: output.relations,
            imports: output.imports,
        });
    }
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect();
    Corpus {
        files,
        artifact_ids,
    }
}

/// Every `(importer, target)` pair the linker produced as an artifact-level
/// `Imports` edge, keyed by repo-relative path.
fn resolved_import_pairs(corpus: &Corpus) -> HashSet<(String, String)> {
    let relations =
        link_cross_file(&corpus.files, &corpus.artifact_ids).expect("corpus links");
    let by_id: HashMap<&ArtifactId, &String> = corpus
        .artifact_ids
        .iter()
        .map(|(path, id)| (id, path))
        .collect();
    let path_of = |node: &GraphNodeId| -> Option<String> {
        match node {
            GraphNodeId::Artifact(id) => by_id.get(id).map(|p| (*p).clone()),
            _ => None,
        }
    };
    relations
        .iter()
        .filter(|r| r.kind == RelationKind::Imports)
        .filter_map(|r| Some((path_of(&r.src)?, path_of(&r.dst)?)))
        .collect()
}

/// Count entity-rooted `Imports` edges, the class that answers "who imports
/// this export" at entity level.
fn entity_rooted_import_edges(corpus: &Corpus) -> usize {
    let relations =
        link_cross_file(&corpus.files, &corpus.artifact_ids).expect("corpus links");
    relations
        .iter()
        .filter(|r| r.kind == RelationKind::Imports)
        .filter(|r| matches!(r.src, GraphNodeId::Entity(_)) || matches!(r.dst, GraphNodeId::Entity(_)))
        .count()
}

fn census_root() -> Option<PathBuf> {
    std::env::var_os("KIN_IMPORT_CENSUS_ROOT").map(PathBuf::from)
}

/// How many files carry a `module`-kind entity, the endpoint an entity-level
/// import edge would need on its importing side.
fn files_with_module_entity(corpus: &Corpus) -> usize {
    corpus
        .files
        .iter()
        .filter(|f| {
            f.entities
                .iter()
                .any(|e| e.kind == EntityKind::Module)
        })
        .count()
}

/// What the census reports about the yield an entity-level import edge reaches.
#[derive(Default)]
struct Yield {
    /// Import sites whose specifier the linker resolved to a repo file. The
    /// only population where an entity-level edge is possible at all.
    sites_resolved_in_repo: usize,
    /// Import sites whose specifier resolved to nothing in this repo, which is
    /// the external-module population.
    sites_external: usize,
    /// Named specifiers carried by the in-repo-resolving sites.
    named_specifiers: usize,
    /// Of those, the ones naming an entity the resolved target file defines.
    matched: usize,
    /// Of those, the ones naming nothing the target defines. A submodule name
    /// in `from pkg import mod` lands here, and so does a re-export.
    unmatched: usize,
    /// Unmatched specifiers that bind the WHOLE module rather than a name it
    /// exports. `var express = require('../..')` is this: the local name is the
    /// importer's choice and the target defines no such symbol, so the entity
    /// this import reaches is the target's module entity, not a member.
    /// The parser marks these `is_default`.
    unmatched_whole_module: usize,
    /// Unmatched specifiers naming a SUBMODULE of the resolved target's own
    /// package, so the import names a file rather than a symbol.
    /// `from . import routing` against `pkg/__init__.py` is this.
    unmatched_is_submodule: usize,
    /// Unmatched specifiers the resolved target does not define but some other
    /// file in the repository does. This is the re-export class: the target is
    /// a package `__init__` or barrel that forwards the name.
    unmatched_reexported: usize,
    /// Unmatched specifiers no file in the repository defines at all.
    unmatched_unknown: usize,
    /// Matched specifiers whose IMPORTING file also carries a module entity, so
    /// an entity-to-entity edge has both endpoints available. `find_references`
    /// skips any relation whose src is not an entity, so a file with no module
    /// entity cannot source one however well its specifier resolved.
    buildable_member_edges: usize,
    /// Whole-module binds where BOTH files carry a module entity.
    buildable_module_edges: usize,
    /// Specifiers that matched but whose importer has no module entity.
    blocked_no_importer_module: usize,
    sample_whole_module: Vec<String>,
    sample_submodule: Vec<String>,
    sample_reexported: Vec<String>,
    sample_unknown: Vec<String>,
}

/// Map each `(importer, specifier)` to the file the linker resolved it to.
///
/// The linker records the specifier it resolved on the relation's own evidence
/// (`source_path`) alongside the file it reached (`resolved_path`), so this
/// reads the linker's real decision per site rather than re-deriving one.
fn resolution_by_site(corpus: &Corpus) -> HashMap<(String, String), String> {
    let relations =
        link_cross_file(&corpus.files, &corpus.artifact_ids).expect("corpus links");
    let by_id: HashMap<&ArtifactId, &String> = corpus
        .artifact_ids
        .iter()
        .map(|(path, id)| (id, path))
        .collect();
    let mut out = HashMap::new();
    for rel in relations.iter().filter(|r| r.kind == RelationKind::Imports) {
        let GraphNodeId::Artifact(src_id) = rel.src else {
            continue;
        };
        let Some(importer) = by_id.get(&src_id) else {
            continue;
        };
        for ev in &rel.evidence {
            if let (Some(specifier), Some(resolved)) = (&ev.source_path, &ev.resolved_path) {
                out.insert(
                    ((*importer).clone(), specifier.clone()),
                    resolved.clone(),
                );
            }
        }
    }
    out
}

/// The yield an entity-level import edge could reach, measured per site against
/// the linker's own resolution rather than against a guess.
fn nameable_specifier_yield(corpus: &Corpus) -> Yield {
    let entities_by_file: HashMap<&str, HashSet<&str>> = corpus
        .files
        .iter()
        .map(|f| {
            (
                f.file_path.as_str(),
                f.entities.iter().map(|e| e.name.as_str()).collect(),
            )
        })
        .collect();
    let resolved = resolution_by_site(corpus);
    let has_module: HashSet<&str> = corpus
        .files
        .iter()
        .filter(|f| {
            f.entities
                .iter()
                .any(|e| e.kind == EntityKind::Module)
        })
        .map(|f| f.file_path.as_str())
        .collect();

    let mut out = Yield::default();
    for file in &corpus.files {
        for import in &file.imports {
            let key = (file.file_path.clone(), import.module_path.clone());
            let Some(target) = resolved.get(&key) else {
                out.sites_external += 1;
                continue;
            };
            out.sites_resolved_in_repo += 1;
            let names = entities_by_file.get(target.as_str());
            for spec in &import.specifiers {
                out.named_specifiers += 1;
                let wanted = spec
                    .original_name
                    .as_deref()
                    .unwrap_or(spec.local_name.as_str());
                if names.is_some_and(|n| n.contains(wanted)) {
                    out.matched += 1;
                    if has_module.contains(file.file_path.as_str()) {
                        out.buildable_member_edges += 1;
                    } else {
                        out.blocked_no_importer_module += 1;
                    }
                    continue;
                }
                out.unmatched += 1;
                let site = format!(
                    "{} :: {} :: name={wanted} -> {target}",
                    file.file_path, import.module_path
                );
                // A name the target does not define is one of four things, and
                // they want different fixes, so the census separates them
                // rather than reporting one undifferentiated miss.
                //
                // A default specifier binds the module object itself, which is
                // what CommonJS `require` produces. Classifying it by name
                // against the target's symbols reports a miss for an import
                // that never named a symbol, so this arm comes first.
                if spec.is_default {
                    out.unmatched_whole_module += 1;
                    if has_module.contains(file.file_path.as_str())
                        && has_module.contains(target.as_str())
                    {
                        out.buildable_module_edges += 1;
                    }
                    if out.sample_whole_module.len() < 8 {
                        out.sample_whole_module.push(site);
                    }
                    continue;
                }
                // A submodule is a sibling FILE inside the resolved target's own
                // package directory, which only makes sense when the target is
                // that package's `__init__` or index.
                let target_dir = target.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                let target_is_package_root = target
                    .rsplit_once('/')
                    .map(|(_, n)| n)
                    .unwrap_or(target.as_str())
                    .starts_with("__init__.")
                    || target.ends_with("/index.js")
                    || target == "index.js";
                let is_submodule = target_is_package_root
                    && corpus.files.iter().any(|f| {
                        let Some(rest) = f.file_path.strip_prefix(target_dir) else {
                            return false;
                        };
                        let rest = rest.trim_start_matches('/');
                        let stem = rest.rsplit_once('.').map(|(s, _)| s).unwrap_or(rest);
                        stem == wanted || rest.starts_with(&format!("{wanted}/"))
                    });
                if is_submodule {
                    out.unmatched_is_submodule += 1;
                    if out.sample_submodule.len() < 8 {
                        out.sample_submodule.push(site);
                    }
                    continue;
                }
                let defined_elsewhere = entities_by_file
                    .values()
                    .any(|n| n.contains(wanted));
                if defined_elsewhere {
                    out.unmatched_reexported += 1;
                    if out.sample_reexported.len() < 8 {
                        out.sample_reexported.push(site);
                    }
                } else {
                    out.unmatched_unknown += 1;
                    if out.sample_unknown.len() < 8 {
                        out.sample_unknown.push(site);
                    }
                }
            }
        }
    }
    out
}

#[test]
fn census_reports_import_resolution_over_a_corpus() {
    let Some(root) = census_root() else {
        eprintln!("KIN_IMPORT_CENSUS_ROOT unset; census inert");
        return;
    };
    let corpus = parse_corpus(&root);
    let total_sites: usize = corpus.files.iter().map(|f| f.imports.len()).sum();
    let pairs = resolved_import_pairs(&corpus);
    let entity_rooted = entity_rooted_import_edges(&corpus);

    println!("CENSUS_ROOT {}", root.display());
    println!("CENSUS_FILES {}", corpus.files.len());
    println!("CENSUS_IMPORT_SITES {total_sites}");
    println!("CENSUS_RESOLVED_ARTIFACT_PAIRS {}", pairs.len());
    println!("CENSUS_ENTITY_ROOTED_IMPORT_EDGES {entity_rooted}");
    println!(
        "CENSUS_FILES_WITH_MODULE_ENTITY {}",
        files_with_module_entity(&corpus)
    );
    let y = nameable_specifier_yield(&corpus);
    println!("CENSUS_SITES_RESOLVED_IN_REPO {}", y.sites_resolved_in_repo);
    println!("CENSUS_SITES_EXTERNAL {}", y.sites_external);
    println!("CENSUS_NAMED_SPECIFIERS_IN_REPO {}", y.named_specifiers);
    println!("CENSUS_SPECIFIERS_MATCHING_TARGET_ENTITY {}", y.matched);
    println!("CENSUS_SPECIFIERS_WITH_NO_TARGET_ENTITY {}", y.unmatched);
    println!("CENSUS_UNMATCHED_WHOLE_MODULE {}", y.unmatched_whole_module);
    println!("CENSUS_UNMATCHED_IS_SUBMODULE {}", y.unmatched_is_submodule);
    println!("CENSUS_UNMATCHED_REEXPORTED {}", y.unmatched_reexported);
    println!("CENSUS_UNMATCHED_UNKNOWN {}", y.unmatched_unknown);
    println!("CENSUS_BUILDABLE_MEMBER_EDGES {}", y.buildable_member_edges);
    println!("CENSUS_BUILDABLE_MODULE_EDGES {}", y.buildable_module_edges);
    println!(
        "CENSUS_BLOCKED_NO_IMPORTER_MODULE {}",
        y.blocked_no_importer_module
    );
    for s in &y.sample_whole_module {
        println!("SAMPLE_WHOLE_MODULE\t{s}");
    }
    for s in &y.sample_submodule {
        println!("SAMPLE_SUBMODULE\t{s}");
    }
    for s in &y.sample_reexported {
        println!("SAMPLE_REEXPORTED\t{s}");
    }
    for s in &y.sample_unknown {
        println!("SAMPLE_UNKNOWN\t{s}");
    }

    // Every resolved pair, so the diff against ground truth is exact rather
    // than a count comparison.
    let mut sorted: Vec<_> = pairs.into_iter().collect();
    sorted.sort();
    for (src, dst) in &sorted {
        println!("PAIR\t{src}\t{dst}");
    }

    // Every parsed import site with its specifier, so an unresolved specifier
    // can be classified by shape rather than only counted.
    for file in &corpus.files {
        for import in &file.imports {
            println!("SITE\t{}\t{}", file.file_path, import.module_path);
        }
    }
}
