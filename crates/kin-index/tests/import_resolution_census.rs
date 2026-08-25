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
use kin_model::{ArtifactId, Entity, FilePathId, GraphNodeId, RelationKind};
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
