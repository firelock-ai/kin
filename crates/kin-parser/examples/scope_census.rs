// kin/crates/kin-parser/examples/scope_census.rs
//
// How many entities land in each scope state, per language, over a tree.
//
// Run before letting any query answer by scope, because the answer to "what is
// in this namespace" is only as good as the fraction of entities that have one.
// This walks a directory the way ingestion walks it, extracts with the same
// adapters, and derives each entity's scope with the same rules, so the tally is
// the one the product would produce rather than an estimate of it.
//
//   cargo run -p kin-parser --example scope_census -- <dir>
//
// It lives in `examples/` because it reads the filesystem. That is ingestion IO
// here, not an answer path, and the zero-file-search checker excludes cargo's
// examples directory for exactly this reason.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use kin_model::{EntityScope, FilePathId, LanguageId, ScopeAbsence};
use kin_parser::scope::{derive, Manifest, ManifestKind, ScopeInputs, ScopeLayout};
use kin_parser::AdapterRegistry;

/// Directories that hold no repository source, so walking them measures the
/// toolchain rather than the tree.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".kin",
    "dist",
    "build",
    "vendor",
    ".venv",
];

/// The layout read off the disk, for a census taken before any store exists.
///
/// PR B's implementation answers these two questions from the graph's own
/// `Package` entities. This one answers them from the tree being censused, which
/// is the same tree ingestion would read.
struct DiskLayout {
    root: PathBuf,
}

impl DiskLayout {
    fn manifest_name(&self, dir: &str, kind: ManifestKind) -> Option<String> {
        let (file, key) = match kind {
            ManifestKind::Cargo => ("Cargo.toml", "name"),
            ManifestKind::Node => ("package.json", "\"name\""),
        };
        let text = fs::read_to_string(self.root.join(dir).join(file)).ok()?;
        match kind {
            // The first `name =` under `[package]`. A workspace-only manifest
            // has no `[package]` section and so declares no crate, which is the
            // right answer for a directory that is not a crate.
            ManifestKind::Cargo => {
                let after = text.split("[package]").nth(1)?;
                after
                    .lines()
                    .take_while(|line| !line.trim_start().starts_with('['))
                    .find_map(|line| toml_string_value(line, key))
            }
            ManifestKind::Node => text.lines().find_map(|line| json_string_value(line, key)),
        }
    }

    fn has_manifest(&self, dir: &str, kind: ManifestKind) -> bool {
        let file = match kind {
            ManifestKind::Cargo => "Cargo.toml",
            ManifestKind::Node => "package.json",
        };
        self.root.join(dir).join(file).is_file()
    }
}

impl ScopeLayout for DiskLayout {
    fn is_python_package(&self, dir: &str) -> bool {
        self.root.join(dir).join("__init__.py").is_file()
    }

    fn manifest_at_or_above(&self, dir: &str, kind: ManifestKind) -> Option<Manifest> {
        let mut current = dir;
        loop {
            if self.has_manifest(current, kind) {
                return Some(Manifest {
                    dir: current.to_string(),
                    name: self.manifest_name(current, kind),
                });
            }
            if current.is_empty() {
                return None;
            }
            current = match current.rsplit_once('/') {
                Some((head, _)) => head,
                None => "",
            };
        }
    }
}

fn toml_string_value(line: &str, key: &str) -> Option<String> {
    let (name, rest) = line.split_once('=')?;
    (name.trim() == key).then(|| rest.trim().trim_matches('"').to_string())
}

fn json_string_value(line: &str, key: &str) -> Option<String> {
    let (name, rest) = line.split_once(':')?;
    (name.trim() == key).then(|| {
        rest.trim()
            .trim_end_matches(',')
            .trim_matches('"')
            .to_string()
    })
}

/// One row of the census: a language, and where its entities landed.
#[derive(Default, Clone, Copy)]
struct Row {
    known: u64,
    none_language: u64,
    none_other: u64,
    not_computed: u64,
    /// Of the known ones, how many were rooted at the repository's own manifest
    /// rather than at a nested package's.
    rooted_at_repository: u64,
    /// Of the known ones, how many had no manifest above them at all, so the
    /// repository root was used with nothing declaring it a package.
    rooted_with_no_manifest: u64,
}

impl Row {
    fn total(&self) -> u64 {
        self.known + self.none_language + self.none_other + self.not_computed
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') && name != "." {
            continue;
        }
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let root = PathBuf::from(args.get(1).cloned().unwrap_or_else(|| ".".to_string()));
    let root = root.canonicalize().unwrap_or(root);

    let registry = AdapterRegistry::new();
    let layout = DiskLayout { root: root.clone() };
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();

    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    let mut parsed_files = 0u64;
    for path in &files {
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_string();
        let Ok(content) = fs::read(path) else {
            continue;
        };
        let Some(adapter) = registry.get_by_extension_and_content(&extension, &content) else {
            continue;
        };
        let Ok(tree) = adapter.parse(&content) else {
            continue;
        };
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let file_id = FilePathId::new(relative.clone());
        let Ok(output) = adapter.extract(&tree, &content, &file_id) else {
            continue;
        };
        parsed_files += 1;

        let language = adapter.language_id();
        let row = rows.entry(language.to_string()).or_default();
        let ecmascript = matches!(language, LanguageId::TypeScript | LanguageId::JavaScript);
        let nearest = ecmascript
            .then(|| layout.manifest_at_or_above(parent_of(&relative), ManifestKind::Node))
            .flatten();
        let repository_rooted = ecmascript && nearest.as_ref().is_some_and(|m| m.dir.is_empty());
        let unclaimed = ecmascript && nearest.is_none();

        for _entity in &output.entities {
            // Every extractor passes no declared namespace today, which is the
            // measurement: the seven declared languages report NotComputed until
            // their extractor reads the declaration.
            let scope = derive(
                ScopeInputs {
                    language,
                    file: Some(&file_id),
                    declared: None,
                },
                &layout,
            );
            match scope {
                EntityScope::Known(_) => {
                    row.known += 1;
                    if repository_rooted {
                        row.rooted_at_repository += 1;
                    }
                    if unclaimed {
                        row.rooted_with_no_manifest += 1;
                    }
                }
                EntityScope::None(ScopeAbsence::LanguageHasNone) => row.none_language += 1,
                EntityScope::None(_) => row.none_other += 1,
                EntityScope::NotComputed => row.not_computed += 1,
            }
        }
    }

    println!("scope census over {}", root.display());
    println!("{parsed_files} files parsed of {} walked", files.len());
    println!();
    println!(
        "{:<12} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "language", "entities", "known", "none(lang)", "none(oth)", "uncomputed"
    );
    let mut totals = Row::default();
    for (language, row) in &rows {
        println!(
            "{:<12} {:>9} {:>9} {:>9} {:>9} {:>9}",
            language,
            row.total(),
            row.known,
            row.none_language,
            row.none_other,
            row.not_computed
        );
        totals.known += row.known;
        totals.none_language += row.none_language;
        totals.none_other += row.none_other;
        totals.not_computed += row.not_computed;
        totals.rooted_at_repository += row.rooted_at_repository;
        totals.rooted_with_no_manifest += row.rooted_with_no_manifest;
    }
    println!(
        "{:<12} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "TOTAL",
        totals.total(),
        totals.known,
        totals.none_language,
        totals.none_other,
        totals.not_computed
    );
    println!();
    println!(
        "of the known ECMAScript entities, {} are rooted at the repository's own package.json \
         because no nested package claimed them, and {} had no package.json above them at all",
        totals.rooted_at_repository, totals.rooted_with_no_manifest
    );
}

fn parent_of(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((head, _)) => head,
        None => "",
    }
}
