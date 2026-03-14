//! Planted benchmark artifacts with real-codebase integration.
//!
//! During benchmark workspace setup we inject a small set of files into the
//! source tree **before** it is copied into individual arm directories. Every
//! arm — git, compat, native-mcp, native-cli — therefore sees identical
//! planted content, keeping the comparison fair.
//!
//! ## Anti-gaming
//!
//! - Every name (functions, types, files, constants) includes a random tag
//!   so models cannot rely on training data.
//! - Secret values are random UUIDs, unique per run.
//! - Planted files import **real symbols** from the repository, creating
//!   genuine edges in Kin's semantic graph.
//! - A reference is injected into the repo's entry file, so the planted
//!   code is reachable through the real dependency graph.
//!
//! ## Fairness
//!
//! All planting happens in `_source/` before arm copies. Every arm gets
//! identical files. Task prompts are identical across arms — only the
//! available tools differ.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::runner::{LiveTask, Validator};

// ---------------------------------------------------------------------------
// Public types — serialised into the benchmark report so reviewers can
// inspect exactly what was planted and what the correct answers were.
// ---------------------------------------------------------------------------

/// Top-level metadata for all planted artifacts in a single benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlantedArtifacts {
    /// Random tag embedded in all planted names (8 hex chars).
    pub tag: String,
    /// Detected primary language of the repository.
    pub language: String,
    /// File extension used for planted code (e.g. "ts", "py").
    pub extension: String,
    /// Real symbols imported by planted files (for graph integration).
    pub real_symbols: Vec<RealSymbol>,
    /// Entry file that was injected with a probe reference (if any).
    pub injected_entry_file: Option<String>,

    /// Task 1 — trace an import chain to find a secret value.
    pub chain: ChainArtifact,
    /// Task 2 — identify which files import a planted type (vs local decoys).
    pub impact: ImpactArtifact,
    /// Task 3 — find and fix a planted bug.
    pub bugfix: BugfixArtifact,
    /// Task 4 — implement a stubbed-out function.
    pub feature: FeatureArtifact,
    /// Task 5 — trace a multi-file computation chain to compute a return value.
    pub behavioral: BehavioralTraceArtifact,
    /// Task 6 — count files that import a shared function vs define locally.
    pub caller_count: CallerCountArtifact,
    /// Task 7 — identify functions that are never called (dead code).
    pub dead_code: DeadCodeArtifact,
}

/// A real symbol found in the repository and imported by planted code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealSymbol {
    pub name: String,
    pub file: String,
    pub kind: String, // "function", "class", "const"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainArtifact {
    /// Paths (relative to repo root) of the 3 files forming the real chain.
    pub chain_files: Vec<String>,
    /// Paths of 2 decoy files that look related but are not in the chain.
    pub decoy_files: Vec<String>,
    /// The secret value the model must report. A random UUID.
    pub secret_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactArtifact {
    /// Name of the planted type (includes random tag).
    pub type_name: String,
    /// File where the canonical type is defined.
    pub definition_file: String,
    /// Files that genuinely import the type from its definition module.
    pub import_files: Vec<String>,
    /// Files that define their own LOCAL type with the same name (decoys).
    pub decoy_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugfixArtifact {
    /// File containing the buggy function.
    pub file: String,
    /// Name of the buggy function (includes random tag).
    pub function_name: String,
    /// The exact string that must appear in the corrected output.
    pub fix_indicator: String,
    /// Short description of the bug (used in the task prompt).
    pub bug_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureArtifact {
    /// File containing the stub.
    pub file: String,
    /// Name of the function to implement (includes random tag).
    pub function_name: String,
    /// The exact return value the implementation must produce.
    pub expected_return: String,
}

/// A multi-file computation chain where the model must trace calls to compute
/// a return value. Requires following imports across 9 files (base + 7 steps)
/// with conditional branching — `kin trace` gives the full chain in one shot
/// while grep needs 9+ rounds and the model must reason about control flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralTraceArtifact {
    /// Files forming the computation chain, in call order (caller → callee).
    /// 9 files: step7 (entry), step6..step1, base.
    pub chain_files: Vec<String>,
    /// A decoy file with a similar function name but different logic.
    pub decoy_file: String,
    /// Name of the top-level function the model is asked about.
    pub entry_function: String,
    /// The input value given in the prompt.
    pub input_value: i64,
    /// The correct computed result.
    pub expected_result: i64,
    /// The base constant planted in the deepest file.
    pub base_constant: i64,
}

/// A shared function imported by N files, plus M decoy files that define
/// their own local function with the same name, plus K files that import
/// but never call. The model must count only files that both import AND call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerCountArtifact {
    /// File where the canonical function is defined.
    pub definition_file: String,
    /// Name of the shared function (includes random tag).
    pub function_name: String,
    /// Files that genuinely import AND call the function.
    pub import_files: Vec<String>,
    /// Files that import the function but never call it (import-only).
    pub import_only_files: Vec<String>,
    /// Files that define their own local function with the same name.
    pub decoy_files: Vec<String>,
    /// The correct count of files that both import AND call.
    pub expected_count: usize,
}

/// A mix of planted functions across multiple files — some called from
/// other planted files, some never called (dead code). The model must
/// cross-reference 3 caller files against 3 definition files to find
/// the functions with zero callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeArtifact {
    /// Files containing probe function definitions (3 files, 4 functions each).
    pub function_files: Vec<String>,
    /// Files that call subsets of the probe functions (3 caller files).
    pub caller_files: Vec<String>,
    /// Functions that ARE called (live).
    pub live_functions: Vec<String>,
    /// Functions that are NEVER called (dead).
    pub dead_functions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

/// Detect the dominant source language in `dir` by counting file extensions.
/// Returns `(language_name, extension)` — e.g. `("typescript", "ts")`.
pub fn detect_language(dir: &Path) -> (String, String) {
    let mut counts: HashMap<String, usize> = HashMap::new();

    if let Ok(extensions) = collect_extensions(dir) {
        for ext in extensions {
            *counts.entry(ext).or_default() += 1;
        }
    }

    let lang_map: Vec<(&str, &str, &[&str])> = vec![
        ("typescript", "ts", &["ts", "tsx"]),
        ("javascript", "js", &["js", "jsx", "mjs", "cjs"]),
        ("python", "py", &["py"]),
        ("rust", "rs", &["rs"]),
        ("go", "go", &["go"]),
        ("java", "java", &["java"]),
    ];

    let mut best: Option<(&str, &str, usize)> = None;
    for (lang, ext, exts) in &lang_map {
        let total: usize = exts.iter().filter_map(|e| counts.get(*e)).sum();
        match best {
            Some((_, _, best_count)) if total > best_count => {
                best = Some((lang, ext, total));
            }
            None if total > 0 => {
                best = Some((lang, ext, total));
            }
            _ => {}
        }
    }

    best.map(|(l, e, _)| (l.to_string(), e.to_string()))
        .unwrap_or_else(|| ("javascript".to_string(), "js".to_string()))
}

fn collect_extensions(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut exts = Vec::new();
    walk_for_extensions(dir, &mut exts, 0)?;
    Ok(exts)
}

fn walk_for_extensions(dir: &Path, exts: &mut Vec<String>, depth: usize) -> std::io::Result<()> {
    if depth > 8 {
        return Ok(());
    }
    let skip = [
        "node_modules",
        ".git",
        ".kin",
        "__pycache__",
        "target",
        "vendor",
        "dist",
        "build",
        ".venv",
        "venv",
    ];

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }
        if skip.contains(&name_str.as_ref()) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            walk_for_extensions(&path, exts, depth + 1)?;
        } else if let Some(ext) = path.extension() {
            exts.push(ext.to_string_lossy().to_string());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Real symbol scanning — find exported symbols to import in planted code
// ---------------------------------------------------------------------------

/// Scan the source tree for real exported symbols we can import from
/// planted code. This creates genuine edges in Kin's semantic graph.
fn scan_real_symbols(dir: &Path, lang: &str, ext: &str) -> Vec<RealSymbol> {
    let mut symbols = Vec::new();
    scan_dir_for_symbols(dir, dir, lang, ext, &mut symbols, 0);

    // Deduplicate and take at most 5 symbols
    symbols.truncate(5);
    symbols
}

fn scan_dir_for_symbols(
    root: &Path,
    dir: &Path,
    lang: &str,
    ext: &str,
    symbols: &mut Vec<RealSymbol>,
    depth: usize,
) {
    if depth > 4 || symbols.len() >= 5 {
        return;
    }
    let skip = [
        "node_modules",
        ".git",
        ".kin",
        "__pycache__",
        "target",
        "vendor",
        "dist",
        "build",
        "test",
        "tests",
        "__tests__",
    ];

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') || name_str.starts_with('_') {
            continue;
        }
        if skip.contains(&name_str.as_ref()) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            scan_dir_for_symbols(root, &path, lang, ext, symbols, depth + 1);
        } else if path.extension().map(|e| e == ext).unwrap_or(false) && symbols.len() < 5 {
            extract_symbols_from_file(root, &path, lang, symbols);
        }
    }
}

fn extract_symbols_from_file(root: &Path, file: &Path, lang: &str, symbols: &mut Vec<RealSymbol>) {
    let content = match fs::read_to_string(file) {
        Ok(c) => c,
        Err(_) => return,
    };

    let rel_path = file
        .strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .to_string();

    for line in content.lines() {
        if symbols.len() >= 5 {
            return;
        }
        let trimmed = line.trim();

        match lang {
            "typescript" | "javascript" => {
                // export function foo(
                if let Some(rest) = trimmed.strip_prefix("export function ") {
                    if let Some(name) = rest.split('(').next() {
                        let name = name.trim();
                        if is_valid_symbol(name) {
                            symbols.push(RealSymbol {
                                name: name.to_string(),
                                file: rel_path.clone(),
                                kind: "function".to_string(),
                            });
                        }
                    }
                }
                // export class Foo
                else if let Some(rest) = trimmed.strip_prefix("export class ") {
                    if let Some(name) = rest
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                    {
                        if is_valid_symbol(name) {
                            symbols.push(RealSymbol {
                                name: name.to_string(),
                                file: rel_path.clone(),
                                kind: "class".to_string(),
                            });
                        }
                    }
                }
            }
            "python" => {
                // def foo( or class Foo
                if let Some(rest) = trimmed.strip_prefix("def ") {
                    if let Some(name) = rest.split('(').next() {
                        let name = name.trim();
                        if is_valid_symbol(name) && !name.starts_with('_') {
                            symbols.push(RealSymbol {
                                name: name.to_string(),
                                file: rel_path.clone(),
                                kind: "function".to_string(),
                            });
                        }
                    }
                } else if let Some(rest) = trimmed.strip_prefix("class ") {
                    if let Some(name) = rest
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                    {
                        if is_valid_symbol(name) {
                            symbols.push(RealSymbol {
                                name: name.to_string(),
                                file: rel_path.clone(),
                                kind: "class".to_string(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn is_valid_symbol(name: &str) -> bool {
    !name.is_empty()
        && name.len() >= 3
        && name.len() <= 40
        && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

// ---------------------------------------------------------------------------
// Entry file detection and injection
// ---------------------------------------------------------------------------

/// Common entry file names, in priority order.
const ENTRY_CANDIDATES: &[&str] = &[
    "src/index.ts",
    "src/index.js",
    "src/app.ts",
    "src/app.js",
    "src/main.ts",
    "src/main.js",
    "index.ts",
    "index.js",
    "app.ts",
    "app.js",
    "lib/index.js",
    "lib/express.js",
    "src/__init__.py",
    "src/app.py",
    "src/main.py",
    "app.py",
    "main.py",
    // Flask/FastAPI patterns
    "src/flask/__init__.py",
    "flask/__init__.py",
    "fastapi/__init__.py",
    "typer/__init__.py",
];

/// Find the repo's entry file and inject a reference to the planted probe.
/// Returns the relative path of the injected file, or None if no entry found.
fn inject_into_entry_file(
    source_dir: &Path,
    lang: &str,
    probe_dir: &str,
    tag: &str,
) -> Option<String> {
    for candidate in ENTRY_CANDIDATES {
        let path = source_dir.join(candidate);
        if path.exists() {
            // Only inject into files matching our detected language
            let file_ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let lang_match = match lang {
                "typescript" => file_ext == "ts" || file_ext == "tsx",
                "javascript" => file_ext == "js" || file_ext == "jsx" || file_ext == "mjs",
                "python" => file_ext == "py",
                _ => false,
            };
            if !lang_match {
                continue;
            }

            if let Ok(content) = fs::read_to_string(&path) {
                let injection = match lang {
                    "python" => format!(
                        "# Probe integration [{tag}]\n\
                         try:\n\
                         \x20\x20\x20\x20from {probe_module} import PROBE_SECRET_{tag} as _probe  # noqa: F401\n\
                         except ImportError:\n\
                         \x20\x20\x20\x20pass\n",
                        probe_module = python_module_path(candidate, probe_dir, "entry"),
                        tag = tag,
                    ),
                    _ => format!(
                        "// Probe integration [{tag}]\n\
                         // @ts-ignore\n\
                         import {{ PROBE_SECRET_{tag} }} from './{rel_import}';\n",
                        tag = tag,
                        rel_import = js_relative_import(candidate, probe_dir, "entry"),
                    ),
                };

                let new_content = format!("{injection}\n{content}");
                let _ = fs::write(&path, new_content);
                return Some(candidate.to_string());
            }
        }
    }
    None
}

/// Compute a Python module import path from an entry file to a probe file.
fn python_module_path(entry_file: &str, probe_dir: &str, probe_file: &str) -> String {
    // Simple heuristic: if entry is in src/, use relative import
    if entry_file.starts_with("src/") {
        format!(
            ".{}.{}",
            probe_dir.replace('/', ".").trim_start_matches('.'),
            probe_file
        )
    } else {
        format!("{}.{}", probe_dir.replace('/', "."), probe_file)
    }
}

/// Compute a JS/TS relative import path from an entry file to a probe file.
fn js_relative_import(entry_file: &str, probe_dir: &str, probe_file: &str) -> String {
    let entry_dir = Path::new(entry_file)
        .parent()
        .unwrap_or(Path::new(""))
        .to_string_lossy();

    if entry_dir.is_empty() {
        format!("{probe_dir}/{probe_file}")
    } else {
        // Both in src/ or similar — compute relative path
        let probe_path = format!("{probe_dir}/{probe_file}");
        if probe_path.starts_with(entry_dir.as_ref()) {
            format!(
                "./{}",
                probe_path
                    .strip_prefix(&format!("{}/", entry_dir))
                    .unwrap_or(&probe_path)
            )
        } else {
            format!("../{probe_path}")
        }
    }
}

// ---------------------------------------------------------------------------
// Main planting logic
// ---------------------------------------------------------------------------

/// Plant benchmark artifacts into `source_dir` and return metadata describing
/// exactly what was planted and what the correct answers are.
///
/// This must be called AFTER the source checkout is ready but BEFORE the
/// source is copied into individual arm directories, so every arm gets
/// identical planted files.
pub fn plant_artifacts(source_dir: &Path) -> PlantedArtifacts {
    let (language, extension) = detect_language(source_dir);
    let tag = generate_tag();
    let secret = Uuid::new_v4().to_string();
    let version_value = format!("probe-{tag}-v1");

    // Scan for real symbols to import (creates graph edges)
    let real_symbols = scan_real_symbols(source_dir, &language, &extension);

    // All planted files go under a uniquely-named directory
    let probe_dir = format!("src/_kin_probe_{tag}");

    let gen = CodeGen::new(&language, &extension, &tag, &real_symbols);

    // Plant the 7 artifact sets
    let chain = plant_chain(source_dir, &gen, &probe_dir, &secret);
    let impact = plant_impact(source_dir, &gen, &probe_dir);
    let bugfix = plant_bugfix(source_dir, &gen, &probe_dir);
    let feature = plant_feature(source_dir, &gen, &probe_dir, &version_value);

    // Relationship-heavy tasks — these require understanding how code connects
    // 8-step chain with branching: step1..step7 over base, expected = 126
    let base_val: i64 = 13;
    let input_val: i64 = 5;
    let behavioral = plant_behavioral_trace(source_dir, &gen, &probe_dir, base_val, input_val);
    let caller_count = plant_caller_count(source_dir, &gen, &probe_dir);
    let dead_code = plant_dead_code(source_dir, &gen, &probe_dir);

    // Inject a reference into the repo's entry file
    let injected_entry_file = inject_into_entry_file(source_dir, &language, &probe_dir, &tag);

    PlantedArtifacts {
        tag: tag.clone(),
        language,
        extension,
        real_symbols,
        injected_entry_file,
        chain,
        impact,
        bugfix,
        feature,
        behavioral,
        caller_count,
        dead_code,
    }
}

// ---------------------------------------------------------------------------
// Task generation — turns planted metadata into validated LiveTasks
// ---------------------------------------------------------------------------

/// Build the 7 validated benchmark tasks from planted artifact metadata.
pub fn validated_tasks(artifacts: &PlantedArtifacts) -> Vec<LiveTask> {
    let tag = &artifacts.tag;

    vec![
        // Task 1: Find the secret via import chain tracing
        LiveTask {
            name: "find-planted-secret".to_string(),
            prompt: format!(
                "Somewhere in this codebase a constant called PROBE_SECRET_{tag} is defined. \
                 It is re-exported through a chain of imports/re-exports. Find the actual \
                 string value of PROBE_SECRET_{tag} (it is a UUID). \
                 \n\nAnswer with EXACTLY this format on its own line:\n\
                 ANSWER: SECRET=<the uuid value>"
            ),
            validators: vec![Validator::ContainsAll(vec![format!(
                "SECRET={}",
                artifacts.chain.secret_value
            )])],
        },
        // Task 2: Trace which files import the planted type (not local decoys)
        LiveTask {
            name: "trace-type-imports".to_string(),
            prompt: format!(
                "A type called `{type_name}` is defined somewhere in this codebase. \
                 Several files reference this name, but some files define their own \
                 local version with the same name instead of importing the original. \
                 \n\nList ONLY the files that import `{type_name}` from its original \
                 definition module (not files that define their own local copy). \
                 \n\nAnswer with EXACTLY this format on its own line:\n\
                 ANSWER: IMPORTS=<comma-separated file paths>",
                type_name = artifacts.impact.type_name
            ),
            validators: vec![Validator::ContainsAll(
                artifacts.impact.import_files.clone(),
            )],
        },
        // Task 3: Find and fix the planted bug
        LiveTask {
            name: "fix-planted-bug".to_string(),
            prompt: format!(
                "Find the function `{fn_name}` in this codebase. It has a bug: \
                 {description}. Fix the bug and show the corrected function.\n\n\
                 Show the complete corrected function code.",
                fn_name = artifacts.bugfix.function_name,
                description = artifacts.bugfix.bug_description
            ),
            validators: vec![Validator::ContainsAll(vec![artifacts
                .bugfix
                .fix_indicator
                .clone()])],
        },
        // Task 4: Implement the stubbed function
        LiveTask {
            name: "implement-stub".to_string(),
            prompt: format!(
                "Find the function `{fn_name}` in this codebase. It has a TODO comment \
                 asking you to implement it. The function should return the string \
                 \"{return_val}\". Write the complete implemented function.\n\n\
                 Show the complete function code with the TODO resolved.",
                fn_name = artifacts.feature.function_name,
                return_val = artifacts.feature.expected_return
            ),
            validators: vec![Validator::ContainsAll(vec![
                artifacts.feature.function_name.clone(),
                artifacts.feature.expected_return.clone(),
            ])],
        },
        // Task 5: Behavioral trace — follow an 8-step computation chain with branching
        LiveTask {
            name: "trace-computation".to_string(),
            prompt: format!(
                "The function `{fn_name}` in this codebase calls other functions across \
                 multiple files to compute its result. Each function in the chain transforms \
                 the value before passing it along — some steps use conditional logic \
                 (branching on even/odd) so you must reason about intermediate values.\n\n\
                 Trace the ENTIRE call chain starting from `{fn_name}({input})` and compute \
                 the final return value. Show your work — list each function call and its \
                 intermediate result.\n\n\
                 IMPORTANT: There is also a function called `{fn_name}Alt` (or similar) that \
                 does something completely different — make sure you trace the right one.\n\n\
                 Answer with EXACTLY this format on its own line:\n\
                 ANSWER: RESULT=<number>",
                fn_name = artifacts.behavioral.entry_function,
                input = artifacts.behavioral.input_value
            ),
            validators: vec![Validator::ContainsAll(vec![format!(
                "RESULT={}",
                artifacts.behavioral.expected_result
            )])],
        },
        // Task 6: Caller count — distinguish real import+call from decoys and import-only
        LiveTask {
            name: "count-real-callers".to_string(),
            prompt: format!(
                "The function `{fn_name}` is defined in one file and used in several others. \
                 However, some files define their OWN local function with the exact same name \
                 `{fn_name}` instead of importing the original. Additionally, some files \
                 import the function but never actually CALL it.\n\n\
                 Count ONLY the files that IMPORT `{fn_name}` from its original definition \
                 module AND actively CALL it. Do NOT count the definition file itself, \
                 do NOT count files that define their own local version, and do NOT count \
                 files that import the function but never invoke it.\n\n\
                 Answer with EXACTLY this format on its own line:\n\
                 ANSWER: COUNT=<number>",
                fn_name = artifacts.caller_count.function_name
            ),
            validators: vec![Validator::ContainsAll(vec![format!(
                "COUNT={}",
                artifacts.caller_count.expected_count
            )])],
        },
        // Task 7: Dead code detection — find functions never called across multiple files
        LiveTask {
            name: "find-dead-code".to_string(),
            prompt: format!(
                "The following files define exported functions whose names all start \
                 with `probe`:\n  - `{f0}`\n  - `{f1}`\n  - `{f2}`\n\n\
                 Together they define 12 functions. Some of these functions are imported \
                 and called from other files in the codebase. Others are never called \
                 from anywhere — they are dead code.\n\n\
                 List ONLY the function names that are NEVER called from any other file. \
                 Do not list functions that are imported or called somewhere.\n\n\
                 Answer with EXACTLY this format on its own line:\n\
                 ANSWER: DEAD=<comma-separated function names>",
                f0 = artifacts.dead_code.function_files[0],
                f1 = artifacts.dead_code.function_files[1],
                f2 = artifacts.dead_code.function_files[2],
            ),
            validators: vec![Validator::ContainsAll(
                artifacts.dead_code.dead_functions.clone(),
            )],
        },
    ]
}

// ---------------------------------------------------------------------------
// Code generation
// ---------------------------------------------------------------------------

struct CodeGen {
    lang: String,
    ext: String,
    tag: String,
    real_symbols: Vec<RealSymbol>,
}

impl CodeGen {
    fn new(lang: &str, ext: &str, tag: &str, real_symbols: &[RealSymbol]) -> Self {
        Self {
            lang: lang.to_string(),
            ext: ext.to_string(),
            tag: tag.to_string(),
            real_symbols: real_symbols.to_vec(),
        }
    }

    /// Generate a real-symbol import line to create a graph edge.
    fn real_import_line(&self, probe_dir: &str) -> String {
        if self.real_symbols.is_empty() {
            return match self.lang.as_str() {
                "python" => format!("# No real symbols found for graph integration\n"),
                _ => format!("// No real symbols found for graph integration\n"),
            };
        }

        let sym = &self.real_symbols[0];
        match self.lang.as_str() {
            "python" => {
                let module = sym.file.trim_end_matches(".py").replace('/', ".");
                format!(
                    "from {} import {}  # real symbol — graph edge  # noqa: F401\n",
                    module, sym.name
                )
            }
            _ => {
                // Compute relative import from probe_dir to the symbol's file
                let sym_path = sym.file.trim_end_matches(&format!(".{}", self.ext));
                let depth = probe_dir.matches('/').count();
                let prefix = "../".repeat(depth);
                format!(
                    "import {{ {} }} from '{}{}';  // real symbol — graph edge\n",
                    sym.name, prefix, sym_path
                )
            }
        }
    }

    // --- Chain files ---

    fn chain_entry(&self, probe_dir: &str) -> String {
        let t = &self.tag;
        let real_import = self.real_import_line(probe_dir);
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Probe entry — re-exports PROBE_SECRET_{t}.\"\"\"\n\
                 {real_import}\
                 from .chain.middle_{t} import PROBE_SECRET_{t}\n\
                 \n\
                 __all__ = [\"PROBE_SECRET_{t}\"]\n"
            ),
            _ => format!(
                "// Probe entry — re-exports PROBE_SECRET_{t}.\n\
                 {real_import}\
                 export {{ PROBE_SECRET_{t} }} from './chain/middle_{t}';\n"
            ),
        }
    }

    fn chain_middle(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Probe chain — middle link.\"\"\"\n\
                 from .core_{t} import PROBE_SECRET_{t}  # noqa: F401\n\
                 \n\
                 __all__ = [\"PROBE_SECRET_{t}\"]\n"
            ),
            _ => format!(
                "// Probe chain — middle link.\n\
                 export {{ PROBE_SECRET_{t} }} from './core_{t}';\n"
            ),
        }
    }

    fn chain_core(&self, secret: &str) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Core probe — the actual secret definition.\"\"\"\n\
                 \n\
                 PROBE_SECRET_{t} = \"{secret}\"\n"
            ),
            _ => format!(
                "// Core probe — the actual secret definition.\n\
                 export const PROBE_SECRET_{t} = '{secret}';\n"
            ),
        }
    }

    fn chain_decoy(&self, index: usize) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Probe helper — not part of the secret chain.\"\"\"\n\
                 \n\
                 PROBE_LABEL_{t} = \"decoy-{index}\"\n\
                 \n\
                 def probe_helper_{t}_{index}(value: str) -> str:\n\
                     return f\"probe-{{value}}-{index}\"\n"
            ),
            _ => format!(
                "// Probe helper — not part of the secret chain.\n\
                 export const PROBE_LABEL_{t} = 'decoy-{index}';\n\
                 \n\
                 export function probeHelper_{t}_{index}(value: string): string {{\n\
                 \x20 return `probe-${{value}}-{index}`;\n\
                 }}\n"
            ),
        }
    }

    // --- Impact files ---

    fn type_definition(&self) -> String {
        let t = &self.tag;
        let type_name = format!("ProbeConfig_{t}");
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Canonical definition of {type_name}.\"\"\"\n\
                 from dataclasses import dataclass\n\
                 \n\
                 @dataclass\n\
                 class {type_name}:\n\
                     host: str\n\
                     port: int\n\
                     debug: bool\n\
                     max_retries: int\n\
                     timeout_ms: int\n"
            ),
            "javascript" => format!(
                "// Canonical definition of {type_name}.\n\
                 export class {type_name} {{\n\
                 \x20 constructor(options = {{}}) {{\n\
                 \x20\x20\x20 this.host = options.host ?? 'localhost';\n\
                 \x20\x20\x20 this.port = options.port ?? 3000;\n\
                 \x20\x20\x20 this.debug = options.debug ?? false;\n\
                 \x20\x20\x20 this.maxRetries = options.maxRetries ?? 3;\n\
                 \x20\x20\x20 this.timeoutMs = options.timeoutMs ?? 1000;\n\
                 \x20 }}\n\
                 }}\n"
            ),
            _ => format!(
                "// Canonical definition of {type_name}.\n\
                 export interface {type_name} {{\n\
                 \x20 host: string;\n\
                 \x20 port: number;\n\
                 \x20 debug: boolean;\n\
                 \x20 maxRetries: number;\n\
                 \x20 timeoutMs: number;\n\
                 }}\n"
            ),
        }
    }

    fn type_importer(&self, import_from: &str, index: usize) -> String {
        let t = &self.tag;
        let type_name = format!("ProbeConfig_{t}");
        let usage = match index {
            0 => "connects to host",
            1 => "checks debug flag",
            _ => "reads timeout",
        };
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Module that {usage} using {type_name}.\"\"\"\n\
                 from {import_from} import {type_name}\n\
                 \n\
                 def apply_config_{t}_{index}(cfg: {type_name}) -> str:\n\
                     return f\"applied-{{cfg.host}}\"\n"
            ),
            "javascript" => format!(
                "// Module that {usage} using {type_name}.\n\
                 import {{ {type_name} }} from '{import_from}';\n\
                 \n\
                 export function applyConfig_{t}_{index}(cfg) {{\n\
                 \x20 if (!(cfg instanceof {type_name})) {{\n\
                 \x20\x20\x20 return 'invalid-config';\n\
                 \x20 }}\n\
                 \x20 return `applied-${{cfg.host}}`;\n\
                 }}\n"
            ),
            _ => format!(
                "// Module that {usage} using {type_name}.\n\
                 import {{ {type_name} }} from '{import_from}';\n\
                 \n\
                 export function applyConfig_{t}_{index}(cfg: {type_name}): string {{\n\
                 \x20 return `applied-${{cfg.host}}`;\n\
                 }}\n"
            ),
        }
    }

    fn type_decoy(&self, index: usize) -> String {
        let t = &self.tag;
        let type_name = format!("ProbeConfig_{t}");
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Local {type_name} — NOT imported from the canonical module.\"\"\"\n\
                 from dataclasses import dataclass\n\
                 \n\
                 @dataclass\n\
                 class {type_name}:\n\
                     \"\"\"Local override with different fields.\"\"\"\n\
                     name: str\n\
                     enabled: bool\n\
                 \n\
                 def local_check_{t}_{index}(cfg: {type_name}) -> bool:\n\
                     return cfg.enabled\n"
            ),
            "javascript" => format!(
                "// Local {type_name} — NOT imported from the canonical module.\n\
                 class {type_name} {{\n\
                 \x20 constructor(name, enabled) {{\n\
                 \x20\x20\x20 this.name = name;\n\
                 \x20\x20\x20 this.enabled = enabled;\n\
                 \x20 }}\n\
                 }}\n\
                 \n\
                 export function localCheck_{t}_{index}(cfg) {{\n\
                 \x20 return cfg.enabled;\n\
                 }}\n"
            ),
            _ => format!(
                "// Local {type_name} — NOT imported from the canonical module.\n\
                 interface {type_name} {{\n\
                 \x20 name: string;\n\
                 \x20 enabled: boolean;\n\
                 }}\n\
                 \n\
                 export function localCheck_{t}_{index}(cfg: {type_name}): boolean {{\n\
                 \x20 return cfg.enabled;\n\
                 }}\n"
            ),
        }
    }

    // --- Bugfix ---

    fn buggy_function(&self) -> String {
        let t = &self.tag;
        let fn_name = format!("validate_probe_range_{t}");
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Range validation utilities.\"\"\"\n\
                 \n\
                 def {fn_name}(value: float, min_val: float, max_val: float) -> bool:\n\
                     \"\"\"Return True if value is between min_val and max_val inclusive.\"\"\"\n\
                     if value < min_val:\n\
                         return False\n\
                     if value < max_val:\n\
                         return True\n\
                     return False\n"
            ),
            "javascript" => format!(
                "// Range validation utilities.\n\
                 \n\
                 export function {fn_name}(value, minVal, maxVal) {{\n\
                 \x20 if (value < minVal) return false;\n\
                 \x20 if (value < maxVal) return true;\n\
                 \x20 return false;\n\
                 }}\n"
            ),
            _ => format!(
                "// Range validation utilities.\n\
                 \n\
                 export function {fn_name}(\n\
                 \x20 value: number,\n\
                 \x20 minVal: number,\n\
                 \x20 maxVal: number,\n\
                 ): boolean {{\n\
                 \x20 if (value < minVal) return false;\n\
                 \x20 if (value < maxVal) return true;\n\
                 \x20 return false;\n\
                 }}\n"
            ),
        }
    }

    fn bug_description(&self) -> String {
        "the upper-bound check uses strict less-than (<) instead of \
         less-than-or-equal (<=), so it returns false when value equals max_val"
            .to_string()
    }

    fn fix_indicator(&self) -> String {
        match self.lang.as_str() {
            "python" => "value <= max_val".to_string(),
            _ => "value <= maxVal".to_string(),
        }
    }

    // --- Feature stub ---

    fn feature_stub(&self, return_value: &str) -> String {
        let t = &self.tag;
        let fn_name = format!("probe_version_{t}");
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Probe status reporter.\"\"\"\n\
                 \n\
                 class ProbeReporter_{t}:\n\
                     def name(self) -> str:\n\
                         return \"kin-benchmark-probe\"\n\
                 \n\
                     def {fn_name}(self) -> str:\n\
                         # TODO: implement this method to return \"{return_value}\"\n\
                         raise NotImplementedError\n"
            ),
            "javascript" => format!(
                "// Probe status reporter.\n\
                 \n\
                 export class ProbeReporter_{t} {{\n\
                 \x20 name() {{\n\
                 \x20\x20\x20 return 'kin-benchmark-probe';\n\
                 \x20 }}\n\
                 \n\
                 \x20 // TODO: implement this method to return \"{return_value}\"\n\
                 \x20 {fn_name}() {{\n\
                 \x20\x20\x20 throw new Error('Not implemented');\n\
                 \x20 }}\n\
                 }}\n"
            ),
            _ => format!(
                "// Probe status reporter.\n\
                 \n\
                 export class ProbeReporter_{t} {{\n\
                 \x20 name(): string {{\n\
                 \x20\x20\x20 return 'kin-benchmark-probe';\n\
                 \x20 }}\n\
                 \n\
                 \x20 // TODO: implement this method to return \"{return_value}\"\n\
                 \x20 {fn_name}(): string {{\n\
                 \x20\x20\x20 throw new Error('Not implemented');\n\
                 \x20 }}\n\
                 }}\n"
            ),
        }
    }

    // --- Behavioral trace files ---

    fn compute_base(&self, base_val: i64) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Base constant for the probe computation chain.\"\"\"\n\
                 \n\
                 PROBE_BASE_{t} = {base_val}\n"
            ),
            _ => format!(
                "// Base constant for the probe computation chain.\n\
                 export const PROBE_BASE_{t} = {base_val};\n"
            ),
        }
    }

    fn compute_step1(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Step 1: add the base constant to the input.\"\"\"\n\
                 from .base_{t} import PROBE_BASE_{t}\n\
                 \n\
                 def probe_add_offset_{t}(n: int) -> int:\n\
                     return n + PROBE_BASE_{t}\n"
            ),
            _ => format!(
                "// Step 1: add the base constant to the input.\n\
                 import {{ PROBE_BASE_{t} }} from './base_{t}';\n\
                 \n\
                 export function probeAddOffset_{t}(n: number): number {{\n\
                 \x20 return n + PROBE_BASE_{t};\n\
                 }}\n",
            ),
        }
    }

    fn compute_step2(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Step 2: double the offset result.\"\"\"\n\
                 from .step1_{t} import probe_add_offset_{t}\n\
                 \n\
                 def probe_double_shifted_{t}(n: int) -> int:\n\
                     return probe_add_offset_{t}(n) * 2\n"
            ),
            _ => format!(
                "// Step 2: double the offset result.\n\
                 import {{ probeAddOffset_{t} }} from './step1_{t}';\n\
                 \n\
                 export function probeDoubleShifted_{t}(n: number): number {{\n\
                 \x20 return probeAddOffset_{t}(n) * 2;\n\
                 }}\n",
            ),
        }
    }

    fn compute_step3(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Step 3: conditionally adjust — add 3 if even, double if odd.\"\"\"\n\
                 from .step2_{t} import probe_double_shifted_{t}\n\
                 \n\
                 def probe_conditional_adjust_{t}(n: int) -> int:\n\
                     intermediate = probe_double_shifted_{t}(n)\n\
                     if intermediate % 2 == 0:\n\
                         return intermediate + 3\n\
                     else:\n\
                         return intermediate * 2\n"
            ),
            _ => format!(
                "// Step 3: conditionally adjust — add 3 if even, double if odd.\n\
                 import {{ probeDoubleShifted_{t} }} from './step2_{t}';\n\
                 \n\
                 export function probeConditionalAdjust_{t}(n: number): number {{\n\
                 \x20 const intermediate = probeDoubleShifted_{t}(n);\n\
                 \x20 if (intermediate % 2 === 0) {{\n\
                 \x20\x20\x20 return intermediate + 3;\n\
                 \x20 }} else {{\n\
                 \x20\x20\x20 return intermediate * 2;\n\
                 \x20 }}\n\
                 }}\n",
            ),
        }
    }

    fn compute_step4(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Step 4: subtract 5 from the adjusted result.\"\"\"\n\
                 from .step3_{t} import probe_conditional_adjust_{t}\n\
                 \n\
                 def probe_reduce_{t}(n: int) -> int:\n\
                     return probe_conditional_adjust_{t}(n) - 5\n"
            ),
            _ => format!(
                "// Step 4: subtract 5 from the adjusted result.\n\
                 import {{ probeConditionalAdjust_{t} }} from './step3_{t}';\n\
                 \n\
                 export function probeReduce_{t}(n: number): number {{\n\
                 \x20 return probeConditionalAdjust_{t}(n) - 5;\n\
                 }}\n",
            ),
        }
    }

    fn compute_step5(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Step 5: triple the reduced result.\"\"\"\n\
                 from .step4_{t} import probe_reduce_{t}\n\
                 \n\
                 def probe_amplify_{t}(n: int) -> int:\n\
                     return probe_reduce_{t}(n) * 3\n"
            ),
            _ => format!(
                "// Step 5: triple the reduced result.\n\
                 import {{ probeReduce_{t} }} from './step4_{t}';\n\
                 \n\
                 export function probeAmplify_{t}(n: number): number {{\n\
                 \x20 return probeReduce_{t}(n) * 3;\n\
                 }}\n",
            ),
        }
    }

    fn compute_step6(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Step 6: conditionally shift — add 7 if even, subtract 11 if odd.\"\"\"\n\
                 from .step5_{t} import probe_amplify_{t}\n\
                 \n\
                 def probe_conditional_shift_{t}(n: int) -> int:\n\
                     amplified = probe_amplify_{t}(n)\n\
                     if amplified % 2 == 0:\n\
                         return amplified + 7\n\
                     else:\n\
                         return amplified - 11\n"
            ),
            _ => format!(
                "// Step 6: conditionally shift — add 7 if even, subtract 11 if odd.\n\
                 import {{ probeAmplify_{t} }} from './step5_{t}';\n\
                 \n\
                 export function probeConditionalShift_{t}(n: number): number {{\n\
                 \x20 const amplified = probeAmplify_{t}(n);\n\
                 \x20 if (amplified % 2 === 0) {{\n\
                 \x20\x20\x20 return amplified + 7;\n\
                 \x20 }} else {{\n\
                 \x20\x20\x20 return amplified - 11;\n\
                 \x20 }}\n\
                 }}\n",
            ),
        }
    }

    fn compute_step7(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Step 7 (entry): add 17 to produce the final result.\"\"\"\n\
                 from .step6_{t} import probe_conditional_shift_{t}\n\
                 \n\
                 def probe_final_transform_{t}(n: int) -> int:\n\
                     return probe_conditional_shift_{t}(n) + 17\n"
            ),
            _ => format!(
                "// Step 7 (entry): add 17 to produce the final result.\n\
                 import {{ probeConditionalShift_{t} }} from './step6_{t}';\n\
                 \n\
                 export function probeFinalTransform_{t}(n: number): number {{\n\
                 \x20 return probeConditionalShift_{t}(n) + 17;\n\
                 }}\n",
            ),
        }
    }

    fn compute_decoy(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Alternative transform — NOT part of the real chain.\"\"\"\n\
                 from .step4_{t} import probe_reduce_{t}\n\
                 \n\
                 def probe_final_transform_alt_{t}(n: int) -> int:\n\
                     \"\"\"Completely different logic — multiplies by 100.\"\"\"\n\
                     return probe_reduce_{t}(n) * 100\n"
            ),
            _ => format!(
                "// Alternative transform — NOT part of the real chain.\n\
                 import {{ probeReduce_{t} }} from './step4_{t}';\n\
                 \n\
                 export function probeFinalTransformAlt_{t}(n: number): number {{\n\
                 \x20 // Completely different logic — multiplies by 100.\n\
                 \x20 return probeReduce_{t}(n) * 100;\n\
                 }}\n"
            ),
        }
    }

    // --- Caller count files ---

    fn shared_function_def(&self) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Shared formatting utility.\"\"\"\n\
                 \n\
                 def probe_format_{t}(val: str) -> str:\n\
                     return f\"[probe-{{val}}]\"\n"
            ),
            _ => format!(
                "// Shared formatting utility.\n\
                 \n\
                 export function probeFormat_{t}(val: string): string {{\n\
                 \x20 return `[probe-${{val}}]`;\n\
                 }}\n"
            ),
        }
    }

    fn shared_function_importer(&self, import_from: &str, index: usize) -> String {
        let t = &self.tag;
        let usage = match index {
            0 => "formats user names",
            1 => "formats error codes",
            2 => "formats log entries",
            3 => "formats timestamps",
            4 => "formats headers",
            5 => "formats metrics",
            6 => "formats alerts",
            _ => "formats output",
        };
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Module that {usage}.\"\"\"\n\
                 from {import_from} import probe_format_{t}\n\
                 \n\
                 def use_format_{t}_{index}(value: str) -> str:\n\
                     return probe_format_{t}(value) + \"-{index}\"\n"
            ),
            _ => format!(
                "// Module that {usage}.\n\
                 import {{ probeFormat_{t} }} from '{import_from}';\n\
                 \n\
                 export function useFormat_{t}_{index}(value: string): string {{\n\
                 \x20 return probeFormat_{t}(value) + '-{index}';\n\
                 }}\n"
            ),
        }
    }

    /// Files that import the function but never call it — just re-export or hold a reference.
    fn shared_function_import_only(&self, import_from: &str, index: usize) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Re-export module — imports probe_format_{t} but never calls it.\"\"\"\n\
                 from {import_from} import probe_format_{t}  # noqa: F401\n\
                 \n\
                 # Exposed for downstream but this module itself never invokes it.\n\
                 __all__ = [\"probe_format_{t}\"]\n\
                 \n\
                 IMPORT_ONLY_MARKER_{t}_{index} = \"imported-not-called\"\n"
            ),
            _ => format!(
                "// Re-export module — imports probeFormat_{t} but never calls it.\n\
                 import {{ probeFormat_{t} }} from '{import_from}';\n\
                 \n\
                 // Exposed for downstream but this module itself never invokes it.\n\
                 export {{ probeFormat_{t} }};\n\
                 \n\
                 export const IMPORT_ONLY_MARKER_{t}_{index} = 'imported-not-called';\n"
            ),
        }
    }

    fn shared_function_local(&self, index: usize) -> String {
        let t = &self.tag;
        match self.lang.as_str() {
            "python" => format!(
                "\"\"\"Local version — defines its own probe_format_{t}, NOT imported.\"\"\"\n\
                 \n\
                 def probe_format_{t}(val: str) -> str:\n\
                     \"\"\"Local override — different implementation.\"\"\"\n\
                     return val.upper()\n\
                 \n\
                 def local_use_{t}_{index}(value: str) -> str:\n\
                     return probe_format_{t}(value)\n"
            ),
            _ => format!(
                "// Local version — defines its own probeFormat_{t}, NOT imported.\n\
                 \n\
                 function probeFormat_{t}(val: string): string {{\n\
                 \x20 // Local override — different implementation.\n\
                 \x20 return val.toUpperCase();\n\
                 }}\n\
                 \n\
                 export function localUse_{t}_{index}(value: string): string {{\n\
                 \x20 return probeFormat_{t}(value);\n\
                 }}\n"
            ),
        }
    }

    /// Subtle decoy: commented-out import, dead conditional import, or dynamic require.
    fn shared_function_subtle_decoy(&self, index: usize) -> String {
        let t = &self.tag;
        match index % 3 {
            0 => {
                // Commented-out import
                match self.lang.as_str() {
                    "python" => format!(
                        "\"\"\"Commented-out import of probe_format_{t}.\"\"\"\n\
                         # from .shared_{t} import probe_format_{t}  # disabled: using local\n\
                         \n\
                         def probe_format_{t}(val: str) -> str:\n\
                             return val.strip()\n\
                         \n\
                         def subtle_use_{t}_{index}(value: str) -> str:\n\
                             return probe_format_{t}(value)\n"
                    ),
                    _ => format!(
                        "// import {{ probeFormat_{t} }} from './shared_{t}';  // disabled: using local\n\
                         \n\
                         function probeFormat_{t}(val: string): string {{\n\
                         \x20 return val.trim();\n\
                         }}\n\
                         \n\
                         export function subtleUse_{t}_{index}(value: string): string {{\n\
                         \x20 return probeFormat_{t}(value);\n\
                         }}\n"
                    ),
                }
            }
            1 => {
                // Import inside a dead conditional
                match self.lang.as_str() {
                    "python" => format!(
                        "\"\"\"Dead conditional import of probe_format_{t}.\"\"\"\n\
                         import os\n\
                         \n\
                         if os.environ.get('NEVER_SET_VAR_{t}') == 'yes':\n\
                             from .shared_{t} import probe_format_{t}\n\
                         else:\n\
                             def probe_format_{t}(val: str) -> str:\n\
                                 return val.lower()\n\
                         \n\
                         def subtle_use_{t}_{index}(value: str) -> str:\n\
                             return probe_format_{t}(value)\n"
                    ),
                    _ => format!(
                        "// Dead conditional import of probeFormat_{t}.\n\
                         \n\
                         let probeFormat_{t}: (val: string) => string;\n\
                         if (false) {{\n\
                         \x20 // @ts-ignore\n\
                         \x20 const mod = await import('./shared_{t}');\n\
                         \x20 probeFormat_{t} = mod.probeFormat_{t};\n\
                         }} else {{\n\
                         \x20 probeFormat_{t} = (val: string) => val.toLowerCase();\n\
                         }}\n\
                         \n\
                         export function subtleUse_{t}_{index}(value: string): string {{\n\
                         \x20 return probeFormat_{t}(value);\n\
                         }}\n"
                    ),
                }
            }
            _ => {
                // Dynamic require with a variable (not string literal)
                match self.lang.as_str() {
                    "python" => format!(
                        "\"\"\"Dynamic import of probe_format_{t} — not a static dependency.\"\"\"\n\
                         import importlib\n\
                         \n\
                         _MODULE_NAME = \"shared_{t}\"\n\
                         _mod = importlib.import_module(f\".{{_MODULE_NAME}}\", package=__package__)\n\
                         probe_format_{t} = getattr(_mod, \"probe_format_{t}\")\n\
                         \n\
                         def subtle_use_{t}_{index}(value: str) -> str:\n\
                             return probe_format_{t}(value)\n"
                    ),
                    _ => format!(
                        "// Dynamic require of probeFormat_{t} — not a static dependency.\n\
                         \n\
                         const _moduleName = './shared_{t}';\n\
                         // eslint-disable-next-line @typescript-eslint/no-var-requires\n\
                         const _mod = require(_moduleName);\n\
                         const probeFormat_{t} = _mod.probeFormat_{t};\n\
                         \n\
                         export function subtleUse_{t}_{index}(value: string): string {{\n\
                         \x20 return probeFormat_{t}(value);\n\
                         }}\n"
                    ),
                }
            }
        }
    }

    // --- Dead code files ---

    /// Dead code functions file. `file_index` 0..3, each has 4 functions.
    /// Functions: alive_{name} or dead_{name}. Names vary per file_index.
    fn dead_code_functions_file(&self, file_index: usize) -> String {
        let t = &self.tag;
        let names: &[(&str, &str, bool, &str, &str)] = match file_index {
            0 => &[
                ("alpha", "Alpha", true, "x + 1", "x + 1"),
                ("beta", "Beta", true, "x * 2", "x * 2"),
                ("delta", "Delta", false, "x ** 2", "x ** 2"),
                ("epsilon", "Epsilon", false, "x // 2", "Math.floor(x / 2)"),
            ],
            1 => &[
                ("gamma", "Gamma", true, "x - 3", "x - 3"),
                ("eta", "Eta", true, "x + 7", "x + 7"),
                ("zeta", "Zeta", false, "abs(x)", "Math.abs(x)"),
                ("theta", "Theta", false, "x * x + 1", "x * x + 1"),
            ],
            _ => &[
                ("iota", "Iota", true, "x + 10", "x + 10"),
                ("kappa", "Kappa", true, "x * 3", "x * 3"),
                ("lambda_fn", "Lambda", true, "x - 1", "x - 1"),
                ("mu", "Mu", true, "x + 5", "x + 5"),
            ],
        };

        match self.lang.as_str() {
            "python" => {
                let mut out = format!(
                    "\"\"\"Probe utility functions (group {file_index}) — some used, some dead code.\"\"\"\n\n"
                );
                for (py_name, _js_name, _live, py_body, _js_body) in names {
                    out.push_str(&format!(
                        "def probe_{py_name}_{t}(x: int) -> int:\n\
                         \x20\x20\x20\x20return {py_body}\n\n"
                    ));
                }
                out
            }
            _ => {
                let mut out = format!(
                    "// Probe utility functions (group {file_index}) — some used, some dead code.\n\n"
                );
                for (_py_name, js_name, _live, _py_body, js_body) in names {
                    out.push_str(&format!(
                        "export function probe{js_name}_{t}(x: number): number {{\n\
                         \x20 return {js_body};\n\
                         }}\n\n"
                    ));
                }
                out
            }
        }
    }

    /// Dead code caller file. `caller_index` determines which functions it calls.
    /// caller 0: calls alpha, beta, gamma (from files 0, 0, 1)
    /// caller 1: calls eta, iota, kappa (from files 1, 2, 2)
    /// caller 2: calls lambda_fn, mu (from file 2) — these keep them alive
    fn dead_code_caller_file(&self, caller_index: usize) -> String {
        let t = &self.tag;
        match caller_index {
            0 => match self.lang.as_str() {
                "python" => format!(
                    "\"\"\"Caller 0 — uses alpha, beta from group 0 and gamma from group 1.\"\"\"\n\
                     from .probe_group0_{t} import probe_alpha_{t}\n\
                     from .probe_group0_{t} import probe_beta_{t}\n\
                     from .probe_group1_{t} import probe_gamma_{t}\n\
                     \n\
                     def run_probes_a_{t}(x: int) -> int:\n\
                         a = probe_alpha_{t}(x)\n\
                         b = probe_beta_{t}(a)\n\
                         c = probe_gamma_{t}(b)\n\
                         return c\n"
                ),
                _ => format!(
                    "// Caller 0 — uses Alpha, Beta from group 0 and Gamma from group 1.\n\
                     import {{ probeAlpha_{t} }} from './probe_group0_{t}';\n\
                     import {{ probeBeta_{t} }} from './probe_group0_{t}';\n\
                     import {{ probeGamma_{t} }} from './probe_group1_{t}';\n\
                     \n\
                     export function runProbesA_{t}(x: number): number {{\n\
                     \x20 const a = probeAlpha_{t}(x);\n\
                     \x20 const b = probeBeta_{t}(a);\n\
                     \x20 const c = probeGamma_{t}(b);\n\
                     \x20 return c;\n\
                     }}\n"
                ),
            },
            1 => match self.lang.as_str() {
                "python" => format!(
                    "\"\"\"Caller 1 — uses eta from group 1, iota and kappa from group 2.\"\"\"\n\
                     from .probe_group1_{t} import probe_eta_{t}\n\
                     from .probe_group2_{t} import probe_iota_{t}\n\
                     from .probe_group2_{t} import probe_kappa_{t}\n\
                     \n\
                     def run_probes_b_{t}(x: int) -> int:\n\
                         a = probe_eta_{t}(x)\n\
                         b = probe_iota_{t}(a)\n\
                         c = probe_kappa_{t}(b)\n\
                         return c\n"
                ),
                _ => format!(
                    "// Caller 1 — uses Eta from group 1, Iota and Kappa from group 2.\n\
                     import {{ probeEta_{t} }} from './probe_group1_{t}';\n\
                     import {{ probeIota_{t} }} from './probe_group2_{t}';\n\
                     import {{ probeKappa_{t} }} from './probe_group2_{t}';\n\
                     \n\
                     export function runProbesB_{t}(x: number): number {{\n\
                     \x20 const a = probeEta_{t}(x);\n\
                     \x20 const b = probeIota_{t}(a);\n\
                     \x20 const c = probeKappa_{t}(b);\n\
                     \x20 return c;\n\
                     }}\n"
                ),
            },
            _ => match self.lang.as_str() {
                "python" => format!(
                    "\"\"\"Caller 2 — uses lambda_fn and mu from group 2.\"\"\"\n\
                     from .probe_group2_{t} import probe_lambda_fn_{t}\n\
                     from .probe_group2_{t} import probe_mu_{t}\n\
                     \n\
                     def run_probes_c_{t}(x: int) -> int:\n\
                         a = probe_lambda_fn_{t}(x)\n\
                         b = probe_mu_{t}(a)\n\
                         return b\n"
                ),
                _ => format!(
                    "// Caller 2 — uses Lambda and Mu from group 2.\n\
                     import {{ probeLambda_{t} }} from './probe_group2_{t}';\n\
                     import {{ probeMu_{t} }} from './probe_group2_{t}';\n\
                     \n\
                     export function runProbesC_{t}(x: number): number {{\n\
                     \x20 const a = probeLambda_{t}(x);\n\
                     \x20 const b = probeMu_{t}(a);\n\
                     \x20 return b;\n\
                     }}\n"
                ),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Planting helpers
// ---------------------------------------------------------------------------

fn plant_chain(source_dir: &Path, gen: &CodeGen, probe_dir: &str, secret: &str) -> ChainArtifact {
    let t = &gen.tag;
    let ext = &gen.ext;

    let chain_files = vec![
        format!("{probe_dir}/entry.{ext}"),
        format!("{probe_dir}/chain/middle_{t}.{ext}"),
        format!("{probe_dir}/chain/core_{t}.{ext}"),
    ];

    let decoy_files = vec![
        format!("{probe_dir}/helpers_{t}.{ext}"),
        format!("{probe_dir}/utils_{t}.{ext}"),
    ];

    write_file(source_dir, &chain_files[0], &gen.chain_entry(probe_dir));
    write_file(source_dir, &chain_files[1], &gen.chain_middle());
    write_file(source_dir, &chain_files[2], &gen.chain_core(secret));
    write_file(source_dir, &decoy_files[0], &gen.chain_decoy(1));
    write_file(source_dir, &decoy_files[1], &gen.chain_decoy(2));

    // Python __init__.py files for package imports
    if gen.lang == "python" {
        ensure_init_py(source_dir, probe_dir);
        ensure_init_py(source_dir, &format!("{probe_dir}/chain"));
    }

    ChainArtifact {
        chain_files,
        decoy_files,
        secret_value: secret.to_string(),
    }
}

fn plant_impact(source_dir: &Path, gen: &CodeGen, probe_dir: &str) -> ImpactArtifact {
    let t = &gen.tag;
    let ext = &gen.ext;
    let type_name = format!("ProbeConfig_{t}");

    let definition_file = format!("{probe_dir}/config_{t}.{ext}");
    let import_files = vec![
        format!("{probe_dir}/apply_host_{t}.{ext}"),
        format!("{probe_dir}/apply_debug_{t}.{ext}"),
        format!("{probe_dir}/apply_timeout_{t}.{ext}"),
    ];
    let decoy_files = vec![
        format!("{probe_dir}/decoy/local_config_{t}.{ext}"),
        format!("{probe_dir}/decoy/override_config_{t}.{ext}"),
    ];

    let import_from = match gen.lang.as_str() {
        "python" => format!(".config_{t}"),
        _ => format!("./config_{t}"),
    };

    write_file(source_dir, &definition_file, &gen.type_definition());

    for (i, f) in import_files.iter().enumerate() {
        write_file(source_dir, f, &gen.type_importer(&import_from, i));
    }
    for (i, f) in decoy_files.iter().enumerate() {
        write_file(source_dir, f, &gen.type_decoy(i));
    }

    if gen.lang == "python" {
        ensure_init_py(source_dir, &format!("{probe_dir}/decoy"));
    }

    ImpactArtifact {
        type_name,
        definition_file,
        import_files,
        decoy_files,
    }
}

fn plant_bugfix(source_dir: &Path, gen: &CodeGen, probe_dir: &str) -> BugfixArtifact {
    let t = &gen.tag;
    let ext = &gen.ext;
    let function_name = format!("validate_probe_range_{t}");
    let file = format!("{probe_dir}/validate_{t}.{ext}");

    write_file(source_dir, &file, &gen.buggy_function());

    BugfixArtifact {
        file,
        function_name,
        fix_indicator: gen.fix_indicator(),
        bug_description: gen.bug_description(),
    }
}

fn plant_feature(
    source_dir: &Path,
    gen: &CodeGen,
    probe_dir: &str,
    return_value: &str,
) -> FeatureArtifact {
    let t = &gen.tag;
    let ext = &gen.ext;
    let function_name = format!("probe_version_{t}");
    let file = format!("{probe_dir}/reporter_{t}.{ext}");

    write_file(source_dir, &file, &gen.feature_stub(return_value));

    FeatureArtifact {
        file,
        function_name,
        expected_return: return_value.to_string(),
    }
}

fn plant_behavioral_trace(
    source_dir: &Path,
    gen: &CodeGen,
    probe_dir: &str,
    base_val: i64,
    input_val: i64,
) -> BehavioralTraceArtifact {
    let t = &gen.tag;
    let ext = &gen.ext;

    let compute_dir = format!("{probe_dir}/compute");

    // 9 files: step7 (entry) → step6 → step5 → step4 → step3 → step2 → step1 → base
    let chain_files = vec![
        format!("{compute_dir}/step7_{t}.{ext}"),
        format!("{compute_dir}/step6_{t}.{ext}"),
        format!("{compute_dir}/step5_{t}.{ext}"),
        format!("{compute_dir}/step4_{t}.{ext}"),
        format!("{compute_dir}/step3_{t}.{ext}"),
        format!("{compute_dir}/step2_{t}.{ext}"),
        format!("{compute_dir}/step1_{t}.{ext}"),
        format!("{compute_dir}/base_{t}.{ext}"),
    ];
    let decoy_file = format!("{compute_dir}/decoy_transform_{t}.{ext}");

    // Write files: base, step1..step7, decoy
    write_file(source_dir, &chain_files[7], &gen.compute_base(base_val));
    write_file(source_dir, &chain_files[6], &gen.compute_step1());
    write_file(source_dir, &chain_files[5], &gen.compute_step2());
    write_file(source_dir, &chain_files[4], &gen.compute_step3());
    write_file(source_dir, &chain_files[3], &gen.compute_step4());
    write_file(source_dir, &chain_files[2], &gen.compute_step5());
    write_file(source_dir, &chain_files[1], &gen.compute_step6());
    write_file(source_dir, &chain_files[0], &gen.compute_step7());
    write_file(source_dir, &decoy_file, &gen.compute_decoy());

    if gen.lang == "python" {
        ensure_init_py(source_dir, &compute_dir);
    }

    // Compute expected result with the 7-step chain:
    // step1: input + base = 5 + 13 = 18
    // step2: result * 2 = 36
    // step3: if even: result + 3, else: result * 2 → 36 is even → 39
    // step4: result - 5 = 34
    // step5: result * 3 = 102
    // step6: if even: result + 7, else: result - 11 → 102 is even → 109
    // step7: result + 17 = 126
    let s1 = input_val + base_val;
    let s2 = s1 * 2;
    let s3 = if s2 % 2 == 0 { s2 + 3 } else { s2 * 2 };
    let s4 = s3 - 5;
    let s5 = s4 * 3;
    let s6 = if s5 % 2 == 0 { s5 + 7 } else { s5 - 11 };
    let expected_result = s6 + 17;

    let entry_function = match gen.lang.as_str() {
        "python" => format!("probe_final_transform_{t}"),
        _ => format!("probeFinalTransform_{t}"),
    };

    BehavioralTraceArtifact {
        chain_files,
        decoy_file,
        entry_function,
        input_value: input_val,
        expected_result,
        base_constant: base_val,
    }
}

fn plant_caller_count(source_dir: &Path, gen: &CodeGen, probe_dir: &str) -> CallerCountArtifact {
    let t = &gen.tag;
    let ext = &gen.ext;

    let callers_dir = format!("{probe_dir}/callers");

    let definition_file = format!("{callers_dir}/shared_{t}.{ext}");
    // 8 files that import AND call
    let import_files: Vec<String> = (0..8)
        .map(|i| format!("{callers_dir}/use_{t}_{i}.{ext}"))
        .collect();
    // 3 files that import but never call
    let import_only_files: Vec<String> = (0..3)
        .map(|i| format!("{callers_dir}/reexport_{t}_{i}.{ext}"))
        .collect();
    // 3 files with local redefinitions
    let local_decoy_files: Vec<String> = (0..3)
        .map(|i| format!("{callers_dir}/local_{t}_{i}.{ext}"))
        .collect();
    // 3 files with subtle decoy patterns (commented, dead conditional, dynamic)
    let subtle_decoy_files: Vec<String> = (0..3)
        .map(|i| format!("{callers_dir}/subtle_{t}_{i}.{ext}"))
        .collect();

    let import_from = match gen.lang.as_str() {
        "python" => format!(".shared_{t}"),
        _ => format!("./shared_{t}"),
    };

    write_file(source_dir, &definition_file, &gen.shared_function_def());
    for (i, f) in import_files.iter().enumerate() {
        write_file(
            source_dir,
            f,
            &gen.shared_function_importer(&import_from, i),
        );
    }
    for (i, f) in import_only_files.iter().enumerate() {
        write_file(
            source_dir,
            f,
            &gen.shared_function_import_only(&import_from, i),
        );
    }
    for (i, f) in local_decoy_files.iter().enumerate() {
        write_file(source_dir, f, &gen.shared_function_local(i));
    }
    for (i, f) in subtle_decoy_files.iter().enumerate() {
        write_file(source_dir, f, &gen.shared_function_subtle_decoy(i));
    }

    if gen.lang == "python" {
        ensure_init_py(source_dir, &callers_dir);
    }

    let function_name = match gen.lang.as_str() {
        "python" => format!("probe_format_{t}"),
        _ => format!("probeFormat_{t}"),
    };

    // Combine local + subtle decoys into one decoy_files vec
    let mut decoy_files = local_decoy_files;
    decoy_files.extend(subtle_decoy_files);

    CallerCountArtifact {
        definition_file,
        function_name,
        import_files,
        import_only_files,
        decoy_files,
        expected_count: 8,
    }
}

fn plant_dead_code(source_dir: &Path, gen: &CodeGen, probe_dir: &str) -> DeadCodeArtifact {
    let t = &gen.tag;
    let ext = &gen.ext;

    let dead_dir = format!("{probe_dir}/deadcheck");

    // 3 function-definition files, 4 functions each (12 total)
    let function_files: Vec<String> = (0..3)
        .map(|i| format!("{dead_dir}/probe_group{i}_{t}.{ext}"))
        .collect();

    // 3 caller files that each use different subsets
    let caller_files: Vec<String> = (0..3)
        .map(|i| format!("{dead_dir}/caller{i}_{t}.{ext}"))
        .collect();

    for i in 0..3 {
        write_file(
            source_dir,
            &function_files[i],
            &gen.dead_code_functions_file(i),
        );
    }
    for i in 0..3 {
        write_file(source_dir, &caller_files[i], &gen.dead_code_caller_file(i));
    }

    if gen.lang == "python" {
        ensure_init_py(source_dir, &dead_dir);
    }

    // Live functions (8): alpha, beta, gamma, eta, iota, kappa, lambda_fn, mu
    // Dead functions (4): delta, epsilon, zeta, theta
    let (live_functions, dead_functions) = match gen.lang.as_str() {
        "python" => (
            vec![
                format!("probe_alpha_{t}"),
                format!("probe_beta_{t}"),
                format!("probe_gamma_{t}"),
                format!("probe_eta_{t}"),
                format!("probe_iota_{t}"),
                format!("probe_kappa_{t}"),
                format!("probe_lambda_fn_{t}"),
                format!("probe_mu_{t}"),
            ],
            vec![
                format!("probe_delta_{t}"),
                format!("probe_epsilon_{t}"),
                format!("probe_zeta_{t}"),
                format!("probe_theta_{t}"),
            ],
        ),
        _ => (
            vec![
                format!("probeAlpha_{t}"),
                format!("probeBeta_{t}"),
                format!("probeGamma_{t}"),
                format!("probeEta_{t}"),
                format!("probeIota_{t}"),
                format!("probeKappa_{t}"),
                format!("probeLambda_{t}"),
                format!("probeMu_{t}"),
            ],
            vec![
                format!("probeDelta_{t}"),
                format!("probeEpsilon_{t}"),
                format!("probeZeta_{t}"),
                format!("probeTheta_{t}"),
            ],
        ),
    };

    DeadCodeArtifact {
        function_files,
        caller_files,
        live_functions,
        dead_functions,
    }
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

fn write_file(root: &Path, relative_path: &str, content: &str) {
    let full_path = root.join(relative_path);
    if let Some(parent) = full_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&full_path, content);
}

fn ensure_init_py(root: &Path, dir: &str) {
    let init = root.join(dir).join("__init__.py");
    if !init.exists() {
        write_file(root, &format!("{dir}/__init__.py"), "");
    }
    // Also ensure parent dirs have __init__.py
    let parent = Path::new(dir).parent();
    if let Some(p) = parent {
        let p_str = p.to_string_lossy();
        if !p_str.is_empty() && p_str != "." {
            let parent_init = root.join(p_str.as_ref()).join("__init__.py");
            if !parent_init.exists() {
                write_file(root, &format!("{p_str}/__init__.py"), "");
            }
        }
    }
}

fn generate_tag() -> String {
    // Use UUID to get good randomness, take first 8 chars
    Uuid::new_v4()
        .to_string()
        .replace('-', "")
        .chars()
        .take(8)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_ts_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(
            dir.path().join("src/index.ts"),
            "export function createApp() { return {}; }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("src/router.ts"),
            "export class Router { handle() {} }\n\
             export function createRouter() { return new Router(); }\n",
        )
        .unwrap();
        dir
    }

    fn setup_py_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(
            dir.path().join("src/app.py"),
            "class Application:\n    pass\n\ndef create_app():\n    return Application()\n",
        )
        .unwrap();
        dir
    }

    fn setup_js_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(
            dir.path().join("src/index.js"),
            "export function createApp() { return {}; }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("src/router.js"),
            "export class Router { handle() {} }\n\
             export function createRouter() { return new Router(); }\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn detect_language_typescript() {
        let dir = setup_ts_repo();
        let (lang, ext) = detect_language(dir.path());
        assert_eq!(lang, "typescript");
        assert_eq!(ext, "ts");
    }

    #[test]
    fn detect_language_python() {
        let dir = setup_py_repo();
        let (lang, ext) = detect_language(dir.path());
        assert_eq!(lang, "python");
        assert_eq!(ext, "py");
    }

    #[test]
    fn detect_language_javascript() {
        let dir = setup_js_repo();
        let (lang, ext) = detect_language(dir.path());
        assert_eq!(lang, "javascript");
        assert_eq!(ext, "js");
    }

    #[test]
    fn scan_finds_real_symbols() {
        let dir = setup_ts_repo();
        let symbols = scan_real_symbols(dir.path(), "typescript", "ts");
        assert!(!symbols.is_empty(), "should find at least one symbol");
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"createApp")
                || names.contains(&"Router")
                || names.contains(&"createRouter"),
            "should find real symbols: {:?}",
            names
        );
    }

    #[test]
    fn plant_creates_unique_names() {
        let dir = setup_ts_repo();
        let a1 = plant_artifacts(dir.path());
        // Create another repo to plant into (different tag)
        let dir2 = setup_ts_repo();
        let a2 = plant_artifacts(dir2.path());

        assert_ne!(a1.tag, a2.tag, "tags should differ between runs");
        assert_ne!(
            a1.chain.secret_value, a2.chain.secret_value,
            "secrets should differ"
        );
        assert_ne!(
            a1.impact.type_name, a2.impact.type_name,
            "type names should differ"
        );
    }

    #[test]
    fn all_chain_files_exist_and_contain_tag() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        for f in &artifacts.chain.chain_files {
            let path = dir.path().join(f);
            assert!(path.exists(), "chain file should exist: {f}");
            // File path itself contains the tag (via probe dir)
            assert!(
                f.contains(&artifacts.tag),
                "file path should contain tag: {f}"
            );
        }
    }

    #[test]
    fn secret_only_in_core_file() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        // Core (last in chain) has the secret
        let core = fs::read_to_string(dir.path().join(&artifacts.chain.chain_files[2])).unwrap();
        assert!(core.contains(&artifacts.chain.secret_value));

        // Entry and middle re-export but don't define it
        let entry = fs::read_to_string(dir.path().join(&artifacts.chain.chain_files[0])).unwrap();
        assert!(!entry.contains(&artifacts.chain.secret_value));

        // Decoys don't have the secret
        for f in &artifacts.chain.decoy_files {
            let content = fs::read_to_string(dir.path().join(f)).unwrap();
            assert!(
                !content.contains(&artifacts.chain.secret_value),
                "decoy should not contain secret: {f}"
            );
        }
    }

    #[test]
    fn import_files_reference_definition_module() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        for f in &artifacts.impact.import_files {
            let content = fs::read_to_string(dir.path().join(f)).unwrap();
            assert!(
                content.contains(&artifacts.impact.type_name),
                "import file should reference type: {f}"
            );
            assert!(
                content.contains("import") || content.contains("from"),
                "import file should have import statement: {f}"
            );
        }
    }

    #[test]
    fn decoy_files_define_local_type() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        for f in &artifacts.impact.decoy_files {
            let content = fs::read_to_string(dir.path().join(f)).unwrap();
            assert!(content.contains(&artifacts.impact.type_name));
            // Decoys should NOT import from the config module
            let import_from = format!("config_{}", artifacts.tag);
            assert!(
                !content.contains(&import_from),
                "decoy should not import from canonical module: {f}"
            );
        }
    }

    #[test]
    fn buggy_code_does_not_contain_fix() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        let content = fs::read_to_string(dir.path().join(&artifacts.bugfix.file)).unwrap();
        assert!(content.contains(&artifacts.bugfix.function_name));
        assert!(
            !content.contains(&artifacts.bugfix.fix_indicator),
            "buggy code should not contain the fix"
        );
    }

    #[test]
    fn feature_stub_has_todo() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        let content = fs::read_to_string(dir.path().join(&artifacts.feature.file)).unwrap();
        assert!(content.contains(&artifacts.feature.function_name));
        assert!(content.contains("TODO"));
        assert!(content.contains(&artifacts.feature.expected_return));
    }

    #[test]
    fn entry_file_gets_injected() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        assert!(
            artifacts.injected_entry_file.is_some(),
            "should inject into entry file"
        );
        let entry_path = dir
            .path()
            .join(artifacts.injected_entry_file.as_ref().unwrap());
        let content = fs::read_to_string(entry_path).unwrap();
        assert!(
            content.contains(&format!("PROBE_SECRET_{}", artifacts.tag)),
            "entry file should reference the planted probe"
        );
    }

    #[test]
    fn real_symbols_imported_in_entry() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        if !artifacts.real_symbols.is_empty() {
            let entry_content =
                fs::read_to_string(dir.path().join(&artifacts.chain.chain_files[0])).unwrap();
            assert!(
                entry_content.contains("graph edge"),
                "probe entry should import a real symbol for graph integration"
            );
        }
    }

    #[test]
    fn validated_tasks_all_have_validators() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());
        let tasks = validated_tasks(&artifacts);

        assert_eq!(tasks.len(), 7);
        for task in &tasks {
            assert!(
                !task.validators.is_empty(),
                "task {} must have validators",
                task.name
            );
        }
    }

    #[test]
    fn validator_rejects_buggy_code_accepts_fix() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());
        let tasks = validated_tasks(&artifacts);
        let bugfix_task = &tasks[2];

        // Buggy code should fail validation
        let buggy = fs::read_to_string(dir.path().join(&artifacts.bugfix.file)).unwrap();
        for v in &bugfix_task.validators {
            assert!(!v.check(&buggy), "should reject buggy code");
        }

        // Fixed code should pass
        let fixed = format!(
            "function {}(value, minVal, maxVal) {{ if (value < minVal) return false; if (value <= maxVal) return true; return false; }}",
            artifacts.bugfix.function_name
        );
        for v in &bugfix_task.validators {
            assert!(v.check(&fixed), "should accept fixed code");
        }
    }

    #[test]
    fn python_planting_creates_init_files() {
        let dir = setup_py_repo();
        let artifacts = plant_artifacts(dir.path());
        assert_eq!(artifacts.language, "python");

        // Probe dir should have __init__.py
        let probe_dir = format!("src/_kin_probe_{}", artifacts.tag);
        assert!(
            dir.path().join(&probe_dir).join("__init__.py").exists(),
            "probe dir should have __init__.py"
        );
        assert!(
            dir.path()
                .join(&probe_dir)
                .join("chain")
                .join("__init__.py")
                .exists(),
            "chain dir should have __init__.py"
        );
    }

    #[test]
    fn javascript_planting_uses_valid_javascript_syntax() {
        let dir = setup_js_repo();
        let artifacts = plant_artifacts(dir.path());
        assert_eq!(artifacts.language, "javascript");

        let config =
            fs::read_to_string(dir.path().join(&artifacts.impact.definition_file)).unwrap();
        assert!(config.contains("export class"));
        assert!(!config.contains("export interface"));

        let importer =
            fs::read_to_string(dir.path().join(&artifacts.impact.import_files[0])).unwrap();
        assert!(importer.contains("instanceof"));
        assert!(!importer.contains("cfg:"));

        let bugfix = fs::read_to_string(dir.path().join(&artifacts.bugfix.file)).unwrap();
        assert!(bugfix.contains(&artifacts.bugfix.function_name));
        assert!(!bugfix.contains(": number"));
        assert!(!bugfix.contains("): boolean"));

        let feature = fs::read_to_string(dir.path().join(&artifacts.feature.file)).unwrap();
        assert!(feature.contains(&artifacts.feature.function_name));
        assert!(!feature.contains("(): string"));
    }

    // --- Behavioral trace tests ---

    #[test]
    fn behavioral_trace_chain_files_exist() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        assert_eq!(
            artifacts.behavioral.chain_files.len(),
            8,
            "should have 8 chain files (step7..step1 + base)"
        );
        for f in &artifacts.behavioral.chain_files {
            assert!(
                dir.path().join(f).exists(),
                "behavioral chain file should exist: {f}"
            );
        }
        assert!(
            dir.path().join(&artifacts.behavioral.decoy_file).exists(),
            "behavioral decoy should exist"
        );
    }

    #[test]
    fn behavioral_trace_computes_correctly() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        // 8-step chain with branching:
        // step1: 5 + 13 = 18
        // step2: 18 * 2 = 36
        // step3: 36 is even → 36 + 3 = 39
        // step4: 39 - 5 = 34
        // step5: 34 * 3 = 102
        // step6: 102 is even → 102 + 7 = 109
        // step7: 109 + 17 = 126
        assert_eq!(artifacts.behavioral.input_value, 5);
        assert_eq!(artifacts.behavioral.base_constant, 13);
        assert_eq!(artifacts.behavioral.expected_result, 126);
    }

    #[test]
    fn behavioral_trace_decoy_has_different_logic() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        let decoy = fs::read_to_string(dir.path().join(&artifacts.behavioral.decoy_file)).unwrap();
        // Decoy multiplies by 100, not the real chain logic
        assert!(decoy.contains("100"), "decoy should use different logic");
        assert!(
            decoy.contains("Alt") || decoy.contains("alt"),
            "decoy should have 'alt' in its name"
        );
    }

    #[test]
    fn behavioral_trace_decoy_imports_from_mid_chain() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        let decoy = fs::read_to_string(dir.path().join(&artifacts.behavioral.decoy_file)).unwrap();
        // Decoy should import from step4 (not step7/entry), making it confusing
        assert!(
            decoy.contains("step4") || decoy.contains("Reduce") || decoy.contains("reduce"),
            "decoy should import from a middle step in the chain"
        );
    }

    #[test]
    fn behavioral_trace_validator_accepts_correct_answer() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());
        let tasks = validated_tasks(&artifacts);
        let trace_task = tasks
            .iter()
            .find(|t| t.name == "trace-computation")
            .unwrap();

        let correct = format!(
            "The answer is ANSWER: RESULT={}",
            artifacts.behavioral.expected_result
        );
        for v in &trace_task.validators {
            assert!(v.check(&correct), "should accept correct result");
        }

        // Decoy result would be different — e.g. old formula was 29
        let wrong = "ANSWER: RESULT=29";
        for v in &trace_task.validators {
            assert!(!v.check(wrong), "should reject old/wrong result");
        }
    }

    // --- Caller count tests ---

    #[test]
    fn caller_count_files_exist() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        assert!(dir
            .path()
            .join(&artifacts.caller_count.definition_file)
            .exists());
        for f in &artifacts.caller_count.import_files {
            assert!(dir.path().join(f).exists(), "import file should exist: {f}");
        }
        for f in &artifacts.caller_count.import_only_files {
            assert!(
                dir.path().join(f).exists(),
                "import-only file should exist: {f}"
            );
        }
        for f in &artifacts.caller_count.decoy_files {
            assert!(dir.path().join(f).exists(), "decoy file should exist: {f}");
        }
    }

    #[test]
    fn caller_count_importers_actually_import_and_call() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        for f in &artifacts.caller_count.import_files {
            let content = fs::read_to_string(dir.path().join(f)).unwrap();
            assert!(
                content.contains("import")
                    && content.contains(&artifacts.caller_count.function_name),
                "importer should import the shared function: {f}"
            );
            // Should also CALL the function (not just import it)
            let fn_name = &artifacts.caller_count.function_name;
            let call_pattern = format!("{fn_name}(");
            assert!(
                content.contains(&call_pattern),
                "importer should call the function: {f}"
            );
        }
    }

    #[test]
    fn caller_count_import_only_files_dont_call() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        for f in &artifacts.caller_count.import_only_files {
            let content = fs::read_to_string(dir.path().join(f)).unwrap();
            // Should import it
            assert!(
                content.contains(&artifacts.caller_count.function_name),
                "import-only file should reference function: {f}"
            );
            // Should NOT call it (no function_name followed by '(' except in import)
            let fn_name = &artifacts.caller_count.function_name;
            let call_pattern = format!("{fn_name}(");
            assert!(
                !content.contains(&call_pattern),
                "import-only file should NOT call the function: {f}"
            );
        }
    }

    #[test]
    fn caller_count_decoys_mention_function_name() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        for f in &artifacts.caller_count.decoy_files {
            let content = fs::read_to_string(dir.path().join(f)).unwrap();
            assert!(
                content.contains(&artifacts.caller_count.function_name),
                "decoy should mention function name: {f}"
            );
        }
    }

    #[test]
    fn caller_count_expected_is_correct() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());
        assert_eq!(artifacts.caller_count.expected_count, 8);
        assert_eq!(artifacts.caller_count.import_files.len(), 8);
        assert_eq!(artifacts.caller_count.import_only_files.len(), 3);
        assert_eq!(artifacts.caller_count.decoy_files.len(), 6);
    }

    // --- Dead code tests ---

    #[test]
    fn dead_code_files_exist() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        assert_eq!(artifacts.dead_code.function_files.len(), 3);
        assert_eq!(artifacts.dead_code.caller_files.len(), 3);
        for f in &artifacts.dead_code.function_files {
            assert!(
                dir.path().join(f).exists(),
                "function file should exist: {f}"
            );
        }
        for f in &artifacts.dead_code.caller_files {
            assert!(dir.path().join(f).exists(), "caller file should exist: {f}");
        }
    }

    #[test]
    fn dead_code_callers_only_reference_live_functions() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        // Concatenate all caller file contents
        let mut all_callers = String::new();
        for f in &artifacts.dead_code.caller_files {
            all_callers.push_str(&fs::read_to_string(dir.path().join(f)).unwrap());
            all_callers.push('\n');
        }

        for live_fn in &artifacts.dead_code.live_functions {
            assert!(
                all_callers.contains(live_fn),
                "some caller should reference live function: {live_fn}"
            );
        }
        for dead_fn in &artifacts.dead_code.dead_functions {
            assert!(
                !all_callers.contains(dead_fn),
                "no caller should reference dead function: {dead_fn}"
            );
        }
    }

    #[test]
    fn dead_code_function_files_have_all_twelve() {
        let dir = setup_ts_repo();
        let artifacts = plant_artifacts(dir.path());

        // Concatenate all function file contents
        let mut all_funcs = String::new();
        for f in &artifacts.dead_code.function_files {
            all_funcs.push_str(&fs::read_to_string(dir.path().join(f)).unwrap());
            all_funcs.push('\n');
        }

        assert_eq!(artifacts.dead_code.live_functions.len(), 8);
        assert_eq!(artifacts.dead_code.dead_functions.len(), 4);

        for f in artifacts
            .dead_code
            .live_functions
            .iter()
            .chain(artifacts.dead_code.dead_functions.iter())
        {
            assert!(all_funcs.contains(f), "function files should define: {f}");
        }
    }
}
