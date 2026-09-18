// kin/crates/kin-parser/examples/typescript_coverage.rs
//
// How much of each TypeScript file the parser actually reads, and how many
// entities it gets out.
//
// A grammar defect does not announce itself. The parse returns a tree either
// way, and the file's declarations simply stop arriving from wherever the ERROR
// node begins. This walks a tree the way ingestion walks it, extracts with the
// same adapter, and prints per file the lines an ERROR covered and the entities
// that survived, so a coverage claim about a grammar change is a measurement
// rather than an impression.
//
//   cargo run -p kin-parser --example typescript_coverage -- <dir-or-file>...
//
// Output is tab separated: path, total lines, covered lines, covered percent,
// entities, top-level declarations, error count, first error line.
//
// It lives in `examples/` because it reads the filesystem. That is ingestion IO
// here, not an answer path, and the zero-file-search checker excludes cargo's
// examples directory for exactly this reason.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use kin_model::{FilePathId, ParseState};
use kin_parser::{LanguageAdapter, TypeScriptAdapter};

fn main() {
    let roots: Vec<PathBuf> = env::args().skip(1).map(PathBuf::from).collect();
    if roots.is_empty() {
        eprintln!("Usage: typescript_coverage <dir-or-file>...");
        std::process::exit(1);
    }

    let mut files = Vec::new();
    for root in &roots {
        collect(root, &mut files);
    }
    files.sort();

    println!("path\tlines\tcovered\tcovered_pct\tentities\ttop_level\terrors\tfirst_error_line");
    let (mut total_lines, mut total_covered, mut total_entities, mut bad_files) =
        (0usize, 0usize, 0usize, 0usize);
    for path in &files {
        let Ok(source) = fs::read(path) else { continue };
        let tree = match TypeScriptAdapter.parse(&source) {
            Ok(tree) => tree,
            Err(err) => {
                eprintln!("{}: {err}", path.display());
                continue;
            }
        };
        let out = match TypeScriptAdapter.extract(
            &tree,
            &source,
            &FilePathId::new(path.to_string_lossy().as_ref()),
        ) {
            Ok(out) => out,
            Err(err) => {
                eprintln!("{}: {err}", path.display());
                continue;
            }
        };

        let lines = line_count(&source);
        let ranges = match &out.parse_state {
            ParseState::Incomplete { error_ranges } => error_ranges.clone(),
            _ => Vec::new(),
        };
        let unread = unread_lines(&source, &ranges);
        let covered = lines.saturating_sub(unread);
        let top_level = {
            let mut cursor = tree.walk();
            tree.root_node().named_children(&mut cursor).count()
        };
        let first_error_line = ranges
            .iter()
            .map(|(start, _)| line_of(&source, *start))
            .min()
            .map(|l| l.to_string())
            .unwrap_or_else(|| "-".to_string());

        println!(
            "{}\t{lines}\t{covered}\t{:.1}\t{}\t{top_level}\t{}\t{first_error_line}",
            path.display(),
            if lines == 0 {
                100.0
            } else {
                covered as f64 * 100.0 / lines as f64
            },
            out.entities.len(),
            ranges.len(),
        );

        total_lines += lines;
        total_covered += covered;
        total_entities += out.entities.len();
        if !ranges.is_empty() {
            bad_files += 1;
        }
    }

    eprintln!(
        "files={} with_errors={} lines={} covered={} ({:.2}%) entities={}",
        files.len(),
        bad_files,
        total_lines,
        total_covered,
        if total_lines == 0 {
            100.0
        } else {
            total_covered as f64 * 100.0 / total_lines as f64
        },
        total_entities,
    );
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("ts") | Some("tsx")
        ) {
            out.push(path.to_path_buf());
        }
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.file_name().and_then(|n| n.to_str()) == Some("node_modules") {
            continue;
        }
        collect(&child, out);
    }
}

fn line_count(source: &[u8]) -> usize {
    if source.is_empty() {
        return 0;
    }
    let newlines = source.iter().filter(|b| **b == b'\n').count();
    if source.last() == Some(&b'\n') {
        newlines
    } else {
        newlines + 1
    }
}

fn line_of(source: &[u8], byte: usize) -> usize {
    source[..byte.min(source.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

/// Lines touched by any error range, counted once even where ranges nest or
/// overlap, which they do: `collect_error_ranges` walks into an ERROR node and
/// reports the ones inside it too.
fn unread_lines(source: &[u8], ranges: &[(usize, usize)]) -> usize {
    if ranges.is_empty() {
        return 0;
    }
    let mut spans: Vec<(usize, usize)> = ranges
        .iter()
        .map(|(start, end)| {
            (
                line_of(source, *start),
                line_of(source, end.saturating_sub(1).max(*start)),
            )
        })
        .collect();
    spans.sort_unstable();
    let mut counted = 0usize;
    let mut reach = 0usize;
    for (start, end) in spans {
        let from = start.max(reach + 1);
        if end >= from {
            counted += end - from + 1;
            reach = end;
        }
    }
    counted
}
