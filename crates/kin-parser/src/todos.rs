// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Inline TODO/FIXME/HACK extraction from source files.
//!
//! Scans source code comments for common task markers and returns
//! structured data suitable for conversion into work graph items.

use std::path::{Path, PathBuf};

use crate::error::Result;

/// An extracted inline TODO/FIXME/HACK from a source file.
#[derive(Debug, Clone)]
pub struct ExtractedTodo {
    /// The marker kind: "TODO", "FIXME", "HACK", "NOTE".
    pub kind: String,
    /// The body text after the marker.
    pub body: String,
    /// Relative file path where the TODO was found.
    pub file_path: String,
    /// 1-based line number.
    pub line_number: usize,
}

/// File extensions to scan for TODOs.
const TODO_EXTENSIONS: &[&str] = &["rs", "ts", "js", "tsx", "jsx", "py", "go", "java"];

/// Regex-like markers we scan for (case-insensitive match on the tag).
const TODO_MARKERS: &[&str] = &["TODO", "FIXME", "HACK", "NOTE"];

/// Directory depth this walk descends before it stops.
///
/// `path.is_dir()` follows symlinks, so a link pointing at any ancestor makes
/// the recursion below unbounded and overflows the stack. The caller is a
/// daemon route, so that crash is reachable from a request; a depth ceiling
/// ends the walk instead. No real source tree approaches this depth.
const MAX_SCAN_DEPTH: usize = 64;

/// Resolve a caller-supplied scan root against `boundary`, refusing anything
/// outside it.
///
/// Containment lives here rather than at each call site because every caller of
/// `extract_todos` takes its root from a request: the daemon's POST /work and
/// POST /note routes, and the `kin_todo_import` MCP tool. Guarding them one at a
/// time is what left the MCP handler reading any directory the process could
/// reach while the daemon routes were already bounded, so the check belongs next
/// to the walk it protects and a fourth caller inherits it.
///
/// Fails closed in both directions. The boundary and the resolved candidate must
/// each canonicalize, so a path that cannot be resolved is refused rather than
/// compared unresolved, and a scan root that does not exist is an error rather
/// than a silently empty import. Joining an absolute path discards the base, so
/// the containment test is the single check that rejects an absolute path and a
/// `..` traversal alike.
pub fn resolve_scan_root(boundary: &Path, requested: Option<&str>) -> Result<PathBuf> {
    let base = boundary.canonicalize().map_err(|e| {
        crate::error::ParseError::Extraction(format!(
            "scan boundary {} cannot be resolved: {e}",
            boundary.display()
        ))
    })?;
    let Some(requested) = requested else {
        return Ok(base);
    };
    let candidate = base.join(requested).canonicalize().map_err(|e| {
        crate::error::ParseError::Extraction(format!(
            "scan root {requested:?} cannot be resolved: {e}"
        ))
    })?;
    if !candidate.starts_with(&base) {
        return Err(crate::error::ParseError::Extraction(format!(
            "scan root {requested:?} resolves outside {}",
            base.display()
        )));
    }
    Ok(candidate)
}

/// Scan a directory tree for inline TODO/FIXME/HACK/NOTE markers.
pub fn extract_todos(root: &Path) -> Result<Vec<ExtractedTodo>> {
    let mut todos = Vec::new();
    scan_dir(root, root, 0, &mut todos)?;
    Ok(todos)
}

fn scan_dir(base: &Path, dir: &Path, depth: usize, out: &mut Vec<ExtractedTodo>) -> Result<()> {
    if depth >= MAX_SCAN_DEPTH {
        return Ok(());
    }
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };

    for entry in read_dir {
        let entry = entry.map_err(|e| crate::error::ParseError::Io(e.to_string()))?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden directories and .kin/.
        if name_str.starts_with('.') || name_str == "node_modules" || name_str == "target" {
            continue;
        }

        if path.is_dir() {
            scan_dir(base, &path, depth + 1, out)?;
        } else if path.is_file() {
            let has_ext = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| TODO_EXTENSIONS.contains(&ext));
            if has_ext {
                scan_file(base, &path, out)?;
            }
        }
    }
    Ok(())
}

fn scan_file(base: &Path, path: &PathBuf, out: &mut Vec<ExtractedTodo>) -> Result<()> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(()), // Skip unreadable files.
    };

    let rel_path = path
        .strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Look for comment-style TODO markers.
        // Supports: // TODO, # TODO, /* TODO, * TODO, -- TODO
        let comment_body = if let Some(rest) = trimmed.strip_prefix("//") {
            Some(rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix('#') {
            Some(rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix("/*") {
            Some(rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix('*') {
            Some(rest.trim())
        } else {
            trimmed.strip_prefix("--").map(|rest| rest.trim())
        };

        if let Some(body) = comment_body {
            for marker in TODO_MARKERS {
                // Match "TODO:", "TODO(", "TODO ", "TODO -" patterns.
                let upper = body.to_uppercase();
                if let Some(after) = upper.strip_prefix(marker) {
                    if after.is_empty()
                        || after.starts_with(':')
                        || after.starts_with('(')
                        || after.starts_with(' ')
                        || after.starts_with('-')
                    {
                        // Extract the actual body text after the marker.
                        let marker_len = marker.len();
                        let raw = &body[marker_len..];
                        let clean = raw
                            .trim_start_matches(':')
                            .trim_start_matches('(')
                            .trim_end_matches(')')
                            .trim_start_matches('-')
                            .trim();

                        if !clean.is_empty() {
                            out.push(ExtractedTodo {
                                kind: marker.to_string(),
                                body: clean.to_string(),
                                file_path: rel_path.clone(),
                                line_number: line_idx + 1,
                            });
                        }
                        break; // Only match first marker per line.
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn extract_rust_todos() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "src/main.rs",
            "// TODO: implement error handling\nfn main() {}\n// FIXME: this is broken\n",
        );

        let todos = extract_todos(dir.path()).unwrap();
        assert_eq!(todos.len(), 2);
        assert_eq!(todos[0].kind, "TODO");
        assert!(todos[0].body.contains("implement error handling"));
        assert_eq!(todos[0].line_number, 1);
        assert_eq!(todos[1].kind, "FIXME");
        assert!(todos[1].body.contains("this is broken"));
    }

    #[test]
    fn extract_python_todos() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "app.py",
            "# TODO: add logging\ndef hello():\n    pass\n# HACK: temporary workaround\n",
        );

        let todos = extract_todos(dir.path()).unwrap();
        assert_eq!(todos.len(), 2);
        assert_eq!(todos[0].kind, "TODO");
        assert_eq!(todos[1].kind, "HACK");
    }

    #[test]
    fn skips_hidden_dirs() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            ".hidden/file.rs",
            "// TODO: should be skipped\n",
        );
        write_file(dir.path(), "src/visible.rs", "// TODO: should be found\n");

        let todos = extract_todos(dir.path()).unwrap();
        assert_eq!(todos.len(), 1);
        assert_eq!(todos[0].file_path, "src/visible.rs");
    }

    #[test]
    fn handles_various_marker_formats() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "src/test.rs",
            concat!(
                "// TODO: colon style\n",
                "// TODO(user) paren style\n",
                "// TODO - dash style\n",
                "// NOTE: informational\n",
            ),
        );

        let todos = extract_todos(dir.path()).unwrap();
        assert_eq!(todos.len(), 4);
        assert_eq!(todos[0].kind, "TODO");
        assert_eq!(todos[1].kind, "TODO");
        assert_eq!(todos[2].kind, "TODO");
        assert_eq!(todos[3].kind, "NOTE");
    }

    #[test]
    fn empty_directory_returns_empty() {
        let dir = TempDir::new().unwrap();
        let todos = extract_todos(dir.path()).unwrap();
        assert!(todos.is_empty());
    }

    #[test]
    fn resolve_scan_root_accepts_a_subdirectory_and_defaults_to_the_boundary() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        let base = dir.path().canonicalize().unwrap();

        assert_eq!(resolve_scan_root(dir.path(), None).unwrap(), base);
        assert_eq!(
            resolve_scan_root(dir.path(), Some("src")).unwrap(),
            base.join("src")
        );
    }

    #[test]
    fn resolve_scan_root_refuses_a_path_outside_the_boundary() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();

        let refused = resolve_scan_root(dir.path(), Some(&outside.path().to_string_lossy()));
        assert!(
            refused.is_err(),
            "an absolute path outside the boundary must be refused, got {refused:?}"
        );
    }

    #[test]
    fn resolve_scan_root_refuses_a_traversal_that_cannot_be_resolved() {
        // The one that fails open if canonicalization is treated as optional.
        // `<base>/../escape` starts with `<base>` as plain text, so a resolver
        // that falls back to the unresolved join admits it while the directory
        // it names sits outside. Refusing an unresolvable path is what closes
        // that, so this asserts the refusal rather than the comparison.
        let dir = TempDir::new().unwrap();
        let refused = resolve_scan_root(dir.path(), Some("../escape-does-not-exist"));
        assert!(
            refused.is_err(),
            "an unresolvable traversal must be refused, got {refused:?}"
        );
    }

    #[test]
    fn the_walk_stops_at_the_depth_ceiling() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "shallow.rs", "// TODO: inside the ceiling\n");

        // A chain two levels past the ceiling. Asserting both halves is what
        // makes this fail for the right reason: a bound set to zero would also
        // hide the deep marker, and the shallow assertion catches that.
        let mut chain = PathBuf::new();
        for _ in 0..MAX_SCAN_DEPTH + 2 {
            chain.push("d");
        }
        let deep = chain.join("deep.rs");
        write_file(
            dir.path(),
            deep.to_str().unwrap(),
            "// TODO: past the ceiling\n",
        );

        let todos = extract_todos(dir.path()).unwrap();
        let bodies: Vec<&str> = todos.iter().map(|todo| todo.body.as_str()).collect();
        assert!(
            bodies
                .iter()
                .any(|body| body.contains("inside the ceiling")),
            "a marker above the ceiling must still be found: {bodies:?}"
        );
        assert!(
            !bodies.iter().any(|body| body.contains("past the ceiling")),
            "the walk must stop at the depth ceiling: {bodies:?}"
        );
    }
}
