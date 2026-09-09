// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Guards the founder's no-em-dash rule for kin-daemon's runtime-facing
//! strings: log lines (warn!/error!/info!/debug!), eprintln status lines,
//! and JSON string values a user reads. Comments and doc comments stay out
//! of scope on purpose, so this scans every `.rs` file under `src/` and
//! skips any line whose trimmed text starts with `//`, which covers `//`,
//! `///` and `//!` alike.
//!
//! That line-start check cannot tell a trailing `// comment` on a code line
//! from a real string, so the two lines below are a content-keyed allowlist
//! of the trailing comments already known to carry an em dash. Add to it
//! only for a genuine comment, never to silence a real user-facing string,
//! and key by the trimmed line text (not a line number) so an unrelated
//! edit earlier in the file cannot make the allowlist miss its target.

use std::path::{Path, PathBuf};

const ALLOWED_TRAILING_COMMENTS: &[(&str, &str)] = &[
    ("api.rs", "} // state dropped — models daemon shutdown."),
    (
        "lifecycle.rs",
        "None // PID alive but port not open — daemon still starting or wedged",
    ),
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_em_dash_outside_comments_in_src() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    assert!(!files.is_empty(), "expected to find kin-daemon's src/ tree");

    let mut violations = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(&src_dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(contents) = std::fs::read_to_string(file) else {
            continue;
        };
        for (idx, line) in contents.lines().enumerate() {
            if !line.contains('—') {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if ALLOWED_TRAILING_COMMENTS.contains(&(rel.as_str(), trimmed)) {
                continue;
            }
            violations.push(format!("{rel}:{}: {trimmed}", idx + 1));
        }
    }

    assert!(
        violations.is_empty(),
        "em dash found in a kin-daemon runtime string (log line, eprintln status line, or a \
         JSON string value a user reads). Restructure the sentence instead (a comma, colon, \
         semicolon, or two sentences), never a bare hyphen swap. If this is a new trailing \
         comment rather than a real string, add its (path, trimmed line) to \
         ALLOWED_TRAILING_COMMENTS in this file instead.\n{}",
        violations.join("\n")
    );
}
