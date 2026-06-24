// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fuzz the C2 shallow parse path.
//!
//! `parse_shallow_file` looks up a tree-sitter grammar by language hint, parses
//! arbitrary bytes, and runs the generic shallow extractor (top-level
//! declaration / import classification plus file-level fingerprinting). It is
//! the ingestion tier for languages that have a grammar but no full semantic
//! adapter.
//!
//! Invariant: shallow parsing is total on arbitrary bytes for every supported
//! hint -- it returns `Some(ShallowFile)` or `None`, never panicking or crashing.

#![no_main]

use kin_model::FilePathId;
use kin_parser::parse_shallow_file;
use libfuzzer_sys::fuzz_target;

// Language hints accepted by `get_shallow_grammar`.
const SHALLOW_HINTS: &[&str] = &["c", "cpp", "csharp", "ruby", "php", "swift"];

fuzz_target!(|data: &[u8]| {
    let file_id = FilePathId::new("fuzz_input");
    for hint in SHALLOW_HINTS {
        let _ = parse_shallow_file(data, &file_id, hint);
    }
});
