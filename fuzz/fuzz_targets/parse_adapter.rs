// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fuzz the full language-adapter parse + extract path.
//!
//! Every built-in `LanguageAdapter` is handed the same arbitrary byte slice:
//! `parse` turns it into a tree-sitter `Tree`, then `extract` walks that tree
//! into entities and relations. Arbitrary input lands almost entirely on the
//! error / partial-tree branches -- exactly where `utf8_text`, byte-range
//! slicing, and name/identifier extraction are most likely to panic.
//!
//! Invariant: the adapter is total on arbitrary bytes. `parse` / `extract` may
//! return an error, but must never panic, crash, or trigger undefined behavior.

#![no_main]

use kin_model::FilePathId;
use kin_parser::AdapterRegistry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let registry = AdapterRegistry::new();
    let file_id = FilePathId::new("fuzz_input");

    for lang in registry.supported_languages() {
        let Some(adapter) = registry.get_by_language(lang) else {
            continue;
        };
        if let Ok(tree) = adapter.parse(data) {
            let _ = adapter.extract(&tree, data, &file_id);
        }
    }
});
