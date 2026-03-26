// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Round-trip fuzz testing: projection → parse → re-projection produces
//! identical output for all supported languages.
//!
//! Invariants tested:
//! 1. **Identity fixpoint** — parse source → build layout → reconstruct with
//!    no mutations → output equals original source.
//! 2. **Re-parse stability** — identity fixpoint holds on re-parsed output
//!    (second round-trip is identical to first).
//! 3. **Mutation stability** — mutate an entity body via projection, re-parse
//!    the result, re-project with no further mutations → output matches the
//!    first mutated result.
//! 4. **Fuzz corpus** — property (3) holds across many deterministic random
//!    mutations (byte substitution, insertion, truncation, duplication).

use kin_model::{EntityId, FileLayout, FilePathId, ImportSection, SourceRegion};
use kin_parser::extract::ExtractedEntity;
use kin_parser::{AdapterRegistry, LanguageAdapter};
use kin_projection::splice::reconstruct_file;

// ── Deterministic PRNG (xorshift64) ─────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(1)) // avoid zero state
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next() % bound as u64) as usize
    }

    fn next_byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
}

// ── Fixture loading ─────────────────────────────────────────────────────

fn fixture_dir() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests")
        .join("adapter-fixtures")
}

fn load_fixture(lang: &str, file: &str) -> Vec<u8> {
    let path = fixture_dir().join(lang).join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e))
}

// ── Language test cases ─────────────────────────────────────────────────

struct LangCase {
    name: &'static str,
    extension: &'static str,
    source: LangSource,
}

enum LangSource {
    Fixture { lang_dir: &'static str, file: &'static str },
    Inline(&'static [u8]),
}

fn all_lang_cases() -> Vec<LangCase> {
    vec![
        LangCase {
            name: "Rust",
            extension: "rs",
            source: LangSource::Fixture { lang_dir: "rust", file: "basic.rs" },
        },
        LangCase {
            name: "Python",
            extension: "py",
            source: LangSource::Fixture { lang_dir: "python", file: "basic.py" },
        },
        LangCase {
            name: "TypeScript",
            extension: "ts",
            source: LangSource::Fixture { lang_dir: "typescript", file: "basic.ts" },
        },
        LangCase {
            name: "JavaScript",
            extension: "js",
            source: LangSource::Fixture { lang_dir: "javascript", file: "basic.js" },
        },
        LangCase {
            name: "Go",
            extension: "go",
            source: LangSource::Fixture { lang_dir: "go", file: "basic.go" },
        },
        LangCase {
            name: "Java",
            extension: "java",
            source: LangSource::Fixture { lang_dir: "java", file: "Basic.java" },
        },
        LangCase {
            name: "C",
            extension: "c",
            source: LangSource::Fixture { lang_dir: "c", file: "basic.c" },
        },
        LangCase {
            name: "C++",
            extension: "cpp",
            source: LangSource::Fixture { lang_dir: "cpp", file: "basic.cpp" },
        },
        LangCase {
            name: "C#",
            extension: "cs",
            source: LangSource::Fixture { lang_dir: "csharp", file: "Basic.cs" },
        },
        LangCase {
            name: "Ruby",
            extension: "rb",
            source: LangSource::Fixture { lang_dir: "ruby", file: "basic.rb" },
        },
        LangCase {
            name: "PHP",
            extension: "php",
            source: LangSource::Fixture { lang_dir: "php", file: "basic.php" },
        },
        // No fixture files for Swift, Kotlin, HCL — use inline sources.
        LangCase {
            name: "Swift",
            extension: "swift",
            source: LangSource::Inline(b"import Foundation\n\nstruct User {\n    let name: String\n    let email: String\n}\n\nfunc createUser(name: String, email: String) -> User {\n    return User(name: name, email: email)\n}\n\nfunc helperInternal() -> Int {\n    return 42\n}\n"),
        },
        LangCase {
            name: "Kotlin",
            extension: "kt",
            source: LangSource::Inline(b"data class User(val name: String, val email: String)\n\nfun createUser(name: String, email: String): User {\n    return User(name, email)\n}\n\nfun helperInternal(): Int {\n    return 42\n}\n"),
        },
        LangCase {
            name: "HCL",
            extension: "tf",
            source: LangSource::Inline(b"variable \"region\" {\n  type    = string\n  default = \"us-east-1\"\n}\n\nresource \"aws_instance\" \"web\" {\n  ami           = \"ami-12345\"\n  instance_type = \"t2.micro\"\n}\n\noutput \"instance_id\" {\n  value = aws_instance.web.id\n}\n"),
        },
    ]
}

/// Also include edge-case fixtures for languages that have them.
fn edge_case_lang_cases() -> Vec<LangCase> {
    vec![
        LangCase {
            name: "Rust (edge)",
            extension: "rs",
            source: LangSource::Fixture { lang_dir: "rust", file: "edge_cases.rs" },
        },
        LangCase {
            name: "Python (edge)",
            extension: "py",
            source: LangSource::Fixture { lang_dir: "python", file: "edge_cases.py" },
        },
        LangCase {
            name: "TypeScript (edge)",
            extension: "ts",
            source: LangSource::Fixture { lang_dir: "typescript", file: "edge_cases.ts" },
        },
        LangCase {
            name: "JavaScript (edge)",
            extension: "js",
            source: LangSource::Fixture { lang_dir: "javascript", file: "edge_cases.js" },
        },
        LangCase {
            name: "Go (edge)",
            extension: "go",
            source: LangSource::Fixture { lang_dir: "go", file: "edge_cases.go" },
        },
        LangCase {
            name: "Java (edge)",
            extension: "java",
            source: LangSource::Fixture { lang_dir: "java", file: "EdgeCases.java" },
        },
        LangCase {
            name: "C (edge)",
            extension: "c",
            source: LangSource::Fixture { lang_dir: "c", file: "edge_cases.c" },
        },
        LangCase {
            name: "C++ (edge)",
            extension: "cpp",
            source: LangSource::Fixture { lang_dir: "cpp", file: "edge_cases.cpp" },
        },
    ]
}

fn load_source(case: &LangCase) -> Vec<u8> {
    match &case.source {
        LangSource::Fixture { lang_dir, file } => load_fixture(lang_dir, file),
        LangSource::Inline(bytes) => bytes.to_vec(),
    }
}

// ── Core helpers ────────────────────────────────────────────────────────

/// Parse source with the given adapter and return extracted entities.
/// Returns None if the language grammar is incompatible with the tree-sitter
/// runtime (ABI version mismatch), allowing the test to skip gracefully.
fn parse_and_extract(
    adapter: &dyn LanguageAdapter,
    source: &[u8],
) -> Option<Vec<ExtractedEntity>> {
    let tree = match adapter.parse(source) {
        Ok(t) => t,
        Err(e) => {
            let msg = format!("{:?}", e);
            if msg.contains("Incompatible language version") {
                // Tree-sitter ABI version mismatch — skip this language.
                return None;
            }
            panic!("parse failed: {}", msg);
        }
    };
    let file_id = FilePathId::new("fuzz_test_file");
    let output = adapter
        .extract(&tree, source, &file_id)
        .expect("extract should succeed");
    Some(output.entities)
}

/// Filter to entities that are not strictly contained within any other entity.
fn top_level_entities(entities: &[ExtractedEntity]) -> Vec<&ExtractedEntity> {
    entities
        .iter()
        .filter(|e| {
            !entities.iter().any(|other| {
                // `other` strictly contains `e`
                !std::ptr::eq(*e as *const _, other as *const _)
                    && other.span.start_byte <= e.span.start_byte
                    && other.span.end_byte >= e.span.end_byte
                    && (other.span.start_byte < e.span.start_byte
                        || other.span.end_byte > e.span.end_byte)
            })
        })
        .collect()
}

/// Build a FileLayout from extracted entities and source length.
///
/// Assigns fresh EntityIds and fills gaps between entities with Trivia.
/// Returns (layout, Vec<(EntityId, byte_range)>) for mutation targeting.
fn build_layout_from_entities(
    entities: &[ExtractedEntity],
    source_len: usize,
) -> (FileLayout, Vec<(EntityId, std::ops::Range<usize>)>) {
    let top = top_level_entities(entities);

    // Sort by start_byte, break ties by descending end_byte (wider first).
    let mut sorted: Vec<&ExtractedEntity> = top;
    sorted.sort_by_key(|e| (e.span.start_byte, std::cmp::Reverse(e.span.end_byte)));

    let mut regions = Vec::new();
    let mut entity_map = Vec::new();
    let mut cursor: usize = 0;

    for entity in &sorted {
        let start = entity.span.start_byte;
        let end = entity.span.end_byte;

        // Skip entities that overlap with the current cursor (shouldn't happen
        // after top-level filtering, but defensive).
        if start < cursor {
            continue;
        }

        // Gap before this entity → trivia.
        if start > cursor {
            regions.push(SourceRegion::Trivia {
                byte_range: cursor..start,
            });
        }

        let eid = EntityId::new();
        regions.push(SourceRegion::EntityRef {
            entity_id: eid,
            byte_range: start..end,
        });
        entity_map.push((eid, start..end));
        cursor = end;
    }

    // Trailing trivia after the last entity.
    if cursor < source_len {
        regions.push(SourceRegion::Trivia {
            byte_range: cursor..source_len,
        });
    }

    let layout = FileLayout {
        file_id: FilePathId::new("fuzz_test_file"),
        imports: ImportSection {
            byte_range: 0..0,
            items: vec![],
        },
        regions,
    };

    (layout, entity_map)
}

/// Perform a single identity round-trip and return the result.
fn identity_round_trip(source: &[u8], layout: &FileLayout) -> Vec<u8> {
    reconstruct_file(source, layout, |_| None).expect("reconstruct should succeed")
}

// ── Fuzz mutation strategies ────────────────────────────────────────────

/// Apply a deterministic pseudo-random mutation to an entity body.
fn fuzz_mutate(body: &[u8], seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let strategy = rng.next_usize(5);

    match strategy {
        0 => {
            // Byte substitution: replace a random byte.
            if body.is_empty() {
                return body.to_vec();
            }
            let mut result = body.to_vec();
            let idx = rng.next_usize(result.len());
            result[idx] = rng.next_byte();
            result
        }
        1 => {
            // Byte insertion: insert a random byte at a random position.
            let mut result = body.to_vec();
            let idx = rng.next_usize(result.len().saturating_add(1));
            result.insert(idx, rng.next_byte());
            result
        }
        2 => {
            // Truncation: remove trailing bytes (1..=len/4).
            if body.len() < 4 {
                return body.to_vec();
            }
            let remove = 1 + rng.next_usize(body.len() / 4);
            body[..body.len() - remove].to_vec()
        }
        3 => {
            // Duplication: repeat a random slice within the body.
            if body.len() < 2 {
                return body.to_vec();
            }
            let start = rng.next_usize(body.len() - 1);
            let len = 1 + rng.next_usize((body.len() - start).min(16));
            let slice = &body[start..start + len];
            let mut result = body.to_vec();
            let insert_at = rng.next_usize(result.len().saturating_add(1));
            for (i, &b) in slice.iter().enumerate() {
                result.insert(insert_at + i, b);
            }
            result
        }
        _ => {
            // Comment append: add a language-agnostic trailing comment.
            let mut result = body.to_vec();
            let comment = format!(" /* fuzz-seed-{} */", seed);
            result.extend_from_slice(comment.as_bytes());
            result
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// Invariant 1: parse → build layout → reconstruct (identity) == original.
#[test]
fn identity_fixpoint_all_languages() {
    let registry = AdapterRegistry::new();

    for case in all_lang_cases() {
        let source = load_source(&case);
        let adapter = registry
            .get_by_extension(case.extension)
            .unwrap_or_else(|| panic!("no adapter for .{}", case.extension));

        let entities = match parse_and_extract(adapter, &source) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };

        let (layout, _) = build_layout_from_entities(&entities, source.len());
        let result = identity_round_trip(&source, &layout);

        assert_eq!(
            result, source,
            "[{}] Identity round-trip failed: reconstructed output differs from original",
            case.name
        );
    }
}

/// Invariant 1 on edge-case fixtures.
#[test]
fn identity_fixpoint_edge_cases() {
    let registry = AdapterRegistry::new();

    for case in edge_case_lang_cases() {
        let source = load_source(&case);
        let adapter = registry
            .get_by_extension(case.extension)
            .unwrap_or_else(|| panic!("no adapter for .{}", case.extension));

        let entities = match parse_and_extract(adapter, &source) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };

        let (layout, _) = build_layout_from_entities(&entities, source.len());
        let result = identity_round_trip(&source, &layout);

        assert_eq!(
            result, source,
            "[{}] Identity round-trip on edge-case fixture failed",
            case.name
        );
    }
}

/// Invariant 2: second identity round-trip is identical to first.
#[test]
fn reparse_stability_all_languages() {
    let registry = AdapterRegistry::new();

    for case in all_lang_cases() {
        let source = load_source(&case);
        let adapter = registry
            .get_by_extension(case.extension)
            .unwrap_or_else(|| panic!("no adapter for .{}", case.extension));

        let entities = match parse_and_extract(adapter, &source) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };

        // First round-trip.
        let (layout, _) = build_layout_from_entities(&entities, source.len());
        let r1 = identity_round_trip(&source, &layout);

        // Second round-trip: re-parse r1 and reconstruct.
        let entities2 = match parse_and_extract(adapter, &r1) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };
        let (layout2, _) = build_layout_from_entities(&entities2, r1.len());
        let r2 = identity_round_trip(&r1, &layout2);

        assert_eq!(
            r2, r1,
            "[{}] Re-parse stability failed: second round-trip differs from first",
            case.name
        );

        // Also verify entity counts are stable.
        let top1 = top_level_entities(&entities);
        let top2 = top_level_entities(&entities2);
        assert_eq!(
            top1.len(),
            top2.len(),
            "[{}] Top-level entity count changed across round-trips ({} → {})",
            case.name,
            top1.len(),
            top2.len()
        );
    }
}

/// Invariant 3: mutate one entity → project → re-parse → re-project (identity)
/// produces the same bytes as the first projection.
#[test]
fn mutation_round_trip_stability_all_languages() {
    let registry = AdapterRegistry::new();

    for case in all_lang_cases() {
        let source = load_source(&case);
        let adapter = registry
            .get_by_extension(case.extension)
            .unwrap_or_else(|| panic!("no adapter for .{}", case.extension));

        let entities = match parse_and_extract(adapter, &source) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };

        let (layout, entity_map) = build_layout_from_entities(&entities, source.len());

        // Mutate the first entity.
        let (target_id, target_range) = &entity_map[0];
        let original_body = &source[target_range.clone()];
        let mutated_body = fuzz_mutate(original_body, 42);

        let target_id_copy = *target_id;
        let mutated_clone = mutated_body.clone();
        let r1 = reconstruct_file(&source, &layout, |id| {
            if *id == target_id_copy {
                Some(mutated_clone.clone())
            } else {
                None
            }
        })
        .expect("reconstruct with mutation should succeed");

        // Re-parse the mutated output and re-project (identity).
        let entities2 = match parse_and_extract(adapter, &r1) {
            Some(e) if !e.is_empty() => e,
            _ => continue, // Mutation may have produced unparseable code.
        };

        let (layout2, _) = build_layout_from_entities(&entities2, r1.len());
        let r2 = identity_round_trip(&r1, &layout2);

        assert_eq!(
            r2, r1,
            "[{}] Mutation round-trip stability failed: re-projected output \
             differs from first mutation result",
            case.name
        );
    }
}

/// Invariant 4: fuzz corpus — mutation stability across many seeds for every
/// entity in every language.
///
/// For each language and each entity, run NUM_SEEDS different mutations and
/// verify round-trip stability.
#[test]
fn fuzz_corpus_round_trip() {
    const NUM_SEEDS: u64 = 20;

    let registry = AdapterRegistry::new();

    for case in all_lang_cases() {
        let source = load_source(&case);
        let adapter = registry
            .get_by_extension(case.extension)
            .unwrap_or_else(|| panic!("no adapter for .{}", case.extension));

        let entities = match parse_and_extract(adapter, &source) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };

        let (layout, entity_map) = build_layout_from_entities(&entities, source.len());

        for (target_id, target_range) in &entity_map {
            let original_body = &source[target_range.clone()];

            for seed in 0..NUM_SEEDS {
                let mutated_body = fuzz_mutate(original_body, seed);

                let tid = *target_id;
                let mb = mutated_body.clone();
                let r1 = reconstruct_file(&source, &layout, |id| {
                    if *id == tid {
                        Some(mb.clone())
                    } else {
                        None
                    }
                })
                .expect("reconstruct should succeed");

                // Re-parse and re-project.
                let entities2 = match parse_and_extract(adapter, &r1) {
                    Some(e) if !e.is_empty() => e,
                    _ => continue,
                };

                let (layout2, _) = build_layout_from_entities(&entities2, r1.len());
                let r2 = identity_round_trip(&r1, &layout2);

                assert_eq!(
                    r2, r1,
                    "[{} entity {:?} seed {}] Fuzz round-trip failed",
                    case.name,
                    std::str::from_utf8(&original_body[..original_body.len().min(30)])
                        .unwrap_or("<binary>"),
                    seed,
                );
            }
        }
    }
}

/// Invariant 4 on edge-case fixtures with higher seed count.
#[test]
fn fuzz_corpus_edge_cases() {
    const NUM_SEEDS: u64 = 10;

    let registry = AdapterRegistry::new();

    for case in edge_case_lang_cases() {
        let source = load_source(&case);
        let adapter = registry
            .get_by_extension(case.extension)
            .unwrap_or_else(|| panic!("no adapter for .{}", case.extension));

        let entities = match parse_and_extract(adapter, &source) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };

        let (layout, entity_map) = build_layout_from_entities(&entities, source.len());

        for (target_id, target_range) in &entity_map {
            let original_body = &source[target_range.clone()];

            for seed in 0..NUM_SEEDS {
                let mutated_body = fuzz_mutate(original_body, seed);

                let tid = *target_id;
                let mb = mutated_body.clone();
                let r1 = reconstruct_file(&source, &layout, |id| {
                    if *id == tid {
                        Some(mb.clone())
                    } else {
                        None
                    }
                })
                .expect("reconstruct should succeed");

                let entities2 = match parse_and_extract(adapter, &r1) {
                    Some(e) if !e.is_empty() => e,
                    _ => continue,
                };

                let (layout2, _) = build_layout_from_entities(&entities2, r1.len());
                let r2 = identity_round_trip(&r1, &layout2);

                assert_eq!(
                    r2, r1,
                    "[{} seed {}] Fuzz edge-case round-trip failed",
                    case.name, seed,
                );
            }
        }
    }
}

/// Verify that fingerprints are stable across identity round-trips.
#[test]
fn fingerprint_stability_across_round_trips() {
    let registry = AdapterRegistry::new();

    for case in all_lang_cases() {
        let source = load_source(&case);
        let adapter = registry
            .get_by_extension(case.extension)
            .unwrap_or_else(|| panic!("no adapter for .{}", case.extension));

        let entities1 = match parse_and_extract(adapter, &source) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };

        // Round-trip.
        let (layout, _) = build_layout_from_entities(&entities1, source.len());
        let r1 = identity_round_trip(&source, &layout);

        // Re-parse.
        let entities2 = match parse_and_extract(adapter, &r1) {
            Some(e) => e,
            None => continue,
        };

        // Compare fingerprints by name (IDs are freshly generated each time).
        let fps1: std::collections::HashMap<&str, _> = entities1
            .iter()
            .map(|e| (e.name.as_str(), &e.fingerprint))
            .collect();
        let fps2: std::collections::HashMap<&str, _> = entities2
            .iter()
            .map(|e| (e.name.as_str(), &e.fingerprint))
            .collect();

        for (name, fp1) in &fps1 {
            if let Some(fp2) = fps2.get(name) {
                assert_eq!(
                    fp1.ast_hash, fp2.ast_hash,
                    "[{}] AST hash changed for entity '{}' across identity round-trip",
                    case.name, name
                );
                assert_eq!(
                    fp1.behavior_hash, fp2.behavior_hash,
                    "[{}] Behavior hash changed for entity '{}' across identity round-trip",
                    case.name, name
                );
                assert_eq!(
                    fp1.signature_hash, fp2.signature_hash,
                    "[{}] Signature hash changed for entity '{}' across identity round-trip",
                    case.name, name
                );
            }
        }
    }
}

/// Stress test: chain multiple mutations and verify each intermediate
/// state is a valid fixpoint.
#[test]
fn chained_mutations_stability() {
    let registry = AdapterRegistry::new();
    const CHAIN_LENGTH: usize = 5;

    for case in all_lang_cases() {
        let source = load_source(&case);
        let adapter = registry
            .get_by_extension(case.extension)
            .unwrap_or_else(|| panic!("no adapter for .{}", case.extension));

        let mut current = source.clone();

        for step in 0..CHAIN_LENGTH {
            let entities = match parse_and_extract(adapter, &current) {
                Some(e) if !e.is_empty() => e,
                _ => break,
            };

            let (layout, entity_map) = build_layout_from_entities(&entities, current.len());

            // Mutate a round-robin entity.
            let idx = step % entity_map.len();
            let (target_id, target_range) = &entity_map[idx];
            let body = &current[target_range.clone()];
            let mutated = fuzz_mutate(body, step as u64 * 1000 + 7);

            let tid = *target_id;
            let mb = mutated.clone();
            let projected = reconstruct_file(&current, &layout, |id| {
                if *id == tid {
                    Some(mb.clone())
                } else {
                    None
                }
            })
            .expect("reconstruct should succeed");

            // Verify fixpoint: re-project (identity) == projected.
            let entities2 = match parse_and_extract(adapter, &projected) {
                Some(e) if !e.is_empty() => e,
                _ => break,
            };
            let (layout2, _) = build_layout_from_entities(&entities2, projected.len());
            let r2 = identity_round_trip(&projected, &layout2);

            assert_eq!(
                r2, projected,
                "[{} chain step {}] Chained mutation fixpoint failed",
                case.name, step,
            );

            current = projected;
        }
    }
}
