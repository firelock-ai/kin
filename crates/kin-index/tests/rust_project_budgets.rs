// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_index::rust_project::{RustProjectAuthority, RustProjectLimits, RustProjectObservation};
use kin_model::{ArtifactId, Hash256, RepoPath, ResolvedArtifact, ResolvedTree, TreeEntry};
use kin_parser::{languages::rust_lang::RustAdapter, LanguageAdapter};

const MANIFEST: &[u8] = b"[package]\nname='budget_fixture'\nedition='2021'\n";
const LARGE_KIN_SOURCES: &[&str] = &[
    "../kin-daemon/src/api.rs",
    "../kin-cli/src/commands/locate.rs",
    "../kin-db/src/storage/repository.rs",
];

struct Fixture {
    _root: tempfile::TempDir,
    blobs: kin_blobs::BlobStore,
    tree: ResolvedTree,
}

impl Fixture {
    fn new(files: &[(&str, &[u8])]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = kin_blobs::BlobStore::new(root.path().join("blobs")).unwrap();
        let artifacts: Vec<_> = files
            .iter()
            .map(|(path, body)| {
                let hash = blobs.write(body).unwrap();
                ResolvedArtifact::new(
                    ArtifactId::new(),
                    RepoPath::from_utf8(*path).unwrap(),
                    TreeEntry::blob(Hash256::from_bytes(hash.0), false),
                )
            })
            .collect();
        Self {
            _root: root,
            blobs,
            tree: ResolvedTree::from_artifacts(artifacts).unwrap(),
        }
    }

    fn observe(&self, limits: RustProjectLimits) -> Result<RustProjectObservation, String> {
        RustProjectAuthority::observe_admitted_tree(&self.tree, limits, |hash| {
            self.blobs
                .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                .map_err(|error| error.to_string())
        })
    }
}

fn parser_cost(bytes: &[u8]) -> (usize, usize, bool) {
    let tree = RustAdapter.parse(bytes).unwrap();
    let mut cursor = tree.walk();
    let (mut nodes, mut depth, mut max_depth) = (1usize, 0usize, 0usize);
    loop {
        if cursor.goto_first_child() {
            depth += 1;
        } else {
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    break;
                }
                depth -= 1;
            }
            if depth == 0 {
                break;
            }
        }
        nodes += 1;
        max_depth = max_depth.max(depth);
    }
    (nodes, max_depth, tree.root_node().has_error())
}

fn current(observation: Result<RustProjectObservation, String>) {
    assert!(
        matches!(observation, Ok(RustProjectObservation::Current(_))),
        "{observation:?}"
    );
}

fn refused(observation: Result<RustProjectObservation, String>, reason: &str) {
    let error =
        observation.expect_err("exhaustion must refuse, never return partial/unknown authority");
    assert!(error.contains(reason), "{error}");
}

#[test]
fn measured_large_kin_sources_have_recorded_parser_cost() {
    for relative in LARGE_KIN_SOURCES {
        // Host reads are fixture construction only. Product observation below
        // receives the exact admitted tree and real CAS; it has no host path.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        let bytes = std::fs::read(&path).unwrap();
        let (nodes, max_depth, has_parse_error) = parser_cost(&bytes);
        println!(
            "RUST_BUDGET_MEASUREMENT {}",
            serde_json::json!({
                "source": relative,
                "bytes": bytes.len(),
                "digest": kin_blobs::digest(&bytes).to_string(),
                "all_ast_nodes": nodes,
                "maximum_ast_depth": max_depth,
                "has_parse_error": has_parse_error,
            })
        );
        assert!(!has_parse_error, "{relative}");
        let limits = RustProjectLimits::default();
        assert!(nodes <= limits.syntax_nodes, "{relative}: {nodes}");
        assert!(max_depth <= limits.syntax_depth, "{relative}: {max_depth}");
        assert!(bytes.len() <= limits.body_bytes, "{relative}");
    }
}

#[test]
fn real_large_admitted_kin_sources_reach_honest_unsupported_observation() {
    for relative in LARGE_KIN_SOURCES {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        let bytes = std::fs::read(path).unwrap();
        let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", &bytes)]);
        let observation = fixture.observe(RustProjectLimits::default());
        assert!(
            matches!(observation, Ok(RustProjectObservation::Unproven { .. })),
            "ordinary source must reach explicit unsupported syntax, not a processing-budget refusal or invented authority: {relative}: {observation:?}"
        );
    }
}

#[test]
fn ordinary_source_between_hidden_and_public_byte_caps_is_observed() {
    let mut bytes = b"//".to_vec();
    bytes.extend(std::iter::repeat_n(b' ', 300 * 1024));
    bytes.extend_from_slice(b"\npub fn work() {}\n");
    let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", &bytes)]);
    assert!(matches!(
        fixture.observe(RustProjectLimits::default()),
        Ok(RustProjectObservation::Current(_))
    ));
}

#[test]
fn default_source_byte_boundary_has_no_smaller_hidden_syntax_cap() {
    let cap = RustProjectLimits::default().body_bytes;
    for length in [cap - 1, cap, cap + 1] {
        let mut body = vec![b' '; length];
        body[..2].copy_from_slice(b"//");
        let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", &body)]);
        let result = fixture.observe(RustProjectLimits::default());
        if length <= cap {
            current(result);
        } else {
            refused(result, "body bound failed: src/lib.rs");
        }
    }
}

#[test]
fn separate_manifest_boundary_does_not_borrow_the_source_allowance() {
    let defaults = RustProjectLimits::default();
    for length in [
        defaults.manifest_bytes - 1,
        defaults.manifest_bytes,
        defaults.manifest_bytes + 1,
    ] {
        let mut manifest = MANIFEST.to_vec();
        manifest.push(b'#');
        manifest.resize(length, b' ');
        let body = b"pub fn f() {}";
        let fixture = Fixture::new(&[("Cargo.toml", &manifest), ("src/lib.rs", body)]);
        // A source allowance smaller than the manifest is valid: each class
        // uses its own cap, but both still charge the cumulative byte budget.
        let result = fixture.observe(RustProjectLimits {
            body_bytes: body.len(),
            ..defaults
        });
        if length <= defaults.manifest_bytes {
            current(result);
        } else {
            refused(result, "body bound failed: Cargo.toml");
        }
    }
}

#[test]
fn cumulative_source_and_manifest_bytes_have_an_exact_boundary() {
    let root = b"pub mod leaf; pub fn f() {}";
    let leaf = b"pub fn leaf() {}";
    let total = MANIFEST.len() + root.len() + leaf.len();
    let fixture = Fixture::new(&[
        ("Cargo.toml", MANIFEST),
        ("src/lib.rs", root),
        ("src/leaf.rs", leaf),
    ]);
    for cap in [total - 1, total, total + 1] {
        let result = fixture.observe(RustProjectLimits {
            total_body_bytes: cap,
            ..Default::default()
        });
        if cap < total {
            refused(result, "source bytes budget exceeded");
        } else {
            current(result);
        }
    }
}

#[test]
fn configured_ast_node_and_depth_bounds_are_exact_refusals() {
    let body = b"pub fn f() { let value = (((1 + 2) * 3)); }";
    let (nodes, depth, parse_error) = parser_cost(body);
    assert!(!parse_error);
    let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", body)]);
    for cap in [nodes - 1, nodes, nodes + 1] {
        let result = fixture.observe(RustProjectLimits {
            syntax_nodes: cap,
            ..Default::default()
        });
        if cap < nodes {
            refused(result, "Rust syntax AST limit");
        } else {
            current(result);
        }
    }
    for cap in [depth - 1, depth, depth + 1] {
        let result = fixture.observe(RustProjectLimits {
            syntax_depth: cap,
            ..Default::default()
        });
        if cap < depth {
            refused(result, "Rust syntax AST limit");
        } else {
            current(result);
        }
    }
}

#[test]
fn supported_deep_expression_uses_ast_budget_not_module_depth_budget() {
    let body = format!(
        "pub fn f() {{ let value = {}1{}; }}",
        "(".repeat(300),
        ")".repeat(300)
    );
    let (nodes, depth, parse_error) = parser_cost(body.as_bytes());
    assert!(!parse_error);
    assert!(depth > 128 && depth <= RustProjectLimits::default().syntax_depth);
    assert!(nodes <= RustProjectLimits::default().syntax_nodes);
    let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", body.as_bytes())]);
    current(fixture.observe(RustProjectLimits::default()));
}

#[test]
fn unsupported_syntax_remains_unknown_and_bad_custody_remains_an_error() {
    let body = b"#[cfg(feature = \"optional\")] pub fn f() {}";
    let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", body)]);
    assert!(matches!(
        fixture.observe(RustProjectLimits::default()),
        Ok(RustProjectObservation::Unproven { .. })
    ));
    refused(
        fixture.observe(RustProjectLimits {
            body_bytes: body.len() - 1,
            ..Default::default()
        }),
        "body bound failed",
    );
    let source_hash = kin_blobs::digest(body);
    let corrupted = RustProjectAuthority::observe_admitted_tree(
        &fixture.tree,
        RustProjectLimits::default(),
        |hash| {
            if hash == source_hash {
                Ok(b"pub fn different() {}".to_vec())
            } else {
                fixture
                    .blobs
                    .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                    .map_err(|error| error.to_string())
            }
        },
    );
    refused(corrupted, "body bound failed");
    let unavailable = RustProjectAuthority::observe_admitted_tree(
        &fixture.tree,
        RustProjectLimits::default(),
        |_| Err("CAS unavailable".into()),
    );
    refused(unavailable, "CAS unavailable");
}
