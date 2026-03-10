use kin_model::{FingerprintAlgorithm, Hash256, SemanticFingerprint};
use sha2::{Digest, Sha256};

/// Compute a SemanticFingerprint from source text and a signature string.
///
/// This operates at the entity level (post-extraction), complementing the
/// tree-sitter node-level fingerprint in kin-parser. It normalizes the source
/// before hashing so that whitespace and comment changes do not alter the
/// fingerprint.
pub fn compute_entity_fingerprint(source: &str, signature: &str) -> SemanticFingerprint {
    let normalized = normalize_source(source);

    // AST hash: hash the normalized source (approximates structure without comments/whitespace)
    let ast_hash = hash_bytes(normalized.as_bytes());

    // Signature hash: hash just the signature line
    let signature_hash = hash_bytes(signature.as_bytes());

    // Behavior hash: hash the full source including whitespace (exact content)
    let behavior_hash = hash_bytes(source.as_bytes());

    SemanticFingerprint {
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        ast_hash,
        signature_hash,
        behavior_hash,
        stability_score: compute_stability(source),
    }
}

/// Normalize source text by stripping comments, collapsing whitespace, and
/// removing blank lines. This makes the fingerprint stable across formatting
/// changes while still being sensitive to structural changes.
fn normalize_source(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut in_block_comment = false;

    for line in source.lines() {
        let trimmed = line.trim();

        // Handle block comments
        if in_block_comment {
            if let Some(pos) = trimmed.find("*/") {
                in_block_comment = false;
                let after = trimmed[pos + 2..].trim();
                if !after.is_empty() {
                    result.push_str(after);
                    result.push('\n');
                }
            }
            continue;
        }

        // Skip line comments
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // Handle start of block comment
        if let Some(pos) = trimmed.find("/*") {
            let before = trimmed[..pos].trim();
            if let Some(end_pos) = trimmed[pos..].find("*/") {
                // Single-line block comment: join before + after
                let after = trimmed[pos + end_pos + 2..].trim();
                let combined = match (before.is_empty(), after.is_empty()) {
                    (true, true) => String::new(),
                    (true, false) => after.to_string(),
                    (false, true) => before.to_string(),
                    (false, false) => format!("{} {}", before, after),
                };
                if !combined.is_empty() {
                    result.push_str(&combined);
                    result.push('\n');
                }
            } else {
                // Multi-line block comment starts here
                if !before.is_empty() {
                    result.push_str(before);
                    result.push('\n');
                }
                in_block_comment = true;
            }
            continue;
        }

        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Collapse internal whitespace
        let collapsed: String = trimmed
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        result.push_str(&collapsed);
        result.push('\n');
    }

    result
}

/// Compute a stability score based on source characteristics.
/// Longer, more complex entities get a slightly lower score since they are
/// more likely to change.
fn compute_stability(source: &str) -> f32 {
    let lines = source.lines().count();
    if lines <= 5 {
        1.0
    } else if lines <= 20 {
        0.9
    } else if lines <= 50 {
        0.8
    } else {
        0.7
    }
}

fn hash_bytes(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash256::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        assert_eq!(fp1.ast_hash, fp2.ast_hash);
        assert_eq!(fp1.signature_hash, fp2.signature_hash);
        assert_eq!(fp1.behavior_hash, fp2.behavior_hash);
    }

    #[test]
    fn whitespace_changes_do_not_affect_ast_hash() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("fn  foo()  {  1  }", "fn foo()");
        assert_eq!(fp1.ast_hash, fp2.ast_hash);
        // But behavior hash differs since exact text changed
        assert_ne!(fp1.behavior_hash, fp2.behavior_hash);
    }

    #[test]
    fn comment_changes_do_not_affect_ast_hash() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("// a comment\nfn foo() { 1 }", "fn foo()");
        assert_eq!(fp1.ast_hash, fp2.ast_hash);
    }

    #[test]
    fn different_signatures_produce_different_signature_hash() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo(x: i32)");
        assert_ne!(fp1.signature_hash, fp2.signature_hash);
    }

    #[test]
    fn structural_change_affects_ast_hash() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("fn foo() { bar(); 1 }", "fn foo()");
        assert_ne!(fp1.ast_hash, fp2.ast_hash);
    }

    #[test]
    fn stability_score_scales_with_size() {
        let small = compute_entity_fingerprint("fn x() { 1 }", "fn x()");
        let large_source = (0..60).map(|i| format!("let x{i} = {i};")).collect::<Vec<_>>().join("\n");
        let large = compute_entity_fingerprint(&large_source, "fn big()");
        assert!(small.stability_score > large.stability_score);
    }

    #[test]
    fn normalize_strips_line_comments() {
        let result = normalize_source("// hello\nfn foo() {}\n// bye\n");
        assert_eq!(result, "fn foo() {}\n");
    }

    #[test]
    fn normalize_strips_block_comments() {
        let result = normalize_source("fn foo() /* comment */ {}\n");
        assert_eq!(result, "fn foo() {}\n");
    }

    #[test]
    fn normalize_strips_python_comments() {
        let result = normalize_source("# comment\ndef foo():\n    pass\n");
        assert_eq!(result, "def foo():\npass\n");
    }

    #[test]
    fn normalize_collapses_whitespace() {
        let result = normalize_source("fn   foo(  a:   i32  ) {}\n");
        assert_eq!(result, "fn foo( a: i32 ) {}\n");
    }
}
