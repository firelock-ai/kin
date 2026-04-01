// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/// Estimate token count from text using a structure-aware heuristic.
///
/// Instead of the naive `len / 4` approximation, this counts meaningful
/// token-like units:
/// - Each word or identifier (alphanumeric + underscore runs) counts as 1 token.
/// - Each punctuation/operator character counts as 1 token.
/// - Whitespace is free (merged into adjacent tokens by real tokenizers).
///
/// A 15% safety margin (`tokens + tokens / 7`) is applied to account for
/// tokenizer variance (e.g., BPE splitting long identifiers into sub-tokens).
///
/// This produces significantly better estimates for code (which is
/// punctuation-heavy) compared to the character-count heuristic.
pub fn estimate_tokens(text: &str) -> usize {
    let mut tokens = 0;
    let mut in_word = false;
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            if !in_word {
                tokens += 1; // start of new word/identifier = 1 token
                in_word = true;
            }
        } else {
            in_word = false;
            if !ch.is_whitespace() {
                tokens += 1; // punctuation/operator = 1 token
            }
            // whitespace is free (merged into adjacent tokens)
        }
    }
    // Apply 15% safety margin for tokenizer variance
    tokens + tokens / 7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_zero_tokens() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn single_word() {
        // "hello" → 1 word, no punctuation → 1 token + margin = 1
        let tokens = estimate_tokens("hello");
        assert_eq!(
            tokens, 1,
            "single word should be 1 token (margin rounds down)"
        );
    }

    #[test]
    fn rust_code_snippet() {
        // fn foo(x: i32) -> bool { x > 0 }
        // Words: fn, foo, x, i32, bool, x, 0 = 7
        // Punctuation: (, :, ), -, >, {, >, } = 8
        // Raw tokens = 15, with margin = 15 + 15/7 = 15 + 2 = 17
        let text = "fn foo(x: i32) -> bool { x > 0 }";
        let tokens = estimate_tokens(text);
        assert_eq!(tokens, 17, "Rust snippet should produce 17 tokens");
    }

    #[test]
    fn python_code_snippet() {
        // def hello(name): print(f"hi {name}")
        // Words: def, hello, name, print, f, hi, name = 7
        // Punctuation: (, ), :, (, ", {, }, ", ) = 9
        // Raw tokens = 16, with margin = 16 + 16/7 = 16 + 2 = 18
        let text = r#"def hello(name): print(f"hi {name}")"#;
        let tokens = estimate_tokens(text);
        assert_eq!(tokens, 18, "Python snippet should produce 18 tokens");
    }

    #[test]
    fn improvement_over_old_heuristic() {
        // The old heuristic was text.len().div_ceil(4).
        // For code with lots of punctuation, the new heuristic should differ.
        let text = "fn foo(x: i32) -> bool { x > 0 }";
        let old = text.len().div_ceil(4); // 33/4 = 9
        let new = estimate_tokens(text); // 17

        // The new heuristic should give a higher (more accurate) count for
        // punctuation-heavy code. Real tokenizers produce ~15-18 tokens for this.
        assert!(
            new > old,
            "new heuristic ({new}) should exceed old heuristic ({old}) for code"
        );
    }

    #[test]
    fn whitespace_only_is_zero() {
        assert_eq!(estimate_tokens("   \t\n  "), 0);
    }

    #[test]
    fn punctuation_only() {
        // "{}()" → 4 punctuation = 4 + 4/7 = 4
        assert_eq!(estimate_tokens("{}()"), 4);
    }

    #[test]
    fn underscore_identifier() {
        // "__init__" is one contiguous identifier = 1 + margin = 1
        assert_eq!(estimate_tokens("__init__"), 1);
    }

    #[test]
    fn mixed_prose_and_code() {
        // "// This is a comment\nlet x = 42;"
        // Words: This, is, a, comment, let, x, 42 = 7
        // Punctuation: /, /, =, ; = 4
        // Raw = 11, margin = 11 + 11/7 = 11 + 1 = 12
        let text = "// This is a comment\nlet x = 42;";
        let tokens = estimate_tokens(text);
        assert_eq!(tokens, 12);
    }
}
