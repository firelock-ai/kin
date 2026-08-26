// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod c_lang;
pub mod cpp_lang;
pub mod go;
pub mod hcl;
pub mod java;
pub mod javascript;
pub mod kotlin;
pub mod php;
pub mod python;
pub mod rust_lang;
pub mod shallow_backed;
pub mod swift;
pub mod typescript;

pub use c_lang::CAdapter;
pub use cpp_lang::CppAdapter;
pub use go::{attach_go_command_effect_contract_metadata, GoAdapter};
pub use hcl::HclAdapter;
pub use java::JavaAdapter;
pub use javascript::JavaScriptAdapter;
pub use kotlin::KotlinAdapter;
pub use php::PhpAdapter;
pub use python::{is_python_builtin_name, PythonAdapter, PYTHON_BUILTIN_NAMES};
pub use rust_lang::RustAdapter;
pub use shallow_backed::{CSharpAdapter, RubyAdapter};
pub use swift::SwiftAdapter;
pub use typescript::TypeScriptAdapter;

use kin_model::LanguageId;

use crate::adapter::LanguageAdapter;

/// Every `LanguageId` this crate knows, as one list other code can iterate.
///
/// Rust cannot enumerate an enum without a macro, and this workspace has no
/// `strum`, so a hand-written list is unavoidable. What IS avoidable is the
/// list going stale silently, and that is what [`language_ordinal`] below is
/// for: it matches every variant with no wildcard arm, so adding a variant to
/// `LanguageId` fails to COMPILE there rather than quietly producing a shorter
/// list here.
///
/// Be exact about what that does and does not close, because a guard whose
/// name promises more than it detects is worse than no guard, which is the
/// defect this constant exists to fix:
///
/// * Add a variant and forget everything else: **compile error**, at
///   `language_ordinal`.
/// * Add a variant and its ordinal arm, register no adapter: **test failure**,
///   at `registry_covers_every_language_id`.
/// * Add a variant, its ordinal arm and an adapter, and forget
///   `adapter_conformance.rs`: **test failure**, at
///   `conformance_list_covers_every_language_id`.
/// * Add a variant, its ordinal arm, and forget THIS list: not caught. No
///   hand-written list can catch its own omission. It is the one residual hole
///   and it is stated rather than papered over.
pub const ALL_LANGUAGE_IDS: &[LanguageId] = &[
    LanguageId::TypeScript,
    LanguageId::JavaScript,
    LanguageId::Python,
    LanguageId::Go,
    LanguageId::Java,
    LanguageId::Rust,
    LanguageId::C,
    LanguageId::Cpp,
    LanguageId::CSharp,
    LanguageId::Ruby,
    LanguageId::Php,
    LanguageId::Swift,
    LanguageId::Kotlin,
    LanguageId::Hcl,
];

/// A stable index per language, and the tripwire that makes the list above
/// maintainable.
///
/// The body is an exhaustive match with **no wildcard arm**. That is the whole
/// point: `_ => 0` would make this compile forever and turn every guard built
/// on it into a guard that cannot fail. Do not add one.
pub fn language_ordinal(id: LanguageId) -> usize {
    match id {
        LanguageId::TypeScript => 0,
        LanguageId::JavaScript => 1,
        LanguageId::Python => 2,
        LanguageId::Go => 3,
        LanguageId::Java => 4,
        LanguageId::Rust => 5,
        LanguageId::C => 6,
        LanguageId::Cpp => 7,
        LanguageId::CSharp => 8,
        LanguageId::Ruby => 9,
        LanguageId::Php => 10,
        LanguageId::Swift => 11,
        LanguageId::Kotlin => 12,
        LanguageId::Hcl => 13,
    }
}

/// Registry of all built-in language adapters.
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn LanguageAdapter>>,
}

impl AdapterRegistry {
    /// Create a registry with all built-in adapters.
    pub fn new() -> Self {
        Self {
            adapters: vec![
                Box::new(TypeScriptAdapter),
                Box::new(JavaScriptAdapter),
                Box::new(PythonAdapter),
                Box::new(GoAdapter),
                Box::new(JavaAdapter),
                Box::new(RustAdapter),
                Box::new(CAdapter),
                Box::new(CppAdapter),
                Box::new(CSharpAdapter),
                Box::new(RubyAdapter),
                Box::new(PhpAdapter),
                Box::new(SwiftAdapter),
                Box::new(KotlinAdapter),
                Box::new(HclAdapter),
            ],
        }
    }

    /// Find an adapter by language ID.
    pub fn get_by_language(&self, lang: LanguageId) -> Option<&dyn LanguageAdapter> {
        self.adapters
            .iter()
            .find(|a| a.language_id() == lang)
            .map(|a| a.as_ref())
    }

    /// Find an adapter by file extension.
    pub fn get_by_extension(&self, ext: &str) -> Option<&dyn LanguageAdapter> {
        self.adapters
            .iter()
            .find(|a| a.file_extensions().contains(&ext))
            .map(|a| a.as_ref())
    }

    /// Find an adapter by file extension, disambiguating extensions shared
    /// between languages by inspecting the content.
    ///
    /// `.h` is the C/C++ collision: a C++ header under a `.h` name parsed
    /// with the C grammar shreds namespaces and templates into error
    /// recovery, so entity and call extraction silently degrades. A scan for
    /// constructs that exist only in C++ routes those headers to the C++
    /// adapter. The scan is biased toward C++ on ambiguity (a marker inside
    /// a comment still routes to C++): the C++ grammar parses C headers
    /// essentially intact, while the C grammar destroys C++ ones.
    pub fn get_by_extension_and_content(
        &self,
        ext: &str,
        source: &[u8],
    ) -> Option<&dyn LanguageAdapter> {
        if ext == "h" && header_content_is_cpp(source) {
            return self.get_by_language(LanguageId::Cpp);
        }
        self.get_by_extension(ext)
    }

    /// List all supported language IDs.
    pub fn supported_languages(&self) -> Vec<LanguageId> {
        self.adapters.iter().map(|a| a.language_id()).collect()
    }

    /// Every registered adapter's language and the extensions it claims, in
    /// registration order.
    ///
    /// This registry IS the supported set: admission asks it which adapter
    /// matches an extension and there is no second gate, so anything that
    /// reports Kin's supported languages must read THIS rather than keep its own
    /// list. A separate list is a second statement of one fact, and the two can
    /// only ever come to disagree — silently, because the disagreement looks
    /// like a language simply not working.
    pub fn supported_languages_with_extensions(&self) -> Vec<(LanguageId, &[&str])> {
        self.adapters
            .iter()
            .map(|adapter| (adapter.language_id(), adapter.file_extensions()))
            .collect()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether header bytes carry constructs that only exist in C++.
///
/// Markers are matched at identifier boundaries so `subclass` or
/// `mytemplate` never trigger. `class` alone is not proof (it is a legal C
/// identifier), so it counts only when followed by an identifier — the shape
/// of a declaration. Deterministic: a pure function of the bytes.
fn header_content_is_cpp(source: &[u8]) -> bool {
    const KEYWORD_MARKERS: &[&[u8]] = &[b"namespace", b"typename", b"constexpr", b"template"];
    for marker in KEYWORD_MARKERS {
        if contains_identifier_token(source, marker) {
            return true;
        }
    }
    if cpp_class_declaration_present(source) {
        return true;
    }
    // Access specifiers are C++-only syntax even without other keywords.
    for marker in [b"public:".as_slice(), b"private:", b"protected:"] {
        if find_token_boundary_match(source, marker, false).is_some() {
            return true;
        }
    }
    false
}

fn is_identifier_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

/// Whether `needle` occurs in `haystack` with non-identifier bytes (or the
/// buffer edge) on both sides.
fn contains_identifier_token(haystack: &[u8], needle: &[u8]) -> bool {
    find_token_boundary_match(haystack, needle, true).is_some()
}

/// Position of the first occurrence of `needle` whose left side is a
/// non-identifier byte or the buffer start; when `check_right` is set the
/// right side must also be a non-identifier byte or the buffer end.
fn find_token_boundary_match(haystack: &[u8], needle: &[u8], check_right: bool) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        let offset = haystack[start..]
            .windows(needle.len())
            .position(|window| window == needle)?;
        let idx = start + offset;
        let left_ok = idx == 0 || !is_identifier_byte(haystack[idx - 1]);
        let right_ok = !check_right
            || idx + needle.len() == haystack.len()
            || !is_identifier_byte(haystack[idx + needle.len()]);
        if left_ok && right_ok {
            return Some(idx);
        }
        start = idx + 1;
    }
    None
}

/// Whether the bytes contain `class <identifier>` — the shape of a C++ class
/// declaration. `class` is a legal identifier in C, so the bare token is not
/// proof by itself.
fn cpp_class_declaration_present(source: &[u8]) -> bool {
    let mut start = 0;
    while let Some(idx) = find_token_boundary_match(&source[start..], b"class", true) {
        let after = start + idx + b"class".len();
        let mut cursor = after;
        while cursor < source.len() && (source[cursor] == b' ' || source[cursor] == b'\t') {
            cursor += 1;
        }
        if cursor > after
            && cursor < source.len()
            && (source[cursor] == b'_' || source[cursor].is_ascii_alphabetic())
        {
            return true;
        }
        start = after;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry carries an adapter for every `LanguageId`, and nothing else.
    ///
    /// This replaces a guard that could not fail. The previous version read
    /// `registry.supported_languages()`, asserted its length was 14, and then
    /// asserted that same Vec contained each of 14 named variants.
    /// `supported_languages()` is `self.adapters.iter().map(|a| a.language_id())`,
    /// so **it compared the registry to itself**: add a fifteenth `LanguageId`
    /// and register no adapter, and the Vec stays at fourteen, the length
    /// assertion passes, all fourteen `contains` pass, green. A test named
    /// "registry has all languages" could not detect a language the registry
    /// lacked, which is the only thing it existed to catch. Filed as FIR-2704.
    ///
    /// The fix is to compare against something that is not the registry.
    /// [`ALL_LANGUAGE_IDS`] is that something, and [`language_ordinal`] is what
    /// keeps it honest: a new variant is a compile error there.
    ///
    /// Both directions are asserted, because either alone is half a guard. A
    /// language with no adapter is a hole; an adapter for a language the
    /// enumeration does not know means the two lists have drifted and the
    /// coverage claims built on them are measuring different sets.
    #[test]
    fn registry_covers_every_language_id() {
        let registry = AdapterRegistry::new();
        let mut registered: Vec<usize> = registry
            .supported_languages()
            .into_iter()
            .map(language_ordinal)
            .collect();
        let mut expected: Vec<usize> = ALL_LANGUAGE_IDS
            .iter()
            .copied()
            .map(language_ordinal)
            .collect();
        registered.sort_unstable();
        expected.sort_unstable();

        let missing: Vec<usize> = expected
            .iter()
            .copied()
            .filter(|o| !registered.contains(o))
            .collect();
        assert!(
            missing.is_empty(),
            "these LanguageId ordinals have no registered adapter: {missing:?}"
        );

        let extra: Vec<usize> = registered
            .iter()
            .copied()
            .filter(|o| !expected.contains(o))
            .collect();
        assert!(
            extra.is_empty(),
            "the registry holds adapters the enumeration does not know: {extra:?}"
        );

        assert_eq!(
            registered.len(),
            ALL_LANGUAGE_IDS.len(),
            "one language must have exactly one adapter; duplicates hide a language behind another"
        );
    }

    #[test]
    fn lookup_by_extension() {
        let registry = AdapterRegistry::new();
        assert!(registry.get_by_extension("ts").is_some());
        assert!(registry.get_by_extension("py").is_some());
        assert!(registry.get_by_extension("go").is_some());
        assert!(registry.get_by_extension("java").is_some());
        assert!(registry.get_by_extension("rs").is_some());
        assert!(registry.get_by_extension("js").is_some());
        assert!(registry.get_by_extension("c").is_some());
        assert!(registry.get_by_extension("cpp").is_some());
        assert!(registry.get_by_extension("cs").is_some());
        assert!(registry.get_by_extension("rb").is_some());
        assert!(registry.get_by_extension("php").is_some());
        assert!(registry.get_by_extension("swift").is_some());
        assert!(registry.get_by_extension("kt").is_some());
        assert!(registry.get_by_extension("kts").is_some());
        assert!(registry.get_by_extension("tf").is_some());
        assert!(registry.get_by_extension("tfvars").is_some());
        assert!(registry.get_by_extension("unknown").is_none());
    }

    #[test]
    fn lookup_by_language() {
        let registry = AdapterRegistry::new();
        assert!(registry.get_by_language(LanguageId::Rust).is_some());
        assert!(registry.get_by_language(LanguageId::Python).is_some());
        assert!(registry.get_by_language(LanguageId::C).is_some());
        assert!(registry.get_by_language(LanguageId::Cpp).is_some());
        assert!(registry.get_by_language(LanguageId::CSharp).is_some());
        assert!(registry.get_by_language(LanguageId::Ruby).is_some());
        assert!(registry.get_by_language(LanguageId::Php).is_some());
    }

    #[test]
    fn dot_h_header_with_cpp_constructs_routes_to_cpp() {
        let registry = AdapterRegistry::new();
        let cpp_header =
            b"namespace Catch {\n    struct ratio_string {\n        static int symbol();\n    };\n}\n";
        let adapter = registry
            .get_by_extension_and_content("h", cpp_header)
            .unwrap();
        assert_eq!(adapter.language_id(), LanguageId::Cpp);

        let template_header = b"template <class T>\nstruct maker { T value; };\n";
        let adapter = registry
            .get_by_extension_and_content("h", template_header)
            .unwrap();
        assert_eq!(adapter.language_id(), LanguageId::Cpp);
    }

    #[test]
    fn dot_h_header_without_cpp_constructs_stays_c() {
        let registry = AdapterRegistry::new();
        // `classic_config` and `subclass_id` must not trip the
        // identifier-boundary markers.
        let c_header = b"#include <stdio.h>\n\nstruct classic_config { int subclass_id; };\nint parse_config(struct classic_config *cfg);\n";
        let adapter = registry
            .get_by_extension_and_content("h", c_header)
            .unwrap();
        assert_eq!(adapter.language_id(), LanguageId::C);
    }

    #[test]
    fn non_header_extensions_ignore_content() {
        let registry = AdapterRegistry::new();
        let adapter = registry
            .get_by_extension_and_content("c", b"namespace fake {}\n")
            .unwrap();
        assert_eq!(adapter.language_id(), LanguageId::C);
    }

    #[test]
    fn cpp_header_markers_are_identifier_bounded() {
        assert!(header_content_is_cpp(b"class Session;\n"));
        assert!(header_content_is_cpp(b"struct S { public: int x; };\n"));
        // A declaration-shaped `class <identifier>` is required: `class` used
        // as a C identifier does not count.
        assert!(!header_content_is_cpp(b"int class = 1;\n"));
        assert!(!header_content_is_cpp(b"struct subclass_t { int x; };\n"));
        assert!(!header_content_is_cpp(b"int mytemplate(int namespaces);\n"));
    }
}
