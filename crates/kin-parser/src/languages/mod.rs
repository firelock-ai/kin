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
pub use go::GoAdapter;
pub use hcl::HclAdapter;
pub use java::JavaAdapter;
pub use javascript::JavaScriptAdapter;
pub use kotlin::KotlinAdapter;
pub use php::PhpAdapter;
pub use python::PythonAdapter;
pub use rust_lang::RustAdapter;
pub use shallow_backed::{CSharpAdapter, RubyAdapter};
pub use swift::SwiftAdapter;
pub use typescript::TypeScriptAdapter;

use kin_model::LanguageId;

use crate::adapter::LanguageAdapter;

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

    /// List all supported language IDs.
    pub fn supported_languages(&self) -> Vec<LanguageId> {
        self.adapters.iter().map(|a| a.language_id()).collect()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_all_languages() {
        let registry = AdapterRegistry::new();
        let langs = registry.supported_languages();
        assert_eq!(langs.len(), 14);
        assert!(langs.contains(&LanguageId::TypeScript));
        assert!(langs.contains(&LanguageId::JavaScript));
        assert!(langs.contains(&LanguageId::Python));
        assert!(langs.contains(&LanguageId::Go));
        assert!(langs.contains(&LanguageId::Java));
        assert!(langs.contains(&LanguageId::Rust));
        assert!(langs.contains(&LanguageId::C));
        assert!(langs.contains(&LanguageId::Cpp));
        assert!(langs.contains(&LanguageId::CSharp));
        assert!(langs.contains(&LanguageId::Ruby));
        assert!(langs.contains(&LanguageId::Php));
        assert!(langs.contains(&LanguageId::Swift));
        assert!(langs.contains(&LanguageId::Kotlin));
        assert!(langs.contains(&LanguageId::Hcl));
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
}
