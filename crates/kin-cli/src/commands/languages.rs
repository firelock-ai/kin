// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin languages` — print the languages Kin extracts semantics from.
//!
//! Exists because the answer was previously unobtainable. A repository whose
//! files have no adapter initializes successfully and then answers every query
//! with an empty list, identically to a query that simply found nothing, and
//! nothing anywhere named the reason. A stranger cannot tell "Kin does not parse
//! this language" from "my search was bad", and the two call for opposite next
//! actions.
//!
//! The list is READ FROM THE REGISTRY, never written down here. Admission asks
//! `AdapterRegistry` which adapter matches an extension and there is no second
//! gate, so the registry IS the supported set. A hardcoded list beside it would
//! be a second statement of one fact, and the failure it produces is the worst
//! kind: the command keeps answering confidently while the answer quietly stops
//! being true.

use anyhow::Result;
use kin_parser::AdapterRegistry;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SupportedLanguage {
    /// Canonical language id, the same token `kin search --language` accepts.
    pub language: String,
    /// Every file extension this adapter claims, without a leading dot.
    pub extensions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LanguagesJson {
    pub schema: &'static str,
    pub count: usize,
    pub languages: Vec<SupportedLanguage>,
}

/// The registry's contents, projected for display.
///
/// Registration order is preserved rather than sorted: it is the order admission
/// consults adapters in, so a reader comparing this against behavior sees the
/// same sequence the code takes.
pub fn supported_languages() -> Vec<SupportedLanguage> {
    AdapterRegistry::new()
        .supported_languages_with_extensions()
        .into_iter()
        .map(|(language, extensions)| SupportedLanguage {
            language: language.to_string(),
            extensions: extensions.iter().map(|ext| (*ext).to_string()).collect(),
        })
        .collect()
}

pub async fn run(json: bool) -> Result<()> {
    let languages = supported_languages();
    if json {
        let payload = LanguagesJson {
            schema: "kin.languages.v1",
            count: languages.len(),
            languages,
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("Kin extracts semantics from {} languages:", languages.len());
    let width = languages
        .iter()
        .map(|entry| entry.language.len())
        .max()
        .unwrap_or(0);
    for entry in &languages {
        println!(
            "  {:width$}  {}",
            entry.language,
            entry
                .extensions
                .iter()
                .map(|ext| format!(".{ext}"))
                .collect::<Vec<_>>()
                .join(" "),
            width = width
        );
    }
    println!();
    // The honest boundary, stated where someone is already asking the question.
    // Kin still admits a file it cannot parse: it becomes repository authority
    // with content and history, and only the semantic layer is absent. Saying
    // "unsupported" without that distinction would read as "Kin refused my
    // repository", which is not what happens.
    println!(
        "Files in other languages are still admitted as repository authority \
         with their content and history. What they do not get is entities, \
         relations, and the semantic search built on them."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command's list must equal the registry's, computed by iterating the
    /// registry HERE too.
    ///
    /// A test that spelled out fourteen names would pass forever while the
    /// command drifted, which is the drift this command exists to prevent, so
    /// it must not be written that way.
    #[test]
    fn the_printed_set_is_the_registered_set() {
        let registry = AdapterRegistry::new();
        let registered: Vec<String> = registry
            .supported_languages()
            .into_iter()
            .map(|language| language.to_string())
            .collect();
        let printed: Vec<String> = supported_languages()
            .into_iter()
            .map(|entry| entry.language)
            .collect();
        assert_eq!(printed, registered);
        assert!(
            !registered.is_empty(),
            "an empty registry would make every assertion here vacuous"
        );
    }

    /// Every language reports at least one extension, and every extension is
    /// bare (no leading dot) so it can be compared against a path suffix.
    #[test]
    fn every_language_reports_matchable_extensions() {
        for entry in supported_languages() {
            assert!(
                !entry.extensions.is_empty(),
                "{} claims no extension, so nothing could ever route to it",
                entry.language
            );
            for ext in &entry.extensions {
                assert!(
                    !ext.starts_with('.'),
                    "{} reports extension {ext:?} with a leading dot; the registry \
                     matches bare extensions and the two forms would silently disagree",
                    entry.language
                );
            }
        }
    }

    /// Each reported extension must actually route to the language that claims
    /// it, so the printed table is a statement about behavior rather than about
    /// a struct.
    ///
    /// Shared extensions are the exception this asserts around: `.h` is claimed
    /// by C and disambiguated to C++ by content, so the check is that SOME
    /// adapter accepts every printed extension and that no extension is printed
    /// which routes nowhere.
    #[test]
    fn every_printed_extension_routes_to_an_adapter() {
        let registry = AdapterRegistry::new();
        for entry in supported_languages() {
            for ext in &entry.extensions {
                assert!(
                    registry.get_by_extension(ext).is_some(),
                    "{} prints extension {ext:?} that routes to no adapter",
                    entry.language
                );
            }
        }
        assert!(
            registry
                .get_by_extension("kin-not-a-real-extension")
                .is_none(),
            "the routing probe must be able to answer no, or the assertions above \
             prove nothing"
        );
    }

    #[test]
    fn the_json_surface_carries_a_schema_and_a_count_that_match_the_list() {
        let languages = supported_languages();
        let payload = LanguagesJson {
            schema: "kin.languages.v1",
            count: languages.len(),
            languages,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(value["schema"], "kin.languages.v1");
        assert_eq!(
            value["count"].as_u64().unwrap() as usize,
            value["languages"].as_array().unwrap().len()
        );
        assert!(value["languages"][0]["language"].is_string());
        assert!(value["languages"][0]["extensions"].is_array());
    }
}
