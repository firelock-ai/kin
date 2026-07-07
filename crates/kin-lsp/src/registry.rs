// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Provider registry: which language server serves which language, how it is
//! discovered, which capabilities it serves, and the provenance every
//! LSP-derived relation carries.
//!
//! LSP enrichment is an addon over Kin's own parsers and linkers — never a
//! replacement. Relations discovered here are tagged [`RelationOrigin::Lsp`] and
//! additionally carry an [`LspProvenance`] (provider + version + capability) so
//! they are always distinguishable from tree-sitter / linker-derived edges.
//!
//! The registry is the contract the per-language enrichment lanes consume:
//! prefer the explicit types here over stringly configuration.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use kin_model::{LanguageId, Relation, RelationEvidence};
use serde::{Deserialize, Serialize};

use crate::discovery::detect_version;

/// A capability an LSP server can provide that Kin enrichment consumes. Each
/// variant maps to a concrete LSP request the enrichment pipeline issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LspCapability {
    /// `textDocument/definition`.
    Definition,
    /// `textDocument/typeDefinition`.
    TypeDefinition,
    /// `textDocument/references`.
    References,
    /// `textDocument/prepareCallHierarchy` + `callHierarchy/outgoingCalls`.
    CallHierarchy,
    /// `textDocument/prepareTypeHierarchy` + `typeHierarchy/supertypes`.
    TypeHierarchy,
}

impl LspCapability {
    /// Every capability Kin enrichment knows how to consume.
    pub const ALL: [LspCapability; 5] = [
        LspCapability::Definition,
        LspCapability::TypeDefinition,
        LspCapability::References,
        LspCapability::CallHierarchy,
        LspCapability::TypeHierarchy,
    ];

    /// The minimum capability floor a required language's live server must meet
    /// for a citable enrichment run: without go-to-definition and find-refs the
    /// pass produces effectively nothing, so a required server below this floor
    /// is a fail-loud gap rather than a degraded-but-acceptable run.
    pub const CITABLE_MINIMUM: [LspCapability; 2] =
        [LspCapability::Definition, LspCapability::References];

    /// Stable slug used in provenance encoding and proof records.
    pub fn as_slug(&self) -> &'static str {
        match self {
            LspCapability::Definition => "definition",
            LspCapability::TypeDefinition => "typeDefinition",
            LspCapability::References => "references",
            LspCapability::CallHierarchy => "callHierarchy",
            LspCapability::TypeHierarchy => "typeHierarchy",
        }
    }

    /// Parse a slug produced by [`LspCapability::as_slug`].
    pub fn from_slug(slug: &str) -> Option<Self> {
        LspCapability::ALL
            .into_iter()
            .find(|cap| cap.as_slug() == slug)
    }

    /// The primary LSP method this capability is exercised through.
    pub fn lsp_method(&self) -> &'static str {
        match self {
            LspCapability::Definition => "textDocument/definition",
            LspCapability::TypeDefinition => "textDocument/typeDefinition",
            LspCapability::References => "textDocument/references",
            LspCapability::CallHierarchy => "textDocument/prepareCallHierarchy",
            LspCapability::TypeHierarchy => "textDocument/prepareTypeHierarchy",
        }
    }
}

impl fmt::Display for LspCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_slug())
    }
}

/// A stable identifier for a language-server implementation (e.g.
/// `rust-analyzer`, `pyright`, `gopls`). Controlled slugs — safe to embed in
/// provenance without escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ProviderId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Static specification of a provider: the binaries to search on PATH, the args
/// to launch it with, and the capabilities Kin expects it to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSpec {
    pub id: ProviderId,
    pub language: LanguageId,
    /// Binary names to search on PATH, in preference order.
    pub binaries: Vec<String>,
    /// Launch arguments passed to whichever binary is found.
    pub args: Vec<String>,
    /// Capabilities this provider is expected to serve. The live handshake is
    /// the source of truth; this drives the expected-vs-probed diff recorded in
    /// the proof, not a hard gate on its own.
    pub expected_capabilities: BTreeSet<LspCapability>,
}

impl ProviderSpec {
    fn new(
        id: &str,
        language: LanguageId,
        binaries: &[&str],
        args: &[&str],
        capabilities: &[LspCapability],
    ) -> Self {
        Self {
            id: ProviderId::new(id),
            language,
            binaries: binaries.iter().map(|b| b.to_string()).collect(),
            args: args.iter().map(|a| a.to_string()).collect(),
            expected_capabilities: capabilities.iter().copied().collect(),
        }
    }
}

/// A provider resolved to a concrete binary present on this system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProvider {
    pub id: ProviderId,
    pub language: LanguageId,
    /// Absolute path to the discovered server binary.
    pub command: PathBuf,
    pub args: Vec<String>,
    /// Version string as reported by `--version`, when the probe succeeded.
    pub version: Option<String>,
    pub expected_capabilities: BTreeSet<LspCapability>,
}

/// A resolved provider paired with the capabilities its live server actually
/// reported during the initialize handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderProbe {
    pub resolved: ResolvedProvider,
    /// Capabilities the running server reported (from the LSP handshake).
    pub probed_capabilities: BTreeSet<LspCapability>,
}

impl ProviderProbe {
    /// Whether the live server serves a capability.
    pub fn serves(&self, capability: LspCapability) -> bool {
        self.probed_capabilities.contains(&capability)
    }

    /// Expected capabilities the live server did NOT report — informational
    /// drift between what Kin designed around and what this server/version
    /// actually offers.
    pub fn missing_expected(&self) -> BTreeSet<LspCapability> {
        self.resolved
            .expected_capabilities
            .difference(&self.probed_capabilities)
            .copied()
            .collect()
    }

    /// Citable-floor capabilities the live server did NOT report. A non-empty
    /// result for a required language is a fail-loud gap.
    pub fn missing_minimum(&self) -> BTreeSet<LspCapability> {
        LspCapability::CITABLE_MINIMUM
            .into_iter()
            .filter(|cap| !self.probed_capabilities.contains(cap))
            .collect()
    }

    /// Build provenance for a relation this provider produced via `capability`.
    pub fn provenance(&self, capability: LspCapability) -> LspProvenance {
        LspProvenance {
            provider: self.resolved.id.clone(),
            version: self.resolved.version.clone(),
            capability,
        }
    }
}

/// Why a provider could not be resolved for a language. A citable/proof run
/// must surface this as a reportable gap — never a silent skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderGap {
    pub language: LanguageId,
    pub reason: ProviderGapReason,
    /// The provider ids that were considered.
    pub tried: Vec<ProviderId>,
}

impl fmt::Display for ProviderGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no LSP provider available for {}: {}",
            self.language, self.reason
        )
    }
}

/// The specific reason a provider gap exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderGapReason {
    /// No provider is registered for the language at all.
    NoProviderRegistered,
    /// Providers are registered but none of their binaries were found on PATH.
    NoBinaryOnPath,
    /// A repo config named a provider id the registry does not know.
    UnknownConfiguredProvider(ProviderId),
}

impl fmt::Display for ProviderGapReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderGapReason::NoProviderRegistered => {
                f.write_str("no provider registered for this language")
            }
            ProviderGapReason::NoBinaryOnPath => {
                f.write_str("no registered server binary found on PATH")
            }
            ProviderGapReason::UnknownConfiguredProvider(id) => {
                write!(f, "configured provider '{id}' is not known to the registry")
            }
        }
    }
}

/// Abstraction over locating and version-probing binaries, so discovery is
/// unit-testable without depending on the host PATH or real servers.
pub trait BinaryFinder: Send + Sync {
    /// Absolute path to `binary` if it is on PATH.
    fn find_on_path(&self, binary: &str) -> Option<PathBuf>;
    /// Version string reported by the binary, if probing succeeds.
    fn probe_version(&self, path: &Path) -> Option<String>;
}

/// Production binary finder: `which` for PATH lookup + `--version` probe.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemBinaryFinder;

impl BinaryFinder for SystemBinaryFinder {
    fn find_on_path(&self, binary: &str) -> Option<PathBuf> {
        which::which(binary).ok()
    }

    fn probe_version(&self, path: &Path) -> Option<String> {
        detect_version(path)
    }
}

/// Repo-level override for provider selection. Deserialized from Kin repo
/// config (e.g. a `.kin/config.toml` `[lsp]` section) rather than environment
/// sprawl. Keys are language / provider slugs at the config boundary; they are
/// validated into the typed registry by [`ProviderRegistry::apply_config`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Force a specific provider id per language, overriding default order.
    /// Language slug (see [`language_from_slug`]) → provider id slug.
    #[serde(default)]
    pub providers: Vec<ProviderOverride>,
    /// Languages whose enrichment is REQUIRED. A gap for a required language is
    /// fail-loud in citable mode.
    #[serde(default)]
    pub required: Vec<String>,
    /// Languages whose enrichment is disabled entirely.
    #[serde(default)]
    pub disabled: Vec<String>,
}

/// A single per-language provider override entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderOverride {
    /// Language slug, e.g. `python` (see [`LanguageId`]'s `Display`).
    pub language: String,
    /// Provider id to prefer, e.g. `pylsp`.
    pub provider: String,
    /// Optional extra binary-name candidates, tried before the provider's
    /// built-in binary list.
    #[serde(default)]
    pub binaries: Vec<String>,
    /// Optional launch-arg override; when set, replaces the provider's default
    /// args (empty vec means "launch with no args").
    #[serde(default)]
    pub args: Option<Vec<String>>,
}

/// A repo config that could not be validated into the typed registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryConfigError {
    /// A config entry named a language slug that is not a known [`LanguageId`].
    UnknownLanguage(String),
    /// A `providers` entry named a provider id not registered for its language.
    UnknownProvider {
        language: LanguageId,
        provider: ProviderId,
    },
    /// A language appears in both `required` and `disabled`.
    RequiredAndDisabled(LanguageId),
}

impl fmt::Display for RegistryConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryConfigError::UnknownLanguage(slug) => {
                write!(f, "unknown language '{slug}' in [lsp] config")
            }
            RegistryConfigError::UnknownProvider { language, provider } => write!(
                f,
                "provider '{provider}' is not registered for language '{language}'"
            ),
            RegistryConfigError::RequiredAndDisabled(language) => write!(
                f,
                "language '{language}' is both required and disabled in [lsp] config"
            ),
        }
    }
}

impl std::error::Error for RegistryConfigError {}

/// Parse a language slug (the form produced by [`LanguageId`]'s `Display`) into
/// a typed [`LanguageId`].
pub fn language_from_slug(slug: &str) -> Option<LanguageId> {
    const ALL: [LanguageId; 14] = [
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
    let lowered = slug.to_ascii_lowercase();
    ALL.into_iter().find(|lang| lang.to_string() == lowered)
}

/// The registry of providers, plus the repo policy (required / disabled) layered
/// on top of the built-in defaults.
#[derive(Debug, Clone)]
pub struct ProviderRegistry {
    /// Ordered provider candidates per language (preference order).
    entries: Vec<(LanguageId, Vec<ProviderSpec>)>,
    required: Vec<LanguageId>,
    disabled: Vec<LanguageId>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl ProviderRegistry {
    /// A registry seeded with Kin's built-in provider defaults and no policy.
    pub fn with_defaults() -> Self {
        use LanguageId::*;
        use LspCapability::*;

        let entries = vec![
            (
                Rust,
                vec![ProviderSpec::new(
                    "rust-analyzer",
                    Rust,
                    &["rust-analyzer"],
                    &[],
                    &[
                        Definition,
                        TypeDefinition,
                        References,
                        CallHierarchy,
                        TypeHierarchy,
                    ],
                )],
            ),
            (
                Python,
                vec![
                    ProviderSpec::new(
                        "pyright",
                        Python,
                        &["pyright-langserver"],
                        &["--stdio"],
                        &[Definition, TypeDefinition, References, CallHierarchy],
                    ),
                    ProviderSpec::new("pylsp", Python, &["pylsp"], &[], &[Definition, References]),
                ],
            ),
            (
                TypeScript,
                vec![
                    ProviderSpec::new(
                        "typescript-language-server",
                        TypeScript,
                        &["typescript-language-server"],
                        &["--stdio"],
                        &[Definition, TypeDefinition, References, CallHierarchy],
                    ),
                    ProviderSpec::new(
                        "vtsls",
                        TypeScript,
                        &["vtsls"],
                        &["--stdio"],
                        &[Definition, TypeDefinition, References, CallHierarchy],
                    ),
                ],
            ),
            (
                JavaScript,
                vec![ProviderSpec::new(
                    "typescript-language-server",
                    JavaScript,
                    &["typescript-language-server"],
                    &["--stdio"],
                    &[Definition, TypeDefinition, References, CallHierarchy],
                )],
            ),
            (
                Go,
                vec![ProviderSpec::new(
                    "gopls",
                    Go,
                    &["gopls"],
                    &["serve"],
                    &[Definition, TypeDefinition, References, CallHierarchy],
                )],
            ),
            (
                Java,
                vec![ProviderSpec::new(
                    "jdtls",
                    Java,
                    &["jdtls"],
                    &[],
                    &[
                        Definition,
                        TypeDefinition,
                        References,
                        CallHierarchy,
                        TypeHierarchy,
                    ],
                )],
            ),
            (
                C,
                vec![ProviderSpec::new(
                    "clangd",
                    C,
                    &["clangd"],
                    &[],
                    &[
                        Definition,
                        TypeDefinition,
                        References,
                        CallHierarchy,
                        TypeHierarchy,
                    ],
                )],
            ),
            (
                Cpp,
                vec![ProviderSpec::new(
                    "clangd",
                    Cpp,
                    &["clangd"],
                    &[],
                    &[
                        Definition,
                        TypeDefinition,
                        References,
                        CallHierarchy,
                        TypeHierarchy,
                    ],
                )],
            ),
        ];

        Self {
            entries,
            required: Vec::new(),
            disabled: Vec::new(),
        }
    }

    /// A registry seeded with defaults and the given repo config applied.
    pub fn from_config(config: &RegistryConfig) -> Result<Self, RegistryConfigError> {
        let mut registry = Self::with_defaults();
        registry.apply_config(config)?;
        Ok(registry)
    }

    /// Layer a repo config over the defaults, validating every slug into typed
    /// form. Fail-loud: unknown language/provider names and required∧disabled
    /// contradictions are hard errors rather than silently ignored config.
    pub fn apply_config(&mut self, config: &RegistryConfig) -> Result<(), RegistryConfigError> {
        // Provider overrides: reorder / re-arg the candidate list per language.
        for over in &config.providers {
            let language = language_from_slug(&over.language)
                .ok_or_else(|| RegistryConfigError::UnknownLanguage(over.language.clone()))?;
            let provider = ProviderId::new(over.provider.clone());
            let candidates = self
                .entries
                .iter_mut()
                .find(|(lang, _)| *lang == language)
                .map(|(_, specs)| specs)
                .ok_or_else(|| RegistryConfigError::UnknownProvider {
                    language,
                    provider: provider.clone(),
                })?;
            let idx = candidates
                .iter()
                .position(|spec| spec.id == provider)
                .ok_or_else(|| RegistryConfigError::UnknownProvider {
                    language,
                    provider: provider.clone(),
                })?;
            // Move the chosen provider to the front and apply arg/binary overrides.
            let mut chosen = candidates.remove(idx);
            if !over.binaries.is_empty() {
                let mut merged = over.binaries.clone();
                merged.extend(chosen.binaries.iter().cloned());
                chosen.binaries = merged;
            }
            if let Some(args) = &over.args {
                chosen.args = args.clone();
            }
            candidates.insert(0, chosen);
        }

        for slug in &config.required {
            let language = language_from_slug(slug)
                .ok_or_else(|| RegistryConfigError::UnknownLanguage(slug.clone()))?;
            if !self.required.contains(&language) {
                self.required.push(language);
            }
        }
        for slug in &config.disabled {
            let language = language_from_slug(slug)
                .ok_or_else(|| RegistryConfigError::UnknownLanguage(slug.clone()))?;
            if !self.disabled.contains(&language) {
                self.disabled.push(language);
            }
        }
        if let Some(language) = self
            .required
            .iter()
            .find(|lang| self.disabled.contains(lang))
        {
            return Err(RegistryConfigError::RequiredAndDisabled(*language));
        }
        Ok(())
    }

    /// Ordered provider candidates for a language (after overrides), or empty.
    pub fn candidates(&self, language: LanguageId) -> &[ProviderSpec] {
        self.entries
            .iter()
            .find(|(lang, _)| *lang == language)
            .map(|(_, specs)| specs.as_slice())
            .unwrap_or(&[])
    }

    pub fn is_disabled(&self, language: LanguageId) -> bool {
        self.disabled.contains(&language)
    }

    pub fn is_required(&self, language: LanguageId) -> bool {
        self.required.contains(&language)
    }

    /// Languages the repo config marked as required for citable enrichment.
    pub fn required_languages(&self) -> &[LanguageId] {
        &self.required
    }

    /// Resolve the first candidate whose binary is on PATH, using the system
    /// PATH + version probe.
    pub fn resolve(&self, language: LanguageId) -> Result<ResolvedProvider, ProviderGap> {
        self.resolve_with(language, &SystemBinaryFinder)
    }

    /// Resolve using an injected [`BinaryFinder`] (unit-testable, no real PATH).
    pub fn resolve_with(
        &self,
        language: LanguageId,
        finder: &dyn BinaryFinder,
    ) -> Result<ResolvedProvider, ProviderGap> {
        let candidates = self.candidates(language);
        if candidates.is_empty() {
            return Err(ProviderGap {
                language,
                reason: ProviderGapReason::NoProviderRegistered,
                tried: Vec::new(),
            });
        }

        let tried: Vec<ProviderId> = candidates.iter().map(|spec| spec.id.clone()).collect();
        for spec in candidates {
            for binary in &spec.binaries {
                if let Some(command) = finder.find_on_path(binary) {
                    let version = finder.probe_version(&command);
                    return Ok(ResolvedProvider {
                        id: spec.id.clone(),
                        language,
                        command,
                        args: spec.args.clone(),
                        version,
                        expected_capabilities: spec.expected_capabilities.clone(),
                    });
                }
            }
        }

        Err(ProviderGap {
            language,
            reason: ProviderGapReason::NoBinaryOnPath,
            tried,
        })
    }
}

/// Provenance carried by every LSP-derived relation: which provider, at which
/// version, via which capability produced the edge. This is the LSP-specific
/// detail beneath the coarse [`RelationOrigin::Lsp`] tag; it distinguishes an
/// LSP relation from a tree-sitter / linker one and names the exact server that
/// vouches for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LspProvenance {
    pub provider: ProviderId,
    pub version: Option<String>,
    pub capability: LspCapability,
}

/// Marker prefix identifying an [`RelationEvidence`] as LSP provenance. Versioned
/// so the encoding can evolve without ambiguity.
const LSP_EVIDENCE_TAG: &str = "lsp/1";

impl LspProvenance {
    /// Encode this provenance into a kin-model [`RelationEvidence`] so it
    /// persists through the existing evidence field with no kin-model schema
    /// change. `parser_rule` carries the controlled-slug structured tag; the
    /// free-form version string rides in `token`. Replay / reconcile can
    /// round-trip it via [`LspProvenance::from_relation_evidence`].
    pub fn to_relation_evidence(&self) -> RelationEvidence {
        RelationEvidence {
            parser_rule: Some(format!(
                "{LSP_EVIDENCE_TAG};provider={};capability={}",
                self.provider.as_str(),
                self.capability.as_slug()
            )),
            token: self.version.clone(),
            ..RelationEvidence::default()
        }
    }

    /// Decode provenance previously written by [`to_relation_evidence`]. Returns
    /// `None` for evidence that is not LSP provenance (e.g. parser/linker
    /// evidence), so it is safe to call on any relation's evidence.
    pub fn from_relation_evidence(evidence: &RelationEvidence) -> Option<Self> {
        let rule = evidence.parser_rule.as_deref()?;
        let mut parts = rule.split(';');
        if parts.next()? != LSP_EVIDENCE_TAG {
            return None;
        }
        let mut provider = None;
        let mut capability = None;
        for part in parts {
            let (key, value) = part.split_once('=')?;
            match key {
                "provider" => provider = Some(ProviderId::new(value)),
                "capability" => capability = LspCapability::from_slug(value),
                _ => {}
            }
        }
        Some(Self {
            provider: provider?,
            version: evidence.token.clone(),
            capability: capability?,
        })
    }

    /// Whether an evidence record is LSP provenance (cheap prefix check).
    pub fn is_lsp_evidence(evidence: &RelationEvidence) -> bool {
        evidence
            .parser_rule
            .as_deref()
            .is_some_and(|rule| rule.starts_with(LSP_EVIDENCE_TAG))
    }
}

/// Stamp LSP provenance onto a batch of relations produced by one capability.
///
/// Each enrichment entry point emits relations for exactly one capability, so
/// the caller — which knows the running provider and the capability it just
/// exercised — attaches provenance here without the enrichment functions
/// needing to know the provider identity. Evidence is appended (never
/// replacing existing evidence), keeping the operation additive.
pub fn stamp_lsp_provenance(relations: &mut [Relation], provenance: &LspProvenance) {
    let evidence = provenance.to_relation_evidence();
    for relation in relations.iter_mut() {
        relation.evidence.push(evidence.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Fake finder mapping binary name → (path, version) with no host PATH.
    #[derive(Default)]
    struct FakeFinder {
        present: HashMap<String, (PathBuf, Option<String>)>,
    }

    impl FakeFinder {
        fn with(mut self, binary: &str, path: &str, version: Option<&str>) -> Self {
            self.present.insert(
                binary.to_string(),
                (PathBuf::from(path), version.map(|v| v.to_string())),
            );
            self
        }
    }

    impl BinaryFinder for FakeFinder {
        fn find_on_path(&self, binary: &str) -> Option<PathBuf> {
            self.present.get(binary).map(|(path, _)| path.clone())
        }
        fn probe_version(&self, path: &Path) -> Option<String> {
            self.present
                .values()
                .find(|(p, _)| p == path)
                .and_then(|(_, v)| v.clone())
        }
    }

    #[test]
    fn defaults_register_first_class_languages() {
        let registry = ProviderRegistry::with_defaults();
        assert_eq!(
            registry.candidates(LanguageId::Rust)[0].id.as_str(),
            "rust-analyzer"
        );
        assert_eq!(
            registry.candidates(LanguageId::Python)[0].id.as_str(),
            "pyright"
        );
        assert_eq!(
            registry.candidates(LanguageId::Python)[1].id.as_str(),
            "pylsp"
        );
        assert!(!registry.candidates(LanguageId::Go).is_empty());
        assert!(!registry.candidates(LanguageId::Cpp).is_empty());
        // A language with no LSP provider registered resolves to nothing.
        assert!(registry.candidates(LanguageId::Ruby).is_empty());
    }

    #[test]
    fn resolve_picks_first_binary_on_path_and_probes_version() {
        let registry = ProviderRegistry::with_defaults();
        let finder = FakeFinder::default().with(
            "rust-analyzer",
            "/usr/bin/rust-analyzer",
            Some("rust-analyzer 1.79.0"),
        );
        let resolved = registry.resolve_with(LanguageId::Rust, &finder).unwrap();
        assert_eq!(resolved.id.as_str(), "rust-analyzer");
        assert_eq!(resolved.command, PathBuf::from("/usr/bin/rust-analyzer"));
        assert_eq!(resolved.version.as_deref(), Some("rust-analyzer 1.79.0"));
    }

    #[test]
    fn resolve_falls_through_to_second_candidate() {
        let registry = ProviderRegistry::with_defaults();
        // pyright absent, pylsp present → resolves pylsp.
        let finder = FakeFinder::default().with("pylsp", "/usr/bin/pylsp", None);
        let resolved = registry.resolve_with(LanguageId::Python, &finder).unwrap();
        assert_eq!(resolved.id.as_str(), "pylsp");
    }

    #[test]
    fn resolve_missing_binary_is_a_fail_loud_gap() {
        let registry = ProviderRegistry::with_defaults();
        let finder = FakeFinder::default();
        let gap = registry
            .resolve_with(LanguageId::Rust, &finder)
            .unwrap_err();
        assert_eq!(gap.reason, ProviderGapReason::NoBinaryOnPath);
        assert_eq!(gap.tried, vec![ProviderId::new("rust-analyzer")]);
    }

    #[test]
    fn resolve_unregistered_language_reports_no_provider() {
        let registry = ProviderRegistry::with_defaults();
        let finder = FakeFinder::default();
        let gap = registry
            .resolve_with(LanguageId::Ruby, &finder)
            .unwrap_err();
        assert_eq!(gap.reason, ProviderGapReason::NoProviderRegistered);
    }

    #[test]
    fn config_override_reorders_provider_preference() {
        let config = RegistryConfig {
            providers: vec![ProviderOverride {
                language: "python".to_string(),
                provider: "pylsp".to_string(),
                binaries: vec![],
                args: None,
            }],
            required: vec![],
            disabled: vec![],
        };
        let registry = ProviderRegistry::from_config(&config).unwrap();
        // pylsp is now the first candidate, even though pyright is the default.
        assert_eq!(
            registry.candidates(LanguageId::Python)[0].id.as_str(),
            "pylsp"
        );
    }

    #[test]
    fn config_override_applies_binary_and_arg_overrides() {
        let config = RegistryConfig {
            providers: vec![ProviderOverride {
                language: "rust".to_string(),
                provider: "rust-analyzer".to_string(),
                binaries: vec!["/opt/ra/rust-analyzer".to_string()],
                args: Some(vec!["--log-file".to_string(), "/tmp/ra.log".to_string()]),
            }],
            required: vec![],
            disabled: vec![],
        };
        let registry = ProviderRegistry::from_config(&config).unwrap();
        let spec = &registry.candidates(LanguageId::Rust)[0];
        assert_eq!(spec.binaries[0], "/opt/ra/rust-analyzer");
        assert_eq!(spec.args, vec!["--log-file", "/tmp/ra.log"]);
    }

    #[test]
    fn config_unknown_language_is_fail_loud() {
        let config = RegistryConfig {
            providers: vec![],
            required: vec!["cobol".to_string()],
            disabled: vec![],
        };
        let err = ProviderRegistry::from_config(&config).unwrap_err();
        assert_eq!(
            err,
            RegistryConfigError::UnknownLanguage("cobol".to_string())
        );
    }

    #[test]
    fn config_unknown_provider_is_fail_loud() {
        let config = RegistryConfig {
            providers: vec![ProviderOverride {
                language: "rust".to_string(),
                provider: "not-a-server".to_string(),
                binaries: vec![],
                args: None,
            }],
            required: vec![],
            disabled: vec![],
        };
        let err = ProviderRegistry::from_config(&config).unwrap_err();
        assert_eq!(
            err,
            RegistryConfigError::UnknownProvider {
                language: LanguageId::Rust,
                provider: ProviderId::new("not-a-server"),
            }
        );
    }

    #[test]
    fn config_required_and_disabled_conflict_is_fail_loud() {
        let config = RegistryConfig {
            providers: vec![],
            required: vec!["rust".to_string()],
            disabled: vec!["rust".to_string()],
        };
        let err = ProviderRegistry::from_config(&config).unwrap_err();
        assert_eq!(
            err,
            RegistryConfigError::RequiredAndDisabled(LanguageId::Rust)
        );
    }

    #[test]
    fn required_and_disabled_flags_round_trip() {
        let config = RegistryConfig {
            providers: vec![],
            required: vec!["rust".to_string(), "python".to_string()],
            disabled: vec!["go".to_string()],
        };
        let registry = ProviderRegistry::from_config(&config).unwrap();
        assert!(registry.is_required(LanguageId::Rust));
        assert!(registry.is_required(LanguageId::Python));
        assert!(!registry.is_required(LanguageId::Go));
        assert!(registry.is_disabled(LanguageId::Go));
        assert_eq!(registry.required_languages().len(), 2);
    }

    #[test]
    fn probe_reports_missing_expected_and_minimum() {
        let registry = ProviderRegistry::with_defaults();
        let finder = FakeFinder::default().with("rust-analyzer", "/usr/bin/rust-analyzer", None);
        let resolved = registry.resolve_with(LanguageId::Rust, &finder).unwrap();
        // Live server reports only definition + references (missing the rest).
        let probe = ProviderProbe {
            resolved,
            probed_capabilities: [LspCapability::Definition, LspCapability::References]
                .into_iter()
                .collect(),
        };
        assert!(probe.serves(LspCapability::Definition));
        assert!(!probe.serves(LspCapability::CallHierarchy));
        // Minimum floor met → no fail-loud gap.
        assert!(probe.missing_minimum().is_empty());
        // But the expected-vs-probed drift is recorded.
        assert!(probe
            .missing_expected()
            .contains(&LspCapability::CallHierarchy));
        assert!(probe
            .missing_expected()
            .contains(&LspCapability::TypeHierarchy));
    }

    #[test]
    fn probe_below_minimum_is_detectable() {
        let registry = ProviderRegistry::with_defaults();
        let finder = FakeFinder::default().with("rust-analyzer", "/usr/bin/rust-analyzer", None);
        let resolved = registry.resolve_with(LanguageId::Rust, &finder).unwrap();
        // A server that serves neither definition nor references.
        let probe = ProviderProbe {
            resolved,
            probed_capabilities: BTreeSet::new(),
        };
        let missing = probe.missing_minimum();
        assert!(missing.contains(&LspCapability::Definition));
        assert!(missing.contains(&LspCapability::References));
    }

    #[test]
    fn provenance_round_trips_through_relation_evidence() {
        let prov = LspProvenance {
            provider: ProviderId::new("rust-analyzer"),
            version: Some("rust-analyzer 1.79.0 (abcdef 2026-01-01)".to_string()),
            capability: LspCapability::CallHierarchy,
        };
        let evidence = prov.to_relation_evidence();
        assert!(LspProvenance::is_lsp_evidence(&evidence));
        let decoded = LspProvenance::from_relation_evidence(&evidence).unwrap();
        assert_eq!(decoded, prov);
    }

    #[test]
    fn provenance_round_trips_without_version() {
        let prov = LspProvenance {
            provider: ProviderId::new("pyright"),
            version: None,
            capability: LspCapability::References,
        };
        let evidence = prov.to_relation_evidence();
        let decoded = LspProvenance::from_relation_evidence(&evidence).unwrap();
        assert_eq!(decoded, prov);
    }

    #[test]
    fn non_lsp_evidence_decodes_to_none() {
        let parser_evidence = RelationEvidence {
            parser_rule: Some("include_directive".to_string()),
            token: Some("#include \"app.hpp\"".to_string()),
            ..RelationEvidence::default()
        };
        assert!(!LspProvenance::is_lsp_evidence(&parser_evidence));
        assert!(LspProvenance::from_relation_evidence(&parser_evidence).is_none());
        // Fully-empty evidence is also safely ignored.
        assert!(LspProvenance::from_relation_evidence(&RelationEvidence::default()).is_none());
    }

    #[test]
    fn capability_slug_round_trips() {
        for cap in LspCapability::ALL {
            assert_eq!(LspCapability::from_slug(cap.as_slug()), Some(cap));
        }
        assert_eq!(LspCapability::from_slug("bogus"), None);
    }
}
