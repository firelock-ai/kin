// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical, persistence-neutral repository admission primitives.
//!
//! The durable repository authority resolves graph-owned shared policy and a
//! frozen local overlay into these types. Callers may use the matcher for
//! previews, but only `RepositoryAuthorityManager` can turn a decision into
//! persisted authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use bstr::{BString, ByteSlice};
pub use kin_model::AdmissionCase;
use kin_model::{Hash256, RepoPath, SensitiveArtifactAllowance, SensitiveArtifactKind};
use sha2::{Digest, Sha256};
use thiserror::Error;

fn gix_case(case: AdmissionCase) -> gix_ignore::glob::pattern::Case {
    match case {
        AdmissionCase::Sensitive => gix_ignore::glob::pattern::Case::Sensitive,
        AdmissionCase::FoldAscii => gix_ignore::glob::pattern::Case::Fold,
    }
}

/// Provenance tier for one resolved rule set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdmissionRuleSource {
    GlobalExclude,
    InfoExclude,
    Shared { source_path: RepoPath },
    KinLocal { ordinal: u32 },
    CommandLine { ordinal: u32 },
}

impl AdmissionRuleSource {
    fn synthetic_path(&self) -> Result<PathBuf, AdmissionMatcherError> {
        match self {
            Self::GlobalExclude => Ok(PathBuf::from(".kin-admission/global-excludes")),
            Self::InfoExclude => Ok(PathBuf::from(".kin-admission/info-exclude")),
            Self::Shared { source_path } => repo_path_to_host_path(source_path),
            Self::KinLocal { ordinal } => {
                Ok(PathBuf::from(format!(".kin-admission/kin-local-{ordinal}")))
            }
            Self::CommandLine { ordinal } => Ok(PathBuf::from(format!(
                ".kin-admission/command-line-{ordinal}"
            ))),
        }
    }
}

/// One byte-exact rule source loaded from repository-owned immutable CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAdmissionRuleSet {
    pub source: AdmissionRuleSource,
    pub precedence: u32,
    pub base_directory: Option<RepoPath>,
    pub content_hash: Hash256,
    pub content_len: u64,
    pub contents: Vec<u8>,
}

impl ResolvedAdmissionRuleSet {
    pub fn new(
        source: AdmissionRuleSource,
        precedence: u32,
        base_directory: Option<RepoPath>,
        content_hash: Hash256,
        content_len: u64,
        contents: Vec<u8>,
    ) -> Self {
        Self {
            source,
            precedence,
            base_directory,
            content_hash,
            content_len,
            contents,
        }
    }

    pub fn from_bytes(
        source: AdmissionRuleSource,
        precedence: u32,
        base_directory: Option<RepoPath>,
        contents: impl Into<Vec<u8>>,
    ) -> Self {
        let contents = contents.into();
        let content_hash = sha256(&contents);
        let content_len = contents.len() as u64;
        Self::new(
            source,
            precedence,
            base_directory,
            content_hash,
            content_len,
            contents,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRuleProvenance {
    pub source: AdmissionRuleSource,
    pub line: usize,
    pub pattern: Vec<u8>,
    pub negated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecisionReason {
    NoMatchingRule,
    TrackedArtifact,
    IntrinsicControl,
    Rule(AdmissionRuleProvenance),
    IgnoredAncestor {
        ancestor: RepoPath,
        rule: AdmissionRuleProvenance,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDecision {
    pub admitted: bool,
    pub reason: AdmissionDecisionReason,
}

impl AdmissionDecision {
    pub const fn is_ignored(&self) -> bool {
        !self.admitted
    }
}

#[derive(Debug, Error)]
pub enum AdmissionMatcherError {
    #[error(
        "admission rule bytes do not match declared content hash for source {rule_source:?}: declared {declared}, observed {observed}"
    )]
    ContentHashMismatch {
        rule_source: AdmissionRuleSource,
        declared: Hash256,
        observed: Hash256,
    },
    #[error(
        "admission rule bytes do not match declared length for source {rule_source:?}: declared {declared}, observed {observed}"
    )]
    ContentLengthMismatch {
        rule_source: AdmissionRuleSource,
        declared: u64,
        observed: u64,
    },
    #[error(
        "resolved admission precedence must be contiguous from zero: expected {expected}, observed {observed}"
    )]
    NonContiguousPrecedence { expected: u32, observed: u32 },
    #[error("resolved admission policy contains more than u32::MAX rule sets")]
    TooManyRuleSets,
    #[error("admission policy contains duplicate singleton source {0:?}")]
    DuplicateSingletonSource(AdmissionRuleSource),
    #[error("admission policy contains more than one shared rule set at {0}")]
    DuplicateSharedSource(RepoPath),
    #[error("admission policy contains more than one Kin-local rule set at ordinal {0}")]
    DuplicateKinLocalOrdinal(u32),
    #[error("admission policy contains more than one command-line rule set at ordinal {0}")]
    DuplicateCommandLineOrdinal(u32),
    #[error("repository-root admission source {0:?} cannot declare a base directory")]
    UnexpectedBaseDirectory(AdmissionRuleSource),
    #[error(
        "admission rule sources {first_source:?} and {second_source:?} map to the same matcher path"
    )]
    SourcePathCollision {
        first_source: AdmissionRuleSource,
        second_source: AdmissionRuleSource,
    },
    #[error("repository path cannot be represented by gitwildmatch on this host: {0}")]
    UnrepresentablePath(RepoPath),
}

/// A compiled, immutable admission-policy generation.
#[derive(Debug, Clone)]
pub struct ResolvedAdmissionMatcher {
    search: gix_ignore::Search,
    sources: BTreeMap<PathBuf, AdmissionRuleSource>,
    case: AdmissionCase,
    generation: Hash256,
}

impl ResolvedAdmissionMatcher {
    pub fn compile(
        case: AdmissionCase,
        mut rule_sets: Vec<ResolvedAdmissionRuleSet>,
    ) -> Result<Self, AdmissionMatcherError> {
        rule_sets.sort_by_key(|rule_set| rule_set.precedence);
        validate_rule_sets(&rule_sets)?;

        let mut search = gix_ignore::Search::default();
        let mut sources = BTreeMap::<PathBuf, AdmissionRuleSource>::new();
        let mut generation = Sha256::new();
        generation.update(b"kin-resolved-admission-policy-v1\0");
        generation.update(match case {
            AdmissionCase::Sensitive => b"sensitive".as_slice(),
            AdmissionCase::FoldAscii => b"fold-ascii".as_slice(),
        });

        for rule_set in &rule_sets {
            let source_path = rule_set.source.synthetic_path()?;
            if let Some(first_source) = sources.get(&source_path) {
                return Err(AdmissionMatcherError::SourcePathCollision {
                    first_source: first_source.clone(),
                    second_source: rule_set.source.clone(),
                });
            }
            let mut patterns = gix_ignore::glob::search::pattern::List::from_bytes(
                &rule_set.contents,
                source_path.clone(),
                None,
                gix_ignore::search::Ignore::default(),
            );
            patterns.base = matcher_base(rule_set.base_directory.as_ref());
            search.patterns.push(patterns);
            sources.insert(source_path, rule_set.source.clone());
            append_generation_source(&mut generation, rule_set);
        }

        Ok(Self {
            search,
            sources,
            case,
            generation: finish_hash(generation),
        })
    }

    pub fn empty(case: AdmissionCase) -> Self {
        Self::compile(case, Vec::new()).expect("empty policy is valid")
    }

    pub const fn generation(&self) -> Hash256 {
        self.generation
    }

    pub fn decide(&self, path: &RepoPath, is_dir: bool, tracked: bool) -> AdmissionDecision {
        if is_intrinsic_repository_control_path(path) {
            return AdmissionDecision {
                admitted: false,
                reason: AdmissionDecisionReason::IntrinsicControl,
            };
        }
        if tracked {
            return AdmissionDecision {
                admitted: true,
                reason: AdmissionDecisionReason::TrackedArtifact,
            };
        }

        for ancestor in ancestors(path) {
            if let Some(rule) = self.match_rule(&ancestor, true) {
                if !rule.negated {
                    return AdmissionDecision {
                        admitted: false,
                        reason: AdmissionDecisionReason::IgnoredAncestor { ancestor, rule },
                    };
                }
            }
        }

        match self.match_rule(path, is_dir) {
            Some(rule) if !rule.negated => AdmissionDecision {
                admitted: false,
                reason: AdmissionDecisionReason::Rule(rule),
            },
            Some(rule) => AdmissionDecision {
                admitted: true,
                reason: AdmissionDecisionReason::Rule(rule),
            },
            None => AdmissionDecision {
                admitted: true,
                reason: AdmissionDecisionReason::NoMatchingRule,
            },
        }
    }

    fn match_rule(&self, path: &RepoPath, is_dir: bool) -> Option<AdmissionRuleProvenance> {
        let matched = self.search.pattern_matching_relative_path(
            path.as_bytes().as_bstr(),
            Some(is_dir),
            gix_case(self.case),
        )?;
        let source_path = matched.source?;
        let source = self.sources.get(source_path)?.clone();
        Some(AdmissionRuleProvenance {
            source,
            line: matched.sequence_number,
            pattern: matched.pattern.text.to_vec(),
            negated: matched.pattern.is_negative(),
        })
    }
}

fn validate_rule_sets(rule_sets: &[ResolvedAdmissionRuleSet]) -> Result<(), AdmissionMatcherError> {
    let mut singleton_sources = BTreeSet::new();
    let mut shared_sources = BTreeSet::new();
    let mut kin_local_ordinals = BTreeSet::new();
    let mut command_line_ordinals = BTreeSet::new();

    for (index, rule_set) in rule_sets.iter().enumerate() {
        let expected = u32::try_from(index).map_err(|_| AdmissionMatcherError::TooManyRuleSets)?;
        if rule_set.precedence != expected {
            return Err(AdmissionMatcherError::NonContiguousPrecedence {
                expected,
                observed: rule_set.precedence,
            });
        }
        let observed_len = rule_set.contents.len() as u64;
        if observed_len != rule_set.content_len {
            return Err(AdmissionMatcherError::ContentLengthMismatch {
                rule_source: rule_set.source.clone(),
                declared: rule_set.content_len,
                observed: observed_len,
            });
        }
        let observed = sha256(&rule_set.contents);
        if observed != rule_set.content_hash {
            return Err(AdmissionMatcherError::ContentHashMismatch {
                rule_source: rule_set.source.clone(),
                declared: rule_set.content_hash,
                observed,
            });
        }

        match &rule_set.source {
            AdmissionRuleSource::GlobalExclude | AdmissionRuleSource::InfoExclude => {
                if rule_set.base_directory.is_some() {
                    return Err(AdmissionMatcherError::UnexpectedBaseDirectory(
                        rule_set.source.clone(),
                    ));
                }
                if !singleton_sources.insert(rule_set.source.clone()) {
                    return Err(AdmissionMatcherError::DuplicateSingletonSource(
                        rule_set.source.clone(),
                    ));
                }
            }
            AdmissionRuleSource::Shared { source_path } => {
                if !shared_sources.insert(source_path.clone()) {
                    return Err(AdmissionMatcherError::DuplicateSharedSource(
                        source_path.clone(),
                    ));
                }
            }
            AdmissionRuleSource::KinLocal { ordinal } => {
                if rule_set.base_directory.is_some() {
                    return Err(AdmissionMatcherError::UnexpectedBaseDirectory(
                        rule_set.source.clone(),
                    ));
                }
                if !kin_local_ordinals.insert(*ordinal) {
                    return Err(AdmissionMatcherError::DuplicateKinLocalOrdinal(*ordinal));
                }
            }
            AdmissionRuleSource::CommandLine { ordinal } => {
                if rule_set.base_directory.is_some() {
                    return Err(AdmissionMatcherError::UnexpectedBaseDirectory(
                        rule_set.source.clone(),
                    ));
                }
                if !command_line_ordinals.insert(*ordinal) {
                    return Err(AdmissionMatcherError::DuplicateCommandLineOrdinal(*ordinal));
                }
            }
        }
    }
    Ok(())
}

fn append_generation_source(hasher: &mut Sha256, rule_set: &ResolvedAdmissionRuleSet) {
    hasher.update(rule_set.precedence.to_le_bytes());
    match &rule_set.source {
        AdmissionRuleSource::GlobalExclude => hasher.update(b"global\0"),
        AdmissionRuleSource::InfoExclude => hasher.update(b"info\0"),
        AdmissionRuleSource::Shared { source_path } => {
            hasher.update(b"shared\0");
            append_len_prefixed(hasher, source_path.as_bytes());
        }
        AdmissionRuleSource::KinLocal { ordinal } => {
            hasher.update(b"kin-local\0");
            hasher.update(ordinal.to_le_bytes());
        }
        AdmissionRuleSource::CommandLine { ordinal } => {
            hasher.update(b"command\0");
            hasher.update(ordinal.to_le_bytes());
        }
    }
    match &rule_set.base_directory {
        Some(base_directory) => {
            hasher.update(b"base\0");
            append_len_prefixed(hasher, base_directory.as_bytes());
        }
        None => hasher.update(b"root\0"),
    }
    hasher.update(rule_set.content_len.to_le_bytes());
    hasher.update(rule_set.content_hash.0);
}

fn append_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn finish_hash(hasher: Sha256) -> Hash256 {
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Hash256::from_bytes(bytes)
}

fn sha256(bytes: &[u8]) -> Hash256 {
    let digest = Sha256::digest(bytes);
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&digest);
    Hash256::from_bytes(hash)
}

fn repo_path_to_host_path(path: &RepoPath) -> Result<PathBuf, AdmissionMatcherError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(std::ffi::OsString::from_vec(
            path.as_bytes().to_vec(),
        )))
    }
    #[cfg(not(unix))]
    {
        path.as_utf8()
            .map(|value| PathBuf::from(value.replace('/', std::path::MAIN_SEPARATOR_STR)))
            .ok_or_else(|| AdmissionMatcherError::UnrepresentablePath(path.clone()))
    }
}

fn matcher_base(path: Option<&RepoPath>) -> Option<BString> {
    path.map(|path| {
        let mut base = path.as_bytes().to_vec();
        base.push(b'/');
        BString::from(base)
    })
}

fn ancestors(path: &RepoPath) -> impl Iterator<Item = RepoPath> + '_ {
    path.as_bytes()
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .filter_map(|(index, _)| RepoPath::from_bytes(path.as_bytes()[..index].to_vec()).ok())
}

fn is_intrinsic_repository_control_component(component: &[u8]) -> bool {
    component.eq_ignore_ascii_case(b".kin")
        || component.eq_ignore_ascii_case(b".git")
        || component.eq_ignore_ascii_case(b".git-export")
        || component.eq_ignore_ascii_case(b".kin-session")
        || component.eq_ignore_ascii_case(b".kin-session.json")
        || component.eq_ignore_ascii_case(b".kin-shadow")
        || component
            .get(..b".kin-reconcile-".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b".kin-reconcile-"))
        || component
            .get(..b".kin-checkout-".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b".kin-checkout-"))
}

pub fn is_intrinsic_repository_control_path(path: &RepoPath) -> bool {
    path.as_bytes()
        .split(|byte| *byte == b'/')
        .any(is_intrinsic_repository_control_component)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveFindingKind {
    SensitivePath,
    PrivateKey,
    CloudCredential,
    CredentialAssignment,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SensitiveAdmissionError {
    #[error(
        "candidate bytes for {path} do not match the scan digest: declared {declared}, observed {observed}"
    )]
    DigestMismatch {
        path: RepoPath,
        declared: Hash256,
        observed: Hash256,
    },
    #[error(
        "untracked sensitive content at {path} is blocked before authority publication ({finding:?}); approve this exact path, digest, and entry kind explicitly"
    )]
    Blocked {
        path: RepoPath,
        content_hash: Hash256,
        kind: SensitiveArtifactKind,
        finding: SensitiveFindingKind,
    },
}

pub fn enforce_sensitive_admission(
    path: &RepoPath,
    content_hash: Hash256,
    kind: SensitiveArtifactKind,
    contents: &[u8],
    tracked: bool,
    allowances: &[SensitiveArtifactAllowance],
) -> Result<(), SensitiveAdmissionError> {
    let observed = sha256(contents);
    if observed != content_hash {
        return Err(SensitiveAdmissionError::DigestMismatch {
            path: path.clone(),
            declared: content_hash,
            observed,
        });
    }
    if tracked {
        return Ok(());
    }
    let Some(finding) = sensitive_finding(path, contents) else {
        return Ok(());
    };
    if allowances
        .iter()
        .any(|allowance| allowance.matches(path, content_hash, kind))
    {
        return Ok(());
    }
    Err(SensitiveAdmissionError::Blocked {
        path: path.clone(),
        content_hash,
        kind,
        finding,
    })
}

fn sensitive_finding(path: &RepoPath, contents: &[u8]) -> Option<SensitiveFindingKind> {
    if sensitive_path(path) {
        return Some(SensitiveFindingKind::SensitivePath);
    }
    if [b"".as_slice(), b"RSA ", b"EC ", b"OPENSSH "]
        .iter()
        .any(|key_kind| {
            let marker = [
                b"-----BE".as_slice(),
                b"GIN ".as_slice(),
                *key_kind,
                b"PRIVATE KEY-----".as_slice(),
            ]
            .concat();
            contains_bytes(contents, &marker)
        })
    {
        return Some(SensitiveFindingKind::PrivateKey);
    }
    if [
        (b"AKIA".as_slice(), 16),
        (b"ASIA".as_slice(), 16),
        (b"ghp_".as_slice(), 30),
        (b"github_pat_".as_slice(), 20),
        (b"xoxb-".as_slice(), 20),
        (b"xoxp-".as_slice(), 20),
        (b"sk-proj-".as_slice(), 20),
        (b"sk-live-".as_slice(), 20),
        (b"AIza".as_slice(), 30),
    ]
    .iter()
    .any(|(prefix, tail)| contains_prefixed_credential(contents, prefix, *tail))
    {
        return Some(SensitiveFindingKind::CloudCredential);
    }
    credential_assignment(path, contents).then_some(SensitiveFindingKind::CredentialAssignment)
}

fn sensitive_path(path: &RepoPath) -> bool {
    let name = path
        .as_bytes()
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or_default();
    let lower = name.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    let env_template = lower.starts_with(b".env.")
        && [b".example".as_slice(), b".sample", b".template"]
            .iter()
            .any(|suffix| lower.ends_with(suffix));
    if env_template {
        return false;
    }
    lower == b".env"
        || lower.starts_with(b".env.")
        || lower.ends_with(b".pem")
        || lower.ends_with(b".key")
        || matches!(
            lower.as_slice(),
            b"id_rsa"
                | b"id_ed25519"
                | b"credentials"
                | b"credentials.json"
                | b"service-account.json"
        )
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_prefixed_credential(haystack: &[u8], prefix: &[u8], minimum_tail: usize) -> bool {
    haystack
        .windows(prefix.len())
        .enumerate()
        .filter(|(_, window)| *window == prefix)
        .any(|(start, _)| {
            haystack[start + prefix.len()..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                .count()
                >= minimum_tail
        })
}

fn credential_assignment(path: &RepoPath, contents: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(contents) else {
        return false;
    };
    let bare_values_can_be_secrets = !is_program_source_path(path);
    text.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            return false;
        }
        let Some(split) = line.find(['=', ':']) else {
            return false;
        };
        let key = line[..split].trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return false;
        }
        let key = key.to_ascii_uppercase();
        if ![
            "SECRET",
            "TOKEN",
            "PASSWORD",
            "PRIVATE_KEY",
            "ACCESS_KEY",
            "ACCESS_KEY_ID",
            "SECRET_ACCESS_KEY",
            "API_KEY",
        ]
        .iter()
        .any(|marker| {
            key == *marker
                || key
                    .strip_suffix(marker)
                    .is_some_and(|prefix| prefix.ends_with('_'))
        }) {
            return false;
        }
        let Some(value) = credential_literal(&line[split + 1..], bare_values_can_be_secrets) else {
            return false;
        };
        value.len() >= 8 && !is_placeholder_secret(value)
    })
}

/// The literal a right-hand side carries, or `None` when it carries none.
///
/// A credential is a literal. `token = term.strip()` is a call on a local and
/// `token = next_token` is a reference to one, and neither can leak a secret
/// this scanner could name. Bare unquoted values stay in scope for env, ini,
/// yaml and shell style files, where an unquoted run really is the secret, and
/// are refused in program source, where a bare word is always an identifier.
fn credential_literal(right_hand_side: &str, bare_values_can_be_secrets: bool) -> Option<&str> {
    let value = right_hand_side
        .trim()
        .trim_end_matches([',', ';'])
        .trim_end();
    let quote = value.chars().next()?;
    if !matches!(quote, '"' | '\'') {
        let opaque = value.bytes().all(is_opaque_secret_byte);
        return (bare_values_can_be_secrets && opaque).then_some(value);
    }
    let body = &value[quote.len_utf8()..];
    let end = body.find(quote)?;
    let remainder = body[end + quote.len_utf8()..].trim_start();
    let closes_the_line =
        remainder.is_empty() || remainder.starts_with('#') || remainder.starts_with("//");
    closes_the_line.then(|| &body[..end])
}

fn is_opaque_secret_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'/' | b'=' | b':' | b'~')
}

/// Whether a bare word on the right of an assignment is necessarily an identifier.
fn is_program_source_path(path: &RepoPath) -> bool {
    let name = path
        .as_bytes()
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or_default();
    let Some(dot) = name.iter().rposition(|byte| *byte == b'.') else {
        return false;
    };
    let extension = name[dot + 1..]
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    [
        "rs", "py", "pyi", "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "go", "java",
        "kt", "kts", "scala", "rb", "php", "swift", "c", "h", "cc", "cpp", "cxx", "hpp", "hxx",
        "hh", "cs", "m", "mm", "dart", "ex", "exs", "erl", "hrl", "hs", "lua", "pl", "pm", "zig",
        "nim", "jl", "groovy", "clj", "cljs", "cljc", "fs", "fsx", "ml", "mli", "vue", "svelte",
    ]
    .iter()
    .any(|candidate| extension.as_slice() == candidate.as_bytes())
}

fn is_placeholder_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("${")
        || lower.starts_with('<')
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("changeme")
        || lower.contains("your_")
        || lower
            .chars()
            .all(|character| matches!(character, '*' | 'x' | 'X'))
}

#[cfg(test)]
mod sensitive_finding_tests {
    use super::*;

    const STRANGER_SEARCH_PY: &str = r#"FIELDS = ("title", "body", "tags")


def build_match_query(term):
    token = term.strip()
    if not token:
        return ""
    return " OR ".join("{}:{}".format(field, token) for field in FIELDS)
"#;

    fn finding(path: &str, contents: &str) -> Option<SensitiveFindingKind> {
        sensitive_finding(&RepoPath::from_utf8(path).unwrap(), contents.as_bytes())
    }

    fn admit(path: &str, contents: &str) -> Result<(), SensitiveAdmissionError> {
        let contents = contents.as_bytes();
        enforce_sensitive_admission(
            &RepoPath::from_utf8(path).unwrap(),
            sha256(contents),
            SensitiveArtifactKind::Blob { executable: false },
            contents,
            false,
            &[],
        )
    }

    #[test]
    fn the_query_builder_that_blocked_the_stranger_is_not_a_credential() {
        assert_eq!(
            finding("notekeeper/search.py", STRANGER_SEARCH_PY),
            None,
            "`token = term.strip()` is a call on a local, not a leaked credential"
        );
        admit("notekeeper/search.py", STRANGER_SEARCH_PY)
            .expect("a tokenizer must be publishable without an explicit allowance");
    }

    #[test]
    fn a_secretish_name_bound_to_an_expression_is_not_a_credential() {
        for line in [
            "token = term.strip()\n",
            "token = x.strip()\n",
            "token = tokens[index]\n",
            "secret = derive_secret(seed)\n",
            "password = input(\"password: \")\n",
            "api_key = os.environ[\"API_KEY\"]\n",
            "token = prefix + suffix\n",
        ] {
            for path in ["lexer/scan.py", "deploy/app.conf"] {
                assert_eq!(
                    finding(path, line),
                    None,
                    "expression right-hand side must not be a credential: {path} {line:?}"
                );
            }
        }
    }

    #[test]
    fn a_secretish_name_bound_to_an_identifier_in_source_is_not_a_credential() {
        for line in [
            "token = next_token\n",
            "token = self.buffer\n",
            "token = abcdefgh\n",
            "let token = current_token;\n",
        ] {
            assert_eq!(
                finding("lexer/scan.py", line),
                None,
                "identifier reference must not be a credential: {line:?}"
            );
        }
    }

    #[test]
    fn a_quoted_key_literal_in_source_is_still_a_credential() {
        assert_eq!(
            finding(
                "notekeeper/client.py",
                "api_key = \"9f8a7b6c5d4e3f2a1b0c4d5e\"\n"
            ),
            Some(SensitiveFindingKind::CredentialAssignment),
            "a hardcoded key literal must still block publication"
        );
        let error = admit(
            "notekeeper/client.py",
            "api_key = \"9f8a7b6c5d4e3f2a1b0c4d5e\"\n",
        )
        .expect_err("a hardcoded key literal must still block publication");
        assert!(
            error.to_string().contains("untracked sensitive content"),
            "unexpected error for a hardcoded key literal: {error}"
        );
    }

    #[test]
    fn an_unquoted_secret_in_a_config_file_is_still_a_credential() {
        for (path, line) in [
            (
                "deploy/app.conf",
                "SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY\n",
            ),
            ("deploy/values.yaml", "db_password: 7Hs9-Kq2-Lm4-Pv8x\n"),
            ("scripts/publish.sh", "TOKEN=a1b2c3d4e5f6a7b8\n"),
        ] {
            assert_eq!(
                finding(path, line),
                Some(SensitiveFindingKind::CredentialAssignment),
                "an unquoted secret must still block publication: {path} {line:?}"
            );
        }
    }

    #[test]
    fn the_sibling_sensitive_rules_are_unchanged() {
        assert_eq!(
            finding(".env", "TOKEN=supersecret123\n"),
            Some(SensitiveFindingKind::SensitivePath)
        );
        assert_eq!(finding(".env.example", "TOKEN=your_token_here\n"), None);
        let pem = format!("{}{}\nMIIB\n", "-----BE", "GIN PRIVATE KEY-----");
        assert_eq!(
            finding("notes.txt", &pem),
            Some(SensitiveFindingKind::PrivateKey)
        );
        let aws = format!("id = {}{}\n", "AK", "IAIOSFODNN7ABCDEFGH");
        assert_eq!(
            finding("notes.txt", &aws),
            Some(SensitiveFindingKind::CloudCredential)
        );
    }

    #[test]
    fn placeholders_and_short_values_stay_admissible() {
        for line in [
            "password = \"${DB_PASSWORD}\"\n",
            "api_key = \"your_api_key_here\"\n",
            "token = \"abc\"\n",
            "token = 5\n",
        ] {
            assert_eq!(
                finding("deploy/app.conf", line),
                None,
                "placeholder or short value must stay admissible: {line:?}"
            );
        }
    }
}
