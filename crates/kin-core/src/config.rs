// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
// Carried only by the Unix `ConfigAuthority` and `ConfigTemp` fields below.
// The Windows arm owns its own, in its own module, so this gate must stay
// narrower than the one on the writer it serves.
#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
use std::path::PathBuf;

use gix::bstr::ByteSlice;

use crate::error::{KinError, Result};

/// Capability-owned atomic config replacement on Windows.
///
/// The Unix writer is built on directory-descriptor-relative renames, which
/// Windows does not have. The arm behind this module publishes through the
/// primitives Windows does provide and satisfies the same contract; both are
/// held to it by the `capability_owned_config_replacement_tests` module below.
#[cfg(windows)]
mod windows;

/// High-level worldview preset for how Kin should treat non-code artifacts
/// and external tool execution.
///
/// There is only one mode now — Native.  Legacy config values are accepted
/// by `from_str()` for backwards compatibility but always resolve to Native.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WorldPreset {
    /// Kin-native mode: graph is source of truth, files are projections.
    Native,
}

/// Custom deserialize: accept any legacy preset name and map to Native.
impl<'de> serde::Deserialize<'de> for WorldPreset {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // All values map to Native — there's only one mode now.
        match s.as_str() {
            "Native" | "native" | "compatibility" | "hybrid" | "brownfield" | "radical" => {
                Ok(Self::Native)
            }
            other => Err(serde::de::Error::custom(format!("unknown preset: {other}"))),
        }
    }
}

impl WorldPreset {
    pub fn as_str(&self) -> &'static str {
        "native"
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "native" | "compatibility" | "hybrid" | "brownfield" => Some(Self::Native),
            _ => None,
        }
    }

    pub fn defaults(self) -> ExternalToolExecutionPolicy {
        ExternalToolExecutionPolicy::Workspace
    }
}

impl std::fmt::Display for WorldPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// How Kin should handle broad external tools such as Docker Compose and Make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalToolExecutionPolicy {
    /// Widen broad tool execution to a full compatibility workspace when needed.
    Workspace,
    /// Do not auto-widen scoped execution for broad external tools.
    Strict,
}

impl ExternalToolExecutionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Strict => "strict",
        }
    }
}

impl std::fmt::Display for ExternalToolExecutionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// High-level world policy stored in repo config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldConfig {
    /// Named preset describing Kin's worldview for non-code artifacts.
    #[serde(default = "default_world_preset")]
    pub preset: WorldPreset,
}

impl Default for WorldConfig {
    fn default() -> Self {
        Self {
            preset: default_world_preset(),
        }
    }
}

/// Execution policy for external tools that expect a conventional workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicyConfig {
    /// How Kin should handle broad external tool execution.
    #[serde(default = "default_external_tool_policy")]
    pub external_tools: ExternalToolExecutionPolicy,
}

impl Default for ExecutionPolicyConfig {
    fn default() -> Self {
        Self {
            external_tools: default_external_tool_policy(),
        }
    }
}

/// Host kind for a Kin remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteHostKind {
    #[serde(rename = "github", alias = "git-hub")]
    GitHub,
    #[serde(rename = "gitlab", alias = "git-lab")]
    GitLab,
    #[serde(rename = "bitbucket", alias = "bit-bucket")]
    Bitbucket,
    #[serde(rename = "kinlab", alias = "kin-lab", alias = "kin-hub")]
    KinLab,
}

impl RemoteHostKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Bitbucket => "bitbucket",
            Self::KinLab => "kinlab",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "github" => Some(Self::GitHub),
            "gitlab" => Some(Self::GitLab),
            "bitbucket" => Some(Self::Bitbucket),
            "kinlab" => Some(Self::KinLab),
            _ => None,
        }
    }
}

impl std::fmt::Display for RemoteHostKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Transport kind for a Kin remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteTransportKind {
    GitExport,
    NativeKin,
}

impl RemoteTransportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitExport => "git-export",
            Self::NativeKin => "native-kin",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "git-export" => Some(Self::GitExport),
            "native-kin" => Some(Self::NativeKin),
            _ => None,
        }
    }
}

impl std::fmt::Display for RemoteTransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A configured Kin remote reference.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRefConfig {
    /// Remote name such as `origin`.
    pub name: String,
    /// Host type.
    pub host: RemoteHostKind,
    /// Transport type.
    pub transport: RemoteTransportKind,
    /// Optional remote URL or locator.
    #[serde(default)]
    pub url: Option<String>,
    /// Whether review state should publish with this remote.
    #[serde(default)]
    pub publish_review_state: bool,
    /// Whether proof state should publish with this remote.
    #[serde(default)]
    pub publish_proofs: bool,
}

impl fmt::Debug for RemoteRefConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteRefConfig")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("transport", &self.transport)
            .field("url_present", &self.url.is_some())
            .field("url", &"<redacted>")
            .field("publish_review_state", &self.publish_review_state)
            .field("publish_proofs", &self.publish_proofs)
            .finish()
    }
}

/// Remote configuration stored in repo config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// Default remote name.
    #[serde(default)]
    pub default: Option<String>,
    /// Explicitly configured remotes.
    #[serde(default)]
    pub refs: Vec<RemoteRefConfig>,
}

/// Canonical repository-local Git push behavior admitted during coexistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitPushDefault {
    Nothing,
    Current,
    Upstream,
    Simple,
    Matching,
}

impl GitPushDefault {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nothing => "nothing",
            Self::Current => "current",
            Self::Upstream => "upstream",
            Self::Simple => "simple",
            Self::Matching => "matching",
        }
    }

    pub fn from_exact_git_value(value: &str) -> Option<Self> {
        match value {
            "nothing" => Some(Self::Nothing),
            "current" => Some(Self::Current),
            "upstream" => Some(Self::Upstream),
            "simple" => Some(Self::Simple),
            "matching" => Some(Self::Matching),
            _ => None,
        }
    }
}

impl fmt::Display for GitPushDefault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One exact, credential-free Git remote admitted from repository-local config.
///
/// Empty URL/refspec lists are meaningful and preserve explicit absence. Values
/// remain ordered exactly as Git presented them at the admission boundary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitRemoteTransportConfig {
    pub name: String,
    #[serde(default)]
    pub fetch_urls: Vec<String>,
    #[serde(default)]
    pub push_urls: Vec<String>,
    #[serde(default)]
    pub fetch_refspecs: Vec<String>,
    #[serde(default)]
    pub push_refspecs: Vec<String>,
}

impl GitRemoteTransportConfig {
    /// The URL Git would publish through: the first sealed push URL when Git
    /// recorded one, otherwise the first sealed fetch URL. `None` means Git
    /// sealed the remote without any transport URL.
    pub fn publish_url(&self) -> Option<&str> {
        self.push_urls
            .first()
            .or_else(|| self.fetch_urls.first())
            .map(String::as_str)
    }

    /// Classify the hosting service from the sealed URL's host labels.
    ///
    /// Classification reads the parsed host rather than matching substrings of
    /// the whole URL, so a repository path segment cannot masquerade as a host.
    pub fn host_kind(&self) -> RemoteHostKind {
        let Some(host) = self
            .publish_url()
            .and_then(|url| gix::Url::try_from(url).ok())
            .and_then(|url| url.host().map(str::to_ascii_lowercase))
        else {
            return RemoteHostKind::GitHub;
        };
        let has_label = |label: &str| host.split('.').any(|part| part == label);
        if has_label("kinlab") {
            RemoteHostKind::KinLab
        } else if has_label("gitlab") {
            RemoteHostKind::GitLab
        } else if has_label("bitbucket") {
            RemoteHostKind::Bitbucket
        } else {
            RemoteHostKind::GitHub
        }
    }
}

impl fmt::Debug for GitRemoteTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitRemoteTransportConfig")
            .field("name", &self.name)
            .field("fetch_url_count", &self.fetch_urls.len())
            .field("push_url_count", &self.push_urls.len())
            .field("fetch_refspec_count", &self.fetch_refspecs.len())
            .field("push_refspec_count", &self.push_refspecs.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

/// Exact tracking configuration for one local Git branch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitBranchTrackingConfig {
    pub branch: String,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub merge_refs: Vec<String>,
    #[serde(default)]
    pub push_remote: Option<String>,
}

impl fmt::Debug for GitBranchTrackingConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitBranchTrackingConfig")
            .field("branch", &self.branch)
            .field("remote_present", &self.remote.is_some())
            .field("merge_ref_count", &self.merge_refs.len())
            .field("push_remote_present", &self.push_remote.is_some())
            .field("values", &"<redacted>")
            .finish()
    }
}

/// Sealed local Git coexistence configuration.
///
/// This is transport/projection configuration, not graph-owned
/// `GitExternalAuthority`. It is written into `.kin/config.toml` and sealed by
/// repository initialization alongside the other local configuration bytes.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCoexistenceConfig {
    #[serde(default)]
    pub remotes: Vec<GitRemoteTransportConfig>,
    #[serde(default)]
    pub branches: Vec<GitBranchTrackingConfig>,
    #[serde(default)]
    pub remote_push_default: Option<String>,
    #[serde(default)]
    pub push_default: Option<GitPushDefault>,
    /// Sealed repository-local `push.autoSetupRemote`, if the source set it.
    #[serde(default)]
    pub push_auto_setup_remote: Option<bool>,
}

impl fmt::Debug for GitCoexistenceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitCoexistenceConfig")
            .field("remote_count", &self.remotes.len())
            .field("branch_count", &self.branches.len())
            .field(
                "remote_push_default_present",
                &self.remote_push_default.is_some(),
            )
            .field("push_default", &self.push_default)
            .field("push_auto_setup_remote", &self.push_auto_setup_remote)
            .field("transport_values", &"<redacted>")
            .finish()
    }
}

impl GitCoexistenceConfig {
    /// The sealed remote Git would publish `branch` through.
    ///
    /// Resolution reads only sealed configuration, in Git's own precedence:
    /// the branch's `pushRemote`, then its tracking `remote`, then
    /// `remote.pushDefault`. A branch that publishes to `.` resolves to `None`
    /// because it names the local repository, not a transport remote. When no
    /// sealed entry designates a remote at all, a repository holding exactly
    /// one sealed remote resolves to that remote; anything else resolves to
    /// `None` rather than guessing a conventional name.
    pub fn publish_remote_for_branch(
        &self,
        branch: Option<&str>,
    ) -> Option<&GitRemoteTransportConfig> {
        let tracking = branch.and_then(|branch| {
            self.branches
                .iter()
                .find(|candidate| candidate.branch == branch)
        });
        let designated = [
            tracking.and_then(|entry| entry.push_remote.as_deref()),
            tracking.and_then(|entry| entry.remote.as_deref()),
            self.remote_push_default.as_deref(),
        ]
        .into_iter()
        .flatten()
        .next();

        match designated {
            Some(".") => None,
            Some(name) => self.remotes.iter().find(|remote| remote.name == name),
            None => match self.remotes.as_slice() {
                [only] => Some(only),
                _ => None,
            },
        }
    }

    /// Validate that manually edited or reopened local config remains inside
    /// the same credential-free subset admitted from Git.
    pub fn validate(&self) -> Result<()> {
        let mut remote_names = BTreeSet::new();
        for remote in &self.remotes {
            validate_git_identifier(&remote.name, "Git remote name")?;
            if !remote_names.insert(remote.name.as_str()) {
                return Err(git_config_error("duplicate Git remote name"));
            }
            for url in remote.fetch_urls.iter().chain(&remote.push_urls) {
                validate_git_remote_url(url)?;
            }
            for refspec in &remote.fetch_refspecs {
                validate_git_refspec(refspec, gix::refspec::parse::Operation::Fetch)?;
            }
            for refspec in &remote.push_refspecs {
                validate_git_refspec(refspec, gix::refspec::parse::Operation::Push)?;
            }
        }

        let known_remote = |candidate: &str| candidate == "." || remote_names.contains(candidate);
        if self
            .remote_push_default
            .as_deref()
            .is_some_and(|remote| !known_remote(remote))
        {
            return Err(git_config_error(
                "Git remote_push_default names an unknown remote",
            ));
        }

        let mut branch_names = BTreeSet::new();
        for branch in &self.branches {
            validate_git_branch_name(&branch.branch)?;
            if !branch_names.insert(branch.branch.as_str()) {
                return Err(git_config_error("duplicate Git branch tracking entry"));
            }
            if branch
                .remote
                .as_deref()
                .is_some_and(|remote| !known_remote(remote))
                || branch
                    .push_remote
                    .as_deref()
                    .is_some_and(|remote| !known_remote(remote))
            {
                return Err(git_config_error(
                    "Git branch tracking names an unknown remote",
                ));
            }
            if !branch.merge_refs.is_empty() && branch.remote.is_none() {
                return Err(git_config_error(
                    "Git branch merge refs require an explicit remote",
                ));
            }
            for merge_ref in &branch.merge_refs {
                gix::validate::reference::name(merge_ref.as_bytes().as_bstr())
                    .map_err(|_| git_config_error("invalid Git branch merge ref"))?;
            }
        }
        Ok(())
    }
}

fn validate_git_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(git_config_error(format!("unsafe {label}")));
    }
    Ok(())
}

fn validate_git_branch_name(value: &str) -> Result<()> {
    validate_git_identifier(value, "Git branch name")?;
    let full = format!("refs/heads/{value}");
    gix::validate::reference::name(full.as_bytes().as_bstr())
        .map_err(|_| git_config_error("invalid Git branch name"))?;
    Ok(())
}

fn validate_git_remote_url(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'?' | b'#'))
    {
        return Err(git_config_error("unsafe Git remote URL"));
    }
    let parsed =
        gix::Url::try_from(value).map_err(|_| git_config_error("unparseable Git remote URL"))?;
    if parsed.user.is_some() || parsed.password.is_some() {
        return Err(git_config_error("credential or userinfo in Git remote URL"));
    }
    match parsed.scheme {
        gix::url::Scheme::File => {}
        gix::url::Scheme::Git
        | gix::url::Scheme::Ssh
        | gix::url::Scheme::Http
        | gix::url::Scheme::Https => {
            if parsed.host.as_deref().is_none_or(str::is_empty) {
                return Err(git_config_error("network Git remote URL has no host"));
            }
        }
        gix::url::Scheme::Ext(_) => {
            return Err(git_config_error("unsupported custom Git remote scheme"));
        }
    }
    if parsed.path_argument_safe().is_none() {
        return Err(git_config_error("unsafe Git remote path"));
    }
    Ok(())
}

fn validate_git_refspec(value: &str, operation: gix::refspec::parse::Operation) -> Result<()> {
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(git_config_error("unsafe Git refspec"));
    }
    gix::refspec::parse(value.as_bytes().as_bstr(), operation)
        .map_err(|_| git_config_error("invalid Git refspec"))?;
    Ok(())
}

fn git_config_error(reason: impl Into<String>) -> KinError {
    KinError::Config(format!(
        "sealed Git coexistence config is outside Kin's safe exact subset ({})",
        reason.into()
    ))
}

/// Proof posture for LSP enrichment. Mirrors `kin_lsp::ProofMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LspProofMode {
    /// Best-effort enrichment; gaps are recorded but not fatal.
    #[default]
    Advisory,
    /// Citable / proof run; required-language gaps and silent failures are fatal.
    Citable,
}

impl LspProofMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Citable => "citable",
        }
    }
}

impl std::fmt::Display for LspProofMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A per-language LSP provider override. Selects a specific language server for
/// a language and optionally overrides the binaries searched / launch args.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LspProviderOverride {
    /// Language slug, e.g. `python`, `rust`, `go`.
    pub language: String,
    /// Provider id to prefer, e.g. `pylsp`, `rust-analyzer`, `gopls`.
    pub provider: String,
    /// Extra binary-name candidates, tried before the provider's defaults.
    #[serde(default)]
    pub binaries: Vec<String>,
    /// Launch-arg override; when set, replaces the provider's default args.
    #[serde(default)]
    pub args: Option<Vec<String>>,
}

/// Repo-local LSP enrichment configuration, stored under `[lsp]` in
/// `.kin/config.toml`.
///
/// LSP is default-on enrichment layered over Kin's own parsers and linkers.
/// This section replaces environment sprawl (e.g. `KIN_DAEMON_DISABLE_LSP`) with
/// an explicit, versioned config surface. Provider selection here maps directly
/// into the `kin_lsp` provider registry (`RegistryConfig`): `providers` become
/// registry overrides, `required` / `disabled` become the registry's
/// required / disabled language policy, and `proof_mode` selects the enrichment
/// proof posture.
///
/// Field order matters for TOML serialization: the scalar and string-array keys
/// come first and `providers` (a TOML array-of-tables) is last, so a config with
/// provider overrides serializes without moving a key past the `[[lsp.providers]]`
/// section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspConfig {
    /// Whether LSP enrichment runs at all. Absent config means enabled with
    /// auto-detection of installed servers.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Proof posture for enrichment runs.
    #[serde(default)]
    pub proof_mode: LspProofMode,
    /// Languages whose enrichment is REQUIRED. A gap for a required language is
    /// fail-loud in a citable proof run.
    #[serde(default)]
    pub required: Vec<String>,
    /// Languages whose enrichment is disabled entirely.
    #[serde(default)]
    pub disabled: Vec<String>,
    /// Per-language provider overrides.
    #[serde(default)]
    pub providers: Vec<LspProviderOverride>,
}

impl Default for LspConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proof_mode: LspProofMode::Advisory,
            required: Vec::new(),
            disabled: Vec::new(),
            providers: Vec::new(),
        }
    }
}

impl LspConfig {
    /// Validate the section for internal consistency, independent of which
    /// servers are installed. Fail-loud: a language cannot be both required and
    /// disabled. Provider-id and language-slug validation against the live
    /// registry happens when this section is mapped into
    /// `kin_lsp::RegistryConfig`.
    pub fn validate(&self) -> Result<()> {
        for language in &self.required {
            if self
                .disabled
                .iter()
                .any(|disabled| disabled.eq_ignore_ascii_case(language))
            {
                return Err(KinError::Config(format!(
                    "language '{language}' is both required and disabled in [lsp] config"
                )));
            }
        }
        Ok(())
    }
}

/// Repo-local configuration stored in `.kin/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KinConfig {
    /// User-visible name for the repository.
    #[serde(default)]
    pub name: Option<String>,

    /// Default author for commits when not otherwise specified.
    #[serde(default)]
    pub default_author: Option<String>,

    /// Default branch name (created at init time).
    #[serde(default = "default_branch_name")]
    pub default_branch: String,

    /// Auto-index on file save (used by the daemon).
    #[serde(default = "default_true")]
    pub auto_index: bool,

    /// Token budget tiers for context pack builder.
    #[serde(default)]
    pub context: ContextConfig,

    /// Repository mode: "compat" (default) or "native".
    #[serde(default = "default_mode")]
    pub mode: String,

    /// High-level worldview preset for artifacts and execution.
    #[serde(default)]
    pub world: WorldConfig,

    /// External tool execution policy.
    #[serde(default)]
    pub execution: ExecutionPolicyConfig,

    /// Native and compatibility remote configuration.
    #[serde(default)]
    pub remote: RemoteConfig,

    /// Exact repository-local Git coexistence configuration admitted at init.
    #[serde(default)]
    pub git: GitCoexistenceConfig,

    /// LSP enrichment configuration: provider selection, required/disabled
    /// languages, and proof posture.
    #[serde(default)]
    pub lsp: LspConfig,

    /// Resource knobs that must survive a daemon restart.
    #[serde(default)]
    pub resources: ResourcesConfig,
}

/// The two knobs an operator reaches for on a constrained host, recorded where
/// they outlive the process that set them (FIR-2504).
///
/// Before this section both knobs lived only in the environment of whichever
/// process happened to spawn the daemon, so the batch size an operator set
/// reverted to the daemon default on the restart an OOM forced, which is
/// precisely when it was needed. Absent fields mean "not set here" and leave the
/// environment and the built-in defaults in charge; this section never
/// outranks an explicit environment variable.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcesConfig {
    /// Resource profile this repository's daemon should run under: `proof`,
    /// `interactive`, `throughput`, or `ci`. Validated at load and at save, so
    /// an unusable value is rejected at the moment it is written rather than
    /// silently ignored at the moment it would have mattered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// Batch size for the daemon's background embedding queue. `None` leaves the
    /// daemon's own default in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embed_batch_size: Option<usize>,
}

/// The profile names a repository config may carry, which are the same names
/// `KIN_RESOURCE_PROFILE` accepts. Duplicated as data here rather than imported
/// so kin-core keeps no dependency on the CLI; the two are pinned together by a
/// test in `crates/kin-cli/src/commands/resources.rs`.
pub const RESOURCE_PROFILE_NAMES: [&str; 4] = ["proof", "interactive", "throughput", "ci"];

impl ResourcesConfig {
    /// Reject a profile name the runtime cannot act on, and a batch size of
    /// zero, which would stall the embedding queue rather than slow it.
    pub fn validate(&self) -> Result<()> {
        if let Some(profile) = &self.profile {
            let normalized = profile.trim().to_ascii_lowercase();
            if !RESOURCE_PROFILE_NAMES.contains(&normalized.as_str()) {
                return Err(KinError::Config(format!(
                    "unknown resource profile '{profile}' in [resources] config (expected {})",
                    RESOURCE_PROFILE_NAMES.join(", ")
                )));
            }
        }
        if self.embed_batch_size == Some(0) {
            return Err(KinError::Config(
                "[resources] embed_batch_size must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }

    /// The profile name normalized to what the runtime compares against, so a
    /// config carrying `CI` behaves exactly like one carrying `ci`.
    pub fn normalized_profile(&self) -> Option<String> {
        self.profile
            .as_ref()
            .map(|profile| profile.trim().to_ascii_lowercase())
    }
}

fn default_mode() -> String {
    "native".to_string()
}

fn default_world_preset() -> WorldPreset {
    WorldPreset::Native
}

fn default_external_tool_policy() -> ExternalToolExecutionPolicy {
    ExternalToolExecutionPolicy::Workspace
}

fn default_branch_name() -> String {
    "main".to_string()
}

fn default_true() -> bool {
    true
}

/// Context-pack builder configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConfig {
    /// Default token budget.
    #[serde(default = "default_token_budget")]
    pub default_budget: u32,
}

fn default_token_budget() -> u32 {
    8000
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            default_budget: default_token_budget(),
        }
    }
}

impl Default for KinConfig {
    fn default() -> Self {
        Self {
            name: None,
            default_author: None,
            default_branch: default_branch_name(),
            auto_index: true,
            context: ContextConfig::default(),
            mode: default_mode(),
            world: WorldConfig::default(),
            execution: ExecutionPolicyConfig::default(),
            remote: RemoteConfig::default(),
            git: GitCoexistenceConfig::default(),
            lsp: LspConfig::default(),
            resources: ResourcesConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigAuthorityKind {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        windows
    ))]
    PublishedRepository,
    InitializationStage,
}

impl KinConfig {
    /// Apply a worldview preset and synchronize the explicit policy knobs.
    pub fn apply_world_preset(&mut self, preset: WorldPreset) {
        self.world.preset = preset;
        self.execution.external_tools = preset.defaults();
    }

    /// Validate cross-field invariants that serde cannot express on its own.
    /// Fail-loud: a config that contradicts a substrate contract must not load
    /// silently and degrade behavior at runtime.
    pub fn validate(&self) -> Result<()> {
        self.lsp.validate()?;
        self.git.validate()?;
        self.resources.validate()?;
        Ok(())
    }

    /// Load config from a TOML file. The parsed config is validated before it is
    /// returned, so a contradictory config fails loud at load rather than
    /// silently degrading enrichment later.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| KinError::io(path, e))?;
        let config: Self = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Load config or return defaults when the repo does not have a config yet.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default())
        }
    }

    /// Atomically and durably replace `.kin/config.toml`.
    ///
    /// The writer retains the real `.kin` directory, creates and flushes an
    /// owner-private sibling temp file, and publishes through that capability.
    /// Existing config is exchanged rather than blindly overwritten so a
    /// raced name can be detected and restored. Unsupported hosts fail before
    /// creating a temp file; there is no truncating path-based fallback.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let contents = toml::to_string_pretty(self)?;
        save_config_atomically(path, contents.as_bytes())
    }

    /// Save config inside an already validated unpublished repository stage.
    ///
    /// This is deliberately crate-private: ordinary callers own only the
    /// published `.kin/config.toml` namespace.
    pub(crate) fn save_initialization_stage(&self, staging_root: &Path) -> Result<()> {
        self.validate()?;
        let contents = toml::to_string_pretty(self)?;
        save_config_atomically_scoped(
            &staging_root.join("config.toml"),
            contents.as_bytes(),
            ConfigAuthorityKind::InitializationStage,
        )
    }

    /// Resolve a configured remote by explicit name or default remote.
    pub fn resolve_remote(&self, requested: Option<&str>) -> Option<&RemoteRefConfig> {
        let name = requested.or(self.remote.default.as_deref())?;
        self.remote.refs.iter().find(|remote| remote.name == name)
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigFileIdentity {
    device: u64,
    inode: u64,
}

/// Where a contract case may inject a failure into either arm's transaction.
///
/// Both arms carry the same four points so one case can drive both. That
/// matters most for rollback, which is the reason the Windows arm publishes
/// with `ReplaceFileW` rather than the atomic replacing move, and which no
/// ordinary save can reach.
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    windows
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigSaveHookPoint {
    AfterPartialTempWrite,
    AfterTempSync,
    BeforePublication,
    AfterPublication,
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
struct ConfigAuthority {
    directory: cap_std::fs::Dir,
    directory_identity: ConfigFileIdentity,
    display_directory: PathBuf,
    display_config: PathBuf,
    config_name: std::ffi::OsString,
    expected_config: Option<ConfigFileIdentity>,
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
struct ConfigTemp {
    file: std::fs::File,
    name: std::ffi::OsString,
    identity: ConfigFileIdentity,
    display_path: PathBuf,
}

/// Resolve which directory and name a config write is allowed to own.
///
/// Every platform arm answers this the same way, because it is a statement
/// about the repository namespace rather than about any host primitive: the
/// writer owns `.kin/config.toml` under a published repository and
/// `config.toml` under one canonical `.kin.init-<uuid-v4>` stage, and nothing
/// else. Sharing one body keeps the two arms from drifting into different
/// answers about what a caller may replace.
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    windows
))]
fn validated_config_authority_path(
    path: &Path,
    kind: ConfigAuthorityKind,
) -> Result<(&std::ffi::OsStr, &Path)> {
    if !path.is_absolute() {
        return Err(KinError::Config(format!(
            "repository config path must be absolute: {}",
            path.display()
        )));
    }
    let config_name = path.file_name().ok_or_else(|| {
        KinError::Config(format!(
            "repository config path has no file name: {}",
            path.display()
        ))
    })?;
    if config_name != std::ffi::OsStr::new("config.toml") {
        return Err(KinError::Config(format!(
            "KinConfig::save only owns .kin/config.toml, not {}",
            path.display()
        )));
    }
    let directory_path = path.parent().ok_or_else(|| {
        KinError::Config(format!(
            "repository config path has no .kin parent: {}",
            path.display()
        ))
    })?;
    match kind {
        ConfigAuthorityKind::PublishedRepository
            if directory_path.file_name() != Some(std::ffi::OsStr::new(".kin")) =>
        {
            return Err(KinError::Config(format!(
                "repository config must be a direct child of .kin: {}",
                path.display()
            )));
        }
        ConfigAuthorityKind::InitializationStage
            if !is_initialization_stage_directory(directory_path) =>
        {
            return Err(KinError::Config(format!(
                "staged repository config must be a direct child of a canonical \
                 .kin.init-<uuid-v4> authority: {}",
                path.display()
            )));
        }
        _ => {}
    }
    Ok((config_name, directory_path))
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
impl ConfigAuthority {
    fn open(path: &Path, kind: ConfigAuthorityKind) -> Result<Self> {
        let (config_name, directory_path) = validated_config_authority_path(path, kind)?;

        let directory = open_config_directory_nofollow(directory_path)?;
        let directory_identity = config_directory_identity(&directory)
            .map_err(|error| KinError::io(directory_path, error))?;
        let expected_config =
            inspect_config_file(&directory, config_name, path, "repository config")?;
        let authority = Self {
            directory,
            directory_identity,
            display_directory: directory_path.to_path_buf(),
            display_config: path.to_path_buf(),
            config_name: config_name.to_os_string(),
            expected_config,
        };
        authority.revalidate_visible_directory()?;
        authority.revalidate_expected_config()?;
        Ok(authority)
    }

    fn create_temp(&self) -> Result<ConfigTemp> {
        loop {
            let name = std::ffi::OsString::from(format!(
                ".config.toml.kin-tmp-{}",
                uuid::Uuid::new_v4().simple()
            ));
            let display_path = self.display_directory.join(&name);
            let descriptor = match rustix::fs::openat(
                &self.directory,
                &name,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => {
                    return Err(KinError::io(&display_path, std::io::Error::from(error)));
                }
            };
            let file = std::fs::File::from(descriptor);
            let identity = config_std_file_identity(&file)
                .map_err(|error| KinError::io(&display_path, error))?;
            self.require_named_identity(&name, identity, &display_path, "config temp file")?;
            return Ok(ConfigTemp {
                file,
                name,
                identity,
                display_path,
            });
        }
    }

    fn revalidate_visible_directory(&self) -> Result<()> {
        let visible = open_config_directory_nofollow(&self.display_directory)?;
        let visible_identity = config_directory_identity(&visible)
            .map_err(|error| KinError::io(&self.display_directory, error))?;
        let retained_identity = config_directory_identity(&self.directory)
            .map_err(|error| KinError::io(&self.display_directory, error))?;
        if visible_identity != self.directory_identity
            || retained_identity != self.directory_identity
        {
            return Err(KinError::Config(format!(
                "retained .kin authority changed or was replaced while saving {}",
                self.display_config.display()
            )));
        }
        Ok(())
    }

    fn revalidate_expected_config(&self) -> Result<()> {
        let actual = inspect_config_file(
            &self.directory,
            &self.config_name,
            &self.display_config,
            "repository config",
        )?;
        if actual != self.expected_config {
            return Err(KinError::Config(format!(
                "repository config changed identity while saving {}",
                self.display_config.display()
            )));
        }
        Ok(())
    }

    fn require_named_identity(
        &self,
        name: &std::ffi::OsStr,
        expected: ConfigFileIdentity,
        display: &Path,
        label: &str,
    ) -> Result<()> {
        let actual = inspect_config_file(&self.directory, name, display, label)?;
        if actual != Some(expected) {
            return Err(KinError::Config(format!(
                "{label} changed identity while saving {}",
                self.display_config.display()
            )));
        }
        Ok(())
    }

    fn require_named_absent(
        &self,
        name: &std::ffi::OsStr,
        display: &Path,
        label: &str,
    ) -> Result<()> {
        match self.directory.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(KinError::io(display, error)),
            Ok(_) => Err(KinError::Config(format!(
                "{label} unexpectedly exists while saving {}",
                self.display_config.display()
            ))),
        }
    }

    fn sync(&self) -> Result<()> {
        rustix::fs::fsync(&self.directory)
            .map_err(|error| KinError::io(&self.display_directory, std::io::Error::from(error)))
    }

    fn cleanup_exact_temp(&self, temp: &ConfigTemp) -> Result<()> {
        match inspect_config_file(
            &self.directory,
            &temp.name,
            &temp.display_path,
            "config temp file",
        )? {
            None => return Ok(()),
            Some(actual) if actual == temp.identity => {}
            Some(_) => {
                return Err(KinError::Config(format!(
                    "refusing to remove a replacement at config temp name {}",
                    temp.display_path.display()
                )));
            }
        }
        rustix::fs::unlinkat(&self.directory, &temp.name, rustix::fs::AtFlags::empty())
            .map_err(|error| KinError::io(&temp.display_path, std::io::Error::from(error)))?;
        self.sync()
    }

    fn rollback_exchange(&self, temp: &ConfigTemp) -> Result<()> {
        self.require_named_identity(
            &self.config_name,
            temp.identity,
            &self.display_config,
            "published repository config",
        )?;
        self.directory
            .symlink_metadata(&temp.name)
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        rustix::fs::renameat_with(
            &self.directory,
            &self.config_name,
            &self.directory,
            &temp.name,
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .map_err(|error| KinError::io(&self.display_config, std::io::Error::from(error)))?;
        self.sync()?;
        self.require_named_identity(
            &temp.name,
            temp.identity,
            &temp.display_path,
            "rolled-back config temp file",
        )
    }

    fn rollback_new_publication(&self, temp: &ConfigTemp) -> Result<()> {
        self.require_named_identity(
            &self.config_name,
            temp.identity,
            &self.display_config,
            "published repository config",
        )?;
        self.require_named_absent(&temp.name, &temp.display_path, "config temp file")?;
        rustix::fs::renameat_with(
            &self.directory,
            &self.config_name,
            &self.directory,
            &temp.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| KinError::io(&self.display_config, std::io::Error::from(error)))?;
        self.sync()?;
        self.require_named_absent(&self.config_name, &self.display_config, "repository config")?;
        self.require_named_identity(
            &temp.name,
            temp.identity,
            &temp.display_path,
            "rolled-back config temp file",
        )
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn save_config_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    save_config_atomically_scoped(path, contents, ConfigAuthorityKind::PublishedRepository)
}

#[cfg(windows)]
fn save_config_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    windows::save_config_atomically_scoped(path, contents, ConfigAuthorityKind::PublishedRepository)
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    windows
)))]
fn save_config_atomically(path: &Path, _contents: &[u8]) -> Result<()> {
    Err(unsupported_config_replacement(path))
}

/// Say what the host is missing, not merely that it is missing something.
///
/// Publishing a config means exchanging a fully written owner-private sibling
/// for the current one under a retained directory capability, so a name raced
/// in between is detected and the exchange rolled back. That needs an atomic
/// exchanging or no-replace directory rename plus a durable directory flush.
/// A host without them gets no truncating path-based fallback: a partially
/// written config would become repository authority with no way back.
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    windows
)))]
fn unsupported_config_replacement(path: &Path) -> KinError {
    KinError::Config(format!(
        "cannot publish repository config {} on this platform: capability-owned replacement needs \
         an atomic exchanging or no-replace directory rename and a durable directory flush, which \
         this host does not provide. Kin does not fall back to overwriting the file in place, \
         because a partially written config would become repository authority with no rollback",
        path.display()
    ))
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    windows
))]
fn is_initialization_stage_directory(path: &Path) -> bool {
    let Some(raw) = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|name| name.strip_prefix(".kin.init-"))
    else {
        return false;
    };
    let Ok(id) = uuid::Uuid::parse_str(raw) else {
        return false;
    };
    id.get_version_num() == 4 && id.to_string() == raw
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn save_config_atomically_scoped(
    path: &Path,
    contents: &[u8],
    kind: ConfigAuthorityKind,
) -> Result<()> {
    save_config_atomically_scoped_with_hook(path, contents, kind, |_| Ok(()))
}

#[cfg(windows)]
fn save_config_atomically_scoped(
    path: &Path,
    contents: &[u8],
    kind: ConfigAuthorityKind,
) -> Result<()> {
    windows::save_config_atomically_scoped(path, contents, kind)
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    windows
)))]
fn save_config_atomically_scoped(
    path: &Path,
    _contents: &[u8],
    _kind: ConfigAuthorityKind,
) -> Result<()> {
    Err(unsupported_config_replacement(path))
}

#[cfg(all(
    test,
    any(target_vendor = "apple", target_os = "linux", target_os = "android")
))]
fn save_config_atomically_with_hook(
    path: &Path,
    contents: &[u8],
    hook: impl FnMut(ConfigSaveHookPoint) -> Result<()>,
) -> Result<()> {
    save_config_atomically_scoped_with_hook(
        path,
        contents,
        ConfigAuthorityKind::PublishedRepository,
        hook,
    )
}

#[cfg(all(test, windows))]
fn save_config_atomically_with_hook(
    path: &Path,
    contents: &[u8],
    hook: impl FnMut(ConfigSaveHookPoint) -> Result<()>,
) -> Result<()> {
    windows::save_config_atomically_scoped_with_hook(
        path,
        contents,
        ConfigAuthorityKind::PublishedRepository,
        hook,
    )
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn save_config_atomically_scoped_with_hook(
    path: &Path,
    contents: &[u8],
    kind: ConfigAuthorityKind,
    mut hook: impl FnMut(ConfigSaveHookPoint) -> Result<()>,
) -> Result<()> {
    use std::io::Write as _;

    let authority = ConfigAuthority::open(path, kind)?;
    let mut temp = authority.create_temp()?;
    let result = (|| {
        let split = contents.len() / 2;
        temp.file
            .write_all(&contents[..split])
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        hook(ConfigSaveHookPoint::AfterPartialTempWrite)?;
        temp.file
            .write_all(&contents[split..])
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        temp.file
            .sync_all()
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        authority.require_named_identity(
            &temp.name,
            temp.identity,
            &temp.display_path,
            "config temp file",
        )?;
        hook(ConfigSaveHookPoint::AfterTempSync)?;
        authority.revalidate_visible_directory()?;
        authority.revalidate_expected_config()?;
        authority.require_named_identity(
            &temp.name,
            temp.identity,
            &temp.display_path,
            "config temp file",
        )?;
        hook(ConfigSaveHookPoint::BeforePublication)?;

        if let Some(expected) = authority.expected_config {
            rustix::fs::renameat_with(
                &authority.directory,
                &temp.name,
                &authority.directory,
                &authority.config_name,
                rustix::fs::RenameFlags::EXCHANGE,
            )
            .map_err(|error| KinError::io(path, std::io::Error::from(error)))?;

            let post_publication = authority
                .sync()
                .and_then(|()| hook(ConfigSaveHookPoint::AfterPublication))
                .and_then(|()| {
                    authority.require_named_identity(
                        &authority.config_name,
                        temp.identity,
                        &authority.display_config,
                        "published repository config",
                    )
                })
                .and_then(|()| {
                    authority.require_named_identity(
                        &temp.name,
                        expected,
                        &temp.display_path,
                        "replaced repository config",
                    )
                })
                .and_then(|()| authority.revalidate_visible_directory());
            if let Err(error) = post_publication {
                let rollback = authority.rollback_exchange(&temp);
                return Err(config_save_rollback_error(error, rollback));
            }

            authority
                .cleanup_named_identity(
                    &temp.name,
                    expected,
                    &temp.display_path,
                    "replaced repository config",
                )
                .map_err(|error| {
                    KinError::Other(format!(
                        "repository config was atomically published at {}, but durable cleanup of \
                         the replaced config failed: {error}",
                        path.display()
                    ))
                })?;
        } else {
            rustix::fs::renameat_with(
                &authority.directory,
                &temp.name,
                &authority.directory,
                &authority.config_name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    KinError::Config(format!(
                        "repository config appeared while saving {}; refusing to replace it",
                        path.display()
                    ))
                } else {
                    KinError::io(path, std::io::Error::from(error))
                }
            })?;

            let post_publication = authority
                .sync()
                .and_then(|()| hook(ConfigSaveHookPoint::AfterPublication))
                .and_then(|()| {
                    authority.require_named_identity(
                        &authority.config_name,
                        temp.identity,
                        &authority.display_config,
                        "published repository config",
                    )
                })
                .and_then(|()| {
                    authority.require_named_absent(
                        &temp.name,
                        &temp.display_path,
                        "config temp file",
                    )
                })
                .and_then(|()| authority.revalidate_visible_directory());
            if let Err(error) = post_publication {
                let rollback = authority.rollback_new_publication(&temp);
                return Err(config_save_rollback_error(error, rollback));
            }
        }
        Ok(())
    })();

    if result.is_err() {
        let cleanup = authority.cleanup_exact_temp(&temp);
        if let Err(cleanup) = cleanup {
            return Err(KinError::Other(format!(
                "{}; exact config temp cleanup also failed: {cleanup}",
                result.expect_err("checked error")
            )));
        }
    }
    drop(temp.file);
    result
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
impl ConfigAuthority {
    fn cleanup_named_identity(
        &self,
        name: &std::ffi::OsStr,
        expected: ConfigFileIdentity,
        display: &Path,
        label: &str,
    ) -> Result<()> {
        self.require_named_identity(name, expected, display, label)?;
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
            .map_err(|error| KinError::io(display, std::io::Error::from(error)))?;
        self.sync()?;
        self.require_named_absent(name, display, label)
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn config_save_rollback_error(error: KinError, rollback: Result<()>) -> KinError {
    match rollback {
        Ok(()) => error,
        Err(rollback) => KinError::Other(format!(
            "{error}; capability-owned config rollback also failed: {rollback}"
        )),
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn open_config_directory_nofollow(path: &Path) -> Result<cap_std::fs::Dir> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(|descriptor| cap_std::fs::Dir::from_std_file(descriptor.into()))
    .map_err(|error| KinError::io(path, std::io::Error::from(error)))
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn config_directory_identity(directory: &cap_std::fs::Dir) -> std::io::Result<ConfigFileIdentity> {
    use cap_std::fs::MetadataExt as _;

    directory.dir_metadata().map(|metadata| ConfigFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn config_std_file_identity(file: &std::fs::File) -> std::io::Result<ConfigFileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other(
            "repository config object is not a regular file",
        ));
    }
    Ok(ConfigFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn inspect_config_file(
    directory: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    display: &Path,
    label: &str,
) -> Result<Option<ConfigFileIdentity>> {
    let descriptor = match rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(KinError::io(display, std::io::Error::from(error))),
    };
    let file = std::fs::File::from(descriptor);
    let identity = config_std_file_identity(&file).map_err(|error| KinError::io(display, error))?;
    let named = directory
        .symlink_metadata(name)
        .map_err(|error| KinError::io(display, error))?;
    if named.file_type().is_symlink() || !named.is_file() {
        return Err(KinError::Config(format!(
            "{label} at {} is not a regular no-follow file",
            display.display()
        )));
    }
    use cap_std::fs::MetadataExt as _;
    let named_identity = ConfigFileIdentity {
        device: named.dev(),
        inode: named.ino(),
    };
    if named_identity != identity {
        return Err(KinError::Config(format!(
            "{label} changed identity while opening {}",
            display.display()
        )));
    }
    Ok(Some(identity))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_config_path(directory: &tempfile::TempDir) -> std::path::PathBuf {
        let kin = directory.path().join(".kin");
        std::fs::create_dir(&kin).unwrap();
        kin.join("config.toml")
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    fn config_temp_entries(path: &Path) -> Vec<std::path::PathBuf> {
        let parent = path.parent().unwrap();
        std::fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|entry| {
                entry
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".config.toml.kin-tmp-"))
            })
            .collect()
    }

    fn sealed_remote(name: &str, url: &str) -> GitRemoteTransportConfig {
        GitRemoteTransportConfig {
            name: name.to_string(),
            fetch_urls: vec![url.to_string()],
            push_urls: Vec::new(),
            fetch_refspecs: Vec::new(),
            push_refspecs: Vec::new(),
        }
    }

    #[test]
    fn sealed_host_classification_reads_the_url_host_not_the_path() {
        assert_eq!(
            sealed_remote("origin", "https://github.invalid/acme/gitlab.git").host_kind(),
            RemoteHostKind::GitHub
        );
        assert_eq!(
            sealed_remote("origin", "https://gitlab.acme.invalid/team/repo.git").host_kind(),
            RemoteHostKind::GitLab
        );
        assert_eq!(
            sealed_remote("origin", "https://kinlab.ai/acme/repo.git").host_kind(),
            RemoteHostKind::KinLab
        );
        assert_eq!(
            sealed_remote("origin", "https://bitbucket.org/acme/repo.git").host_kind(),
            RemoteHostKind::Bitbucket
        );
    }

    #[test]
    fn sealed_tracking_resolves_a_publish_remote_in_git_precedence() {
        let mut git = GitCoexistenceConfig {
            remotes: vec![
                sealed_remote("origin", "https://github.invalid/acme/mirror.git"),
                sealed_remote("release", "https://github.invalid/acme/app.git"),
            ],
            branches: vec![GitBranchTrackingConfig {
                branch: "main".into(),
                remote: Some("origin".into()),
                merge_refs: vec!["refs/heads/main".into()],
                push_remote: Some("release".into()),
            }],
            remote_push_default: None,
            push_default: None,
            push_auto_setup_remote: None,
        };
        git.validate().unwrap();

        assert_eq!(
            git.publish_remote_for_branch(Some("main"))
                .map(|remote| remote.name.as_str()),
            Some("release")
        );

        git.branches[0].push_remote = None;
        assert_eq!(
            git.publish_remote_for_branch(Some("main"))
                .map(|remote| remote.name.as_str()),
            Some("origin")
        );

        git.remote_push_default = Some("release".into());
        assert_eq!(
            git.publish_remote_for_branch(Some("untracked"))
                .map(|remote| remote.name.as_str()),
            Some("release")
        );

        git.remote_push_default = None;
        assert!(git.publish_remote_for_branch(Some("untracked")).is_none());
        assert!(git.publish_remote_for_branch(None).is_none());
    }

    #[test]
    fn a_local_publish_target_resolves_no_transport_remote() {
        let git = GitCoexistenceConfig {
            remotes: vec![sealed_remote(
                "origin",
                "https://github.invalid/acme/app.git",
            )],
            branches: Vec::new(),
            remote_push_default: Some(".".into()),
            push_default: None,
            push_auto_setup_remote: None,
        };
        git.validate().unwrap();

        assert!(git.publish_remote_for_branch(Some("main")).is_none());
    }

    #[test]
    fn sealed_publish_url_prefers_the_push_url() {
        let remote = GitRemoteTransportConfig {
            name: "origin".into(),
            fetch_urls: vec!["https://github.invalid/acme/read.git".into()],
            push_urls: vec!["https://github.invalid/acme/write.git".into()],
            fetch_refspecs: Vec::new(),
            push_refspecs: Vec::new(),
        };
        assert_eq!(
            remote.publish_url(),
            Some("https://github.invalid/acme/write.git")
        );

        let fetch_only = sealed_remote("origin", "https://github.invalid/acme/read.git");
        assert_eq!(
            fetch_only.publish_url(),
            Some("https://github.invalid/acme/read.git")
        );

        let sealed_without_urls = GitRemoteTransportConfig {
            name: "archive".into(),
            fetch_urls: Vec::new(),
            push_urls: Vec::new(),
            fetch_refspecs: Vec::new(),
            push_refspecs: Vec::new(),
        };
        assert_eq!(sealed_without_urls.publish_url(), None);
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    fn named_config(name: &str) -> KinConfig {
        KinConfig {
            name: Some(name.to_string()),
            ..KinConfig::default()
        }
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    fn serialized_config(config: &KinConfig) -> Vec<u8> {
        toml::to_string_pretty(config).unwrap().into_bytes()
    }

    #[test]
    fn default_config_round_trips() {
        let config = KinConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: KinConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.default_branch, "main");
        assert!(parsed.auto_index);
        assert_eq!(parsed.context.default_budget, 8000);
        assert_eq!(parsed.world.preset, WorldPreset::Native);
        assert_eq!(
            parsed.execution.external_tools,
            ExternalToolExecutionPolicy::Workspace
        );
        assert!(parsed.remote.refs.is_empty());
        assert!(parsed.git.remotes.is_empty());
        assert!(parsed.git.branches.is_empty());
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);

        let config = KinConfig {
            name: Some("test-repo".to_string()),
            ..KinConfig::default()
        };
        config.save(&path).unwrap();

        let loaded = KinConfig::load(&path).unwrap();
        assert_eq!(loaded.name, Some("test-repo".to_string()));
        assert_eq!(loaded.default_branch, "main");
    }

    /// FIR-2504: the knobs an operator sets on a constrained host must be
    /// readable again after the process that read them is gone. A round trip
    /// through the real writer is the only proof of that.
    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn resource_knobs_survive_a_write_and_a_fresh_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);
        let mut config = KinConfig::default();
        assert_eq!(config.resources, ResourcesConfig::default());
        config.resources.profile = Some("ci".to_string());
        config.resources.embed_batch_size = Some(16);
        config.save(&path).unwrap();

        let loaded = KinConfig::load(&path).unwrap();
        assert_eq!(loaded.resources.profile.as_deref(), Some("ci"));
        assert_eq!(loaded.resources.embed_batch_size, Some(16));
        // A config that records nothing writes nothing, so an untouched repo
        // keeps a config with no [resources] table at all.
        let bare = toml::to_string_pretty(&KinConfig::default()).unwrap();
        assert!(!bare.contains("profile"), "{bare}");
        assert!(!bare.contains("embed_batch_size"), "{bare}");
    }

    /// A knob the runtime cannot act on is refused where the operator is
    /// watching. Both directions: load and save.
    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn an_unusable_resource_knob_is_refused_rather_than_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);

        let mut config = KinConfig::default();
        config.resources.profile = Some("bananas".to_string());
        let error = config
            .save(&path)
            .expect_err("an unknown profile must not be written");
        assert!(
            error.to_string().contains("unknown resource profile"),
            "{error}"
        );
        assert!(!path.exists(), "a refused save left a file behind");

        let mut zero = KinConfig::default();
        zero.resources.embed_batch_size = Some(0);
        let error = zero
            .save(&path)
            .expect_err("a zero batch would stall the queue, not slow it");
        assert!(error.to_string().contains("greater than 0"), "{error}");

        // The same rule on the way in, so a hand-edited file fails loud.
        std::fs::write(&path, "[resources]\nprofile = \"bananas\"\n").unwrap();
        let error = KinConfig::load(&path).expect_err("a hand-edited bad profile must fail loud");
        assert!(
            error.to_string().contains("unknown resource profile"),
            "{error}"
        );

        // Control: the four accepted names all load, so the check above can
        // fail for the right reason rather than because every value is refused.
        for name in RESOURCE_PROFILE_NAMES {
            std::fs::write(&path, format!("[resources]\nprofile = \"{name}\"\n")).unwrap();
            KinConfig::load(&path).unwrap_or_else(|error| panic!("{name} must load: {error}"));
        }
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn save_rejects_a_non_authority_path_without_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let error = KinConfig::default()
            .save(&path)
            .expect_err("config save must be scoped to a retained .kin authority");
        assert!(
            error.to_string().contains("direct child of .kin"),
            "unexpected path rejection: {error}"
        );
        assert!(!path.exists());
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn atomic_save_failure_after_temp_sync_preserves_the_complete_previous_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);
        let original = named_config("original");
        original.save(&path).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();
        let replacement = serialized_config(&named_config("replacement"));

        let error = save_config_atomically_with_hook(&path, &replacement, |point| {
            if point == ConfigSaveHookPoint::AfterTempSync {
                return Err(KinError::Other(
                    "injected failure after durable temp write".to_string(),
                ));
            }
            Ok(())
        })
        .expect_err("a prepublication failure must not replace config");

        assert!(error.to_string().contains("injected failure"));
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert!(config_temp_entries(&path).is_empty());
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn atomic_save_discards_a_torn_temp_without_exposing_partial_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);
        let original = named_config("original");
        original.save(&path).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();
        let replacement = serialized_config(&named_config("replacement-with-more-bytes"));

        let error = save_config_atomically_with_hook(&path, &replacement, |point| {
            if point == ConfigSaveHookPoint::AfterPartialTempWrite {
                return Err(KinError::Other(
                    "injected failure after partial config temp write".to_string(),
                ));
            }
            Ok(())
        })
        .expect_err("a torn temp must never become the named repository config");

        assert!(error.to_string().contains("partial config temp"));
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert!(config_temp_entries(&path).is_empty());
        KinConfig::load(&path).expect("the named config must remain complete and parseable");
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn atomic_save_restores_a_raced_config_name_instead_of_overwriting_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);
        let displaced = path.with_file_name("config.displaced");
        let original = named_config("original");
        original.save(&path).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();
        let replacement_bytes = b"name = \"raced-name\"\n".to_vec();
        let intended = serialized_config(&named_config("intended"));

        let error = save_config_atomically_with_hook(&path, &intended, |point| {
            if point == ConfigSaveHookPoint::BeforePublication {
                std::fs::rename(&path, &displaced).unwrap();
                std::fs::write(&path, &replacement_bytes).unwrap();
            }
            Ok(())
        })
        .expect_err("a raced config name must fail closed");

        assert!(error.to_string().contains("changed identity"));
        assert_eq!(std::fs::read(&path).unwrap(), replacement_bytes);
        assert_eq!(std::fs::read(&displaced).unwrap(), original_bytes);
        assert!(config_temp_entries(&path).is_empty());
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn atomic_save_rolls_back_inside_the_retained_parent_when_dot_kin_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);
        let kin = path.parent().unwrap().to_path_buf();
        let displaced_kin = dir.path().join(".kin.displaced");
        let original = named_config("original");
        original.save(&path).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();
        let intended = serialized_config(&named_config("intended"));
        let replacement_bytes = b"name = \"replacement-parent\"\n".to_vec();

        let error = save_config_atomically_with_hook(&path, &intended, |point| {
            if point == ConfigSaveHookPoint::AfterPublication {
                std::fs::rename(&kin, &displaced_kin).unwrap();
                std::fs::create_dir(&kin).unwrap();
                std::fs::write(kin.join("config.toml"), &replacement_bytes).unwrap();
            }
            Ok(())
        })
        .expect_err("a replaced .kin parent must fail closed");

        assert!(error.to_string().contains("replaced"));
        assert_eq!(std::fs::read(&path).unwrap(), replacement_bytes);
        assert_eq!(
            std::fs::read(displaced_kin.join("config.toml")).unwrap(),
            original_bytes
        );
        assert!(config_temp_entries(&displaced_kin.join("config.toml")).is_empty());
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn first_save_refuses_a_raced_destination_without_overwriting_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);
        let raced_bytes = b"name = \"raced-first-config\"\n".to_vec();
        let intended = serialized_config(&named_config("intended"));

        let error = save_config_atomically_with_hook(&path, &intended, |point| {
            if point == ConfigSaveHookPoint::BeforePublication {
                std::fs::write(&path, &raced_bytes).unwrap();
            }
            Ok(())
        })
        .expect_err("a raced first config must fail no-replace");

        assert!(error.to_string().contains("appeared while saving"));
        assert_eq!(std::fs::read(&path).unwrap(), raced_bytes);
        assert!(config_temp_entries(&path).is_empty());
    }

    #[test]
    fn partial_toml_uses_defaults() {
        let toml_str = r#"
name = "partial"
"#;
        let config: KinConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.name, Some("partial".to_string()));
        assert_eq!(config.default_branch, "main");
        assert!(config.auto_index);
        assert_eq!(config.world.preset, WorldPreset::Native);
        assert!(config.remote.refs.is_empty());
    }

    #[test]
    fn apply_world_preset_syncs_policy_knobs() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Native);

        assert_eq!(config.world.preset, WorldPreset::Native);
        assert_eq!(
            config.execution.external_tools,
            ExternalToolExecutionPolicy::Workspace
        );
    }

    #[test]
    fn remote_config_round_trips() {
        let mut config = KinConfig::default();
        config.remote.default = Some("origin".to_string());
        config.remote.refs.push(RemoteRefConfig {
            name: "origin".to_string(),
            host: RemoteHostKind::GitHub,
            transport: RemoteTransportKind::GitExport,
            url: Some("https://github.com/firelock-ai/kin.git".to_string()),
            publish_review_state: false,
            publish_proofs: false,
        });

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: KinConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.remote.default.as_deref(), Some("origin"));
        assert_eq!(parsed.remote.refs.len(), 1);
        assert_eq!(
            parsed.remote.refs[0].transport,
            RemoteTransportKind::GitExport
        );
    }

    #[test]
    fn remote_config_accepts_legacy_host_aliases() {
        let legacy = r#"
[remote]
default = "origin"

[[remote.refs]]
name = "origin"
host = "kin-hub"
transport = "native-kin"
"#;

        let parsed: KinConfig = toml::from_str(legacy).unwrap();
        assert_eq!(parsed.remote.refs.len(), 1);
        assert_eq!(parsed.remote.refs[0].host, RemoteHostKind::KinLab);
    }

    #[test]
    fn exact_git_coexistence_config_round_trips_and_redacts_debug() {
        let config = KinConfig {
            git: GitCoexistenceConfig {
                remotes: vec![GitRemoteTransportConfig {
                    name: "origin".to_string(),
                    fetch_urls: vec![
                        "https://example.invalid/org/repo.git".to_string(),
                        "https://mirror.example.invalid/org/repo.git".to_string(),
                    ],
                    push_urls: Vec::new(),
                    fetch_refspecs: vec![
                        "+refs/heads/*:refs/remotes/origin/*".to_string(),
                        "+refs/tags/*:refs/tags/*".to_string(),
                    ],
                    push_refspecs: vec!["refs/heads/main:refs/heads/main".to_string()],
                }],
                branches: vec![GitBranchTrackingConfig {
                    branch: "main".to_string(),
                    remote: Some("origin".to_string()),
                    merge_refs: vec!["refs/heads/main".to_string()],
                    push_remote: None,
                }],
                remote_push_default: Some("origin".to_string()),
                push_default: Some(GitPushDefault::Simple),
                push_auto_setup_remote: None,
            },
            ..KinConfig::default()
        };
        config.validate().unwrap();

        let encoded = toml::to_string_pretty(&config).unwrap();
        let decoded: KinConfig = toml::from_str(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.git, config.git);
        assert!(decoded.git.remotes[0].push_urls.is_empty());
        let debug = format!("{decoded:?}");
        assert!(!debug.contains("example.invalid"));
        assert!(!debug.contains("refs/heads/main"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn exact_git_coexistence_config_rejects_unsafe_urls_without_disclosure() {
        let config = KinConfig {
            git: GitCoexistenceConfig {
                remotes: vec![GitRemoteTransportConfig {
                    name: "origin".to_string(),
                    fetch_urls: vec![
                        "https://super-secret@example.invalid/private/repo.git".to_string()
                    ],
                    push_urls: Vec::new(),
                    fetch_refspecs: Vec::new(),
                    push_refspecs: Vec::new(),
                }],
                ..GitCoexistenceConfig::default()
            },
            ..KinConfig::default()
        };

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("safe exact subset"));
        assert!(!error.contains("super-secret"));
    }

    #[test]
    fn lsp_config_defaults_to_enabled_advisory() {
        let config = KinConfig::default();
        assert!(config.lsp.enabled);
        assert_eq!(config.lsp.proof_mode, LspProofMode::Advisory);
        assert!(config.lsp.providers.is_empty());
        assert!(config.lsp.required.is_empty());
        assert!(config.lsp.disabled.is_empty());
    }

    #[test]
    fn lsp_config_absent_section_uses_defaults() {
        let config: KinConfig = toml::from_str("name = \"no-lsp-section\"").unwrap();
        assert!(config.lsp.enabled);
        assert_eq!(config.lsp.proof_mode, LspProofMode::Advisory);
    }

    #[test]
    fn lsp_section_parses_typed_fields() {
        let toml_str = r#"
[lsp]
enabled = true
proof_mode = "citable"
required = ["rust", "python"]
disabled = ["go"]

[[lsp.providers]]
language = "python"
provider = "pylsp"
binaries = ["/opt/py/pylsp"]
args = ["--verbose"]
"#;
        let config: KinConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.lsp.proof_mode, LspProofMode::Citable);
        assert_eq!(config.lsp.required, vec!["rust", "python"]);
        assert_eq!(config.lsp.disabled, vec!["go"]);
        assert_eq!(config.lsp.providers.len(), 1);
        let over = &config.lsp.providers[0];
        assert_eq!(over.language, "python");
        assert_eq!(over.provider, "pylsp");
        assert_eq!(over.binaries, vec!["/opt/py/pylsp"]);
        assert_eq!(over.args.as_deref(), Some(&["--verbose".to_string()][..]));
    }

    #[test]
    fn lsp_proof_mode_display_round_trips() {
        assert_eq!(LspProofMode::Advisory.as_str(), "advisory");
        assert_eq!(LspProofMode::Citable.to_string(), "citable");
    }

    #[test]
    fn lsp_required_and_disabled_conflict_is_rejected() {
        let config = LspConfig {
            required: vec!["rust".to_string()],
            disabled: vec!["Rust".to_string()],
            ..LspConfig::default()
        };
        // Case-insensitive, fail-loud.
        assert!(config.validate().is_err());
    }

    #[test]
    fn load_rejects_contradictory_lsp_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[lsp]\nrequired = [\"rust\"]\ndisabled = [\"rust\"]\n",
        )
        .unwrap();
        // A contradictory config must fail at load, not silently degrade later.
        assert!(KinConfig::load(&path).is_err());
    }

    #[test]
    fn lsp_provider_override_round_trips_through_save() {
        // With a non-empty `providers` array-of-tables, `save()` only produces
        // valid TOML if `providers` is the last field of the section — this
        // exercises that ordering end to end.
        let dir = tempfile::tempdir().unwrap();
        let path = repository_config_path(&dir);
        let mut config = KinConfig::default();
        config.lsp.proof_mode = LspProofMode::Citable;
        config.lsp.required = vec!["rust".to_string()];
        config.lsp.providers = vec![LspProviderOverride {
            language: "rust".to_string(),
            provider: "rust-analyzer".to_string(),
            binaries: vec![],
            args: None,
        }];
        config.save(&path).unwrap();

        let loaded = KinConfig::load(&path).unwrap();
        assert_eq!(loaded.lsp.proof_mode, LspProofMode::Citable);
        assert_eq!(loaded.lsp.required, vec!["rust"]);
        assert_eq!(loaded.lsp.providers.len(), 1);
        assert_eq!(loaded.lsp.providers[0].provider, "rust-analyzer");
    }
}

/// One contract, held by every platform arm that publishes repository config.
///
/// The arms share no code below the namespace validation: Unix publishes with
/// directory-descriptor-relative renames and Windows with `ReplaceFileW` and
/// `MoveFileExW`. Gating this module on the whole supported-platform set
/// rather than on the Unix arm it grew from is what makes the Windows CI leg
/// execute these cases instead of only compiling them, which is the difference
/// between a Windows arm that builds and a Windows arm that is known to
/// behave.
#[cfg(all(
    test,
    any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        windows
    )
))]
mod capability_owned_config_replacement_tests {
    use super::*;

    const TEMP_PREFIXES: [&str; 2] = [".config.toml.kin-tmp-", ".config.toml.kin-replaced-"];

    fn published_config_path(directory: &tempfile::TempDir) -> std::path::PathBuf {
        let kin = directory.path().join(".kin");
        std::fs::create_dir(&kin).expect("create .kin");
        kin.join("config.toml")
    }

    fn staged_config_path(directory: &tempfile::TempDir) -> std::path::PathBuf {
        let stage = directory
            .path()
            .join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&stage).expect("create stage");
        stage.join("config.toml")
    }

    /// Every intermediate name this writer owns, still present after a save.
    ///
    /// A publication that leaves one behind has either not finished its
    /// cleanup or has published something other than what it staged, and both
    /// are failures of the same contract.
    fn residual_writer_entries(config: &Path) -> Vec<std::ffi::OsString> {
        let parent = config.parent().expect("config has a parent");
        std::fs::read_dir(parent)
            .expect("read config directory")
            .map(|entry| entry.expect("directory entry").file_name())
            .filter(|name| {
                let name = name.to_string_lossy().into_owned();
                TEMP_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
            })
            .collect()
    }

    #[test]
    fn a_first_publication_holds_exactly_the_bytes_it_was_given() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = published_config_path(&directory);

        save_config_atomically(&config, b"mode = \"native\"\n").expect("publish repository config");

        assert_eq!(
            std::fs::read(&config).expect("read published config"),
            b"mode = \"native\"\n",
            "publication must not alter, truncate, or re-encode the bytes it was given"
        );
        assert!(
            residual_writer_entries(&config).is_empty(),
            "publication left writer-owned intermediates behind: {:?}",
            residual_writer_entries(&config)
        );
    }

    #[test]
    fn replacing_a_published_config_leaves_only_the_new_bytes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = published_config_path(&directory);

        save_config_atomically(&config, b"auto_index = true\n").expect("publish first");
        save_config_atomically(&config, b"auto_index = false\n").expect("replace published");

        assert_eq!(
            std::fs::read(&config).expect("read replaced config"),
            b"auto_index = false\n",
            "the replacement must win outright, with no merged or appended remnant"
        );
        assert!(
            residual_writer_entries(&config).is_empty(),
            "replacement left the predecessor or a temp behind: {:?}",
            residual_writer_entries(&config)
        );
    }

    #[test]
    fn a_shorter_replacement_does_not_leave_a_longer_predecessor_tail() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = published_config_path(&directory);

        save_config_atomically(&config, b"auto_index = true\n# a long trailing comment\n")
            .expect("publish long");
        save_config_atomically(&config, b"x = 1\n").expect("publish short");

        // An in-place truncating writer is the failure mode this whole design
        // exists to exclude, and a surviving tail is how it shows up.
        assert_eq!(
            std::fs::read(&config).expect("read replaced config"),
            b"x = 1\n"
        );
    }

    #[test]
    fn an_initialization_stage_publishes_under_its_own_canonical_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = staged_config_path(&directory);

        save_config_atomically_scoped(
            &config,
            b"mode = \"native\"\n",
            ConfigAuthorityKind::InitializationStage,
        )
        .expect("publish staged repository config");

        assert_eq!(
            std::fs::read(&config).expect("read staged config"),
            b"mode = \"native\"\n"
        );
        assert!(residual_writer_entries(&config).is_empty());
    }

    /// The path shape admission actually hands the writer.
    ///
    /// `kin init` canonicalizes the stage root before it saves anything, and a
    /// canonical path on Windows carries the `\\?\` verbatim prefix. Every
    /// other case in this module passes a temporary path that was never
    /// canonicalized, so none of them exercises the shape the binary uses, and
    /// all of them pass on a platform where `kin init` fails at this exact
    /// file. That gap is why this case exists.
    ///
    /// Publication and the read-back are asserted as separate steps because
    /// they are separate calls that fail for different reasons. Admission
    /// reads this file again immediately afterwards to seal repository
    /// metadata, and that read reports the same path as the writer would, so a
    /// test that collapsed them could not say which one refused.
    #[test]
    fn a_canonical_stage_path_publishes_the_way_admission_calls_it() {
        let directory = tempfile::tempdir().expect("tempdir");
        let stage = directory
            .path()
            .join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&stage).expect("create stage");
        let config = std::fs::canonicalize(&stage)
            .expect("canonicalize stage")
            .join("config.toml");

        if let Err(error) = save_config_atomically_scoped(
            &config,
            b"mode = \"native\"\n",
            ConfigAuthorityKind::InitializationStage,
        ) {
            panic!("publishing through a canonical stage path refused: {error}");
        }

        match std::fs::read(&config) {
            Ok(published) => assert_eq!(published, b"mode = \"native\"\n"),
            Err(error) => panic!(
                "the published config could not be read back, which is the call that seals \
                 repository metadata: {error}"
            ),
        }
        assert!(
            residual_writer_entries(&config).is_empty(),
            "publication left writer-owned intermediates behind: {:?}",
            residual_writer_entries(&config)
        );
    }

    #[test]
    fn a_stage_directory_that_is_not_a_canonical_uuid_v4_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let stage = directory.path().join(".kin.init-not-a-uuid");
        std::fs::create_dir(&stage).expect("create stage");
        let config = stage.join("config.toml");

        let error = save_config_atomically_scoped(
            &config,
            b"mode = \"native\"\n",
            ConfigAuthorityKind::InitializationStage,
        )
        .expect_err("a non-canonical stage name is not an authority");
        assert!(
            error.to_string().contains(".kin.init-<uuid-v4>"),
            "the refusal must name the shape it required: {error}"
        );
        assert!(
            !config.exists(),
            "a refused save must not create the file it refused to publish"
        );
    }

    #[test]
    fn a_config_outside_the_owned_namespace_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let elsewhere = directory.path().join("notes.toml");

        let error = save_config_atomically(&elsewhere, b"x = 1\n")
            .expect_err("the writer owns one name and no other");
        assert!(
            error.to_string().contains("only owns .kin/config.toml"),
            "unexpected refusal: {error}"
        );
        assert!(!elsewhere.exists());
    }

    #[test]
    fn a_config_whose_parent_is_not_dot_kin_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let parent = directory.path().join("config");
        std::fs::create_dir(&parent).expect("create parent");
        let config = parent.join("config.toml");

        let error = save_config_atomically(&config, b"x = 1\n")
            .expect_err("only .kin carries repository config authority");
        assert!(
            error.to_string().contains("direct child of .kin"),
            "unexpected refusal: {error}"
        );
        assert!(!config.exists());
    }

    #[test]
    fn a_relative_config_path_is_refused_before_any_file_is_created() {
        let error = save_config_atomically(Path::new(".kin/config.toml"), b"x = 1\n")
            .expect_err("a relative path names no directory this writer can retain");
        assert!(
            error.to_string().contains("must be absolute"),
            "unexpected refusal: {error}"
        );
    }

    #[test]
    fn a_directory_standing_where_the_config_belongs_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = published_config_path(&directory);
        std::fs::create_dir(&config).expect("directory at the config name");

        let error = save_config_atomically(&config, b"x = 1\n")
            .expect_err("a directory is not a config this writer may replace");
        // The arms word this differently because they discover it at different
        // calls, so what is pinned here is the cause each one must name, not
        // one arm's sentence.
        assert!(
            error.to_string().contains("not a regular"),
            "unexpected refusal: {error}"
        );
        assert!(
            config.is_dir(),
            "a refused save must leave what it found untouched"
        );
    }

    #[test]
    fn an_absent_authority_directory_is_refused_rather_than_created() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = directory.path().join(".kin").join("config.toml");

        save_config_atomically(&config, b"x = 1\n")
            .expect_err("the writer publishes into an authority, it does not invent one");
        assert!(
            !directory.path().join(".kin").exists(),
            "a refused save must not create the authority directory"
        );
    }

    #[test]
    fn a_refused_save_leaves_the_previously_published_bytes_in_place() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = published_config_path(&directory);
        save_config_atomically(&config, b"auto_index = true\n").expect("publish first");

        let wrong_name = config
            .parent()
            .expect("config parent")
            .join("config.toml.bak");
        save_config_atomically(&wrong_name, b"auto_index = false\n")
            .expect_err("the writer owns one name and no other");

        assert_eq!(
            std::fs::read(&config).expect("read published config"),
            b"auto_index = true\n"
        );
        assert!(residual_writer_entries(&config).is_empty());
    }

    /// Rollback is why the Windows arm publishes with `ReplaceFileW` instead
    /// of the atomic replacing move, and why the Unix arm exchanges rather
    /// than renames over. No ordinary save reaches it, so without an injected
    /// failure the justification would ship and the behaviour would not.
    #[test]
    fn a_failure_after_publication_puts_the_predecessor_back() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = published_config_path(&directory);
        save_config_atomically(&config, b"auto_index = true\n").expect("publish predecessor");

        let error = save_config_atomically_with_hook(&config, b"auto_index = false\n", |point| {
            if point == ConfigSaveHookPoint::AfterPublication {
                return Err(KinError::Other(
                    "injected failure after publication".to_string(),
                ));
            }
            Ok(())
        })
        .expect_err("a post-publication failure must not leave the replacement as authority");

        assert!(
            error
                .to_string()
                .contains("injected failure after publication"),
            "the original failure must survive the rollback, not be replaced by it: {error}"
        );
        assert_eq!(
            std::fs::read(&config).expect("read the rolled-back config"),
            b"auto_index = true\n",
            "the predecessor's bytes must be authority again"
        );
        assert!(
            residual_writer_entries(&config).is_empty(),
            "a rolled-back replacement left writer-owned entries behind: {:?}",
            residual_writer_entries(&config)
        );
    }

    #[test]
    fn a_failure_after_a_first_publication_leaves_the_name_as_it_found_it() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = published_config_path(&directory);

        let error = save_config_atomically_with_hook(&config, b"auto_index = true\n", |point| {
            if point == ConfigSaveHookPoint::AfterPublication {
                return Err(KinError::Other(
                    "injected failure after first publication".to_string(),
                ));
            }
            Ok(())
        })
        .expect_err("a post-publication failure must not leave a config nobody agreed to");

        assert!(error
            .to_string()
            .contains("injected failure after first publication"));
        assert!(
            !config.exists(),
            "a rolled-back first publication must leave the name absent, not half-published"
        );
        assert!(
            residual_writer_entries(&config).is_empty(),
            "a rolled-back first publication left writer-owned entries behind: {:?}",
            residual_writer_entries(&config)
        );
    }
}
