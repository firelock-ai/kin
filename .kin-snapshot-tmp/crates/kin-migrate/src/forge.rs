// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Git forge detection, URL parsing, and authentication for migration.
//!
//! Supports GitHub, GitLab (including self-hosted instances), and Bitbucket
//! (Cloud and Server). Detection works on HTTPS, SSH, and Git protocol URLs.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The kind of Git forge hosting the repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForgeKind {
    GitHub,
    GitLab,
    Bitbucket,
    /// A plain Git server with no forge-specific features.
    Generic,
}

impl ForgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Bitbucket => "bitbucket",
            Self::Generic => "generic",
        }
    }

    /// Environment variable name for the forge's authentication token.
    pub fn token_env_var(&self) -> Option<&'static str> {
        match self {
            Self::GitHub => Some("GITHUB_TOKEN"),
            Self::GitLab => Some("GITLAB_TOKEN"),
            Self::Bitbucket => Some("BITBUCKET_TOKEN"),
            Self::Generic => None,
        }
    }
}

impl fmt::Display for ForgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Parsed information about a forge-hosted repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeInfo {
    /// Detected forge type.
    pub kind: ForgeKind,
    /// Forge host (e.g., "github.com", "gitlab.mycompany.com").
    pub host: String,
    /// Owner or namespace (may contain slashes for GitLab subgroups).
    pub owner: String,
    /// Repository name (without `.git` suffix).
    pub repo: String,
    /// The original URL as provided.
    pub original_url: String,
    /// Whether this is an SSH-style URL.
    pub is_ssh: bool,
}

impl ForgeInfo {
    /// Construct an HTTPS clone URL, optionally embedding an auth token.
    pub fn https_clone_url(&self, token: Option<&str>) -> String {
        let repo_path = if self.owner.is_empty() {
            self.repo.clone()
        } else {
            format!("{}/{}", self.owner, self.repo)
        };

        match (self.kind, token) {
            (ForgeKind::GitHub, Some(t)) => {
                format!("https://x-access-token:{t}@{}/{repo_path}.git", self.host)
            }
            (ForgeKind::GitLab, Some(t)) => {
                format!("https://oauth2:{t}@{}/{repo_path}.git", self.host)
            }
            (ForgeKind::Bitbucket, Some(t)) => {
                format!("https://x-token-auth:{t}@{}/{repo_path}.git", self.host)
            }
            _ => format!("https://{}/{repo_path}.git", self.host),
        }
    }

    /// Resolve an auth token from the environment for this forge.
    pub fn resolve_token_from_env(&self) -> Option<String> {
        self.kind
            .token_env_var()
            .and_then(|var| std::env::var(var).ok())
            .filter(|v| !v.is_empty())
    }

    /// Convert to the corresponding `RemoteHostKind` for kin-core config.
    pub fn to_remote_host_kind(&self) -> kin_core::RemoteHostKind {
        match self.kind {
            ForgeKind::GitHub => kin_core::RemoteHostKind::GitHub,
            ForgeKind::GitLab => kin_core::RemoteHostKind::GitLab,
            ForgeKind::Bitbucket => kin_core::RemoteHostKind::Bitbucket,
            // Generic forges map to GitHub as the default git-export host.
            ForgeKind::Generic => kin_core::RemoteHostKind::GitHub,
        }
    }
}

/// Detect the forge kind and parse repository coordinates from a URL.
///
/// Handles these URL formats:
/// - `https://github.com/owner/repo.git`
/// - `https://gitlab.com/group/subgroup/repo.git`
/// - `https://bitbucket.org/workspace/repo.git`
/// - `git@github.com:owner/repo.git`
/// - `ssh://git@gitlab.mycompany.com/group/repo.git`
/// - `https://gitlab.mycompany.com/group/repo` (self-hosted)
/// - `https://my-server.example.com/repo.git` (generic)
///
/// Returns `None` if the URL cannot be parsed as a Git repository URL.
pub fn detect_forge(url: &str) -> Option<ForgeInfo> {
    // Try SSH-style first: git@host:path.git
    if let Some(info) = parse_ssh_url(url) {
        return Some(info);
    }

    // Try ssh:// protocol URLs.
    if let Some(info) = parse_ssh_protocol_url(url) {
        return Some(info);
    }

    // Try HTTPS/HTTP URLs.
    parse_https_url(url)
}

/// Parse `git@host:owner/repo.git` style SSH URLs.
fn parse_ssh_url(url: &str) -> Option<ForgeInfo> {
    // Match: git@host:path.git or user@host:path.git
    let at_pos = url.find('@')?;
    let colon_pos = url[at_pos..].find(':').map(|p| p + at_pos)?;

    // Ensure no slashes before the colon (that would be ssh:// style).
    if url[..colon_pos].contains("//") {
        return None;
    }

    let host = &url[at_pos + 1..colon_pos];
    let path = url[colon_pos + 1..].trim_end_matches(".git");

    if host.is_empty() || path.is_empty() {
        return None;
    }

    let kind = detect_kind_from_host(host);
    let (owner, repo) = split_owner_repo(path, kind);

    Some(ForgeInfo {
        kind,
        host: host.to_string(),
        owner,
        repo,
        original_url: url.to_string(),
        is_ssh: true,
    })
}

/// Parse `ssh://git@host/path.git` style URLs.
fn parse_ssh_protocol_url(url: &str) -> Option<ForgeInfo> {
    let rest = url.strip_prefix("ssh://")?;
    let at_pos = rest.find('@')?;
    let after_at = &rest[at_pos + 1..];

    // host/path
    let slash_pos = after_at.find('/')?;
    let host = &after_at[..slash_pos];
    let path = after_at[slash_pos + 1..].trim_end_matches(".git");

    if host.is_empty() || path.is_empty() {
        return None;
    }

    let kind = detect_kind_from_host(host);
    let (owner, repo) = split_owner_repo(path, kind);

    Some(ForgeInfo {
        kind,
        host: host.to_string(),
        owner,
        repo,
        original_url: url.to_string(),
        is_ssh: true,
    })
}

/// Parse `https://host/path.git` or `http://host/path.git` style URLs.
fn parse_https_url(url: &str) -> Option<ForgeInfo> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;

    // Strip any embedded credentials (user:pass@host).
    let rest = if let Some(at_pos) = rest.find('@') {
        // Only strip if the @ is before the first slash (part of host, not path).
        let slash_pos = rest.find('/').unwrap_or(rest.len());
        if at_pos < slash_pos {
            &rest[at_pos + 1..]
        } else {
            rest
        }
    } else {
        rest
    };

    // host/path
    let slash_pos = rest.find('/')?;
    let host = &rest[..slash_pos];
    let path = rest[slash_pos + 1..]
        .trim_end_matches(".git")
        .trim_end_matches('/');

    if host.is_empty() || path.is_empty() {
        return None;
    }

    let kind = detect_kind_from_host(host);
    let (owner, repo) = split_owner_repo(path, kind);

    Some(ForgeInfo {
        kind,
        host: host.to_string(),
        owner,
        repo,
        original_url: url.to_string(),
        is_ssh: false,
    })
}

/// Detect forge kind from hostname.
///
/// Recognizes well-known SaaS hosts and common self-hosted patterns:
/// - `github.com` → GitHub
/// - `gitlab.com`, `*.gitlab.*`, hostnames containing "gitlab" → GitLab
/// - `bitbucket.org`, hostnames containing "bitbucket" → Bitbucket
/// - Everything else → Generic
fn detect_kind_from_host(host: &str) -> ForgeKind {
    let lower = host.to_lowercase();

    if lower == "github.com" || lower.ends_with(".github.com") {
        ForgeKind::GitHub
    } else if lower == "gitlab.com" || lower.ends_with(".gitlab.com") || lower.contains("gitlab") {
        // Self-hosted GitLab instances often use "gitlab" in the hostname.
        ForgeKind::GitLab
    } else if lower == "bitbucket.org"
        || lower.ends_with(".bitbucket.org")
        || lower.contains("bitbucket")
    {
        ForgeKind::Bitbucket
    } else {
        ForgeKind::Generic
    }
}

/// Split a path into (owner, repo), handling forge-specific conventions.
///
/// GitLab supports nested groups: `group/subgroup/project` →
/// owner="group/subgroup", repo="project".
///
/// GitHub and Bitbucket are always `owner/repo`.
fn split_owner_repo(path: &str, kind: ForgeKind) -> (String, String) {
    match kind {
        ForgeKind::GitLab => {
            // GitLab: last path segment is the repo, everything before is the namespace.
            if let Some(last_slash) = path.rfind('/') {
                let owner = &path[..last_slash];
                let repo = &path[last_slash + 1..];
                (owner.to_string(), repo.to_string())
            } else {
                (String::new(), path.to_string())
            }
        }
        _ => {
            // GitHub, Bitbucket, Generic: first segment is owner, second is repo.
            if let Some(slash_pos) = path.find('/') {
                let owner = &path[..slash_pos];
                let repo = &path[slash_pos + 1..];
                // For Generic, the repo might contain additional path segments;
                // take only the last component.
                let repo = repo.rsplit('/').next().unwrap_or(repo);
                (owner.to_string(), repo.to_string())
            } else {
                (String::new(), path.to_string())
            }
        }
    }
}

/// Configure a Kin remote after cloning from a forge.
///
/// Sets up the `origin` remote in `.kin/config.toml` with the correct
/// host kind and transport for the detected forge.
pub fn configure_forge_remote(
    layout: &kin_core::KinLayout,
    forge: &ForgeInfo,
) -> crate::Result<()> {
    let config_path = layout.config_path();
    let mut config = kin_core::KinConfig::load_or_default(&config_path)
        .map_err(|e| crate::MigrateError::Init(e.to_string()))?;

    let remote_ref = kin_core::RemoteRefConfig {
        name: "origin".to_string(),
        host: forge.to_remote_host_kind(),
        transport: kin_core::RemoteTransportKind::GitExport,
        url: Some(forge.original_url.clone()),
        publish_review_state: false,
        publish_proofs: false,
    };

    if let Some(existing) = config.remote.refs.iter_mut().find(|r| r.name == "origin") {
        *existing = remote_ref;
    } else {
        config.remote.refs.push(remote_ref);
    }
    config.remote.default = Some("origin".to_string());
    config
        .save(&config_path)
        .map_err(|e| crate::MigrateError::Init(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- GitHub URL detection ---

    #[test]
    fn github_https_url() {
        let info = detect_forge("https://github.com/user/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::GitHub);
        assert_eq!(info.host, "github.com");
        assert_eq!(info.owner, "user");
        assert_eq!(info.repo, "repo");
        assert!(!info.is_ssh);
    }

    #[test]
    fn github_https_url_without_dot_git() {
        let info = detect_forge("https://github.com/user/repo").unwrap();
        assert_eq!(info.kind, ForgeKind::GitHub);
        assert_eq!(info.repo, "repo");
    }

    #[test]
    fn github_ssh_url() {
        let info = detect_forge("git@github.com:org/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::GitHub);
        assert_eq!(info.host, "github.com");
        assert_eq!(info.owner, "org");
        assert_eq!(info.repo, "repo");
        assert!(info.is_ssh);
    }

    // --- GitLab URL detection ---

    #[test]
    fn gitlab_https_url() {
        let info = detect_forge("https://gitlab.com/user/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::GitLab);
        assert_eq!(info.host, "gitlab.com");
        assert_eq!(info.owner, "user");
        assert_eq!(info.repo, "repo");
    }

    #[test]
    fn gitlab_nested_groups() {
        let info = detect_forge("https://gitlab.com/group/subgroup/project.git").unwrap();
        assert_eq!(info.kind, ForgeKind::GitLab);
        assert_eq!(info.owner, "group/subgroup");
        assert_eq!(info.repo, "project");
    }

    #[test]
    fn gitlab_deeply_nested_groups() {
        let info = detect_forge("https://gitlab.com/a/b/c/d/repo").unwrap();
        assert_eq!(info.kind, ForgeKind::GitLab);
        assert_eq!(info.owner, "a/b/c/d");
        assert_eq!(info.repo, "repo");
    }

    #[test]
    fn gitlab_self_hosted() {
        let info = detect_forge("https://gitlab.mycompany.com/team/project.git").unwrap();
        assert_eq!(info.kind, ForgeKind::GitLab);
        assert_eq!(info.host, "gitlab.mycompany.com");
        assert_eq!(info.owner, "team");
        assert_eq!(info.repo, "project");
    }

    #[test]
    fn gitlab_ssh_url() {
        let info = detect_forge("git@gitlab.com:group/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::GitLab);
        assert_eq!(info.owner, "group");
        assert_eq!(info.repo, "repo");
        assert!(info.is_ssh);
    }

    #[test]
    fn gitlab_ssh_protocol_url() {
        let info = detect_forge("ssh://git@gitlab.com/group/subgroup/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::GitLab);
        assert_eq!(info.owner, "group/subgroup");
        assert_eq!(info.repo, "repo");
        assert!(info.is_ssh);
    }

    // --- Bitbucket URL detection ---

    #[test]
    fn bitbucket_https_url() {
        let info = detect_forge("https://bitbucket.org/workspace/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::Bitbucket);
        assert_eq!(info.host, "bitbucket.org");
        assert_eq!(info.owner, "workspace");
        assert_eq!(info.repo, "repo");
    }

    #[test]
    fn bitbucket_ssh_url() {
        let info = detect_forge("git@bitbucket.org:workspace/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::Bitbucket);
        assert_eq!(info.owner, "workspace");
        assert_eq!(info.repo, "repo");
        assert!(info.is_ssh);
    }

    #[test]
    fn bitbucket_self_hosted() {
        let info = detect_forge("https://bitbucket.internal.co/scm/proj/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::Bitbucket);
        assert_eq!(info.host, "bitbucket.internal.co");
    }

    // --- Generic URL detection ---

    #[test]
    fn generic_https_url_with_dot_git() {
        let info = detect_forge("https://my-server.example.com/org/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::Generic);
        assert_eq!(info.host, "my-server.example.com");
        assert_eq!(info.owner, "org");
        assert_eq!(info.repo, "repo");
    }

    #[test]
    fn generic_ssh_url() {
        let info = detect_forge("git@my-server.example.com:org/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::Generic);
        assert!(info.is_ssh);
    }

    // --- Edge cases ---

    #[test]
    fn url_with_embedded_credentials() {
        let info = detect_forge("https://x-access-token:ghp_abc@github.com/user/repo.git").unwrap();
        assert_eq!(info.kind, ForgeKind::GitHub);
        assert_eq!(info.host, "github.com");
        assert_eq!(info.owner, "user");
        assert_eq!(info.repo, "repo");
    }

    #[test]
    fn url_with_trailing_slash() {
        let info = detect_forge("https://gitlab.com/group/repo/").unwrap();
        assert_eq!(info.kind, ForgeKind::GitLab);
        assert_eq!(info.repo, "repo");
    }

    #[test]
    fn not_a_url_returns_none() {
        assert!(detect_forge("just-a-name").is_none());
        assert!(detect_forge("").is_none());
    }

    // --- Clone URL construction ---

    #[test]
    fn github_authenticated_clone_url() {
        let info = detect_forge("https://github.com/user/repo").unwrap();
        let url = info.https_clone_url(Some("ghp_token123"));
        assert_eq!(
            url,
            "https://x-access-token:ghp_token123@github.com/user/repo.git"
        );
    }

    #[test]
    fn gitlab_authenticated_clone_url() {
        let info = detect_forge("https://gitlab.com/group/repo").unwrap();
        let url = info.https_clone_url(Some("glpat_token123"));
        assert_eq!(
            url,
            "https://oauth2:glpat_token123@gitlab.com/group/repo.git"
        );
    }

    #[test]
    fn bitbucket_authenticated_clone_url() {
        let info = detect_forge("https://bitbucket.org/workspace/repo").unwrap();
        let url = info.https_clone_url(Some("bb_token123"));
        assert_eq!(
            url,
            "https://x-token-auth:bb_token123@bitbucket.org/workspace/repo.git"
        );
    }

    #[test]
    fn unauthenticated_clone_url() {
        let info = detect_forge("https://github.com/user/repo").unwrap();
        let url = info.https_clone_url(None);
        assert_eq!(url, "https://github.com/user/repo.git");
    }

    // --- ForgeKind token env vars ---

    #[test]
    fn forge_kind_token_env_vars() {
        assert_eq!(ForgeKind::GitHub.token_env_var(), Some("GITHUB_TOKEN"));
        assert_eq!(ForgeKind::GitLab.token_env_var(), Some("GITLAB_TOKEN"));
        assert_eq!(
            ForgeKind::Bitbucket.token_env_var(),
            Some("BITBUCKET_TOKEN")
        );
        assert_eq!(ForgeKind::Generic.token_env_var(), None);
    }

    // --- ForgeKind display ---

    #[test]
    fn forge_kind_display() {
        assert_eq!(ForgeKind::GitHub.to_string(), "github");
        assert_eq!(ForgeKind::GitLab.to_string(), "gitlab");
        assert_eq!(ForgeKind::Bitbucket.to_string(), "bitbucket");
        assert_eq!(ForgeKind::Generic.to_string(), "generic");
    }

    // --- Serialization ---

    #[test]
    fn forge_info_serializes() {
        let info = detect_forge("https://gitlab.com/group/subgroup/repo.git").unwrap();
        let json = serde_json::to_string(&info).unwrap();
        let parsed: ForgeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kind, ForgeKind::GitLab);
        assert_eq!(parsed.owner, "group/subgroup");
        assert_eq!(parsed.repo, "repo");
    }
}
