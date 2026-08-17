// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Who a newly minted change is attributed to.
//!
//! Authorship is provenance, and provenance is authority Kin publishes once and
//! cannot correct later without rewriting history. So this module resolves an
//! identity from configuration a person actually set, reports which surface it
//! came from, and refuses when nothing is set rather than standing a placeholder
//! in for a person.
//!
//! A placeholder is worse than a refusal precisely because it succeeds: the
//! commit lands, the record looks complete, and the fabrication is only visible
//! once a history exists that nobody can attribute. Git has the same failure
//! mode wearing a different name, synthesizing `user@host.local` from the local
//! account and hostname when no email is configured, so a value shaped like that
//! is treated as unresolved rather than accepted.

use std::fmt;
use std::path::Path;

use crate::config::KinConfig;
use crate::error::KinError;
use crate::layout::KinLayout;

/// Which configured surface supplied the identity a change is stamped with.
///
/// Recorded rather than discarded so a reader can tell a repository-scoped
/// identity from a host-wide one, and so `kin doctor` can name the surface a
/// user would have to edit to change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// `default_author` in the repository's own `.kin/config.toml`.
    KinConfig,
    /// `user.name` / `user.email` set in this repository's or worktree's Git
    /// configuration.
    GitRepository,
    /// `user.name` / `user.email` merged in from a scope wider than this
    /// repository: the user's global file, the system file, the git
    /// installation, or a `GIT_CONFIG_*` override.
    GitGlobal,
}

impl IdentitySource {
    /// A stable machine-readable name for the surface, safe to assert on.
    pub fn id(self) -> &'static str {
        match self {
            Self::KinConfig => "kin-config",
            Self::GitRepository => "git-repo",
            Self::GitGlobal => "git-global",
        }
    }

    /// How the surface is named to a person.
    pub fn label(self) -> &'static str {
        match self {
            Self::KinConfig => "kin config default_author",
            Self::GitRepository => "git repository config",
            Self::GitGlobal => "git global config",
        }
    }
}

impl fmt::Display for IdentitySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// One resolved identity plus the surface it was resolved from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitIdentity {
    /// The author string a change record carries, `Name <email>` when both
    /// halves are configured.
    pub author: String,
    /// The surface `author` came from.
    pub source: IdentitySource,
}

/// What a person has to do so a commit can be attributed to them.
///
/// One constant so the refusal, the `kin doctor` row, and the tests that hold
/// them to it cannot drift apart into three different sets of instructions.
pub const IDENTITY_REMEDIATION: &str = "Set your Git identity:\n  \
     git config --global user.name \"Your Name\"\n  \
     git config --global user.email \"you@example.com\"\n\
     Or set a Kin-specific author in .kin/config.toml:\n  \
     default_author = \"Your Name <you@example.com>\"";

/// The message a mint refuses with when nobody can be named as its author.
pub fn unresolved_identity_message() -> String {
    format!(
        "kin has no author identity to record for this change.\n\n\
         Authorship is provenance. A change attributed to nobody cannot support review \
         attribution, blame, or audit, and it cannot be corrected later without rewriting \
         history, so kin refuses to invent one.\n\n\
         {IDENTITY_REMEDIATION}"
    )
}

/// Resolve who a newly minted change in this repository is authored by.
///
/// Order is most specific first: the repository's own Kin setting, then the Git
/// identity Git itself would use here (repository scope before host scope), then
/// refusal. There is no fourth step, and no synthesized value is accepted at any
/// step.
pub fn resolve_commit_identity(layout: &KinLayout) -> Result<CommitIdentity, KinError> {
    if let Some(author) = kin_config_author(layout) {
        return Ok(CommitIdentity {
            author,
            source: IdentitySource::KinConfig,
        });
    }
    if let Some(identity) = git_identity(layout.working_dir()) {
        return Ok(identity);
    }
    Err(KinError::Config(unresolved_identity_message()))
}

/// The explicit Kin-specific author for this repository, when one is set and
/// usable.
///
/// A config this cannot parse is not an identity, and must not become one: an
/// unreadable config yields no author and the caller falls through to Git
/// rather than inheriting a half-read value.
fn kin_config_author(layout: &KinLayout) -> Option<String> {
    let config = KinConfig::load_or_default(&layout.config_path()).ok()?;
    usable_author(config.default_author.as_deref()?)
}

/// The identity Git itself would attribute a commit in `working_dir` to.
///
/// The repository's merged configuration already layers host scope underneath
/// repository scope, so one read answers both and the winning section reports
/// which scope actually supplied the value. When there is no Git repository here
/// at all, which is the ordinary shape of a native Kin repository, the host
/// scopes are read on their own.
fn git_identity(working_dir: &Path) -> Option<CommitIdentity> {
    match gix::open(working_dir) {
        Ok(repository) => {
            let snapshot = repository.config_snapshot();
            identity_from_config(snapshot.plumbing())
        }
        Err(_) => {
            let globals = gix::config::File::from_globals().ok()?;
            identity_from_config(&globals)
        }
    }
}

/// Read `user.name` and `user.email` out of one merged configuration.
///
/// Both halves are required. Git will happily commit with only one of them by
/// synthesizing the other from the local account and hostname, which is the
/// fabrication this whole module exists to keep out of history, so a half-set
/// identity is reported as no identity and the remediation names both commands.
fn identity_from_config(config: &gix::config::File<'_>) -> Option<CommitIdentity> {
    let name = config_field(config, "name")?;
    let email = config_field(config, "email")?;
    if is_fabricated_email(&email) {
        return None;
    }
    Some(CommitIdentity {
        author: format!("{name} <{email}>"),
        source: user_scope(config),
    })
}

/// One `user.*` string, trimmed and checked for usability.
fn config_field(config: &gix::config::File<'_>, value_name: &str) -> Option<String> {
    let raw = config.string_by("user", None, value_name)?;
    usable_field(&raw.to_string())
}

/// Which scope set the `user` section value that won.
///
/// Sections merge in precedence order, so the last one carrying a value is the
/// one Git would use. Scope wider than this repository is reported as global
/// without splitting further: a user editing it is editing something outside the
/// repository either way, and the distinction between their file and the
/// system's does not change what they resolve.
fn user_scope(config: &gix::config::File<'_>) -> IdentitySource {
    let mut winner = None;
    if let Some(sections) = config.sections_by_name("user") {
        for section in sections {
            if section.contains_value_name("name") || section.contains_value_name("email") {
                winner = Some(section.meta().source);
            }
        }
    }
    match winner {
        Some(gix::config::Source::Local | gix::config::Source::Worktree) => {
            IdentitySource::GitRepository
        }
        _ => IdentitySource::GitGlobal,
    }
}

/// A configured field, or `None` when what is configured names nobody.
fn usable_field(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return None;
    }
    Some(trimmed.to_string())
}

/// A configured `Name <email>` author, or `None` when it names nobody.
fn usable_author(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (name, email) = split_author(trimmed);
    usable_field(name)?;
    if let Some(email) = email {
        usable_field(email)?;
        if is_fabricated_email(email) {
            return None;
        }
    }
    Some(trimmed.to_string())
}

/// Split `Name <email>` into its halves, tolerating an author with no email.
fn split_author(raw: &str) -> (&str, Option<&str>) {
    match (raw.find('<'), raw.rfind('>')) {
        (Some(open), Some(close)) if close > open => {
            (raw[..open].trim(), Some(raw[open + 1..close].trim()))
        }
        _ => (raw, None),
    }
}

/// Whether an address is the one Git invents when none is configured.
///
/// Git builds `<account>@<hostname>` and macOS hands it a `.local` hostname, so
/// the whole class is rejected rather than the exact string. This workspace has
/// already published a commit under such an address; it reads as a real identity
/// right up until someone tries to reach the person it names.
fn is_fabricated_email(email: &str) -> bool {
    email.trim().to_ascii_lowercase().ends_with(".local")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::EnvVarGuard;
    use std::fs;
    use tempfile::tempdir;

    /// A repository whose `.kin` exists and whose Git configuration this test
    /// controls outright.
    ///
    /// Every scope Git would read is pinned: the system file is refused, the
    /// global file is redirected into the fixture, and the repository file is
    /// written directly. A test that left any of those to the host would pass or
    /// fail on whoever ran it.
    struct Fixture {
        _dir: tempfile::TempDir,
        layout: KinLayout,
        working_dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempdir().expect("temp dir");
            let working_dir = dir.path().join("repo");
            fs::create_dir_all(working_dir.join(".kin")).expect("create .kin");
            let layout = KinLayout::new(working_dir.join(".kin"));
            fs::write(dir.path().join("global.gitconfig"), "").expect("write global config");
            Self {
                _dir: dir,
                layout,
                working_dir,
            }
        }

        fn init_git(&self) {
            let status = std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&self.working_dir)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", self.global_config())
                .status()
                .expect("git init");
            assert!(status.success(), "git init failed");
        }

        fn global_config(&self) -> std::path::PathBuf {
            self._dir.path().join("global.gitconfig")
        }

        fn set_repo_identity(&self, name: &str, email: &str) {
            self.git_config(&self.working_dir, name, email);
        }

        fn set_global_identity(&self, name: &str, email: &str) {
            fs::write(
                self.global_config(),
                format!("[user]\n\tname = {name}\n\temail = {email}\n"),
            )
            .expect("write global identity");
        }

        fn git_config(&self, dir: &Path, name: &str, email: &str) {
            for (key, value) in [("user.name", name), ("user.email", email)] {
                let status = std::process::Command::new("git")
                    .args(["config", key, value])
                    .current_dir(dir)
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", self.global_config())
                    .status()
                    .expect("git config");
                assert!(status.success(), "git config {key} failed");
            }
        }

        fn set_kin_author(&self, author: &str) {
            fs::write(
                self.layout.config_path(),
                format!("default_author = \"{author}\"\ndefault_branch = \"main\"\n"),
            )
            .expect("write kin config");
        }

        /// Resolve with every ambient Git scope pinned to this fixture.
        ///
        /// The resolver reads Git configuration, and which files Git considers
        /// is decided by the process environment, so a test that left the host's
        /// own `~/.gitconfig` reachable would pass or fail on whoever ran it.
        fn resolve(&self) -> Result<CommitIdentity, KinError> {
            let _pinned = EnvVarGuard::new()
                .with("GIT_CONFIG_NOSYSTEM", "1")
                .with("GIT_CONFIG_GLOBAL", self.global_config())
                .with("HOME", self._dir.path())
                .without("XDG_CONFIG_HOME");
            resolve_commit_identity(&self.layout)
        }
    }

    #[test]
    fn a_configured_git_identity_is_recorded_verbatim() {
        let fixture = Fixture::new();
        fixture.init_git();
        fixture.set_repo_identity("Ada Lovelace", "ada@example.com");

        let identity = fixture.resolve().expect("resolve identity");

        assert_eq!(identity.author, "Ada Lovelace <ada@example.com>");
        assert_eq!(identity.source, IdentitySource::GitRepository);
    }

    #[test]
    fn a_global_git_identity_resolves_and_reports_its_scope() {
        let fixture = Fixture::new();
        fixture.init_git();
        fixture.set_global_identity("Grace Hopper", "grace@example.com");

        let identity = fixture.resolve().expect("resolve identity");

        assert_eq!(identity.author, "Grace Hopper <grace@example.com>");
        assert_eq!(identity.source, IdentitySource::GitGlobal);
    }

    #[test]
    fn a_kin_specific_author_wins_over_the_git_identity() {
        let fixture = Fixture::new();
        fixture.init_git();
        fixture.set_repo_identity("Ada Lovelace", "ada@example.com");
        fixture.set_kin_author("Kin Author <kin@example.com>");

        let identity = fixture.resolve().expect("resolve identity");

        assert_eq!(identity.author, "Kin Author <kin@example.com>");
        assert_eq!(identity.source, IdentitySource::KinConfig);
    }

    #[test]
    fn no_resolvable_identity_refuses_with_both_remediation_commands() {
        let fixture = Fixture::new();
        fixture.init_git();

        let error = fixture.resolve().expect_err("refuse without an identity");
        let message = error.to_string();

        assert!(
            message.contains("git config --global user.name"),
            "{message}"
        );
        assert!(
            message.contains("git config --global user.email"),
            "{message}"
        );
        assert!(message.contains("default_author"), "{message}");
        assert!(!message.contains("unknown"), "{message}");
    }

    /// A repository that never had Git in it still resolves from host scope,
    /// because a native Kin repository is the ordinary case rather than an edge
    /// one.
    #[test]
    fn a_repository_with_no_git_directory_still_reads_the_global_identity() {
        let fixture = Fixture::new();
        fixture.set_global_identity("Grace Hopper", "grace@example.com");

        let identity = fixture.resolve().expect("resolve identity");

        assert_eq!(identity.author, "Grace Hopper <grace@example.com>");
        assert_eq!(identity.source, IdentitySource::GitGlobal);
    }

    /// The exact defect this module exists for: the placeholder must not be
    /// accepted back in through configuration either.
    #[test]
    fn a_configured_placeholder_is_not_an_identity() {
        let fixture = Fixture::new();
        fixture.init_git();
        fixture.set_repo_identity("unknown", "unknown");

        fixture.resolve().expect_err("refuse a placeholder identity");
    }

    /// Git's own synthesized address is the same defect wearing a different
    /// name, so an explicitly configured one is refused too.
    #[test]
    fn a_synthesized_host_local_address_is_not_an_identity() {
        let fixture = Fixture::new();
        fixture.init_git();
        fixture.set_repo_identity("troy", "troy@Troys-MacBook-Pro.local");

        fixture.resolve().expect_err("refuse a synthesized address");
    }

    /// Half an identity is not an identity: Git would complete it by inventing
    /// the other half.
    #[test]
    fn a_name_without_an_email_does_not_resolve() {
        let fixture = Fixture::new();
        fixture.init_git();
        let status = std::process::Command::new("git")
            .args(["config", "user.name", "Ada Lovelace"])
            .current_dir(&fixture.working_dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", fixture.global_config())
            .status()
            .expect("git config");
        assert!(status.success());

        fixture.resolve().expect_err("refuse a half-set identity");
    }

    #[test]
    fn a_kin_author_naming_nobody_falls_through_to_git() {
        let fixture = Fixture::new();
        fixture.init_git();
        fixture.set_repo_identity("Ada Lovelace", "ada@example.com");
        fixture.set_kin_author("   ");

        let identity = fixture.resolve().expect("resolve identity");

        assert_eq!(identity.source, IdentitySource::GitRepository);
    }

    #[test]
    fn source_ids_are_stable_and_distinct() {
        assert_eq!(IdentitySource::KinConfig.id(), "kin-config");
        assert_eq!(IdentitySource::GitRepository.id(), "git-repo");
        assert_eq!(IdentitySource::GitGlobal.id(), "git-global");
    }
}
