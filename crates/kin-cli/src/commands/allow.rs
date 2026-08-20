// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin allow` — record an explicit approval for one blocked sensitive artifact.
//!
//! Admission refuses to publish untracked content that looks like a leaked
//! credential, and names the path, digest and entry kind that an approval has to
//! carry. This writes exactly that triple into the tracked `.kin-allowances`
//! file at the repository root, which is where policy derivation reads
//! approvals from.
//!
//! The approval rides the tree rather than daemon state on purpose. Policy state
//! dies at the repository boundary, so a teammate who cloned the repository and
//! ran `kin init` would hit the wall a colleague had already cleared. A tracked
//! file survives clone and convert, derives on init, and reaches review as an
//! ordinary diff, which is also its security story: an approval is something a
//! reviewer sees, bound to a digest, so editing the artifact blocks it again.

use anyhow::{bail, Context, Result};
use kin_model::admission::{parse_sensitive_allowances, SENSITIVE_ALLOWANCE_SOURCE_PATH};
use kin_model::{RepoPath, SensitiveArtifactAllowance, SensitiveArtifactKind};
use sha2::{Digest, Sha256};
use std::path::Path;

/// `kin allow <path> --reason <why>`
pub async fn run(path: String, reason: String) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let approved_by = crate::commands::require_commit_author_for(&layout)?;
    let root = repo_root_of(&layout);

    if reason.trim().is_empty() {
        bail!("an approval needs a reason: it is what a reviewer reads to judge the exemption");
    }
    if reason.contains('\t') || reason.contains('\n') {
        bail!("a reason is one line and cannot contain a tab, which separates the fields");
    }

    let repo_path = repo_relative(&root, &path)?;
    let target = root.join(
        repo_path
            .as_utf8()
            .context("approval paths must be valid UTF-8 to be written to the allowance file")?,
    );

    let metadata = std::fs::symlink_metadata(&target)
        .with_context(|| format!("read {}", target.display()))?;
    if metadata.is_dir() {
        bail!(
            "{} is a directory; approve the exact file that admission named",
            repo_path
        );
    }
    if metadata.file_type().is_symlink() {
        bail!(
            "{repo_path} is a symlink, and a symlink's digest is the hash of its target rather \
             than of any file body; approving one is not supported yet, so approve the file it \
             points at or exclude the link"
        );
    }
    let body = std::fs::read(&target).with_context(|| format!("read {}", target.display()))?;
    let content_hash = sha256(&body);
    let executable = is_executable(&metadata);

    let allowance = SensitiveArtifactAllowance {
        path: repo_path.clone(),
        content_hash,
        kind: SensitiveArtifactKind::Blob { executable },
        approved_by,
        reason: reason.clone(),
    };
    allowance.validate()?;

    let allowance_file = allowance_file_path(&layout);
    let mut existing = match std::fs::read(&allowance_file) {
        Ok(body) => parse_sensitive_allowances(&body).with_context(|| {
            format!("{SENSITIVE_ALLOWANCE_SOURCE_PATH} is present but could not be read")
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", allowance_file.display()))
        }
    };

    // One approval per path, which is what the policy's own validation enforces.
    // A moved digest replaces the line rather than adding a second, so the file
    // never says two contradictory things about one artifact.
    let replaced = existing.iter().position(|entry| entry.path == repo_path);
    match replaced {
        Some(index) => existing[index] = allowance.clone(),
        None => existing.push(allowance.clone()),
    }
    existing.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));

    std::fs::write(&allowance_file, render(&existing))
        .with_context(|| format!("write {}", allowance_file.display()))?;

    println!(
        "{} {} in {SENSITIVE_ALLOWANCE_SOURCE_PATH}",
        if replaced.is_some() {
            "Updated the approval for"
        } else {
            "Approved"
        },
        repo_path
    );
    println!("  digest  {content_hash}");
    println!(
        "  kind    {}",
        if executable { "blob+x" } else { "blob" }
    );
    println!("  reason  {reason}");
    println!();
    println!(
        "Commit {SENSITIVE_ALLOWANCE_SOURCE_PATH} for the approval to take effect. It is tracked \
         on purpose, so it travels with the repository and a reviewer sees it. Editing {repo_path} \
         changes its digest and blocks it again."
    );
    Ok(())
}

/// The canonical rendering of an approval set, matching what kin-model parses.
fn render(allowances: &[SensitiveArtifactAllowance]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("# Sensitive artifacts approved for publication, one per line.\n");
    out.push_str("# Fields: path, sha256, kind, approver, reason. Tab separated.\n");
    out.push_str("# Deleting a line revokes that approval. Editing the artifact re-blocks it.\n");
    out.push_str("kin-allowances 1\n");
    for allowance in allowances {
        let kind = match allowance.kind {
            SensitiveArtifactKind::Blob { executable: false } => "blob",
            SensitiveArtifactKind::Blob { executable: true } => "blob+x",
            SensitiveArtifactKind::Symlink => "symlink",
        };
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            allowance.path,
            allowance.content_hash,
            kind,
            allowance.approved_by,
            allowance.reason
        ));
    }
    out.into_bytes()
}

/// The repository working directory.
///
/// `working_dir()`, never `root()`: `root()` is the `.kin/` directory itself, so
/// resolving against it reports every repository path as outside the repository
/// and writes the approval where no derivation reads it. One accessor for both
/// callers, so the two cannot disagree.
fn repo_root_of(layout: &kin_core::KinLayout) -> std::path::PathBuf {
    layout.working_dir().to_path_buf()
}

/// Where the approval file lives: beside `.kin/`, not inside it.
fn allowance_file_path(layout: &kin_core::KinLayout) -> std::path::PathBuf {
    repo_root_of(layout).join(SENSITIVE_ALLOWANCE_SOURCE_PATH)
}

fn repo_relative(root: &Path, given: &str) -> Result<RepoPath> {
    let candidate = Path::new(given);
    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve the current directory")?
            .join(candidate)
    };
    let absolute = normalize(&absolute);
    let root = normalize(root);
    let relative = absolute.strip_prefix(&root).map_err(|_| {
        anyhow::anyhow!(
            "{} is outside this repository at {}",
            absolute.display(),
            root.display()
        )
    })?;
    let text = relative
        .to_str()
        .context("repository paths must be valid UTF-8")?
        .replace(std::path::MAIN_SEPARATOR, "/");
    RepoPath::from_utf8(text).map_err(|error| anyhow::anyhow!("invalid repository path: {error}"))
}

fn normalize(path: &Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn sha256(bytes: &[u8]) -> kin_model::Hash256 {
    let digest = Sha256::digest(bytes);
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&digest);
    kin_model::Hash256::from_bytes(hash)
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{AuthorId, Hash256};

    fn allowance(path: &str, byte: u8, kind: SensitiveArtifactKind) -> SensitiveArtifactAllowance {
        SensitiveArtifactAllowance {
            path: RepoPath::from_utf8(path).unwrap(),
            content_hash: Hash256::from_bytes([byte; 32]),
            kind,
            approved_by: AuthorId::new("troy@firelock.ai"),
            reason: "reviewed in the pull request that adds this line".to_string(),
        }
    }

    /// `root()` is the `.kin/` directory and `working_dir()` is the repository.
    /// Reaching for the wrong one reports every repository path as outside the
    /// repository and writes the approval inside `.kin/`, where no derivation
    /// reads it. A live acceptance run caught exactly that; this pins it.
    #[test]
    fn paths_resolve_against_the_repository_not_against_dot_kin() {
        let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/tmp/repo/.kin"));
        assert_eq!(
            repo_root_of(&layout),
            std::path::PathBuf::from("/tmp/repo"),
            "paths resolve against the repository, not against .kin/"
        );
        let path = allowance_file_path(&layout);
        assert_eq!(
            path,
            std::path::PathBuf::from("/tmp/repo").join(SENSITIVE_ALLOWANCE_SOURCE_PATH)
        );
        assert!(
            !path.starts_with("/tmp/repo/.kin/"),
            "an approval inside .kin/ is invisible to policy derivation: {path:?}"
        );
    }

    /// The writer and the reader live in different crates, so nothing but a
    /// round trip stops them drifting. If this file's format ever stops being
    /// the format policy derivation reads, approvals silently stop applying.
    #[test]
    fn what_this_writes_is_what_kin_model_parses() {
        let written = vec![
            allowance(
                "notekeeper/client.py",
                0x51,
                SensitiveArtifactKind::Blob { executable: false },
            ),
            allowance(
                "scripts/deploy.sh",
                0x52,
                SensitiveArtifactKind::Blob { executable: true },
            ),
            allowance("config/link", 0x53, SensitiveArtifactKind::Symlink),
        ];
        let rendered = render(&written);
        let parsed = parse_sensitive_allowances(&rendered)
            .expect("what kin allow writes must parse as an approval set");
        assert_eq!(parsed.len(), written.len());
        for expected in &written {
            assert!(
                parsed.iter().any(|entry| entry == expected),
                "the round trip lost or altered {}: {parsed:?}",
                expected.path
            );
        }
    }

    /// An empty approval set is still a readable file rather than a truncated
    /// one, which is what makes revoking the last approval safe.
    #[test]
    fn an_empty_approval_set_still_parses() {
        assert_eq!(
            parse_sensitive_allowances(&render(&[])).expect("an empty set is valid"),
            Vec::new()
        );
    }
}
