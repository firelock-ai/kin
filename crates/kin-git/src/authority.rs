// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Convert the lossless Git ingestion boundary into model-owned authority.
//!
//! The conversion reads object bodies only from the capture CAS. It never
//! reopens Git or the worktree, so every decoded dependency, commit projection,
//! raw ref, and raw `HEAD` remains bound to the exact preflighted snapshot.

use kin_blobs::{BlobError, BlobStore};
use kin_model::{
    GitExternalAuthority, GitObjectBodyLoader, GitObjectFormat as AuthorityObjectFormat, GitRawRef,
    GitRawTarget, Hash256, RefTarget, WorkspaceHead,
};

use crate::error::{GitError, Result};
use crate::lossless::{GitObjectFormat, LosslessGitRepository};

struct CaptureCasBodyLoader<'a> {
    store: &'a BlobStore,
}

impl GitObjectBodyLoader for CaptureCasBodyLoader<'_> {
    type Error = String;

    fn load_body(
        &mut self,
        body_hash: &Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        let hash = kin_blobs::Hash256::from_bytes(*body_hash.as_bytes());
        match self.store.read(&hash) {
            Ok(body) => Ok(Some(body)),
            Err(BlobError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Build independently verifiable Git authority from one lossless snapshot.
///
/// Raw target shape is preserved exactly. Semantic aliases and workspace
/// admission are deliberately separate transaction fields; this function
/// grants only the external Git closure represented by `snapshot`.
pub fn build_git_external_authority(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
) -> Result<GitExternalAuthority> {
    let raw_refs = snapshot
        .refs
        .refs
        .iter()
        .map(|repository_ref| {
            Ok(GitRawRef {
                name: repository_ref.name.clone(),
                target: raw_target(&repository_ref.target)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let raw_head = match &snapshot.head {
        WorkspaceHead::Symbolic { target } => GitRawTarget::Symbolic {
            target: target.clone(),
        },
        WorkspaceHead::Detached { target } => raw_target(target)?,
    };
    let object_format = match snapshot.object_format {
        GitObjectFormat::Sha1 => AuthorityObjectFormat::Sha1,
        GitObjectFormat::Sha256 => AuthorityObjectFormat::Sha256,
    };
    let mut loader = CaptureCasBodyLoader { store: blob_store };
    GitExternalAuthority::from_raw_parts(
        snapshot.repository_id.clone(),
        object_format,
        raw_refs,
        raw_head,
        snapshot.objects.clone(),
        &mut loader,
    )
    .map_err(|error| {
        GitError::InvalidSnapshot(format!(
            "lossless snapshot cannot establish Git external authority: {error}"
        ))
    })
}

fn raw_target(target: &RefTarget) -> Result<GitRawTarget> {
    match target {
        RefTarget::ExternalObject { object } => Ok(GitRawTarget::Direct { object: *object }),
        RefTarget::Symbolic { target } => Ok(GitRawTarget::Symbolic {
            target: target.clone(),
        }),
        RefTarget::Change { change_id } => Err(GitError::InvalidSnapshot(format!(
            "lossless Git state contains native semantic target {change_id}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use kin_model::{GitMaterialHead, RepositoryId};
    use tempfile::tempdir;

    use super::*;
    use crate::capture_lossless_git_repository;
    use crate::test_support::fixture_git;

    #[test]
    fn converts_exact_snapshot_into_model_owned_git_authority() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        std::fs::create_dir(&repository).unwrap();
        git(&repository, ["init", "--initial-branch=main"]);
        git(&repository, ["config", "user.email", "kin@example.invalid"]);
        git(&repository, ["config", "user.name", "Kin Test"]);
        std::fs::write(
            repository.join("compose.yaml"),
            b"services:\n  api:\n    image: kin:test\n",
        )
        .unwrap();
        std::fs::write(repository.join("payload.bin"), [0, 255, 17, 0, 128]).unwrap();
        git(&repository, ["add", "--all"]);
        git(&repository, ["commit", "-m", "exact mixed artifacts"]);

        let store = BlobStore::new(root.path().join("capture-cas")).unwrap();
        let repository_id = RepositoryId::new("authority-fixture").unwrap();
        let snapshot =
            capture_lossless_git_repository(&repository, repository_id.clone(), &store).unwrap();

        let authority = build_git_external_authority(&snapshot, &store).unwrap();

        assert_eq!(authority.repository_id, repository_id);
        assert_eq!(
            authority
                .closure
                .objects
                .iter()
                .map(|entry| entry.record.clone())
                .collect::<Vec<_>>(),
            snapshot.objects
        );
        assert!(matches!(
            authority.material_head,
            GitMaterialHead::Commit { .. }
        ));
        assert_eq!(authority.raw_refs.len(), snapshot.refs.refs.len());
        assert_eq!(authority.commit_projections.len(), 1);
    }

    fn git<const N: usize>(repository: &Path, args: [&str; N]) {
        let output = fixture_git()
            .args(args)
            .current_dir(repository)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", crate::empty_global_git_config())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
