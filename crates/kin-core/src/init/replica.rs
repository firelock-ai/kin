// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Assemble a replica and its projection privately before publishing its root.

use super::*;

/// Validated remote history and its immutable source bodies.
pub struct ReplicaBootstrapInput {
    pub transaction: RepositoryTransaction,
    pub bodies: Vec<(Hash256, Vec<u8>)>,
    /// What the pack this history came from declared about its replay
    /// semantics, or `None` when it declared nothing.
    ///
    /// `None` is what a caller with no pack at all passes, and it is the safe
    /// value: a bootstrap whose provenance nobody declared leaves the published
    /// replica unstamped rather than stamped over history it cannot speak for.
    pub source_hydration_semantics: Option<u32>,
}

/// Publish a complete replica without exposing a partially initialized target.
///
/// The callback receives genuinely unborn authority. Its transaction must bind
/// history, the default ref and the initial workspace in one generation. All
/// validation and projection precede the no-replace directory publication.
pub fn initialize(
    target: &Path,
    default_branch: &str,
    repository_id: &RepositoryId,
    bootstrap: impl FnOnce(
        &PreparedRepositoryInit,
        AdmissionCase,
    ) -> Result<Option<ReplicaBootstrapInput>>,
) -> Result<InitResult> {
    let absolute = std::path::absolute(target).map_err(|error| KinError::io(target, error))?;
    let parent = absolute
        .parent()
        .ok_or_else(|| KinError::Other("clone target needs a parent".into()))?;
    std::fs::create_dir_all(parent).map_err(|error| KinError::io(parent, error))?;
    let canonical_parent = parent.canonicalize();
    let parent = canonical_parent.map_err(|error| KinError::io(parent, error))?;
    let target = parent.join(
        absolute
            .file_name()
            .ok_or_else(|| KinError::Other("clone target needs a directory name".into()))?,
    );
    require_empty_or_absent(&target)?;
    let stage = tempfile::Builder::new()
        .prefix(".kin-clone-")
        .tempdir_in(&parent)
        .map_err(|error| KinError::io(&parent, error))?;
    let canonical_root = stage.path().canonicalize();
    let root = canonical_root.map_err(|error| KinError::io(stage.path(), error))?;
    let case = detect_admission_case(&root)?;
    let mut prepared = prepare_repository_layout_with_origin(
        &root.join(format!(".kin.init-{}", uuid::Uuid::new_v4())),
        &root.join(".kin"),
        replica_config(default_branch),
        KinManifest::adopting(repository_id.as_str()),
        RepositoryIdentityOrigin::Adopted,
    )?;
    let transaction = match bootstrap(&prepared, case)? {
        Some(input) => {
            prepared.with_source_blob_batch(&mut |batch| {
                for (hash, bytes) in &input.bodies {
                    batch.save(*hash, bytes)?;
                }
                Ok(())
            })?;
            // The staging above stamped this replica with THIS build's version,
            // and the history about to be committed into it was authored
            // somewhere else. This is the transfer receiver's rule, run at the
            // one boundary a bootstrap actually crosses.
            prepared.reconcile_bootstrap_hydration_semantics(input.source_hydration_semantics)?;
            input.transaction
        }
        None => build_repository_bootstrap_transaction(
            prepared.initial_roots().clone(),
            prepared.repository_id().clone(),
            prepared.workspace_id(),
            case,
            prepared.default_ref().clone(),
            SharedAdmissionPolicy::empty(0),
            None,
        )?,
    };
    let workspace = transaction
        .workspace_mutation
        .as_ref()
        .ok_or_else(|| KinError::Other("replica bootstrap has no workspace".into()))?;
    let tree = kin_model::ResolvedTree::default()
        .apply(&workspace.tree_deltas)
        .map_err(|error| KinError::Other(error.to_string()))?;
    // Receiving history validates every introduced artifact against shared
    // policy, without pretending this workspace authored each ancestor.
    prepared.commit_bootstrap(transaction, Some(case))?;
    let entries = tree
        .artifacts()
        .map(|artifact| {
            let bytes = match artifact.entry.blob_identity() {
                Some(hash) => prepared.load_source_blob(hash)?.ok_or_else(|| {
                    KinError::Other(format!("replica source body {hash} is absent"))
                })?,
                None => {
                    return Err(KinError::Other(format!(
                        "replica cannot materialize {} as a source body",
                        artifact.path
                    )))
                }
            };
            Ok((artifact.path.clone(), artifact.entry, bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    let seal = prepared.metadata_seal.clone();
    let mut initialized = publish_repository_layout(prepared)?;
    crate::materialize_source_tree(
        &root,
        entries
            .iter()
            .map(|(path, entry, body)| (path, *entry, body.as_slice())),
    )?;
    require_empty_or_absent(&target)?;
    match std::fs::remove_dir(&target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(KinError::io(&target, error)),
    }
    rename_directory_noreplace(&root, &target)?;
    initialized.layout = KinLayout::new(target.join(".kin"));
    let finish = || -> Result<()> {
        sync_parent_directory(&parent)?;
        verify_repository_layout(
            &initialized.layout,
            &seal,
            &initialized.repository_id,
            initialized.workspace_id,
            &initialized.authority,
        )?;
        Ok(())
    };
    finish().map_err(|error| KinError::RepositoryPublishedButUncertain {
        path: target.display().to_string(),
        detail: error.to_string(),
    })?;
    Ok(initialized)
}

fn require_empty_or_absent(target: &Path) -> Result<()> {
    match std::fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(KinError::io(target, error)),
        Ok(metadata) if !metadata.file_type().is_dir() => Err(KinError::Other(format!(
            "clone target is not a directory: {}",
            target.display()
        ))),
        Ok(_) => {
            let mut entries =
                std::fs::read_dir(target).map_err(|error| KinError::io(target, error))?;
            if entries
                .next()
                .transpose()
                .map_err(|error| KinError::io(target, error))?
                .is_some()
            {
                return Err(KinError::Other(format!(
                    "clone target is not empty: {}",
                    target.display()
                )));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(
        prepared: &PreparedRepositoryInit,
        case: AdmissionCase,
    ) -> RepositoryTransaction {
        build_repository_bootstrap_transaction(
            prepared.initial_roots().clone(),
            prepared.repository_id().clone(),
            prepared.workspace_id(),
            case,
            prepared.default_ref().clone(),
            SharedAdmissionPolicy::empty(0),
            None,
        )
        .unwrap()
    }

    #[test]
    fn replica_publication_preserves_unborn_identity_and_branch() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("replica");
        let identity = RepositoryId::new("hosted-repository".to_string()).unwrap();
        let initialized = initialize(&target, "trunk", &identity, |_, _| Ok(None)).unwrap();
        assert_eq!(initialized.repository_id, identity);
        assert_eq!(initialized.authority.receipt.roots_before.generation, 0);
        assert_eq!(initialized.authority.receipt.roots_after.generation, 1);
        assert_eq!(
            initialized.head,
            WorkspaceHead::Symbolic {
                target: RefName::branch(b"trunk").unwrap()
            }
        );
        assert_eq!(initialized.authority.initial_change_id, None);
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 1);
    }

    /// A bootstrap that declares the version this build stamps keeps the
    /// record, which is what makes a clone between two stores of one build
    /// certify instead of going inconclusive on arrival.
    #[test]
    fn a_bootstrap_declaring_this_builds_version_keeps_the_creation_record() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("replica");
        let identity = RepositoryId::new("hosted-repository".to_string()).unwrap();
        let initialized = initialize(&target, "trunk", &identity, |prepared, case| {
            Ok(Some(ReplicaBootstrapInput {
                transaction: transaction(prepared, case),
                bodies: vec![],
                source_hydration_semantics: Some(crate::hydration_semantics::binary_version()),
            }))
        })
        .unwrap();
        assert_eq!(
            crate::hydration_semantics::standing(&initialized.layout),
            crate::hydration_semantics::HydrationStanding::Current {
                version: crate::hydration_semantics::binary_version()
            }
        );
    }

    /// A bootstrap whose declaration this build cannot match must publish no
    /// creation record.
    ///
    /// This is the clone door, and before the pack declared anything it was open:
    /// `kin clone` admits a peer's history inside the staging that writes this
    /// stamp, never through the transfer receiver, so a replica of a peer whose
    /// history was authored under another version published a store reading
    /// `Current` over it. The `None` arm is the same door for a caller that
    /// declares nothing at all.
    #[test]
    fn a_bootstrap_this_build_cannot_match_publishes_no_creation_record() {
        for declared in [None, Some(crate::hydration_semantics::binary_version() - 1)] {
            let parent = tempfile::tempdir().unwrap();
            let target = parent.path().join("replica");
            let identity = RepositoryId::new("hosted-repository".to_string()).unwrap();
            let initialized = initialize(&target, "trunk", &identity, |prepared, case| {
                Ok(Some(ReplicaBootstrapInput {
                    transaction: transaction(prepared, case),
                    bodies: vec![],
                    source_hydration_semantics: declared,
                }))
            })
            .unwrap();
            assert_eq!(
                crate::hydration_semantics::standing(&initialized.layout),
                crate::hydration_semantics::HydrationStanding::Unstamped {
                    derives: crate::hydration_semantics::binary_version()
                },
                "a bootstrap declaring {declared:?} published a creation record anyway"
            );
        }
    }

    /// The control that keeps both arms above honest: a replica created with no
    /// bootstrap at all admits nothing from anywhere, so its own creation record
    /// must survive untouched.
    #[test]
    fn a_replica_with_no_bootstrap_keeps_its_creation_record() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("replica");
        let identity = RepositoryId::new("hosted-repository".to_string()).unwrap();
        let initialized = initialize(&target, "trunk", &identity, |_, _| Ok(None)).unwrap();
        assert_eq!(
            crate::hydration_semantics::standing(&initialized.layout),
            crate::hydration_semantics::HydrationStanding::Current {
                version: crate::hydration_semantics::binary_version()
            }
        );
    }

    #[test]
    fn replica_publication_rejects_wrong_identity_before_target_exists() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("replica");
        let identity = RepositoryId::new("hosted-repository".to_string()).unwrap();
        let error = initialize(&target, "trunk", &identity, |prepared, case| {
            let mut transaction = transaction(prepared, case);
            transaction.repository_id =
                RepositoryId::new("different-repository".to_string()).unwrap();
            Ok(Some(ReplicaBootstrapInput {
                transaction,
                bodies: vec![],
                source_hydration_semantics: None,
            }))
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("belongs to different-repository"),
            "{error}"
        );
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn replica_publication_rejects_corrupt_body_before_target_exists() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("replica");
        let identity = RepositoryId::new("hosted-repository".to_string()).unwrap();
        let error = initialize(&target, "trunk", &identity, |prepared, case| {
            Ok(Some(ReplicaBootstrapInput {
                transaction: transaction(prepared, case),
                source_hydration_semantics: None,
                bodies: vec![(
                    Hash256::from_bytes(Sha256::digest(b"original").into()),
                    b"corrupt".to_vec(),
                )],
            }))
        })
        .unwrap_err();
        assert!(error.to_string().contains("digest mismatch"), "{error}");
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    /// A gitlink is the only tree entry `blob_identity` cannot answer for, so it
    /// is what puts a real non-materializable source entry into a bootstrap.
    ///
    /// The bootstrap transaction is edited rather than transferred from a peer
    /// on purpose: `prepare_replica_bootstrap` refuses a gitlink pack at the
    /// transport boundary, so the only way to hand `initialize` one is to build
    /// it. What refuses it here is the graph's own admission rule inside
    /// `commit_bootstrap`, which admits a gitlink only when it arrives on a
    /// Git-origin change whose commit projection the same transaction verifies.
    /// The `None` arm in the projection loop below is the second defence behind
    /// that rule, and reaching it needs verified Git external authority this
    /// unit test cannot mint. Both refusals sit above publication, which is what
    /// this asserts.
    #[test]
    fn replica_publication_refuses_an_unmaterializable_entry_before_target_exists() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("replica");
        let identity = RepositoryId::new("hosted-repository".to_string()).unwrap();
        let error = initialize(&target, "trunk", &identity, |prepared, case| {
            let mut transaction = transaction(prepared, case);
            let workspace = transaction
                .workspace_mutation
                .as_mut()
                .expect("a bootstrap transaction carries its workspace mutation");
            workspace.tree_deltas.push(kin_model::TreeDelta::Added {
                artifact_id: kin_model::ArtifactId::new(),
                new: kin_model::LocatedEntry::new(
                    kin_model::RepoPath::from_utf8("vendor/dependency").unwrap(),
                    kin_model::TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x5a; 20])),
                ),
            });
            let tree = kin_model::ResolvedTree::default()
                .apply(&workspace.tree_deltas)
                .unwrap();
            workspace.new_tree_hash = compute_resolved_tree_hash(&tree).unwrap();
            Ok(Some(ReplicaBootstrapInput {
                transaction,
                bodies: vec![],
                source_hydration_semantics: None,
            }))
        })
        .unwrap_err();
        let reported = error.to_string();
        assert!(reported.contains("gitlink"), "{reported}");
        assert!(reported.contains("vendor/dependency"), "{reported}");
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn replica_publication_refuses_a_target_populated_during_preparation() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("replica");
        std::fs::create_dir(&target).unwrap();
        let identity = RepositoryId::new("hosted-repository".to_string()).unwrap();
        let error = initialize(&target, "trunk", &identity, |_, _| {
            std::fs::write(target.join("sentinel"), b"keep exact bytes").unwrap();
            Ok(None)
        })
        .unwrap_err();
        assert!(error.to_string().contains("not empty"), "{error}");
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"keep exact bytes"
        );
        assert!(!target.join(".kin").exists());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 1);
    }
}
