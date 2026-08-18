// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact, fail-closed Git repository admission.
//!
//! Git is consulted only at this explicit ingestion boundary. The resulting
//! history, refs, raw object closure, workspace tree, admission policy, and
//! local ignore overlay are committed together as graph-owned authority before
//! the staged `.kin` repository is atomically published.

use std::path::Path;
use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_git::{
    admit_semantic_git_import, build_git_external_authority, capture_lossless_git_repository,
    check_git_admission_blockers, plan_semantic_git_import, preflight_git_migration,
    reprove_git_migration, reprove_git_migration_after_publication,
    seal_all_content_observation_observed, AdmittedContentClosure, GitLocalIgnoreSourceKind,
    GitMigrationPreflightProof, LosslessGitRepository, SealedContentObservation,
    SealedContentSource,
};
use kin_model::{
    compute_resolved_tree_hash, AdmissionCase, AuthorId, ChangeStore,
    EffectiveAdmissionPolicyStamp, ExternalObjectId, ExternalObjectKind, FrozenLocalOverlay,
    FrozenLocalOverlayDelta, GitExternalAuthorityDelta, GitMaterialHead, Hash256,
    LocalAdmissionRuleSource, LocalAdmissionRuleSourceKind, LocatedEntry, OperationId,
    RepositoryId, RepositoryTransaction, TreeDelta, WorkspaceExpectation, WorkspaceMutation,
    WorkspaceSemanticDelta,
};
use tracing::{info, info_span};

use crate::config::{
    GitBranchTrackingConfig, GitCoexistenceConfig, GitPushDefault, GitRemoteTransportConfig,
    KinConfig,
};
use crate::error::{KinError, Result};
use crate::init::{
    prepare_repository_layout_at, publish_repository_layout_linearized, GraphOwnedContent,
    InitResult,
};
use crate::init_progress::{PhaseProgress, GIT_ADMISSION_PHASES};
use crate::layout::KinLayout;
use crate::manifest::KinManifest;

// Gated on unix as well as test because exact Git admission is unix-only, so
// the tests that drive this injection are too. Leaving it on every test build
// would make it dead code on Windows, which CI rejects under `-D warnings`.
#[cfg(all(unix, test))]
std::thread_local! {
    static WITHHELD_STAGED_BODY: std::cell::Cell<Option<Hash256>> =
        const { std::cell::Cell::new(None) };
    static DIVERGED_PUBLISHED_CLOSURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Drop one captured body on its way into the staged repository, so a test can
/// prove admission refuses a graph that cannot answer for its own content.
#[cfg(all(unix, test))]
fn withhold_staged_body(digest: Hash256) {
    WITHHELD_STAGED_BODY.set(Some(digest));
}

#[cfg(all(unix, test))]
fn clear_withheld_staged_body() {
    WITHHELD_STAGED_BODY.set(None);
}

#[cfg(all(unix, test))]
fn staged_body_is_withheld(digest: Hash256) -> bool {
    WITHHELD_STAGED_BODY.with(|withheld| withheld.get() == Some(digest))
}

#[cfg(not(all(unix, test)))]
const fn staged_body_is_withheld(_digest: Hash256) -> bool {
    false
}

/// Derive the published observation from a deliberately diverged closure, so a
/// test can prove the cross-check refuses a divergence rather than assuming it.
#[cfg(all(unix, test))]
fn diverge_published_closure(diverged: bool) {
    DIVERGED_PUBLISHED_CLOSURE.set(diverged);
}

#[cfg(all(unix, test))]
fn published_closure_is_diverged() -> bool {
    DIVERGED_PUBLISHED_CLOSURE.get()
}

/// A closure whose last admitted tree carries the bodies of two plain files
/// exchanged.
///
/// Every shape count, distinct body, and byte total is unchanged by the
/// exchange, so this is exactly the divergence a fingerprint over counts alone
/// cannot see and a fingerprint bound to observed content must reject.
#[cfg(all(unix, test))]
struct DivergedClosure {
    repository_id: RepositoryId,
    trees: Vec<kin_model::ResolvedTree>,
}

#[cfg(all(unix, test))]
impl DivergedClosure {
    fn from_closure(closure: &impl AdmittedContentClosure) -> Self {
        use kin_model::{ResolvedTree, TreeEntry};

        let mut trees = closure
            .admitted_trees()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let head = trees
            .last_mut()
            .expect("an admitted closure observes a tree");
        let plain_files = head
            .artifacts_by_path()
            .filter(|artifact| {
                matches!(
                    artifact.entry,
                    TreeEntry::Blob {
                        executable: false,
                        ..
                    }
                )
            })
            .map(|artifact| (artifact.path.clone(), artifact.entry))
            .take(2)
            .collect::<Vec<_>>();
        let [(left_path, left_entry), (right_path, right_entry)] = plain_files.as_slice() else {
            panic!("the admitted head tree carries two plain files to exchange");
        };
        assert_ne!(
            left_entry, right_entry,
            "exchanging equal entries is not a divergence"
        );
        let exchanged = head
            .clone()
            .into_artifacts()
            .map(|mut artifact| {
                if artifact.path == *left_path {
                    artifact.entry = *right_entry;
                } else if artifact.path == *right_path {
                    artifact.entry = *left_entry;
                }
                artifact
            })
            .collect::<Vec<_>>();
        *head = ResolvedTree::from_artifacts(exchanged)
            .expect("exchanging two entries preserves tree validity");
        Self {
            repository_id: closure.closure_repository_id().clone(),
            trees,
        }
    }
}

#[cfg(all(unix, test))]
impl AdmittedContentClosure for DivergedClosure {
    fn closure_repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }

    fn admitted_trees(&self) -> Vec<&kin_model::ResolvedTree> {
        self.trees.iter().collect()
    }
}

/// Admit one clean materialized Git worktree as a complete Kin repository.
///
/// The source Git repository is never mutated. Every refusal before the
/// publication rename leaves `.kin` absent: source drift, unsupported
/// compatibility state, an existing destination, a graph or CAS validation
/// error, or an admitted closure the staged graph cannot answer for. Divergence
/// found after the rename cannot unpublish, so it fails loud as
/// [`KinError::RepositoryPublishedButUncertain`] with the published repository
/// left in place for recovery.
pub fn init_from_git(working_dir: &Path) -> Result<InitResult> {
    init_from_git_with_hook(working_dir, || {})
}

fn init_from_git_with_hook(
    working_dir: &Path,
    before_final_source_proof: impl FnOnce(),
) -> Result<InitResult> {
    init_from_git_with_hooks(working_dir, before_final_source_proof, || {})
}

fn init_from_git_with_hooks(
    working_dir: &Path,
    before_final_source_proof: impl FnOnce(),
    after_repository_publication: impl FnOnce(),
) -> Result<InitResult> {
    let source = canonical_new_repository_root(working_dir)?;
    require_git_boundary(&source)?;

    let mut progress = PhaseProgress::new(GIT_ADMISSION_PHASES);

    // Ahead of every derivation phase on purpose. Each blocker below is source
    // state the proof would refuse anyway, and deriving a whole semantic
    // history first only means the operator waits minutes to be told that a
    // file they could see is untracked.
    progress.begin("check admission blockers");
    {
        let _span = info_span!("kin.init.check_admission_blockers").entered();
        check_git_admission_blockers(&source)
            .map_err(|error| git_boundary_error("admit this Git repository", error))?;
    }

    let manifest = KinManifest::new();
    let repository_id = RepositoryId::new(manifest.repo_id.clone())
        .map_err(|error| KinError::Other(format!("invalid repository identity: {error}")))?;
    let source_parent = source.parent().ok_or_else(|| {
        KinError::Other(format!(
            "repository root has no parent for isolated Git capture: {}",
            source.display()
        ))
    })?;
    let capture_dir = crate::init_staging::GitCaptureStaging::claim(source_parent)?;
    // The capture store lives and dies inside this call, so its bodies are
    // written without device barriers. Its root is the per-init `capture_dir`
    // above, removed when that handle drops, when a terminating signal reaches
    // this process, or by the next init's reap when neither ran; every later
    // init mints a fresh random name rather than reopening this one; and
    // nothing durable ever records a path inside it. Every body that has to
    // outlive init is copied into the repository's own source-blob store by
    // `copy_captured_authority`, under that store's unchanged durability. A
    // crash that could tear these bytes therefore destroys the only reader they
    // ever had, and leaves no published `.kin` behind to reference them.
    let capture_store = BlobStore::new_ephemeral(capture_dir.path().join("objects"))
        .map_err(|error| git_boundary_error("create capture CAS", error))?;

    progress.begin("capture Git repository");
    let snapshot = {
        let _span = info_span!("kin.init.capture_git_repository").entered();
        capture_lossless_git_repository(&source, repository_id, &capture_store)
            .map_err(|error| git_boundary_error("capture exact Git repository", error))?
    };
    park_at_capture_barrier(capture_dir.path());

    progress.begin("build Git authority");
    let git_authority = {
        let _span = info_span!(
            "kin.init.build_git_authority",
            objects = snapshot.objects.len()
        )
        .entered();
        build_git_external_authority(&snapshot, &capture_store)
            .map_err(|error| git_boundary_error("build exact Git authority", error))?
    };

    progress.begin("plan semantic import");
    let semantic_plan = {
        let _span = info_span!("kin.init.plan_semantic_import").entered();
        let plan = plan_semantic_git_import(&snapshot, &capture_store)
            .map_err(|error| git_boundary_error("derive exact semantic Git history", error))?;
        verify_material_workspace_seed(&plan.workspace_seed, &git_authority.material_head)?;
        plan
    };

    progress.begin("derive semantic history");
    let semantic_plan = {
        let _span = info_span!(
            "kin.init.bind_historical_semantics",
            changes = semantic_plan.commit_trees.len()
        )
        .entered();
        bind_historical_semantics(semantic_plan, &capture_store)?
    };

    progress.begin("apply admission policy");
    let admitted = {
        let _span = info_span!("kin.init.admit_semantic_import").entered();
        admit_semantic_git_import(&semantic_plan, &capture_store).map_err(|error| {
            git_boundary_error("derive branch-versioned admission policy", error)
        })?
    };

    // PROOF 1 of 3. Guards: the mutable Git boundary this admission is about to
    // build a repository from is exactly the committed state the capture was
    // taken from, and the import plan is a deterministic function of those raw
    // objects rather than something enriched beyond them.
    //
    // It is first because everything after it consumes it: the remote mapping
    // becomes the repository's Git config, the ignored-local inputs are copied
    // as authority, the workspace binding is sealed from it, and the divergence
    // it observed is what init reports to the operator. It is also the only one
    // of the three that revalidates the plan structurally, which is what the
    // other two reuse rather than repeat.
    progress.begin("prove Git source");
    let source_proof = {
        let _span = info_span!("kin.init.source_proof_staged").entered();
        preflight_git_migration(&source, &snapshot, &semantic_plan, &capture_store)
            .map_err(|error| git_boundary_error("prove mutable Git workspace", error))?
    };

    let final_kin_dir = source.join(".kin");
    let staging_dir = source_parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
    let config = config_for_source(&snapshot, &source_proof.remote_mapping)?;

    progress.begin("stage repository layout");
    let mut prepared = {
        let _span = info_span!("kin.init.prepare_layout").entered();
        prepare_repository_layout_at(&staging_dir, &final_kin_dir, config, manifest)?
    };

    progress.begin("copy Git objects");
    {
        let _span = info_span!(
            "kin.init.copy_captured_authority",
            objects = snapshot.objects.len()
        )
        .entered();
        copy_captured_authority(
            &prepared,
            &snapshot,
            &capture_store,
            &source_proof,
            &mut progress,
        )?;
    }

    progress.begin("seal staged content");
    let sealed_observation = {
        let _span = info_span!("kin.init.seal_staged_content").entered();
        seal_observed_content(&admitted, &prepared, &mut progress)
            .map_err(|error| git_boundary_error("seal all-content observation", error))?
    };

    let workspace_seed = admitted.workspace_seed.clone();
    let workspace_policy = admitted.workspace_policy().clone();
    let workspace_base_change_id = admitted.workspace_base_change_id();

    progress.begin("build bootstrap transaction");
    let transaction = {
        let _span = info_span!(
            "kin.init.build_bootstrap_transaction",
            observed_trees = sealed_observation.observed_trees,
            observed_entries = sealed_observation.observed_entries
        )
        .entered();
        let mut transaction = admitted
            .into_generation_zero_repository_transaction(
                &capture_store,
                OperationId::new(),
                prepared.initial_roots().clone(),
                AuthorId::new("kin-git-import"),
                "admit exact Git repository authority",
            )
            .map_err(|error| git_boundary_error("construct Git bootstrap transaction", error))?;
        bind_workspace_authority(
            &mut transaction,
            prepared.workspace_id(),
            workspace_seed,
            workspace_policy,
            &source_proof,
        )?;
        transaction.git_authority_delta =
            Some(GitExternalAuthorityDelta::initialize(git_authority));
        transaction
    };

    progress.begin("validate bootstrap transaction");
    {
        let _span = info_span!("kin.init.validate_bootstrap_transaction").entered();
        transaction.validate().map_err(|error| {
            KinError::Other(format!("invalid Git bootstrap transaction: {error}"))
        })?;
    }

    progress.begin("commit bootstrap transaction");
    {
        let _span = info_span!("kin.init.commit_bootstrap_transaction").entered();
        prepared.commit_repository_bootstrap(transaction)?;
    }

    let mut result = publish_repository_layout_linearized(prepared, |publication| {
        before_final_source_proof();
        // PROOF 2 of 3. Guards: nothing moved the source during the minutes
        // between proof 1 and this instant. Everything expensive in the ladder
        // sits in that window, so it is the window a source can actually drift
        // in, and this is the last point at which drift can still be prevented
        // rather than merely reported: the rename below is the linearization
        // point, and a refusal here leaves `.kin` absent.
        //
        // Distinct from proof 1 by WHEN it runs, not by what it looks at, which
        // is why it observes once against proof 1 rather than twice against
        // itself.
        progress.begin("re-prove Git source");
        {
            let _span = info_span!("kin.init.source_proof_final").entered();
            reprove_git_migration(
                &source,
                &source_proof,
                &snapshot,
                &semantic_plan,
                &capture_store,
            )
            .map_err(|error| git_boundary_error("repeat final Git source proof", error))?
        };
        progress.begin("publish repository");
        let published = {
            let _span = info_span!("kin.init.publish_repository").entered();
            publication.publish()?
        };
        after_repository_publication();
        // PROOF 3 of 3. Guards: publication put `.kin` in the worktree and did
        // nothing else to it. Proof 2 cannot cover this, because it necessarily
        // ran before the rename; this is the only proof taken on a source that
        // Kin has written into, and the only one that has to be told which
        // directory is legitimately new.
        //
        // Its power is different from proof 2's rather than additional. Past
        // the linearization point a refusal cannot unpublish, so this detects
        // and reports as `RepositoryPublishedButUncertain` where proof 2
        // prevents. That is what makes it worth keeping and what bounds it:
        // publication is one no-replace rename, so an honest re-proof here
        // needs one observation measured against proof 1, not a fresh
        // self-contained double proof.
        progress.begin("prove Git source after publication");
        {
            let _span = info_span!("kin.init.source_proof_published").entered();
            reprove_git_migration_after_publication(
                &source,
                published.path(),
                &source_proof,
                &snapshot,
                &semantic_plan,
                &capture_store,
            )
            .map_err(|error| git_boundary_error("prove Git source after publication", error))?
        };
        // Re-seal the published repository, deriving the closure from the exact
        // import plan rather than its admitted form. Requiring both derivations
        // to fingerprint identically proves publication preserved graph-owned
        // content and that the two closures agree, instead of assuming it.
        //
        // This observation is after the linearization point, so it detects
        // divergence rather than preventing publication: a refusal here leaves
        // the published `.kin` on disk and reports
        // `RepositoryPublishedButUncertain`, exactly like the post-publication
        // source proof above. The staged observation before publication is what
        // keeps a repository that cannot answer for its content from being
        // published at all. Neither site degrades into a filesystem read.
        progress.begin("seal published content");
        let published_observation = {
            let _span = info_span!("kin.init.seal_published_content").entered();
            seal_published_content_observation(published.path(), &semantic_plan, &mut progress)?
        };
        if published_observation.fingerprint != sealed_observation.fingerprint {
            return Err(KinError::Other(
                "sealed all-content observation changed across repository publication; published \
                 authority is not safe to use without recovery"
                    .to_string(),
            ));
        }
        progress.finish("admitted exact Git repository");
        Ok(())
    })?;
    // Exact Git refs intentionally retain external-object targets, so the
    // generic bootstrap helper cannot infer the semantic identity of a peeled
    // HEAD from `WorkspaceMutation::new_base_target`. The admitted plan already
    // proved that alias while validating the complete history; preserve it in
    // the initialization receipt instead of reporting an absent initial change.
    result.authority.initial_change_id = workspace_base_change_id;
    // What the source held that the committed state does not. None of it is in
    // the repository this call published; all of it is still in the worktree,
    // where the daemon admits it as workspace state on its first run.
    result
        .workspace_divergence
        .clone_from(&source_proof.workspace_divergence);

    info!(
        path = %source.display(),
        repository = %result.repository_id,
        workspace = %result.workspace_id,
        generation = result.authority.receipt.generation,
        observed_trees = sealed_observation.observed_trees,
        observed_entries = sealed_observation.observed_entries,
        sealed_bodies = sealed_observation.coverage.sealed_bodies,
        sealed_body_bytes = sealed_observation.coverage.sealed_body_bytes,
        opaque_bodies = sealed_observation.coverage.opaque_bodies,
        declared_exclusions = sealed_observation.exclusions.len(),
        seal = %sealed_observation.fingerprint,
        "admitted exact Git repository as graph-owned Kin authority"
    );
    Ok(result)
}

/// Re-derive the sealed all-content observation against a published repository.
///
/// Reads only graph-owned content through the published repository's own
/// authority, so a repository that seals here answers for its admitted content
/// without consulting the working tree or the source object store.
fn seal_published_content_observation(
    published_kin_dir: &Path,
    closure: &impl AdmittedContentClosure,
    progress: &mut PhaseProgress,
) -> Result<SealedContentObservation> {
    let layout = KinLayout::new(published_kin_dir.to_path_buf());
    let authority = RepositoryAuthorityManager::open(
        closure.closure_repository_id().clone(),
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .map_err(|error| KinError::Graph(error.to_string()))?;
    let content = GraphOwnedContent::new(&authority);
    #[cfg(all(unix, test))]
    if published_closure_is_diverged() {
        let diverged = DivergedClosure::from_closure(closure);
        return seal_observed_content(&diverged, &content, progress)
            .map_err(|error| git_boundary_error("seal published all-content observation", error));
    }
    seal_observed_content(closure, &content, progress)
        .map_err(|error| git_boundary_error("seal published all-content observation", error))
}

fn verify_material_workspace_seed(
    seed: &kin_git::GitWorkspaceSeed,
    material_head: &GitMaterialHead,
) -> Result<()> {
    match material_head {
        GitMaterialHead::Unborn { .. } => {
            let exact_unborn = matches!(&seed.head, kin_model::WorkspaceHead::Symbolic { .. })
                && seed.base_target.is_none()
                && seed.base_commit_oid.is_none()
                && seed.base_tree_hash.is_none()
                && seed.base_tree.is_empty();
            if !exact_unborn {
                return Err(KinError::Other(
                    "semantic workspace seed disagrees with verified unborn Git HEAD".to_string(),
                ));
            }
        }
        GitMaterialHead::Commit { commit_oid, .. } => {
            let material_target = kin_model::RefTarget::external_object(ExternalObjectId::new(
                ExternalObjectKind::Commit,
                *commit_oid,
            ));
            let exact_head = match &seed.head {
                kin_model::WorkspaceHead::Symbolic { .. } => true,
                kin_model::WorkspaceHead::Detached { target } => target == &material_target,
            };
            if !exact_head
                || seed.base_target.as_ref() != Some(&material_target)
                || seed.base_commit_oid != Some(*commit_oid)
                || seed.base_tree_hash.is_none()
            {
                return Err(KinError::Other(
                    "semantic workspace seed disagrees with verified material Git HEAD".to_string(),
                ));
            }
        }
        GitMaterialHead::NonMaterializable { .. } => {
            return Err(KinError::Other(
                "verified Git HEAD cannot seed a material Kin workspace".to_string(),
            ));
        }
    }
    Ok(())
}

fn canonical_new_repository_root(working_dir: &Path) -> Result<std::path::PathBuf> {
    let source = working_dir
        .canonicalize()
        .map_err(|error| KinError::io(working_dir, error))?;
    let kin_dir = source.join(".kin");
    match std::fs::symlink_metadata(&kin_dir) {
        Ok(_) => return Err(KinError::AlreadyInitialized(source.display().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(KinError::io(&kin_dir, error)),
    }
    Ok(source)
}

fn require_git_boundary(source: &Path) -> Result<()> {
    let marker = source.join(".git");
    match std::fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(KinError::Other(format!(
            "Git repository marker must not be a symlink: {}",
            marker.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(KinError::Other(
            format!("no Git repository marker found at {}", marker.display()),
        )),
        Err(error) => Err(KinError::io(&marker, error)),
    }
}

fn config_for_source(
    snapshot: &LosslessGitRepository,
    remote_mapping: &kin_git::GitRemoteMappingFacts,
) -> Result<KinConfig> {
    let mut config = KinConfig::default();
    if let kin_model::WorkspaceHead::Symbolic { target } = &snapshot.head {
        if target.is_branch() {
            let short = &target.as_bytes()[b"refs/heads/".len()..];
            if let Ok(short) = std::str::from_utf8(short) {
                config.default_branch = short.to_string();
            }
        }
    }
    config.git = map_git_coexistence_config(remote_mapping)?;
    config.validate()?;
    Ok(config)
}

fn map_git_coexistence_config(
    facts: &kin_git::GitRemoteMappingFacts,
) -> Result<GitCoexistenceConfig> {
    let remotes = facts
        .remotes
        .iter()
        .map(|remote| {
            Ok(GitRemoteTransportConfig {
                name: exact_utf8(&remote.name, "Git remote name")?,
                fetch_urls: exact_utf8_values(&remote.fetch_urls, "Git fetch URL")?,
                push_urls: exact_utf8_values(&remote.push_urls, "Git push URL")?,
                fetch_refspecs: exact_utf8_values(&remote.fetch_refspecs, "Git fetch refspec")?,
                push_refspecs: exact_utf8_values(&remote.push_refspecs, "Git push refspec")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let branches = facts
        .branch_tracking
        .iter()
        .map(|branch| {
            Ok(GitBranchTrackingConfig {
                branch: exact_utf8(&branch.branch, "Git branch name")?,
                remote: branch
                    .remote
                    .as_deref()
                    .map(|value| exact_utf8(value, "Git branch remote"))
                    .transpose()?,
                merge_refs: exact_utf8_values(&branch.merge_refs, "Git branch merge ref")?,
                push_remote: branch
                    .push_remote
                    .as_deref()
                    .map(|value| exact_utf8(value, "Git branch pushRemote"))
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let remote_push_default = facts
        .remote_push_default
        .as_deref()
        .map(|value| exact_utf8(value, "Git remote.pushDefault"))
        .transpose()?;
    let push_default = facts
        .push_default
        .as_deref()
        .map(|value| {
            let value = exact_utf8(value, "Git push.default")?;
            GitPushDefault::from_exact_git_value(&value).ok_or_else(|| {
                KinError::Other(
                    "Git push.default escaped preflight without an exact typed mapping".to_string(),
                )
            })
        })
        .transpose()?;
    let push_auto_setup_remote = facts
        .push_auto_setup_remote
        .as_deref()
        .map(|value| {
            git_boolean(value).ok_or_else(|| {
                KinError::Other(
                    "Git push.autoSetupRemote escaped preflight without a boolean value"
                        .to_string(),
                )
            })
        })
        .transpose()?;
    Ok(GitCoexistenceConfig {
        remotes,
        branches,
        remote_push_default,
        push_default,
        push_auto_setup_remote,
    })
}

/// Read one Git boolean exactly as Git reads it.
///
/// An empty value is Git's shorthand for true, which is why this cannot be a
/// plain string comparison against `true`.
fn git_boolean(value: &[u8]) -> Option<bool> {
    match value.to_ascii_lowercase().as_slice() {
        b"" | b"true" | b"yes" | b"on" | b"1" => Some(true),
        b"false" | b"no" | b"off" | b"0" => Some(false),
        _ => None,
    }
}

fn exact_utf8(value: &[u8], label: &str) -> Result<String> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| KinError::Other(format!("{label} escaped preflight with non-UTF-8 bytes")))
}

fn exact_utf8_values(values: &[Vec<u8>], label: &str) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| exact_utf8(value, label))
        .collect()
}

fn copy_captured_authority(
    prepared: &crate::init::PreparedRepositoryInit,
    snapshot: &LosslessGitRepository,
    capture_store: &BlobStore,
    proof: &GitMigrationPreflightProof,
    progress: &mut PhaseProgress,
) -> Result<()> {
    let total_objects = snapshot.objects.len();
    let report_every = progress_interval(total_objects);
    // One session for the whole copy. Every body here lands in a staging store
    // that holds no authority yet, and a crash before
    // `commit_repository_bootstrap` discards the store whole, so the batch
    // boundary and the durability boundary this phase actually needs are the
    // same boundary.
    prepared.with_source_blob_batch(&mut |batch| {
        for (copied, record) in snapshot.objects.iter().enumerate() {
            if copied.is_multiple_of(report_every) {
                progress.detail(format_args!("{copied}/{total_objects} objects"));
            }
            let capture_hash = kin_blobs::Hash256::from_bytes(*record.body_hash.as_bytes());
            let body = capture_store.read(&capture_hash).map_err(|error| {
                git_boundary_error(
                    format!("read captured Git object {}", record.object.oid),
                    error,
                )
            })?;
            if staged_body_is_withheld(record.body_hash) {
                continue;
            }
            batch.save(record.body_hash, &body)?;
        }
        for input in &proof.ignored_local.inputs {
            let observed_len = u64::try_from(input.body.len()).map_err(|_| {
                KinError::Other("local Git ignore input exceeds u64 byte length".to_string())
            })?;
            let observed_hash = Hash256::from_bytes(kin_blobs::digest_bytes(&input.body));
            if observed_len != input.body_len || observed_hash != input.body_hash {
                return Err(KinError::Other(
                    "local Git ignore input no longer matches its preflight identity".to_string(),
                ));
            }
            batch.save(input.body_hash, &input.body)?;
        }
        Ok(())
    })?;
    progress.detail(format_args!("{total_objects}/{total_objects} objects"));
    Ok(())
}

/// How often a bounded walk should report, so a long phase stays visible
/// without the reporting itself becoming the cost. Never zero, so the caller's
/// modulo is always defined on an empty walk.
fn progress_interval(total: usize) -> usize {
    (total / 100).max(1)
}

/// Seal the staged closure, reporting the walk as it advances.
fn seal_observed_content(
    closure: &impl AdmittedContentClosure,
    content: &impl SealedContentSource,
    progress: &mut PhaseProgress,
) -> kin_git::Result<SealedContentObservation> {
    let mut report_every = 0usize;
    seal_all_content_observation_observed(closure, content, &mut |done, total| {
        if report_every == 0 {
            report_every = progress_interval(total);
        }
        if done.is_multiple_of(report_every) || done == total {
            progress.detail(format_args!("{done}/{total} trees"));
        }
    })
}

fn bind_workspace_authority(
    transaction: &mut RepositoryTransaction,
    workspace_id: kin_model::WorkspaceId,
    workspace_seed: kin_git::GitWorkspaceSeed,
    workspace_policy: kin_model::SharedAdmissionPolicy,
    proof: &GitMigrationPreflightProof,
) -> Result<()> {
    if proof.head != workspace_seed.head
        || proof.base_target != workspace_seed.base_target
        || proof.base_commit_oid != workspace_seed.base_commit_oid
        || proof.base_tree_hash != workspace_seed.base_tree_hash
    {
        return Err(KinError::Other(
            "Git preflight is not bound to the admitted workspace seed".to_string(),
        ));
    }
    let tree_hash = compute_resolved_tree_hash(&workspace_seed.base_tree)
        .map_err(|error| KinError::Other(error.to_string()))?;
    let valid_tree_identity = match workspace_seed.base_tree_hash {
        Some(expected) => expected == tree_hash,
        None => {
            workspace_seed.base_target.is_none()
                && workspace_seed.base_commit_oid.is_none()
                && workspace_seed.base_tree.is_empty()
        }
    };
    if !valid_tree_identity {
        return Err(KinError::Other(
            "admitted Git workspace tree does not match its canonical base identity".to_string(),
        ));
    }
    let tree_deltas = workspace_seed
        .base_tree
        .artifacts()
        .map(|artifact| TreeDelta::Added {
            artifact_id: artifact.artifact_id,
            new: LocatedEntry::new(artifact.path.clone(), artifact.entry),
        })
        .collect::<Vec<_>>();
    let local_overlay = frozen_local_overlay(workspace_id, proof)?;
    let effective_policy = EffectiveAdmissionPolicyStamp {
        shared: workspace_policy.stamp(),
        local: local_overlay.stamp(),
    };
    let semantic_delta = imported_workspace_semantic_delta(transaction, &workspace_seed)?;
    transaction.workspace_mutation = Some(WorkspaceMutation {
        workspace_id,
        expected: WorkspaceExpectation::MustNotExist,
        new_generation: 0,
        new_head: workspace_seed.head.clone(),
        new_base_target: workspace_seed.base_target,
        new_base_tree_hash: workspace_seed.base_tree_hash,
        tree_deltas,
        new_tree_hash: tree_hash,
        semantic_delta,
        new_shared_admission_policy: workspace_policy,
        new_admission_policy: effective_policy,
    });
    transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(local_overlay));
    Ok(())
}

fn imported_workspace_semantic_delta(
    transaction: &RepositoryTransaction,
    workspace_seed: &kin_git::GitWorkspaceSeed,
) -> Result<WorkspaceSemanticDelta> {
    let Some(base_target) = &workspace_seed.base_target else {
        return Ok(WorkspaceSemanticDelta::default());
    };
    let change_id = match base_target {
        kin_model::RefTarget::Change { change_id } => *change_id,
        kin_model::RefTarget::ExternalObject { object } => transaction
            .aliases
            .iter()
            .find(|alias| alias.oid == object.oid)
            .map(|alias| alias.change_id)
            .ok_or_else(|| {
                KinError::Other(format!(
                    "Git workspace base {} has no semantic change alias in its bootstrap transaction",
                    object.oid
                ))
            })?,
        kin_model::RefTarget::Symbolic { .. } => {
            return Err(KinError::Other(
                "Git workspace bootstrap base must be resolved before semantic admission"
                    .to_string(),
            ))
        }
    };

    let graph = kin_db::InMemoryGraph::new();
    for change in &transaction.changes {
        graph.create_change(change).map_err(|error| {
            KinError::Other(format!("stage imported semantic history: {error}"))
        })?;
    }
    let target = graph.resolve_graph_at(&change_id).map_err(|error| {
        KinError::Other(format!("resolve imported workspace semantics: {error}"))
    })?;
    crate::diff_workspace_semantics(
        &Default::default(),
        &Default::default(),
        &target.entities,
        &target.relations,
    )
    .map_err(|error| KinError::Other(format!("derive imported workspace semantics: {error}")))
}

fn frozen_local_overlay(
    workspace_id: kin_model::WorkspaceId,
    proof: &GitMigrationPreflightProof,
) -> Result<FrozenLocalOverlay> {
    let sources = proof
        .ignored_local
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            if input.order != index {
                return Err(KinError::Other(
                    "local Git ignore precedence is not contiguous".to_string(),
                ));
            }
            let precedence = u32::try_from(index).map_err(|_| {
                KinError::Other("local Git ignore source count exceeds u32".to_string())
            })?;
            let kind = match input.source_kind {
                GitLocalIgnoreSourceKind::ResolvedGlobalExcludes => {
                    LocalAdmissionRuleSourceKind::GitGlobalExclude
                }
                GitLocalIgnoreSourceKind::RepositoryInfoExclude => {
                    LocalAdmissionRuleSourceKind::GitInfoExclude
                }
            };
            Ok(LocalAdmissionRuleSource {
                kind,
                body_hash: input.body_hash,
                body_len: input.body_len,
                precedence,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let case = if proof.ignored_local.ignore_case {
        AdmissionCase::FoldAscii
    } else {
        AdmissionCase::Sensitive
    };
    FrozenLocalOverlay::new(workspace_id, 0, case, sources)
        .map_err(|error| KinError::Other(error.to_string()))
}

fn git_boundary_error(context: impl std::fmt::Display, error: impl std::fmt::Display) -> KinError {
    KinError::Other(format!("{context}: {error}"))
}

/// Bind the deterministic entity and relation deltas of every imported change.
///
/// The replay reads only graph-owned resolved trees and verified CAS bodies, so
/// admitted history carries its semantics without consulting the source
/// repository, its index, or the worktree. Binding recomputes change, parent,
/// and alias identities, so it must happen before any identity derived from the
/// plan is published.
fn bind_historical_semantics(
    plan: kin_git::SemanticGitImportPlan,
    capture_store: &BlobStore,
) -> Result<kin_git::SemanticGitImportPlan> {
    let mut trees = std::collections::BTreeMap::new();
    for alias in &plan.aliases {
        let tree = plan.commit_trees.get(&alias.oid).ok_or_else(|| {
            git_boundary_error(
                "bind historical semantics",
                format!("imported commit {} has no exact resolved tree", alias.oid),
            )
        })?;
        if trees.insert(alias.change_id, tree.clone()).is_some() {
            return Err(git_boundary_error(
                "bind historical semantics",
                format!("imported history repeats change {}", alias.change_id),
            ));
        }
    }

    let bindings =
        kin_index::derive_historical_semantic_deltas(&plan.changes, &trees, capture_store)
            .map_err(|error| git_boundary_error("derive historical semantics", error))?
            .into_iter()
            .map(|delta| (delta.change_id, delta.entity_deltas, delta.relation_deltas))
            .collect::<Vec<_>>();

    plan.with_historical_semantics(capture_store, &bindings)
        .map_err(|error| git_boundary_error("bind historical semantics", error))
}

/// Park a captured init where a test can kill it on a settled capture tree.
///
/// The kill point belongs to the child, not to a parent guessing at it from
/// outside. A parent that polls the capture directory and signals once it looks
/// full enough is signalling a live writer, and removing a tree a writer is
/// still extending is allowed to fail: `remove_staging_tree` retries a bounded
/// number of times and then leaves the directory carrying its lease for the
/// next init to reap. The interrupted-init test asserts the directory is gone,
/// which is the stronger of the two outcomes, so guessing the moment made the
/// assertion a coin flip and ejected merge-queue batches that had touched no
/// Rust at all.
///
/// Parking here settles it. The capture holds the entire object closure by this
/// point and nothing writes into it again, so the signal path's removal is the
/// only thing left to decide the result. The path is published by rename, so a
/// parent never reads a half-written name, and the thread then blocks: only the
/// signal ends this process.
#[cfg(all(test, unix))]
fn park_at_capture_barrier(capture: &Path) {
    use std::os::unix::ffi::OsStrExt as _;

    let Some(barrier) = std::env::var_os("KIN_INIT_INTERRUPTED_TEST_BARRIER") else {
        return;
    };
    let barrier = std::path::PathBuf::from(barrier);
    let staging = barrier.with_extension("publishing");
    std::fs::write(&staging, capture.as_os_str().as_bytes()).expect("stage the capture barrier");
    std::fs::rename(&staging, &barrier).expect("publish the capture barrier");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[cfg(not(all(test, unix)))]
fn park_at_capture_barrier(_capture: &Path) {}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn exact_remote_configuration_is_sealed_in_local_kin_config() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        git(
            &source,
            ["remote", "add", "origin", "https://example.invalid/kin.git"],
        );
        git(
            &source,
            [
                "remote",
                "set-url",
                "--add",
                "origin",
                "https://mirror.example.invalid/kin.git",
            ],
        );
        git(
            &source,
            [
                "remote",
                "set-url",
                "--push",
                "origin",
                "ssh://example.invalid/kin.git",
            ],
        );
        git(
            &source,
            [
                "config",
                "--add",
                "remote.origin.push",
                "refs/heads/main:refs/heads/main",
            ],
        );
        git(&source, ["config", "branch.main.remote", "origin"]);
        git(&source, ["config", "branch.main.merge", "refs/heads/main"]);
        git(&source, ["config", "remote.pushDefault", "origin"]);
        git(&source, ["config", "push.default", "simple"]);

        let result = init_from_git(&source).unwrap();

        assert_eq!(result.config.git.remotes.len(), 1);
        assert_eq!(
            result.config.git.remotes[0].fetch_urls,
            vec![
                "https://example.invalid/kin.git",
                "https://mirror.example.invalid/kin.git",
            ]
        );
        assert_eq!(
            result.config.git.remotes[0].push_urls,
            vec!["ssh://example.invalid/kin.git"]
        );
        assert_eq!(
            result.config.git.remotes[0].fetch_refspecs,
            vec!["+refs/heads/*:refs/remotes/origin/*"]
        );
        assert_eq!(
            result.config.git.remotes[0].push_refspecs,
            vec!["refs/heads/main:refs/heads/main"]
        );
        assert_eq!(result.config.git.branches.len(), 1);
        assert_eq!(
            result.config.git.branches[0].remote.as_deref(),
            Some("origin")
        );
        assert_eq!(
            result.config.git.remote_push_default.as_deref(),
            Some("origin")
        );
        assert_eq!(result.config.git.push_default, Some(GitPushDefault::Simple));
        let reopened = KinConfig::load(&result.layout.config_path()).unwrap();
        assert_eq!(reopened.git, result.config.git);
        assert!(!format!("{reopened:?}").contains("example.invalid"));
        assert_no_staging_directories(root.path());
    }

    /// Source blockers are reported before any derivation phase runs.
    ///
    /// The fixture is shallow as well as blocked. Capture is the phase after the
    /// blocker check and refuses a shallow source with its own message, so
    /// whichever message comes back names the phase that ran first. A timing
    /// assertion would claim the same thing and pass on a slow machine for the
    /// wrong reason.
    #[test]
    fn source_blockers_are_reported_before_any_history_is_derived() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        let head = git_stdout(&source, ["rev-parse", "HEAD"]);
        std::fs::write(source.join(".git/shallow"), format!("{}\n", head.trim())).unwrap();
        git(&source, ["config", "remote.origin.tagOpt", "--tags"]);

        let error = init_from_git(&source).unwrap_err().to_string();

        assert!(error.contains("remote.origin.tagOpt"), "{error}");
        assert!(
            !error.contains("shallow"),
            "capture must not have run yet: {error}"
        );
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    /// One refusal carries every blocker, each with the way out.
    #[test]
    fn every_source_blocker_reaches_the_operator_together() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        git(&source, ["config", "remote.origin.tagOpt", "--tags"]);
        git(&source, ["config", "branch.main.pushRemoteRef", "main"]);
        git(&source, ["config", "filter.demo.clean", "external-clean"]);
        // Admissible beside the three blockers, so this also proves a
        // classified key does not add a fourth line to the refusal.
        git(&source, ["config", "branch.main.vscode-merge-base", "main"]);

        let error = init_from_git(&source).unwrap_err().to_string();

        assert!(error.contains("remote.origin.tagOpt"), "{error}");
        assert!(error.contains("branch.main.pushRemoteRef"), "{error}");
        assert!(error.contains("filter \"demo\""), "{error}");
        assert!(
            !error.contains("vscode-merge-base"),
            "a classified key must not reach the refusal: {error}"
        );
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    /// A repository someone has been working in initializes.
    ///
    /// This is the whole point of the change: the wall a first adopter hits is
    /// an ordinary working tree, and the repository that comes out of it must
    /// still be sealed at the committed state. The assertions are therefore both
    /// halves, that init succeeded and that nothing uncommitted reached
    /// authority, plus the disclosure that says where the delta went.
    #[test]
    fn a_worked_in_repository_initializes_and_discloses_what_it_did_not_admit() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        std::fs::write(source.join("kept.txt"), b"committed\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        let committed_tree = git_stdout(&source, ["rev-parse", "HEAD^{tree}"]);

        std::fs::write(source.join("README.md"), b"edited after the commit\n").unwrap();
        std::fs::write(source.join("init.log"), b"log\n").unwrap();
        std::fs::write(source.join("staged.txt"), b"staged\n").unwrap();
        git(&source, ["add", "staged.txt"]);

        let result = init_from_git(&source).unwrap();

        // The tree under authority is the committed one, byte for byte. Reading
        // it back out of the repository and comparing against Git's own hash of
        // the commit is what proves the edit did not enter, rather than the
        // absence of an error.
        assert_eq!(
            git_stdout(&source, ["rev-parse", "HEAD^{tree}"]),
            committed_tree
        );
        assert_eq!(result.authority.workspace.workspace_generation, 0);
        let divergence = &result.workspace_divergence;
        assert_eq!(divergence.observed_paths(), 3, "{divergence:?}");
        let disclosed = divergence
            .entries
            .iter()
            .map(|entry| (entry.path.to_string(), entry.kind))
            .collect::<Vec<_>>();
        assert!(
            disclosed.contains(&(
                "README.md".to_string(),
                kin_git::GitWorkspaceDivergenceKind::Modified
            )),
            "{disclosed:?}"
        );
        assert!(
            disclosed.contains(&(
                "staged.txt".to_string(),
                kin_git::GitWorkspaceDivergenceKind::Staged
            )),
            "{disclosed:?}"
        );
        assert!(
            disclosed.contains(&(
                "init.log".to_string(),
                kin_git::GitWorkspaceDivergenceKind::Untracked
            )),
            "{disclosed:?}"
        );
        // The source keeps every one of them.
        assert_eq!(
            std::fs::read(source.join("README.md")).unwrap(),
            b"edited after the commit\n"
        );
        assert!(source.join("init.log").exists());
        assert_no_staging_directories(root.path());
    }

    /// An init killed mid-capture leaves neither `.kin` nor a capture directory.
    ///
    /// The reported failure was exactly this: a `SIGTERM` left no `.kin`, so
    /// the store stayed atomic, and stranded the whole captured object closure
    /// beside the repository where nothing named it for a day.
    ///
    /// The child picks the moment. It captures the whole source, publishes the
    /// directory it staged, and blocks there, so the signal always lands on a
    /// capture tree that is complete and settled. Guessing that moment from
    /// outside was the flake: a parent polling for "enough files" signalled a
    /// live writer, and removal against a live writer may give up and leave the
    /// directory leased for the next init's reap, which is weaker than what
    /// this test asserts.
    #[cfg(unix)]
    #[test]
    fn an_init_killed_mid_capture_leaves_no_kin_and_no_capture_directory() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        // A closure worth stranding. The reported incident left 837 MiB of
        // loose objects behind, and removing an all-but-empty directory would
        // prove nothing about removing a real one.
        for index in 0..400 {
            std::fs::write(
                source.join(format!("body-{index:04}.txt")),
                format!("exact source body {index}\n").repeat(64),
            )
            .unwrap();
        }
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);

        let barrier = root.path().join("capture-barrier");
        let mut child = ParkedChild::spawn(
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("git_init::tests::interrupted_init_subprocess")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("KIN_INIT_INTERRUPTED_TEST_SOURCE", &source)
                .env("KIN_INIT_INTERRUPTED_TEST_BARRIER", &barrier),
        );

        let staged = wait_for_capture_barrier(&barrier, &mut child);
        // What the removal has to clear is a real closure, so say how real. A
        // barrier that ever moved ahead of the capture would otherwise leave
        // this test removing an empty directory and still passing.
        let captured = count_files(&staged);
        assert!(
            captured > 400,
            "{} holds {captured} files, too few to be the captured closure",
            staged.display()
        );
        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
            0,
            "deliver SIGTERM to the interrupted init"
        );
        let status = child.wait();

        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "the interrupted init must still die of its signal: {status:?}"
        );
        assert!(
            !source.join(".kin").exists(),
            "an interrupted init must publish nothing"
        );
        assert!(
            !staged.exists(),
            "{} survived the interrupted init",
            staged.display()
        );
        assert_no_staging_directories(root.path());
    }

    /// An init subprocess killed when it goes out of scope.
    ///
    /// The interrupted init blocks at its barrier until something signals it,
    /// so a parent that fails an assertion on the way there would otherwise
    /// leave a process parked for the rest of the run. Waiting takes the child
    /// out, so a reaped process is never signalled again under a pid something
    /// else has since been given.
    #[cfg(unix)]
    struct ParkedChild(Option<std::process::Child>);

    #[cfg(unix)]
    impl ParkedChild {
        fn spawn(command: &mut std::process::Command) -> Self {
            let child = command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn the interrupted init");
            Self(Some(child))
        }

        fn live(&mut self) -> &mut std::process::Child {
            self.0.as_mut().expect("the interrupted init is still live")
        }

        fn id(&mut self) -> u32 {
            self.live().id()
        }

        fn wait(&mut self) -> std::process::ExitStatus {
            self.0
                .take()
                .expect("the interrupted init is still live")
                .wait()
                .expect("await the interrupted init")
        }
    }

    #[cfg(unix)]
    impl Drop for ParkedChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Count every file under one tree, so a claim about what a capture holds
    /// can be wrong out loud.
    #[cfg(unix)]
    fn count_files(root: &Path) -> usize {
        let Ok(entries) = std::fs::read_dir(root) else {
            return 0;
        };
        entries
            .flatten()
            .map(|entry| match entry.path() {
                path if path.is_dir() => count_files(&path),
                _ => 1,
            })
            .sum()
    }

    /// Wait for the child to publish the capture directory it staged.
    ///
    /// The barrier appears only once a whole object closure is on disk, so a
    /// child that died before capturing anything fails this test rather than
    /// passing it.
    #[cfg(unix)]
    fn wait_for_capture_barrier(barrier: &Path, child: &mut ParkedChild) -> std::path::PathBuf {
        use std::os::unix::ffi::OsStrExt as _;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            match std::fs::read(barrier) {
                Ok(published) => {
                    let staged = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&published));
                    assert!(
                        staged.is_dir(),
                        "the init subprocess published {}, which is no capture directory",
                        staged.display()
                    );
                    return staged;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    panic!("read the capture barrier {}: {error}", barrier.display())
                }
            }
            if let Some(status) = child.live().try_wait().unwrap() {
                panic!("the init subprocess exited before it captured anything: {status:?}");
            }
            if std::time::Instant::now() >= deadline {
                panic!("the init subprocess never reached its capture barrier");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Child half of
    /// [`an_init_killed_mid_capture_leaves_no_kin_and_no_capture_directory`].
    ///
    /// Parks at the end of the capture phase through
    /// [`park_at_capture_barrier`], so the parent signals a settled tree rather
    /// than racing one still being written.
    #[cfg(unix)]
    #[test]
    fn interrupted_init_subprocess() {
        let Some(source) = std::env::var_os("KIN_INIT_INTERRUPTED_TEST_SOURCE") else {
            return;
        };
        let _ = init_from_git(Path::new(&source));
    }

    /// A capture directory a previous interrupted init left behind is removed
    /// by the next real init rather than accumulating beside the repository.
    #[test]
    fn a_stale_capture_directory_is_reaped_by_the_next_init() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        let stale = root.path().join(".kin-git-capture-Stranded");
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("capture.lease"), b"").unwrap();
        std::fs::create_dir(stale.join("objects")).unwrap();
        std::fs::write(stale.join("objects/body"), b"orphaned closure").unwrap();

        init_from_git(&source).unwrap();

        assert!(source.join(".kin").exists());
        assert!(
            !stale.exists(),
            "an abandoned capture directory must not survive the next init"
        );
        assert_no_staging_directories(root.path());
    }

    /// An ambiguous source still refuses, and says so before deriving anything.
    #[test]
    fn an_in_progress_git_operation_still_refuses() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        let head = git_stdout(&source, ["rev-parse", "HEAD"]);
        std::fs::write(source.join(".git/MERGE_HEAD"), format!("{}\n", head.trim())).unwrap();

        let error = init_from_git(&source).unwrap_err().to_string();

        assert!(
            error.contains("MERGE_HEAD") || error.contains("Merge"),
            "{error}"
        );
        assert!(error.contains("finish or abort"), "{error}");
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn unsafe_remote_configuration_fails_before_staging_without_disclosure() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        git(
            &source,
            [
                "remote",
                "add",
                "origin",
                "https://super-secret@example.invalid/private/repo.git",
            ],
        );

        let error = init_from_git(&source).unwrap_err().to_string();

        assert!(error.contains("safe exact subset"), "{error}");
        assert!(!error.contains("super-secret"), "{error}");
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn same_count_remote_url_drift_at_final_proof_blocks_publication() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        git(
            &source,
            ["remote", "add", "origin", "https://example.invalid/kin.git"],
        );

        let source_for_hook = source.clone();
        let error = init_from_git_with_hook(&source, move || {
            git(
                &source_for_hook,
                [
                    "remote",
                    "set-url",
                    "origin",
                    "https://changed.example.invalid/kin.git",
                ],
            );
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("source proof changed"), "{error}");
        assert!(!error.contains("changed.example.invalid"), "{error}");
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    /// A moving ambient Git scope must not move an admission proof.
    ///
    /// The proof folds in the bytes of whatever ignore file Git resolves for
    /// this repository, and unpinned that file is decided by `core.excludesFile`
    /// then `XDG_CONFIG_HOME` then `HOME`. All three are process-global and this
    /// suite runs its tests as threads in one process, so a sibling test pinning
    /// the ambient scope for its own resolve shifts what a proof in flight
    /// beside it reads. The baseline then carries the host's ignore file and the
    /// re-proof carries none, and init refuses a source nothing wrote to. That
    /// is FIR-2388, seen as a 1-in-45 refusal of an unrelated test.
    ///
    /// This drives the shift deliberately, from inside the window between the
    /// first proof and the re-proof, which is the only placement that can fail:
    /// a scope moved before init is simply the scope all three proofs read. The
    /// guard is dropped the instant init returns, so the window this opens for
    /// the rest of the suite is the one it is testing and no wider.
    #[test]
    fn a_moving_ambient_git_scope_does_not_move_the_admission_proof() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);

        let elsewhere = tempfile::tempdir().unwrap();
        let global_config = elsewhere.path().join("global.gitconfig");
        std::fs::write(&global_config, "").unwrap();

        let mut ambient = None;
        let result = init_from_git_with_hook(&source, || {
            ambient = Some(
                crate::test_env::EnvVarGuard::new()
                    .with("GIT_CONFIG_NOSYSTEM", "1")
                    .with("GIT_CONFIG_GLOBAL", &global_config)
                    .with("HOME", elsewhere.path())
                    .without("XDG_CONFIG_HOME"),
            );
        });
        drop(ambient);

        result.unwrap();
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());
    }

    /// A tracked edit racing publication is still fatal.
    ///
    /// The proof no longer refuses an edited worktree, so what catches this is
    /// the comparison of the two proofs rather than the second one failing. The
    /// outcome is the same and the reason is different, which is why the
    /// assertion names the sentence the comparison produces.
    #[test]
    fn source_drift_immediately_after_publication_is_detected_fail_loud() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);

        let source_for_hook = source.clone();
        let error = init_from_git_with_hooks(
            &source,
            || {},
            move || {
                std::fs::write(source_for_hook.join("README.md"), b"raced source\n").unwrap();
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            KinError::RepositoryPublishedButUncertain { .. }
        ));
        assert!(
            error
                .to_string()
                .contains("changed across repository publication"),
            "{error}"
        );
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn pristine_unborn_repository_without_an_index_initializes_atomically() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        assert!(!source.join(".git/index").exists());

        let result = init_from_git(&source).unwrap();

        assert_eq!(result.authority.receipt.generation, 1);
        assert!(result.authority.workspace.base_target.is_none());
        assert!(result.authority.workspace.base_tree_hash.is_none());
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn born_empty_commit_keeps_a_present_empty_tree_identity() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        git(
            &source,
            [
                "commit",
                "--allow-empty",
                "--no-gpg-sign",
                "-m",
                "born empty",
            ],
        );

        let result = init_from_git(&source).unwrap();

        assert!(result.authority.workspace.base_target.is_some());
        assert!(result.authority.workspace.base_tree_hash.is_some());
        assert_eq!(
            result.authority.workspace.base_tree_hash,
            Some(result.authority.workspace.workspace_tree_hash)
        );
        assert!(!result.authority.workspace.is_dirty());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn detached_annotated_tag_keeps_raw_tag_authority_and_seeds_the_peeled_commit() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_annotated_tag_source(&source);
        let tag_oid = git_stdout(&source, ["rev-parse", "refs/tags/release"]);
        std::fs::write(source.join(".git/HEAD"), format!("{}\n", tag_oid.trim())).unwrap();

        let result = init_from_git(&source).unwrap();
        let backend = std::sync::Arc::new(kin_db::LocalFileBackend::new(result.layout.kindb_dir()));
        let authority =
            kin_db::RepositoryAuthorityManager::open(result.repository_id.clone(), backend)
                .unwrap();
        let lease = authority.read_authority();
        let git_authority = lease.metadata().git_external_authority.as_ref().unwrap();
        let (direct_target, commit_oid) = match &git_authority.material_head {
            GitMaterialHead::Commit {
                direct_target,
                tag_chain,
                commit_oid,
                ..
            } => {
                assert_eq!(direct_target.kind, ExternalObjectKind::Tag);
                assert_eq!(tag_chain.as_slice(), [*direct_target]);
                (*direct_target, *commit_oid)
            }
            other => panic!("expected material annotated-tag commit, got {other:?}"),
        };
        assert!(matches!(
            git_authority.raw_head,
            kin_model::GitRawTarget::Direct { object } if object == direct_target
        ));
        let material_target = kin_model::RefTarget::external_object(ExternalObjectId::new(
            ExternalObjectKind::Commit,
            commit_oid,
        ));
        assert_eq!(
            result.authority.workspace.workspace_head,
            kin_model::WorkspaceHead::Detached {
                target: material_target.clone()
            }
        );
        assert_eq!(
            result.head,
            kin_model::WorkspaceHead::Detached {
                target: material_target.clone()
            }
        );
        assert_eq!(
            result.authority.workspace.base_target,
            Some(material_target)
        );
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn symbolic_annotated_tag_keeps_raw_ref_authority_and_seeds_the_peeled_commit() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_annotated_tag_source(&source);
        git(&source, ["symbolic-ref", "HEAD", "refs/tags/release"]);

        let result = init_from_git(&source).unwrap();
        let backend = std::sync::Arc::new(kin_db::LocalFileBackend::new(result.layout.kindb_dir()));
        let authority =
            kin_db::RepositoryAuthorityManager::open(result.repository_id.clone(), backend)
                .unwrap();
        let lease = authority.read_authority();
        let git_authority = lease.metadata().git_external_authority.as_ref().unwrap();
        let (direct_target, commit_oid) = match &git_authority.material_head {
            GitMaterialHead::Commit {
                direct_target,
                tag_chain,
                commit_oid,
                ..
            } => {
                assert_eq!(direct_target.kind, ExternalObjectKind::Tag);
                assert_eq!(tag_chain.as_slice(), [*direct_target]);
                (*direct_target, *commit_oid)
            }
            other => panic!("expected material annotated-tag commit, got {other:?}"),
        };
        let tag_ref = kin_model::RefName::tag(b"release").unwrap();
        assert_eq!(
            git_authority.raw_head,
            kin_model::GitRawTarget::Symbolic {
                target: tag_ref.clone()
            }
        );
        assert!(git_authority.raw_refs.iter().any(|raw_ref| {
            raw_ref.name == tag_ref
                && matches!(
                    raw_ref.target,
                    kin_model::GitRawTarget::Direct { object } if object == direct_target
                )
        }));
        assert_eq!(
            result.authority.workspace.workspace_head,
            kin_model::WorkspaceHead::Symbolic {
                target: tag_ref.clone()
            }
        );
        assert_eq!(
            result.head,
            kin_model::WorkspaceHead::Symbolic {
                target: tag_ref.clone()
            }
        );
        assert_eq!(
            result.authority.workspace.base_target,
            Some(kin_model::RefTarget::external_object(
                ExternalObjectId::new(ExternalObjectKind::Commit, commit_oid)
            ))
        );
        assert_no_staging_directories(root.path());
    }

    #[cfg(unix)]
    #[test]
    fn byte_symbolic_git_head_is_reported_exactly_without_inventing_main() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        let raw_branch_leaf = b"raw-\xff".to_vec();
        let mut raw_head = b"ref: refs/heads/".to_vec();
        raw_head.extend_from_slice(&raw_branch_leaf);
        raw_head.push(b'\n');
        std::fs::write(source.join(".git/HEAD"), raw_head).unwrap();

        let result = init_from_git(&source).unwrap();

        let mut expected = b"refs/heads/".to_vec();
        expected.extend_from_slice(&raw_branch_leaf);
        assert!(matches!(
            &result.head,
            kin_model::WorkspaceHead::Symbolic { target } if target.as_bytes() == expected
        ));
        assert!(matches!(
            &result.authority.workspace.workspace_head,
            kin_model::WorkspaceHead::Symbolic { target } if target.as_bytes() == expected
        ));
        assert_ne!(
            match &result.head {
                kin_model::WorkspaceHead::Symbolic { target } => target.as_bytes(),
                kin_model::WorkspaceHead::Detached { .. } => unreachable!(),
            },
            b"refs/heads/main"
        );
        assert_no_staging_directories(root.path());
    }

    #[cfg(unix)]
    #[test]
    fn private_git_repository_keeps_staged_and_published_authority_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"private source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "private history"]);

        let staging_parent = root.path().to_path_buf();
        let result = init_from_git_with_hook(&source, move || {
            let staging = std::fs::read_dir(&staging_parent)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.is_dir()
                        && path
                            .file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with(".kin.init-"))
                })
                .expect("complete unpublished staging directory");
            assert_eq!(
                std::fs::symlink_metadata(&staging)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert!(staging.join("config.toml").is_file());
        })
        .unwrap();

        assert_eq!(
            std::fs::symlink_metadata(result.layout.root())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_no_staging_directories(root.path());
    }

    #[cfg(unix)]
    #[test]
    fn exact_git_init_admits_polyglot_non_code_and_opaque_history_atomically() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::Arc;

        use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
        use kin_model::{RepoPath, TreeEntry};

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::create_dir_all(source.join("src")).unwrap();
        std::fs::create_dir_all(source.join("service")).unwrap();
        std::fs::write(source.join(".gitignore"), b"*.tmp\n").unwrap();
        std::fs::write(
            source.join("compose.yaml"),
            b"services:\n  api:\n    build: .\n",
        )
        .unwrap();
        std::fs::write(source.join("Dockerfile"), b"FROM scratch\n").unwrap();
        std::fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 42 }\n").unwrap();
        std::fs::write(source.join("service/app.py"), b"print('kin')\n").unwrap();
        let payload = [0_u8, 255, 17, 0, 128, 42];
        std::fs::write(source.join("payload.bin"), payload).unwrap();
        let executable = source.join("tool");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
        symlink("compose.yaml", source.join("compose-link")).unwrap();
        let raw_name = if cfg!(target_os = "linux") {
            let name = OsString::from_vec(vec![b'r', b'a', b'w', b'-', 0x80]);
            std::fs::write(source.join(&name), b"raw path\n").unwrap();
            Some(name)
        } else {
            // macOS rejects an invalid UTF-8 pathname at the filesystem API
            // boundary. The DB/raw-tree contract covers that case without
            // pretending the local checkout can materialize it.
            None
        };
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "mixed exact tree"]);

        std::fs::create_dir_all(source.join("containers")).unwrap();
        git(&source, ["mv", "Dockerfile", "containers/Dockerfile"]);
        std::fs::write(
            source.join("compose.yaml"),
            b"services:\n  api:\n    build:\n      context: .\n",
        )
        .unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "move build artifact"]);
        std::fs::write(source.join("scratch.tmp"), b"ignored local state\n").unwrap();

        let result = init_from_git(&source).unwrap();

        assert_eq!(result.authority.receipt.generation, 1);
        assert!(result.authority.initial_change_id.is_some());
        assert!(!result.authority.workspace.is_dirty());
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());

        let backend = Arc::new(LocalFileBackend::new(result.layout.kindb_dir()));
        let authority =
            RepositoryAuthorityManager::open(result.repository_id.clone(), backend).unwrap();
        let lease = authority.read_authority();
        let metadata = lease.metadata();
        let git_authority = metadata.git_external_authority.as_ref().unwrap();
        assert_eq!(git_authority.commit_projections.len(), 2);
        assert_eq!(metadata.aliases.len(), 2);
        assert_eq!(metadata.workspaces.len(), 1);
        let workspace = &metadata.workspaces[0];
        assert_eq!(
            workspace.tree.artifacts().len(),
            if raw_name.is_some() { 9 } else { 8 }
        );

        let compose_path = RepoPath::from_utf8("compose.yaml").unwrap();
        let compose = workspace.tree.artifact_at_path(&compose_path).unwrap();
        let TreeEntry::Blob {
            hash: compose_hash,
            executable: false,
        } = compose.entry
        else {
            panic!("Compose file lost exact blob identity");
        };
        assert_eq!(
            authority.load_source_blob(compose_hash).unwrap().unwrap(),
            b"services:\n  api:\n    build:\n      context: .\n"
        );

        let payload_path = RepoPath::from_utf8("payload.bin").unwrap();
        let payload_artifact = workspace.tree.artifact_at_path(&payload_path).unwrap();
        let TreeEntry::Blob {
            hash: payload_hash,
            executable: false,
        } = payload_artifact.entry
        else {
            panic!("binary payload lost exact blob identity");
        };
        assert_eq!(
            authority.load_source_blob(payload_hash).unwrap().unwrap(),
            payload
        );

        if let Some(raw_name) = raw_name {
            let raw_path = RepoPath::from_bytes(raw_name.as_encoded_bytes()).unwrap();
            assert!(workspace.tree.artifact_at_path(&raw_path).is_some());
        }
        assert!(matches!(
            workspace
                .tree
                .artifact_at_path(&RepoPath::from_utf8("compose-link").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Symlink { .. }
        ));
        assert!(matches!(
            workspace
                .tree
                .artifact_at_path(&RepoPath::from_utf8("tool").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Blob {
                executable: true,
                ..
            }
        ));
        assert!(workspace
            .tree
            .artifact_at_path(&RepoPath::from_utf8("containers/Dockerfile").unwrap())
            .is_some());
    }

    /// A source repository carrying an opaque binary, an executable bit, a
    /// symlink, an empty file, and two revisions of a source file, so the
    /// admitted closure spans more content than the workspace head alone.
    #[cfg(unix)]
    fn initialize_all_shapes_source(source: &Path) {
        use std::os::unix::fs::{symlink, PermissionsExt};

        initialize_git(source);
        std::fs::create_dir_all(source.join("src")).unwrap();
        std::fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 42 }\n").unwrap();
        std::fs::write(source.join("payload.bin"), [0_u8, 255, 17, 0, 128, 42]).unwrap();
        std::fs::write(source.join("empty.txt"), b"").unwrap();
        let executable = source.join("tool");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
        symlink("src/lib.rs", source.join("source-link")).unwrap();
        git(source, ["add", "--all"]);
        git(source, ["commit", "-m", "exact tree with every shape"]);

        // A second revision so a body that no longer appears at the workspace
        // head still belongs to the admitted closure.
        std::fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 43 }\n").unwrap();
        git(source, ["add", "--all"]);
        git(source, ["commit", "-m", "second revision"]);
    }

    #[cfg(unix)]
    #[test]
    fn admitted_repository_owns_every_historical_body_without_the_source_git_repository() {
        use std::sync::Arc;

        use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
        use kin_model::TreeEntry;

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_all_shapes_source(&source);

        let result = init_from_git(&source).unwrap();

        // Remove the Git object store the content came from. Anything the
        // repository can still answer is genuinely graph-owned.
        std::fs::remove_dir_all(source.join(".git")).unwrap();

        let backend = Arc::new(LocalFileBackend::new(result.layout.kindb_dir()));
        let authority =
            RepositoryAuthorityManager::open(result.repository_id.clone(), backend).unwrap();
        let lease = authority.read_authority();
        let metadata = lease.metadata();
        assert_eq!(metadata.aliases.len(), 2);

        let workspace = &metadata.workspaces[0];
        let mut proven = 0_usize;
        for artifact in workspace.tree.artifacts() {
            let Some(identity) = artifact.entry.blob_identity() else {
                continue;
            };
            let body = authority
                .load_source_blob(identity)
                .unwrap()
                .unwrap_or_else(|| {
                    panic!(
                        "admitted repository cannot answer for {}",
                        String::from_utf8_lossy(artifact.path.as_bytes())
                    )
                });
            assert_eq!(kin_blobs::digest(&body), identity);
            proven += 1;
        }
        // Five content-bearing paths: the source file, the opaque binary, the
        // empty file, the executable, and the symlink target.
        assert_eq!(proven, 5);

        // The superseded first revision is still owned, so history reads never
        // need the source Git repository either. Its body appears at no path in
        // the head tree, so only the admitted closure can account for it.
        let superseded_body = kin_blobs::digest(b"pub fn answer() -> u8 { 42 }\n");
        assert!(
            workspace
                .tree
                .artifacts()
                .all(|artifact| artifact.entry.blob_identity() != Some(superseded_body)),
            "the superseded body must not be reachable from the head tree"
        );
        let body = authority
            .load_source_blob(superseded_body)
            .unwrap()
            .expect("admitted repository cannot answer for the superseded revision");
        assert_eq!(kin_blobs::digest(&body), superseded_body);

        let superseded = lease
            .metadata()
            .aliases
            .iter()
            .map(|alias| alias.change_id)
            .collect::<Vec<_>>();
        assert_eq!(superseded.len(), 2);
        assert!(matches!(
            workspace
                .tree
                .artifact_at_path(&kin_model::RepoPath::from_utf8("source-link").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Symlink { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn admission_fails_closed_when_a_body_never_reaches_graph_storage() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_all_shapes_source(&source);

        // A Git blob's CAS identity is the digest of its raw body, which for a
        // regular file is the file's exact bytes.
        let opaque = kin_blobs::digest(&std::fs::read(source.join("payload.bin")).unwrap());

        withhold_staged_body(opaque);
        let error = init_from_git(&source).unwrap_err();
        clear_withheld_staged_body();

        let message = error.to_string();
        assert!(
            message.contains("seal all-content observation"),
            "admission must fail on the seal, got: {message}"
        );
        assert!(
            message.contains("payload.bin"),
            "the failure must name the unsealed path, got: {message}"
        );
        // Fail closed means nothing was published.
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    #[cfg(unix)]
    #[test]
    fn a_body_lost_across_publication_is_refused_before_the_published_seal_reads_it() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_all_shapes_source(&source);

        // Remove one body from the published store between the two
        // observations, which the staged observation already proved present.
        let opaque = kin_blobs::digest(&std::fs::read(source.join("payload.bin")).unwrap());
        let external_oid = match gix::hash::ObjectId::from_hex(
            git_stdout(&source, ["hash-object", "payload.bin"])
                .trim()
                .as_bytes(),
        )
        .unwrap()
        {
            gix::hash::ObjectId::Sha1(bytes) => kin_model::GitObjectId::sha1(bytes),
            gix::hash::ObjectId::Sha256(bytes) => kin_model::GitObjectId::sha256(bytes),
            _ => panic!("fixture Git returned an unsupported object ID algorithm"),
        };
        let external_object = ExternalObjectId::new(ExternalObjectKind::Blob, external_oid);
        let published_kin_dir = source.join(".kin");
        let error = init_from_git_with_hooks(
            &source,
            || {},
            move || remove_published_body(&published_kin_dir, opaque),
        )
        .unwrap_err();

        // A physically defective published body never reaches the published
        // seal: opening the published repository's authority loads and
        // re-digests every body the admitted trees reference, so it refuses
        // first. That is the layering this pins, and it is why the published
        // seal's own detection power is closure divergence rather than store
        // corruption. Do not rewrite this to expect the seal; a store defect
        // cannot get past graph-authority verification to reach it.
        let message = error.to_string();
        let missing_body = format!("body for {external_object:?} is absent");
        assert!(
            message.contains("Git external authority body validation failed"),
            "graph authority must refuse the absent body, got: {message}"
        );
        assert!(
            message.contains(&missing_body),
            "the refusal must name the exact lost external object, got: {message}"
        );
        // The rename already happened, so the contract here is uncertain rather
        // than absent: the operator is told to recover, not to reinitialize.
        assert!(matches!(
            error,
            KinError::RepositoryPublishedButUncertain { .. }
        ));
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());
    }

    #[cfg(unix)]
    #[test]
    fn published_closure_divergence_fails_loud_as_published_but_uncertain() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_all_shapes_source(&source);

        // The published derivation observes two plain files with their bodies
        // exchanged. Both bodies are present and byte-exact, so the seal itself
        // succeeds and only the cross-check against the staged observation can
        // refuse. Counts and byte totals are identical, so the fingerprint has
        // to bind content for this to be detectable at all.
        diverge_published_closure(true);
        let error = init_from_git(&source).unwrap_err();
        diverge_published_closure(false);

        let message = error.to_string();
        assert!(
            message
                .contains("sealed all-content observation changed across repository publication"),
            "the cross-check must name the divergence, got: {message}"
        );
        assert!(matches!(
            error,
            KinError::RepositoryPublishedButUncertain { .. }
        ));
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());
    }

    /// Delete one graph-owned body from a published repository.
    ///
    /// The body is located by the content identity the store names its file
    /// after, rather than by a hardcoded store layout, so the injection keeps
    /// working if the directory shape changes and fails loudly if the naming
    /// convention does.
    #[cfg(unix)]
    fn remove_published_body(published_kin_dir: &Path, identity: Hash256) {
        let name = identity
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(
            remove_first_named_file(published_kin_dir, &name),
            "published repository stores no body named {name}"
        );
    }

    #[cfg(unix)]
    fn remove_first_named_file(directory: &Path, name: &str) -> bool {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                if remove_first_named_file(&entry.path(), name) {
                    return true;
                }
            } else if entry.file_name() == std::ffi::OsStr::new(name) {
                std::fs::remove_file(entry.path()).unwrap();
                return true;
            }
        }
        false
    }

    fn initialize_git(source: &Path) {
        git(source, ["init", "--initial-branch=main"]);
        git(source, ["config", "user.email", "kin@example.invalid"]);
        git(source, ["config", "user.name", "Kin Test"]);
        pin_default_hook_surface(source);
        pin_resolved_global_excludes(source);
    }

    /// Bind a fixture's resolved global excludes to a file it owns.
    ///
    /// An exact source proof folds in the bytes of whatever ignore file Git
    /// resolves for this repository, and unpinned that file is decided by
    /// `core.excludesFile`, then `XDG_CONFIG_HOME`, then `HOME`. All three are
    /// process-global and this suite runs its tests as threads in one process,
    /// so a sibling test that pins the ambient Git scope for its own resolve
    /// moves what a proof in flight beside it observes. The baseline proof then
    /// carries the host's ignore file and the re-proof carries none, and init
    /// refuses a source nothing wrote to. Repository scope outranks both the
    /// host and that sibling, so pinning it here makes the observation depend on
    /// the fixture alone.
    fn pin_resolved_global_excludes(source: &Path) {
        let excludes = source.join(".git/kin-fixture-global-excludes");
        std::fs::write(&excludes, b"").unwrap();
        git(
            source,
            ["config", "core.excludesFile", excludes.to_str().unwrap()],
        );
    }

    /// Bind a fixture's hook surface to its own `.git/hooks`.
    ///
    /// Admission resolves hooks from merged Git configuration, and this process
    /// is not the isolated Git child a fixture launches, so a developer host
    /// that sets `core.hooksPath` globally would redirect every fixture at once
    /// and refuse them all. Repository scope outranks the host.
    fn pin_default_hook_surface(source: &Path) {
        let hooks = source.join(".git/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        git(
            source,
            ["config", "core.hooksPath", hooks.to_str().unwrap()],
        );
    }

    fn initialize_annotated_tag_source(source: &Path) {
        initialize_git(source);
        std::fs::write(source.join("README.md"), b"annotated tag source\n").unwrap();
        git(source, ["add", "--all"]);
        git(source, ["commit", "-m", "tagged commit"]);
        git(source, ["tag", "--annotate", "release", "-m", "release"]);
    }

    fn assert_no_staging_directories(parent: &Path) {
        let leftovers = std::fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| {
                name.to_string_lossy().starts_with(".kin.init-")
                    || name.to_string_lossy().starts_with(".kin-git-capture-")
            })
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty(), "staging leftovers: {leftovers:?}");
    }

    fn fixture_git(repository: &Path) -> kin_git::test_support::FixtureGitCommand {
        kin_git::test_support::fixture_git_in(repository)
    }

    fn git<const N: usize>(repository: &Path, args: [&str; N]) {
        let output = fixture_git(repository).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_stdout<const N: usize>(repository: &Path, args: [&str; N]) -> String {
        let output = fixture_git(repository).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
}
