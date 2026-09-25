// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Real retained projections and manager-prepared records. These are source
//! custody/replay controls, not daemon startup or semantic indexing acceptance.

use super::*;
use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    AuthorId, RepositoryTransaction, WorkspaceExpectation, WorkspaceMutation,
    WorkspaceSemanticDelta, WorkspaceState, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use std::sync::Arc;

#[test]
fn prepared_lookup_distinguishes_absent_active_and_completed_exact_operation() {
    let f = Fixture::new("session-lookup");
    assert!(f.lookup().unwrap().is_none());
    std::fs::write(f.session.join("answer.txt"), b"recorded target\n").unwrap();
    let observed = f.observe(false).unwrap();
    let prepared = f.prepare(&observed, false);
    let loaded = f.lookup().unwrap().unwrap();
    assert_eq!(loaded.operation_id(), prepared.operation_id());
    assert_eq!(loaded.expected_receipt(), prepared.expected_receipt());
    let (receipt, freeze) = f
        .manager
        .commit_prepared_session_publication(&prepared)
        .unwrap();
    drop(freeze);
    let roots = f.manager.read_authority().roots().clone();
    let replay = f.lookup().unwrap().unwrap();
    assert_eq!(replay.expected_receipt(), &receipt);
    assert_eq!(f.manager.read_authority().roots(), &roots);
}

#[test]
fn prepared_lookup_refuses_copied_controls_and_changed_base_bytes() {
    let f = Fixture::new("session-lookup-owner");
    std::fs::write(f.session.join("answer.txt"), b"recorded target\n").unwrap();
    let observed = f.observe(false).unwrap();
    f.prepare(&observed, false);
    let roots = f.manager.read_authority().roots().clone();
    let copied = f.layout.runs_dir().join("session-copied-controls");
    std::fs::create_dir_all(copied.join(".kin-session")).unwrap();
    std::fs::copy(
        f.session.join(".kin-session/base.json"),
        copied.join(".kin-session/base.json"),
    )
    .unwrap();
    let error = lookup_prepared_session_workspace(&f.layout, &f.binding, &copied, &f.manager)
        .expect_err("an operation ID in copied controls is not ownership");
    assert!(format!("{error:#}").contains("identity differs"));
    let mut changed = observed.base_bytes.clone();
    changed.push(b'\n');
    std::fs::write(f.session.join(".kin-session/base.json"), changed).unwrap();
    let error = f
        .lookup()
        .expect_err("exact acknowledged base bytes changed");
    assert!(format!("{error:#}").contains("identity differs"));
    assert_eq!(f.manager.read_authority().roots(), &roots);
}

#[test]
fn prepared_lookup_and_recovery_refuse_another_workspace_binding_or_manager() {
    let f = Fixture::new("session-binding-owner");
    std::fs::write(f.session.join("answer.txt"), b"recorded target\n").unwrap();
    let observed = f.observe(false).unwrap();
    let prepared = f.prepare(&observed, false);
    let wrong_workspace = kin_core::LocalRepositoryAuthorityBinding::from_parts(
        observed.base().repository_id.clone(),
        kin_model::WorkspaceId::new(),
        Arc::new(LocalFileBackend::new(f.layout.kindb_dir())),
    );
    let error =
        lookup_prepared_session_workspace(&f.layout, &wrong_workspace, &f.session, &f.manager)
            .expect_err("lookup rejects a different workspace");
    assert!(format!("{error:#}").contains("workspace identity does not match"));
    let error =
        observe_prepared_session_workspace(&f.layout, &wrong_workspace, &f.blobs, &prepared)
            .err()
            .expect("recovery rejects a different workspace");
    assert!(format!("{error:#}").contains("workspace identity does not match"));
    let other = Fixture::new("session-unrelated-authority");
    let error =
        lookup_prepared_session_workspace(&f.layout, &f.binding, &f.session, &other.manager)
            .expect_err("lookup must use this repository's manager");
    assert!(format!("{error:#}").contains("authority belongs to another repository"));
}

#[test]
fn prepared_recovery_observer_can_run_while_publication_authority_is_frozen() {
    for committed in [false, true] {
        let f = Fixture::new("session-frozen-observer");
        std::fs::write(f.session.join("answer.txt"), b"recorded target\n").unwrap();
        let observed = f.observe(false).unwrap();
        let prepared = f.prepare(&observed, false);
        let freeze = if committed {
            f.manager
                .commit_prepared_session_publication(&prepared)
                .unwrap()
                .1
        } else {
            let roots = f.manager.read_authority().roots().clone();
            f.manager.freeze_current_authority(&roots).unwrap()
        };
        std::thread::scope(|scope| {
            let (sent, received) = std::sync::mpsc::channel();
            let fixture = &f;
            let handle = &prepared;
            let child = scope.spawn(move || {
                let result = fixture.recover(handle);
                sent.send(()).unwrap();
                result
            });
            // A failed assertion must still release the freeze and join the
            // observer, rather than leave a thread blocked on the old reopen.
            let completed = received
                .recv_timeout(std::time::Duration::from_secs(2))
                .is_ok();
            drop(freeze);
            let recovered = child.join().unwrap().unwrap();
            assert!(
                completed,
                "prepared observation reopened frozen authority (committed={committed})"
            );
            assert_eq!(recovered.desired_tree(), observed.desired_tree());
        });
    }
}

#[test]
fn prepared_recovery_observer_preserves_historical_receipt_after_newer_work() {
    let f = Fixture::new("session-historical-observer");
    std::fs::write(f.session.join("answer.txt"), b"recorded target\n").unwrap();
    let observed = f.observe(false).unwrap();
    let prepared = f.prepare(&observed, false);
    let (original, freeze) = f
        .manager
        .commit_prepared_session_publication(&prepared)
        .unwrap();
    drop(freeze);
    let lease = f.manager.read_authority();
    let mut later = observed.base().clone();
    later.reconcile_operation_id = kin_model::OperationId::new();
    later.authority_roots = lease.roots().clone();
    later.source_workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == later.source_workspace.workspace_id)
        .unwrap()
        .clone();
    drop(lease);
    let body = b"newer unrelated work\n";
    let hash = kin_blobs::digest(body);
    f.manager.save_source_blob(hash, body).unwrap();
    let newer_tree = later
        .source_workspace
        .tree
        .apply(&[TreeDelta::Added {
            artifact_id: kin_model::ArtifactId::new(),
            new: kin_model::LocatedEntry::new(
                RepoPath::from_utf8("newer.txt").unwrap(),
                TreeEntry::blob(hash, false),
            ),
        }])
        .unwrap();
    f.manager
        .commit_repository_transaction(transaction(&later, &newer_tree))
        .unwrap();
    let before = f.manager.read_authority().roots().clone();
    assert!(before.generation > original.roots_after.generation);
    let loaded = f.lookup().unwrap().unwrap();
    let recovered = f.recover(&loaded).unwrap();
    assert_eq!(loaded.expected_receipt(), &original);
    assert_eq!(recovered.desired_tree(), observed.desired_tree());
    assert_eq!(f.manager.read_authority().roots(), &before);
    assert_eq!(
        f.manager
            .read_authority()
            .workspace_graph_snapshot(&later.source_workspace.workspace_id)
            .unwrap()
            .unwrap()
            .resolved_tree,
        newer_tree
    );
    std::fs::write(f.session.join("answer.txt"), b"changed retry target\n").unwrap();
    assert!(f.recover(&loaded).is_err());
    assert_eq!(f.manager.read_authority().roots(), &before);
}

struct Fixture {
    _repo: tempfile::TempDir,
    layout: kin_core::KinLayout,
    binding: kin_core::LocalRepositoryAuthorityBinding,
    blobs: kin_blobs::BlobStore,
    session: PathBuf,
    manager: RepositoryAuthorityManager<LocalFileBackend>,
}

fn transaction(base: &SessionWorkspaceBase, desired: &ResolvedTree) -> RepositoryTransaction {
    let current = &base.source_workspace;
    RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: base.reconcile_operation_id,
        repository_id: base.repository_id.clone(),
        expected_generation: base.authority_roots.generation,
        expected_roots: base.authority_roots.clone(),
        actor: AuthorId::new("retained-locator-test"),
        reason: "prepare exact retained target".into(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id: current.workspace_id,
            expected: expectation(current),
            new_generation: current.generation + 1,
            new_head: current.head.clone(),
            new_base_target: current.base_target.clone(),
            new_base_tree_hash: current.base_tree_hash,
            tree_deltas: kin_core::exact_tree_correction(&current.tree, desired).unwrap(),
            new_tree_hash: kin_model::compute_resolved_tree_hash(desired).unwrap(),
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: current.shared_admission_policy.clone(),
            new_admission_policy: current.admission_policy,
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    }
}

fn expectation(current: &WorkspaceState) -> WorkspaceExpectation {
    WorkspaceExpectation::MustEqual {
        generation: current.generation,
        head: current.head.clone(),
        base_target: current.base_target.clone(),
        base_tree_hash: current.base_tree_hash,
        tree_hash: current.tree_hash,
        semantic_overlay_hash: current.semantic_overlay_hash,
        admission_policy: current.admission_policy,
    }
}

impl Fixture {
    fn new(leaf: &str) -> Self {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let layout = initialized.layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let blobs = kin_blobs::BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let manager = RepositoryAuthorityManager::open(
            initialized.repository_id,
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        )
        .unwrap();
        let session = layout.runs_dir().join(leaf);
        crate::commands::session_workspace::materialize_session_workspace(
            &layout,
            &binding,
            &crate::commands::session_workspace::SessionWorkspaceRequest {
                session_dir: session.display().to_string(),
                strategy: None,
                scope: None,
            },
        )
        .unwrap();
        Self {
            _repo: repo,
            layout,
            binding,
            blobs,
            session,
            manager,
        }
    }
    fn observe(&self, confirmed: bool) -> Result<SessionReconcileObservation> {
        observe_session_workspace(
            &self.layout,
            &self.binding,
            &self.session,
            &self.blobs,
            confirmed,
        )
    }
    fn lookup(&self) -> Result<Option<kin_db::storage::PreparedSessionPublication>> {
        lookup_prepared_session_workspace(&self.layout, &self.binding, &self.session, &self.manager)
    }
    fn prepare(
        &self,
        observation: &SessionReconcileObservation,
        legacy: bool,
    ) -> kin_db::storage::PreparedSessionPublication {
        let base = observation.base();
        for artifact in observation.desired_tree().artifacts() {
            if let Some(digest) = artifact.entry.blob_identity() {
                let body = self
                    .blobs
                    .read(&kin_blobs::Hash256::from_bytes(*digest.as_bytes()))
                    .unwrap();
                self.manager.save_source_blob(digest, &body).unwrap();
            }
        }
        let observed = self
            .manager
            .workspace_graph_snapshot(&base.repository_id, &base.source_workspace.workspace_id)
            .unwrap()
            .unwrap();
        let binding = observation.publication_binding().unwrap();
        if legacy {
            self.manager
                .prepare_session_publication(
                    transaction(base, observation.desired_tree()),
                    base.source_workspace.workspace_id,
                    binding.binding().clone(),
                    &observed,
                    &kin_index::binding_history::LocalBindingHistoryVerifier,
                )
                .unwrap()
        } else {
            self.manager
                .prepare_session_publication_with_locator(
                    transaction(base, observation.desired_tree()),
                    base.source_workspace.workspace_id,
                    binding.binding().clone(),
                    binding.locator().clone(),
                    &observed,
                    &kin_index::binding_history::LocalBindingHistoryVerifier,
                )
                .unwrap()
        }
    }
    fn recover(
        &self,
        prepared: &kin_db::storage::PreparedSessionPublication,
    ) -> Result<SessionReconcileObservation> {
        observe_prepared_session_workspace(&self.layout, &self.binding, &self.blobs, prepared)
    }
    fn base(&self) -> SessionWorkspaceBase {
        serde_json::from_slice(&std::fs::read(self.session.join(".kin-session/base.json")).unwrap())
            .unwrap()
    }
    fn workspace(&self) -> WorkspaceState {
        self.manager
            .read_authority()
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == self.binding.workspace_id())
            .unwrap()
            .clone()
    }
    /// Commit another writer's workspace change straight to authority, the
    /// way a guarded entity mutation does, leaving every projection untouched.
    fn advance(&self, path: &str, body: &[u8]) -> kin_model::RootBundle {
        let lease = self.manager.read_authority();
        let mut later = self.base();
        later.reconcile_operation_id = kin_model::OperationId::new();
        later.authority_roots = lease.roots().clone();
        later.source_workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == later.source_workspace.workspace_id)
            .unwrap()
            .clone();
        drop(lease);
        let hash = kin_blobs::digest(body);
        self.manager.save_source_blob(hash, body).unwrap();
        let tree = later
            .source_workspace
            .tree
            .apply(&[TreeDelta::Added {
                artifact_id: kin_model::ArtifactId::new(),
                new: kin_model::LocatedEntry::new(
                    RepoPath::from_utf8(path).unwrap(),
                    TreeEntry::blob(hash, false),
                ),
            }])
            .unwrap();
        self.manager
            .commit_repository_transaction(transaction(&later, &tree))
            .unwrap()
            .roots_after
    }
}

impl Fixture {
    /// A fixture whose session is materialized over a base graph truth
    /// already holds `files` in, so a session can change and remove them.
    fn seeded(leaf: &str, files: &[(&str, &[u8])]) -> Self {
        let seed = Self::new(&format!("{leaf}-seed"));
        for (path, body) in files {
            seed.advance(path, body);
        }
        let session = seed.layout.runs_dir().join(leaf);
        crate::commands::session_workspace::materialize_session_workspace(
            &seed.layout,
            &seed.binding,
            &crate::commands::session_workspace::SessionWorkspaceRequest {
                session_dir: session.display().to_string(),
                strategy: None,
                scope: None,
            },
        )
        .unwrap();
        Self { session, ..seed }
    }

    fn observe_under(&self, write_back: SessionWriteBack) -> Result<SessionReconcileObservation> {
        observe_session_workspace_under(
            &self.layout,
            &self.binding,
            &self.session,
            &self.blobs,
            false,
            write_back,
        )
    }
}

fn admitted(observation: &SessionReconcileObservation) -> Vec<String> {
    observation
        .deltas()
        .iter()
        .filter_map(|delta| delta.new_state().or_else(|| delta.old_state()))
        .filter_map(|entry| entry.path.as_utf8().map(str::to_string))
        .collect()
}

fn withheld(
    observation: &SessionReconcileObservation,
) -> Vec<(String, ReconcileChangeKind, WithheldReason)> {
    observation
        .withheld()
        .iter()
        .map(|change| {
            let ReconcilePath::Utf8(path) = &change.path else {
                panic!("a UTF-8 path");
            };
            (path.clone(), change.kind, change.reason)
        })
        .collect()
}

fn mach_o() -> Vec<u8> {
    let mut body = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
    body.resize(4096, 0);
    body
}

const SEED: &[(&str, &[u8])] = &[
    ("main.go", b"package main\n\nfunc main() {}\n"),
    ("member.txt", b"admitted\n"),
];

/// An agent's toolchain run hands back the manifests and lockfiles its
/// toolchain owns and nothing else. Source it wrote, changed or removed is
/// refused and reported, so a command is never a whole-file write path into
/// the graph; so is every other file, and a build output is never admitted.
#[test]
fn an_agent_run_admits_toolchain_manifests_and_refuses_source() {
    let f = Fixture::seeded("session-agent-policy", SEED);
    std::fs::write(
        f.session.join("go.mod"),
        b"module example.com/app\n\ngo 1.25\n",
    )
    .unwrap();
    std::fs::write(f.session.join("go.sum"), b"").unwrap();
    std::fs::write(
        f.session.join("main.go"),
        b"package main\n\nfunc main() { println(\"hi\") }\n",
    )
    .unwrap();
    std::fs::write(f.session.join("extra.go"), b"package main\n").unwrap();
    std::fs::write(f.session.join("package.json"), b"{}\n").unwrap();
    std::fs::write(f.session.join("tasks.json"), b"[]\n").unwrap();
    std::fs::write(f.session.join("app"), mach_o()).unwrap();
    std::fs::remove_file(f.session.join("member.txt")).unwrap();

    let observation = f
        .observe_under(SessionWriteBack::ManifestsOf(Toolchain::Go))
        .unwrap();
    assert_eq!(admitted(&observation), vec!["go.mod", "go.sum"]);
    assert_eq!(
        withheld(&observation),
        vec![
            (
                "app".to_string(),
                ReconcileChangeKind::Added,
                WithheldReason::BuildOutput
            ),
            (
                "extra.go".to_string(),
                ReconcileChangeKind::Added,
                WithheldReason::SourceUnit
            ),
            (
                "main.go".to_string(),
                ReconcileChangeKind::Modified,
                WithheldReason::SourceUnit
            ),
            (
                "package.json".to_string(),
                ReconcileChangeKind::Added,
                WithheldReason::NotAToolchainManifest
            ),
            (
                "tasks.json".to_string(),
                ReconcileChangeKind::Added,
                WithheldReason::NotAToolchainManifest
            ),
            (
                "member.txt".to_string(),
                ReconcileChangeKind::Removed,
                WithheldReason::NotAToolchainManifest
            ),
        ]
    );
    // The desired tree keeps the base's main.go and member.txt exactly.
    let base_tree = &observation.base().source_workspace.tree;
    for kept in ["main.go", "member.txt"] {
        let path = RepoPath::from_utf8(kept).unwrap();
        assert_eq!(
            observation
                .desired_tree()
                .artifact_at_path(&path)
                .map(|a| a.entry),
            base_tree.artifact_at_path(&path).map(|a| a.entry),
            "{kept}"
        );
    }

    // The same session observed as a person's admits the source and the
    // removal, and still never the binary.
    let person = f
        .observe_under(SessionWriteBack::ExceptBuildOutputs)
        .unwrap();
    assert_eq!(
        admitted(&person),
        vec![
            "extra.go",
            "go.mod",
            "go.sum",
            "main.go",
            "member.txt",
            "package.json",
            "tasks.json"
        ]
    );
    assert_eq!(
        withheld(&person),
        vec![(
            "app".to_string(),
            ReconcileChangeKind::Added,
            WithheldReason::BuildOutput
        )]
    );
}

/// A rebuilt file graph truth already tracks is the repository's own, so a
/// person's session that changes it is admitted as before, binary or not.
#[test]
fn a_tracked_binary_a_person_rebuilds_is_still_admitted() {
    let f = Fixture::seeded("session-tracked-binary", &[("tool", b"\x7fELF old")]);
    std::fs::write(f.session.join("tool"), b"\x7fELF new").unwrap();
    let observation = f.observe(false).unwrap();
    assert_eq!(admitted(&observation), vec!["tool"]);
    assert!(observation.withheld().is_empty());
}

/// Recovery of an acknowledged publication reproduces its exact target
/// whichever policy planned it: the agent's manifest-only target recovers
/// with the source changes still withheld, and nothing new is admitted.
#[test]
fn recovery_reproduces_an_agent_publication_under_its_own_policy() {
    let f = Fixture::seeded("session-agent-recovery", SEED);
    std::fs::write(f.session.join("go.mod"), b"module example.com/app\n").unwrap();
    std::fs::write(f.session.join("extra.go"), b"package main\n").unwrap();
    let observation = f
        .observe_under(SessionWriteBack::ManifestsOf(Toolchain::Go))
        .unwrap();
    assert_eq!(admitted(&observation), vec!["go.mod"]);
    let prepared = f.prepare(&observation, false);
    let recovered = f.recover(&prepared).unwrap();
    assert_eq!(recovered.desired_tree(), observation.desired_tree());
    assert_eq!(admitted(&recovered), vec!["go.mod"]);
    assert_eq!(withheld(&recovered), withheld(&observation));
}

#[test]
fn prepared_locator_unicode_space_leaf_cold_reobserve_and_committed_replay() {
    let f = Fixture::new("session-actual space-東京");
    std::fs::write(f.session.join("answer.txt"), b"exact target\n").unwrap();
    let observation = f.observe(false).unwrap();
    let binding = observation.publication_binding().unwrap();
    assert!(binding.binding().session_id.starts_with("retained-"));
    assert!(!binding.binding().session_id.contains("東京"));
    assert_eq!(
        binding.locator(),
        &kin_db::storage::SessionPublicationLocator::RetainedUnixV1 {
            session_leaf: "session-actual space-東京".into(),
        }
    );
    let prepared = f.prepare(&observation, false);
    let cold = RepositoryAuthorityManager::open(
        observation.base().repository_id.clone(),
        Arc::new(LocalFileBackend::new(f.layout.kindb_dir())),
    )
    .unwrap();
    let loaded = cold
        .load_prepared_session_publication(prepared.operation_id())
        .unwrap()
        .unwrap();
    assert_eq!(
        f.recover(&loaded).unwrap().desired_tree(),
        observation.desired_tree()
    );
    // A newer unrelated session is never selected by recovery.
    std::fs::create_dir(f.layout.runs_dir().join("session-newer")).unwrap();
    let (receipt, freeze) = cold.commit_prepared_session_publication(&loaded).unwrap();
    drop(freeze);
    let replay = RepositoryAuthorityManager::open(
        observation.base().repository_id.clone(),
        Arc::new(LocalFileBackend::new(f.layout.kindb_dir())),
    )
    .unwrap();
    let loaded = replay
        .load_prepared_session_publication(prepared.operation_id())
        .unwrap()
        .unwrap();
    assert_eq!(loaded.expected_receipt(), &receipt);
    assert_eq!(
        f.recover(&loaded).unwrap().desired_tree(),
        observation.desired_tree()
    );
}

#[test]
fn prepared_locator_changed_target_is_not_mass_deletion_permission() {
    let f = Fixture::new("session-exact-target");
    for index in 0..20 {
        std::fs::write(f.session.join(format!("file-{index}.txt")), b"keep\n").unwrap();
    }
    let observation = f.observe(false).unwrap();
    let prepared = f.prepare(&observation, false);
    std::fs::remove_file(f.session.join("file-0.txt")).unwrap();
    let error = f
        .recover(&prepared)
        .err()
        .expect("changed target must refuse");
    assert!(format!("{error:#}").contains("acknowledged immutable target"));
    std::fs::write(f.session.join("file-0.txt"), b"keep\n").unwrap();
    f.recover(&prepared).unwrap();
}

#[test]
fn prepared_locator_legacy_record_has_no_filesystem_fallback() {
    let f = Fixture::new("session-legacy");
    std::fs::write(f.session.join("answer.txt"), b"target\n").unwrap();
    let prepared = f.prepare(&f.observe(false).unwrap(), true);
    let error = f
        .recover(&prepared)
        .err()
        .expect("legacy runtime identity unsupported");
    assert!(format!("{error:#}").contains("unsupported runtime recovery identity"));
}

#[test]
fn prepared_locator_exact_base_bytes_and_control_directory_replacements_refuse() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for replacement in ["bytes", "control", "session", "symlink"] {
        let f = Fixture::new("session-retained");
        std::fs::write(f.session.join("answer.txt"), b"target\n").unwrap();
        let prepared = f.prepare(&f.observe(false).unwrap(), false);
        let control = f.session.join(".kin-session");
        let base = control.join("base.json");
        let original = std::fs::read(&base).unwrap();
        match replacement {
            "bytes" => {
                let mut changed = original.clone();
                changed.push(b'\n');
                std::fs::write(&base, changed).unwrap();
            }
            "control" => {
                std::fs::rename(&control, f.session.join("old-control")).unwrap();
                std::fs::create_dir(&control).unwrap();
                std::fs::write(&base, &original).unwrap();
                std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            "session" => {
                std::fs::rename(&f.session, f.layout.runs_dir().join("session-original")).unwrap();
                std::fs::create_dir(&f.session).unwrap();
                std::fs::create_dir(&control).unwrap();
                std::fs::write(&base, &original).unwrap();
                std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::write(f.session.join("answer.txt"), b"target\n").unwrap();
            }
            "symlink" => {
                let displaced = f.layout.runs_dir().join("session-original");
                std::fs::rename(&f.session, &displaced).unwrap();
                symlink(&displaced, &f.session).unwrap();
            }
            _ => unreachable!(),
        }
        let error = f.recover(&prepared).err().expect(replacement);
        assert!(
            format!("{error:#}").contains("identity differs") || replacement == "symlink",
            "{replacement}: {error:#}"
        );
    }
}

#[test]
fn prepared_locator_identity_binds_workspace_control_runs_and_logical_owner() {
    let f = Fixture::new("session-chain");
    let observation = f.observe(false).unwrap();
    let expected = observation.publication_binding().unwrap();
    for position in 0..7 {
        let mut retained = RetainedSession::open(&f.layout, &f.session).unwrap();
        let mut base = observation.base().clone();
        match position {
            0 => retained.workspace_identity.inode ^= 1,
            1 => retained.kin_identity.inode ^= 1,
            2 => retained.runs_identity.inode ^= 1,
            3 => retained.session_identity.inode ^= 1,
            4 => retained.control_identity.inode ^= 1,
            5 => base.repository_id = kin_model::RepositoryId::new("other-repository").unwrap(),
            6 => base.source_workspace.workspace_id = kin_model::WorkspaceId::new(),
            _ => unreachable!(),
        }
        let actual = retained
            .publication_binding(&base, &observation.base_bytes)
            .unwrap();
        assert_ne!(
            actual.binding().control_identity,
            expected.binding().control_identity,
            "component {position}"
        );
    }
}

#[test]
fn prepared_locator_acknowledged_mass_deletion_recovers_only_exact_target() {
    let mut f = Fixture::new("session-initial-twenty");
    for index in 0..20 {
        std::fs::write(f.session.join(format!("file-{index}.txt")), b"keep\n").unwrap();
    }
    let first = f.observe(false).unwrap();
    let prepared = f.prepare(&first, false);
    let (_, freeze) = f
        .manager
        .commit_prepared_session_publication(&prepared)
        .unwrap();
    drop(freeze);
    f.session = f.layout.runs_dir().join("session-confirmed-deletion");
    crate::commands::session_workspace::materialize_session_workspace(
        &f.layout,
        &f.binding,
        &crate::commands::session_workspace::SessionWorkspaceRequest {
            session_dir: f.session.display().to_string(),
            strategy: None,
            scope: None,
        },
    )
    .unwrap();
    for index in 0..17 {
        std::fs::remove_file(f.session.join(format!("file-{index}.txt"))).unwrap();
    }
    let error = f
        .observe(false)
        .err()
        .expect("unconfirmed mass deletion must refuse");
    assert!(
        format!("{error:#}").contains("remove 17 of 20"),
        "{error:#}"
    );
    let observed = f.observe(true).unwrap();
    let prepared = f.prepare(&observed, false);
    f.recover(&prepared).unwrap();
    std::fs::remove_file(f.session.join("file-17.txt")).unwrap();
    let error = f
        .recover(&prepared)
        .err()
        .expect("new deletion is not acknowledged");
    assert!(format!("{error:#}").contains("acknowledged immutable target"));
}

#[test]
fn prepared_locator_publication_rescan_refuses_post_observation_body_and_membership_changes() {
    let f = Fixture::new("session-rescan");
    std::fs::write(f.session.join("answer.txt"), b"target\n").unwrap();
    let observation = f.observe(false).unwrap();
    observation
        .revalidate_publication_inputs(&f.layout, &f.blobs)
        .unwrap();
    std::fs::write(f.session.join("answer.txt"), b"changed\n").unwrap();
    assert!(observation
        .revalidate_publication_inputs(&f.layout, &f.blobs)
        .is_err());
    std::fs::write(f.session.join("answer.txt"), b"target\n").unwrap();
    std::fs::write(f.session.join("added.txt"), b"unexpected\n").unwrap();
    assert!(observation
        .revalidate_publication_inputs(&f.layout, &f.blobs)
        .is_err());
    std::fs::remove_file(f.session.join("added.txt")).unwrap();
    observation
        .revalidate_publication_inputs(&f.layout, &f.blobs)
        .unwrap();
    std::fs::remove_file(f.session.join("answer.txt")).unwrap();
    assert!(observation
        .revalidate_publication_inputs(&f.layout, &f.blobs)
        .is_err());
}

#[test]
fn prepared_locator_physical_ancestor_replacement_refuses_even_with_retained_descendants() {
    for ancestor in ["workspace", "control-root", "runs"] {
        let f = Fixture::new("session-ancestor");
        std::fs::write(f.session.join("answer.txt"), b"target\n").unwrap();
        let observation = f.observe(false).unwrap();
        let prepared = f.prepare(&observation, false);
        let quarantine = tempfile::tempdir().unwrap();
        let displaced = quarantine.path().join("old");
        match ancestor {
            "workspace" => {
                std::fs::rename(f.layout.working_dir(), &displaced).unwrap();
                std::fs::create_dir(f.layout.working_dir()).unwrap();
                std::fs::rename(displaced.join(".kin"), f.layout.root()).unwrap();
            }
            "control-root" => {
                std::fs::rename(f.layout.root(), &displaced).unwrap();
                std::fs::create_dir(f.layout.root()).unwrap();
                for entry in std::fs::read_dir(&displaced).unwrap() {
                    let entry = entry.unwrap();
                    std::fs::rename(entry.path(), f.layout.root().join(entry.file_name())).unwrap();
                }
            }
            "runs" => {
                std::fs::rename(f.layout.runs_dir(), &displaced).unwrap();
                std::fs::create_dir(f.layout.runs_dir()).unwrap();
                std::fs::rename(displaced.join("session-ancestor"), &f.session).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            observation
                .revalidate_publication_inputs(&f.layout, &f.blobs)
                .is_err(),
            "{ancestor}"
        );
        let error = f.recover(&prepared).err().expect(ancestor);
        assert!(
            format!("{error:#}").contains("identity differs"),
            "{ancestor}: {error:#}"
        );
    }
}

#[test]
fn prepared_locator_cannot_recover_through_another_repository_with_copied_base() {
    let original = Fixture::new("session-owner");
    std::fs::write(original.session.join("answer.txt"), b"target\n").unwrap();
    let observation = original.observe(false).unwrap();
    let prepared = original.prepare(&observation, false);
    let other = Fixture::new("session-owner");
    std::fs::write(other.session.join("answer.txt"), b"target\n").unwrap();
    std::fs::write(
        other.session.join(".kin-session/base.json"),
        &observation.base_bytes,
    )
    .unwrap();
    let error = other
        .recover(&prepared)
        .err()
        .expect("copied base has no repository authority");
    assert!(
        format!("{error:#}").contains("repository identity does not match"),
        "{error:#}"
    );
}

/// An unchanged projection closes against a base another writer has since
/// advanced. Nothing is admitted, so the base must be authentic history rather
/// than current, and the observation reports the generations it authenticated
/// against rather than the session's snapshot.
#[test]
fn unchanged_session_closes_against_authentic_history_another_writer_advanced() {
    let f = Fixture::new("session-superseded-unchanged");
    let base = f.base();
    let advanced = f.advance("newer.txt", b"another writer\n");
    let workspace = f.workspace();
    assert!(advanced.generation > base.authority_roots.generation);
    assert_ne!(workspace, base.source_workspace);

    let observation = f.observe(false).unwrap();
    assert!(observation.deltas().is_empty());
    assert_eq!(
        observation.current_generations(),
        Some(CurrentAuthorityGenerations {
            authority: advanced.generation,
            workspace: workspace.generation,
        }),
        "an unchanged close reports current generations, not the base snapshot"
    );
    assert_eq!(
        f.manager.read_authority().roots(),
        &advanced,
        "observing commits nothing"
    );

    // The acknowledgement boundary still re-proves the exact retained inputs.
    observation
        .revalidate_publication_inputs(&f.layout, &f.blobs)
        .unwrap();
    std::fs::write(f.session.join("late.txt"), b"written after observation\n").unwrap();
    assert!(observation
        .revalidate_publication_inputs(&f.layout, &f.blobs)
        .is_err());
}

/// Any change against a superseded base is refused, and authority stays
/// exactly where the other writer left it. Only an unchanged projection may
/// close without its base being current.
#[test]
fn changed_session_against_a_superseded_base_is_refused_without_mutation() {
    for change in ["edit", "delete", "add"] {
        let mut f = Fixture::new("session-seed");
        f.advance("member.txt", b"admitted\n");
        f.session = f.layout.runs_dir().join("session-stale-change");
        crate::commands::session_workspace::materialize_session_workspace(
            &f.layout,
            &f.binding,
            &crate::commands::session_workspace::SessionWorkspaceRequest {
                session_dir: f.session.display().to_string(),
                strategy: None,
                scope: None,
            },
        )
        .unwrap();
        let member = f.session.join("member.txt");
        assert_eq!(std::fs::read(&member).unwrap(), b"admitted\n");
        let advanced = f.advance("newer.txt", b"another writer\n");
        match change {
            "edit" => std::fs::write(&member, b"edited against a stale base\n").unwrap(),
            "delete" => std::fs::remove_file(&member).unwrap(),
            "add" => std::fs::write(f.session.join("added.txt"), b"added against a stale base\n")
                .unwrap(),
            _ => unreachable!(),
        }
        let error = f.observe(false).err().expect(change);
        assert!(
            format!("{error:#}").contains("session base is stale"),
            "{change}: {error:#}"
        );
        assert_eq!(
            f.manager.read_authority().roots(),
            &advanced,
            "{change}: a refused stale session must not move authority"
        );
    }
}

/// A session whose own operation already committed is never closed as a
/// no-op. The relaxed rule covers bases other writers advanced; a receipt for
/// this session's operation still binds the target it committed.
#[test]
fn unchanged_session_whose_own_operation_committed_is_refused() {
    let f = Fixture::new("session-own-receipt");
    let base = f.base();
    let body: &[u8] = b"committed by the session's own operation\n";
    let hash = kin_blobs::digest(body);
    f.manager.save_source_blob(hash, body).unwrap();
    let target = base
        .source_workspace
        .tree
        .apply(&[TreeDelta::Added {
            artifact_id: kin_model::ArtifactId::new(),
            new: kin_model::LocatedEntry::new(
                RepoPath::from_utf8("own.txt").unwrap(),
                TreeEntry::blob(hash, false),
            ),
        }])
        .unwrap();
    let committed = f
        .manager
        .commit_repository_transaction(transaction(&base, &target))
        .unwrap();

    let error = f
        .observe(false)
        .err()
        .expect("an unchanged projection cannot close a committed session operation");
    assert!(
        format!("{error:#}").contains("unchanged session base is stale or tampered"),
        "{error:#}"
    );
    // The changed projection its receipt describes is still read as before.
    std::fs::write(f.session.join("own.txt"), body).unwrap();
    assert_eq!(f.observe(false).unwrap().deltas().len(), 1);
    assert_eq!(f.manager.read_authority().roots(), &committed.roots_after);
}

/// An editable base that history does not authenticate is refused, whether or
/// not another writer advanced authority, even when the projection matches it
/// byte for byte. Closing it would dispose of a projection holding work nobody
/// admitted. The fixture's base is empty and a forged Gitlink is graph-only, so
/// these include scans that observe nothing at all.
#[test]
fn unchanged_session_with_an_unauthenticated_base_is_refused() {
    for superseded in [false, true] {
        for tamper in [
            "member",
            "gitlink",
            "workspace",
            "roots",
            "unborn",
            "generation",
            "head",
        ] {
            let f = Fixture::new("session-forged");
            if superseded {
                f.advance("newer.txt", b"another writer\n");
            }
            let roots = f.manager.read_authority().roots().clone();
            let mut base = f.base();
            match tamper {
                "member" => {
                    let body: &[u8] = b"forged member\n";
                    forge_member(
                        &mut base,
                        "forged.txt",
                        TreeEntry::blob(kin_blobs::digest(body), false),
                    );
                    std::fs::write(f.session.join("forged.txt"), body).unwrap();
                }
                "gitlink" => forge_member(
                    &mut base,
                    "vendor/forged",
                    TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x44; 20])),
                ),
                "workspace" => base.source_workspace.workspace_id = kin_model::WorkspaceId::new(),
                "roots" => base.authority_roots.history.hash = Hash256::from_bytes([0x5a; 32]),
                "unborn" => {
                    base.authority_roots = f.manager.read_authority().metadata().operation_log[0]
                        .roots_before
                        .clone()
                }
                "generation" => base.source_workspace.generation += 1,
                "head" => {
                    base.source_workspace.head = kin_model::WorkspaceHead::Symbolic {
                        target: kin_model::RefName::branch("forged").unwrap(),
                    }
                }
                _ => unreachable!(),
            }
            base.validate().unwrap();
            std::fs::write(
                f.session.join(".kin-session/base.json"),
                serde_json::to_vec(&base).unwrap(),
            )
            .unwrap();

            let error = f.observe(false).err().expect(tamper);
            let expected = if tamper == "workspace" {
                "workspace identity does not match"
            } else {
                "stale or tampered"
            };
            assert!(
                format!("{error:#}").contains(expected),
                "{tamper} (superseded={superseded}): {error:#}"
            );
            assert_eq!(
                f.manager.read_authority().roots(),
                &roots,
                "{tamper} (superseded={superseded})"
            );
        }
    }
}

/// A superseded base relaxes currency for an unchanged projection only. Every
/// retained control and scanner refusal still applies to it.
#[test]
fn superseded_base_keeps_every_retained_control_and_scanner_refusal() {
    use std::os::unix::fs::symlink;
    for (failure, expected) in [
        ("hard-link", "hard-link aliases"),
        ("base-symlink", "without following links"),
        ("reserved-control", "reserved control path"),
    ] {
        let f = Fixture::new("session-superseded-refusal");
        let advanced = f.advance("newer.txt", b"another writer\n");
        match failure {
            "hard-link" => {
                std::fs::write(f.session.join("linked.txt"), b"aliased\n").unwrap();
                std::fs::hard_link(
                    f.session.join("linked.txt"),
                    f.layout.runs_dir().join("linked-alias"),
                )
                .unwrap();
            }
            "base-symlink" => {
                let base = f.session.join(".kin-session/base.json");
                std::fs::rename(&base, f.session.join(".kin-session/aliased-base.json")).unwrap();
                symlink("aliased-base.json", &base).unwrap();
            }
            "reserved-control" => {
                std::fs::create_dir(f.session.join(".kin")).unwrap();
                std::fs::write(f.session.join(".kin/stowaway"), b"reserved\n").unwrap();
            }
            _ => unreachable!(),
        }
        let error = f.observe(false).err().expect(failure);
        assert!(
            format!("{error:#}").contains(expected),
            "{failure}: {error:#}"
        );
        assert_eq!(f.manager.read_authority().roots(), &advanced, "{failure}");
    }
}

/// Add one artifact to a base and reseal every identity `validate` recomputes,
/// so the forgery is internally self-consistent.
fn forge_member(base: &mut SessionWorkspaceBase, path: &str, entry: TreeEntry) {
    let workspace = &mut base.source_workspace;
    workspace.tree = workspace
        .tree
        .apply(&[TreeDelta::Added {
            artifact_id: kin_model::ArtifactId::new(),
            new: kin_model::LocatedEntry::new(RepoPath::from_utf8(path).unwrap(), entry),
        }])
        .unwrap();
    workspace.tree_hash = kin_model::compute_resolved_tree_hash(&workspace.tree).unwrap();
    let materialized = workspace
        .tree
        .artifacts()
        .filter(|artifact| {
            kin_core::source_projection_disposition(&artifact.path, artifact.entry).unwrap()
                == kin_core::SourceProjectionDisposition::Materialized
        })
        .cloned()
        .collect::<Vec<_>>();
    base.materialized_artifact_ids = materialized
        .iter()
        .map(|artifact| artifact.artifact_id)
        .collect();
    base.materialized_tree_hash =
        kin_model::compute_resolved_tree_hash(&ResolvedTree::from_artifacts(materialized).unwrap())
            .unwrap();
}
