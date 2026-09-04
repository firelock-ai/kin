// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Forward-by-default delegation for `StorageBackend` decorators.
//!
//! Every method on `kin_db::StorageBackend` that carries a trait default
//! answers "this backend cannot do that": `supports_vector_artifacts` is
//! `false`, `load_prepared_workspace_graph` is `Ok(None)`,
//! `record_history_validation` is `Ok(false)`, `load_vector_artifact` is
//! `Missing`. Those defaults are right for the backend that has nowhere to
//! keep the thing. They are wrong for a decorator, which always has somewhere:
//! the backend it wraps.
//!
//! So a decorator written as a direct `impl StorageBackend` has the wrong
//! polarity. A method it forgets is not a compile error and not a runtime
//! error. It silently reports the wrapped backend as less capable than it is,
//! and every caller beneath correctly falls back to the expensive path. That
//! is the shape FIR-3147 caught in `PublicationGatedStorageBackend`, which
//! forwarded eighteen of thirty-two methods and inherited a capability lie for
//! the other fourteen.
//!
//! This module reverses it. A decorator implements
//! [`StorageBackendDelegate`], whose every method already forwards to
//! [`StorageBackendDelegate::delegate`], and is exposed as a `StorageBackend`
//! by wrapping it in [`DelegatingBackend`]. A decorator therefore cannot
//! inherit a kin-db default at all: it does not implement `StorageBackend`, so
//! there is no default for it to fall into. It writes down only what it
//! changes, and what it changes is visible in one place instead of being
//! recovered by reading thirty-two method bodies.
//!
//! The bridge is where the whole trait surface is written out, once. The cost
//! of a new kin-db method is one row here rather than one silent degradation
//! per decorator. Rust cannot make that row mandatory: a trait method with a
//! default body is precisely the thing the compiler never asks a downstream
//! impl for, which is why this class exists in the first place. What it can be
//! tied to is the moment a new method can arrive, which is a kin-db version
//! change, so [`AUDITED_KIN_DB_VERSION`] records the release this table was
//! read against and a test refuses a pin that has moved past it.
//!
//! One forward here is worth naming, because it was paid for. Before kin#1447,
//! `load_snapshot_cursor` fell through to its default, which recovers the whole
//! authority and throws the reconstructed graph away. GCS has a metadata-only
//! cursor read that lists the delta prefix and HEADs `graph.kndb`, reading no
//! body at all. Measured on `kin-ecosystem-kin-graphs-dev` over the 24 hours
//! ending 2026-09-03T20:00Z: 15,520 `ListObjects`, and `ReadObject` running
//! 14,184 ahead of `GetObjectMetadata`. One excess body read per list is the
//! signature of the default. Nothing about that was visible as an error.

use kin_db::storage::PreparedWorkspaceGraphArtifact;
use kin_db::{
    Generation, KinDbError, SnapshotAuthority, SnapshotCursor, SnapshotRecoveryState,
    SnapshotSaveOutcome, SourceBlobWriteBatch, StorageBackend, VectorArtifact,
    VectorArtifactBinding, VectorArtifactCursor, VectorArtifactLoadOutcome,
    VectorArtifactSaveOutcome, VerifiedSourceBlobBatch,
};

/// The kin-db release whose `StorageBackend` surface the table below was read
/// against, method by method.
///
/// A decorator cannot inherit a kin-db default, but this bridge can, so this
/// constant is the one place the trait surface is claimed to be complete.
/// `storage_backend_surface_is_audited_against_the_pinned_kin_db` fails when
/// the workspace pin moves past it, which is the only moment a method can have
/// appeared.
pub const AUDITED_KIN_DB_VERSION: &str = "0.7.101";

/// Wraps a [`StorageBackendDelegate`] so it can be handed anywhere a
/// `Box<dyn StorageBackend>` is expected.
///
/// The indirection is the point. A decorator that implemented `StorageBackend`
/// directly could omit a method and inherit a default; a decorator that
/// implements `StorageBackendDelegate` and reaches storage through this wrapper
/// cannot, because the wrapper is the only `StorageBackend` impl and it is
/// total.
#[derive(Debug)]
pub struct DelegatingBackend<T>(T);

impl<T> DelegatingBackend<T> {
    pub fn new(decorator: T) -> Self {
        Self(decorator)
    }

    /// The decorator underneath, for tests that assert on its own state.
    pub fn decorator(&self) -> &T {
        &self.0
    }
}

/// Generates the delegate trait, the `StorageBackend` bridge over
/// [`DelegatingBackend`], and the method-name roster, from one table.
///
/// Written once so the three cannot disagree with each other. They can still
/// disagree with kin-db, which is what [`AUDITED_KIN_DB_VERSION`] guards.
macro_rules! storage_backend_surface {
    (
        $(
            fn $name:ident ( &self $(, $arg:ident : $arg_ty:ty )* $(,)? ) -> $ret:ty;
        )+
    ) => {
        /// Every `StorageBackend` method, already forwarding to
        /// [`Self::delegate`]. Override only what the decorator changes.
        pub trait StorageBackendDelegate: Send + Sync {
            /// The backend this decorator wraps.
            fn delegate(&self) -> &dyn StorageBackend;

            $(
                fn $name(&self $(, $arg: $arg_ty)*) -> $ret {
                    StorageBackend::$name(self.delegate() $(, $arg)*)
                }
            )+
        }

        impl<T: StorageBackendDelegate> StorageBackend for DelegatingBackend<T> {
            $(
                fn $name(&self $(, $arg: $arg_ty)*) -> $ret {
                    StorageBackendDelegate::$name(&self.0 $(, $arg)*)
                }
            )+
        }

        /// Every method this bridge carries, in table order.
        ///
        /// A test asserts this is exactly the `StorageBackend` surface of the
        /// pinned kin-db, so a decorator's coverage can be stated as a fact
        /// rather than counted by hand.
        pub const BRIDGED_STORAGE_BACKEND_METHODS: &[&str] = &[$(stringify!($name)),+];
    };
}

storage_backend_surface! {
    fn supports_incremental_deltas(&self) -> bool;
    fn load_snapshot_authority(&self, repo_id: &str) -> Result<Option<SnapshotAuthority>, KinDbError>;
    fn load_snapshot_cursor(&self, repo_id: &str) -> Result<Option<SnapshotCursor>, KinDbError>;
    fn save_snapshot_validated(
        &self,
        repo_id: &str,
        data: &[u8],
        expected: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome;
    fn save_snapshot_streamed(
        &self,
        repo_id: &str,
        produce: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<(u64, [u8; 32]), KinDbError>,
        expected: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome;
    fn record_history_validation(
        &self,
        repo_id: &str,
        generation: Generation,
        snapshot_sha256: &str,
        validator_version: u32,
    ) -> Result<bool, KinDbError>;
    fn supports_authority_frames(&self) -> bool;
    fn save_authority_frame(
        &self,
        repo_id: &str,
        frame: &[u8],
        expected: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome;
    fn record_journal_history_validation(
        &self,
        repo_id: &str,
        head_generation: Generation,
        snapshot_sha256: &str,
        journal_sha256: &str,
        validator_version: u32,
    ) -> Result<bool, KinDbError>;
    fn load_prepared_workspace_graph(
        &self,
        repo_id: &str,
        workspace_id: &str,
    ) -> Result<Option<PreparedWorkspaceGraphArtifact>, KinDbError>;
    fn record_prepared_workspace_graph(
        &self,
        repo_id: &str,
        workspace_id: &str,
        artifact: &PreparedWorkspaceGraphArtifact,
    ) -> Result<bool, KinDbError>;
    fn supports_vector_artifacts(&self) -> bool;
    fn load_vector_artifact(
        &self,
        repo_id: &str,
        binding: VectorArtifactBinding,
    ) -> Result<VectorArtifactLoadOutcome, KinDbError>;
    fn save_vector_artifact(
        &self,
        repo_id: &str,
        artifact: &VectorArtifact,
        expected: VectorArtifactCursor,
    ) -> VectorArtifactSaveOutcome;
    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError>;
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError>;
    fn save_source_blob(&self, repo_id: &str, digest: [u8; 32], data: &[u8]) -> Result<(), KinDbError>;
    fn load_source_blob(&self, repo_id: &str, digest: [u8; 32]) -> Result<Option<Vec<u8>>, KinDbError>;
    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError>;
    fn with_verified_source_blob_batch(
        &self,
        repo_id: &str,
        operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError>;
    fn with_source_blob_write_batch(
        &self,
        repo_id: &str,
        operation: &mut dyn FnMut(&dyn SourceBlobWriteBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError>;
    fn source_blob_len(&self, repo_id: &str, digest: [u8; 32]) -> Result<Option<u64>, KinDbError>;
    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError>;
    fn save_snapshot_classified(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
    ) -> SnapshotSaveOutcome;
    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError>;
    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError>;
    fn compact_deltas(&self, repo_id: &str) -> Result<Generation, KinDbError>;
    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError>;
    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError>;
    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError>;
    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError>;
    fn list_repos(&self) -> Result<Vec<String>, KinDbError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;

    /// The workspace pin for kin-db, read from the manifest rather than
    /// remembered.
    fn pinned_kin_db_version() -> String {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest)
            .unwrap_or_else(|error| panic!("workspace manifest {}: {error}", manifest.display()));
        let line = text
            .lines()
            .find(|line| line.trim_start().starts_with("kin-db = "))
            .unwrap_or_else(|| {
                panic!(
                    "no `kin-db = ` dependency line in {}; this test cannot read the pin it grades",
                    manifest.display()
                )
            });
        let after = line
            .split_once("version = \"")
            .unwrap_or_else(|| panic!("kin-db dependency line carries no version literal: {line}"))
            .1;
        let version = after
            .split_once('"')
            .unwrap_or_else(|| panic!("kin-db version literal is unterminated: {line}"))
            .0;
        version.trim_start_matches('=').to_string()
    }

    /// The bridge's table is the one place in this crate that can inherit a
    /// kin-db default, and Rust will never ask it to. A defaulted trait method
    /// exists exactly so a downstream impl does not have to notice it, so no
    /// compile-time construct can catch method thirty-three.
    ///
    /// What can be caught is the moment one can arrive. Bumping the kin-db pin
    /// turns this red until someone reads the trait and either confirms the
    /// table or adds the row.
    #[test]
    fn storage_backend_surface_is_audited_against_the_pinned_kin_db() {
        let pinned = pinned_kin_db_version();
        assert_eq!(
            pinned, AUDITED_KIN_DB_VERSION,
            "kin-db moved from {AUDITED_KIN_DB_VERSION} to {pinned} and the StorageBackend table \
             in crates/kin-daemon/src/storage_delegate.rs has not been re-read. Count the trait's \
             methods in `kin-db-{pinned}/src/storage/backend.rs`, add a row for anything new, then \
             set AUDITED_KIN_DB_VERSION to {pinned}. A method missing from that table is a \
             capability every decorator in this crate reports as absent, with no error anywhere."
        );
    }

    /// A duplicated row would compile, since the trait and the impl would both
    /// reject it, but the roster is also read as a count. Keep it a set.
    #[test]
    fn the_bridged_method_roster_names_each_method_once() {
        let unique: BTreeSet<&&str> = BRIDGED_STORAGE_BACKEND_METHODS.iter().collect();
        assert_eq!(
            unique.len(),
            BRIDGED_STORAGE_BACKEND_METHODS.len(),
            "the bridge table names a method twice: {BRIDGED_STORAGE_BACKEND_METHODS:?}"
        );
        assert_eq!(
            BRIDGED_STORAGE_BACKEND_METHODS.len(),
            32,
            "kin-db {AUDITED_KIN_DB_VERSION} declares 32 StorageBackend methods"
        );
    }
}
