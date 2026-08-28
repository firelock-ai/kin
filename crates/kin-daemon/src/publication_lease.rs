// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fleet-wide reader admission and graph-publication serialization.
//!
//! Hosted graph objects are one authority shared by every daemon serving the
//! same bucket prefix. A deployment recheck alone cannot stop a writer from
//! committing after the check and before the replacement reader starts. This
//! module closes that window with one CAS-owned record beside the graph
//! objects. Rollouts and graph publications take mutually exclusive leases
//! from that record. A rollout also advances every graph object's generation
//! with an exact-generation, same-bytes rewrite before it can admit a reader.
//! That resource fence makes a paused pre-rollout writer lose its conditional
//! authority PUT even if its process-local lease check happened before the
//! rollout began.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use kin_db::{
    Generation, KinDbError, SnapshotAuthority, SnapshotCursor, SnapshotRecoveryState,
    SnapshotSaveOutcome, StorageBackend,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const PUBLICATION_CONTROL_SCHEMA: &str = "kin.graph-publication-control.v2";
pub const DEFAULT_ROLLOUT_LEASE_SECONDS: u64 = 300;
pub const MAX_ROLLOUT_LEASE_SECONDS: u64 = 1_800;
pub const PUBLICATION_LEASE_SECONDS: u64 = 1_800;
pub const MAX_READER_ADMISSION_SECONDS: u64 = 2_592_000;
const STARTUP_BOOTSTRAP_HOLDER: &str = "kin-daemon-startup-bootstrap";
const STARTUP_BOOTSTRAP_REQUEST_ID: &str = "publication-control-v2";
const MAX_CAS_ATTEMPTS: usize = 32;
const MAX_COMPLETED_ROLLOUT_HISTORY: usize = 8;
const MAX_FLEET_REPOSITORIES: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderAdmission {
    pub identity: String,
    pub min_snapshot_schema: u32,
    pub max_snapshot_schema: u32,
    pub admitted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderAdmissionInput {
    pub identity: String,
    pub min_snapshot_schema: u32,
    pub max_snapshot_schema: u32,
    pub valid_for_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    Publication,
    Rollout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePublicationLease {
    pub kind: LeaseKind,
    pub holder: String,
    pub request_id: String,
    pub token: String,
    pub fence: u64,
    pub repo_id: Option<String>,
    /// Membership installed when a rollout completes. Empty for publication
    /// leases.
    #[serde(default)]
    pub target_repositories: Vec<String>,
    /// Exact membership in the durable record when the rollout acquired its
    /// fence. Empty for publication leases.
    #[serde(default)]
    pub previous_repositories: Vec<String>,
    /// Union of current and target membership physically generation-fenced by
    /// a transition, so a paused writer for a removed repo also loses.
    #[serde(default)]
    pub fence_repositories: Vec<String>,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub authority_fencing_token: Option<String>,
    #[serde(default)]
    pub authority_fencing_started_at: Option<DateTime<Utc>>,
    /// Exact full-fleet metadata captured before the fencing claim. Bodies are
    /// deliberately absent: the store re-reads one object at a time after the
    /// claim and verifies this digest and generation before its conditional
    /// same-bytes rewrite.
    #[serde(default)]
    pub authority_capture: Vec<RepositoryAuthorityCapture>,
    pub authority_fenced_at: Option<DateTime<Utc>>,
    /// Durable strict-prefix progress while `authority_fencing_token` is set;
    /// the complete fleet after `authority_fenced_at` is set.
    pub authority_fence: Vec<RepositoryAuthorityFence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAuthorityCapture {
    pub repo_id: String,
    pub generation: u64,
    pub snapshot_schema: u32,
    pub size_bytes: u64,
    pub sha256: String,
    pub e_tag: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAuthorityFence {
    pub repo_id: String,
    pub pre_fence_generation: u64,
    pub fenced_generation: u64,
    pub snapshot_schema: u32,
    pub e_tag: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedPublicationLease {
    pub kind: LeaseKind,
    pub token: String,
    pub fence: u64,
    pub released_at: DateTime<Utc>,
    #[serde(default)]
    pub target_repositories: Vec<String>,
    #[serde(default)]
    pub previous_repositories: Vec<String>,
    #[serde(default)]
    pub fence_repositories: Vec<String>,
    pub authority_fenced_at: Option<DateTime<Utc>>,
    pub authority_fence: Vec<RepositoryAuthorityFence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationControlRecord {
    pub schema: String,
    pub scope: String,
    pub revision: u64,
    pub last_fence: u64,
    pub repositories: Vec<String>,
    pub reader: ReaderAdmission,
    pub last_authority_fenced_at: Option<DateTime<Utc>>,
    pub last_authority_fence: Vec<RepositoryAuthorityFence>,
    pub active_lease: Option<ActivePublicationLease>,
    pub last_completed_lease: Option<CompletedPublicationLease>,
    #[serde(default)]
    pub last_completed_rollout: Option<CompletedPublicationLease>,
    #[serde(default)]
    pub completed_rollout_history: Vec<CompletedPublicationLease>,
}

/// Operator-readable state with every capability-bearing lease token removed.
/// Mutating admin responses may echo a proof the caller already supplied;
/// status is diagnostic state, never credential recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicationControlStatus {
    pub schema: String,
    pub scope: String,
    pub revision: u64,
    pub last_fence: u64,
    pub repositories: Vec<String>,
    pub reader: ReaderAdmission,
    pub last_authority_fenced_at: Option<DateTime<Utc>>,
    pub last_authority_fence: Vec<RepositoryAuthorityFence>,
    pub active_lease: Option<ActivePublicationLeaseStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActivePublicationLeaseStatus {
    pub kind: LeaseKind,
    pub holder: String,
    pub request_id: String,
    pub fence: u64,
    pub repo_id: Option<String>,
    pub target_repositories: Vec<String>,
    pub previous_repositories: Vec<String>,
    pub fence_repositories: Vec<String>,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub authority_fencing_in_progress: bool,
    pub authority_fenced_at: Option<DateTime<Utc>>,
    pub authority_fence: Vec<RepositoryAuthorityFence>,
}

impl From<PublicationControlRecord> for PublicationControlStatus {
    fn from(record: PublicationControlRecord) -> Self {
        Self {
            schema: record.schema,
            scope: record.scope,
            revision: record.revision,
            last_fence: record.last_fence,
            repositories: record.repositories,
            reader: record.reader,
            last_authority_fenced_at: record.last_authority_fenced_at,
            last_authority_fence: record.last_authority_fence,
            active_lease: record.active_lease.map(|active| ActivePublicationLeaseStatus {
                kind: active.kind,
                holder: active.holder,
                request_id: active.request_id,
                fence: active.fence,
                repo_id: active.repo_id,
                target_repositories: active.target_repositories,
                previous_repositories: active.previous_repositories,
                fence_repositories: active.fence_repositories,
                acquired_at: active.acquired_at,
                expires_at: active.expires_at,
                authority_fencing_in_progress: active.authority_fencing_token.is_some(),
                authority_fenced_at: active.authority_fenced_at,
                authority_fence: active.authority_fence,
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquireRolloutLeaseRequest {
    pub scope: String,
    pub repositories: Vec<String>,
    /// Required exact current membership when `repositories` changes. This
    /// makes a fleet transition an explicit CAS intent, not a daemon-config
    /// side effect.
    #[serde(default)]
    pub previous_repositories: Option<Vec<String>>,
    pub holder: String,
    pub request_id: String,
    #[serde(default = "default_rollout_lease_seconds")]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub bootstrap_reader: Option<ReaderAdmissionInput>,
}

const fn default_rollout_lease_seconds() -> u64 {
    DEFAULT_ROLLOUT_LEASE_SECONDS
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseProof {
    pub scope: String,
    pub token: String,
    pub fence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRolloutLeaseRequest {
    #[serde(flatten)]
    pub lease: LeaseProof,
    #[serde(default = "default_rollout_lease_seconds")]
    pub ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitReaderRequest {
    #[serde(flatten)]
    pub lease: LeaseProof,
    pub repositories: Vec<String>,
    pub reader: ReaderAdmissionInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRolloutLeaseRequest {
    #[serde(flatten)]
    pub lease: LeaseProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationRecordVersion {
    pub e_tag: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StoredPublicationControlRecord {
    pub record: PublicationControlRecord,
    pub version: PublicationRecordVersion,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum PublicationControlError {
    #[error("invalid graph publication control request: {0}")]
    Invalid(String),
    #[error("graph publication control record is absent for scope {0}")]
    Missing(String),
    #[error("graph publication admission is unavailable: {0}")]
    Admission(String),
    #[error("graph publication lease conflict: {0}")]
    Conflict(String),
    #[error("graph publication lease is stale or fenced: {0}")]
    Fenced(String),
    #[error("graph publication control store failed: {0}")]
    Store(String),
}

impl PublicationControlError {
    fn is_cas_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_))
    }

    pub fn is_request_error(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }

    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_) | Self::Fenced(_))
    }
}

pub trait PublicationControlStore: Send + Sync {
    fn load(
        &self,
    ) -> Result<Option<StoredPublicationControlRecord>, PublicationControlError>;

    fn create(
        &self,
        record: &PublicationControlRecord,
    ) -> Result<PublicationRecordVersion, PublicationControlError>;

    fn update(
        &self,
        expected: &PublicationRecordVersion,
        record: &PublicationControlRecord,
    ) -> Result<PublicationRecordVersion, PublicationControlError>;

    /// Capture the exact complete fleet without retaining object bodies.
    fn capture_authority(
        &self,
        repositories: &[String],
    ) -> Result<Vec<RepositoryAuthorityCapture>, PublicationControlError>;

    /// Advance one captured graph object by an exact-generation, same-bytes
    /// conditional rewrite. Any generation change, including identical bytes,
    /// must be recaptured and rewritten from the new exact generation because
    /// an uncheckpointed advance is indistinguishable from a paused old writer.
    fn fence_authority(
        &self,
        capture: &RepositoryAuthorityCapture,
    ) -> Result<RepositoryAuthorityFence, PublicationControlError>;

    /// Re-read one durable checkpoint before an exact-holder resume completes.
    fn verify_authority_fence(
        &self,
        capture: &RepositoryAuthorityCapture,
        fence: &RepositoryAuthorityFence,
    ) -> Result<(), PublicationControlError>;
}

pub trait PublicationClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default)]
pub struct SystemPublicationClock;

impl PublicationClock for SystemPublicationClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// CAS coordinator shared by the HTTP rollout surface and every authority
/// writer installed beneath [`DaemonState`](crate::state::DaemonState).
pub struct PublicationControl {
    scope: String,
    runtime_reader_identity: String,
    fleet_repositories: Vec<String>,
    store: Arc<dyn PublicationControlStore>,
    clock: Arc<dyn PublicationClock>,
    runtime_admission: Mutex<RuntimeAdmissionStatus>,
    /// Same-fence retries are idempotent, but two threads in one daemon must
    /// not concurrently download the same bounded object body. A process crash
    /// drops this local guard, while the durable claim remains resumable by the
    /// exact holder.
    rollout_fencing_flights: Arc<Mutex<BTreeSet<u64>>>,
}

struct RolloutFencingFlightGuard {
    flights: Arc<Mutex<BTreeSet<u64>>>,
    fence: u64,
}

impl RolloutFencingFlightGuard {
    fn acquire(
        flights: Arc<Mutex<BTreeSet<u64>>>,
        fence: u64,
    ) -> Result<Self, PublicationControlError> {
        let mut active = flights
            .lock()
            .map_err(|_| PublicationControlError::Store(
                "rollout fencing single-flight state is poisoned".to_string(),
            ))?;
        if !active.insert(fence) {
            return Err(PublicationControlError::Conflict(format!(
                "rollout fence {fence} resource-fencing attempt is already in progress in this daemon"
            )));
        }
        drop(active);
        Ok(Self { flights, fence })
    }
}

impl Drop for RolloutFencingFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.flights.lock() {
            active.remove(&self.fence);
        }
    }
}

/// Last admission verdict observed by this process.
///
/// Liveness must not make a remote object-store request. Readiness performs the
/// authoritative check and refreshes this snapshot; `/health` reports it
/// without turning a slow or unavailable control store into a dead-process
/// signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAdmissionStatus {
    pub admitted: bool,
    pub error: Option<String>,
}

impl std::fmt::Debug for PublicationControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicationControl")
            .field("scope", &self.scope)
            .field("runtime_reader_identity", &self.runtime_reader_identity)
            .finish_non_exhaustive()
    }
}

impl PublicationControl {
    pub fn new(
        scope: impl Into<String>,
        runtime_reader_identity: impl Into<String>,
        fleet_repositories: Vec<String>,
        store: Arc<dyn PublicationControlStore>,
    ) -> Result<Self, PublicationControlError> {
        Self::with_clock(
            scope,
            runtime_reader_identity,
            fleet_repositories,
            store,
            Arc::new(SystemPublicationClock),
        )
    }

    pub fn with_clock(
        scope: impl Into<String>,
        runtime_reader_identity: impl Into<String>,
        fleet_repositories: Vec<String>,
        store: Arc<dyn PublicationControlStore>,
        clock: Arc<dyn PublicationClock>,
    ) -> Result<Self, PublicationControlError> {
        let scope = scope.into();
        validate_identifier("scope", &scope)?;
        let runtime_reader_identity = runtime_reader_identity.into();
        validate_image_identity(&runtime_reader_identity)?;
        let fleet_repositories = canonical_repositories(&fleet_repositories)?;
        Ok(Self {
            scope,
            runtime_reader_identity,
            fleet_repositories,
            store,
            clock,
            runtime_admission: Mutex::new(RuntimeAdmissionStatus {
                admitted: false,
                error: Some("hosted reader admission has not been checked".to_string()),
            }),
            rollout_fencing_flights: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn runtime_reader_identity(&self) -> &str {
        &self.runtime_reader_identity
    }

    pub fn fleet_repositories(&self) -> &[String] {
        &self.fleet_repositories
    }

    pub fn status(&self) -> Result<PublicationControlRecord, PublicationControlError> {
        let stored = self
            .store
            .load()?
            .ok_or_else(|| PublicationControlError::Missing(self.scope.clone()))?;
        self.validate_record(&stored.record)?;
        Ok(stored.record)
    }

    pub fn redacted_status(&self) -> Result<PublicationControlStatus, PublicationControlError> {
        self.status().map(PublicationControlStatus::from)
    }

    pub fn assert_runtime_admitted(
        &self,
        snapshot_schema: u32,
    ) -> Result<ReaderAdmission, PublicationControlError> {
        let result = self.evaluate_runtime_admission(snapshot_schema);
        let diagnostic = match &result {
            Ok(_) => RuntimeAdmissionStatus {
                admitted: true,
                error: None,
            },
            Err(error) => RuntimeAdmissionStatus {
                admitted: false,
                error: Some(error.to_string()),
            },
        };
        *self
            .runtime_admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = diagnostic;
        result
    }

    fn evaluate_runtime_admission(
        &self,
        snapshot_schema: u32,
    ) -> Result<ReaderAdmission, PublicationControlError> {
        let record = self.status()?;
        if record.repositories != self.fleet_repositories {
            return Err(PublicationControlError::Admission(format!(
                "scope {} durable fleet {:?} does not match this daemon's configured fleet {:?}",
                self.scope, record.repositories, self.fleet_repositories
            )));
        }
        let now = self.clock.now();
        if let Some(active) = record
            .active_lease
            .as_ref()
            .filter(|active| active.kind == LeaseKind::Rollout)
        {
            return Err(PublicationControlError::Admission(format!(
                "scope {} rollout fence {} remains active and must be released or recovered before reader admission",
                self.scope, active.fence
            )));
        }
        validate_reader_admission(&record.reader, now)?;
        require_complete_record_authority_fence(&record)?;
        validate_reader_against_authority_fence(&record.reader, &record.last_authority_fence)?;
        if record.reader.identity != self.runtime_reader_identity {
            return Err(PublicationControlError::Admission(format!(
                "scope {} admits reader {}, but this daemon is {}",
                self.scope, record.reader.identity, self.runtime_reader_identity
            )));
        }
        if snapshot_schema < record.reader.min_snapshot_schema
            || snapshot_schema > record.reader.max_snapshot_schema
        {
            return Err(PublicationControlError::Admission(format!(
                "scope {} admits snapshot schemas {} through {}, but this publication uses schema {}",
                self.scope,
                record.reader.min_snapshot_schema,
                record.reader.max_snapshot_schema,
                snapshot_schema
            )));
        }
        Ok(record.reader)
    }

    /// Refresh the process-local liveness diagnostic from durable authority.
    /// The authoritative result is still returned to the caller, so readiness
    /// and publication paths fail closed rather than trusting this cache.
    pub fn refresh_runtime_admission(
        &self,
        snapshot_schema: u32,
    ) -> Result<ReaderAdmission, PublicationControlError> {
        self.assert_runtime_admitted(snapshot_schema)
    }

    pub fn runtime_admission_status(&self) -> RuntimeAdmissionStatus {
        self.runtime_admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Create the first fleet record before a hosted daemon opens authority.
    ///
    /// Kubernetes cannot call an HTTP bootstrap route on a pod that correctly
    /// remains unready while admission is absent. The graph authority therefore
    /// owns this one startup transition: an absent record is initialized for
    /// the exact running image and compiled reader range, every configured graph
    /// object is resource-fenced, and only then is the rollout lease released.
    ///
    /// This is deliberately not an automatic rollout. Once a complete record
    /// exists, a different image identity, an expired reader, or an operator
    /// rollout must use the authenticated rollout API. The only existing-record
    /// recovery performed here is resuming this exact startup lease after a
    /// crash or retry.
    pub fn bootstrap_runtime_if_absent(&self) -> Result<(), PublicationControlError> {
        let existing = self.store.load()?;
        if let Some(stored) = existing.as_ref() {
            self.validate_record(&stored.record)?;
            let resumes_startup = stored.record.active_lease.as_ref().is_some_and(|active| {
                active.kind == LeaseKind::Rollout
                    && active.holder == STARTUP_BOOTSTRAP_HOLDER
                    && active.request_id == STARTUP_BOOTSTRAP_REQUEST_ID
                    && active.target_repositories == self.fleet_repositories
                    && active.previous_repositories == self.fleet_repositories
                    && active.fence_repositories == self.fleet_repositories
                    && stored.record.reader.identity == self.runtime_reader_identity
            });
            if !resumes_startup {
                let _ = self.refresh_runtime_admission(kin_db::GraphSnapshot::CURRENT_VERSION);
                return Ok(());
            }
        }

        let lease = self.acquire_rollout(AcquireRolloutLeaseRequest {
            scope: self.scope.clone(),
            repositories: self.fleet_repositories.clone(),
            previous_repositories: None,
            holder: STARTUP_BOOTSTRAP_HOLDER.to_string(),
            request_id: STARTUP_BOOTSTRAP_REQUEST_ID.to_string(),
            ttl_seconds: DEFAULT_ROLLOUT_LEASE_SECONDS,
            bootstrap_reader: Some(ReaderAdmissionInput {
                identity: self.runtime_reader_identity.clone(),
                min_snapshot_schema: kin_db::GraphSnapshot::MIN_SUPPORTED_VERSION,
                max_snapshot_schema: kin_db::GraphSnapshot::CURRENT_VERSION,
                valid_for_seconds: MAX_READER_ADMISSION_SECONDS,
            }),
        })?;
        self.release_rollout(ReleaseRolloutLeaseRequest {
            lease: LeaseProof {
                scope: self.scope.clone(),
                token: lease.token,
                fence: lease.fence,
            },
        })?;
        let _ = self.refresh_runtime_admission(kin_db::GraphSnapshot::CURRENT_VERSION);
        Ok(())
    }

    pub fn acquire_rollout(
        &self,
        request: AcquireRolloutLeaseRequest,
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        self.validate_scope(&request.scope)?;
        self.validate_fleet_request(&request.repositories)?;
        let target_repositories = canonical_repositories(&request.repositories)?;
        let previous_repositories = request
            .previous_repositories
            .as_ref()
            .map(|repositories| canonical_repositories(repositories))
            .transpose()?;
        validate_identifier("holder", &request.holder)?;
        validate_identifier("request_id", &request.request_id)?;
        validate_rollout_ttl(request.ttl_seconds)?;
        if let Some(reader) = request.bootstrap_reader.as_ref() {
            validate_reader_input(reader)?;
        }

        for _ in 0..MAX_CAS_ATTEMPTS {
            let now = self.clock.now();
            match self.store.load()? {
                None => {
                    if previous_repositories.is_some() {
                        return Err(PublicationControlError::Invalid(
                            "previous_repositories must be absent for first fleet bootstrap"
                                .to_string(),
                        ));
                    }
                    let bootstrap = request.bootstrap_reader.as_ref().ok_or_else(|| {
                        PublicationControlError::Missing(format!(
                            "{}; first acquisition must carry bootstrap_reader",
                            self.scope
                        ))
                    })?;
                    if bootstrap.identity != self.runtime_reader_identity {
                        return Err(PublicationControlError::Admission(format!(
                            "initial reader {} does not identify the running daemon {}",
                            bootstrap.identity, self.runtime_reader_identity
                        )));
                    }
                    let lease = self.new_lease(
                        LeaseKind::Rollout,
                        request.holder.clone(),
                        request.request_id.clone(),
                        None,
                        target_repositories.clone(),
                        target_repositories.clone(),
                        target_repositories.clone(),
                        1,
                        request.ttl_seconds,
                        now,
                    )?;
                    let record = PublicationControlRecord {
                        schema: PUBLICATION_CONTROL_SCHEMA.to_string(),
                        scope: self.scope.clone(),
                        revision: 1,
                        last_fence: 1,
                        repositories: target_repositories.clone(),
                        reader: materialize_reader(bootstrap, now)?,
                        last_authority_fenced_at: None,
                        last_authority_fence: Vec::new(),
                        active_lease: Some(lease.clone()),
                        last_completed_lease: None,
                        last_completed_rollout: None,
                        completed_rollout_history: Vec::new(),
                    };
                    match self.store.create(&record) {
                        Ok(_) => return self.finish_rollout_acquisition(lease),
                        Err(error) if error.is_cas_conflict() => continue,
                        Err(error) => return Err(error),
                    }
                }
                Some(stored) => {
                    self.validate_record(&stored.record)?;
                    let current_repositories = stored.record.repositories.clone();
                    if let Some(active) = stored.record.active_lease.as_ref() {
                        if active.expires_at > now
                            && active.kind == LeaseKind::Rollout
                            && active.holder == request.holder
                            && active.request_id == request.request_id
                        {
                            let retried_previous_repositories = previous_repositories
                                .clone()
                                .unwrap_or_else(|| target_repositories.clone());
                            if active.target_repositories != target_repositories
                                || active.previous_repositories
                                    != retried_previous_repositories
                            {
                                return Err(PublicationControlError::Invalid(
                                    "rollout request_id was reused with different fleet membership"
                                        .to_string(),
                                ));
                            }
                            return self.finish_rollout_acquisition(active.clone());
                        }
                    }
                    if target_repositories != current_repositories {
                        if previous_repositories.as_ref() != Some(&current_repositories) {
                            return Err(PublicationControlError::Invalid(format!(
                                "fleet transition from {:?} to {:?} requires previous_repositories to equal the exact current fleet",
                                current_repositories, target_repositories
                            )));
                        }
                    } else if previous_repositories
                        .as_ref()
                        .is_some_and(|previous| previous != &current_repositories)
                    {
                        return Err(PublicationControlError::Invalid(format!(
                            "previous_repositories {:?} do not equal current fleet {:?}",
                            previous_repositories, current_repositories
                        )));
                    }
                    let fence_repositories = repository_union(
                        &current_repositories,
                        &target_repositories,
                    );
                    if fence_repositories.len() > MAX_FLEET_REPOSITORIES {
                        return Err(PublicationControlError::Invalid(format!(
                            "fleet transition fence union contains {} entries, above the bounded fleet limit {MAX_FLEET_REPOSITORIES}",
                            fence_repositories.len()
                        )));
                    }
                    if let Some(active) = stored.record.active_lease.as_ref() {
                        if active.expires_at > now {
                            return Err(PublicationControlError::Conflict(format!(
                                "{} lease fence {} held by {} until {}",
                                lease_kind_name(active.kind),
                                active.fence,
                                active.holder,
                                active.expires_at.to_rfc3339()
                            )));
                        }
                    }
                    let fence = stored.record.last_fence.checked_add(1).ok_or_else(|| {
                        PublicationControlError::Fenced(
                            "lease fence exhausted u64; refusing wraparound".to_string(),
                        )
                    })?;
                    let lease = self.new_lease(
                        LeaseKind::Rollout,
                        request.holder.clone(),
                        request.request_id.clone(),
                        None,
                        target_repositories.clone(),
                        current_repositories,
                        fence_repositories,
                        fence,
                        request.ttl_seconds,
                        now,
                    )?;
                    let mut record = stored.record;
                    record.revision = checked_revision(record.revision)?;
                    record.last_fence = fence;
                    record.active_lease = Some(lease.clone());
                    match self.store.update(&stored.version, &record) {
                        Ok(_) => return self.finish_rollout_acquisition(lease),
                        Err(error) if error.is_cas_conflict() => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Err(PublicationControlError::Conflict(format!(
            "scope {} changed during every acquisition attempt",
            self.scope
        )))
    }

    fn finish_rollout_acquisition(
        &self,
        lease: ActivePublicationLease,
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        let _single_flight = RolloutFencingFlightGuard::acquire(
            Arc::clone(&self.rollout_fencing_flights),
            lease.fence,
        )?;
        let proof = LeaseProof {
            scope: self.scope.clone(),
            token: lease.token,
            fence: lease.fence,
        };
        'recapture: for _ in 0..MAX_CAS_ATTEMPTS {
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let active = require_lease(
                &stored.record,
                &proof,
                LeaseKind::Rollout,
                self.clock.now(),
            )?;
            if active.authority_fenced_at.is_some() {
                require_complete_authority_fence(active, &active.fence_repositories)?;
                return Ok(active.clone());
            }
            let repositories = active.fence_repositories.clone();
            let (fencing_token, capture, mut progress) =
                if let Some(fencing_token) = active.authority_fencing_token.as_ref() {
                    validate_authority_capture(&active.authority_capture, &repositories)?;
                    validate_authority_fence_progress(
                        &active.authority_fence,
                        &active.authority_capture,
                    )?;
                    (
                        fencing_token.clone(),
                        active.authority_capture.clone(),
                        active.authority_fence.clone(),
                    )
                } else {
                    // Capture every repo before installing the claim, but retain
                    // metadata only. A missing fifth object therefore performs no
                    // rewrite and leaves no claimed attempt behind.
                    let capture = self.store.capture_authority(&repositories)?;
                    validate_authority_capture(&capture, &repositories)?;
                    let fencing_token = Uuid::new_v4().to_string();
                    let claimed =
                        self.claim_fencing_attempt(&proof, &fencing_token, &capture)?;
                    (fencing_token, capture, claimed.authority_fence)
                };

            for (position, captured) in capture.iter().enumerate() {
                if let Some(checkpoint) = progress.get(position) {
                    if let Err(error) = self.store.verify_authority_fence(captured, checkpoint) {
                        if matches!(
                            &error,
                            PublicationControlError::Conflict(_)
                                | PublicationControlError::Fenced(_)
                        ) {
                            self.restart_fencing_capture(
                                &proof,
                                &fencing_token,
                                &repositories,
                            )?;
                            continue 'recapture;
                        }
                        return Err(error);
                    }
                    continue;
                }
                let fenced = match self.store.fence_authority(captured) {
                    Ok(fenced) => fenced,
                    Err(error)
                        if matches!(
                            &error,
                            PublicationControlError::Conflict(_)
                                | PublicationControlError::Fenced(_)
                        ) =>
                    {
                        self.restart_fencing_capture(
                            &proof,
                            &fencing_token,
                            &repositories,
                        )?;
                        continue 'recapture;
                    }
                    Err(error) => return Err(error),
                };
                validate_authority_fence_entry(captured, &fenced)?;
                let checkpointed = self.checkpoint_fencing_attempt(
                    &proof,
                    &fencing_token,
                    &capture,
                    fenced,
                )?;
                progress = checkpointed.authority_fence;
            }

            return self.complete_fencing_attempt(&proof, &fencing_token);
        }
        Err(PublicationControlError::Conflict(
            "graph authority changed during every full-fleet recapture attempt".to_string(),
        ))
    }

    /// A real writer may win after the full-fleet capture but before its row is
    /// conditionally rewritten. Keep the exact claim, recapture all current
    /// rows as metadata only, and clear the prior strict-prefix checkpoints.
    /// The next retry fences the whole new capture, including that winner.
    fn restart_fencing_capture(
        &self,
        proof: &LeaseProof,
        fencing_token: &str,
        repositories: &[String],
    ) -> Result<(), PublicationControlError> {
        let capture = self.store.capture_authority(repositories)?;
        validate_authority_capture(&capture, repositories)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let active = require_lease(
                &stored.record,
                proof,
                LeaseKind::Rollout,
                self.clock.now(),
            )?;
            if active.authority_fencing_token.as_deref() != Some(fencing_token) {
                return Err(PublicationControlError::Fenced(format!(
                    "rollout fence {} resource-fencing claim changed before recapture",
                    active.fence
                )));
            }
            let mut restarted = active.clone();
            restarted.authority_capture = capture.clone();
            restarted.authority_fence.clear();
            restarted.authority_fencing_started_at = Some(self.clock.now());
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.active_lease = Some(restarted);
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(()),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(
            "resource-fencing recapture changed during every attempt".to_string(),
        ))
    }

    fn claim_fencing_attempt(
        &self,
        proof: &LeaseProof,
        fencing_token: &str,
        capture: &[RepositoryAuthorityCapture],
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let now = self.clock.now();
            let active = require_lease(&stored.record, proof, LeaseKind::Rollout, now)?;
            if active.authority_fenced_at.is_some() {
                return Err(PublicationControlError::Conflict(format!(
                    "rollout fence {} completed while its object generations were being captured",
                    active.fence
                )));
            }
            if let Some(owner) = active.authority_fencing_token.as_ref() {
                if owner == fencing_token && active.authority_capture == capture {
                    return Ok(active.clone());
                }
                return Err(PublicationControlError::Conflict(format!(
                    "rollout fence {} already has resource fencing attempt {} in progress",
                    active.fence, owner
                )));
            }
            let mut claimed = active.clone();
            claimed.authority_fencing_token = Some(fencing_token.to_string());
            claimed.authority_fencing_started_at = Some(now);
            claimed.authority_capture = capture.to_vec();
            claimed.authority_fence.clear();
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.active_lease = Some(claimed);
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(record.active_lease.expect("claimed lease was installed")),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(
            "resource-fencing claim changed during every acquisition attempt".to_string(),
        ))
    }

    fn checkpoint_fencing_attempt(
        &self,
        proof: &LeaseProof,
        fencing_token: &str,
        capture: &[RepositoryAuthorityCapture],
        fenced: RepositoryAuthorityFence,
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let active = require_lease(
                &stored.record,
                proof,
                LeaseKind::Rollout,
                self.clock.now(),
            )?;
            if active.authority_fenced_at.is_some() {
                require_complete_authority_fence(active, &active.fence_repositories)?;
                return Ok(active.clone());
            }
            if active.authority_fencing_token.as_deref() != Some(fencing_token) {
                return Err(PublicationControlError::Fenced(format!(
                    "rollout fence {} resource-fencing claim changed",
                    active.fence
                )));
            }
            if active.authority_capture != capture {
                return Err(PublicationControlError::Fenced(format!(
                    "rollout fence {} resource capture changed before checkpoint",
                    active.fence
                )));
            }
            validate_authority_fence_progress(&active.authority_fence, capture)?;
            let position = active.authority_fence.len();
            if let Some(existing) = active.authority_fence.get(position.saturating_sub(1)) {
                if existing == &fenced {
                    return Ok(active.clone());
                }
            }
            let expected = capture.get(position).ok_or_else(|| {
                PublicationControlError::Fenced(format!(
                    "rollout fence {} received an extra checkpoint for {}",
                    active.fence, fenced.repo_id
                ))
            })?;
            validate_authority_fence_entry(expected, &fenced)?;
            let mut checkpointed = active.clone();
            checkpointed.authority_fence.push(fenced);
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.active_lease = Some(checkpointed.clone());
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(checkpointed),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(
            "resource-fencing checkpoint changed during every attempt".to_string(),
        ))
    }

    fn complete_fencing_attempt(
        &self,
        proof: &LeaseProof,
        fencing_token: &str,
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let now = self.clock.now();
            let active = require_lease(&stored.record, proof, LeaseKind::Rollout, now)?;
            if active.authority_fenced_at.is_some() {
                require_complete_authority_fence(active, &active.fence_repositories)?;
                return Ok(active.clone());
            }
            if active.authority_fencing_token.as_deref() != Some(fencing_token) {
                return Err(PublicationControlError::Fenced(format!(
                    "rollout fence {} resource-fencing claim changed before completion",
                    active.fence
                )));
            }
            validate_authority_capture(
                &active.authority_capture,
                &active.fence_repositories,
            )?;
            validate_authority_fence(&active.authority_fence, &active.fence_repositories)?;
            let target_authority_fence = authority_fence_for_repositories(
                &active.authority_fence,
                &active.target_repositories,
            )?;
            let mut completed = active.clone();
            completed.authority_fencing_token = None;
            completed.authority_fencing_started_at = None;
            completed.authority_capture.clear();
            completed.authority_fenced_at = Some(now);
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.repositories = completed.target_repositories.clone();
            record.last_authority_fenced_at = Some(now);
            record.last_authority_fence = target_authority_fence;
            record.active_lease = Some(completed.clone());
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(completed),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(
            "resource-fencing completion changed during every attempt".to_string(),
        ))
    }

    pub fn renew_rollout(
        &self,
        request: RenewRolloutLeaseRequest,
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        self.validate_scope(&request.lease.scope)?;
        validate_rollout_ttl(request.ttl_seconds)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let now = self.clock.now();
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let active = require_lease(
                &stored.record,
                &request.lease,
                LeaseKind::Rollout,
                now,
            )?;
            let mut renewed = active.clone();
            renewed.expires_at = checked_expiry(now, request.ttl_seconds)?;
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.active_lease = Some(renewed.clone());
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(renewed),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(
            "rollout lease changed during every renewal attempt".to_string(),
        ))
    }

    pub fn admit_reader(
        &self,
        request: AdmitReaderRequest,
    ) -> Result<PublicationControlRecord, PublicationControlError> {
        self.validate_scope(&request.lease.scope)?;
        self.validate_fleet_request(&request.repositories)?;
        let requested_repositories = canonical_repositories(&request.repositories)?;
        validate_reader_input(&request.reader)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let now = self.clock.now();
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let active = require_lease(
                &stored.record,
                &request.lease,
                LeaseKind::Rollout,
                now,
            )?;
            if requested_repositories != active.target_repositories {
                return Err(PublicationControlError::Invalid(format!(
                    "reader admission fleet {:?} does not equal rollout target {:?}",
                    requested_repositories, active.target_repositories
                )));
            }
            require_complete_authority_fence(active, &active.fence_repositories)?;
            let target_authority_fence = authority_fence_for_repositories(
                &active.authority_fence,
                &active.target_repositories,
            )?;
            let candidate = materialize_reader(&request.reader, now)?;
            validate_reader_against_authority_fence(&candidate, &target_authority_fence)?;
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.reader = candidate;
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(record),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(
            "publication record changed during every reader admission attempt".to_string(),
        ))
    }

    pub fn release_rollout(
        &self,
        request: ReleaseRolloutLeaseRequest,
    ) -> Result<PublicationControlRecord, PublicationControlError> {
        self.validate_scope(&request.lease.scope)?;
        self.release(&request.lease, LeaseKind::Rollout)
    }

    pub(crate) fn acquire_publication(
        &self,
        repo_id: &str,
        snapshot_schema: u32,
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        validate_identifier("repo_id", repo_id)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let now = self.clock.now();
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            if stored.record.repositories != self.fleet_repositories {
                return Err(PublicationControlError::Admission(format!(
                    "scope {} durable fleet {:?} does not match this daemon's configured fleet {:?}",
                    self.scope, stored.record.repositories, self.fleet_repositories
                )));
            }
            if stored
                .record
                .repositories
                .binary_search_by(|candidate| candidate.as_str().cmp(repo_id))
                .is_err()
            {
                return Err(PublicationControlError::Admission(format!(
                    "repo {repo_id} is outside fleet membership for scope {}",
                    self.scope
                )));
            }
            validate_reader_admission(&stored.record.reader, now)?;
            require_complete_record_authority_fence(&stored.record)?;
            validate_reader_against_authority_fence(
                &stored.record.reader,
                &stored.record.last_authority_fence,
            )?;
            if stored.record.reader.identity != self.runtime_reader_identity {
                return Err(PublicationControlError::Admission(format!(
                    "scope {} admits reader {}, but writer {} is running",
                    self.scope, stored.record.reader.identity, self.runtime_reader_identity
                )));
            }
            if snapshot_schema < stored.record.reader.min_snapshot_schema
                || snapshot_schema > stored.record.reader.max_snapshot_schema
            {
                return Err(PublicationControlError::Admission(format!(
                    "reader {} admits schemas {} through {}, not writer schema {}",
                    stored.record.reader.identity,
                    stored.record.reader.min_snapshot_schema,
                    stored.record.reader.max_snapshot_schema,
                    snapshot_schema
                )));
            }
            if let Some(active) = stored.record.active_lease.as_ref() {
                if active.kind == LeaseKind::Rollout {
                    return Err(PublicationControlError::Conflict(format!(
                        "rollout lease fence {} remains active and must be recovered before graph publication",
                        active.fence
                    )));
                }
                if active.expires_at > now {
                    return Err(PublicationControlError::Conflict(format!(
                        "{} lease fence {} held by {} until {}",
                        lease_kind_name(active.kind),
                        active.fence,
                        active.holder,
                        active.expires_at.to_rfc3339()
                    )));
                }
            }
            let fence = stored.record.last_fence.checked_add(1).ok_or_else(|| {
                PublicationControlError::Fenced(
                    "lease fence exhausted u64; refusing wraparound".to_string(),
                )
            })?;
            let request_id = Uuid::new_v4().to_string();
            let lease = self.new_lease(
                LeaseKind::Publication,
                format!("{}:{repo_id}", self.runtime_reader_identity),
                request_id,
                Some(repo_id.to_string()),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                fence,
                PUBLICATION_LEASE_SECONDS,
                now,
            )?;
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.last_fence = fence;
            record.active_lease = Some(lease.clone());
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(lease),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(format!(
            "scope {} changed during every publication acquisition attempt",
            self.scope
        )))
    }

    pub(crate) fn release_publication(
        &self,
        lease: &ActivePublicationLease,
    ) -> Result<PublicationControlRecord, PublicationControlError> {
        self.release(
            &LeaseProof {
                scope: self.scope.clone(),
                token: lease.token.clone(),
                fence: lease.fence,
            },
            LeaseKind::Publication,
        )
    }

    /// Renew the exact publication proof. Long-running server operations call
    /// this before every external mutation rather than assuming the lease they
    /// acquired at operation start is still live.
    pub(crate) fn renew_publication(
        &self,
        lease: &ActivePublicationLease,
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let now = self.clock.now();
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let current = require_lease(
                &stored.record,
                &LeaseProof {
                    scope: self.scope.clone(),
                    token: lease.token.clone(),
                    fence: lease.fence,
                },
                LeaseKind::Publication,
                now,
            )?;
            let mut renewed = current.clone();
            renewed.expires_at = checked_expiry(now, PUBLICATION_LEASE_SECONDS)?;
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.active_lease = Some(renewed.clone());
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(renewed),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(
            "publication lease changed during every renewal attempt".to_string(),
        ))
    }

    pub(crate) fn assert_publication_lease(
        &self,
        lease: &ActivePublicationLease,
    ) -> Result<(), PublicationControlError> {
        let stored = self.load_required()?;
        self.validate_record(&stored.record)?;
        require_lease(
            &stored.record,
            &LeaseProof {
                scope: self.scope.clone(),
                token: lease.token.clone(),
                fence: lease.fence,
            },
            LeaseKind::Publication,
            self.clock.now(),
        )?;
        Ok(())
    }

    fn release(
        &self,
        proof: &LeaseProof,
        kind: LeaseKind,
    ) -> Result<PublicationControlRecord, PublicationControlError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let now = self.clock.now();
            let stored = self.load_required()?;
            self.validate_record(&stored.record)?;
            let completed_retry = if kind == LeaseKind::Rollout {
                stored
                    .record
                    .completed_rollout_history
                    .iter()
                    .chain(stored.record.last_completed_rollout.iter())
                    .any(|last| completed_lease_matches(last, kind, proof))
            } else {
                stored
                    .record
                    .last_completed_lease
                    .as_ref()
                    .is_some_and(|last| completed_lease_matches(last, kind, proof))
            };
            if completed_retry {
                // A lost release response must remain retryable while an
                // unrelated newer lease is active. Never apply the stale proof
                // to that active lease; return the current ordered record.
                return Ok(stored.record);
            }
            if stored.record.active_lease.is_none() {
                return Err(PublicationControlError::Fenced(format!(
                    "lease fence {} is not active",
                    proof.fence
                )));
            }
            let active = require_lease(&stored.record, proof, kind, now)?.clone();
            if kind == LeaseKind::Rollout {
                require_complete_authority_fence(&active, &active.fence_repositories)?;
                if active.target_repositories != stored.record.repositories {
                    return Err(PublicationControlError::Admission(format!(
                        "completed rollout target {:?} does not equal installed fleet {:?}",
                        active.target_repositories, stored.record.repositories
                    )));
                }
                validate_reader_admission(&stored.record.reader, now)?;
                validate_reader_against_authority_fence(
                    &stored.record.reader,
                    &stored.record.last_authority_fence,
                )?;
            }
            let mut record = stored.record;
            record.revision = checked_revision(record.revision)?;
            record.active_lease = None;
            let completed = CompletedPublicationLease {
                kind,
                token: proof.token.clone(),
                fence: proof.fence,
                released_at: now,
                target_repositories: active.target_repositories,
                previous_repositories: active.previous_repositories,
                fence_repositories: active.fence_repositories,
                authority_fenced_at: active.authority_fenced_at,
                authority_fence: active.authority_fence,
            };
            record.last_completed_lease = Some(completed.clone());
            if kind == LeaseKind::Rollout {
                record.last_completed_rollout = Some(completed.clone());
                record.completed_rollout_history.retain(|prior| {
                    prior.token != completed.token || prior.fence != completed.fence
                });
                record.completed_rollout_history.push(completed);
                if record.completed_rollout_history.len() > MAX_COMPLETED_ROLLOUT_HISTORY {
                    let excess = record.completed_rollout_history.len()
                        - MAX_COMPLETED_ROLLOUT_HISTORY;
                    record.completed_rollout_history.drain(..excess);
                }
            }
            match self.store.update(&stored.version, &record) {
                Ok(_) => return Ok(record),
                Err(error) if error.is_cas_conflict() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(PublicationControlError::Conflict(
            "publication record changed during every release attempt".to_string(),
        ))
    }

    fn load_required(
        &self,
    ) -> Result<StoredPublicationControlRecord, PublicationControlError> {
        self.store
            .load()?
            .ok_or_else(|| PublicationControlError::Missing(self.scope.clone()))
    }

    fn validate_scope(&self, scope: &str) -> Result<(), PublicationControlError> {
        if scope != self.scope {
            return Err(PublicationControlError::Invalid(format!(
                "request scope {scope:?} does not match daemon scope {:?}",
                self.scope
            )));
        }
        Ok(())
    }

    fn validate_fleet_request(
        &self,
        repositories: &[String],
    ) -> Result<(), PublicationControlError> {
        let repositories = canonical_repositories(repositories)?;
        if repositories != self.fleet_repositories {
            return Err(PublicationControlError::Invalid(format!(
                "request repositories {:?} do not match daemon fleet {:?}",
                repositories, self.fleet_repositories
            )));
        }
        Ok(())
    }

    fn validate_record(
        &self,
        record: &PublicationControlRecord,
    ) -> Result<(), PublicationControlError> {
        if record.schema != PUBLICATION_CONTROL_SCHEMA {
            return Err(PublicationControlError::Admission(format!(
                "scope {} record has schema {:?}, expected {}",
                self.scope, record.schema, PUBLICATION_CONTROL_SCHEMA
            )));
        }
        if record.scope != self.scope {
            return Err(PublicationControlError::Admission(format!(
                "record scope {:?} does not match daemon scope {:?}",
                record.scope, self.scope
            )));
        }
        let canonical_record_repositories = canonical_repositories(&record.repositories)
            .map_err(|error| PublicationControlError::Admission(error.to_string()))?;
        if canonical_record_repositories != record.repositories {
            return Err(PublicationControlError::Admission(
                "stored fleet repositories are not in canonical order".to_string(),
            ));
        }
        if record.revision == 0 || record.last_fence == 0 {
            return Err(PublicationControlError::Admission(
                "record revision and last_fence must be nonzero".to_string(),
            ));
        }
        if record.revision < record.last_fence {
            return Err(PublicationControlError::Admission(format!(
                "record revision {} is behind last fence {}",
                record.revision, record.last_fence
            )));
        }
        validate_reader_shape(&record.reader)?;
        match record.last_authority_fenced_at {
            Some(_) => {
                validate_authority_fence(&record.last_authority_fence, &record.repositories)?;
            }
            None if record.last_authority_fence.is_empty()
                && record.active_lease.as_ref().is_some_and(|active| {
                    active.kind == LeaseKind::Rollout
                        && active.authority_fenced_at.is_none()
                }) => {}
            None if !record.last_authority_fence.is_empty() => {
                return Err(PublicationControlError::Admission(
                    "record carries authority fence evidence without its completion time"
                        .to_string(),
                ));
            }
            None => {
                return Err(PublicationControlError::Admission(
                    "record has no complete fleet authority fence".to_string(),
                ));
            }
        }
        if let Some(active) = record.active_lease.as_ref() {
            if active.fence != record.last_fence || active.fence == 0 {
                return Err(PublicationControlError::Admission(format!(
                    "active fence {} does not equal record fence {}",
                    active.fence, record.last_fence
                )));
            }
            validate_identifier("lease holder", &active.holder)?;
            validate_identifier("lease request_id", &active.request_id)?;
            validate_identifier("lease token", &active.token)?;
            if active.expires_at <= active.acquired_at {
                return Err(PublicationControlError::Admission(
                    "active lease expiry is not after acquisition".to_string(),
                ));
            }
            match (active.kind, active.repo_id.as_deref()) {
                (LeaseKind::Publication, Some(repo_id)) => {
                    validate_repo_id(repo_id)?;
                    if !active.target_repositories.is_empty()
                        || !active.previous_repositories.is_empty()
                        || !active.fence_repositories.is_empty()
                    {
                        return Err(PublicationControlError::Admission(
                            "publication lease must not carry fleet-transition membership"
                                .to_string(),
                        ));
                    }
                    if record
                        .repositories
                        .binary_search_by(|candidate| candidate.as_str().cmp(repo_id))
                        .is_err()
                    {
                        return Err(PublicationControlError::Admission(format!(
                            "publication lease repo {repo_id} is outside durable fleet membership"
                        )));
                    }
                    if active.authority_fencing_token.is_some()
                        || active.authority_fencing_started_at.is_some()
                        || !active.authority_capture.is_empty()
                        || active.authority_fenced_at.is_some()
                        || !active.authority_fence.is_empty()
                    {
                        return Err(PublicationControlError::Admission(
                            "publication lease must not carry rollout fencing state".to_string(),
                        ));
                    }
                }
                (LeaseKind::Rollout, None) => {
                    validate_rollout_membership(active, &record.repositories)?;
                    if active.authority_fenced_at.is_some() {
                        if active.authority_fencing_token.is_some()
                            || active.authority_fencing_started_at.is_some()
                            || !active.authority_capture.is_empty()
                        {
                            return Err(PublicationControlError::Admission(
                                "completed rollout fence still carries an in-progress claim"
                                    .to_string(),
                            ));
                        }
                        require_complete_authority_fence(
                            active,
                            &active.fence_repositories,
                        )?;
                        let target_authority_fence = authority_fence_for_repositories(
                            &active.authority_fence,
                            &active.target_repositories,
                        )?;
                        if active.target_repositories != record.repositories
                            || active.authority_fenced_at != record.last_authority_fenced_at
                            || target_authority_fence != record.last_authority_fence
                        {
                            return Err(PublicationControlError::Admission(
                                "completed active rollout does not install its target fleet and target-only fence evidence".to_string(),
                            ));
                        }
                    } else {
                        match (
                            active.authority_fencing_token.as_deref(),
                            active.authority_fencing_started_at,
                        ) {
                            (None, None) => {
                                if !active.authority_capture.is_empty()
                                    || !active.authority_fence.is_empty()
                                {
                                    return Err(PublicationControlError::Admission(
                                        "unclaimed rollout carries capture or checkpoint state"
                                            .to_string(),
                                    ));
                                }
                            }
                            (Some(token), Some(started_at)) => {
                                validate_identifier("authority fencing token", token)?;
                                if started_at < active.acquired_at
                                    || started_at >= active.expires_at
                                {
                                    return Err(PublicationControlError::Admission(
                                        "rollout resource-fencing claim is outside its live lease"
                                            .to_string(),
                                    ));
                                }
                                validate_authority_capture(
                                    &active.authority_capture,
                                    &active.fence_repositories,
                                )?;
                                validate_authority_fence_progress(
                                    &active.authority_fence,
                                    &active.authority_capture,
                                )?;
                            }
                            _ => {
                                return Err(PublicationControlError::Admission(
                                    "rollout resource-fencing token and start time must appear together"
                                        .to_string(),
                                ))
                            }
                        }
                    }
                }
                _ => {
                    return Err(PublicationControlError::Admission(
                        "publication leases require repo_id and rollout leases forbid it"
                            .to_string(),
                    ))
                }
            }
        }
        if let Some(completed) = record.last_completed_lease.as_ref() {
            validate_identifier("completed lease token", &completed.token)?;
            if completed.fence == 0 || completed.fence > record.last_fence {
                return Err(PublicationControlError::Admission(format!(
                    "completed fence {} is outside record fence {}",
                    completed.fence, record.last_fence
                )));
            }
            match completed.kind {
                LeaseKind::Publication => {
                    if !completed.target_repositories.is_empty()
                        || !completed.previous_repositories.is_empty()
                        || !completed.fence_repositories.is_empty()
                        || completed.authority_fenced_at.is_some()
                        || !completed.authority_fence.is_empty()
                    {
                        return Err(PublicationControlError::Admission(
                            "completed publication lease carries rollout fence evidence"
                                .to_string(),
                        ));
                    }
                }
                LeaseKind::Rollout => require_complete_completed_authority_fence(completed)?,
            }
        }
        if let Some(completed) = record.last_completed_rollout.as_ref() {
            if completed.kind != LeaseKind::Rollout {
                return Err(PublicationControlError::Admission(
                    "last_completed_rollout does not identify a rollout lease".to_string(),
                ));
            }
            validate_identifier("completed rollout token", &completed.token)?;
            if completed.fence == 0 || completed.fence > record.last_fence {
                return Err(PublicationControlError::Admission(format!(
                    "completed rollout fence {} is outside record fence {}",
                    completed.fence, record.last_fence
                )));
            }
            require_complete_completed_authority_fence(completed)?;
        }
        if record.completed_rollout_history.len() > MAX_COMPLETED_ROLLOUT_HISTORY {
            return Err(PublicationControlError::Admission(format!(
                "completed rollout history has {} entries, maximum is {MAX_COMPLETED_ROLLOUT_HISTORY}",
                record.completed_rollout_history.len()
            )));
        }
        let mut previous_fence = None;
        for completed in &record.completed_rollout_history {
            if completed.kind != LeaseKind::Rollout {
                return Err(PublicationControlError::Admission(
                    "completed rollout history contains a publication lease".to_string(),
                ));
            }
            validate_identifier("completed rollout history token", &completed.token)?;
            if completed.fence == 0 || completed.fence > record.last_fence {
                return Err(PublicationControlError::Admission(format!(
                    "completed rollout history fence {} is outside record fence {}",
                    completed.fence, record.last_fence
                )));
            }
            if previous_fence.is_some_and(|previous| previous >= completed.fence) {
                return Err(PublicationControlError::Admission(
                    "completed rollout history fences must be strictly increasing".to_string(),
                ));
            }
            require_complete_completed_authority_fence(completed)?;
            previous_fence = Some(completed.fence);
        }
        if let Some(latest) = record.completed_rollout_history.last() {
            if record.last_completed_rollout.as_ref() != Some(latest) {
                return Err(PublicationControlError::Admission(
                    "completed rollout history does not end at last_completed_rollout"
                        .to_string(),
                ));
            }
        }
        if record
            .last_completed_lease
            .as_ref()
            .is_some_and(|completed| completed.kind == LeaseKind::Rollout)
            && record.last_completed_lease != record.last_completed_rollout
        {
            return Err(PublicationControlError::Admission(
                "latest completed rollout does not match rollout retry history".to_string(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn new_lease(
        &self,
        kind: LeaseKind,
        holder: String,
        request_id: String,
        repo_id: Option<String>,
        target_repositories: Vec<String>,
        previous_repositories: Vec<String>,
        fence_repositories: Vec<String>,
        fence: u64,
        ttl_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<ActivePublicationLease, PublicationControlError> {
        Ok(ActivePublicationLease {
            kind,
            holder,
            request_id,
            token: Uuid::new_v4().to_string(),
            fence,
            repo_id,
            target_repositories,
            previous_repositories,
            fence_repositories,
            acquired_at: now,
            expires_at: checked_expiry(now, ttl_seconds)?,
            authority_fencing_token: None,
            authority_fencing_started_at: None,
            authority_capture: Vec::new(),
            authority_fenced_at: None,
            authority_fence: Vec::new(),
        })
    }
}

fn require_lease<'a>(
    record: &'a PublicationControlRecord,
    proof: &LeaseProof,
    expected_kind: LeaseKind,
    now: DateTime<Utc>,
) -> Result<&'a ActivePublicationLease, PublicationControlError> {
    let active = record.active_lease.as_ref().ok_or_else(|| {
        PublicationControlError::Fenced(format!("lease fence {} is not active", proof.fence))
    })?;
    if active.kind != expected_kind || active.token != proof.token || active.fence != proof.fence {
        return Err(PublicationControlError::Fenced(format!(
            "lease proof fence {} does not identify active {} fence {}",
            proof.fence,
            lease_kind_name(active.kind),
            active.fence
        )));
    }
    if active.expires_at <= now {
        return Err(PublicationControlError::Fenced(format!(
            "lease fence {} expired at {}",
            active.fence,
            active.expires_at.to_rfc3339()
        )));
    }
    Ok(active)
}

fn completed_lease_matches(
    completed: &CompletedPublicationLease,
    kind: LeaseKind,
    proof: &LeaseProof,
) -> bool {
    completed.kind == kind && completed.token == proof.token && completed.fence == proof.fence
}

fn canonical_repositories(
    repositories: &[String],
) -> Result<Vec<String>, PublicationControlError> {
    if repositories.is_empty() {
        return Err(PublicationControlError::Invalid(
            "fleet repositories must not be empty".to_string(),
        ));
    }
    if repositories.len() > MAX_FLEET_REPOSITORIES {
        return Err(PublicationControlError::Invalid(format!(
            "fleet repositories contains {} entries, above the bounded fleet limit {MAX_FLEET_REPOSITORIES}",
            repositories.len()
        )));
    }
    let mut canonical = repositories.to_vec();
    for repo_id in &canonical {
        validate_repo_id(repo_id)?;
    }
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PublicationControlError::Invalid(
            "fleet repositories must not contain duplicates".to_string(),
        ));
    }
    Ok(canonical)
}

fn repository_union(current: &[String], target: &[String]) -> Vec<String> {
    let mut union = current.to_vec();
    union.extend(target.iter().cloned());
    union.sort();
    union.dedup();
    union
}

fn validate_rollout_membership(
    lease: &ActivePublicationLease,
    record_repositories: &[String],
) -> Result<(), PublicationControlError> {
    let target = canonical_repositories(&lease.target_repositories)
        .map_err(|error| PublicationControlError::Admission(error.to_string()))?;
    if target != lease.target_repositories {
        return Err(PublicationControlError::Admission(
            "rollout target repositories are not in canonical order".to_string(),
        ));
    }
    let previous = canonical_repositories(&lease.previous_repositories)
        .map_err(|error| PublicationControlError::Admission(error.to_string()))?;
    if previous != lease.previous_repositories {
        return Err(PublicationControlError::Admission(
            "rollout previous repositories are not in canonical order".to_string(),
        ));
    }
    let fence = canonical_repositories(&lease.fence_repositories)
        .map_err(|error| PublicationControlError::Admission(error.to_string()))?;
    if fence != lease.fence_repositories {
        return Err(PublicationControlError::Admission(
            "rollout fence repositories are not in canonical order".to_string(),
        ));
    }
    if fence != repository_union(&previous, &target) {
        return Err(PublicationControlError::Admission(format!(
            "rollout fence fleet {:?} is not the exact union of previous {:?} and target {:?}",
            fence, previous, target
        )));
    }
    let expected_record_repositories = if lease.authority_fenced_at.is_some() {
        &target
    } else {
        &previous
    };
    if record_repositories != expected_record_repositories {
        return Err(PublicationControlError::Admission(format!(
            "rollout record fleet {:?} does not equal its expected {:?} membership {:?}",
            record_repositories,
            if lease.authority_fenced_at.is_some() {
                "target"
            } else {
                "previous"
            },
            expected_record_repositories
        )));
    }
    Ok(())
}

fn authority_fence_for_repositories(
    authority_fence: &[RepositoryAuthorityFence],
    repositories: &[String],
) -> Result<Vec<RepositoryAuthorityFence>, PublicationControlError> {
    let selected: Vec<RepositoryAuthorityFence> = authority_fence
        .iter()
        .filter(|entry| repositories.binary_search(&entry.repo_id).is_ok())
        .cloned()
        .collect();
    validate_authority_fence(&selected, repositories)?;
    Ok(selected)
}

fn validate_repo_id(repo_id: &str) -> Result<(), PublicationControlError> {
    if repo_id.is_empty()
        || repo_id.len() > 128
        || !repo_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(PublicationControlError::Invalid(format!(
            "repo_id {repo_id:?} must contain 1 through 128 ASCII letters, digits, '.', '-', or '_'"
        )));
    }
    Ok(())
}

fn validate_authority_capture(
    capture: &[RepositoryAuthorityCapture],
    repositories: &[String],
) -> Result<(), PublicationControlError> {
    let captured_repositories: Vec<&str> =
        capture.iter().map(|entry| entry.repo_id.as_str()).collect();
    let expected_repositories: Vec<&str> = repositories.iter().map(String::as_str).collect();
    if captured_repositories != expected_repositories {
        return Err(PublicationControlError::Admission(format!(
            "authority capture covers {:?}, expected exact fleet {:?}",
            captured_repositories, expected_repositories
        )));
    }
    for entry in capture {
        validate_repo_id(&entry.repo_id)?;
        if entry.generation == 0 || entry.snapshot_schema == 0 || entry.size_bytes == 0 {
            return Err(PublicationControlError::Admission(format!(
                "repo {} has invalid captured generation {}, schema {}, or size {}",
                entry.repo_id, entry.generation, entry.snapshot_schema, entry.size_bytes
            )));
        }
        let digest = entry.sha256.strip_prefix("sha256:").ok_or_else(|| {
            PublicationControlError::Admission(format!(
                "repo {} capture digest is not sha256-prefixed",
                entry.repo_id
            ))
        })?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PublicationControlError::Admission(format!(
                "repo {} capture digest is not 64 lowercase hex characters",
                entry.repo_id
            )));
        }
    }
    Ok(())
}

fn validate_authority_fence_entry(
    capture: &RepositoryAuthorityCapture,
    fence: &RepositoryAuthorityFence,
) -> Result<(), PublicationControlError> {
    if fence.repo_id != capture.repo_id
        || fence.pre_fence_generation != capture.generation
        || fence.fenced_generation <= fence.pre_fence_generation
        || fence.snapshot_schema != capture.snapshot_schema
    {
        return Err(PublicationControlError::Admission(format!(
            "repo {} fence {} -> {} at schema {} does not match capture {} at schema {}",
            fence.repo_id,
            fence.pre_fence_generation,
            fence.fenced_generation,
            fence.snapshot_schema,
            capture.generation,
            capture.snapshot_schema
        )));
    }
    Ok(())
}

fn validate_authority_fence_progress(
    progress: &[RepositoryAuthorityFence],
    capture: &[RepositoryAuthorityCapture],
) -> Result<(), PublicationControlError> {
    if progress.len() > capture.len() {
        return Err(PublicationControlError::Admission(format!(
            "authority fence progress has {} rows for a {}-row capture",
            progress.len(),
            capture.len()
        )));
    }
    for (captured, fenced) in capture.iter().zip(progress) {
        validate_authority_fence_entry(captured, fenced)?;
    }
    Ok(())
}

fn validate_authority_fence(
    authority_fence: &[RepositoryAuthorityFence],
    repositories: &[String],
) -> Result<(), PublicationControlError> {
    let fenced_repositories: Vec<&str> = authority_fence
        .iter()
        .map(|entry| entry.repo_id.as_str())
        .collect();
    let expected_repositories: Vec<&str> = repositories.iter().map(String::as_str).collect();
    if fenced_repositories != expected_repositories {
        return Err(PublicationControlError::Admission(format!(
            "authority fence covers {:?}, expected exact fleet {:?}",
            fenced_repositories, expected_repositories
        )));
    }
    for entry in authority_fence {
        validate_repo_id(&entry.repo_id)?;
        if entry.pre_fence_generation == 0
            || entry.fenced_generation <= entry.pre_fence_generation
            || entry.snapshot_schema == 0
        {
            return Err(PublicationControlError::Admission(format!(
                "repo {} has invalid authority fence generations {} -> {} or schema {}",
                entry.repo_id,
                entry.pre_fence_generation,
                entry.fenced_generation,
                entry.snapshot_schema
            )));
        }
    }
    Ok(())
}

fn require_complete_record_authority_fence(
    record: &PublicationControlRecord,
) -> Result<(), PublicationControlError> {
    if record.last_authority_fenced_at.is_none() {
        return Err(PublicationControlError::Admission(
            "fleet graph authority has not completed its generation fence".to_string(),
        ));
    }
    validate_authority_fence(&record.last_authority_fence, &record.repositories)
}

fn validate_reader_against_authority_fence(
    reader: &ReaderAdmission,
    authority_fence: &[RepositoryAuthorityFence],
) -> Result<(), PublicationControlError> {
    for authority in authority_fence {
        if authority.snapshot_schema < reader.min_snapshot_schema
            || authority.snapshot_schema > reader.max_snapshot_schema
        {
            return Err(PublicationControlError::Admission(format!(
                "reader {} admits schemas {} through {}, but fenced repo {} is schema {} at generation {}",
                reader.identity,
                reader.min_snapshot_schema,
                reader.max_snapshot_schema,
                authority.repo_id,
                authority.snapshot_schema,
                authority.fenced_generation
            )));
        }
    }
    Ok(())
}

fn require_complete_authority_fence(
    lease: &ActivePublicationLease,
    repositories: &[String],
) -> Result<(), PublicationControlError> {
    let fenced_at = lease.authority_fenced_at.ok_or_else(|| {
        PublicationControlError::Fenced(format!(
            "rollout lease fence {} has not fenced graph generations",
            lease.fence
        ))
    })?;
    if fenced_at < lease.acquired_at || fenced_at >= lease.expires_at {
        return Err(PublicationControlError::Admission(format!(
            "rollout lease fence {} has fence time outside its live interval",
            lease.fence
        )));
    }
    if !lease.authority_capture.is_empty()
        || lease.authority_fencing_token.is_some()
        || lease.authority_fencing_started_at.is_some()
    {
        return Err(PublicationControlError::Admission(format!(
            "rollout lease fence {} completed with in-progress capture state",
            lease.fence
        )));
    }
    validate_authority_fence(&lease.authority_fence, repositories)
}

fn require_complete_completed_authority_fence(
    lease: &CompletedPublicationLease,
) -> Result<(), PublicationControlError> {
    let target = canonical_repositories(&lease.target_repositories)
        .map_err(|error| PublicationControlError::Admission(error.to_string()))?;
    if target != lease.target_repositories {
        return Err(PublicationControlError::Admission(
            "completed rollout target repositories are not in canonical order".to_string(),
        ));
    }
    let previous = canonical_repositories(&lease.previous_repositories)
        .map_err(|error| PublicationControlError::Admission(error.to_string()))?;
    if previous != lease.previous_repositories {
        return Err(PublicationControlError::Admission(
            "completed rollout previous repositories are not in canonical order".to_string(),
        ));
    }
    let fence = canonical_repositories(&lease.fence_repositories)
        .map_err(|error| PublicationControlError::Admission(error.to_string()))?;
    if fence != lease.fence_repositories {
        return Err(PublicationControlError::Admission(
            "completed rollout fence repositories are not in canonical order".to_string(),
        ));
    }
    if fence != repository_union(&previous, &target) {
        return Err(PublicationControlError::Admission(format!(
            "completed rollout fence fleet {:?} is not the exact union of previous {:?} and target {:?}",
            fence, previous, target
        )));
    }
    if lease.authority_fenced_at.is_none() {
        return Err(PublicationControlError::Admission(format!(
            "completed rollout lease fence {} has no authority fence time",
            lease.fence
        )));
    }
    validate_authority_fence(&lease.authority_fence, &lease.fence_repositories)
}

fn validate_reader_input(input: &ReaderAdmissionInput) -> Result<(), PublicationControlError> {
    validate_image_identity(&input.identity)?;
    if input.min_snapshot_schema == 0 {
        return Err(PublicationControlError::Invalid(
            "min_snapshot_schema must be nonzero".to_string(),
        ));
    }
    if input.min_snapshot_schema > input.max_snapshot_schema {
        return Err(PublicationControlError::Invalid(format!(
            "reader schema range {} through {} is inverted",
            input.min_snapshot_schema, input.max_snapshot_schema
        )));
    }
    if input.valid_for_seconds == 0 || input.valid_for_seconds > MAX_READER_ADMISSION_SECONDS {
        return Err(PublicationControlError::Invalid(format!(
            "valid_for_seconds must be between 1 and {MAX_READER_ADMISSION_SECONDS}"
        )));
    }
    Ok(())
}

fn validate_reader_shape(reader: &ReaderAdmission) -> Result<(), PublicationControlError> {
    validate_image_identity(&reader.identity).map_err(|error| {
        PublicationControlError::Admission(format!("stored reader identity is invalid: {error}"))
    })?;
    if reader.min_snapshot_schema == 0
        || reader.min_snapshot_schema > reader.max_snapshot_schema
        || reader.expires_at <= reader.admitted_at
    {
        return Err(PublicationControlError::Admission(
            "stored reader admission has an invalid range or lifetime".to_string(),
        ));
    }
    Ok(())
}

fn validate_reader_admission(
    reader: &ReaderAdmission,
    now: DateTime<Utc>,
) -> Result<(), PublicationControlError> {
    validate_reader_shape(reader)?;
    if reader.expires_at <= now {
        return Err(PublicationControlError::Admission(format!(
            "reader {} expired at {}",
            reader.identity,
            reader.expires_at.to_rfc3339()
        )));
    }
    Ok(())
}

fn materialize_reader(
    input: &ReaderAdmissionInput,
    now: DateTime<Utc>,
) -> Result<ReaderAdmission, PublicationControlError> {
    validate_reader_input(input)?;
    Ok(ReaderAdmission {
        identity: input.identity.clone(),
        min_snapshot_schema: input.min_snapshot_schema,
        max_snapshot_schema: input.max_snapshot_schema,
        admitted_at: now,
        expires_at: checked_expiry(now, input.valid_for_seconds)?,
    })
}

fn validate_rollout_ttl(ttl_seconds: u64) -> Result<(), PublicationControlError> {
    if ttl_seconds == 0 || ttl_seconds > MAX_ROLLOUT_LEASE_SECONDS {
        return Err(PublicationControlError::Invalid(format!(
            "ttl_seconds must be between 1 and {MAX_ROLLOUT_LEASE_SECONDS}"
        )));
    }
    Ok(())
}

fn checked_expiry(
    now: DateTime<Utc>,
    seconds: u64,
) -> Result<DateTime<Utc>, PublicationControlError> {
    let seconds = i64::try_from(seconds).map_err(|_| {
        PublicationControlError::Invalid("lease lifetime exceeds i64 seconds".to_string())
    })?;
    now.checked_add_signed(ChronoDuration::seconds(seconds))
        .ok_or_else(|| PublicationControlError::Invalid("lease expiry overflows time".to_string()))
}

fn checked_revision(revision: u64) -> Result<u64, PublicationControlError> {
    revision.checked_add(1).ok_or_else(|| {
        PublicationControlError::Fenced("record revision exhausted u64".to_string())
    })
}

fn validate_identifier(name: &str, value: &str) -> Result<(), PublicationControlError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(PublicationControlError::Invalid(format!(
            "{name} must contain 1 through 512 non-control characters"
        )));
    }
    Ok(())
}

fn validate_image_identity(identity: &str) -> Result<(), PublicationControlError> {
    let Some(hex) = identity.strip_prefix("sha256:") else {
        return Err(PublicationControlError::Invalid(
            "reader identity must be sha256:<64 lowercase hex>".to_string(),
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PublicationControlError::Invalid(
            "reader identity must be sha256:<64 lowercase hex>".to_string(),
        ));
    }
    Ok(())
}

fn lease_kind_name(kind: LeaseKind) -> &'static str {
    match kind {
        LeaseKind::Publication => "publication",
        LeaseKind::Rollout => "rollout",
    }
}

fn as_storage_error(error: PublicationControlError) -> KinDbError {
    KinDbError::StorageError(format!("graph publication admission refused: {error}"))
}

/// Read the schema asserted by the exact KNDB bytes crossing the final storage
/// boundary. The inner backend remains responsible for full frame, checksum,
/// and semantic validation. This small header read exists so admission cannot
/// authorize a caller-supplied payload using the daemon's compiled constant.
fn snapshot_schema_from_bytes(data: &[u8]) -> Result<u32, KinDbError> {
    if data.len() < 8 || &data[..4] != b"KNDB" {
        return Err(KinDbError::StorageError(
            "graph publication payload is truncated or has no KNDB header".to_string(),
        ));
    }
    let version = u32::from_le_bytes(data[4..8].try_into().map_err(|_| {
        KinDbError::StorageError(
            "graph publication payload has a malformed KNDB schema".to_string(),
        )
    })?);
    if version == 0 {
        return Err(KinDbError::StorageError(
            "graph publication payload declares KNDB schema zero".to_string(),
        ));
    }
    Ok(version)
}

/// Storage wrapper installed once, under every hosted server-side publication
/// path. New authority-manager and transfer callers inherit the gate because
/// they receive this same erased backend from `DaemonState`.
pub struct PublicationGatedStorageBackend {
    inner: Box<dyn StorageBackend>,
    control: Arc<PublicationControl>,
}

/// Owns one graph-storage publication lease until explicit release. The
/// storage trait is synchronous, so an unwind cannot be intercepted by the
/// caller; Drop is the only reliable cleanup boundary for a panicking backend.
struct StoragePublicationGuard {
    control: Arc<PublicationControl>,
    lease: Option<ActivePublicationLease>,
}

impl StoragePublicationGuard {
    fn acquire(
        control: Arc<PublicationControl>,
        repo_id: &str,
        snapshot_schema: u32,
    ) -> Result<Self, PublicationControlError> {
        let lease = control.acquire_publication(repo_id, snapshot_schema)?;
        Ok(Self {
            control,
            lease: Some(lease),
        })
    }

    fn lease(&self) -> &ActivePublicationLease {
        self.lease
            .as_ref()
            .expect("storage publication guard retains its lease until release")
    }

    fn assert_current(&self) -> Result<(), PublicationControlError> {
        self.control.assert_publication_lease(self.lease())
    }

    fn renew_and_assert(&mut self) -> Result<(), PublicationControlError> {
        let renewed = self.control.renew_publication(self.lease())?;
        self.lease = Some(renewed);
        self.assert_current()
    }

    fn release(mut self) -> Result<PublicationControlRecord, PublicationControlError> {
        let lease = self
            .lease
            .take()
            .expect("storage publication guard releases at most once");
        self.control.release_publication(&lease)
    }
}

impl Drop for StoragePublicationGuard {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        if let Err(error) = self.control.release_publication(&lease) {
            tracing::warn!(
                fence = lease.fence,
                %error,
                "graph storage publication guard could not release during cleanup"
            );
        }
    }
}

impl PublicationGatedStorageBackend {
    pub fn new(inner: Box<dyn StorageBackend>, control: Arc<PublicationControl>) -> Self {
        Self { inner, control }
    }

    fn with_publication<T>(
        &self,
        repo_id: &str,
        snapshot_schema: u32,
        operation: impl FnOnce(&dyn StorageBackend) -> Result<T, KinDbError>,
    ) -> Result<T, KinDbError> {
        let mut guard = StoragePublicationGuard::acquire(
            Arc::clone(&self.control),
            repo_id,
            snapshot_schema,
        )
        .map_err(as_storage_error)?;
        guard.renew_and_assert().map_err(as_storage_error)?;
        let fence = guard.lease().fence;
        let outcome = operation(self.inner.as_ref());
        let post_assert = guard.assert_current();
        let release = guard.release();
        match (outcome, post_assert, release) {
            (Ok(value), Ok(()), Ok(_)) => Ok(value),
            (Ok(_), Err(error), release) => {
                if let Err(release_error) = release {
                    tracing::warn!(
                        fence,
                        %release_error,
                        "authority operation lost its publication proof and release also failed"
                    );
                }
                Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                    "authority operation returned success under lease fence {fence}, but that proof was no longer current afterward: {error}"
                )))
            }
            (Ok(_), Ok(()), Err(error)) => Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                "authority operation returned success under lease fence {}, but releasing that fence failed: {error}",
                fence
            ))),
            (Err(error), post_assert, release) => {
                if let Err(assert_error) = post_assert {
                    tracing::warn!(
                        fence,
                        %assert_error,
                        "failed authority operation no longer held its publication proof afterward"
                    );
                }
                if let Err(release_error) = release {
                    tracing::warn!(
                        fence,
                        %release_error,
                        "authority operation failed and its publication lease could not be released"
                    );
                }
                Err(error)
            }
        }
    }

    fn with_classified_publication(
        &self,
        repo_id: &str,
        snapshot_schema: u32,
        operation: impl FnOnce(&dyn StorageBackend) -> SnapshotSaveOutcome,
    ) -> SnapshotSaveOutcome {
        let mut guard = match StoragePublicationGuard::acquire(
            Arc::clone(&self.control),
            repo_id,
            snapshot_schema,
        ) {
            Ok(guard) => guard,
            Err(error) => return SnapshotSaveOutcome::NotCommitted(as_storage_error(error)),
        };
        if let Err(error) = guard.renew_and_assert() {
            return SnapshotSaveOutcome::NotCommitted(as_storage_error(error));
        }
        let fence = guard.lease().fence;
        let outcome = operation(self.inner.as_ref());
        let post_assert = guard.assert_current();
        let release = guard.release();
        match (outcome, post_assert, release) {
            (outcome, Ok(()), Ok(_)) => outcome,
            (SnapshotSaveOutcome::Committed { .. }, Err(error), release) => {
                if let Err(release_error) = release {
                    tracing::warn!(
                        fence,
                        %release_error,
                        "committed authority lost its publication proof and release also failed"
                    );
                }
                SnapshotSaveOutcome::Indeterminate(KinDbError::SnapshotPersistenceIndeterminate(
                    format!(
                        "authority committed under lease fence {fence}, but that proof was no longer current afterward: {error}"
                    ),
                ))
            }
            (SnapshotSaveOutcome::Committed { .. }, Ok(()), Err(error)) => {
                SnapshotSaveOutcome::Indeterminate(KinDbError::SnapshotPersistenceIndeterminate(
                    format!(
                        "authority committed under lease fence {}, but releasing that fence failed: {error}",
                        fence
                    ),
                ))
            }
            (outcome, post_assert, release) => {
                if let Err(assert_error) = post_assert {
                    tracing::warn!(
                        fence,
                        %assert_error,
                        "non-committed authority operation no longer held its publication proof afterward"
                    );
                }
                if let Err(error) = release {
                    tracing::warn!(
                        fence,
                        %error,
                        "non-committed authority operation could not release its publication lease"
                    );
                }
                outcome
            }
        }
    }
}

impl StorageBackend for PublicationGatedStorageBackend {
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        self.inner.load_snapshot(repo_id)
    }

    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        self.inner.load_snapshot_authority(repo_id)
    }

    fn load_recovery_state(
        &self,
        repo_id: &str,
    ) -> Result<SnapshotRecoveryState, KinDbError> {
        self.inner.load_recovery_state(repo_id)
    }

    fn save_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        data: &[u8],
    ) -> Result<(), KinDbError> {
        self.inner.save_source_blob(repo_id, digest, data)
    }

    fn load_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.inner.load_source_blob(repo_id, digest)
    }

    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.inner
            .load_source_blob_bounded(repo_id, digest, max_bytes)
    }

    fn source_blob_len(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<u64>, KinDbError> {
        self.inner.source_blob_len(repo_id, digest)
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let snapshot_schema = snapshot_schema_from_bytes(data)?;
        self.with_publication(repo_id, snapshot_schema, |inner| {
            inner.save_snapshot(repo_id, data, expected_gen)
        })
    }

    fn save_snapshot_classified(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
    ) -> SnapshotSaveOutcome {
        let snapshot_schema = match snapshot_schema_from_bytes(data) {
            Ok(snapshot_schema) => snapshot_schema,
            Err(error) => return SnapshotSaveOutcome::NotCommitted(error),
        };
        self.with_classified_publication(repo_id, snapshot_schema, |inner| {
            inner.save_snapshot_classified(repo_id, data, expected_cursor)
        })
    }

    fn save_snapshot_validated(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome {
        let snapshot_schema = match snapshot_schema_from_bytes(data) {
            Ok(snapshot_schema) => snapshot_schema,
            Err(error) => return SnapshotSaveOutcome::NotCommitted(error),
        };
        self.with_classified_publication(repo_id, snapshot_schema, |inner| {
            inner.save_snapshot_validated(
                repo_id,
                data,
                expected_cursor,
                history_validator_version,
            )
        })
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _ = (delta_data, base_gen);
        Err(KinDbError::StorageError(format!(
            "hosted graph publication refuses incremental delta authority for repo {repo_id}: the fleet resource fence covers full graph.kndb generations only"
        )))
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        self.inner.load_deltas_since(repo_id, since_gen)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        Err(KinDbError::StorageError(format!(
            "hosted graph publication refuses delta cleanup for repo {repo_id}: the fleet resource fence covers full graph.kndb generations only"
        )))
    }

    fn save_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), KinDbError> {
        self.inner.save_overlay(repo_id, session_id, data)
    }

    fn load_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.inner.load_overlay(repo_id, session_id)
    }

    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
        self.inner.delete_overlay(repo_id, session_id)
    }

    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        self.inner.list_repos()
    }
}

/// Deterministic CAS store used by direct API, expiry, retry, and race tests.
#[derive(Debug, Default)]
pub struct InMemoryPublicationControlStore {
    state: Mutex<Option<(PublicationControlRecord, u64)>>,
    authority: Mutex<BTreeMap<String, (u64, u32)>>,
    #[cfg(test)]
    fence_gate: Mutex<Option<Arc<(Mutex<(bool, bool)>, std::sync::Condvar)>>>,
    #[cfg(test)]
    fence_failure: Mutex<Option<String>>,
    #[cfg(test)]
    missing_authority: Mutex<Option<String>>,
    #[cfg(test)]
    crash_after_fenced_repositories: Mutex<Option<usize>>,
}

impl PublicationControlStore for InMemoryPublicationControlStore {
    fn load(
        &self,
    ) -> Result<Option<StoredPublicationControlRecord>, PublicationControlError> {
        let state = self
            .state
            .lock()
            .map_err(|_| PublicationControlError::Store("memory store poisoned".to_string()))?;
        Ok(state
            .as_ref()
            .map(|(record, version)| StoredPublicationControlRecord {
                record: record.clone(),
                version: memory_version(*version),
            }))
    }

    fn create(
        &self,
        record: &PublicationControlRecord,
    ) -> Result<PublicationRecordVersion, PublicationControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PublicationControlError::Store("memory store poisoned".to_string()))?;
        if state.is_some() {
            return Err(PublicationControlError::Conflict(
                "record already exists".to_string(),
            ));
        }
        *state = Some((record.clone(), 1));
        Ok(memory_version(1))
    }

    fn update(
        &self,
        expected: &PublicationRecordVersion,
        record: &PublicationControlRecord,
    ) -> Result<PublicationRecordVersion, PublicationControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PublicationControlError::Store("memory store poisoned".to_string()))?;
        let Some((_, version)) = state.as_ref() else {
            return Err(PublicationControlError::Conflict(
                "record disappeared".to_string(),
            ));
        };
        if &memory_version(*version) != expected {
            return Err(PublicationControlError::Conflict(format!(
                "record version {} no longer matches",
                version
            )));
        }
        let next = version.checked_add(1).ok_or_else(|| {
            PublicationControlError::Store("memory version exhausted u64".to_string())
        })?;
        *state = Some((record.clone(), next));
        Ok(memory_version(next))
    }

    fn capture_authority(
        &self,
        repositories: &[String],
    ) -> Result<Vec<RepositoryAuthorityCapture>, PublicationControlError> {
        let mut authority = self.authority.lock().map_err(|_| {
            PublicationControlError::Store("memory authority poisoned".to_string())
        })?;
        let mut captured = Vec::with_capacity(repositories.len());
        for repo_id in repositories {
            #[cfg(test)]
            if self
                .missing_authority
                .lock()
                .map_err(|_| {
                    PublicationControlError::Store("memory missing hook poisoned".to_string())
                })?
                .as_deref()
                == Some(repo_id.as_str())
            {
                return Err(PublicationControlError::Admission(format!(
                    "fleet repo {repo_id} has no graph authority object"
                )));
            }
            let current = authority
                .entry(repo_id.clone())
                .or_insert((1, kin_db::GraphSnapshot::CURRENT_VERSION));
            captured.push(RepositoryAuthorityCapture {
                repo_id: repo_id.clone(),
                generation: current.0,
                snapshot_schema: current.1,
                size_bytes: 1,
                sha256: format!("sha256:{:064x}", current.1),
                e_tag: Some(format!("memory-graph-{repo_id}-{}", current.0)),
            });
        }
        Ok(captured)
    }

    fn fence_authority(
        &self,
        capture: &RepositoryAuthorityCapture,
    ) -> Result<RepositoryAuthorityFence, PublicationControlError> {
        let repo_id = capture.repo_id.as_str();

        #[cfg(test)]
        if let Some(gate) = self
            .fence_gate
            .lock()
            .map_err(|_| PublicationControlError::Store("memory fence gate poisoned".to_string()))?
            .take()
        {
            let (state, changed) = gate.as_ref();
            let mut state = state.lock().map_err(|_| {
                PublicationControlError::Store("memory fence gate state poisoned".to_string())
            })?;
            state.0 = true;
            changed.notify_all();
            while !state.1 {
                state = changed.wait(state).map_err(|_| {
                    PublicationControlError::Store("memory fence gate wait poisoned".to_string())
                })?;
            }
        }

        #[cfg(test)]
        if self
            .fence_failure
            .lock()
            .map_err(|_| PublicationControlError::Store("memory fence hook poisoned".to_string()))?
            .as_deref()
            == Some(repo_id)
        {
            return Err(PublicationControlError::Store(format!(
                "repo {repo_id} authority is unavailable during fencing"
            )));
        }

        let fenced_generation = {
            let mut authority = self.authority.lock().map_err(|_| {
                PublicationControlError::Store("memory authority poisoned".to_string())
            })?;
            let current = authority.get_mut(repo_id).ok_or_else(|| {
                PublicationControlError::Conflict(format!(
                    "repo {repo_id} authority disappeared after fence capture"
                ))
            })?;
            if current.1 != capture.snapshot_schema
                || capture.sha256 != format!("sha256:{:064x}", current.1)
            {
                return Err(PublicationControlError::Conflict(format!(
                    "repo {repo_id} authority bytes changed after fleet capture"
                )));
            }
            if current.0 != capture.generation {
                return Err(PublicationControlError::Conflict(format!(
                    "repo {repo_id} authority generation changed after the complete fleet capture; recapture every repository before retrying"
                )));
            }
            current.0 = current.0.checked_add(1).ok_or_else(|| {
                PublicationControlError::Store(format!(
                    "repo {repo_id} authority generation exhausted u64"
                ))
            })?;
            current.0
        };

        #[cfg(test)]
        {
            let completed = self
                .state
                .lock()
                .map_err(|_| PublicationControlError::Store("memory state poisoned".to_string()))?
                .as_ref()
                .and_then(|(record, _)| record.active_lease.as_ref())
                .map(|active| active.authority_fence.len() + 1)
                .unwrap_or(1);
            let mut hook = self.crash_after_fenced_repositories.lock().map_err(|_| {
                PublicationControlError::Store("memory crash hook poisoned".to_string())
            })?;
            if hook.is_some_and(|count| count == completed) {
                *hook = None;
                panic!("injected abrupt death after a strict fleet prefix");
            }
        }

        Ok(RepositoryAuthorityFence {
            repo_id: capture.repo_id.clone(),
            pre_fence_generation: capture.generation,
            fenced_generation,
            snapshot_schema: capture.snapshot_schema,
            e_tag: Some(format!("memory-graph-{repo_id}-{fenced_generation}")),
        })
    }

    fn verify_authority_fence(
        &self,
        capture: &RepositoryAuthorityCapture,
        fence: &RepositoryAuthorityFence,
    ) -> Result<(), PublicationControlError> {
        validate_authority_fence_entry(capture, fence)?;
        let authority = self.authority.lock().map_err(|_| {
            PublicationControlError::Store("memory authority poisoned".to_string())
        })?;
        let current = authority.get(&capture.repo_id).ok_or_else(|| {
            PublicationControlError::Conflict(format!(
                "repo {} authority disappeared after checkpoint",
                capture.repo_id
            ))
        })?;
        if *current != (fence.fenced_generation, capture.snapshot_schema) {
            return Err(PublicationControlError::Fenced(format!(
                "repo {} checkpoint generation {} is no longer durable",
                capture.repo_id, fence.fenced_generation
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
impl InMemoryPublicationControlStore {
    fn block_next_fence(&self) -> Arc<(Mutex<(bool, bool)>, std::sync::Condvar)> {
        let gate = Arc::new((Mutex::new((false, false)), std::sync::Condvar::new()));
        *self.fence_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }

    fn seed_authority(&self, repo_id: &str, generation: u64, snapshot_schema: u32) {
        self.authority
            .lock()
            .unwrap()
            .insert(repo_id.to_string(), (generation, snapshot_schema));
    }

    fn advance_authority(
        &self,
        repo_id: &str,
        expected_generation: u64,
        snapshot_schema: u32,
    ) -> Result<u64, KinDbError> {
        let mut authority = self.authority.lock().unwrap();
        let current = authority
            .entry(repo_id.to_string())
            .or_insert((1, snapshot_schema));
        if current.0 != expected_generation {
            return Err(KinDbError::ConcurrentAccessError(format!(
                "repo {repo_id} expected generation {expected_generation}, found {}",
                current.0
            )));
        }
        current.0 += 1;
        current.1 = snapshot_schema;
        Ok(current.0)
    }

    fn fail_fence_on(&self, repo_id: Option<&str>) {
        *self.fence_failure.lock().unwrap() = repo_id.map(str::to_string);
    }

    fn crash_fence_after(&self, repositories: Option<usize>) {
        *self.crash_after_fenced_repositories.lock().unwrap() = repositories;
    }

    fn mark_authority_missing(&self, repo_id: Option<&str>) {
        *self.missing_authority.lock().unwrap() = repo_id.map(str::to_string);
    }

    fn authority_state(&self, repo_id: &str) -> Option<(u64, u32)> {
        self.authority.lock().unwrap().get(repo_id).copied()
    }
}

fn memory_version(version: u64) -> PublicationRecordVersion {
    PublicationRecordVersion {
        e_tag: Some(format!("memory-{version}")),
        version: Some(version.to_string()),
    }
}

#[cfg(feature = "gcs")]
mod object_store_control {
    use std::future::Future;
    use std::sync::{Arc, OnceLock};

    use object_store::path::Path as ObjectPath;
    use object_store::{
        ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion,
    };
    use sha2::{Digest, Sha256};

    use super::{
        PublicationControlError, PublicationControlRecord, PublicationControlStore,
        PublicationRecordVersion, RepositoryAuthorityCapture, RepositoryAuthorityFence,
        StoredPublicationControlRecord,
    };

    const GCS_FULL_AUTHORITY_MAGIC: &[u8; 8] = b"KNGCSF02";
    const GCS_FULL_AUTHORITY_HEADER_LEN: usize = 48;
    const SNAPSHOT_HEADER_LEN: usize = 16;
    const SNAPSHOT_CHECKSUM_LEN: usize = 32;
    const ROOT_HASH_TRAILER_LEN: usize = 68;
    const MAX_AUTHORITY_FENCE_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
    const MAX_PUBLICATION_CONTROL_RECORD_BYTES: u64 = 1024 * 1024;

    pub struct ObjectStorePublicationControlStore {
        store: Arc<dyn ObjectStore>,
        prefix: String,
        path: ObjectPath,
        max_authority_fence_object_bytes: u64,
        max_control_record_bytes: u64,
        fallback_rt: OnceLock<tokio::runtime::Runtime>,
        #[cfg(test)]
        fence_body_residency: std::sync::Mutex<(usize, usize)>,
    }

    #[cfg(test)]
    struct FenceBodyResidency<'a> {
        state: &'a std::sync::Mutex<(usize, usize)>,
        bytes: usize,
    }

    #[cfg(test)]
    impl Drop for FenceBodyResidency<'_> {
        fn drop(&mut self) {
            let mut state = self.state.lock().unwrap();
            state.0 = state.0.saturating_sub(self.bytes);
        }
    }

    impl std::fmt::Debug for ObjectStorePublicationControlStore {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("ObjectStorePublicationControlStore")
                .field("path", &self.path)
                .finish_non_exhaustive()
        }
    }

    impl ObjectStorePublicationControlStore {
        pub fn new(store: Arc<dyn ObjectStore>, prefix: &str) -> Self {
            let prefix = prefix.trim_matches('/').to_string();
            let path = if prefix.is_empty() {
                ObjectPath::from(".kin-graph-publication-control.json")
            } else {
                ObjectPath::from(format!(
                    "{}/.kin-graph-publication-control.json",
                    prefix
                ))
            };
            Self {
                store,
                prefix,
                path,
                max_authority_fence_object_bytes: MAX_AUTHORITY_FENCE_OBJECT_BYTES,
                max_control_record_bytes: MAX_PUBLICATION_CONTROL_RECORD_BYTES,
                fallback_rt: OnceLock::new(),
                #[cfg(test)]
                fence_body_residency: std::sync::Mutex::new((0, 0)),
            }
        }

        #[cfg(test)]
        pub(super) fn with_fence_memory_limit(
            store: Arc<dyn ObjectStore>,
            prefix: &str,
            max_authority_fence_object_bytes: u64,
        ) -> Self {
            let mut control = Self::new(store, prefix);
            control.max_authority_fence_object_bytes = max_authority_fence_object_bytes;
            control
        }

        #[cfg(test)]
        pub(super) fn with_control_record_limit(
            store: Arc<dyn ObjectStore>,
            prefix: &str,
            max_control_record_bytes: u64,
        ) -> Self {
            let mut control = Self::new(store, prefix);
            control.max_control_record_bytes = max_control_record_bytes;
            control
        }

        #[cfg(test)]
        fn track_fence_body(&self, bytes: usize) -> FenceBodyResidency<'_> {
            let mut state = self.fence_body_residency.lock().unwrap();
            state.0 += bytes;
            state.1 = state.1.max(state.0);
            drop(state);
            FenceBodyResidency {
                state: &self.fence_body_residency,
                bytes,
            }
        }

        #[cfg(test)]
        pub(super) fn peak_fence_body_bytes(&self) -> usize {
            self.fence_body_residency.lock().unwrap().1
        }

        fn block_on<F: Future>(&self, future: F) -> F::Output {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                tokio::task::block_in_place(|| handle.block_on(future))
            } else {
                self.fallback_rt
                    .get_or_init(|| {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("publication control runtime")
                    })
                    .block_on(future)
            }
        }

        fn version_from_meta(meta: &object_store::ObjectMeta) -> PublicationRecordVersion {
            PublicationRecordVersion {
                e_tag: meta.e_tag.clone(),
                version: meta.version.clone(),
            }
        }

        fn version_for_update(version: &PublicationRecordVersion) -> UpdateVersion {
            UpdateVersion {
                e_tag: version.e_tag.clone(),
                version: version.version.clone(),
            }
        }

        fn snapshot_path(&self, repo_id: &str) -> ObjectPath {
            if self.prefix.is_empty() {
                ObjectPath::from(format!("{repo_id}/graph.kndb"))
            } else {
                ObjectPath::from(format!("{}/{repo_id}/graph.kndb", self.prefix))
            }
        }

        fn numeric_generation(
            version: Option<&str>,
            authority: &str,
        ) -> Result<u64, PublicationControlError> {
            let version = version.ok_or_else(|| {
                PublicationControlError::Store(format!(
                    "{authority} has no object generation; resource fencing is unavailable"
                ))
            })?;
            version.parse::<u64>().map_err(|error| {
                PublicationControlError::Store(format!(
                    "{authority} has nonnumeric generation {version:?}: {error}"
                ))
            })
        }

        fn snapshot_schema(bytes: &[u8], authority: &str) -> Result<u32, PublicationControlError> {
            if bytes.len() < GCS_FULL_AUTHORITY_HEADER_LEN + SNAPSHOT_HEADER_LEN {
                return Err(PublicationControlError::Admission(format!(
                    "{authority} is truncated before the snapshot header"
                )));
            }
            if &bytes[..8] != GCS_FULL_AUTHORITY_MAGIC {
                return Err(PublicationControlError::Admission(format!(
                    "{authority} does not carry KNGCSF02 graph authority"
                )));
            }
            let payload_len = u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| {
                PublicationControlError::Admission(format!(
                    "{authority} has a malformed envelope length"
                ))
            })?);
            let payload_len = usize::try_from(payload_len).map_err(|_| {
                PublicationControlError::Admission(format!(
                    "{authority} payload length exceeds this platform"
                ))
            })?;
            let expected_len = GCS_FULL_AUTHORITY_HEADER_LEN
                .checked_add(payload_len)
                .ok_or_else(|| {
                    PublicationControlError::Admission(format!(
                        "{authority} payload length overflows"
                    ))
                })?;
            if bytes.len() != expected_len {
                return Err(PublicationControlError::Admission(format!(
                    "{authority} length is {}, envelope declares {expected_len}",
                    bytes.len()
                )));
            }
            let payload = &bytes[GCS_FULL_AUTHORITY_HEADER_LEN..];
            let outer_digest: [u8; 32] = Sha256::digest(payload).into();
            if bytes[16..48] != outer_digest {
                return Err(PublicationControlError::Admission(format!(
                    "{authority} envelope digest does not match its payload"
                )));
            }
            if &payload[..4] != b"KNDB" {
                return Err(PublicationControlError::Admission(format!(
                    "{authority} payload does not carry a KNDB snapshot"
                )));
            }
            let snapshot_schema = u32::from_le_bytes(payload[4..8].try_into().map_err(|_| {
                PublicationControlError::Admission(format!(
                    "{authority} has a malformed snapshot schema"
                ))
            })?);
            if snapshot_schema == 0 {
                return Err(PublicationControlError::Admission(format!(
                    "{authority} declares snapshot schema zero"
                )));
            }
            let body_len = u64::from_le_bytes(payload[8..16].try_into().map_err(|_| {
                PublicationControlError::Admission(format!(
                    "{authority} has a malformed snapshot body length"
                ))
            })?);
            let body_len = usize::try_from(body_len).map_err(|_| {
                PublicationControlError::Admission(format!(
                    "{authority} snapshot body length exceeds this platform"
                ))
            })?;
            let body_end = SNAPSHOT_HEADER_LEN.checked_add(body_len).ok_or_else(|| {
                PublicationControlError::Admission(format!(
                    "{authority} snapshot body length overflows"
                ))
            })?;
            let checksum_end = body_end
                .checked_add(SNAPSHOT_CHECKSUM_LEN)
                .ok_or_else(|| {
                    PublicationControlError::Admission(format!(
                        "{authority} snapshot body length overflows"
                    ))
                })?;
            let trailer_end = checksum_end
                .checked_add(ROOT_HASH_TRAILER_LEN)
                .ok_or_else(|| {
                    PublicationControlError::Admission(format!(
                        "{authority} snapshot trailer length overflows"
                    ))
                })?;
            if payload.len() != checksum_end && payload.len() != trailer_end {
                return Err(PublicationControlError::Admission(format!(
                    "{authority} snapshot length {} does not match body and checksum boundary {checksum_end}",
                    payload.len()
                )));
            }
            let body_digest: [u8; 32] = Sha256::digest(&payload[SNAPSHOT_HEADER_LEN..body_end]).into();
            if payload[body_end..checksum_end] != body_digest {
                return Err(PublicationControlError::Admission(format!(
                    "{authority} snapshot body checksum does not match"
                )));
            }
            if payload.len() == trailer_end {
                let trailer = &payload[checksum_end..];
                if &trailer[..4] != b"KRTH" {
                    return Err(PublicationControlError::Admission(format!(
                        "{authority} has an unknown snapshot trailer"
                    )));
                }
                let mut hasher = Sha256::new();
                hasher.update(b"KRTH");
                hasher.update(body_digest);
                hasher.update(&trailer[4..36]);
                let expected_trailer: [u8; 32] = hasher.finalize().into();
                if trailer[36..68] != expected_trailer {
                    return Err(PublicationControlError::Admission(format!(
                        "{authority} root-hash trailer digest does not match"
                    )));
                }
            }
            Ok(snapshot_schema)
        }

        fn capture_fence(
            &self,
            repo_id: &str,
        ) -> Result<RepositoryAuthorityCapture, PublicationControlError> {
            let path = self.snapshot_path(repo_id);
            let result = match self.block_on(self.store.get(&path)) {
                Ok(result) => result,
                Err(object_store::Error::NotFound { .. }) => {
                    return Err(PublicationControlError::Admission(format!(
                        "fleet repo {repo_id} has no graph authority object at {path}"
                    )))
                }
                Err(error) => {
                    return Err(PublicationControlError::Store(format!(
                        "read graph authority {path} for fencing: {error}"
                    )))
                }
            };
            let expected = Self::version_from_meta(&result.meta);
            if result.meta.size > self.max_authority_fence_object_bytes {
                return Err(PublicationControlError::Admission(format!(
                    "graph authority {path} is {} bytes, above the bounded in-memory fencing limit {}",
                    result.meta.size, self.max_authority_fence_object_bytes
                )));
            }
            let pre_fence_generation = Self::numeric_generation(
                expected.version.as_deref(),
                &format!("graph authority {path}"),
            )?;
            let bytes = self.block_on(result.bytes()).map_err(|error| {
                PublicationControlError::Store(format!(
                    "read graph authority {path} body for fencing: {error}"
                ))
            })?;
            #[cfg(test)]
            let _body_residency = self.track_fence_body(bytes.len());
            let snapshot_schema = Self::snapshot_schema(&bytes, path.as_ref())?;
            let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            Ok(RepositoryAuthorityCapture {
                repo_id: repo_id.to_string(),
                generation: pre_fence_generation,
                snapshot_schema,
                size_bytes: u64::try_from(bytes.len()).map_err(|_| {
                    PublicationControlError::Admission(format!(
                        "graph authority {path} length exceeds u64"
                    ))
                })?,
                sha256,
                e_tag: expected.e_tag,
            })
        }

        fn commit_fence(
            &self,
            capture: &RepositoryAuthorityCapture,
        ) -> Result<RepositoryAuthorityFence, PublicationControlError> {
            let path = self.snapshot_path(&capture.repo_id);
            let current = self.block_on(self.store.get(&path)).map_err(|error| match error {
                object_store::Error::NotFound { .. } => PublicationControlError::Conflict(
                    format!("graph authority {path} disappeared after fleet capture"),
                ),
                other => PublicationControlError::Store(format!(
                    "re-read graph authority {path} for fencing: {other}"
                )),
            })?;
            if current.meta.size > self.max_authority_fence_object_bytes {
                return Err(PublicationControlError::Admission(format!(
                    "graph authority {path} grew to {} bytes, above the bounded in-memory fencing limit {}",
                    current.meta.size, self.max_authority_fence_object_bytes
                )));
            }
            let current_version = Self::version_from_meta(&current.meta);
            let current_generation = Self::numeric_generation(
                current_version.version.as_deref(),
                &format!("graph authority {path}"),
            )?;
            let bytes = self.block_on(current.bytes()).map_err(|error| {
                PublicationControlError::Store(format!(
                    "re-read graph authority {path} body for fencing: {error}"
                ))
            })?;
            #[cfg(test)]
            let _body_residency = self.track_fence_body(bytes.len());
            let snapshot_schema = Self::snapshot_schema(&bytes, path.as_ref())?;
            let size_bytes = u64::try_from(bytes.len()).map_err(|_| {
                PublicationControlError::Admission(format!(
                    "graph authority {path} length exceeds u64"
                ))
            })?;
            let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            if size_bytes != capture.size_bytes
                || sha256 != capture.sha256
                || snapshot_schema != capture.snapshot_schema
            {
                return Err(PublicationControlError::Conflict(format!(
                    "graph authority {path} bytes changed after the complete fleet capture"
                )));
            }
            if current_generation != capture.generation
                || current_version.e_tag != capture.e_tag
            {
                return Err(PublicationControlError::Conflict(format!(
                    "graph authority {path} version changed after the complete fleet capture; reread every repository and conditionally rewrite the new exact generation"
                )));
            }
            let expected = PublicationRecordVersion {
                e_tag: capture.e_tag.clone(),
                version: Some(capture.generation.to_string()),
            };
            let result = self.block_on(self.store.put_opts(
                &path,
                PutPayload::from(bytes),
                PutOptions {
                    mode: PutMode::Update(Self::version_for_update(&expected)),
                    ..PutOptions::default()
                },
            ));
            let result = match result {
                Ok(result) => result,
                Err(error @ object_store::Error::Precondition { .. })
                | Err(error @ object_store::Error::NotModified { .. }) => {
                    return Err(PublicationControlError::Conflict(format!(
                        "graph authority {} changed after the complete fleet was captured; reread every repository before retrying: {error}",
                        path
                    )))
                }
                Err(error) => return Err(Self::map_write_error(error)),
            };
            let fenced_generation = Self::numeric_generation(
                result.version.as_deref(),
                &format!("fenced graph authority {path}"),
            )?;
            if fenced_generation <= capture.generation {
                return Err(PublicationControlError::Store(format!(
                    "graph authority {} fence did not advance generation {}; got {fenced_generation}",
                    path, capture.generation
                )));
            }
            Ok(RepositoryAuthorityFence {
                repo_id: capture.repo_id.clone(),
                pre_fence_generation: capture.generation,
                fenced_generation,
                snapshot_schema: capture.snapshot_schema,
                e_tag: result.e_tag,
            })
        }

        fn encode(
            &self,
            record: &PublicationControlRecord,
        ) -> Result<PutPayload, PublicationControlError> {
            let mut bytes = serde_json::to_vec(record).map_err(|error| {
                PublicationControlError::Store(format!("encode control record: {error}"))
            })?;
            bytes.push(b'\n');
            let encoded_len = u64::try_from(bytes.len()).map_err(|_| {
                PublicationControlError::Store(
                    "encoded publication-control record length exceeds u64".to_string(),
                )
            })?;
            if encoded_len > self.max_control_record_bytes {
                return Err(PublicationControlError::Store(format!(
                    "encoded publication-control record is {encoded_len} bytes, above the bounded publication-control record limit {}",
                    self.max_control_record_bytes
                )));
            }
            Ok(PutPayload::from(bytes))
        }

        fn map_write_error(error: object_store::Error) -> PublicationControlError {
            match error {
                object_store::Error::AlreadyExists { .. }
                | object_store::Error::Precondition { .. }
                | object_store::Error::NotModified { .. } => {
                    PublicationControlError::Conflict(error.to_string())
                }
                other => PublicationControlError::Store(other.to_string()),
            }
        }
    }

    impl PublicationControlStore for ObjectStorePublicationControlStore {
        fn load(
            &self,
        ) -> Result<Option<StoredPublicationControlRecord>, PublicationControlError> {
            let result = match self.block_on(self.store.get(&self.path)) {
                Ok(result) => result,
                Err(object_store::Error::NotFound { .. }) => return Ok(None),
                Err(error) => {
                    return Err(PublicationControlError::Store(format!(
                        "read {}: {error}",
                        self.path
                    )))
                }
            };
            let version = Self::version_from_meta(&result.meta);
            if version.e_tag.is_none() && version.version.is_none() {
                return Err(PublicationControlError::Store(format!(
                    "{} has neither ETag nor version; CAS is unavailable",
                    self.path
                )));
            }
            if result.meta.size > self.max_control_record_bytes {
                return Err(PublicationControlError::Store(format!(
                    "{} is {} bytes, above the bounded publication-control record limit {}",
                    self.path, result.meta.size, self.max_control_record_bytes
                )));
            }
            let bytes = self.block_on(result.bytes()).map_err(|error| {
                PublicationControlError::Store(format!("read {} body: {error}", self.path))
            })?;
            let record = serde_json::from_slice(&bytes).map_err(|error| {
                PublicationControlError::Store(format!("decode {}: {error}", self.path))
            })?;
            Ok(Some(StoredPublicationControlRecord { record, version }))
        }

        fn create(
            &self,
            record: &PublicationControlRecord,
        ) -> Result<PublicationRecordVersion, PublicationControlError> {
            let result = self
                .block_on(self.store.put_opts(
                    &self.path,
                    self.encode(record)?,
                    PutOptions {
                        mode: PutMode::Create,
                        ..PutOptions::default()
                    },
                ))
                .map_err(Self::map_write_error)?;
            Ok(PublicationRecordVersion {
                e_tag: result.e_tag,
                version: result.version,
            })
        }

        fn update(
            &self,
            expected: &PublicationRecordVersion,
            record: &PublicationControlRecord,
        ) -> Result<PublicationRecordVersion, PublicationControlError> {
            let result = self
                .block_on(self.store.put_opts(
                    &self.path,
                    self.encode(record)?,
                    PutOptions {
                        mode: PutMode::Update(Self::version_for_update(expected)),
                        ..PutOptions::default()
                    },
                ))
                .map_err(Self::map_write_error)?;
            Ok(PublicationRecordVersion {
                e_tag: result.e_tag,
                version: result.version,
            })
        }

        fn capture_authority(
            &self,
            repositories: &[String],
        ) -> Result<Vec<RepositoryAuthorityCapture>, PublicationControlError> {
            let mut captured = Vec::with_capacity(repositories.len());
            for repo_id in repositories {
                captured.push(self.capture_fence(repo_id)?);
            }
            Ok(captured)
        }

        fn fence_authority(
            &self,
            capture: &RepositoryAuthorityCapture,
        ) -> Result<RepositoryAuthorityFence, PublicationControlError> {
            self.commit_fence(capture)
        }

        fn verify_authority_fence(
            &self,
            capture: &RepositoryAuthorityCapture,
            fence: &RepositoryAuthorityFence,
        ) -> Result<(), PublicationControlError> {
            super::validate_authority_fence_entry(capture, fence)?;
            let path = self.snapshot_path(&capture.repo_id);
            let current = self.block_on(self.store.get(&path)).map_err(|error| {
                PublicationControlError::Store(format!(
                    "verify fenced graph authority {path}: {error}"
                ))
            })?;
            let version = Self::version_from_meta(&current.meta);
            let generation = Self::numeric_generation(
                version.version.as_deref(),
                &format!("fenced graph authority {path}"),
            )?;
            if generation != fence.fenced_generation {
                return Err(PublicationControlError::Fenced(format!(
                    "graph authority {path} checkpoint generation {} changed to {generation}",
                    fence.fenced_generation
                )));
            }
            if current.meta.size > self.max_authority_fence_object_bytes {
                return Err(PublicationControlError::Admission(format!(
                    "graph authority {path} is {} bytes, above the bounded in-memory fencing limit {}",
                    current.meta.size, self.max_authority_fence_object_bytes
                )));
            }
            let bytes = self.block_on(current.bytes()).map_err(|error| {
                PublicationControlError::Store(format!(
                    "verify fenced graph authority {path} body: {error}"
                ))
            })?;
            #[cfg(test)]
            let _body_residency = self.track_fence_body(bytes.len());
            let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            if u64::try_from(bytes.len()).ok() != Some(capture.size_bytes)
                || sha256 != capture.sha256
                || Self::snapshot_schema(&bytes, path.as_ref())? != capture.snapshot_schema
            {
                return Err(PublicationControlError::Fenced(format!(
                    "graph authority {path} checkpoint bytes no longer match its capture"
                )));
            }
            Ok(())
        }
    }

    pub use ObjectStorePublicationControlStore as Store;
}

#[cfg(feature = "gcs")]
pub use object_store_control::Store as ObjectStorePublicationControlStore;

#[cfg(test)]
mod tests {
    #[cfg(feature = "gcs")]
    use std::collections::HashMap;
    #[cfg(feature = "gcs")]
    use std::fmt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Condvar, Mutex};

    #[cfg(feature = "gcs")]
    use futures_util::stream::BoxStream;
    #[cfg(feature = "gcs")]
    use futures_util::StreamExt;
    #[cfg(feature = "gcs")]
    use object_store::memory::InMemory;
    #[cfg(feature = "gcs")]
    use object_store::path::Path as ObjectPath;
    #[cfg(feature = "gcs")]
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
        ObjectStoreExt, PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult,
        Result as ObjectStoreResult, UpdateVersion,
    };
    #[cfg(feature = "gcs")]
    use sha2::{Digest, Sha256};

    use super::*;

    const READER_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const READER_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SCOPE: &str = "gcs://fixture/v2";

    #[cfg(feature = "gcs")]
    #[derive(Debug)]
    struct VersionState {
        next_generation: u64,
        generations: HashMap<String, u64>,
    }

    /// GCS-shaped object store for the resource-fence test. The ordinary
    /// object-store memory backend has ETags but no numeric generations, so it
    /// cannot prove the invariant the production GCS path requires.
    #[cfg(feature = "gcs")]
    struct VersionedMemoryStore {
        inner: InMemory,
        state: Arc<tokio::sync::Mutex<VersionState>>,
        writer_winner: Mutex<Option<(String, Vec<u8>)>>,
    }

    #[cfg(feature = "gcs")]
    impl VersionedMemoryStore {
        fn new() -> Self {
            Self {
                inner: InMemory::new(),
                state: Arc::new(tokio::sync::Mutex::new(VersionState {
                    next_generation: 100,
                    generations: HashMap::new(),
                })),
                writer_winner: Mutex::new(None),
            }
        }

        fn inject_writer_winner(&self, path: &ObjectPath, bytes: Vec<u8>) {
            *self.writer_winner.lock().unwrap() = Some((path.to_string(), bytes));
        }

        fn precondition_error(path: &ObjectPath, message: String) -> object_store::Error {
            object_store::Error::Precondition {
                path: path.to_string(),
                source: Box::new(std::io::Error::other(message)),
            }
        }

        fn apply_generation(meta: &mut ObjectMeta, state: &VersionState) {
            meta.version = state
                .generations
                .get(meta.location.as_ref())
                .map(ToString::to_string);
        }
    }

    #[cfg(feature = "gcs")]
    impl fmt::Debug for VersionedMemoryStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("VersionedMemoryStore")
        }
    }

    #[cfg(feature = "gcs")]
    impl fmt::Display for VersionedMemoryStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("VersionedMemoryStore")
        }
    }

    #[cfg(feature = "gcs")]
    #[async_trait::async_trait]
    impl ObjectStore for VersionedMemoryStore {
        async fn put_opts(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            opts: PutOptions,
        ) -> ObjectStoreResult<PutResult> {
            let injected = if matches!(&opts.mode, PutMode::Update(_)) {
                let mut winner = self.writer_winner.lock().unwrap();
                if winner
                    .as_ref()
                    .is_some_and(|(path, _)| path == location.as_ref())
                {
                    winner.take()
                } else {
                    None
                }
            } else {
                None
            };

            let mut state = self.state.lock().await;
            if let Some((_, winner_bytes)) = injected {
                self.inner
                    .put_opts(
                        location,
                        PutPayload::from(winner_bytes),
                        PutOptions::default(),
                    )
                    .await?;
                let generation = state.next_generation;
                state.next_generation += 1;
                state
                    .generations
                    .insert(location.to_string(), generation);
            }

            if let PutMode::Update(update) = &opts.mode {
                let expected = update.version.as_deref().ok_or_else(|| {
                    Self::precondition_error(location, "numeric generation is required".to_string())
                })?;
                let current = state.generations.get(location.as_ref()).ok_or_else(|| {
                    Self::precondition_error(location, "object has no generation".to_string())
                })?;
                if expected != current.to_string() {
                    return Err(Self::precondition_error(
                        location,
                        format!("generation {current} does not match {expected}"),
                    ));
                }
            }

            let mut result = self.inner.put_opts(location, payload, opts).await?;
            let generation = state.next_generation;
            state.next_generation += 1;
            state
                .generations
                .insert(location.to_string(), generation);
            result.version = Some(generation.to_string());
            Ok(result)
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjectPath,
            opts: PutMultipartOptions,
        ) -> ObjectStoreResult<Box<dyn MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> ObjectStoreResult<GetResult> {
            let mut result = self.inner.get_opts(location, options).await?;
            let state = self.state.lock().await;
            Self::apply_generation(&mut result.meta, &state);
            Ok(result)
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, ObjectStoreResult<ObjectPath>>,
        ) -> BoxStream<'static, ObjectStoreResult<ObjectPath>> {
            self.inner.delete_stream(locations)
        }

        fn list(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, ObjectStoreResult<ObjectMeta>> {
            let state = Arc::clone(&self.state);
            self.inner
                .list(prefix)
                .then(move |result| {
                    let state = Arc::clone(&state);
                    async move {
                        let mut meta = result?;
                        let state = state.lock().await;
                        Self::apply_generation(&mut meta, &state);
                        Ok(meta)
                    }
                })
                .boxed()
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> ObjectStoreResult<ListResult> {
            let mut result = self.inner.list_with_delimiter(prefix).await?;
            let state = self.state.lock().await;
            for meta in &mut result.objects {
                Self::apply_generation(meta, &state);
            }
            Ok(result)
        }

        async fn copy_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> ObjectStoreResult<()> {
            self.inner.copy_opts(from, to, options).await?;
            let mut state = self.state.lock().await;
            let generation = state.next_generation;
            state.next_generation += 1;
            state.generations.insert(to.to_string(), generation);
            Ok(())
        }
    }

    fn fleet() -> Vec<String> {
        vec!["kin".to_string(), "kin-db".to_string()]
    }

    fn staging_fleet() -> Vec<String> {
        vec![
            "kin".to_string(),
            "kin-db".to_string(),
            "kin-vfs".to_string(),
            "kinlab".to_string(),
            "kin-editor".to_string(),
        ]
    }

    #[cfg(feature = "gcs")]
    fn wrapped_snapshot(schema: u32) -> Vec<u8> {
        let mut snapshot = kin_db::InMemoryGraph::new()
            .to_snapshot()
            .to_bytes()
            .unwrap();
        snapshot[4..8].copy_from_slice(&schema.to_le_bytes());
        let mut authority = Vec::with_capacity(48 + snapshot.len());
        authority.extend_from_slice(b"KNGCSF02");
        authority.extend_from_slice(&u64::try_from(snapshot.len()).unwrap().to_le_bytes());
        authority.extend_from_slice(&Sha256::digest(&snapshot));
        authority.extend_from_slice(&snapshot);
        authority
    }

    #[derive(Debug)]
    struct ManualClock(Mutex<DateTime<Utc>>);

    impl ManualClock {
        fn new() -> Self {
            Self(Mutex::new(
                DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ))
        }

        fn advance(&self, seconds: i64) {
            let mut now = self.0.lock().unwrap();
            *now = now
                .checked_add_signed(ChronoDuration::seconds(seconds))
                .unwrap();
        }
    }

    impl PublicationClock for ManualClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    fn reader(identity: &str, valid_for_seconds: u64) -> ReaderAdmissionInput {
        ReaderAdmissionInput {
            identity: identity.to_string(),
            min_snapshot_schema: kin_db::GraphSnapshot::CURRENT_VERSION,
            max_snapshot_schema: kin_db::GraphSnapshot::CURRENT_VERSION,
            valid_for_seconds,
        }
    }

    fn snapshot_bytes(schema: u32) -> Vec<u8> {
        let mut bytes = kin_db::GraphSnapshot::empty().to_bytes().unwrap();
        bytes[4..8].copy_from_slice(&schema.to_le_bytes());
        bytes
    }

    fn control(
        store: Arc<InMemoryPublicationControlStore>,
        clock: Arc<ManualClock>,
        identity: &str,
    ) -> Arc<PublicationControl> {
        control_for_fleet(store, clock, identity, fleet())
    }

    fn control_for_fleet(
        store: Arc<InMemoryPublicationControlStore>,
        clock: Arc<ManualClock>,
        identity: &str,
        repositories: Vec<String>,
    ) -> Arc<PublicationControl> {
        Arc::new(
            PublicationControl::with_clock(SCOPE, identity, repositories, store, clock)
                .expect("valid publication control fixture"),
        )
    }

    fn rollout_request(
        holder: &str,
        request_id: &str,
        bootstrap_reader: Option<ReaderAdmissionInput>,
    ) -> AcquireRolloutLeaseRequest {
        rollout_request_for_fleet(fleet(), holder, request_id, bootstrap_reader)
    }

    fn rollout_request_for_fleet(
        repositories: Vec<String>,
        holder: &str,
        request_id: &str,
        bootstrap_reader: Option<ReaderAdmissionInput>,
    ) -> AcquireRolloutLeaseRequest {
        AcquireRolloutLeaseRequest {
            scope: SCOPE.to_string(),
            repositories,
            previous_repositories: None,
            holder: holder.to_string(),
            request_id: request_id.to_string(),
            ttl_seconds: 30,
            bootstrap_reader,
        }
    }

    fn proof(lease: &ActivePublicationLease) -> LeaseProof {
        LeaseProof {
            scope: SCOPE.to_string(),
            token: lease.token.clone(),
            fence: lease.fence,
        }
    }

    fn release(control: &PublicationControl, lease: &ActivePublicationLease) {
        control
            .release_rollout(ReleaseRolloutLeaseRequest {
                lease: proof(lease),
            })
            .unwrap();
    }

    #[test]
    fn startup_bootstrap_fences_exact_fleet_and_releases_before_state_open() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let repositories = staging_fleet();
        let control = control_for_fleet(
            Arc::clone(&store),
            clock,
            READER_A,
            repositories.clone(),
        );

        control.bootstrap_runtime_if_absent().unwrap();

        let record = control.status().unwrap();
        assert!(record.active_lease.is_none());
        assert_eq!(
            record.repositories,
            canonical_repositories(&repositories).unwrap()
        );
        assert_eq!(record.reader.identity, READER_A);
        assert_eq!(
            record.reader.min_snapshot_schema,
            kin_db::GraphSnapshot::MIN_SUPPORTED_VERSION
        );
        assert_eq!(
            record.reader.max_snapshot_schema,
            kin_db::GraphSnapshot::CURRENT_VERSION
        );
        assert_eq!(record.last_authority_fence.len(), repositories.len());
        assert!(record.last_authority_fence.iter().all(|entry| {
            entry.pre_fence_generation == 1 && entry.fenced_generation == 2
        }));
        control
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap();

        control.bootstrap_runtime_if_absent().unwrap();
        let unchanged = control.status().unwrap();
        assert_eq!(unchanged.revision, record.revision);
        assert_eq!(unchanged.last_fence, record.last_fence);
        assert_eq!(
            unchanged.last_authority_fence,
            record.last_authority_fence
        );
    }

    #[test]
    fn startup_bootstrap_retries_a_handled_partial_fence_failure() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let repositories = staging_fleet();
        let control = control_for_fleet(
            Arc::clone(&store),
            clock,
            READER_A,
            repositories.clone(),
        );
        store.fail_fence_on(Some("kin-vfs"));

        let failed = control.bootstrap_runtime_if_absent().unwrap_err();
        assert!(failed.to_string().contains("kin-vfs"), "{failed}");
        let incomplete = control.status().unwrap();
        let lease = incomplete.active_lease.as_ref().unwrap();
        assert_eq!(lease.holder, STARTUP_BOOTSTRAP_HOLDER);
        assert_eq!(lease.request_id, STARTUP_BOOTSTRAP_REQUEST_ID);
        assert!(lease.authority_fenced_at.is_none());
        assert!(!lease.authority_capture.is_empty());
        assert!(!lease.authority_fence.is_empty());
        assert!(lease.authority_fence.len() < repositories.len());

        store.fail_fence_on(None);
        control.bootstrap_runtime_if_absent().unwrap();
        let recovered = control.status().unwrap();
        assert!(recovered.active_lease.is_none());
        assert_eq!(recovered.last_authority_fence.len(), repositories.len());
        // Exact-holder recovery verifies durable checkpoints and continues at
        // the first missing row instead of rewriting the prefix again.
        assert_eq!(store.authority_state("kin").unwrap().0, 2);
        control
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap();
    }

    #[test]
    fn abrupt_death_after_each_fleet_rewrite_resumes_the_exact_holder_immediately() {
        let repositories = staging_fleet();
        for crash_after in 1..=repositories.len() {
            let store = Arc::new(InMemoryPublicationControlStore::default());
            let clock = Arc::new(ManualClock::new());
            let control = control_for_fleet(
                Arc::clone(&store),
                Arc::clone(&clock),
                READER_A,
                repositories.clone(),
            );
            store.crash_fence_after(Some(crash_after));
            let request = AcquireRolloutLeaseRequest {
                ttl_seconds: 1,
                ..rollout_request_for_fleet(
                    repositories.clone(),
                    "startup",
                    &format!("crash-after-{crash_after}"),
                    Some(reader(READER_A, 300)),
                )
            };
            let crashed_control = Arc::clone(&control);
            let crashed_request = request.clone();
            let crashed = std::thread::spawn(move || {
                crashed_control.acquire_rollout(crashed_request)
            });
            assert!(
                crashed.join().is_err(),
                "the injected process death after row {crash_after} must unwind"
            );

            let stranded = control.status().unwrap();
            let stranded_lease = stranded.active_lease.as_ref().unwrap();
            assert!(stranded_lease.authority_fencing_token.is_some());
            assert_eq!(stranded_lease.authority_fence.len(), crash_after - 1);
            assert!(stranded.last_authority_fence.is_empty());
            for (position, repo_id) in repositories.iter().enumerate() {
                assert_eq!(
                    store.authority_state(repo_id).unwrap().0,
                    if position < crash_after { 2 } else { 1 },
                    "crash after row {crash_after} changed the wrong prefix at {repo_id}"
                );
            }

            let competing = control
                .acquire_rollout(rollout_request_for_fleet(
                    repositories.clone(),
                    "other-holder",
                    &format!("cannot-steal-live-checkpoint-{crash_after}"),
                    None,
                ))
                .unwrap_err();
            assert!(competing.to_string().contains("held by"), "{competing}");

            let recovered = control.acquire_rollout(request).unwrap();
            assert_eq!(recovered.fence, stranded_lease.fence);
            assert_eq!(recovered.token, stranded_lease.token);
            assert_eq!(recovered.authority_fence.len(), repositories.len());
            for (position, repo_id) in repositories.iter().enumerate() {
                assert_eq!(
                    store.authority_state(repo_id).unwrap().0,
                    if position < crash_after { 3 } else { 2 },
                    "an uncheckpointed row {crash_after} must force a complete recapture before refencing {repo_id}"
                );
            }
            release(&control, &recovered);
        }
    }

    #[test]
    fn startup_bootstrap_never_auto_admits_over_an_existing_reader() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let old = control(Arc::clone(&store), Arc::clone(&clock), READER_A);
        old.bootstrap_runtime_if_absent().unwrap();
        let before = old.status().unwrap();

        let candidate = control(store, clock, READER_B);
        candidate.bootstrap_runtime_if_absent().unwrap();
        let after = candidate.status().unwrap();
        assert_eq!(after, before);
        let refusal = candidate
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap_err();
        assert!(
            refusal.to_string().contains(READER_A)
                && refusal.to_string().contains(READER_B),
            "{refusal}"
        );
    }

    #[test]
    fn duplicate_rollout_retry_cannot_run_a_second_generation_fence() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(Arc::clone(&store), clock, READER_A);
        let gate = store.block_next_fence();
        let request = rollout_request(
            "deploy",
            "same-request",
            Some(reader(READER_A, 300)),
        );
        let first_control = Arc::clone(&control);
        let first_request = request.clone();
        let first = std::thread::spawn(move || first_control.acquire_rollout(first_request));

        let (gate_state, changed) = gate.as_ref();
        let mut observed = gate_state.lock().unwrap();
        while !observed.0 {
            observed = changed.wait(observed).unwrap();
        }
        drop(observed);

        let duplicate = control.acquire_rollout(request).unwrap_err();
        assert!(
            duplicate.to_string().contains("fencing attempt")
                && duplicate.to_string().contains("in progress"),
            "{duplicate}"
        );
        assert_eq!(store.authority_state("kin").unwrap().0, 1);
        assert_eq!(store.authority_state("kin-db").unwrap().0, 1);

        let mut observed = gate_state.lock().unwrap();
        observed.1 = true;
        changed.notify_all();
        drop(observed);
        let lease = first.join().unwrap().unwrap();
        release(&control, &lease);
        assert_eq!(store.authority_state("kin").unwrap().0, 2);
        assert_eq!(store.authority_state("kin-db").unwrap().0, 2);
    }

    #[test]
    fn paused_expired_fencer_cannot_advance_after_a_higher_fence() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(Arc::clone(&store), Arc::clone(&clock), READER_A);
        let gate = store.block_next_fence();
        let first_control = Arc::clone(&control);
        let first = std::thread::spawn(move || {
            first_control.acquire_rollout(AcquireRolloutLeaseRequest {
                ttl_seconds: 1,
                ..rollout_request(
                    "deploy-one",
                    "paused-fencer",
                    Some(reader(READER_A, 300)),
                )
            })
        });

        let (gate_state, changed) = gate.as_ref();
        let mut observed = gate_state.lock().unwrap();
        while !observed.0 {
            observed = changed.wait(observed).unwrap();
        }
        drop(observed);

        clock.advance(2);
        let recovery = control
            .acquire_rollout(rollout_request("deploy-two", "higher-fence", None))
            .unwrap();
        assert!(recovery.fence > 1);
        assert_eq!(store.authority_state("kin").unwrap().0, 2);
        assert_eq!(store.authority_state("kin-db").unwrap().0, 2);

        let mut observed = gate_state.lock().unwrap();
        observed.1 = true;
        changed.notify_all();
        drop(observed);
        let stale = first.join().unwrap().unwrap_err();
        assert!(
            stale.to_string().contains("does not identify active")
                || stale.to_string().contains("stale or fenced"),
            "{stale}"
        );
        assert_eq!(
            store.authority_state("kin").unwrap().0,
            2,
            "the paused fencer must not write after the higher fence"
        );
        assert_eq!(store.authority_state("kin-db").unwrap().0, 2);
        release(&control, &recovery);
    }

    #[test]
    fn missing_malformed_and_stale_reader_identity_fail_closed() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(Arc::clone(&store), Arc::clone(&clock), READER_A);

        assert!(matches!(
            control.assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION),
            Err(PublicationControlError::Missing(_))
        ));
        assert!(matches!(
            control.acquire_rollout(rollout_request("deploy", "first", None)),
            Err(PublicationControlError::Missing(_))
        ));
        let malformed = PublicationControl::with_clock(
            SCOPE,
            "latest",
            fleet(),
            store.clone(),
            clock.clone(),
        );
        assert!(matches!(malformed, Err(PublicationControlError::Invalid(_))));

        let malformed_store = Arc::new(InMemoryPublicationControlStore::default());
        let malformed_record = PublicationControlRecord {
            schema: "kin.graph-publication-control.future".to_string(),
            scope: SCOPE.to_string(),
            revision: 1,
            last_fence: 1,
            repositories: fleet(),
            reader: materialize_reader(&reader(READER_A, 300), clock.now()).unwrap(),
            last_authority_fenced_at: None,
            last_authority_fence: Vec::new(),
            active_lease: None,
            last_completed_lease: None,
            last_completed_rollout: None,
            completed_rollout_history: Vec::new(),
        };
        malformed_store.create(&malformed_record).unwrap();
        let malformed_control = control(malformed_store, Arc::clone(&clock), READER_A);
        assert!(matches!(
            malformed_control.status(),
            Err(PublicationControlError::Admission(_))
        ));

        let lease = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 10)),
            ))
            .unwrap();
        release(&control, &lease);
        control
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap();
        clock.advance(11);
        let stale = control
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap_err();
        assert!(
            stale.to_string().contains("expired"),
            "stale reader must name its expiry: {stale}"
        );
    }

    #[test]
    fn rollout_is_idempotent_and_switches_writer_identity_under_one_fence() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let old = control(Arc::clone(&store), Arc::clone(&clock), READER_A);
        let bootstrap = old
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&old, &bootstrap);

        let request = rollout_request("deploy", "rollout-b", None);
        let lease = old.acquire_rollout(request.clone()).unwrap();
        let retry = old.acquire_rollout(request).unwrap();
        assert_eq!(retry.token, lease.token);
        assert_eq!(retry.fence, lease.fence);

        let blocked_validator_version = Arc::new(Mutex::new(None));
        let writer = PublicationGatedStorageBackend::new(
            Box::new(NoopBackend {
                last_history_validator_version: Arc::clone(&blocked_validator_version),
                ..NoopBackend::default()
            }),
            Arc::clone(&old),
        );
        let current_snapshot = snapshot_bytes(kin_db::GraphSnapshot::CURRENT_VERSION);
        let blocked = writer
            .save_snapshot("kin", &current_snapshot, 0)
            .unwrap_err();
        assert!(
            blocked.to_string().contains("rollout lease"),
            "active rollout must block direct writers: {blocked}"
        );
        assert!(matches!(
            writer.save_snapshot_validated(
                "kin",
                &current_snapshot,
                SnapshotCursor::from_backend_generation(0),
                Some(1),
            ),
            SnapshotSaveOutcome::NotCommitted(_)
        ));
        assert_eq!(
            *blocked_validator_version.lock().unwrap(),
            None,
            "a refused validated save must never reach the inner backend"
        );

        old.admit_reader(AdmitReaderRequest {
            lease: proof(&lease),
            repositories: fleet(),
            reader: reader(READER_B, 300),
        })
        .unwrap();
        let released = old
            .release_rollout(ReleaseRolloutLeaseRequest {
                lease: proof(&lease),
            })
            .unwrap();
        let release_retry = old
            .release_rollout(ReleaseRolloutLeaseRequest {
                lease: proof(&lease),
            })
            .unwrap();
        assert_eq!(release_retry, released);

        let fenced_old = writer
            .save_snapshot("kin", &current_snapshot, 0)
            .unwrap_err();
        assert!(
            fenced_old.to_string().contains(READER_B),
            "old digest must self-fence after admission moves: {fenced_old}"
        );
        let new = control(store, clock, READER_B);
        let admitted_validator_version = Arc::new(Mutex::new(None));
        let admitted_writer = PublicationGatedStorageBackend::new(
            Box::new(NoopBackend {
                last_history_validator_version: Arc::clone(&admitted_validator_version),
                ..NoopBackend::default()
            }),
            new,
        );
        assert!(matches!(
            admitted_writer.save_snapshot_validated(
                "kin",
                &current_snapshot,
                SnapshotCursor::from_backend_generation(0),
                Some(7),
            ),
            SnapshotSaveOutcome::Committed { .. }
        ));
        assert_eq!(
            *admitted_validator_version.lock().unwrap(),
            Some(Some(7)),
            "the publication gate must preserve the inner backend's validation binding"
        );
    }

    #[test]
    fn graph_storage_guard_releases_after_inner_backend_unwind() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, clock, READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap-storage-unwind",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&control, &bootstrap);

        let writer = PublicationGatedStorageBackend::new(
            Box::new(NoopBackend::default()),
            Arc::clone(&control),
        );
        let ordinary = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer.with_publication(
                "kin",
                kin_db::GraphSnapshot::CURRENT_VERSION,
                |_| -> Result<(), KinDbError> {
                    panic!("injected inner save unwind");
                },
            )
        }));
        assert!(ordinary.is_err());
        assert!(
            control.status().unwrap().active_lease.is_none(),
            "ordinary save unwind must release its publication lease"
        );

        let classified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer.with_classified_publication(
                "kin",
                kin_db::GraphSnapshot::CURRENT_VERSION,
                |_| -> SnapshotSaveOutcome {
                    panic!("injected classified save unwind");
                },
            )
        }));
        assert!(classified.is_err());
        assert!(
            control.status().unwrap().active_lease.is_none(),
            "classified save unwind must release its publication lease"
        );
    }

    #[test]
    fn rollout_release_retry_survives_later_publication_leases() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, clock, READER_A);
        let rollout = control
            .acquire_rollout(rollout_request(
                "deploy",
                "release-response-lost",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        let rollout_proof = proof(&rollout);
        release(&control, &rollout);

        let writer = PublicationGatedStorageBackend::new(
            Box::new(NoopBackend::default()),
            Arc::clone(&control),
        );
        writer
            .save_snapshot(
                "kin",
                &snapshot_bytes(kin_db::GraphSnapshot::CURRENT_VERSION),
                0,
            )
            .unwrap();

        let retry = control
            .release_rollout(ReleaseRolloutLeaseRequest {
                lease: rollout_proof,
            })
            .unwrap();
        assert!(retry.active_lease.is_none());
        assert_eq!(
            retry.last_completed_rollout.as_ref().unwrap().fence,
            rollout.fence
        );
        assert_eq!(
            retry.last_completed_lease.as_ref().unwrap().kind,
            LeaseKind::Publication
        );
    }

    #[test]
    fn rollout_release_retry_survives_a_later_completed_rollout() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, clock, READER_A);
        let first = control
            .acquire_rollout(rollout_request(
                "deploy",
                "first-release-response-lost",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        let first_proof = proof(&first);
        release(&control, &first);

        let second = control
            .acquire_rollout(rollout_request("deploy", "second-rollout", None))
            .unwrap();
        release(&control, &second);

        let retry = control
            .release_rollout(ReleaseRolloutLeaseRequest { lease: first_proof })
            .unwrap();
        assert_eq!(retry.last_completed_rollout.as_ref().unwrap().fence, second.fence);
        assert!(retry
            .completed_rollout_history
            .iter()
            .any(|completed| completed.fence == first.fence));
        assert!(retry
            .completed_rollout_history
            .iter()
            .any(|completed| completed.fence == second.fence));
    }

    #[test]
    fn an_expired_crash_lease_is_reclaimed_with_a_higher_fence() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, Arc::clone(&clock), READER_A);
        let first = control
            .acquire_rollout(AcquireRolloutLeaseRequest {
                ttl_seconds: 1,
                ..rollout_request(
                    "deploy-one",
                    "crashed",
                    Some(reader(READER_A, 300)),
                )
            })
            .unwrap();
        clock.advance(2);
        let second = control
            .acquire_rollout(AcquireRolloutLeaseRequest {
                ttl_seconds: 10,
                ..rollout_request("deploy-two", "recovery", None)
            })
            .unwrap();
        assert!(second.fence > first.fence);
        assert!(matches!(
            control.release_rollout(ReleaseRolloutLeaseRequest {
                lease: proof(&first)
            }),
            Err(PublicationControlError::Fenced(_))
        ));
        assert!(matches!(
            control.renew_rollout(RenewRolloutLeaseRequest {
                lease: proof(&first),
                ttl_seconds: 10,
            }),
            Err(PublicationControlError::Fenced(_))
        ));
        release(&control, &second);
    }

    #[test]
    fn scope_and_schema_are_exact_not_advisory() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, clock, READER_A);
        let wrong_scope = control.acquire_rollout(AcquireRolloutLeaseRequest {
            scope: "gcs://fixture/prod".to_string(),
            ..rollout_request("deploy", "wrong-scope", Some(reader(READER_A, 300)))
        });
        assert!(matches!(
            wrong_scope,
            Err(PublicationControlError::Invalid(_))
        ));

        let lease = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&control, &lease);
        let future = kin_db::GraphSnapshot::CURRENT_VERSION + 1;
        assert!(matches!(
            control.assert_runtime_admitted(future),
            Err(PublicationControlError::Admission(_))
        ));
    }

    #[test]
    fn snapshot_writer_authorizes_the_encoded_schema_and_never_calls_inner_on_refusal() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, clock, READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&control, &bootstrap);

        let calls = Arc::new(AtomicU64::new(0));
        let writer = PublicationGatedStorageBackend::new(
            Box::new(NoopBackend {
                generation: Arc::clone(&calls),
                ..NoopBackend::default()
            }),
            control,
        );
        let future = snapshot_bytes(kin_db::GraphSnapshot::CURRENT_VERSION + 1);
        let direct = writer.save_snapshot("kin", &future, 0).unwrap_err();
        assert!(direct.to_string().contains("writer schema"), "{direct}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let classified = writer.save_snapshot_classified(
            "kin",
            &future,
            SnapshotCursor::from_backend_generation(0),
        );
        assert!(matches!(classified, SnapshotSaveOutcome::NotCommitted(_)));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "classified refusal must not call the inner backend"
        );

        let malformed = writer.save_snapshot("kin", b"not-a-snapshot", 0).unwrap_err();
        assert!(malformed.to_string().contains("KNDB"), "{malformed}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn hosted_delta_mutations_fail_loud_outside_the_graph_generation_fence() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, clock, READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&control, &bootstrap);
        let writer = PublicationGatedStorageBackend::new(
            Box::new(NoopBackend::default()),
            control,
        );

        let delta = writer.save_delta("kin", b"delta", 1).unwrap_err();
        assert!(delta.to_string().contains("full graph.kndb"), "{delta}");
        let cleanup = writer.clear_deltas("kin").unwrap_err();
        assert!(
            cleanup.to_string().contains("full graph.kndb"),
            "{cleanup}"
        );
    }

    #[test]
    fn duplicate_or_wrong_fleet_membership_is_rejected_before_bootstrap() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        assert!(matches!(
            PublicationControl::with_clock(
                SCOPE,
                READER_A,
                vec!["kin".to_string(), "kin".to_string()],
                store.clone(),
                clock.clone(),
            ),
            Err(PublicationControlError::Invalid(_))
        ));
        let oversized_fleet: Vec<String> = (0..=MAX_FLEET_REPOSITORIES)
            .map(|index| format!("repo-{index:03}"))
            .collect();
        let oversized = PublicationControl::with_clock(
            SCOPE,
            READER_A,
            oversized_fleet,
            store.clone(),
            clock.clone(),
        )
        .unwrap_err();
        assert!(
            oversized.to_string().contains("bounded fleet limit"),
            "{oversized}"
        );

        let control = control(store, clock, READER_A);
        let mut duplicate = rollout_request(
            "deploy",
            "duplicate",
            Some(reader(READER_A, 300)),
        );
        duplicate.repositories.push("kin".to_string());
        assert!(matches!(
            control.acquire_rollout(duplicate),
            Err(PublicationControlError::Invalid(_))
        ));
        let mut wrong = rollout_request("deploy", "wrong", Some(reader(READER_A, 300)));
        wrong.repositories = vec!["kin".to_string()];
        assert!(matches!(
            control.acquire_rollout(wrong),
            Err(PublicationControlError::Invalid(_))
        ));
    }

    #[test]
    fn changed_fleet_does_not_hijack_an_incomplete_startup_bootstrap() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let old_repositories = canonical_repositories(&staging_fleet()).unwrap();
        let old = control_for_fleet(
            Arc::clone(&store),
            Arc::clone(&clock),
            READER_A,
            old_repositories,
        );
        old.acquire_rollout(AcquireRolloutLeaseRequest {
            scope: SCOPE.to_string(),
            repositories: staging_fleet(),
            previous_repositories: None,
            holder: STARTUP_BOOTSTRAP_HOLDER.to_string(),
            request_id: STARTUP_BOOTSTRAP_REQUEST_ID.to_string(),
            ttl_seconds: DEFAULT_ROLLOUT_LEASE_SECONDS,
            bootstrap_reader: Some(reader(READER_A, 300)),
        })
        .unwrap();

        let target_repositories = canonical_repositories(&[
            "kin".to_string(),
            "kin-db".to_string(),
            "kin-search".to_string(),
            "kin-vfs".to_string(),
            "kinlab".to_string(),
        ])
        .unwrap();
        let candidate = control_for_fleet(
            Arc::clone(&store),
            clock,
            READER_A,
            target_repositories,
        );
        let before = candidate.status().unwrap();

        candidate.bootstrap_runtime_if_absent().unwrap();

        assert_eq!(candidate.status().unwrap(), before);
        assert!(store.authority_state("kin-search").is_none());
        let mismatch = candidate
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap_err();
        assert!(mismatch.to_string().contains("configured fleet"), "{mismatch}");
    }

    #[test]
    fn explicit_five_repo_transition_fences_the_union_and_self_fences_old_daemons() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let old_repositories = canonical_repositories(&staging_fleet()).unwrap();
        let old = control_for_fleet(
            Arc::clone(&store),
            Arc::clone(&clock),
            READER_A,
            old_repositories.clone(),
        );
        old.bootstrap_runtime_if_absent().unwrap();
        let paused_removed_repo_generation = store.authority_state("kin-editor").unwrap().0;

        let target_repositories = canonical_repositories(&[
            "kin".to_string(),
            "kin-db".to_string(),
            "kin-search".to_string(),
            "kin-vfs".to_string(),
            "kinlab".to_string(),
        ])
        .unwrap();
        let candidate = control_for_fleet(
            Arc::clone(&store),
            Arc::clone(&clock),
            READER_B,
            target_repositories.clone(),
        );

        // A changed daemon configuration is only a recovery/control surface.
        // Startup neither rewrites membership nor silently admits itself.
        let before = candidate.status().unwrap();
        candidate.bootstrap_runtime_if_absent().unwrap();
        assert_eq!(candidate.status().unwrap(), before);
        let mismatch = candidate
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap_err();
        assert!(mismatch.to_string().contains("configured fleet"), "{mismatch}");

        let base_request = rollout_request_for_fleet(
            target_repositories.clone(),
            "deploy",
            "five-repo-transition",
            None,
        );
        let missing_previous = candidate
            .acquire_rollout(base_request.clone())
            .unwrap_err();
        assert!(
            missing_previous.to_string().contains("previous_repositories"),
            "{missing_previous}"
        );
        let mut duplicate_previous = base_request.clone();
        duplicate_previous.previous_repositories = Some(vec![
            "kin".to_string(),
            "kin".to_string(),
        ]);
        assert!(matches!(
            candidate.acquire_rollout(duplicate_previous),
            Err(PublicationControlError::Invalid(_))
        ));
        let mut incomplete_previous = base_request.clone();
        incomplete_previous.previous_repositories = Some(
            old_repositories
                .iter()
                .filter(|repo_id| repo_id.as_str() != "kin-editor")
                .cloned()
                .collect(),
        );
        assert!(matches!(
            candidate.acquire_rollout(incomplete_previous),
            Err(PublicationControlError::Invalid(_))
        ));
        assert_eq!(candidate.status().unwrap(), before);
        assert_eq!(
            store.authority_state("kin-editor").unwrap().0,
            paused_removed_repo_generation,
            "rejected transition intents must not mutate graph authority"
        );

        let mut transition = base_request;
        transition.previous_repositories = Some(old_repositories.clone());
        let lease = candidate.acquire_rollout(transition.clone()).unwrap();
        let acquire_response_lost = candidate.acquire_rollout(transition).unwrap();
        assert_eq!(acquire_response_lost.token, lease.token);
        assert_eq!(acquire_response_lost.fence, lease.fence);
        let expected_union = repository_union(&old_repositories, &target_repositories);
        assert_eq!(lease.target_repositories, target_repositories);
        assert_eq!(lease.fence_repositories, expected_union);
        assert_eq!(lease.authority_fence.len(), 6);

        let installed = candidate.status().unwrap();
        assert_eq!(installed.repositories, lease.target_repositories);
        assert_eq!(installed.last_authority_fence.len(), 5);
        assert!(installed
            .last_authority_fence
            .iter()
            .all(|entry| entry.repo_id != "kin-editor"));
        assert!(lease
            .authority_fence
            .iter()
            .any(|entry| entry.repo_id == "kin-editor"));
        let paused_removed_writer = store
            .advance_authority(
                "kin-editor",
                paused_removed_repo_generation,
                kin_db::GraphSnapshot::CURRENT_VERSION,
            )
            .unwrap_err();
        assert!(
            paused_removed_writer.to_string().contains("expected generation"),
            "{paused_removed_writer}"
        );

        candidate
            .admit_reader(AdmitReaderRequest {
                lease: proof(&lease),
                repositories: lease.target_repositories.clone(),
                reader: reader(READER_B, 300),
            })
            .unwrap();
        release(&candidate, &lease);
        let old_refusal = old
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap_err();
        assert!(
            old_refusal.to_string().contains("configured fleet"),
            "{old_refusal}"
        );
        candidate
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap();
    }

    #[test]
    fn oversized_transition_union_is_refused_before_ordered_record_mutation() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let current: Vec<String> = (0..40).map(|index| format!("old-{index:03}")).collect();
        let target: Vec<String> = (0..40).map(|index| format!("new-{index:03}")).collect();
        let old = control_for_fleet(
            Arc::clone(&store),
            Arc::clone(&clock),
            READER_A,
            current.clone(),
        );
        old.bootstrap_runtime_if_absent().unwrap();
        let before = old.status().unwrap();

        let candidate = control_for_fleet(
            Arc::clone(&store),
            clock,
            READER_A,
            target.clone(),
        );
        let refused = candidate
            .acquire_rollout(AcquireRolloutLeaseRequest {
                scope: SCOPE.to_string(),
                repositories: target,
                previous_repositories: Some(current),
                holder: "deploy".to_string(),
                request_id: "oversized-union".to_string(),
                ttl_seconds: DEFAULT_ROLLOUT_LEASE_SECONDS,
                bootstrap_reader: None,
            })
            .unwrap_err();
        assert!(refused.to_string().contains("fence union"), "{refused}");
        assert_eq!(
            candidate.status().unwrap(),
            before,
            "an unrepresentable transition must not install an unrecoverable active record"
        );
    }

    #[test]
    fn missing_repo_leaves_rollout_unadmitted_until_exact_fleet_fences() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let repositories = staging_fleet();
        let control = control_for_fleet(
            Arc::clone(&store),
            clock,
            READER_A,
            repositories.clone(),
        );
        store.mark_authority_missing(Some("kin-editor"));
        let request = rollout_request_for_fleet(
            repositories.clone(),
            "deploy",
            "missing-repo",
            Some(reader(READER_A, 300)),
        );
        let error = control.acquire_rollout(request.clone()).unwrap_err();
        assert!(
            error.to_string().contains("kin-editor")
                && error.to_string().contains("no graph authority")
        );
        let incomplete = control.status().unwrap();
        let incomplete = incomplete.active_lease.unwrap();
        assert!(incomplete.authority_fenced_at.is_none());
        assert!(matches!(
            control.release_rollout(ReleaseRolloutLeaseRequest {
                lease: proof(&incomplete)
            }),
            Err(PublicationControlError::Fenced(_))
        ));

        store.mark_authority_missing(None);
        let lease = control.acquire_rollout(request).unwrap();
        let expected = canonical_repositories(&repositories).unwrap();
        let actual: Vec<String> = lease
            .authority_fence
            .iter()
            .map(|entry| entry.repo_id.clone())
            .collect();
        assert_eq!(actual, expected);
        release(&control, &lease);
    }

    #[test]
    fn incompatible_bootstrap_reader_stays_blocked_after_lease_timeout() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let future_schema = kin_db::GraphSnapshot::CURRENT_VERSION + 1;
        store.seed_authority("kin-db", 7, future_schema);
        let control = control(Arc::clone(&store), Arc::clone(&clock), READER_A);
        let lease = control
            .acquire_rollout(AcquireRolloutLeaseRequest {
                ttl_seconds: 1,
                ..rollout_request(
                    "deploy",
                    "incompatible-bootstrap",
                    Some(reader(READER_A, 300)),
                )
            })
            .unwrap();

        assert!(matches!(
            control.assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION),
            Err(PublicationControlError::Admission(_))
        ));
        assert!(matches!(
            control.release_rollout(ReleaseRolloutLeaseRequest {
                lease: proof(&lease)
            }),
            Err(PublicationControlError::Admission(_))
        ));

        clock.advance(2);
        assert!(matches!(
            control.assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION),
            Err(PublicationControlError::Admission(_))
        ));
        let recovery = control
            .acquire_rollout(rollout_request("deploy", "compatible-recovery", None))
            .unwrap();
        control
            .admit_reader(AdmitReaderRequest {
                lease: proof(&recovery),
                repositories: fleet(),
                reader: ReaderAdmissionInput {
                    identity: READER_B.to_string(),
                    min_snapshot_schema: kin_db::GraphSnapshot::CURRENT_VERSION,
                    max_snapshot_schema: future_schema,
                    valid_for_seconds: 300,
                },
            })
            .unwrap();
        release(&control, &recovery);
        let replacement = control_for_fleet(store, clock, READER_B, fleet());
        replacement
            .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap();
    }

    #[test]
    fn partial_fleet_fence_cannot_admit_or_release_and_retry_refences_every_repo() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let repositories = staging_fleet();
        let control = control_for_fleet(
            Arc::clone(&store),
            clock,
            READER_A,
            repositories.clone(),
        );
        store.fail_fence_on(Some("kin-vfs"));
        let request = rollout_request_for_fleet(
            repositories.clone(),
            "deploy",
            "partial",
            Some(reader(READER_A, 300)),
        );
        assert!(matches!(
            control.acquire_rollout(request.clone()),
            Err(PublicationControlError::Store(_))
        ));
        assert_eq!(store.authority_state("kin").unwrap().0, 2);
        assert_eq!(store.authority_state("kin-db").unwrap().0, 2);
        assert_eq!(store.authority_state("kin-editor").unwrap().0, 2);
        assert_eq!(store.authority_state("kin-vfs").unwrap().0, 1);
        assert_eq!(store.authority_state("kinlab").unwrap().0, 1);

        let active = control.status().unwrap().active_lease.unwrap();
        assert!(matches!(
            control.admit_reader(AdmitReaderRequest {
                lease: proof(&active),
                repositories: repositories.clone(),
                reader: reader(READER_B, 300),
            }),
            Err(PublicationControlError::Fenced(_))
        ));
        assert!(matches!(
            control.release_rollout(ReleaseRolloutLeaseRequest {
                lease: proof(&active)
            }),
            Err(PublicationControlError::Fenced(_))
        ));

        store.fail_fence_on(None);
        let completed = control.acquire_rollout(request).unwrap();
        assert_eq!(completed.authority_fence.len(), repositories.len());
        assert_eq!(
            store.authority_state("kin").unwrap().0,
            2,
            "durably checkpointed prefix rows must be verified, not rewritten"
        );
        release(&control, &completed);
    }

    #[test]
    fn a_writer_winning_before_fence_is_reread_into_compatibility_evidence() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(Arc::clone(&store), clock, READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&control, &bootstrap);

        let expected = store.authority_state("kin").unwrap().0;
        let future_schema = kin_db::GraphSnapshot::CURRENT_VERSION + 1;
        let winner_generation = store
            .advance_authority("kin", expected, future_schema)
            .unwrap();
        let rollout = control
            .acquire_rollout(rollout_request("deploy", "candidate", None))
            .unwrap();
        let kin_fence = rollout
            .authority_fence
            .iter()
            .find(|entry| entry.repo_id == "kin")
            .unwrap();
        assert_eq!(kin_fence.pre_fence_generation, winner_generation);
        assert_eq!(kin_fence.snapshot_schema, future_schema);
        assert!(matches!(
            control.admit_reader(AdmitReaderRequest {
                lease: proof(&rollout),
                repositories: fleet(),
                reader: reader(READER_B, 300),
            }),
            Err(PublicationControlError::Admission(_))
        ));
        control
            .admit_reader(AdmitReaderRequest {
                lease: proof(&rollout),
                repositories: fleet(),
                reader: ReaderAdmissionInput {
                    identity: READER_B.to_string(),
                    min_snapshot_schema: kin_db::GraphSnapshot::CURRENT_VERSION,
                    max_snapshot_schema: future_schema,
                    valid_for_seconds: 300,
                },
            })
            .unwrap();
        release(&control, &rollout);
    }

    #[test]
    fn a_paused_writer_loses_its_pre_fence_generation_after_expiry() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(Arc::clone(&store), Arc::clone(&clock), READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 10_000)),
            ))
            .unwrap();
        release(&control, &bootstrap);

        let expected_generation = store.authority_state("kin").unwrap().0;
        let stale_publication = control
            .acquire_publication("kin", kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap();
        clock.advance(PUBLICATION_LEASE_SECONDS as i64 + 1);
        let rollout = control
            .acquire_rollout(rollout_request("deploy", "after-timeout", None))
            .unwrap();
        let fence = rollout
            .authority_fence
            .iter()
            .find(|entry| entry.repo_id == "kin")
            .unwrap();
        assert_eq!(fence.pre_fence_generation, expected_generation);
        assert!(fence.fenced_generation > expected_generation);
        assert!(matches!(
            store.advance_authority(
                "kin",
                expected_generation,
                kin_db::GraphSnapshot::CURRENT_VERSION,
            ),
            Err(KinDbError::ConcurrentAccessError(_))
        ));
        assert!(matches!(
            control.release_publication(&stale_publication),
            Err(PublicationControlError::Fenced(_))
        ));
        release(&control, &rollout);
    }

    #[test]
    fn long_publication_renews_the_exact_proof_before_its_next_mutation() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(Arc::clone(&store), Arc::clone(&clock), READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 10_000)),
            ))
            .unwrap();
        release(&control, &bootstrap);

        let lease = control
            .acquire_publication("kin", kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap();
        let first_expiry = lease.expires_at;
        clock.advance((PUBLICATION_LEASE_SECONDS / 2) as i64);
        let renewed = control.renew_publication(&lease).unwrap();
        assert_eq!(renewed.token, lease.token);
        assert_eq!(renewed.fence, lease.fence);
        assert!(renewed.expires_at > first_expiry);
        control.assert_publication_lease(&renewed).unwrap();
        control.release_publication(&renewed).unwrap();
    }

    #[test]
    fn expired_publication_is_refused_before_the_external_mutation_seam() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(Arc::clone(&store), Arc::clone(&clock), READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 10_000)),
            ))
            .unwrap();
        release(&control, &bootstrap);

        let lease = control
            .acquire_publication("kin", kin_db::GraphSnapshot::CURRENT_VERSION)
            .unwrap();
        clock.advance(PUBLICATION_LEASE_SECONDS as i64 + 1);
        let mut external_mutations = 0;
        if let Ok(renewed) = control.renew_publication(&lease) {
            control.assert_publication_lease(&renewed).unwrap();
            external_mutations += 1;
        }
        assert_eq!(
            external_mutations, 0,
            "an expired proof must fail before a Firestore mutation can start"
        );
    }

    #[derive(Default)]
    struct NoopBackend {
        generation: Arc<AtomicU64>,
        last_history_validator_version: Arc<Mutex<Option<Option<u32>>>>,
    }

    impl StorageBackend for NoopBackend {
        fn load_snapshot(
            &self,
            _repo_id: &str,
        ) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
            Ok(None)
        }

        fn save_snapshot(
            &self,
            _repo_id: &str,
            _data: &[u8],
            expected_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            let current = self.generation.load(Ordering::SeqCst);
            if current != expected_gen {
                return Err(KinDbError::ConcurrentAccessError(format!(
                    "expected {expected_gen}, found {current}"
                )));
            }
            let next = current + 1;
            self.generation.store(next, Ordering::SeqCst);
            Ok(next)
        }

        fn save_snapshot_validated(
            &self,
            repo_id: &str,
            data: &[u8],
            expected_cursor: SnapshotCursor,
            history_validator_version: Option<u32>,
        ) -> SnapshotSaveOutcome {
            *self.last_history_validator_version.lock().unwrap() =
                Some(history_validator_version);
            match self.save_snapshot(
                repo_id,
                data,
                expected_cursor.backend_generation(),
            ) {
                Ok(generation) => SnapshotSaveOutcome::Committed {
                    cursor: SnapshotCursor::from_backend_generation(generation),
                },
                Err(error) => SnapshotSaveOutcome::NotCommitted(error),
            }
        }

        fn save_delta(
            &self,
            _repo_id: &str,
            _delta_data: &[u8],
            _base_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            Err(KinDbError::StorageError("deltas disabled".to_string()))
        }

        fn load_deltas_since(
            &self,
            _repo_id: &str,
            _since_gen: Generation,
        ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
            Ok(Vec::new())
        }

        fn clear_deltas(&self, _repo_id: &str) -> Result<(), KinDbError> {
            Ok(())
        }

        fn save_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
            _data: &[u8],
        ) -> Result<(), KinDbError> {
            Ok(())
        }

        fn load_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            Ok(None)
        }

        fn delete_overlay(&self, _repo_id: &str, _session_id: &str) -> Result<(), KinDbError> {
            Ok(())
        }

        fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
            Ok(vec!["kin".to_string()])
        }
    }

    struct BlockingBackend {
        entered: Arc<(Mutex<bool>, Condvar)>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl StorageBackend for BlockingBackend {
        fn load_snapshot(
            &self,
            _repo_id: &str,
        ) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
            Ok(None)
        }

        fn save_snapshot(
            &self,
            _repo_id: &str,
            _data: &[u8],
            expected_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            let (entered, ready) = self.entered.as_ref();
            *entered.lock().unwrap() = true;
            ready.notify_all();
            let (release, go) = self.release.as_ref();
            let mut released = release.lock().unwrap();
            while !*released {
                released = go.wait(released).unwrap();
            }
            Ok(expected_gen + 1)
        }

        fn save_delta(
            &self,
            _repo_id: &str,
            _delta_data: &[u8],
            _base_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            Err(KinDbError::StorageError("deltas disabled".to_string()))
        }

        fn load_deltas_since(
            &self,
            _repo_id: &str,
            _since_gen: Generation,
        ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
            Ok(Vec::new())
        }

        fn clear_deltas(&self, _repo_id: &str) -> Result<(), KinDbError> {
            Ok(())
        }

        fn save_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
            _data: &[u8],
        ) -> Result<(), KinDbError> {
            Ok(())
        }

        fn load_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            Ok(None)
        }

        fn delete_overlay(&self, _repo_id: &str, _session_id: &str) -> Result<(), KinDbError> {
            Ok(())
        }

        fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
            Ok(vec!["kin".to_string()])
        }
    }

    #[test]
    fn two_server_writers_cannot_cross_the_same_fleet_lease() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, clock, READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&control, &bootstrap);

        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let release_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let first = PublicationGatedStorageBackend::new(
            Box::new(BlockingBackend {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release_gate),
            }),
            Arc::clone(&control),
        );
        let first_thread = std::thread::spawn(move || {
            first.save_snapshot(
                "kin",
                &snapshot_bytes(kin_db::GraphSnapshot::CURRENT_VERSION),
                0,
            )
        });

        let (entered_lock, entered_signal) = entered.as_ref();
        let mut has_entered = entered_lock.lock().unwrap();
        while !*has_entered {
            has_entered = entered_signal.wait(has_entered).unwrap();
        }
        drop(has_entered);

        let second = PublicationGatedStorageBackend::new(
            Box::new(NoopBackend::default()),
            Arc::clone(&control),
        );
        let collision = second
            .save_snapshot(
                "kin-db",
                &snapshot_bytes(kin_db::GraphSnapshot::CURRENT_VERSION),
                0,
            )
            .unwrap_err();
        assert!(
            collision.to_string().contains("publication lease"),
            "second repo writer must collide at fleet scope: {collision}"
        );

        let (release_lock, release_signal) = release_gate.as_ref();
        *release_lock.lock().unwrap() = true;
        release_signal.notify_all();
        assert_eq!(first_thread.join().unwrap().unwrap(), 1);
        assert!(control.status().unwrap().active_lease.is_none());
    }

    #[test]
    fn long_graph_save_reasserts_after_inner_operation_and_reports_lost_proof() {
        let store = Arc::new(InMemoryPublicationControlStore::default());
        let clock = Arc::new(ManualClock::new());
        let control = control(store, Arc::clone(&clock), READER_A);
        let bootstrap = control
            .acquire_rollout(rollout_request(
                "deploy",
                "bootstrap-long-save",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&control, &bootstrap);

        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let release_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let writer = PublicationGatedStorageBackend::new(
            Box::new(BlockingBackend {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release_gate),
            }),
            Arc::clone(&control),
        );
        let writer_thread = std::thread::spawn(move || {
            writer.save_snapshot(
                "kin",
                &snapshot_bytes(kin_db::GraphSnapshot::CURRENT_VERSION),
                0,
            )
        });

        let (entered_lock, entered_signal) = entered.as_ref();
        let mut has_entered = entered_lock.lock().unwrap();
        while !*has_entered {
            has_entered = entered_signal.wait(has_entered).unwrap();
        }
        drop(has_entered);

        clock.advance(i64::try_from(PUBLICATION_LEASE_SECONDS).unwrap() + 1);
        let rollout = control
            .acquire_rollout(rollout_request("deploy", "fence-long-save", None))
            .unwrap();
        let (release_lock, release_signal) = release_gate.as_ref();
        *release_lock.lock().unwrap() = true;
        release_signal.notify_all();

        let lost = writer_thread.join().unwrap().unwrap_err();
        assert!(
            matches!(lost, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "a save returning after its proof was fenced must be indeterminate: {lost}"
        );
        release(&control, &rollout);
    }

    #[cfg(feature = "gcs")]
    #[tokio::test(flavor = "multi_thread")]
    async fn object_generation_fence_rereads_winner_and_rejects_paused_writer() {
        let raw = Arc::new(VersionedMemoryStore::new());
        let object_store: Arc<dyn ObjectStore> = raw.clone();
        let kin_path = ObjectPath::from("fixture/kin/graph.kndb");
        let repositories = staging_fleet();
        let current_authority = wrapped_snapshot(kin_db::GraphSnapshot::CURRENT_VERSION);
        let original = raw
            .put_opts(
                &kin_path,
                PutPayload::from(current_authority.clone()),
                PutOptions {
                    mode: PutMode::Create,
                    ..PutOptions::default()
                },
            )
            .await
            .unwrap();
        for repo_id in repositories.iter().filter(|repo_id| repo_id.as_str() != "kin") {
            raw.put_opts(
                &ObjectPath::from(format!("fixture/{repo_id}/graph.kndb")),
                PutPayload::from(current_authority.clone()),
                PutOptions {
                    mode: PutMode::Create,
                    ..PutOptions::default()
                },
            )
            .await
            .unwrap();
        }
        let original_generation = original
            .version
            .as_deref()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let future_schema = kin_db::GraphSnapshot::CURRENT_VERSION + 1;
        raw.inject_writer_winner(&kin_path, wrapped_snapshot(future_schema));

        let control_store: Arc<dyn PublicationControlStore> = Arc::new(
            ObjectStorePublicationControlStore::new(object_store, "fixture"),
        );
        let control = PublicationControl::new(
            SCOPE,
            READER_A,
            repositories.clone(),
            control_store,
        )
        .unwrap();
        let request = rollout_request_for_fleet(
            repositories.clone(),
            "deploy",
            "object-generation-race",
            Some(reader(READER_A, 300)),
        );
        let rollout = control.acquire_rollout(request).unwrap();
        let kin_fence = rollout
            .authority_fence
            .iter()
            .find(|entry| entry.repo_id == "kin")
            .unwrap();
        assert!(kin_fence.pre_fence_generation > original_generation);
        assert!(kin_fence.fenced_generation > kin_fence.pre_fence_generation);
        assert_eq!(kin_fence.snapshot_schema, future_schema);
        let installed = raw.get(&kin_path).await.unwrap().bytes().await.unwrap();
        assert_eq!(installed.as_ref(), wrapped_snapshot(future_schema));

        let stale = raw
            .put_opts(
                &kin_path,
                PutPayload::from(current_authority),
                PutOptions {
                    mode: PutMode::Update(UpdateVersion {
                        e_tag: original.e_tag,
                        version: Some(original_generation.to_string()),
                    }),
                    ..PutOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(stale, object_store::Error::Precondition { .. }));
        assert!(matches!(
            control.admit_reader(AdmitReaderRequest {
                lease: proof(&rollout),
                repositories: repositories.clone(),
                reader: reader(READER_B, 300),
            }),
            Err(PublicationControlError::Admission(_))
        ));
        control
            .admit_reader(AdmitReaderRequest {
                lease: proof(&rollout),
                repositories,
                reader: ReaderAdmissionInput {
                    identity: READER_B.to_string(),
                    min_snapshot_schema: kin_db::GraphSnapshot::CURRENT_VERSION,
                    max_snapshot_schema: future_schema,
                    valid_for_seconds: 300,
                },
            })
            .unwrap();
        release(&control, &rollout);
    }

    #[cfg(feature = "gcs")]
    #[tokio::test(flavor = "multi_thread")]
    async fn object_generation_fence_missing_fifth_repo_writes_nothing_and_claims_nothing() {
        let raw = Arc::new(VersionedMemoryStore::new());
        let object_store: Arc<dyn ObjectStore> = raw.clone();
        let repositories = staging_fleet();
        let authority = wrapped_snapshot(kin_db::GraphSnapshot::CURRENT_VERSION);
        let mut before = BTreeMap::new();
        for repo_id in repositories.iter().take(repositories.len() - 1) {
            let path = ObjectPath::from(format!("fixture/{repo_id}/graph.kndb"));
            raw.put_opts(
                &path,
                PutPayload::from(authority.clone()),
                PutOptions {
                    mode: PutMode::Create,
                    ..PutOptions::default()
                },
            )
            .await
            .unwrap();
            before.insert(repo_id.clone(), raw.get(&path).await.unwrap().meta.version);
        }

        let control_store: Arc<dyn PublicationControlStore> = Arc::new(
            ObjectStorePublicationControlStore::new(object_store, "fixture"),
        );
        let control = PublicationControl::new(
            SCOPE,
            READER_A,
            repositories.clone(),
            control_store,
        )
        .unwrap();
        let request = rollout_request_for_fleet(
            repositories.clone(),
            "deploy",
            "missing-fifth",
            Some(reader(READER_A, 300)),
        );
        let missing = control.acquire_rollout(request.clone()).unwrap_err();
        assert!(missing.to_string().contains("kin-editor"), "{missing}");
        let incomplete = control.status().unwrap();
        let active = incomplete.active_lease.as_ref().unwrap();
        assert!(active.authority_fencing_token.is_none());
        assert!(active.authority_capture.is_empty());
        assert!(active.authority_fence.is_empty());
        assert!(incomplete.last_authority_fence.is_empty());
        for (repo_id, expected) in &before {
            let path = ObjectPath::from(format!("fixture/{repo_id}/graph.kndb"));
            assert_eq!(
                raw.get(&path).await.unwrap().meta.version.as_ref(),
                expected.as_ref(),
                "capturing a partial fleet must not rewrite {repo_id}"
            );
        }

        raw.put_opts(
            &ObjectPath::from("fixture/kin-editor/graph.kndb"),
            PutPayload::from(authority),
            PutOptions {
                mode: PutMode::Create,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();
        let completed = control.acquire_rollout(request).unwrap();
        assert_eq!(completed.authority_fence.len(), repositories.len());
        release(&control, &completed);
    }

    #[cfg(feature = "gcs")]
    #[tokio::test(flavor = "multi_thread")]
    async fn fleet_capture_retains_at_most_one_bounded_object_body() {
        let raw = Arc::new(VersionedMemoryStore::new());
        let object_store: Arc<dyn ObjectStore> = raw.clone();
        let repositories = staging_fleet();
        let authority = wrapped_snapshot(kin_db::GraphSnapshot::CURRENT_VERSION);
        let per_object_limit = u64::try_from(authority.len()).unwrap() + 1;
        assert!(
            u64::try_from(authority.len() * repositories.len()).unwrap() > per_object_limit,
            "the aggregate fixture must exceed the configured in-memory cap"
        );
        for repo_id in &repositories {
            raw.put_opts(
                &ObjectPath::from(format!("fixture/{repo_id}/graph.kndb")),
                PutPayload::from(authority.clone()),
                PutOptions {
                    mode: PutMode::Create,
                    ..PutOptions::default()
                },
            )
            .await
            .unwrap();
        }

        let concrete = Arc::new(
            ObjectStorePublicationControlStore::with_fence_memory_limit(
                object_store,
                "fixture",
                per_object_limit,
            ),
        );
        let control_store: Arc<dyn PublicationControlStore> = concrete.clone();
        let control = PublicationControl::new(
            SCOPE,
            READER_A,
            repositories.clone(),
            control_store,
        )
        .unwrap();
        let rollout = control
            .acquire_rollout(rollout_request_for_fleet(
                repositories,
                "deploy",
                "bounded-memory",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        assert!(
            concrete.peak_fence_body_bytes() <= authority.len(),
            "fleet capture retained more than one graph body: peak {} for one-body size {}",
            concrete.peak_fence_body_bytes(),
            authority.len()
        );
        release(&control, &rollout);
    }

    #[cfg(feature = "gcs")]
    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_authority_is_refused_before_any_generation_fence() {
        let raw = Arc::new(VersionedMemoryStore::new());
        let object_store: Arc<dyn ObjectStore> = raw.clone();
        let repositories = staging_fleet();
        let authority = wrapped_snapshot(kin_db::GraphSnapshot::CURRENT_VERSION);
        let limit = u64::try_from(authority.len() - 1).unwrap();
        let mut before = HashMap::new();
        for repo_id in &repositories {
            let result = raw
                .put_opts(
                    &ObjectPath::from(format!("fixture/{repo_id}/graph.kndb")),
                    PutPayload::from(authority.clone()),
                    PutOptions {
                        mode: PutMode::Create,
                        ..PutOptions::default()
                    },
                )
                .await
                .unwrap();
            before.insert(repo_id.clone(), result.version);
        }

        let concrete = Arc::new(
            ObjectStorePublicationControlStore::with_fence_memory_limit(
                object_store,
                "fixture",
                limit,
            ),
        );
        let control_store: Arc<dyn PublicationControlStore> = concrete;
        let control = PublicationControl::new(
            SCOPE,
            READER_A,
            repositories.clone(),
            control_store,
        )
        .unwrap();
        let refused = control
            .acquire_rollout(rollout_request_for_fleet(
                repositories.clone(),
                "deploy",
                "oversized-authority",
                Some(reader(READER_A, 300)),
            ))
            .unwrap_err();
        assert!(
            refused.to_string().contains("bounded in-memory fencing limit"),
            "{refused}"
        );
        let active = control.status().unwrap().active_lease.unwrap();
        assert!(active.authority_capture.is_empty());
        assert!(active.authority_fence.is_empty());
        assert!(active.authority_fencing_token.is_none());
        for repo_id in &repositories {
            let path = ObjectPath::from(format!("fixture/{repo_id}/graph.kndb"));
            assert_eq!(
                raw.get(&path).await.unwrap().meta.version,
                before[repo_id],
                "oversized fleet capture must not rewrite {repo_id}"
            );
        }
    }

    #[cfg(feature = "gcs")]
    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_control_record_is_refused_before_body_allocation() {
        let raw_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let path = ObjectPath::from("fixture/.kin-graph-publication-control.json");
        raw_store
            .put(&path, PutPayload::from(vec![b'x'; 33]))
            .await
            .unwrap();
        let control = ObjectStorePublicationControlStore::with_control_record_limit(
            raw_store,
            "fixture",
            32,
        );
        let refused = control.load().unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("bounded publication-control record limit 32"),
            "{refused}"
        );

        let write_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let bounded_writer = ObjectStorePublicationControlStore::with_control_record_limit(
            Arc::clone(&write_store),
            "fixture",
            32,
        );
        let logical = control(
            Arc::new(InMemoryPublicationControlStore::default()),
            Arc::new(ManualClock::new()),
            READER_A,
        );
        logical
            .acquire_rollout(rollout_request(
                "deploy",
                "oversized-control-write",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        let refused = bounded_writer.create(&logical.status().unwrap()).unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("bounded publication-control record limit 32"),
            "{refused}"
        );
        assert!(matches!(
            write_store
                .get(&ObjectPath::from(
                    "fixture/.kin-graph-publication-control.json"
                ))
                .await,
            Err(object_store::Error::NotFound { .. })
        ));
    }

    #[cfg(feature = "gcs")]
    #[test]
    fn object_store_record_create_and_update_share_exact_cas_state() {
        let raw_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let first_store: Arc<dyn PublicationControlStore> = Arc::new(
            ObjectStorePublicationControlStore::new(Arc::clone(&raw_store), "fixture"),
        );
        let second_store: Arc<dyn PublicationControlStore> = Arc::new(
            ObjectStorePublicationControlStore::new(Arc::clone(&raw_store), "fixture"),
        );
        let logical_store = Arc::new(InMemoryPublicationControlStore::default());
        let logical = control(
            logical_store,
            Arc::new(ManualClock::new()),
            READER_A,
        );
        let lease = logical
            .acquire_rollout(rollout_request(
                "deploy-one",
                "bootstrap",
                Some(reader(READER_A, 300)),
            ))
            .unwrap();
        release(&logical, &lease);
        let mut record = logical.status().unwrap();
        first_store.create(&record).unwrap();
        let loaded = second_store.load().unwrap().unwrap();
        assert_eq!(loaded.record, record);
        record.revision += 1;
        second_store.update(&loaded.version, &record).unwrap();
        assert_eq!(first_store.load().unwrap().unwrap().record, record);
        assert!(matches!(
            first_store.create(&record),
            Err(PublicationControlError::Conflict(_))
        ));
    }
}
