// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable-before-publication authority for immutable repository state.
//!
//! A repository transaction must never mutate the graph, refs, receipts, or
//! any other authority domain in place. [`AuthorityPublication`] serializes
//! writers, prepares a complete replacement state, persists that state, and
//! only then publishes one new `Arc`. Readers retain a coherent lease to the
//! exact state they loaded even while a later generation is committed.

use parking_lot::{Mutex, RwLock};
use std::ops::Deref;
use std::sync::Arc;

use crate::error::KinDbError;
use crate::storage::Generation;

/// Immutable state that participates in one monotonically versioned authority.
///
/// Implementations must not expose interior mutation of authority-bearing
/// fields. Derived caches may use interior mutability only when they cannot
/// change the state represented by [`generation`](Self::generation).
pub trait VersionedAuthorityState: Send + Sync + 'static {
    fn generation(&self) -> Generation;
}

/// Persistence boundary for a complete candidate authority state.
///
/// [`PersistOutcome::Committed`] acknowledges that `next` is durable and
/// recoverable as the exact successor of `expected_generation`.
/// Implementations must provide compare-and-swap semantics and must not
/// acknowledge a partially persisted state.
pub trait DurableAuthorityPersistence<S>: Send + Sync + 'static
where
    S: VersionedAuthorityState,
{
    /// Persist `next` as the exact successor of `current`, the state published
    /// when the candidate was prepared.
    ///
    /// Both states are handed over because a persistence that journals only
    /// what changed needs the predecessor to say what that was; a persistence
    /// that writes complete states may ignore `current` beyond its generation.
    fn persist(&self, current: &S, next: &S) -> PersistOutcome;

    /// Reconcile a candidate retained after an indeterminate persistence
    /// result.
    ///
    /// The default retries the exact candidate. Backends that can inspect
    /// installed authority should override this to confirm exact bytes before
    /// attempting another conditional write.
    fn reconcile(&self, current: &S, next: &S) -> PersistOutcome {
        self.persist(current, next)
    }

    /// Persist a representation-only replacement of `current`.
    ///
    /// The replacement carries the same logical authority generation and may
    /// differ only in derived, non-authoritative state. Persistence still has
    /// to perform a fenced compare-and-swap and acknowledge the exact complete
    /// replacement before it can be published. The default refuses because
    /// most authority domains have no representation-only rewrite.
    fn persist_equivalent(&self, _current: &S, _next: &S) -> PersistOutcome {
        PersistOutcome::NotCommitted(KinDbError::StorageError(
            "this authority persistence does not support equivalent representation rewrites"
                .to_string(),
        ))
    }

    /// Reconcile an indeterminate representation-only replacement.
    ///
    /// A persistence whose equivalent rewrite can return `Indeterminate` must
    /// either make its ordinary reconciliation understand the same exact
    /// candidate or override this method. The default retries through
    /// [`persist_equivalent`](Self::persist_equivalent).
    fn reconcile_equivalent(&self, current: &S, next: &S) -> PersistOutcome {
        self.persist_equivalent(current, next)
    }
}

/// Classified result of attempting to durably persist one authority candidate.
#[must_use = "an authority persistence outcome must be classified before publication"]
#[derive(Debug)]
pub enum PersistOutcome {
    /// The exact candidate is durable and recoverable.
    Committed,
    /// The backend proved that the candidate was not committed.
    NotCommitted(KinDbError),
    /// The backend cannot prove whether the candidate was committed.
    ///
    /// The caller must retain the exact candidate and reconcile it before
    /// preparing any later successor.
    Indeterminate(KinDbError),
}

/// Classified persistence result that retains an authority capability on
/// durable success.
///
/// The retained value must keep the backend's mutation exclusion alive until
/// it is dropped. This lets a caller publish the exact in-memory successor
/// while the same backend commit lock is still held, without a release and
/// reacquire window.
pub(crate) enum RetainedPersistOutcome<R> {
    /// The exact candidate is durable and `retained` still excludes writers.
    Committed { retained: R },
    /// The backend proved that the candidate was not committed.
    NotCommitted(KinDbError),
    /// The backend cannot prove whether the candidate was committed.
    Indeterminate(KinDbError),
}

/// A coherent read lease for one published authority generation.
///
/// The lease owns an `Arc`, so a writer can publish a later generation without
/// changing or invalidating the state observed by this reader.
pub struct AuthorityReadLease<S>(Arc<S>);

impl<S> Clone for AuthorityReadLease<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<S> Deref for AuthorityReadLease<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<S> AuthorityReadLease<S> {
    pub fn into_arc(self) -> Arc<S> {
        self.0
    }
}

/// Decision prepared while holding the single repository-writer permit.
pub enum AuthorityCommitDecision<S, O> {
    /// Persist and publish a complete next generation.
    Publish { next: S, output: O },
    /// Return an already-durable result without changing authority.
    ///
    /// This is reserved for verified idempotent replay. Callers must validate
    /// the operation identity and transaction hash before selecting it.
    IdempotentReplay { output: O },
}

/// Decision prepared for a representation-only authority rewrite.
///
/// Unlike [`AuthorityCommitDecision::Publish`], `Rewrite` must keep the exact
/// logical generation. It exists for derived state whose durable bytes need a
/// fenced replacement without fabricating a semantic repository operation.
pub(crate) enum AuthorityRewriteDecision<S, O> {
    /// Persist and publish an equivalent representation at the same logical
    /// generation.
    Rewrite { next: S, output: O },
    /// The current representation already answers the request.
    Unchanged { output: O },
}

/// One shared authority cell with serialized copy-on-write commits.
///
/// There is deliberately no API for replacing individual fields. A commit has
/// exactly one fallible durability step followed by one infallible pointer
/// replacement.
pub struct AuthorityPublication<S, P>
where
    S: VersionedAuthorityState,
    P: DurableAuthorityPersistence<S>,
{
    current: RwLock<Arc<S>>,
    writer: Mutex<AuthorityWriterState<S>>,
    persistence: P,
}

struct AuthorityWriterState<S> {
    pending: Option<PendingAuthority<S>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAuthorityKind {
    Successor,
    EquivalentRewrite,
}

struct PendingAuthority<S> {
    state: Arc<S>,
    kind: PendingAuthorityKind,
}

impl<S, P> AuthorityPublication<S, P>
where
    S: VersionedAuthorityState,
    P: DurableAuthorityPersistence<S>,
{
    pub fn new(initial: S, persistence: P) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
            writer: Mutex::new(AuthorityWriterState { pending: None }),
            persistence,
        }
    }

    /// Load the exact currently published authority once.
    pub fn read(&self) -> AuthorityReadLease<S> {
        AuthorityReadLease(Arc::clone(&self.current.read()))
    }

    #[cfg(test)]
    pub(crate) fn persistence(&self) -> &P {
        &self.persistence
    }

    /// Resolve one exact candidate whose persistence acknowledgement was
    /// indeterminate before any later writer is allowed to prepare.
    fn reconcile_pending(
        &self,
        writer: &mut AuthorityWriterState<S>,
        mut current: Arc<S>,
    ) -> Result<Arc<S>, KinDbError> {
        let pending = writer
            .pending
            .as_ref()
            .map(|pending| (pending.kind, Arc::clone(&pending.state)));
        let Some((kind, pending)) = pending else {
            return Ok(current);
        };
        let outcome = match kind {
            PendingAuthorityKind::Successor => self
                .persistence
                .reconcile(current.as_ref(), pending.as_ref()),
            PendingAuthorityKind::EquivalentRewrite => self
                .persistence
                .reconcile_equivalent(current.as_ref(), pending.as_ref()),
        };
        match outcome {
            PersistOutcome::Committed => {
                *self.current.write() = Arc::clone(&pending);
                writer.pending = None;
                current = pending;
                Ok(current)
            }
            PersistOutcome::NotCommitted(error) => {
                writer.pending = None;
                Err(error)
            }
            PersistOutcome::Indeterminate(error) => Err(error),
        }
    }

    /// Commit one complete authority successor.
    ///
    /// `prepare` runs while all writers are serialized and receives the exact
    /// current state. The candidate `Arc` is allocated before persistence, so
    /// once durable acknowledgement succeeds the remaining publication is a
    /// single infallible pointer replacement with no user callback.
    pub fn commit<O>(
        &self,
        prepare: impl FnOnce(&S) -> Result<AuthorityCommitDecision<S, O>, KinDbError>,
    ) -> Result<O, KinDbError> {
        let mut writer = self.writer.lock();
        let current = Arc::clone(&self.current.read());
        let current = self.reconcile_pending(&mut writer, current)?;

        match prepare(current.as_ref())? {
            AuthorityCommitDecision::IdempotentReplay { output } => Ok(output),
            AuthorityCommitDecision::Publish { next, output } => {
                let expected_generation = current.generation();
                let required_generation = expected_generation.checked_add(1).ok_or_else(|| {
                    KinDbError::StorageError(format!(
                        "repository authority generation exhausted at {expected_generation}"
                    ))
                })?;
                if next.generation() != required_generation {
                    return Err(KinDbError::ConcurrentAccessError(format!(
                        "repository authority successor must be generation {required_generation}, found {}",
                        next.generation()
                    )));
                }

                // Allocate before the durable boundary. After persist returns
                // success there must be no fallible work before publication.
                let next = Arc::new(next);
                match self.persistence.persist(current.as_ref(), next.as_ref()) {
                    PersistOutcome::Committed => {
                        *self.current.write() = next;
                        Ok(output)
                    }
                    PersistOutcome::NotCommitted(error) => Err(error),
                    PersistOutcome::Indeterminate(error) => {
                        writer.pending = Some(PendingAuthority {
                            state: next,
                            kind: PendingAuthorityKind::Successor,
                        });
                        Err(error)
                    }
                }
            }
        }
    }

    /// Persist and publish an equivalent representation of current authority.
    ///
    /// This is the narrow escape hatch for derived state that must live beside
    /// authority bytes but must not fabricate a semantic operation or advance
    /// the logical generation. It shares the exact writer permit and pending
    /// reconciliation discipline with ordinary commits. The persistence is
    /// responsible for a fenced complete replacement; a partial or in-place
    /// rewrite is never acknowledged here.
    pub(crate) fn rewrite_equivalent<O>(
        &self,
        prepare: impl FnOnce(&S) -> Result<AuthorityRewriteDecision<S, O>, KinDbError>,
    ) -> Result<O, KinDbError> {
        let mut writer = self.writer.lock();
        let current = Arc::clone(&self.current.read());
        let current = self.reconcile_pending(&mut writer, current)?;

        match prepare(current.as_ref())? {
            AuthorityRewriteDecision::Unchanged { output } => Ok(output),
            AuthorityRewriteDecision::Rewrite { next, output } => {
                if next.generation() != current.generation() {
                    return Err(KinDbError::ConcurrentAccessError(format!(
                        "equivalent authority rewrite must remain at logical generation {}, found {}",
                        current.generation(),
                        next.generation()
                    )));
                }

                // Allocate before durability. A successful acknowledgement is
                // followed only by the infallible pointer replacement.
                let next = Arc::new(next);
                match self
                    .persistence
                    .persist_equivalent(current.as_ref(), next.as_ref())
                {
                    PersistOutcome::Committed => {
                        *self.current.write() = next;
                        Ok(output)
                    }
                    PersistOutcome::NotCommitted(error) => Err(error),
                    PersistOutcome::Indeterminate(error) => {
                        writer.pending = Some(PendingAuthority {
                            state: next,
                            kind: PendingAuthorityKind::EquivalentRewrite,
                        });
                        Err(error)
                    }
                }
            }
        }
    }

    /// Commit one complete successor and return a retained backend authority
    /// capability without releasing it between durability and publication.
    ///
    /// `persist_and_retain` must use the same exclusion capability for the
    /// durable compare-and-swap and the returned value. On idempotent replay,
    /// `retain_current` must acquire and revalidate a capability for the exact
    /// currently published state. Both callbacks run while the single
    /// in-process writer permit is held.
    pub(crate) fn commit_and_retain<O, R>(
        &self,
        prepare: impl FnOnce(&S) -> Result<AuthorityCommitDecision<S, O>, KinDbError>,
        retain_current: impl FnOnce(&P, &S) -> Result<R, KinDbError>,
        persist_and_retain: impl FnOnce(&P, &S, &S) -> RetainedPersistOutcome<R>,
    ) -> Result<(O, R), KinDbError> {
        let mut writer = self.writer.lock();
        let current = Arc::clone(&self.current.read());
        let current = self.reconcile_pending(&mut writer, current)?;

        match prepare(current.as_ref())? {
            AuthorityCommitDecision::IdempotentReplay { output } => {
                let retained = retain_current(&self.persistence, current.as_ref())?;
                Ok((output, retained))
            }
            AuthorityCommitDecision::Publish { next, output } => {
                let expected_generation = current.generation();
                let required_generation = expected_generation.checked_add(1).ok_or_else(|| {
                    KinDbError::StorageError(format!(
                        "repository authority generation exhausted at {expected_generation}"
                    ))
                })?;
                if next.generation() != required_generation {
                    return Err(KinDbError::ConcurrentAccessError(format!(
                        "repository authority successor must be generation {required_generation}, found {}",
                        next.generation()
                    )));
                }

                // Allocate before durability. `retained` remains alive across
                // the infallible pointer publication and is returned to the
                // caller still holding the backend exclusion capability.
                let next = Arc::new(next);
                match persist_and_retain(&self.persistence, current.as_ref(), next.as_ref()) {
                    RetainedPersistOutcome::Committed { retained } => {
                        *self.current.write() = next;
                        Ok((output, retained))
                    }
                    RetainedPersistOutcome::NotCommitted(error) => Err(error),
                    RetainedPersistOutcome::Indeterminate(error) => {
                        writer.pending = Some(PendingAuthority {
                            state: next,
                            kind: PendingAuthorityKind::Successor,
                        });
                        Err(error)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Barrier, Condvar, Mutex as StdMutex};
    use std::time::Duration;

    #[derive(Debug)]
    struct TestState {
        generation: Generation,
        value: u64,
    }

    impl VersionedAuthorityState for TestState {
        fn generation(&self) -> Generation {
            self.generation
        }
    }

    #[derive(Default)]
    struct TestPersistence {
        fail_next: AtomicBool,
        persisted_generation: AtomicU64,
        persisted_value: AtomicU64,
    }

    impl DurableAuthorityPersistence<TestState> for TestPersistence {
        fn persist(&self, current: &TestState, next: &TestState) -> PersistOutcome {
            let expected_generation = current.generation;
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return PersistOutcome::NotCommitted(KinDbError::StorageError(
                    "injected authority persistence failure".to_string(),
                ));
            }
            assert_eq!(next.generation, expected_generation + 1);
            self.persisted_generation
                .store(next.generation, Ordering::Release);
            self.persisted_value.store(next.value, Ordering::Release);
            PersistOutcome::Committed
        }

        fn persist_equivalent(&self, current: &TestState, next: &TestState) -> PersistOutcome {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return PersistOutcome::NotCommitted(KinDbError::StorageError(
                    "injected authority persistence failure".to_string(),
                ));
            }
            assert_eq!(next.generation, current.generation);
            self.persisted_generation
                .store(next.generation, Ordering::Release);
            self.persisted_value.store(next.value, Ordering::Release);
            PersistOutcome::Committed
        }
    }

    fn publication(
        persistence: TestPersistence,
    ) -> AuthorityPublication<TestState, TestPersistence> {
        AuthorityPublication::new(
            TestState {
                generation: 0,
                value: 10,
            },
            persistence,
        )
    }

    #[test]
    fn old_read_lease_remains_coherent_after_publication() {
        let authority = publication(TestPersistence::default());
        let old = authority.read();

        authority
            .commit(|current| {
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: current.generation + 1,
                        value: 20,
                    },
                    output: (),
                })
            })
            .unwrap();

        assert_eq!((old.generation, old.value), (0, 10));
        let current = authority.read();
        assert_eq!((current.generation, current.value), (1, 20));
    }

    #[test]
    fn equivalent_rewrite_keeps_generation_and_old_read_lease_coherent() {
        let authority = publication(TestPersistence::default());
        let old = authority.read();

        authority
            .rewrite_equivalent(|current| {
                Ok(AuthorityRewriteDecision::Rewrite {
                    next: TestState {
                        generation: current.generation,
                        value: 20,
                    },
                    output: (),
                })
            })
            .unwrap();

        assert_eq!((old.generation, old.value), (0, 10));
        let current = authority.read();
        assert_eq!((current.generation, current.value), (0, 20));
        assert_eq!(
            authority
                .persistence
                .persisted_generation
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            authority
                .persistence
                .persisted_value
                .load(Ordering::Acquire),
            20
        );
    }

    #[test]
    fn equivalent_rewrite_refuses_a_different_logical_generation_before_persistence() {
        let authority = publication(TestPersistence::default());
        let error = authority
            .rewrite_equivalent(|current| {
                Ok(AuthorityRewriteDecision::Rewrite {
                    next: TestState {
                        generation: current.generation + 1,
                        value: 20,
                    },
                    output: (),
                })
            })
            .expect_err("a representation rewrite cannot become a semantic successor");

        assert!(error
            .to_string()
            .contains("must remain at logical generation 0"));
        assert_eq!(
            (authority.read().generation, authority.read().value),
            (0, 10)
        );
        assert_eq!(
            authority
                .persistence
                .persisted_value
                .load(Ordering::Acquire),
            0,
            "the invalid candidate must not reach persistence"
        );
    }

    #[test]
    fn definite_persistence_failure_publishes_and_retains_nothing() {
        let persistence = TestPersistence::default();
        persistence.fail_next.store(true, Ordering::Release);
        let authority = publication(persistence);

        let error = authority
            .commit(|current| {
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: current.generation + 1,
                        value: 99,
                    },
                    output: (),
                })
            })
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected authority persistence failure"));
        let current = authority.read();
        assert_eq!((current.generation, current.value), (0, 10));

        authority
            .commit(|current| {
                assert_eq!(
                    current.generation, 0,
                    "a definitely uncommitted candidate must not be retried"
                );
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: 1,
                        value: 20,
                    },
                    output: (),
                })
            })
            .unwrap();
        assert_eq!(authority.read().value, 20);
        assert_eq!(
            authority
                .persistence
                .persisted_value
                .load(Ordering::Acquire),
            20
        );
    }

    struct IndeterminatePersistence {
        fail_after_install_once: AtomicBool,
        attempts: StdMutex<Vec<(Generation, Generation, u64, usize)>>,
    }

    impl DurableAuthorityPersistence<TestState> for IndeterminatePersistence {
        fn persist(&self, current: &TestState, next: &TestState) -> PersistOutcome {
            let expected_generation = current.generation;
            self.attempts.lock().unwrap().push((
                expected_generation,
                next.generation,
                next.value,
                std::ptr::from_ref(next) as usize,
            ));
            if self.fail_after_install_once.swap(false, Ordering::SeqCst) {
                return PersistOutcome::Indeterminate(
                    KinDbError::SnapshotPersistenceIndeterminate(
                        "injected acknowledgement loss after exact install".to_string(),
                    ),
                );
            }
            PersistOutcome::Committed
        }
    }

    #[test]
    fn indeterminate_candidate_is_reconciled_before_the_next_writer_prepares() {
        let authority = AuthorityPublication::new(
            TestState {
                generation: 0,
                value: 10,
            },
            IndeterminatePersistence {
                fail_after_install_once: AtomicBool::new(true),
                attempts: StdMutex::new(Vec::new()),
            },
        );

        authority
            .commit(|current| {
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: current.generation + 1,
                        value: 20,
                    },
                    output: "first receipt",
                })
            })
            .expect_err("lost acknowledgement must remain indeterminate");
        assert_eq!(
            (authority.read().generation, authority.read().value),
            (0, 10)
        );

        let output = authority
            .commit(|current| {
                assert_eq!(
                    (current.generation, current.value),
                    (1, 20),
                    "the exact pending candidate must publish before prepare"
                );
                Ok(AuthorityCommitDecision::IdempotentReplay {
                    output: "recovered receipt",
                })
            })
            .unwrap();
        assert_eq!(output, "recovered receipt");

        authority
            .commit(|current| {
                assert_eq!(
                    (current.generation, current.value),
                    (1, 20),
                    "a different operation must prepare from recovered authority"
                );
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: 2,
                        value: 30,
                    },
                    output: (),
                })
            })
            .unwrap();

        let attempts = authority.persistence.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 3);
        assert_eq!((attempts[0].0, attempts[0].1, attempts[0].2), (0, 1, 20));
        assert_eq!((attempts[1].0, attempts[1].1, attempts[1].2), (0, 1, 20));
        assert_eq!((attempts[2].0, attempts[2].1, attempts[2].2), (1, 2, 30));
        assert_eq!(
            attempts[0].3, attempts[1].3,
            "reconciliation must retry the same retained Arc, not rebuild state"
        );
    }

    struct IndeterminateRewritePersistence {
        fail_after_install_once: AtomicBool,
        attempts: StdMutex<Vec<(&'static str, Generation, u64, usize)>>,
    }

    impl DurableAuthorityPersistence<TestState> for IndeterminateRewritePersistence {
        fn persist(&self, current: &TestState, next: &TestState) -> PersistOutcome {
            self.attempts.lock().unwrap().push((
                "successor",
                next.generation,
                next.value,
                std::ptr::from_ref(next) as usize,
            ));
            assert_eq!(next.generation, current.generation + 1);
            PersistOutcome::Committed
        }

        fn persist_equivalent(&self, current: &TestState, next: &TestState) -> PersistOutcome {
            self.attempts.lock().unwrap().push((
                "rewrite",
                next.generation,
                next.value,
                std::ptr::from_ref(next) as usize,
            ));
            assert_eq!(next.generation, current.generation);
            if self.fail_after_install_once.swap(false, Ordering::SeqCst) {
                PersistOutcome::Indeterminate(KinDbError::SnapshotPersistenceIndeterminate(
                    "injected acknowledgement loss after equivalent install".to_string(),
                ))
            } else {
                PersistOutcome::Committed
            }
        }

        fn reconcile_equivalent(&self, current: &TestState, next: &TestState) -> PersistOutcome {
            self.attempts.lock().unwrap().push((
                "rewrite-reconcile",
                next.generation,
                next.value,
                std::ptr::from_ref(next) as usize,
            ));
            assert_eq!(next.generation, current.generation);
            PersistOutcome::Committed
        }
    }

    #[test]
    fn indeterminate_equivalent_rewrite_is_reconciled_before_a_successor_prepares() {
        let authority = AuthorityPublication::new(
            TestState {
                generation: 0,
                value: 10,
            },
            IndeterminateRewritePersistence {
                fail_after_install_once: AtomicBool::new(true),
                attempts: StdMutex::new(Vec::new()),
            },
        );

        authority
            .rewrite_equivalent(|current| {
                Ok(AuthorityRewriteDecision::Rewrite {
                    next: TestState {
                        generation: current.generation,
                        value: 20,
                    },
                    output: (),
                })
            })
            .expect_err("lost acknowledgement must retain the equivalent candidate");
        assert_eq!(
            (authority.read().generation, authority.read().value),
            (0, 10)
        );

        authority
            .commit(|current| {
                assert_eq!(
                    (current.generation, current.value),
                    (0, 20),
                    "the equivalent candidate must publish before successor preparation"
                );
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: 1,
                        value: 30,
                    },
                    output: (),
                })
            })
            .unwrap();

        let attempts = authority.persistence.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 3);
        assert_eq!(
            (attempts[0].0, attempts[0].1, attempts[0].2),
            ("rewrite", 0, 20)
        );
        assert_eq!(
            (attempts[1].0, attempts[1].1, attempts[1].2),
            ("rewrite-reconcile", 0, 20)
        );
        assert_eq!(
            attempts[0].3, attempts[1].3,
            "equivalent reconciliation must retain the exact candidate Arc"
        );
        assert_eq!(
            (attempts[2].0, attempts[2].1, attempts[2].2),
            ("successor", 1, 30)
        );
        assert_eq!(
            (authority.read().generation, authority.read().value),
            (1, 30)
        );
    }

    struct ReconcileRejectionPersistence {
        attempts: AtomicUsize,
    }

    impl DurableAuthorityPersistence<TestState> for ReconcileRejectionPersistence {
        fn persist(&self, _current: &TestState, _next: &TestState) -> PersistOutcome {
            match self.attempts.fetch_add(1, Ordering::SeqCst) {
                0 => PersistOutcome::Indeterminate(KinDbError::SnapshotPersistenceIndeterminate(
                    "first result is unknown".to_string(),
                )),
                1 => PersistOutcome::NotCommitted(KinDbError::ConcurrentAccessError(
                    "reconciliation proved that another authority won".to_string(),
                )),
                _ => PersistOutcome::Committed,
            }
        }
    }

    #[test]
    fn definitive_reconciliation_rejection_drops_pending_before_a_later_writer() {
        let authority = AuthorityPublication::new(
            TestState {
                generation: 0,
                value: 10,
            },
            ReconcileRejectionPersistence {
                attempts: AtomicUsize::new(0),
            },
        );
        authority
            .commit(|current| {
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: current.generation + 1,
                        value: 99,
                    },
                    output: (),
                })
            })
            .expect_err("first result remains unknown");

        authority
            .commit::<()>(|_| panic!("prepare cannot run before pending reconciliation"))
            .expect_err("definitive reconciliation rejection must reach the caller");
        assert_eq!(
            (authority.read().generation, authority.read().value),
            (0, 10)
        );

        authority
            .commit(|current| {
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: current.generation + 1,
                        value: 20,
                    },
                    output: (),
                })
            })
            .unwrap();
        assert_eq!(
            (authority.read().generation, authority.read().value),
            (1, 20)
        );
    }

    struct SerializedPersistence {
        active: AtomicUsize,
        max_active: AtomicUsize,
        persisted_generation: AtomicU64,
    }

    impl DurableAuthorityPersistence<TestState> for SerializedPersistence {
        fn persist(&self, current: &TestState, next: &TestState) -> PersistOutcome {
            let expected_generation = current.generation;
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(
                self.persisted_generation.load(Ordering::Acquire),
                expected_generation
            );
            self.persisted_generation
                .store(next.generation, Ordering::Release);
            self.active.fetch_sub(1, Ordering::SeqCst);
            PersistOutcome::Committed
        }
    }

    #[test]
    fn writers_serialize_over_prepare_persist_and_publish() {
        let authority = Arc::new(AuthorityPublication::new(
            TestState {
                generation: 0,
                value: 0,
            },
            SerializedPersistence {
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                persisted_generation: AtomicU64::new(0),
            },
        ));
        let start = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let authority = Arc::clone(&authority);
            let start = Arc::clone(&start);
            threads.push(std::thread::spawn(move || {
                start.wait();
                authority
                    .commit(|current| {
                        Ok(AuthorityCommitDecision::Publish {
                            next: TestState {
                                generation: current.generation + 1,
                                value: current.value + 1,
                            },
                            output: (),
                        })
                    })
                    .unwrap();
            }));
        }
        start.wait();
        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(authority.persistence.max_active.load(Ordering::SeqCst), 1);
        let current = authority.read();
        assert_eq!((current.generation, current.value), (2, 2));
    }

    struct BlockingPersistence {
        entered: Arc<(StdMutex<bool>, Condvar)>,
        release: Arc<(StdMutex<bool>, Condvar)>,
    }

    impl DurableAuthorityPersistence<TestState> for BlockingPersistence {
        fn persist(&self, _current: &TestState, _next: &TestState) -> PersistOutcome {
            let (entered, entered_cv) = self.entered.as_ref();
            *entered.lock().unwrap() = true;
            entered_cv.notify_one();

            let (release, release_cv) = self.release.as_ref();
            let mut allowed = release.lock().unwrap();
            while !*allowed {
                allowed = release_cv.wait(allowed).unwrap();
            }
            PersistOutcome::Committed
        }
    }

    #[test]
    fn candidate_is_not_visible_until_durability_acknowledges() {
        let entered = Arc::new((StdMutex::new(false), Condvar::new()));
        let release = Arc::new((StdMutex::new(false), Condvar::new()));
        let authority = Arc::new(AuthorityPublication::new(
            TestState {
                generation: 0,
                value: 10,
            },
            BlockingPersistence {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        ));
        let writer = {
            let authority = Arc::clone(&authority);
            std::thread::spawn(move || {
                authority
                    .commit(|current| {
                        Ok(AuthorityCommitDecision::Publish {
                            next: TestState {
                                generation: current.generation + 1,
                                value: 20,
                            },
                            output: (),
                        })
                    })
                    .unwrap();
            })
        };

        let (entered_lock, entered_cv) = entered.as_ref();
        let mut did_enter = entered_lock.lock().unwrap();
        while !*did_enter {
            did_enter = entered_cv.wait(did_enter).unwrap();
        }
        drop(did_enter);

        assert_eq!(authority.read().value, 10);
        let (release_lock, release_cv) = release.as_ref();
        *release_lock.lock().unwrap() = true;
        release_cv.notify_one();
        writer.join().unwrap();
        assert_eq!(authority.read().value, 20);
    }

    #[test]
    fn idempotent_replay_neither_persists_nor_publishes() {
        let authority = publication(TestPersistence::default());
        let output = authority
            .commit(|_| Ok(AuthorityCommitDecision::IdempotentReplay { output: "receipt" }))
            .unwrap();

        assert_eq!(output, "receipt");
        assert_eq!(authority.read().generation, 0);
        assert_eq!(
            authority
                .persistence
                .persisted_generation
                .load(Ordering::Acquire),
            0
        );
    }

    #[test]
    fn successor_must_be_exactly_one_generation() {
        let authority = publication(TestPersistence::default());
        let error = authority
            .commit(|current| {
                Ok(AuthorityCommitDecision::Publish {
                    next: TestState {
                        generation: current.generation + 2,
                        value: 20,
                    },
                    output: (),
                })
            })
            .unwrap_err();

        assert!(error.to_string().contains("successor must be generation 1"));
        assert_eq!(authority.read().generation, 0);
    }
}
