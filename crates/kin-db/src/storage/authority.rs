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
    fn persist(&self, expected_generation: Generation, next: &S) -> PersistOutcome;

    /// Reconcile a candidate retained after an indeterminate persistence
    /// result.
    ///
    /// The default retries the exact candidate. Backends that can inspect
    /// installed authority should override this to confirm exact bytes before
    /// attempting another conditional write.
    fn reconcile(&self, expected_generation: Generation, next: &S) -> PersistOutcome {
        self.persist(expected_generation, next)
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
    pending: Option<Arc<S>>,
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
        let mut current = Arc::clone(&self.current.read());

        // An indeterminate attempt may already have installed this exact
        // candidate. No later operation may prepare a different successor
        // until that uncertainty is resolved.
        if let Some(pending) = writer.pending.as_ref().map(Arc::clone) {
            let expected_generation = current.generation();
            match self
                .persistence
                .reconcile(expected_generation, pending.as_ref())
            {
                PersistOutcome::Committed => {
                    *self.current.write() = Arc::clone(&pending);
                    writer.pending = None;
                    current = pending;
                }
                PersistOutcome::NotCommitted(error) => {
                    writer.pending = None;
                    return Err(error);
                }
                PersistOutcome::Indeterminate(error) => return Err(error),
            }
        }

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
                match self.persistence.persist(expected_generation, next.as_ref()) {
                    PersistOutcome::Committed => {
                        *self.current.write() = next;
                        Ok(output)
                    }
                    PersistOutcome::NotCommitted(error) => Err(error),
                    PersistOutcome::Indeterminate(error) => {
                        writer.pending = Some(next);
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
        fn persist(&self, expected_generation: Generation, next: &TestState) -> PersistOutcome {
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
        fn persist(&self, expected_generation: Generation, next: &TestState) -> PersistOutcome {
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

    struct ReconcileRejectionPersistence {
        attempts: AtomicUsize,
    }

    impl DurableAuthorityPersistence<TestState> for ReconcileRejectionPersistence {
        fn persist(&self, _expected_generation: Generation, _next: &TestState) -> PersistOutcome {
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
        fn persist(&self, expected_generation: Generation, next: &TestState) -> PersistOutcome {
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
        fn persist(&self, _expected_generation: Generation, _next: &TestState) -> PersistOutcome {
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
