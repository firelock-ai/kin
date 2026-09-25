// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Explicit test-support only. `root` is the retained repository directory
//! beneath kindb, not the primary workspace. The single event follows immutable
//! payload confirmation and precedes required acknowledgement installation.

use kin_model::{Hash256, OperationId};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;

struct Registration {
    root: PathBuf,
    operation: OperationId,
    callback: Rc<dyn Fn(&Observation)>,
}
thread_local! {
    static OBSERVER: RefCell<Option<Registration>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    RootMustBeAbsolute,
    AlreadyRegisteredOnThread,
}
impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session publication observer registration: {self:?}")
    }
}
impl std::error::Error for RegistrationError {}

/// Own this guard on the actual blocking publication thread. It is !Send and
/// clears the observer on scope exit/unwind; nested registration is refused.
#[must_use = "dropping the guard unregisters the thread-local observer"]
pub struct ObserverGuard {
    _thread_bound: PhantomData<Rc<()>>,
}
impl Drop for ObserverGuard {
    fn drop(&mut self) {
        OBSERVER.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

/// Match the exact absolute path passed by the runtime and operation ID.
/// No normalization, environment trigger, global registration or wire input is
/// involved. The callback runs synchronously under the phase's existing locks;
/// do not recursively acquire those locks. No observer return value changes
/// publication. A process-crash harness may terminate only its owned child.
pub fn observe(
    root: PathBuf,
    operation: OperationId,
    callback: impl Fn(&Observation) + 'static,
) -> Result<ObserverGuard, RegistrationError> {
    if !root.is_absolute() {
        return Err(RegistrationError::RootMustBeAbsolute);
    }
    OBSERVER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err(RegistrationError::AlreadyRegisteredOnThread);
        }
        *slot = Some(Registration {
            root,
            operation,
            callback: Rc::new(callback),
        });
        Ok(ObserverGuard {
            _thread_bound: PhantomData,
        })
    })
}

fn matching_observer(root: &Path, operation: OperationId) -> Option<Rc<dyn Fn(&Observation)>> {
    OBSERVER.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|registered| registered.root == root && registered.operation == operation)
            .map(|registered| Rc::clone(&registered.callback))
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Point {
    PayloadConfirmedBeforeAcknowledgement,
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub point: Point,
    pub root: PathBuf,
    pub operation: OperationId,
    pub transaction_hash: Hash256,
    pub payload_sha256: String,
}

pub(crate) fn notify(
    root: &Path,
    operation: OperationId,
    transaction_hash: Hash256,
    payload_sha256: &str,
) {
    if let Some(callback) = matching_observer(root, operation) {
        callback(&Observation {
            point: Point::PayloadConfirmedBeforeAcknowledgement,
            root: root.to_path_buf(),
            operation,
            transaction_hash,
            payload_sha256: payload_sha256.into(),
        });
    }
}

#[cfg(test)]
#[path = "session_publication_observer_test.rs"]
mod tests;
