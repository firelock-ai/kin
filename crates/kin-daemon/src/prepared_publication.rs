// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Serving and process custody for a required prepared publication.
//!
//! This is not a planner or recovery protocol. The trusted owner supplies its
//! locks, arms at the actual irreversible prepare call, and may release only
//! after proving either no acknowledgement/mutation or exact finalization.
//! No request, serialized flag, or caller timeout can complete this guard.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, Json};
use http_body::{Frame, SizeHint};
use kin_model::OperationId;
use tokio::sync::watch;

use crate::lifecycle::DaemonLock;
use crate::DaemonState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    NoSupervisor,
    Busy,
    Closing,
    ObservationChanged,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "prepared publication unavailable: {self:?}")
    }
}

impl std::error::Error for Refused {}

#[derive(Default)]
struct Control {
    epoch: u64,
    active: Option<OperationId>,
    runtime: Option<PathBuf>,
    closing: bool,
}

pub(crate) struct ServingFence {
    control: Mutex<Control>,
    changed: watch::Sender<u64>,
}

impl Default for ServingFence {
    fn default() -> Self {
        Self {
            control: Mutex::new(Control::default()),
            changed: watch::channel(0).0,
        }
    }
}

impl ServingFence {
    fn lock(&self) -> MutexGuard<'_, Control> {
        // Poison must not turn an armed Drop into an unwind that frees custody.
        self.control
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn advance(&self, control: &mut Control) {
        control.epoch = control.epoch.checked_add(1).unwrap_or_else(|| {
            std::process::abort(); // Never wrap an observation into validity.
        });
        self.changed.send_replace(control.epoch);
    }

    /// Registered only by the actual run function, with its singleton borrowed
    /// until registration ends. A bare router cannot arm irreversible work.
    pub(crate) fn register<'a>(
        self: &Arc<Self>,
        singleton: &'a DaemonLock,
        root: &Path,
    ) -> std::io::Result<RuntimeRegistration<'a>> {
        let root = root.canonicalize()?;
        if singleton.canonical_kin_root() != root {
            return Err(std::io::Error::other("prepared runtime authority mismatch"));
        }
        let mut control = self.lock();
        if control.runtime.is_some() || control.closing {
            return Err(std::io::Error::other(
                "prepared runtime already registered or closing",
            ));
        }
        control.runtime = Some(root);
        Ok(RuntimeRegistration {
            fence: Arc::clone(self),
            _singleton: singleton,
        })
    }

    pub(crate) fn begin<C>(
        self: &Arc<Self>,
        operation: OperationId,
        custody: C,
    ) -> Result<Preflight<C>, Refused> {
        let mut control = self.lock();
        if control.runtime.is_none() {
            return Err(Refused::NoSupervisor);
        }
        if control.closing {
            return Err(Refused::Closing);
        }
        if control.active.is_some() {
            return Err(Refused::Busy);
        }
        control.active = Some(operation);
        self.advance(&mut control);
        Ok(Preflight {
            fence: Arc::clone(self),
            operation,
            custody: Some(custody),
        })
    }

    fn completed(&self, operation: OperationId) -> u64 {
        let mut control = self.lock();
        if control.active != Some(operation) {
            // Internal ownership corruption must never release publication locks.
            std::process::abort();
        }
        control.active = None;
        self.advance(&mut control);
        control.epoch
    }

    pub(crate) fn pending(&self) -> bool {
        self.lock().active.is_some()
    }

    pub(crate) fn ensure_serving(&self) -> Result<(), Refused> {
        let control = self.lock();
        if control.closing {
            Err(Refused::Closing)
        } else if control.active.is_some() {
            Err(Refused::Busy)
        } else {
            Ok(())
        }
    }

    /// Atomic against begin: a later owner cannot arm during ordinary save or
    /// drain. An unresolved owner terminates while its custody remains held.
    pub(crate) fn shutdown(&self) {
        let stop = {
            let mut control = self.lock();
            control.closing = true;
            self.advance(&mut control);
            control
                .active
                .map(|operation| (control.runtime.clone(), operation))
        };
        if let Some((root, operation)) = stop {
            terminate(
                root,
                operation,
                "shutdown with unresolved prepared publication",
            );
        }
    }

    fn abandoned(&self, operation: OperationId) -> ! {
        let root = {
            let mut control = self.lock();
            control.closing = true;
            self.advance(&mut control);
            control.runtime.clone()
        };
        terminate(
            root,
            operation,
            "armed publication owner dropped before verified completion",
        )
    }

    fn observe(self: &Arc<Self>) -> Result<Observation, Refused> {
        let control = self.lock();
        if control.closing {
            return Err(Refused::Closing);
        }
        if control.active.is_some() {
            return Err(Refused::Busy);
        }
        Ok(Observation {
            fence: Arc::clone(self),
            epoch: control.epoch,
            changes: self.changed.subscribe(),
        })
    }
}

fn terminate(root: Option<PathBuf>, operation: OperationId, reason: &'static str) -> ! {
    match root {
        Some(root) => crate::daemon::protected_prepared_publication_stop(root, operation, reason),
        None => std::process::abort(),
    }
}

pub(crate) struct RuntimeRegistration<'a> {
    fence: Arc<ServingFence>,
    _singleton: &'a DaemonLock,
}

impl Drop for RuntimeRegistration<'_> {
    fn drop(&mut self) {
        self.fence.shutdown();
        self.fence.lock().runtime = None;
    }
}

/// Holds the owner's real locks during reversible planning. It is safe to drop
/// only because no irreversible prepare has been attempted yet.
pub(crate) struct Preflight<C> {
    fence: Arc<ServingFence>,
    operation: OperationId,
    custody: Option<C>,
}

impl<C> Preflight<C> {
    pub(crate) fn arm(mut self) -> Armed<C> {
        Armed {
            fence: Arc::clone(&self.fence),
            operation: self.operation,
            custody: self.custody.take(),
        }
    }
}

impl<C> Drop for Preflight<C> {
    fn drop(&mut self) {
        if self.custody.is_some() {
            self.fence.completed(self.operation);
        }
    }
}

/// Must travel inside the core's preparation/committed custody and drop before
/// its projection/authority freeze on error. Drop never returns while armed.
pub(crate) struct Armed<C> {
    fence: Arc<ServingFence>,
    operation: OperationId,
    custody: Option<C>,
}

impl<C> Armed<C> {
    /// Borrow the held writer guards for finalization without releasing custody.
    /// The armed owner still stops the process if any later step fails.
    pub(crate) fn custody_mut(&mut self) -> &mut C {
        self.custody.as_mut().expect("armed custody")
    }

    /// Trusted lifecycle classification, never inferred from an Err alone.
    pub(crate) fn verified_no_acknowledgement_or_mutation(mut self) -> C {
        self.fence.completed(self.operation);
        self.custody.take().expect("armed custody")
    }

    /// Called only after exact durable/live/projection finalization agrees.
    pub(crate) fn verified_finalized(mut self) -> (C, FinalizedResponsePermit) {
        let epoch = self.fence.completed(self.operation);
        let permit = FinalizedResponsePermit {
            fence: Arc::clone(&self.fence),
            operation: self.operation,
            epoch,
        };
        (self.custody.take().expect("armed custody"), permit)
    }
}

impl<C> Drop for Armed<C> {
    fn drop(&mut self) {
        if self.custody.is_some() {
            self.fence.abandoned(self.operation);
        }
    }
}

/// Internal response extension for the owning operation's immutable receipt.
/// It cannot be constructed from a request or deserialized.
#[derive(Clone)]
pub(crate) struct FinalizedResponsePermit {
    fence: Arc<ServingFence>,
    // Serving admits the permit on fence identity and epoch alone, so the owning
    // operation is evidence this guard's own control reads rather than routing
    // input. Remove the expectation, not the field, if production ever reads it.
    #[cfg_attr(not(test), expect(dead_code))]
    operation: OperationId,
    epoch: u64,
}

struct Observation {
    fence: Arc<ServingFence>,
    epoch: u64,
    changes: watch::Receiver<u64>,
}

impl Observation {
    fn current(&self) -> bool {
        let control = self.fence.lock();
        !control.closing && control.active.is_none() && control.epoch == self.epoch
    }
}

fn unavailable(reason: Refused) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
        "error": "prepared_publication_unavailable", "reason": reason.to_string(),
        "live": true, "semantic_ready": false,
        "retry": "retry the original operation after recovery; do not infer whether a write committed"
    }))).into_response()
}

pub(crate) fn write_refusal(reason: Refused) -> (StatusCode, String) {
    (StatusCode::SERVICE_UNAVAILABLE, reason.to_string())
}

pub(crate) async fn serving(
    State(state): State<Arc<DaemonState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Identity-bound shutdown remains callable; it enters the protected stop
    // branch, never an alternate save. Identity-bound retirement does too: it
    // only records the request, and the pending operation is one of the gates
    // it then waits on. Even /health must not expose its normal graph
    // freshness payload during a pending operation.
    if matches!(
        request
            .uri()
            .path()
            .strip_prefix("/v2")
            .unwrap_or(request.uri().path()),
        "/shutdown" | "/retire"
    ) {
        return next.run(request).await;
    }
    let observation = match state.prepared_publication.observe() {
        Ok(observation) => observation,
        Err(reason) => return unavailable(reason),
    };
    let response = next.run(request).await;
    if let Some(permit) = response.extensions().get::<FinalizedResponsePermit>() {
        if Arc::ptr_eq(&permit.fence, &observation.fence) && permit.epoch > observation.epoch {
            return response;
        }
    }
    if !observation.current() {
        return unavailable(Refused::ObservationChanged);
    }
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Body::new(ObservedBody::new(body, observation)))
}

/// Covers body polling as well as handler completion: in particular an existing
/// graph/VFS SSE subscription wakes and ends on any pending epoch, even if that
/// operation completed before the subscriber is polled again.
struct ObservedBody {
    inner: Body,
    fence: Arc<ServingFence>,
    epoch: u64,
    changed: Pin<Box<dyn Future<Output = ()> + Send>>,
    ended: bool,
}

impl ObservedBody {
    fn new(inner: Body, observation: Observation) -> Self {
        let mut changes = observation.changes;
        Self {
            inner,
            fence: observation.fence,
            epoch: observation.epoch,
            changed: Box::pin(async move {
                let _ = changes.changed().await;
            }),
            ended: false,
        }
    }
}

impl http_body::Body for ObservedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        let _ = this.changed.as_mut().poll(cx); // Register wakeup even without graph events.
                                                // Keep the small control lock across the frame poll. A frame is either
                                                // observed before arm or refused; no graph frame is produced mid-arm.
        let control = this.fence.lock();
        if control.closing || control.active.is_some() || control.epoch != this.epoch {
            this.ended = true;
            return Poll::Ready(Some(Err(axum::Error::new(std::io::Error::other(
                "prepared publication observation changed; resubscribe after recovery",
            )))));
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.ended || self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
#[path = "prepared_publication_test.rs"]
pub(crate) mod tests;
