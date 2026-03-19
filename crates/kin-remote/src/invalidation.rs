// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

//! Invalidation channel: receives push notifications from KinHub.
//!
//! The channel is transport-agnostic via the `InvalidationTransport` trait,
//! supporting both WebSocket and SSE backends. Events are buffered when the
//! daemon is busy processing, and drained on demand.

use crate::sync_types::{ChannelEvent, StaleTracker};
use std::collections::VecDeque;
use thiserror::Error;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum InvalidationError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("channel closed")]
    ChannelClosed,
    #[error("buffer overflow: {buffered} events buffered, limit is {limit}")]
    BufferOverflow { buffered: usize, limit: usize },
}

/// A transport handle. The transport implementation writes events into the
/// provided `mpsc::Sender<ChannelEvent>`. When the transport is done it drops
/// the sender, which signals EOF to the channel.
pub struct TransportHandle {
    /// Sender that the transport writes events into.
    pub sender: mpsc::Sender<ChannelEvent>,
}

// ---------------------------------------------------------------------------
// InvalidationChannel
// ---------------------------------------------------------------------------

pub struct InvalidationChannel {
    receiver: mpsc::Receiver<ChannelEvent>,
    buffer: VecDeque<ChannelEvent>,
    buffer_limit: usize,
    stale_tracker: StaleTracker,
}

impl InvalidationChannel {
    /// Create a new channel and a `TransportHandle` that the transport backend
    /// uses to push events.
    pub fn new(buffer_limit: usize) -> (Self, TransportHandle) {
        let (tx, rx) = mpsc::channel(buffer_limit);
        let channel = Self {
            receiver: rx,
            buffer: VecDeque::new(),
            buffer_limit,
            stale_tracker: StaleTracker::new(),
        };
        let handle = TransportHandle { sender: tx };
        (channel, handle)
    }

    /// Receive the next event, blocking until one arrives.
    /// Returns `None` when the transport is closed.
    pub async fn recv(&mut self) -> Option<ChannelEvent> {
        // Drain from internal buffer first.
        if let Some(event) = self.buffer.pop_front() {
            return Some(event);
        }
        self.receiver.recv().await
    }

    /// Non-blocking: drain all currently available events into the internal
    /// buffer and return a slice view of the buffer.
    pub fn drain_available(&mut self) -> &VecDeque<ChannelEvent> {
        while let Ok(event) = self.receiver.try_recv() {
            if self.buffer.len() < self.buffer_limit {
                self.buffer.push_back(event);
            }
            // If buffer is full we drop the event — back-pressure.
        }
        &self.buffer
    }

    /// Buffer an event for later processing (e.g. when the daemon is busy).
    pub fn buffer_event(&mut self, event: ChannelEvent) -> Result<(), InvalidationError> {
        if self.buffer.len() >= self.buffer_limit {
            return Err(InvalidationError::BufferOverflow {
                buffered: self.buffer.len(),
                limit: self.buffer_limit,
            });
        }
        self.buffer.push_back(event);
        Ok(())
    }

    /// Process an event: update the stale tracker based on its contents.
    pub fn process_event(&mut self, event: &ChannelEvent) {
        match event {
            ChannelEvent::EntityInvalidated(inv) | ChannelEvent::RelationInvalidated(inv) => {
                self.stale_tracker.mark_stale(inv.clone());
            }
            ChannelEvent::IntentLockAcquired(_) | ChannelEvent::IntentLockReleased { .. } => {
                // Intent locks don't mark entities as stale by themselves.
            }
        }
    }

    /// Receive and immediately process the next event.
    pub async fn recv_and_process(&mut self) -> Option<ChannelEvent> {
        let event = self.recv().await?;
        self.process_event(&event);
        Some(event)
    }

    pub fn stale_tracker(&self) -> &StaleTracker {
        &self.stale_tracker
    }

    pub fn stale_tracker_mut(&mut self) -> &mut StaleTracker {
        &mut self.stale_tracker
    }

    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }
}
