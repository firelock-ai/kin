//! Connection management for the sync protocol.
//!
//! Implements a state machine: Disconnected → Connecting → Connected → Syncing → Idle.
//! Handles auto-reconnection with exponential backoff, graceful degradation when the
//! connection drops (queuing local mutations for replay), and heartbeat health checks.

use crate::sync_types::{ConnectionState, LocalMutation};
use std::collections::VecDeque;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Reconnect policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            max_attempts: None, // unlimited
        }
    }
}

impl ReconnectPolicy {
    /// Compute the delay for a given attempt number using exponential backoff
    /// capped at `max_delay`.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let multiplier = 2u64.saturating_pow(attempt);
        let delay = self
            .base_delay
            .saturating_mul(multiplier as u32)
            .min(self.max_delay);
        delay
    }

    /// Returns `true` if we should attempt reconnection given the current
    /// attempt count.
    pub fn should_retry(&self, attempt: u32) -> bool {
        match self.max_attempts {
            Some(max) => attempt < max,
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Connection state machine
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ConnectionManager {
    state: ConnectionState,
    reconnect_policy: ReconnectPolicy,
    reconnect_attempts: u32,
    /// Mutations queued while disconnected, to replay on reconnect.
    queued_mutations: VecDeque<LocalMutation>,
}

impl ConnectionManager {
    pub fn new(policy: ReconnectPolicy) -> Self {
        Self {
            state: ConnectionState::Disconnected,
            reconnect_policy: policy,
            reconnect_attempts: 0,
            queued_mutations: VecDeque::new(),
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn reconnect_attempts(&self) -> u32 {
        self.reconnect_attempts
    }

    pub fn queued_mutation_count(&self) -> usize {
        self.queued_mutations.len()
    }

    // -- State transitions --------------------------------------------------

    /// Transition from Disconnected → Connecting.
    /// Returns an error string if the transition is invalid.
    pub fn begin_connect(&mut self) -> Result<(), &'static str> {
        if self.state != ConnectionState::Disconnected {
            return Err("can only begin_connect from Disconnected state");
        }
        self.state = ConnectionState::Connecting;
        Ok(())
    }

    /// Transition from Connecting → Connected.
    pub fn mark_connected(&mut self) -> Result<(), &'static str> {
        if self.state != ConnectionState::Connecting {
            return Err("can only mark_connected from Connecting state");
        }
        self.state = ConnectionState::Connected;
        self.reconnect_attempts = 0;
        Ok(())
    }

    /// Transition from Connected → Syncing.
    pub fn begin_sync(&mut self) -> Result<(), &'static str> {
        if self.state != ConnectionState::Connected && self.state != ConnectionState::Idle {
            return Err("can only begin_sync from Connected or Idle state");
        }
        self.state = ConnectionState::Syncing;
        Ok(())
    }

    /// Transition from Syncing → Idle.
    pub fn sync_complete(&mut self) -> Result<(), &'static str> {
        if self.state != ConnectionState::Syncing {
            return Err("can only sync_complete from Syncing state");
        }
        self.state = ConnectionState::Idle;
        Ok(())
    }

    /// Transition any active state → Disconnected (connection dropped).
    pub fn mark_disconnected(&mut self) {
        self.state = ConnectionState::Disconnected;
    }

    /// Attempt to transition Disconnected → Connecting with backoff.
    /// Returns `Some(delay)` if we should wait before connecting, or `None`
    /// if max attempts are exhausted.
    pub fn attempt_reconnect(&mut self) -> Option<Duration> {
        if self.state != ConnectionState::Disconnected {
            return None;
        }
        if !self.reconnect_policy.should_retry(self.reconnect_attempts) {
            return None;
        }
        let delay = self
            .reconnect_policy
            .delay_for_attempt(self.reconnect_attempts);
        self.reconnect_attempts += 1;
        self.state = ConnectionState::Connecting;
        Some(delay)
    }

    // -- Mutation queue (graceful degradation) ------------------------------

    /// Queue a mutation for replay when connection is restored.
    pub fn queue_mutation(&mut self, mutation: LocalMutation) {
        self.queued_mutations.push_back(mutation);
    }

    /// Drain all queued mutations for replay. Returns them in FIFO order.
    pub fn drain_queued_mutations(&mut self) -> Vec<LocalMutation> {
        self.queued_mutations.drain(..).collect()
    }

    /// Peek at queued mutations without draining.
    pub fn queued_mutations(&self) -> &VecDeque<LocalMutation> {
        &self.queued_mutations
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new(ReconnectPolicy::default())
    }
}
