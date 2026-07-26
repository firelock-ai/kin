// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-crate acceptance tests for current Kin repository authority.
//!
//! Pre-release compatibility suites that depended on the removed branch,
//! overlay, sidecar-object, and snapshot Git APIs are intentionally absent.
//! Exact repository-v6 init/branch/checkout/export behavior is covered at the
//! owning crate boundaries; this crate keeps only genuine cross-crate flows.

#[cfg(test)]
mod helpers;

#[cfg(test)]
mod p7_acceptance;

#[cfg(test)]
mod p8_acceptance;

#[cfg(test)]
mod never_drop;

#[cfg(test)]
mod p10_acceptance;

#[cfg(test)]
mod provenance_chain;

#[cfg(test)]
mod round_trip_fuzz;

#[cfg(test)]
mod concurrency_enforcement;
