// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end acceptance tests for Kin.
//!
//! These tests exercise the full vertical stack — from init through
//! parse/index/project to session coordination and review.
//!
//! Organization:
//! - V1 acceptance: sovereign init, parse+index, projection, branch+merge, context, review, git export
//! - Phase 7 acceptance: session lifecycle, intent collision, traffic-aware context, orphan sweep

#[cfg(test)]
mod helpers;

#[cfg(test)]
mod v1_acceptance;

#[cfg(test)]
mod p3_acceptance;

#[cfg(test)]
mod p7_acceptance;

#[cfg(test)]
mod p8_acceptance;

#[cfg(test)]
mod cross_file_relations;

#[cfg(test)]
mod p9_acceptance;

#[cfg(test)]
mod never_drop;

#[cfg(test)]
mod p10_acceptance;

#[cfg(test)]
mod p11_mutation_parity;

#[cfg(test)]
mod provenance_chain;

#[cfg(test)]
mod checkout_acceptance;

#[cfg(test)]
mod round_trip_fuzz;

#[cfg(test)]
mod concurrency_enforcement;
