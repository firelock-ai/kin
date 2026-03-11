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
