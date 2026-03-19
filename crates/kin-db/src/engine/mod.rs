// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

mod graph;
pub mod incremental;
mod index;
mod traverse;

pub use graph::InMemoryGraph;
pub use incremental::{compute_diff, IncrementalDiff};
