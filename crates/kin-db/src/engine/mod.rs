mod graph;
pub mod incremental;
mod index;
mod traverse;

pub use graph::InMemoryGraph;
pub use incremental::{compute_diff, IncrementalDiff};
