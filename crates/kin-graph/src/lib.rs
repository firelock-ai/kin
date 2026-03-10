//! KuzuDB-backed graph store for Kin semantic VCS.
//!
//! This crate is the sole owner of all Cypher queries.
//! External crates interact through the `GraphStore` trait
//! defined in `kin-model`.

pub mod error;
mod queries;
pub mod schema;
pub mod store;

pub use error::GraphError;
pub use store::KuzuGraphStore;
