pub mod diff;
pub mod error;
pub mod format;
pub mod impact;
pub mod review;
pub mod risk;

pub use diff::{compute_diff, diff_from_change, EntityChange, EntityChangeKind, SemanticDiff};
pub use error::ReviewError;
pub use format::{format_diff, format_impact, format_review, format_risk_highlights};
pub use impact::{analyze_impact, ImpactReport};
pub use review::{Review, SemanticReview};
pub use risk::assess_risk;
