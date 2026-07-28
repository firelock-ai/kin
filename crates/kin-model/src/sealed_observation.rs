// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Transaction binding for a sealed all-content observation.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Hash256, ModelError, Result};

pub const SEALED_OBSERVATION_BINDING_SCHEMA_VERSION: u32 = 1;

/// Authority binding supplied by the component that sealed an admitted
/// content closure.
///
/// This type proves only that the transaction names one exact observation and
/// binds its coverage summary into transaction identity. Repository storage
/// validates this shape but does not re-derive or verify the fingerprint:
/// enforcement remains the responsibility of the admission component that can
/// read the admitted closure and its graph-owned bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedObservationBinding {
    pub schema_version: u32,
    pub fingerprint: Hash256,
    pub observed_trees: u64,
    pub observed_entries: u64,
    pub sealed_bodies: u64,
    pub sealed_body_bytes: u64,
    pub opaque_bodies: u64,
    pub declared_exclusions: u64,
}

impl SealedObservationBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fingerprint: Hash256,
        observed_trees: u64,
        observed_entries: u64,
        sealed_bodies: u64,
        sealed_body_bytes: u64,
        opaque_bodies: u64,
        declared_exclusions: u64,
    ) -> Result<Self> {
        let binding = Self {
            schema_version: SEALED_OBSERVATION_BINDING_SCHEMA_VERSION,
            fingerprint,
            observed_trees,
            observed_entries,
            sealed_bodies,
            sealed_body_bytes,
            opaque_bodies,
            declared_exclusions,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validate only internally provable coverage relationships.
    ///
    /// The fingerprint itself is opaque at this boundary. Matching it against
    /// an admitted closure is intentionally outside kin-model and repository
    /// storage.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SEALED_OBSERVATION_BINDING_SCHEMA_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported sealed-observation binding version {}",
                self.schema_version
            )));
        }
        if self.observed_trees == 0 {
            return Err(ModelError::InvalidOperation(
                "sealed observation must cover at least one admitted tree".to_string(),
            ));
        }
        if self.declared_exclusions > self.observed_entries {
            return Err(ModelError::InvalidOperation(
                "sealed observation has more declared exclusions than observed entries".to_string(),
            ));
        }
        let included_entries = self.observed_entries - self.declared_exclusions;
        if self.sealed_bodies > included_entries {
            return Err(ModelError::InvalidOperation(
                "sealed observation has more sealed bodies than non-excluded observed entries"
                    .to_string(),
            ));
        }
        if self.opaque_bodies > self.sealed_bodies {
            return Err(ModelError::InvalidOperation(
                "sealed observation has more opaque bodies than sealed bodies".to_string(),
            ));
        }
        if self.sealed_bodies == 0 && self.sealed_body_bytes != 0 {
            return Err(ModelError::InvalidOperation(
                "sealed observation has body bytes but no sealed bodies".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SealedObservationBinding {
        SealedObservationBinding::new(Hash256::from_bytes([0x41; 32]), 3, 21, 7, 98, 1, 1).unwrap()
    }

    #[test]
    fn binding_round_trips_and_keeps_the_fingerprint_opaque() {
        let expected = binding();
        expected.validate().unwrap();
        let encoded = serde_json::to_vec(&expected).unwrap();
        let decoded: SealedObservationBinding = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn impossible_coverage_relationships_fail_closed() {
        let mut malformed = binding();
        malformed.schema_version = 2;
        assert_eq!(
            malformed.validate().unwrap_err().to_string(),
            "invalid operation: unsupported sealed-observation binding version 2"
        );

        malformed = binding();
        malformed.observed_trees = 0;
        assert_eq!(
            malformed.validate().unwrap_err().to_string(),
            "invalid operation: sealed observation must cover at least one admitted tree"
        );

        malformed = binding();
        malformed.declared_exclusions = malformed.observed_entries + 1;
        assert_eq!(
            malformed.validate().unwrap_err().to_string(),
            "invalid operation: sealed observation has more declared exclusions than observed entries"
        );

        malformed = binding();
        malformed.declared_exclusions = malformed.observed_entries - malformed.sealed_bodies + 1;
        assert_eq!(
            malformed.validate().unwrap_err().to_string(),
            "invalid operation: sealed observation has more sealed bodies than non-excluded observed entries"
        );

        malformed = binding();
        malformed.opaque_bodies = malformed.sealed_bodies + 1;
        assert_eq!(
            malformed.validate().unwrap_err().to_string(),
            "invalid operation: sealed observation has more opaque bodies than sealed bodies"
        );

        malformed = binding();
        malformed.sealed_bodies = 0;
        malformed.opaque_bodies = 0;
        assert_eq!(
            malformed.validate().unwrap_err().to_string(),
            "invalid operation: sealed observation has body bytes but no sealed bodies"
        );
    }

    #[test]
    fn zero_length_opaque_bodies_are_valid() {
        SealedObservationBinding::new(Hash256::from_bytes([0x42; 32]), 1, 1, 1, 0, 1, 0).unwrap();
    }
}
