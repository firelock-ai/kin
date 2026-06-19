// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_infer::resource::{Profile, ResourcePlan};

use crate::error::{MigrateError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourcePoolConfig {
    pub profile: Profile,
    pub logical_cores: usize,
    pub rayon_threads: usize,
    pub reserve_logical_cores: usize,
}

pub(crate) fn resource_pool_config_from_env() -> Result<Option<ResourcePoolConfig>> {
    let Some(profile) = resource_profile_from_env()? else {
        return Ok(None);
    };
    if profile == Profile::Proof {
        return Ok(None);
    }

    let plan = ResourcePlan::detect(profile);
    Ok(Some(ResourcePoolConfig {
        profile,
        logical_cores: plan.host.logical_cores,
        rayon_threads: plan.host.rayon_threads.max(1),
        reserve_logical_cores: plan.host.reserve_logical_cores,
    }))
}

pub(crate) fn proof_profile_requested() -> Result<bool> {
    Ok(matches!(resource_profile_from_env()?, Some(Profile::Proof)))
}

fn resource_profile_from_env() -> Result<Option<Profile>> {
    let Some(raw_profile) = std::env::var("KIN_RESOURCE_PROFILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };

    Ok(Some(parse_profile(&raw_profile)?))
}

pub(crate) fn with_resource_rayon_pool<T, F>(phase: &'static str, work: F) -> Result<T>
where
    T: Send,
    F: FnOnce() -> Result<T> + Send,
{
    let Some(config) = resource_pool_config_from_env()? else {
        return work();
    };

    tracing::info!(
        target: "kin.resource",
        phase,
        profile = ?config.profile,
        logical_cores = config.logical_cores,
        rayon_threads = config.rayon_threads,
        reserve_logical_cores = config.reserve_logical_cores,
        "using resource-plan Rayon pool"
    );

    rayon::ThreadPoolBuilder::new()
        .num_threads(config.rayon_threads)
        .thread_name(move |idx| format!("kin-migrate-{phase}-{idx}"))
        .build()
        .map_err(|error| {
            MigrateError::Other(format!("failed to build migrate Rayon pool: {error}"))
        })?
        .install(work)
}

fn parse_profile(raw: &str) -> Result<Profile> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => Ok(Profile::Interactive),
        "proof" => Ok(Profile::Proof),
        "interactive" => Ok(Profile::Interactive),
        "throughput" => Ok(Profile::Throughput),
        "ci" => Ok(Profile::Ci),
        other => Err(MigrateError::Other(format!(
            "unknown KIN_RESOURCE_PROFILE `{other}` (expected proof, interactive, throughput, or ci)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_profile_accepts_supported_modes() {
        assert_eq!(parse_profile("proof").unwrap(), Profile::Proof);
        assert_eq!(
            parse_profile(" interactive ").unwrap(),
            Profile::Interactive
        );
        assert_eq!(parse_profile("throughput").unwrap(), Profile::Throughput);
        assert_eq!(parse_profile("ci").unwrap(), Profile::Ci);
    }

    #[test]
    fn parse_profile_rejects_unknown_modes() {
        let error = parse_profile("turbo").unwrap_err().to_string();
        assert!(error.contains("unknown KIN_RESOURCE_PROFILE"));
    }
}
