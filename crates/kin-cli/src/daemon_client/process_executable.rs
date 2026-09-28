// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The executing image a daemon observed when publishing its own endpoint.
//! This is accidental-process attribution, not authentication of an owner-file
//! writer. Never enroll a legacy endpoint by inspecting its target at stop time.

use serde::{Deserialize, Serialize};
use std::io;
use std::time::Instant;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algorithm")]
pub(crate) enum ExecutableIdentity {
    #[serde(rename = "linux-proc-exe-sha256-v1")]
    LinuxProcExeSha256V1 {
        device: u64,
        inode: u64,
        sha256: String,
    },
    #[serde(rename = "macos-proc-execution-v1")]
    MacosProcExecutionV1 {
        main_executable_uuid: [u8; 16],
        process_unique_id: u64,
        pid_version: i32,
    },
}

impl ExecutableIdentity {
    #[cfg(any(unix, test))]
    pub(crate) fn validate(&self) -> io::Result<()> {
        let valid = match self {
            Self::LinuxProcExeSha256V1 { inode, sha256, .. } => {
                *inode != 0
                    && sha256.len() == 64
                    && sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            }
            Self::MacosProcExecutionV1 {
                main_executable_uuid,
                process_unique_id,
                ..
            } => *main_executable_uuid != [0; 16] && *process_unique_id != 0,
        };
        if valid {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published executable identity is unusable",
            ))
        }
    }
}

pub(crate) fn observe(pid: u32, deadline: Instant) -> io::Result<ExecutableIdentity> {
    check_deadline(deadline)?;
    #[cfg(target_os = "linux")]
    let image = linux::observe(pid, deadline)?;
    #[cfg(target_os = "macos")]
    let image = macos::observe(pid, deadline)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "executing-image observation is unavailable on this platform",
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        image.validate()?;
        check_deadline(deadline)?;
        Ok(image)
    }
}

/// The slowest rate an observation is budgeted to read an executing image at.
///
/// Linux hashes the whole image. Measured unloaded on one host, an optimized
/// build hashed about 540 MB/s and an unoptimized one about 28 MB/s, so each
/// floor leaves a wide margin for a loaded machine: a 126 MB release image
/// fits the ordinary minimum budget, and a debug image of a gigabyte or more,
/// which tests execute, is still observed rather than refused for its size.
#[cfg(target_os = "linux")]
const LOADED_IMAGE_READ_BYTES_PER_SEC: u64 = if cfg!(debug_assertions) {
    8 * 1024 * 1024
} else {
    32 * 1024 * 1024
};

/// How long an observation of `pid`'s executing image may take: `minimum`,
/// or longer for an image too large to read within it at a loaded machine's
/// rate. Only the budget is sized here; the identity the observation proves is
/// unchanged. Elsewhere than Linux observation reads no image, so `minimum`
/// stands.
pub(crate) fn observation_budget(pid: u32, minimum: std::time::Duration) -> std::time::Duration {
    #[cfg(target_os = "linux")]
    if let Ok(image) = std::fs::metadata(format!("/proc/{pid}/exe")) {
        return minimum.max(std::time::Duration::from_secs_f64(
            image.len() as f64 / LOADED_IMAGE_READ_BYTES_PER_SEC as f64,
        ));
    }
    let _ = pid;
    minimum
}

pub(crate) fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "executing-image observation exhausted the operation's deadline",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_expired_budget_refuses_before_observing_a_process() {
        assert_eq!(
            observe(std::process::id(), Instant::now())
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn macos_execution_version_is_opaque_including_zero_and_negative() {
        for pid_version in [0, -1, i32::MIN, i32::MAX] {
            ExecutableIdentity::MacosProcExecutionV1 {
                main_executable_uuid: [1; 16],
                process_unique_id: 1,
                pid_version,
            }
            .validate()
            .unwrap();
        }
    }
}
