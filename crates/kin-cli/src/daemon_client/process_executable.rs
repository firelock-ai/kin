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
