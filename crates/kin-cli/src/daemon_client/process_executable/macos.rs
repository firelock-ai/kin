use std::io;
use std::time::Instant;

use super::{check_deadline, ExecutableIdentity};

const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

// Darwin's proc_uniqidentifierinfo ABI. Only the UUID, unique ID and PID version
// are identity inputs; the parent metadata and reserved tail stay opaque.
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info_private.h#L45
#[repr(C)]
#[derive(Default)]
struct ProcUniqueIdentifierInfo {
    main_executable_uuid: [u8; 16],
    process_unique_id: u64,
    _parent_unique_id: u64,
    pid_version: i32,
    _reserved0: u32,
    _reserved: [u64; 2],
}

const _: [(); 56] = [(); std::mem::size_of::<ProcUniqueIdentifierInfo>()];

pub(super) fn observe(pid: u32, deadline: Instant) -> io::Result<ExecutableIdentity> {
    check_deadline(deadline)?;
    let pid = libc::c_int::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process identifier"))?;
    let mut info = ProcUniqueIdentifierInfo::default();
    let copied = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            (&mut info as *mut ProcUniqueIdentifierInfo).cast(),
            std::mem::size_of::<ProcUniqueIdentifierInfo>() as libc::c_int,
        )
    };
    // Capture the query's errno before the deadline check or any other call.
    let error = (copied <= 0).then(io::Error::last_os_error);
    check_deadline(deadline)?;
    if let Some(error) = error {
        return Err(if error.raw_os_error() == Some(0) {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "macOS process executable query returned no data",
            )
        } else {
            error
        });
    }
    decode(info, copied)
}

fn decode(info: ProcUniqueIdentifierInfo, copied: libc::c_int) -> io::Result<ExecutableIdentity> {
    if usize::try_from(copied).ok() != Some(std::mem::size_of::<ProcUniqueIdentifierInfo>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS process executable query returned an incomplete or unsupported record",
        ));
    }
    if info.main_executable_uuid == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS process has no main executable UUID",
        ));
    }
    if info.process_unique_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS process has no unique process identifier",
        ));
    }
    Ok(ExecutableIdentity::MacosProcExecutionV1 {
        main_executable_uuid: info.main_executable_uuid,
        process_unique_id: info.process_unique_id,
        pid_version: info.pid_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn valid_info(pid_version: i32) -> ProcUniqueIdentifierInfo {
        ProcUniqueIdentifierInfo {
            main_executable_uuid: [0x42; 16],
            process_unique_id: 123,
            pid_version,
            ..ProcUniqueIdentifierInfo::default()
        }
    }

    #[test]
    fn rejects_incomplete_or_unsupported_query_records() {
        for copied in [-1, 0, 32, 55, 57] {
            let error = decode(valid_info(1), copied)
                .expect_err("an unexpected record size must not grant executable authority");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn rejects_an_absent_main_executable_uuid() {
        let mut info = valid_info(1);
        info.main_executable_uuid = [0; 16];
        let error =
            decode(info, 56).expect_err("a missing main executable UUID must not grant authority");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_an_absent_unique_process_identifier() {
        let mut info = valid_info(1);
        info.process_unique_id = 0;
        let error =
            decode(info, 56).expect_err("a missing process identifier must not grant authority");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn preserves_zero_and_negative_pid_versions() {
        for expected in [i32::MIN, -1, 0, 1, i32::MAX] {
            let observed = decode(valid_info(expected), 56).expect("PID versions are opaque");
            let ExecutableIdentity::MacosProcExecutionV1 {
                main_executable_uuid,
                process_unique_id,
                pid_version,
            } = observed
            else {
                panic!("macOS observation must have the macOS identity variant");
            };
            assert_eq!(main_executable_uuid, [0x42; 16]);
            assert_eq!(process_unique_id, 123);
            assert_eq!(pid_version, expected);
        }
    }

    #[test]
    fn observes_the_current_process_execution() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let first = observe(std::process::id(), deadline)
            .expect("the current test executable must have an observable execution identity");
        let second = observe(std::process::id(), deadline)
            .expect("the same execution must remain observable");
        let (
            ExecutableIdentity::MacosProcExecutionV1 {
                main_executable_uuid: first_uuid,
                process_unique_id: first_id,
                pid_version: first_version,
            },
            ExecutableIdentity::MacosProcExecutionV1 {
                main_executable_uuid: second_uuid,
                process_unique_id: second_id,
                pid_version: second_version,
            },
        ) = (first, second)
        else {
            panic!("macOS observations must have the macOS identity variant");
        };
        assert_ne!(first_uuid, [0; 16]);
        assert_ne!(first_id, 0);
        assert_eq!(first_uuid, second_uuid);
        assert_eq!(first_id, second_id);
        assert_eq!(first_version, second_version);
    }
}
