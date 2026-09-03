// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! This process's open-file limit, and the one place Kin raises it.
//!
//! macOS ships every machine with an open-file soft limit of 256. That is
//! below what a single admission needs, so `kin init` on a stock Mac failed on
//! the first real repository a person tried, at step 9 of 17, with
//! `Too many open files (os error 24)`. The only Macs this project had ever
//! admitted on were tuned ones, which is why it went unseen.
//!
//! The demand is bounded and known. A write batch in the storage layer pins one
//! directory capability per digest prefix it writes into, each capability holds
//! two open directory descriptors, and there are 256 possible prefixes. So a
//! warmed batch costs 512 descriptors however large the repository is, and a
//! sweep of `kin init` on a 237-file, 2,287-commit repository measured that
//! exactly: it failed at soft limits 256, 384 and 512, and passed from 576 up,
//! peaking at 544 open files. The ceiling does not grow with the repository.
//! What decides it is how many of the 256 prefixes the batch touches, which is
//! why a six-file fixture passed on the same machine and a real repository did
//! not.
//!
//! So Kin raises its own soft limit at startup rather than asking the user to.
//! [`TARGET_OPEN_FILES`] is 10,240, the macOS `OPEN_MAX`, which leaves roughly
//! eighteen times the measured ceiling in reserve. The raise never lowers a
//! limit an operator already set higher, never touches the hard limit, which
//! would need privilege Kin does not have and should not want, and says nothing
//! when it works, because a limit that is now correct is not news.
//!
//! Windows has no `RLIMIT_NOFILE`. Its C runtime cap, `_setmaxstdio`, governs
//! CRT file descriptors, and Rust's file APIs use handles rather than those, so
//! there is nothing here for this module to raise and it is a no-op.

/// The open-file soft limit Kin raises toward.
///
/// 10,240 is `OPEN_MAX` on macOS, the value `kern.maxfilesperproc` defaults to
/// on a clean install, and comfortably above the 544 open files a full
/// admission was measured to peak at.
pub const TARGET_OPEN_FILES: u64 = 10_240;

/// A process's open-file limit, as a caller writing an error message needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFileLimit {
    /// The limit in force now.
    pub soft: u64,
    /// The ceiling the soft limit may be raised to without privilege, or
    /// `None` when the platform reports no ceiling at all.
    pub hard: Option<u64>,
}

#[cfg(unix)]
mod imp {
    use super::{OpenFileLimit, TARGET_OPEN_FILES};

    /// The soft limit to ask for, or `None` when the one in force is already at
    /// least as high as anything this would achieve.
    ///
    /// Separated from the syscalls so the decision is testable. Every path that
    /// would not improve the limit returns `None`, so a process an operator
    /// already tuned is left exactly as it was found.
    ///
    /// It lives inside this module rather than beside the public surface for a
    /// reason that cost a red main. `raise` is its only caller and `raise` is
    /// cfg-gated, so at the outer level this function was dead code on every
    /// platform without an `rlimit`, and the workspace builds with
    /// `-D warnings`. Windows found that; the pull request could not, because
    /// kin's Windows jobs do not run on a pull request. Keeping a helper inside
    /// the same cfg as its caller makes that class impossible rather than
    /// remembered.
    fn target_soft_limit(current: OpenFileLimit) -> Option<u64> {
        let ceiling = match current.hard {
            Some(hard) => hard.min(TARGET_OPEN_FILES),
            None => TARGET_OPEN_FILES,
        };
        (ceiling > current.soft).then_some(ceiling)
    }

    /// Read this process's open-file limit, or `None` when the kernel refuses
    /// to say.
    pub fn read() -> Option<OpenFileLimit> {
        // SAFETY: `getrlimit` fills a caller-owned `rlimit` this call owns for
        // its whole lifetime, and reads nothing else.
        let mut limits = unsafe { std::mem::zeroed::<libc::rlimit>() };
        let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) };
        if read != 0 {
            return None;
        }
        Some(OpenFileLimit {
            soft: limits.rlim_cur as u64,
            hard: (limits.rlim_max != libc::RLIM_INFINITY).then_some(limits.rlim_max as u64),
        })
    }

    /// Ask for `soft`, leaving the hard limit exactly as it was found.
    ///
    /// The hard limit is passed back unchanged rather than raised: raising it
    /// takes privilege, and a Kin that asked for privilege to read a repository
    /// would be a worse trade than a slow one.
    fn request(soft: u64, hard: libc::rlim_t) -> bool {
        let limits = libc::rlimit {
            rlim_cur: soft as libc::rlim_t,
            rlim_max: hard,
        };
        // SAFETY: `setrlimit` reads the caller-owned `rlimit` above and returns
        // a status. It cannot fail in a way that leaves this process's limit
        // partly applied; either the new pair is in force or the old one is.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) == 0 }
    }

    /// Raise the soft limit toward the hard limit, best effort.
    ///
    /// macOS refuses `RLIM_INFINITY` for this resource and refuses anything
    /// above `kern.maxfilesperproc`, which an administrator can lower. So a
    /// refusal is answered by halving the request and asking again rather than
    /// by giving up: the ladder bottoms out at the limit already in force, so
    /// the worst outcome is the limit this process started with, and a machine
    /// whose real ceiling sits between two rungs still gets the lower rung
    /// instead of nothing. Six attempts carry 10,240 down below 256.
    pub fn raise() {
        let Some(current) = read() else {
            return;
        };
        let Some(target) = target_soft_limit(current) else {
            return;
        };
        let hard = match current.hard {
            Some(hard) => hard as libc::rlim_t,
            None => libc::RLIM_INFINITY,
        };
        let mut candidate = target;
        while candidate > current.soft {
            if request(candidate, hard) {
                return;
            }
            candidate /= 2;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_stock_macos_limit_is_raised_to_the_target() {
            assert_eq!(
                target_soft_limit(OpenFileLimit {
                    soft: 256,
                    hard: None
                }),
                Some(TARGET_OPEN_FILES)
            );
        }

        #[test]
        fn a_hard_limit_below_the_target_caps_the_request() {
            assert_eq!(
                target_soft_limit(OpenFileLimit {
                    soft: 256,
                    hard: Some(4096)
                }),
                Some(4096)
            );
        }

        #[test]
        fn a_limit_an_operator_already_raised_is_left_alone() {
            assert_eq!(
                target_soft_limit(OpenFileLimit {
                    soft: 1_048_576,
                    hard: None
                }),
                None
            );
            assert_eq!(
                target_soft_limit(OpenFileLimit {
                    soft: TARGET_OPEN_FILES,
                    hard: Some(TARGET_OPEN_FILES)
                }),
                None
            );
        }

        /// A pinned hard limit is the case the error path exists for: nothing
        /// can be asked for, so nothing is.
        #[test]
        fn a_soft_limit_pinned_at_its_hard_limit_asks_for_nothing() {
            assert_eq!(
                target_soft_limit(OpenFileLimit {
                    soft: 256,
                    hard: Some(256)
                }),
                None
            );
        }

        /// The ladder must be able to reach the floor, or a machine with a low
        /// `kern.maxfilesperproc` would spin rather than settle.
        #[test]
        fn halving_from_the_target_reaches_the_default_macos_soft_limit() {
            let mut candidate = TARGET_OPEN_FILES;
            let mut steps = 0;
            while candidate > 256 {
                candidate /= 2;
                steps += 1;
            }
            assert!(steps <= 6, "the ladder took {steps} steps to pass 256");
        }

        /// Reading the limit is the input to every decision above, so a
        /// platform that cannot answer must be visible rather than assumed.
        #[test]
        fn this_process_reports_an_open_file_limit() {
            let limit = read().expect("read this process's open-file limit");
            assert!(limit.soft > 0, "a soft limit of zero cannot open a file");
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::OpenFileLimit;

    pub fn read() -> Option<OpenFileLimit> {
        None
    }

    pub fn raise() {}

    #[cfg(test)]
    mod tests {
        /// The no-op contract, asserted rather than assumed, because
        /// `kin_cli::open_files` renders its guidance from exactly these two
        /// answers: a limit of `None` prints the remedy with no limit line, and
        /// a raise that cannot panic is what lets it be called unconditionally
        /// at startup.
        #[test]
        fn a_platform_without_rlimit_reports_no_limit_and_raises_nothing() {
            super::raise();
            assert!(super::read().is_none());
        }
    }
}

/// Raise this process's open-file soft limit toward its hard limit.
///
/// Call once, early, while the process is still single-threaded, from every
/// binary a person runs. Silent on success and on failure alike: a failure is
/// not yet a problem, and the command that actually runs out of descriptors is
/// the one that can say so usefully.
pub fn raise_open_file_limit() {
    imp::raise();
}

/// This process's open-file limit as it stands now.
///
/// Read at the moment of failure rather than remembered from startup, so the
/// number in an error message is the number that was in force.
pub fn open_file_limit() -> Option<OpenFileLimit> {
    imp::read()
}

/// The margin between the target and what an admission was measured to need,
/// enforced at compile time.
///
/// 544 is the open-file peak of a full admission on a 237-file, 2,287-commit
/// repository, and it was the peak at every soft limit above the threshold
/// including 1,048,576, so it is a ceiling rather than a sample. Lowering
/// [`TARGET_OPEN_FILES`] below eight times it stops the build and says why.
///
/// A compile error rather than a test, because both sides are constants: there
/// is no runtime at which this could be false but a build in which it is true.
/// The peak is written in place rather than named as its own constant, because
/// dead-code analysis does not traverse an underscore-prefixed item, so a
/// constant used only here reads as unused under `-D warnings`.
const _TARGET_CLEARS_THE_MEASURED_ADMISSION_PEAK: () = {
    if TARGET_OPEN_FILES < 544 * 8 {
        panic!("TARGET_OPEN_FILES leaves less than eight times the measured admission peak");
    }
};
