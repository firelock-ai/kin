// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A language server's process and every process it starts, owned as one.
//!
//! A language server is rarely one process. typescript-language-server runs
//! two tsserver processes as its children and one of those runs a typings
//! installer; rust-analyzer runs cargo and a proc-macro server; gopls runs the
//! go command. Ending only the process this crate started leaves the rest to
//! notice on their own, and they do not reliably: after kin-bench proof daemons
//! stopped, 19 tsserver processes of 50 to 115 MB each were still running with
//! init as their parent 20 to 40 minutes later.
//!
//! So a server starts as the leader of a new process group, which everything
//! it starts inherits, and every way this crate lets go of it ends the group:
//!
//! - [`ServerProcess::terminate`] is the deliberate stop. It sends SIGTERM to
//!   the group, then SIGKILL to whatever is still in it after
//!   [`TERMINATION_GRACE`].
//! - Dropping a [`ServerProcess`] that was not terminated sends SIGKILL to the
//!   group at once, which is what `kill_on_drop` did for the leader alone.
//! - An owner that dies without doing either, because it was killed, crashed or
//!   force-exited, runs no code on the way out. For that, a watcher process
//!   blocks reading a pipe whose only write end the owner holds. The kernel
//!   closes that write end when the owner ends, however it ends, so the read
//!   returns and the watcher sends the group the same SIGTERM, grace and
//!   SIGKILL. macOS has no `PR_SET_PDEATHSIG`, and a pipe that reaches
//!   end-of-file when its writer dies is the death notice both platforms give.
//!
//! Windows keeps `kill_on_drop` on the leader alone.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

/// How long a language server's process group has to exit after SIGTERM
/// before whatever is left of it is sent SIGKILL.
///
/// Short, because Kin keeps nothing in a language server worth waiting for,
/// and a daemon stops every server it holds out of one bounded shutdown budget.
/// Whole seconds, because the watcher's shell counts it with `sleep 1`.
pub const TERMINATION_GRACE: Duration = Duration::from_secs(2);

/// How often a stop checks whether the group has emptied.
#[cfg(unix)]
const GROUP_POLL: Duration = Duration::from_millis(20);

/// How long a stop waits for SIGKILL to finish the group before it gives up
/// and says what is left.
#[cfg(unix)]
const KILL_SETTLE: Duration = Duration::from_secs(1);

/// The watcher, run by `/bin/sh` with the server's process group as `$1` and
/// the grace in whole seconds as `$2`.
///
/// `read` returns only when every write end of stdin is closed, and the owner
/// holds the only one. The group check between sleeps lets a group that took
/// SIGTERM release the watcher at once rather than after the whole grace.
#[cfg(unix)]
const WATCHER_SCRIPT: &str = r#"read -r ignored
kill -s TERM -- "-$1" 2>/dev/null || exit 0
i=0
while [ "$i" -lt "$2" ]; do
  sleep 1
  kill -s 0 -- "-$1" 2>/dev/null || exit 0
  i=$((i + 1))
done
kill -s KILL -- "-$1" 2>/dev/null
exit 0
"#;

/// A running language server: the process this crate started and, on Unix,
/// the process group it leads.
pub(crate) struct ServerProcess {
    child: Child,
    /// The group's id, which is the leader's pid.
    #[cfg(unix)]
    group: libc::pid_t,
    /// `None` when the watcher could not be started; a stop and a drop still
    /// end the group.
    #[cfg(unix)]
    watcher: Option<GroupWatcher>,
    /// Set once this process has finished signalling the group: the group was
    /// seen empty, or a stop has sent everything it sends. An empty group's id
    /// is free for the system to hand out again, so nothing signals it after.
    #[cfg(unix)]
    done: bool,
}

impl ServerProcess {
    /// Start `command` with piped stdio, as the leader of a new process group.
    pub(crate) fn spawn(mut command: Command) -> std::io::Result<Self> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The whole mechanism on Windows. On Unix it also hands a leader
            // that outlived its drop to tokio, which reaps it.
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let child = command.spawn()?;

        #[cfg(unix)]
        {
            // A group id of 0 or 1 would turn every signal below into one sent
            // to this process's own group or to every process it may signal.
            // A child's pid is never either, and this makes that a checked fact.
            let group = child
                .id()
                .and_then(|pid| libc::pid_t::try_from(pid).ok())
                .filter(|pid| *pid > 1)
                .ok_or_else(|| std::io::Error::other("the server started without a usable pid"))?;
            let watcher = match GroupWatcher::spawn(group) {
                Ok(watcher) => Some(watcher),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        group,
                        "could not start the watcher that ends this language server's \
                         process group if this process dies; a stop or a drop still ends it"
                    );
                    None
                }
            };
            Ok(Self {
                child,
                group,
                watcher,
                done: false,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { child })
        }
    }

    /// The leader's pid, which is also the group's id.
    #[cfg(unix)]
    pub(crate) fn leader_pid(&self) -> libc::pid_t {
        self.group
    }

    /// The server's stdin, stdout and stderr, each available once.
    pub(crate) fn take_stdio(
        &mut self,
    ) -> (Option<ChildStdin>, Option<ChildStdout>, Option<ChildStderr>) {
        (
            self.child.stdin.take(),
            self.child.stdout.take(),
            self.child.stderr.take(),
        )
    }

    /// How the server's own process ended, once it has. `None` while it is
    /// still running.
    ///
    /// On Unix this reads the status without reaping the leader. Its pid is
    /// the group's id, and an unreaped leader is still a member that keeps the
    /// id reserved, so the stop [`Self::terminate`] sends afterwards reaches
    /// this group and no other. Reaping here would free the id before that
    /// signal: a leader that died alone leaves an empty group, and a new
    /// process could be handed its id. `terminate` reaps it after signalling.
    pub(crate) fn exit_status(&mut self) -> Option<std::process::ExitStatus> {
        #[cfg(unix)]
        {
            match exit_without_reaping(self.group) {
                Ok(status) => status,
                // Not this process's child to wait on any more: already
                // reaped, in which case the handle kept the status and asking
                // it reaps nothing.
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                    self.child.try_wait().ok().flatten()
                }
                Err(_) => None,
            }
        }
        #[cfg(not(unix))]
        {
            self.child.try_wait().ok().flatten()
        }
    }

    /// Stop the server and everything it started: SIGTERM to the group, then
    /// SIGKILL to whatever is left after [`TERMINATION_GRACE`].
    ///
    /// Returns once the group is empty, or once SIGKILL has had a further
    /// second to empty it.
    pub(crate) async fn terminate(mut self) {
        #[cfg(unix)]
        {
            signal_group(self.group, libc::SIGTERM);
            if !self.wait_for_empty_group(TERMINATION_GRACE).await {
                signal_group(self.group, libc::SIGKILL);
                if !self.wait_for_empty_group(KILL_SETTLE).await {
                    tracing::warn!(
                        group = self.group,
                        "a language server's process group still has members after SIGKILL"
                    );
                }
            }
            self.done = true;
            if let Some(watcher) = self.watcher.take() {
                watcher.stand_down().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.start_kill();
            let _ = tokio::time::timeout(TERMINATION_GRACE, self.child.wait()).await;
        }
    }

    /// Whether the group empties within `budget`.
    #[cfg(unix)]
    async fn wait_for_empty_group(&mut self, budget: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            // Reap the leader as soon as it exits. Until it is reaped it is
            // still a member of its group and reads as a survivor.
            let _ = self.child.try_wait();
            if group_is_empty(self.group) {
                self.done = true;
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(GROUP_POLL).await;
        }
    }
}

#[cfg(unix)]
impl Drop for ServerProcess {
    fn drop(&mut self) {
        // A group's id is not handed out again while the group has a member,
        // so short of the group emptying in the instant before this runs, this
        // reaches only this server's processes.
        if !self.done {
            signal_group(self.group, libc::SIGKILL);
        }
    }
}

/// The process that ends a server's group when its owner dies.
#[cfg(unix)]
struct GroupWatcher {
    // Declared first so it drops first: a watcher killed before its pipe closes
    // never mistakes the close for its owner's death.
    process: Child,
    // Never written. Holding it open is the whole message.
    _lifeline: ChildStdin,
}

#[cfg(unix)]
impl GroupWatcher {
    fn spawn(group: libc::pid_t) -> std::io::Result<Self> {
        let mut process = Command::new("/bin/sh")
            .arg("-c")
            .arg(WATCHER_SCRIPT)
            .arg("kin-lsp-group-watcher")
            .arg(group.to_string())
            .arg(TERMINATION_GRACE.as_secs().to_string())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Its own group, so a signal aimed at the owner's group, a
            // terminal's Ctrl-C for one, cannot end it before it has acted.
            .process_group(0)
            .kill_on_drop(true)
            .spawn()?;
        let lifeline = process
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("the watcher's stdin was not captured"))?;
        Ok(Self {
            process,
            _lifeline: lifeline,
        })
    }

    /// End the watcher without letting it act, once the group it guards is
    /// already gone.
    async fn stand_down(mut self) {
        let _ = self.process.start_kill();
        let _ = tokio::time::timeout(KILL_SETTLE, self.process.wait()).await;
    }
}

/// Send `signal` to every process in `group`. ESRCH, the only failure for a
/// group this process created, means the group has already emptied.
#[cfg(unix)]
fn signal_group(group: libc::pid_t, signal: libc::c_int) {
    // SAFETY: `kill` takes no pointers. `group` is a started child's pid,
    // checked above 1, so `-group` names exactly that process group.
    unsafe {
        libc::kill(-group, signal);
    }
}

/// How the child `pid` ended, read with `WNOWAIT` so it stays waitable, or
/// `None` while it is still running.
#[cfg(unix)]
fn exit_without_reaping(pid: libc::pid_t) -> std::io::Result<Option<std::process::ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;

    // SAFETY: `info` is zeroed and the call writes only into it. Zeroing is
    // also how WNOHANG's "nothing to report" is told apart: si_pid stays 0.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let (code, reported, status) = child_status_parts(&info);
    if reported == 0 {
        return Ok(None);
    }
    // Rebuilt in the wait-status encoding `ExitStatus` reads on both Linux and
    // macOS: an exit code in the second byte, a signal in the low seven bits,
    // and 0x80 for a core dump.
    Ok(match code {
        libc::CLD_EXITED => Some(std::process::ExitStatus::from_raw((status & 0xff) << 8)),
        libc::CLD_KILLED => Some(std::process::ExitStatus::from_raw(status & 0x7f)),
        libc::CLD_DUMPED => Some(std::process::ExitStatus::from_raw((status & 0x7f) | 0x80)),
        _ => None,
    })
}

/// The code, pid and status a child-status `siginfo_t` carries.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn child_status_parts(info: &libc::siginfo_t) -> (libc::c_int, libc::pid_t, libc::c_int) {
    // SAFETY: waitid filled a child-status siginfo, which sets these fields.
    unsafe { (info.si_code, info.si_pid(), info.si_status()) }
}

/// The code, pid and status a child-status `siginfo_t` carries.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn child_status_parts(info: &libc::siginfo_t) -> (libc::c_int, libc::pid_t, libc::c_int) {
    (info.si_code, info.si_pid, info.si_status)
}

/// Whether no process is left in `group`.
#[cfg(unix)]
fn group_is_empty(group: libc::pid_t) -> bool {
    // SAFETY: as in `signal_group`; signal 0 only asks whether any member exists.
    let result = unsafe { libc::kill(-group, 0) };
    result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}
