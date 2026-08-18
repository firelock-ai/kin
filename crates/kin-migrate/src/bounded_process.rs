// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded, tree-contained execution for migration metadata subprocesses.
//!
//! Stdout and stderr are actively drained into byte-bounded in-memory sinks.
//! Readers keep draining and discard bytes after the ceiling, so a runaway
//! writer cannot grow memory or disk while the launcher notices the overflow.
//! Descendants are terminated before the launcher waits a bounded interval for
//! reader EOF. Unix children join a stable parent-death guardian's process
//! group; Windows probes are created suspended, assigned to a kill-on-close Job
//! Object, and only then resumed.

use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const REAP_GRACE: Duration = Duration::from_secs(5);
const TRUNCATION_MARKER: &[u8] = b"\n[output truncated at capture limit]\n";

/// Execute a command that its caller has already finalized and scrubbed.
///
/// Callers must make this the immediate next operation after their authority
/// boundary. This function installs owned stdio before spawning; on Windows the
/// containment spawn also adds `CREATE_SUSPENDED` until Job ownership is bound.
pub(crate) fn output_finalized_with_timeout_and_limit(
    process_host: &crate::MigrationProcessHost,
    mut command: Command,
    label: &str,
    timeout: Duration,
    max_capture_bytes_per_stream: u64,
) -> std::io::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let (mut child, mut tree) = ProbeProcessTree::spawn(process_host, command)?;
    let capture = match BoundedCapturePair::start(&mut child, max_capture_bytes_per_stream, label) {
        Ok(capture) => capture,
        Err(error) => {
            let cleanup = terminate_tree_and_reap(child, tree, label);
            return Err(contextual_io(
                error,
                format!(
                    "start {label} bounded capture; cleanup={}",
                    render_result(&cleanup)
                ),
            ));
        }
    };
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(event) = capture.try_event() {
            match event {
                CaptureEvent::LimitExceeded { stream } => {
                    let cleanup = terminate_tree_and_reap(child, tree, label);
                    let captured = capture.finish_until(Instant::now() + REAP_GRACE);
                    return Err(contextual_io(
                        capture_limit_error(
                            label,
                            max_capture_bytes_per_stream,
                            cleanup,
                            &captured,
                        ),
                        format!("{stream} capture crossed its bounded sink"),
                    ));
                }
                CaptureEvent::ReadFailed { stream, error } => {
                    let cleanup = terminate_tree_and_reap(child, tree, label);
                    let captured = capture.finish_until(Instant::now() + REAP_GRACE);
                    return Err(std::io::Error::other(format!(
                        "read {label} {stream} capture: {error}; cleanup={}; capture={}",
                        render_result(&cleanup),
                        captured.render_errors(),
                    )));
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let cleanup = terminate_descendants(&mut tree, label);
                let captured = capture.finish_until(Instant::now() + REAP_GRACE);
                cleanup?;
                if captured.any_truncated() {
                    return Err(capture_limit_error(
                        label,
                        max_capture_bytes_per_stream,
                        Ok(()),
                        &captured,
                    ));
                }
                if let Some(error) = captured.first_error() {
                    return Err(std::io::Error::other(format!(
                        "read {label} bounded capture: {error}"
                    )));
                }
                return Ok(captured.into_output(status));
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Ok(None) => {
                let cleanup = terminate_tree_and_reap(child, tree, label);
                let captured = capture.finish_until(Instant::now() + REAP_GRACE);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "{label} timed out after {timeout:?}; cleanup={}; capture={}; stdout={} \
                         stderr={}",
                        render_result(&cleanup),
                        captured.render_errors(),
                        compact_capture(&captured.stdout),
                        compact_capture(&captured.stderr),
                    ),
                ));
            }
            Err(error) => {
                let cleanup = terminate_tree_and_reap(child, tree, label);
                let captured = capture.finish_until(Instant::now() + REAP_GRACE);
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "poll {label}: {error}; cleanup={}; capture={}",
                        render_result(&cleanup),
                        captured.render_errors(),
                    ),
                ));
            }
        }
    }
}

#[derive(Debug)]
enum CaptureEvent {
    LimitExceeded { stream: &'static str },
    ReadFailed { stream: &'static str, error: String },
}

struct BoundedCapturePair {
    events: mpsc::Receiver<CaptureEvent>,
    stdout: BoundedCaptureReader,
    stderr: BoundedCaptureReader,
}

impl BoundedCapturePair {
    fn start(
        child: &mut Child,
        max_capture_bytes_per_stream: u64,
        label: &str,
    ) -> std::io::Result<Self> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other(format!("{label} stdout was not piped")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other(format!("{label} stderr was not piped")))?;
        let (events_tx, events) = mpsc::channel();
        let stdout = BoundedCaptureReader::spawn(
            stdout,
            "stdout",
            max_capture_bytes_per_stream,
            events_tx.clone(),
        )?;
        let stderr =
            BoundedCaptureReader::spawn(stderr, "stderr", max_capture_bytes_per_stream, events_tx)?;
        Ok(Self {
            events,
            stdout,
            stderr,
        })
    }

    fn try_event(&self) -> Option<CaptureEvent> {
        self.events.try_recv().ok()
    }

    fn finish_until(self, deadline: Instant) -> CapturedStreams {
        CapturedStreams {
            stdout: self.stdout.finish_until(deadline),
            stderr: self.stderr.finish_until(deadline),
        }
    }
}

struct BoundedCaptureReader {
    stream: &'static str,
    result: Option<mpsc::Receiver<CapturedBytes>>,
    thread: Option<std::thread::JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
}

impl BoundedCaptureReader {
    fn spawn<R>(
        reader: R,
        stream: &'static str,
        max_capture_bytes: u64,
        events: mpsc::Sender<CaptureEvent>,
    ) -> std::io::Result<Self>
    where
        R: CapturePipe,
    {
        reader.prepare_nonblocking()?;
        let (result_tx, result) = mpsc::sync_channel(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let reader_cancel = Arc::clone(&cancel);
        let thread = std::thread::Builder::new()
            .name(format!("kin-capture-{stream}"))
            .spawn(move || {
                let captured = drain_bounded_stream(
                    reader,
                    stream,
                    max_capture_bytes,
                    &events,
                    &reader_cancel,
                );
                let _ = result_tx.send(captured);
            })?;
        Ok(Self {
            stream,
            result: Some(result),
            thread: Some(thread),
            cancel,
        })
    }

    fn finish_until(mut self, deadline: Instant) -> CapturedBytes {
        let result = self
            .result
            .as_ref()
            .expect("bounded capture result receiver remains owned");
        let wait = deadline.saturating_duration_since(Instant::now());
        let (capture, acknowledged) = match result.recv_timeout(wait) {
            Ok(captured) => (Some(captured), true),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.cancel.store(true, Ordering::Release);
                if let Some(thread) = &self.thread {
                    thread.thread().unpark();
                }
                match result.recv_timeout(POLL_INTERVAL.saturating_mul(2)) {
                    Ok(captured) => (Some(captured), true),
                    Err(mpsc::RecvTimeoutError::Disconnected) => (None, true),
                    Err(mpsc::RecvTimeoutError::Timeout) => (None, false),
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => (None, true),
        };
        self.result.take();
        let joined = acknowledged
            && self
                .thread
                .take()
                .expect("bounded capture reader thread remains owned")
                .join()
                .is_ok();
        match (capture, joined) {
            (Some(captured), true) => captured,
            (Some(mut captured), false) => {
                captured.error = Some(format!("{} capture reader panicked", self.stream));
                captured
            }
            (None, _) => CapturedBytes::failed(format!(
                "{} capture reader did not return a result before its cancellation deadline",
                self.stream
            )),
        }
    }
}

impl Drop for BoundedCaptureReader {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
        let acknowledged = self.result.as_ref().is_some_and(|result| {
            !matches!(
                result.recv_timeout(POLL_INTERVAL.saturating_mul(2)),
                Err(mpsc::RecvTimeoutError::Timeout)
            )
        });
        self.result.take();
        if acknowledged {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

enum PipeRead {
    Data(usize),
    Pending,
    Eof,
}

trait CapturePipe: std::io::Read + Send + 'static {
    fn prepare_nonblocking(&self) -> std::io::Result<()>;
    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<PipeRead>;
}

macro_rules! impl_capture_pipe {
    ($pipe:ty) => {
        impl CapturePipe for $pipe {
            fn prepare_nonblocking(&self) -> std::io::Result<()> {
                prepare_capture_pipe(self)
            }

            fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<PipeRead> {
                read_capture_pipe(self, buffer)
            }
        }
    };
}

impl_capture_pipe!(std::process::ChildStdout);
impl_capture_pipe!(std::process::ChildStderr);

#[cfg(unix)]
fn prepare_capture_pipe(pipe: &(impl std::os::fd::AsRawFd + ?Sized)) -> std::io::Result<()> {
    let descriptor = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(contextual_io(
            std::io::Error::last_os_error(),
            "inspect bounded capture pipe flags".to_string(),
        ));
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(contextual_io(
            std::io::Error::last_os_error(),
            "make bounded capture pipe nonblocking".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_capture_pipe(
    pipe: &mut impl std::io::Read,
    buffer: &mut [u8],
) -> std::io::Result<PipeRead> {
    match pipe.read(buffer) {
        Ok(0) => Ok(PipeRead::Eof),
        Ok(read) => Ok(PipeRead::Data(read)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(PipeRead::Pending),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn prepare_capture_pipe(
    _pipe: &(impl std::os::windows::io::AsRawHandle + ?Sized),
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn read_capture_pipe(
    pipe: &mut (impl std::io::Read + std::os::windows::io::AsRawHandle),
    buffer: &mut [u8],
) -> std::io::Result<PipeRead> {
    use windows_sys::Win32::Foundation::{
        ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED,
    };
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    let mut available = 0_u32;
    let peeked = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle().cast(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if peeked == 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED) => Ok(PipeRead::Eof),
            _ => Err(error),
        };
    }
    if available == 0 {
        return Ok(PipeRead::Pending);
    }
    let available = usize::try_from(available).unwrap_or(usize::MAX);
    let request = buffer.len().min(available);
    match pipe.read(&mut buffer[..request]) {
        Ok(0) => Ok(PipeRead::Eof),
        Ok(read) => Ok(PipeRead::Data(read)),
        Err(error)
            if error.kind() == std::io::ErrorKind::BrokenPipe
                || matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
                ) =>
        {
            Ok(PipeRead::Eof)
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(any(unix, windows)))]
fn prepare_capture_pipe<T: ?Sized>(_pipe: &T) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_capture_pipe(
    pipe: &mut impl std::io::Read,
    buffer: &mut [u8],
) -> std::io::Result<PipeRead> {
    match pipe.read(buffer)? {
        0 => Ok(PipeRead::Eof),
        read => Ok(PipeRead::Data(read)),
    }
}

#[derive(Default)]
struct CapturedBytes {
    bytes: Vec<u8>,
    truncated: bool,
    observed_bytes: u64,
    peak_buffered_bytes: usize,
    error: Option<String>,
}

impl CapturedBytes {
    fn failed(error: String) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }
}

struct CapturedStreams {
    stdout: CapturedBytes,
    stderr: CapturedBytes,
}

impl CapturedStreams {
    fn any_truncated(&self) -> bool {
        self.stdout.truncated || self.stderr.truncated
    }

    fn first_error(&self) -> Option<&str> {
        self.stdout
            .error
            .as_deref()
            .or(self.stderr.error.as_deref())
    }

    fn render_errors(&self) -> String {
        match (self.stdout.error.as_deref(), self.stderr.error.as_deref()) {
            (None, None) => "ok".to_string(),
            (stdout, stderr) => format!(
                "stdout={}; stderr={}",
                stdout.unwrap_or("ok"),
                stderr.unwrap_or("ok")
            ),
        }
    }

    fn into_output(self, status: ExitStatus) -> Output {
        Output {
            status,
            stdout: self.stdout.bytes,
            stderr: self.stderr.bytes,
        }
    }
}

fn drain_bounded_stream<R: CapturePipe>(
    mut reader: R,
    stream: &'static str,
    max_capture_bytes: u64,
    events: &mpsc::Sender<CaptureEvent>,
    cancel: &AtomicBool,
) -> CapturedBytes {
    let max_buffered = usize::try_from(max_capture_bytes).unwrap_or(usize::MAX);
    let mut captured = CapturedBytes {
        bytes: Vec::with_capacity(max_buffered.min(64 * 1024)),
        ..CapturedBytes::default()
    };
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        if cancel.load(Ordering::Acquire) {
            captured.error = Some(format!("{stream} capture cancelled before EOF"));
            break;
        }
        let read = match reader.read_available(&mut chunk) {
            Ok(PipeRead::Eof) => break,
            Ok(PipeRead::Pending) => {
                std::thread::park_timeout(POLL_INTERVAL);
                continue;
            }
            Ok(PipeRead::Data(read)) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let error = error.to_string();
                captured.error = Some(error.clone());
                let _ = events.send(CaptureEvent::ReadFailed { stream, error });
                break;
            }
        };
        retain_bounded_chunk(&mut captured, &chunk[..read], max_buffered, stream, events);
        if cancel.load(Ordering::Acquire) {
            captured.error = Some(format!("{stream} capture cancelled before EOF"));
            break;
        }
    }
    if captured.truncated {
        if max_buffered >= TRUNCATION_MARKER.len() {
            captured
                .bytes
                .truncate(max_buffered - TRUNCATION_MARKER.len());
            captured.bytes.extend_from_slice(TRUNCATION_MARKER);
        } else {
            captured.bytes.truncate(max_buffered);
        }
    }
    captured
}

fn retain_bounded_chunk(
    captured: &mut CapturedBytes,
    chunk: &[u8],
    max_buffered: usize,
    stream: &'static str,
    events: &mpsc::Sender<CaptureEvent>,
) {
    captured.observed_bytes = captured
        .observed_bytes
        .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
    let remaining = max_buffered.saturating_sub(captured.bytes.len());
    let retained = remaining.min(chunk.len());
    captured.bytes.extend_from_slice(&chunk[..retained]);
    captured.peak_buffered_bytes = captured.peak_buffered_bytes.max(captured.bytes.len());
    if retained < chunk.len() && !captured.truncated {
        captured.truncated = true;
        let _ = events.send(CaptureEvent::LimitExceeded { stream });
    }
}

fn capture_limit_error(
    label: &str,
    max_capture_bytes_per_stream: u64,
    cleanup: std::io::Result<()>,
    captured: &CapturedStreams,
) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "{label} exceeded the {max_capture_bytes_per_stream}-byte per-stream capture limit \
             (stdout={}, stderr={}; peak-buffered stdout={}, stderr={}); cleanup={}; capture={}; \
             stdout={} stderr={}",
            captured.stdout.observed_bytes,
            captured.stderr.observed_bytes,
            captured.stdout.peak_buffered_bytes,
            captured.stderr.peak_buffered_bytes,
            render_result(&cleanup),
            captured.render_errors(),
            compact_capture(&captured.stdout),
            compact_capture(&captured.stderr),
        ),
    )
}

fn compact_capture(capture: &CapturedBytes) -> String {
    const MAX_BYTES: usize = 400;
    let prefix = &capture.bytes[..capture.bytes.len().min(MAX_BYTES)];
    let mut rendered = String::from_utf8_lossy(prefix).trim().to_string();
    if capture.bytes.len() > MAX_BYTES || capture.truncated {
        rendered.push_str("...");
    }
    if let Some(error) = &capture.error {
        if !rendered.is_empty() {
            rendered.push(' ');
        }
        rendered.push_str("[capture error: ");
        rendered.push_str(error);
        rendered.push(']');
    }
    if rendered.is_empty() {
        "<empty>".to_string()
    } else {
        rendered
    }
}

fn poll_child_until(
    child: &mut Child,
    deadline: Instant,
    label: &str,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| contextual_io(error, format!("poll {label} during cleanup")))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn confirm_tree_empty_until(
    tree: &mut ProbeProcessTree,
    deadline: Instant,
    label: &str,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        return tree.confirm_empty_until(deadline, label);
    }

    #[cfg(not(unix))]
    loop {
        if tree.is_empty()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{label} containment remained live after termination"),
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn terminate_descendants(tree: &mut ProbeProcessTree, label: &str) -> std::io::Result<()> {
    let terminate = tree.terminate();
    let empty = confirm_tree_empty_until(tree, Instant::now() + REAP_GRACE, label);
    let auxiliary_reap = reap_auxiliary_after_confirmed_empty(tree, &empty, label);
    combine_cleanup(terminate, Ok(()), empty, auxiliary_reap)
}

fn terminate_tree_and_reap(
    mut child: Child,
    mut tree: ProbeProcessTree,
    label: &str,
) -> std::io::Result<()> {
    let terminate = tree.terminate();
    let direct_kill = match child.kill() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        Err(error) => Err(contextual_io(error, format!("kill direct {label} process"))),
    };
    let direct_status = poll_child_until(&mut child, Instant::now() + REAP_GRACE, label);
    #[cfg(unix)]
    let direct_reaped = matches!(&direct_status, Ok(Some(_)));
    let reap = match direct_status {
        Ok(Some(_)) => direct_kill,
        Ok(None) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("direct {label} process was not reaped"),
        )),
        Err(error) => Err(error),
    };

    #[cfg(unix)]
    if !direct_reaped {
        let terminate_detail = render_result(&terminate);
        let reap_detail = render_result(&reap);
        let retention = retain_unreaped_probe_process(child, tree, label);
        return Err(std::io::Error::other(format!(
            "containment terminate={terminate_detail}; direct reap={reap_detail}; containment \
             empty=skipped until exact child status is reaped; auxiliary reap=skipped until exact \
             child status is reaped; {retention}"
        )));
    }

    // Unix guardian finalization is permitted only after the exact direct
    // status above. Other platforms retain their existing independent
    // containment cleanup after a polling failure.
    let empty = confirm_tree_empty_until(&mut tree, Instant::now() + REAP_GRACE, label);
    let auxiliary_reap = reap_auxiliary_after_confirmed_empty(&mut tree, &empty, label);
    combine_cleanup(terminate, reap, empty, auxiliary_reap)
}

fn reap_auxiliary_after_confirmed_empty(
    tree: &mut ProbeProcessTree,
    empty: &std::io::Result<()>,
    label: &str,
) -> std::io::Result<()> {
    if empty.is_err() {
        return Err(std::io::Error::other(
            "guardian reap skipped because live containment was not disproven",
        ));
    }
    tree.reap_auxiliary_until(Instant::now() + REAP_GRACE, label)
}

fn combine_cleanup(
    terminate: std::io::Result<()>,
    reap: std::io::Result<()>,
    empty: std::io::Result<()>,
    auxiliary_reap: std::io::Result<()>,
) -> std::io::Result<()> {
    if terminate.is_ok() && reap.is_ok() && empty.is_ok() && auxiliary_reap.is_ok() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "containment terminate={}; direct reap={}; containment empty={}; auxiliary reap={}",
        render_result(&terminate),
        render_result(&reap),
        render_result(&empty),
        render_result(&auxiliary_reap),
    )))
}

fn render_result(result: &std::io::Result<()>) -> String {
    result
        .as_ref()
        .map(|_| "ok".to_string())
        .unwrap_or_else(|error| error.to_string())
}

fn contextual_io(error: std::io::Error, context: String) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(unix)]
struct ProbeProcessTree {
    guardian: Option<kin_daemon_spawn::ProcessGroupGuardian>,
}

#[cfg(unix)]
impl ProbeProcessTree {
    fn spawn(
        process_host: &crate::MigrationProcessHost,
        command: Command,
    ) -> std::io::Result<(Child, Self)> {
        // The watcher owns an inert sentinel in the target process group. Its
        // ownership pipe closes both on ordinary cleanup and hard parent death,
        // while the separately grouped watcher stays alive long enough to stop,
        // kill, and repeatedly prove the target group empty.
        let readiness_root = tempfile::tempdir()?;
        let ready_path = readiness_root.path().join("guardian.ready");
        let mut guardian = process_host
            .guardian_launcher()
            .spawn_with(
                &ready_path,
                Instant::now() + REAP_GRACE,
                |guardian_environment| {
                    // The old guardian inherited no ambient authority. Keep that
                    // boundary in the shared launcher; its private dispatch values
                    // are installed only after this scrub returns.
                    guardian_environment.env_clear();
                },
            )
            .map_err(|error| {
                contextual_io(
                    error,
                    "spawn migration-probe parent-death guardian".to_string(),
                )
            })?;

        match guardian.spawn(command) {
            Ok(child) => Ok((
                child,
                Self {
                    guardian: Some(guardian),
                },
            )),
            Err(error) => {
                let mut tree = Self {
                    guardian: Some(guardian),
                };
                let cleanup = terminate_descendants(&mut tree, "unlaunched migration probe");
                Err(contextual_io(
                    error,
                    format!(
                        "spawn migration probe inside stable guardian; cleanup={}",
                        render_result(&cleanup)
                    ),
                ))
            }
        }
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        if let Some(guardian) = self.guardian.as_mut() {
            guardian.request_cleanup();
        }
        Ok(())
    }

    fn confirm_empty_until(&mut self, deadline: Instant, label: &str) -> std::io::Result<()> {
        let Some(guardian) = self.guardian.as_mut() else {
            return Ok(());
        };
        match guardian.reap_until(deadline) {
            Ok(_) => {
                self.guardian.take();
                Ok(())
            }
            Err(error) => Err(contextual_io(
                error,
                format!("prove {label} process-group containment empty"),
            )),
        }
    }

    fn reap_auxiliary_until(&mut self, deadline: Instant, label: &str) -> std::io::Result<()> {
        self.confirm_empty_until(deadline, label)
    }
}

#[cfg(unix)]
impl Drop for ProbeProcessTree {
    fn drop(&mut self) {
        let _ = self.terminate();
        let _ = confirm_tree_empty_until(self, Instant::now() + REAP_GRACE, "migration probe");
    }
}

#[cfg(unix)]
struct RetainedProbeProcessCleanup {
    child: Child,
    tree: ProbeProcessTree,
}

#[cfg(unix)]
impl RetainedProbeProcessCleanup {
    fn run(mut self) -> ExitStatus {
        let _ = self.tree.terminate();
        let _ = self.child.kill();
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) | Err(_) => {
                    let _ = self.child.kill();
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
        };

        // Keep the sentinel PGID pin until the exact child status has been
        // consumed, then allow the guardian to prove the group empty.
        let _ = terminate_descendants(&mut self.tree, "retained migration probe");
        status
    }
}

#[cfg(unix)]
fn retain_unreaped_probe_process(child: Child, tree: ProbeProcessTree, label: &str) -> String {
    let retained = std::mem::ManuallyDrop::new(RetainedProbeProcessCleanup { child, tree });
    match std::thread::Builder::new()
        .name("kin-retained-migration-probe".to_string())
        .spawn(move || {
            let retained = std::mem::ManuallyDrop::into_inner(retained);
            let _ = retained.run();
        }) {
        Ok(_) => format!("retained exact child and guardian for asynchronous cleanup of {label}"),
        Err(error) => format!(
            "failed to spawn retained cleanup owner for {label}: {error}; exact child and \
             guardian intentionally leaked"
        ),
    }
}

#[cfg(windows)]
struct ProbeProcessTree {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
impl ProbeProcessTree {
    fn spawn(
        _process_host: &crate::MigrationProcessHost,
        mut command: Command,
    ) -> std::io::Result<(Child, Self)> {
        use std::os::windows::io::AsRawHandle as _;
        use std::os::windows::process::CommandExt as _;
        use windows_sys::Win32::Foundation::{
            GetLastError, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        use windows_sys::Win32::System::Threading::{
            GetProcessIdOfThread, OpenThread, ResumeThread, CREATE_SUSPENDED,
            THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
        };

        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(contextual_io(
                std::io::Error::last_os_error(),
                "create migration-probe Job Object".to_string(),
            ));
        }
        let mut tree = Self { job };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                tree.job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(contextual_io(
                std::io::Error::last_os_error(),
                "configure migration-probe Job Object".to_string(),
            ));
        }

        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command.spawn()?;
        if unsafe { AssignProcessToJobObject(tree.job, child.as_raw_handle()) } == 0 {
            let error = contextual_io(
                std::io::Error::last_os_error(),
                "assign migration probe to Job Object".to_string(),
            );
            return Err(failed_windows_spawn(&mut child, Some(&mut tree), error));
        }

        let thread_id = (|| -> std::io::Result<u32> {
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(contextual_io(
                    std::io::Error::last_os_error(),
                    "snapshot suspended migration-probe threads".to_string(),
                ));
            }
            let snapshot = OwnedHandle(snapshot);
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
                let error = unsafe { GetLastError() };
                return if error == ERROR_NO_MORE_FILES {
                    Err(std::io::Error::other(
                        "suspended migration probe has no primary thread",
                    ))
                } else {
                    Err(std::io::Error::from_raw_os_error(error as i32))
                };
            }
            let expected_size = std::mem::size_of::<THREADENTRY32>() as u32;
            let minimum_size = (std::mem::offset_of!(THREADENTRY32, th32OwnerProcessID)
                + std::mem::size_of::<u32>()) as u32;
            let mut matches = Vec::new();
            loop {
                if entry.dwSize < minimum_size {
                    return Err(std::io::Error::other(format!(
                        "migration-probe thread entry is too small: {} < {minimum_size}",
                        entry.dwSize
                    )));
                }
                if entry.th32OwnerProcessID == child.id() {
                    matches.push(entry.th32ThreadID);
                }
                entry.dwSize = expected_size;
                if unsafe { Thread32Next(snapshot.0, &mut entry) } == 0 {
                    let error = unsafe { GetLastError() };
                    if error == ERROR_NO_MORE_FILES {
                        break;
                    }
                    return Err(std::io::Error::from_raw_os_error(error as i32));
                }
            }
            if matches.len() != 1 {
                return Err(std::io::Error::other(format!(
                    "suspended migration probe must have one primary thread, found {}",
                    matches.len()
                )));
            }
            Ok(matches[0])
        })();
        let thread_id =
            thread_id.map_err(|error| failed_windows_spawn(&mut child, Some(&mut tree), error))?;
        let thread = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                thread_id,
            )
        };
        if thread.is_null() {
            let error = contextual_io(
                std::io::Error::last_os_error(),
                "open suspended migration-probe primary thread".to_string(),
            );
            return Err(failed_windows_spawn(&mut child, Some(&mut tree), error));
        }
        let thread = OwnedHandle(thread);
        if unsafe { GetProcessIdOfThread(thread.0) } != child.id() {
            return Err(failed_windows_spawn(
                &mut child,
                Some(&mut tree),
                std::io::Error::other("migration-probe primary-thread owner changed"),
            ));
        }
        let previous_suspend_count = unsafe { ResumeThread(thread.0) };
        if previous_suspend_count != 1 {
            return Err(failed_windows_spawn(
                &mut child,
                Some(&mut tree),
                std::io::Error::other(format!(
                    "migration-probe primary-thread resume returned {previous_suspend_count}, \
                     expected 1"
                )),
            ));
        }
        Ok((child, tree))
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if unsafe { TerminateJobObject(self.job, 1) } == 0 {
            Err(contextual_io(
                std::io::Error::last_os_error(),
                "terminate migration-probe Job Object".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };

        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe {
            QueryInformationJobObject(
                self.job,
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut accounting).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            Err(contextual_io(
                std::io::Error::last_os_error(),
                "inspect migration-probe Job Object".to_string(),
            ))
        } else {
            Ok(accounting.ActiveProcesses == 0)
        }
    }

    fn reap_auxiliary_until(&mut self, _deadline: Instant, _label: &str) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ProbeProcessTree {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        let _ = self.terminate();
        let _ = unsafe { CloseHandle(self.job) };
    }
}

#[cfg(windows)]
fn failed_windows_spawn(
    child: &mut Child,
    tree: Option<&mut ProbeProcessTree>,
    cause: std::io::Error,
) -> std::io::Error {
    let tree_terminate = tree.map(ProbeProcessTree::terminate);
    let direct_kill = child.kill();
    let reaped = poll_child_until(
        child,
        Instant::now() + REAP_GRACE,
        "suspended migration probe",
    );
    std::io::Error::new(
        cause.kind(),
        format!(
            "{cause}; tree terminate={}; direct kill={}; direct reap={}",
            tree_terminate
                .as_ref()
                .map(|result| render_result(result))
                .unwrap_or_else(|| "not assigned".to_string()),
            render_result(&direct_kill),
            reaped
                .as_ref()
                .map(|status| format!("{status:?}"))
                .unwrap_or_else(|error| error.to_string()),
        ),
    )
}

#[cfg(not(any(unix, windows)))]
struct ProbeProcessTree;

#[cfg(not(any(unix, windows)))]
impl ProbeProcessTree {
    fn spawn(
        _process_host: &crate::MigrationProcessHost,
        mut command: Command,
    ) -> std::io::Result<(Child, Self)> {
        Ok((command.spawn()?, Self))
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        Ok(true)
    }

    fn reap_auxiliary_until(&mut self, _deadline: Instant, _label: &str) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    const PROBE_WORKER_ENV: &str = "KINTEST_MIGRATION_PROBE_WORKER";
    const PROBE_DESCENDANT_MARKER_ENV: &str = "KINTEST_MIGRATION_PROBE_DESCENDANT_MARKER";

    fn test_process_host() -> crate::MigrationProcessHost {
        crate::MigrationProcessHost::exact_test(
            std::env::current_exe().expect("resolve migration bounded-process test executable"),
            "kin_process_group_guardian_worker",
        )
    }

    fn publish_pid_marker(marker: &std::path::Path) -> std::io::Result<()> {
        let pid = std::process::id();
        let mut staged_name = marker
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("probe-descendant.pid"))
            .to_os_string();
        staged_name.push(format!(".{pid}.tmp"));
        let staged_marker = marker.with_file_name(staged_name);
        std::fs::write(&staged_marker, pid.to_string())?;
        if let Err(error) = std::fs::rename(&staged_marker, marker) {
            let _ = std::fs::remove_file(staged_marker);
            return Err(error);
        }
        Ok(())
    }

    fn read_pid_marker(marker: &std::path::Path) -> Option<u32> {
        std::fs::read_to_string(marker)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid != 0)
    }

    struct NeverEofCapturePipe;

    impl std::io::Read for NeverEofCapturePipe {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::WouldBlock.into())
        }
    }

    impl CapturePipe for NeverEofCapturePipe {
        fn prepare_nonblocking(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn read_available(&mut self, _buffer: &mut [u8]) -> std::io::Result<PipeRead> {
            Ok(PipeRead::Pending)
        }
    }

    #[test]
    fn active_capture_sink_never_buffers_past_the_byte_ceiling() {
        let (events, received) = mpsc::channel();
        let mut captured = CapturedBytes::default();
        retain_bounded_chunk(&mut captured, &[b'a'; 3_000], 4_096, "stdout", &events);
        retain_bounded_chunk(&mut captured, &[b'b'; 3_000], 4_096, "stdout", &events);

        assert_eq!(captured.observed_bytes, 6_000);
        assert_eq!(captured.bytes.len(), 4_096);
        assert_eq!(captured.peak_buffered_bytes, 4_096);
        assert!(captured.truncated);
        assert!(matches!(
            received.try_recv(),
            Ok(CaptureEvent::LimitExceeded { stream: "stdout" })
        ));
    }

    #[test]
    fn capture_deadline_cannot_be_misreported_as_eof() {
        let (events, _received) = mpsc::channel();
        let reader =
            BoundedCaptureReader::spawn(NeverEofCapturePipe, "stdout", 4_096, events).unwrap();
        let captured = reader.finish_until(Instant::now());
        assert_eq!(
            captured.error.as_deref(),
            Some("stdout capture cancelled before EOF")
        );
    }

    #[test]
    fn probe_worker() {
        let Ok(mode) = std::env::var(PROBE_WORKER_ENV) else {
            return;
        };
        let mut stdin = Vec::new();
        std::io::stdin().read_to_end(&mut stdin).unwrap();
        assert!(stdin.is_empty(), "migration probe inherited readable stdin");
        println!("probe stdout");
        eprintln!("probe stderr");
        if mode == "sleep" {
            std::thread::sleep(Duration::from_secs(30));
        } else if mode == "runaway-output" {
            let chunk = vec![b'x'; 64 * 1024];
            loop {
                std::io::stdout().write_all(&chunk).unwrap();
                std::io::stdout().flush().unwrap();
            }
        } else if mode == "parent-owner" {
            let marker = std::env::var_os(PROBE_DESCENDANT_MARKER_ENV).unwrap();
            let mut nested_probe = Command::new(std::env::current_exe().unwrap());
            nested_probe
                .args([
                    "--exact",
                    "bounded_process::tests::probe_worker",
                    "--nocapture",
                ])
                .env(PROBE_WORKER_ENV, "descendant")
                .env(PROBE_DESCENDANT_MARKER_ENV, marker);
            let result = output_finalized_with_timeout_and_limit(
                &test_process_host(),
                nested_probe,
                "parent-death migration probe fixture",
                Duration::from_secs(30),
                1024 * 1024,
            );
            panic!("parent-owner fixture unexpectedly returned: {result:?}");
        } else if mode == "descendant" {
            let marker =
                std::path::PathBuf::from(std::env::var_os(PROBE_DESCENDANT_MARKER_ENV).unwrap());
            publish_pid_marker(&marker).unwrap();
            std::thread::sleep(Duration::from_secs(30));
        } else if mode == "spawn-descendant" {
            let marker =
                std::path::PathBuf::from(std::env::var_os(PROBE_DESCENDANT_MARKER_ENV).unwrap());
            let mut descendant = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bounded_process::tests::probe_worker",
                    "--nocapture",
                ])
                .env(PROBE_WORKER_ENV, "descendant")
                .env(PROBE_DESCENDANT_MARKER_ENV, &marker)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut descendant_pid = read_pid_marker(&marker);
            while descendant_pid.is_none() && Instant::now() < deadline {
                assert!(descendant.try_wait().unwrap().is_none());
                std::thread::sleep(POLL_INTERVAL);
                descendant_pid = read_pid_marker(&marker);
            }
            descendant_pid.expect("probe descendant did not publish a parseable PID");
            drop(descendant);
        }
    }

    #[cfg(unix)]
    #[test]
    fn retained_cleanup_reaps_exact_child_before_guardian_finalization() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "bounded_process::tests::probe_worker",
                "--nocapture",
            ])
            .env(PROBE_WORKER_ENV, "sleep")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (child, tree) = ProbeProcessTree::spawn(&test_process_host(), command).unwrap();

        let status = RetainedProbeProcessCleanup { child, tree }.run();
        assert!(
            !status.success(),
            "retained cleanup did not terminate its exact direct child"
        );
    }

    #[test]
    fn bounded_probe_closes_stdin_and_captures_output() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "bounded_process::tests::probe_worker",
                "--nocapture",
            ])
            .env(PROBE_WORKER_ENV, "complete");
        let output = output_finalized_with_timeout_and_limit(
            &test_process_host(),
            command,
            "migration probe fixture",
            Duration::from_secs(5),
            1024 * 1024,
        )
        .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("probe stdout"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("probe stderr"));
    }

    #[test]
    fn bounded_probe_times_out_and_reaps_direct_child() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "bounded_process::tests::probe_worker",
                "--nocapture",
            ])
            .env(PROBE_WORKER_ENV, "sleep");
        let error = output_finalized_with_timeout_and_limit(
            &test_process_host(),
            command,
            "sleeping migration probe fixture",
            Duration::from_secs(2),
            1024 * 1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let message = error.to_string();
        assert!(message.contains("cleanup=ok"), "{message}");
        assert!(message.contains("probe stdout"), "{message}");
        assert!(message.contains("probe stderr"), "{message}");
    }

    #[test]
    fn bounded_probe_rejects_runaway_output_and_reaps_the_tree() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "bounded_process::tests::probe_worker",
                "--nocapture",
            ])
            .env(PROBE_WORKER_ENV, "runaway-output");
        let error = output_finalized_with_timeout_and_limit(
            &test_process_host(),
            command,
            "runaway migration probe fixture",
            Duration::from_secs(5),
            4 * 1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let message = error.to_string();
        assert!(message.contains("exceeded the 4096-byte"), "{message}");
        assert!(message.contains("cleanup=ok"), "{message}");
    }

    #[test]
    fn bounded_probe_reaps_inherited_descendants_after_direct_exit() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("probe-descendant.pid");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "bounded_process::tests::probe_worker",
                "--nocapture",
            ])
            .env(PROBE_WORKER_ENV, "spawn-descendant")
            .env(PROBE_DESCENDANT_MARKER_ENV, &marker);
        let output = output_finalized_with_timeout_and_limit(
            &test_process_host(),
            command,
            "migration probe tree fixture",
            Duration::from_secs(10),
            1024 * 1024,
        )
        .unwrap();
        assert!(output.status.success());

        let pid =
            read_pid_marker(&marker).expect("probe descendant did not publish a parseable PID");
        assert!(
            !process_is_live(pid),
            "probe descendant {pid} survived bounded return"
        );
    }

    fn process_is_live(pid: u32) -> bool {
        let system = sysinfo::System::new_all();
        system
            .process(sysinfo::Pid::from_u32(pid))
            .is_some_and(|process| {
                !matches!(
                    process.status(),
                    sysinfo::ProcessStatus::Dead | sysinfo::ProcessStatus::Zombie
                )
            })
    }

    #[cfg(unix)]
    struct KillAndReapOnDrop(Option<Child>);

    #[cfg(unix)]
    impl KillAndReapOnDrop {
        fn child_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("parent fixture child remains owned")
        }

        fn kill_and_reap(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[cfg(unix)]
    impl Drop for KillAndReapOnDrop {
        fn drop(&mut self) {
            self.kill_and_reap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn hard_parent_death_terminates_the_guarded_probe() {
        // Readiness here is a three-hop spawn chain whose middle hop already
        // waits out a full REAP_GRACE of its own, so a budget no larger than one
        // nested product budget can expire while every component is still inside
        // its permitted window. Both guards are deliberately local: REAP_GRACE
        // carries production reap semantics at many other call sites and must
        // not move for a test's benefit.
        //
        // Both must also stay strictly BELOW the descendant fixture's own 30s
        // lifetime. A cleanup guard above it cannot fail: a probe that survives
        // cleanup completely would return of old age inside the window, every
        // liveness check would find it gone, and the test would pass green while
        // proving nothing. That ceiling, not the cleanup latency, is what bounds
        // these numbers; observed cleanup is under 100ms, so 20s already leaves
        // two orders of magnitude of margin.
        const PARENT_DEATH_READY_GUARD: Duration = Duration::from_secs(20);
        const PARENT_DEATH_CLEANUP_GUARD: Duration = Duration::from_secs(20);

        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("parent-death-probe.pid");
        let mut owner_command = Command::new(std::env::current_exe().unwrap());
        owner_command
            .args([
                "--exact",
                "bounded_process::tests::probe_worker",
                "--nocapture",
            ])
            .env(PROBE_WORKER_ENV, "parent-owner")
            .env(PROBE_DESCENDANT_MARKER_ENV, &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut owner = KillAndReapOnDrop(Some(owner_command.spawn().unwrap()));
        let owner_pid = owner.child_mut().id();
        let ready_deadline = Instant::now() + PARENT_DEATH_READY_GUARD;
        let guarded_pid = loop {
            if let Some(pid) = read_pid_marker(&marker) {
                break pid;
            }
            assert!(
                owner.child_mut().try_wait().unwrap().is_none(),
                "parent fixture exited before its guarded probe became ready"
            );
            assert!(
                Instant::now() < ready_deadline,
                "guarded probe published no parseable PID {}s after the owner was spawned; \
                 the readiness chain never reached the nested probe",
                PARENT_DEATH_READY_GUARD.as_secs()
            );
            std::thread::sleep(POLL_INTERVAL);
        };
        assert_ne!(
            guarded_pid, owner_pid,
            "the marker must name the nested guarded probe, not the owner the test spawned"
        );

        // This bypasses Rust Drop inside the owner process. Only the
        // guardian's parent-death ownership pipe can clean the nested probe.
        owner.kill_and_reap();

        let cleanup_deadline = Instant::now() + PARENT_DEATH_CLEANUP_GUARD;
        loop {
            if !process_is_live(guarded_pid) {
                break;
            }
            assert!(
                Instant::now() < cleanup_deadline,
                "guarded probe {guarded_pid} was still live {}s after hard parent death; \
                 the guardian's parent-death ownership pipe did not clean it",
                PARENT_DEATH_CLEANUP_GUARD.as_secs()
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_empty_proof_does_not_discard_the_guardian_handle() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "bounded_process::tests::probe_worker",
                "--nocapture",
            ])
            .env(PROBE_WORKER_ENV, "sleep");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (mut child, mut tree) = ProbeProcessTree::spawn(&test_process_host(), command).unwrap();
        tree.terminate().unwrap();
        let failed_quiescence = Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "synthetic failed containment proof",
        ));
        let error = reap_auxiliary_after_confirmed_empty(
            &mut tree,
            &failed_quiescence,
            "failed-quiescence fixture",
        )
        .unwrap_err();
        assert!(error.to_string().contains("reap skipped"), "{error}");
        assert!(
            tree.guardian.is_some(),
            "failed empty proof discarded the guardian status handle"
        );

        let _ = child.kill();
        let _ = child.wait();
        confirm_tree_empty_until(
            &mut tree,
            Instant::now() + REAP_GRACE,
            "failed-quiescence fixture cleanup",
        )
        .unwrap();
        tree.reap_auxiliary_until(
            Instant::now() + REAP_GRACE,
            "failed-quiescence fixture cleanup",
        )
        .unwrap();
    }
}
