// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The single path every user-facing Kin notification takes.
//!
//! Callers never talk to a platform notification API directly. Routing through
//! one entry point is what makes sender identity, urgency tiering, and
//! suppression enforceable properties rather than per-caller conventions that
//! drift apart.
//!
//! # Identity
//!
//! macOS derives a notification's sender name, icon, and Notification Center
//! grouping from the posting process's bundle. A CLI has no bundle, so anything
//! posted through `osascript` is credited to Script Editor. `KinNotifier.app`
//! exists to be that bundle; this crate prefers it and falls back only when it
//! cannot deliver.
//!
//! # Fallback, never silence, but never quiet about it
//!
//! Every backend failure degrades to a worse-looking notification rather than
//! to nothing. A missing bundle, a revoked authorization, or a platform without
//! a notification daemon must still reach the user somehow, because the alerts
//! routed through here are the ones that say a machine is about to freeze.
//!
//! A degraded notification still looks like a working one, so the degradation
//! is stated rather than left to be inferred: [`Status::degradation`] names the
//! bundle that is missing, the install channel that should have delivered it,
//! and what to do about it. Not every channel installs the bundle to the same
//! place, so the bundle is looked for along a short search path rather than at
//! one hardcoded location.
//!
//! # Suppression is declared, not inferred
//!
//! Repetition control is the caller's stated intent:
//!
//! * [`Suppression::Cooldown`] re-notifies once a fixed interval has passed.
//! * [`Suppression::Latch`] notifies once and stays quiet until [`Notifier::clear`].
//!
//! Both require a key. A latch models "this condition is ongoing, say it once";
//! a cooldown models "this recurs, rate-limit it". They are not interchangeable,
//! and picking for the caller would get one of them wrong.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// Alert urgency. Determines whether a notification makes a sound and whether
/// the platform may let it break through Do Not Disturb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Completions and recoveries. Silent, never breaks through Focus.
    Info,
    /// State that needs attention but not this second. Silent.
    Warn,
    /// Act now or lose something. Sound, time-sensitive interruption.
    Urgent,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Urgent => "urgent",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "info" => Some(Self::Info),
            "warn" => Some(Self::Warn),
            "urgent" => Some(Self::Urgent),
            _ => None,
        }
    }

    fn makes_sound(self) -> bool {
        self == Self::Urgent
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How repeats of the same keyed alert are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppression {
    /// Deliver every time.
    None,
    /// Deliver again only after this much time has passed.
    Cooldown(Duration),
    /// Deliver once, then stay quiet until the key is cleared.
    Latch,
}

impl Suppression {
    /// Whether this mode needs somewhere to remember that it fired.
    fn is_stateful(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// One notification to deliver.
#[derive(Debug, Clone)]
pub struct Notification {
    pub title: String,
    pub body: String,
    pub level: Level,
    /// Suppression and replacement identity. Reposting under the same key
    /// replaces the previous notification rather than stacking another copy.
    pub key: Option<String>,
}

impl Notification {
    pub fn new(title: impl Into<String>, body: impl Into<String>, level: Level) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            level,
            key: None,
        }
    }

    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }
}

/// Which transport actually delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `KinNotifier.app`. The only backend that posts as Kin.
    KinNotifier,
    /// AppleScript. Visible, but credited to Script Editor.
    OsaScript,
    /// freedesktop `notify-send`.
    NotifySend,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KinNotifier => "KinNotifier",
            Self::OsaScript => "osascript",
            Self::NotifySend => "notify-send",
        }
    }
}

/// Why a notification was withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressedBy {
    Cooldown,
    Latch,
}

/// What happened to a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Delivered(Backend),
    Suppressed(SuppressedBy),
    /// Every backend failed. The caller has already lost the notification, so
    /// this is reported rather than swallowed.
    Failed(String),
}

impl Outcome {
    pub fn delivered(&self) -> bool {
        matches!(self, Self::Delivered(_))
    }
}

/// How this copy of Kin was installed.
///
/// Which channel delivered the CLI decides where its notification bundle should
/// have landed, and therefore what a user has to do to get it back. Reporting
/// "not installed" without saying which install to repair leaves them guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallChannel {
    /// The managed root: the `install.sh` installer, the npm launcher, and
    /// anything `kin update` has since replaced. The bundle belongs in
    /// `$KIN_HOME/lib`.
    Managed,
    /// A Homebrew cellar. The bundle travels inside the formula's prefix,
    /// because a formula must not write into a user's home directory.
    Homebrew,
    /// Somewhere else: a hand-placed binary, a build tree, a distro package.
    Unknown,
}

impl InstallChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Homebrew => "homebrew",
            Self::Unknown => "unknown",
        }
    }

    /// What to do to get the bundle back on this channel.
    fn remedy(self) -> &'static str {
        match self {
            Self::Managed => "run `kin update` to reinstall the managed release",
            Self::Homebrew => "run `brew reinstall kin`",
            Self::Unknown => {
                "reinstall Kin from https://github.com/firelock-ai/kin (scripts/install.sh)"
            }
        }
    }
}

impl fmt::Display for InstallChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Current routing state, for `kin notify status` and `kin doctor`.
#[derive(Debug, Clone)]
pub struct Status {
    /// Path to the notifier bundle executable, when it is installed.
    pub notifier: Option<PathBuf>,
    /// Where a bundle is expected when none was found anywhere on the search
    /// path. Reported so the gap names a location rather than an absence.
    pub expected: PathBuf,
    /// How this copy of Kin was installed.
    pub channel: InstallChannel,
    /// Raw authorization report from the bundle, when it could be queried.
    pub identity: Option<String>,
    /// Keys currently holding back a repeat.
    pub held_keys: Vec<String>,
}

impl Status {
    /// One line stating the degradation, or `None` when there is none.
    ///
    /// Only macOS has a bundle to miss. Everywhere else the absence is not a
    /// degradation, it is simply how the platform works.
    pub fn degradation(&self) -> Option<String> {
        if !cfg!(target_os = "macos") || self.notifier.is_some() {
            return None;
        }
        Some(format!(
            "KinNotifier.app is not installed (looked for {}); this {} install did not deliver it, \
             so notifications post as Script Editor instead of Kin. To fix: {}.",
            self.expected.display(),
            self.channel,
            self.channel.remedy()
        ))
    }
}

/// Routes notifications and remembers what it already said.
pub struct Notifier {
    kin_home: PathBuf,
    /// The running Kin executable, when it is known. Used only to find a bundle
    /// that a non-managed channel installed beside the binary rather than into
    /// the managed root.
    executable: Option<PathBuf>,
}

impl Notifier {
    /// Resolve the managed Kin root the same way the launcher, setup, and shell
    /// hooks do: `KIN_HOME`, then the `KIN_DIR` compatibility alias, then
    /// `~/.kin`.
    pub fn new() -> Result<Self> {
        let executable = std::env::current_exe().ok();
        for key in ["KIN_HOME", "KIN_DIR"] {
            if let Some(value) = std::env::var_os(key) {
                if !value.is_empty() {
                    return Ok(Self::with_home(PathBuf::from(value)).with_executable(executable));
                }
            }
        }
        let home = directories::BaseDirs::new()
            .map(|d| d.home_dir().to_path_buf())
            .context("could not determine home directory")?;
        Ok(Self::with_home(home.join(".kin")).with_executable(executable))
    }

    /// Build against an explicit root. Every path this type touches derives from
    /// it, so tests never reach a real `$HOME`.
    pub fn with_home(kin_home: PathBuf) -> Self {
        Self {
            kin_home,
            executable: None,
        }
    }

    /// Tell the router which binary is running, so it can find a bundle
    /// installed beside that binary instead of under the managed root.
    pub fn with_executable(mut self, executable: Option<PathBuf>) -> Self {
        self.executable = executable;
        self
    }

    fn state_dir(&self) -> PathBuf {
        self.kin_home.join("state").join("notify")
    }

    fn log_path(&self) -> PathBuf {
        self.kin_home.join("logs").join("notify.log")
    }

    /// Where a managed install keeps the notifier bundle's executable.
    ///
    /// This is the canonical location: what `install.sh`, the npm launcher, and
    /// `kin update` all write. It is reported when no bundle was found at all,
    /// so the gap names a path instead of just being an absence.
    pub fn notifier_path(&self) -> PathBuf {
        bundle_executable(&self.kin_home.join("lib"))
    }

    /// Every place a bundle could legitimately have been installed, in the
    /// order they are preferred.
    ///
    /// The managed root wins because it is the only location `kin update`
    /// maintains. The two prefix-relative candidates cover a channel that
    /// cannot write to a user's home directory: a Homebrew formula installs
    /// into its own prefix, so its bundle sits beside the binary rather than
    /// under `$KIN_HOME`.
    fn bundle_candidates(&self) -> Vec<PathBuf> {
        let mut candidates = vec![self.notifier_path()];
        if let Some(prefix) = self
            .executable
            .as_deref()
            .and_then(|executable| executable.parent())
            .and_then(|bin| bin.parent())
        {
            candidates.push(bundle_executable(&prefix.join("lib")));
            candidates.push(bundle_executable(prefix));
        }
        candidates.dedup();
        candidates
    }

    /// The bundle executable to post through, if one is installed anywhere on
    /// the search path.
    pub fn resolve_notifier(&self) -> Option<PathBuf> {
        self.bundle_candidates()
            .into_iter()
            .find(|candidate| candidate.is_file())
    }

    /// Which channel installed the running binary.
    pub fn install_channel(&self) -> InstallChannel {
        let Some(executable) = self.executable.as_deref() else {
            return InstallChannel::Unknown;
        };
        install_channel_of(executable, &self.kin_home)
    }

    fn state_path(&self, key: &str) -> PathBuf {
        self.state_dir().join(sanitize_key(key))
    }

    /// Forget that `key` already fired, so the next send is delivered.
    pub fn clear(&self, key: &str) -> Result<()> {
        let path = self.state_path(key);
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to clear notify state at {}", path.display()))?;
        }
        self.log(&format!("CLEAR key={key}"));
        Ok(())
    }

    /// Report what is installed and what is currently held back.
    pub fn status(&self) -> Status {
        let installed = self.resolve_notifier();
        let identity = installed.as_ref().and_then(|path| query_identity(path));
        let mut held_keys: Vec<String> = fs::read_dir(self.state_dir())
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        held_keys.sort();
        Status {
            notifier: installed,
            expected: self.notifier_path(),
            channel: self.install_channel(),
            identity,
            held_keys,
        }
    }

    /// Whether a keyed send is currently held back.
    fn suppressed_by(&self, key: &str, suppression: Suppression) -> Option<SuppressedBy> {
        let path = self.state_path(key);
        let recorded = fs::read_to_string(&path).ok()?;
        match suppression {
            Suppression::None => None,
            Suppression::Latch => Some(SuppressedBy::Latch),
            Suppression::Cooldown(window) => {
                let last: u64 = recorded.trim().parse().ok()?;
                let elapsed = now_unix().saturating_sub(last);
                (elapsed < window.as_secs()).then_some(SuppressedBy::Cooldown)
            }
        }
    }

    fn record_sent(&self, key: &str) -> Result<()> {
        let dir = self.state_dir();
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        fs::write(self.state_path(key), now_unix().to_string())
            .with_context(|| format!("failed to record notify state for {key}"))?;
        Ok(())
    }

    /// Append one decision line. Logging must never be the reason a
    /// notification fails, so errors here are dropped.
    fn log(&self, message: &str) {
        let path = self.log_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| {
                use std::io::Write as _;
                writeln!(file, "{stamp} {message}")
            });
    }

    /// Deliver `notification`, honouring `suppression`.
    ///
    /// Returns `Err` only for state that could not be read or written. A
    /// notification that no backend could deliver is [`Outcome::Failed`], not an
    /// error, because the caller's job is to keep going.
    pub fn send(&self, notification: &Notification, suppression: Suppression) -> Result<Outcome> {
        if suppression.is_stateful() && notification.key.is_none() {
            anyhow::bail!("suppression requires a key");
        }

        if let Some(key) = notification.key.as_deref() {
            if let Some(reason) = self.suppressed_by(key, suppression) {
                self.log(&format!(
                    "SUPPRESSED ({}) key={key} title={}",
                    match reason {
                        SuppressedBy::Cooldown => "cooldown",
                        SuppressedBy::Latch => "latched",
                    },
                    notification.title
                ));
                return Ok(Outcome::Suppressed(reason));
            }
        }

        let outcome = self.deliver(notification);

        if let Outcome::Delivered(backend) = outcome {
            if suppression.is_stateful() {
                if let Some(key) = notification.key.as_deref() {
                    self.record_sent(key)?;
                }
            }
            self.log(&format!(
                "SENT via {} level={} key={} title={}",
                backend.as_str(),
                notification.level,
                notification.key.as_deref().unwrap_or("-"),
                notification.title
            ));
        }
        Ok(outcome)
    }

    /// Try each backend in preference order.
    fn deliver(&self, notification: &Notification) -> Outcome {
        let mut last_error = String::new();

        for attempt in backends() {
            match attempt {
                Backend::KinNotifier => {
                    let Some(path) = self.resolve_notifier() else {
                        // Not an error the caller can act on mid-alert, but not
                        // something to pass over in silence either: the log is
                        // where a wrong sender name gets explained afterwards.
                        self.log(&format!(
                            "FALLBACK KinNotifier (not installed at {}; channel={}) level={} key={}",
                            self.notifier_path().display(),
                            self.install_channel(),
                            notification.level,
                            notification.key.as_deref().unwrap_or("-")
                        ));
                        continue;
                    };
                    match post_via_bundle(&path, notification) {
                        Ok(()) => return Outcome::Delivered(Backend::KinNotifier),
                        Err(reason) => {
                            self.log(&format!(
                                "FALLBACK KinNotifier ({reason}) level={} key={}",
                                notification.level,
                                notification.key.as_deref().unwrap_or("-")
                            ));
                            last_error = reason;
                        }
                    }
                }
                Backend::OsaScript => match post_via_osascript(notification) {
                    Ok(()) => return Outcome::Delivered(Backend::OsaScript),
                    Err(reason) => last_error = reason,
                },
                Backend::NotifySend => match post_via_notify_send(notification) {
                    Ok(()) => return Outcome::Delivered(Backend::NotifySend),
                    Err(reason) => last_error = reason,
                },
            }
        }

        self.log(&format!(
            "FAILED all backends level={} key={} title={}",
            notification.level,
            notification.key.as_deref().unwrap_or("-"),
            notification.title
        ));
        Outcome::Failed(if last_error.is_empty() {
            "no notification backend available".to_string()
        } else {
            last_error
        })
    }
}

/// Backends in preference order for this platform.
fn backends() -> &'static [Backend] {
    #[cfg(target_os = "macos")]
    {
        &[Backend::KinNotifier, Backend::OsaScript]
    }
    #[cfg(target_os = "linux")]
    {
        &[Backend::NotifySend]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        &[]
    }
}

/// The bundle executable inside a directory that holds `KinNotifier.app`.
fn bundle_executable(parent: &Path) -> PathBuf {
    parent
        .join("KinNotifier.app")
        .join("Contents")
        .join("MacOS")
        .join("KinNotifier")
}

/// Classify an install from where its executable lives.
///
/// Kept as a free function over explicit paths so it can be tested without a
/// real install of any channel on the machine running the tests.
///
/// Homebrew is recognized by the `Cellar` path component every formula install
/// sits under. The symlink Homebrew puts on `PATH` points into that cellar, and
/// `current_exe` may report either, so both the reported path and its resolved
/// target are considered.
pub fn install_channel_of(executable: &Path, kin_home: &Path) -> InstallChannel {
    if executable.starts_with(kin_home) {
        return InstallChannel::Managed;
    }
    let resolved = std::fs::canonicalize(executable).ok();
    if resolved
        .as_deref()
        .is_some_and(|path| path.starts_with(kin_home))
    {
        return InstallChannel::Managed;
    }
    let in_cellar = |path: &Path| {
        path.components()
            .any(|component| component.as_os_str() == "Cellar")
    };
    if in_cellar(executable) || resolved.as_deref().is_some_and(in_cellar) {
        return InstallChannel::Homebrew;
    }
    InstallChannel::Unknown
}

/// Keys name files in the state directory, so they are restricted to a safe
/// alphabet rather than escaped. A key containing a path separator would
/// otherwise write outside that directory.
fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn query_identity(notifier: &Path) -> Option<String> {
    let output = std::process::Command::new(notifier)
        .arg("--status")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn post_via_bundle(notifier: &Path, notification: &Notification) -> Result<(), String> {
    let mut command = std::process::Command::new(notifier);
    command
        .arg("--title")
        .arg(&notification.title)
        .arg("--body")
        .arg(&notification.body)
        .arg("--level")
        .arg(notification.level.as_str());
    if let Some(key) = notification.key.as_deref() {
        command.arg("--key").arg(key);
    }
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        // Exit codes are the bundle's contract. They are surfaced verbatim so
        // the log says which gap to fix rather than just "it failed".
        Ok(status) => Err(match status.code() {
            Some(3) => "no bundle identity".to_string(),
            Some(4) => "authorization denied".to_string(),
            Some(7) => "authorization never requested; run `kin setup` interactively".to_string(),
            Some(code) => format!("exit {code}"),
            None => "terminated by signal".to_string(),
        }),
        Err(error) => Err(error.to_string()),
    }
}

fn post_via_osascript(notification: &Notification) -> Result<(), String> {
    // Both strings are passed as arguments rather than interpolated into the
    // script source: embedding user text in AppleScript is an injection surface.
    let script = if notification.level.makes_sound() {
        "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv) sound name \"Sosumi\"\nend run"
    } else {
        "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run"
    };
    match std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .arg(&notification.title)
        .arg(&notification.body)
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("osascript {status}")),
        Err(error) => Err(error.to_string()),
    }
}

fn post_via_notify_send(notification: &Notification) -> Result<(), String> {
    let urgency = match notification.level {
        Level::Info => "low",
        Level::Warn => "normal",
        Level::Urgent => "critical",
    };
    match std::process::Command::new("notify-send")
        .arg("--urgency")
        .arg(urgency)
        .arg("--app-name")
        .arg("Kin")
        .arg(&notification.title)
        .arg(&notification.body)
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("notify-send {status}")),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notifier() -> (tempfile::TempDir, Notifier) {
        let dir = tempfile::tempdir().unwrap();
        let notifier = Notifier::with_home(dir.path().to_path_buf());
        (dir, notifier)
    }

    #[test]
    fn keys_cannot_escape_the_state_directory() {
        assert_eq!(sanitize_key("../../../etc/evil"), ".._.._.._etc_evil");
        assert_eq!(sanitize_key("install-drift"), "install-drift");
        assert_eq!(sanitize_key("a b/c"), "a_b_c");

        let (dir, notifier) = notifier();
        let path = notifier.state_path("../../../etc/evil");
        assert!(
            path.starts_with(dir.path()),
            "escaped to {}",
            path.display()
        );
    }

    #[test]
    fn suppression_without_a_key_is_rejected() {
        let (_dir, notifier) = notifier();
        let notification = Notification::new("t", "b", Level::Info);
        let error = notifier
            .send(&notification, Suppression::Latch)
            .expect_err("a latch with no key has no identity to latch on");
        assert!(error.to_string().contains("requires a key"));
    }

    #[test]
    fn latch_holds_until_cleared() {
        let (_dir, notifier) = notifier();
        // Record a prior send directly so the test does not depend on a real
        // notification daemon being present.
        notifier.record_sent("storm").unwrap();
        assert_eq!(
            notifier.suppressed_by("storm", Suppression::Latch),
            Some(SuppressedBy::Latch)
        );
        notifier.clear("storm").unwrap();
        assert_eq!(notifier.suppressed_by("storm", Suppression::Latch), None);
    }

    #[test]
    fn cooldown_expires_but_a_latch_does_not() {
        let (_dir, notifier) = notifier();
        notifier.record_sent("drift").unwrap();

        // Inside the window.
        assert_eq!(
            notifier.suppressed_by("drift", Suppression::Cooldown(Duration::from_secs(300))),
            Some(SuppressedBy::Cooldown)
        );
        // A zero-length window is always already elapsed.
        assert_eq!(
            notifier.suppressed_by("drift", Suppression::Cooldown(Duration::ZERO)),
            None
        );
        // The same recorded state still latches, which is the distinction
        // between the two modes.
        assert_eq!(
            notifier.suppressed_by("drift", Suppression::Latch),
            Some(SuppressedBy::Latch)
        );
    }

    #[test]
    fn an_unrecorded_key_is_never_suppressed() {
        let (_dir, notifier) = notifier();
        assert_eq!(notifier.suppressed_by("fresh", Suppression::Latch), None);
        assert_eq!(
            notifier.suppressed_by("fresh", Suppression::Cooldown(Duration::from_secs(9999))),
            None
        );
    }

    #[test]
    fn clearing_an_unknown_key_is_not_an_error() {
        let (_dir, notifier) = notifier();
        notifier.clear("never-seen").unwrap();
    }

    #[test]
    fn status_reports_held_keys_sorted() {
        let (_dir, notifier) = notifier();
        notifier.record_sent("zebra").unwrap();
        notifier.record_sent("alpha").unwrap();
        assert_eq!(notifier.status().held_keys, vec!["alpha", "zebra"]);
    }

    #[test]
    fn status_reports_a_missing_bundle_rather_than_guessing() {
        let (_dir, notifier) = notifier();
        assert!(notifier.status().notifier.is_none());
        assert!(notifier.status().identity.is_none());
    }

    /// Install a fake bundle executable under `parent` and return its path.
    fn install_fake_bundle(parent: &Path) -> PathBuf {
        let executable = bundle_executable(parent);
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"#!/bin/sh\n").unwrap();
        executable
    }

    #[test]
    fn the_managed_root_is_preferred_over_a_bundle_beside_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let kin_home = dir.path().join("kin-home");
        let prefix = dir.path().join("opt/kin");
        let executable = prefix.join("bin/kin");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"kin").unwrap();

        let notifier =
            Notifier::with_home(kin_home.clone()).with_executable(Some(executable.clone()));
        assert_eq!(notifier.resolve_notifier(), None);

        // A prefix-relative bundle is found when the managed root has none.
        let beside = install_fake_bundle(&prefix);
        assert_eq!(notifier.resolve_notifier(), Some(beside));

        // Once the managed root has one, it wins: that is the only copy `kin
        // update` maintains.
        let managed = install_fake_bundle(&kin_home.join("lib"));
        assert_eq!(notifier.resolve_notifier(), Some(managed));
    }

    #[test]
    fn a_homebrew_prefix_bundle_is_found_beside_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let kin_home = dir.path().join("kin-home");
        let cellar = dir.path().join("brew/Cellar/kin/0.4.5");
        let executable = cellar.join("bin/kin");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"kin").unwrap();
        let bundle = install_fake_bundle(&cellar);

        let notifier = Notifier::with_home(kin_home).with_executable(Some(executable));
        assert_eq!(notifier.resolve_notifier(), Some(bundle));
        assert_eq!(notifier.install_channel(), InstallChannel::Homebrew);
    }

    #[test]
    fn install_channels_are_told_apart_by_where_the_binary_lives() {
        let kin_home = Path::new("/home/dev/.kin");
        assert_eq!(
            install_channel_of(Path::new("/home/dev/.kin/bin/kin"), kin_home),
            InstallChannel::Managed
        );
        assert_eq!(
            install_channel_of(
                Path::new("/opt/homebrew/Cellar/kin/0.4.5/bin/kin"),
                kin_home
            ),
            InstallChannel::Homebrew
        );
        assert_eq!(
            install_channel_of(Path::new("/usr/local/bin/kin"), kin_home),
            InstallChannel::Unknown
        );
        // A path merely containing the word must not be mistaken for the
        // cellar's own directory component.
        assert_eq!(
            install_channel_of(Path::new("/home/dev/CellarNotes/kin"), kin_home),
            InstallChannel::Unknown
        );
    }

    /// The whole point of reporting a gap is that somebody can close it, so the
    /// message has to name the file, the channel, and the fix.
    #[test]
    fn a_missing_bundle_degradation_names_the_channel_and_the_remedy() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("brew/Cellar/kin/0.4.5/bin/kin");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"kin").unwrap();
        let notifier =
            Notifier::with_home(dir.path().join("kin-home")).with_executable(Some(executable));

        let status = notifier.status();
        // Only macOS has a bundle to miss; elsewhere there is no degradation to
        // report and saying otherwise would be noise.
        #[cfg(target_os = "macos")]
        {
            let message = status
                .degradation()
                .expect("a macOS install with no bundle anywhere is degraded");
            assert!(message.contains("KinNotifier.app"), "{message}");
            assert!(message.contains("homebrew"), "{message}");
            assert!(message.contains("brew reinstall kin"), "{message}");
            assert!(message.contains("Script Editor"), "{message}");
        }
        #[cfg(not(target_os = "macos"))]
        assert!(status.degradation().is_none());
    }

    #[test]
    fn an_installed_bundle_reports_no_degradation() {
        let dir = tempfile::tempdir().unwrap();
        let kin_home = dir.path().join("kin-home");
        install_fake_bundle(&kin_home.join("lib"));
        let notifier = Notifier::with_home(kin_home);
        assert!(notifier.status().degradation().is_none());
    }

    #[test]
    fn levels_round_trip() {
        for level in [Level::Info, Level::Warn, Level::Urgent] {
            assert_eq!(Level::parse(level.as_str()), Some(level));
        }
        assert_eq!(Level::parse("shouty"), None);
    }

    #[test]
    fn only_urgent_makes_a_sound() {
        assert!(!Level::Info.makes_sound());
        assert!(!Level::Warn.makes_sound());
        assert!(Level::Urgent.makes_sound());
    }
}
