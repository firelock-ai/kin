// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which of three ways Kin is showing graph truth as ordinary files.
//!
//! The graph is the authority. A projection is a view of it, and Kin has three:
//!
//! * **shim**: `libkin_vfs_shim` injected into a process by the shell hook, so
//!   intercepted libc calls answer from the graph. It needs no kernel support
//!   and no privileges, which is why it is the compatibility fallback, and it
//!   is also the only one an operating system can take away: a container, a
//!   signed binary, macOS SIP, or a static binary that never calls libc all
//!   leave the process reading raw disk while everything still looks fine.
//! * **NFS mount**: an in-process NFSv3 server the kernel mounts. Every tool
//!   on the machine sees graph truth because the kernel serves it, with no
//!   injection and no shell hook.
//! * **FUSE mount**: the same property through libfuse, FUSE-T or macFUSE.
//!
//! ## The fallback order, and why it is this way
//!
//! A mount is preferred over the shim wherever one is available, because a
//! mount cannot be stripped out from under a process. Between the two mounts
//! the platform's native one comes first: macOS carries an NFS client in the
//! base system while FUSE there needs FUSE-T or macFUSE installed, and Linux
//! carries libfuse far more often than it carries a configured NFS client. The
//! shim is last, and it is a real answer rather than a failure: it is what
//! makes graph-first adoption work on a host that will mount nothing.
//!
//! ## Prove, do not assert
//!
//! Every probe here runs something. A mode is available because a command
//! answered, not because a file exists at a path where the feature would live.
//! That distinction is the whole history of this surface: `kin doctor` used to
//! infer projection's presence from one path and state the guess as fact, and
//! FIR-2394 replaced that with a driver it actually executes. The same
//! discipline applies to the mount modes, with one addition that matters today:
//! the shipped `kin-vfs` binary is built without the `nfs` and `fuse` features,
//! so the subcommands below are absent from it. Kin asks the driver which
//! subcommands it carries rather than assuming, reports the absence with the
//! path to a driver that has them, and falls back to the shim with a message.
//! It never reports a mount that is not running.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use console::style;

use crate::commands::health::{
    pinned_vfs_driver, resolve_vfs_driver, vfs_driver_candidates, VfsDriverState,
};
use crate::commands::setup::{check_binary_in_path, kin_dir, shim_filename};

/// Every `kin-vfs` subcommand Kin drives, named once.
///
/// The mount features are compiled out of the shipped driver, and the work that
/// makes them real is landing in `kin-vfs` under these names. Keeping them in
/// one place means a rename downstream is one edit here, and the probe that
/// asks a driver which subcommands it carries reads the same constants the
/// engage path spawns.
pub(crate) mod driver {
    /// Present in every build. Used as the control that proves a parsed help
    /// listing is readable at all, so an unparseable help cannot masquerade as
    /// a driver carrying no mount features.
    pub const STATUS: &str = "status";
    pub const NFS_START: &str = "nfs-start";
    pub const NFS_STOP: &str = "nfs-stop";
    pub const NFS_STATUS: &str = "nfs-status";
    pub const WORKSPACES: &str = "workspaces";
    pub const MOUNT: &str = "mount";
    pub const UNMOUNT: &str = "unmount";
    pub const FUSE_STATUS: &str = "fuse-status";
}

/// Where a driver carrying the mount features comes from, for every message
/// that has to explain an absent one. Naming the build is the honest remedy
/// while the shipped binary has neither feature.
pub(crate) const MOUNT_FEATURE_REMEDY: &str =
    "the shipped kin-vfs is built without the mount features; build one that has them with \
     `cargo build --release -p kin-vfs-cli --features nfs` (or `--features fuse`) from the \
     kin-vfs repository, then point Kin at it with KIN_VFS_BIN=/path/to/kin-vfs";

/// A projection: one way graph truth is presented as files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProjectionMode {
    /// The injected `libkin_vfs_shim`, engaged per process by the shell hook.
    Shim,
    /// An NFSv3 mount served by `kin-vfs`.
    Nfs,
    /// A FUSE mount served by `kin-vfs`.
    Fuse,
}

impl ProjectionMode {
    /// The token used in config and on the command line.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Shim => "shim",
            Self::Nfs => "nfs",
            Self::Fuse => "fuse",
        }
    }

    /// Parse a recorded or user-supplied token.
    pub(crate) fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "shim" => Some(Self::Shim),
            "nfs" => Some(Self::Nfs),
            "fuse" => Some(Self::Fuse),
            _ => None,
        }
    }

    /// Whether this mode presents the repository at a mount point rather than
    /// inside the process that asked.
    pub(crate) fn is_mount(self) -> bool {
        matches!(self, Self::Nfs | Self::Fuse)
    }

    /// One line on what this projection is, for `kin vfs status` and the docs
    /// surface that has to explain a fallback.
    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::Shim => {
                "injected into each process by the shell hook; no mount, and an OS that strips \
                 the injection leaves the process on raw disk"
            }
            Self::Nfs => "an NFSv3 mount served by kin-vfs; every tool on the host sees it",
            Self::Fuse => "a FUSE mount served by kin-vfs; every tool on the host sees it",
        }
    }
}

impl std::fmt::Display for ProjectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The order modes are tried in on `os`, best first.
///
/// Split out from the chooser and taken as a plain string so both platform
/// orders are testable from either platform. A host that is neither macOS nor
/// Linux has no projection mount Kin drives, so it gets the shim alone rather
/// than an order that would probe two features it cannot have.
pub(crate) fn fallback_order(os: &str) -> Vec<ProjectionMode> {
    match os {
        "macos" => vec![
            ProjectionMode::Nfs,
            ProjectionMode::Fuse,
            ProjectionMode::Shim,
        ],
        "linux" => vec![
            ProjectionMode::Fuse,
            ProjectionMode::Nfs,
            ProjectionMode::Shim,
        ],
        _ => vec![ProjectionMode::Shim],
    }
}

/// What a probe of one mode found.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ModeProbe {
    pub mode: ProjectionMode,
    /// Whether this mode can be engaged on this host right now.
    pub available: bool,
    /// The literal result the probe produced. Never a restatement of `available`.
    pub evidence: String,
    /// What to do about an unavailable mode, when there is something to do.
    pub remedy: Option<String>,
}

/// The resolved projection driver and the subcommands it actually carries.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DriverProbe {
    /// Where the driver that answered is, when one did.
    pub path: Option<PathBuf>,
    /// The loader's complaint when a driver is present and refuses to run.
    pub refusal: Option<String>,
    /// The subcommands parsed out of the driver's own help, or `None` when the
    /// help could not be read as a listing at all.
    pub subcommands: Option<BTreeSet<String>>,
}

impl DriverProbe {
    /// Whether a driver ran.
    pub(crate) fn runs(&self) -> bool {
        self.path.is_some() && self.refusal.is_none()
    }

    /// Whether the running driver carries `subcommand`.
    ///
    /// An unreadable help answers no, and the caller reports that as unreadable
    /// rather than absent: a help listing Kin cannot parse is a fact about the
    /// probe, not about the feature.
    pub(crate) fn carries(&self, subcommand: &str) -> bool {
        self.subcommands
            .as_ref()
            .is_some_and(|found| found.contains(subcommand))
    }
}

/// Run the resolved driver once and read both facts out of the same run:
/// whether it loads, and which subcommands it was built with.
pub(crate) fn probe_driver(kin_home: &Path, exe: Option<&Path>) -> DriverProbe {
    match resolve_vfs_driver(&vfs_driver_candidates(
        pinned_vfs_driver().as_deref(),
        kin_home,
        exe,
    )) {
        VfsDriverState::Absent => DriverProbe {
            path: None,
            refusal: None,
            subcommands: None,
        },
        VfsDriverState::Unloadable { path, message } => DriverProbe {
            path: Some(path),
            refusal: Some(message),
            subcommands: None,
        },
        VfsDriverState::Loadable(path) => {
            let subcommands = driver_help(&path).as_deref().and_then(parse_subcommands);
            DriverProbe {
                path: Some(path),
                refusal: None,
                subcommands,
            }
        }
    }
}

/// The driver's own `--help`, as text.
fn driver_help(path: &Path) -> Option<String> {
    let output = Command::new(path)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    // clap prints help to stdout for `--help` and to stderr for a usage error.
    // Reading both means a driver that answers either way is still readable.
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Some(text)
}

/// Parse the subcommand names out of a clap help listing.
///
/// Returns `None` when the parse produced no listing it can trust. The test for
/// that is not "the set is empty" but "the set is missing a subcommand every
/// build has": `kin-vfs status` is unconditional, so a listing without it did
/// not parse, and reporting that as "this driver has no mount features" would
/// be a confident negative built from a broken read. Every mount probe treats
/// an unreadable listing as unknown rather than absent for exactly that reason.
pub(crate) fn parse_subcommands(help: &str) -> Option<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    let mut in_commands = false;
    for line in help.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim().eq_ignore_ascii_case("commands:") {
            in_commands = true;
            continue;
        }
        if !in_commands {
            continue;
        }
        // A blank line or an unindented heading ends the section.
        if trimmed.trim().is_empty() || !trimmed.starts_with(char::is_whitespace) {
            if trimmed.trim().is_empty() {
                continue;
            }
            break;
        }
        if let Some(name) = trimmed.split_whitespace().next() {
            if name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                found.insert(name.to_string());
            }
        }
    }
    found.contains(driver::STATUS).then_some(found)
}

/// The host's NFS client binary, when it has one.
///
/// A mount needs a client in userspace, and the two platforms name it
/// differently. This is the only part of the NFS probe that is about the host
/// rather than about Kin's driver.
pub(crate) fn nfs_client_binary() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(target_os = "macos") {
        &["mount_nfs"]
    } else {
        &["mount.nfs", "mount.nfs4"]
    };
    names.iter().find_map(|name| {
        check_binary_in_path(name).or_else(|| {
            // The mount helpers live in sbin, which is off an ordinary user's
            // PATH on most Linux distributions and on macOS.
            ["/sbin", "/usr/sbin", "/usr/local/sbin"]
                .iter()
                .map(|dir| Path::new(dir).join(name))
                .find(|candidate| candidate.is_file())
        })
    })
}

/// Ask the driver whether FUSE is available, and return its literal answer.
///
/// The driver prints `FUSE available: <variant>` or `FUSE not available: <e>`,
/// so the variant (FUSE-T, macFUSE, libfuse) reaches the report rather than a
/// yes or no Kin invented.
fn fuse_availability(path: &Path) -> Option<(bool, String)> {
    let output = Command::new(path)
        .arg(driver::FUSE_STATUS)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("FUSE "))?;
    Some((line.starts_with("FUSE available"), line.to_string()))
}

/// Probe every mode against one resolved driver.
pub(crate) fn probe_modes(driver: &DriverProbe, shim: &ShimPresence) -> Vec<ModeProbe> {
    fallback_order(std::env::consts::OS)
        .into_iter()
        .map(|mode| match mode {
            ProjectionMode::Shim => probe_shim_mode(driver, shim),
            ProjectionMode::Nfs => probe_nfs_mode(driver),
            ProjectionMode::Fuse => probe_fuse_mode(driver),
        })
        .collect()
}

/// Whether the shim library is installed, and whether it is engaged here.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ShimPresence {
    /// The library path Kin looks for.
    pub path: PathBuf,
    /// Whether a file is there at all.
    pub installed: bool,
    /// Whether the current process was launched with the shim preloaded.
    pub engaged: bool,
}

/// Read the shim's installed and engaged state.
pub(crate) fn probe_shim(kin_home: &Path) -> ShimPresence {
    let path = kin_home.join("lib").join(shim_filename());
    ShimPresence {
        installed: path.is_file(),
        engaged: shim_engaged(&preload_value(), shim_filename()),
        path,
    }
}

/// The preload variable this platform injects through, as the process sees it.
fn preload_value() -> String {
    let name = if cfg!(target_os = "macos") {
        "DYLD_INSERT_LIBRARIES"
    } else {
        "LD_PRELOAD"
    };
    std::env::var(name).unwrap_or_default()
}

/// Whether a preload list names Kin's shim.
///
/// Pure over the variable's value so both the engaged and the not-engaged case
/// are testable without launching a process under an injected library. Matching
/// on the file name rather than the full path is deliberate: a lane build, a
/// Homebrew install and a managed install all inject the same library from
/// different directories, and the question here is whether this process is
/// running under Kin's shim at all.
pub(crate) fn shim_engaged(preload: &str, filename: &str) -> bool {
    preload
        .split([':', ' '])
        .filter(|entry| !entry.is_empty())
        .any(|entry| Path::new(entry).file_name().is_some_and(|f| f == filename))
}

fn probe_shim_mode(driver: &DriverProbe, shim: &ShimPresence) -> ModeProbe {
    let (available, evidence, remedy) = match (&driver.refusal, shim.installed) {
        (Some(message), _) => (
            false,
            format!(
                "the kin-vfs driver at {} will not run: {message}",
                driver
                    .path
                    .as_deref()
                    .unwrap_or(Path::new("an unknown path"))
                    .display()
            ),
            Some(
                "reinstall kin for this platform: curl -fsSL https://get.kinlab.dev/install | sh"
                    .to_string(),
            ),
        ),
        (None, false) => (
            false,
            format!("no shim library at {}", shim.path.display()),
            Some(
                "reinstall kin to restore the shim: curl -fsSL https://get.kinlab.dev/install | sh"
                    .to_string(),
            ),
        ),
        (None, true) => (
            true,
            format!(
                "shim library at {} ({})",
                shim.path.display(),
                if shim.engaged {
                    "preloaded into this process"
                } else {
                    "not preloaded into this process"
                }
            ),
            None,
        ),
    };
    ModeProbe {
        mode: ProjectionMode::Shim,
        available,
        evidence,
        remedy,
    }
}

fn probe_nfs_mode(driver: &DriverProbe) -> ModeProbe {
    let Some(path) = driver.path.as_deref().filter(|_| driver.runs()) else {
        return unavailable_without_driver(ProjectionMode::Nfs, driver);
    };
    if driver.subcommands.is_none() {
        return ModeProbe {
            mode: ProjectionMode::Nfs,
            available: false,
            evidence: format!(
                "the driver at {} ran but its help could not be read as a subcommand listing, so \
                 whether it carries {} is unknown",
                path.display(),
                driver::NFS_START
            ),
            remedy: Some(MOUNT_FEATURE_REMEDY.to_string()),
        };
    }
    if !driver.carries(driver::NFS_START) {
        return ModeProbe {
            mode: ProjectionMode::Nfs,
            available: false,
            evidence: format!(
                "the driver at {} does not carry `{}`, so it was built without the nfs feature",
                path.display(),
                driver::NFS_START
            ),
            remedy: Some(MOUNT_FEATURE_REMEDY.to_string()),
        };
    }
    match nfs_client_binary() {
        Some(client) => ModeProbe {
            mode: ProjectionMode::Nfs,
            available: true,
            evidence: format!(
                "the driver at {} carries `{}` and this host has an NFS client at {}",
                path.display(),
                driver::NFS_START,
                client.display()
            ),
            remedy: None,
        },
        None => ModeProbe {
            mode: ProjectionMode::Nfs,
            available: false,
            evidence: format!(
                "the driver at {} carries `{}` but no NFS client binary was found on PATH or in \
                 the sbin directories",
                path.display(),
                driver::NFS_START
            ),
            remedy: Some(
                "install this host's NFS client package (nfs-common on Debian and Ubuntu, \
                 nfs-utils on Fedora and Arch); macOS carries mount_nfs in the base system"
                    .to_string(),
            ),
        },
    }
}

fn probe_fuse_mode(driver: &DriverProbe) -> ModeProbe {
    let Some(path) = driver.path.as_deref().filter(|_| driver.runs()) else {
        return unavailable_without_driver(ProjectionMode::Fuse, driver);
    };
    if driver.subcommands.is_none() {
        return ModeProbe {
            mode: ProjectionMode::Fuse,
            available: false,
            evidence: format!(
                "the driver at {} ran but its help could not be read as a subcommand listing, so \
                 whether it carries {} is unknown",
                path.display(),
                driver::MOUNT
            ),
            remedy: Some(MOUNT_FEATURE_REMEDY.to_string()),
        };
    }
    if !driver.carries(driver::MOUNT) || !driver.carries(driver::FUSE_STATUS) {
        return ModeProbe {
            mode: ProjectionMode::Fuse,
            available: false,
            evidence: format!(
                "the driver at {} does not carry `{}`, so it was built without the fuse feature",
                path.display(),
                driver::MOUNT
            ),
            remedy: Some(MOUNT_FEATURE_REMEDY.to_string()),
        };
    }
    match fuse_availability(path) {
        Some((true, line)) => ModeProbe {
            mode: ProjectionMode::Fuse,
            available: true,
            evidence: format!("the driver at {} reports: {line}", path.display()),
            remedy: None,
        },
        Some((false, line)) => ModeProbe {
            mode: ProjectionMode::Fuse,
            available: false,
            evidence: format!("the driver at {} reports: {line}", path.display()),
            remedy: Some(
                "install FUSE-T or macFUSE on macOS, or libfuse on Linux, then run `kin vfs on` \
                 again"
                    .to_string(),
            ),
        },
        None => ModeProbe {
            mode: ProjectionMode::Fuse,
            available: false,
            evidence: format!(
                "the driver at {} carries `{}` but answered nothing readable",
                path.display(),
                driver::FUSE_STATUS
            ),
            remedy: Some(MOUNT_FEATURE_REMEDY.to_string()),
        },
    }
}

fn unavailable_without_driver(mode: ProjectionMode, driver: &DriverProbe) -> ModeProbe {
    let (evidence, remedy) = match (&driver.path, &driver.refusal) {
        (Some(path), Some(message)) => (
            format!(
                "the kin-vfs driver at {} will not run: {message}",
                path.display()
            ),
            Some(
                "reinstall kin for this platform: curl -fsSL https://get.kinlab.dev/install | sh"
                    .to_string(),
            ),
        ),
        _ => (
            "no kin-vfs driver was found beside the kin binary, in ~/.kin/bin, or on PATH"
                .to_string(),
            Some(MOUNT_FEATURE_REMEDY.to_string()),
        ),
    };
    ModeProbe {
        mode,
        available: false,
        evidence,
        remedy,
    }
}

/// Pick the mode to run, given an explicit request, a recorded choice, and what
/// the probes found.
///
/// Precedence is request, then recording, then the fallback order. A requested
/// or recorded mode that is not available does NOT silently become another one:
/// the caller is told which mode it asked for, which it got, and why. That
/// difference is what `degraded` reports, and collapsing it here would make the
/// honest row impossible to build.
pub(crate) fn choose_mode(
    requested: Option<ProjectionMode>,
    recorded: Option<ProjectionMode>,
    probes: &[ModeProbe],
) -> (ProjectionMode, ProjectionMode) {
    let available = |mode: ProjectionMode| {
        probes
            .iter()
            .any(|probe| probe.mode == mode && probe.available)
    };
    let intent = requested
        .or(recorded)
        .unwrap_or_else(|| first_available(probes));
    let effective = if available(intent) {
        intent
    } else {
        first_available(probes)
    };
    (intent, effective)
}

/// The best mode the probes say can run, or the shim when none can.
///
/// The shim is the floor rather than an error: a host where nothing is
/// available still gets a named mode, and the row that reports it carries the
/// probe evidence saying the shim is not working either.
fn first_available(probes: &[ModeProbe]) -> ProjectionMode {
    probes
        .iter()
        .find(|probe| probe.available)
        .map(|probe| probe.mode)
        .unwrap_or(ProjectionMode::Shim)
}

// ---------------------------------------------------------------------------
// Live state: what the projection is actually doing right now
// ---------------------------------------------------------------------------

/// A probe answer that can also be inapplicable. `Yes`/`No` are measurements;
/// `NotApplicable` is the shim's honest answer to "is it mounted", and it must
/// not be spelled `No`, which would read as a mount that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Tri {
    Yes,
    No,
    NotApplicable,
}

impl Tri {
    fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::NotApplicable => "n/a",
        }
    }
}

/// The projection in force for one repository, as probed.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct LiveProjection {
    /// The mode the user asked for, explicitly or through a recorded choice.
    pub intent: ProjectionMode,
    /// The mode actually in force.
    pub mode: ProjectionMode,
    /// Where the projected files are, when the mode presents them somewhere.
    pub at: PathBuf,
    pub mounted: Tri,
    pub readable: Tri,
    pub writable: Tri,
    /// True when the mode in force is not the intent, or when the mode in force
    /// failed one of its own probes.
    pub degraded: bool,
    /// The literal probe results, in the order they were taken.
    pub evidence: Vec<String>,
}

impl LiveProjection {
    /// The one-line form used by the doctor row and by `kin status`.
    pub(crate) fn row(&self) -> String {
        format!(
            "mode={} mounted={} readable={} writable={} degraded={}",
            self.mode,
            self.mounted.as_str(),
            self.readable.as_str(),
            self.writable.as_str(),
            if self.degraded { "yes" } else { "no" }
        )
    }
}

/// Whether `path` is the root of a mounted filesystem.
///
/// Compared by device id against the parent directory, which is what a mount
/// actually is, rather than by asking a command whether it mounted something
/// earlier. A path that does not exist is not a mount point.
#[cfg(unix)]
pub(crate) fn is_mount_point(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(here) = std::fs::metadata(path) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        // `/` has no parent and is always a mount point.
        return true;
    };
    match std::fs::metadata(parent) {
        Ok(above) => here.dev() != above.dev(),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub(crate) fn is_mount_point(_path: &Path) -> bool {
    false
}

/// Read one entry out of `path`, and say what happened in the caller's words.
pub(crate) fn probe_readable(path: &Path) -> (Tri, String) {
    match std::fs::read_dir(path) {
        Ok(mut entries) => match entries.next() {
            Some(Ok(entry)) => (
                Tri::Yes,
                format!(
                    "read {} and it lists {}",
                    path.display(),
                    entry.file_name().to_string_lossy()
                ),
            ),
            Some(Err(error)) => (
                Tri::No,
                format!("{} listed an unreadable entry: {error}", path.display()),
            ),
            None => (Tri::Yes, format!("read {} and it is empty", path.display())),
        },
        Err(error) => (
            Tri::No,
            format!("could not read {}: {error}", path.display()),
        ),
    }
}

/// Write a file under `path`, read it back, and remove it.
///
/// A write that is not read back is not proof of a writable projection: a mount
/// can accept a write into a cache it never serves. The bytes are compared, and
/// the probe file is removed whichever way the comparison goes.
pub(crate) fn probe_writable(path: &Path) -> (Tri, String) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let probe = path.join(format!(
        ".kin-projection-probe-{}-{nonce}",
        std::process::id()
    ));
    let payload = format!("kin projection probe {nonce}");
    if let Err(error) = std::fs::write(&probe, payload.as_bytes()) {
        return (
            Tri::No,
            format!("could not write under {}: {error}", path.display()),
        );
    }
    let read_back = std::fs::read_to_string(&probe);
    let _ = std::fs::remove_file(&probe);
    match read_back {
        Ok(found) if found == payload => (
            Tri::Yes,
            format!(
                "wrote a probe file under {} and read it back",
                path.display()
            ),
        ),
        Ok(_) => (
            Tri::No,
            format!(
                "wrote a probe file under {} and read back different bytes",
                path.display()
            ),
        ),
        Err(error) => (
            Tri::No,
            format!(
                "wrote a probe file under {} and could not read it back: {error}",
                path.display()
            ),
        ),
    }
}

/// The directory the NFS server mounts under.
pub(crate) fn mount_root(kin_home: &Path) -> PathBuf {
    kin_home.join("mnt")
}

/// Where one repository appears under a mount.
pub(crate) fn repo_mount_point(kin_home: &Path, repo_root: &Path) -> PathBuf {
    let name = repo_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "repo".to_string());
    mount_root(kin_home).join(name)
}

/// The driver's own account of the mount it is serving.
///
/// Kin measures the mount itself by device id, which is the fact that decides
/// whether files are being served from the graph. This asks the driver as well,
/// because the two can disagree in a way worth seeing: a driver holding a live
/// server whose mount the kernel dropped reports running while the device test
/// says no. Its answer is quoted, never substituted for the measurement.
fn driver_mount_report(driver: &DriverProbe, mode: ProjectionMode) -> Option<String> {
    let path = driver.path.as_deref().filter(|_| driver.runs())?;
    let subcommand = match mode {
        ProjectionMode::Nfs => driver::NFS_STATUS,
        ProjectionMode::Fuse => driver::FUSE_STATUS,
        ProjectionMode::Shim => return None,
    };
    if !driver.carries(subcommand) {
        return None;
    }
    let output = Command::new(path)
        .arg(subcommand)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = first_line(&text);
    Some(format!("`kin-vfs {subcommand}` says: {summary}"))
}

/// Probe the projection actually in force for `repo_root`.
///
/// For a mount, the projected path is the mount point and the probes are taken
/// there. For the shim, the projected path is the repository itself, because
/// that is where an injected process sees graph truth, and `mounted` is
/// inapplicable rather than false.
pub(crate) fn probe_live(
    intent: ProjectionMode,
    mode: ProjectionMode,
    kin_home: &Path,
    repo_root: &Path,
    shim: &ShimPresence,
) -> LiveProjection {
    let mut evidence = Vec::new();
    let at = if mode.is_mount() {
        repo_mount_point(kin_home, repo_root)
    } else {
        repo_root.to_path_buf()
    };

    let mounted = if mode.is_mount() {
        let mounted = is_mount_point(&at);
        evidence.push(format!(
            "{} {} the root of a mounted filesystem",
            at.display(),
            if mounted { "is" } else { "is not" }
        ));
        if mounted {
            Tri::Yes
        } else {
            Tri::No
        }
    } else {
        evidence.push(format!(
            "the shim is injected per process, not mounted; it {} preloaded into this process",
            if shim.engaged { "is" } else { "is not" }
        ));
        Tri::NotApplicable
    };

    // A mount that is not mounted has nothing to read or write at, and probing
    // the empty mount point would report the host directory underneath it as
    // the projection. That is precisely the false green this surface exists to
    // stop, so the read and write probes are skipped and said to be skipped.
    let (readable, writable) = if mode.is_mount() && mounted != Tri::Yes {
        evidence.push(
            "read and write were not probed: there is no mount at the projected path, so any \
             answer would describe the host directory underneath it"
                .to_string(),
        );
        (Tri::No, Tri::No)
    } else {
        let (readable, read_evidence) = probe_readable(&at);
        evidence.push(read_evidence);
        // Writability is a question about a mount, and it is asked by writing
        // into the mount point under ~/.kin/mnt. It is deliberately NOT asked
        // of the shim: the shim serves reads out of the graph and lets writes
        // land on disk, where admission picks them up, so there is nothing
        // about writing the projection decides. Probing it anyway would mean
        // creating and deleting a file inside the user's repository on every
        // `kin doctor` and every `kin status`, which is a working tree change
        // and a reconcile wake-up in exchange for an answer that is always yes.
        if mode.is_mount() {
            let (writable, write_evidence) = probe_writable(&at);
            evidence.push(write_evidence);
            (readable, writable)
        } else {
            evidence.push(
                "writes are not projected: under the shim they land on disk and reach the graph \
                 through admission"
                    .to_string(),
            );
            (readable, Tri::NotApplicable)
        }
    };

    let mode_failed = match mode {
        ProjectionMode::Shim => !shim.engaged || readable != Tri::Yes,
        ProjectionMode::Nfs | ProjectionMode::Fuse => mounted != Tri::Yes || readable != Tri::Yes,
    };
    // Both halves of "not projected" get their own sentence, because they need
    // different things done about them and a reader who is told the wrong one
    // goes looking in the wrong place. A shim on disk that is not injected wants
    // a new shell; no shim at all wants an install.
    if mode == ProjectionMode::Shim && !shim.engaged {
        evidence.push(if shim.installed {
            "the shim is installed but not engaged in this shell, so this process is reading raw \
             disk rather than graph truth"
                .to_string()
        } else {
            format!(
                "no shim is installed at {}, so nothing is projecting this directory and this \
                 process is reading raw disk",
                shim.path.display()
            )
        });
    }
    if intent != mode {
        evidence.push(format!(
            "{intent} was chosen but is not available here, so {mode} is in force"
        ));
    }

    LiveProjection {
        intent,
        mode,
        at,
        mounted,
        readable,
        writable,
        degraded: intent != mode || mode_failed,
        evidence,
    }
}

// ---------------------------------------------------------------------------
// The recorded choice, in `~/.kin/config/setup.toml`
// ---------------------------------------------------------------------------

/// The header every generated `setup.toml` carries.
pub(crate) const SETUP_TOML_HEADER: &str = "# Generated by: kin setup\n";

/// Where the recorded projection mode lives.
pub(crate) fn setup_config_path(kin_home: &Path) -> PathBuf {
    kin_home.join("config").join("setup.toml")
}

/// Read one string key out of a `setup.toml` body.
pub(crate) fn config_str(body: &str, table: &str, key: &str) -> Option<String> {
    body.parse::<toml::Table>()
        .ok()?
        .get(table)?
        .as_table()?
        .get(key)?
        .as_str()
        .map(ToOwned::to_owned)
}

/// Read one boolean key out of a `setup.toml` body. Test-only for now: the
/// daemon key is written here and read by the daemon, not by this crate.
#[cfg(test)]
pub(crate) fn config_bool(body: &str, table: &str, key: &str) -> Option<bool> {
    body.parse::<toml::Table>()
        .ok()?
        .get(table)?
        .as_table()?
        .get(key)?
        .as_bool()
}

/// Set one key in `setup.toml`, preserving every other table.
///
/// Pure over the text so it is testable without a real `~/.kin`, and a
/// read-modify-write rather than a rewrite because two different settings now
/// live in this file. The previous writer replaced the whole file on every
/// `kin setup` run, which would have silently discarded a recorded projection
/// mode the next time anyone ran setup.
pub(crate) fn config_set(body: &str, table: &str, key: &str, value: toml::Value) -> Result<String> {
    let mut root: toml::Table = if body.trim().is_empty() {
        toml::Table::new()
    } else {
        body.parse().context("parsing ~/.kin/config/setup.toml")?
    };
    let entry = root
        .entry(table.to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if !entry.is_table() {
        *entry = toml::Value::Table(toml::Table::new());
    }
    entry
        .as_table_mut()
        .expect("entry was just made a table")
        .insert(key.to_string(), value);
    Ok(format!(
        "{SETUP_TOML_HEADER}{}",
        toml::to_string_pretty(&root)?
    ))
}

/// The projection mode recorded on this machine, if any.
pub(crate) fn recorded_mode(kin_home: &Path) -> Option<ProjectionMode> {
    let body = std::fs::read_to_string(setup_config_path(kin_home)).ok()?;
    ProjectionMode::parse(&config_str(&body, "projection", "mode")?)
}

/// Record the projection mode this machine should use.
pub(crate) fn record_mode(kin_home: &Path, mode: ProjectionMode) -> Result<()> {
    let path = setup_config_path(kin_home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    let updated = config_set(
        &body,
        "projection",
        "mode",
        toml::Value::String(mode.as_str().to_string()),
    )?;
    std::fs::write(&path, updated).with_context(|| format!("failed to write {}", path.display()))
}

// ---------------------------------------------------------------------------
// The report every surface reads
// ---------------------------------------------------------------------------

/// Everything the projection surfaces report, probed once.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ProjectionReport {
    pub recorded: Option<ProjectionMode>,
    pub modes: Vec<ModeProbe>,
    /// The driver as probed. Carried on the report because "no projection is
    /// installed here" and "a projection is installed and the loader refuses
    /// it" are the same absence of available modes and must not be the same
    /// row: the first is what an install that ships without projection looks
    /// like, the second is a container reading raw disk.
    pub driver: DriverProbe,
    pub shim: ShimPresence,
    pub live: LiveProjection,
}

/// Probe the whole projection surface for `repo_root`.
///
/// One entry point so `kin doctor`, `kin status` and `kin vfs status` cannot
/// drift into three different answers about the same machine.
pub(crate) fn report_for(
    kin_home: &Path,
    exe: Option<&Path>,
    repo_root: &Path,
    requested: Option<ProjectionMode>,
) -> ProjectionReport {
    let driver = probe_driver(kin_home, exe);
    let shim = probe_shim(kin_home);
    let modes = probe_modes(&driver, &shim);
    let recorded = recorded_mode(kin_home);
    let (intent, mode) = choose_mode(requested, recorded, &modes);
    let mut live = probe_live(intent, mode, kin_home, repo_root, &shim);
    if let Some(line) = driver_mount_report(&driver, mode) {
        live.evidence.push(line);
    }
    ProjectionReport {
        recorded,
        modes,
        driver,
        shim,
        live,
    }
}

/// Probe without a repository, for surfaces that run outside one.
pub(crate) fn report_here(requested: Option<ProjectionMode>) -> Result<ProjectionReport> {
    let kin_home = kin_dir()?;
    let repo_root = crate::commands::require_repository_layout()
        .map(|layout| layout.root().to_path_buf())
        .or_else(|_| std::env::current_dir())?;
    Ok(report_for(
        &kin_home,
        std::env::current_exe().ok().as_deref(),
        &repo_root,
        requested,
    ))
}

/// One line naming the projection in force, for the status surfaces.
///
/// Rides alongside the status report rather than inside it, the same way store
/// size and the build stamp do: a [`crate::commands::status::StatusReport`] is
/// derived from one immutable authority lease and must not vary with the
/// filesystem the command is standing on, and which projection is mounted here
/// is exactly that kind of fact. A probe that cannot run says so rather than
/// leaving the line off, because a silent status is what lets someone edit raw
/// disk believing the graph took it.
pub(crate) fn status_line(repo_root: &Path) -> String {
    let Ok(kin_home) = kin_dir() else {
        return "Projection: unknown (could not resolve ~/.kin)".to_string();
    };
    let report = report_for(
        &kin_home,
        std::env::current_exe().ok().as_deref(),
        repo_root,
        None,
    );
    format!(
        "Projection: {} (files at {}){}",
        report.live.row(),
        report.live.at.display(),
        if report.live.degraded {
            "; run `kin vfs status` for why"
        } else {
            ""
        }
    )
}

// ---------------------------------------------------------------------------
// `kin vfs`
// ---------------------------------------------------------------------------

/// Run one `kin-vfs` subcommand and report its literal outcome.
fn run_driver(path: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run {} {}", path.display(), args.join(" ")))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        anyhow::bail!(
            "{} {} exited with {}: {}",
            path.display(),
            args.join(" "),
            output.status,
            first_line(&text)
        )
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no output")
        .to_string()
}

/// `kin vfs on`: engage the chosen projection for this repository.
pub async fn on(mode: Option<String>) -> Result<()> {
    let requested = parse_requested(mode.as_deref())?;
    let kin_home = kin_dir()?;
    let layout = crate::commands::require_repository_layout()?;
    let repo_root = layout.root().to_path_buf();
    let exe = std::env::current_exe().ok();
    let driver = probe_driver(&kin_home, exe.as_deref());
    let shim = probe_shim(&kin_home);
    let modes = probe_modes(&driver, &shim);
    let recorded = recorded_mode(&kin_home);
    let (intent, effective) = choose_mode(requested, recorded, &modes);

    if intent != effective {
        let blocked = modes.iter().find(|probe| probe.mode == intent);
        println!(
            "{} {intent} is not available here, so Kin is falling back to {effective}.",
            style("!").yellow()
        );
        if let Some(probe) = blocked {
            println!("  {}", probe.evidence);
            if let Some(remedy) = &probe.remedy {
                println!("  {remedy}");
            }
        }
        println!();
    }

    match effective {
        ProjectionMode::Shim => engage_shim(&shim, &modes)?,
        ProjectionMode::Nfs => engage_nfs(&driver, &repo_root)?,
        ProjectionMode::Fuse => engage_fuse(&driver, &kin_home, &repo_root)?,
    }

    // Record intent, never the fallback: a recorded mode is what the user asked
    // for, and overwriting it with what happened to work would make doctor
    // unable to say a configured mode is degraded. A machine with nothing
    // recorded gets the mode that actually engaged.
    let to_record = requested.or(recorded).unwrap_or(effective);
    record_mode(&kin_home, to_record)?;

    let live = probe_live(intent, effective, &kin_home, &repo_root, &shim);
    println!();
    print_live(&live);
    Ok(())
}

/// `kin vfs off`: disengage the projection for this repository.
pub async fn off() -> Result<()> {
    let kin_home = kin_dir()?;
    let repo_root = crate::commands::require_repository_layout()?
        .root()
        .to_path_buf();
    let exe = std::env::current_exe().ok();
    let driver = probe_driver(&kin_home, exe.as_deref());
    let shim = probe_shim(&kin_home);
    let modes = probe_modes(&driver, &shim);
    let (_, effective) = choose_mode(None, recorded_mode(&kin_home), &modes);

    match effective {
        ProjectionMode::Shim => {
            println!(
                "{} The shim is injected into each process as it starts, so it cannot be \
                 withdrawn from a shell that is already running.",
                style("i").cyan()
            );
            println!("  Set KIN_VFS_DISABLE=1 and the hook will leave new shells on raw disk.");
        }
        ProjectionMode::Nfs => {
            let Some(path) = driver.path.as_deref().filter(|_| driver.runs()) else {
                anyhow::bail!("no kin-vfs driver to stop the NFS mount with");
            };
            let out = run_driver(path, &[driver::NFS_STOP])?;
            println!("{} {}", style("✓").green(), first_line(&out));
        }
        ProjectionMode::Fuse => {
            let Some(path) = driver.path.as_deref().filter(|_| driver.runs()) else {
                anyhow::bail!("no kin-vfs driver to unmount with");
            };
            let point = repo_mount_point(&kin_home, &repo_root);
            let out = run_driver(
                path,
                &[driver::UNMOUNT, "--mount-point", &point.to_string_lossy()],
            )?;
            println!("{} {}", style("✓").green(), first_line(&out));
        }
    }
    Ok(())
}

/// `kin vfs status`: what projection is in force, probed live.
pub async fn status(json: bool) -> Result<()> {
    let report = report_here(None)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("Projection modes on this host:");
    for probe in &report.modes {
        let mark = if probe.available {
            style("✓").green()
        } else {
            style("✗").red()
        };
        println!("  {mark} {:<5} {}", probe.mode.as_str(), probe.evidence);
        if let Some(remedy) = &probe.remedy {
            println!("        {remedy}");
        }
    }
    println!();
    match report.recorded {
        Some(mode) => println!("Recorded mode: {mode}"),
        None => println!("Recorded mode: none; Kin picks by the fallback order"),
    }
    println!();
    print_live(&report.live);
    Ok(())
}

fn print_live(live: &LiveProjection) {
    let mark = if live.degraded {
        style("!").yellow()
    } else {
        style("✓").green()
    };
    println!("{mark} Projection in force: {}", live.row());
    println!("  {}: {}", live.mode, live.mode.description());
    println!("  files at {}", live.at.display());
    for line in &live.evidence {
        println!("  {line}");
    }
}

fn parse_requested(mode: Option<&str>) -> Result<Option<ProjectionMode>> {
    match mode {
        None => Ok(None),
        Some(token) => ProjectionMode::parse(token).map(Some).ok_or_else(|| {
            anyhow::anyhow!("unknown projection mode {token:?}; expected shim, nfs, or fuse")
        }),
    }
}

fn engage_shim(shim: &ShimPresence, modes: &[ModeProbe]) -> Result<()> {
    let probe = modes
        .iter()
        .find(|probe| probe.mode == ProjectionMode::Shim);
    if let Some(probe) = probe {
        if !probe.available {
            println!("{} {}", style("✗").red(), probe.evidence);
            if let Some(remedy) = &probe.remedy {
                println!("  {remedy}");
            }
            anyhow::bail!("the shim projection cannot be engaged on this host");
        }
    }
    if shim.engaged {
        println!(
            "{} The shim is already preloaded into this process.",
            style("✓").green()
        );
    } else {
        println!(
            "{} The shim is installed at {}, and the shell hook injects it into each new \
             process rather than into one that is already running.",
            style("i").cyan(),
            shim.path.display()
        );
        println!("  Start a new shell, or run `exec $SHELL -l`, and this repository is projected.");
    }
    Ok(())
}

fn engage_nfs(driver: &DriverProbe, repo_root: &Path) -> Result<()> {
    let Some(path) = driver.path.as_deref().filter(|_| driver.runs()) else {
        anyhow::bail!("no kin-vfs driver to start the NFS mount with");
    };
    if driver.carries(driver::WORKSPACES) {
        let out = run_driver(
            path,
            &[
                driver::WORKSPACES,
                "add",
                "--path",
                &repo_root.to_string_lossy(),
            ],
        )?;
        println!("{} {}", style("✓").green(), first_line(&out));
    }
    let out = run_driver(path, &[driver::NFS_START])?;
    println!("{} {}", style("✓").green(), first_line(&out));
    Ok(())
}

fn engage_fuse(driver: &DriverProbe, kin_home: &Path, repo_root: &Path) -> Result<()> {
    let Some(path) = driver.path.as_deref().filter(|_| driver.runs()) else {
        anyhow::bail!("no kin-vfs driver to mount with");
    };
    let point = repo_mount_point(kin_home, repo_root);
    std::fs::create_dir_all(&point)
        .with_context(|| format!("failed to create {}", point.display()))?;
    let out = run_driver(
        path,
        &[
            driver::MOUNT,
            "--workspace",
            &repo_root.to_string_lossy(),
            "--mount-point",
            &point.to_string_lossy(),
        ],
    )?;
    println!("{} {}", style("✓").green(), first_line(&out));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `kin-vfs --help` from the shipped driver: `status` and `exec` are
    /// unconditional, and neither mount feature is compiled in.
    const SHIPPED_HELP: &str = "\
Virtual filesystem daemon for Kin

Usage: kin-vfs <COMMAND>

Commands:
  start   Start the VFS daemon for a workspace
  stop    Stop the running VFS daemon
  status  Show VFS daemon status
  exec    Run a command with VFS file interception active
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
";

    /// The same help from a driver built with both features.
    const FEATURED_HELP: &str = "\
Virtual filesystem daemon for Kin

Usage: kin-vfs <COMMAND>

Commands:
  start        Start the VFS daemon for a workspace
  stop         Stop the running VFS daemon
  status       Show VFS daemon status
  mount        Mount the VFS as a FUSE filesystem
  unmount      Unmount a FUSE virtual filesystem
  fuse-status  Check if FUSE is available on this system
  nfs-start    Start the NFS server and mount at ~/.kin/mnt/
  nfs-stop     Stop the NFS server and unmount
  nfs-status   Show NFS server status
  workspaces   Manage registered workspaces
  exec         Run a command with VFS file interception active
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
";

    fn loadable(help: &str) -> DriverProbe {
        DriverProbe {
            path: Some(PathBuf::from("/opt/kin/kin-vfs")),
            refusal: None,
            subcommands: parse_subcommands(help),
        }
    }

    /// The shipped driver carries neither mount feature, and that has to be
    /// readable off its own help rather than assumed. A parse that returned
    /// everything or nothing would make both mount probes useless.
    #[test]
    fn a_help_listing_names_exactly_the_subcommands_that_build_carries() {
        let shipped = parse_subcommands(SHIPPED_HELP).expect("shipped help must parse");
        assert!(shipped.contains(driver::STATUS));
        assert!(
            !shipped.contains(driver::NFS_START) && !shipped.contains(driver::MOUNT),
            "the shipped driver carries no mount subcommands: {shipped:?}"
        );

        let featured = parse_subcommands(FEATURED_HELP).expect("featured help must parse");
        for wanted in [
            driver::NFS_START,
            driver::NFS_STOP,
            driver::NFS_STATUS,
            driver::MOUNT,
            driver::UNMOUNT,
            driver::FUSE_STATUS,
            driver::WORKSPACES,
        ] {
            assert!(
                featured.contains(wanted),
                "a featured driver must list {wanted}: {featured:?}"
            );
        }
        assert!(
            !featured.contains("Options:") && !featured.contains("-h,"),
            "the option block must not be read as subcommands: {featured:?}"
        );
    }

    /// A help Kin cannot parse is unknown, not empty. Without the control the
    /// parse degrades silently to "this driver has no mount features", which is
    /// a confident negative built from a broken read and would survive every
    /// clap format change.
    #[test]
    fn an_unreadable_help_is_unknown_rather_than_an_absent_feature() {
        assert!(
            parse_subcommands("some other program's output\nwith no listing\n").is_none(),
            "a help with no Commands section must not parse as a listing"
        );
        assert!(
            parse_subcommands("Commands:\n  frobnicate  do a thing\n").is_none(),
            "a listing missing the control subcommand must not be trusted"
        );

        let unknown = DriverProbe {
            path: Some(PathBuf::from("/opt/kin/kin-vfs")),
            refusal: None,
            subcommands: None,
        };
        let probe = probe_nfs_mode(&unknown);
        assert!(!probe.available);
        assert!(
            probe.evidence.contains("could not be read"),
            "an unreadable help must be reported as unreadable: {}",
            probe.evidence
        );
    }

    /// The three modes must produce three different answers against the driver
    /// a user actually has today, and the mount ones must name the remedy.
    #[test]
    fn the_shipped_driver_offers_the_shim_and_refuses_both_mounts() {
        let driver = loadable(SHIPPED_HELP);
        let nfs = probe_nfs_mode(&driver);
        let fuse = probe_fuse_mode(&driver);

        assert!(!nfs.available && !fuse.available);
        assert!(
            nfs.evidence.contains(driver::NFS_START) && nfs.evidence.contains("nfs feature"),
            "the nfs row must name the missing subcommand: {}",
            nfs.evidence
        );
        assert!(
            fuse.evidence.contains(driver::MOUNT) && fuse.evidence.contains("fuse feature"),
            "the fuse row must name the missing subcommand: {}",
            fuse.evidence
        );
        for probe in [&nfs, &fuse] {
            assert!(
                probe
                    .remedy
                    .as_deref()
                    .is_some_and(|r| r.contains("--features")),
                "an absent mount feature must carry the build that has it: {:?}",
                probe.remedy
            );
        }
    }

    /// A driver the loader refuses fails every mode, including the shim, and
    /// carries the loader's own words into each row. An install with a shim
    /// file on disk beside a driver that will not run is broken, not healthy.
    #[test]
    fn a_driver_the_loader_refuses_fails_every_mode() {
        let refused = DriverProbe {
            path: Some(PathBuf::from("/opt/kin/kin-vfs")),
            refusal: Some("libc.so.6: version GLIBC_2.39 not found".to_string()),
            subcommands: None,
        };
        let shim = ShimPresence {
            path: PathBuf::from("/home/u/.kin/lib/libkin_vfs_shim.so"),
            installed: true,
            engaged: true,
        };
        for probe in [
            probe_shim_mode(&refused, &shim),
            probe_nfs_mode(&refused),
            probe_fuse_mode(&refused),
        ] {
            assert!(
                !probe.available,
                "{} must be unavailable behind a refused driver",
                probe.mode
            );
            assert!(
                probe.evidence.contains("GLIBC_2.39"),
                "{} must quote the loader: {}",
                probe.mode,
                probe.evidence
            );
        }
    }

    /// The order is platform-specific on purpose, and the shim is last in both.
    #[test]
    fn each_platform_prefers_its_native_mount_and_ends_at_the_shim() {
        assert_eq!(
            fallback_order("macos"),
            vec![
                ProjectionMode::Nfs,
                ProjectionMode::Fuse,
                ProjectionMode::Shim
            ]
        );
        assert_eq!(
            fallback_order("linux"),
            vec![
                ProjectionMode::Fuse,
                ProjectionMode::Nfs,
                ProjectionMode::Shim
            ]
        );
        assert_eq!(fallback_order("windows"), vec![ProjectionMode::Shim]);
        for os in ["macos", "linux", "windows"] {
            assert_eq!(
                fallback_order(os).last(),
                Some(&ProjectionMode::Shim),
                "{os} must fall back to the shim"
            );
        }
    }

    fn probes(available: &[ProjectionMode]) -> Vec<ModeProbe> {
        [
            ProjectionMode::Nfs,
            ProjectionMode::Fuse,
            ProjectionMode::Shim,
        ]
        .into_iter()
        .map(|mode| ModeProbe {
            mode,
            available: available.contains(&mode),
            evidence: format!("{mode} test probe"),
            remedy: None,
        })
        .collect()
    }

    /// A requested mode that cannot run must not be silently rewritten to the
    /// one that can. Intent and effect are two values, and collapsing them is
    /// what would make a degraded projection unreportable.
    #[test]
    fn an_unavailable_request_keeps_its_intent_and_falls_back() {
        let only_shim = probes(&[ProjectionMode::Shim]);
        assert_eq!(
            choose_mode(Some(ProjectionMode::Nfs), None, &only_shim),
            (ProjectionMode::Nfs, ProjectionMode::Shim)
        );
        assert_eq!(
            choose_mode(None, Some(ProjectionMode::Fuse), &only_shim),
            (ProjectionMode::Fuse, ProjectionMode::Shim)
        );

        // A request outranks a recording, and an available request is honored.
        let both = probes(&[ProjectionMode::Nfs, ProjectionMode::Shim]);
        assert_eq!(
            choose_mode(Some(ProjectionMode::Nfs), Some(ProjectionMode::Shim), &both),
            (ProjectionMode::Nfs, ProjectionMode::Nfs)
        );

        // With nothing asked for, the order decides.
        assert_eq!(
            choose_mode(None, None, &both).1,
            first_available(&both),
            "the fallback order picks when nothing is requested or recorded"
        );

        // Nothing available at all still names a mode rather than panicking.
        assert_eq!(
            choose_mode(None, None, &probes(&[])).1,
            ProjectionMode::Shim
        );
    }

    /// A preload list naming Kin's shim means this process is projected. The
    /// engaged and not-engaged cases have to be distinguishable from the
    /// variable alone, because that is the only evidence a running process has.
    #[test]
    fn the_preload_variable_says_whether_the_shim_is_engaged() {
        assert!(shim_engaged(
            "/home/u/.kin/lib/libkin_vfs_shim.so",
            "libkin_vfs_shim.so"
        ));
        assert!(shim_engaged(
            "/opt/other.so:/usr/local/lib/libkin_vfs_shim.dylib",
            "libkin_vfs_shim.dylib"
        ));
        assert!(!shim_engaged("", "libkin_vfs_shim.so"));
        assert!(!shim_engaged("/opt/other.so", "libkin_vfs_shim.so"));
        assert!(
            !shim_engaged("/opt/libkin_vfs_shim.so.disabled", "libkin_vfs_shim.so"),
            "a similar name must not count as the shim"
        );
    }

    /// The three fixtures the doctor row has to tell apart: everything present,
    /// no shim, and a mode whose mount is not there. Each must produce a
    /// different row.
    #[test]
    fn the_doctor_row_changes_with_what_is_actually_there() {
        let dir = tempfile::tempdir().unwrap();
        let kin_home = dir.path().join("kin-home");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("a.rs"), b"fn main() {}").unwrap();

        let engaged = ShimPresence {
            path: kin_home.join("lib").join(shim_filename()),
            installed: true,
            engaged: true,
        };
        let healthy = probe_live(
            ProjectionMode::Shim,
            ProjectionMode::Shim,
            &kin_home,
            &repo,
            &engaged,
        );
        assert_eq!(healthy.mounted, Tri::NotApplicable);
        assert_eq!(healthy.readable, Tri::Yes);
        assert_eq!(
            healthy.writable,
            Tri::NotApplicable,
            "the shim must not write into the repository to answer a status question"
        );
        assert!(!healthy.degraded, "{}", healthy.row());
        assert_eq!(
            std::fs::read_dir(&repo).unwrap().count(),
            1,
            "probing the shim must leave the working tree exactly as it found it"
        );

        // A shim installed but not injected: this is the container case, and it
        // must not read as healthy.
        let stripped = ShimPresence {
            engaged: false,
            ..engaged.clone()
        };
        let container = probe_live(
            ProjectionMode::Shim,
            ProjectionMode::Shim,
            &kin_home,
            &repo,
            &stripped,
        );
        assert!(
            container.degraded,
            "a shim that is not engaged must read degraded: {}",
            container.row()
        );
        assert!(
            container
                .evidence
                .iter()
                .any(|line| line.contains("installed but not engaged")),
            "an installed shim that is not injected must be named as such: {:?}",
            container.evidence
        );
        assert_ne!(healthy.row(), container.row());

        // The other half of "not projected" is a shim that was never installed,
        // and it must not borrow the installed-but-not-engaged sentence. Running
        // `kin vfs status` on a host with no shim printed exactly that, which
        // sends a reader looking for a hook problem that is not there.
        let uninstalled = ShimPresence {
            installed: false,
            engaged: false,
            ..engaged.clone()
        };
        let bare = probe_live(
            ProjectionMode::Shim,
            ProjectionMode::Shim,
            &kin_home,
            &repo,
            &uninstalled,
        );
        assert!(
            bare.evidence
                .iter()
                .any(|line| line.contains("no shim is installed at")),
            "an absent shim must say it is absent: {:?}",
            bare.evidence
        );
        assert!(
            !bare
                .evidence
                .iter()
                .any(|line| line.contains("installed but not engaged")),
            "an absent shim must not read as an installed one: {:?}",
            bare.evidence
        );

        // A mount mode whose mount point is not a mount: nothing is read or
        // written, and the row says so rather than describing the empty
        // directory underneath.
        let unmounted = probe_live(
            ProjectionMode::Nfs,
            ProjectionMode::Nfs,
            &kin_home,
            &repo,
            &engaged,
        );
        assert_eq!(unmounted.mounted, Tri::No);
        assert_eq!(unmounted.readable, Tri::No);
        assert!(unmounted.degraded);
        assert!(
            unmounted
                .evidence
                .iter()
                .any(|line| line.contains("were not probed")),
            "an unmounted mount must not report the host directory: {:?}",
            unmounted.evidence
        );
        assert_ne!(unmounted.row(), healthy.row());
        assert_ne!(unmounted.row(), container.row());

        // A fallback names both modes.
        let fell_back = probe_live(
            ProjectionMode::Nfs,
            ProjectionMode::Shim,
            &kin_home,
            &repo,
            &engaged,
        );
        assert!(fell_back.degraded);
        assert!(fell_back
            .evidence
            .iter()
            .any(|line| line.contains("nfs was chosen")));
    }

    /// The mount test must be able to answer both ways on any host, or it is a
    /// check that cannot fail. A tempdir is not a mount point; the root always
    /// is.
    #[test]
    #[cfg(unix)]
    fn a_mount_point_is_told_from_an_ordinary_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_mount_point(dir.path()));
        assert!(!is_mount_point(&dir.path().join("does-not-exist")));
        assert!(is_mount_point(Path::new("/")));
    }

    /// A write that is never read back is not proof. The read-back path has to
    /// be exercised, and an unwritable directory has to answer no.
    #[test]
    #[cfg(unix)]
    fn writability_is_proved_by_reading_the_bytes_back() {
        let dir = tempfile::tempdir().unwrap();
        let (writable, evidence) = probe_writable(dir.path());
        assert_eq!(writable, Tri::Yes, "{evidence}");
        assert!(evidence.contains("read it back"), "{evidence}");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "the probe file must be removed"
        );

        let (unwritable, evidence) = probe_writable(&dir.path().join("no-such-directory"));
        assert_eq!(unwritable, Tri::No, "{evidence}");
        assert!(evidence.contains("could not write"), "{evidence}");
    }

    /// Recording a projection mode must survive the next `kin setup` run, which
    /// rewrites the daemon key in the same file. The old writer replaced the
    /// whole file, so a second setting could not have coexisted with it.
    #[test]
    fn recording_one_setting_preserves_the_other() {
        let with_daemon = format!("{SETUP_TOML_HEADER}[daemon]\nauto_start = true\n");
        let with_both = config_set(
            &with_daemon,
            "projection",
            "mode",
            toml::Value::String("nfs".to_string()),
        )
        .unwrap();
        assert_eq!(config_bool(&with_both, "daemon", "auto_start"), Some(true));
        assert_eq!(
            config_str(&with_both, "projection", "mode").as_deref(),
            Some("nfs")
        );

        let after_setup = config_set(
            &with_both,
            "daemon",
            "auto_start",
            toml::Value::Boolean(false),
        )
        .unwrap();
        assert_eq!(
            config_bool(&after_setup, "daemon", "auto_start"),
            Some(false)
        );
        assert_eq!(
            config_str(&after_setup, "projection", "mode").as_deref(),
            Some("nfs"),
            "a setup run must not discard the recorded projection mode"
        );
        assert!(after_setup.starts_with(SETUP_TOML_HEADER));

        // An empty or absent file is a legitimate starting point.
        let fresh =
            config_set("", "projection", "mode", toml::Value::String("fuse".into())).unwrap();
        assert_eq!(
            config_str(&fresh, "projection", "mode").as_deref(),
            Some("fuse")
        );
    }

    /// A recorded mode round-trips through the real file, and an unrecognised
    /// token is not silently accepted as a mode.
    #[test]
    fn a_recorded_mode_round_trips_and_a_bad_token_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let kin_home = dir.path().join("kin-home");
        assert_eq!(recorded_mode(&kin_home), None);
        record_mode(&kin_home, ProjectionMode::Fuse).unwrap();
        assert_eq!(recorded_mode(&kin_home), Some(ProjectionMode::Fuse));
        record_mode(&kin_home, ProjectionMode::Shim).unwrap();
        assert_eq!(recorded_mode(&kin_home), Some(ProjectionMode::Shim));

        assert_eq!(ProjectionMode::parse("NFS"), Some(ProjectionMode::Nfs));
        assert_eq!(ProjectionMode::parse("projfs"), None);
        assert!(parse_requested(Some("projfs")).is_err());
        assert_eq!(parse_requested(None).unwrap(), None);
    }
}
