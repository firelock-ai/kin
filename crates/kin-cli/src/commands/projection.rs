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
//! * **Windows ProjFS**: the Windows Projected File System, which is the
//!   Windows path on every SKU including Home. Windows has no injected shim and
//!   no FUSE, so ProjFS is both its primary and its floor.
//!
//! ## The fallback order, and why it is this way
//!
//! A mount is preferred over the shim wherever one is available, because a
//! mount cannot be stripped out from under a process. Between the two mounts
//! the platform's native one comes first: macOS carries an NFS client in the
//! base system while FUSE there needs FUSE-T or macFUSE installed, and Linux
//! carries libfuse far more often than it carries a configured NFS client. The
//! shim is last on those two, and it is a real answer rather than a failure: it
//! is what makes graph-first adoption work on a host that will mount nothing.
//!
//! Windows runs a different order for a different reason. There is no injected
//! shim to fall back to, so ProjFS leads and is also the floor, and the NFS
//! client is the documented second choice rather than a compatibility layer:
//! it ships only on Pro, Enterprise and Education, and it mounts to a drive
//! letter instead of projecting the repository in place.
//!
//! Which mode is possible on which platform, and the exact line that enables a
//! missing one, live in [`requirement`] and nowhere else. Twelve answers spread
//! across twelve call sites is how a platform silently loses its remedy.
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
use crate::commands::setup::{check_binary_in_path, home_dir, kin_dir, shim_filename};

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
    /// Admits every write staged through the mount into graph truth now.
    pub const NFS_SYNC: &str = "nfs-sync";
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
    /// The Windows Projected File System.
    ProjFs,
}

impl ProjectionMode {
    /// The token used in config and on the command line.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Shim => "shim",
            Self::Nfs => "nfs",
            Self::Fuse => "fuse",
            Self::ProjFs => "projfs",
        }
    }

    /// Parse a recorded or user-supplied token.
    pub(crate) fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "shim" => Some(Self::Shim),
            "nfs" => Some(Self::Nfs),
            "fuse" => Some(Self::Fuse),
            "projfs" => Some(Self::ProjFs),
            _ => None,
        }
    }

    /// Whether this mode presents the repository at a mount point rather than
    /// inside the process that asked.
    pub(crate) fn is_mount(self) -> bool {
        matches!(self, Self::Nfs | Self::Fuse | Self::ProjFs)
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
            Self::ProjFs => {
                "the Windows Projected File System, which projects the repository in place; \
                 available on every Windows SKU including Home"
            }
        }
    }

    /// What this mode cannot project, where that is a property of the mode
    /// rather than of the host.
    ///
    /// The shim is injected through `LD_PRELOAD` and `DYLD_INSERT_LIBRARIES`,
    /// which interpose libc and nothing else, so what it cannot project is a
    /// binary that reaches the kernel without libc at all. A Go binary built
    /// the usual way is that binary: it issues its own syscalls, and inside a
    /// projected repository it reads the working copy on the same path where
    /// git, Node, Python and the coreutils read graph truth.
    ///
    /// This note used to name Node, and named it wrongly. libuv issues `statx`
    /// itself rather than calling a libc stat entry point, which did put Node
    /// in this class for a release (FIR-2572), but it reaches the kernel
    /// through glibc's `syscall(2)` wrapper rather than through the
    /// instruction, and a wrapper is a symbol the shim can interpose like any
    /// other. It does now, so Node reads the projection here. A binary with no
    /// libc call to interpose is the case that remains, and it has no symbol to
    /// hook. A mount has no such gap at all, because the kernel serves every
    /// process on the host.
    pub(crate) fn raw_syscall_note(self) -> Option<&'static str> {
        match self {
            Self::Shim => Some(
                "A binary that reaches the kernel without libc is not projected in this mode: \
                 the shim interposes libc, so a Go binary making its own syscalls reads the \
                 working copy here while git, Node, Python and the coreutils read graph truth. \
                 The nfs and fuse mounts project every process on the host.",
            ),
            Self::Nfs | Self::Fuse | Self::ProjFs => None,
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
        // No injected shim and no FUSE here. ProjFS leads because it is the
        // only mode present on every SKU, and the NFS client is second rather
        // than a floor: it ships on Pro, Enterprise and Education alone, and it
        // mounts to a drive letter instead of projecting in place.
        "windows" => vec![ProjectionMode::ProjFs, ProjectionMode::Nfs],
        _ => vec![ProjectionMode::Shim],
    }
}

/// The mode named when nothing on this host is available.
///
/// Not simply the last entry of the order. On macOS and Linux the compatibility
/// answer is the shim, which is last; on Windows the last entry is the NFS
/// client, which most machines cannot install, and naming it would send a Home
/// user after a feature their edition does not have. The floor is the mode the
/// platform's remedy actually points at.
pub(crate) fn floor_mode(os: &str) -> ProjectionMode {
    match os {
        "windows" => ProjectionMode::ProjFs,
        _ => ProjectionMode::Shim,
    }
}

/// What a mode needs on one operating system, and the exact line that supplies
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Requirement {
    /// What has to be present for this mode to run here.
    pub needs: &'static str,
    /// The exact command or package that provides it, or the reason none is
    /// needed. Never a paraphrase: this text is what a stranger pastes.
    pub install: &'static str,
}

/// The whole per-OS matrix, in one place.
///
/// `None` means the mode does not exist on that platform at all, which is a
/// different answer from "it exists and is not installed" and must not be
/// reported as something to go and fix. Keeping every cell here is what makes
/// adding a platform one edit; the previous shape had the macOS and Linux
/// remedies inlined at their probes, and a Windows row would have had nowhere
/// to live.
pub(crate) fn requirement(mode: ProjectionMode, os: &str) -> Option<Requirement> {
    use ProjectionMode::*;
    let cell = match (mode, os) {
        (Shim, "macos") | (Shim, "linux") => Requirement {
            needs: "the kin-vfs shim library and a kin-vfs driver that runs",
            install: "reinstall kin: curl -fsSL https://get.kinlab.dev/install | sh",
        },
        // Windows has no shim projection: there is no LD_PRELOAD equivalent the
        // shell hook can inject, and ProjFS is the supported path instead.
        (Shim, _) => return None,

        (Nfs, "macos") => Requirement {
            needs: "an NFS client",
            install: "nothing to install: macOS carries mount_nfs in the base system",
        },
        (Nfs, "linux") => Requirement {
            needs: "an NFS client",
            install: "install nfs-common (Debian, Ubuntu) or nfs-utils (Fedora, Arch)",
        },
        (Nfs, "windows") => Requirement {
            needs: "the Windows Services for NFS client, on Pro, Enterprise or Education only",
            install: "Enable-WindowsOptionalFeature -Online -FeatureName ServicesForNFS-ClientOnly",
        },
        (Nfs, _) => return None,

        (Fuse, "macos") => Requirement {
            needs: "FUSE-T or macFUSE",
            install: "install FUSE-T or macFUSE, then run `kin vfs on` again",
        },
        (Fuse, "linux") => Requirement {
            needs: "libfuse",
            install: "install your distribution's fuse3 package",
        },
        (Fuse, _) => return None,

        (ProjFs, "windows") => Requirement {
            needs: "the Windows Projected File System optional feature and its PrjFlt filter",
            install: PROJFS_ENABLE_COMMAND,
        },
        (ProjFs, _) => return None,
    };
    Some(cell)
}

/// The one line that enables ProjFS. Named because three surfaces print it.
pub(crate) const PROJFS_ENABLE_COMMAND: &str =
    "Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart";

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

/// Whether `subcommand` accepts `flag`, read from its own help.
///
/// The driver's flags move under the lanes building the mounts, and asking is
/// how one binary can be driven correctly before and after. `nfs-start --repo`
/// registers and serves in one step where it exists; where it does not, the
/// repository has to be registered with `workspaces add` first.
pub(crate) fn subcommand_supports_flag(path: &Path, subcommand: &str, flag: &str) -> bool {
    let Ok(output) = Command::new(path)
        .args([subcommand, "--help"])
        .stdin(Stdio::null())
        .output()
    else {
        return false;
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    help_lists_flag(&text, flag)
}

/// Whether a help body offers `flag`. Pure so the match is testable without a
/// driver, and anchored on a word boundary so `--repo` does not match
/// `--repository-url`.
pub(crate) fn help_lists_flag(help: &str, flag: &str) -> bool {
    help.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .any(|token| token == flag)
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

// ---------------------------------------------------------------------------
// Windows: ProjFS
// ---------------------------------------------------------------------------

/// The message a user sees when the ProjFS optional feature is not enabled.
///
/// Fixed text agreed with the lane that owns the Windows side in `kin-vfs`, so
/// the two products say the same thing about the same machine. Do not reword.
pub(crate) const PROJFS_FEATURE_OFF: &str = "\
Windows filesystem projection is unavailable: the Windows Projected File
System optional feature is not enabled.

Enable it once, in an elevated PowerShell:
  Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart

Restart if that command reports RestartNeeded: True, then run kin doctor again.";

/// The message when the feature is on but the filter driver is not loaded.
/// Fixed text, same agreement as [`PROJFS_FEATURE_OFF`]. Do not reword.
pub(crate) const PROJFS_FILTER_NOT_RUNNING: &str = "\
Windows filesystem projection is unavailable: the ProjFS optional feature is
enabled but its filter driver is not running. Restart Windows, or load it now
in an elevated PowerShell:
  fltmc load PrjFlt";

/// The Windows service that actually serves ProjFS callbacks.
pub(crate) const PROJFS_FILTER_SERVICE: &str = "PrjFlt";

/// The optional feature name ProjFS ships under.
pub(crate) const PROJFS_FEATURE_NAME: &str = "Client-ProjFS";

/// What one `sc query` said about a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServiceState {
    /// `ERROR_SERVICE_DOES_NOT_EXIST`: the feature was never enabled.
    Missing,
    /// Installed and not running.
    Stopped,
    /// Installed and running.
    Running,
    /// The query answered something this code cannot read.
    Unreadable(String),
}

/// The Win32 error a service query returns when the service is not installed.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// Read a service query's answer.
///
/// Pure over the text and the exit status so both the missing and the stopped
/// case are testable off Windows, which is the only place this code can be
/// exercised today. The distinction matters: a missing service means the
/// optional feature was never enabled, and a stopped one means it was and the
/// filter is not loaded, and those two states have different remedies.
pub(crate) fn parse_service_state(text: &str, exit_code: Option<i32>) -> ServiceState {
    let haystack = text.to_ascii_uppercase();
    if exit_code == Some(ERROR_SERVICE_DOES_NOT_EXIST)
        || haystack.contains("DOES NOT EXIST")
        || haystack.contains("1060")
    {
        return ServiceState::Missing;
    }
    if let Some(state) = haystack
        .lines()
        .find(|line| line.trim_start().starts_with("STATE"))
    {
        if state.contains("RUNNING") {
            return ServiceState::Running;
        }
        if state.contains("STOPPED") {
            return ServiceState::Stopped;
        }
    }
    ServiceState::Unreadable(first_line(text))
}

/// Read `Get-WindowsOptionalFeature`'s answer for one feature.
///
/// Returns whether the feature is enabled, or `None` when the output carries no
/// state line at all. An unreadable answer is not a disabled feature: reporting
/// it as one would print an enable command at a user whose feature is already
/// on, which is the shape of wrong answer this whole surface exists to remove.
pub(crate) fn parse_optional_feature_state(text: &str) -> Option<bool> {
    let state = text
        .lines()
        .map(str::trim)
        .find(|line| line.to_ascii_lowercase().starts_with("state"))?;
    let value = state.split(':').nth(1)?.trim().to_ascii_lowercase();
    match value.as_str() {
        "enabled" | "enablepending" => Some(true),
        "disabled" | "disablepending" => Some(false),
        _ => None,
    }
}

/// What Windows says about ProjFS right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjFsState {
    /// The optional feature is not enabled.
    FeatureOff,
    /// The feature is enabled and the PrjFlt filter is not running.
    FilterNotRunning,
    /// Feature enabled, filter running.
    Ready,
    /// Neither query could be read, carrying what was seen.
    Unknown(String),
}

/// Decide ProjFS's state from the two queries.
///
/// Pure over both answers so every branch is testable off Windows. The service
/// answer leads: a missing `PrjFlt` is the same fact as a feature that was
/// never enabled and needs no second process to establish, and the feature
/// query is what distinguishes "enabled but not loaded" from "never enabled"
/// when the service is present but stopped.
pub(crate) fn projfs_state(feature_enabled: Option<bool>, service: &ServiceState) -> ProjFsState {
    match (service, feature_enabled) {
        (ServiceState::Missing, _) => ProjFsState::FeatureOff,
        (_, Some(false)) => ProjFsState::FeatureOff,
        (ServiceState::Running, _) => ProjFsState::Ready,
        (ServiceState::Stopped, _) => ProjFsState::FilterNotRunning,
        (ServiceState::Unreadable(seen), None) => ProjFsState::Unknown(seen.clone()),
        (ServiceState::Unreadable(seen), Some(true)) => ProjFsState::Unknown(seen.clone()),
    }
}

/// Ask Windows for the two facts.
///
/// Both queries run as ordinary subprocesses rather than through the service
/// control manager API. That is deliberate and it is a limitation worth
/// stating: this code cannot be compiled or run on the machine that wrote it,
/// and untested `unsafe` FFI against `OpenSCManagerW` would be a worse thing to
/// ship than two commands whose output parsers are unit-tested here. Neither
/// command needs elevation. Explicitly NOT probed by loading
/// `projectedfslib.dll`: a load can succeed on a host where the feature is off,
/// so it cannot tell absence from presence.
/// Ask Windows for the two facts.
///
/// Both queries run as ordinary subprocesses rather than through the service
/// control manager API. That is deliberate and it is a limitation worth
/// stating: this code cannot be compiled or run on the machine that wrote it,
/// and untested `unsafe` FFI against `OpenSCManagerW` would be a worse thing to
/// ship than two commands whose output parsers are unit-tested here. Neither
/// command needs elevation. Explicitly NOT probed by loading
/// `projectedfslib.dll`: a load can succeed on a host where the feature is off,
/// so it cannot tell absence from presence.
///
/// The platform test is a runtime `cfg!` rather than a `#[cfg]` block, for the
/// reason `resolve_home_dir` gives for the same choice: behind `#[cfg]` the
/// parsers below would be compiled, and therefore tested, only on the one
/// platform this fleet has no host for.
fn probe_projfs() -> ProjFsState {
    if !cfg!(windows) {
        return ProjFsState::Unknown("ProjFS exists only on Windows".to_string());
    }

    let feature = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "Get-WindowsOptionalFeature -Online -FeatureName {PROJFS_FEATURE_NAME} | \
                 Format-List State"
            ),
        ])
        .stdin(Stdio::null())
        .output()
        .ok()
        .and_then(|out| parse_optional_feature_state(&String::from_utf8_lossy(&out.stdout)));

    let service = match Command::new("sc.exe")
        .args(["query", PROJFS_FILTER_SERVICE])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) => parse_service_state(
            &format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            out.status.code(),
        ),
        Err(error) => ServiceState::Unreadable(error.to_string()),
    };

    projfs_state(feature, &service)
}

/// Build the ProjFS mode row from a probed state.
///
/// Split from the probe so all four states are testable on any platform.
pub(crate) fn projfs_mode_probe(state: &ProjFsState) -> ModeProbe {
    let (available, evidence, remedy) = match state {
        ProjFsState::Ready => (
            true,
            format!(
                "the {PROJFS_FEATURE_NAME} optional feature is enabled and the \
                 {PROJFS_FILTER_SERVICE} filter is running"
            ),
            None,
        ),
        ProjFsState::FeatureOff => (
            false,
            format!("the {PROJFS_FEATURE_NAME} optional feature is not enabled"),
            Some(PROJFS_FEATURE_OFF.to_string()),
        ),
        ProjFsState::FilterNotRunning => (
            false,
            format!(
                "the {PROJFS_FEATURE_NAME} optional feature is enabled but the \
                 {PROJFS_FILTER_SERVICE} filter is not running"
            ),
            Some(PROJFS_FILTER_NOT_RUNNING.to_string()),
        ),
        ProjFsState::Unknown(seen) => (
            false,
            format!("ProjFS state could not be read: {seen}"),
            Some(PROJFS_FEATURE_OFF.to_string()),
        ),
    };
    ModeProbe {
        mode: ProjectionMode::ProjFs,
        available,
        evidence,
        remedy,
    }
}

/// Probe every mode against one resolved driver.
pub(crate) fn probe_modes(driver: &DriverProbe, shim: &ShimPresence) -> Vec<ModeProbe> {
    fallback_order(std::env::consts::OS)
        .into_iter()
        .map(|mode| match mode {
            ProjectionMode::Shim => probe_shim_mode(driver, shim),
            ProjectionMode::Nfs => probe_nfs_mode(driver),
            ProjectionMode::Fuse => probe_fuse_mode(driver),
            ProjectionMode::ProjFs => projfs_mode_probe(&probe_projfs()),
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

/// The projection root this process is bound to, and whether anything serves
/// it.
///
/// The shim answers every path under its bound root out of the graph and fails
/// closed when it cannot, so a bound root with no daemon behind it returns EIO
/// for every path under it, existing or not. A read of the repository cannot
/// see that when the bound root does not contain the repository: the read never
/// reaches the shim, the row reads healthy, and every path under the bound root
/// is unreadable. That is the state a home directory bound as a projection root
/// produced on a stock container (FIR-2552), and it is why this question is
/// asked of the binding rather than of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShimBinding {
    /// No root is bound in this process, so the shim intercepts nothing.
    Unbound,
    /// A root is bound, named with the socket the shim is answered through.
    Bound {
        root: PathBuf,
        socket: PathBuf,
        /// Whether a connect to that socket was answered by a listener.
        /// `NotApplicable` where the shim is not answered over a Unix socket.
        listening: Tri,
        /// What the connect actually did, in its own words.
        detail: String,
        /// Whether the path this report is about lies inside the bound root.
        covers: bool,
    },
}

impl ShimBinding {
    /// Whether the graph is serving the path this report is about.
    ///
    /// False in every direction that leaves the caller on raw disk or on an
    /// EIO: nothing bound, a root that does not contain this path, or a root
    /// whose socket no listener answered.
    pub(crate) fn projects(&self) -> bool {
        match self {
            Self::Unbound => false,
            Self::Bound {
                listening, covers, ..
            } => *covers && *listening != Tri::No,
        }
    }

    /// The literal probe result, in the words the surfaces print.
    pub(crate) fn evidence(&self) -> String {
        match self {
            Self::Unbound => "no projection root is bound in this process: KIN_VFS_WORKSPACE is \
                              unset, so nothing here is answered from the graph"
                .to_string(),
            Self::Bound {
                root,
                socket,
                covers,
                detail,
                ..
            } => {
                if *covers {
                    format!(
                        "the projection root bound here is {}, its socket is {}, and {detail}",
                        root.display(),
                        socket.display()
                    )
                } else {
                    format!(
                        "the projection root bound here is {}, which does not contain this \
                         directory, so this directory is read from raw disk; its socket is {} \
                         and {detail}",
                        root.display(),
                        socket.display()
                    )
                }
            }
        }
    }
}

/// Read the binding the shell hook exports into every process it starts.
pub(crate) fn shim_binding_here(at: &Path) -> ShimBinding {
    let workspace = std::env::var_os("KIN_VFS_WORKSPACE").map(PathBuf::from);
    let socket = std::env::var_os("KIN_VFS_SOCK").map(PathBuf::from);
    shim_binding_for(
        workspace.as_deref(),
        socket.as_deref(),
        at,
        socket_listening,
    )
}

/// Pure over its inputs, so every case is testable without a process
/// environment and without a daemon.
pub(crate) fn shim_binding_for(
    workspace: Option<&Path>,
    socket: Option<&Path>,
    at: &Path,
    listening: impl Fn(&Path) -> (Tri, String),
) -> ShimBinding {
    let Some(root) = workspace.filter(|root| !root.as_os_str().is_empty()) else {
        return ShimBinding::Unbound;
    };
    let socket = socket
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(".kin").join("vfs.sock"));
    let (listening, detail) = listening(&socket);
    ShimBinding::Bound {
        covers: path_within(at, root),
        listening,
        detail,
        root: root.to_path_buf(),
        socket,
    }
}

/// Whether `path` is `root` or sits under it.
///
/// Component-wise rather than textual, so a sibling that merely shares a byte
/// prefix is rejected. Canonical forms are compared when both resolve, so a
/// `/var` spelling beside a canonical `/private/var` still matches; a path that
/// cannot be resolved falls back to the literal compare rather than reporting
/// containment it never established.
fn path_within(path: &Path, root: &Path) -> bool {
    if path.starts_with(root) {
        return true;
    }
    match (path.canonicalize(), root.canonicalize()) {
        (Ok(path), Ok(root)) => path.starts_with(root),
        _ => false,
    }
}

/// Whether a listener answers `socket`, and what the attempt did.
///
/// A socket file outlives the daemon that bound it, so its presence proves
/// nothing and only an accepted connect does. The hook's own guard says the
/// same thing about `kin-vfs status`.
#[cfg(unix)]
fn socket_listening(socket: &Path) -> (Tri, String) {
    match std::os::unix::net::UnixStream::connect(socket) {
        Ok(_) => (Tri::Yes, "a daemon answered it".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            Tri::No,
            "there is no socket there, so every path under that root fails EIO rather than \
             falling back to disk"
                .to_string(),
        ),
        Err(error) => (
            Tri::No,
            format!(
                "nothing answered it: {error}; every path under that root fails EIO rather than \
                 falling back to disk"
            ),
        ),
    }
}

#[cfg(not(unix))]
fn socket_listening(_socket: &Path) -> (Tri, String) {
    (
        Tri::NotApplicable,
        "it was not probed: this platform does not answer the shim over a Unix socket".to_string(),
    )
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

/// This platform's install line for `mode`, or `None` where the mode does not
/// exist here. Every remedy comes through here so the per-OS table stays the
/// only place a platform's answer is written down.
pub(crate) fn install_line(mode: ProjectionMode) -> Option<String> {
    requirement(mode, std::env::consts::OS).map(|cell| cell.install.to_string())
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
            install_line(ProjectionMode::Shim),
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
            remedy: install_line(ProjectionMode::Nfs),
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
            remedy: install_line(ProjectionMode::Fuse),
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
        .unwrap_or_else(|| floor_mode(std::env::consts::OS))
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

/// The directory mounts appear under when nothing has published one.
///
/// `~/Kin`, not `~/.kin/mnt`. It is user-writable without sudo, survives an
/// unmount, and can be dragged into Finder's sidebar, which a dotted directory
/// under the toolchain's own home cannot.
pub(crate) fn mount_root(home: &Path) -> PathBuf {
    home.join("Kin")
}

/// Where one repository appears under a mount, when nothing has published a
/// mount point.
pub(crate) fn default_repo_mount_point(home: &Path, repo_root: &Path) -> PathBuf {
    let name = repo_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "repo".to_string());
    mount_root(home).join(name)
}

/// The mount point a driver status line published, if it published one.
///
/// Read rather than assumed. A probe that assumed a default reported a healthy
/// mount as not mounted, because the server had published somewhere else, and
/// the only thing that knows where a mount actually is is the export itself.
/// Pure over the text so both the published and the silent case are testable.
pub(crate) fn parse_published_mount_point(status: &str) -> Option<PathBuf> {
    let line = status
        .lines()
        .map(str::trim)
        .find(|line| line.to_ascii_lowercase().starts_with("mount:"))?;
    let value = line.split_once(':')?.1.trim();
    // `nfs-status` renders the mount point followed by a parenthesised state.
    let value = value.split(" (").next().unwrap_or(value).trim();
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// Where this repository's files appear under `mode`.
///
/// Asks the driver first and falls back to the default only when nothing was
/// published, so a server that chose its own mount point is believed over a
/// constant in this file.
pub(crate) fn repo_mount_point(
    driver: &DriverProbe,
    mode: ProjectionMode,
    home: &Path,
    repo_root: &Path,
) -> PathBuf {
    published_mount_point(driver, mode).unwrap_or_else(|| default_repo_mount_point(home, repo_root))
}

/// Run the driver's status subcommand for `mode` and read the mount point it
/// publishes.
fn published_mount_point(driver: &DriverProbe, mode: ProjectionMode) -> Option<PathBuf> {
    let path = driver.path.as_deref().filter(|_| driver.runs())?;
    let subcommand = match mode {
        ProjectionMode::Nfs => driver::NFS_STATUS,
        _ => return None,
    };
    if !driver.carries(subcommand) {
        return None;
    }
    let output = Command::new(path)
        .arg(subcommand)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    parse_published_mount_point(&String::from_utf8_lossy(&output.stdout))
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
        // ProjFS is served by Windows, not by kin-vfs, so the driver has
        // nothing to say about it; its own probe is the whole answer.
        ProjectionMode::Shim | ProjectionMode::ProjFs => return None,
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
    at: &Path,
    shim: &ShimPresence,
    binding: &ShimBinding,
) -> LiveProjection {
    let mut evidence = Vec::new();
    let at = at.to_path_buf();

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

    // What the shim is bound to, and whether a daemon is behind it. The read
    // above cannot answer this: where the bound root does not contain this
    // directory the read never reaches the shim at all, which is how a home
    // directory bound as a projection root reported a healthy row while every
    // path under it returned EIO (FIR-2552). Asked of the shim only, because a
    // mount answers the same question with its own mounted and readable probes.
    if mode == ProjectionMode::Shim {
        evidence.push(binding.evidence());
    }

    let mode_failed = match mode {
        ProjectionMode::Shim => !shim.engaged || readable != Tri::Yes || !binding.projects(),
        ProjectionMode::Nfs | ProjectionMode::Fuse | ProjectionMode::ProjFs => {
            mounted != Tri::Yes || readable != Tri::Yes
        }
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
    let at = projected_path(&driver, mode, repo_root);
    let binding = shim_binding_here(&at);
    let mut live = probe_live(intent, mode, &at, &shim, &binding);
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

/// Where `mode` presents this repository's files.
///
/// A mount is wherever its server published, or the default under `~/Kin`; the
/// shim projects the repository in place. Resolved once per command so every
/// row, probe and message names the same path.
pub(crate) fn projected_path(
    driver: &DriverProbe,
    mode: ProjectionMode,
    repo_root: &Path,
) -> PathBuf {
    if !mode.is_mount() {
        return repo_root.to_path_buf();
    }
    let home = home_dir().unwrap_or_else(|_| repo_root.to_path_buf());
    repo_mount_point(driver, mode, &home, repo_root)
}

/// ProjFS is a Windows feature rather than something kin-vfs starts, so
/// engaging it is a state check plus the enable line when it is off.
fn engage_projfs(modes: &[ModeProbe]) -> Result<()> {
    let Some(probe) = modes
        .iter()
        .find(|probe| probe.mode == ProjectionMode::ProjFs)
    else {
        anyhow::bail!("ProjFS is not a projection mode on this platform");
    };
    if probe.available {
        println!("{} {}", style("\u{2713}").green(), probe.evidence);
        return Ok(());
    }
    println!("{} {}", style("\u{2717}").red(), probe.evidence);
    if let Some(remedy) = &probe.remedy {
        println!("{remedy}");
    }
    anyhow::bail!("ProjFS is not available on this host");
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
        ProjectionMode::Fuse => engage_fuse(&driver, &repo_root)?,
        ProjectionMode::ProjFs => engage_projfs(&modes)?,
    }

    // Record intent, never the fallback: a recorded mode is what the user asked
    // for, and overwriting it with what happened to work would make doctor
    // unable to say a configured mode is degraded. A machine with nothing
    // recorded gets the mode that actually engaged.
    let to_record = requested.or(recorded).unwrap_or(effective);
    record_mode(&kin_home, to_record)?;

    let at = projected_path(&driver, effective, &repo_root);
    let binding = shim_binding_here(&at);
    let live = probe_live(intent, effective, &at, &shim, &binding);
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
            // Admit staged writes before the mount goes away. Unmounting first
            // would strand whatever was written through it but not yet admitted,
            // and the whole point of the mount is that those writes reach the
            // graph.
            if driver.carries(driver::NFS_SYNC) {
                match run_driver(path, &[driver::NFS_SYNC]) {
                    Ok(out) => println!("{} {}", style("\u{2713}").green(), first_line(&out)),
                    Err(error) => println!(
                        "{} could not admit staged writes before unmounting: {error}",
                        style("!").yellow()
                    ),
                }
            }
            let out = run_driver(path, &[driver::NFS_STOP])?;
            println!("{} {}", style("\u{2713}").green(), first_line(&out));
        }
        ProjectionMode::ProjFs => {
            println!(
                "{} ProjFS is a Windows feature rather than a process Kin starts, so there is \
                 nothing to stop. Disable the optional feature if you want it off.",
                style("i").cyan()
            );
        }
        ProjectionMode::Fuse => {
            let Some(path) = driver.path.as_deref().filter(|_| driver.runs()) else {
                anyhow::bail!("no kin-vfs driver to unmount with");
            };
            let point = projected_path(&driver, ProjectionMode::Fuse, &repo_root);
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
    let mut lines = live_lines(live).into_iter();
    let row = lines
        .next()
        .expect("live_lines always yields the row it is built around");
    println!("{mark} {row}");
    for line in lines {
        println!("  {line}");
    }
}

/// Every line the projection block prints, in order, with the row first and the
/// rest indented under it.
///
/// Split out from the printing so what this surface says, and what it must not
/// say, are both testable without running a command.
fn live_lines(live: &LiveProjection) -> Vec<String> {
    let mut lines = vec![
        format!("Projection in force: {}", live.row()),
        format!("{}: {}", live.mode, live.mode.description()),
        format!("files at {}", live.at.display()),
    ];
    lines.extend(live.mode.raw_syscall_note().map(str::to_string));
    lines.extend(live.evidence.iter().cloned());
    lines
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
    let root = repo_root.to_string_lossy().into_owned();

    // One command where the driver takes a repository: `nfs-start --repo`
    // registers it on first use and serves it. Registering separately is the
    // older two-step shape, and doing both would register a repository the
    // server is about to register again.
    if subcommand_supports_flag(path, driver::NFS_START, "--repo") {
        let out = run_driver(path, &[driver::NFS_START, "--repo", &root])?;
        println!("{} {}", style("\u{2713}").green(), first_line(&out));
        return Ok(());
    }

    if driver.carries(driver::WORKSPACES) {
        let out = run_driver(path, &[driver::WORKSPACES, "add", "--path", &root])?;
        println!("{} {}", style("\u{2713}").green(), first_line(&out));
    }
    let out = run_driver(path, &[driver::NFS_START])?;
    println!("{} {}", style("\u{2713}").green(), first_line(&out));
    Ok(())
}

fn engage_fuse(driver: &DriverProbe, repo_root: &Path) -> Result<()> {
    let Some(path) = driver.path.as_deref().filter(|_| driver.runs()) else {
        anyhow::bail!("no kin-vfs driver to mount with");
    };
    let point = projected_path(driver, ProjectionMode::Fuse, repo_root);
    // kin-vfs refuses a mount point inside the workspace, because a write
    // through the mount would land on the workspace path underneath it.
    if point.starts_with(repo_root) {
        anyhow::bail!(
            "the mount point {} is inside the repository; a write through it would land on the \
             path underneath rather than in the graph",
            point.display()
        );
    }
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
        for os in ["macos", "linux"] {
            assert_eq!(
                fallback_order(os).last(),
                Some(&ProjectionMode::Shim),
                "{os} must fall back to the shim"
            );
        }
        // A platform Kin drives no mount on gets the shim alone. Windows is not
        // that platform any more and has its own test.
        assert_eq!(fallback_order("freebsd"), vec![ProjectionMode::Shim]);
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

    /// FIR-2572: the shim interposes libc, so what it cannot project is a
    /// binary that never calls libc. The status block has to say so under the
    /// shim, and must not say it under a mount, where the kernel serves every
    /// process.
    ///
    /// It must also no longer say it about Node. The note named Node for a
    /// release, correctly at the time, because libuv issued `statx` itself; the
    /// shim now interposes the `syscall(2)` wrapper libuv reaches it through,
    /// and a measured static Go binary is the case that remains. A note still
    /// telling a JavaScript developer their toolchain is unprojected would send
    /// them to a mount they no longer need, so the old sentence is asserted
    /// gone rather than merely replaced.
    #[test]
    fn the_status_block_declares_the_shim_raw_syscall_gap_and_only_there() {
        let shim_note = ProjectionMode::Shim
            .raw_syscall_note()
            .expect("the shim mode declares its raw-syscall gap");
        assert!(
            shim_note.contains("libc"),
            "the note must name what the gap is about: {shim_note}"
        );
        assert!(
            shim_note.contains("Go"),
            "the note must name a binary actually in the class: {shim_note}"
        );
        assert!(
            !shim_note.contains("Node is not projected"),
            "Node is projected under the shim since FIR-2572; the note must not send a \
             JavaScript developer to a mount they do not need: {shim_note}"
        );
        assert!(
            shim_note.contains("nfs") && shim_note.contains("fuse"),
            "the note must name the modes with no such gap: {shim_note}"
        );
        for mode in [
            ProjectionMode::Nfs,
            ProjectionMode::Fuse,
            ProjectionMode::ProjFs,
        ] {
            assert_eq!(
                mode.raw_syscall_note(),
                None,
                "{mode} is served by the kernel and projects every process, so it must not carry \
                 the shim's gap"
            );
        }

        let at = Path::new("/w/repo");
        let shim = LiveProjection {
            intent: ProjectionMode::Shim,
            mode: ProjectionMode::Shim,
            at: at.to_path_buf(),
            mounted: Tri::NotApplicable,
            readable: Tri::Yes,
            writable: Tri::NotApplicable,
            degraded: false,
            evidence: vec!["fixture evidence".to_string()],
        };
        let printed = live_lines(&shim).join("\n");
        assert!(
            printed.contains(shim_note),
            "the shim block must carry the note verbatim:\n{printed}"
        );

        let mount = LiveProjection {
            intent: ProjectionMode::Fuse,
            mode: ProjectionMode::Fuse,
            mounted: Tri::Yes,
            ..shim.clone()
        };
        let printed = live_lines(&mount).join("\n");
        assert!(
            !printed.contains("Node"),
            "a mount projects Node, so its block must not carry the shim's gap:\n{printed}"
        );
        let nfs = LiveProjection {
            intent: ProjectionMode::Nfs,
            mode: ProjectionMode::Nfs,
            ..mount.clone()
        };
        assert!(
            !live_lines(&nfs).join("\n").contains("Node"),
            "the nfs block must not carry the shim's gap"
        );
    }

    /// A binding that covers `at` and is answered: what a working shim
    /// projection looks like from this process.
    fn served_binding(at: &Path) -> ShimBinding {
        ShimBinding::Bound {
            root: at.to_path_buf(),
            socket: at.join(".kin").join("vfs.sock"),
            listening: Tri::Yes,
            detail: "a daemon answered its socket (fixture)".to_string(),
            covers: true,
        }
    }

    /// FIR-2552 in one function: the four bindings a shim process can be in,
    /// and which of them mean the graph is actually answering.
    #[test]
    fn a_binding_projects_only_when_it_covers_this_path_and_something_answers() {
        let answered = |_: &Path| (Tri::Yes, "a daemon answered (fixture)".to_string());
        let silent = |_: &Path| (Tri::No, "nothing answered (fixture)".to_string());
        let home = Path::new("/home/dev");
        let repo = Path::new("/work/notekeeper");

        assert!(
            !shim_binding_for(None, None, repo, answered).projects(),
            "an unbound process projects nothing, whatever is listening"
        );

        // The container's own shape: the hook bound $HOME, the repository is
        // elsewhere, and reading the repository succeeds because the shim never
        // sees it. That read is exactly what reported degraded=no.
        let bound_home = shim_binding_for(Some(home), None, repo, silent);
        assert!(
            !bound_home.projects(),
            "a root that does not contain this directory is not projecting it: {}",
            bound_home.evidence()
        );
        assert!(
            bound_home
                .evidence()
                .contains("does not contain this directory"),
            "the row must name the mismatch: {}",
            bound_home.evidence()
        );

        // The same root, with the caller inside it, and nothing serving it.
        // Every path under it answers EIO, so the projection is not in force.
        let unserved = shim_binding_for(Some(home), None, Path::new("/home/dev/src"), silent);
        assert!(
            !unserved.projects(),
            "a bound root with no listener is not in force: {}",
            unserved.evidence()
        );
        assert_eq!(
            unserved,
            ShimBinding::Bound {
                root: home.to_path_buf(),
                socket: Path::new("/home/dev/.kin/vfs.sock").to_path_buf(),
                listening: Tri::No,
                detail: "nothing answered (fixture)".to_string(),
                covers: true,
            },
            "the default socket is the bound root's own, and the row carries it"
        );

        // And the one case that is genuinely in force.
        let working = shim_binding_for(Some(home), None, Path::new("/home/dev/src"), answered);
        assert!(working.projects(), "{}", working.evidence());

        // An explicitly exported socket wins over the default, because that is
        // what the hook exports and what the shim connects to.
        let elsewhere = shim_binding_for(
            Some(home),
            Some(Path::new("/run/kin/vfs.sock")),
            home,
            answered,
        );
        assert!(
            elsewhere.evidence().contains("/run/kin/vfs.sock"),
            "the row must name the socket the shim would use: {}",
            elsewhere.evidence()
        );
    }

    /// The socket probe itself, against a real listener and a real absence.
    /// A socket file outlives the daemon that bound it, so the file test and
    /// the connect have to disagree here or the probe proves nothing.
    #[cfg(unix)]
    #[test]
    fn only_an_answered_connect_counts_as_a_listener() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent.sock");
        let (verdict, detail) = socket_listening(&absent);
        assert_eq!(verdict, Tri::No, "{detail}");
        assert!(
            detail.contains("there is no socket there"),
            "an absent socket must say so: {detail}"
        );

        let live = dir.path().join("live.sock");
        let listener = std::os::unix::net::UnixListener::bind(&live).unwrap();
        let (verdict, detail) = socket_listening(&live);
        assert_eq!(verdict, Tri::Yes, "{detail}");
        assert!(
            detail.contains("a daemon answered it"),
            "an answered connect must say so: {detail}"
        );

        // The stale socket: the inode is still there, the listener is gone.
        drop(listener);
        assert!(
            live.exists(),
            "the fixture must leave the socket file behind, or it is not the stale case"
        );
        let (verdict, detail) = socket_listening(&live);
        assert_eq!(
            verdict,
            Tri::No,
            "a socket file with nothing behind it must not read as a listener: {detail}"
        );
    }

    /// The row `kin vfs status` prints in the FIR-2552 state, end to end
    /// through the probe: the shim is injected, the repository reads fine off
    /// raw disk, and the projection is still not in force.
    #[test]
    fn a_shim_bound_to_a_root_nothing_serves_is_not_in_force() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let repo = dir.path().join("work/notekeeper");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("a.rs"), b"fn main() {}").unwrap();

        let engaged = ShimPresence {
            path: home.join(".kin/lib").join(shim_filename()),
            installed: true,
            engaged: true,
        };
        let silent = |_: &Path| (Tri::No, "there is no socket there (fixture)".to_string());
        let bound_home = shim_binding_for(Some(&home), None, &repo, silent);
        let live = probe_live(
            ProjectionMode::Shim,
            ProjectionMode::Shim,
            &repo,
            &engaged,
            &bound_home,
        );

        assert_eq!(
            live.readable,
            Tri::Yes,
            "the repository still reads, which is exactly why the old row said healthy"
        );
        assert!(
            live.degraded,
            "a projection bound to a root that serves nothing is not in force: {}",
            live.row()
        );
        assert!(
            live.row().contains("degraded=yes"),
            "the printed row must carry the verdict: {}",
            live.row()
        );
        assert!(
            live.evidence
                .iter()
                .any(|line| line.contains("does not contain this directory")),
            "the row must say which root is bound and why it does not serve here: {:?}",
            live.evidence
        );

        // The positive control: the same shim, the same repository, with the
        // repository itself bound and answered. A fix that simply reports every
        // shim as degraded has removed the surface rather than made it honest.
        let served = probe_live(
            ProjectionMode::Shim,
            ProjectionMode::Shim,
            &repo,
            &engaged,
            &served_binding(&repo),
        );
        assert!(
            !served.degraded,
            "a bound, answered repository is in force: {}",
            served.row()
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
        let served = served_binding(&repo);
        let healthy = probe_live(
            ProjectionMode::Shim,
            ProjectionMode::Shim,
            &repo,
            &engaged,
            &served,
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
            &repo,
            &stripped,
            &served,
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
            &repo,
            &uninstalled,
            &served,
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
            &repo,
            &engaged,
            &served,
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
            &repo,
            &engaged,
            &served,
        );
        assert!(fell_back.degraded);
        assert!(fell_back
            .evidence
            .iter()
            .any(|line| line.contains("nfs was chosen")));
    }

    /// Every platform gets an order, and Windows gets a different one for a
    /// different reason: no shim exists there, so ProjFS leads and is also the
    /// floor, while the NFS client is a second choice most editions cannot
    /// install.
    #[test]
    fn windows_leads_with_projfs_and_floors_on_it() {
        assert_eq!(
            fallback_order("windows"),
            vec![ProjectionMode::ProjFs, ProjectionMode::Nfs]
        );
        assert!(
            !fallback_order("windows").contains(&ProjectionMode::Shim),
            "Windows has no injected shim to fall back to"
        );
        assert_eq!(floor_mode("windows"), ProjectionMode::ProjFs);
        assert_eq!(floor_mode("macos"), ProjectionMode::Shim);
        assert_eq!(floor_mode("linux"), ProjectionMode::Shim);
    }

    /// Every cell of the per-OS matrix has to answer, and a mode that does not
    /// exist on a platform has to answer differently from one that exists and
    /// is missing. Reporting ProjFS as installable on macOS would send someone
    /// after a Windows feature.
    #[test]
    fn the_per_os_table_has_a_line_for_every_mode_that_exists() {
        for (mode, os) in [
            (ProjectionMode::Shim, "macos"),
            (ProjectionMode::Shim, "linux"),
            (ProjectionMode::Nfs, "macos"),
            (ProjectionMode::Nfs, "linux"),
            (ProjectionMode::Nfs, "windows"),
            (ProjectionMode::Fuse, "macos"),
            (ProjectionMode::Fuse, "linux"),
            (ProjectionMode::ProjFs, "windows"),
        ] {
            let cell = requirement(mode, os)
                .unwrap_or_else(|| panic!("{mode} on {os} must carry a requirement"));
            assert!(
                !cell.needs.is_empty() && !cell.install.is_empty(),
                "{mode}/{os}"
            );
        }

        for (mode, os) in [
            (ProjectionMode::Shim, "windows"),
            (ProjectionMode::Fuse, "windows"),
            (ProjectionMode::ProjFs, "macos"),
            (ProjectionMode::ProjFs, "linux"),
        ] {
            assert!(
                requirement(mode, os).is_none(),
                "{mode} does not exist on {os} and must not be offered as installable"
            );
        }

        // The exact enable lines the platforms need, so a reworded table is a
        // failing test rather than a stranger pasting something that does not work.
        assert_eq!(
            requirement(ProjectionMode::ProjFs, "windows")
                .unwrap()
                .install,
            "Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart"
        );
        assert!(requirement(ProjectionMode::Nfs, "windows")
            .unwrap()
            .install
            .contains("ServicesForNFS-ClientOnly"));
        assert!(requirement(ProjectionMode::Fuse, "linux")
            .unwrap()
            .install
            .contains("fuse3"));
        assert!(requirement(ProjectionMode::Nfs, "linux")
            .unwrap()
            .install
            .contains("nfs-common"));
        assert!(requirement(ProjectionMode::Fuse, "macos")
            .unwrap()
            .install
            .contains("FUSE-T"));
    }

    /// A missing service and a stopped one are two different machines with two
    /// different remedies, and the probe has to tell them apart from the text
    /// Windows actually prints.
    #[test]
    fn the_projfs_service_query_tells_missing_from_stopped() {
        let missing = "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\n                       The specified service does not exist as an installed service.\n";
        assert_eq!(
            parse_service_state(missing, Some(1060)),
            ServiceState::Missing
        );
        // The exit code alone is enough, and so is the text alone.
        assert_eq!(parse_service_state(missing, None), ServiceState::Missing);
        assert_eq!(
            parse_service_state("nothing readable", Some(1060)),
            ServiceState::Missing
        );

        let running = "SERVICE_NAME: PrjFlt\n        TYPE               : 2  FILE_SYSTEM_DRIVER\n                               STATE              : 4  RUNNING\n";
        assert_eq!(parse_service_state(running, Some(0)), ServiceState::Running);

        let stopped = "SERVICE_NAME: PrjFlt\n        TYPE               : 2  FILE_SYSTEM_DRIVER\n                               STATE              : 1  STOPPED\n";
        assert_eq!(parse_service_state(stopped, Some(0)), ServiceState::Stopped);

        assert!(matches!(
            parse_service_state("something else entirely", Some(0)),
            ServiceState::Unreadable(_)
        ));
    }

    /// An unreadable feature answer is not a disabled feature. Treating it as
    /// one prints an enable command at a user whose feature is already on.
    #[test]
    fn an_unreadable_feature_state_is_not_a_disabled_one() {
        assert_eq!(
            parse_optional_feature_state("FeatureName : Client-ProjFS\nState : Enabled\n"),
            Some(true)
        );
        assert_eq!(
            parse_optional_feature_state("State : Disabled\n"),
            Some(false)
        );
        assert_eq!(
            parse_optional_feature_state("State : EnablePending\n"),
            Some(true)
        );
        assert_eq!(parse_optional_feature_state("some error text\n"), None);
        assert_eq!(parse_optional_feature_state(""), None);
        // A state line Windows prints that this code does not recognise. Without
        // this case the unrecognised arm is never reached, because every input
        // above returns early from the missing-line lookup, and changing that
        // arm to report "disabled" would have gone unnoticed.
        assert_eq!(parse_optional_feature_state("State : Superseded\n"), None);
        assert_eq!(parse_optional_feature_state("State :\n"), None);
    }

    /// The four ProjFS states are four different rows, and the two that have
    /// fixed message text carry it verbatim, because kin and kin-vfs agreed to
    /// say the same thing about the same machine.
    #[test]
    fn the_projfs_states_are_four_rows_and_two_are_verbatim() {
        assert_eq!(
            projfs_state(Some(false), &ServiceState::Stopped),
            ProjFsState::FeatureOff
        );
        assert_eq!(
            projfs_state(Some(true), &ServiceState::Missing),
            ProjFsState::FeatureOff,
            "a missing filter is the same fact as a feature never enabled"
        );
        assert_eq!(
            projfs_state(Some(true), &ServiceState::Stopped),
            ProjFsState::FilterNotRunning
        );
        assert_eq!(
            projfs_state(Some(true), &ServiceState::Running),
            ProjFsState::Ready
        );

        let ready = projfs_mode_probe(&ProjFsState::Ready);
        assert!(ready.available && ready.remedy.is_none());

        let off = projfs_mode_probe(&ProjFsState::FeatureOff);
        assert!(!off.available);
        assert_eq!(off.remedy.as_deref(), Some(PROJFS_FEATURE_OFF));
        assert!(PROJFS_FEATURE_OFF.contains(
            "Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart"
        ));
        assert!(PROJFS_FEATURE_OFF.contains("RestartNeeded: True"));

        let filter = projfs_mode_probe(&ProjFsState::FilterNotRunning);
        assert!(!filter.available);
        assert_eq!(filter.remedy.as_deref(), Some(PROJFS_FILTER_NOT_RUNNING));
        assert!(PROJFS_FILTER_NOT_RUNNING.contains("fltmc load PrjFlt"));

        let rows = [&ready, &off, &filter];
        for (i, a) in rows.iter().enumerate() {
            for b in rows.iter().skip(i + 1) {
                assert_ne!(
                    a.evidence, b.evidence,
                    "each ProjFS state must read differently"
                );
            }
        }
    }

    /// A mount is wherever its server published, not wherever a constant in
    /// this file says. Assuming a default reported a healthy mount as not
    /// mounted, which is the failure this parse exists to prevent.
    #[test]
    fn the_published_mount_point_beats_the_default() {
        let status = "NFS server:  running (PID 4242)\nPort:        2049\n                      Mount:       /Users/x/Kin/repo (mounted)\nWorkspaces:  1 registered\n";
        assert_eq!(
            parse_published_mount_point(status),
            Some(PathBuf::from("/Users/x/Kin/repo"))
        );
        // Without the parenthesised state, and with nothing to read at all.
        assert_eq!(
            parse_published_mount_point("Mount:       /srv/elsewhere\n"),
            Some(PathBuf::from("/srv/elsewhere"))
        );
        assert_eq!(parse_published_mount_point("NFS server:  stopped\n"), None);
        assert_eq!(parse_published_mount_point("Mount:\n"), None);

        // The default is under ~/Kin, not ~/.kin/mnt: user-writable, survives an
        // unmount, and can be dragged into a file manager's sidebar.
        let home = Path::new("/Users/x");
        assert_eq!(
            default_repo_mount_point(home, Path::new("/w/myrepo")),
            PathBuf::from("/Users/x/Kin/myrepo")
        );
        assert_eq!(mount_root(home), PathBuf::from("/Users/x/Kin"));
    }

    /// A flag probe that matched a prefix would drive the wrong command shape.
    #[test]
    fn a_flag_is_matched_whole_rather_than_as_a_prefix() {
        let help = "Usage: kin-vfs nfs-start [OPTIONS]\n\nOptions:\n      --repo <PATH>\n                          --port <PORT>\n      --read-only\n";
        assert!(help_lists_flag(help, "--repo"));
        assert!(help_lists_flag(help, "--read-only"));
        assert!(!help_lists_flag(help, "--repository"));
        assert!(
            !help_lists_flag("Options:\n      --repository-url <URL>\n", "--repo"),
            "a longer flag must not answer for a shorter one"
        );
        assert!(!help_lists_flag("", "--repo"));
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
        record_mode(&kin_home, ProjectionMode::ProjFs).unwrap();
        assert_eq!(recorded_mode(&kin_home), Some(ProjectionMode::ProjFs));

        assert_eq!(ProjectionMode::parse("NFS"), Some(ProjectionMode::Nfs));
        assert_eq!(
            ProjectionMode::parse("ProjFS"),
            Some(ProjectionMode::ProjFs)
        );
        assert_eq!(ProjectionMode::parse("prjflt"), None);
        assert!(parse_requested(Some("prjflt")).is_err());
        assert_eq!(parse_requested(None).unwrap(), None);
    }
}
