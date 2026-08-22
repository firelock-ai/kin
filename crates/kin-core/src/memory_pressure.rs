// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What this machine can say about memory pressure right now, and what heavy
//! work is allowed to do about it.
//!
//! Kin must never do to a user's machine what it did to the box it was built
//! on. The standard is one sentence: measure the pressure, cap and stream the
//! work, back off before the host swaps, and say so, rather than pushing on
//! until the kernel decides. Two measured failures are what that sentence is
//! made of. A full-history `kin init` was OOM-killed at a 12 GiB container cap,
//! and a language-server cold sweep peaked at 18.2 GB on a one-gigabyte store
//! while its pyright child held another 1.9 GiB. Neither run consulted anything
//! before starting, and neither said a word about memory when it died.
//!
//! This module is the one reading both worlds go through. Inside a container it
//! reads the cgroup: the cap, what is charged against it now, the high-water
//! mark, and the kernel's own OOM-kill counter. On a bare host it reads the
//! host's accounting instead, plus the swap standing, because a Mac does not
//! OOM-kill an over-committed process, it pages until the machine stops being
//! usable, and the swap figure is what sees that coming.
//!
//! Three properties are load-bearing.
//!
//! **A reading that cannot be obtained is `Unknown`, and unknown never refuses
//! work.** Absence of evidence is not pressure. A Windows host, a kernel
//! without the counter, a `/proc` that will not open: each of those is this
//! process being unable to ask, and a tool that stops working because it could
//! not read a file is worse than the problem it was guarding against. Every
//! surface reports the unknown as unknown rather than as nominal, so nobody
//! reads silence as an all-clear.
//!
//! **The reading is cheap.** At most four small pseudo-file reads on Linux and
//! two syscalls on macOS, no allocation past a few short strings, and nothing
//! that touches the graph. A pressure check that costs a graph walk would be
//! its own reason to run out of memory.
//!
//! **The decision is pure.** [`Verdict::for_reading`] takes a reading and a set
//! of thresholds and returns what heavy work may do, so every branch is
//! testable on a host that is nowhere near its limit. Only [`read`] touches the
//! machine.

use std::path::{Path, PathBuf};

/// Where a reading came from, which is what decides how to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureSource {
    /// A container memory cap accounts this process, so the cap is the ceiling
    /// and the kernel will kill under it rather than page.
    Cgroup,
    /// No cap accounts this process, so the host's own memory is the ceiling
    /// and the machine pages before anything is killed.
    Host,
}

impl PressureSource {
    /// The word a disclosure uses for this ceiling.
    pub fn as_str(self) -> &'static str {
        match self {
            PressureSource::Cgroup => "container",
            PressureSource::Host => "machine",
        }
    }
}

/// What this process measured about the memory it is allowed to use.
///
/// Every field is what some kernel actually published. Nothing here is derived
/// from a default, so a surface that prints one of these numbers is quoting the
/// machine rather than an assumption about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryReading {
    /// Which accounting answered.
    pub source: PressureSource,
    /// The ceiling this process runs under, in bytes.
    pub limit_bytes: u64,
    /// Bytes charged against that ceiling right now.
    pub used_bytes: u64,
    /// Swap in use on this host, and the swap it has, when the host publishes
    /// them. `None` inside a cgroup and on a host with no swap accounting.
    pub swap_used_bytes: Option<u64>,
    /// Total swap this host has configured.
    pub swap_total_bytes: Option<u64>,
    /// Kernel OOM kills accounted here. `Some(0)` is the kernel saying nothing
    /// was killed; `None` is this process being unable to ask. The two are
    /// never conflated, because the first is evidence and the second is not.
    pub oom_kills: Option<u64>,
    /// The high-water mark this accounting has recorded, when it keeps one.
    pub peak_bytes: Option<u64>,
}

impl MemoryReading {
    /// Bytes still obtainable before the ceiling.
    pub fn available_bytes(&self) -> u64 {
        self.limit_bytes.saturating_sub(self.used_bytes)
    }

    /// How much of the ceiling is in use, in `0.0..=1.0`.
    ///
    /// A ceiling of zero cannot be divided into, and a host that reported one
    /// has told us nothing, so it reads as no pressure rather than as total
    /// pressure. The alternative divides by zero into infinity and refuses
    /// every piece of work on the machine.
    pub fn used_fraction(&self) -> f64 {
        if self.limit_bytes == 0 {
            return 0.0;
        }
        self.used_bytes as f64 / self.limit_bytes as f64
    }

    /// How much of this host's swap is in use, when it has any.
    pub fn swap_used_fraction(&self) -> Option<f64> {
        let total = self.swap_total_bytes.filter(|total| *total > 0)?;
        let used = self.swap_used_bytes?;
        Some(used as f64 / total as f64)
    }

    /// Whether the kernel has already killed something under this ceiling.
    pub fn kernel_has_killed_here(&self) -> bool {
        self.oom_kills.is_some_and(|kills| kills > 0)
    }
}

/// What this process can say about memory pressure right now.
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryPressure {
    /// This machine's accounting could not be read, for this reason. Never a
    /// reason to refuse work: a tool that stops because it could not open a
    /// file has invented a limit nobody measured.
    Unknown { reason: String },
    /// This is what the machine says.
    Known(MemoryReading),
    /// An operator pinned the level through [`PRESSURE_OVERRIDE_ENV`], so no
    /// machine was read.
    ///
    /// A third variant rather than a synthesized reading, because a synthesized
    /// one would be printed by every surface as though a kernel had published
    /// it. The whole register of these disclosures is that their numbers are
    /// quoted from the machine; inventing a plausible pair to satisfy the
    /// grader would be the one line in them a reader could not check.
    Forced { level: PressureLevel },
}

impl MemoryPressure {
    /// The reading, when there is one.
    pub fn reading(&self) -> Option<&MemoryReading> {
        match self {
            MemoryPressure::Known(reading) => Some(reading),
            MemoryPressure::Unknown { .. } | MemoryPressure::Forced { .. } => None,
        }
    }

    /// Why no reading could be taken, when none could.
    pub fn unknown_reason(&self) -> Option<&str> {
        match self {
            MemoryPressure::Unknown { reason } => Some(reason),
            MemoryPressure::Known(_) | MemoryPressure::Forced { .. } => None,
        }
    }

    /// The level this reading sits at, under the thresholds this process runs
    /// with.
    pub fn level(&self) -> PressureLevel {
        self.level_under(&Thresholds::from_env())
    }

    /// [`Self::level`] against explicit thresholds, so the rule is testable
    /// without touching the environment.
    pub fn level_under(&self, thresholds: &Thresholds) -> PressureLevel {
        match self {
            MemoryPressure::Unknown { .. } => PressureLevel::Unknown,
            MemoryPressure::Known(reading) => thresholds.level_for(reading),
            // A pinned level is the answer, not an input to the grader. Running
            // it back through the fractions would let an operator who also
            // moved a bar get a level they did not ask for, which is the one
            // thing an override must never do.
            MemoryPressure::Forced { level } => *level,
        }
    }
}

/// How much of the ceiling is in use, graded.
///
/// Four values rather than a bool because the two middle ones are different
/// instructions. `Elevated` means shrink what you are about to do; `Critical`
/// means do not start it. Collapsing them would make the only available
/// response to any pressure at all a refusal, and a tool that refuses at
/// seventy-five percent is a tool nobody keeps installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    /// Nothing could be read. Work proceeds exactly as it did before this
    /// module existed.
    Unknown,
    /// There is room. Work proceeds.
    Nominal,
    /// The ceiling is close enough that a batch should be smaller.
    Elevated,
    /// Starting heavy work here is how the machine goes down.
    Critical,
}

impl PressureLevel {
    /// The word a disclosure and a log line use for this level.
    pub fn as_str(self) -> &'static str {
        match self {
            PressureLevel::Unknown => "unknown",
            PressureLevel::Nominal => "nominal",
            PressureLevel::Elevated => "elevated",
            PressureLevel::Critical => "critical",
        }
    }

    /// Parse the operator override. `None` for anything unrecognized, which the
    /// caller treats as "measure the machine instead".
    pub fn from_override(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "unknown" => Some(PressureLevel::Unknown),
            "nominal" => Some(PressureLevel::Nominal),
            "elevated" => Some(PressureLevel::Elevated),
            "critical" => Some(PressureLevel::Critical),
            _ => None,
        }
    }
}

/// Operator override forcing the level, in place of measuring the machine.
///
/// Its first purpose is the acceptance suite: a test that has to prove heavy
/// work refuses under pressure cannot fill the host's memory to make it
/// happen. Its second is an operator on a machine Kin reads wrongly, who can
/// pin the answer either way while a real fix is written.
pub const PRESSURE_OVERRIDE_ENV: &str = "KIN_MEMORY_PRESSURE";

/// Where the fraction of the ceiling that counts as elevated is set.
pub const ELEVATED_FRACTION_ENV: &str = "KIN_MEMORY_PRESSURE_ELEVATED_FRACTION";

/// Where the fraction of the ceiling that counts as critical is set.
pub const CRITICAL_FRACTION_ENV: &str = "KIN_MEMORY_PRESSURE_CRITICAL_FRACTION";

/// Where the swap fraction that escalates an elevated host is set.
pub const SWAP_FRACTION_ENV: &str = "KIN_MEMORY_PRESSURE_SWAP_FRACTION";

/// The bars a reading is graded against.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    /// At or above this fraction of the ceiling, shrink.
    pub elevated: f64,
    /// At or above this fraction of the ceiling, do not start.
    pub critical: f64,
    /// Swap standing at or above this fraction of configured swap turns an
    /// already-elevated host critical.
    pub swap: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            elevated: 0.75,
            critical: 0.90,
            swap: 0.50,
        }
    }
}

impl Thresholds {
    /// The thresholds this process runs with, after any operator override.
    ///
    /// An unparsable or out-of-range value keeps the default rather than
    /// disabling the guard, and a critical bar set below the elevated bar is
    /// raised to it, because the ordering is what the two levels mean.
    pub fn from_env() -> Self {
        let default = Self::default();
        let mut thresholds = Self {
            elevated: fraction_from_env(ELEVATED_FRACTION_ENV, default.elevated),
            critical: fraction_from_env(CRITICAL_FRACTION_ENV, default.critical),
            swap: fraction_from_env(SWAP_FRACTION_ENV, default.swap),
        };
        if thresholds.critical < thresholds.elevated {
            thresholds.critical = thresholds.elevated;
        }
        thresholds
    }

    /// Grade one reading.
    ///
    /// Three inputs, in the order they are trusted. The fraction of the ceiling
    /// in use is the measurement and sets the level. A host already paging
    /// heavily while that fraction is elevated is one step worse than the
    /// fraction alone says, because the machine has started trading speed for
    /// space and the next allocation is what stops it being usable. A kernel
    /// that has already OOM-killed something under this ceiling holds the level
    /// at elevated for the life of the accounting, which is a floor and never a
    /// refusal: the counter is cumulative, so treating it as critical would
    /// suspend a container's work forever over one kill it has long recovered
    /// from.
    pub fn level_for(&self, reading: &MemoryReading) -> PressureLevel {
        let fraction = reading.used_fraction();
        let mut measured = if fraction >= self.critical {
            PressureLevel::Critical
        } else if fraction >= self.elevated {
            PressureLevel::Elevated
        } else {
            PressureLevel::Nominal
        };
        if measured == PressureLevel::Elevated
            && reading
                .swap_used_fraction()
                .is_some_and(|swap| swap >= self.swap)
        {
            measured = PressureLevel::Critical;
        }
        if reading.kernel_has_killed_here() {
            measured = measured.max(PressureLevel::Elevated);
        }
        measured
    }
}

/// A fraction from the environment, or `default` when it is unset, unparsable,
/// or outside `0.0..=1.0`.
fn fraction_from_env(name: &str, default: f64) -> f64 {
    let Ok(raw) = std::env::var(name) else {
        return default;
    };
    match raw.trim().parse::<f64>() {
        Ok(value) if value.is_finite() && (0.0..=1.0).contains(&value) => value,
        _ => default,
    }
}

/// A piece of work heavy enough to be worth asking about.
///
/// Named rather than a size, because the disclosure has to say what did not
/// happen. "Kin declined 400 MB of work" tells a reader nothing they can act
/// on; "the language-server enrichment sweep did not start" tells them which
/// answers will be missing and which command asks for them again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeavyWork {
    /// The cold language-server enrichment sweep, which reopens repository
    /// authority, rebuilds the graph from snapshot, and holds a language server
    /// per language beside it. The measured peak was 18.2 GB.
    LspSweep,
    /// One background embedding batch, which holds a batch of vectors and the
    /// model that produced them.
    EmbedBatch,
    /// One ambient admission tick: a complete working-copy walk planned into a
    /// tree transition, from a host event nobody asked for.
    AmbientAdmission,
}

impl HeavyWork {
    /// The stable id a disclosure and a record key on.
    pub fn id(self) -> &'static str {
        match self {
            HeavyWork::LspSweep => "lsp-sweep",
            HeavyWork::EmbedBatch => "embed-batch",
            HeavyWork::AmbientAdmission => "ambient-admission",
        }
    }

    /// What a person reading the disclosure would call it.
    pub fn label(self) -> &'static str {
        match self {
            HeavyWork::LspSweep => "the language-server enrichment sweep",
            HeavyWork::EmbedBatch => "background embedding",
            HeavyWork::AmbientAdmission => "ambient admission of working-copy changes",
        }
    }

    /// What is lost while this work is not running, and what asks for it again.
    fn consequence(self) -> &'static str {
        match self {
            HeavyWork::LspSweep => {
                "cross-file relations stay at whatever is already durable instead of converging"
            }
            HeavyWork::EmbedBatch => {
                "semantic coverage stays where it is, so vector search answers from the vectors \
                 that already exist"
            }
            HeavyWork::AmbientAdmission => {
                "working-copy changes stay unadmitted, so a file written just now is not \
                 queryable yet; nothing is lost and the next tick admits them"
            }
        }
    }
}

/// What heavy work may do under the pressure that was measured.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Proceed exactly as before. Both the nominal case and the unknown one.
    Proceed,
    /// Do the work smaller, for this reason.
    Shrink { reason: String },
    /// Do not start, for this reason.
    Refuse { reason: String },
}

impl Verdict {
    /// The verdict for one piece of work under one reading.
    ///
    /// `Unknown` and `Nominal` proceed, always. `Elevated` shrinks the work
    /// that can be done smaller and proceeds with the rest, because a sweep has
    /// no smaller size and refusing it at three-quarters of the ceiling would
    /// suspend enrichment on every busy machine. `Critical` refuses everything
    /// here, which is the whole point: this is the state the daemon used to
    /// push through and get killed in.
    pub fn for_reading(
        work: HeavyWork,
        pressure: &MemoryPressure,
        thresholds: &Thresholds,
    ) -> Self {
        let level = pressure.level_under(thresholds);
        let reading = pressure.reading();
        match level {
            PressureLevel::Unknown | PressureLevel::Nominal => Verdict::Proceed,
            PressureLevel::Elevated => match work {
                HeavyWork::EmbedBatch => Verdict::Shrink {
                    reason: describe(work, level, reading, "runs in smaller batches"),
                },
                HeavyWork::LspSweep | HeavyWork::AmbientAdmission => Verdict::Proceed,
            },
            PressureLevel::Critical => Verdict::Refuse {
                reason: describe(work, level, reading, "did not start"),
            },
        }
    }

    /// The sentence this verdict carries, when it carries one.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Verdict::Proceed => None,
            Verdict::Shrink { reason } | Verdict::Refuse { reason } => Some(reason),
        }
    }

    /// Whether the work must not start.
    pub fn refused(&self) -> bool {
        matches!(self, Verdict::Refuse { .. })
    }
}

/// The disclosure sentence, in the register the commit post-kill diagnosis
/// established: what was measured, against what ceiling, what Kin did about it,
/// and what that costs.
///
/// The numbers come from the reading and nothing is rounded into a claim the
/// machine did not make. A kill counter is quoted only when the kernel actually
/// moved it, for the reason the commit diagnosis quotes it only then: a host
/// that could not be asked must never be reported as having answered.
fn describe(
    work: HeavyWork,
    level: PressureLevel,
    reading: Option<&MemoryReading>,
    did: &'static str,
) -> String {
    let mut sentence = format!("host memory pressure is {}", level.as_str());
    match reading {
        Some(reading) => {
            sentence.push_str(&format!(
                ": {} of the {} this {} allows is in use",
                human_bytes(reading.used_bytes),
                human_bytes(reading.limit_bytes),
                reading.source.as_str(),
            ));
            if let (Some(swap_used), Some(swap_total)) =
                (reading.swap_used_bytes, reading.swap_total_bytes)
            {
                if swap_total > 0 {
                    sentence.push_str(&format!(
                        ", and {} of {} swap is in use",
                        human_bytes(swap_used),
                        human_bytes(swap_total)
                    ));
                }
            }
            if let Some(kills) = reading.oom_kills.filter(|kills| *kills > 0) {
                sentence.push_str(&format!(
                    ", and this machine's kernel has recorded {kills} out-of-memory kill(s) \
                     against it"
                ));
            }
        }
        // No numbers, because none were measured. A level nobody read is
        // reported as exactly that.
        None => sentence.push_str(&format!(" because {PRESSURE_OVERRIDE_ENV} pins it there")),
    }
    sentence.push_str(&format!(
        ", so {} {}. {}.",
        work.label(),
        did,
        work.consequence()
    ));
    sentence
}

/// What the reader can do about a pressure refusal.
///
/// Deliberately short of naming a command that would clear it, because none
/// does: the pressure is the machine's, not the store's, and the honest advice
/// is to give the machine room. Kin retries on its own once there is room, so
/// the reader is not being asked to run anything to resume.
pub const PRESSURE_REMEDY: &str =
    "Give the machine or container more memory, or close what is holding it, and Kin resumes \
     this work on its own once there is room.";

fn human_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

// ---------------------------------------------------------------------------
// The reading itself
// ---------------------------------------------------------------------------

/// Read what this machine says about memory pressure right now.
///
/// The override is consulted first and short-circuits the probe entirely, so a
/// test forcing a level never depends on the host it runs on. Otherwise the
/// cgroup answers when this process is capped, and the host's own accounting
/// answers when it is not.
pub fn read() -> MemoryPressure {
    if let Some(forced) = forced_pressure() {
        return forced;
    }
    probe()
}

/// The level pinned by [`PRESSURE_OVERRIDE_ENV`], when one is pinned.
///
/// A pinned `unknown` arrives as an ordinary unreadable machine, because that
/// is exactly what it is asking to simulate: a host this process cannot ask.
/// Every other level arrives as [`MemoryPressure::Forced`], carrying no numbers
/// at all, so nothing downstream can print an invented reading as a measured
/// one.
fn forced_pressure() -> Option<MemoryPressure> {
    let raw = std::env::var(PRESSURE_OVERRIDE_ENV).ok()?;
    let level = PressureLevel::from_override(&raw)?;
    Some(match level {
        PressureLevel::Unknown => MemoryPressure::Unknown {
            reason: format!("{PRESSURE_OVERRIDE_ENV} is set to {raw:?}"),
        },
        level => MemoryPressure::Forced { level },
    })
}

/// Read the machine, cgroup first.
fn probe() -> MemoryPressure {
    let cgroup = kin_daemon_spawn::cgroup_memory();
    if let (Some(limit), Some(current)) = (cgroup.limit_bytes, cgroup.current_bytes) {
        return MemoryPressure::Known(MemoryReading {
            source: PressureSource::Cgroup,
            limit_bytes: limit,
            used_bytes: current,
            // A cgroup's own swap accounting is a separate controller that many
            // hosts do not enable, and the cap is what the kernel kills on, so
            // the container case decides on the cap alone.
            swap_used_bytes: None,
            swap_total_bytes: None,
            oom_kills: cgroup.oom_kills,
            peak_bytes: cgroup.peak_bytes,
        });
    }
    match host_reading() {
        Ok(mut reading) => {
            // A capped process whose usage counter is unreadable still runs
            // under the cap, and the host figure above it would be a ceiling
            // this process can never reach.
            if let Some(limit) = cgroup.limit_bytes {
                reading.source = PressureSource::Cgroup;
                reading.limit_bytes = reading.limit_bytes.min(limit);
            }
            reading.oom_kills = cgroup.oom_kills.or(reading.oom_kills);
            MemoryPressure::Known(reading)
        }
        Err(reason) => MemoryPressure::Unknown { reason },
    }
}

/// The host's own accounting, or why it could not be read.
#[cfg(target_os = "linux")]
fn host_reading() -> Result<MemoryReading, String> {
    let contents = std::fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("/proc/meminfo unreadable: {error}"))?;
    parse_meminfo(&contents).ok_or_else(|| {
        "/proc/meminfo carries no parsable MemTotal and MemAvailable pair".to_string()
    })
}

/// A reading out of a `/proc/meminfo` body.
///
/// `MemAvailable` rather than `MemFree` because free memory on a working Linux
/// host is close to zero by design: the page cache holds the rest and gives it
/// back on demand. Deciding on `MemFree` would report every healthy machine as
/// out of memory. Kernels before 3.14 publish no `MemAvailable`, and this
/// returns `None` for them rather than substituting `MemFree`, because an
/// unreadable machine is a better answer than a wrong one.
#[cfg(any(target_os = "linux", test))]
fn parse_meminfo(contents: &str) -> Option<MemoryReading> {
    let field = |name: &str| -> Option<u64> {
        contents.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?.strip_prefix(':')?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    };
    let total_kb = field("MemTotal")?;
    let available_kb = field("MemAvailable")?;
    let swap_total_kb = field("SwapTotal");
    let swap_free_kb = field("SwapFree");
    let total = total_kb.saturating_mul(1024);
    let available = available_kb.saturating_mul(1024).min(total);
    Some(MemoryReading {
        source: PressureSource::Host,
        limit_bytes: total,
        used_bytes: total.saturating_sub(available),
        swap_used_bytes: match (swap_total_kb, swap_free_kb) {
            (Some(total), Some(free)) => Some(total.saturating_sub(free).saturating_mul(1024)),
            _ => None,
        },
        swap_total_bytes: swap_total_kb.map(|kb| kb.saturating_mul(1024)),
        oom_kills: None,
        peak_bytes: None,
    })
}

/// The host's own accounting on macOS, or why it could not be read.
///
/// Two probes, both syscalls, because the file-shaped alternatives do not exist
/// here. `host_statistics64` gives the page counts, and available memory is
/// free plus the pages the kernel can take back without paging anything out:
/// inactive, purgeable, and speculative. Free pages alone would be the same
/// mistake `MemFree` is on Linux and worse, since macOS deliberately keeps very
/// few of them.
///
/// `vm.swapusage` is the swap standing, and on this platform it is the signal
/// that matters most. macOS does not OOM-kill a process that asks for too much;
/// it compresses, then pages, and the machine becomes unusable long before
/// anything dies. That is the failure this whole module exists to stop, and it
/// is invisible in the page counts alone.
#[cfg(target_os = "macos")]
fn host_reading() -> Result<MemoryReading, String> {
    let page_size = mach_page_size()?;
    let stats = mach_vm_statistics()?;
    let total = sysctl_u64("hw.memsize")?;
    let reclaimable = u64::from(stats.free_count)
        + u64::from(stats.inactive_count)
        + u64::from(stats.purgeable_count)
        + u64::from(stats.speculative_count);
    let available = reclaimable.saturating_mul(page_size).min(total);
    let swap = sysctl_swapusage().ok();
    Ok(MemoryReading {
        source: PressureSource::Host,
        limit_bytes: total,
        used_bytes: total.saturating_sub(available),
        swap_used_bytes: swap.map(|(_, used)| used),
        swap_total_bytes: swap.map(|(total, _)| total),
        oom_kills: None,
        peak_bytes: None,
    })
}

#[cfg(target_os = "macos")]
fn mach_page_size() -> Result<u64, String> {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 {
        return Err(format!(
            "sysconf(_SC_PAGESIZE) returned {size}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(size as u64)
}

// The mach port for this host. Declared here rather than called through
// `libc`, whose binding is deprecated in favour of a crate this workspace does
// not carry. The symbol itself is stable kernel ABI; only the binding moved.
#[cfg(target_os = "macos")]
extern "C" {
    fn mach_host_self() -> libc::mach_port_t;
}

#[cfg(target_os = "macos")]
fn mach_vm_statistics() -> Result<libc::vm_statistics64, String> {
    let mut stats = unsafe { std::mem::zeroed::<libc::vm_statistics64>() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let status = unsafe {
        libc::host_statistics64(
            mach_host_self(),
            libc::HOST_VM_INFO64,
            std::ptr::addr_of_mut!(stats).cast::<libc::integer_t>(),
            &mut count,
        )
    };
    if status != libc::KERN_SUCCESS {
        return Err(format!("host_statistics64(HOST_VM_INFO64) returned {status}"));
    }
    Ok(stats)
}

#[cfg(target_os = "macos")]
fn sysctl_u64(name: &str) -> Result<u64, String> {
    let key = std::ffi::CString::new(name).map_err(|error| error.to_string())?;
    let mut value: u64 = 0;
    let mut size = std::mem::size_of::<u64>() as libc::size_t;
    let status = unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            std::ptr::addr_of_mut!(value).cast::<libc::c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(format!(
            "sysctlbyname({name}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if size != std::mem::size_of::<u64>() as libc::size_t || value == 0 {
        return Err(format!(
            "sysctlbyname({name}) returned {size} bytes holding {value}"
        ));
    }
    Ok(value)
}

/// Total and used swap, in bytes, out of the `vm.swapusage` sysctl.
///
/// The kernel answers with `struct xsw_usage`, whose first three fields are the
/// three byte counts. It is described here by its layout rather than imported,
/// because `libc` binds no type for it on this platform.
#[cfg(target_os = "macos")]
fn sysctl_swapusage() -> Result<(u64, u64), String> {
    #[repr(C)]
    #[derive(Default)]
    struct XswUsage {
        total: u64,
        avail: u64,
        used: u64,
        pagesize: u32,
        encrypted: u32,
    }
    let key = std::ffi::CString::new("vm.swapusage").map_err(|error| error.to_string())?;
    let mut usage = XswUsage::default();
    let mut size = std::mem::size_of::<XswUsage>() as libc::size_t;
    let status = unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            std::ptr::addr_of_mut!(usage).cast::<libc::c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(format!(
            "sysctlbyname(vm.swapusage) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((usage.total, usage.used))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn host_reading() -> Result<MemoryReading, String> {
    Err(format!(
        "no host-memory pressure probe for target_os {}",
        std::env::consts::OS
    ))
}

// ---------------------------------------------------------------------------
// The durable record every surface reads
// ---------------------------------------------------------------------------

/// File the daemon writes a pressure refusal into, beside the sweep tally it
/// sits next to.
pub const PRESSURE_RECORD_FILE_NAME: &str = "memory-pressure";

/// Where `kin_root` keeps it.
pub fn pressure_record_path(kin_root: &Path) -> PathBuf {
    kin_root.join(PRESSURE_RECORD_FILE_NAME)
}

/// A piece of heavy work this store's daemon declined, and what it measured
/// when it declined it.
///
/// Durable for the reason the sweep tally is: the process that decided is a
/// daemon nobody is watching, and every surface that has to say what happened
/// runs later and in another process. A daemon-log WARN reaches whoever thinks
/// to open the log, which in practice is nobody, and it was the entire
/// disclosure for the sweep circuit until a doctor row was added.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PressureRefusal {
    /// Which work was declined ([`HeavyWork::id`]).
    pub work: String,
    /// The level measured when it was declined.
    pub level: String,
    /// The sentence the daemon wrote, ready to print.
    pub reason: String,
    /// When it was declined, in unix seconds.
    pub at_unix: u64,
}

impl PressureRefusal {
    /// Record one refusal for this store.
    ///
    /// Last writer wins, deliberately: the useful fact is the most recent
    /// refusal, and a store keeping a history of them would be a log with worse
    /// ergonomics. A write that fails is dropped, because a daemon that cannot
    /// write its own disclosure must not fail the work it was disclosing about.
    pub fn record(kin_root: &Path, work: HeavyWork, level: PressureLevel, reason: &str) {
        let record = Self {
            work: work.id().to_string(),
            level: level.as_str().to_string(),
            reason: reason.to_string(),
            at_unix: unix_now(),
        };
        if let Ok(body) = serde_json::to_vec(&record) {
            let _ = std::fs::write(pressure_record_path(kin_root), body);
        }
    }

    /// What this store records, or `None` when it records nothing.
    ///
    /// An unreadable or unparsable record reads as absent, for the same reason
    /// the sweep tally does: this record exists to report a degradation, and it
    /// must never become one.
    pub fn read(kin_root: &Path) -> Option<Self> {
        let raw = std::fs::read(pressure_record_path(kin_root)).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Retire the record, because the work it describes has since run.
    ///
    /// Called by the work itself on the pass that proceeds. Without this the
    /// row heals only when a store is reinitialized, and a surface reporting a
    /// refusal from last week reads exactly like one reporting a refusal from
    /// this second.
    pub fn clear(kin_root: &Path) {
        let _ = std::fs::remove_file(pressure_record_path(kin_root));
    }

    /// The fact alone, for a surface that carries its own remediation field.
    pub fn cause_sentence(&self) -> String {
        self.reason.clone()
    }

    /// What the reader can do about it.
    pub fn remediation(&self) -> String {
        PRESSURE_REMEDY.to_string()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn reading(limit: u64, used: u64) -> MemoryReading {
        MemoryReading {
            source: PressureSource::Cgroup,
            limit_bytes: limit,
            used_bytes: used,
            swap_used_bytes: None,
            swap_total_bytes: None,
            oom_kills: None,
            peak_bytes: None,
        }
    }

    #[test]
    fn a_reading_with_room_is_nominal_and_a_reading_near_the_cap_is_critical() {
        let bars = Thresholds::default();
        assert_eq!(
            bars.level_for(&reading(12 * GIB, GIB)),
            PressureLevel::Nominal
        );
        assert_eq!(
            bars.level_for(&reading(12 * GIB, 9 * GIB + GIB / 2)),
            PressureLevel::Elevated
        );
        // The measured case: 11.5 GiB charged against a 12 GiB cap is where the
        // full-history init died.
        assert_eq!(
            bars.level_for(&reading(12 * GIB, 11 * GIB + GIB / 2)),
            PressureLevel::Critical
        );
    }

    #[test]
    fn a_ceiling_of_zero_reads_as_no_pressure_rather_than_total_pressure() {
        // A host that reported a zero ceiling told us nothing. Dividing into it
        // would refuse every piece of work on the machine.
        assert_eq!(Thresholds::default().level_for(&reading(0, 0)), PressureLevel::Nominal);
    }

    #[test]
    fn a_kernel_that_already_killed_here_holds_the_level_at_elevated() {
        let mut nominal = reading(12 * GIB, GIB);
        nominal.oom_kills = Some(2);
        assert_eq!(
            Thresholds::default().level_for(&nominal),
            PressureLevel::Elevated,
            "a cgroup with recorded kills is not a cgroup to start a bulk pass in"
        );
    }

    #[test]
    fn a_kill_counter_at_zero_is_the_kernel_saying_nothing_was_killed() {
        let mut nominal = reading(12 * GIB, GIB);
        nominal.oom_kills = Some(0);
        assert_eq!(
            Thresholds::default().level_for(&nominal),
            PressureLevel::Nominal
        );
    }

    #[test]
    fn a_host_already_paging_heavily_turns_an_elevated_reading_critical() {
        let mut elevated = reading(12 * GIB, 9 * GIB + GIB / 2);
        elevated.source = PressureSource::Host;
        elevated.swap_total_bytes = Some(8 * GIB);
        elevated.swap_used_bytes = Some(7 * GIB);
        assert_eq!(
            Thresholds::default().level_for(&elevated),
            PressureLevel::Critical
        );

        // The same swap standing on a host with room is not pressure. The dev
        // box this was written on sat at 97% swap used with 44 GiB free, and a
        // rule that refused work there would refuse it on a healthy machine.
        let mut roomy = reading(128 * GIB, 84 * GIB);
        roomy.source = PressureSource::Host;
        roomy.swap_total_bytes = Some(27 * GIB);
        roomy.swap_used_bytes = Some(26 * GIB);
        assert_eq!(
            Thresholds::default().level_for(&roomy),
            PressureLevel::Nominal
        );
    }

    #[test]
    fn an_unreadable_machine_never_refuses_work() {
        let unknown = MemoryPressure::Unknown {
            reason: "/proc/meminfo unreadable: No such file or directory".to_string(),
        };
        assert_eq!(unknown.level_under(&Thresholds::default()), PressureLevel::Unknown);
        for work in [
            HeavyWork::LspSweep,
            HeavyWork::EmbedBatch,
            HeavyWork::AmbientAdmission,
        ] {
            assert_eq!(
                Verdict::for_reading(work, &unknown, &Thresholds::default()),
                Verdict::Proceed,
                "absence of evidence is not pressure"
            );
        }
    }

    #[test]
    fn critical_pressure_refuses_every_heavy_work_with_a_named_reason() {
        let pressure = MemoryPressure::Known(reading(12 * GIB, 11 * GIB + GIB / 2));
        for work in [
            HeavyWork::LspSweep,
            HeavyWork::EmbedBatch,
            HeavyWork::AmbientAdmission,
        ] {
            let verdict = Verdict::for_reading(work, &pressure, &Thresholds::default());
            assert!(verdict.refused(), "{work:?} must not start under critical pressure");
            let reason = verdict.reason().expect("a refusal carries its reason");
            assert!(
                reason.contains("critical") && reason.contains("11.5 GiB") && reason.contains("12.0 GiB"),
                "the refusal quotes what it measured: {reason}"
            );
            assert!(
                reason.contains(work.label()),
                "the refusal names the work: {reason}"
            );
        }
    }

    #[test]
    fn elevated_pressure_shrinks_the_batch_and_lets_the_sweep_run() {
        let pressure = MemoryPressure::Known(reading(12 * GIB, 9 * GIB + GIB / 2));
        let bars = Thresholds::default();
        assert!(matches!(
            Verdict::for_reading(HeavyWork::EmbedBatch, &pressure, &bars),
            Verdict::Shrink { .. }
        ));
        assert_eq!(
            Verdict::for_reading(HeavyWork::LspSweep, &pressure, &bars),
            Verdict::Proceed,
            "a sweep has no smaller size, so refusing it at three-quarters would suspend \
             enrichment on every busy machine"
        );
    }

    #[test]
    fn a_refusal_quotes_the_kernel_only_when_the_kernel_counted_something() {
        let mut killed = reading(12 * GIB, 11 * GIB + GIB / 2);
        killed.oom_kills = Some(24);
        let named = Verdict::for_reading(
            HeavyWork::LspSweep,
            &MemoryPressure::Known(killed),
            &Thresholds::default(),
        );
        assert!(named
            .reason()
            .expect("refused")
            .contains("24 out-of-memory kill(s)"));

        let mut unasked = reading(12 * GIB, 11 * GIB + GIB / 2);
        unasked.oom_kills = None;
        let silent = Verdict::for_reading(
            HeavyWork::LspSweep,
            &MemoryPressure::Known(unasked),
            &Thresholds::default(),
        );
        assert!(
            !silent.reason().expect("refused").contains("out-of-memory kill"),
            "a host that could not be asked must not be reported as having answered"
        );
    }

    #[test]
    fn meminfo_decides_on_available_rather_than_free() {
        // A working Linux host keeps MemFree near zero and the page cache holds
        // the rest. Deciding on MemFree would call this machine critical.
        let body = "MemTotal:       16000000 kB\nMemFree:          120000 kB\n\
                    MemAvailable:   12000000 kB\nSwapTotal:       2000000 kB\n\
                    SwapFree:        1500000 kB\n";
        let reading = parse_meminfo(body).expect("a parsable meminfo");
        assert_eq!(reading.limit_bytes, 16_000_000 * 1024);
        assert_eq!(reading.used_bytes, 4_000_000 * 1024);
        assert_eq!(reading.swap_used_bytes, Some(500_000 * 1024));
        assert_eq!(
            Thresholds::default().level_for(&reading),
            PressureLevel::Nominal
        );
    }

    #[test]
    fn a_meminfo_without_memavailable_is_unreadable_rather_than_guessed() {
        let body = "MemTotal:       16000000 kB\nMemFree:          120000 kB\n";
        assert!(
            parse_meminfo(body).is_none(),
            "an unreadable machine is a better answer than a wrong one"
        );
    }

    #[test]
    fn the_override_forces_a_level_without_touching_the_host() {
        for (raw, want) in [
            ("nominal", PressureLevel::Nominal),
            ("elevated", PressureLevel::Elevated),
            ("critical", PressureLevel::Critical),
            ("unknown", PressureLevel::Unknown),
        ] {
            let level = PressureLevel::from_override(raw).expect("a recognized level");
            assert_eq!(level, want);
        }
        assert!(PressureLevel::from_override("mostly fine").is_none());
    }

    #[test]
    fn thresholds_reject_a_critical_bar_below_the_elevated_one() {
        let bars = Thresholds {
            elevated: 0.8,
            critical: 0.4,
            swap: 0.5,
        };
        // Written as the from_env repair rather than asserted on the raw pair,
        // because the ordering is what the two levels mean.
        let repaired = Thresholds {
            critical: bars.critical.max(bars.elevated),
            ..bars
        };
        assert_eq!(repaired.critical, 0.8);
    }

    #[test]
    fn a_forced_level_refuses_without_quoting_numbers_nobody_measured() {
        // The override exists so an acceptance run can prove the refusal
        // without filling a machine's memory. What it must not do is put an
        // invented pair of figures into a sentence whose whole register is
        // that its numbers came from a kernel.
        let forced = MemoryPressure::Forced {
            level: PressureLevel::Critical,
        };
        assert_eq!(
            forced.level_under(&Thresholds::default()),
            PressureLevel::Critical
        );
        let verdict =
            Verdict::for_reading(HeavyWork::LspSweep, &forced, &Thresholds::default());
        let reason = verdict.reason().expect("a refusal carries its reason");
        assert!(reason.contains("KIN_MEMORY_PRESSURE pins it there"), "{reason}");
        assert!(
            !reason.contains("GiB") && !reason.contains("MiB"),
            "a level nobody read must not be dressed up with figures: {reason}"
        );
        assert!(reason.contains("the language-server enrichment sweep did not start"));
    }

    #[test]
    fn a_pinned_level_ignores_a_moved_bar() {
        // An operator who pins critical and also moves the fractions must get
        // critical. Running the pin back through the grader would hand them a
        // level they did not ask for.
        let forced = MemoryPressure::Forced {
            level: PressureLevel::Critical,
        };
        let odd = Thresholds {
            elevated: 0.99,
            critical: 1.0,
            swap: 1.0,
        };
        assert_eq!(forced.level_under(&odd), PressureLevel::Critical);
    }

    #[test]
    fn a_refusal_survives_a_round_trip_through_the_store() {
        let dir = tempfile::tempdir().expect("a temp dir");
        assert!(PressureRefusal::read(dir.path()).is_none());
        PressureRefusal::record(
            dir.path(),
            HeavyWork::LspSweep,
            PressureLevel::Critical,
            "host memory pressure is critical",
        );
        let record = PressureRefusal::read(dir.path()).expect("a recorded refusal");
        assert_eq!(record.work, "lsp-sweep");
        assert_eq!(record.level, "critical");
        assert_eq!(record.reason, "host memory pressure is critical");
        PressureRefusal::clear(dir.path());
        assert!(
            PressureRefusal::read(dir.path()).is_none(),
            "the pass that proceeds retires the record, or the row never heals"
        );
    }

    #[test]
    fn an_unparsable_record_reads_as_absent() {
        let dir = tempfile::tempdir().expect("a temp dir");
        std::fs::write(pressure_record_path(dir.path()), b"{not json").expect("write");
        assert!(
            PressureRefusal::read(dir.path()).is_none(),
            "a record that exists to report a degradation must never become one"
        );
    }

    /// The reading this host actually produces, whatever host that is.
    ///
    /// Asserting a level here would be asserting on the machine CI happens to
    /// run on. What is assertable is that the probe answers at all, and that
    /// whatever it answers is internally consistent.
    #[test]
    fn the_probe_answers_this_host_consistently() {
        let pressure = probe();
        match pressure {
            MemoryPressure::Known(reading) => {
                assert!(reading.limit_bytes > 0, "a known reading has a ceiling");
                assert!(
                    reading.used_bytes <= reading.limit_bytes,
                    "usage cannot exceed the ceiling it is measured against"
                );
                let fraction = reading.used_fraction();
                assert!((0.0..=1.0).contains(&fraction), "fraction {fraction} out of range");
            }
            MemoryPressure::Unknown { reason } => {
                assert!(!reason.is_empty(), "an unknown reading says why");
            }
            MemoryPressure::Forced { level } => {
                panic!("nothing forces a level in this test, yet the probe returned {level:?}")
            }
        }
    }
}
