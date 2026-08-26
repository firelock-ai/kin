// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Machine capability detection for adaptive locate behavior.
//!
//! Determines the [`LocateProfile`] tier from effective CPU cores + available
//! RAM. Lower tiers narrow the graph multihop budget (shallower depth, a
//! smaller frontier, a shorter timeout), which trades recall for latency on
//! constrained hardware, so the tier changes retrieval quality and that
//! downgrade is surfaced, never silent (see [`LocateProfile::name`] /
//! [`LocateProfile::disabled_signals`], reported as a `capability_tier`
//! degradation on every `kin locate` result).
//!
//! The multihop budget is the whole of it. The tier does not select between a
//! fused and a lexical retrieval arm, and it does not gate the cross-encoder,
//! which [`crate::retrieval_profile::RetrievalProfile`] owns. Entity-granularity
//! fusion, the lexical parity floor and the calibrated embedding seed floor are
//! `accuracy-v2` defaults and run on every tier.
//!
//! Detection is container-aware: cores and RAM are capped by the active cgroup
//! v2 (`cpu.max` / `memory.max`) or v1 (CFS quota / `memory.limit_in_bytes`)
//! budget when one is set, so a `--cpus 2` container is scored as 2 cores rather
//! than reading the host's full topology. A bare-metal host with no cgroup limit
//! is unaffected.
//!
//! Override the auto-detected tier with the `KIN_LOCATE_PROFILE` environment
//! variable, set to `minimal`, `standard`, or `performance` (case-insensitive);
//! any other value falls through to auto-detection.
//!
//! [`CapabilityDetection::detect`] reads that variable from the environment of
//! the process it runs in, once per call, and the process that runs it is
//! whichever one serves the query. `kin-daemon` serves `/locate` by calling
//! straight into this crate, and a daemon captured its environment when it
//! started, so exporting the variable in front of a CLI invocation reaches the
//! client and never the daemon that ranks. The tier a result reports is the
//! daemon's. Changing it means setting the variable where the daemon will start
//! and restarting it, which is what the `capability_tier` degradation's
//! remediation says rather than naming the variable alone.
//!
//! Detection that cannot read the host says so. A probe failure used to be
//! swallowed and replaced with a plausible number, which scored a large machine
//! as `Minimal` and then advised its operator to obtain the hardware they were
//! already running on. [`CapabilityDetection::misread_host`] carries that
//! reason out to the caller so a tier chosen from a stand-in is never presented
//! as a reading.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocateProfile {
    /// ≤2 cores OR ≤4GB RAM
    Minimal,
    /// 4+ cores AND 8GB+ RAM (default)
    Standard,
    /// 8+ cores AND 16GB+ RAM
    Performance,
}

impl LocateProfile {
    pub fn detect() -> Self {
        CapabilityDetection::detect().profile
    }

    /// Score a tier from an effective core count and RAM figure.
    ///
    /// Pure, so the thresholds are testable without a host to run on and
    /// without the env override in the way.
    fn score(cores: usize, ram_gb: f64) -> Self {
        if cores >= 8 && ram_gb >= 16.0 {
            Self::Performance
        } else if cores >= 4 && ram_gb >= 8.0 {
            Self::Standard
        } else {
            Self::Minimal
        }
    }

    /// The tier named by `KIN_LOCATE_PROFILE`, or `None` when the value is
    /// absent or is not one of the three tier tokens.
    fn from_override(value: Option<&str>) -> Option<Self> {
        match value?.trim().to_lowercase().as_str() {
            "minimal" => Some(Self::Minimal),
            "standard" => Some(Self::Standard),
            "performance" => Some(Self::Performance),
            _ => None,
        }
    }

    pub fn multihop_max_depth(&self) -> usize {
        match self {
            Self::Minimal => 2,
            Self::Standard => 3,
            Self::Performance => 4,
        }
    }

    pub fn multihop_frontier_limit(&self) -> usize {
        match self {
            Self::Minimal => 50,
            Self::Standard => 100,
            Self::Performance => 200,
        }
    }

    pub fn multihop_timeout_ms(&self) -> u64 {
        match self {
            Self::Minimal => 200,
            Self::Standard => 500,
            Self::Performance => 1000,
        }
    }

    /// Stable lowercase tier name. Also the exact token accepted by the
    /// `KIN_LOCATE_PROFILE` override, so surfaced output names the lever a user
    /// would set to change it.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Performance => "performance",
        }
    }

    /// Retrieval signals this tier turns off relative to the full `Performance`
    /// pipeline, as stable machine-readable tokens. Empty on `Performance`.
    ///
    /// This is the no-silent-downgrade contract for hardware-adaptive locate: a
    /// smaller machine really does return lower-recall results, and the caller
    /// can see exactly which signals were dropped rather than inferring it from
    /// differing results across machines.
    ///
    /// It names the graph multihop budget and nothing else, because that budget
    /// is the only thing the tier actually gates. This list used to also claim
    /// `reranker`, `prf` and `ltr`. None of the three was ever read from the
    /// tier: `prf` has no implementation anywhere in the tree, and `reranker`
    /// and `ltr` are the same cross-encoder, owned by
    /// [`crate::retrieval_profile::RetrievalProfile`] and off unconditionally
    /// under the default `accuracy-v2` on every tier, the proof machine
    /// included. So the entry told a below-tier operator that three signals had
    /// been withdrawn when two were running exactly as they run everywhere and
    /// the third does not exist, and then advised buying hardware that would
    /// not have changed any of them. A disclosure that overstates the downgrade
    /// is the same defect as one that hides it.
    pub fn disabled_signals(&self) -> Vec<&'static str> {
        let mut off = Vec::new();
        if self.multihop_max_depth() < Self::Performance.multihop_max_depth() {
            off.push("multihop_depth");
        }
        if self.multihop_frontier_limit() < Self::Performance.multihop_frontier_limit() {
            off.push("multihop_frontier");
        }
        if self.multihop_timeout_ms() < Self::Performance.multihop_timeout_ms() {
            off.push("multihop_timeout");
        }
        off
    }
}

/// Effective schedulable core count: host parallelism, capped by a container
/// CPU quota (cgroup v2 `cpu.max` / v1 CFS quota) when one is set. Without a
/// quota this is the raw host count, so bare-metal detection is unchanged.
fn num_cpus() -> usize {
    let host = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    match cgroup_cpu_quota() {
        Some(quota) => host.min(quota).max(1),
        None => host,
    }
}

/// GiB assumed for a host whose memory could not be read.
///
/// Deliberately conservative, and deliberately never reported as a
/// measurement: every path that scores a tier against it also carries
/// [`HostMemory::Undetected`] so the caller can say the number was invented.
const UNDETECTED_RAM_GB: f64 = 4.0;

/// What a host-memory probe returned, or why it could not answer.
#[derive(Debug, Clone, PartialEq)]
pub enum HostMemory {
    /// Physical RAM in GiB as read from the host.
    Detected(f64),
    /// The probe could not answer, with the reason it gave.
    Undetected(String),
}

impl HostMemory {
    /// GiB to score a tier against: the reading when there is one, otherwise
    /// the conservative stand-in.
    pub fn gb_or_stand_in(&self) -> f64 {
        match self {
            Self::Detected(gb) => *gb,
            Self::Undetected(_) => UNDETECTED_RAM_GB,
        }
    }

    /// Why the host could not be read, when it could not.
    pub fn undetected_reason(&self) -> Option<&str> {
        match self {
            Self::Detected(_) => None,
            Self::Undetected(reason) => Some(reason),
        }
    }
}

/// Physical RAM as reported by the `hw.memsize` sysctl, read through
/// `sysctlbyname` rather than by running `/usr/sbin/sysctl`.
///
/// The subprocess form depended on the caller's `PATH`, and `/usr/sbin` is
/// absent from the minimal environments that matter most here: an MCP client
/// spawning `kin mcp start`, a launchd agent, a container entrypoint, a CI
/// runner. There, command-not-found was swallowed and the host was scored as
/// though it had 4 GB. The syscall cannot be defeated by the environment.
#[cfg(target_os = "macos")]
fn probe_host_ram() -> HostMemory {
    let mut bytes: u64 = 0;
    let mut size = std::mem::size_of::<u64>() as libc::size_t;
    let status = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            std::ptr::addr_of_mut!(bytes).cast::<libc::c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return HostMemory::Undetected(format!(
            "sysctlbyname(hw.memsize) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if size != std::mem::size_of::<u64>() as libc::size_t || bytes == 0 {
        return HostMemory::Undetected(format!(
            "sysctlbyname(hw.memsize) returned {size} bytes holding {bytes}"
        ));
    }
    HostMemory::Detected(bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

#[cfg(target_os = "linux")]
fn probe_host_ram() -> HostMemory {
    let contents = match std::fs::read_to_string("/proc/meminfo") {
        Ok(contents) => contents,
        Err(error) => return HostMemory::Undetected(format!("/proc/meminfo unreadable: {error}")),
    };
    match parse_meminfo_total_gb(&contents) {
        Some(gb) => HostMemory::Detected(gb),
        None => HostMemory::Undetected("/proc/meminfo carries no parsable MemTotal".to_string()),
    }
}

/// `MemTotal` out of a `/proc/meminfo` body, in GiB.
#[cfg(any(target_os = "linux", test))]
fn parse_meminfo_total_gb(contents: &str) -> Option<f64> {
    contents.lines().find_map(|line| {
        let kb: u64 = line
            .strip_prefix("MemTotal:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some(kb as f64 / (1024.0 * 1024.0))
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn probe_host_ram() -> HostMemory {
    HostMemory::Undetected(format!(
        "no host-memory probe for target_os {}",
        std::env::consts::OS
    ))
}

/// Probe the host once per process and warn the first time it cannot answer.
///
/// The warning is what stops a misread host from being silent for consumers
/// that do not carry a structured degradation ledger of their own; `kin locate`
/// additionally reports it in-band (see
/// [`CapabilityDetection::misread_host`]).
fn host_memory() -> HostMemory {
    let memory = probe_host_ram();
    if let Some(reason) = memory.undetected_reason() {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                reason,
                stand_in_gb = UNDETECTED_RAM_GB,
                "host memory could not be read; capability tiers on this process are scored \
                 against a conservative stand-in, not a reading of this machine"
            );
        });
    }
    memory
}

fn host_ram_gb() -> f64 {
    host_memory().gb_or_stand_in()
}

/// Effective available RAM: the host figure, capped by a container memory
/// limit (cgroup v2 `memory.max` / v1 `memory.limit_in_bytes`) when one is set.
/// Without a limit this is the host figure, so bare-metal detection is
/// unchanged. A cap never turns an undetected host into a detected one.
fn available_memory(host: HostMemory) -> HostMemory {
    let Some(limit) = cgroup_memory_limit_bytes() else {
        return host;
    };
    let limit_gb = limit as f64 / (1024.0 * 1024.0 * 1024.0);
    match host {
        HostMemory::Detected(gb) => HostMemory::Detected(gb.min(limit_gb)),
        HostMemory::Undetected(reason) => HostMemory::Undetected(reason),
    }
}

/// The tier this process will run at, and the evidence it was chosen from.
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityDetection {
    pub profile: LocateProfile,
    /// The operator named the tier through `KIN_LOCATE_PROFILE`; no probe was
    /// consulted, so a probe that would have failed is not this tier's reason.
    pub forced_by_env: bool,
    /// Effective schedulable cores, or `None` under a forced tier.
    pub cores: Option<usize>,
    /// Effective memory, or `None` under a forced tier.
    pub memory: Option<HostMemory>,
}

impl CapabilityDetection {
    pub fn detect() -> Self {
        Self::resolve(
            std::env::var("KIN_LOCATE_PROFILE").ok().as_deref(),
            num_cpus,
            || available_memory(host_memory()),
        )
    }

    /// Core of [`Self::detect`] with the override string and both probes as
    /// explicit inputs, so every branch is testable on any host.
    fn resolve(
        override_value: Option<&str>,
        cores: impl FnOnce() -> usize,
        memory: impl FnOnce() -> HostMemory,
    ) -> Self {
        if let Some(profile) = LocateProfile::from_override(override_value) {
            return Self {
                profile,
                forced_by_env: true,
                cores: None,
                memory: None,
            };
        }
        let cores = cores();
        let memory = memory();
        Self {
            profile: LocateProfile::score(cores, memory.gb_or_stand_in()),
            forced_by_env: false,
            cores: Some(cores),
            memory: Some(memory),
        }
    }

    /// Why this tier is not a reading of the host, when it is not.
    ///
    /// A tier derived from a failed probe must never be reported as though the
    /// numbers behind it were measured: the remediation that follows from a
    /// real reading ("run on a bigger host") is actively wrong advice when the
    /// host was never read.
    pub fn misread_host(&self) -> Option<&str> {
        self.memory.as_ref()?.undetected_reason()
    }
}

/// Which reading supplied the ceiling in [`MemoryEvidence`].
///
/// A row that warns about running out of memory has to be able to say which
/// number it read, because the two answers can differ by far more than the
/// margin they get compared against. That is FIR-2638 in one sentence: the
/// probe read the host figure for a process capped at twelve gigabytes,
/// reported nineteen, and the kernel killed it with nothing disclosed. A reader
/// inside a container cannot tell those apart from the byte count alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryLimitSource {
    /// A cgroup memory cap, found by walking up from this process's own
    /// `/proc/self/cgroup` path rather than by reading the hierarchy root.
    ContainerLimit,
    /// This host's physical RAM, because no cgroup cap binds tighter than it.
    HostRam,
}

impl MemoryLimitSource {
    /// How to name this ceiling to somebody deciding where to run a write.
    pub fn describe(self) -> &'static str {
        match self {
            Self::ContainerLimit => "this container's memory cap",
            Self::HostRam => "this host's RAM",
        }
    }
}

/// What the host can say about memory pressure, for a command that has to
/// decide whether a failure it just saw was the machine running out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryEvidence {
    /// The ceiling this process actually runs under: the container limit when
    /// one is set, otherwise the host's physical RAM.
    pub limit_bytes: u64,
    /// Which of those two `limit_bytes` came from, so a surface quoting it can
    /// name what it read instead of leaving a reader to guess.
    pub limit_source: MemoryLimitSource,
    /// Kernel OOM kills the cgroup recorded BETWEEN the baseline this evidence
    /// was measured against and the moment it was taken.
    ///
    /// Not a lifetime total, and that distinction is the whole of FIR-1823.
    /// The kernel's counter only ever counts upwards for as long as the cgroup
    /// exists, so a container that killed something an hour ago answers the
    /// question "have you ever" with a number, and a surface that reads it as
    /// "did this run" hands a caller an unhedged wrong cause for a failure that
    /// had nothing to do with memory. Two readings can tell those apart; one
    /// cannot.
    ///
    /// `Some(0)` is the kernel saying nothing was killed while this run was
    /// going on. `None` is this process being unable to say: no accounting was
    /// readable, no baseline was taken, or the counter moved backwards because
    /// the cgroup was not the same one both times. All three are "not
    /// observed", and none of them is "did not happen".
    pub cgroup_oom_kills: Option<u64>,
    /// Times the cgroup's charge was held at its own ceiling over that same
    /// window, graded exactly as the kills above are.
    ///
    /// This is the evidence a run that was never killed used to leave nowhere a
    /// reader could find it. A container that spends its life pinned against
    /// the cap, reclaiming on every allocation, is in obvious memory trouble
    /// and reports `oom_kills` of zero; before this field the only honest thing
    /// any diagnosis could say about it was nothing at all. The 4 GiB arm on
    /// 2026-08-25 recorded 6344 ceiling hits, and no kin surface read one of
    /// them.
    pub cgroup_ceiling_hits: Option<u64>,
}

/// The cumulative cgroup counters as they stood before a piece of work began.
///
/// Taken by a caller that intends to diagnose its own failure later, because
/// the counters it will want are cumulative and a single reading of a
/// cumulative counter cannot be attributed to anything. This is the same shape
/// `kin_daemon_spawn` already grades a daemon's death with, for the same
/// reason: the reading taken before is what makes the reading taken after mean
/// something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryBaseline {
    oom_kills: Option<u64>,
    ceiling_hits: Option<u64>,
}

impl MemoryBaseline {
    /// The counters out of a reading already taken.
    pub(crate) fn from_reading(cgroup: kin_daemon_spawn::CgroupMemory) -> Self {
        Self {
            oom_kills: cgroup.oom_kills,
            ceiling_hits: cgroup.ceiling_hits,
        }
    }
}

/// Take the counters as they stand now, to compare a later reading against.
pub fn memory_baseline() -> MemoryBaseline {
    MemoryBaseline::from_reading(kin_daemon_spawn::cgroup_memory())
}

/// How far a cumulative counter advanced between two readings.
///
/// `None` unless both readings exist and the second is not behind the first. A
/// counter that went backwards belongs to a cgroup that is not the one the
/// baseline described, and a difference taken across two different scopes is
/// not a measurement of anything.
fn counter_advance(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    match (before, after) {
        (Some(before), Some(after)) if after >= before => Some(after - before),
        _ => None,
    }
}

/// Read the ceiling this process runs under, attributing no counter movement.
///
/// For a caller that wants the ceiling and nothing else: a notice printed
/// before any work starts, or a health row scoring the machine. Both counter
/// fields come back `None`, because without a baseline there is no window to
/// attribute movement to and reporting a lifetime total in a field documented
/// as a per-run one is the defect this signature exists to make impossible.
/// A caller that has to explain a failure it just saw takes
/// [`memory_baseline`] first and calls [`memory_evidence_since`] instead.
pub fn memory_evidence() -> MemoryEvidence {
    evidence_from(host_ram_bytes(), kin_daemon_spawn::cgroup_memory(), None)
}

/// Read the ceiling, plus what the cgroup's counters did since `baseline`.
pub fn memory_evidence_since(baseline: MemoryBaseline) -> MemoryEvidence {
    evidence_from(
        host_ram_bytes(),
        kin_daemon_spawn::cgroup_memory(),
        Some(baseline),
    )
}

/// Core of both readers with every input passed in, so each branch is testable
/// on any host.
///
/// The seam is here rather than one layer up because the branch that matters is
/// the one no macOS developer can reach: a container with a violent history,
/// judged against a baseline. A test that can only reach it through
/// `/sys/fs/cgroup` is a test that never runs on the machine the code is
/// written on.
pub(crate) fn evidence_from(
    host_ram_bytes: u64,
    cgroup: kin_daemon_spawn::CgroupMemory,
    baseline: Option<MemoryBaseline>,
) -> MemoryEvidence {
    let (limit_bytes, limit_source) = resolve_memory_limit(host_ram_bytes, cgroup.limit_bytes);
    // No baseline is no window, and no window is no attribution. Falling back
    // to the raw lifetime totals here is exactly FIR-1823, so the absent case
    // reports nothing rather than reporting the container's whole history as
    // though it belonged to whatever just failed.
    let baseline = match baseline {
        Some(baseline) => baseline,
        None => {
            return MemoryEvidence {
                limit_bytes,
                limit_source,
                cgroup_oom_kills: None,
                cgroup_ceiling_hits: None,
            };
        }
    };
    MemoryEvidence {
        limit_bytes,
        limit_source,
        cgroup_oom_kills: counter_advance(baseline.oom_kills, cgroup.oom_kills),
        cgroup_ceiling_hits: counter_advance(baseline.ceiling_hits, cgroup.ceiling_hits),
    }
}

fn host_ram_bytes() -> u64 {
    (host_ram_gb() * 1024.0 * 1024.0 * 1024.0) as u64
}

/// The memory ceiling a Kin process runs under, and which reading supplied it.
///
/// Pure over both readings so the tie and both orderings are testable on any
/// host. A cap equal to the host figure is attributed to the host, because the
/// cap constrains nothing that the physical memory did not already constrain,
/// and naming a container cap that binds nothing invites a reader to raise a
/// limit that was never the wall.
fn resolve_memory_limit(host: u64, cgroup: Option<u64>) -> (u64, MemoryLimitSource) {
    match cgroup {
        Some(limit) if limit < host => (limit, MemoryLimitSource::ContainerLimit),
        _ => (host, MemoryLimitSource::HostRam),
    }
}

// ---------------------------------------------------------------------------
// Container (cgroup) quota detection — Linux only
// ---------------------------------------------------------------------------
//
// The tier must reflect the real budget, not the host topology, so a `--cpus 2`
// container is not mis-scored as an 8-core Performance box. The FS-reading
// probes are Linux-only and return `None` when no quota is set (an unlimited
// group, absent files, or off-Linux), keeping bare-metal detection unchanged.
// The parsing is factored into pure helpers so it is unit-tested on any host.

/// Effective CPU count from a container CPU quota, or `None` when unlimited,
/// unset, unparsable, or off Linux.
#[cfg(target_os = "linux")]
fn cgroup_cpu_quota() -> Option<usize> {
    // cgroup v2 unified hierarchy: `cpu.max` is "<quota> <period>" (µs) or
    // "max <period>" when unthrottled.
    if let Ok(contents) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        if let Some(cores) = parse_v2_cpu_max(&contents) {
            return Some(cores);
        }
        if contents.trim_start().starts_with("max") {
            return None;
        }
    }
    // cgroup v1: cpu.cfs_quota_us / cpu.cfs_period_us.
    let quota: i64 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let period: i64 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    parse_v1_cpu_quota(quota, period)
}

#[cfg(not(target_os = "linux"))]
fn cgroup_cpu_quota() -> Option<usize> {
    None
}

/// Effective memory limit in bytes from a container memory cap, or `None` when
/// unlimited, unset, unparsable, or off Linux.
///
/// One reader for the whole product, in `kin_daemon_spawn`, because the process
/// that records why a daemon died cannot depend on this crate and must decide
/// from the same two numbers this tier is scored from.
fn cgroup_memory_limit_bytes() -> Option<u64> {
    kin_daemon_spawn::cgroup_memory().limit_bytes
}

/// Whole-core count for a cgroup v2 `cpu.max` value ("<quota> <period>" in µs,
/// or "max <period>"). Rounds a fractional quota up to one core; `None` when
/// unlimited or unparsable.
#[cfg(any(target_os = "linux", test))]
fn parse_v2_cpu_max(contents: &str) -> Option<usize> {
    let mut fields = contents.split_whitespace();
    let quota = fields.next()?;
    if quota == "max" {
        return None;
    }
    let quota: u64 = quota.parse().ok()?;
    let period: u64 = fields
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(100_000);
    if period == 0 {
        return None;
    }
    Some((quota.div_ceil(period) as usize).max(1))
}

/// Whole-core count for cgroup v1 CFS `quota`/`period` (µs). A non-positive
/// quota/period is "unlimited" → `None`.
#[cfg(any(target_os = "linux", test))]
fn parse_v1_cpu_quota(quota_us: i64, period_us: i64) -> Option<usize> {
    if quota_us <= 0 || period_us <= 0 {
        return None;
    }
    Some(((quota_us as u64).div_ceil(period_us as u64) as usize).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A container reading with a history: killed before, pinned before.
    fn cgroup(oom_kills: Option<u64>, ceiling_hits: Option<u64>) -> kin_daemon_spawn::CgroupMemory {
        kin_daemon_spawn::CgroupMemory {
            limit_bytes: Some(4 * 1024 * 1024 * 1024),
            oom_kills,
            ceiling_hits,
            ..kin_daemon_spawn::CgroupMemory::default()
        }
    }

    const HOST_RAM: u64 = 64 * 1024 * 1024 * 1024;

    /// FIR-1823, at the layer that decides it. Both counters are cumulative for
    /// the container's whole life, so the number that answers "did this run"
    /// is the difference across the run and never the total after it.
    ///
    /// The two arms are identical except for when the kill happened. A run that
    /// began and ended at three killed nothing, however loudly the container's
    /// history reads; a run that began at three and ended at four killed one.
    /// Before the fix both of these reported three.
    #[test]
    fn counters_are_the_advance_across_the_run_not_the_containers_lifetime() {
        let before = MemoryBaseline::from_reading(cgroup(Some(3), Some(900)));

        let quiet = evidence_from(HOST_RAM, cgroup(Some(3), Some(900)), Some(before));
        assert_eq!(
            quiet.cgroup_oom_kills,
            Some(0),
            "a counter that did not move means this run killed nothing, not that three kills \
             belong to it"
        );
        assert_eq!(quiet.cgroup_ceiling_hits, Some(0));

        let killed = evidence_from(HOST_RAM, cgroup(Some(4), Some(1_244)), Some(before));
        assert_eq!(
            killed.cgroup_oom_kills,
            Some(1),
            "one kill during the run is one kill, not the four the container has ever seen"
        );
        assert_eq!(
            killed.cgroup_ceiling_hits,
            Some(344),
            "the ceiling counter is graded the same way, for the same reason"
        );
    }

    /// The reading with no baseline attributes nothing, whatever the container
    /// has been through.
    ///
    /// This is the property the fix rests on. A caller that never took a
    /// before-reading cannot be handed a per-run number, so the worst a future
    /// edit reverting to this reader can produce is a hedged diagnosis, never a
    /// confident wrong one.
    #[test]
    fn a_reading_with_no_baseline_attributes_no_counter_movement() {
        let violent = evidence_from(HOST_RAM, cgroup(Some(9), Some(6_344)), None);
        assert_eq!(
            violent.cgroup_oom_kills, None,
            "nine lifetime kills belong to no particular run and must be reported as belonging \
             to none"
        );
        assert_eq!(violent.cgroup_ceiling_hits, None);
        assert_eq!(
            violent.limit_bytes,
            4 * 1024 * 1024 * 1024,
            "the ceiling is still read; it is the attribution that is withheld"
        );
    }

    /// The three ways an advance is not measurable, each distinct from zero.
    #[test]
    fn an_unaskable_or_incoherent_counter_is_not_an_advance_of_zero() {
        let unreadable = MemoryBaseline::from_reading(cgroup(None, None));
        let now = evidence_from(HOST_RAM, cgroup(Some(4), Some(10)), Some(unreadable));
        assert_eq!(
            now.cgroup_oom_kills, None,
            "a baseline nobody could read cannot be subtracted from"
        );
        assert_eq!(now.cgroup_ceiling_hits, None);

        let readable = MemoryBaseline::from_reading(cgroup(Some(4), Some(10)));
        let gone = evidence_from(HOST_RAM, cgroup(None, None), Some(readable));
        assert_eq!(
            gone.cgroup_oom_kills, None,
            "a host that stopped answering reports nothing, not that nothing happened"
        );

        let backwards = evidence_from(HOST_RAM, cgroup(Some(1), Some(2)), Some(readable));
        assert_eq!(
            backwards.cgroup_oom_kills, None,
            "a counter behind its own baseline belongs to a different cgroup, and the difference \
             across two scopes measures nothing"
        );
        assert_eq!(backwards.cgroup_ceiling_hits, None);
    }

    #[test]
    fn tier_names_match_env_override_tokens() {
        assert_eq!(LocateProfile::Minimal.name(), "minimal");
        assert_eq!(LocateProfile::Standard.name(), "standard");
        assert_eq!(LocateProfile::Performance.name(), "performance");
    }

    #[test]
    fn performance_disables_nothing_lower_tiers_do() {
        assert!(LocateProfile::Performance.disabled_signals().is_empty());
        // Every sub-Performance tier narrows all three multihop bounds.
        for tier in [LocateProfile::Standard, LocateProfile::Minimal] {
            let off = tier.disabled_signals();
            for sig in ["multihop_depth", "multihop_frontier", "multihop_timeout"] {
                assert!(off.contains(&sig), "{} should narrow {sig}", tier.name());
            }
        }
    }

    /// The tier may only claim what it actually gates.
    ///
    /// `reranker`, `prf` and `ltr` were reported here for tiers that never
    /// gated them, which told a below-tier operator that three signals had been
    /// withdrawn when two run identically on every tier and the third is not
    /// implemented at all. Nothing in the tree reads a tier to decide any of
    /// them, so a disclosure naming them cannot be true.
    #[test]
    fn the_tier_claims_no_signal_it_does_not_gate() {
        for tier in [
            LocateProfile::Minimal,
            LocateProfile::Standard,
            LocateProfile::Performance,
        ] {
            for phantom in ["reranker", "prf", "ltr"] {
                assert!(
                    !tier.disabled_signals().contains(&phantom),
                    "{} must not claim to disable {phantom}, which no tier gates",
                    tier.name()
                );
            }
            for signal in tier.disabled_signals() {
                assert!(
                    signal.starts_with("multihop_"),
                    "{} reports {signal}, which is not a multihop bound",
                    tier.name()
                );
            }
        }
    }

    #[test]
    fn v2_cpu_max_parses_quota_period_and_unlimited() {
        assert_eq!(parse_v2_cpu_max("200000 100000"), Some(2));
        assert_eq!(parse_v2_cpu_max("50000 100000"), Some(1)); // ceil fractional
        assert_eq!(parse_v2_cpu_max("150000 100000"), Some(2));
        assert_eq!(parse_v2_cpu_max("max 100000"), None);
        assert_eq!(parse_v2_cpu_max(""), None);
        assert_eq!(parse_v2_cpu_max("bogus 100000"), None);
    }

    #[test]
    fn v1_cpu_quota_treats_negative_as_unlimited() {
        assert_eq!(parse_v1_cpu_quota(200000, 100000), Some(2));
        assert_eq!(parse_v1_cpu_quota(-1, 100000), None);
        assert_eq!(parse_v1_cpu_quota(0, 100000), None);
    }

    /// A failed memory probe and a real one, both ways round. An 18-core host
    /// whose memory probe fails must not be scored `Minimal` and reported as
    /// though 4 GB had been measured; the same host with a reading must score
    /// `Performance`.
    #[test]
    fn a_failed_memory_probe_is_reported_rather_than_scored_as_four_gigabytes() {
        let misread = CapabilityDetection::resolve(
            None,
            || 18,
            || HostMemory::Undetected("sysctlbyname(hw.memsize) failed: no such file".to_string()),
        );
        assert_eq!(misread.profile, LocateProfile::Minimal);
        assert_eq!(
            misread.misread_host(),
            Some("sysctlbyname(hw.memsize) failed: no such file"),
            "a tier scored against the stand-in must carry the probe failure out to the caller"
        );

        let read = CapabilityDetection::resolve(None, || 18, || HostMemory::Detected(128.0));
        assert_eq!(read.profile, LocateProfile::Performance);
        assert_eq!(
            read.misread_host(),
            None,
            "a successful probe must not be reported as a detection failure"
        );
    }

    /// A genuinely small machine still reaches `Minimal`, and does so as a
    /// reading rather than as a failure. Without this the fix could pass by
    /// calling every low tier a misread.
    #[test]
    fn a_genuinely_constrained_host_still_scores_minimal_with_nothing_to_report() {
        let constrained = CapabilityDetection::resolve(None, || 2, || HostMemory::Detected(2.0));
        assert_eq!(constrained.profile, LocateProfile::Minimal);
        assert_eq!(constrained.misread_host(), None);
        assert!(!constrained.profile.disabled_signals().is_empty());
    }

    /// An operator who names the tier is not consulting a probe, so a probe
    /// that would have failed is not this tier's reason and must not be
    /// reported as one.
    #[test]
    fn a_forced_tier_reports_no_detection_failure() {
        let forced = CapabilityDetection::resolve(
            Some("performance"),
            || unreachable!("a forced tier must not probe cores"),
            || unreachable!("a forced tier must not probe memory"),
        );
        assert_eq!(forced.profile, LocateProfile::Performance);
        assert!(forced.forced_by_env);
        assert_eq!(forced.misread_host(), None);
    }

    #[test]
    fn override_tokens_are_case_and_whitespace_tolerant_and_otherwise_ignored() {
        assert_eq!(
            LocateProfile::from_override(Some("  Performance ")),
            Some(LocateProfile::Performance)
        );
        assert_eq!(LocateProfile::from_override(Some("turbo")), None);
        assert_eq!(LocateProfile::from_override(None), None);
    }

    #[test]
    fn tier_thresholds_need_both_cores_and_memory() {
        assert_eq!(LocateProfile::score(8, 16.0), LocateProfile::Performance);
        assert_eq!(LocateProfile::score(8, 15.9), LocateProfile::Standard);
        assert_eq!(LocateProfile::score(4, 8.0), LocateProfile::Standard);
        assert_eq!(LocateProfile::score(3, 64.0), LocateProfile::Minimal);
    }

    /// The probe on the host this test runs on. It is the only assertion here
    /// that would have caught the original defect in situ: on a developer or CI
    /// machine, memory is readable, and any environment-shaped failure to read
    /// it shows up as `Undetected`.
    #[test]
    fn this_host_reports_its_memory() {
        let memory = probe_host_ram();
        match &memory {
            HostMemory::Detected(gb) => assert!(*gb > 0.0, "a detected host must report real GiB"),
            HostMemory::Undetected(reason) => {
                panic!("host memory probe failed on the test host: {reason}")
            }
        }
    }

    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn meminfo_total_is_parsed_and_a_body_without_it_is_a_miss() {
        assert_eq!(
            parse_meminfo_total_gb("MemFree: 100 kB\nMemTotal:       16777216 kB\n"),
            Some(16.0)
        );
        assert_eq!(parse_meminfo_total_gb("MemFree: 100 kB\n"), None);
        assert_eq!(parse_meminfo_total_gb("MemTotal:       nope kB\n"), None);
    }

    /// The ceiling has to carry which reading produced it, in both directions.
    ///
    /// A byte count alone cannot tell a reader inside a container whether their
    /// cap was seen at all, which is the shape FIR-2638 shipped: the host figure
    /// answered for a capped process and the disclosure stayed silent through
    /// the kill. A surface that quotes this number quotes the source beside it,
    /// so it can only do that if the source travels with the number.
    ///
    /// Falsify by returning `HostRam` unconditionally, which leaves the byte
    /// count correct and every band unchanged: only the first case below fails.
    #[test]
    fn the_memory_ceiling_names_which_reading_bound_it() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(
            resolve_memory_limit(19 * GIB, Some(12 * GIB)),
            (12 * GIB, MemoryLimitSource::ContainerLimit),
            "a cap under the host figure is the wall, and saying so is the FIR-2638 disclosure"
        );
        assert_eq!(
            resolve_memory_limit(8 * GIB, Some(64 * GIB)),
            (8 * GIB, MemoryLimitSource::HostRam),
            "a cap the host cannot reach binds nothing"
        );
        assert_eq!(
            resolve_memory_limit(16 * GIB, None),
            (16 * GIB, MemoryLimitSource::HostRam),
            "no cgroup accounting means the host figure, named as the host figure"
        );
        assert_eq!(
            resolve_memory_limit(12 * GIB, Some(12 * GIB)),
            (12 * GIB, MemoryLimitSource::HostRam),
            "a cap level with the host constrains nothing the host did not, and pointing a \
             reader at raising it would send them at the wrong wall"
        );
    }

    /// Both names have to read as an answer to "which number is this".
    #[test]
    fn each_ceiling_source_names_itself_to_a_reader() {
        assert!(
            MemoryLimitSource::ContainerLimit
                .describe()
                .contains("container"),
            "a capped process is told it is capped"
        );
        assert!(
            MemoryLimitSource::HostRam.describe().contains("host"),
            "an uncapped process is told it is reading the machine"
        );
        assert_ne!(
            MemoryLimitSource::ContainerLimit.describe(),
            MemoryLimitSource::HostRam.describe(),
            "two sources that print the same words disclose nothing"
        );
    }
}
