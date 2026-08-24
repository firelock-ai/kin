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
    ///
    /// Measured and never refused. Holding it is not the same trade as holding
    /// the two above: a sweep held costs relations the next sweep restores and
    /// a batch held costs vectors the next batch restores, while admission held
    /// costs the thing itself, since it is the path by which a written file
    /// becomes queryable at all. On a machine that stays loaded the tick that
    /// would admit never comes, so the file stays invisible for as long as the
    /// machine is busy. Neither measured failure implicated it, and it is one
    /// bounded walk over a working copy. It keeps its place here because the
    /// reconcile loop is the cheapest cadence in the daemon to publish the
    /// footprint standing from, and a labelled call is what publishes it.
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

/// What a daemon's process tree is holding right now.
///
/// A tree rather than a process, because the thing that killed the daemon was
/// not the daemon. The cold sweep peaked at 18.2 GB while its pyright child
/// held another 1.93 GiB in a process of its own, and every per-pid view of
/// that daemon was blind to the second number. A language server is started by
/// the daemon, lives as long as the sweep does, and is charged to the same
/// container; a budget that cannot see it is a budget that is wrong by
/// whatever the servers happen to hold.
/// Every figure here is proportional or private rather than resident, and that
/// is the second thing this type is for. Summing resident sets across a tree
/// counts every shared page once per process, so a daemon and thirteen children
/// mapping the same binary and the same libraries are charged for all of it
/// thirteen times. The v0.5.51 stranger measured the result: `graph status`
/// claiming 25.3 GiB inside a cgroup hard-capped at 12 GiB whose true peak was
/// 9.99 GiB, and background embedding refused on every store, so every vector
/// answer came from an empty index on a box that had room (FIR-2653).
/// `kin_daemon_spawn::process_footprint_bytes` is where each figure comes from
/// and what each platform can say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct TreeFootprint {
    /// The daemon process's own proportional footprint.
    pub own_bytes: u64,
    /// Every descendant's proportional footprint, summed. A page two of them
    /// share is counted once across the two, never once each.
    pub children_bytes: u64,
    /// How many descendants were counted, so a reading of zero children can be
    /// told from a reading that found them and they were small.
    pub child_count: usize,
    /// Whether [`Self::clamped_to`] held this reading down to what the kernel
    /// charges the cgroup this process runs in.
    ///
    /// Defaulted on read so a standing published by an older daemon still
    /// parses, and reported rather than kept, because a number the kernel
    /// overrode is a different fact from one this process measured outright.
    #[serde(default)]
    pub kernel_capped: bool,
}

impl TreeFootprint {
    /// What the whole tree holds.
    pub fn total_bytes(&self) -> u64 {
        self.own_bytes.saturating_add(self.children_bytes)
    }

    /// This reading, held down to what the kernel says the whole cgroup is
    /// charged.
    ///
    /// A process tree inside a cgroup cannot be holding more than the cgroup is
    /// charged, so a total above `charged_bytes` is this process's arithmetic
    /// disagreeing with the kernel's, and the kernel wins. That is the
    /// invariant a reader needs: the footprint printed beside a container's cap
    /// can never exceed it, so a figure like 25.3 GiB against a 12 GiB cap is
    /// unreachable by construction rather than merely unlikely.
    ///
    /// It is a ceiling and not the measurement. The per-process readings this
    /// folds are already proportional, so the clamp is expected never to bite;
    /// when it does, it says so through [`Self::kernel_capped`] rather than
    /// quietly presenting the kernel's figure as its own. Both halves are
    /// scaled by the same factor so the child figure keeps its share and the
    /// two still add up to the total.
    ///
    /// `None` is a host with no cgroup accounting, where there is no such
    /// ceiling to hold anything to and the reading stands as measured.
    pub fn clamped_to(self, charged_bytes: Option<u64>) -> Self {
        let Some(charged) = charged_bytes else {
            return self;
        };
        let total = self.total_bytes();
        if total <= charged {
            return self;
        }
        let scale = |part: u64| -> u64 {
            ((u128::from(part) * u128::from(charged)) / u128::from(total)) as u64
        };
        let own_bytes = scale(self.own_bytes);
        Self {
            own_bytes,
            children_bytes: charged.saturating_sub(own_bytes),
            child_count: self.child_count,
            kernel_capped: true,
        }
    }
}

/// Where a budget's number came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetSource {
    /// Derived from the ceiling this process runs under.
    Derived,
    /// An operator named it outright.
    Operator,
}

impl BudgetSource {
    /// How a disclosure describes the number's provenance.
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetSource::Derived => "derived from the memory available here",
            BudgetSource::Operator => "set by an operator",
        }
    }
}

/// Where an operator names the budget outright, in bytes.
pub const FOOTPRINT_BUDGET_ENV: &str = "KIN_DAEMON_MEMORY_BUDGET_BYTES";

/// The most a derived budget will ever allow one repository daemon to hold.
///
/// This constant is the lever that would have caught the measured failure, and
/// it is a judgement rather than a measurement, so it is written where a reader
/// can find and argue with it. The sweep that killed the daemon peaked at 18.2
/// GB on a store of about one gigabyte, on a host with 128 GiB. Any budget
/// derived only as a fraction of the ceiling would have allowed it: half of 128
/// GiB is 64. A repository daemon holding more than eight gigabytes is
/// pathological for any store a person is working in, whatever the host has
/// spare, so the derived budget is capped here regardless of how large the
/// machine is.
pub const DERIVED_BUDGET_CEILING_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The least a derived budget will ever allow.
///
/// A budget smaller than this would make a daemon back off before it could do
/// anything useful, which is worse than no budget at all: the store never
/// converges and the disclosure blames a machine that was merely small.
pub const DERIVED_BUDGET_FLOOR_BYTES: u64 = 1024 * 1024 * 1024;

/// What a daemon is allowed to hold, and where the number came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FootprintBudget {
    pub bytes: u64,
    pub source: BudgetSource,
}

impl FootprintBudget {
    /// The budget this process runs under, given the ceiling it runs under.
    ///
    /// An operator value wins outright and is not clamped: someone who names a
    /// number has said what they want, and silently moving it would be the
    /// same silence this whole module exists to remove. A value that will not
    /// parse, or is zero, is ignored rather than obeyed, because a budget of
    /// zero refuses everything forever.
    pub fn resolve(ceiling_bytes: Option<u64>) -> Option<Self> {
        if let Some(bytes) = std::env::var(FOOTPRINT_BUDGET_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|bytes| *bytes > 0)
        {
            return Some(Self {
                bytes,
                source: BudgetSource::Operator,
            });
        }
        ceiling_bytes.map(|ceiling| Self {
            bytes: derive_budget(ceiling),
            source: BudgetSource::Derived,
        })
    }

    /// Half the ceiling, held between the floor and the ceiling constant.
    ///
    /// Half because a daemon is not the only thing on the machine, and the
    /// other half is the user's editor, their language servers outside Kin,
    /// their browser and their build.
    pub fn derived_from(ceiling_bytes: u64) -> u64 {
        derive_budget(ceiling_bytes)
    }
}

fn derive_budget(ceiling_bytes: u64) -> u64 {
    (ceiling_bytes / 2).clamp(DERIVED_BUDGET_FLOOR_BYTES, DERIVED_BUDGET_CEILING_BYTES)
}

/// How a daemon's tree stands against its budget.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BudgetStanding {
    pub footprint: TreeFootprint,
    pub budget: FootprintBudget,
}

impl BudgetStanding {
    /// How much of the budget the tree is holding, in `0.0..`.
    ///
    /// Not clamped at one. A tree that has passed its budget is over it, and a
    /// surface that reported 100% for both a small overrun and a fourfold one
    /// would hide the difference that matters.
    pub fn used_fraction(&self) -> f64 {
        if self.budget.bytes == 0 {
            return 0.0;
        }
        self.footprint.total_bytes() as f64 / self.budget.bytes as f64
    }

    /// The rung this standing sits at, on the same scale host pressure uses.
    ///
    /// The same two bars, so an operator learns one set of numbers rather than
    /// two, and so the four consultation points can take the worse of the two
    /// without translating between scales.
    pub fn level_under(&self, thresholds: &Thresholds) -> PressureLevel {
        let fraction = self.used_fraction();
        if fraction >= thresholds.critical {
            PressureLevel::Critical
        } else if fraction >= thresholds.elevated {
            PressureLevel::Elevated
        } else {
            PressureLevel::Nominal
        }
    }

    /// What this standing is, in one sentence, with the children named.
    ///
    /// The child figure is always printed, including when it is zero, because
    /// its absence is the defect this exists to fix: a reader who cannot see a
    /// child line cannot tell a daemon with no language servers from a reading
    /// that never looked for them.
    pub fn sentence(&self) -> String {
        format!(
            "this repository's daemon and the {} process(es) it started hold {} of the {} it is \
             allowed ({}), of which {} is in those child processes{}",
            self.footprint.child_count,
            human_bytes(self.footprint.total_bytes()),
            human_bytes(self.budget.bytes),
            self.budget.source.as_str(),
            human_bytes(self.footprint.children_bytes),
            if self.footprint.kernel_capped {
                ", held at what the kernel charges this container"
            } else {
                ""
            },
        )
    }
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
        Self::decide(work, pressure, None, thresholds)
    }

    /// The verdict for one piece of work under both constraints a daemon has.
    ///
    /// Two questions, one answer. The host reading asks whether the machine has
    /// room; the standing asks whether this daemon is entitled to more of it.
    /// They fail in different situations and neither implies the other: a
    /// daemon whose tree has ballooned to eighteen gigabytes on a host with a
    /// hundred spare is inside every host bar and still the thing that is about
    /// to die, and a daemon holding a modest amount on a machine somebody else
    /// has filled is inside its budget and still must not start.
    ///
    /// So the worse rung wins, and the sentence names the one that produced
    /// it. Reporting the wrong constraint would send the reader to add memory
    /// when the fix is to let a sweep finish, or the other way round.
    pub fn decide(
        work: HeavyWork,
        pressure: &MemoryPressure,
        standing: Option<&BudgetStanding>,
        thresholds: &Thresholds,
    ) -> Self {
        let host_level = pressure.level_under(thresholds);
        let budget_level = standing.map(|standing| standing.level_under(thresholds));
        // `Unknown` is the lowest rung and can never win this comparison, which
        // is what keeps an unreadable host from overriding a budget that was
        // measured, and an unmeasurable tree from overriding a host that was.
        let level = budget_level.map_or(host_level, |budget| host_level.max(budget));
        let by_budget = budget_level == Some(level) && level > host_level;
        let did = match level {
            PressureLevel::Elevated => "runs in smaller batches",
            _ => "did not start",
        };
        let reason = || {
            if by_budget {
                describe_budget(
                    work,
                    standing.expect("a budget level implies a standing"),
                    did,
                )
            } else {
                describe(work, level, pressure.reading(), did)
            }
        };
        // Admission is measured and never refused, at any rung. See
        // [`HeavyWork::AmbientAdmission`] for why holding it is a different
        // trade from holding the two passes that actually spend the machine.
        if work == HeavyWork::AmbientAdmission {
            return Verdict::Proceed;
        }
        match level {
            PressureLevel::Unknown | PressureLevel::Nominal => Verdict::Proceed,
            PressureLevel::Elevated => match work {
                HeavyWork::EmbedBatch => Verdict::Shrink { reason: reason() },
                HeavyWork::LspSweep => Verdict::Proceed,
                HeavyWork::AmbientAdmission => unreachable!("returned above"),
            },
            PressureLevel::Critical => Verdict::Refuse { reason: reason() },
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

/// The disclosure sentence when it was this daemon's own budget that bit, in
/// the same register and with the children named.
fn describe_budget(work: HeavyWork, standing: &BudgetStanding, did: &'static str) -> String {
    format!(
        "{}, so {} {}. {}.",
        standing.sentence(),
        work.label(),
        did,
        work.consequence()
    )
}

/// What the reader can do about a budget the daemon has reached.
///
/// Different advice from [`PRESSURE_REMEDY`] on purpose. A machine with no room
/// is the user's to fix; a daemon that has outgrown its own budget is Kin's,
/// and the honest thing to say is what the number is and how to move it, not to
/// send someone out to buy memory they already have.
pub const BUDGET_REMEDY: &str =
    "This is Kin's own limit on itself, not the machine running out. Restarting the daemon \
     releases what it holds, and KIN_DAEMON_MEMORY_BUDGET_BYTES raises the limit if this \
     repository genuinely needs more.";

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

/// The memory ceiling this process runs under, measured, whatever
/// [`PRESSURE_OVERRIDE_ENV`] is pinned to.
///
/// The pin says how much pressure to act as though there is. It says nothing
/// about how large the machine is, and the two are different facts: a budget
/// derived from the ceiling is derived from a measurement, and pinning a level
/// must not silently delete it. Without this, forcing any level left a daemon
/// with no derived budget at all, which is a lever that quietly turns off a
/// guard rather than exercising it.
///
/// `None` when the machine could not be read, which leaves the derived budget
/// absent for the same reason every other unknown leaves work alone. An
/// operator budget does not consult this at all and stands on its own.
pub fn ceiling_bytes() -> Option<u64> {
    probe().reading().map(|reading| reading.limit_bytes)
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
        return Err(format!(
            "host_statistics64(HOST_VM_INFO64) returned {status}"
        ));
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

/// File a daemon publishes its current footprint standing into.
pub const FOOTPRINT_RECORD_FILE_NAME: &str = "daemon-footprint";

/// Where `kin_root` keeps it.
pub fn footprint_record_path(kin_root: &Path) -> PathBuf {
    kin_root.join(FOOTPRINT_RECORD_FILE_NAME)
}

/// How old a published standing may be before a surface stops calling it
/// current.
///
/// The daemon republishes on a slower cadence than it samples, so a reader can
/// always find a recent standing without the daemon writing a file every
/// second. Past this age the number is still printed and is labelled as the
/// last one published, because a standing from two minutes ago is a fact about
/// this daemon and a blank line is not.
pub const FOOTPRINT_RECORD_FRESH_FOR_SECS: u64 = 90;

/// What this repository's daemon last published about what it is holding.
///
/// Durable for the reason a refusal is: the process that measures is a daemon
/// nobody is watching, and every surface that reports it runs later and in
/// another process. `kin status` reads this rather than asking the daemon,
/// which keeps the status wire contract unchanged and lets the line appear even
/// when the daemon has since gone.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DaemonFootprint {
    /// What the tree held when this was published.
    pub footprint: TreeFootprint,
    /// What it was allowed to hold, in bytes.
    pub budget_bytes: u64,
    /// Whether that number was derived or named by an operator.
    pub budget_is_derived: bool,
    /// The rung it sat at.
    pub level: String,
    /// The pid that published it, so a reader can tell one daemon's record from
    /// its successor's.
    pub pid: u32,
    /// When it was published, in unix seconds.
    pub at_unix: u64,
}

impl DaemonFootprint {
    /// Publish this standing for this store.
    pub fn record(kin_root: &Path, standing: &BudgetStanding, level: PressureLevel, pid: u32) {
        let record = Self {
            footprint: standing.footprint,
            budget_bytes: standing.budget.bytes,
            budget_is_derived: standing.budget.source == BudgetSource::Derived,
            level: level.as_str().to_string(),
            pid,
            at_unix: unix_now(),
        };
        if let Ok(body) = serde_json::to_vec(&record) {
            let _ = std::fs::write(footprint_record_path(kin_root), body);
        }
    }

    /// What this store records, or `None` when it records nothing readable.
    pub fn read(kin_root: &Path) -> Option<Self> {
        let raw = std::fs::read(footprint_record_path(kin_root)).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Retire the record, because the daemon that published it is going away.
    pub fn clear(kin_root: &Path) {
        let _ = std::fs::remove_file(footprint_record_path(kin_root));
    }

    /// How old this reading is, in seconds, against a clock the caller supplies.
    ///
    /// Saturating rather than signed: a record stamped in the future is a clock
    /// that moved, not a reading from the future, and reporting a negative age
    /// would be the strangest line on the page.
    pub fn age_secs(&self, now_unix: u64) -> u64 {
        now_unix.saturating_sub(self.at_unix)
    }

    /// The standing as one line, labelled with its age when it is no longer
    /// current.
    pub fn line(&self, now_unix: u64) -> String {
        let age = self.age_secs(now_unix);
        let standing = BudgetStanding {
            footprint: self.footprint,
            budget: FootprintBudget {
                bytes: self.budget_bytes,
                source: if self.budget_is_derived {
                    BudgetSource::Derived
                } else {
                    BudgetSource::Operator
                },
            },
        };
        if age <= FOOTPRINT_RECORD_FRESH_FOR_SECS {
            standing.sentence()
        } else {
            format!(
                "{} (last published {age}s ago, by pid {})",
                standing.sentence(),
                self.pid
            )
        }
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
        assert_eq!(
            Thresholds::default().level_for(&reading(0, 0)),
            PressureLevel::Nominal
        );
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
        assert_eq!(
            unknown.level_under(&Thresholds::default()),
            PressureLevel::Unknown
        );
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
        assert_eq!(unknown.unknown_reason().is_some(), true);
    }

    /// Admission is measured and never refused, at any rung.
    ///
    /// It was refused when this seam landed and that was FIR-2632's sibling
    /// half: on a machine that stays loaded the tick that would admit never
    /// comes, so a file somebody wrote stops being queryable for as long as
    /// their machine is busy. The model says so here, so it cannot drift from
    /// the loop that obeys it.
    #[test]
    fn ambient_admission_is_never_refused_at_any_rung() {
        let bars = Thresholds::default();
        for pressure in [
            MemoryPressure::Known(reading(12 * GIB, GIB)),
            MemoryPressure::Known(reading(12 * GIB, 9 * GIB + GIB / 2)),
            MemoryPressure::Known(reading(12 * GIB, 11 * GIB + GIB / 2)),
            MemoryPressure::Forced {
                level: PressureLevel::Critical,
            },
        ] {
            assert_eq!(
                Verdict::for_reading(HeavyWork::AmbientAdmission, &pressure, &bars),
                Verdict::Proceed,
                "a written file must not stop being queryable because the machine is busy"
            );
        }
        // Including when this daemon's own tree is far over its budget.
        let over = standing(32 * GIB, 0, 0, 8 * GIB);
        assert_eq!(
            Verdict::decide(
                HeavyWork::AmbientAdmission,
                &MemoryPressure::Known(reading(128 * GIB, 8 * GIB)),
                Some(&over),
                &bars
            ),
            Verdict::Proceed
        );
    }

    #[test]
    fn critical_pressure_refuses_every_heavy_work_with_a_named_reason() {
        let pressure = MemoryPressure::Known(reading(12 * GIB, 11 * GIB + GIB / 2));
        for work in [HeavyWork::LspSweep, HeavyWork::EmbedBatch] {
            let verdict = Verdict::for_reading(work, &pressure, &Thresholds::default());
            assert!(
                verdict.refused(),
                "{work:?} must not start under critical pressure"
            );
            let reason = verdict.reason().expect("a refusal carries its reason");
            assert!(
                reason.contains("critical")
                    && reason.contains("11.5 GiB")
                    && reason.contains("12.0 GiB"),
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
            !silent
                .reason()
                .expect("refused")
                .contains("out-of-memory kill"),
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
        let verdict = Verdict::for_reading(HeavyWork::LspSweep, &forced, &Thresholds::default());
        let reason = verdict.reason().expect("a refusal carries its reason");
        assert!(
            reason.contains("KIN_MEMORY_PRESSURE pins it there"),
            "{reason}"
        );
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

    // ---- the per-daemon footprint budget ---------------------------------

    const MIB: u64 = 1024 * 1024;

    /// FIR-2653. A tree cannot hold more than its cgroup is charged.
    ///
    /// The measured numbers, so the assertion is about the run that produced
    /// the ticket rather than about a shape: 25.3 GiB claimed inside a 12 GiB
    /// container whose kernel charge at the time was roughly 2 GiB.
    #[test]
    fn a_reading_above_what_the_kernel_charges_the_container_is_held_to_it() {
        const CHARGED: u64 = 2 * GIB + GIB / 8;
        let impossible = TreeFootprint {
            own_bytes: 2 * GIB + GIB / 5,
            children_bytes: 23 * GIB + GIB / 10,
            child_count: 13,
            kernel_capped: false,
        };
        assert!(
            impossible.total_bytes() > 25 * GIB,
            "the pre-fix reading is the input to this test"
        );
        let held = impossible.clamped_to(Some(CHARGED));
        assert_eq!(held.total_bytes(), CHARGED);
        assert!(
            held.kernel_capped,
            "a reading the kernel overrode has to say so"
        );
        assert_eq!(held.child_count, 13, "the children were still counted");
        assert!(
            held.children_bytes > held.own_bytes,
            "both halves are scaled by the same factor, so the children keep their share"
        );
        assert!(
            held.total_bytes() <= 12 * GIB,
            "and the figure printed beside a 12 GiB cap can never exceed it"
        );
    }

    /// The clamp is a ceiling, not the measurement.
    #[test]
    fn a_reading_inside_what_the_kernel_charges_is_left_exactly_as_measured() {
        let measured = TreeFootprint {
            own_bytes: 700 * 1024 * 1024,
            children_bytes: 54 * 1024 * 1024,
            child_count: 13,
            kernel_capped: false,
        };
        assert_eq!(measured.clamped_to(Some(2 * GIB)), measured);
        assert_eq!(
            measured.clamped_to(Some(measured.total_bytes())),
            measured,
            "equal is inside, so the ceiling does not fire on its own boundary"
        );
        // A host with no cgroup accounting has no such ceiling, and the reading
        // stands as measured rather than collapsing to zero.
        assert_eq!(measured.clamped_to(None), measured);
    }

    /// A clamped standing says so where a reader is already looking.
    #[test]
    fn the_standing_sentence_names_a_reading_the_kernel_held_down() {
        let mut held = standing(2 * GIB, 23 * GIB, 13, 6 * GIB);
        held.footprint = held.footprint.clamped_to(Some(2 * GIB));
        let sentence = held.sentence();
        assert!(
            sentence.contains("what the kernel charges this container"),
            "a clamped reading has to name itself: {sentence}"
        );
        // And an unclamped one carries no such clause, so the phrase means
        // something when it appears.
        let plain = standing(GIB, GIB, 2, 6 * GIB).sentence();
        assert!(
            !plain.contains("what the kernel charges"),
            "an unclamped standing must not claim a ceiling bit it: {plain}"
        );
    }

    fn standing(own: u64, children: u64, child_count: usize, budget: u64) -> BudgetStanding {
        BudgetStanding {
            footprint: TreeFootprint {
                own_bytes: own,
                children_bytes: children,
                child_count,
                kernel_capped: false,
            },
            budget: FootprintBudget {
                bytes: budget,
                source: BudgetSource::Derived,
            },
        }
    }

    /// The measured failure, in the numbers it actually had, asserted as the
    /// decision rather than as the rung.
    ///
    /// The sweep peaked at 18.2 GB while pyright held 1.93 GiB in a process of
    /// its own, and counting only the daemon is what made every surface blind
    /// to the second number. What the blindness costs is not a different label
    /// on a dial, it is a different answer to "may this sweep start": with the
    /// child counted the tree is over budget and the sweep is refused, and with
    /// the child dropped the identical moment is merely elevated, which lets a
    /// sweep run because a sweep has no smaller size. Reverting this to a
    /// per-pid reading restores exactly the run that died.
    #[test]
    fn the_language_server_child_is_counted_and_is_what_refuses_the_sweep() {
        let bars = Thresholds::default();
        let budget = 8 * GIB;
        let roomy_host = MemoryPressure::Known(reading(128 * GIB, 8 * GIB));

        let with_child = standing(6 * GIB + 512 * MIB, 1930 * MIB, 1, budget);
        assert!(
            with_child.used_fraction() > 1.0,
            "6.5 GiB of daemon plus 1.93 GiB of pyright is over an 8 GiB budget"
        );
        assert_eq!(with_child.level_under(&bars), PressureLevel::Critical);
        assert!(
            Verdict::decide(HeavyWork::LspSweep, &roomy_host, Some(&with_child), &bars).refused(),
            "the tree is over its budget, so the pass that killed the daemon does not start"
        );

        // The per-pid view of the identical moment, which is the blindness this
        // is built to end.
        let per_pid_only = standing(6 * GIB + 512 * MIB, 0, 0, budget);
        assert_eq!(
            per_pid_only.level_under(&bars),
            PressureLevel::Elevated,
            "the daemon alone is inside the budget it is about to blow through"
        );
        assert_eq!(
            Verdict::decide(HeavyWork::LspSweep, &roomy_host, Some(&per_pid_only), &bars),
            Verdict::Proceed,
            "counting only the daemon lets the sweep start, which is how the daemon died"
        );
    }

    #[test]
    fn the_sentence_names_the_children_even_when_there_are_none() {
        // A reader who cannot see a child line cannot tell a daemon with no
        // language servers from a reading that never looked for them.
        let quiet = standing(2 * GIB, 0, 0, 8 * GIB);
        let sentence = quiet.sentence();
        assert!(
            sentence.contains("the 0 process(es) it started"),
            "{sentence}"
        );
        assert!(
            sentence.contains("of which 0 MiB is in those child processes"),
            "{sentence}"
        );
    }

    #[test]
    fn pinning_a_level_does_not_delete_the_measured_ceiling() {
        // The pin says how much pressure to act as though there is, not how
        // large the machine is. A lever that quietly turned off the budget
        // would exercise nothing and hide a guard.
        let _guard = crate::test_env::EnvVarGuard::set(PRESSURE_OVERRIDE_ENV, "nominal");
        assert!(
            matches!(read(), MemoryPressure::Forced { .. }),
            "the pin is in force"
        );
        assert!(read().reading().is_none(), "and it carries no figures");
        match ceiling_bytes() {
            Some(ceiling) => assert!(ceiling > 0, "a measured ceiling is a real size"),
            // A host this process cannot read has no ceiling to report, which
            // is the same absence every other unknown produces.
            None => assert!(matches!(probe(), MemoryPressure::Unknown { .. })),
        }
    }

    #[test]
    fn a_derived_budget_is_half_the_ceiling_between_its_floor_and_its_cap() {
        assert_eq!(FootprintBudget::derived_from(12 * GIB), 6 * GIB);
        // The case the cap exists for: half of a 128 GiB host is 64 GiB, which
        // would have allowed the 18.2 GB sweep without a murmur.
        assert_eq!(
            FootprintBudget::derived_from(128 * GIB),
            DERIVED_BUDGET_CEILING_BYTES
        );
        // And the case the floor exists for: a daemon on a 1 GiB container
        // must still be allowed to do something.
        assert_eq!(
            FootprintBudget::derived_from(512 * MIB),
            DERIVED_BUDGET_FLOOR_BYTES
        );
    }

    #[test]
    fn a_budget_of_zero_reads_as_no_pressure_rather_than_total_pressure() {
        // Same asymmetry the zero ceiling gets: a number nobody set must not
        // refuse every piece of work on the machine.
        let impossible = standing(GIB, 0, 0, 0);
        assert_eq!(impossible.used_fraction(), 0.0);
        assert_eq!(
            impossible.level_under(&Thresholds::default()),
            PressureLevel::Nominal
        );
    }

    #[test]
    fn an_overrun_is_reported_past_one_rather_than_clamped() {
        // A surface reporting 100% for both a small overrun and a fourfold one
        // would hide the difference that matters.
        let quadruple = standing(32 * GIB, 0, 0, 8 * GIB);
        assert_eq!(quadruple.used_fraction(), 4.0);
    }

    #[test]
    fn the_worse_of_the_two_constraints_wins_and_the_sentence_names_it() {
        let bars = Thresholds::default();
        // A machine with room, a daemon that has outgrown its budget. Every
        // host bar is clear and this is still the thing about to die.
        let roomy = MemoryPressure::Known(reading(128 * GIB, 8 * GIB));
        let over = standing(6 * GIB, 3 * GIB, 2, 8 * GIB);
        let verdict = Verdict::decide(HeavyWork::LspSweep, &roomy, Some(&over), &bars);
        let reason = verdict.reason().expect("refused");
        assert!(verdict.refused());
        assert!(
            reason.contains("it is allowed") && reason.contains("child processes"),
            "the budget is what bit, so the budget is what the sentence names: {reason}"
        );
        assert!(
            !reason.contains("host memory pressure"),
            "sending the reader to add memory they already have: {reason}"
        );

        // The reverse: a daemon well inside its budget on a machine somebody
        // else has filled.
        let full = MemoryPressure::Known(reading(12 * GIB, 11 * GIB + GIB / 2));
        let small = standing(512 * MIB, 0, 0, 6 * GIB);
        let verdict = Verdict::decide(HeavyWork::LspSweep, &full, Some(&small), &bars);
        let reason = verdict.reason().expect("refused");
        assert!(
            reason.contains("host memory pressure is critical"),
            "the host is what bit: {reason}"
        );
        assert!(!reason.contains("it is allowed"), "{reason}");
    }

    #[test]
    fn an_unmeasurable_tree_leaves_the_host_verdict_exactly_as_it_was() {
        // Absence of evidence again, on the second axis. A daemon that could
        // not read its own process table must behave as it did before P2.
        let bars = Thresholds::default();
        for pressure in [
            MemoryPressure::Known(reading(12 * GIB, GIB)),
            MemoryPressure::Known(reading(12 * GIB, 11 * GIB + GIB / 2)),
            MemoryPressure::Unknown {
                reason: "unreadable".to_string(),
            },
        ] {
            assert_eq!(
                Verdict::decide(HeavyWork::LspSweep, &pressure, None, &bars),
                Verdict::for_reading(HeavyWork::LspSweep, &pressure, &bars),
            );
        }
    }

    #[test]
    fn a_measured_budget_is_not_overridden_by_an_unreadable_host() {
        // `Unknown` is the lowest rung and must never win the comparison, or an
        // unreadable host would silence a budget that was measured.
        let bars = Thresholds::default();
        let unknown = MemoryPressure::Unknown {
            reason: "unreadable".to_string(),
        };
        let over = standing(9 * GIB, 0, 0, 8 * GIB);
        let verdict = Verdict::decide(HeavyWork::LspSweep, &unknown, Some(&over), &bars);
        assert!(verdict.refused(), "a measured overrun still refuses");
    }

    #[test]
    fn an_operator_budget_wins_outright_and_is_not_clamped() {
        let _guard = crate::test_env::EnvVarGuard::set(FOOTPRINT_BUDGET_ENV, "17179869184");
        let resolved = FootprintBudget::resolve(Some(12 * GIB)).expect("a budget");
        assert_eq!(resolved.bytes, 16 * GIB);
        assert_eq!(resolved.source, BudgetSource::Operator);
    }

    #[test]
    fn a_budget_of_zero_or_junk_is_ignored_rather_than_obeyed() {
        // A budget of zero refuses everything forever, which is the one value
        // an operator cannot have meant.
        for raw in ["0", "not-a-number", ""] {
            let _guard = crate::test_env::EnvVarGuard::set(FOOTPRINT_BUDGET_ENV, raw);
            let resolved = FootprintBudget::resolve(Some(12 * GIB)).expect("a budget");
            assert_eq!(resolved.bytes, 6 * GIB, "raw {raw:?} should be ignored");
            assert_eq!(resolved.source, BudgetSource::Derived);
        }
    }

    #[test]
    fn a_published_standing_survives_a_round_trip_and_ages() {
        let dir = tempfile::tempdir().expect("a temp dir");
        assert!(DaemonFootprint::read(dir.path()).is_none());
        let over = standing(6 * GIB, 1930 * MIB, 1, 8 * GIB);
        DaemonFootprint::record(dir.path(), &over, PressureLevel::Critical, 4103);
        let published = DaemonFootprint::read(dir.path()).expect("a published standing");
        assert_eq!(published.footprint.child_count, 1);
        assert_eq!(published.budget_bytes, 8 * GIB);
        assert!(published.budget_is_derived);

        // Fresh reads as itself; stale says how old it is and whose it was.
        let fresh = published.line(published.at_unix + 10);
        assert!(!fresh.contains("last published"), "{fresh}");
        let stale = published.line(published.at_unix + FOOTPRINT_RECORD_FRESH_FOR_SECS + 60);
        assert!(
            stale.contains("last published") && stale.contains("pid 4103"),
            "{stale}"
        );

        DaemonFootprint::clear(dir.path());
        assert!(DaemonFootprint::read(dir.path()).is_none());
    }

    #[test]
    fn a_record_stamped_in_the_future_ages_to_zero_rather_than_backwards() {
        let over = standing(GIB, 0, 0, 8 * GIB);
        let record = DaemonFootprint {
            footprint: over.footprint,
            budget_bytes: over.budget.bytes,
            budget_is_derived: true,
            level: "nominal".to_string(),
            pid: 1,
            at_unix: 5_000,
        };
        assert_eq!(
            record.age_secs(4_000),
            0,
            "a clock that moved is not a reading from the future"
        );
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
                assert!(
                    (0.0..=1.0).contains(&fraction),
                    "fraction {fraction} out of range"
                );
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
