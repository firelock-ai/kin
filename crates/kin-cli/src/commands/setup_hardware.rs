// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The hardware check `kin setup` opens with, and the resource profile it
//! recommends from what it found.
//!
//! Setup is the one moment a person is present and the one moment Kin knows
//! what this host can actually run, so it is where the machine's resource
//! profile is decided. Before this, the profile was chosen by
//! [`crate::resource_profile::apply_product_default`] alone: every machine got
//! `interactive`, nobody was told, and the only way to see the reasoning was to
//! run `kin resources inspect` after the fact and read an env var.
//!
//! Three properties this holds to:
//!
//! - **One detector.** Every number here comes from `kin_infer::resource`, the
//!   same detection the embedding budgets, the Metal submission depth and
//!   `kin resources inspect` are derived from. A second detector in setup would
//!   be a second answer to "what is this machine", and the two would drift.
//! - **The recommendation is what the binary already does.** Setup recommends
//!   `interactive` because that is the profile a kin binary selects for itself,
//!   and a setup that recommended something else would be making a performance
//!   claim nobody measured on this host. What varies with the hardware is the
//!   reason, and whether `throughput` is named as an upgrade the machine can
//!   actually use.
//! - **Nothing is recorded unless someone chose it.** Accepting the
//!   recommendation writes no file, so the fast path stays a print. Only an
//!   adjustment is recorded, and re-selecting the recommendation clears it, so
//!   the record always means "a person chose this".

use std::path::Path;

use kin_infer::resource::{
    AcceleratorBackend, AcceleratorInfo, HostInfo, MemoryInfo, Profile, ResourcePlan,
};

use super::byte_fmt::human_bytes;

/// The unified-memory floor at which `throughput` actually scales the embedding
/// batch budgets.
///
/// Not a round number picked for the prompt: `unified_throughput_scale` in
/// `kin_infer::resource` returns 1 below 32 GiB, so under this figure the
/// profile costs citability and buys no batch budget at all. Naming the exact
/// threshold is what lets the upgrade line be checked rather than believed.
const THROUGHPUT_UNIFIED_MEMORY_FLOOR: u64 = 32 * 1024 * 1024 * 1024;

/// The warning the advanced adjustment carries, in the words the founder asked
/// for: a value beyond the real machine is not merely slower.
pub(crate) const ADVANCED_PROFILE_WARNING: &str =
    "A profile that budgets past what this machine actually has can exceed safe memory and \
     GPU thresholds and crash the machine. The detected figures above are the ceiling.";

/// What one detection pass found, kept as the raw facts rather than a rendered
/// string so the sentence, the detail lines and the recommendation are all
/// derived from the same values.
#[derive(Debug, Clone)]
pub(crate) struct DetectedHardware {
    pub(crate) host: HostInfo,
    pub(crate) memory: MemoryInfo,
    pub(crate) accelerator: AcceleratorInfo,
    /// Apple-silicon `gpu-core-count`, when the host reports one.
    pub(crate) gpu_core_count: Option<usize>,
}

impl DetectedHardware {
    /// Detect this machine through `kin_infer`'s own plan.
    ///
    /// [`ResourcePlan::detect`] is the only entry point that also fills
    /// `gpu_core_count`, so it is called rather than the three public detectors
    /// separately. The profile passed in only shapes the budget fields, which
    /// this struct does not carry: every field read here is raw detection, and
    /// `host.rayon_threads` / `host.reserve_logical_cores` / `blas_threads` are
    /// deliberately not reported by [`Self::detail_lines`] because those are
    /// derived from the profile rather than from the machine.
    pub(crate) fn detect() -> Self {
        let plan = ResourcePlan::detect(Profile::Interactive);
        Self {
            host: plan.host,
            memory: plan.memory,
            accelerator: plan.accelerator,
            gpu_core_count: plan.gpu_core_count,
        }
    }

    /// Whether this host has a real accelerator rather than the CPU fallback.
    fn has_accelerator(&self) -> bool {
        matches!(
            self.accelerator.backend,
            AcceleratorBackend::Metal | AcceleratorBackend::Cuda
        )
    }

    /// The memory figure every budget in `kin_infer::resource` keys off. A
    /// container cap is already folded into it by the detector, so this is the
    /// memory Kin can actually plan against, not the host's sticker figure.
    fn effective_memory_bytes(&self) -> Option<u64> {
        self.memory.system_total_bytes
    }
}

/// Render the accelerator the way the rest of the product spells it.
fn accelerator_name(backend: AcceleratorBackend) -> &'static str {
    match backend {
        AcceleratorBackend::Metal => "Metal",
        AcceleratorBackend::Cuda => "CUDA",
        AcceleratorBackend::Cpu => "CPU",
        AcceleratorBackend::Auto => "auto",
    }
}

/// The canonical spelling of a profile, matching `kin resources` and the
/// `KIN_RESOURCE_PROFILE` registry entry.
pub(crate) fn profile_name(profile: Profile) -> &'static str {
    match profile {
        Profile::Proof => "proof",
        Profile::Interactive => "interactive",
        Profile::Throughput => "throughput",
        Profile::Ci => "ci",
    }
}

/// Parse a profile name the way `kin resources set` does, so a `--resource-profile`
/// flag and that command cannot accept different spellings.
pub(crate) fn parse_profile_name(raw: &str) -> Option<Profile> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "proof" => Some(Profile::Proof),
        "interactive" => Some(Profile::Interactive),
        "throughput" => Some(Profile::Throughput),
        "ci" => Some(Profile::Ci),
        _ => None,
    }
}

/// The CPU half of the detection sentence.
fn cpu_phrase(host: &HostInfo) -> String {
    let logical = host.logical_cores;
    let mut phrase = match host.physical_cores {
        Some(physical) if physical != logical => {
            format!("{physical} physical cores ({logical} logical)")
        }
        Some(physical) => format!("{physical} cores"),
        None => format!("{logical} logical cores"),
    };
    if let (Some(performance), Some(efficiency)) = (host.performance_cores, host.efficiency_cores) {
        phrase.push_str(&format!(
            ", {performance} performance and {efficiency} efficiency"
        ));
    }
    phrase
}

/// The accelerator half of the detection sentence.
fn accelerator_phrase(hardware: &DetectedHardware) -> String {
    let name = accelerator_name(hardware.accelerator.backend);
    if !hardware.has_accelerator() {
        return "no GPU accelerator, so embedding runs on the CPU".to_string();
    }
    let mut phrase = format!("a {name} accelerator");
    if let Some(cores) = hardware.gpu_core_count {
        phrase.push_str(&format!(" with {cores} GPU cores"));
    }
    if hardware.accelerator.unified_memory {
        phrase.push_str(" sharing unified memory with the CPU");
    } else if let Some(bytes) = hardware.accelerator.device_total_bytes {
        phrase.push_str(&format!(" with {} of its own memory", human_bytes(bytes)));
    }
    phrase
}

/// The one sentence the hardware check leads with.
///
/// Deliberately a sentence rather than a table. It is the first thing a
/// stranger reads, it has to be true on a machine with no GPU and on one with
/// four of them, and every clause in it names something a reader can check
/// against their own machine.
pub(crate) fn detected_sentence(hardware: &DetectedHardware) -> String {
    // The whole clause, not just the figure. An unknown total has to read as
    // unknown rather than as a zero, and splicing a bare figure into a fixed
    // "{} of memory" is what produced "an unreported amount of of memory".
    let memory = match hardware.effective_memory_bytes() {
        Some(bytes) => format!("{} of memory", human_bytes(bytes)),
        None => "an unreported amount of memory".to_string(),
    };
    format!(
        "We detected your hardware to be {} with {}, {memory}, and {}.",
        hardware.host.arch,
        cpu_phrase(&hardware.host),
        accelerator_phrase(hardware)
    )
}

/// The detail lines under the sentence, one fact per line.
///
/// Only raw detection appears here. The numbers a profile derives (rayon
/// threads, reserved cores, batch budgets) belong to `kin resources inspect`,
/// which reports them for the profile actually in effect in the process that is
/// doing the work; restating a guess at them here would be a second answer.
pub(crate) fn detail_lines(hardware: &DetectedHardware) -> Vec<String> {
    let mut lines = vec![format!("Architecture: {}", hardware.host.arch)];
    lines.push(format!("CPU: {}", cpu_phrase(&hardware.host)));
    lines.push(match hardware.effective_memory_bytes() {
        Some(bytes) => format!("Memory: {}", human_bytes(bytes)),
        None => "Memory: not reported by this host".to_string(),
    });
    lines.push(format!(
        "Accelerator: {}",
        accelerator_name(hardware.accelerator.backend)
    ));
    if let Some(cores) = hardware.gpu_core_count {
        lines.push(format!("GPU cores: {cores}"));
    }
    if hardware.has_accelerator() {
        lines.push(format!(
            "Unified memory: {}",
            if hardware.accelerator.unified_memory {
                "yes"
            } else {
                "no"
            }
        ));
        if let Some(bytes) = hardware.accelerator.recommended_working_set_bytes {
            lines.push(format!(
                "Recommended GPU working set: {}",
                human_bytes(bytes)
            ));
        } else if let Some(bytes) = hardware.accelerator.device_total_bytes {
            lines.push(format!("Device memory: {}", human_bytes(bytes)));
        }
    }
    lines
}

/// What setup recommends for this machine, why, and what else the hardware
/// makes available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileRecommendation {
    /// The profile setup recommends and pre-selects.
    pub(crate) profile: Profile,
    /// Why, stated from the facts that were actually detected.
    pub(crate) reason: String,
    /// A profile this hardware can genuinely use that setup still does not
    /// recommend, with what it buys and what it costs. `None` when the machine
    /// would gain nothing from one.
    pub(crate) upgrade: Option<String>,
}

/// Map detected hardware to the profile setup recommends.
///
/// The profile is always `interactive`, and that is the point rather than a
/// placeholder: it is what `apply_product_default` already selects, so
/// accepting the recommendation changes nothing and needs no file. What the
/// hardware decides is the reason and the upgrade, and both are checkable
/// statements about this machine.
pub(crate) fn recommend_profile(hardware: &DetectedHardware) -> ProfileRecommendation {
    let logical = hardware.host.logical_cores.max(1);
    // The same expression `ResourcePlan::for_profile` uses for the interactive
    // arm, rather than a restatement of it. A sentence that described a core
    // split the plan does not actually apply would be worse than no sentence:
    // it is checkable, and it would be wrong.
    let reserve = (logical / 4).clamp(2, 4);
    let working = logical.saturating_sub(reserve).max(1);
    let reason = if hardware.has_accelerator() {
        format!(
            "it keeps the value-preserving {} kernels and a bounded submission depth, and runs \
             Kin's own work on {working} of {logical} cores so the machine stays responsive while \
             Kin works",
            accelerator_name(hardware.accelerator.backend)
        )
    } else {
        format!(
            "there is no accelerator to schedule against, so it runs the same embedding budgets \
             on the CPU and runs Kin's own work on {working} of {logical} cores so the machine \
             stays responsive while Kin works"
        )
    };

    let unified = hardware.accelerator.unified_memory
        && hardware.accelerator.backend == AcceleratorBackend::Metal;
    let memory = hardware.effective_memory_bytes();
    let upgrade = match (unified, memory) {
        (true, Some(bytes)) if bytes >= THROUGHPUT_UNIFIED_MEMORY_FLOOR => Some(format!(
            "throughput would scale the embedding batch budgets with this machine's {} of unified \
             memory and engage the CPU twin. It stays opt-in because it also overlaps a batch's \
             persist with the next batch's compute, which changes the order vectors are written \
             in, so its results are not citable.",
            human_bytes(bytes)
        )),
        (true, Some(bytes)) => Some(format!(
            "throughput would not raise the batch budgets on this machine: they scale with \
             unified memory from {}, and this host has {}.",
            human_bytes(THROUGHPUT_UNIFIED_MEMORY_FLOOR),
            human_bytes(bytes)
        )),
        _ => None,
    };

    ProfileRecommendation {
        profile: Profile::Interactive,
        reason,
        upgrade,
    }
}

/// Every profile the advanced adjustment offers, in menu order, each with what
/// it actually does. The recommendation is first so one keypress accepts it.
pub(crate) fn profile_choices(recommended: Profile) -> Vec<(Profile, String)> {
    let described = |profile: Profile| -> String {
        let body = match profile {
            Profile::Interactive => {
                "value-preserving GPU kernels, proof's embedding budgets, and a quarter of the \
                 cores left free"
            }
            Profile::Throughput => {
                "scales the batch budgets with unified memory and overlaps persist with compute; \
                 results are not citable"
            }
            Profile::Proof => {
                "the smallest budgets and a bit-identical configuration; what a citable benchmark \
                 wants"
            }
            Profile::Ci => {
                "four rayon threads and a 4096-token batch; sized for a shared build runner, not \
                 a workstation"
            }
        };
        // The note only. The caller pairs it with `profile_name`, and returning
        // the name here too rendered every menu row with the profile printed
        // twice.
        if profile == recommended {
            format!("recommended: {body}")
        } else {
            body.to_string()
        }
    };
    let mut ordered = vec![recommended];
    for profile in [
        Profile::Interactive,
        Profile::Throughput,
        Profile::Proof,
        Profile::Ci,
    ] {
        if profile != recommended {
            ordered.push(profile);
        }
    }
    ordered
        .into_iter()
        .map(|profile| (profile, described(profile)))
        .collect()
}

// ---------------------------------------------------------------------------
// The recorded machine profile, in `~/.kin/config/setup.toml`
// ---------------------------------------------------------------------------

/// The `setup.toml` table and key the machine profile is recorded under.
///
/// `[resources] profile` deliberately matches the shape a repository's
/// `.kin/config.toml` uses for the same setting, so an operator reading either
/// file finds the same name for the same thing.
pub(crate) const PROFILE_TABLE: &str = "resources";
pub(crate) const PROFILE_KEY: &str = "profile";

/// The profile recorded for this machine, if a person chose one.
pub(crate) fn recorded_profile(kin_home: &Path) -> Option<String> {
    super::projection::recorded_setup_value(kin_home, PROFILE_TABLE, PROFILE_KEY)
}

/// Record the machine profile a person chose, or clear the record when they
/// chose the recommendation.
///
/// Clearing writes an empty value rather than removing the key, which
/// [`recorded_setup_value`] reads back as nothing recorded. That is the undo
/// path: re-running the wizard and taking the recommendation has to be able to
/// put the machine back on kin's own default rather than leave an old pin in
/// place.
///
/// [`recorded_setup_value`]: super::projection::recorded_setup_value
pub(crate) fn record_profile(kin_home: &Path, profile: Option<Profile>) -> anyhow::Result<()> {
    super::projection::record_setup_value(
        kin_home,
        PROFILE_TABLE,
        PROFILE_KEY,
        profile.map(profile_name).unwrap_or(""),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn host(arch: &str, logical: usize, physical: Option<usize>) -> HostInfo {
        HostInfo {
            arch: arch.to_string(),
            logical_cores: logical,
            physical_cores: physical,
            performance_cores: None,
            efficiency_cores: None,
            rayon_threads: logical,
            reserve_logical_cores: 0,
            blas_threads: 1,
        }
    }

    fn memory(bytes: Option<u64>) -> MemoryInfo {
        MemoryInfo {
            system_total_bytes: bytes,
            system_available_bytes: None,
            max_process_rss_bytes: None,
            hot_graph_budget_bytes: None,
        }
    }

    fn accelerator(backend: AcceleratorBackend, unified: bool) -> AcceleratorInfo {
        AcceleratorInfo {
            backend,
            device_index: 0,
            unified_memory: unified,
            device_total_bytes: None,
            device_available_bytes: None,
            recommended_working_set_bytes: None,
            max_single_buffer_bytes: None,
            max_inflight_command_buffers: 1,
            reserve_device_bytes: None,
            allow_cpu_fallback: true,
        }
    }

    /// A 36 GiB Apple-silicon laptop, the machine most first runs happen on.
    fn apple_laptop() -> DetectedHardware {
        let mut host = host("aarch64", 12, Some(12));
        host.performance_cores = Some(8);
        host.efficiency_cores = Some(4);
        DetectedHardware {
            host,
            memory: memory(Some(36 * GIB)),
            accelerator: accelerator(AcceleratorBackend::Metal, true),
            gpu_core_count: Some(30),
        }
    }

    /// A CPU-only Linux box with no accelerator and no reported memory, which
    /// is what `detect_memory` returns off macOS with no cgroup limit.
    fn headless_linux() -> DetectedHardware {
        DetectedHardware {
            host: host("x86_64", 8, Some(4)),
            memory: memory(None),
            accelerator: accelerator(AcceleratorBackend::Cpu, false),
            gpu_core_count: None,
        }
    }

    /// The sentence names every fact it was given, and names it once.
    #[test]
    fn the_detected_sentence_reports_what_was_detected() {
        let sentence = detected_sentence(&apple_laptop());
        assert!(
            sentence.starts_with("We detected your hardware to be "),
            "the founder's opening words are the contract: {sentence:?}"
        );
        for fragment in [
            "aarch64",
            "12 cores",
            "8 performance and 4 efficiency",
            "36.0 GiB of memory",
            "Metal accelerator",
            "30 GPU cores",
            "unified memory",
        ] {
            assert!(
                sentence.contains(fragment),
                "{fragment:?} is detected but missing from {sentence:?}"
            );
        }
    }

    /// The half of the sentence that has to survive a machine with nothing
    /// interesting on it. A host that reports no memory and no GPU must still
    /// produce one true sentence rather than a hole or a zero.
    #[test]
    fn a_machine_with_no_accelerator_still_gets_a_true_sentence() {
        let sentence = detected_sentence(&headless_linux());
        assert!(sentence.contains("x86_64"), "{sentence:?}");
        assert!(
            sentence.contains("4 physical cores (8 logical)"),
            "a host whose logical count exceeds its physical one must say both: {sentence:?}"
        );
        assert!(
            sentence.contains("no GPU accelerator, so embedding runs on the CPU"),
            "{sentence:?}"
        );
        assert!(
            sentence.contains("an unreported amount of memory"),
            "an unknown memory total must read as unknown, never as 0 MiB: {sentence:?}"
        );
        assert!(
            !sentence.contains("0 MiB"),
            "an absent figure was rendered as a zero: {sentence:?}"
        );
    }

    /// Detail lines carry only detected facts. A profile-derived number here
    /// would be a second answer to a question `kin resources inspect` owns.
    #[test]
    fn detail_lines_report_detection_and_not_profile_budgets() {
        let lines = detail_lines(&apple_laptop()).join("\n");
        assert!(lines.contains("Architecture: aarch64"), "{lines}");
        assert!(lines.contains("Memory: 36.0 GiB"), "{lines}");
        assert!(lines.contains("Accelerator: Metal"), "{lines}");
        assert!(lines.contains("GPU cores: 30"), "{lines}");
        assert!(lines.contains("Unified memory: yes"), "{lines}");
        for derived in ["rayon", "batch", "max_seq_len", "reserve"] {
            assert!(
                !lines.to_ascii_lowercase().contains(derived),
                "{derived:?} is derived from the profile, not detected: {lines}"
            );
        }
    }

    /// A CPU-only host reports no GPU rows at all rather than empty ones.
    #[test]
    fn detail_lines_omit_gpu_rows_on_a_host_without_one() {
        let lines = detail_lines(&headless_linux()).join("\n");
        assert!(lines.contains("Accelerator: CPU"), "{lines}");
        assert!(!lines.contains("GPU cores"), "{lines}");
        assert!(!lines.contains("Unified memory"), "{lines}");
        assert!(
            lines.contains("Memory: not reported by this host"),
            "{lines}"
        );
    }

    /// The recommendation is the profile the binary already selects, on every
    /// machine. A setup that recommended something else would be making a
    /// performance claim nobody measured on this host.
    #[test]
    fn the_recommendation_is_the_profile_the_binary_already_selects() {
        for hardware in [apple_laptop(), headless_linux()] {
            let recommendation = recommend_profile(&hardware);
            assert_eq!(recommendation.profile, Profile::Interactive);
            assert_eq!(
                profile_name(recommendation.profile),
                crate::resource_profile::PRODUCT_DEFAULT_PROFILE,
                "accepting the recommendation must change nothing, so it has to name the ship \
                 default"
            );
        }
    }

    /// The reason varies with the hardware, because that is the half of the
    /// recommendation the machine actually decides.
    #[test]
    fn the_reason_names_the_accelerator_it_found() {
        let with_gpu = recommend_profile(&apple_laptop());
        assert!(with_gpu.reason.contains("Metal"), "{:?}", with_gpu.reason);
        let without = recommend_profile(&headless_linux());
        assert!(
            without
                .reason
                .contains("no accelerator to schedule against"),
            "{:?}",
            without.reason
        );
        assert!(
            !without.reason.contains("Metal"),
            "a CPU-only host must not be told about GPU kernels: {:?}",
            without.reason
        );
    }

    /// The upgrade line is the real mapping, and it turns on the exact figure
    /// `unified_throughput_scale` turns on. Both sides are asserted: one GiB
    /// under the floor the machine is told throughput buys it nothing, and at
    /// the floor it is told what it buys and what it costs.
    #[test]
    fn the_throughput_upgrade_tracks_the_budget_floor_in_both_directions() {
        let mut under = apple_laptop();
        under.memory = memory(Some(THROUGHPUT_UNIFIED_MEMORY_FLOOR - GIB));
        let under = recommend_profile(&under)
            .upgrade
            .expect("a unified-memory host is told where the floor is");
        assert!(
            under.contains("would not raise the batch budgets"),
            "{under:?}"
        );
        assert!(under.contains("32.0 GiB"), "the floor is named: {under:?}");

        let mut at_floor = apple_laptop();
        at_floor.memory = memory(Some(THROUGHPUT_UNIFIED_MEMORY_FLOOR));
        let at_floor = recommend_profile(&at_floor)
            .upgrade
            .expect("a host at the floor is offered the upgrade");
        assert!(
            at_floor.contains("would scale the embedding batch budgets"),
            "{at_floor:?}"
        );
        assert!(
            at_floor.contains("not citable"),
            "an upgrade offered without its cost is a recommendation, not an option: {at_floor:?}"
        );
    }

    /// A machine with no unified-memory accelerator is offered no upgrade at
    /// all, rather than one it cannot use.
    #[test]
    fn a_host_without_unified_memory_is_offered_no_upgrade() {
        assert!(recommend_profile(&headless_linux()).upgrade.is_none());
        let mut discrete = apple_laptop();
        discrete.accelerator = accelerator(AcceleratorBackend::Cuda, false);
        assert!(recommend_profile(&discrete).upgrade.is_none());
    }

    /// The menu leads with the recommendation so one keypress accepts it, and
    /// still offers every profile exactly once.
    #[test]
    fn the_profile_menu_leads_with_the_recommendation() {
        let choices = profile_choices(Profile::Interactive);
        assert_eq!(choices.len(), 4);
        assert_eq!(choices[0].0, Profile::Interactive);
        assert!(choices[0].1.contains("recommended:"), "{:?}", choices[0].1);
        let mut names: Vec<&str> = choices.iter().map(|(p, _)| profile_name(*p)).collect();
        names.sort_unstable();
        assert_eq!(names, ["ci", "interactive", "proof", "throughput"]);
        for (profile, line) in &choices[1..] {
            assert!(
                !line.contains("recommended:"),
                "{} is not the recommendation",
                profile_name(*profile)
            );
        }
        // The note does not lead with the profile name. The caller renders the
        // name beside it, and returning it here as well printed every menu row
        // with the profile spelled twice.
        for (profile, line) in &choices {
            assert!(
                !line.trim_start().starts_with(profile_name(*profile)),
                "the note for {} leads with its own name: {line:?}",
                profile_name(*profile)
            );
        }
    }

    /// Every name the menu offers is a name `kin resources set` accepts, or the
    /// wizard would record a profile the runtime rejects at the next start.
    #[test]
    fn every_offered_profile_name_round_trips_through_the_resources_parser() {
        for (profile, _) in profile_choices(Profile::Interactive) {
            let name = profile_name(profile);
            assert_eq!(parse_profile_name(name), Some(profile));
            assert_eq!(
                super::super::resources::parse_profile(Some(name)),
                Ok(profile),
                "{name} is offered by setup but rejected by `kin resources set`"
            );
        }
    }

    /// The warning the founder asked for says the consequence, not just that a
    /// value is large.
    #[test]
    fn the_advanced_warning_names_the_consequence() {
        assert!(ADVANCED_PROFILE_WARNING.contains("crash the machine"));
        assert!(ADVANCED_PROFILE_WARNING.contains("safe memory"));
    }

    /// A recorded adjustment survives a round trip, and re-selecting the
    /// recommendation clears it. The second half is the undo path: without it a
    /// profile chosen once could never be taken back from the wizard.
    #[test]
    fn a_recorded_profile_round_trips_and_clears() {
        let home = tempfile::tempdir().expect("tempdir");
        assert_eq!(recorded_profile(home.path()), None);

        record_profile(home.path(), Some(Profile::Throughput)).expect("record");
        assert_eq!(recorded_profile(home.path()).as_deref(), Some("throughput"));

        record_profile(home.path(), None).expect("clear");
        assert_eq!(
            recorded_profile(home.path()),
            None,
            "re-selecting the recommendation must clear the record, not pin the default"
        );
    }

    /// Recording the profile must not discard the other settings that share
    /// `setup.toml`. A rewrite here would silently un-configure the machine's
    /// projection mode and daemon auto-start, which is the exact defect
    /// `config_set` was made a read-modify-write for.
    #[test]
    fn recording_a_profile_preserves_the_rest_of_setup_toml() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = super::super::projection::setup_config_path(home.path());
        std::fs::create_dir_all(path.parent().expect("config dir")).expect("mkdir");
        std::fs::write(
            &path,
            "[daemon]\nauto_start = true\n\n[projection]\nmode = \"shim\"\n",
        )
        .expect("seed");

        record_profile(home.path(), Some(Profile::Ci)).expect("record");

        let body = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            super::super::projection::config_str(&body, "projection", "mode").as_deref(),
            Some("shim"),
            "the recorded projection mode was discarded: {body}"
        );
        assert!(
            body.contains("auto_start = true"),
            "the daemon setting was discarded: {body}"
        );
        assert_eq!(recorded_profile(home.path()).as_deref(), Some("ci"));
    }
}
