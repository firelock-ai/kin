// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Honest, machine-readable Git-replacement capability inventory.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const INVENTORY_JSON: &str =
    include_str!("../../tests/fixtures/git-replacement-capabilities-v1.json");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Ready,
    ReadyBounded,
    OpenGate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityExposure {
    Enabled,
    FailClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandCapability {
    pub command: String,
    pub status: CapabilityStatus,
    pub exposure: CapabilityExposure,
    pub authority: String,
    pub required_for_bounded_dogfood: bool,
    pub acceptance_spec: Vec<String>,
    #[serde(default)]
    pub evidence_tests: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityInventory {
    pub schema: String,
    pub substrate: String,
    pub commands: Vec<CommandCapability>,
}

#[derive(Debug, Serialize)]
struct CapabilityReport<'a> {
    schema: &'a str,
    substrate: &'a str,
    bounded_dogfood_ready: bool,
    bounded_dogfood_required_ready: usize,
    bounded_dogfood_required_total: usize,
    all_declared_command_surfaces_enabled: bool,
    enabled_commands: usize,
    full_git_replacement_ready: bool,
    ready_commands: usize,
    command_total: usize,
    commands: &'a [CommandCapability],
}

pub fn inventory() -> Result<CapabilityInventory> {
    serde_json::from_str(INVENTORY_JSON)
        .context("embedded Git-replacement capability inventory is invalid")
}

pub fn require_ready(command: &str) -> Result<()> {
    let inventory = inventory()?;
    let capability = inventory
        .commands
        .iter()
        .find(|capability| capability.command == command)
        .ok_or_else(|| {
            // An undeclared command cannot be satisfied by any repository
            // state, so this arm is reached only on a build whose command tree
            // and inventory disagree. It has to name the command and the one
            // thing a caller can do about it. The old wording named an internal
            // table nobody has seen and offered no remedy at all.
            anyhow::anyhow!(
                "`kin {}` is not available in this build\n\
                 hint: run `kin capabilities` to see which commands are ready",
                command
            )
        })?;
    if capability.status != CapabilityStatus::OpenGate
        && capability.exposure == CapabilityExposure::Enabled
    {
        return Ok(());
    }

    bail!(
        "`kin {}` is fail-closed on repository-v6: {}\nopen acceptance gates:\n  - {}\n\
         inspect the complete machine-readable matrix with `kin capabilities --json`",
        command,
        capability.note,
        capability.acceptance_spec.join("\n  - ")
    )
}

pub fn run(json: bool, verbose: bool) -> Result<()> {
    let inventory = inventory()?;
    let required = inventory
        .commands
        .iter()
        .filter(|capability| capability.required_for_bounded_dogfood)
        .collect::<Vec<_>>();
    let bounded_dogfood_required_ready = required
        .iter()
        .filter(|capability| {
            capability.status != CapabilityStatus::OpenGate
                && capability.exposure == CapabilityExposure::Enabled
        })
        .count();
    let ready_commands = inventory
        .commands
        .iter()
        .filter(|capability| {
            capability.status == CapabilityStatus::Ready
                && capability.exposure == CapabilityExposure::Enabled
        })
        .count();
    let enabled_commands = inventory
        .commands
        .iter()
        .filter(|capability| capability.exposure == CapabilityExposure::Enabled)
        .count();
    let report = CapabilityReport {
        schema: &inventory.schema,
        substrate: &inventory.substrate,
        bounded_dogfood_ready: bounded_dogfood_required_ready == required.len(),
        bounded_dogfood_required_ready,
        bounded_dogfood_required_total: required.len(),
        all_declared_command_surfaces_enabled: enabled_commands == inventory.commands.len(),
        enabled_commands,
        full_git_replacement_ready: ready_commands == inventory.commands.len(),
        ready_commands,
        command_total: inventory.commands.len(),
        commands: &inventory.commands,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("Kin repository-v6 command capabilities");
    println!(
        "Bounded dogfood ready: {} ({}/{})",
        if report.bounded_dogfood_ready {
            "yes"
        } else {
            "no"
        },
        report.bounded_dogfood_required_ready,
        report.bounded_dogfood_required_total
    );
    println!(
        "All declared command surfaces enabled: {} ({}/{})",
        if report.all_declared_command_surfaces_enabled {
            "yes"
        } else {
            "no"
        },
        report.enabled_commands,
        report.command_total
    );
    println!(
        "Fully general Git replacement ready: {} ({}/{} general)",
        if report.full_git_replacement_ready {
            "yes"
        } else {
            "no"
        },
        report.ready_commands,
        report.command_total
    );
    println!();
    for capability in report.commands {
        let status = match capability.status {
            CapabilityStatus::Ready => "READY",
            CapabilityStatus::ReadyBounded => "BOUND",
            CapabilityStatus::OpenGate => "OPEN ",
        };
        let dogfood = if capability.required_for_bounded_dogfood {
            "  required"
        } else {
            ""
        };
        // Root help sends every caller here to answer "what works", and status
        // against command name is that answer. Authority and note are prose,
        // several of them running past a terminal width and one past three
        // thousand characters on a single line, and printing them by default
        // buried the answer under 27KB.
        println!("{status}  {:18}{dogfood}", capability.command);
        if verbose {
            println!("       authority: {}", capability.authority);
            println!("       {}", capability.note);
        }
    }
    if !verbose {
        println!();
        println!("`--verbose` adds authority and notes per command, `--json` the full inventory.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_ready_capability_is_enabled_and_every_open_gate_fails_closed() {
        let inventory = inventory().unwrap();
        assert!(!inventory.commands.is_empty());
        for capability in inventory.commands {
            match capability.status {
                CapabilityStatus::Ready => {
                    assert_eq!(capability.exposure, CapabilityExposure::Enabled)
                }
                CapabilityStatus::ReadyBounded => {
                    assert_eq!(capability.exposure, CapabilityExposure::Enabled);
                    assert!(!capability.acceptance_spec.is_empty());
                    assert!(!capability.note.is_empty());
                }
                CapabilityStatus::OpenGate => {
                    assert_eq!(capability.exposure, CapabilityExposure::FailClosed);
                    assert!(!capability.acceptance_spec.is_empty());
                }
            }
        }
    }

    /// A command is only ready if the inventory names the tests that prove it.
    /// Flipping a gate without evidence is the failure this bars.
    #[test]
    fn every_ready_capability_names_the_evidence_that_proves_it() {
        for capability in inventory().unwrap().commands {
            if capability.status == CapabilityStatus::OpenGate {
                continue;
            }
            assert!(
                !capability.evidence_tests.is_empty(),
                "ready capability '{}' names no evidence test",
                capability.command
            );
            assert!(
                !capability.acceptance_spec.is_empty(),
                "ready capability '{}' states no acceptance spec",
                capability.command
            );
        }
    }

    /// The session cluster runs one process inside one exact projection, so it
    /// stands or falls together. If any of these regresses to a gate, the
    /// others are reporting a contract the surface no longer has.
    #[test]
    fn the_session_cluster_is_ready_on_the_session_projection_surface() {
        let inventory = inventory().unwrap();
        for command in ["exec", "open", "with", "shell"] {
            let capability = inventory
                .commands
                .iter()
                .find(|capability| capability.command == command)
                .unwrap_or_else(|| panic!("missing session capability {command}"));
            assert_eq!(
                capability.status,
                CapabilityStatus::Ready,
                "{command} must stay ready"
            );
            assert_eq!(capability.exposure, CapabilityExposure::Enabled);
            assert!(
                capability.authority.contains("session projection"),
                "{command} must declare the session projection as its authority: {}",
                capability.authority
            );
            assert!(
                require_ready(command).is_ok(),
                "{command} must no longer refuse at the CLI boundary"
            );
        }
    }

    /// Every command that gates itself on the inventory must be in it.
    ///
    /// An undeclared command takes the not-found arm, which no repository state
    /// can satisfy, so it is dead on every host rather than gated on one.
    /// `purge-ignored` shipped that way: a complete implementation, a daemon
    /// route, its own tests, and a root-help entry, refusing everywhere because
    /// nothing named it here. The gate tests could not see it, because they all
    /// start from the inventory and it was the inventory that was missing.
    #[test]
    fn every_gated_command_is_declared_in_the_inventory() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut gated: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut files = 0usize;
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read source dir").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                files += 1;
                let text = std::fs::read_to_string(&path).expect("read source file");
                for (_, rest) in text.match_indices("require_ready(\"").map(|(i, m)| (i, &text[i + m.len()..])) {
                    if let Some(end) = rest.find('"') {
                        gated.insert(rest[..end].to_string());
                    }
                }
            }
        }

        // Positive controls. A wrong root or a changed call spelling would
        // otherwise scan nothing and pass as "no undeclared commands".
        assert!(files > 20, "scanned only {files} source files under {src:?}");
        assert!(
            gated.len() >= 20,
            "found only {} gated commands, so the scan is not seeing the call sites: {gated:?}",
            gated.len()
        );
        for expected in ["commit", "purge-ignored", "stash", "doctor --heal"] {
            assert!(
                gated.contains(expected),
                "the scan must find the known call site {expected:?}: {gated:?}"
            );
        }

        let declared: std::collections::BTreeSet<String> = inventory()
            .unwrap()
            .commands
            .into_iter()
            .map(|capability| capability.command)
            .collect();
        let undeclared: Vec<&String> = gated.difference(&declared).collect();
        assert!(
            undeclared.is_empty(),
            "these commands gate on the inventory but are not in it, so they refuse on every \
             host: {undeclared:?}"
        );
    }

    #[test]
    fn bounded_dogfood_bar_cannot_disappear_from_inventory() {
        let inventory = inventory().unwrap();
        for required in [
            "init",
            "status",
            "commit",
            "log",
            "diff",
            "branch list",
            "branch create",
            "branch delete",
            "branch switch",
            "git export",
            "eject",
        ] {
            let capability = inventory
                .commands
                .iter()
                .find(|capability| capability.command == required)
                .unwrap_or_else(|| panic!("missing bounded-dogfood capability {required}"));
            assert!(capability.required_for_bounded_dogfood);
            assert!(!capability.acceptance_spec.is_empty());
        }
    }
}
