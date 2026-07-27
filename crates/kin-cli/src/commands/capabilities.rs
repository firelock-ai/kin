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
            anyhow::anyhow!(
                "command capability '{}' is not declared; refusing an unversioned authority path",
                command
            )
        })?;
    if capability.status == CapabilityStatus::Ready
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

pub fn run(json: bool) -> Result<()> {
    let inventory = inventory()?;
    let required = inventory
        .commands
        .iter()
        .filter(|capability| capability.required_for_bounded_dogfood)
        .collect::<Vec<_>>();
    let bounded_dogfood_required_ready = required
        .iter()
        .filter(|capability| {
            capability.status == CapabilityStatus::Ready
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
    let report = CapabilityReport {
        schema: &inventory.schema,
        substrate: &inventory.substrate,
        bounded_dogfood_ready: bounded_dogfood_required_ready == required.len(),
        bounded_dogfood_required_ready,
        bounded_dogfood_required_total: required.len(),
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
        "Full Git replacement ready: {} ({}/{})",
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
            CapabilityStatus::OpenGate => "OPEN ",
        };
        let dogfood = if capability.required_for_bounded_dogfood {
            " required"
        } else {
            ""
        };
        println!(
            "{status}  {:18}  {}{dogfood}",
            capability.command, capability.authority
        );
        println!("       {}", capability.note);
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
                CapabilityStatus::OpenGate => {
                    assert_eq!(capability.exposure, CapabilityExposure::FailClosed);
                    assert!(!capability.acceptance_spec.is_empty());
                }
            }
        }
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
