// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which language servers this build enriches with, and how to install them.
//!
//! Two facts have to hold together before a cross-file reference edge can
//! exist: the daemon wires an adapter for the language, and a server binary is
//! installed on the host. The first is a property of the build and is asserted
//! in `kin_daemon` against
//! [`kin_core::reference_coverage::ENRICHABLE_LANGUAGES`]. The second is a
//! property of the machine, and until this module existed nothing in Kin could
//! close it: `kin doctor` named the gap in prose and left the operator to work
//! out the command.
//!
//! That gap is not hypothetical. The v0.5.42 install a stranger exercised
//! carried no language server at all, so the Python adapter was wired, started
//! nothing, logged the failure at debug level, and every cross-file call fell
//! back to matching bare names. A wired adapter with no server behind it is
//! indistinguishable at the query surface from a language Kin does not support,
//! which is why provisioning belongs beside the wiring rather than in a doc.
//!
//! Nothing here installs without consent. A language server is a network
//! download into a shared global prefix, and Kin does not spend a user's
//! bandwidth or mutate their toolchain on a probe's say-so.

use std::collections::HashSet;
use std::process::Command;

use kin_model::LanguageId;

/// How to install the language server for one language.
///
/// `binaries` mirrors `kin_lsp::discovery::KNOWN_SERVERS` for the same
/// language, because discovery is what the daemon actually consults; a name
/// that differs here would advertise a fix that leaves the gap open. The first
/// entry is the binary the daemon's adapter starts, and the remaining ones are
/// alternatives discovery accepts.
pub(crate) struct LanguageServerRecipe {
    pub(crate) language: LanguageId,
    pub(crate) binaries: &'static [&'static str],
    pub(crate) program: &'static str,
    pub(crate) args: &'static [&'static str],
    /// What the operator is spending by saying yes. Named per recipe rather
    /// than as one sentence, because "this downloads a package" is exactly the
    /// disclosure that reads as boilerplate and gets clicked through.
    pub(crate) disclosure: &'static str,
}

impl LanguageServerRecipe {
    /// The command as an operator would type it.
    pub(crate) fn command_line(&self) -> String {
        if self.args.is_empty() {
            self.program.to_string()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }

    /// Whether any binary that satisfies this language is on `PATH`.
    pub(crate) fn installed(&self) -> bool {
        self.binaries
            .iter()
            .any(|binary| which::which(binary).is_ok())
    }

    /// Whether the tool that performs the install exists on this host.
    ///
    /// Reported separately from the install itself so a host without `npm`
    /// gets told that rather than a subprocess spawn error, which reads like a
    /// Kin defect.
    pub(crate) fn installer_available(&self) -> bool {
        which::which(self.program).is_ok()
    }
}

/// Every language this build can enrich, with the server that enriches it.
///
/// JavaScript and TypeScript are separate rows resolving to one binary and one
/// install command. They are separate because coverage is reported per language
/// the repository actually holds, and a JavaScript-only repository must not be
/// told its enrichment depends on a TypeScript row it has no files for. The
/// installer deduplicates by command line, so consenting to both runs `npm`
/// once.
pub(crate) const LANGUAGE_SERVERS: &[LanguageServerRecipe] = &[
    LanguageServerRecipe {
        language: LanguageId::Rust,
        binaries: &["rust-analyzer"],
        program: "rustup",
        args: &["component", "add", "rust-analyzer"],
        disclosure: "adds a rustup component to the active toolchain",
    },
    LanguageServerRecipe {
        language: LanguageId::Python,
        binaries: &["pyright-langserver", "pylsp"],
        program: "npm",
        args: &["install", "-g", "pyright"],
        disclosure: "downloads the pyright npm package into your global npm prefix",
    },
    LanguageServerRecipe {
        language: LanguageId::TypeScript,
        binaries: &["typescript-language-server", "vtsls"],
        program: "npm",
        args: &["install", "-g", "typescript-language-server", "typescript"],
        disclosure: "downloads the typescript-language-server and typescript npm packages into \
                     your global npm prefix",
    },
    LanguageServerRecipe {
        language: LanguageId::JavaScript,
        binaries: &["typescript-language-server"],
        program: "npm",
        args: &["install", "-g", "typescript-language-server", "typescript"],
        disclosure: "downloads the typescript-language-server and typescript npm packages into \
                     your global npm prefix",
    },
];

/// The recipe for one language, if this build enriches it at all.
pub(crate) fn recipe_for(language: LanguageId) -> Option<&'static LanguageServerRecipe> {
    LANGUAGE_SERVERS
        .iter()
        .find(|recipe| recipe.language == language)
}

/// Language servers this build can enrich with, and the binaries that provide
/// them.
///
/// The shape `kin doctor` and `kin graph status` already consumed. Kept as a
/// projection of [`LANGUAGE_SERVERS`] rather than a second table, because two
/// tables listing the same binaries is how the runtime and the advice come
/// apart.
pub(crate) fn language_server_binaries() -> Vec<(LanguageId, &'static [&'static str])> {
    LANGUAGE_SERVERS
        .iter()
        .map(|recipe| (recipe.language, recipe.binaries))
        .collect()
}

/// Languages whose enrichment server is installed on this host.
pub(crate) fn installed_language_servers() -> HashSet<LanguageId> {
    LANGUAGE_SERVERS
        .iter()
        .filter(|recipe| recipe.installed())
        .map(|recipe| recipe.language)
        .collect()
}

/// The exact command that closes the gap for `missing`, deduplicated.
///
/// One string an operator can paste. Two languages served by one package
/// produce one command, so the advice never asks for the same install twice.
pub(crate) fn install_commands_for(missing: &[LanguageId]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for language in missing {
        if let Some(recipe) = recipe_for(*language) {
            let command = recipe.command_line();
            if !seen.contains(&command) {
                seen.push(command);
            }
        }
    }
    seen
}

/// Every language this build enriches whose server is absent from this host.
///
/// Scoped to the build rather than to the repository on purpose. The per-repo
/// list is the better one to WARN about, and the coverage row already uses it,
/// but it is measured through a running daemon and this is the repair that has
/// to work on a host where nothing is running yet. Consent is per install
/// command, so an operator on a Python-only machine still declines the Rust
/// one rather than being handed a toolchain they did not ask for.
pub(crate) fn missing_enrichable_languages() -> Vec<LanguageId> {
    LANGUAGE_SERVERS
        .iter()
        .filter(|recipe| !recipe.installed())
        .map(|recipe| recipe.language)
        .collect()
}

/// The exact commands for languages named by their wire name.
///
/// The coverage report hands out `LanguageId`'s display strings rather than the
/// ids themselves, so the fix line that quotes them back has to resolve through
/// the same names. An unrecognised name yields no command rather than a guess.
pub(crate) fn install_commands_for_names(names: &[&str]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for name in names {
        // The coverage row prints `python (pyright-langserver or pylsp)` in
        // some surfaces and a bare `python` in others, so match on the leading
        // token rather than the whole string.
        let bare = name.split_whitespace().next().unwrap_or(name);
        for recipe in LANGUAGE_SERVERS {
            if recipe.language.to_string() == bare {
                let command = recipe.command_line();
                if !seen.contains(&command) {
                    seen.push(command);
                }
            }
        }
    }
    seen
}

/// The fix line for a set of languages whose servers are missing.
///
/// Names the command rather than describing it. A row that says "install a
/// language server" and leaves the operator to find out which package provides
/// `pyright-langserver` is a gap report wearing a fix's clothes.
pub(crate) fn install_fix_line(missing_names: &[&str]) -> String {
    let commands = install_commands_for_names(missing_names);
    if commands.is_empty() {
        return format!(
            "install a language server for the named language, then {RESTART_AFTER_INSTALL}"
        );
    }
    format!(
        "run `kin doctor --fix --install-language-servers` to install {} for you, or run {} \
         yourself; then {RESTART_AFTER_INSTALL}",
        if commands.len() == 1 { "it" } else { "them" },
        commands
            .iter()
            .map(|command| format!("`{command}`"))
            .collect::<Vec<_>>()
            .join(" and "),
    )
}

/// Whether Kin may install a language server, and on whose say-so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallConsent {
    /// A person is at the terminal: ask, then act on the answer.
    Ask,
    /// The caller passed the flag. Act without asking.
    Granted,
    /// No flag and nobody to ask. Print the command and change nothing.
    Withheld,
}

impl InstallConsent {
    /// Resolve consent from the flag and whether a person is present.
    ///
    /// The flag wins over the terminal in both directions: a script that passes
    /// it is not prompted, and an interactive run that does not is still asked
    /// rather than silently skipped.
    pub(crate) fn resolve(flag: bool, interactive: bool) -> Self {
        if flag {
            Self::Granted
        } else if interactive {
            Self::Ask
        } else {
            Self::Withheld
        }
    }
}

/// What happened to one language's server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallOutcome {
    /// A binary for this language was already on `PATH`.
    AlreadyPresent,
    /// The install command ran and the binary is now on `PATH`.
    Installed { command: String },
    /// The install command ran and the binary is still not on `PATH`. Reported
    /// rather than assumed installed: a zero exit from a package manager that
    /// wrote to a prefix outside `PATH` is the failure that reads as success.
    RanButStillMissing { command: String },
    /// The install command failed.
    Failed { command: String, reason: String },
    /// Consent was not given, or nobody was there to give it.
    Declined { command: String },
    /// The installer itself is not on this host.
    NoInstaller { program: String, command: String },
}

/// One language's provisioning result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstallReport {
    pub(crate) language: LanguageId,
    pub(crate) outcome: InstallOutcome,
}

/// Provision the servers for `missing`, honouring `consent`.
///
/// Every input is an argument, including the two `PATH` probes. Reading `PATH`
/// directly would make each test below assert about the machine it happens to
/// run on: on a host that already has pyright the declined-prompt case takes
/// the `AlreadyPresent` branch and passes without ever exercising a decline,
/// which is a green test that has stopped checking its own subject. As written,
/// a test states the whole environment it is asserting against.
///
/// `ask` is called at most once per distinct command, so consenting to
/// TypeScript does not produce a second prompt for JavaScript.
pub(crate) fn provision(
    missing: &[LanguageId],
    consent: InstallConsent,
    mut installed: impl FnMut(&LanguageServerRecipe) -> bool,
    mut installer_available: impl FnMut(&LanguageServerRecipe) -> bool,
    mut ask: impl FnMut(&LanguageServerRecipe) -> bool,
    mut run: impl FnMut(&LanguageServerRecipe) -> Result<(), String>,
) -> Vec<InstallReport> {
    let mut reports = Vec::new();
    // Keyed on the command rather than the language: one npm install serves
    // both JavaScript and TypeScript, and running it twice would download the
    // same package again and ask twice for one decision.
    let mut decided: Vec<(String, bool)> = Vec::new();
    let mut ran: Vec<(String, Result<(), String>)> = Vec::new();

    for language in missing {
        let Some(recipe) = recipe_for(*language) else {
            continue;
        };
        let command = recipe.command_line();

        if installed(recipe) {
            reports.push(InstallReport {
                language: *language,
                outcome: InstallOutcome::AlreadyPresent,
            });
            continue;
        }

        if !installer_available(recipe) {
            reports.push(InstallReport {
                language: *language,
                outcome: InstallOutcome::NoInstaller {
                    program: recipe.program.to_string(),
                    command,
                },
            });
            continue;
        }

        let approved = match consent {
            InstallConsent::Granted => true,
            InstallConsent::Withheld => false,
            InstallConsent::Ask => match decided.iter().find(|(cmd, _)| cmd == &command) {
                Some((_, answer)) => *answer,
                None => {
                    let answer = ask(recipe);
                    decided.push((command.clone(), answer));
                    answer
                }
            },
        };

        if !approved {
            reports.push(InstallReport {
                language: *language,
                outcome: InstallOutcome::Declined { command },
            });
            continue;
        }

        let result = match ran.iter().find(|(cmd, _)| cmd == &command) {
            Some((_, result)) => result.clone(),
            None => {
                let result = run(recipe);
                ran.push((command.clone(), result.clone()));
                result
            }
        };

        let outcome = match result {
            Err(reason) => InstallOutcome::Failed { command, reason },
            // Re-probe `PATH` rather than trusting the exit code. A global npm
            // prefix outside `PATH` installs successfully and leaves the binary
            // unreachable, which is the shape of success that would let doctor
            // report a closed gap that is still open.
            Ok(()) if installed(recipe) => InstallOutcome::Installed { command },
            Ok(()) => InstallOutcome::RanButStillMissing { command },
        };
        reports.push(InstallReport {
            language: *language,
            outcome,
        });
    }

    reports
}

/// Run a recipe's install command, inheriting stdio so the operator sees the
/// package manager's own progress rather than a spinner hiding it.
pub(crate) fn run_install(recipe: &LanguageServerRecipe) -> Result<(), String> {
    let status = Command::new(recipe.program)
        .args(recipe.args)
        .status()
        .map_err(|error| format!("could not run `{}`: {error}", recipe.command_line()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "`{}` exited with {}",
            recipe.command_line(),
            status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "a signal".to_string())
        ))
    }
}

/// Whether a newly installed server reaches a daemon that is already running.
///
/// It does not, when the daemon started on a host with no server at all.
/// `kin_daemon::daemon` calls `kin_lsp::discovery::discover_servers()` once
/// during startup and, on an empty result, never creates the enrichment channel
/// for the life of that process, so no later install can be picked up. When
/// discovery found at least one server the channel exists and each language's
/// server is started lazily on first use, so a server installed afterwards is
/// picked up without a restart.
///
/// Both halves are true and only the pessimistic one is safe to print, because
/// the surface asking cannot see which case the running daemon is in: a fresh
/// install is exactly the host where discovery found nothing.
pub(crate) const RESTART_AFTER_INSTALL: &str =
    "run `kin daemon stop` so the next kin command starts a daemon that discovers the new server; \
     a daemon that started with no language server on the host never opens its enrichment channel";

#[cfg(test)]
mod tests {
    use super::*;

    /// The advice and the runtime must name the same binaries.
    ///
    /// `kin doctor` tells an operator to install a binary and the daemon starts
    /// one; a difference between the two names is advice that leaves the gap
    /// open while reporting it closed. These are the names in
    /// `kin_lsp::discovery::KNOWN_SERVERS` and in the daemon's adapter map,
    /// asserted here because kin-cli cannot see either at compile time.
    #[test]
    fn recipes_name_the_binaries_the_daemon_starts() {
        for (language, expected) in [
            (LanguageId::Rust, "rust-analyzer"),
            (LanguageId::Python, "pyright-langserver"),
            (LanguageId::TypeScript, "typescript-language-server"),
            (LanguageId::JavaScript, "typescript-language-server"),
        ] {
            let recipe = recipe_for(language).expect("language must have a recipe");
            assert_eq!(
                recipe.binaries.first().copied(),
                Some(expected),
                "{language}: first binary is what the daemon's adapter starts"
            );
        }
    }

    /// Every language the coverage report calls enrichable must be installable.
    ///
    /// The failing case this rules out is a language wired for enrichment whose
    /// doctor row can only say "no language server found" with no command
    /// behind it, which is the state every language was in before this module.
    #[test]
    fn every_enrichable_language_has_an_install_command() {
        for language in kin_core::reference_coverage::ENRICHABLE_LANGUAGES {
            let recipe =
                recipe_for(*language).unwrap_or_else(|| panic!("{language} has no install recipe"));
            assert!(
                !recipe.command_line().is_empty(),
                "{language} install command is empty"
            );
        }
        assert_eq!(
            LANGUAGE_SERVERS.len(),
            kin_core::reference_coverage::ENRICHABLE_LANGUAGES.len(),
            "a recipe exists for a language the build does not enrich, or the other way round"
        );
    }

    #[test]
    fn install_commands_are_what_an_operator_would_type() {
        assert_eq!(
            recipe_for(LanguageId::Python).unwrap().command_line(),
            "npm install -g pyright"
        );
        assert_eq!(
            recipe_for(LanguageId::TypeScript).unwrap().command_line(),
            "npm install -g typescript-language-server typescript"
        );
        assert_eq!(
            recipe_for(LanguageId::Rust).unwrap().command_line(),
            "rustup component add rust-analyzer"
        );
    }

    /// One npm package serves both JavaScript and TypeScript, so the advice is
    /// one line rather than the same line twice.
    #[test]
    fn one_package_serving_two_languages_produces_one_command() {
        let commands = install_commands_for(&[LanguageId::JavaScript, LanguageId::TypeScript]);
        assert_eq!(
            commands,
            vec!["npm install -g typescript-language-server typescript".to_string()]
        );
    }

    #[test]
    fn install_commands_cover_every_distinct_missing_language() {
        let commands =
            install_commands_for(&[LanguageId::Python, LanguageId::JavaScript, LanguageId::Rust]);
        assert_eq!(commands.len(), 3, "{commands:?}");
        assert!(commands.contains(&"npm install -g pyright".to_string()));
    }

    #[test]
    fn consent_follows_the_flag_then_the_terminal() {
        assert_eq!(
            InstallConsent::resolve(true, false),
            InstallConsent::Granted,
            "the flag grants consent with nobody at the terminal"
        );
        assert_eq!(
            InstallConsent::resolve(false, true),
            InstallConsent::Ask,
            "an interactive run without the flag asks rather than skipping"
        );
        assert_eq!(
            InstallConsent::resolve(false, false),
            InstallConsent::Withheld,
            "no flag and no terminal changes nothing"
        );
    }

    /// A host with nothing installed and every installer available. Stated
    /// explicitly so no assertion below depends on what this machine has.
    fn nothing_installed(_: &LanguageServerRecipe) -> bool {
        false
    }
    fn installer_present(_: &LanguageServerRecipe) -> bool {
        true
    }

    /// The whole point of the consent model: nothing runs unless someone said so.
    #[test]
    fn withheld_consent_runs_no_command() {
        let mut runs = 0;
        let reports = provision(
            &[LanguageId::Python],
            InstallConsent::Withheld,
            nothing_installed,
            installer_present,
            |_| panic!("must not prompt when consent is withheld"),
            |_| {
                runs += 1;
                Ok(())
            },
        );
        assert_eq!(runs, 0, "an install ran without consent");
        assert!(matches!(
            reports.first().map(|r| &r.outcome),
            Some(InstallOutcome::Declined { .. })
        ));
    }

    /// A declined prompt is recorded with the command it did not run, not
    /// retried and not silently dropped.
    #[test]
    fn a_declined_prompt_records_the_command_it_did_not_run() {
        let mut runs = 0;
        let reports = provision(
            &[LanguageId::Python],
            InstallConsent::Ask,
            nothing_installed,
            installer_present,
            |_| false,
            |_| {
                runs += 1;
                Ok(())
            },
        );
        assert_eq!(runs, 0);
        match reports.first().map(|r| &r.outcome) {
            Some(InstallOutcome::Declined { command }) => {
                assert_eq!(command, "npm install -g pyright");
            }
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    /// Two languages behind one package ask once and install once.
    #[test]
    fn one_package_prompts_once_and_runs_once_for_two_languages() {
        let mut prompts = 0;
        let mut runs = 0;
        let reports = provision(
            &[LanguageId::TypeScript, LanguageId::JavaScript],
            InstallConsent::Ask,
            nothing_installed,
            installer_present,
            |_| {
                prompts += 1;
                true
            },
            |_| {
                runs += 1;
                Ok(())
            },
        );
        assert_eq!(prompts, 1, "one install command must ask exactly once");
        assert_eq!(runs, 1, "one install command must run exactly once");
        assert_eq!(reports.len(), 2, "both languages still get a report");
    }

    /// Consent granted for a package serves both its languages with one run.
    ///
    /// The second language reports `AlreadyPresent` rather than `Installed`,
    /// because by the time it is considered the binary genuinely is on `PATH`.
    /// What matters is the pair of facts asserted here: the command ran once,
    /// and neither language ends in a state that still needs an operator.
    #[test]
    fn a_granted_install_that_lands_serves_both_languages_with_one_run() {
        // Absent before the run, present after: the probe and the runner share
        // one cell, which is what a real install does to `PATH`.
        let ran = std::cell::Cell::new(false);
        let reports = provision(
            &[LanguageId::TypeScript, LanguageId::JavaScript],
            InstallConsent::Granted,
            |_| ran.get(),
            installer_present,
            |_| panic!("granted consent must not prompt"),
            |_| {
                ran.set(true);
                Ok(())
            },
        );
        assert!(ran.get(), "the install command never ran");
        assert_eq!(reports.len(), 2);
        assert!(
            reports.iter().all(|r| matches!(
                r.outcome,
                InstallOutcome::Installed { .. } | InstallOutcome::AlreadyPresent
            )),
            "{reports:?}"
        );
        assert!(
            reports
                .iter()
                .any(|r| matches!(r.outcome, InstallOutcome::Installed { .. })),
            "one of the two must report the install that happened: {reports:?}"
        );
    }

    /// A command that exits zero without putting the binary on `PATH` is not an
    /// install. This is the npm-prefix-outside-PATH case, where the package
    /// manager succeeds and the server stays unreachable.
    #[test]
    fn a_successful_command_that_leaves_the_binary_missing_is_not_reported_installed() {
        let reports = provision(
            &[LanguageId::TypeScript],
            InstallConsent::Granted,
            nothing_installed,
            installer_present,
            |_| true,
            |_| Ok(()),
        );
        assert!(
            matches!(
                reports.first().map(|r| &r.outcome),
                Some(InstallOutcome::RanButStillMissing { .. })
            ),
            "a no-op install must not report Installed: {reports:?}"
        );
    }

    #[test]
    fn a_failing_command_reports_its_own_reason() {
        let reports = provision(
            &[LanguageId::Python],
            InstallConsent::Granted,
            nothing_installed,
            installer_present,
            |_| true,
            |_| Err("network unreachable".to_string()),
        );
        match reports.first().map(|r| &r.outcome) {
            Some(InstallOutcome::Failed { reason, command }) => {
                assert_eq!(reason, "network unreachable");
                assert_eq!(command, "npm install -g pyright");
            }
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    /// A host with no npm is told that, rather than being handed a spawn error
    /// that reads like a Kin defect.
    #[test]
    fn a_missing_installer_is_named_rather_than_attempted() {
        let mut runs = 0;
        let reports = provision(
            &[LanguageId::Python],
            InstallConsent::Granted,
            nothing_installed,
            |_| false,
            |_| panic!("must not prompt when the installer is absent"),
            |_| {
                runs += 1;
                Ok(())
            },
        );
        assert_eq!(runs, 0);
        match reports.first().map(|r| &r.outcome) {
            Some(InstallOutcome::NoInstaller { program, command }) => {
                assert_eq!(program, "npm");
                assert_eq!(command, "npm install -g pyright");
            }
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    /// An already-installed server is left alone, so a repeated `--fix` is a
    /// no-op rather than a re-download.
    #[test]
    fn an_installed_server_is_not_reinstalled() {
        let mut runs = 0;
        let reports = provision(
            &[LanguageId::Python, LanguageId::Rust],
            InstallConsent::Granted,
            |_| true,
            installer_present,
            |_| panic!("must not prompt for something already installed"),
            |_| {
                runs += 1;
                Ok(())
            },
        );
        assert_eq!(runs, 0);
        assert!(
            reports
                .iter()
                .all(|r| r.outcome == InstallOutcome::AlreadyPresent),
            "{reports:?}"
        );
    }

    /// The restart sentence must stay pessimistic and must name the command.
    #[test]
    fn the_restart_advice_names_a_command_and_claims_no_hot_pickup() {
        // `kin daemon` has exactly two subcommands, `status` and `stop`, so
        // the obvious `restart` is a command that does not exist. A fix line
        // naming one is worse than no fix line: it fails in front of the
        // operator at the moment they are already blocked.
        assert!(RESTART_AFTER_INSTALL.contains("kin daemon stop"));
        assert!(!RESTART_AFTER_INSTALL.contains("kin daemon restart"));
        assert!(
            !RESTART_AFTER_INSTALL.contains("no restart"),
            "the advice must not promise a pickup the startup gate cannot deliver"
        );
    }
}
