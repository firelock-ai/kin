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

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// The typescript package `typescript-language-server` is installed beside.
///
/// Pinned to 5.x, and the pin is load-bearing. `typescript-language-server`
/// runs `tsserver`, which ships as `lib/tsserver.js` inside the typescript
/// package. TypeScript 7 dropped that entry point: its package exposes only a
/// `tsc` binary and carries no `lib/tsserver.js`. Installing typescript
/// unpinned resolves the `latest` dist-tag, which is 7.x, and the server then
/// answers Kin's `initialize` with "Could not find a valid TypeScript
/// installation" and exits. Nothing in npm metadata prevents that pairing,
/// because `typescript-language-server` declares no peer dependency on
/// typescript at all.
const TYPESCRIPT_PACKAGE: &str = "typescript@^5";

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
        args: &[
            "install",
            "-g",
            "typescript-language-server",
            TYPESCRIPT_PACKAGE,
        ],
        disclosure: "downloads the typescript-language-server and typescript npm packages into \
                     your global npm prefix",
    },
    LanguageServerRecipe {
        language: LanguageId::JavaScript,
        binaries: &["typescript-language-server"],
        program: "npm",
        args: &[
            "install",
            "-g",
            "typescript-language-server",
            TYPESCRIPT_PACKAGE,
        ],
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

/// Where a global npm install would land on this host, and whether this user
/// can write there.
///
/// npm's own answer rather than a guess: `npm config get prefix` resolves the
/// value the install will actually use, including one set by `npm config set
/// prefix`, by `NPM_CONFIG_PREFIX`, or by a version manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmGlobalPrefix {
    pub(crate) prefix: PathBuf,
    pub(crate) install_dir: PathBuf,
    pub(crate) writable: bool,
}

/// Where npm unpacks a global package under `prefix`.
fn npm_global_install_dir(prefix: &Path) -> PathBuf {
    if cfg!(windows) {
        prefix.join("node_modules")
    } else {
        prefix.join("lib").join("node_modules")
    }
}

/// Whether this process can create an entry in `dir`, or in the nearest
/// existing ancestor npm would have to create it under.
///
/// Asked by trying, because the permission bits do not answer it: a directory
/// can be group-writable through a group this user is not in, and an ACL or a
/// read-only mount refuses a directory whose mode says yes.
fn directory_is_writable(dir: &Path) -> bool {
    let mut candidate = dir;
    while !candidate.exists() {
        match candidate.parent() {
            Some(parent) => candidate = parent,
            None => return false,
        }
    }
    let probe = candidate.join(format!(".kin-install-probe-{}", std::process::id()));
    match std::fs::create_dir(&probe) {
        Ok(()) => {
            let _ = std::fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Ask npm where its global prefix is, and whether this user owns it.
fn npm_global_prefix() -> Option<NpmGlobalPrefix> {
    let output = Command::new("npm")
        .args(["config", "get", "prefix"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let answer = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if answer.is_empty() || answer == "undefined" || answer == "null" {
        return None;
    }
    let prefix = PathBuf::from(answer);
    let install_dir = npm_global_install_dir(&prefix);
    let writable = directory_is_writable(&install_dir);
    Some(NpmGlobalPrefix {
        prefix,
        install_dir,
        writable,
    })
}

/// The reason a global npm install cannot succeed, stated before it is tried.
pub(crate) fn npm_prefix_blocker(prefix: &NpmGlobalPrefix) -> Option<String> {
    if prefix.writable {
        return None;
    }
    Some(format!(
        "the global npm prefix {} is not writable by this user, so `npm install -g` cannot \
         create {}",
        prefix.prefix.display(),
        prefix.install_dir.display()
    ))
}

/// Why this install cannot succeed, known before it is attempted.
///
/// Only the npm recipes have one today, and it is the one a container hits:
/// the Node base images set the global prefix to `/usr/local`, whose
/// `lib/node_modules` is owned by root, and a Kin running as an unprivileged
/// user cannot write there. Attempting it anyway spends the download and ends
/// in npm's own EACCES trace, which reads as a Kin defect and names no remedy.
fn install_blocker(recipe: &LanguageServerRecipe) -> Option<String> {
    if recipe.program != "npm" {
        return None;
    }
    npm_prefix_blocker(&npm_global_prefix()?)
}

/// How many of an installer's stderr lines are kept for the failure report.
const MAX_RETAINED_INSTALLER_LINES: usize = 200;

/// How many of an installer's own error lines a failure reason repeats.
const MAX_REPORTED_INSTALLER_LINES: usize = 4;

/// Whether a failure is the install location refusing this user.
///
/// Matched against the installer's own words as well as Kin's preflight
/// sentence, because the two describe the same wall from opposite sides.
pub(crate) fn is_permission_failure(reason: &str) -> bool {
    const SIGNATURES: [&str; 6] = [
        "eacces",
        "eperm",
        "permission denied",
        "operation not permitted",
        "not writable",
        "access is denied",
    ];
    let lowered = reason.to_lowercase();
    SIGNATURES
        .iter()
        .any(|signature| lowered.contains(signature))
}

/// The installer's own account of the failure, reduced to the lines naming it.
///
/// npm leads with the code, the syscall and the path, which is exactly the
/// triple an operator needs and exactly what an exit code alone destroys. When
/// nothing announces itself as an error the last lines stand in, because a
/// reason that carries no words at all sends someone back to scroll a terminal.
pub(crate) fn installer_error_summary(lines: &[String]) -> Option<String> {
    let said: Vec<&str> = lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();
    let mut named: Vec<&str> = said
        .iter()
        .copied()
        .filter(|line| line.to_lowercase().contains("error"))
        .take(MAX_REPORTED_INSTALLER_LINES)
        .collect();
    if named.is_empty() {
        named = said.iter().copied().rev().take(2).collect();
        named.reverse();
    }
    if named.is_empty() {
        return None;
    }
    Some(named.join("; "))
}

/// The failure reason for an installer that ran and exited non-zero.
pub(crate) fn installer_failure_reason(
    command: &str,
    code: Option<i32>,
    stderr_lines: &[String],
) -> String {
    let exit = code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "a signal".to_string());
    match installer_error_summary(stderr_lines) {
        Some(said) => format!("`{command}` exited with {exit}: {said}"),
        None => format!("`{command}` exited with {exit}"),
    }
}

/// What to tell an operator whose install failed, chosen by the cause.
///
/// A permission failure has two real remedies and Kin can run neither: moving
/// the prefix somewhere the user owns, or running the same command with the
/// privileges the current prefix needs. Naming both is the whole value, because
/// the container this was found in has no `sudo` at all and the first is the
/// only one available there.
pub(crate) fn install_failure_remediation(
    recipe: &LanguageServerRecipe,
    reason: &str,
) -> Vec<String> {
    let command = recipe.command_line();
    if !is_permission_failure(reason) {
        return vec![format!(
            "run `{command}` yourself to see the installer's own error"
        )];
    }
    if recipe.program != "npm" {
        return vec![format!(
            "the directory `{command}` writes to refuses this user; fix its permissions, then \
             run the command again"
        )];
    }
    vec![
        "point npm at a prefix you own, then install again:".to_string(),
        "    npm config set prefix \"$HOME/.npm-global\"".to_string(),
        "    export PATH=\"$HOME/.npm-global/bin:$PATH\"".to_string(),
        format!("    {command}"),
        format!(
            "or install into the current prefix with the privileges it requires: sudo {command}"
        ),
    ]
}

/// What to tell an operator whose install succeeded somewhere nothing reads.
pub(crate) fn unreachable_after_install_remediation(recipe: &LanguageServerRecipe) -> Vec<String> {
    let command = recipe.command_line();
    if recipe.program == "npm" {
        return vec![
            format!(
                "`{command}` reported success, so the package landed outside this shell's PATH"
            ),
            "`npm prefix -g` prints the prefix; add its `bin` subdirectory to PATH".to_string(),
        ];
    }
    vec![format!(
        "`{command}` reported success, so the binary landed outside this shell's PATH; add the \
         directory {} installs into to PATH",
        recipe.program
    )]
}

/// Run a recipe's install command, streaming the installer's own output.
///
/// Two things happen here that a bare `status()` cannot do. The prefix is
/// checked before the command runs, because `npm install -g` against a prefix
/// this user cannot write ends in an EACCES trace that is npm's diagnostic
/// rather than Kin's, and Kin can know the answer without spending the attempt.
/// And stderr is teed rather than inherited, so the operator still reads the
/// installer live while a failure keeps the installer's own words for the
/// report at the end: a reason that says only "exited with 243" sends someone
/// back to scroll a terminal for the cause (FIR-2547).
pub(crate) fn run_install(recipe: &LanguageServerRecipe) -> Result<(), String> {
    if let Some(blocker) = install_blocker(recipe) {
        return Err(blocker);
    }
    let mut child = Command::new(recipe.program)
        .args(recipe.args)
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not run `{}`: {error}", recipe.command_line()))?;
    let mut stderr_lines: Vec<String> = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            // Written rather than `eprintln!`, and the error dropped on
            // purpose. Rust ignores SIGPIPE, so `eprintln!` panics when the
            // reader has gone away, and the process exits 101. A caller who
            // piped this run into `head` would then get a panic exit out of an
            // install that completed, which is the same lie as the exit 0 this
            // ticket is about, told in the other direction. An echoed progress
            // line is not worth an exit code.
            let _ = writeln!(std::io::stderr(), "{line}");
            if stderr_lines.len() < MAX_RETAINED_INSTALLER_LINES {
                stderr_lines.push(line);
            }
        }
    }
    let status = child
        .wait()
        .map_err(|error| format!("could not wait for `{}`: {error}", recipe.command_line()))?;
    if status.success() {
        Ok(())
    } else {
        Err(installer_failure_reason(
            &recipe.command_line(),
            status.code(),
            &stderr_lines,
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
    /// The advice and the runtime must name the same binaries, asserted against
    /// the crate that actually launches them.
    ///
    /// `kin doctor` tells an operator to install a binary and the daemon starts
    /// one; a difference between the two names is advice that leaves the gap
    /// open while reporting it closed. This used to restate the names by hand,
    /// because kin-cli could not see kin-lsp at compile time. It can, and
    /// kin-lsp now exports the list its own resolver reads, so the expectation
    /// comes from there instead. A hardcoded copy could agree with nothing and
    /// still pass.
    #[test]
    fn recipes_name_the_binaries_the_daemon_starts() {
        let runtime: std::collections::HashMap<LanguageId, Vec<String>> =
            kin_lsp::registry::ProviderRegistry::with_defaults()
                .known_binaries()
                .into_iter()
                .collect();

        for recipe in LANGUAGE_SERVERS {
            let expected = runtime.get(&recipe.language).unwrap_or_else(|| {
                panic!(
                    "{}: kin-cli advertises an install for a language kin-lsp registers no \
                     provider for, so the advice names a server nothing will start",
                    recipe.language
                )
            });
            let advertised: Vec<String> =
                recipe.binaries.iter().map(|b| (*b).to_string()).collect();
            assert_eq!(
                &advertised, expected,
                "{}: the install advice and the runtime name different binaries",
                recipe.language
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
            "npm install -g typescript-language-server typescript@^5"
        );
        assert_eq!(
            recipe_for(LanguageId::Rust).unwrap().command_line(),
            "rustup component add rust-analyzer"
        );
    }

    /// The typescript package must never be installed unpinned.
    ///
    /// TypeScript 7 ships no `lib/tsserver.js`, so a bare `typescript`
    /// argument resolves the `latest` dist-tag to 7.x and the language server
    /// refuses to initialize. The failure is invisible from the install side:
    /// `npm install -g` succeeds, `typescript-language-server` lands on PATH,
    /// and `installed()` reports the language served. Only a start attempt
    /// disagrees, which is why the pin is asserted here rather than left to a
    /// runtime check.
    #[test]
    fn the_typescript_package_is_pinned_away_from_the_version_without_tsserver() {
        for language in [LanguageId::TypeScript, LanguageId::JavaScript] {
            let recipe = recipe_for(language).expect("language must have a recipe");
            let typescript_arg = recipe
                .args
                .iter()
                .find(|arg| arg.starts_with("typescript@") || **arg == "typescript")
                .unwrap_or_else(|| panic!("{language}: recipe installs no typescript package"));
            assert_eq!(
                *typescript_arg, "typescript@^5",
                "{language}: the typescript package must carry the 5.x pin. Unpinned, npm \
                 resolves latest to TypeScript 7, which ships no lib/tsserver.js, and \
                 typescript-language-server answers initialize with \"Could not find a valid \
                 TypeScript installation\" and exits."
            );
        }
    }

    /// The pin has to survive every line that quotes the command back.
    ///
    /// The remediation for a permission failure hands the operator the same
    /// install to run under `sudo` or under a prefix they own, and a copy that
    /// dropped the pin would walk them into TypeScript 7 by hand. It is
    /// composed from the recipe rather than restated, and this is what holds
    /// that composition to it.
    #[test]
    fn the_remediation_quotes_the_install_with_its_pin_intact() {
        for language in [LanguageId::TypeScript, LanguageId::JavaScript] {
            let recipe = recipe_for(language).expect("language must have a recipe");
            let lines = install_failure_remediation(
                recipe,
                "npm error code EACCES: permission denied, mkdir '/usr/local/lib/node_modules'",
            );
            let quoting: Vec<&String> = lines
                .iter()
                .filter(|line| line.contains("npm install -g"))
                .collect();
            assert!(
                !quoting.is_empty(),
                "{language}: the permission remedy must hand back the install command"
            );
            for line in quoting {
                assert!(
                    line.contains("typescript@^5"),
                    "{language}: a remedy quoting the install dropped the 5.x pin, which walks \
                     the operator into the TypeScript 7 that ships no lib/tsserver.js: {line}"
                );
            }
        }
    }

    /// An unwritable global prefix is Kin's finding, not npm's stack trace.
    #[test]
    fn an_unwritable_npm_prefix_is_named_before_the_install_runs() {
        let refused = NpmGlobalPrefix {
            prefix: PathBuf::from("/usr/local"),
            install_dir: PathBuf::from("/usr/local/lib/node_modules"),
            writable: false,
        };
        let blocker = npm_prefix_blocker(&refused)
            .expect("a prefix this user cannot write must block the install");
        assert!(blocker.contains("/usr/local"), "{blocker}");
        assert!(blocker.contains("/usr/local/lib/node_modules"), "{blocker}");
        assert!(is_permission_failure(&blocker), "{blocker}");

        // Positive control: the same probe on a prefix the user owns must let
        // the install proceed, or this check would refuse every host.
        let owned = NpmGlobalPrefix {
            prefix: PathBuf::from("/home/dev/.npm-global"),
            install_dir: PathBuf::from("/home/dev/.npm-global/lib/node_modules"),
            writable: true,
        };
        assert_eq!(npm_prefix_blocker(&owned), None);
    }

    /// A permission failure gets the two remedies that exist, and Kin can run
    /// neither: a prefix the user owns, or the privileged command.
    #[test]
    fn a_permission_failure_names_a_prefix_the_user_owns_and_the_privileged_command() {
        let recipe = recipe_for(LanguageId::Python).expect("python must have a recipe");
        let lines = install_failure_remediation(
            recipe,
            "`npm install -g pyright` exited with 243: npm error code EACCES; npm error Error: \
             EACCES: permission denied, mkdir '/usr/local/lib/node_modules/pyright'",
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("npm config set prefix"),
            "the container that found this has no sudo at all, so the prefix move is the only \
             remedy available there: {joined}"
        );
        assert!(joined.contains("sudo npm install -g pyright"), "{joined}");
    }

    /// A failure that is not about permissions must not be handed a permission
    /// remedy, or the advice sends an operator to change a prefix that was
    /// never the problem.
    #[test]
    fn a_failure_that_is_not_about_permissions_gets_no_permission_remedy() {
        let recipe = recipe_for(LanguageId::Python).expect("python must have a recipe");
        let lines = install_failure_remediation(
            recipe,
            "`npm install -g pyright` exited with 1: npm error code E404; npm error 404 Not Found",
        );
        let joined = lines.join("\n");
        assert!(!joined.contains("npm config set prefix"), "{joined}");
        assert!(!joined.contains("sudo"), "{joined}");
        assert!(joined.contains("npm install -g pyright"), "{joined}");
    }

    /// The failure reason has to carry the installer's own words.
    ///
    /// An exit code alone is what sent the reader of the run this came from
    /// back to scroll a terminal: 243 names nothing, while the code, the
    /// syscall and the path name the whole cause.
    #[test]
    fn an_installer_failure_reason_carries_the_installers_own_words() {
        let stderr: Vec<String> = [
            "npm error code EACCES",
            "npm error syscall mkdir",
            "npm error path /usr/local/lib/node_modules/pyright",
            "npm error errno -13",
        ]
        .iter()
        .map(|line| (*line).to_string())
        .collect();
        let reason = installer_failure_reason("npm install -g pyright", Some(243), &stderr);
        assert!(reason.contains("243"), "{reason}");
        assert!(reason.contains("EACCES"), "{reason}");
        assert!(
            reason.contains("/usr/local/lib/node_modules/pyright"),
            "{reason}"
        );
        assert!(is_permission_failure(&reason), "{reason}");

        // An installer that said nothing recognisable still reports its exit,
        // and must not invent an error it never printed.
        let quiet = installer_failure_reason("npm install -g pyright", Some(1), &[]);
        assert_eq!(quiet, "`npm install -g pyright` exited with 1");
        assert!(!is_permission_failure(&quiet), "{quiet}");
    }

    /// One npm package serves both JavaScript and TypeScript, so the advice is
    /// one line rather than the same line twice.
    #[test]
    fn one_package_serving_two_languages_produces_one_command() {
        let commands = install_commands_for(&[LanguageId::JavaScript, LanguageId::TypeScript]);
        assert_eq!(
            commands,
            vec!["npm install -g typescript-language-server typescript@^5".to_string()]
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

/// Ask what each enrichable language's server can actually do on this host.
///
/// The question every surface here used to answer with `which::which`. A binary
/// on `PATH` is not a working language server: a host carrying
/// `typescript-language-server` beside a TypeScript that ships no `tsserver`
/// resolves fine and fails every start. Only a handshake tells them apart, so
/// this starts each server and runs one.
///
/// Probes run concurrently, so the wait is one probe budget rather than one per
/// language. Belongs to command paths, which may spawn; a query path must read
/// the verdict a spawner published instead.
pub(crate) async fn probe_language_server_readiness(
    workspace_root: &std::path::Path,
) -> kin_core::reference_coverage::LanguageServerReadinessMap {
    use kin_core::reference_coverage::{
        LanguageServerReadiness, LanguageServerReadinessMap, ENRICHABLE_LANGUAGES,
    };
    use kin_lsp::registry::{ProviderGapReason, ProviderRegistry};

    let probes: Vec<_> = ENRICHABLE_LANGUAGES
        .iter()
        .copied()
        .map(|language| {
            let workspace_root = workspace_root.to_path_buf();
            tokio::spawn(async move {
                let registry = ProviderRegistry::with_defaults();
                let readiness = match kin_lsp::lifecycle::probe_readiness(
                    &registry,
                    language,
                    &workspace_root,
                    None,
                )
                .await
                {
                    Ok(_) => LanguageServerReadiness::Usable,
                    Err(gap) => match gap.reason {
                        ProviderGapReason::ServerUnusable { message } => {
                            LanguageServerReadiness::Unusable { reason: message }
                        }
                        _ => LanguageServerReadiness::Absent,
                    },
                };
                (language, readiness)
            })
        })
        .collect();

    let mut readiness = LanguageServerReadinessMap::new();
    for probe in probes {
        // A probe that did not finish establishes nothing about its language,
        // and recording it as absent would be a claim this process did not
        // earn. Leaving it out reads as unknown.
        if let Ok((language, state)) = probe.await {
            readiness.insert(language, state);
        }
    }
    readiness
}
