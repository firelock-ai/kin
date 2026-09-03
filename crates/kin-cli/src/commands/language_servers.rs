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

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kin_model::LanguageId;

use super::language_server_release::{self, PinnedRelease, RUST_ANALYZER_RELEASE};

/// What Kin can do for a language whose named installer this host does not
/// have, or cannot use.
///
/// The recipes name a package manager or a toolchain: `rustup` for Rust, `npm`
/// for the rest. Both assumptions break on an ordinary machine, and they break
/// differently. A developer who is not a Rust developer has no rustup at all,
/// so the Rust row's only advice was to install a toolchain in order to read
/// somebody else's code. A user running as themselves in a Node base image has
/// npm, and its global prefix is owned by root, so the install cannot write
/// where it would put the binary.
///
/// Neither of those is a reason to leave a repository with no reference edges,
/// so each recipe carries the route Kin takes instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fallback {
    /// Kin fetches the project's own release binary, pinned to one tag and
    /// verified against a digest recorded in Kin's source.
    PinnedRelease(&'static PinnedRelease),
    /// Kin re-runs the same installer against a prefix Kin owns, under
    /// `KIN_HOME`, which needs no privilege and no shared directory.
    ManagedPrefix,
}

/// Which of a recipe's routes one run takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallRoute {
    /// The recipe's own installer, against its own default target. Preferred
    /// wherever it works: a rustup component tracks the toolchain that compiles
    /// the repository, and Kin's pinned copy does not.
    Installer,
    /// The pinned release binary Kin downloads and verifies itself.
    PinnedRelease,
    /// The recipe's installer, redirected at a prefix Kin owns.
    ManagedPrefix,
}

/// What this host can offer one recipe, measured before a route is chosen.
///
/// Taken as data rather than probed inside [`choose_route`] so the rule is
/// decidable with no host, no network and no subprocess. Every field is a fact
/// somebody measured; none of them is a preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostRoutes {
    /// The recipe's named program is on `PATH`.
    pub(crate) installer_on_path: bool,
    /// The installer's default target refuses this user, so running it would
    /// spend the download and end in the installer's own permission trace.
    pub(crate) default_target_blocked: bool,
    /// Kin pins a release binary for this host's os and architecture.
    pub(crate) pinned_release_for_this_host: bool,
}

/// Which route this host leaves open for a recipe, or `None` when it leaves
/// none.
///
/// Ordered by what serves the operator best, not by what is easiest. The
/// installer wins whenever it can actually run, because a server the operator's
/// own toolchain manages is the one their toolchain expects. Kin's own routes
/// are what a host without that toolchain gets instead of a refusal.
pub(crate) fn choose_route(
    recipe: &LanguageServerRecipe,
    host: HostRoutes,
) -> Option<InstallRoute> {
    if host.installer_on_path && !host.default_target_blocked {
        return Some(InstallRoute::Installer);
    }
    match recipe.fallback {
        // A pinned release needs nothing from this host but a network, so it
        // serves both the no-installer case and the blocked-target one.
        Fallback::PinnedRelease(_) if host.pinned_release_for_this_host => {
            Some(InstallRoute::PinnedRelease)
        }
        // A managed prefix is the same installer pointed somewhere else, so it
        // answers a blocked target and cannot answer a missing installer. npm
        // absent means Node absent, and Kin does not install a language
        // runtime behind a user's back.
        Fallback::ManagedPrefix if host.installer_on_path => Some(InstallRoute::ManagedPrefix),
        _ => None,
    }
}

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
    /// What Kin does when [`Self::program`] cannot serve this host.
    pub(crate) fallback: Fallback,
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

    /// Whether this recipe redirects with `GOBIN` rather than an installer flag.
    ///
    /// `go install` has no prefix argument at all. Its destination is the
    /// `GOBIN` environment variable, defaulting to `$(go env GOPATH)/bin`, so
    /// the Go row's redirect is an environment entry where every npm row's is
    /// an argument. The two cannot share one shape, and a Go recipe pushed
    /// through the npm shape would hand `go` a `--prefix` flag it rejects.
    fn redirects_through_gobin(&self) -> bool {
        self.program == "go"
    }

    /// The environment the managed route runs its installer under.
    ///
    /// Empty for every npm recipe, which redirects with `--prefix`. For Go it
    /// is `GOBIN` pointed at [`kin_core::tool_prefix::managed_tool_bin_dir`],
    /// a directory both binaries already append to `PATH` at startup through
    /// `augment_path_with_managed_tools`. That is the whole answer to the gap
    /// wiring the adapter does not close: an ordinary `go install` writes into
    /// `$(go env GOPATH)/bin`, which nothing puts on `PATH`, and the daemon
    /// starts a language server with a bare `Command::new("gopls")`.
    pub(crate) fn managed_prefix_env(&self) -> Vec<(String, String)> {
        if self.redirects_through_gobin() {
            return vec![(
                "GOBIN".to_string(),
                kin_core::tool_prefix::managed_tool_bin_dir()
                    .display()
                    .to_string(),
            )];
        }
        Vec::new()
    }

    /// The directory the managed route needs to exist before it runs.
    pub(crate) fn managed_prefix_dir(&self) -> PathBuf {
        if self.redirects_through_gobin() {
            kin_core::tool_prefix::managed_tool_bin_dir()
        } else {
            kin_core::tool_prefix::managed_node_prefix()
        }
    }

    /// Where the managed route's binary lands, as the report says it back.
    ///
    /// Not the same as [`Self::managed_prefix_dir`] for npm, which installs
    /// into a prefix and links executables into `node_modules/.bin` beneath it.
    /// Naming the wrong one is a run that reports success over a binary nothing
    /// can reach.
    pub(crate) fn managed_prefix_bin_dir(&self) -> PathBuf {
        if self.redirects_through_gobin() {
            kin_core::tool_prefix::managed_tool_bin_dir()
        } else {
            kin_core::tool_prefix::managed_node_bin_dir()
        }
    }

    /// What vouches for the bytes the managed route installs.
    fn managed_route_source(&self) -> String {
        if self.redirects_through_gobin() {
            return format!(
                "{GOPLS_MODULE}, built from source and verified against the Go checksum database"
            );
        }
        format!("{}, integrity checked by npm", self.program)
    }

    /// The arguments for the same installer pointed at a prefix Kin owns.
    ///
    /// `-g` is dropped and `--prefix` inserted, which turns a global install
    /// into a local one rooted where Kin can always write. The package
    /// arguments are untouched, pin included, because the whole hazard the
    /// TypeScript pin exists for is a copy that quietly drops it.
    pub(crate) fn managed_prefix_args(&self, prefix: &Path) -> Vec<String> {
        // The Go route redirects through the environment, so its arguments are
        // the recipe's own, module pin included. Rewriting them would be the
        // exact copy that drops a pin, in a route whose whole reason to exist
        // is that the default destination is unreachable.
        if self.redirects_through_gobin() {
            return self.args.iter().map(|arg| (*arg).to_string()).collect();
        }
        let mut args: Vec<String> = vec!["install".to_string()];
        args.push("--prefix".to_string());
        args.push(prefix.display().to_string());
        for arg in self.args {
            if matches!(*arg, "install" | "-g" | "--global") {
                continue;
            }
            args.push((*arg).to_string());
        }
        args
    }

    /// What one route does, as a line an operator reads back.
    ///
    /// This is the string every report row quotes, and the key `provision`
    /// deduplicates on, so two languages served by one route still ask once and
    /// run once.
    pub(crate) fn route_command_line(&self, route: InstallRoute) -> String {
        match route {
            InstallRoute::Installer => self.command_line(),
            InstallRoute::ManagedPrefix => {
                // The environment is part of the command for the Go route,
                // because GOBIN is the whole redirect. A printed `go install`
                // with the environment stripped is a command that installs
                // somewhere else, handed to an operator as the thing that ran.
                let environment: String = self
                    .managed_prefix_env()
                    .iter()
                    .map(|(key, value)| format!("{key}={value} "))
                    .collect();
                let arguments = self.managed_prefix_args(&self.managed_prefix_dir());
                format!("{environment}{} {}", self.program, arguments.join(" "))
            }
            InstallRoute::PinnedRelease => match self.fallback {
                Fallback::PinnedRelease(release) => format!(
                    "download {} {} from the {} release binaries",
                    release.binary, release.tag, release.project
                ),
                // Unreachable through `choose_route`, which only returns this
                // route for a recipe whose fallback is a pinned release. Stated
                // rather than panicked, because a report row is not worth an
                // abort.
                Fallback::ManagedPrefix => self.command_line(),
            },
        }
    }
}

/// What this host leaves open for a recipe, measured against the live machine.
///
/// The probe half of [`choose_route`], kept apart from the rule so the rule
/// stays decidable without a host. `default_target_blocked` costs an `npm
/// config get prefix` subprocess for the npm recipes and nothing for the rest.
pub(crate) fn resolve_host_routes(recipe: &LanguageServerRecipe) -> HostRoutes {
    let installer_on_path = recipe.installer_available();
    HostRoutes {
        installer_on_path,
        default_target_blocked: installer_on_path && install_blocker(recipe).is_some(),
        pinned_release_for_this_host: match recipe.fallback {
            Fallback::PinnedRelease(release) => language_server_release::host_target()
                .is_some_and(|target| release.asset_for(target).is_some()),
            Fallback::ManagedPrefix => false,
        },
    }
}

/// The route this host leaves open for a recipe, probing the machine.
pub(crate) fn resolve_route(recipe: &LanguageServerRecipe) -> Option<InstallRoute> {
    choose_route(recipe, resolve_host_routes(recipe))
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

/// The gopls module `go install` builds, pinned to a tag.
///
/// Pinned for the reason the typescript package is. `@latest` resolves to
/// whatever upstream tagged that morning, so two machines set up a week apart
/// index one repository with two different servers and nothing records which of
/// them produced an edge. The failure is invisible from the install side: both
/// runs exit zero, both put `gopls` on PATH, and only the graph disagrees.
///
/// A source pin rather than a binary one, because gopls is distributed as a Go
/// module rather than as prebuilt release assets. `go install` builds it with
/// the host's own toolchain, so this route adds nothing to Kin's release
/// archive and redistributes nothing.
const GOPLS_MODULE: &str = "golang.org/x/tools/gopls@v0.22.0";

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
        fallback: Fallback::PinnedRelease(&RUST_ANALYZER_RELEASE),
        disclosure: "adds a rustup component to the active toolchain",
    },
    LanguageServerRecipe {
        language: LanguageId::Python,
        binaries: &["pyright-langserver", "pylsp"],
        program: "npm",
        args: &["install", "-g", "pyright"],
        fallback: Fallback::ManagedPrefix,
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
        fallback: Fallback::ManagedPrefix,
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
        fallback: Fallback::ManagedPrefix,
        disclosure: "downloads the typescript-language-server and typescript npm packages into \
                     your global npm prefix",
    },
    LanguageServerRecipe {
        language: LanguageId::Go,
        binaries: &["gopls"],
        program: "go",
        args: &["install", GOPLS_MODULE],
        fallback: Fallback::ManagedPrefix,
        disclosure: "builds gopls from source with your Go toolchain and installs it into your \
                     Go bin directory",
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

/// Every language this build enriches with, whether or not its server is here.
///
/// The set [`missing_enrichable_languages`] is a subset of. A run that installed
/// nothing has to be able to name what was even in scope, because "nothing
/// happened" and "nothing was ever going to happen here" are different facts and
/// a reader acts differently on each.
pub(crate) fn enrichable_languages() -> Vec<LanguageId> {
    LANGUAGE_SERVERS
        .iter()
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

/// What Kin would actually do for each missing language on THIS host,
/// deduplicated.
///
/// The sibling of [`install_commands_for`], and the one to print at a person.
/// That function answers "what does this recipe say", which is the right answer
/// for a doc and the wrong one at a terminal: on a host with no rustup it prints
/// `rustup component add rust-analyzer`, an instruction to install a toolchain
/// in order to read somebody else's code. This one probes the host and prints
/// the route Kin has, which on that host is a pinned download.
pub(crate) fn route_commands_for(missing: &[LanguageId]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for language in missing {
        let Some(recipe) = recipe_for(*language) else {
            continue;
        };
        let command = match resolve_route(recipe) {
            Some(route) => recipe.route_command_line(route),
            // No route at all. The recipe's own command is still the honest
            // thing to print, because installing what it names is exactly what
            // would open one.
            None => recipe.command_line(),
        };
        if !seen.contains(&command) {
            seen.push(command);
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

/// What the operator is spending by saying yes to one ROUTE.
///
/// The recipe's own `disclosure` describes its installer, and it is the wrong
/// sentence for two of the three routes. "Adds a rustup component to the active
/// toolchain" is not what a pinned download does, and a person consenting to a
/// network fetch of a binary from a project's releases is owed the tag, the
/// digest and the directory rather than a sentence about a toolchain they do
/// not have.
pub(crate) fn route_disclosure(recipe: &LanguageServerRecipe, route: InstallRoute) -> String {
    match route {
        InstallRoute::Installer => recipe.disclosure.to_string(),
        // The Go route is not a redirected npm install and must not describe
        // itself as one. It builds from source with the operator's own
        // toolchain, and the reason it redirects is a PATH gap rather than a
        // permission one. Different spend, different repair, different sentence.
        InstallRoute::ManagedPrefix if recipe.redirects_through_gobin() => format!(
            "builds gopls from source with your Go toolchain and installs it into {}, a \
             directory Kin owns under KIN_HOME and already appends to PATH. An ordinary `go \
             install` writes into your Go bin directory instead, which this host's PATH does \
             not carry, and the daemon starts a language server with a bare `gopls`",
            kin_core::tool_prefix::managed_tool_bin_dir().display()
        ),
        InstallRoute::ManagedPrefix => format!(
            "runs the same install against {}, a prefix Kin owns under KIN_HOME, because this \
             host's global npm prefix refuses this user",
            kin_core::tool_prefix::managed_node_prefix().display()
        ),
        InstallRoute::PinnedRelease => match recipe.fallback {
            Fallback::PinnedRelease(release) => format!(
                "downloads {} {} from the {} release binaries, checks it against a sha256 \
                 recorded in Kin's own source, and installs it into {}. Your toolchain is not \
                 touched, and this route is taken because `{}` is not on this host.",
                release.binary,
                release.tag,
                release.project,
                kin_core::tool_prefix::managed_tool_bin_dir().display(),
                recipe.program,
            ),
            Fallback::ManagedPrefix => recipe.disclosure.to_string(),
        },
    }
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

/// Why one install could not be completed, separated by what a reader has to
/// do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallProblem {
    /// The installer ran, or the download was attempted, and it did not work.
    Failed { reason: String },
    /// Bytes arrived and are not the bytes Kin pins. Its own variant because it
    /// is the one failure that is never worth retrying and never the network's
    /// fault, and because a reader must not read it as a flaky download.
    ChecksumMismatch { reason: String },
}

/// What happened to one language's server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallOutcome {
    /// A binary for this language was already on `PATH`.
    AlreadyPresent,
    /// The install command ran and the binary is now on `PATH`.
    ///
    /// `evidence` is what the run can show for it: for a download Kin performed
    /// itself, the URL the bytes came from and the digest verified before they
    /// were written. Empty for a route where the disclosure belongs to the
    /// installer, which printed its own output live.
    Installed {
        command: String,
        evidence: Vec<String>,
    },
    /// Bytes were served and refused. Nothing was installed.
    ChecksumRefused { command: String, reason: String },
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
/// `route` reports which of a recipe's routes this host leaves open, and `None`
/// is the state that used to be the only answer for a host with no installer.
/// `ask` and `run` both take the route, because the disclosure and the work
/// differ by it: consenting to a rustup component and consenting to a download
/// from a release Kin pins are not the same consent.
///
/// `ask` is called at most once per distinct command, so consenting to
/// TypeScript does not produce a second prompt for JavaScript.
pub(crate) fn provision(
    missing: &[LanguageId],
    consent: InstallConsent,
    mut installed: impl FnMut(&LanguageServerRecipe) -> bool,
    mut route: impl FnMut(&LanguageServerRecipe) -> Option<InstallRoute>,
    mut ask: impl FnMut(&LanguageServerRecipe, InstallRoute) -> bool,
    mut run: impl FnMut(&LanguageServerRecipe, InstallRoute) -> Result<Vec<String>, InstallProblem>,
) -> Vec<InstallReport> {
    let mut reports = Vec::new();
    // Keyed on the command rather than the language: one npm install serves
    // both JavaScript and TypeScript, and running it twice would download the
    // same package again and ask twice for one decision.
    let mut decided: Vec<(String, bool)> = Vec::new();
    let mut ran: Vec<(String, Result<Vec<String>, InstallProblem>)> = Vec::new();

    for language in missing {
        let Some(recipe) = recipe_for(*language) else {
            continue;
        };

        if installed(recipe) {
            reports.push(InstallReport {
                language: *language,
                outcome: InstallOutcome::AlreadyPresent,
            });
            continue;
        }

        let Some(chosen) = route(recipe) else {
            reports.push(InstallReport {
                language: *language,
                outcome: InstallOutcome::NoInstaller {
                    program: recipe.program.to_string(),
                    command: recipe.command_line(),
                },
            });
            continue;
        };
        let command = recipe.route_command_line(chosen);

        let approved = match consent {
            InstallConsent::Granted => true,
            InstallConsent::Withheld => false,
            InstallConsent::Ask => match decided.iter().find(|(cmd, _)| cmd == &command) {
                Some((_, answer)) => *answer,
                None => {
                    let answer = ask(recipe, chosen);
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
                let result = run(recipe, chosen);
                ran.push((command.clone(), result.clone()));
                result
            }
        };

        let outcome = match result {
            Err(InstallProblem::ChecksumMismatch { reason }) => {
                InstallOutcome::ChecksumRefused { command, reason }
            }
            Err(InstallProblem::Failed { reason }) => InstallOutcome::Failed { command, reason },
            // Re-probe `PATH` rather than trusting the exit code. A global npm
            // prefix outside `PATH` installs successfully and leaves the binary
            // unreachable, which is the shape of success that would let doctor
            // report a closed gap that is still open.
            Ok(evidence) if installed(recipe) => InstallOutcome::Installed { command, evidence },
            Ok(_) => InstallOutcome::RanButStillMissing { command },
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

/// Where a bare `go install` would put the binary.
///
/// `GOBIN` when the toolchain has one, otherwise `$(go env GOPATH)/bin`. Asked
/// of the toolchain rather than assembled from `$HOME`, because GOPATH is
/// configurable and a guess would name the wrong directory in the one message
/// whose whole job is to name the right one. `None` when there is no `go` to
/// ask, which is the same host state `installer_available` already reports.
fn go_default_bin_dir() -> Option<PathBuf> {
    let output = Command::new("go")
        .args(["env", "GOBIN", "GOPATH"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let gobin = lines.next().unwrap_or_default().trim();
    if !gobin.is_empty() {
        return Some(PathBuf::from(gobin));
    }
    let gopath = lines.next().unwrap_or_default().trim();
    if gopath.is_empty() {
        return None;
    }
    Some(PathBuf::from(gopath).join("bin"))
}

/// Whether a binary installed into `dir` would be reachable from `path`.
///
/// Pure over its inputs, so the rule that decides Go's route is decidable with
/// no host, no toolchain and no subprocess, exactly as [`choose_route`] is.
pub(crate) fn directory_is_on_path(dir: &Path, path: Option<&OsString>) -> bool {
    path.is_some_and(|value| std::env::split_paths(value).any(|entry| entry == dir))
}

/// The reason a bare `go install` cannot close this gap, stated before it runs.
///
/// `go install` has no prefix flag and nothing resolves for it afterwards. It
/// writes into `$(go env GOPATH)/bin`, which nothing puts on `PATH` by default,
/// and `kin_lsp::lifecycle::LspServer::start` runs the bare string `gopls` with
/// no `which` and no GOPATH fallback. So the ordinary install succeeds and the
/// daemon still starts nothing: the same exit-zero-over-an-open-gap the npm
/// prefix blocker exists for, arriving through a different door.
pub(crate) fn go_default_bin_blocker(dir: &Path, path: Option<&OsString>) -> Option<String> {
    if directory_is_on_path(dir, path) {
        return None;
    }
    Some(format!(
        "`go install` writes gopls into {}, which is not on this process's PATH, and the daemon \
         starts a language server with a bare `gopls` and no GOPATH fallback, so a server \
         installed there is one nothing can start",
        dir.display()
    ))
}

/// Why this install cannot succeed, known before it is attempted.
///
/// The npm recipes have the one a container hits: the Node base images set the
/// global prefix to `/usr/local`, whose `lib/node_modules` is owned by root, and
/// a Kin running as an unprivileged user cannot write there. Attempting it
/// anyway spends the download and ends in npm's own EACCES trace, which reads as
/// a Kin defect and names no remedy.
///
/// Go's is the same failure with a different cause: the install succeeds and
/// lands somewhere nothing reads. Both are "running this installer against its
/// own default target cannot close the gap", which is what
/// `HostRoutes::default_target_blocked` means and what routes each of them to a
/// destination Kin owns.
fn install_blocker(recipe: &LanguageServerRecipe) -> Option<String> {
    if recipe.redirects_through_gobin() {
        return go_default_bin_blocker(&go_default_bin_dir()?, std::env::var_os("PATH").as_ref());
    }
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

/// Whether a failure is the network refusing the installer rather than the
/// installer refusing the package, and in which of its three shapes.
///
/// Matched against the installer's own words, because that is all Kin has: npm
/// and rustup both exit non-zero with the cause in stderr and nothing in the
/// status. The signatures are the shapes a proxied or filtered network
/// produces, split three ways because they are three different fixes. A
/// connection that never completes is routing, a certificate that will not
/// verify is a proxy re-signing TLS, and a 403 or 407 from a registry that
/// answered is an allowlist or proxy credentials.
///
/// Deliberately checked AFTER `is_permission_failure`: an EACCES that also
/// mentions a registry URL is still a permission failure, and its remedy is the
/// one that moves the prefix. `None` when nothing in the reason looks like the
/// network.
pub(crate) fn network_shape(reason: &str) -> Option<&'static str> {
    const UNREACHABLE: [&str; 12] = [
        "etimedout",
        "esockettimedout",
        "econnrefused",
        "econnreset",
        "enotfound",
        "eai_again",
        "ehostunreach",
        "enetunreach",
        "socket hang up",
        "network request to",
        "error network",
        "could not download",
    ];
    const TLS: [&str; 7] = [
        "self signed certificate",
        "self-signed certificate",
        "unable to get local issuer",
        "unable to verify the first certificate",
        "cert_",
        "depth_zero_self_signed_cert",
        "ssl routines",
    ];
    const REFUSED_BY_A_MIDDLEBOX: [&str; 6] = [
        "e403",
        "403 forbidden",
        "e407",
        "407 proxy",
        "proxy authentication required",
        "tunneling socket could not be established",
    ];
    let lowered = reason.to_lowercase();
    let has = |signatures: &[&str]| {
        signatures
            .iter()
            .any(|signature| lowered.contains(signature))
    };
    if has(&TLS) {
        return Some(
            "a TLS certificate this host would not verify, which is what a proxy that \
                     re-signs traffic looks like",
        );
    }
    if has(&REFUSED_BY_A_MIDDLEBOX) {
        return Some(
            "a server that answered and refused, which is what a proxy or a registry \
                     allowlist looks like",
        );
    }
    if has(&UNREACHABLE) {
        return Some(
            "a connection that never completed, which is what a blocked or unrouted \
                     network looks like",
        );
    }
    None
}

/// What Kin still does when a language server is not installed.
///
/// The half FIR-2629 found missing. A failed install told an operator what
/// broke and left them to guess whether Kin was now useless, which it is not:
/// the parse-derived graph is unaffected, and the loss is bounded and named.
pub(crate) const WORKS_WITHOUT_LANGUAGE_SERVERS: &str =
    "Kin runs without this server. Parsing, search, history, review and commits are unaffected; \
     what is missing is cross-file reference enrichment for that language, which Kin reports as \
     pending rather than certifying that no reference exists.";

/// Every binary this recipe's language is satisfied by, as a reader would say them.
///
/// One name on its own, two joined by "or", and a comma list beyond that. Each
/// name is wrapped in backticks because these are literal binaries to type, and
/// a bare pylsp in a sentence reads as a typo rather than as a command.
fn quoted_or_list(names: &[&str]) -> String {
    let quoted: Vec<String> = names.iter().map(|name| format!("`{name}`")).collect();
    match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
    }
}

/// The route to a working server that needs no registry at all.
///
/// The other half FIR-2629 asks for by name, beside the degraded mode: the
/// offline path. Kin has a real one and it is worth stating, because discovery
/// is `which` over `PATH` and nothing else, so a server carried in from an
/// internal mirror, baked into an image layer or copied off another machine
/// counts the moment `PATH` can see it. Named by BINARY rather than by package,
/// because the binary name is what discovery matches.
fn offline_install_path(recipe: &LanguageServerRecipe) -> String {
    format!(
        "no registry is needed either: Kin looks for {} on PATH and starts whichever it finds, \
         so a copy from an internal mirror, an image layer or another machine closes this gap \
         with the network still down",
        quoted_or_list(recipe.binaries)
    )
}

/// The environment every installer here reads to route through a proxy.
///
/// Per program, because they do not agree. npm reads its own config keys as
/// well as the environment, and rustup reads only the lowercase environment
/// variables. Printing one blanket list would send half of its readers to a
/// setting their installer ignores.
fn proxy_environment_lines(program: &str) -> Vec<String> {
    let mut lines = vec![
        "    export HTTPS_PROXY=http://proxy.example:3128 HTTP_PROXY=http://proxy.example:3128"
            .to_string(),
        "    export NO_PROXY=localhost,127.0.0.1".to_string(),
    ];
    if program == "npm" {
        lines.push(
            "    npm config set proxy \"$HTTP_PROXY\"; npm config set https-proxy \
             \"$HTTPS_PROXY\""
                .to_string(),
        );
        lines.push(
            "    export NODE_EXTRA_CA_CERTS=/path/to/proxy-ca.pem   # when the proxy re-signs TLS"
                .to_string(),
        );
    } else {
        // rustup reads the lowercase spellings only and takes its certificate
        // bundle from the OS store; the Go toolchain reads either case and its
        // module fetches honour the same pair. Neither reads npm's config, so
        // quoting npm's keys at them is advice that does nothing.
        lines
            .push("    export https_proxy=\"$HTTPS_PROXY\" http_proxy=\"$HTTP_PROXY\"".to_string());
    }
    lines
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
        // A network shape is named before the generic advice, because "run it
        // yourself to see the error" is worthless when the error is the one
        // already printed and the cause is the environment rather than the
        // command (FIR-2629).
        if let Some(shape) = network_shape(reason) {
            let mut lines = vec![
                format!(
                    "this is the network refusing `{command}`, not Kin and not the package: \
                     {shape}"
                ),
                "if this host reaches the internet through a proxy, name it where the installer \
                 reads it, then run the command again:"
                    .to_string(),
            ];
            lines.extend(proxy_environment_lines(recipe.program));
            lines.push(offline_install_path(recipe));
            lines.push(WORKS_WITHOUT_LANGUAGE_SERVERS.to_string());
            return lines;
        }
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

/// Perform one recipe's install along the route this host left open.
///
/// Three routes, one contract: the returned lines are what the run can SHOW for
/// what it did, and an error is either an ordinary failure or a digest that did
/// not match. Nothing here reports success it did not verify; `provision`
/// re-probes `PATH` afterwards either way, because a package manager that
/// wrote to a prefix nothing reads exits zero.
pub(crate) fn run_install(
    recipe: &LanguageServerRecipe,
    route: InstallRoute,
) -> Result<Vec<String>, InstallProblem> {
    match route {
        InstallRoute::Installer => {
            if let Some(blocker) = install_blocker(recipe) {
                return Err(InstallProblem::Failed { reason: blocker });
            }
            run_program(
                recipe,
                recipe.program,
                &recipe
                    .args
                    .iter()
                    .map(|a| (*a).to_string())
                    .collect::<Vec<_>>(),
                &[],
                &recipe.command_line(),
            )
            .map(|()| Vec::new())
        }
        InstallRoute::ManagedPrefix => {
            let prefix = recipe.managed_prefix_dir();
            std::fs::create_dir_all(&prefix).map_err(|error| InstallProblem::Failed {
                reason: format!("could not create {}: {error}", prefix.display()),
            })?;
            let args = recipe.managed_prefix_args(&prefix);
            let command = recipe.route_command_line(route);
            let environment = recipe.managed_prefix_env();
            run_program(recipe, recipe.program, &args, &environment, &command).map(|()| {
                vec![
                    format!("source:   {}", recipe.managed_route_source()),
                    format!(
                        "installed to: {}",
                        recipe.managed_prefix_bin_dir().display()
                    ),
                ]
            })
        }
        InstallRoute::PinnedRelease => {
            let Fallback::PinnedRelease(release) = recipe.fallback else {
                return Err(InstallProblem::Failed {
                    reason: format!(
                        "{}: no pinned release binary is recorded for this language",
                        recipe.language
                    ),
                });
            };
            let bin_dir = kin_core::tool_prefix::managed_tool_bin_dir();
            let target = language_server_release::host_target();
            let Some(asset) = target.and_then(|target| release.asset_for(target)) else {
                return Err(InstallProblem::Failed {
                    reason: language_server_release::InstallFailure::UnsupportedHost {
                        target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                    }
                    .reason(),
                });
            };
            let (base, expected) = language_server_release::resolve_source_from_env(release, asset);
            match language_server_release::install_pinned_release(
                release, target, &bin_dir, &base, &expected,
            ) {
                Ok(install) => Ok(install.evidence_lines()),
                Err(failure @ language_server_release::InstallFailure::ChecksumMismatch { .. }) => {
                    Err(InstallProblem::ChecksumMismatch {
                        reason: failure.reason(),
                    })
                }
                Err(failure) => Err(InstallProblem::Failed {
                    reason: failure.reason(),
                }),
            }
        }
    }
}

/// Run one installer, streaming its own output and keeping its words on a
/// failure.
///
/// Two things happen here that a bare `status()` cannot do. Stderr is teed
/// rather than inherited, so the operator still reads the installer live while
/// a failure keeps the installer's own words for the report at the end: a
/// reason that says only "exited with 243" sends someone back to scroll a
/// terminal for the cause (FIR-2547). And the command as an operator would type
/// it is passed in rather than recomposed, so a redirected install reports the
/// command that actually ran.
fn run_program(
    recipe: &LanguageServerRecipe,
    program: &str,
    args: &[String],
    environment: &[(String, String)],
    command_line: &str,
) -> Result<(), InstallProblem> {
    let _ = recipe;
    // Set rather than inherited, because one route's redirect lives here: `go
    // install` takes no prefix argument and writes wherever GOBIN says. The npm
    // routes pass an empty slice and keep the environment they already had.
    let mut child = Command::new(program)
        .args(args)
        .envs(environment.iter().cloned())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| InstallProblem::Failed {
            reason: format!("could not run `{command_line}`: {error}"),
        })?;
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
    let status = child.wait().map_err(|error| InstallProblem::Failed {
        reason: format!("could not wait for `{command_line}`: {error}"),
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(InstallProblem::Failed {
            reason: installer_failure_reason(command_line, status.code(), &stderr_lines),
        })
    }
}

/// A dependency the installed server itself needs, which Kin did not install.
///
/// Installing the server is not the same as the server being able to answer,
/// and for Rust the difference is total. rust-analyzer loads a workspace by
/// running `cargo metadata`; with no `cargo` on PATH it starts, completes a
/// handshake, reports itself available, and loads no project at all, so every
/// reference query comes back empty from a server that is running. Its own
/// words on such a host are "Failed to load the project at Cargo.toml", caused
/// by `cargo locate-project` failing.
///
/// Measured on 2026-08-28 in a Debian 12 container on `tokio-rs/axum` at
/// `8f6bb9ce`, twice from a fresh store with only this variable changed. With
/// cargo: `calls 3498/11883 (29%)`, `cross-file 5345`, and `find_references`
/// on `Router` answers. Without it: `calls 2191/11883 (18%)`, `cross-file
/// 1557`, and the same query answers zero.
///
/// Kin does not install a language toolchain on a user's machine, so the only
/// honest move is to name the gap beside the install that did not close it.
/// `present` is taken as an argument so a test states the host it asserts
/// against rather than inheriting whichever machine ran it.
pub(crate) fn unmet_runtime_dependency(
    recipe: &LanguageServerRecipe,
    present: impl Fn(&str) -> bool,
) -> Option<String> {
    if recipe.language != LanguageId::Rust || present("cargo") {
        return None;
    }
    Some(
        "the rust language server is installed and cannot resolve this project yet: \
         rust-analyzer loads a Rust workspace by running `cargo metadata`, and no `cargo` is \
         on PATH. Cross-file Rust reference edges stay parse-derived until a Rust toolchain is \
         installed, so `find_references` on a Rust symbol will keep answering empty and Kin \
         will keep reporting that answer as inconclusive rather than as an absence."
            .to_string(),
    )
}

/// The remedy for the gap [`unmet_runtime_dependency`] names.
pub(crate) fn runtime_dependency_remedy() -> Vec<String> {
    vec![
        "install a Rust toolchain, which is what rust-analyzer reads the project through:"
            .to_string(),
        "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh".to_string(),
        format!("then {RESTART_AFTER_INSTALL}"),
        WORKS_WITHOUT_LANGUAGE_SERVERS.to_string(),
    ]
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
        assert_eq!(
            recipe_for(LanguageId::Go).unwrap().command_line(),
            "go install golang.org/x/tools/gopls@v0.22.0"
        );
    }

    /// The gopls module must never be installed unpinned.
    ///
    /// `@latest` resolves to whatever upstream tagged that morning, so two
    /// machines set up a week apart index one repository with two different
    /// servers and nothing records which of them produced an edge. The same
    /// argument the TypeScript pin exists for, and the same failure shape: both
    /// installs exit zero, both put the binary on PATH, and only the graph
    /// disagrees. `go install` with no `@version` is a hard error rather than a
    /// silent latest, so the case this guards is a bare `@latest` somebody
    /// wrote to stop thinking about the tag.
    #[test]
    fn the_gopls_module_is_pinned_to_a_tag_rather_than_to_latest() {
        let recipe = recipe_for(LanguageId::Go).expect("go must have a recipe");
        let module = recipe
            .args
            .iter()
            .find(|arg| arg.starts_with("golang.org/x/tools/gopls"))
            .expect("the go recipe must install the gopls module");
        let (_, version) = module
            .split_once('@')
            .unwrap_or_else(|| panic!("{module}: `go install` needs an explicit @version"));
        assert_ne!(
            version, "latest",
            "{module}: an unpinned gopls gives two machines two different servers with nothing \
             recording why"
        );
        assert!(
            version.starts_with('v') && version[1..].starts_with(|c: char| c.is_ascii_digit()),
            "{module}: the gopls module must carry an explicit vX.Y.Z tag, got `{version}`"
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

    /// A proxied network gets the environment named, not "run it yourself".
    ///
    /// The container the npm0549 stranger worked in reached the registry
    /// through a proxy, and `kin doctor --fix --install-language-servers` came
    /// back with four failures whose only advice was to run the same command
    /// again by hand (FIR-2629). The command was never the problem, so the
    /// advice could not work: what an operator needs is the suspicion that the
    /// environment is the cause, the variables their installer actually reads,
    /// and the size of what they lose by stopping here.
    ///
    /// Falsify by deleting the `network_shape` branch in
    /// `install_failure_remediation`: the reason falls through to the generic
    /// line and every assertion below fails.
    #[test]
    fn a_network_failure_names_the_environment_the_proxy_vars_and_what_still_works() {
        let recipe = recipe_for(LanguageId::Python).expect("python must have a recipe");
        let lines = install_failure_remediation(
            recipe,
            "`npm install -g pyright` exited with 1: npm error code ECONNREFUSED; npm error \
             network request to https://registry.npmjs.org/pyright failed, reason: connect \
             ECONNREFUSED 127.0.0.1:443",
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("the network refusing"),
            "the cause must be attributed to the environment: {joined}"
        );
        assert!(
            joined.contains("HTTPS_PROXY") && joined.contains("NO_PROXY"),
            "the variables that would route it must be named: {joined}"
        );
        assert!(
            joined.contains("npm config set https-proxy"),
            "npm reads its own config as well as the environment: {joined}"
        );
        assert!(
            joined.contains("NODE_EXTRA_CA_CERTS"),
            "a proxy that re-signs TLS needs its bundle named: {joined}"
        );
        assert!(
            joined.contains("Kin runs without this server"),
            "the degraded mode must be stated, not left to be guessed: {joined}"
        );
        assert!(
            joined.contains("no registry is needed either")
                && joined.contains("pyright-langserver")
                && joined.contains("pylsp"),
            "the offline path must be named, by the binaries discovery accepts: {joined}"
        );

        // Falsification control. A permission remedy here would mean the two
        // classifiers cannot tell their own cases apart.
        assert!(
            !joined.contains("npm config set prefix"),
            "a network failure must not be handed the permission remedy: {joined}"
        );
        assert!(!joined.contains("sudo"), "{joined}");
    }

    /// Each network shape is named as its own fix, and nothing else matches.
    ///
    /// Three shapes because they are three different repairs, and a classifier
    /// that collapsed them would send a TLS interception to a routing fix. The
    /// negative cases are the point: a 404, an EACCES and a compiler error must
    /// all read as not-the-network, or the diagnosis is decoration.
    #[test]
    fn the_network_classifier_separates_its_three_shapes_and_refuses_everything_else() {
        let unreachable = network_shape("npm error network request to https://r/x failed")
            .expect("an unrouted network must classify");
        assert!(unreachable.contains("never completed"), "{unreachable}");

        let tls = network_shape(
            "npm error code SELF_SIGNED_CERT_IN_CHAIN; npm error self signed certificate in \
             certificate chain",
        )
        .expect("an intercepted TLS handshake must classify");
        assert!(tls.contains("TLS certificate"), "{tls}");

        let refused =
            network_shape("npm error code E403; npm error 403 Forbidden - GET https://r/x")
                .expect("a middlebox refusal must classify");
        assert!(refused.contains("answered and refused"), "{refused}");

        assert_eq!(
            network_shape("npm error code E404; npm error 404 Not Found - GET https://r/x"),
            None,
            "a package that does not exist is not a network failure"
        );
        assert_eq!(
            network_shape(
                "npm error code EACCES; npm error Error: EACCES: permission denied, mkdir \
                 '/usr/local/lib/node_modules/pyright'"
            ),
            None,
            "a permission failure must keep its own remedy"
        );
        assert_eq!(
            network_shape("error: could not compile `pyright`"),
            None,
            "an unrelated failure must not be dressed as a proxy problem"
        );
    }

    /// rustup and npm are told about different variables.
    ///
    /// rustup reads only the lowercase environment spellings and takes its
    /// certificate bundle from the OS store, so quoting npm's config keys at a
    /// rustup failure is advice that does nothing. One blanket list would be
    /// wrong for whichever half read it second.
    #[test]
    fn the_proxy_advice_matches_the_installer_that_failed() {
        let rust = recipe_for(LanguageId::Rust).expect("rust must have a recipe");
        let lines = install_failure_remediation(
            rust,
            "`rustup component add rust-analyzer` exited with 1: error: could not download file \
             from 'https://static.rust-lang.org/x': ETIMEDOUT",
        );
        let joined = lines.join("\n");
        assert!(joined.contains("https_proxy"), "{joined}");
        assert!(
            !joined.contains("npm config set"),
            "rustup does not read npm config: {joined}"
        );
        assert!(
            !joined.contains("NODE_EXTRA_CA_CERTS"),
            "rustup does not read Node's certificate variable: {joined}"
        );
        assert!(joined.contains("Kin runs without this server"), "{joined}");
        assert!(joined.contains("`rust-analyzer`"), "{joined}");
        assert!(
            !joined.contains("pyright-langserver"),
            "a rustup failure must not be handed npm's binaries: {joined}"
        );
    }

    /// The offline path names what discovery matches, and only that.
    ///
    /// A language satisfied by two binaries has to say both, because a reader
    /// who already has `pylsp` should not go looking for pyright. A language
    /// satisfied by one must not read as a list, which is the case a naive
    /// join gets wrong.
    #[test]
    fn the_offline_path_names_every_binary_discovery_accepts() {
        let python = recipe_for(LanguageId::Python).expect("python must have a recipe");
        let listed = offline_install_path(python);
        assert!(
            listed.contains("`pyright-langserver` or `pylsp`"),
            "both binaries must be named: {listed}"
        );

        let rust = recipe_for(LanguageId::Rust).expect("rust must have a recipe");
        let single = offline_install_path(rust);
        assert!(single.contains("`rust-analyzer`"), "{single}");
        assert!(
            !single.contains("` or `"),
            "a one-binary recipe must not read as a list: {single}"
        );

        // Falsification. An empty recipe would satisfy every `!contains` above,
        // so the joiner is asserted on directly as well.
        assert_eq!(quoted_or_list(&[]), "");
        assert_eq!(quoted_or_list(&["a", "b", "c"]), "`a`, `b` or `c`");
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
    fn installer_present(_: &LanguageServerRecipe) -> Option<InstallRoute> {
        Some(InstallRoute::Installer)
    }
    fn no_route(_: &LanguageServerRecipe) -> Option<InstallRoute> {
        None
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
            |_, _| panic!("must not prompt when consent is withheld"),
            |_, _| {
                runs += 1;
                Ok(Vec::new())
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
            |_, _| false,
            |_, _| {
                runs += 1;
                Ok(Vec::new())
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
            |_, _| {
                prompts += 1;
                true
            },
            |_, _| {
                runs += 1;
                Ok(Vec::new())
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
            |_, _| panic!("granted consent must not prompt"),
            |_, _| {
                ran.set(true);
                Ok(Vec::new())
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
            |_, _| true,
            |_, _| Ok(Vec::new()),
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
            |_, _| true,
            |_, _| {
                Err(InstallProblem::Failed {
                    reason: "network unreachable".to_string(),
                })
            },
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
            no_route,
            |_, _| panic!("must not prompt when no route is open"),
            |_, _| {
                runs += 1;
                Ok(Vec::new())
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
            |_, _| panic!("must not prompt for something already installed"),
            |_, _| {
                runs += 1;
                Ok(Vec::new())
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

    // ---- the dependency the installed server itself needs ------------------

    /// Rust with no cargo is named; Rust with cargo is silent.
    ///
    /// The container proof is what this encodes. Installing rust-analyzer on a
    /// host with no toolchain leaves a server that starts and loads nothing, and
    /// a run that reported only "installed" would be telling a reader their
    /// reference edges are coming.
    #[test]
    fn rust_without_cargo_is_named_and_rust_with_cargo_is_not() {
        let rust = recipe_for(LanguageId::Rust).expect("rust must have a recipe");
        let gap = unmet_runtime_dependency(rust, |_| false)
            .expect("a host with no cargo must be told what the server still cannot do");
        assert!(gap.contains("cargo metadata"), "{gap}");
        assert!(
            gap.contains("parse-derived"),
            "the reader must be told what they still have: {gap}"
        );
        assert_eq!(
            unmet_runtime_dependency(rust, |program| program == "cargo"),
            None,
            "a host with cargo has no gap to name"
        );
    }

    /// No other language claims a toolchain dependency it does not have.
    ///
    /// The control. A check that named a gap for every language would fire on
    /// every host and be wallpaper, and the npm-served servers genuinely need
    /// nothing beyond Node, which installing them already proved present.
    #[test]
    fn the_npm_served_languages_name_no_toolchain_gap() {
        for language in [
            LanguageId::Python,
            LanguageId::TypeScript,
            LanguageId::JavaScript,
        ] {
            let recipe = recipe_for(language).expect("recipe must exist");
            assert_eq!(
                unmet_runtime_dependency(recipe, |_| false),
                None,
                "{language}: no toolchain gap exists for an npm-served server"
            );
        }
    }

    /// The remedy names the toolchain installer and the restart, and says what
    /// still works.
    #[test]
    fn the_toolchain_remedy_names_the_installer_and_the_restart() {
        let lines = runtime_dependency_remedy().join("\n");
        assert!(lines.contains("sh.rustup.rs"), "{lines}");
        assert!(lines.contains("kin daemon stop"), "{lines}");
        assert!(lines.contains("Kin runs without this server"), "{lines}");
    }

    // ---- route selection --------------------------------------------------

    fn host(installer: bool, blocked: bool, pinned: bool) -> HostRoutes {
        HostRoutes {
            installer_on_path: installer,
            default_target_blocked: blocked,
            pinned_release_for_this_host: pinned,
        }
    }

    /// The host the cold walkthrough measured: node and npm present, no rustup.
    ///
    /// This is the finding, stated as a test. On 2026-08-28 a stranger followed
    /// the documented install on exactly this host and `kin doctor --fix
    /// --install-language-servers` exited 1 with "'rustup' is not installed on
    /// this host", leaving a Rust repository at `imports 0/1085 (0%)`. Rust must
    /// now route to the pinned release, and the npm-served languages must keep
    /// the installer they already had, because changing those would be a
    /// regression dressed as a fix.
    #[test]
    fn a_host_with_npm_and_no_rustup_gets_every_language_a_route() {
        let rust = recipe_for(LanguageId::Rust).expect("rust must have a recipe");
        assert_eq!(
            choose_route(rust, host(false, false, true)),
            Some(InstallRoute::PinnedRelease),
            "a host with no rustup must still get a Rust language server"
        );
        for language in [
            LanguageId::Python,
            LanguageId::TypeScript,
            LanguageId::JavaScript,
        ] {
            let recipe = recipe_for(language).expect("recipe must exist");
            assert_eq!(
                choose_route(recipe, host(true, false, false)),
                Some(InstallRoute::Installer),
                "{language}: a working npm must keep its own route"
            );
        }
    }

    /// rustup wins wherever it exists.
    ///
    /// The direction matters as much as the fallback. A rustup component tracks
    /// the toolchain that compiles the repository and Kin's pinned copy does
    /// not, so a host that has rustup must never be quietly moved onto Kin's
    /// download.
    #[test]
    fn the_recipes_own_installer_outranks_kins_fallback() {
        let rust = recipe_for(LanguageId::Rust).expect("rust must have a recipe");
        assert_eq!(
            choose_route(rust, host(true, false, true)),
            Some(InstallRoute::Installer),
            "a host with rustup must get the rustup component"
        );
    }

    /// An npm whose global prefix refuses this user is redirected, not refused.
    ///
    /// The container case: a Node base image sets the global prefix to
    /// `/usr/local`, whose `lib/node_modules` is owned by root. Before this
    /// route the install was correctly refused before it spent the download,
    /// and correctly refused is still no language server.
    #[test]
    fn a_blocked_npm_prefix_routes_to_a_prefix_kin_owns() {
        for language in [
            LanguageId::Python,
            LanguageId::TypeScript,
            LanguageId::JavaScript,
        ] {
            let recipe = recipe_for(language).expect("recipe must exist");
            assert_eq!(
                choose_route(recipe, host(true, true, false)),
                Some(InstallRoute::ManagedPrefix),
                "{language}: a prefix this user cannot write must not end the attempt"
            );
        }
    }

    /// A blocked rustup falls to the pinned release rather than to nothing.
    #[test]
    fn a_blocked_rust_installer_still_reaches_the_pinned_release() {
        let rust = recipe_for(LanguageId::Rust).expect("rust must have a recipe");
        assert_eq!(
            choose_route(rust, host(true, true, true)),
            Some(InstallRoute::PinnedRelease)
        );
    }

    /// The cases that genuinely leave no route, so the refusal is still real.
    ///
    /// A rule that always answers `Some` is a rule that has stopped deciding.
    /// Two hosts must still come back with nothing: a Rust host Kin pins no
    /// binary for, and a machine with no Node at all, where the only honest
    /// move is to say so rather than install a language runtime unasked.
    #[test]
    fn a_host_that_leaves_no_route_open_is_still_refused() {
        let rust = recipe_for(LanguageId::Rust).expect("rust must have a recipe");
        assert_eq!(
            choose_route(rust, host(false, false, false)),
            None,
            "no rustup and no pinned binary for this host is a real refusal"
        );
        let python = recipe_for(LanguageId::Python).expect("python must have a recipe");
        assert_eq!(
            choose_route(python, host(false, false, false)),
            None,
            "no npm means no Node, and Kin does not install a runtime unasked"
        );
        assert_eq!(
            choose_route(python, host(false, false, true)),
            None,
            "a pinned-release flag must not rescue a recipe with no pinned release"
        );
    }

    /// The managed-prefix command is the same install, redirected, pin intact.
    ///
    /// The TypeScript 5.x pin is the reason this is asserted rather than
    /// assumed. Every copy of the install command that drops it walks the
    /// operator into a TypeScript 7 that ships no `lib/tsserver.js`, and this
    /// route rewrites the argument list, which is exactly where a pin gets
    /// lost.
    #[test]
    fn the_managed_prefix_command_keeps_the_packages_and_their_pin() {
        let recipe = recipe_for(LanguageId::TypeScript).expect("typescript must have a recipe");
        let args = recipe.managed_prefix_args(Path::new("/home/u/.kin/tools/node"));
        assert_eq!(
            args,
            vec![
                "install".to_string(),
                "--prefix".to_string(),
                "/home/u/.kin/tools/node".to_string(),
                "typescript-language-server".to_string(),
                "typescript@^5".to_string(),
            ],
            "the global flag is dropped, the prefix inserted, and the packages untouched"
        );
        assert!(
            !args.contains(&"-g".to_string()),
            "a redirected install must not also be global"
        );
    }

    /// The Go managed route installs where Kin has already put PATH.
    ///
    /// This is the half of the ticket that wiring the adapter does not close.
    /// `kin_lsp::lifecycle::LspServer::start` runs the bare string `gopls`, an
    /// ordinary `go install` writes into `$(go env GOPATH)/bin`, and nothing
    /// puts that directory on PATH. Both Kin binaries call
    /// `augment_path_with_managed_tools` at startup, which appends
    /// `managed_tool_bin_dir`, so pointing GOBIN there is what makes an
    /// installed server one the daemon can actually start.
    #[test]
    fn the_go_managed_route_points_gobin_at_a_directory_kin_puts_on_path() {
        let go = recipe_for(LanguageId::Go).expect("go must have a recipe");
        let bin = kin_core::tool_prefix::managed_tool_bin_dir();

        assert_eq!(
            go.managed_prefix_env(),
            vec![("GOBIN".to_string(), bin.display().to_string())],
            "GOBIN is the only redirect `go install` has"
        );
        assert_eq!(go.managed_prefix_bin_dir(), bin);
        assert!(
            kin_core::tool_prefix::managed_tool_dirs().contains(&bin),
            "the directory GOBIN names has to be one PATH actually gains, or this route reports \
             success over a server nothing can start"
        );

        // The command an operator reads back has to be the command that ran,
        // environment included. A printed `go install` with GOBIN stripped
        // sends them to install into the directory this route exists to avoid.
        let line = go.route_command_line(InstallRoute::ManagedPrefix);
        assert_eq!(
            line,
            format!("GOBIN={} go install {GOPLS_MODULE}", bin.display()),
            "the redirect and the pin both have to survive the rewrite"
        );

        // The control, and the reason this is not a blanket change: the npm
        // route keeps the shape it had, with no environment and the same
        // `--prefix` rewrite.
        let typescript = recipe_for(LanguageId::TypeScript).expect("typescript must have a recipe");
        assert!(typescript.managed_prefix_env().is_empty());
        assert_eq!(
            typescript.managed_prefix_bin_dir(),
            kin_core::tool_prefix::managed_node_bin_dir()
        );
        assert!(
            typescript
                .route_command_line(InstallRoute::ManagedPrefix)
                .starts_with("npm install --prefix "),
            "the npm route must be untouched by the Go branch"
        );
    }

    /// A Go bin directory off PATH routes the install to the prefix Kin owns.
    ///
    /// The blocker is what makes `choose_route` prefer the managed route here.
    /// Without it the recipe's own installer wins on every host that has Go:
    /// the build succeeds, gopls lands in `$(go env GOPATH)/bin`, and the daemon
    /// still starts nothing, which is the gap wearing a green install's
    /// clothes. Asserted over an explicit PATH rather than this process's, so
    /// the test states the host it grades instead of inheriting whichever
    /// machine ran it.
    #[test]
    fn a_go_bin_directory_off_path_routes_the_install_to_the_prefix_kin_owns() {
        let dir = Path::new("/home/u/go/bin");

        let elsewhere = OsString::from("/usr/local/bin:/usr/bin");
        let blocker = go_default_bin_blocker(dir, Some(&elsewhere))
            .expect("a Go bin directory off PATH must be named before the install runs");
        assert!(blocker.contains("/home/u/go/bin"), "{blocker}");
        assert!(
            blocker.contains("not on this process's PATH"),
            "the reason has to name the mechanism rather than only refuse: {blocker}"
        );

        // Controls, in both directions. A host that already carries the
        // directory must keep its own toolchain's install, and a check that
        // reported a blocker for every host would route everyone through Kin's
        // prefix and prove nothing.
        let carrying = OsString::from("/usr/bin:/home/u/go/bin");
        assert_eq!(go_default_bin_blocker(dir, Some(&carrying)), None);
        assert!(directory_is_on_path(dir, Some(&carrying)));
        assert!(!directory_is_on_path(dir, None));

        let go = recipe_for(LanguageId::Go).expect("go must have a recipe");
        assert_eq!(
            choose_route(go, host(true, true, false)),
            Some(InstallRoute::ManagedPrefix),
            "a Go toolchain whose bin directory PATH does not carry must reach the managed route"
        );
        assert_eq!(
            choose_route(go, host(true, false, false)),
            Some(InstallRoute::Installer),
            "a host whose PATH already carries it keeps its own toolchain's install"
        );
        assert_eq!(
            choose_route(go, host(false, false, false)),
            None,
            "no Go toolchain means no route: Kin does not install a language toolchain unasked"
        );
    }

    /// Two languages behind one redirected install still ask and run once.
    ///
    /// The deduplication key moved from the recipe's command to the route's
    /// command, and a key that no longer collides would download the same npm
    /// package twice and prompt twice for one decision.
    #[test]
    fn one_redirected_install_serves_both_javascript_and_typescript() {
        let mut prompts = 0;
        let mut runs = 0;
        let reports = provision(
            &[LanguageId::TypeScript, LanguageId::JavaScript],
            InstallConsent::Ask,
            nothing_installed,
            |_| Some(InstallRoute::ManagedPrefix),
            |_, route| {
                assert_eq!(route, InstallRoute::ManagedPrefix);
                prompts += 1;
                true
            },
            |_, _| {
                runs += 1;
                Ok(Vec::new())
            },
        );
        assert_eq!(prompts, 1, "one route command must ask exactly once");
        assert_eq!(runs, 1, "one route command must run exactly once");
        assert_eq!(reports.len(), 2);
    }

    /// A digest that did not match is its own outcome, never a plain failure.
    ///
    /// The two need different words and different advice, and a reader must not
    /// take "the bytes were wrong" for "the network was flaky" and retry into
    /// the same wall.
    #[test]
    fn a_checksum_mismatch_reports_its_own_outcome() {
        let ran = std::cell::Cell::new(false);
        let reports = provision(
            &[LanguageId::Rust],
            InstallConsent::Granted,
            |_| ran.get(),
            |_| Some(InstallRoute::PinnedRelease),
            |_, _| panic!("granted consent must not prompt"),
            |_, _| {
                ran.set(true);
                Err(InstallProblem::ChecksumMismatch {
                    reason: "served bytes hash to abc, Kin pins def".to_string(),
                })
            },
        );
        match reports.first().map(|r| &r.outcome) {
            Some(InstallOutcome::ChecksumRefused { reason, command }) => {
                assert!(reason.contains("Kin pins def"), "{reason}");
                assert!(
                    command.contains("download rust-analyzer"),
                    "the row must name the route that was refused: {command}"
                );
            }
            other => panic!("a mismatch must not read as an ordinary failure: {other:?}"),
        }
    }

    /// A successful pinned install carries its evidence into the report.
    ///
    /// A tick beside "installed" is not a disclosure. The URL and the digest
    /// have to reach the row an operator reads, or the verification happened
    /// somewhere nobody can check it.
    #[test]
    fn a_pinned_install_carries_its_source_and_digest_into_the_report() {
        let ran = std::cell::Cell::new(false);
        let reports = provision(
            &[LanguageId::Rust],
            InstallConsent::Granted,
            |_| ran.get(),
            |_| Some(InstallRoute::PinnedRelease),
            |_, _| panic!("granted consent must not prompt"),
            |_, _| {
                ran.set(true);
                Ok(vec![
                    "source:   https://example.invalid/rust-analyzer.gz".to_string(),
                    "sha256:   abc (verified before install)".to_string(),
                ])
            },
        );
        match reports.first().map(|r| &r.outcome) {
            Some(InstallOutcome::Installed { evidence, .. }) => {
                let joined = evidence.join("\n");
                assert!(joined.contains("https://example.invalid"), "{joined}");
                assert!(joined.contains("sha256"), "{joined}");
            }
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    /// The pinned-download disclosure describes the download, not rustup.
    ///
    /// A person consenting to a network fetch of somebody's release binary is
    /// owed the tag, the digest promise and the directory. "Adds a rustup
    /// component to the active toolchain" is a true sentence about a route this
    /// host is not taking, and it is the sentence the recipe carries.
    #[test]
    fn the_download_disclosure_describes_the_download() {
        let rust = recipe_for(LanguageId::Rust).expect("rust must have a recipe");
        let disclosure = route_disclosure(rust, InstallRoute::PinnedRelease);
        assert!(
            disclosure.contains(RUST_ANALYZER_RELEASE.tag),
            "{disclosure}"
        );
        assert!(disclosure.contains("sha256"), "{disclosure}");
        assert!(
            disclosure.contains("rust-lang/rust-analyzer"),
            "the project the bytes come from must be named: {disclosure}"
        );
        assert!(
            !disclosure.contains("rustup component"),
            "the download must not be described as a toolchain change: {disclosure}"
        );

        // Control: the installer route keeps the recipe's own sentence.
        assert_eq!(
            route_disclosure(rust, InstallRoute::Installer),
            rust.disclosure
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
