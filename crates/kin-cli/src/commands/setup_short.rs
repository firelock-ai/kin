// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin setup` on a terminal: a welcome, a few focused questions in a live
//! frame, one line while the machine is set up, and a short completion.
//!
//! The logo and the welcome print once and scroll away. The questions are asked
//! in [`crate::tui`]'s frame, one at a time, each with what saying yes does
//! shown before its choices. Nothing is changed until the last question is
//! answered, so Ctrl-C at any point leaves the machine as it was. The answers
//! then stay on screen as rows, one live line runs while setup applies them,
//! and the completion lists anything that needs the person first and then
//! exactly one next action. All of it stays in the scrollback.
//!
//! The full record the wizard has always printed is held back (see `say!` in
//! the parent module), and every line here is built from what a step returned,
//! so holding the prose back loses no fact. `kin setup --verbose`, a pipe and a
//! CI log get the full record instead.

use super::*;
use crate::screen::{self, Status, Style, INDENT};
use crate::tui::{self, Question};

/// Whether this run's flags fit the short form.
///
/// The editor, hosted and advanced intents, and a remote embedding provider,
/// each exist to print something the short form has no room for: a pointer to
/// install, a sign-in state, a menu of toggles, the variables a provider needs.
/// Those runs keep the full record.
pub(super) fn fits(opts: &WizardOptions) -> bool {
    let intent_fits = match opts.intent.as_deref() {
        None => true,
        Some(flag) => matches!(
            SetupIntent::from_flag(flag),
            Some(SetupIntent::AgentOnly | SetupIntent::LocalOnly)
        ),
    };
    let provider_fits = opts
        .embedding_provider
        .as_deref()
        .is_none_or(|value| value.trim().eq_ignore_ascii_case("local"));
    intent_fits && provider_fits
}

/// Which question a step is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    Clients,
    Path,
    Servers,
    Model,
}

/// One question and, when a flag already answered it, that answer.
struct Step {
    asked: Asked,
    question: Question,
    preset: Option<bool>,
}

/// Run the wizard in its short form.
pub(super) async fn run(opts: WizardOptions, interactive: bool) -> Result<()> {
    let _held_back = ShortFormScope::enter();
    let style = Style::for_stdout();

    let kin_home = kin_dir().ok();
    let assistants = detect_ai_assistants();
    let shell_name = opts.shell.as_deref().unwrap_or_else(|| detect_shell());
    let cwd = env::current_dir().unwrap_or_default();
    let language_scope = language_servers::language_scope(&cwd, None);
    let in_repo = current_initialized_setup_repo("setup").is_ok();
    let model = crate::embed_model::EmbedModelFetch::probe(false);
    let machine = screen::this_machine();

    let steps = steps(&opts, &assistants, shell_name, &model, kin_home.as_deref());
    let to_ask: Vec<&Step> = steps.iter().filter(|step| step.preset.is_none()).collect();
    // The logo, the welcome and the first question have to fit on screen
    // together, so a short terminal gets the compact logo.
    let first_rows = if interactive {
        let questions: Vec<Question> = to_ask.iter().map(|step| step.question.clone()).collect();
        tui::first_frame_rows(&questions, screen::terminal_width())
    } else {
        0
    };
    if !crate::banner::print_once_leaving(interactive, first_rows + 2) {
        println!();
    }
    println!(
        "{INDENT}Welcome to Kin {}. {}",
        env!("CARGO_PKG_VERSION"),
        welcome_tail(if interactive { to_ask.len() } else { 0 }, machine)
    );

    // Nothing is written before every answer is in.
    let chosen: Vec<usize> = if interactive {
        let questions: Vec<Question> = to_ask.iter().map(|step| step.question.clone()).collect();
        match tui::ask_all(style, &questions) {
            tui::Outcome::Answered(chosen) => chosen,
            tui::Outcome::Cancelled => {
                println!();
                println!(
                    "{INDENT}{} Setup cancelled. Nothing on {machine} changed.",
                    style.glyph(Status::Off)
                );
                super::exit_cancelled();
            }
        }
    } else {
        to_ask.iter().map(|step| step.question.default).collect()
    };
    let mut answers: Vec<(Asked, bool)> = Vec::new();
    let mut asked_index = 0;
    println!();
    for step in &steps {
        let (index, how) = match step.preset {
            Some(value) => (
                step.question
                    .choices
                    .iter()
                    .position(|choice| choice.value == value)
                    .unwrap_or(step.question.default),
                " · from a flag",
            ),
            None => {
                let index = chosen[asked_index];
                asked_index += 1;
                (index, if interactive { "" } else { " · default" })
            }
        };
        let choice = &step.question.choices[index];
        answers.push((step.asked, choice.value));
        println!(
            "{}",
            screen::row(
                style,
                INDENT,
                // Chosen, not done: nothing is applied until the run below,
                // and the completion says what actually happened.
                if choice.value {
                    Status::Chosen
                } else {
                    Status::Off
                },
                step.question.label,
                &format!("{}{}", choice.answered, style.faint(how)),
                None,
            )
        );
    }
    let answer = |asked: Asked| answers.iter().find(|(a, _)| *a == asked).map(|(_, v)| *v);
    let connect = match opts.intent.as_deref().and_then(SetupIntent::from_flag) {
        Some(intent) => intent == SetupIntent::AgentOnly,
        None => answer(Asked::Clients).unwrap_or(false),
    };
    let add_path = answer(Asked::Path).unwrap_or(true);
    let servers = answer(Asked::Servers);
    if let Some(home) = kin_home.as_deref() {
        if let Some(yes) = answer(Asked::Model) {
            let decision = if yes {
                crate::embed_model::MODEL_FETCH_DEFERRED
            } else {
                crate::embed_model::MODEL_FETCH_DECLINED
            };
            let _ = crate::embed_model::record_model_fetch(home, decision);
        }
        // Recorded only when someone answered it: a scripted run that passed
        // no flag has said nothing about installs.
        if let Some(yes) = servers.filter(|_| interactive || opts.install_language_servers) {
            let _ = language_servers::record_install_consent(home, yes);
        }
    }

    // Apply, one live line while it runs.
    println!();
    let live = tui::can_redraw()
        .then(|| screen::LiveLine::start(style, "Setting up"))
        .flatten();
    if live.is_none() {
        println!("{INDENT}Setting up {machine}...");
    }
    let note = |text: &str| {
        if let Some(live) = &live {
            live.note(text);
        }
    };
    let mut skipped: Vec<SkippedDecision> = Vec::new();
    let hardware = hardware_check(&opts, &mut skipped);
    ask_embedding_provider(&opts, false, &mut skipped);
    let intent = if connect {
        SetupIntent::AgentOnly
    } else {
        SetupIntent::LocalOnly
    };
    let plan = build_plan(
        intent,
        &opts,
        &assistants,
        shell_name,
        false,
        &hardware,
        &mut skipped,
    )?;
    let plan = SetupPlan {
        add_bin_to_path: plan.add_bin_to_path && add_path,
        verify_mcp_round_trip: plan.configure_mcp && in_repo && !opts.skip_mcp_check,
        ..plan
    };
    note(if plan.configure_mcp {
        "connecting AI clients"
    } else {
        "writing your shell profile"
    });
    let applied = apply_plan(&plan, &assistants, shell_name, opts.tool_profile.as_deref()).await?;
    if let Some(home) = kin_home.as_deref() {
        let _ = record_client_consent(home, connect);
    }

    // Inside a repository whose languages are known, the servers it needs go
    // in now, with the consent just given.
    let mut installed_servers: Vec<String> = Vec::new();
    let mut server_issues: Vec<String> = Vec::new();
    // Outside one, only `--install-language-servers` installs now, as its help
    // says; an answer to the question waits for a repository.
    let install_now = match &language_scope {
        language_servers::LanguageScope::Repository(_) => servers == Some(true),
        language_servers::LanguageScope::Unknown(_) => opts.install_language_servers,
    };
    if install_now {
        {
            let missing = language_scope.select(&language_servers::missing_enrichable_languages());
            if !missing.is_empty() {
                note("installing language servers");
                let outcome = apply_language_server_provisioning(
                    &missing,
                    language_servers::InstallConsent::Granted,
                )
                .await;
                let still_missing = language_servers::missing_enrichable_languages();
                installed_servers = missing
                    .iter()
                    .filter(|language| !still_missing.contains(language))
                    .map(|language| language.to_string())
                    .collect();
                server_issues = outcome
                    .unfinished
                    .iter()
                    .map(|repair| repair.reason.clone())
                    .collect();
            }
        }
    }
    record_language_tool_dirs_in_wizard();
    let notifier_issue = report_notification_identity(interactive);
    note("checking which kin a new terminal runs");
    let terminal = match applied.shell_integration {
        ShellIntegration::Installed => terminal_kin(shell_name),
        _ => TerminalKin::Unknown,
    };
    note("checking this machine");
    let report = crate::commands::health::run_health_checks().await;
    if let Some(live) = live {
        live.finish();
    }

    let summary = summarize(Observed {
        machine,

        shell_name,
        path_planned: plan.add_bin_to_path,
        path_asked: steps.iter().any(|step| step.asked == Asked::Path),
        connect,
        assistants: &assistants,
        applied: &applied,
        terminal: &terminal,
        installed_servers: &installed_servers,
        server_issues: &server_issues,
        notifier_issue: notifier_issue.as_deref(),
        report: &report,
        in_repo,
    });
    println!();
    for line in completion_lines(style, &summary, screen::terminal_width()) {
        println!("{line}");
    }

    match failed_clients_error(&applied.failed_clients) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// The questions this machine needs asked, each answered already when a flag
/// gave the answer.
fn steps(
    opts: &WizardOptions,
    assistants: &[AiAssistant],
    shell_name: &str,
    model: &crate::embed_model::EmbedModelFetch,
    kin_home: Option<&Path>,
) -> Vec<Step> {
    let mut steps = Vec::new();

    let detected: Vec<&AiAssistant> = assistants.iter().filter(|a| a.detected).collect();
    if !detected.is_empty() {
        let names: Vec<&str> = detected.iter().map(|a| row_label(a.name)).collect();
        let claude = detected
            .iter()
            .any(|a| a.name == assistants[IDX_CLAUDE_CODE].name);
        let mut consent = format!(
            "Kin adds its MCP server to each one's own config and leaves the rest of it alone{}.",
            if claude {
                ", and adds a short Kin note to ~/.claude/CLAUDE.md so Claude Code reaches for it"
            } else {
                ""
            }
        );
        let waits: Vec<&str> = detected
            .iter()
            .map(|a| a.name)
            .filter(|name| {
                *name == assistants[IDX_CODEX].name || *name == assistants[IDX_GROK].name
            })
            .collect();
        if !waits.is_empty() {
            consent.push_str(&format!(
                " {} {} to a repository when you clone or init one.",
                join_names(&waits),
                if waits.len() == 1 {
                    "connects"
                } else {
                    "connect"
                }
            ));
        }
        // Each answer reads as the preference it records, so the recap stays
        // true above the completion's outcome: never a claim that anything
        // is done, and never a promise about what happens next.
        let count = match detected.len() {
            1 => names[0].to_string(),
            2 => "both".to_string(),
            n => format!("all {n}"),
        };
        steps.push(Step {
            asked: Asked::Clients,
            question: Question::yes_no(
                "AI clients",
                if detected.len() == 1 {
                    format!("Connect Kin to {}?", names[0])
                } else {
                    format!("Connect Kin to the {} AI clients here?", detected.len())
                },
                ("Yes, connect them", &format!("on for {count}")),
                ("No, not now", "off"),
                true,
            )
            .consent(consent)
            .note(join_names(&names)),
            preset: opts
                .intent
                .as_deref()
                .and_then(SetupIntent::from_flag)
                .map(|intent| intent == SetupIntent::AgentOnly),
        });
    }

    if let Some(files) = bin_path_needs_asking(opts, shell_name) {
        steps.push(Step {
            asked: Asked::Path,
            question: Question::yes_no(
                "PATH",
                "Put kin on your PATH?",
                ("Yes, add the line", &format!("set in {files}")),
                ("No, leave my shell profile alone", "left alone"),
                true,
            )
            .consent(format!(
                "Adds a line to {files} so a new terminal finds kin. `kin setup uninstall` \
                 removes it."
            )),
            preset: None,
        });
    }

    let missing = language_servers::missing_enrichable_languages();
    if !missing.is_empty() {
        let (npm, other): (Vec<_>, Vec<_>) = missing.iter().partition(|language| {
            language_servers::recipe_for(**language).is_some_and(|recipe| recipe.program == "npm")
        });
        let names = |languages: &[&kin_model::LanguageId]| -> String {
            let named: Vec<String> = languages
                .iter()
                .map(|language| crate::first_run::language_name(**language))
                .collect();
            join_names(&named.iter().map(String::as_str).collect::<Vec<_>>())
        };
        let mut where_ = Vec::new();
        if !npm.is_empty() {
            where_.push(format!(
                "The {} {} install with npm -g, outside ~/.kin.",
                names(&npm),
                if npm.len() == 1 {
                    "server would"
                } else {
                    "servers would"
                }
            ));
        }
        if !other.is_empty() {
            where_.push(format!(
                "The {} {} go in ~/.kin/tools or your toolchain.",
                names(&other),
                if other.len() == 1 {
                    "server would"
                } else {
                    "servers would"
                }
            ));
        }
        let mut question = Question::yes_no(
            "Language servers",
            "Install language servers when a repository needs them?",
            ("Yes, when a repository needs one", "on demand"),
            ("No, I'll install them myself", "you install them"),
            true,
        )
        .consent(
            "When you clone or init a repository, Kin installs the servers its languages need, \
             so calls link across files. Only those languages.",
        );
        // Where each install lands is part of what a person consents to, so
        // it is consent text at full contrast, not a faint note.
        question.consent.push(where_.join(" "));
        steps.push(Step {
            asked: Asked::Servers,
            question,
            preset: opts.install_language_servers.then_some(true),
        });
    }

    if !model.present && (model.no_fetch_reason.is_none() || model.declined) {
        let declined = kin_home
            .and_then(crate::embed_model::recorded_model_fetch)
            .as_deref()
            == Some(crate::embed_model::MODEL_FETCH_DECLINED);
        steps.push(Step {
            asked: Asked::Model,
            question: Question::yes_no(
                "Search model",
                "Download the search model when it's first needed?",
                ("Yes, when it's first needed", "on demand"),
                ("No, never download it", "never downloaded"),
                !declined,
            )
            .consent(format!(
                "Semantic search uses {}, {} from {} into ~/.cache/huggingface. Without it, \
                 search uses names and the graph, and says so.",
                model.model_id,
                model.expected_download(),
                crate::embed_model::EMBED_MODEL_HOST
            )),
            preset: opts.embedding_model.as_deref().map(|flag| {
                !matches!(
                    flag.trim().to_ascii_lowercase().as_str(),
                    "never" | "declined"
                )
            }),
        });
    }
    steps
}

/// What the welcome line says after the version.
fn welcome_tail(asked: usize, machine: &str) -> String {
    let count = match asked {
        0 => return format!("Setting up {machine}."),
        1 => "One question",
        2 => "Two questions",
        3 => "Three questions",
        _ => "Four questions",
    };
    format!("{count}, then you're ready.")
}

/// `A, B and C`.
fn join_names(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// A client's name as a row label: short enough for the label column.
fn row_label(name: &str) -> &str {
    name.strip_prefix("Google ").unwrap_or(name)
}

/// Whether a health row needs the person now, rather than later or never.
///
/// Pending rows are first-run work that finishes on its own, such as the
/// search model not downloaded yet, and rows that do not apply outside a
/// repository are nothing to do. Both stay in `kin doctor`.
fn needs_the_person(status: &crate::commands::health::HealthStatus) -> bool {
    use crate::commands::health::HealthStatus;
    matches!(
        status,
        HealthStatus::Missing
            | HealthStatus::Misconfigured
            | HealthStatus::Degraded
            | HealthStatus::Stale
    )
}

/// Whether a sentence can go in the completion as it is: short, and with no
/// unbroken run of characters long enough to be a path or a digest.
fn short_enough(text: &str) -> bool {
    text.chars().count() <= 90
        && text
            .split_whitespace()
            .all(|word| word.chars().count() <= 32)
}

/// The health rows that need the person, one line per kind.
///
/// Checks of one kind share the label before their colon, such as `MCP` for
/// each AI client's config. One failing is said with its own detail when that
/// fits; several are one line naming them, with their fix when they share one.
/// The detail of each stays in `kin doctor`, so a repeated failure never turns
/// the completion into a wall of near-identical lines, and a long path never
/// lands in it.
fn grouped_health(checks: &[&crate::commands::health::HealthCheck]) -> Vec<Attention> {
    let mut families: Vec<(String, Vec<&crate::commands::health::HealthCheck>)> = Vec::new();
    for check in checks {
        let family = check
            .label
            .split_once(": ")
            .map_or(check.label.as_str(), |(family, _)| family)
            .to_string();
        match families.iter_mut().find(|(name, _)| *name == family) {
            Some((_, members)) => members.push(check),
            None => families.push((family, vec![check])),
        }
    }
    families
        .into_iter()
        .map(|(family, members)| {
            let fixes: Vec<&str> = members
                .iter()
                .filter_map(|check| check.manual_fix.as_deref())
                .collect();
            let shared_fix = fixes
                .first()
                .filter(|first| fixes.len() == members.len() && fixes.iter().all(|f| f == *first))
                .map(|fix| fix.to_string());
            match members.as_slice() {
                [one]
                    if one.id == "commit_author"
                        && matches!(one.status, crate::commands::health::HealthStatus::Missing) =>
                {
                    Attention {
                        status: Status::Fail,
                        what: crate::commands::COMPACT_AUTHOR_CONSEQUENCE.to_string(),
                        fix: Some(crate::commands::compact_author_commands()),
                    }
                }
                [one] => Attention {
                    status: Status::Fail,
                    what: if short_enough(&one.detail) {
                        format!("{}: {}", one.label, one.detail)
                    } else {
                        format!("{} needs attention; kin doctor says why.", one.label)
                    },
                    fix: one
                        .manual_fix
                        .clone()
                        .filter(|fix| one.id == "commit_author" || short_enough(fix)),
                },
                several => {
                    let names: Vec<&str> = several
                        .iter()
                        .map(|check| {
                            check
                                .label
                                .split_once(": ")
                                .map_or(check.label.as_str(), |(_, name)| name)
                        })
                        .collect();
                    let kind = match family.as_str() {
                        "MCP" => "AI client configurations need repair".to_string(),
                        "Instructions" => "AI client instruction files need repair".to_string(),
                        other => format!("{other} checks need attention"),
                    };
                    Attention {
                        status: Status::Fail,
                        what: format!("{} {kind}: {}.", several.len(), join_names(&names)),
                        fix: Some(shared_fix.filter(|fix| short_enough(fix)).unwrap_or_else(
                            || {
                                "kin doctor says why for each, and kin doctor --fix repairs \
                                     what it can."
                                    .to_string()
                            },
                        )),
                    }
                }
            }
        })
        .collect()
}

/// The line to add by hand when a new terminal does not find this kin: the
/// install's `bin` directory in front of `PATH`.
const PATH_LINE: &str = "export PATH=\"$HOME/.kin/bin:$PATH\"";

/// What the new-terminal check means for the person, or `None` when a new
/// terminal runs this kin (or `PATH` was left alone on purpose).
///
/// Anything short of a verified answer is attention, and is counted: a check
/// that could not run is not a pass.
fn terminal_attention(
    terminal: &TerminalKin,
    path_planned: bool,
    path_rc: &str,
) -> Option<Attention> {
    match terminal {
        TerminalKin::This => None,
        TerminalKin::Missing if !path_planned => None,
        TerminalKin::Other(path) => Some(Attention {
            status: Status::Warn,
            what: format!(
                "A new terminal runs {}, not the kin setup just installed.",
                screen::home_relative(path)
            ),
            fix: Some(format!("Put this line last in {path_rc}: {PATH_LINE}")),
        }),
        TerminalKin::Missing => Some(Attention {
            status: Status::Warn,
            what: "A new terminal does not find kin.".to_string(),
            fix: Some(format!("Add this line to {path_rc}: {PATH_LINE}")),
        }),
        TerminalKin::Unknown => Some(Attention {
            status: Status::Warn,
            what: "Setup couldn't confirm which kin a new terminal runs.".to_string(),
            fix: Some(format!(
                "Open a new terminal and run kin --version; it should print {}.",
                env!("CARGO_PKG_VERSION")
            )),
        }),
    }
}

/// The notifier finding as one line and its one fix.
///
/// The notifier module's sentence names the path it looked in and why, which
/// belongs in `kin setup --verbose`. Here it is what is missing, what that
/// costs, and the command in the sentence's remedy.
fn notifier_attention(issue: &str) -> Attention {
    let command = issue
        .split_once("To fix:")
        .and_then(|(_, remedy)| {
            let mut parts = remedy.split('`');
            parts.next()?;
            parts.next()
        })
        .map(str::to_string);
    let what = if issue.contains("present but unusable") {
        "Kin's notifier app can't run, so notifications show as Script Editor."
    } else {
        "Kin's notifier app is missing, so notifications show as Script Editor."
    };
    Attention {
        status: Status::Warn,
        what: what.to_string(),
        fix: Some(match command {
            Some(command) => format!("Reinstall it: {command}"),
            None => "kin setup --verbose says how to restore it.".to_string(),
        }),
    }
}

/// What the run observed, gathered for the completion.
struct Observed<'a> {
    machine: &'static str,

    shell_name: &'a str,
    path_planned: bool,
    path_asked: bool,
    connect: bool,
    assistants: &'a [AiAssistant],
    applied: &'a AppliedSetup,
    terminal: &'a TerminalKin,
    installed_servers: &'a [String],
    server_issues: &'a [String],
    notifier_issue: Option<&'a str>,
    report: &'a crate::commands::health::HealthReport,
    in_repo: bool,
}

/// Something that needs the person, and what fixes it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attention {
    status: Status,
    what: String,
    fix: Option<String>,
}

/// The completion, as data.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Summary {
    machine: &'static str,
    attention: Vec<Attention>,
    /// Facts worth one line each: label and value.
    facts: Vec<(&'static str, String)>,

    next: String,
    next_note: Option<String>,
}

/// Turn what the run observed into the completion.
fn summarize(observed: Observed<'_>) -> Summary {
    use crate::commands::setup_verify::McpProof;

    let mut attention = Vec::new();
    let failed: Vec<&str> = observed
        .applied
        .failed_clients
        .iter()
        .map(|(name, _)| row_label(name))
        .collect();
    match observed.applied.failed_clients.as_slice() {
        [] => {}
        [(name, reason)] if short_enough(reason) => attention.push(Attention {
            status: Status::Fail,
            what: format!("{} was not connected: {reason}", row_label(name)),
            fix: Some("Fix that, then run kin setup again.".to_string()),
        }),
        _ => attention.push(Attention {
            status: Status::Fail,
            what: format!(
                "{} {} not connected: {}.",
                failed.len(),
                if failed.len() == 1 {
                    "AI client was"
                } else {
                    "AI clients were"
                },
                join_names(&failed)
            ),
            fix: Some("kin setup --verbose says why for each one.".to_string()),
        }),
    }
    let untested: Vec<&str> = observed
        .applied
        .proofs
        .iter()
        .filter(|proof| {
            matches!(
                proof.proof,
                McpProof::Failed { .. } | McpProof::Refused { .. } | McpProof::Unreadable { .. }
            )
        })
        .map(|proof| row_label(&proof.client))
        .collect();
    if !untested.is_empty() {
        attention.push(Attention {
            status: Status::Warn,
            what: format!(
                "{} connected, but a test call through {} failed: {}.",
                if untested.len() == 1 {
                    "An AI client is"
                } else {
                    "AI clients are"
                },
                if untested.len() == 1 { "it" } else { "them" },
                join_names(&untested)
            ),
            fix: Some("kin doctor --fix".to_string()),
        });
    }

    let path_rc_shown = shell_path_rcs(observed.shell_name)
        .unwrap_or_default()
        .last()
        .map(|rc| screen::home_relative(rc))
        .unwrap_or_default();
    let mut path_verified = false;
    match &observed.applied.shell_integration {
        ShellIntegration::NotWritten { reason, by_hand } => {
            let files = by_hand
                .iter()
                .map(|(path, _)| screen::home_relative(path))
                .collect::<Vec<_>>()
                .join(", ");
            attention.push(Attention {
                status: Status::Warn,
                what: format!("Setup could not write {files}: {reason}"),
                fix: Some("kin setup --verbose prints the lines to add by hand.".to_string()),
            });
        }
        ShellIntegration::Installed => {
            match terminal_attention(observed.terminal, observed.path_planned, &path_rc_shown) {
                Some(item) => attention.push(item),
                None => path_verified = observed.path_planned,
            }
        }
        ShellIntegration::NotPlanned => {}
    }
    for issue in observed.server_issues {
        attention.push(Attention {
            status: Status::Warn,
            what: format!("A language server did not install: {issue}"),
            fix: Some(crate::first_run::INSTALL_SERVERS.to_string()),
        });
    }
    if let Some(issue) = observed.notifier_issue {
        attention.push(notifier_attention(issue));
    }
    let needs: Vec<&crate::commands::health::HealthCheck> = observed
        .report
        .checks
        .iter()
        .filter(|check| needs_the_person(&check.status))
        // Local-only setup did not select client integration. Existing client
        // configs and instruction blocks remain visible in the full health
        // report, but are not repairs this completion asks the person to make.
        // Failures of work this run actually attempted are disclosed above.
        .filter(|check| {
            observed.connect
                || !(check.id == "mcp_clients"
                    || check.id.starts_with("mcp_client_")
                    || check.id.starts_with("instructions_"))
        })
        .collect();
    attention.extend(grouped_health(&needs));

    let mut facts: Vec<(&'static str, String)> = Vec::new();
    if observed.connect {
        let connected: Vec<&str> = observed
            .applied
            .configured_assistants
            .iter()
            .filter(|(_, path)| path.is_some())
            .map(|(name, _)| row_label(name))
            .collect();
        if !connected.is_empty() {
            facts.push(("Connected", join_names(&connected)));
        }
        let waiting: Vec<String> = observed
            .applied
            .deferred_clients
            .iter()
            .map(|name| {
                if *name == observed.assistants[IDX_ANTIGRAVITY].name {
                    format!("{} (run kin setup inside a repository)", row_label(name))
                } else {
                    format!("{name} (connects at clone or init)")
                }
            })
            .collect();
        if !waiting.is_empty() {
            facts.push(("Waiting", waiting.join(", ")));
        }
    } else {
        facts.push((
            "AI clients",
            "not connected; kin setup --intent agent connects them".to_string(),
        ));
    }
    if path_verified {
        facts.push(("PATH", "a new terminal runs this kin".to_string()));
    } else if !observed.path_planned && observed.path_asked {
        facts.push((
            "PATH",
            "left alone; add ~/.kin/bin to it yourself".to_string(),
        ));
    }
    if !observed.installed_servers.is_empty() {
        facts.push(("Installed", observed.installed_servers.join(", ")));
    }

    let (next, next_note) = if observed.in_repo {
        ("kin refs <function>".to_string(), None)
    } else if path_verified && observed.path_asked {
        (
            "kin clone <git-url>".to_string(),
            Some("in a new terminal".to_string()),
        )
    } else {
        ("kin clone <git-url>".to_string(), None)
    };
    Summary {
        machine: observed.machine,
        attention,
        facts,
        next,
        next_note,
    }
}

/// The completion's lines at `width` columns: the verdict, anything that needs
/// the person, a few facts, and exactly one next action.
///
/// Anything a person acts on or copies is full contrast and is wrapped rather
/// than cut; only labels and secondary words are faint.
fn completion_lines(style: Style, summary: &Summary, width: usize) -> Vec<String> {
    let edge = screen::right_edge_for(width);
    let text = edge.saturating_sub(INDENT.len() + 2);
    let mut lines = Vec::new();
    let things = summary.attention.len();
    if things == 0 {
        lines.push(format!(
            "{INDENT}{} {}",
            style.glyph(Status::Ok),
            style.bold(&format!("Kin is set up on {}.", summary.machine))
        ));
    } else {
        lines.push(format!(
            "{INDENT}{} {}",
            style.glyph(Status::Warn),
            style.bold(&format!(
                "Kin is set up on {}. {} {} you:",
                summary.machine,
                things,
                if things == 1 {
                    "thing needs"
                } else {
                    "things need"
                }
            ))
        ));
        lines.push(String::new());
        for item in &summary.attention {
            for (index, line) in screen::wrap(&item.what, text).into_iter().enumerate() {
                if index == 0 {
                    lines.push(format!("{INDENT}{} {line}", style.glyph(item.status)));
                } else {
                    lines.push(format!("{INDENT}  {line}"));
                }
            }
            if let Some(fix) = &item.fix {
                // Keep separate repair commands separate; wrapping the whole
                // paragraph would join them into an invalid shell command.
                for line in fix.lines().flat_map(|line| screen::wrap(line, text)) {
                    lines.push(format!("{INDENT}  {line}"));
                }
            }
        }
    }
    lines.push(String::new());
    let label_width = summary
        .facts
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0)
        .max(4);
    let value_width = edge.saturating_sub(INDENT.len() + label_width + 2);
    for (label, value) in &summary.facts {
        for (index, line) in screen::wrap(value, value_width).into_iter().enumerate() {
            let head = if index == 0 { *label } else { "" };
            lines.push(format!(
                "{INDENT}{}  {line}",
                style.faint(&format!("{head:<label_width$}"))
            ));
        }
    }

    lines.push(String::new());
    let note = summary
        .next_note
        .as_deref()
        .map(|note| format!("  {}", style.faint(note)))
        .unwrap_or_default();
    lines.push(format!(
        "{INDENT}{}  {}{note}",
        style.lilac("Next"),
        style.bold(&summary.next)
    ));
    lines.push(format!(
        "{INDENT}{}  kin setup status {} kin setup --verbose",
        style.faint("More"),
        style.dot()
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_welcome_counts_the_questions_it_will_ask() {
        assert_eq!(
            welcome_tail(4, "this Mac"),
            "Four questions, then you're ready."
        );
        assert_eq!(
            welcome_tail(1, "this Mac"),
            "One question, then you're ready."
        );
        assert_eq!(welcome_tail(0, "this machine"), "Setting up this machine.");
    }

    #[test]
    fn client_names_read_as_a_list() {
        assert_eq!(join_names(&["Cursor"]), "Cursor");
        assert_eq!(join_names(&["Cursor", "LM Studio"]), "Cursor and LM Studio");
        assert_eq!(
            join_names(&["Claude Code", "Cursor", "LM Studio"]),
            "Claude Code, Cursor and LM Studio"
        );
        assert_eq!(row_label("Google Antigravity"), "Antigravity");
    }

    /// Only a row that needs the person is shown: expected first-run work and
    /// rows that do not apply are `kin doctor`'s.
    #[test]
    fn only_rows_that_need_the_person_are_shown() {
        use crate::commands::health::HealthStatus;
        assert!(needs_the_person(&HealthStatus::Missing));
        assert!(needs_the_person(&HealthStatus::Misconfigured));
        assert!(needs_the_person(&HealthStatus::Degraded));
        assert!(needs_the_person(&HealthStatus::Stale));
        assert!(!needs_the_person(&HealthStatus::Pending));
        assert!(!needs_the_person(&HealthStatus::Unsupported));
        assert!(!needs_the_person(&HealthStatus::Healthy));
    }

    #[test]
    fn a_non_agent_intent_or_a_remote_provider_keeps_the_full_record() {
        let mut opts = WizardOptions {
            mode: None,
            shell: None,
            auto_daemon: false,
            no_interactive: false,
            intent: None,
            skip_mcp_check: false,
            install_language_servers: false,
            resource_profile: None,
            embedding_model: None,
            embedding_provider: None,
            skip_path: false,
            tool_profile: None,
            verbose: false,
        };
        assert!(fits(&opts));
        opts.intent = Some("local".to_string());
        assert!(fits(&opts));
        opts.intent = Some("editor".to_string());
        assert!(!fits(&opts));
        opts.intent = None;
        opts.embedding_provider = Some("remote".to_string());
        assert!(!fits(&opts));
    }

    fn summary(attention: Vec<Attention>) -> Summary {
        Summary {
            machine: "this Mac",
            attention,
            facts: vec![(
                "Connected",
                "Claude Code, Cursor, Gemini CLI and LM Studio".to_string(),
            )],

            next: "kin clone <git-url>".to_string(),
            next_note: Some("in a new terminal".to_string()),
        }
    }

    /// Anything that needs the person comes first, and the completion ends on
    /// exactly one next action.
    #[test]
    fn the_completion_leads_with_attention_and_ends_on_one_next_action() {
        let lines = completion_lines(
            Style::plain(),
            &summary(vec![Attention {
                status: Status::Warn,
                what: "A new terminal runs /usr/local/bin/kin, not the kin setup just installed."
                    .to_string(),
                fix: Some("Remove it, or put ~/.kin/bin before it on your PATH.".to_string()),
            }]),
            80,
        );
        assert!(lines[0].contains("1 thing needs you"), "{lines:#?}");
        let warning = lines
            .iter()
            .position(|l| l.contains("/usr/local/bin/kin"))
            .unwrap();
        let connected = lines.iter().position(|l| l.contains("Connected")).unwrap();
        assert!(
            warning < connected,
            "attention comes before facts: {lines:#?}"
        );
        let next: Vec<&String> = lines.iter().filter(|l| l.contains("Next")).collect();
        assert_eq!(next.len(), 1, "{lines:#?}");
        assert!(next[0].contains("kin clone <git-url>"));
    }

    /// At 60 columns nothing reaches the edge and a fix a person copies is
    /// wrapped whole, never cut.
    #[test]
    fn a_narrow_completion_wraps_and_never_cuts_a_fix() {
        let fix = "kin doctor --fix --install-language-servers";
        let lines = completion_lines(
            Style::plain(),
            &summary(vec![Attention {
                status: Status::Fail,
                what: "Reference edge coverage: the language server for python is not installed \
                       on this host"
                    .to_string(),
                fix: Some(fix.to_string()),
            }]),
            60,
        );
        for line in &lines {
            assert!(console::measure_text_width(line) < 60, "{line:?}");
            assert!(!line.contains('…'), "{line:?}");
        }
        assert!(lines.iter().any(|l| l.contains(fix)), "{lines:#?}");
    }

    fn mcp_check(client: &str) -> crate::commands::health::HealthCheck {
        crate::commands::health::HealthCheck {
            id: format!("mcp_client_{client}"),
            label: format!("MCP: {client}"),
            status: crate::commands::health::HealthStatus::Misconfigured,
            detail: format!(
                "mcpServers.kin in /private/tmp/some/very/long/scratch/home/.{client}/mcp.json \
                 launches /private/tmp/some/other/kin, not the kin this setup installed"
            ),
            platform_note: None,
            fixable: true,
            manual_fix: Some("kin doctor --fix".to_string()),
        }
    }

    #[test]
    fn a_missing_author_is_counted_with_copyable_repair_commands() {
        use crate::commands::health::{HealthCheck, HealthReport, HealthStatus};
        let applied = AppliedSetup {
            configured_assistants: Vec::new(),
            deferred_clients: Vec::new(),
            failed_clients: Vec::new(),
            shell_integration: ShellIntegration::NotPlanned,
            proofs: Vec::new(),
        };
        for missing in [true, false] {
            let report = HealthReport::from_checks(
                "test".to_string(),
                vec![HealthCheck {
                    id: "commit_author".to_string(),
                    label: "Author".to_string(),
                    status: if missing {
                        HealthStatus::Missing
                    } else {
                        HealthStatus::Healthy
                    },
                    detail: "not configured; changes cannot be admitted or committed".to_string(),
                    platform_note: None,
                    fixable: false,
                    manual_fix: missing.then(|| kin_core::IDENTITY_REMEDIATION.to_string()),
                }],
            );
            let summary = summarize(Observed {
                machine: "this machine",
                shell_name: "powershell",
                path_planned: false,
                path_asked: false,
                connect: false,
                assistants: &[],
                applied: &applied,
                terminal: &TerminalKin::Unknown,
                installed_servers: &[],
                server_issues: &[],
                notifier_issue: None,
                report: &report,
                in_repo: false,
            });
            assert_eq!(summary.attention.len(), usize::from(missing));
            let lines = completion_lines(Style::plain(), &summary, 60);
            let text = lines.join("\n");
            assert_eq!(text.contains("1 thing needs you"), missing, "{text}");
            assert_eq!(
                text.contains("git config --global user.name \"Your Name\""),
                missing,
                "{text}"
            );
            assert_eq!(
                text.contains("git config --global user.email \"you@example.com\""),
                missing,
                "{text}"
            );
            assert!(
                lines
                    .iter()
                    .all(|line| console::measure_text_width(line) < 60),
                "{text}"
            );
            assert!(
                !lines
                    .iter()
                    .any(|line| line.contains("user.name") && line.contains("user.email")),
                "{text}"
            );
            assert!(!text.contains("default_author"), "{text}");
            if missing {
                assert!(report.checks[0]
                    .manual_fix
                    .as_deref()
                    .unwrap()
                    .contains("default_author"));
                // The actual narrow-terminal fixture has four independent
                // warnings. Keep its count and both repair commands together
                // in the final 24-row viewport, without hiding other warnings.
                let mut four = summary.clone();
                four.machine = "this Mac";
                four.attention.insert(0, notifier_attention("missing"));
                four.attention.insert(
                    0,
                    terminal_attention(&TerminalKin::Unknown, true, "").unwrap(),
                );
                four.attention.push(Attention {
                    status: Status::Fail,
                    what: "Shell integration needs attention; kin doctor says why.".to_string(),
                    fix: Some(
                        "run `kin setup` (or `kin doctor --fix`) to reinstall the shell hook"
                            .to_string(),
                    ),
                });
                let lines = completion_lines(Style::plain(), &four, 60);
                assert!(
                    lines.len() <= 23,
                    "leave the cursor row below the whole completion: {lines:#?}"
                );
                assert!(lines[0].contains("4 things need you"), "{lines:#?}");
                assert!(
                    lines
                        .iter()
                        .any(|line| line.contains("user.name \"Your Name\"")),
                    "{lines:#?}"
                );
                assert!(
                    lines
                        .iter()
                        .any(|line| line.contains("user.email \"you@example.com\"")),
                    "{lines:#?}"
                );
            }
        }
    }

    /// Seven AI clients failing the same way are one line with one fix, and at
    /// 60 columns nothing reaches the edge and no long path appears.
    #[test]
    fn repeated_findings_collapse_to_one_line_per_kind() {
        let clients = [
            "Claude Code",
            "Cursor",
            "Codex CLI",
            "Gemini CLI",
            "Antigravity",
            "LM Studio",
            "Grok CLI",
        ];
        let checks: Vec<_> = clients.iter().map(|client| mcp_check(client)).collect();
        let refs: Vec<&crate::commands::health::HealthCheck> = checks.iter().collect();
        let grouped = grouped_health(&refs);
        assert_eq!(grouped.len(), 1, "{grouped:#?}");
        assert!(grouped[0]
            .what
            .starts_with("7 AI client configurations need repair: Claude Code"));
        assert_eq!(grouped[0].fix.as_deref(), Some("kin doctor --fix"));

        let lines = completion_lines(Style::plain(), &summary(grouped), 60);
        assert!(lines.len() <= 16, "{lines:#?}");
        for line in &lines {
            assert!(console::measure_text_width(line) < 60, "{line:?}");
            assert!(!line.contains("/private/tmp"), "no long path: {line:?}");
        }
        assert!(
            !lines.iter().any(|l| l.contains("Ready")),
            "never a false ready"
        );
    }

    /// One finding keeps its own detail only when that detail is short and has
    /// no path in it; otherwise it points at `kin doctor`.
    #[test]
    fn a_single_finding_keeps_a_short_detail_and_drops_a_long_one() {
        let long = mcp_check("Cursor");
        let grouped = grouped_health(&[&long]);
        assert_eq!(
            grouped[0].what,
            "MCP: Cursor needs attention; kin doctor says why."
        );
        let mut short = mcp_check("Cursor");
        short.detail = "the entry is missing".to_string();
        let grouped = grouped_health(&[&short]);
        assert_eq!(grouped[0].what, "MCP: Cursor: the entry is missing");
    }

    /// The completion follows the selected setup scope, while the same full
    /// health report still carries every existing client and instruction issue.
    /// Shell, terminal and language-server gaps remain actionable either way.
    #[test]
    fn local_setup_leaves_unselected_client_repairs_in_the_full_health_report() {
        use crate::commands::health::{HealthCheck, HealthReport, HealthStatus};
        let report = HealthReport::from_checks(
            "test".to_string(),
            vec![
                mcp_check("Cursor"),
                mcp_check("Claude Code"),
                HealthCheck {
                    id: "instructions_claude_code".to_string(),
                    label: "Instructions: Claude Code".to_string(),
                    status: HealthStatus::Misconfigured,
                    detail: "the recorded tool profile changed".to_string(),
                    platform_note: None,
                    fixable: true,
                    manual_fix: Some("kin doctor --fix".to_string()),
                },
                HealthCheck {
                    id: "shell_integration".to_string(),
                    label: "Shell integration".to_string(),
                    status: HealthStatus::Missing,
                    detail: "the shell hook is missing".to_string(),
                    platform_note: None,
                    fixable: true,
                    manual_fix: Some("kin doctor --fix".to_string()),
                },
                HealthCheck {
                    id: "lsp_servers".to_string(),
                    label: "Reference edge coverage".to_string(),
                    status: HealthStatus::Degraded,
                    detail: "Python's language server is missing".to_string(),
                    platform_note: None,
                    fixable: false,
                    manual_fix: Some(crate::first_run::INSTALL_SERVERS.to_string()),
                },
            ],
        );
        let full_report = serde_json::to_value(&report).unwrap();
        let applied = AppliedSetup {
            configured_assistants: Vec::new(),
            deferred_clients: Vec::new(),
            failed_clients: Vec::new(),
            shell_integration: ShellIntegration::Installed,
            proofs: Vec::new(),
        };
        for connect in [false, true] {
            let summary = summarize(Observed {
                machine: "this machine",
                shell_name: "powershell",
                path_planned: false,
                path_asked: false,
                connect,
                assistants: &[],
                applied: &applied,
                terminal: &TerminalKin::Unknown,
                installed_servers: &[],
                server_issues: &[],
                notifier_issue: None,
                report: &report,
                in_repo: false,
            });
            let text = completion_lines(Style::plain(), &summary, 80).join("\n");
            assert_eq!(
                text.contains("AI client configurations need repair"),
                connect,
                "{text}"
            );
            assert_eq!(
                text.contains("Instructions: Claude Code"),
                connect,
                "{text}"
            );
            assert!(text.contains("the shell hook is missing"), "{text}");
            assert!(text.contains("language server is missing"), "{text}");
            assert!(text.contains("couldn't confirm which kin"), "{text}");
        }
        assert_eq!(serde_json::to_value(&report).unwrap(), full_report);
    }

    #[test]
    fn selected_client_setup_still_discloses_an_attempted_write_failure() {
        use crate::commands::health::HealthReport;
        let report = HealthReport::from_checks("test".to_string(), Vec::new());
        let applied = AppliedSetup {
            configured_assistants: vec![("Cursor".to_string(), None)],
            deferred_clients: Vec::new(),
            failed_clients: vec![("Cursor".to_string(), "the config is read-only".to_string())],
            shell_integration: ShellIntegration::NotPlanned,
            proofs: Vec::new(),
        };
        let summary = summarize(Observed {
            machine: "this machine",
            shell_name: "powershell",
            path_planned: false,
            path_asked: false,
            connect: true,
            assistants: &[],
            applied: &applied,
            terminal: &TerminalKin::Unknown,
            installed_servers: &[],
            server_issues: &[],
            notifier_issue: None,
            report: &report,
            in_repo: false,
        });
        let text = completion_lines(Style::plain(), &summary, 80).join("\n");
        assert!(
            text.contains("Cursor was not connected: the config is read-only"),
            "{text}"
        );
        assert!(text.contains("1 thing needs you"), "{text}");
        assert!(!text.contains("Connected  Cursor"), "{text}");
    }

    /// A new terminal that could not be checked is attention and is counted,
    /// with one next step; only a verified answer passes.
    #[test]
    fn an_unconfirmed_terminal_is_counted_attention() {
        let unknown = terminal_attention(&TerminalKin::Unknown, true, "~/.zprofile")
            .expect("unconfirmed is attention");
        assert!(unknown.what.contains("couldn't confirm"), "{unknown:?}");
        assert!(unknown.fix.as_deref().unwrap().contains("kin --version"));
        assert_eq!(
            terminal_attention(&TerminalKin::This, true, "~/.zprofile"),
            None
        );
        assert_eq!(
            terminal_attention(&TerminalKin::Missing, false, "~/.zprofile"),
            None
        );
        let missing = terminal_attention(&TerminalKin::Missing, true, "~/.zprofile").unwrap();
        assert!(
            missing.fix.as_deref().unwrap().contains(PATH_LINE),
            "the exact line to add: {missing:?}"
        );

        let lines = completion_lines(Style::plain(), &summary(vec![unknown]), 80);
        assert!(lines[0].contains("1 thing needs you"), "{lines:#?}");
        assert!(!lines.iter().any(|l| l.contains('✓') && l.contains("PATH")));
    }

    /// The notifier's long sentence becomes one line and its command.
    #[test]
    fn a_missing_notifier_is_one_line_and_its_fix() {
        let issue = "KinNotifier.app is not installed (looked for /private/tmp/x/.kin/lib/\
                     KinNotifier.app/Contents/MacOS/KinNotifier); this managed install did not \
                     deliver a launchable bundle, so notifications post as Script Editor instead \
                     of Kin. To fix: rerun the managed installer: `curl -fsSL \
                     https://get.kinlab.dev/install | sh`.";
        let item = notifier_attention(issue);
        assert_eq!(
            item.what,
            "Kin's notifier app is missing, so notifications show as Script Editor."
        );
        assert_eq!(
            item.fix.as_deref(),
            Some("Reinstall it: curl -fsSL https://get.kinlab.dev/install | sh")
        );
        assert!(!item.what.contains("/private"));
    }

    /// The worst case Codex walked at 60x24: seven clients failing alike, a
    /// missing notifier and an unconfirmed terminal. The completion counts
    /// three things, shows three, and fits 24 rows.
    #[test]
    fn a_crowded_completion_fits_sixty_by_twenty_four() {
        let clients = [
            "Claude Code",
            "Cursor",
            "Codex CLI",
            "Gemini CLI",
            "Antigravity",
            "LM Studio",
            "Grok CLI",
        ];
        let checks: Vec<_> = clients.iter().map(|client| mcp_check(client)).collect();
        let refs: Vec<&crate::commands::health::HealthCheck> = checks.iter().collect();
        let mut attention = grouped_health(&refs);
        attention.push(notifier_attention(
            "KinNotifier.app is not installed (looked for /x); To fix: rerun: `curl -fsSL \
             https://get.kinlab.dev/install | sh`.",
        ));
        attention.push(terminal_attention(&TerminalKin::Unknown, true, "~/.zprofile").unwrap());
        let lines = completion_lines(Style::plain(), &summary(attention), 60);
        assert!(lines[0].contains("3 things need you"), "{lines:#?}");
        let marked = lines
            .iter()
            .filter(|l| l.trim_start().starts_with('!') || l.trim_start().starts_with('✗'))
            .count();
        assert_eq!(marked, 1 + 3, "the verdict and three findings: {lines:#?}");
        assert!(lines.len() <= 24, "{} rows: {lines:#?}", lines.len());
        for line in &lines {
            assert!(console::measure_text_width(line) < 60, "{line:?}");
        }
    }
}
