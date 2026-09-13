// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use std::collections::BTreeSet;

fn on_cli_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn grouped_help_categorizes_every_visible_command_exactly_once() {
    on_cli_stack(|| {
        let mut cli = Cli::command();
        cli.build();
        let visible: BTreeSet<_> = cli
            .get_subcommands()
            .filter(|command| !command.is_hide_set())
            .map(|command| command.get_name())
            .collect();
        let mut categorized = BTreeSet::new();
        for (heading, names) in COMMAND_GROUPS {
            for name in *names {
                assert!(categorized.insert(*name), "duplicate command: {name}");
                assert!(
                    visible.contains(name),
                    "{heading} contains unknown or hidden {name}"
                );
            }
        }
        assert_eq!(
            categorized, visible,
            "every visible command needs a task group"
        );
    });
}

#[test]
fn grouped_help_renders_real_descriptions_and_aliases_without_exposing_hidden_commands() {
    let fixture = clap::Command::new("kin")
        .disable_help_subcommand(true)
        .subcommand(
            clap::Command::new("pull")
                .visible_alias("fetch")
                .about("Pull the exact history"),
        )
        .subcommand(
            clap::Command::new("secret-helper")
                .hide(true)
                .about("Hidden protocol helper"),
        );
    let rendered = grouped_commands_help(&fixture, &[("Share", &["pull"])]);
    assert!(rendered.contains("Share:\n  pull"), "{rendered}");
    assert!(rendered.contains("Pull the exact history"), "{rendered}");
    assert!(rendered.contains("[alias: fetch]"), "{rendered}");
    assert!(!rendered.contains("secret-helper"), "{rendered}");
    assert!(!rendered.contains("Hidden protocol helper"), "{rendered}");
}

#[test]
fn grouped_help_keeps_an_uncategorized_future_command_discoverable() {
    let fixture = clap::Command::new("kin")
        .disable_help_subcommand(true)
        .subcommand(clap::Command::new("status").about("Inspect the workspace"))
        .subcommand(clap::Command::new("future-command").about("A newly added capability"));
    let rendered = grouped_commands_help(&fixture, &[("Get started", &["status"])]);
    assert!(rendered.contains("Get started:\n  status"), "{rendered}");
    assert!(
        rendered.contains("Other commands:\n  future-command"),
        "{rendered}"
    );
    assert!(rendered.contains("A newly added capability"), "{rendered}");
}

#[test]
fn grouped_help_keeps_every_command_and_alias_help_route_reachable() {
    on_cli_stack(|| {
        fn visit(root: &clap::Command, command: &clap::Command, path: &mut Vec<String>) {
            for child in command.get_subcommands() {
                if child.get_name() == "help" {
                    continue;
                }
                for name in std::iter::once(child.get_name()).chain(child.get_all_aliases()) {
                    let mut argv = vec!["kin".to_string()];
                    argv.extend(path.iter().cloned());
                    argv.extend([name.to_string(), "--help".to_string()]);
                    let error = root.clone().try_get_matches_from(&argv).unwrap_err();
                    assert_eq!(
                        error.kind(),
                        clap::error::ErrorKind::DisplayHelp,
                        "{argv:?}: {error}"
                    );
                    assert_eq!(error.exit_code(), 0, "{argv:?}");
                    assert!(!error.use_stderr(), "{argv:?}");
                }
                path.push(child.get_name().to_string());
                visit(root, child, path);
                path.pop();
            }
        }
        let mut root = Cli::command();
        root.build();
        visit(&root, &root, &mut Vec::new());
    });
}

#[test]
fn grouped_help_is_complete_on_short_long_and_help_subcommand_routes() {
    on_cli_stack(|| {
        for argv in [
            vec!["kin", "-h"],
            vec!["kin", "--help"],
            vec!["kin", "help"],
            vec!["kin"],
        ] {
            let error = match Cli::try_parse_from(&argv) {
                Ok(_) => panic!("help should not execute a command: {argv:?}"),
                Err(error) => error,
            };
            let bare = argv.len() == 1;
            assert_eq!(error.exit_code(), if bare { 2 } else { 0 }, "{argv:?}");
            assert_eq!(error.use_stderr(), bare, "{argv:?}");
            let help = error.to_string();
            assert!(help.starts_with(CATEGORY_LINE), "{argv:?}: {help}");
            for (heading, names) in COMMAND_GROUPS {
                assert!(help.contains(&format!("{heading}:")), "{argv:?}: {heading}");
                for name in *names {
                    assert!(
                        help.lines().any(|line| line
                            .strip_prefix("  ")
                            .is_some_and(|row| row.split_whitespace().next() == Some(name))),
                        "{argv:?}: missing command row {name}"
                    );
                }
            }
        }
    });
}

#[test]
fn grouped_help_keeps_task_groups_and_global_options_at_narrow_and_wide_widths() {
    on_cli_stack(|| {
        for width in [52, 100, 140] {
            let help = Cli::command()
                .term_width(width)
                .render_long_help()
                .to_string();
            for (heading, _) in COMMAND_GROUPS {
                assert!(
                    help.contains(&format!("{heading}:")),
                    "width={width}: {heading}"
                );
            }
            for option in ["--profile-out", "--profile-summary", "--help", "--version"] {
                assert!(help.contains(option), "width={width}: {option}");
            }
            assert!(help.contains("[alias: fetch]"), "width={width}");
            assert!(help.contains("[alias: revert]"), "width={width}");
            assert!(!help.contains("Other commands:"), "width={width}");
        }
    });
}

#[test]
fn grouped_help_preserves_clap_long_row_wrapping() {
    fn command_row(help: &str, name: &str) -> String {
        let mut lines = help.lines().skip_while(|line| {
            !line
                .strip_prefix("  ")
                .is_some_and(|row| row.split_whitespace().next() == Some(name))
        });
        let mut row = vec![lines.next().expect("command row exists")];
        for line in lines {
            if line.is_empty()
                || line
                    .strip_prefix("  ")
                    .is_some_and(|rest| !rest.starts_with(' '))
            {
                break;
            }
            row.push(line);
        }
        row.join("\n")
    }

    on_cli_stack(|| {
        for width in [52, 100, 140] {
            let grouped = Cli::command()
                .term_width(width)
                .render_long_help()
                .to_string();
            let plain = Cli::command()
                .term_width(width)
                .help_template("{subcommands}")
                .render_long_help()
                .to_string();
            // The shipped Clap feature set does not wrap descriptions. This
            // comparison also catches a divergence if wrapping is enabled.
            assert_eq!(
                command_row(&grouped, "path"),
                command_row(&plain, "path"),
                "width={width}"
            );
        }
    });
}
