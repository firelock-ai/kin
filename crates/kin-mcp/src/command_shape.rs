// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a CLI command looks like in a graph that has no `Command` kind.
//!
//! `semantic_search` accepts `kind: "command"` and, until this module existed,
//! threw it away: `parse_kind_filter` had no arm for it, so the request ran with
//! no kind filter at all and the ranking beside it had no idea a command had
//! been asked for. Measured on a 714-commit slice of `cli/cli`,
//! `semantic_search {kind: "command", query: "gh api"}` answered with
//! `TestGetAttestations_GhAPI_NoAttestationsFound`, the `API` class from
//! `internal/codespaces`, `ghId`, `ghRepo` and `ghTerm`, and never once named
//! `apiRun` or `NewCmdApi` in `pkg/cmd/api/api.go`, which are the two
//! declarations that ARE the `gh api` command. A model given that answer roots
//! its trace on whatever came first.
//!
//! There is no `EntityKind::Command` to filter on, and inventing one would be a
//! claim about every language's extractor. What a command does have is a shape,
//! and the shape is carried by two things the graph already owns: the file path
//! and the declaration name. A command entry point sits under a command
//! directory (`cmd`, `commands`, `cli`, …) and is named for the command plus a
//! role affix -- `apiRun`, `runApi`, `NewCmdApi`, `apiCmd`, `ApiCommand`. Both
//! halves are required, because either alone is noise: `openUserFile` also sits
//! under `pkg/cmd/api`, and a `Run` method on a struct in `internal/` is not a
//! subcommand.
//!
//! The command's own name is returned rather than a bare yes, so the caller can
//! require that the question actually named THIS command. Without that check a
//! query for `gh api` would rank `NewCmdRun` and `prRun` as command entry
//! points too, which is the same failure with different rows in it.

use kin_search::tokenize;

/// Which half of a command a declaration is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommandRole {
    /// The constructor that registers the command with its parent, such as
    /// cobra's `NewCmdApi`. It is where the flags are declared, so it answers
    /// "what does this command take" and not "what does it do".
    Constructor,
    /// The function the command runs, such as `apiRun`. This is the body a
    /// "how does this command work" question is about, so it ranks first.
    Run,
}

/// A declaration that is a CLI command's own entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEntryPoint {
    pub role: CommandRole,
    /// The command this declaration stands for, lowercased, with the role affix
    /// removed: `apiRun` and `NewCmdApi` both report `api`.
    pub command: String,
}

impl CommandEntryPoint {
    /// Rank for ordering, highest first. Zero is "not a command entry point",
    /// so a caller can compare a bare number without an `Option` dance.
    pub fn rank(entry: Option<&Self>) -> u8 {
        match entry.map(|entry| entry.role) {
            Some(CommandRole::Run) => 2,
            Some(CommandRole::Constructor) => 1,
            None => 0,
        }
    }
}

/// Path segments that mark a directory as holding CLI commands.
const COMMAND_DIRECTORIES: &[&str] = &[
    "cmd",
    "cmds",
    "command",
    "commands",
    "subcommand",
    "subcommands",
    "cli",
];

/// Name tokens that mark a declaration as the function a command runs.
const RUN_AFFIXES: &[&str] = &["run", "exec", "execute"];

/// Name tokens that mark a declaration as a command constructor or the command
/// value itself.
const COMMAND_AFFIXES: &[&str] = &["cmd", "command"];

/// The parts of one declaration name, lowercased, in order.
///
/// Deliberately not [`kin_search::tokenize`], which this module uses for the
/// QUESTION. That tokenizer also emits each whole segment for exact matching,
/// so `apiRun` comes back as `["api", "run", "apirun"]` and the affix this rule
/// reads is no longer the last part. Retrieval wants the extra token and this
/// rule cannot have it, which is the whole of the difference.
fn identifier_parts(name: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    for segment in name.split(|ch: char| !ch.is_alphanumeric()) {
        let chars: Vec<char> = segment.chars().collect();
        let mut current = String::new();
        for (index, ch) in chars.iter().enumerate() {
            if index > 0
                && ch.is_uppercase()
                && chars[index - 1].is_lowercase()
                && !current.is_empty()
            {
                parts.push(current.to_lowercase());
                current.clear();
            }
            current.push(*ch);
        }
        if !current.is_empty() {
            parts.push(current.to_lowercase());
        }
    }
    parts
}

/// Whether this path sits under a directory that holds CLI commands.
fn under_command_directory(file_path: &str) -> bool {
    file_path
        .split('/')
        .any(|segment| COMMAND_DIRECTORIES.contains(&segment.to_lowercase().as_str()))
}

/// Read a declaration as a CLI command's entry point, or `None`.
///
/// Both halves are required: the declaration must sit under a command directory
/// AND carry a command role affix in its name. The command name returned is
/// what is left of the name once the affixes are removed, so the caller can
/// check it against the words the question actually used.
pub fn command_entry_point(name: &str, file_path: Option<&str>) -> Option<CommandEntryPoint> {
    let path = file_path?;
    if !under_command_directory(path) {
        return None;
    }
    let tokens = identifier_parts(name);
    if tokens.len() < 2 {
        return None;
    }

    // `new` on its own says nothing; it is the `cmd` beside it that does, so it
    // is stripped rather than matched.
    let mut rest: Vec<&str> = tokens.iter().map(String::as_str).collect();
    if rest.first() == Some(&"new") {
        rest.remove(0);
    }
    if rest.len() < 2 {
        return None;
    }

    let first = *rest.first()?;
    let last = *rest.last()?;
    let (role, command): (CommandRole, Vec<&str>) = if RUN_AFFIXES.contains(&last) {
        (CommandRole::Run, rest[..rest.len() - 1].to_vec())
    } else if RUN_AFFIXES.contains(&first) {
        (CommandRole::Run, rest[1..].to_vec())
    } else if COMMAND_AFFIXES.contains(&last) {
        (CommandRole::Constructor, rest[..rest.len() - 1].to_vec())
    } else if COMMAND_AFFIXES.contains(&first) {
        (CommandRole::Constructor, rest[1..].to_vec())
    } else {
        return None;
    };

    if command.is_empty() {
        return None;
    }
    Some(CommandEntryPoint {
        role,
        command: command.join(""),
    })
}

/// The command entry point a QUESTION named, or `None`.
///
/// [`command_entry_point`] says a declaration is SOME command's entry point.
/// This says it is the one asked about, by requiring the question to carry the
/// command's own name. Without that check, `kind: "command"` with the query
/// `gh api` would promote `NewCmdRun`, `NewCmdPr` and every other subcommand
/// constructor in the tree, which is the same wrong answer with different rows
/// in it.
pub fn command_entry_point_for_query(
    query: &str,
    name: &str,
    file_path: Option<&str>,
) -> Option<CommandEntryPoint> {
    let entry = command_entry_point(name, file_path)?;
    let asked: Vec<String> = tokenize(query);
    asked
        .iter()
        .any(|token| *token == entry.command)
        .then_some(entry)
}

/// The command rank one declaration carries for one question, highest first.
///
/// `0` for everything that is not the named command's own entry point, so this
/// composes as an ordinary sort key rather than an `Option` comparison.
pub fn command_rank_for_query(query: &str, name: &str, file_path: Option<&str>) -> u8 {
    CommandEntryPoint::rank(command_entry_point_for_query(query, name, file_path).as_ref())
}

/// The names a command called `command` could be declared under.
///
/// Retrieval, not ranking. The store's name filter answers an exact name and
/// nothing else useful here: measured on a 714-commit slice of `cli/cli`,
/// `name_pattern: "api"` returns exactly one row, the `API` class in
/// `internal/codespaces`, and never `apiRun`, so no amount of reordering can
/// put the command first because the command was never retrieved. Asking for
/// the spellings a command entry point actually has is what puts it in the
/// candidate set: `apirun` returns `apiRun` and `newcmdapi` returns
/// `NewCmdApi`, both on the store's own case-insensitive name match.
///
/// Every spelling is still checked against [`command_entry_point_for_query`]
/// by the caller, so a coincidence like `Test_apiRun` does not ride in on the
/// same query.
pub fn command_name_spellings(command: &str) -> Vec<String> {
    let command = command.to_lowercase();
    vec![
        format!("{command}run"),
        format!("run{command}"),
        format!("{command}_run"),
        format!("newcmd{command}"),
        format!("new{command}cmd"),
        format!("{command}cmd"),
        format!("cmd{command}"),
        format!("{command}command"),
    ]
}

/// How many of a question's words the declaration's PATH carries.
///
/// A tiebreak among command entry points, and it is needed as soon as a
/// repository has the same subcommand under several parents. On a 714-commit
/// slice of `cli/cli`, `gh pr create` finds 22 declarations named `createRun`,
/// one per `create` subcommand in the tree; every one is a real command entry
/// point and only one of them is under `pkg/cmd/pr/`. The path is what tells
/// them apart, and the graph already owns it.
pub fn command_path_match(query: &str, file_path: Option<&str>) -> usize {
    let Some(path) = file_path else {
        return 0;
    };
    let segments: Vec<String> = path
        .split(|ch: char| !ch.is_alphanumeric())
        .map(str::to_lowercase)
        .collect();
    tokenize(query)
        .into_iter()
        .filter(|token| segments.iter().any(|segment| segment == token))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two declarations that ARE `gh api`, in the shapes cobra writes them.
    #[test]
    fn the_run_function_and_the_constructor_are_both_entry_points() {
        let run = command_entry_point("apiRun", Some("pkg/cmd/api/api.go"))
            .expect("apiRun under pkg/cmd/api is a command entry point");
        assert_eq!(run.role, CommandRole::Run);
        assert_eq!(run.command, "api");

        let constructor = command_entry_point("NewCmdApi", Some("pkg/cmd/api/api.go"))
            .expect("NewCmdApi under pkg/cmd/api is a command entry point");
        assert_eq!(constructor.role, CommandRole::Constructor);
        assert_eq!(constructor.command, "api");

        assert!(
            CommandEntryPoint::rank(Some(&run)) > CommandEntryPoint::rank(Some(&constructor)),
            "the body a command runs answers 'how does this work' before its flag constructor"
        );
    }

    /// Either half alone is noise, and both halves of that are load-bearing:
    /// `pkg/cmd/api/api.go` is full of ordinary helpers, and a `Run` method
    /// outside a command directory is not a subcommand.
    #[test]
    fn a_command_needs_both_its_directory_and_its_name_shape() {
        assert!(
            command_entry_point("openUserFile", Some("pkg/cmd/api/api.go")).is_none(),
            "a helper in a command's own file is not the command"
        );
        assert!(
            command_entry_point("Client.Request", Some("api/client.go")).is_none(),
            "a client method is not a command, whatever word it shares with one"
        );
        assert!(
            command_entry_point("workerRun", Some("internal/worker/worker.go")).is_none(),
            "a run method outside a command directory is not a subcommand"
        );
    }

    /// The command name is what lets a caller require that the question named
    /// THIS command rather than any command.
    #[test]
    fn the_command_name_is_reported_without_its_affix() {
        for (name, path, command) in [
            ("createRun", "pkg/cmd/pr/create/create.go", "create"),
            ("NewCmdCreate", "pkg/cmd/pr/create/create.go", "create"),
            ("runClone", "pkg/cmd/repo/clone/clone.go", "clone"),
            ("cloneCmd", "pkg/cmd/repo/clone/clone.go", "clone"),
            ("newStatusCmd", "src/cli/commands/status.ts", "status"),
            ("StatusCommand", "src/commands/status.ts", "status"),
        ] {
            let entry = command_entry_point(name, Some(path))
                .unwrap_or_else(|| panic!("{name} is a command entry point"));
            assert_eq!(entry.command, command, "{name}");
        }
    }

    /// The reason this module splits names itself. `kin_search::tokenize` adds
    /// the whole segment for exact matching, which buries the affix.
    #[test]
    fn a_name_is_split_into_its_parts_and_not_its_whole() {
        assert_eq!(identifier_parts("apiRun"), vec!["api", "run"]);
        assert_eq!(identifier_parts("NewCmdApi"), vec!["new", "cmd", "api"]);
        assert_eq!(identifier_parts("api_run"), vec!["api", "run"]);
        assert_eq!(
            identifier_parts("Client.Request"),
            vec!["client", "request"]
        );
        assert!(
            tokenize("apiRun").contains(&"apirun".to_string()),
            "the search tokenizer really does emit the whole segment, which is why this module \
             does not use it for a declaration name"
        );
    }

    /// A bare affix names no command, so it cannot be matched against a
    /// question's words and must not be promoted by this rule.
    #[test]
    fn a_bare_affix_names_no_command() {
        assert!(command_entry_point("Run", Some("pkg/cmd/api/api.go")).is_none());
        assert!(command_entry_point("NewCmd", Some("pkg/cmd/api/api.go")).is_none());
        assert!(command_entry_point("cmd", Some("pkg/cmd/api/api.go")).is_none());
    }

    /// The question has to name the command. A `gh api` question must not
    /// promote every other subcommand in the tree just because they are all
    /// command entry points.
    #[test]
    fn only_the_command_the_question_named_is_ranked() {
        assert_eq!(
            command_rank_for_query("gh api", "apiRun", Some("pkg/cmd/api/api.go")),
            2,
            "the run function of the command that was asked about leads"
        );
        assert_eq!(
            command_rank_for_query("gh api", "NewCmdApi", Some("pkg/cmd/api/api.go")),
            1,
            "its constructor follows"
        );
        assert_eq!(
            command_rank_for_query("gh api", "NewCmdRun", Some("pkg/cmd/run/run.go")),
            0,
            "a different subcommand's constructor is not an answer to this question"
        );
        assert_eq!(
            command_rank_for_query("gh api", "Client.Request", Some("api/client.go")),
            0,
            "the client method the measured run rooted its trace on ranks below both"
        );
    }

    /// The spellings are what retrieval asks the store for, so the two that
    /// were measured to work on a real store are named here.
    #[test]
    fn the_spellings_cover_the_shapes_the_store_can_answer() {
        let spellings = command_name_spellings("api");
        assert!(spellings.contains(&"apirun".to_string()));
        assert!(spellings.contains(&"newcmdapi".to_string()));
        assert!(spellings.contains(&"apicmd".to_string()));
    }

    /// The same subcommand under several parents is the case the path decides.
    #[test]
    fn the_path_separates_one_subcommand_from_its_namesakes() {
        let asked = "gh pr create";
        assert!(
            command_path_match(asked, Some("pkg/cmd/pr/create/create.go"))
                > command_path_match(asked, Some("pkg/cmd/label/create.go")),
            "the create under pr carries more of the question than the create under label"
        );
        assert_eq!(command_path_match(asked, None), 0);
    }
}
