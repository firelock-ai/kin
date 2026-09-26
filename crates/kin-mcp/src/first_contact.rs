// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What an answer tells a reader who has to act on it before Kin can help.
//!
//! Three things a first-time user met in a stranger walkthrough of the MCP
//! registry install on 2026-09-22, each of which an answer used to leave to the
//! reader:
//!
//! - A remedy named `kin init .`, a command the reader did not have. The
//!   registry install runs Kin through `npx`, so no `kin` is on the reader's
//!   PATH. Every command an answer names is now spelled by [`kin_command`], as
//!   `kin ...` where that runs and as the `npx` form of the same release where
//!   it does not, and the MCP surface itself can initialize a repository.
//! - A folder with no repository of its own, nested inside one, was answered
//!   from the enclosing repository with nothing saying so. See
//!   [`repository_identity`].
//! - An answer whose cross-file references could not exist, because no
//!   language server was installed, read as complete unless its reader decoded
//!   the verdict's codes. See [`language_server_advice`].
//!
//! Everything here is prose built from facts the caller hands in, so it is
//! decidable with no host, no PATH and no daemon.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The npm package that runs any `kin` command without an install.
pub const NPM_PACKAGE: &str = "@kinlab/kin";

/// How a `kin` command is spelled for the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spelling {
    /// `kin ...`: the reader runs Kin's own CLI.
    Kin,
    /// `npx -y @kinlab/kin@<version> ...`: the reader has Node, because an
    /// MCP client started this server through `npx`, and may have no `kin`.
    Npx,
}

impl Spelling {
    /// The spelling for a reader of this process's answers, as the launcher
    /// recorded it with [`set_spelling`]: `kin` when a `kin` is on the
    /// server's PATH, the `npx` form when it is not. `kin` where nothing was
    /// recorded, which is every process but `kin mcp start`: the daemon and
    /// the CLI are `kin` themselves.
    pub fn here() -> Self {
        SPELLING.get().copied().unwrap_or(Self::Kin)
    }
}

static SPELLING: std::sync::OnceLock<Spelling> = std::sync::OnceLock::new();

/// Record how this process's answers spell a `kin` command. The launcher calls
/// it once, before serving, from whether a `kin` is on its PATH; the first
/// record wins.
///
/// Decided by the launcher rather than here because finding a program on PATH
/// reads the filesystem, and this crate answers from the graph.
pub fn set_spelling(spelling: Spelling) {
    let _ = SPELLING.set(spelling);
}

/// One `kin` command, in backticks, spelled so it runs for the reader.
///
/// The `npx` form pins this release, so the command a reader is handed is the
/// same build as the server that handed it over.
pub fn kin_command(args: &str, spelling: Spelling) -> String {
    match spelling {
        Spelling::Kin => format!("`kin {args}`"),
        Spelling::Npx => format!(
            "`npx -y {NPM_PACKAGE}@{} {args}`",
            env!("CARGO_PKG_VERSION")
        ),
    }
}

/// The language server binaries Kin looks for, per language, by the name the
/// coverage observation prints (`LanguageId`'s debug form).
///
/// Mirrors `kin_lsp::discovery::KNOWN_SERVERS`, which is what the daemon
/// consults; `kin-cli`'s language-server recipes are held to the same list by
/// a test there.
pub const LANGUAGE_SERVER_BINARIES: &[(&str, &[&str])] = &[
    ("Rust", &["rust-analyzer"]),
    ("Python", &["pyright-langserver", "pylsp"]),
    ("TypeScript", &["typescript-language-server", "vtsls"]),
    ("JavaScript", &["typescript-language-server"]),
    ("Go", &["gopls"]),
    ("Java", &["jdtls"]),
    ("C", &["clangd"]),
    ("Cpp", &["clangd"]),
];

/// How a language reads to a person: `Cpp` is C++ to a reader.
fn language_label(language: &str) -> &str {
    match language {
        "Cpp" => "C++",
        "CSharp" => "C#",
        "Php" => "PHP",
        "Hcl" => "HCL",
        other => other,
    }
}

fn server_names(language: &str) -> Option<String> {
    LANGUAGE_SERVER_BINARIES
        .iter()
        .find(|(name, _)| *name == language)
        .map(|(_, binaries)| binaries.join(" or "))
}

/// The plain sentence an answer leads with when a missing language server
/// limits it: what is missing, and how to add it.
///
/// Read off the answer's own `edge_coverage` observation, the one its verdict
/// was computed from, so the sentence and the verdict cannot disagree. `None`
/// wherever the observation names no gap a language server explains.
///
/// The verdict already says `inconclusive`, and its limiting factor already
/// carries the codes. A reader who stops at three rows and a closed code list
/// has an answer that looks complete, which is how the registry walkthrough
/// read a `find_references` on a Go repository with no gopls installed.
pub fn language_server_advice(edge_coverage: &Value, spelling: Spelling) -> Option<String> {
    let enrichment = edge_coverage
        .get("reference_enrichment")
        .and_then(Value::as_str)?;
    let languages: Vec<&str> = edge_coverage
        .get("language")
        .and_then(Value::as_str)?
        .split(", ")
        .filter(|language| !language.is_empty() && !language.starts_with('('))
        .collect();
    if languages.is_empty() {
        return None;
    }
    let labels: Vec<&str> = languages
        .iter()
        .map(|language| language_label(language))
        .collect();
    let named = labels.join(" and ");
    let mut advice = match enrichment {
        "no_language_server" => {
            let servers: Vec<String> = languages
                .iter()
                .filter_map(|language| server_names(language))
                .collect();
            let server = if servers.is_empty() {
                String::new()
            } else {
                format!(" ({})", servers.join("; "))
            };
            format!(
                "Missing: cross-file references and overrides for {named}. No language server \
                 for {named}{server} is installed where Kin runs, so Kin could not link them and \
                 these results are a lower bound. To add them, run {} and then {}, so the next \
                 call starts a daemon that finds it.",
                kin_command("doctor --fix --install-language-servers", spelling),
                kin_command("daemon stop", spelling),
            )
        }
        "language_server_unusable" => format!(
            "Missing: cross-file references and overrides for {named}. A language server for \
             {named} is installed where Kin runs, but it would not start, so Kin could not link \
             them and these results are a lower bound. Run {} to see why it will not start.",
            kin_command("doctor", spelling),
        ),
        "unsupported" => format!(
            "Missing: cross-file references and overrides for {named}. This Kin build has no \
             language server support for {named}, so these results are a lower bound, and \
             nothing installed on this machine adds them."
        ),
        _ => return None,
    };
    let imports_unlinked = edge_coverage
        .pointer("/unproduced_evidence/imports/this_build_mints_no_entity_level_edge_for")
        .and_then(Value::as_array)
        .is_some_and(|languages| !languages.is_empty());
    if imports_unlinked {
        advice.push_str(&format!(
            " Imports between {named} files are not linked by this Kin build at all."
        ));
    }
    Some(advice)
}

/// Which repository answered, and whether it is the folder the client works in.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepositoryIdentity {
    /// The Kin repository the answer came from.
    pub root: String,
    /// The folder the client is working in, when it is not `root`: its first
    /// workspace root, or this server's launch directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_root: Option<String>,
    /// What that difference means for the answer, in one sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// The repository block for one answer: `root` always, and the client's own
/// folder with a warning when the two differ.
///
/// The warning opens with which repository answered, so an answer from a
/// repository that contains the client's folder never reads as one from the
/// folder itself. For a folder nested in the repository it ends with how to have
/// another Kin repository answer, never with creating a repository inside this
/// one. A folder in the repository's `.kin/runs` directory, where Kin keeps
/// session workspaces, gets the facts and no remedy: its path alone does not
/// prove it is a session, so the note claims nothing about what it holds.
/// `kin mcp start` puts it at the head of every answer on such a connection,
/// and the CLI prints it before it answers from such a folder.
///
/// Both paths are compared as given; callers hand in canonical ones.
pub fn repository_identity(root: &Path, client_root: Option<&Path>) -> RepositoryIdentity {
    let differs = client_root.filter(|client| *client != root);
    let warning = differs.map(|client| {
        if in_runs_directory(root, client) {
            format!(
                "This answer comes from the Kin repository at {}. {} is inside that \
                 repository's .kin/runs directory, where Kin keeps session workspaces, and has \
                 no Kin repository of its own.",
                root.display(),
                client.display()
            )
        } else if client.starts_with(root) {
            format!(
                "This answer comes from the Kin repository at {}, not from {}: that folder is \
                 inside it and has no Kin repository of its own, so the answer can name code \
                 outside it. To have another Kin repository answer, run Kin from inside it, or \
                 start the MCP server with {} naming it.",
                root.display(),
                client.display(),
                kin_command("mcp start --repo", Spelling::here())
            )
        } else {
            format!(
                "This answer comes from the Kin repository at {}, not from {}, the folder the \
                 client is working in.",
                root.display(),
                client.display()
            )
        }
    });
    RepositoryIdentity {
        root: root.display().to_string(),
        client_root: differs.map(|client| client.display().to_string()),
        warning,
    }
}

/// Whether `client` is inside `root`'s `.kin/runs` directory, where Kin keeps
/// session workspaces. This is a fact about the path only; it does not
/// establish that the folder is a session or what it holds.
fn in_runs_directory(root: &Path, client: &Path) -> bool {
    let runs = kin_core::KinLayout::new(root.join(".kin")).runs_dir();
    client != runs && client.starts_with(&runs)
}

/// The folder a client works in: its first workspace root, or this server's
/// launch directory when it named none, through `canonicalize` so it compares
/// equal to the repository root a daemon reports for the same folder.
pub fn client_root(
    roots: &[PathBuf],
    launch_dir: Option<&Path>,
    canonicalize: fn(&Path) -> PathBuf,
) -> Option<PathBuf> {
    roots
        .first()
        .map(PathBuf::as_path)
        .or(launch_dir)
        .map(canonicalize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_command_is_spelled_to_run_where_the_reader_is() {
        assert_eq!(kin_command("init .", Spelling::Kin), "`kin init .`");
        assert_eq!(
            kin_command("init .", Spelling::Npx),
            format!("`npx -y @kinlab/kin@{} init .`", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn the_client_folder_is_its_first_root_or_the_launch_directory() {
        fn upper(path: &Path) -> PathBuf {
            PathBuf::from(path.display().to_string().to_uppercase())
        }
        let roots = vec![PathBuf::from("/work/a"), PathBuf::from("/work/b")];
        assert_eq!(
            client_root(&roots, Some(Path::new("/home")), upper),
            Some(PathBuf::from("/WORK/A"))
        );
        assert_eq!(
            client_root(&[], Some(Path::new("/home/x")), upper),
            Some(PathBuf::from("/HOME/X"))
        );
        assert_eq!(client_root(&[], None, upper), None);
    }

    /// The walkthrough's own answer: Go, no gopls, and imports this build
    /// never links.
    #[test]
    fn a_missing_language_server_is_named_with_the_command_that_adds_it() {
        let coverage = json!({
            "language": "Go",
            "reference_enrichment": "no_language_server",
            "classes": {"calls": "present", "imports": "unproduced", "references": "present"},
            "unproduced_evidence": {"imports": {"this_build_mints_no_entity_level_edge_for": ["Go"]}},
        });
        let advice = language_server_advice(&coverage, Spelling::Kin).unwrap();
        assert!(advice.starts_with("Missing: cross-file references and overrides for Go."));
        assert!(advice.contains("(gopls)"), "{advice}");
        assert!(advice.contains("`kin doctor --fix --install-language-servers`"));
        assert!(advice.contains("`kin daemon stop`"));
        assert!(advice.contains("lower bound"));
        assert!(
            advice.ends_with("Imports between Go files are not linked by this Kin build at all.")
        );
        assert!(!advice.contains('\u{2014}'));
        let npx = language_server_advice(&coverage, Spelling::Npx).unwrap();
        assert!(npx.contains("`npx -y @kinlab/kin@"), "{npx}");
    }

    #[test]
    fn a_server_that_will_not_start_points_at_the_diagnosis() {
        let coverage =
            json!({"language": "Python", "reference_enrichment": "language_server_unusable"});
        let advice = language_server_advice(&coverage, Spelling::Kin).unwrap();
        assert!(
            advice.contains("would not start") && advice.contains("`kin doctor`"),
            "{advice}"
        );
    }

    #[test]
    fn a_language_with_no_support_is_named_without_a_fix() {
        let coverage = json!({"language": "Cpp", "reference_enrichment": "unsupported"});
        let advice = language_server_advice(&coverage, Spelling::Kin).unwrap();
        assert!(advice.contains("for C++"), "{advice}");
        assert!(advice.contains("nothing installed on this machine adds them"));
        assert!(!advice.contains("doctor"));
    }

    #[test]
    fn no_gap_no_advice() {
        for coverage in [
            json!({"language": "Go", "reference_enrichment": "available"}),
            json!({"language": "Go"}),
            json!({"reference_enrichment": "no_language_server"}),
            json!({"language": "(no resolved language)", "reference_enrichment": "no_language_server"}),
        ] {
            assert_eq!(
                language_server_advice(&coverage, Spelling::Kin),
                None,
                "{coverage}"
            );
        }
    }

    #[test]
    fn several_languages_are_named_together() {
        let coverage =
            json!({"language": "Python, TypeScript", "reference_enrichment": "no_language_server"});
        let advice = language_server_advice(&coverage, Spelling::Kin).unwrap();
        assert!(advice.contains("for Python and TypeScript"), "{advice}");
        assert!(advice.contains("pyright-langserver or pylsp; typescript-language-server or vtsls"));
    }

    /// The advice is the first line of the answer that needs it: the first key
    /// of the envelope, which is the first key of the payload.
    #[test]
    fn the_advice_is_the_first_thing_an_answer_says() {
        let health = json!({"repo_root": "/work"});
        let base = crate::envelope::Envelope::daemon().with_repository(
            &health,
            Some(Path::new("/work/app")),
            Path::to_path_buf,
        );
        let payload = json!({
            "references": [],
            "edge_coverage": {"language": "Go", "reference_enrichment": "no_language_server"},
        });
        let result = crate::envelope::finalize(
            crate::types::ToolCallResult::text(payload.to_string()),
            base,
            "find_references",
        );
        let crate::types::ContentBlock::Text { text } = &result.content[0];
        // Served compact by default, the advice is the first bytes after the
        // envelope opens.
        assert!(text.starts_with("{\"_kin\":{\"advice\":\""), "{text}");
        // Asked for the pretty form, it is the first line after the envelope
        // opens.
        let pretty = crate::envelope::finalize_bounded(
            crate::types::ToolCallResult::text(payload.to_string()),
            crate::envelope::Envelope::daemon().with_repository(
                &health,
                Some(Path::new("/work/app")),
                Path::to_path_buf,
            ),
            "find_references",
            &crate::budget::ResponseBudget::from_arguments(&std::collections::HashMap::from([(
                "compact".to_string(),
                json!(false),
            )])),
        );
        let crate::types::ContentBlock::Text { text: pretty_text } = &pretty.content[0];
        let mut lines = pretty_text.lines();
        assert_eq!(lines.next(), Some("{"));
        assert_eq!(lines.next().map(str::trim), Some("\"_kin\": {"));
        let first = lines.next().unwrap().trim_start();
        assert!(first.starts_with("\"advice\": \""), "{pretty_text}");
        let value: Value = serde_json::from_str(text).unwrap();
        let advice = value["_kin"]["advice"].as_str().unwrap();
        assert!(
            advice.starts_with(
                "This answer comes from the Kin repository at /work, not from /work/app"
            ),
            "{advice}"
        );
        assert!(
            advice.contains("Missing: cross-file references and overrides for Go"),
            "{advice}"
        );
        assert_eq!(value["_kin"]["repository"]["root"], "/work");
        assert_eq!(value["_kin"]["repository"]["client_root"], "/work/app");

        // An answer from the client's own folder, with nothing missing, carries
        // the repository and no advice.
        let plain = crate::envelope::finalize(
            crate::types::ToolCallResult::text(json!({"references": []}).to_string()),
            crate::envelope::Envelope::daemon().with_repository(
                &health,
                Some(Path::new("/work")),
                Path::to_path_buf,
            ),
            "find_references",
        );
        let crate::types::ContentBlock::Text { text } = &plain.content[0];
        let value: Value = serde_json::from_str(text).unwrap();
        assert!(value["_kin"].get("advice").is_none(), "{text}");
        assert_eq!(value["_kin"]["repository"], json!({"root": "/work"}));
    }

    #[test]
    fn a_nested_client_folder_is_warned_about_and_the_same_folder_is_not() {
        let same = repository_identity(Path::new("/work/repo"), Some(Path::new("/work/repo")));
        assert_eq!(same.root, "/work/repo");
        assert_eq!(same.client_root, None);
        assert_eq!(same.warning, None);

        let nested = repository_identity(Path::new("/work"), Some(Path::new("/work/repo/app")));
        assert_eq!(nested.client_root.as_deref(), Some("/work/repo/app"));
        let warning = nested.warning.unwrap();
        assert!(
            warning.starts_with(
                "This answer comes from the Kin repository at /work, not from /work/repo/app"
            ),
            "{warning}"
        );
        assert!(
            warning.contains("no Kin repository of its own"),
            "{warning}"
        );
        assert!(warning.contains("`kin mcp start --repo`"), "{warning}");
        assert!(
            !warning.contains("git init") && !warning.contains("init ."),
            "no repository is created inside another: {warning}"
        );
        assert!(
            !warning.contains("kin_init"),
            "a remedy every profile can run: {warning}"
        );

        let elsewhere = repository_identity(Path::new("/work/a"), Some(Path::new("/work/b")));
        let elsewhere = elsewhere.warning.unwrap();
        assert!(
            elsewhere.contains("not from /work/b, the folder the client"),
            "{elsewhere}"
        );

        let unknown = repository_identity(Path::new("/work/a"), None);
        assert_eq!(unknown.warning, None);
    }

    /// A folder in the repository's `.kin/runs` directory, where a session launcher
    /// runs its child, is told which repository answered and nothing more: no
    /// remedy creates a repository there, and its path alone is not taken as
    /// proof of a session. Lookalikes outside `.kin/runs` are ordinary nested
    /// folders and keep that warning.
    #[test]
    fn a_folder_in_the_runs_directory_gets_the_facts_and_no_remedy() {
        for client in [
            "/work/repo/.kin/runs/session-3f2a",
            "/work/repo/.kin/runs/other",
        ] {
            let identity = repository_identity(Path::new("/work/repo"), Some(Path::new(client)));
            assert_eq!(identity.root, "/work/repo");
            assert_eq!(identity.client_root.as_deref(), Some(client));
            let warning = identity
                .warning
                .expect("the folder is told which repository answered");
            assert!(
                warning.starts_with("This answer comes from the Kin repository at /work/repo."),
                "{warning}"
            );
            assert!(warning.contains(".kin/runs directory"), "{warning}");
            for remedy in [
                "git init",
                "init .",
                "--repo",
                "session is",
                "whole repository",
            ] {
                assert!(!warning.contains(remedy), "{client}: {remedy}: {warning}");
            }
        }

        for client in [
            "/work/repo/runs/session-3f2a",
            "/work/repo/.kin/session-3f2a",
        ] {
            let identity = repository_identity(Path::new("/work/repo"), Some(Path::new(client)));
            let warning = identity.warning.expect("a nested folder is told");
            assert!(
                warning.contains("no Kin repository of its own"),
                "{warning}"
            );
            assert!(warning.contains("`kin mcp start --repo`"), "{warning}");
        }

        let runs_itself = repository_identity(
            Path::new("/work/repo"),
            Some(Path::new("/work/repo/.kin/runs")),
        );
        assert!(runs_itself
            .warning
            .expect("the runs directory itself is a nested folder")
            .contains("`kin mcp start --repo`"));
    }
}
