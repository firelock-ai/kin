// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The page `kin status` prints on a terminal.
//!
//! The full record is durable authority truth, line by line: ids, generations,
//! payload bytes, the projection and the daemon's memory. `--verbose`,
//! `--json`, a pipe and CI keep it byte for byte, because scripts and the
//! acceptance suites read it. A person at a terminal asked a smaller question:
//! is this repository in step with the files on disk, and is search ready. This
//! page answers that, carries every warning the full record raises, and names
//! the flag that shows the rest. The exit code is the full record's.

use crate::screen::{self, Status, Style, INDENT};

/// Width of the label column.
const LABEL: usize = 12;

/// What the page says, already reduced from the report to plain words.
///
/// Kept apart from the report so the layout can be graded without a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Page {
    /// The repository's directory name.
    pub name: String,
    /// The branch the workspace is on, or how it is detached.
    pub branch: String,
    /// What the graph holds.
    pub graph: String,
    /// Whether the working copy matches the graph, and on what basis.
    pub working_tree: String,
    /// The one command that settles an unchecked or changed working copy.
    pub working_hint: Option<String>,
    /// Files on disk the graph does not hold, when a daemon counted some.
    pub untracked: Option<String>,
    /// How far the search index has got.
    pub search: String,
    /// Every warning the full record raises, as sentences.
    pub attention: Vec<String>,
}

/// The page's lines, each kept inside `right_edge` columns.
pub(super) fn lines(style: Style, page: &Page, right_edge: usize) -> Vec<String> {
    let value_width = right_edge.saturating_sub(INDENT.len() + LABEL + 2).max(24);
    let mut out = vec![
        format!(
            "{INDENT}{} {} {}",
            style.bold(&page.name),
            style.dot(),
            page.branch
        ),
        String::new(),
    ];
    let row = |out: &mut Vec<String>, label: &str, value: &str| {
        for (index, part) in screen::wrap(value, value_width).into_iter().enumerate() {
            let label = if index == 0 { label } else { "" };
            out.push(format!(
                "{INDENT}{}  {part}",
                style.faint(&format!("{label:<LABEL$}"))
            ));
        }
    };
    row(&mut out, "Graph", &page.graph);
    row(&mut out, "Working tree", &page.working_tree);
    if let Some(untracked) = &page.untracked {
        row(&mut out, "Untracked", untracked);
    }
    row(&mut out, "Search index", &page.search);
    if let Some(hint) = &page.working_hint {
        out.push(String::new());
        // Sentence by sentence, so a command that opens a sentence also opens
        // its line and is never split from its subcommand.
        for sentence in hint.split_inclusive(". ") {
            for part in screen::wrap(
                sentence.trim_end(),
                right_edge.saturating_sub(INDENT.len()).max(24),
            ) {
                out.push(format!("{INDENT}{part}"));
            }
        }
    }
    if !page.attention.is_empty() {
        out.push(String::new());
        let width = right_edge.saturating_sub(INDENT.len() + 2).max(24);
        for item in &page.attention {
            for (index, part) in screen::wrap(item, width).into_iter().enumerate() {
                if index == 0 {
                    out.push(format!("{INDENT}{} {part}", style.glyph(Status::Warn)));
                } else {
                    out.push(format!("{INDENT}  {part}"));
                }
            }
        }
    }
    out.push(String::new());
    out.push(format!(
        "{INDENT}{}  {}",
        style.lilac(&format!("{:<LABEL$}", "More")),
        style.bold("kin status --verbose")
    ));
    out
}

/// A full-record warning as it reads on its own, without the clause that
/// points at where it sat among the full record's lines.
pub(super) fn standalone(line: &str) -> String {
    line.replace(", and nothing below describes it", "")
        .replace(", and nothing above describes it", "")
}

/// `refs/heads/main` as `main`; any other ref as itself.
pub(super) fn branch_name(reference: &str) -> String {
    reference
        .strip_prefix("refs/heads/")
        .unwrap_or(reference)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Page {
        Page {
            name: "itsdangerous".to_string(),
            branch: "main".to_string(),
            graph: "197 entities · 556 relations".to_string(),
            working_tree: "matches main".to_string(),
            working_hint: None,
            untracked: None,
            search: "429 entries".to_string(),
            attention: Vec::new(),
        }
    }

    /// A repository in step reads as a handful of short lines and the flag for
    /// the rest, with none of the full record's internals.
    #[test]
    fn a_repository_in_step_is_a_few_short_lines() {
        let lines = lines(Style::plain(), &healthy(), 58);
        assert_eq!(
            lines,
            vec![
                "  itsdangerous · main",
                "",
                "  Graph         197 entities · 556 relations",
                "  Working tree  matches main",
                "  Search index  429 entries",
                "",
                "  More          kin status --verbose",
            ]
        );
    }

    /// An unchecked working copy says so on its row and names the command
    /// that checks it, and every warning is carried, wrapped inside the width.
    #[test]
    fn an_unchecked_tree_and_its_warnings_fit_sixty_columns() {
        let mut page = healthy();
        page.working_tree = "not checked: no daemon is running for this repository".to_string();
        page.working_hint = Some(
            "New files are checked only while a daemon runs. kin admit checks everything now."
                .to_string(),
        );
        page.search = "not read: no daemon is running".to_string();
        page.attention = vec![standalone(
            "Merge in progress: feature into main as merge transaction 7, 1 of 3 conflict(s) \
             settled; `kin conflicts` lists what is outstanding, and nothing below describes it",
        )];
        let lines = lines(Style::plain(), &page, 58);
        for line in &lines {
            assert!(console::measure_text_width(line) <= 58, "{line:?}");
        }
        let text = lines.join("\n");
        assert!(
            text.contains("Working tree  not checked: no daemon"),
            "{text}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.trim() == "kin admit checks everything now."),
            "the command opens its own line: {text}"
        );
        assert!(
            !lines.iter().any(|line| line.trim_end().ends_with(" kin")),
            "no command is split across lines: {text}"
        );
        assert!(
            text.contains("! Merge in progress: feature into main"),
            "{text}"
        );
        assert!(!text.contains("nothing below describes it"), "{text}");
        assert!(
            text.ends_with("More          kin status --verbose"),
            "{text}"
        );
    }

    #[test]
    fn a_branch_ref_reads_as_its_name() {
        assert_eq!(branch_name("refs/heads/main"), "main");
        assert_eq!(branch_name("refs/tags/v1"), "refs/tags/v1");
    }
}
