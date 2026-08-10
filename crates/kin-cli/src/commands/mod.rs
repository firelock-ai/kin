// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod admit;
pub mod approvals;
pub mod assistant;
pub mod assistant_adapter;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod bench;
pub mod bench_meta;
pub mod blame;
pub mod branch;
pub mod cache;
pub mod capabilities;
pub mod checkout;
pub mod clone;
pub mod cochange;
pub mod commit;
pub mod conflicts;
pub mod context;
pub mod contextbench_locate;
pub mod daemon;
pub mod dead_code;
pub mod declaration_neighbors;
pub mod deps;
pub mod diff;
pub mod drift;
pub mod eject;
pub mod embed;
pub mod git;
pub mod graph;
pub mod graph_health;
pub mod graph_viz;
pub mod health;
pub mod history;
pub mod impact;
pub mod init;
pub mod intent;
pub mod languages;
pub mod locate;
pub mod locate_cursor;
pub mod locate_debug;
pub mod locate_sizing;
pub mod locate_telemetry;
pub mod log;
pub mod managed_config_scope;
pub mod mcp;
pub mod merge;
pub mod migrate;
pub mod note;
pub mod notify;
pub mod overview;
pub mod pipeline;
pub mod prepared_state;
pub mod publish;
pub mod purge_ignored;
pub mod reconcile;
pub mod ref_lookup;
pub mod refs;
pub mod registry;
pub mod release_cmd;
pub mod release_orch;
pub mod remote;
pub mod rename;
pub mod repository_authority;
pub mod resolve;
pub mod resources;
pub mod review;
pub mod rollback;
pub mod scope;
pub mod search;
pub mod secret;
pub mod security;
pub mod semver;
pub mod session_run;
pub mod session_workspace;
pub mod setup;
pub mod setup_ledger;
pub mod spec;
pub mod stash;
pub mod status;
pub mod store_footprint;
pub mod support;
pub mod tag;
pub mod telemetry;
#[cfg(test)]
pub(crate) mod test_subprocess;
pub mod trace;
pub mod trace_data_flow;
pub mod traffic;
pub mod transfer;
pub mod update;
pub mod verify;
pub mod work;
pub mod xref;

/// Discover the Kin repository a command is bound to, or refuse by naming the
/// command that creates one.
///
/// Every command that needs a repository refuses through here so the refusal
/// cannot drift per command. Running a repository command from the wrong
/// directory is an ordinary first mistake, and a refusal that only states the
/// absence leaves the caller to guess the remedy.
pub(crate) fn require_repository_layout() -> anyhow::Result<kin_core::KinLayout> {
    require_repository_layout_at(&std::env::current_dir()?)
}

/// Discover the Kin repository containing `start`, refusing the same way.
pub(crate) fn require_repository_layout_at(
    start: &std::path::Path,
) -> anyhow::Result<kin_core::KinLayout> {
    kin_core::KinLayout::discover(start).ok_or_else(not_a_kin_repository)
}

/// The one wording every "you are not in a Kin repository" refusal is raised
/// with, so a command whose condition is its own still states the same remedy.
///
/// A few commands cannot phrase the condition as a discovery, because they hold
/// a specific directory and ask whether that exact directory is a repository.
/// Those raise this rather than restating it. The wording having one home is
/// what the enforcement scan below checks, and it checks the wording rather than
/// any one call spelling.
pub(crate) const NOT_A_KIN_REPOSITORY: &str =
    "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here";

pub(crate) fn not_a_kin_repository() -> anyhow::Error {
    anyhow::anyhow!(NOT_A_KIN_REPOSITORY)
}

/// The one remedy for a `.kin/` store this build cannot open.
///
/// Two messages have to agree on it. The store wall sends the reader to
/// `kin init`, and `kin init` refuses over an existing store, so a refusal that
/// named a different path would send the reader in a circle. The consistency
/// test in `commands::init` holds both texts against this token.
pub(crate) const REBUILD_INCOMPATIBLE_STORE: &str = "remove .kin/ and run `kin init`";

/// The wall a store written by an older kin is refused with.
///
/// The version gap leads, because it is the whole reason nothing else will
/// work. There is no in-place upgrade and no migration command, so the remedy
/// is the rebuild the reader can actually perform, and the case where that
/// rebuild has no source to draw on is named rather than left to be discovered.
pub(crate) fn incompatible_store_refusal(
    kin_root: &std::path::Path,
    error: &kin_core::KinError,
) -> String {
    format!(
        "{error} ({})\nAn older kin wrote this store and there is no in-place upgrade. Kin \
         re-derives the store from the repository's Git history, so {REBUILD_INCOMPATIBLE_STORE} \
         here to rebuild it. If the repository has no Git history to re-admit, keep a copy of \
         .kin/ and open it with the kin that wrote it.",
        kin_root.display()
    )
}

#[cfg(test)]
mod repository_refusal_tests {
    use super::{require_repository_layout_at, NOT_A_KIN_REPOSITORY};

    #[test]
    fn refusing_outside_a_repository_names_the_command_that_creates_one() {
        let empty = tempfile::tempdir().expect("temp dir");
        let err = require_repository_layout_at(empty.path())
            .expect_err("a directory with no .kin/ is not a repository");
        let message = err.to_string();
        assert!(
            message.contains("not a Kin repository"),
            "refusal must state the condition: {message}"
        );
        assert!(
            message.contains("kin init"),
            "refusal must name the remedy: {message}"
        );
    }

    /// Every `.rs` under `root`, other than `canonical`, paired with its text.
    fn crate_sources(root: &std::path::Path, canonical: &std::path::Path) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            let entries = std::fs::read_dir(&directory).expect("read crate sources");
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") || path == canonical
                {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read a crate source");
                found.push((path.display().to_string(), source));
            }
        }
        found
    }

    /// Byte offset just past the parenthesis closing the one at `open`.
    fn end_of_call(source: &str, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (offset, character) in source[open..].char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(open + offset + 1);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Where a discovery is refused in place: `discover(...)` handed straight
    /// to `ok_or_else`. This is one call shape, and naming it is the point.
    fn discovery_refused_in_place(
        root: &std::path::Path,
        canonical: &std::path::Path,
    ) -> Vec<String> {
        const DISCOVERY: &str = "KinLayout::discover(";
        const REFUSAL: &str = ".ok_or_else(";

        let mut found = Vec::new();
        for (path, source) in crate_sources(root, canonical) {
            let mut cursor = 0;
            while let Some(hit) = source[cursor..].find(DISCOVERY) {
                let open = cursor + hit + DISCOVERY.len() - 1;
                let closed = end_of_call(&source, open).unwrap_or(source.len());
                if source[closed..].trim_start().starts_with(REFUSAL) {
                    let line = source[..open].lines().count();
                    found.push(format!("{path}:{line}"));
                }
                cursor = open + 1;
            }
        }
        found.sort();
        found
    }

    /// Where the refusal's own wording is written out again.
    ///
    /// Keyed on the condition sentence rather than on any call spelling, which
    /// is what makes it blind to how the refusal is raised: `ok_or_else`,
    /// `context`, `bail!`, a `match`, or a `let ... else` all carry the same
    /// sentence and are all caught. A test that needs the whole sentence reads
    /// it from `NOT_A_KIN_REPOSITORY` rather than repeating it, so a literal
    /// copy anywhere else is a second home for the wording rather than an
    /// assertion about it.
    fn refusal_wording_restated(
        root: &std::path::Path,
        canonical: &std::path::Path,
    ) -> Vec<String> {
        let condition = NOT_A_KIN_REPOSITORY
            .split('\n')
            .next()
            .expect("the refusal states its condition before its remedy");

        let mut found = Vec::new();
        for (path, source) in crate_sources(root, canonical) {
            let mut cursor = 0;
            while let Some(hit) = source[cursor..].find(condition) {
                let at = cursor + hit;
                let line = source[..at].lines().count();
                found.push(format!("{path}:{line}"));
                cursor = at + condition.len();
            }
        }
        found.sort();
        found
    }

    fn crate_source_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    #[test]
    fn no_command_hand_rolls_the_repository_refusal() {
        // One home for the wording only holds while it stays the only home. A
        // command reverting to a local refusal reads as an ordinary two-line
        // diff and would otherwise pass every gate while dropping the remedy
        // the caller needs. This scan reads the wording, so it does not care
        // which combinator raised it; a command whose condition genuinely is
        // its own still raises `not_a_kin_repository()` rather than restating
        // the sentence.
        let sources = crate_source_root();
        let canonical = sources.join("commands").join("mod.rs");
        assert!(canonical.is_file(), "canonical refusal file must exist");

        let restated = refusal_wording_restated(&sources, &canonical);
        assert!(
            restated.is_empty(),
            "the repository refusal has one home; raise it with \
             require_repository_layout, require_repository_layout_at, or \
             not_a_kin_repository rather than writing the wording again; restated at {restated:?}"
        );
    }

    #[test]
    fn no_command_refuses_a_discovery_in_place() {
        // The narrower shape, kept because it is the one that produced 81
        // copies and it catches a hand-rolled refusal even when the wording
        // drifts too. Deliberate exceptions refuse on their own condition
        // rather than on discovery, so they are outside this shape by
        // construction.
        let sources = crate_source_root();
        let canonical = sources.join("commands").join("mod.rs");

        let in_place = discovery_refused_in_place(&sources, &canonical);
        assert!(
            in_place.is_empty(),
            "a command refusing outside a repository must refuse through \
             require_repository_layout or require_repository_layout_at, so the condition and \
             the remedy cannot drift apart again; hand-rolled at {in_place:?}"
        );
    }

    #[test]
    fn an_equivalent_spelling_is_caught_by_the_wording_scan_the_shape_scan_misses() {
        // The falsification, run rather than described. A refusal spelled with
        // `context` instead of `ok_or_else` is the same refusal, and a guard
        // that only recognised one of the two would keep passing while the
        // wording it exists to protect had quietly grown a second home.
        let staged = tempfile::tempdir().expect("temp dir");
        let commands = staged.path().join("commands");
        std::fs::create_dir_all(&commands).expect("stage a crate source tree");
        let canonical = commands.join("mod.rs");
        std::fs::write(&canonical, "// the canonical refusal lives here\n")
            .expect("stage the canonical file");

        let hand_rolled = commands.join("invented.rs");
        std::fs::write(
            &hand_rolled,
            format!(
                "use anyhow::Context;\nfn run(cwd: &std::path::Path) -> anyhow::Result<()> {{\n    \
                 let _layout = kin_core::KinLayout::discover(cwd).context({:?})?;\n    Ok(())\n}}\n",
                NOT_A_KIN_REPOSITORY
            ),
        )
        .expect("stage a hand-rolled refusal");

        assert!(
            discovery_refused_in_place(staged.path(), &canonical).is_empty(),
            "the call-shape scan does not see a context() spelling, which is why it is not the \
             only guard"
        );
        assert_eq!(
            refusal_wording_restated(staged.path(), &canonical),
            vec![format!("{}:3", hand_rolled.display())],
            "the wording scan must name the file and line that restated the refusal"
        );
    }
}
