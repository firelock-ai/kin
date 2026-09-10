// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Where the CLI looks for graph truth when it reads local storage directly.
//!
//! `kin graph viz`, `kin locate-debug` and `kin remote` share one offline/admin
//! open, and it used to address the fixed `.kin/kindb/graph.kndb`. Repository-v6
//! stopped writing that file: graph truth lives in `.kin/kindb/<repository-id>/`,
//! which is where the daemon's backend puts it. KinDB answers a path holding no
//! artifacts with a valid EMPTY graph and no error, because for an
//! uninitialized namespace that is the right answer, so the CLI drew a blank
//! canvas at exit 0 against a store holding 20,298 entities and said nothing.
//!
//! Every case here admits a real Git repository through the real import
//! boundary, so the namespace under test is the one the product writes rather
//! than a directory a test built to match its own expectation.

use std::path::Path;

use kin_model::{EntityStore, RepositoryId};
use tempfile::{tempdir, TempDir};

mod common;

use common::Command;

/// A real admitted store, plus the identity and layout that name it.
struct Fixture {
    _working: TempDir,
    layout: kin_core::KinLayout,
    repository_id: RepositoryId,
}

impl Fixture {
    fn namespace(&self) -> std::path::PathBuf {
        self.layout
            .kindb_namespace_path(self.repository_id.as_str())
    }
}

/// Run one git command in the fixture, with the developer's own configuration
/// held off.
///
/// The `-c` flags are not decoration. This machine's global git configuration
/// carries hooks and commit signing, and a fixture that inherited either would
/// fail for a reason that has nothing to do with the property under test. The
/// bounded `common::Command` is the harness every other kin-cli integration
/// test uses; `kin_git::test_support::fixture_git_in` cannot spawn its
/// process-group guardian from this test binary.
fn git(repository: &Path, args: &[&str]) {
    let base = [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Kin Fixture",
        "-c",
        "user.email=kin@example.invalid",
    ];
    let output = Command::new("git")
        .args(base.iter().copied().chain(args.iter().copied()))
        .current_dir(repository)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Admit a two-function Rust file through the real Git import.
///
/// Two functions and a call between them rather than an empty tree: the whole
/// property under test is "non-empty", and a fixture that admits nothing would
/// make the defect and the fix indistinguishable.
fn admitted_store() -> Fixture {
    let working = tempdir().expect("temp working directory");
    std::fs::create_dir_all(working.path().join("src")).expect("create src");
    std::fs::write(
        working.path().join("src/lib.rs"),
        b"pub fn greeting(name: &str) -> String { format!(\"hello {name}\") }\n\
          pub fn greet_world() -> String { greeting(\"world\") }\n",
    )
    .expect("write fixture source");
    git(working.path(), &["init", "--initial-branch=main"]);
    git(working.path(), &["add", "--all"]);
    git(working.path(), &["commit", "-m", "import semantic fixture"]);

    let repository_id =
        RepositoryId::new(format!("viz-namespace-{}", uuid::Uuid::new_v4().simple()))
            .expect("valid repository identity");
    let initialized = kin_core::init_from_git_adopting(working.path(), &repository_id)
        .expect("the fixture must be admitted through the real Git import");

    Fixture {
        _working: working,
        layout: initialized.layout,
        repository_id,
    }
}

/// Open the fixture's store expecting a refusal, and return the refusal text.
///
/// A match rather than `expect_err`, for two reasons. `SnapshotManager` is not
/// `Debug`, so `expect_err` will not compile over it at all. More usefully, the
/// regression this guards against does not return a broken graph, it returns a
/// perfectly good EMPTY one, so the panic reports the entity count it opened
/// with. "it answered a graph of 0 entities rather than refusing" names the
/// defect; "expected Err" would only say an assertion failed.
fn refusal_or_panic(fixture: &Fixture, what: &str) -> String {
    match kin_cli::backend::open_snapshot_local(&fixture.layout) {
        Ok(snapshot) => {
            let entities = snapshot
                .graph()
                .list_all_entities()
                .map(|entities| entities.len());
            panic!(
                "{what} must refuse rather than answer; it opened {} at {} and reported {entities:?} entities",
                fixture.repository_id,
                fixture.namespace().display(),
            )
        }
        Err(error) => error.to_string(),
    }
}

/// The local open reads the namespace the product actually writes, and reads it
/// non-empty.
///
/// The third assertion is the falsification, and it is the reason this test can
/// fail. Opening the retired flat path is pinned here as returning a valid,
/// silent, EMPTY graph on this same store: so if the local open ever addresses
/// that path again, the non-empty assertion goes red while the empty one stays
/// green, and the failure names the exact regression rather than a vague
/// "graph was empty".
#[test]
fn the_local_open_reads_the_repository_id_namespace_not_the_retired_flat_path() {
    let fixture = admitted_store();
    let namespace = fixture.namespace();

    assert!(
        namespace.join("authority.json").is_file(),
        "the real import must write authority into {}",
        namespace.display()
    );
    assert!(
        !fixture.layout.kindb_snapshot_path().exists(),
        "nothing writes the retired flat snapshot {}; if this file appeared, \
         the premise of this test changed",
        fixture.layout.kindb_snapshot_path().display()
    );

    let snapshot = kin_cli::backend::open_snapshot_local(&fixture.layout)
        .expect("the local open must find the admitted namespace");
    let entities = snapshot
        .graph()
        .list_all_entities()
        .expect("list entities from the opened graph");
    assert!(
        !entities.is_empty(),
        "the local open resolved a namespace but reported no entities; the \
         fixture admitted two functions"
    );

    // The defect's mechanism, pinned. This is not a bug being asserted as
    // correct: it is KinDB's documented answer for a namespace with nothing in
    // it, and the whole point is that the CLI must not ask it that question.
    let flat = kin_db::SnapshotManager::open_read_only(fixture.layout.kindb_snapshot_path())
        .expect("kin-db answers a bare path with an empty graph rather than an error");
    assert!(
        flat.graph()
            .list_all_entities()
            .expect("list entities from the flat path")
            .is_empty(),
        "the retired flat path must answer empty on a populated store; if it \
         answered non-empty, this test no longer discriminates the two paths"
    );
}

/// A namespace that is not there is an error naming the directory and the
/// identity, never an empty graph.
#[test]
fn an_absent_namespace_fails_loud_and_names_the_path_it_read() {
    let fixture = admitted_store();
    let namespace = fixture.namespace();
    std::fs::remove_dir_all(&namespace).expect("remove the resolved namespace");

    let error = refusal_or_panic(&fixture, "an absent namespace");

    assert!(
        error.contains(&namespace.display().to_string()),
        "the refusal must name the directory it looked at: {error}"
    );
    assert!(
        error.contains(fixture.repository_id.as_str()),
        "the refusal must name the repository id it resolved: {error}"
    );
}

/// A namespace whose authority record is gone is an error naming the directory
/// and the identity, never an empty graph.
///
/// Separate from the absent-directory case because the two reach different
/// refusals, and because this is the shape a half-written or truncated store
/// takes: everything present except the record that says what is authoritative.
#[test]
fn a_namespace_without_its_authority_record_fails_loud_and_names_the_path() {
    let fixture = admitted_store();
    let namespace = fixture.namespace();
    std::fs::remove_file(namespace.join("authority.json"))
        .expect("remove the namespace authority record");

    let error = refusal_or_panic(&fixture, "a namespace with no authority record");

    assert!(
        error.contains(&namespace.display().to_string()),
        "the refusal must name the directory it looked at: {error}"
    );
    assert!(
        error.contains(fixture.repository_id.as_str()),
        "the refusal must name the repository id it resolved: {error}"
    );
}

/// The resolver and the backend spell the namespace the same way.
///
/// Both halves of the original defect were path rules that disagreed while each
/// looked reasonable on its own, so this asserts the agreement directly against
/// a directory the import actually created.
#[test]
fn the_layout_resolver_names_the_directory_the_import_created() {
    let fixture = admitted_store();

    assert_eq!(
        fixture.namespace(),
        fixture
            .layout
            .kindb_dir()
            .join(fixture.repository_id.as_str())
    );
    assert!(
        fixture.namespace().is_dir(),
        "the resolver must name a directory that exists after a real import: {}",
        fixture.namespace().display()
    );
}
