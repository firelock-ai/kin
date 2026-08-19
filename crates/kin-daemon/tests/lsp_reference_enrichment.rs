// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The cross-file reference edge, proved against a real language server.
//!
//! Both fixtures below are shaped like a loss that actually happened on shipped
//! v0.5.42 bytes, where cross-file resolution fell back to matching bare names:
//! that fallback fabricated nine of eleven edges on an express-shaped
//! JavaScript repository and dropped both load-bearing call sites on a
//! requests-shaped Python one.
//!
//! Each fixture holds TWO entities with the SAME name, and the edge under test
//! is the one that distinguishes them. That is the whole point. A bare-name
//! matcher cannot pass these tests by luck: it has a fifty-fifty choice and no
//! information to make it with, so an assertion that the edge lands on the
//! right one of the two is an assertion that something resolved the receiver.
//! Asserting merely that "an edge exists" would pass on the broken build.
//!
//! Every test here needs a real language server. When one is absent the test
//! SKIPS LOUDLY with the binary it looked for and the command that installs it,
//! and never passes quietly: a proof that silently degrades to a no-op is worse
//! than no proof, because the run is green either way.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use kin_daemon::daemon::lsp_adapter_for;
use kin_index::RelationResolution;
use kin_lsp::{EntityIndex, EntityRef};
use kin_model::{EntityId, GraphNodeId, LanguageId};

/// How long a server is given to index a fixture of a dozen lines.
///
/// Generous rather than tight: a slow CI runner producing a flaky failure here
/// would be read as an enrichment defect, which is the worst outcome this file
/// can have.
const INDEX_BUDGET: Duration = Duration::from_secs(60);

/// Resolve the server for `language`, or explain the skip and return `None`.
fn server_command_or_skip(language: LanguageId, test: &str) -> Option<(String, Vec<String>)> {
    let root = Path::new("/");
    let Some((command, args, _)) = lsp_adapter_for(language, root) else {
        panic!(
            "{test}: {language} has no adapter in this build, which contradicts \
             ENRICHABLE_LANGUAGES"
        );
    };
    match which::which(&command) {
        Ok(path) => {
            eprintln!("{test}: using {language} language server at {}", path.display());
            Some((command, args))
        }
        Err(_) => {
            eprintln!(
                "SKIP {test}: no `{command}` on PATH, so the {language} enrichment path cannot be \
                 exercised on this host. Install it with `{}` and re-run.",
                install_hint(language)
            );
            None
        }
    }
}

/// The command that provisions a language's server, mirrored from
/// `kin_cli::commands::language_servers` so the skip message names a real fix.
fn install_hint(language: LanguageId) -> &'static str {
    match language {
        LanguageId::Python => "npm install -g pyright",
        LanguageId::TypeScript | LanguageId::JavaScript => {
            "npm install -g typescript-language-server typescript"
        }
        LanguageId::Rust => "rustup component add rust-analyzer",
        _ => "see `kin doctor`",
    }
}

/// Start a server against `root` and wait for it to finish indexing.
async fn start_server(
    command: &str,
    args: &[String],
    root: &Path,
    language: LanguageId,
) -> kin_lsp::lifecycle::LspServer {
    let (_, _, init_opts) = lsp_adapter_for(language, root).expect("adapter must exist");
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let server = kin_lsp::lifecycle::LspServer::start(command, &arg_refs, root, init_opts)
        .await
        .unwrap_or_else(|error| panic!("could not start `{command}` against the fixture: {error}"));

    // Poll the same way the daemon does rather than sleeping a fixed amount:
    // an unindexed server answers prepareCallHierarchy with an empty list, and
    // an empty list is exactly what a real miss looks like.
    let deadline = tokio::time::Instant::now() + INDEX_BUDGET;
    loop {
        if server
            .client
            .request("workspace/symbol", serde_json::json!({ "query": "" }))
            .await
            .is_ok()
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    server
}

/// Open every fixture file, the way the daemon does before it enriches.
///
/// `enrich_entity_calls` goes straight to `prepareCallHierarchy`, so a server
/// that was never told about the documents answers with an empty list, which is
/// indistinguishable from a genuine miss. The first run of this file failed
/// exactly that way, which is the behaviour these assertions were written to
/// catch, so the harness performs the open rather than the assertions being
/// loosened to tolerate it.
async fn open_documents(
    server: &kin_lsp::lifecycle::LspServer,
    root: &Path,
    files: &[&str],
    language_id: &str,
) {
    for file in files {
        let path = root.join(file);
        let text = std::fs::read_to_string(&path).expect("fixture file must exist");
        let uri = kin_lsp::protocol::path_to_uri(&path);
        let _ = server
            .client
            .notify(
                "textDocument/didOpen",
                serde_json::json!({
                    "textDocument": {
                        "uri": uri,
                        "languageId": language_id,
                        "version": 1,
                        "text": text,
                    }
                }),
            )
            .await;
    }
    // The daemon waits after the first open per language for the same reason:
    // a server processes didOpen asynchronously and answers queries about a
    // document it has not read yet with an empty result.
    tokio::time::sleep(Duration::from_secs(5)).await;
}

/// One entity in the fixture's index. `name_line`/`name_col` are where the
/// server's cursor has to land, which for both languages is the identifier
/// itself rather than the `def`/`function` keyword.
struct Fixture {
    id: EntityId,
    name: &'static str,
    file: &'static str,
    name_line: u32,
    name_col: u32,
}

fn entity_refs(fixtures: &[Fixture]) -> Vec<EntityRef> {
    fixtures
        .iter()
        .map(|fixture| EntityRef {
            id: fixture.id,
            name: fixture.name.to_string(),
            file_path: fixture.file.to_string(),
            start_line: fixture.name_line,
            start_col: 0,
            end_line: fixture.name_line + 2,
            name_line: fixture.name_line,
            name_col: fixture.name_col,
        })
        .collect()
}

/// The Python loss, rebuilt: `Session.send` reaches `HTTPAdapter.send` through
/// `self.connection`, and a second method named `send` sits on the mixin so a
/// name match has no way to pick the right one.
#[tokio::test(flavor = "multi_thread")]
async fn python_resolves_a_call_through_an_attribute_that_a_name_match_cannot() {
    const TEST: &str = "python_resolves_a_call_through_an_attribute_that_a_name_match_cannot";
    let Some((command, args)) = server_command_or_skip(LanguageId::Python, TEST) else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(
        root.join("adapters.py"),
        "class HTTPAdapter:\n    def send(self, request):\n        return \"adapter\"\n",
    )
    .expect("write adapters.py");
    std::fs::write(
        root.join("sessions.py"),
        "from adapters import HTTPAdapter\n\
         \n\
         \n\
         class SendMixin:\n\
         \x20   def send(self, request):\n\
         \x20       return \"mixin\"\n\
         \n\
         \n\
         class Session(SendMixin):\n\
         \x20   def __init__(self):\n\
         \x20       self.connection = HTTPAdapter()\n\
         \n\
         \x20   def dispatch(self, request):\n\
         \x20       return self.connection.send(request)\n",
    )
    .expect("write sessions.py");
    // pyright resolves imports against the workspace root only when it knows it
    // is one; without a config it still works here, but the file makes the
    // fixture independent of the server's default discovery.
    std::fs::write(root.join("pyrightconfig.json"), "{\"include\": [\".\"]}\n")
        .expect("write pyrightconfig.json");

    let adapter_send = EntityId::new();
    let mixin_send = EntityId::new();
    let dispatch = EntityId::new();
    let fixtures = [
        Fixture {
            id: adapter_send,
            name: "send",
            file: "adapters.py",
            name_line: 1,
            name_col: 8,
        },
        Fixture {
            id: mixin_send,
            name: "send",
            file: "sessions.py",
            name_line: 4,
            name_col: 8,
        },
        Fixture {
            id: dispatch,
            name: "dispatch",
            file: "sessions.py",
            name_line: 12,
            name_col: 8,
        },
    ];
    let refs = entity_refs(&fixtures);
    let caller = refs
        .iter()
        .find(|r| r.id == dispatch)
        .expect("caller")
        .clone();
    let index = EntityIndex::new(refs);

    let server = start_server(&command, &args, root, LanguageId::Python).await;
    open_documents(&server, root, &["adapters.py", "sessions.py"], "python").await;
    let relations = kin_lsp::enrichment::enrich_entity_calls(&server, &caller, &index, root)
        .await
        .expect("enrichment must not error");

    let targets: Vec<GraphNodeId> = relations.iter().map(|relation| relation.dst).collect();
    assert!(
        targets.contains(&GraphNodeId::Entity(adapter_send)),
        "Session.dispatch must resolve to HTTPAdapter.send through self.connection; got {targets:?}"
    );
    assert!(
        !targets.contains(&GraphNodeId::Entity(mixin_send)),
        "resolution landed on the same-named mixin method, which is the bare-name guess this \
         fixture exists to rule out: {targets:?}"
    );

    let edge = relations
        .iter()
        .find(|relation| relation.dst == GraphNodeId::Entity(adapter_send))
        .expect("the resolved edge");
    assert_eq!(
        RelationResolution::of(edge),
        RelationResolution::TypeResolved,
        "a language-server edge must classify as type_resolved, not as a name guess"
    );
    assert!(
        RelationResolution::of(edge).is_proven(),
        "the edge must be countable as evidence that the destination is used"
    );
}

/// The express-shaped JavaScript loss: `listen` reaches `router.handle` through
/// a `require` chain, and a second `handle` in the calling file gives a name
/// match something wrong to choose.
#[tokio::test(flavor = "multi_thread")]
async fn javascript_resolves_a_require_chain_that_a_name_match_cannot() {
    const TEST: &str = "javascript_resolves_a_require_chain_that_a_name_match_cannot";
    let Some((command, args)) = server_command_or_skip(LanguageId::JavaScript, TEST) else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(
        root.join("router.js"),
        "function handle(req) {\n  return req.url;\n}\n\nmodule.exports = { handle };\n",
    )
    .expect("write router.js");
    std::fs::write(
        root.join("app.js"),
        "const router = require('./router');\n\
         \n\
         function handle(req) {\n\
         \x20 return 'local';\n\
         }\n\
         \n\
         function listen(req) {\n\
         \x20 return router.handle(req);\n\
         }\n\
         \n\
         module.exports = { listen, handle };\n",
    )
    .expect("write app.js");
    std::fs::write(root.join("jsconfig.json"), "{\"include\": [\"*.js\"]}\n")
        .expect("write jsconfig.json");

    let router_handle = EntityId::new();
    let local_handle = EntityId::new();
    let listen = EntityId::new();
    let fixtures = [
        Fixture {
            id: router_handle,
            name: "handle",
            file: "router.js",
            name_line: 0,
            name_col: 9,
        },
        Fixture {
            id: local_handle,
            name: "handle",
            file: "app.js",
            name_line: 2,
            name_col: 9,
        },
        Fixture {
            id: listen,
            name: "listen",
            file: "app.js",
            name_line: 6,
            name_col: 9,
        },
    ];
    let refs = entity_refs(&fixtures);
    let caller = refs.iter().find(|r| r.id == listen).expect("caller").clone();
    let index = EntityIndex::new(refs);

    let server = start_server(&command, &args, root, LanguageId::JavaScript).await;
    open_documents(&server, root, &["router.js", "app.js"], "javascript").await;
    let relations = kin_lsp::enrichment::enrich_entity_calls(&server, &caller, &index, root)
        .await
        .expect("enrichment must not error");

    let targets: Vec<GraphNodeId> = relations.iter().map(|relation| relation.dst).collect();
    assert!(
        targets.contains(&GraphNodeId::Entity(router_handle)),
        "listen must resolve to router.handle across the require chain; got {targets:?}"
    );
    assert!(
        !targets.contains(&GraphNodeId::Entity(local_handle)),
        "resolution landed on the same-named function in the calling file, which is the \
         fabricated edge this fixture exists to rule out: {targets:?}"
    );

    let edge = relations
        .iter()
        .find(|relation| relation.dst == GraphNodeId::Entity(router_handle))
        .expect("the resolved edge");
    assert_eq!(
        RelationResolution::of(edge),
        RelationResolution::TypeResolved,
        "a language-server edge must classify as type_resolved"
    );
}

/// The other half of the contract: with no server, the state is an actionable
/// gap that names itself, rather than an absence a reader would take as fact.
///
/// Needs no server, so it runs everywhere and is what keeps this file honest on
/// a runner where both tests above skip.
#[test]
fn without_a_server_an_enrichable_language_reports_an_actionable_gap() {
    use kin_core::reference_coverage::{reference_enrichment_for, ReferenceEnrichment};

    let none_installed: HashSet<LanguageId> = HashSet::new();
    for language in [
        LanguageId::Python,
        LanguageId::JavaScript,
        LanguageId::TypeScript,
        LanguageId::Rust,
    ] {
        let state = reference_enrichment_for(language, &none_installed);
        assert_eq!(
            state,
            ReferenceEnrichment::NoLanguageServer,
            "{language} with no server installed"
        );
        assert!(
            state.is_actionable_gap(),
            "{language}: a missing server is a gap an operator can close, so it must be surfaced"
        );
    }

    // And with the server present the same call reports the capability rather
    // than the gap, so the row above cannot be an unconditional warning.
    let mut installed = HashSet::new();
    installed.insert(LanguageId::JavaScript);
    let state = reference_enrichment_for(LanguageId::JavaScript, &installed);
    assert_eq!(state, ReferenceEnrichment::Available);
    assert!(!state.is_actionable_gap());
}

/// JavaScript and TypeScript must no longer report `Unsupported`.
///
/// This is the exact string an express-shaped repository read on shipped
/// v0.5.42 bytes. `Unsupported` says the build wires no adapter, which was true
/// then and is false now, and the difference matters because `Unsupported` is
/// deliberately NOT an actionable gap: a reader is told there is nothing to do.
#[test]
fn javascript_no_longer_reports_the_unsupported_state_it_shipped_with() {
    use kin_core::reference_coverage::{reference_enrichment_for, ReferenceEnrichment};

    let none_installed: HashSet<LanguageId> = HashSet::new();
    for language in [LanguageId::JavaScript, LanguageId::TypeScript] {
        assert_ne!(
            reference_enrichment_for(language, &none_installed),
            ReferenceEnrichment::Unsupported,
            "{language} is wired now, so an absent server is a host gap rather than a build limit"
        );
    }

    // The control: a language this build genuinely does not wire still reports
    // Unsupported, so the assertion above is about JavaScript rather than about
    // the function having stopped returning that state at all.
    assert_eq!(
        reference_enrichment_for(LanguageId::Ruby, &none_installed),
        ReferenceEnrichment::Unsupported,
        "an unwired language must still report Unsupported"
    );
}
