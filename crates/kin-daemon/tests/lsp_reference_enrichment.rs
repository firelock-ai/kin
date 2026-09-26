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

/// Set by a runner provisioned for the Go proof, once gopls and the `go` command
/// it loads packages through are both installed and answer. A runner that sets
/// it and lacks either fails the proof rather than skipping it.
const GO_LANGUAGE_SERVER_PROVISIONED: &str = "KIN_CI_GO_LANGUAGE_SERVER_INSTALLED";

/// Resolve the server for `language`, or explain the skip and return `None`.
fn server_command_or_skip(language: LanguageId, test: &str) -> Option<(String, Vec<String>)> {
    // Only the command is read here. A root with nothing under it keeps the
    // adapters' workspace discovery from reading a real tree.
    let root = Path::new("/nonexistent-kin-workspace");
    let Some((command, args, _)) = lsp_adapter_for(language, root) else {
        panic!(
            "{test}: {language} has no adapter in this build, which contradicts \
             ENRICHABLE_LANGUAGES"
        );
    };
    // In CI the skip is not allowed to be quiet. `scripts/ci-install-language-servers.sh`
    // sets KIN_CI_LANGUAGE_SERVERS_INSTALLED only after proving its binaries are
    // executable, so if it is set and a binary is still missing, the proof is being
    // skipped in the one environment built to run it. A skip that nextest swallows (it
    // captures a passing test's stderr) would read as a 0.02s pass, which is what a real
    // run never looks like and what nobody would notice.
    //
    // The script provisions pyright and typescript-language-server and nothing else, so
    // only a missing one of those contradicts it. A runner provisioned for Go says so with
    // its own variable, because the Go proof needs a toolchain the script does not install.
    let provisioned = match language {
        LanguageId::Python | LanguageId::TypeScript | LanguageId::JavaScript => {
            std::env::var_os("KIN_CI_LANGUAGE_SERVERS_INSTALLED")
                .map(|_| "KIN_CI_LANGUAGE_SERVERS_INSTALLED")
        }
        LanguageId::Go => {
            std::env::var_os(GO_LANGUAGE_SERVER_PROVISIONED).map(|_| GO_LANGUAGE_SERVER_PROVISIONED)
        }
        _ => None,
    };
    let skip = |why: String| -> Option<(String, Vec<String>)> {
        if let Some(variable) = provisioned {
            panic!(
                "{test}: {variable} is set, so this runner was provisioned for the {language} \
                 proof, yet {why}. The enrichment proof would have skipped silently."
            );
        }
        eprintln!(
            "SKIP {test}: {why}, so the {language} enrichment path cannot be exercised on \
             this host. {}",
            install_hint(language)
        );
        None
    };
    let path = match which::which(&command) {
        Ok(path) => path,
        Err(_) => return skip(format!("no `{command}` is on PATH")),
    };
    if let Err(why) = server_prerequisite(language) {
        return skip(why);
    }
    eprintln!(
        "{test}: using {language} language server at {}",
        path.display()
    );
    Some((command, args))
}

/// What a language's server needs beyond its own binary, checked the way the
/// server will look for it.
///
/// gopls loads every workspace through the `go` command. Without one it starts,
/// answers `initialize`, and then answers every query with nothing: "go command
/// required, not found" in its own log, and a `null` definition to its client,
/// which is exactly what a real miss looks like. On runners carrying gopls and
/// no `go`, the Go proof failed after a minute of polling for an answer that
/// could never come. So a missing `go` is a missing server, and the proof skips
/// or fails on that rather than on its own deadline.
fn server_prerequisite(language: LanguageId) -> Result<(), String> {
    if language != LanguageId::Go {
        return Ok(());
    }
    match std::process::Command::new("go").arg("version").output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!(
            "`go version` exited {}, and gopls loads every package through the `go` command",
            output.status
        )),
        Err(error) => Err(format!(
            "no working `go` command is on PATH ({error}), and gopls loads every package \
             through it"
        )),
    }
}

/// How to provision a language's server, mirrored from
/// `kin_cli::commands::language_servers` so the skip message names a real fix.
fn install_hint(language: LanguageId) -> &'static str {
    match language {
        LanguageId::Python => "Install it with `npm install -g pyright` and re-run.",
        LanguageId::TypeScript | LanguageId::JavaScript => {
            "Install it with `npm install -g typescript-language-server typescript` and re-run."
        }
        LanguageId::Rust => "Install it with `rustup component add rust-analyzer` and re-run.",
        LanguageId::Go => {
            "Install Go from https://go.dev/dl/, then gopls with \
             `go install golang.org/x/tools/gopls@v0.22.0`, and re-run."
        }
        _ => "See `kin doctor`.",
    }
}

/// Start a server against `root` and wait for it to finish indexing.
async fn start_server(
    command: &str,
    args: &[String],
    root: &Path,
    language: LanguageId,
) -> kin_lsp::lifecycle::LspServer {
    let (_, _, launch) = lsp_adapter_for(language, root).expect("adapter must exist");
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let grammars = kin_lsp::TypeScriptGrammars {
        typescript: kin_grammar_typescript::LANGUAGE_TYPESCRIPT,
        tsx: kin_grammar_typescript::LANGUAGE_TSX,
    };
    let server = kin_lsp::lifecycle::LspServer::launch_settled(
        command,
        &arg_refs,
        root,
        &launch,
        Some(grammars),
    )
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
            declares_name: true,
            kind: kin_model::EntityKind::Function,
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
    let index = EntityIndex::new(refs, root);

    let server = start_server(&command, &args, root, LanguageId::Python).await;
    open_documents(&server, root, &["adapters.py", "sessions.py"], "python").await;
    let source_text = std::fs::read_to_string(root.join(&caller.file_path)).unwrap();
    let documents = |file: &str| (file == caller.file_path).then(|| source_text.clone());
    let relations =
        kin_lsp::enrichment::enrich_entity_calls(&server, &caller, &index, root, Some(&documents))
            .await
            .expect("enrichment must not error")
            .relations;

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
    let caller = refs
        .iter()
        .find(|r| r.id == listen)
        .expect("caller")
        .clone();
    let index = EntityIndex::new(refs, root);

    let server = start_server(&command, &args, root, LanguageId::JavaScript).await;
    open_documents(&server, root, &["router.js", "app.js"], "javascript").await;
    let source_text = std::fs::read_to_string(root.join(&caller.file_path)).unwrap();
    let documents = |file: &str| (file == caller.file_path).then(|| source_text.clone());
    let relations =
        kin_lsp::enrichment::enrich_entity_calls(&server, &caller, &index, root, Some(&documents))
            .await
            .expect("enrichment must not error")
            .relations;

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
    use kin_core::reference_coverage::{
        reference_enrichment_for, LanguageServerReadiness, LanguageServerReadinessMap,
        ReferenceEnrichment,
    };

    let none_installed = LanguageServerReadinessMap::new();
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
    let mut installed = LanguageServerReadinessMap::new();
    installed.insert(LanguageId::JavaScript, LanguageServerReadiness::Usable);
    let state = reference_enrichment_for(LanguageId::JavaScript, &installed);
    assert_eq!(state, ReferenceEnrichment::Available);
    assert!(!state.is_actionable_gap());

    // The state binary presence cannot see: the server is installed and cannot
    // start. It must read as its own gap rather than as Available, and it must
    // still be actionable, because a broken install is something an operator
    // can repair.
    let mut broken = LanguageServerReadinessMap::new();
    broken.insert(
        LanguageId::JavaScript,
        LanguageServerReadiness::Unusable {
            reason: "Could not find a valid TypeScript installation".to_string(),
        },
    );
    let state = reference_enrichment_for(LanguageId::JavaScript, &broken);
    assert_eq!(
        state,
        ReferenceEnrichment::LanguageServerUnusable,
        "an installed server that cannot start must not report as Available"
    );
    assert!(
        state.is_actionable_gap(),
        "a broken install is a gap an operator can close, so it must be surfaced"
    );
}

/// JavaScript and TypeScript must no longer report `Unsupported`.
///
/// This is the exact string an express-shaped repository read on shipped
/// v0.5.42 bytes. `Unsupported` says the build wires no adapter, which was true
/// then and is false now, and the difference matters because `Unsupported` is
/// deliberately NOT an actionable gap: a reader is told there is nothing to do.
#[test]
fn javascript_no_longer_reports_the_unsupported_state_it_shipped_with() {
    use kin_core::reference_coverage::{
        reference_enrichment_for, LanguageServerReadinessMap, ReferenceEnrichment,
    };

    let none_installed = LanguageServerReadinessMap::new();
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

/// DIAGNOSTIC: what pyright answers for the two real requests dispatch shapes.
///
/// Faithful to the annotations the real source carries, because they are what
/// decides the answer and an unannotated fixture asks a different question:
/// `get_adapter` is declared `-> BaseAdapter` (sessions.py:870) and
/// `Response.connection` is declared `HTTPAdapter` (models.py:750).
#[tokio::test(flavor = "multi_thread")]
async fn pyright_resolves_the_one_hop_to_the_base_and_the_two_hop_to_the_override() {
    const TEST: &str = "pyright_resolves_the_one_hop_to_the_base_and_the_two_hop_to_the_override";
    let Some((command, args)) = server_command_or_skip(LanguageId::Python, TEST) else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(
        root.join("adapters.py"),
        "class BaseAdapter:\n\
         \x20   def send(self, request, **kwargs):\n\
         \x20       raise NotImplementedError\n\
         \n\
         \n\
         class HTTPAdapter(BaseAdapter):\n\
         \x20   def send(self, request, **kwargs):\n\
         \x20       return \"http\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("models.py"),
        "from adapters import HTTPAdapter\n\
         \n\
         \n\
         class Response:\n\
         \x20   connection: HTTPAdapter\n\
         \n\
         \x20   def __init__(self):\n\
         \x20       self.request = None\n",
    )
    .unwrap();
    std::fs::write(
        root.join("sessions.py"),
        "from adapters import BaseAdapter, HTTPAdapter\n\
         \n\
         \n\
         class Session:\n\
         \x20   def __init__(self):\n\
         \x20       self.adapters = {\"http://\": HTTPAdapter()}\n\
         \n\
         \x20   def get_adapter(self, url: str) -> BaseAdapter:\n\
         \x20       return self.adapters[\"http://\"]\n\
         \n\
         \x20   def send(self, request, **kwargs):\n\
         \x20       adapter = self.get_adapter(url=\"u\")\n\
         \x20       r = adapter.send(request, **kwargs)\n\
         \x20       return r\n",
    )
    .unwrap();
    std::fs::write(
        root.join("auth.py"),
        "from models import Response\n\
         \n\
         \n\
         class HTTPDigestAuth:\n\
         \x20   def handle_401(self, r: Response, **kwargs):\n\
         \x20       _r = r.connection.send(r, **kwargs)\n\
         \x20       return _r\n",
    )
    .unwrap();
    std::fs::write(root.join("pyrightconfig.json"), "{\"include\": [\".\"]}\n").unwrap();

    let server = start_server(&command, &args, root, LanguageId::Python).await;
    open_documents(
        &server,
        root,
        &["adapters.py", "models.py", "sessions.py", "auth.py"],
        "python",
    )
    .await;

    // `adapters.py` line 1 is `BaseAdapter.send`; line 6 is `HTTPAdapter.send`.
    // The two cases must answer DIFFERENTLY, and that difference is the finding.
    for (label, file, line, col, want_line) in [
        (
            "Session.send (one-hop through get_adapter -> BaseAdapter)",
            "sessions.py",
            10u32,
            8u32,
            1u64,
        ),
        (
            "HTTPDigestAuth.handle_401 (two-hop through r.connection: HTTPAdapter)",
            "auth.py",
            4,
            8,
            6u64,
        ),
    ] {
        let uri = kin_lsp::protocol::path_to_uri(&root.join(file));
        let prepared = server
            .client
            .request(
                "textDocument/prepareCallHierarchy",
                serde_json::json!({
                    "textDocument": {"uri": uri},
                    "position": {"line": line, "character": col}
                }),
            )
            .await
            .unwrap_or(serde_json::json!(null));
        let item = prepared.get(0).cloned().unwrap_or(serde_json::json!(null));
        if item.is_null() {
            eprintln!("{label}: prepareCallHierarchy found nothing at {file}:{line}");
            continue;
        }
        let out = server
            .client
            .request(
                "callHierarchy/outgoingCalls",
                serde_json::json!({"item": item}),
            )
            .await;
        let calls = match out {
            Ok(value) => value.as_array().cloned().unwrap_or_default(),
            Err(error) => panic!("{label}: outgoingCalls errored: {error}"),
        };
        let sends: Vec<u64> = calls
            .iter()
            .map(|call| &call["to"])
            .filter(|to| to["name"] == "send")
            .filter(|to| to["uri"].as_str().unwrap_or("").ends_with("/adapters.py"))
            .filter_map(|to| to["selectionRange"]["start"]["line"].as_u64())
            .collect();
        assert!(
            sends.contains(&want_line),
            "{label}: pyright must resolve the `.send` call to adapters.py line {want_line}; it \
             answered {sends:?}. Line 1 is BaseAdapter.send and line 6 is HTTPAdapter.send, and \
             which one comes back decides whether the reference surface must compose over an \
             Overrides edge or can count the caller directly."
        );
    }
}

/// A Flask-shaped package reduced to the shapes that took their
/// language-server edges away on the v0.8.0 candidate, parsed by the real
/// Python adapter and handed to pyright through the daemon's own
/// `lsp_entity_ref`. The view imports from its own package relatively, as
/// Flask's modules and its tutorial's views do:
///
/// - the module surface, whose signature is its path, so its name hint (11)
///   ran past the end of `import os` and failed the file's whole definitions
///   pass, imports and call sites included;
/// - a decorated view, whose signature leads with the decorator, so its hint
///   landed on the `next_url` parameter and its own call hierarchy was lost;
/// - an imported constant read as a receiver (`current_app.config`), which
///   answers from another file and was taken for a module, so no edge was
///   recorded for it at all;
/// - an imported module whose first line declares a class, which pyright
///   answers with an empty range at the top of the file.
///
/// A second importer beside the package reaches the same values through
/// `from pkg import ...` and the package's `__init__.py` re-exports. pyright
/// answers `pkg` with the empty range at the top of `__init__.py`, whose first
/// line is an import, so that edge names the package surface and is kept.
#[tokio::test(flavor = "multi_thread")]
async fn python_decorated_views_keep_their_file_and_imported_values_are_references() {
    const TEST: &str = "python_decorated_views_keep_their_file_and_imported_values_are_references";

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical tempdir");
    let sources = [
        (
            "pkg/__init__.py",
            "from .globals import current_app as current_app\n\
             from .helpers import redirect as redirect\n",
        ),
        (
            "pkg/globals.py",
            "class _Proxy:\n\
             \x20   config: dict = {}\n\
             \n\
             \n\
             current_app = _Proxy()\n",
        ),
        (
            "pkg/helpers.py",
            "def redirect(location):\n\
             \x20   return location\n",
        ),
        (
            "pkg/views.py",
            "import os\n\
             from .globals import current_app\n\
             from .helpers import redirect\n\
             \n\
             \n\
             def route(rule):\n\
             \x20   def decorator(view):\n\
             \x20       return view\n\
             \n\
             \x20   return decorator\n\
             \n\
             \n\
             @route(\"/login\")\n\
             def login(next_url: str, remember: bool) -> str:\n\
             \x20   return redirect(current_app.config[os.sep])\n",
        ),
        (
            "app.py",
            "from pkg import current_app, redirect\n\
             \n\
             \n\
             def index():\n\
             \x20   return redirect(current_app.config[1])\n",
        ),
    ];
    let text_of = |file: &str| {
        sources
            .iter()
            .find(|(path, _)| *path == file)
            .map(|(_, text)| *text)
            .unwrap()
    };
    for (path, text) in sources {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }

    let pipeline = kin_index::IndexPipeline::new();
    let mut entities = Vec::new();
    for (path, text) in sources {
        let indexed = pipeline
            .index_file_content_with_tests(
                &kin_model::FilePathId::new(path),
                text.as_bytes(),
                kin_blobs::digest(text.as_bytes()),
            )
            .expect("fixture indexes")
            .indexed_file;
        entities.extend(indexed.entities.into_iter().map(|entity| (path, entity)));
    }
    let find = |path: &str, name: &str, kind: kin_model::EntityKind| {
        entities
            .iter()
            .find(|(file, entity)| *file == path && entity.name == name && entity.kind == kind)
            .map(|(_, entity)| entity.id)
            .unwrap_or_else(|| panic!("the adapter must mint {kind:?} {path}:{name}"))
    };
    let module = find("pkg/views.py", "views", kin_model::EntityKind::Module);
    let login = find("pkg/views.py", "login", kin_model::EntityKind::Function);
    let proxy = find("pkg/globals.py", "_Proxy", kin_model::EntityKind::Class);
    let redirect = find(
        "pkg/helpers.py",
        "redirect",
        kin_model::EntityKind::Function,
    );
    let current_app = find(
        "pkg/globals.py",
        "current_app",
        kin_model::EntityKind::Constant,
    );
    let package = find("pkg/__init__.py", "pkg", kin_model::EntityKind::Module);
    let app = find("app.py", "app", kin_model::EntityKind::Module);
    let index_view = find("app.py", "index", kin_model::EntityKind::Function);
    let refs: Vec<EntityRef> = entities
        .iter()
        .filter_map(|(path, entity)| kin_daemon::daemon::lsp_entity_ref(entity, path))
        .collect();
    let login_ref = refs.iter().find(|r| r.id == login).unwrap().clone();
    let module_ref = refs.iter().find(|r| r.id == module).unwrap().clone();
    assert_eq!(
        (login_ref.start_line, login_ref.name_line),
        (12, 13),
        "the view's span opens on its decorator and its name is asked on the `def` line"
    );
    assert!(
        !module_ref.declares_name,
        "a module surface declares no name of its own"
    );
    let index = EntityIndex::new(refs, &root);

    // Everything above holds on any host. Only what follows needs a server.
    let Some((command, args)) = server_command_or_skip(LanguageId::Python, TEST) else {
        return;
    };
    let server = start_server(&command, &args, &root, LanguageId::Python).await;
    open_documents(&server, &root, &["pkg/views.py", "app.py"], "python").await;
    // Until the server has bound an opened file's imports it answers
    // `definition` with nothing, which is what a real miss looks like. Wait
    // for the answers the passes depend on: `redirect` at each call site.
    let deadline = tokio::time::Instant::now() + INDEX_BUDGET;
    for (file, line, character) in [("pkg/views.py", 14, 11), ("app.py", 4, 11)] {
        let uri = kin_lsp::protocol::path_to_uri(&root.join(file));
        loop {
            let answer = server
                .client
                .request(
                    "textDocument/definition",
                    serde_json::json!({
                        "textDocument": { "uri": uri },
                        "position": { "line": line, "character": character },
                    }),
                )
                .await
                .unwrap_or_default();
            if answer.to_string().contains("pkg/helpers.py") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "pyright never resolved `redirect` in {file}: {answer}"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let documents = |file: &str| {
        sources
            .iter()
            .find(|(path, _)| *path == file)
            .map(|(_, text)| text.to_string())
    };
    let pass = kin_lsp::file_enrichment::enrich_file_definitions(
        &server,
        &root.join("pkg/views.py"),
        text_of("pkg/views.py"),
        &index,
        &root,
        Some(&documents),
    )
    .await
    .expect("the definitions pass must not fail on a decorated view or a module surface");
    assert_eq!(
        pass.failed_queries, 0,
        "every query in the file is answerable, so the file can be recorded as enriched"
    );
    let has = |kind: kin_model::RelationKind, src, dst| {
        pass.relations.iter().any(|relation| {
            relation.kind == kind
                && relation.src == GraphNodeId::Entity(src)
                && relation.dst == GraphNodeId::Entity(dst)
        })
    };
    use kin_model::RelationKind::{Calls, References};
    assert!(
        has(References, module, current_app) && has(References, module, redirect),
        "the import lines keep their edges: {:?}",
        pass.relations
    );
    assert!(
        has(References, login, redirect),
        "the call site keeps its reference: {:?}",
        pass.relations
    );
    assert!(
        has(References, login, current_app),
        "an imported constant read as a receiver is a reference to it: {:?}",
        pass.relations
    );
    assert!(
        has(Calls, login, redirect),
        "the decorated view is asked at its own name and keeps its call: {:?}",
        pass.relations
    );
    assert!(
        pass.relations
            .iter()
            .all(|relation| relation.dst != GraphNodeId::Entity(proxy)),
        "`from .globals import` names the module, not the class its first line declares: {:?}",
        pass.relations
    );
    assert!(
        pass.relations
            .iter()
            .all(|relation| relation.dst != GraphNodeId::Entity(module)),
        "nothing in the file references its own module surface: {:?}",
        pass.relations
    );

    let importer = kin_lsp::file_enrichment::enrich_file_definitions(
        &server,
        &root.join("app.py"),
        text_of("app.py"),
        &index,
        &root,
        Some(&documents),
    )
    .await
    .expect("the definitions pass over the package's importer must not fail");
    assert_eq!(
        importer.failed_queries, 0,
        "every query in the importer is answerable: {:?}",
        importer.relations
    );
    let imports = |kind: kin_model::RelationKind, src, dst| {
        importer.relations.iter().any(|relation| {
            relation.kind == kind
                && relation.src == GraphNodeId::Entity(src)
                && relation.dst == GraphNodeId::Entity(dst)
        })
    };
    assert!(
        imports(References, app, package),
        "`from pkg import` names the package, whose first line is an import, so its \
         empty-range answer keeps its edge: {:?}",
        importer.relations
    );
    assert!(
        imports(References, app, current_app) && imports(References, app, redirect),
        "names imported through the package's re-exports resolve to their own declarations: {:?}",
        importer.relations
    );
    assert!(
        imports(References, index_view, redirect) && imports(References, index_view, current_app),
        "the importer's call site and receiver keep their references: {:?}",
        importer.relations
    );
    assert!(
        importer
            .relations
            .iter()
            .all(|relation| relation.dst != GraphNodeId::Entity(proxy)),
        "no answer in the importer names the class `globals.py` opens with: {:?}",
        importer.relations
    );

    let references = kin_lsp::enrichment::enrich_entity_references(
        &server,
        &module_ref,
        &index,
        &root,
        Some(&documents),
    )
    .await
    .expect("a module surface is not asked about, so it cannot fail");
    assert!(references.is_empty());
    let calls = kin_lsp::enrichment::enrich_entity_calls(
        &server,
        &login_ref,
        &index,
        &root,
        Some(&documents),
    )
    .await
    .expect("the view's own call hierarchy answers")
    .relations;
    assert!(
        calls
            .iter()
            .any(|relation| relation.dst == GraphNodeId::Entity(redirect)),
        "{calls:?}"
    );
    server.shutdown().await.unwrap();
}

/// A Go method reached through an interface, parsed by the real Go adapter,
/// handed to gopls through the daemon's own `lsp_entity_ref`, and asked every
/// question the daemon asks about a file: the definitions pass over each file
/// and the four per-entity arms over each entity.
///
/// gopls answers `references` for a method with the references of every
/// method related to it through interface satisfaction as well. The call in
/// `ViaInterface` is written against `repo.Interface`, so the Go type checker
/// resolves it to the interface method and never to `Concrete.RepoOwner`, yet
/// the references arm recorded it as a proven caller of the concrete method,
/// and the direct call in `Direct` as one of the interface method. The direct
/// call has to stay a caller of the concrete method, and the interface call
/// of the interface method.
#[tokio::test(flavor = "multi_thread")]
async fn go_calls_through_an_interface_are_not_callers_of_the_concrete_method() {
    const TEST: &str = "go_calls_through_an_interface_are_not_callers_of_the_concrete_method";

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical tempdir");
    let sources = [
        (
            "repo/repo.go",
            "package repo\n\
             \n\
             // Interface is satisfied by Concrete.\n\
             type Interface interface {\n\
             \tRepoOwner() string\n\
             }\n\
             \n\
             // Concrete implements Interface.\n\
             type Concrete struct {\n\
             \towner string\n\
             }\n\
             \n\
             // RepoOwner is the concrete method.\n\
             func (c Concrete) RepoOwner() string {\n\
             \treturn c.owner\n\
             }\n",
        ),
        (
            "use/use.go",
            "package use\n\
             \n\
             import \"example.com/dispatch/repo\"\n\
             \n\
             // ViaInterface calls the interface method.\n\
             func ViaInterface(r repo.Interface) string {\n\
             \treturn r.RepoOwner()\n\
             }\n\
             \n\
             // Direct calls the concrete method.\n\
             func Direct(c repo.Concrete) string {\n\
             \treturn c.RepoOwner()\n\
             }\n",
        ),
    ];
    std::fs::write(
        root.join("go.mod"),
        "module example.com/dispatch\n\ngo 1.21\n",
    )
    .unwrap();
    for (path, text) in sources {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }
    let text_of = |file: &str| {
        sources
            .iter()
            .find(|(path, _)| *path == file)
            .map(|(_, text)| *text)
            .unwrap()
    };

    let pipeline = kin_index::IndexPipeline::new();
    let mut entities = Vec::new();
    for (path, text) in sources {
        let indexed = pipeline
            .index_file_content_with_tests(
                &kin_model::FilePathId::new(path),
                text.as_bytes(),
                kin_blobs::digest(text.as_bytes()),
            )
            .expect("fixture indexes")
            .indexed_file;
        entities.extend(indexed.entities.into_iter().map(|entity| (path, entity)));
    }
    let find = |path: &str, name: &str, kind: kin_model::EntityKind| {
        entities
            .iter()
            .find(|(file, entity)| *file == path && entity.name == name && entity.kind == kind)
            .map(|(_, entity)| entity.id)
            .unwrap_or_else(|| panic!("the adapter must mint {kind:?} {path}:{name}"))
    };
    use kin_model::EntityKind::{Function, Method};
    let interface_method = find("repo/repo.go", "Interface.RepoOwner", Method);
    let concrete_method = find("repo/repo.go", "Concrete.RepoOwner", Method);
    let via = find("use/use.go", "ViaInterface", Function);
    let direct = find("use/use.go", "Direct", Function);
    let refs: Vec<EntityRef> = entities
        .iter()
        .filter_map(|(path, entity)| kin_daemon::daemon::lsp_entity_ref(entity, path))
        .collect();
    let index = EntityIndex::new(refs.clone(), &root);

    // Everything above holds on any host. Only what follows needs a server.
    let Some((command, args)) = server_command_or_skip(LanguageId::Go, TEST) else {
        return;
    };
    let server = start_server(&command, &args, &root, LanguageId::Go).await;
    assert!(
        server.has_implementation(),
        "gopls names what a concrete method corresponds to, which is what spares a method no \
         interface reaches from proving every site"
    );
    open_documents(&server, &root, &["repo/repo.go", "use/use.go"], "go").await;
    // Until gopls has loaded the module it answers `definition` with nothing,
    // which is what a real miss looks like. Wait for the call through the
    // interface to resolve into repo.go.
    let deadline = tokio::time::Instant::now() + INDEX_BUDGET;
    let use_uri = kin_lsp::protocol::path_to_uri(&root.join("use/use.go"));
    loop {
        let answer = server
            .client
            .request(
                "textDocument/definition",
                serde_json::json!({
                    "textDocument": { "uri": use_uri },
                    "position": { "line": 6, "character": 10 },
                }),
            )
            .await
            .unwrap_or_default();
        if answer.to_string().contains("repo/repo.go") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "gopls never resolved the call through the interface: {answer}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let documents = |file: &str| {
        sources
            .iter()
            .find(|(path, _)| *path == file)
            .map(|(_, text)| text.to_string())
    };
    let mut relations = Vec::new();
    for file in ["repo/repo.go", "use/use.go"] {
        let pass = kin_lsp::file_enrichment::enrich_file_definitions(
            &server,
            &root.join(file),
            text_of(file),
            &index,
            &root,
            Some(&documents),
        )
        .await
        .expect("the definitions pass answers");
        relations.extend(pass.relations);
    }
    // The daemon's per-entity arms, in its order. A declined or failed arm
    // costs that arm's relations and nothing else, as it does there; the
    // references arm is the one under test, so it has to answer.
    let mut concrete_references = Vec::new();
    for entity in &refs {
        let documents = Some(&documents as kin_lsp::DocumentProvider<'_>);
        if let Ok(found) =
            kin_lsp::enrichment::enrich_entity_calls(&server, entity, &index, &root, documents)
                .await
        {
            relations.extend(found.relations);
        }
        if let Ok(found) =
            kin_lsp::enrichment::enrich_entity_overrides(&server, entity, &index, &root, documents)
                .await
        {
            relations.extend(found);
        }
        if let Ok(found) =
            kin_lsp::enrichment::enrich_entity_uses_type(&server, entity, &index, &root, documents)
                .await
        {
            relations.extend(found);
        }
        let found = kin_lsp::enrichment::enrich_entity_references(
            &server, entity, &index, &root, documents,
        )
        .await
        .unwrap_or_else(|error| panic!("the references arm answers for {}: {error}", entity.name));
        if entity.id == concrete_method {
            concrete_references = found.clone();
        }
        relations.extend(found);
    }
    server.shutdown().await.unwrap();

    let callers_of = |dst: EntityId| {
        relations
            .iter()
            .filter(|relation| {
                matches!(
                    relation.kind,
                    kin_model::RelationKind::Calls | kin_model::RelationKind::References
                ) && relation.dst == GraphNodeId::Entity(dst)
            })
            .map(|relation| relation.src)
            .collect::<std::collections::HashSet<_>>()
    };
    let concrete_callers = callers_of(concrete_method);
    let interface_callers = callers_of(interface_method);
    assert_eq!(
        concrete_references
            .iter()
            .map(|relation| relation.src)
            .collect::<Vec<_>>(),
        [GraphNodeId::Entity(direct)],
        "gopls widened Concrete.RepoOwner's references with the interface call, and only the \
         direct call resolves to it: {concrete_references:?}"
    );
    assert!(
        concrete_callers.contains(&GraphNodeId::Entity(direct)),
        "the direct call is a caller of the concrete method: {relations:?}"
    );
    assert!(
        !concrete_callers.contains(&GraphNodeId::Entity(via)),
        "a call through the interface is not a caller of the concrete method: {relations:?}"
    );
    assert!(
        interface_callers.contains(&GraphNodeId::Entity(via)),
        "the call through the interface is a caller of the interface method: {relations:?}"
    );
    assert!(
        !interface_callers.contains(&GraphNodeId::Entity(direct)),
        "a direct call of the concrete method is not a caller of the interface method: \
         {relations:?}"
    );
}
