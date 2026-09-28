// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin upgrade` over stores the published 0.7.21 release wrote.
//!
//! The fixture is two real stores, not stores this build made and then aged:
//! `fixtures/published-0.7.21-stores.sh` built them with the published 0.7.21
//! archive (checksum-pinned in that script) and packed them as they came out;
//! rerunning it rebuilds the fixture. Both hold imported Git history, a
//! Git-only branch, a native commit on `main`, a Kin branch `feature` with its
//! own native commit, a review with a note, a thread and an approval, and a
//! spec. The second store also holds an uncommitted edit the published daemon
//! admitted, which is the state a working copy is in mid-edit.
//!
//! Every assertion about a native record is by identity: the change id with
//! its message, author and parents, the branch by name, the review by id with
//! its state, the spec by id with its intent, the audit event by the review it
//! names. A count would pass over a record replaced by a lookalike.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::tempdir;

mod common;

use common::IsolatedDaemonRuntime;

const FIXTURE: &[u8] = include_bytes!("fixtures/published-0.7.21-stores.tar.gz");

/// The replay version every published 0.7.x store records at creation.
const PUBLISHED_VERSION: u64 = 11;

fn unpack(root: &Path) {
    let decoder = flate2::read::GzDecoder::new(FIXTURE);
    tar::Archive::new(decoder)
        .unpack(root)
        .expect("unpack the published-store fixture");
}

fn kin(runtime: &IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    runtime
        .kin_command()
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "180")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn succeed(runtime: &IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> String {
    let output = kin(runtime, repo, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("kin stdout is UTF-8")
}

/// `kin status`, which answers 9 rather than 0 when no daemon measured the
/// working copy. That report is still true about durable authority, which is
/// where the hydration line comes from, so both codes are an answer.
fn kin_status(runtime: &IsolatedDaemonRuntime, repo: &Path) -> String {
    let output = kin(runtime, repo, &["status"]);
    assert!(
        matches!(output.status.code(), Some(0) | Some(9)),
        "kin status failed: {:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("kin stdout is UTF-8")
}

fn json(runtime: &IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Value {
    let stdout = succeed(runtime, repo, args);
    serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("kin {args:?}: {error}: {stdout}"))
}

fn hex(value: &Value) -> String {
    value
        .as_array()
        .expect("byte array")
        .iter()
        .map(|byte| format!("{:02x}", byte.as_u64().expect("byte")))
        .collect()
}

/// Every change the log reaches, by id: message, author and parents.
fn log_by_id(
    runtime: &IsolatedDaemonRuntime,
    repo: &Path,
) -> BTreeMap<String, (String, String, Vec<String>)> {
    let log = json(runtime, repo, &["log", "--json", "-n", "200"]);
    log["entries"]
        .as_array()
        .expect("log entries")
        .iter()
        .map(|entry| {
            (
                hex(&entry["change_id"]),
                (
                    entry["message"].as_str().unwrap_or_default().to_string(),
                    entry["author"].as_str().unwrap_or_default().to_string(),
                    entry["parents"]
                        .as_array()
                        .map(|parents| parents.iter().map(hex).collect())
                        .unwrap_or_default(),
                ),
            )
        })
        .collect()
}

/// Every branch, by name, and the change or object it names.
fn branches(runtime: &IsolatedDaemonRuntime, repo: &Path) -> BTreeMap<String, Value> {
    let listed = json(runtime, repo, &["branch", "list", "--json"]);
    listed["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .map(|branch| {
            let name = String::from_utf8(hex_decode(
                branch["name"]["bytes_hex"].as_str().expect("name hex"),
            ))
            .expect("branch names in the fixture are UTF-8");
            (name, branch["target"].clone())
        })
        .collect()
}

fn hex_decode(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn target_change(target: &Value) -> Option<String> {
    (target["type"] == "change").then(|| hex(&target["change_id"]))
}

fn repository_id(repo: &Path) -> String {
    let manifest: Value =
        serde_json::from_slice(&fs::read(repo.join(".kin/manifest.json")).expect("manifest"))
            .expect("manifest is JSON");
    manifest["repo_id"].as_str().expect("repo_id").to_string()
}

/// What the change `branch` names holds for `file`, as "Kind name" lines,
/// read in process from the store's committed history.
///
/// Committed state rather than what a daemon serves: this build's daemon
/// re-derives a file an older build parsed differently into its workspace
/// overlay when it starts, so a served answer can differ from the change a
/// branch names. Called only while no daemon holds the store.
fn committed_declarations(repo: &Path, branch: &str, file: &str) -> Vec<String> {
    use kin_model::ChangeStore as _;

    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .expect("bind the store's authority")
        .open_manager_with_payload_stats()
        .expect("open the store's authority");
    let lease = manager.read_authority();
    let target = lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .find(|reference| reference.name.as_utf8() == Some(branch))
        .unwrap_or_else(|| panic!("the store has no {branch}"))
        .target
        .clone();
    let change = lease
        .resolve_target_change_id(&target)
        .expect("resolve the branch");
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);
    let history = kin_db::InMemoryGraph::from_snapshot(snapshot).expect("open the history");
    let state = history
        .resolve_graph_at(&change)
        .expect("resolve the branch's state");
    let mut found: Vec<String> = state
        .entities
        .values()
        .filter(|entity| {
            entity
                .file_origin
                .as_ref()
                .is_some_and(|origin| origin.0 == file)
        })
        .map(|entity| format!("{:?} {}", entity.kind, entity.name))
        .collect();
    found.sort();
    found
}

fn hydration_record(repo: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(repo.join(".kin/kindb/hydration-semantics")).expect("hydration record"),
    )
    .expect("hydration record is JSON")
}

/// One `find_references` call through `kin mcp start`, returning its payload.
fn find_references(runtime: &IsolatedDaemonRuntime, repo: &Path, name: &str) -> Value {
    let frames = repo.parent().unwrap().join(format!("mcp-{name}.jsonl"));
    fs::write(
        &frames,
        [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kin-store-upgrade-test","version":"0"}}}"#.to_string(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "find_references",
                    "arguments": {"query": name, "relation_kinds": ["calls"], "answer_only": false}
                }
            })
            .to_string(),
        ]
        .join("\n")
            + "\n",
    )
    .expect("write MCP frames");
    let repo_arg = repo.to_str().expect("UTF-8 path");
    // The frames reach the server on stdin, which the harness's bounded
    // `output()` closes, so the server runs as an owned child inside the same
    // containment with its streams on files.
    let stdout_path = frames.with_extension("stdout");
    let stderr_path = frames.with_extension("stderr");
    let mut child = runtime
        .kin_command()
        .args(["mcp", "start", "--repo", repo_arg])
        .env("KIN_MCP_REPO", repo_arg)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "180")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(repo)
        .stdin(Stdio::from(fs::File::open(&frames).expect("open frames")))
        .stdout(Stdio::from(
            fs::File::create(&stdout_path).expect("create the MCP stdout capture"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).expect("create the MCP stderr capture"),
        ))
        .spawn_owned()
        .expect("spawn kin mcp start");
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if child.try_wait().expect("poll kin mcp start").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "kin mcp start did not finish within 300s: stderr={}",
                fs::read_to_string(&stderr_path).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let stdout = fs::read_to_string(&stdout_path).expect("read the MCP stdout capture");
    let frame = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|frame| frame["id"] == 2)
        .unwrap_or_else(|| {
            panic!(
                "no find_references response: stdout={stdout} stderr={}",
                fs::read_to_string(&stderr_path).unwrap_or_default()
            )
        });
    serde_json::from_str(
        frame["result"]["content"][0]["text"]
            .as_str()
            .expect("tool text"),
    )
    .expect("tool payload is JSON")
}

fn verdict(payload: &Value) -> (String, Option<String>) {
    let verdict = &payload["_kin"]["verdict"];
    (
        verdict["state"].as_str().unwrap_or_default().to_string(),
        verdict["limiting_factor"].as_str().map(str::to_string),
    )
}

/// The last lines of this repository's daemon log, for a failure message,
/// without the environment warnings every start repeats.
fn daemon_log_tail(repo: &Path) -> String {
    let log = fs::read(repo.join(".kin/daemon.log")).unwrap_or_default();
    let log = String::from_utf8_lossy(&log);
    let lines: Vec<&str> = log
        .lines()
        .filter(|line| !line.contains("kin_core::env_registry"))
        .collect();
    lines[lines.len().saturating_sub(120)..].join("\n")
}

/// A `find_references` answer that certifies.
///
/// Two states a daemon leaves on its own limit an answer without saying
/// anything about the store, so the call is asked again while they are the
/// whole of its limiting factor. A daemon that has just started publishes this
/// repository's entities to the cross-repo spine after it begins serving, and
/// an answer inside that window reads `cross_repo_authority_incomplete`. A read
/// that ran while one of the daemon's own writers held graph authority, such as
/// the reconcile tick that follows a command rewriting the working copy, is
/// served as `retrieval_degraded` with a graph-authority retry and nothing else
/// degraded. Both close on their own and nothing here restarts the daemon to
/// close them: a commit that leaves the graph root where it was, such as
/// `kin commit` of work the graph already served, used to hold the first open
/// for the rest of the daemon's life. Any other factor, or those outliving the
/// window, fails, except `call_sites_unproven_no_resolver` over a scope holding
/// no site, which is what this daemon's switched-off enrichment leaves (see
/// [`codes_past_unswept_call_sites`]).
fn certified_references(runtime: &IsolatedDaemonRuntime, repo: &Path, name: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let answer = find_references(runtime, repo, name);
        match verdict(&answer) {
            (state, None) if state == "certified" => return answer,
            (_, Some(factor)) if codes_past_unswept_call_sites(&answer, &factor).is_empty() => {
                return answer
            }
            (_, Some(factor))
                if limited_only_by_transient_state(&answer, &factor)
                    && Instant::now() < deadline =>
            {
                eprintln!("asking find_references({name}) again: limited only by {factor}");
                std::thread::sleep(Duration::from_secs(1));
            }
            _ => panic!(
                "the answer did not certify: {answer}\nthe daemon log's last lines:\n{}",
                daemon_log_tail(repo)
            ),
        }
    }
}

/// The factor's codes, less `call_sites_unproven_no_resolver` when this
/// daemon's switched-off language-server enrichment is the whole reason for it.
///
/// A daemon started with `KIN_DAEMON_DISABLE_LSP=1` sweeps nothing and so
/// writes no call-site ledger, and every caller in an answer's scope reads as
/// unproven because enrichment is switched off: no resolver will ever prove
/// it, so it is not owed. That says nothing about what this file tests. It is
/// excused only while the block holds no site at all and names no other
/// reason: a caller a ledger does describe, any unsettled site it holds, and
/// a caller owed a sweep still limit the answer.
fn codes_past_unswept_call_sites<'f>(answer: &Value, factor: &'f str) -> Vec<&'f str> {
    let block = &answer["call_sites"];
    let callers = block["callers_unproven_no_resolver"].as_u64().unwrap_or(0);
    let switched_off = block["no_resolver"].as_object().is_some_and(|reasons| {
        !reasons.is_empty()
            && reasons
                .keys()
                .all(|reason| reason.ends_with("language-server enrichment is switched off"))
    });
    // The block counts every caller in the store that could call the focal,
    // and a caller whose body holds no call has no site for a resolver to
    // prove, so it is not among the unproven. The excuse holds while no site
    // exists and no caller is owed, stale or unverified: every caller left is
    // either one with no call or one only switched-off enrichment leaves
    // unproven.
    let count = |key: &str| block[key].as_u64().unwrap_or(0);
    let unswept = block["sites"] == 0
        && callers > 0
        && count("callers_owed_derivation") == 0
        && count("callers_owed_enrichment") == 0
        && count("callers_stale") == 0
        && count("callers_unverified") == 0
        && switched_off;
    factor
        .split("; ")
        .filter(|code| !(unswept && *code == "call_sites_unproven_no_resolver"))
        .collect()
}

/// Limiting-factor codes that describe a state the daemon leaves on its own.
const TRANSIENT_LIMITS: &[&str] = &[
    // The spine's startup publication window.
    "cross_repo_authority_incomplete",
    // A spine initialization a daemon writer made step aside.
    "spine_initialization_deferred",
];

/// Whether every code in `factor` is transient: one of [`TRANSIENT_LIMITS`],
/// or `retrieval_degraded` when the answer's only degradations are
/// graph-authority retries, reads a daemon writer held.
fn limited_only_by_transient_state(answer: &Value, factor: &str) -> bool {
    codes_past_unswept_call_sites(answer, factor)
        .into_iter()
        .all(|code| {
            TRANSIENT_LIMITS.contains(&code)
                || (code == "retrieval_degraded"
                    && answer["degradations"]
                        .as_array()
                        .is_some_and(|degradations| {
                            !degradations.is_empty()
                                && degradations.iter().all(|degradation| {
                                    degradation["component"] == "graph_authority"
                                        && degradation["reason"] == "retry"
                                })
                        }))
        })
}

/// The semantic keys of the graph a store serves: what a derivation of its
/// tree produces, independent of the identities that name it.
fn graph_keys(runtime: &IsolatedDaemonRuntime, repo: &Path) -> (Vec<String>, Vec<String>) {
    let export = repo.parent().unwrap().join(format!(
        "export-{}.json",
        repo.file_name().unwrap().to_string_lossy()
    ));
    succeed(
        runtime,
        repo,
        &[
            "graph",
            "export",
            "--limit",
            "0",
            "--include",
            "line",
            "--json",
            "--out",
            export.to_str().unwrap(),
        ],
    );
    let graph: Value = serde_json::from_slice(&fs::read(&export).unwrap()).unwrap();
    let nodes = graph["nodes"].as_array().expect("nodes");
    let key = |node: &Value| {
        format!(
            "{}|{}|{}|{}",
            node["kind"], node["name"], node["file"], node["line"]
        )
    };
    let by_id: BTreeMap<String, String> = nodes
        .iter()
        .map(|node| (node["id"].to_string(), key(node)))
        .collect();
    // An import edge's module end is compared by the file that declares it.
    // Where one file declares two modules, such as a crate root and a
    // `mod util;` inside it, this build's linker picks which of them owns an
    // import by an order the entity ids decide, and a fresh admission mints new
    // ids: fresh admissions of this fixture's tree have picked each. Which of
    // the two owns the import is not a property of the tree, so it is not
    // compared.
    let module_file: BTreeMap<String, String> = nodes
        .iter()
        .filter(|node| node["kind"] == "Module")
        .map(|node| {
            (
                node["id"].to_string(),
                format!("Module in {}", node["file"]),
            )
        })
        .collect();
    let mut node_keys: Vec<String> = nodes.iter().map(key).collect();
    node_keys.sort();
    let mut edge_keys: Vec<String> = graph["links"]
        .as_array()
        .expect("links")
        .iter()
        .map(|link| {
            let end = |end: &Value| {
                if link["kind"] == "Imports" {
                    if let Some(module) = module_file.get(&end.to_string()) {
                        return module.clone();
                    }
                }
                by_id
                    .get(&end.to_string())
                    .cloned()
                    .unwrap_or_else(|| end.to_string())
            };
            // The export collapses each relation to an undirected pair ordered
            // by entity id, and the two stores name the same declaration with
            // different ids, so the pair is compared as a set: which end an
            // export lists first says which id sorts first, not which way the
            // relation runs.
            let (source, target) = (end(&link["source"]), end(&link["target"]));
            let (first, second) = if source <= target {
                (source, target)
            } else {
                (target, source)
            };
            format!("{}|{}|{}", link["kind"], first, second)
        })
        .collect();
    edge_keys.sort();
    (node_keys, edge_keys)
}

/// The published store, before and after `kin upgrade`, read through the same
/// commands a person and an agent use.
#[test]
fn upgrading_a_published_store_keeps_every_native_record_and_certifies() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);

    // The control for the semantic check after the upgrade: the published
    // build minted a module for a file that declares nothing, and the change
    // main names carries it.
    let quiet_before = committed_declarations(&repo, "refs/heads/main", "web/quiet.js");
    assert!(
        quiet_before
            .iter()
            .any(|declaration| declaration.starts_with("Module ")),
        "the fixture no longer carries the module the published build minted: {quiet_before:?}"
    );

    // Before: every surface names the same remedy, and answers are qualified
    // by it rather than by a generic degraded signal.
    let status = kin_status(&runtime, &repo);
    assert!(
        status.contains("⚠ hydration semantics:") && status.contains("Remedy: run `kin upgrade`"),
        "kin status must name the upgrade on a store an older build wrote: {status}"
    );
    let graph_status = succeed(&runtime, &repo, &["graph", "status"]);
    assert!(
        graph_status.contains("Remedy: run `kin upgrade`"),
        "{graph_status}"
    );
    // The same remedy, word for word, on every surface that prints one.
    let remedy = remedy_in(&status);
    assert_eq!(remedy_in(&graph_status), remedy);
    assert!(
        remedy.starts_with("run `kin upgrade` in this repository (`npx -y @kinlab/kin@")
            && remedy.contains(" upgrade` when Kin runs through npm)"),
        "{remedy}"
    );
    assert_eq!(
        doctor_hydration_fix(&runtime, &repo).as_deref(),
        Some(remedy.as_str())
    );
    let before_answer = find_references(&runtime, &repo, "double");
    let (state, factor) = verdict(&before_answer);
    assert_eq!(state, "inconclusive", "{before_answer}");
    // The verdict carries listed codes, each explained once in the docs'
    // table, and leads with the one a reader acts on. Every code is listed:
    // a reason whose prose held the clause separator would arrive split, its
    // tail sent as `unlisted_clause`.
    let codes: Vec<&str> = factor.as_deref().unwrap_or_default().split("; ").collect();
    assert_eq!(
        codes.first(),
        Some(&"store_semantics_behind"),
        "{before_answer}"
    );
    assert!(!codes.contains(&"unlisted_clause"), "{before_answer}");
    // The sentence behind the code is the negative block's trust reason, and it
    // names the upgrade the CLI names, with the same pinned npm command.
    let reason = before_answer["negative"]["trust_reason"]
        .as_str()
        .unwrap_or_default();
    assert!(
        reason.starts_with("store_semantics_behind:")
            && reason.contains("run `kin upgrade` in this repository")
            && reason
                .contains(&remedy[remedy.find("(`npx").unwrap()..remedy.find(")").unwrap() + 1]),
        "the answer must name the upgrade the CLI names: {reason}"
    );
    assert_eq!(
        before_answer["_kin"]["degraded"]["hydration_semantics_stale"],
        true
    );
    let log_before = log_by_id(&runtime, &repo);
    let branches_before = branches(&runtime, &repo);
    let repo_id = repository_id(&repo);
    let reviews_before = succeed(&runtime, &repo, &["review", "list"]);
    let review_id = reviews_before
        .split_whitespace()
        .next()
        .expect("the fixture holds a review")
        .to_string();
    assert!(
        reviews_before.contains(&format!("{review_id} [approved]")),
        "{reviews_before}"
    );
    let review_before = succeed(&runtime, &repo, &["review", "show", &review_id]);
    let specs_before = succeed(&runtime, &repo, &["spec", "list"]);
    let spec_line = specs_before
        .lines()
        .find(|line| line.contains("An upgrade keeps every native record"))
        .expect("the fixture holds a spec")
        .trim()
        .to_string();
    assert_eq!(
        branches_before.keys().cloned().collect::<Vec<_>>(),
        vec!["refs/heads/feature", "refs/heads/main", "refs/heads/topic"]
    );
    assert_eq!(
        branches_before["refs/heads/topic"]["type"], "external_object",
        "the Git-only branch must reach the upgrade as the imported object it was"
    );

    // The upgrade.
    let report = json(&runtime, &repo, &["upgrade", "--json"]);
    // `kin upgrade` stops this repository's daemon on the way out, so main's
    // committed state can be read here: its new head no longer carries the
    // module no derivation of that file produces.
    let quiet_committed = committed_declarations(&repo, "refs/heads/main", "web/quiet.js");
    assert!(
        quiet_committed.is_empty(),
        "main's upgraded head still carries what the published build minted for a file that \
         declares nothing: {quiet_committed:?}"
    );
    assert_eq!(report["schema"], "kin.store-upgrade.v1");
    assert_eq!(report["state"], "upgraded", "{report}");
    assert_eq!(report["from"], PUBLISHED_VERSION);
    let to = report["to"].as_u64().expect("to");
    assert!(to > PUBLISHED_VERSION, "{report}");
    assert_eq!(report["binding_history_checked"], true, "{report}");
    assert_eq!(report["warnings"], serde_json::json!([]));
    let heads = report["heads"].as_array().expect("heads");
    let anchor_of = |name: &str| -> (String, String, bool) {
        let head = heads
            .iter()
            .find(|head| {
                head["refs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|reference| reference == name)
            })
            .unwrap_or_else(|| panic!("the upgrade did not report {name}: {report}"));
        (
            head["previous"].as_str().unwrap().to_string(),
            head["anchor"].as_str().unwrap().to_string(),
            head["checkpoint"].as_bool().unwrap(),
        )
    };

    // Every change that existed is still there, by id, with its message,
    // author and parents.
    let log_after = log_by_id(&runtime, &repo);
    for (id, record) in &log_before {
        assert_eq!(
            log_after.get(id),
            Some(record),
            "change {id} did not survive the upgrade unchanged"
        );
    }
    // Each branch moved onto a checkpoint whose only parent is the head it
    // named, and no branch moved anywhere else.
    let branches_after = branches(&runtime, &repo);
    assert_eq!(
        branches_after.keys().collect::<Vec<_>>(),
        branches_before.keys().collect::<Vec<_>>()
    );
    for name in ["refs/heads/main", "refs/heads/feature", "refs/heads/topic"] {
        let (previous, anchor, checkpoint) = anchor_of(name);
        if let Some(before) = target_change(&branches_before[name]) {
            assert_eq!(before, previous, "{name}");
        }
        assert_eq!(
            target_change(&branches_after[name]).as_deref(),
            Some(anchor.as_str()),
            "{name} does not name the change the upgrade reported"
        );
        if checkpoint {
            let checkpoint_log = log_after.get(&anchor);
            if name == "refs/heads/main" {
                let (message, author, parents) =
                    checkpoint_log.expect("the checkpoint on main is in its log");
                assert!(
                    message.starts_with(&format!(
                        "Re-derive semantics under hydration semantics version {to} (was {PUBLISHED_VERSION})"
                    )),
                    "{message}"
                );
                assert_eq!(author, "Kin Fixture <fixture@example.invalid>");
                assert_eq!(parents, &vec![previous.clone()]);
            }
        } else {
            assert_eq!(anchor, previous, "{name}");
        }
    }
    assert!(
        anchor_of("refs/heads/main").2,
        "main held the published build's derivation and must have moved"
    );

    // The review, its thread and decision, the spec, the audit event and the
    // repository identity are the ones the published build wrote.
    let reviews_after = succeed(&runtime, &repo, &["review", "list"]);
    assert!(
        reviews_after.contains(&format!("{review_id} [approved]")),
        "{reviews_after}"
    );
    let review_after = succeed(&runtime, &repo, &["review", "show", &review_id]);
    for text in [
        "A note recorded before the upgrade",
        "A thread started before the upgrade",
    ] {
        assert!(review_before.contains(text), "{review_before}");
        assert!(review_after.contains(text), "{review_after}");
    }
    let specs_after = succeed(&runtime, &repo, &["spec", "list"]);
    assert!(specs_after.contains(&spec_line), "{specs_after}");
    let audit = succeed(&runtime, &repo, &["audit"]);
    assert!(
        audit
            .lines()
            .any(|line| line.contains("review.create") && line.contains(&review_id)),
        "{audit}"
    );
    assert_eq!(repository_id(&repo), repo_id);

    // The record states the upgrade beside the creation version it kept.
    let record = hydration_record(&repo);
    assert_eq!(record["created_under"], PUBLISHED_VERSION);
    assert_eq!(record["upgrade"]["under"], to);
    assert_eq!(record["upgrade"]["from"], PUBLISHED_VERSION);

    // After: no surface qualifies the store, answers certify, and the head
    // serves this build's derivation.
    let status = kin_status(&runtime, &repo);
    assert!(!status.contains("hydration semantics"), "{status}");
    let graph_status = succeed(&runtime, &repo, &["graph", "status"]);
    assert!(
        !graph_status.contains("hydration semantics"),
        "{graph_status}"
    );
    assert_eq!(doctor_hydration_fix(&runtime, &repo), None);
    let answer = certified_references(&runtime, &repo, "double");
    assert!(answer["_kin"]["degraded"]
        .get("hydration_semantics_stale")
        .is_none());
    assert_eq!(answer["_kin"]["hydration_semantics"]["standing"], "current");
    assert_eq!(answer["_kin"]["hydration_semantics"]["upgraded_under"], to);
    let quiet_after = succeed(&runtime, &repo, &["search", "quiet", "--json"]);
    assert!(
        !quiet_after.contains("web/quiet.js"),
        "the module the published build minted for a file with no declaration survived: \
         {quiet_after}"
    );

    // The upgraded head serves exactly what a fresh admission of the same tree
    // under this build derives.
    let fresh = root.path().join("fresh");
    copy_tree(&repo, &fresh);
    let fresh_runtime = IsolatedDaemonRuntime::new(&fresh);
    for args in [
        vec!["init", "--initial-branch=main"],
        vec!["config", "user.email", "fixture@example.invalid"],
        vec!["config", "user.name", "Kin Fixture"],
        vec!["add", "--all"],
        vec!["commit", "-m", "the upgraded head's tree"],
    ] {
        let output = std::process::Command::new("git")
            .args(&args)
            .args(["-c", "commit.gpgsign=false"].iter().take(0))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .current_dir(&fresh)
            .output()
            .expect("run git");
        assert!(output.status.success(), "git {args:?}: {output:?}");
    }
    let init = kin(&fresh_runtime, &fresh, &["init", "--json"]);
    assert!(
        init.status.success(),
        "fresh kin init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert_eq!(
        graph_keys(&runtime, &repo),
        graph_keys(&fresh_runtime, &fresh),
        "the upgraded head does not serve what a fresh admission of its tree derives"
    );
    // A store this build created has nothing to upgrade either.
    let fresh_upgrade = json(&fresh_runtime, &fresh, &["upgrade", "--json"]);
    assert_eq!(fresh_upgrade["state"], "already_current", "{fresh_upgrade}");

    // A cold reopen holds all of it.
    succeed(&runtime, &repo, &["daemon", "stop"]);
    certified_references(&runtime, &repo, "double");
    assert_eq!(log_by_id(&runtime, &repo), log_after);

    // A second run finds nothing to do.
    let again = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(again["state"], "already_current", "{again}");
    assert_eq!(log_by_id(&runtime, &repo), log_after);

    // Rolling back to state recorded before the upgrade returns the store to
    // its creation record, and every surface says so again.
    let pre_upgrade = anchor_of("refs/heads/main").0;
    let (_, _, parents) = log_after
        .get(&pre_upgrade)
        .expect("the pre-upgrade head is in the log")
        .clone();
    let restored = parents
        .first()
        .expect("the native change has a parent")
        .clone();
    succeed(
        &runtime,
        &repo,
        &["rollback", restored.as_str(), "--discard-later"],
    );
    let record = hydration_record(&repo);
    assert!(record.get("upgrade").is_none(), "{record}");
    let status = kin_status(&runtime, &repo);
    assert!(
        status.contains("Remedy: run `kin upgrade`"),
        "a rollback to pre-upgrade state must read behind again: {status}"
    );
    let rerun = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(rerun["state"], "upgraded", "{rerun}");
    certified_references(&runtime, &repo, "double");

    // A path checkout that restores a file's state from before the upgrade
    // does the same.
    succeed(
        &runtime,
        &repo,
        &["checkout", "src/util.rs", "--change", pre_upgrade.as_str()],
    );
    let record = hydration_record(&repo);
    assert!(record.get("upgrade").is_none(), "{record}");
    let status = kin_status(&runtime, &repo);
    assert!(
        status.contains("Remedy: run `kin upgrade`"),
        "a path checkout of pre-upgrade state must read behind again: {status}"
    );
    let rerun = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(rerun["state"], "upgraded", "{rerun}");
    assert_eq!(rerun["workspace_dirty"], true, "{rerun}");

    // Work sealed on the upgraded base and restored onto it keeps the claim,
    // and keeps the binding-history lineage the upgrade started: the seal is a
    // checked commit like the restore, so the answer certifies straight after
    // the round trip, and a further `kin upgrade` has nothing to re-qualify.
    succeed(&runtime, &repo, &["stash", "push", "--yes"]);
    succeed(&runtime, &repo, &["stash", "pop"]);
    let record = hydration_record(&repo);
    assert!(record.get("upgrade").is_some(), "{record}");
    let answer = certified_references(&runtime, &repo, "double");
    assert_eq!(
        answer["_kin"]["hydration_semantics"]["standing"], "current",
        "{answer}"
    );
    let again = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(again["state"], "already_current", "{again}");
    assert_eq!(again["binding_history_checked"], true, "{again}");
    assert_eq!(hydration_record(&repo), record);
}

/// A store holding an uncommitted edit the published daemon admitted serves
/// that edit at its current position once upgraded, and commits it.
#[test]
fn an_upgraded_store_serves_and_commits_the_edit_it_held_uncommitted() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("dirty");
    let runtime = IsolatedDaemonRuntime::new(&repo);

    // Before: whatever this build's daemon makes of the store, starting it, or
    // failing to, tells the reader the remedy every other surface names.
    let before = kin(&runtime, &repo, &["graph", "status"]);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&before.stderr)
    );
    assert!(
        said.contains("Remedy: run `kin upgrade` in this repository"),
        "a daemon on a store an older build wrote must name `kin upgrade`: {said}"
    );

    let report = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(report["state"], "upgraded", "{report}");
    assert_eq!(report["workspace_dirty"], true, "{report}");
    assert_eq!(report["binding_history_checked"], true, "{report}");

    let found: Value =
        serde_json::from_str(&succeed(&runtime, &repo, &["search", "sextuple", "--json"]))
            .expect("search emits JSON");
    let rows = found.as_array().expect("search rows");
    assert!(
        rows.iter().any(|row| row["name"] == "sextuple"
            && row["file"] == "web/lib.mjs"
            && row["line"] == 5),
        "the uncommitted declaration must answer at its current line: {found}"
    );
    certified_references(&runtime, &repo, "double");

    succeed(
        &runtime,
        &repo,
        &["commit", "-m", "Record the edit after the upgrade"],
    );
    let status = kin_status(&runtime, &repo);
    assert!(!status.contains("hydration semantics"), "{status}");
    // A commit after the upgrade extends the lineage the upgrade started.
    certified_references(&runtime, &repo, "double");
}

/// The `kin status` line naming what this repository's running daemon
/// re-derived at startup, if it re-derived anything.
///
/// `kin status` reads a running daemon rather than starting one, so this starts
/// the daemon first with a command that does.
fn startup_repair(runtime: &IsolatedDaemonRuntime, repo: &Path) -> Option<String> {
    succeed(runtime, repo, &["graph", "status"]);
    kin_status(runtime, repo)
        .lines()
        .find(|line| line.contains("Startup repair:"))
        .map(str::to_string)
}

/// What a startup repair line says of source whose parse a record owed, as
/// `kin status` renders the owed-parse cause.
const OWED_PARSE_CLAUSE: &str = "held edits whose parse no commit had recorded";

/// What a daemon's standalone publication does with the workspace's checked
/// binding history. A live admission that observed its own semantic
/// predecessor carries the lineage across through the local verifier; one
/// that did not preserves the publication and invalidates the witness.
#[derive(Clone, Copy)]
enum Lineage {
    Observed,
    Unobserved,
}

/// The publication half of a daemon's admission: `bytes` become `file` in the
/// workspace tree through authority of its own, with no parse and no change,
/// which moves authority on and leaves the graph describing what it did. The
/// same commit records the parse the bytes are owed in the workspace's owed
/// derivation ledger, as this build's daemon does.
fn publish_tree_bytes_as_a_daemon_would(repo: &Path, file: &str, bytes: &[u8], lineage: Lineage) {
    use kin_model::{
        compute_resolved_tree_hash, OperationId, RepoPath, RepositoryTransaction, ResolvedArtifact,
        ResolvedTree, TreeEntry, WorkspaceExpectation, WorkspaceMutation,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let body = kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(bytes));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let repository_id = lease.metadata().repository_id.clone();
    let workspace = lease.metadata().workspaces[0].clone();
    let graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap()
        .unwrap();
    drop(lease);
    manager.save_source_blob(body, bytes).unwrap();
    let path = RepoPath::from_utf8(file.to_string()).unwrap();
    let desired =
        ResolvedTree::from_artifacts(workspace.tree.artifacts().cloned().map(|artifact| {
            if artifact.path == path {
                ResolvedArtifact::new(
                    artifact.artifact_id,
                    artifact.path,
                    TreeEntry::blob(body, false),
                )
            } else {
                artifact
            }
        }))
        .unwrap();
    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &desired).unwrap();
    let semantic_delta = kin_core::diff_workspace_semantics(
        &graph.entities,
        &graph.relations,
        &graph.entities,
        &graph.relations,
    )
    .unwrap();
    let workspace_id = workspace.workspace_id;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id,
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: kin_model::AuthorId::new("kin-daemon-admission"),
        reason: "admit an edit the way a daemon publishes one before its parse".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id: workspace.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                semantic_overlay_hash: workspace.semantic_overlay_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation: workspace.generation + 1,
            new_head: workspace.head.clone(),
            new_base_target: workspace.base_target.clone(),
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas,
            new_tree_hash: compute_resolved_tree_hash(&desired).unwrap(),
            semantic_delta,
            new_shared_admission_policy: workspace.shared_admission_policy.clone(),
            new_admission_policy: workspace.admission_policy,
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    let owing = kin_db::OwedDerivationUpdate::owe(workspace_id, vec![(path, body)], Vec::new());
    match lineage {
        Lineage::Observed => manager
            .commit_repository_transaction_with_observed_binding_history_owing(
                transaction,
                workspace_id,
                &graph,
                &kin_index::binding_history::LocalBindingHistoryVerifier,
                &owing,
            ),
        Lineage::Unobserved => manager.commit_repository_transaction_owing(transaction, &owing),
    }
    .expect("the edit's bytes publish");
}

/// What a daemon does when it admits an edit no commit follows: the working
/// copy holds the new bytes, and they are published to the workspace tree
/// with the parse they are owed recorded in the same commit.
fn publish_an_edit_as_a_daemon_would(repo: &Path) {
    let edited = repo.join("web/lib.mjs");
    let mut bytes = fs::read(&edited).unwrap();
    bytes.extend_from_slice(b"\nexport function later(value) {\n  return value;\n}\n");
    fs::write(&edited, &bytes).unwrap();
    publish_tree_bytes_as_a_daemon_would(repo, "web/lib.mjs", &bytes, Lineage::Unobserved);
}

/// The workspace's owed derivation records, as path and body, and the
/// operation its last payment names, read from repository authority. Read
/// with no daemon serving the store.
fn owed_work(repo: &Path) -> (Vec<(String, String)>, Option<String>) {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let workspace = lease.metadata().workspaces[0].workspace_id;
    let ledger = &lease.metadata().owed_derivations;
    (
        ledger
            .records_for(workspace)
            .map(|record| (record.path().to_string(), record.body().to_string()))
            .collect(),
        ledger
            .payment_for(workspace)
            .map(|payment| payment.operation_id().to_string()),
    )
}

/// The records of owed work the published build's daemon keeps beside the
/// store, which this build never writes.
fn legacy_records(repo: &Path) -> [PathBuf; 2] {
    [
        repo.join(".kin/semantic-debt.json"),
        repo.join(".kin/unpublished-enrichment.json"),
    ]
}

/// The daemon before the upgrade left the parse of its uncommitted edit owed.
/// The upgrade derived that exact body into the state it commits, so no daemon
/// after it re-derives that parse at startup, the first or any later one.
///
/// The upgrade removes the published build's records once its commit has
/// paid them. They are put back here to stand in for a removal that failed:
/// the first start judges each entry against the graph the upgrade committed,
/// finds it paid, and removes them itself. Falsify by judging the entries by
/// the tree's body alone: the first start re-derives the parse as owed work.
#[test]
fn a_daemon_after_the_upgrade_re_derives_no_parse_the_upgrade_derived() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("dirty");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    // The control: the published daemon left the edit's parse owed.
    let debt = fs::read(repo.join(".kin/semantic-debt.json"))
        .expect("the fixture records the uncommitted edit's parse as owed");
    assert!(
        String::from_utf8_lossy(&debt).contains("web/lib.mjs"),
        "the fixture no longer owes the uncommitted edit's parse: {}",
        String::from_utf8_lossy(&debt)
    );
    let legacy = legacy_records(&repo);
    let kept: Vec<Option<Vec<u8>>> = legacy.iter().map(|record| fs::read(record).ok()).collect();

    let report = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(report["state"], "upgraded", "{report}");
    for record in &legacy {
        assert!(
            !record.exists(),
            "{} outlived the upgrade's payment of what it named",
            record.display()
        );
    }
    let (records, payment) = owed_work(&repo);
    assert!(
        records.is_empty(),
        "the upgrade left owed work: {records:?}"
    );
    assert!(
        payment.is_some(),
        "the upgrade's commit recorded no payment"
    );
    for (record, bytes) in legacy.iter().zip(&kept) {
        if let Some(bytes) = bytes {
            fs::write(record, bytes).unwrap();
        }
    }

    for daemon in ["first", "a later"] {
        let repair = startup_repair(&runtime, &repo);
        assert!(
            repair
                .as_deref()
                .is_none_or(|line| !line.contains(OWED_PARSE_CLAUSE)),
            "{daemon} daemon after the upgrade re-derived a parse the upgrade already derived: \
             {repair:?}"
        );
        succeed(&runtime, &repo, &["daemon", "stop"]);
        for record in &legacy {
            assert!(
                !record.exists(),
                "the {daemon} start judged {} paid and left it in place",
                record.display()
            );
        }
    }
}

/// Body A, then body B, then body A again. The upgrade derives `web/lib.mjs`
/// at body A and pays the record the published daemon left for it, and a
/// later commit records body B. A daemon then admits body A again the way a
/// live admission does before its parse: it publishes the bytes alone, and
/// the same commit records the parse owed for A, the same path and body the
/// upgrade paid, at a later generation, while the committed graph describes
/// B. A second upgrade finds the store current and leaves that record alone,
/// so the next daemon re-derives the parse as owed work and the next commit
/// publishes it.
///
/// Falsify by letting an already-current upgrade clear the ledger: the next
/// start re-derives nothing and the commit publishes B's declarations over
/// A's bytes.
#[test]
fn a_body_published_again_over_a_later_commit_is_re_derived_as_owed() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("dirty");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let debt = repo.join(".kin/semantic-debt.json");
    let body_a = fs::read(repo.join("web/lib.mjs")).expect("the fixture's edited file");
    let debt_a = fs::read(&debt).expect("the fixture records the uncommitted edit's parse");
    // The control: the fixture's record is the daemon's own rendering of the
    // one entry owed for body A, which a daemon admitting A again writes.
    assert_eq!(
        String::from_utf8(debt_a.clone()).unwrap(),
        format!(
            r#"[{{"path":"web/lib.mjs","body":"{}"}}]"#,
            kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(&body_a))
        )
    );

    let report = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(report["state"], "upgraded", "{report}");
    assert!(
        !debt.exists(),
        "the upgrade's payment covered the record it removes"
    );

    let mut body_b = body_a.clone();
    body_b.extend_from_slice(b"\nexport function later(value) {\n  return value;\n}\n");
    fs::write(repo.join("web/lib.mjs"), &body_b).unwrap();
    succeed(&runtime, &repo, &["commit", "-m", "Record body B"]);
    succeed(&runtime, &repo, &["daemon", "stop"]);
    assert!(
        committed_declarations(&repo, "refs/heads/main", "web/lib.mjs")
            .iter()
            .any(|declaration| declaration == "Function later"),
        "the commit of body B did not publish its parse"
    );

    // Body A again: the bytes alone, carrying the checked lineage across while
    // the graph describes B, with the parse they owe recorded in the same
    // commit.
    fs::write(repo.join("web/lib.mjs"), &body_a).unwrap();
    publish_tree_bytes_as_a_daemon_would(&repo, "web/lib.mjs", &body_a, Lineage::Observed);
    let body_a_hash = kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(&body_a)).to_string();
    let owed_a = vec![("web/lib.mjs".to_string(), body_a_hash)];
    assert_eq!(
        owed_work(&repo).0,
        owed_a,
        "the publication records A's parse as owed"
    );
    let again = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(again["state"], "already_current", "{again}");
    assert_eq!(
        owed_work(&repo).0,
        owed_a,
        "an upgrade with nothing to commit leaves the record alone"
    );

    let repair = startup_repair(&runtime, &repo);
    assert!(
        repair
            .as_deref()
            .is_some_and(|line| line.contains(OWED_PARSE_CLAUSE)),
        "the next daemon did not re-derive body A as owed work: {repair:?}"
    );
    succeed(
        &runtime,
        &repo,
        &["commit", "-m", "Record body A the daemon admitted again"],
    );
    succeed(&runtime, &repo, &["daemon", "stop"]);
    assert_eq!(
        committed_declarations(&repo, "refs/heads/main", "web/lib.mjs"),
        vec![
            "Function sextuple".to_string(),
            "Function triple".to_string(),
            "Module lib".to_string()
        ],
        "the commit published body A without its parse"
    );
    assert!(
        owed_work(&repo).0.is_empty(),
        "the commit that published A's parse paid its record"
    );
}

/// The owed work a daemon before this build left is paid by the upgrade's
/// commit. The published daemon left the parse of the uncommitted edit owed
/// and named paths whose derivation no commit published. The upgrade's commit
/// records its payment of the workspace in authority, and only then are the
/// published build's records removed.
///
/// Falsify by committing without the payment: no payment is recorded and the
/// published build's records stay.
#[test]
fn an_upgrade_pays_what_the_daemon_before_it_left_owed() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks, UpgradeState};

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("dirty");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let legacy = legacy_records(&repo);
    for record in &legacy {
        assert!(
            record.exists(),
            "the fixture's daemon no longer leaves {}",
            record.display()
        );
    }

    let report = upgrade_store(
        &layout,
        kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>"),
        &UpgradeHooks::default(),
        &|_: &str| {},
    )
    .expect("the published store upgrades");
    assert_eq!(report.state, UpgradeState::Upgraded);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(report.binding_history_checked, Some(true));
    let (records, payment) = owed_work(&repo);
    assert!(
        records.is_empty(),
        "the upgrade's commit left owed work: {records:?}"
    );
    assert!(
        payment.is_some(),
        "the upgrade's commit recorded no payment"
    );
    for record in &legacy {
        assert!(
            !record.exists(),
            "{} outlived the payment that covered it",
            record.display()
        );
    }
}

/// A parse owed after the upgrade's commit stays owed, and the next commit
/// publishes it. A daemon's publication that lands after the commit records at
/// a later generation than the payment, so nothing the upgrade does afterwards
/// can touch it.
///
/// Falsify by clearing the workspace's records after the commit rather than
/// inside it: the later record is lost, the next daemon re-derives nothing,
/// and the commit publishes the new bytes against the old declarations.
#[test]
fn an_upgrade_leaves_a_parse_owed_after_its_commit_for_the_next_commit() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks, UpgradeState};

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("dirty");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let hook_repo = repo.clone();
    let report = upgrade_store(
        &layout,
        kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>"),
        &UpgradeHooks {
            before_commit: None,
            after_commit: Some(Box::new(move || {
                publish_an_edit_as_a_daemon_would(&hook_repo);
                Ok(())
            })),
        },
        &|_: &str| {},
    )
    .expect("the published store upgrades");
    assert_eq!(report.state, UpgradeState::Upgraded);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    let (records, payment) = owed_work(&repo);
    assert!(
        payment.is_some(),
        "the upgrade's commit recorded its payment"
    );
    assert_eq!(
        records
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        vec!["web/lib.mjs"],
        "the publication after the commit stays owed: {records:?}"
    );

    succeed(
        &runtime,
        &repo,
        &["commit", "-m", "Record the edit a daemon admitted"],
    );
    succeed(&runtime, &repo, &["daemon", "stop"]);
    let declared = committed_declarations(&repo, "refs/heads/main", "web/lib.mjs");
    assert!(
        declared
            .iter()
            .any(|declaration| declaration == "Function later"),
        "the owed parse was never published: {declared:?}"
    );
    assert!(
        owed_work(&repo).0.is_empty(),
        "the commit that published the parse paid its record"
    );
}

/// A daemon's publication that lands after the upgrade planned and before it
/// commits makes that commit refuse, and nothing the upgrade does moves: the
/// publication's record stays owed, no payment is recorded, and the published
/// build's records stay where they were.
///
/// Falsify by dropping the compare-and-swap's generation checks: the upgrade
/// commits over the publication and pays a record it never re-derived.
#[test]
fn a_publication_before_the_upgrade_commits_stops_it() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks};

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("dirty");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let legacy = legacy_records(&repo);
    let kept: Vec<Option<Vec<u8>>> = legacy.iter().map(|record| fs::read(record).ok()).collect();
    let hook_repo = repo.clone();
    let refused = upgrade_store(
        &layout,
        kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>"),
        &UpgradeHooks {
            before_commit: Some(Box::new(move || {
                publish_an_edit_as_a_daemon_would(&hook_repo);
                Ok(())
            })),
            after_commit: None,
        },
        &|_: &str| {},
    )
    .expect_err("an upgrade planned before the publication must refuse");
    assert!(
        refused
            .to_string()
            .contains("kin upgrade refused to commit"),
        "{refused:#}"
    );
    let (records, payment) = owed_work(&repo);
    assert_eq!(
        records
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        vec!["web/lib.mjs"],
        "the publication's record stays owed: {records:?}"
    );
    assert!(payment.is_none(), "a refused upgrade pays nothing");
    for (record, bytes) in legacy.iter().zip(&kept) {
        assert_eq!(
            fs::read(record).ok(),
            *bytes,
            "{} moved though the upgrade committed nothing",
            record.display()
        );
    }
    assert_eq!(
        kin_core::hydration_semantics::standing(&layout).label(),
        "behind"
    );
}

/// The upgrade runs with this repository's runtime authority, which every
/// daemon holds for its whole life, so no daemon starts beside it. While
/// another process holds that authority it refuses and changes nothing.
#[test]
fn an_upgrade_refuses_while_another_process_holds_the_runtime_authority() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let held = kin_cli::daemon_client::acquire_repository_runtime_authority(&repo.join(".kin"))
        .expect("acquire the runtime authority")
        .expect("nothing else holds the runtime authority");
    let before = tree_digest(&repo.join(".kin"));

    let refused = kin(&runtime, &repo, &["upgrade", "--json"]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success()
            && stderr.contains("runtime authority")
            && stderr.contains("Nothing was changed"),
        "{stderr}"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "an upgrade that could not exclude the daemon changed the store",
    );

    drop(held);
    let report = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(report["state"], "upgraded", "{report}");
}

/// The workspace's owed derivation records and its recorded payment, whole,
/// read from a freshly opened repository authority with no daemon serving it.
fn owed_ledger(
    repo: &Path,
) -> (
    Vec<kin_db::OwedDerivation>,
    Option<kin_db::DerivationPayment>,
) {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let workspace = lease.metadata().workspaces[0].workspace_id;
    let ledger = &lease.metadata().owed_derivations;
    (
        ledger.records_for(workspace).cloned().collect(),
        ledger.payment_for(workspace).cloned(),
    )
}

/// The logical generation repository authority stands at.
fn authority_generation(repo: &Path) -> u64 {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    lease.roots().generation
}

/// The workspace's committed graph, read from a freshly opened repository
/// authority, and the artifact its tree holds at `file`.
fn committed_workspace_graph(
    repo: &Path,
    file: &str,
) -> (kin_db::GraphSnapshot, kin_model::ArtifactId) {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let workspace = &lease.metadata().workspaces[0];
    let path = kin_model::RepoPath::from_utf8(file.to_string()).unwrap();
    let artifact = workspace
        .tree
        .artifact_at_path(&path)
        .unwrap_or_else(|| panic!("the workspace tree holds no {file}"))
        .artifact_id;
    let graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap()
        .expect("the workspace has a committed graph");
    (graph, artifact)
}

/// The identity of the parse-coverage certificate for `file`'s artifact. It
/// depends on the artifact alone, so an empty certificate from the factory
/// names it without restating the factory's rule.
fn certificate_id(file: &str, artifact: kin_model::ArtifactId) -> kin_model::RelationId {
    kin_index::build_parse_coverage_relation(
        &kin_index::FileParseData {
            file_path: file.to_string(),
            entities: Vec::new(),
            relations: Vec::new(),
            imports: Vec::new(),
        },
        artifact,
        &kin_model::ParseCompleteness::Full,
        &std::collections::HashSet::<String>::new(),
    )
    .id
}

/// A daemon's publication left a Python file owed at a body that does not
/// parse. The parser keeps the declarations it can read and marks the parse
/// partial. The upgrade derives that same partial graph, the re-derivation
/// verifier re-derives the tree itself and finds exactly that, and the
/// upgrade's commit pays the record against the generation it was compared
/// and swapped against. The payment says the owed derivation was made, not
/// that the bytes parse: reopened, the store holds the payment and still
/// reports the file's parse coverage as incomplete, its certificate bound to
/// the malformed body without the full label.
///
/// Falsify by committing a workspace state without its derived call edges:
/// the verifier refuses it, and the record stays owed with no payment.
#[test]
fn an_upgrade_pays_an_honest_partial_derivation_and_its_coverage_stays_incomplete() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks, UpgradeState};
    use kin_review::source_derivation::{inspect_source_derivation, DerivationCoverage};

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let malformed: &[u8] = b"def target(ext, args):\n    return ext, args\n\n\n\
        def caller():\n    target(1, 2)\n    return target(3, args=4\n";
    fs::write(repo.join("pkg/b.py"), malformed).unwrap();
    publish_tree_bytes_as_a_daemon_would(&repo, "pkg/b.py", malformed, Lineage::Unobserved);
    let body = kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(malformed));
    assert_eq!(
        owed_work(&repo).0,
        vec![("pkg/b.py".to_string(), body.to_string())],
        "the publication records the malformed body's parse as owed"
    );
    let predecessor = authority_generation(&repo);

    let report = upgrade_store(
        &layout,
        kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>"),
        &UpgradeHooks::default(),
        &|_: &str| {},
    )
    .expect("the store upgrades");
    assert_eq!(report.state, UpgradeState::Upgraded);

    let (records, payment) = owed_ledger(&repo);
    assert!(
        records.is_empty(),
        "the upgrade's commit left owed work: {records:?}; the verifier's refusal: {:?}",
        report.binding_history_refusal
    );
    assert_eq!(
        report.binding_history_checked,
        Some(true),
        "the verifier did not prove the partial derivation: {:?}",
        report.binding_history_refusal
    );
    let payment = payment.expect("the upgrade's commit recorded its payment");
    assert_eq!(
        payment.paid_through(),
        predecessor,
        "the payment names the generation the commit was taken against"
    );
    assert_eq!(
        payment.hydration_version(),
        kin_core::hydration_semantics::binary_version()
    );

    let (graph, artifact) = committed_workspace_graph(&repo, "pkg/b.py");
    let certificate = graph
        .relations
        .get(&certificate_id("pkg/b.py", artifact))
        .expect("the committed graph holds the file's parse-coverage certificate");
    assert!(kin_index::is_parse_coverage_relation(
        certificate,
        "pkg/b.py",
        artifact
    ));
    assert_eq!(
        kin_index::parse_coverage_source_digest(certificate),
        Some(body),
        "the certificate is bound to the malformed body"
    );
    assert!(
        kin_index::coverage_evidence(certificate, kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1)
            .is_none(),
        "a partial parse was certified full: {certificate:?}"
    );
    let path = kin_model::RepoPath::from_utf8("pkg/b.py".to_string()).unwrap();
    let served = kin_db::InMemoryGraph::from_snapshot(graph).unwrap();
    let facts = served
        .source_derivation_facts(
            kin_db::SourceDerivationLimits::default(),
            Some(std::slice::from_ref(&path)),
        )
        .unwrap();
    let derivation = inspect_source_derivation(&facts);
    assert_ne!(
        derivation.parse_coverage,
        DerivationCoverage::Complete,
        "{derivation:?}"
    );
    assert!(
        !derivation.call_shape_parse_coverage_complete,
        "{derivation:?}"
    );
}

/// A certificate bound to the current bytes pays nothing on its own. After
/// the upgrade, a daemon's publication leaves `pkg/a.py` owed at a new body.
/// A commit through the re-derivation path then installs a partial
/// parse-coverage certificate from the factory, bound to that body, over the
/// declarations the old body left. That is the shape the daemon's
/// answering-graph check reads as parsed. The real re-derivation verifier
/// derives the tree itself, finds the graph the certificate's body implies
/// missing, and refuses, so the commit publishes unproven, pays nothing, and
/// the ledger stays exactly as the publication left it.
///
/// Falsify by treating every re-derivation commit as proved: the commit pays
/// the record the verifier refused.
#[test]
fn a_current_body_certificate_over_stale_declarations_pays_nothing() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks, UpgradeState};
    use kin_model::{
        OperationId, RepositoryTransaction, WorkspaceExpectation, WorkspaceMutation,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let report = upgrade_store(
        &layout,
        kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>"),
        &UpgradeHooks::default(),
        &|_: &str| {},
    )
    .expect("the store upgrades");
    assert_eq!(report.state, UpgradeState::Upgraded);

    let edited: &[u8] = b"def helper():\n    return 1\n\n\ndef user():\n    return helper()\n";
    fs::write(repo.join("pkg/a.py"), edited).unwrap();
    publish_tree_bytes_as_a_daemon_would(&repo, "pkg/a.py", edited, Lineage::Unobserved);
    let body = kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(edited));
    let owed = owed_ledger(&repo);
    assert_eq!(
        owed.0
            .iter()
            .map(|record| (record.path().to_string(), record.body()))
            .collect::<Vec<_>>(),
        vec![("pkg/a.py".to_string(), body)],
        "the publication records the new body's parse as owed"
    );

    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let repository_id = lease.metadata().repository_id.clone();
    let workspace = lease.metadata().workspaces[0].clone();
    let graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap()
        .unwrap();
    drop(lease);
    let path = kin_model::RepoPath::from_utf8("pkg/a.py".to_string()).unwrap();
    let artifact = workspace.tree.artifact_at_path(&path).unwrap().artifact_id;
    let mut certificate = kin_index::build_parse_coverage_relation(
        &kin_index::FileParseData {
            file_path: "pkg/a.py".to_string(),
            entities: Vec::new(),
            relations: Vec::new(),
            imports: Vec::new(),
        },
        artifact,
        &kin_model::ParseCompleteness::Partial("installed with no derivation behind it".into()),
        &std::collections::HashSet::<String>::new(),
    );
    kin_index::bind_parse_coverage_source(&mut certificate, "pkg/a.py", body);
    let mut relations = graph.relations.clone();
    relations.insert(certificate.id, certificate.clone());
    let semantic_delta = kin_core::diff_workspace_semantics(
        &graph.entities,
        &graph.relations,
        &graph.entities,
        &relations,
    )
    .unwrap();
    let workspace_id = workspace.workspace_id;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id,
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>"),
        reason: "install a current-body certificate over the old body's declarations".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                semantic_overlay_hash: workspace.semantic_overlay_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation: workspace.generation + 1,
            new_head: workspace.head.clone(),
            new_base_target: workspace.base_target.clone(),
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas: Vec::new(),
            new_tree_hash: workspace.tree_hash,
            semantic_delta,
            new_shared_admission_policy: workspace.shared_admission_policy.clone(),
            new_admission_policy: workspace.admission_policy,
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    let verifier = kin_index::binding_history::RederivationBindingHistoryVerifier::default();
    manager
        .commit_rederived_repository_transaction(
            transaction,
            &verifier,
            kin_db::RederivationPayment {
                workspace_id,
                hydration_version: kin_core::hydration_semantics::binary_version(),
            },
        )
        .expect("the commit publishes, unproven");
    drop(manager);
    assert!(
        !verifier.refusals().is_empty(),
        "the verifier qualified a graph that is not the derivation of its tree"
    );

    let (committed, artifact) = committed_workspace_graph(&repo, "pkg/a.py");
    let installed = committed
        .relations
        .get(&certificate.id)
        .expect("the commit installed the certificate");
    assert!(
        kin_index::is_parse_coverage_relation(installed, "pkg/a.py", artifact)
            && kin_index::parse_coverage_source_digest(installed) == Some(body),
        "the committed graph holds a certificate for the current body: {installed:?}"
    );
    assert_eq!(
        owed_ledger(&repo),
        owed,
        "a certificate the verifier refused paid the record: {:?}",
        verifier.refusals()
    );
}

/// What `kin graph owed` says of a workspace with no records, word for word.
/// It never says nothing is owed: an empty ledger does not rule out work an
/// earlier build recorded elsewhere, or enrichment still incomplete.
const NO_RECORDS: &str = "no owed derivation records in repository authority";

/// `kin graph owed`, run so that any attempt to reach or start a daemon fails:
/// the daemon binary it is handed does not exist.
fn graph_owed(runtime: &IsolatedDaemonRuntime, repo: &Path, json: bool) -> Output {
    let mut command = runtime.kin_command();
    command.args(["graph", "owed"]);
    if json {
        command.arg("--json");
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_BIN", repo.join("no-daemon-binary-here"))
        .current_dir(repo)
        .output()
        .expect("run kin graph owed")
}

/// The logical generation, read through the read-only envelope read. Unlike a
/// full open, which records its history validation in the authority record of
/// a store this build has not validated before, it writes nothing.
fn envelope_generation(repo: &Path) -> u64 {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .read_authority_metadata_read_only(Duration::from_secs(10))
        .unwrap()
        .expect("the envelope read answers this store")
        .generation()
}

/// Run `kin graph owed` and prove it touched nothing: the store's bytes,
/// generation included, are identical afterwards, and no daemon endpoint was
/// written. Returns its stdout.
fn graph_owed_touching_nothing(runtime: &IsolatedDaemonRuntime, repo: &Path, json: bool) -> String {
    let before = tree_digest(&repo.join(".kin"));
    let generation = envelope_generation(repo);
    let output = graph_owed(runtime, repo, json);
    assert!(
        output.status.success(),
        "kin graph owed failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "kin graph owed changed the store",
    );
    assert_eq!(
        envelope_generation(repo),
        generation,
        "kin graph owed moved the store's generation"
    );
    assert!(
        !repo.join(".kin/daemon.port").exists(),
        "kin graph owed started a daemon"
    );
    String::from_utf8(output.stdout).expect("kin graph owed stdout is UTF-8")
}

/// Add a second workspace detached at the first one's base, holding the same
/// exact tree. Returns its identity.
fn add_a_second_workspace(repo: &Path) -> kin_model::WorkspaceId {
    use kin_model::{
        EffectiveAdmissionPolicyStamp, FrozenLocalOverlay, FrozenLocalOverlayDelta, LocatedEntry,
        OperationId, RepositoryTransaction, TreeDelta, WorkspaceExpectation, WorkspaceHead,
        WorkspaceMutation, WorkspaceSemanticDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let repository_id = lease.metadata().repository_id.clone();
    let first = lease.metadata().workspaces[0].clone();
    drop(lease);
    let workspace_id = kin_model::WorkspaceId::from_uuid(uuid::Uuid::new_v4());
    let overlay = FrozenLocalOverlay::new(
        workspace_id,
        0,
        kin_model::AdmissionCase::Sensitive,
        Vec::new(),
    )
    .unwrap();
    let policy = EffectiveAdmissionPolicyStamp {
        shared: first.shared_admission_policy.stamp(),
        local: overlay.stamp(),
    };
    let base = first
        .base_target
        .clone()
        .expect("the fixture workspace has a base");
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id,
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>"),
        reason: "add a second workspace at the first one's base".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: WorkspaceHead::Detached {
                target: base.clone(),
            },
            new_base_target: Some(base),
            new_base_tree_hash: first.base_tree_hash,
            tree_deltas: first
                .tree
                .artifacts()
                .map(|artifact| TreeDelta::Added {
                    artifact_id: artifact.artifact_id,
                    new: LocatedEntry::new(artifact.path.clone(), artifact.entry),
                })
                .collect(),
            new_tree_hash: first.tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: first.shared_admission_policy.clone(),
            new_admission_policy: policy,
        }),
        local_overlay_delta: Some(FrozenLocalOverlayDelta::initialize(overlay)),
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    manager
        .commit_repository_transaction(transaction)
        .expect("the second workspace is added");
    workspace_id
}

/// A daemon's publication in `workspace` of a new file at `path`, whose bytes
/// may have no UTF-8 rendering, recording the parse it is owed in the same
/// commit.
fn publish_a_new_file_owing_its_parse(
    repo: &Path,
    workspace_id: kin_model::WorkspaceId,
    path: kin_model::RepoPath,
    bytes: &[u8],
) {
    use kin_model::{
        compute_resolved_tree_hash, ArtifactId, OperationId, RepositoryTransaction,
        ResolvedArtifact, ResolvedTree, TreeEntry, WorkspaceExpectation, WorkspaceMutation,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let body = kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(bytes));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let repository_id = lease.metadata().repository_id.clone();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .expect("the workspace exists")
        .clone();
    let graph = lease
        .workspace_graph_snapshot(&workspace_id)
        .unwrap()
        .unwrap();
    drop(lease);
    manager.save_source_blob(body, bytes).unwrap();
    let desired = ResolvedTree::from_artifacts(workspace.tree.artifacts().cloned().chain(
        std::iter::once(ResolvedArtifact::new(
            ArtifactId::new(),
            path.clone(),
            TreeEntry::blob(body, false),
        )),
    ))
    .unwrap();
    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &desired).unwrap();
    let semantic_delta = kin_core::diff_workspace_semantics(
        &graph.entities,
        &graph.relations,
        &graph.entities,
        &graph.relations,
    )
    .unwrap();
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id,
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: kin_model::AuthorId::new("kin-daemon-admission"),
        reason: "admit a new file the way a daemon publishes one before its parse".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                semantic_overlay_hash: workspace.semantic_overlay_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation: workspace.generation + 1,
            new_head: workspace.head.clone(),
            new_base_target: workspace.base_target.clone(),
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas,
            new_tree_hash: compute_resolved_tree_hash(&desired).unwrap(),
            semantic_delta,
            new_shared_admission_policy: workspace.shared_admission_policy.clone(),
            new_admission_policy: workspace.admission_policy,
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    manager
        .commit_repository_transaction_owing(
            transaction,
            &kin_db::OwedDerivationUpdate::owe(workspace_id, vec![(path, body)], Vec::new()),
        )
        .expect("the new file's bytes publish");
}

/// `kin graph owed` reports the owed derivation ledger exactly as repository
/// authority holds it, and touches nothing: no daemon starts, nothing is
/// admitted, and the store's bytes and generation are the same after it as
/// before. After the upgrade the workspace has a recorded payment and no
/// records, which reads as having no records in authority, never as owing
/// nothing, with the payment still shown. Then two workspaces are reported,
/// each with its records, and a path with no UTF-8 rendering is named by its
/// bytes alone.
#[test]
fn kin_graph_owed_reports_the_ledger_and_touches_nothing() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks, UpgradeState};

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let report = upgrade_store(
        &layout,
        kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>"),
        &UpgradeHooks::default(),
        &|_: &str| {},
    )
    .expect("the store upgrades");
    assert_eq!(report.state, UpgradeState::Upgraded);
    let (records, payment) = owed_ledger(&repo);
    assert!(records.is_empty(), "{records:?}");
    let payment = payment.expect("the upgrade recorded its payment");
    let paid = serde_json::json!({
        "paid_through": payment.paid_through(),
        "operation_id": payment.operation_id().to_string(),
        "hydration_version": payment.hydration_version(),
    });

    let human = graph_owed_touching_nothing(&runtime, &repo, false);
    assert!(
        human.contains(NO_RECORDS),
        "an empty workspace must read as having no records: {human}"
    );
    assert!(
        human.contains(&format!(
            "last paid through generation {} by operation {}",
            payment.paid_through(),
            payment.operation_id()
        )),
        "a recorded payment is shown with no records: {human}"
    );
    assert!(!human.contains("nothing owed"), "{human}");
    let empty = serde_json::from_str::<Value>(&graph_owed_touching_nothing(&runtime, &repo, true))
        .expect("kin graph owed --json prints JSON");
    assert_eq!(empty["schema"], "kin.graph.owed-derivations.v1");
    assert_eq!(empty["generation"], authority_generation(&repo));
    assert_eq!(empty["workspaces"].as_array().map(Vec::len), Some(1));
    assert_eq!(empty["workspaces"][0]["records"], serde_json::json!([]));
    assert_eq!(empty["workspaces"][0]["payment"], paid);

    let edited: &[u8] = b"def helper():\n    return 1\n";
    fs::write(repo.join("pkg/a.py"), edited).unwrap();
    publish_tree_bytes_as_a_daemon_would(&repo, "pkg/a.py", edited, Lineage::Unobserved);
    let first_recorded_at = authority_generation(&repo);
    let first_id = owed_ledger(&repo).0[0].workspace_id().to_string();
    let second_id = add_a_second_workspace(&repo);
    let raw_path = kin_model::RepoPath::from_bytes(b"pkg/\xffraw.py".to_vec()).unwrap();
    let raw: &[u8] = b"def raw():\n    return 2\n";
    publish_a_new_file_owing_its_parse(&repo, second_id, raw_path, raw);
    let second_recorded_at = authority_generation(&repo);

    let value = serde_json::from_str::<Value>(&graph_owed_touching_nothing(&runtime, &repo, true))
        .expect("kin graph owed --json prints JSON");
    assert_eq!(value["generation"], second_recorded_at);
    let workspaces = value["workspaces"].as_array().expect("workspaces");
    assert_eq!(workspaces.len(), 2, "{value:#}");
    let first = workspaces
        .iter()
        .find(|workspace| workspace["workspace_id"] == first_id.as_str())
        .expect("the first workspace is reported");
    let second = workspaces
        .iter()
        .find(|workspace| workspace["workspace_id"] == second_id.to_string().as_str())
        .expect("the second workspace is reported");
    let body =
        |bytes: &[u8]| kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(bytes)).to_string();
    assert_eq!(
        first["records"],
        serde_json::json!([{
            "path": "pkg/a.py",
            "path_hex": "706b672f612e7079",
            "body": body(edited),
            "recorded_at": first_recorded_at,
            "cause": "publication",
        }])
    );
    assert_eq!(
        first["payment"], paid,
        "the payment stays shown beside records"
    );
    assert_eq!(
        second["records"],
        serde_json::json!([{
            "path": null,
            "path_hex": "706b672fff7261772e7079",
            "body": body(raw),
            "recorded_at": second_recorded_at,
            "cause": "publication",
        }])
    );
    assert!(second["payment"].is_null(), "{second:#}");

    let human = graph_owed_touching_nothing(&runtime, &repo, false);
    assert!(
        human.contains("<non-UTF-8 path, bytes 706b672fff7261772e7079>"),
        "{human}"
    );
    assert!(human.contains("pkg/a.py: parse owed for body"), "{human}");
}

/// `kin graph owed` refuses authority it cannot read, printing nothing on
/// stdout and changing nothing. A published store before any upgrade is read
/// as it is: its ledger is empty, and the record the published daemon kept
/// beside the store stays exactly where it was, because the command migrates
/// nothing. A store whose layout is newer than this build is refused, and so
/// is a store whose authority snapshot is damaged.
#[test]
fn kin_graph_owed_refuses_authority_it_cannot_read() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let legacy = repo.join(".kin/unpublished-enrichment.json");
    let kept = fs::read(&legacy).expect("the published daemon's record is present");
    let human = graph_owed_touching_nothing(&runtime, &repo, false);
    assert!(human.contains(NO_RECORDS), "{human}");
    assert_eq!(
        fs::read(&legacy).ok(),
        Some(kept),
        "kin graph owed migrated an earlier build's record"
    );

    let refused = |what: &str| {
        let before = tree_digest(&repo.join(".kin"));
        let output = graph_owed(&runtime, &repo, true);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{what} was read: {stderr}");
        assert!(
            output.stdout.is_empty(),
            "{what}: a refusal printed {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            stderr.contains(
                "kin graph owed: could not read the owed derivation ledger from repository \
                 authority"
            ),
            "{what}: {stderr}"
        );
        assert_same_store(
            &before,
            &tree_digest(&repo.join(".kin")),
            &format!("refusing {what} changed the store"),
        );
        stderr
    };

    let version = repo.join(".kin/version");
    let supported = fs::read(&version).unwrap();
    fs::write(&version, b"999").unwrap();
    let stderr = refused("a layout newer than this build");
    assert!(stderr.contains("incompatible .kin/ version"), "{stderr}");
    fs::write(&version, supported).unwrap();

    let snapshots: Vec<PathBuf> = fs::read_dir(repo.join(".kin/kindb"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("snapshots"))
        .filter(|path| path.is_dir())
        .flat_map(|dir| {
            fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
        })
        .collect();
    assert_eq!(snapshots.len(), 1, "{snapshots:?}");
    let mut damaged = fs::read(&snapshots[0]).unwrap();
    let middle = damaged.len() / 2;
    for byte in &mut damaged[middle..middle + 64] {
        *byte = !*byte;
    }
    fs::write(&snapshots[0], &damaged).unwrap();
    refused("a damaged authority snapshot");
}

/// The store's authority namespace, the directory its authority record,
/// snapshots and journal live in.
fn authority_namespace(repo: &Path) -> PathBuf {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .namespace_path()
}

/// `kin graph owed` in `repo`, returning within `bound` or failing, so a read
/// that waits on a lock cannot hang the suite.
fn graph_owed_within(runtime: &IsolatedDaemonRuntime, repo: &Path, bound: Duration) -> Output {
    runtime
        .kin_command()
        .args(["graph", "owed", "--json"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_BIN", repo.join("no-daemon-binary-here"))
        .current_dir(repo)
        .output_within(bound)
        .expect("kin graph owed returned within its bound rather than waiting on")
}

/// `kin graph owed` leaves the store exactly as it found it, including what an
/// open cleans up. A superseded snapshot beside the current one is what a full
/// promotion leaves when its cleanup fails, and the backend's recovery load
/// deletes it on the next open or recovery read. The command reads without
/// that load, answers from the same authority, and the file stays.
///
/// Falsify by reading the envelope through the recovery load: the command
/// still answers, and the superseded snapshot is gone.
#[test]
fn kin_graph_owed_leaves_what_an_open_would_clean_up() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let snapshots = authority_namespace(&repo).join("snapshots");
    let current: Vec<PathBuf> = fs::read_dir(&snapshots)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(current.len(), 1, "{current:?}");
    let generation: u64 = current[0]
        .file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.parse().ok())
        .expect("a snapshot is named by its generation");
    let superseded = snapshots.join(format!("{:020}.kndb", generation - 1));
    fs::copy(&current[0], &superseded).unwrap();
    let before = tree_digest(&repo.join(".kin"));

    let output = graph_owed(&runtime, &repo, true);
    let stdout = String::from_utf8(output.stdout).expect("kin graph owed stdout is UTF-8");
    assert!(
        output.status.success(),
        "stdout={stdout} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        superseded.exists(),
        "kin graph owed deleted the superseded snapshot an open cleans up"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "kin graph owed changed the store",
    );

    let value: Value = serde_json::from_str(&stdout).expect("kin graph owed --json prints JSON");
    assert_eq!(value["schema"], "kin.graph.owed-derivations.v1");
    assert_eq!(
        value["workspaces"].as_array().map(Vec::len),
        Some(1),
        "{value:#}"
    );
    assert_eq!(value["workspaces"][0]["records"], serde_json::json!([]));
    assert!(value["workspaces"][0]["payment"].is_null(), "{value:#}");
    // Opened in full only now, with the store compared: an open writes.
    assert_eq!(value["generation"], authority_generation(&repo));
}

/// When the envelope read cannot answer, `kin graph owed` validates the store
/// in full without writing, and refuses what that validation refuses. A
/// namespace whose authority record and journal are gone is such a store: the
/// envelope read finds no authority to answer from, the read-only validation
/// finds none to validate, and the command refuses with that cause, printing
/// nothing on stdout and writing nothing.
///
/// Falsify by opening the store in full for the fallback: the refusal names
/// the full open's cause, "has no persisted authority record", instead.
#[test]
fn kin_graph_owed_falls_back_to_a_read_only_validation() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let namespace = authority_namespace(&repo);
    fs::remove_file(namespace.join("authority.json")).unwrap();
    for entry in fs::read_dir(namespace.join("deltas")).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let before = tree_digest(&repo.join(".kin"));

    let output = graph_owed(&runtime, &repo, true);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "a store with no authority was read: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "a refusal printed {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(
            "kin graph owed: could not read the owed derivation ledger from repository authority"
        ) && stderr.contains("validate repository authority read-only")
            && stderr.contains("has no existing local snapshot authority to freeze"),
        "{stderr}"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "refusing a store with no authority changed it",
    );
}

/// `kin graph owed` waits a bounded time for a repository authority lock
/// another process holds, the lock a daemon takes while it commits. Held for a
/// moment, the command waits it out and answers. Held throughout, it waits out
/// its ten-second bound and refuses, naming the lock, with nothing on stdout
/// and the store as it was. It never waits on.
///
/// Falsify by taking the lock with a blocking acquisition: the command waits
/// as long as the holder does, and the bounded run times out.
#[test]
fn kin_graph_owed_waits_a_bounded_time_for_a_held_lock() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let repository_id = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .repository_id()
        .clone();
    let before = tree_digest(&repo.join(".kin"));

    // Held for a moment: waited out, then answered.
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let holder = {
        let repository_id = repository_id.clone();
        let kindb = layout.kindb_dir();
        std::thread::spawn(move || {
            let backend = kin_db::LocalFileBackend::new(kindb);
            let held = kin_db::LocalRepositoryAuthorityFreeze::open_existing_read_only(
                repository_id,
                &backend,
            )
            .expect("hold the repository authority lock");
            held_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(1500));
            drop(held);
        })
    };
    held_rx.recv().unwrap();
    let started = Instant::now();
    let answered = graph_owed_within(&runtime, &repo, Duration::from_secs(40));
    let waited = started.elapsed();
    holder.join().unwrap();
    assert!(
        answered.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&answered.stderr)
    );
    assert!(
        waited >= Duration::from_secs(1),
        "it answered while the lock was held: {waited:?}"
    );

    // Held throughout: the bound is waited out, and the command refuses.
    let backend = kin_db::LocalFileBackend::new(layout.kindb_dir());
    let held =
        kin_db::LocalRepositoryAuthorityFreeze::open_existing_read_only(repository_id, &backend)
            .expect("hold the repository authority lock");
    let started = Instant::now();
    let refused = graph_owed_within(&runtime, &repo, Duration::from_secs(40));
    let waited = started.elapsed();
    drop(held);
    let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(
        !refused.status.success(),
        "a held lock was read through: {stderr}"
    );
    assert!(
        refused.stdout.is_empty(),
        "a refusal printed {}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(
        stderr.contains("another process held the repository authority lock"),
        "{stderr}"
    );
    assert!(
        waited >= Duration::from_secs(10),
        "it refused before its bound: {waited:?}"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "waiting on a held lock changed the store",
    );
}

/// A stash sealed on a head the upgrade would move can never be restored
/// after it, so the upgrade refuses and changes nothing; restoring the stash
/// first lets it through.
#[test]
fn an_upgrade_refuses_to_strand_a_stash_and_changes_nothing() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);

    fs::write(
        repo.join("pkg/c.py"),
        "def triple(value):\n    return value * 3\n",
    )
    .unwrap();
    succeed(&runtime, &repo, &["stash", "push", "--yes"]);
    succeed(&runtime, &repo, &["daemon", "stop"]);
    settle_runtime_authority(&repo);
    let before = tree_digest(&repo.join(".kin"));

    let refused = kin(&runtime, &repo, &["upgrade"]);
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("refs/kin/stash/") && stderr.contains("Nothing was changed"),
        "{stderr}"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "a refused upgrade changed the store",
    );

    succeed(&runtime, &repo, &["stash", "pop"]);
    let report = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(report["state"], "upgraded", "{report}");
    assert_eq!(report["workspace_dirty"], true, "{report}");
}

/// The same refusal after a daemon its shutdown watchdog ended. With no
/// shutdown grace the watchdog ends the daemon without the release that clears
/// its owner stamp, which is how a loaded host ended the daemon the test above
/// stops, and the refused upgrade then cleared that stamp when it released the
/// runtime authority. That read as a changed store. The baseline is taken with
/// the lock at rest, so the store, the lock included, must still be unchanged.
#[test]
fn an_upgrade_refusal_after_a_watchdog_ended_daemon_changes_nothing() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);

    fs::write(
        repo.join("pkg/c.py"),
        "def triple(value):\n    return value * 3\n",
    )
    .unwrap();
    let pushed = runtime
        .kin_command()
        .args(["stash", "push", "--yes"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "180")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_SHUTDOWN_GRACE_SECS", "0")
        .current_dir(&repo)
        .output()
        .expect("run kin stash push");
    assert!(
        pushed.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&pushed.stderr)
    );
    succeed(&runtime, &repo, &["daemon", "stop"]);
    settle_runtime_authority(&repo);
    let before = tree_digest(&repo.join(".kin"));

    let refused = kin(&runtime, &repo, &["upgrade"]);
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("refs/kin/stash/") && stderr.contains("Nothing was changed"),
        "{stderr}"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "a refused upgrade after a watchdog-ended daemon changed the store",
    );
}

/// Put `.kin/daemon.lock` at rest before a whole-store baseline is taken.
///
/// The lock's bytes say how its last holder ended, not what the store holds.
/// A daemon that finishes its own shutdown clears its owner stamp on the way
/// out. One ended by its shutdown watchdog or by a signal exits without
/// running that release and leaves its stamp, and this harness gives a daemon
/// three seconds of shutdown grace, so on a loaded host that is the ordinary
/// ending. The next holder of the runtime authority overwrites the stamp and
/// clears it on release, and `kin upgrade` takes that authority before it
/// plans. A refusal after such an ending therefore read as a changed store,
/// although nothing the store holds had moved.
///
/// Taking and releasing the authority here, as every holder does, makes the
/// baseline the released lock whichever way the daemon ended, so the whole
/// tree, the lock included, is still compared byte for byte. The authority
/// must be free: a daemon that outlived its stop fails here rather than later.
fn settle_runtime_authority(repo: &Path) {
    let authority = kin_cli::daemon_client::acquire_repository_runtime_authority_within(
        &repo.join(".kin"),
        Duration::from_secs(1),
    )
    .expect("acquire the runtime authority")
    .expect("a stopped daemon still holds the runtime authority");
    drop(authority);
    assert_eq!(
        fs::read(repo.join(".kin/daemon.lock")).expect("read the released runtime lock"),
        b"",
        "releasing the runtime authority left an owner stamp"
    );
}

/// An upgrade stopped at the last moment before its commit leaves every byte
/// of the store as it was, and one stopped right after its commit is finished
/// by running it again, which adds no second change.
#[test]
fn an_interrupted_upgrade_leaves_the_store_as_it_was_or_finishes_on_rerun() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks, UpgradeState};

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let author = kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>");
    let quiet = |_: &str| {};
    let behind = || {
        kin_core::hydration_semantics::standing(&layout)
            .label()
            .to_string()
    };
    assert_eq!(behind(), "behind");

    // Every open by this build records, in the authority manifest, the
    // history validator version it checked the store under, whatever command
    // opened it; `kin status` does the same. The baseline is the store as an
    // ordinary read by this build left it, so the comparison is about what
    // the upgrade itself writes.
    drop(
        kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
            .unwrap()
            .open_manager_with_payload_stats()
            .unwrap(),
    );
    let before = tree_digest(&repo.join(".kin"));
    let stopped = upgrade_store(
        &layout,
        author.clone(),
        &UpgradeHooks {
            before_commit: Some(Box::new(|| anyhow::bail!("stopped before the commit"))),
            after_commit: None,
        },
        &quiet,
    )
    .expect_err("the hook stops the upgrade");
    assert!(stopped.to_string().contains("stopped before the commit"));
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "an upgrade stopped before its commit changed the store",
    );
    assert_eq!(behind(), "behind");
    assert!(
        owed_work(&repo).1.is_none(),
        "an upgrade stopped before its commit paid nothing"
    );
    let legacy = legacy_records(&repo);
    let kept: Vec<Option<Vec<u8>>> = legacy.iter().map(|record| fs::read(record).ok()).collect();

    upgrade_store(
        &layout,
        author.clone(),
        &UpgradeHooks {
            before_commit: None,
            after_commit: Some(Box::new(|| anyhow::bail!("stopped after the commit"))),
        },
        &quiet,
    )
    .expect_err("the hook stops the upgrade");
    assert_eq!(
        behind(),
        "behind",
        "the record is the claim and is written last, so it must not move before the finish"
    );
    // The payment rode the commit itself, so a stop straight after it leaves
    // the store paid, and the published build's records, removed only after
    // that, for the next daemon start to judge.
    assert!(
        owed_work(&repo).1.is_some(),
        "the payment is part of the commit, not a step after it"
    );
    for (record, bytes) in legacy.iter().zip(&kept) {
        assert_eq!(fs::read(record).ok(), *bytes);
    }

    let finished = upgrade_store(&layout, author, &UpgradeHooks::default(), &quiet)
        .expect("the rerun finishes the upgrade");
    assert_eq!(finished.state, UpgradeState::Upgraded);
    assert!(
        finished.heads.iter().all(|head| !head.checkpoint),
        "the rerun added a second checkpoint over heads the first run already derived"
    );
    assert_eq!(finished.binding_history_checked, Some(true));
    assert_eq!(behind(), "current");
}

/// A second upgrade of an upgraded store changes nothing. One whose lineage an
/// ordinary, unchecked commit ended is re-qualified: the same re-derivation
/// starts a new lineage at a change with no delta on the workspace's head, and
/// the record, already current, is not rewritten.
#[test]
fn a_second_upgrade_is_a_no_op_or_a_clean_requalification() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks, UpgradeState};
    use kin_model::{
        OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
        RepositoryTransaction, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let author = kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>");
    let quiet = |_: &str| {};
    let first = upgrade_store(&layout, author.clone(), &UpgradeHooks::default(), &quiet)
        .expect("the published store upgrades");
    assert_eq!(first.state, UpgradeState::Upgraded);
    assert_eq!(first.binding_history_checked, Some(true));

    let store = tree_digest(&repo.join(".kin"));
    let again = upgrade_store(&layout, author.clone(), &UpgradeHooks::default(), &quiet)
        .expect("a second run succeeds");
    assert_eq!(again.state, UpgradeState::AlreadyCurrent);
    assert_eq!(again.binding_history_checked, Some(true));
    assert_same_store(
        &store,
        &tree_digest(&repo.join(".kin")),
        "a second upgrade of an upgraded store changed it",
    );

    // An ordinary commit carries no binding-history check, so it ends the
    // lineage the upgrade started.
    let record = fs::read(layout.kindb_hydration_semantics_path()).unwrap();
    {
        let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
            .unwrap()
            .open_manager_with_payload_stats()
            .unwrap();
        let lease = manager.read_authority();
        let roots = lease.roots().clone();
        let repository_id = lease.metadata().repository_id.clone();
        drop(lease);
        manager
            .commit_repository_transaction(RepositoryTransaction {
                schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
                operation_id: OperationId::new(),
                repository_id,
                expected_generation: roots.generation,
                expected_roots: roots,
                actor: author.clone(),
                reason: "an ordinary commit that checks no binding history".to_string(),
                external_objects: Vec::new(),
                git_authority_delta: None,
                changes: Vec::new(),
                aliases: Vec::new(),
                ref_mutations: vec![RefMutation {
                    name: RefName::branch(b"requalify-probe").unwrap(),
                    expected: RefExpectation::MustNotExist,
                    new_target: Some(RefTarget::symbolic(RefName::branch(b"main").unwrap())),
                    policy: RefUpdatePolicy::FastForwardOnly,
                }],
                default_ref_mutation: None,
                workspace_mutation: None,
                local_overlay_delta: None,
                merge_transaction_delta: None,
                sealed_observation: None,
                collaboration_delta: None,
            })
            .expect("an ordinary commit lands");
        let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
        assert!(
            manager
                .read_authority()
                .workspace_graph_snapshot(&workspace)
                .unwrap()
                .unwrap()
                .verified_binding_history
                .is_none(),
            "the ordinary commit was meant to end the lineage"
        );
    }

    let requalified = upgrade_store(&layout, author.clone(), &UpgradeHooks::default(), &quiet)
        .expect("the re-qualification succeeds");
    assert_eq!(requalified.state, UpgradeState::Requalified);
    assert_eq!(requalified.binding_history_checked, Some(true));
    // Every head already held this build's derivation and the workspace held
    // nothing to re-derive, so the one change is the commit the lineage starts
    // at: no delta, on the workspace's own head, because a commit that changes
    // nothing is refused.
    let checkpoints: Vec<_> = requalified
        .heads
        .iter()
        .filter(|head| head.checkpoint)
        .collect();
    assert_eq!(checkpoints.len(), 1, "{:?}", requalified.heads);
    assert!(
        checkpoints[0]
            .refs
            .iter()
            .any(|name| name == "refs/heads/main"),
        "the lineage must start on the workspace's own head: {:?}",
        checkpoints[0]
    );
    assert_eq!(
        (checkpoints[0].entity_deltas, checkpoints[0].relation_deltas),
        (0, 0),
        "{:?}",
        checkpoints[0]
    );
    assert_eq!(
        fs::read(layout.kindb_hydration_semantics_path()).unwrap(),
        record,
        "a re-qualification rewrote the hydration record"
    );
    assert_eq!(
        kin_core::hydration_semantics::standing(&layout).label(),
        "current"
    );
    // The lineage it started holds, so a third run has nothing to do.
    let third = upgrade_store(&layout, author, &UpgradeHooks::default(), &quiet)
        .expect("a third run succeeds");
    assert_eq!(third.state, UpgradeState::AlreadyCurrent);
}

/// The upgrade's claim follows first parents from its anchors, so a head that
/// a change the older build recorded already builds on cannot be its own
/// anchor, even when its state is already this build's derivation: restoring
/// that later change would keep the claim over state the older build derived.
/// Such a head gets a checkpoint with no delta; a head nothing builds on stays
/// its own anchor.
#[test]
fn a_head_an_earlier_change_builds_on_gets_a_fresh_anchor() {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks, UpgradeState};
    use kin_model::{
        compute_semantic_change_id, ChangeOrigin, Hash256, OperationId, RefExpectation,
        RefMutation, RefName, RefTarget, RefUpdatePolicy, RepositoryTransaction, SemanticChange,
        SemanticChangeId, Timestamp, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let author = kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>");
    let quiet = |_: &str| {};
    let first = upgrade_store(&layout, author.clone(), &UpgradeHooks::default(), &quiet)
        .expect("the published store upgrades");
    let main_anchor = first
        .heads
        .iter()
        .find(|head| head.refs.iter().any(|name| name == "refs/heads/main"))
        .expect("the upgrade reports main")
        .anchor
        .clone();

    // The store reads behind again, and a change with no delta now builds on
    // main's anchor, as a change an older build recorded would.
    kin_core::hydration_semantics::HydrationStampCapability::open(&layout.kindb_dir())
        .unwrap()
        .drop_upgrade()
        .unwrap();
    assert_eq!(
        kin_core::hydration_semantics::standing(&layout).label(),
        "behind"
    );
    let parent = SemanticChangeId::from_hash(Hash256::from_hex(&main_anchor).unwrap());
    {
        let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
            .unwrap()
            .open_manager_with_payload_stats()
            .unwrap();
        let lease = manager.read_authority();
        let roots = lease.roots().clone();
        let repository_id = lease.metadata().repository_id.clone();
        drop(lease);
        let mut side = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![parent],
            timestamp: Timestamp::now(),
            author: author.clone(),
            message: "A change that builds on main's anchor".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
            resolution_record_deltas: Vec::new(),
        };
        side.id = compute_semantic_change_id(&side).unwrap();
        let side_id = side.id;
        manager
            .commit_repository_transaction(RepositoryTransaction {
                schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
                operation_id: OperationId::new(),
                repository_id,
                expected_generation: roots.generation,
                expected_roots: roots,
                actor: author.clone(),
                reason: "a branch that builds on main".to_string(),
                external_objects: Vec::new(),
                git_authority_delta: None,
                changes: vec![side],
                aliases: Vec::new(),
                ref_mutations: vec![RefMutation {
                    name: RefName::branch(b"side").unwrap(),
                    expected: RefExpectation::MustNotExist,
                    new_target: Some(RefTarget::change(side_id)),
                    policy: RefUpdatePolicy::FastForwardOnly,
                }],
                default_ref_mutation: None,
                workspace_mutation: None,
                local_overlay_delta: None,
                merge_transaction_delta: None,
                sealed_observation: None,
                collaboration_delta: None,
            })
            .expect("a branch builds on main's anchor");
    }

    let second = upgrade_store(&layout, author, &UpgradeHooks::default(), &quiet)
        .expect("the store upgrades again");
    assert_eq!(second.state, UpgradeState::Upgraded);
    let head = |name: &str| {
        second
            .heads
            .iter()
            .find(|head| head.refs.iter().any(|reference| reference == name))
            .unwrap_or_else(|| panic!("the upgrade did not report {name}"))
            .clone()
    };
    let main = head("refs/heads/main");
    assert_eq!(main.previous, main_anchor);
    assert!(
        main.checkpoint && main.entity_deltas == 0 && main.relation_deltas == 0,
        "main's state already matched, and something builds on it, so it needs an empty \
         checkpoint: {main:?}"
    );
    let side = head("refs/heads/side");
    assert!(!side.checkpoint, "nothing builds on side: {side:?}");
    let kin_core::hydration_semantics::HydrationSemanticsRead::Recorded(record) =
        kin_core::hydration_semantics::read(&layout)
    else {
        panic!("the upgrade wrote no record");
    };
    let anchors = &record
        .upgrade
        .expect("the record states the upgrade")
        .anchors;
    assert!(anchors.contains(&main.anchor) && anchors.contains(&side.anchor));
    assert!(
        !anchors.contains(&main_anchor),
        "a head something already built on was recorded as an anchor"
    );
}

/// The remedy a CLI hydration line carries: the text after `Remedy: ` up to the
/// line's final period.
fn remedy_in(output: &str) -> String {
    let line = output
        .lines()
        .find(|line| line.contains("hydration semantics:"))
        .unwrap_or_else(|| panic!("no hydration semantics line: {output}"));
    let remedy =
        &line[line.find("Remedy: ").expect("the line names a remedy") + "Remedy: ".len()..];
    remedy.strip_suffix('.').unwrap_or(remedy).to_string()
}

/// The fix `kin doctor --json` names for the hydration-semantics row.
fn doctor_hydration_fix(runtime: &IsolatedDaemonRuntime, repo: &Path) -> Option<String> {
    let output = kin(runtime, repo, &["doctor", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "kin doctor --json: {error}: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let row = report["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["id"] == "hydration_semantics")
        .unwrap_or_else(|| panic!("doctor has no hydration_semantics row: {report}"))
        .clone();
    row["manual_fix"].as_str().map(str::to_string)
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == ".kin" || name == ".git" {
            continue;
        }
        let target: PathBuf = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Assert two readings of a store are byte for byte equal, naming every path
/// that was added, removed or rewritten when they are not.
fn assert_same_store(
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
    what: &str,
) {
    let differing: Vec<&String> = before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| before.get(*path) != after.get(*path))
        .collect();
    assert!(differing.is_empty(), "{what}: {differing:?}");
}

/// A digest of every file under `root`, by relative path and bytes.
fn tree_digest(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(relative, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// A relation-only publication, using the same durable workspace delta as
/// enrichment. No source, entity or historical object is rewritten.
fn publish_scope_test_relations(repo: &Path, relations: &[kin_model::Relation]) {
    use kin_model::*;
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let repository_id = lease.metadata().repository_id.clone();
    let workspace = lease.metadata().workspaces[0].clone();
    let graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap()
        .unwrap();
    drop(lease);
    let mut desired = graph.relations.clone();
    for relation in relations {
        desired.insert(relation.id, relation.clone());
    }
    let semantic_delta = kin_core::diff_workspace_semantics(
        &graph.entities,
        &graph.relations,
        &graph.entities,
        &desired,
    )
    .unwrap();
    manager
        .commit_repository_transaction(RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id,
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("Scope fixture"),
            reason: "publish language-server fixture evidence".into(),
            external_objects: Vec::new(),
            changes: Vec::new(),
            aliases: Vec::new(),
            git_authority_delta: None,
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(WorkspaceMutation {
                workspace_id: workspace.workspace_id,
                expected: WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: workspace.head.clone(),
                new_base_target: workspace.base_target.clone(),
                new_base_tree_hash: workspace.base_tree_hash,
                tree_deltas: Vec::new(),
                new_tree_hash: workspace.tree_hash,
                semantic_delta,
                new_shared_admission_policy: workspace.shared_admission_policy.clone(),
                new_admission_policy: workspace.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: None,
        })
        .unwrap();
}

struct PythonScopeFixture {
    root: tempfile::TempDir,
    old: kin_model::Relation,
    new: kin_model::Relation,
    manual: kin_model::Relation,
    other: kin_model::Relation,
    accepted_other: kin_model::Relation,
}

impl PythonScopeFixture {
    fn repo(&self) -> PathBuf {
        self.root.path().join("clean")
    }
    fn layout(&self) -> kin_core::KinLayout {
        kin_core::KinLayout::new(self.repo().join(".kin"))
    }
    fn graph(&self) -> kin_db::GraphSnapshot {
        committed_workspace_graph(&self.repo(), "pkg/a.py").0
    }
}

fn python_scope_fixture() -> PythonScopeFixture {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks};
    use kin_model::*;
    let root = tempdir().unwrap();
    unpack(root.path());
    let repo = root.path().join("clean");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    // Keep a real published history, but isolate the new scope transition from
    // unrelated old parser differences by deriving its current served tree first.
    upgrade_store(
        &layout,
        AuthorId::new("Scope fixture"),
        &UpgradeHooks::default(),
        &|_| {},
    )
    .unwrap();
    let graph = committed_workspace_graph(&repo, "pkg/a.py").0;
    let find = |name: &str| {
        graph
            .entities
            .values()
            .find(|entity| entity.language == LanguageId::Python && entity.name == name)
            .unwrap()
            .id
    };
    let (caller, new_target) = (find("run"), find("double"));
    let other_target = graph
        .entities
        .values()
        .find(|entity| entity.language == LanguageId::Rust && entity.kind == EntityKind::Function)
        .unwrap()
        .id;
    let relation = |src, dst, origin| Relation {
        id: RelationId::new(),
        kind: RelationKind::References,
        src: GraphNodeId::Entity(src),
        dst: GraphNodeId::Entity(dst),
        confidence: 0.95,
        origin,
        created_in: None,
        import_source: None,
        evidence: Vec::new(), // Legacy spanless evidence must not evade retirement.
    };
    let old = relation(caller, other_target, RelationOrigin::Lsp);
    let new = relation(caller, new_target, RelationOrigin::Lsp);
    let manual = relation(caller, other_target, RelationOrigin::Manual);
    let other = relation(other_target, other_target, RelationOrigin::Lsp);
    let accepted_other = relation(other_target, other_target, RelationOrigin::Lsp);
    publish_scope_test_relations(&repo, &[old.clone(), manual.clone(), other.clone()]);
    kin_core::hydration_semantics::write(
        &layout,
        &kin_core::hydration_semantics::HydrationSemanticsStamp::new(30, chrono::Utc::now()),
    )
    .unwrap();
    fs::write(
        layout.root().join("lsp-enriched-files.json"),
        br#"{"version":3,"files":["pkg/a.py","pkg/b.py","src/lib.rs"]}"#,
    )
    .unwrap();
    fs::write(layout.root().join("lsp-owed-files.json"),
        br#"{"pkg/a.py":{"blob":"old","attempts":4,"last_attempt_unix_s":100,"reason":"old scope"},"src/lib.rs":{"blob":"keep","attempts":2,"last_attempt_unix_s":99,"reason":"unrelated"}}"#).unwrap();
    let journal = format!(
        "{}\n{}\n",
        serde_json::to_string(&old).unwrap(),
        serde_json::to_string(&accepted_other).unwrap()
    );
    fs::write(layout.root().join("lsp-accepted-evidence.jsonl"), journal).unwrap();
    PythonScopeFixture {
        root,
        old,
        new,
        manual,
        other,
        accepted_other,
    }
}

fn upgrade_python_fixture(
    fixture: &PythonScopeFixture,
    hooks: &kin_cli::commands::upgrade::UpgradeHooks,
) -> anyhow::Result<kin_cli::commands::upgrade::UpgradeReport> {
    kin_cli::commands::upgrade::upgrade_store(
        &fixture.layout(),
        kin_model::AuthorId::new("Scope fixture"),
        hooks,
        &|_| {},
    )
}

#[test]
fn python_scope_upgrade_retires_old_target_preserves_other_truth_and_accepts_new_target() {
    use kin_cli::commands::upgrade::{UpgradeHooks, UpgradeState};
    let fixture = python_scope_fixture();
    let before = fixture.graph();
    let report = upgrade_python_fixture(&fixture, &UpgradeHooks::default()).unwrap();
    assert_eq!(report.state, UpgradeState::Upgraded);
    let after = fixture.graph();
    assert!(!after.relations.contains_key(&fixture.old.id));
    assert_eq!(
        before.entities, after.entities,
        "a scope upgrade must keep entity identities and payloads"
    );
    assert_eq!(before.resolved_tree, after.resolved_tree);
    for (id, change) in &before.changes {
        assert_eq!(after.changes.get(id), Some(change));
    }
    for (id, relation) in &before.relations {
        if *id != fixture.old.id {
            assert_eq!(after.relations.get(id), Some(relation));
        }
    }
    assert_eq!(
        after.relations.get(&fixture.manual.id),
        Some(&fixture.manual)
    );
    assert_eq!(after.relations.get(&fixture.other.id), Some(&fixture.other));
    let root = fixture.layout();
    let marker: Value =
        serde_json::from_slice(&fs::read(root.root().join("lsp-enriched-files.json")).unwrap())
            .unwrap();
    assert_eq!(marker["files"], serde_json::json!(["src/lib.rs"]));
    let owed: Value =
        serde_json::from_slice(&fs::read(root.root().join("lsp-owed-files.json")).unwrap())
            .unwrap();
    assert!(owed.get("pkg/a.py").is_none());
    assert_eq!(owed["src/lib.rs"]["attempts"], 2);
    let journal = fs::read_to_string(root.root().join("lsp-accepted-evidence.jsonl")).unwrap();
    assert!(!journal.contains(&fixture.old.id.to_string()));
    assert!(journal.contains(&fixture.accepted_other.id.to_string()));
    let unchanged = tree_digest(root.root());
    assert_eq!(
        upgrade_python_fixture(&fixture, &UpgradeHooks::default())
            .unwrap()
            .state,
        UpgradeState::AlreadyCurrent
    );
    assert_same_store(
        &unchanged,
        &tree_digest(root.root()),
        "an unchanged upgraded store reset evidence again",
    );
    // A fresh server result can now replace A with B. Later requalification
    // must retain that corrected evidence instead of resetting every upgrade.
    publish_scope_test_relations(&fixture.repo(), std::slice::from_ref(&fixture.new));
    upgrade_python_fixture(&fixture, &UpgradeHooks::default()).unwrap();
    let reopened = fixture.graph();
    assert!(!reopened.relations.contains_key(&fixture.old.id));
    assert_eq!(reopened.relations.get(&fixture.new.id), Some(&fixture.new));
}

#[test]
fn python_scope_upgrade_recovers_committed_prefix_and_sidecar_failure() {
    use kin_cli::commands::upgrade::UpgradeHooks;
    let fixture = python_scope_fixture();
    // An ordinary first graph read refreshes the prepared query memo after
    // the fixture's publication. Baseline that read before checking that the
    // refused upgrade itself leaves every persisted byte unchanged.
    drop(fixture.graph());
    let before = tree_digest(fixture.layout().root());
    let stopped = UpgradeHooks {
        before_commit: Some(Box::new(|| anyhow::bail!("before scope commit"))),
        after_commit: None,
    };
    assert!(upgrade_python_fixture(&fixture, &stopped).is_err());
    assert_same_store(
        &before,
        &tree_digest(fixture.layout().root()),
        "pre-commit refusal modified evidence",
    );
    let stopped = UpgradeHooks {
        before_commit: None,
        after_commit: Some(Box::new(|| anyhow::bail!("after scope commit"))),
    };
    assert!(upgrade_python_fixture(&fixture, &stopped).is_err());
    assert!(!fixture.graph().relations.contains_key(&fixture.old.id));
    assert!(!kin_core::lsp_scope::upgrade_recorded(&fixture.layout()));
    assert!(
        fs::read_to_string(fixture.layout().root().join("lsp-accepted-evidence.jsonl"))
            .unwrap()
            .contains(&fixture.old.id.to_string())
    );
    // Cleanup failure cannot certify completion after the irreversible commit.
    let marker = fixture.layout().root().join("lsp-enriched-files.json");
    let saved = fs::read(&marker).unwrap();
    fs::remove_file(&marker).unwrap();
    fs::create_dir(&marker).unwrap();
    assert!(upgrade_python_fixture(&fixture, &UpgradeHooks::default()).is_err());
    assert!(!kin_core::lsp_scope::upgrade_recorded(&fixture.layout()));
    fs::remove_dir(&marker).unwrap();
    fs::write(&marker, saved).unwrap();
    let finished = upgrade_python_fixture(&fixture, &UpgradeHooks::default()).unwrap();
    assert!(finished.heads.iter().all(|head| !head.checkpoint));
    assert!(kin_core::lsp_scope::upgrade_recorded(&fixture.layout()));
    assert!(!fixture.graph().relations.contains_key(&fixture.old.id));
    assert_eq!(
        fixture.graph().relations.get(&fixture.other.id),
        Some(&fixture.other)
    );
}

#[test]
fn python_scope_upgrade_keeps_unrelated_unversioned_completion_paths() {
    use kin_cli::commands::upgrade::UpgradeHooks;
    let fixture = python_scope_fixture();
    let marker = fixture.layout().root().join("lsp-enriched-files.json");
    fs::write(
        &marker,
        br#"["pkg/a.py","typing.pyi","src/lib.rs","py","pyi"]"#,
    )
    .unwrap();
    upgrade_python_fixture(&fixture, &UpgradeHooks::default()).unwrap();
    let retained: Value = serde_json::from_slice(&fs::read(marker).unwrap()).unwrap();
    assert_eq!(retained, serde_json::json!(["src/lib.rs", "py", "pyi"]));
}

#[test]
fn python_scope_upgrade_refuses_multiple_workspaces_before_retiring_evidence() {
    use kin_cli::commands::upgrade::UpgradeHooks;
    let fixture = python_scope_fixture();
    add_a_second_workspace(&fixture.repo());
    let before = tree_digest(fixture.layout().root());
    let error = upgrade_python_fixture(&fixture, &UpgradeHooks::default()).unwrap_err();
    assert!(format!("{error:#}").contains("moves exactly one"));
    assert_same_store(
        &before,
        &tree_digest(fixture.layout().root()),
        "an unsupported workspace scope retired evidence",
    );
}

#[test]
#[cfg(feature = "vector")]
fn python_scope_upgrade_reuses_compatible_persisted_vectors() {
    use kin_cli::commands::upgrade::UpgradeHooks;
    let fixture = python_scope_fixture();
    let layout = fixture.layout();
    let graph = kin_db::InMemoryGraph::from_snapshot(fixture.graph()).unwrap();
    let kin_model::GraphNodeId::Entity(entity) = fixture.old.src else {
        unreachable!()
    };
    let vectors = kin_db::VectorIndex::new(4).unwrap();
    vectors.upsert(entity, &[1.0, 0.0, 0.0, 0.0]).unwrap();
    let descriptor = kin_db::IndexDescriptor {
        model_id: Some("scope-fixture@v1".to_string()),
        graph_root: Some(hex::encode(graph.compute_root_hash())),
    };
    vectors.set_descriptor(descriptor.clone());
    let seed = layout.kindb_vector_index_path().with_extension("kvec.seed");
    vectors.save(&seed).unwrap();
    assert!(matches!(
        graph.load_vector_index_compatible(&seed, &descriptor),
        kin_db::VectorIndexLoad::Loaded(_)
    ));
    kin_db::SnapshotManager::save_vector_index_for_graph(
        layout.kindb_snapshot_path(),
        &graph,
        None,
    )
    .unwrap();
    fs::remove_file(seed).unwrap();
    let index_bytes = fs::read(layout.kindb_vector_index_path()).unwrap();
    let metadata = layout
        .kindb_vector_index_path()
        .with_extension("kvec.meta.json");
    let metadata_bytes = fs::read(&metadata).unwrap();

    upgrade_python_fixture(&fixture, &UpgradeHooks::default()).unwrap();
    assert_eq!(
        fs::read(layout.kindb_vector_index_path()).unwrap(),
        index_bytes
    );
    assert_eq!(fs::read(metadata).unwrap(), metadata_bytes);
    let reopened = kin_db::InMemoryGraph::from_snapshot(fixture.graph()).unwrap();
    let loaded = kin_db::SnapshotManager::load_vector_index_into_graph_if_valid(
        &reopened,
        &layout.kindb_snapshot_path(),
        None,
    )
    .unwrap();
    assert!(loaded.attached, "{loaded:?}");
    assert_eq!(reopened.embedding_status().indexed, 1);
}

/// Whether the graph this store's workspace selects carries checked binding
/// history, read from a freshly opened repository authority with no daemon
/// serving the store.
fn workspace_lineage_checked(repo: &Path) -> bool {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let workspace = lease.metadata().workspaces[0].workspace_id;
    lease
        .workspace_graph_snapshot(&workspace)
        .unwrap()
        .expect("the workspace has a committed graph")
        .verified_binding_history
        .is_some()
}

/// What a daemon's start says it recorded, in the checkpoint's own words.
const DAEMON_START_CHECKPOINT: &str =
    "The Kin daemon recorded this change when it started on this store";

/// Every change a daemon's start recorded, with its first parent, in id
/// order, read from a freshly opened repository authority with no daemon
/// serving the store.
fn daemon_start_checkpoints(
    repo: &Path,
) -> Vec<(
    kin_model::SemanticChangeId,
    Option<kin_model::SemanticChangeId>,
)> {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let mut checkpoints: Vec<_> = lease
        .snapshot()
        .changes
        .values()
        .filter(|change| change.message.contains(DAEMON_START_CHECKPOINT))
        .map(|change| (change.id, change.parents.first().copied()))
        .collect();
    checkpoints.sort();
    checkpoints
}

/// The change `refs/heads/main` names, read from a freshly opened repository
/// authority with no daemon serving the store.
fn main_head(repo: &Path) -> kin_model::SemanticChangeId {
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let main = kin_model::RefName::branch(b"main").unwrap();
    let reference = lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .find(|reference| reference.name == main)
        .expect("the store has a main branch")
        .target
        .clone();
    lease.resolve_target_change_id(&reference).unwrap()
}

/// Bring an unpacked published store to the shape a store has once another
/// process moved it after its lineage was checked, a pull or a clone the
/// commonest: its record reads current, every head and its workspace hold
/// exactly this build's derivation, and its workspace graph carries no checked
/// binding history. `kin upgrade` re-derives it, then an ordinary commit,
/// which checks nothing, ends the lineage that upgrade started.
fn end_the_lineage_of_an_upgraded_store(repo: &Path) {
    use kin_cli::commands::upgrade::{upgrade_store, UpgradeHooks};
    use kin_model::{
        OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
        RepositoryTransaction, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let author = kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>");
    let upgraded = upgrade_store(&layout, author.clone(), &UpgradeHooks::default(), &|_| {})
        .expect("the published store upgrades");
    assert_eq!(upgraded.binding_history_checked, Some(true));
    let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .unwrap()
        .open_manager_with_payload_stats()
        .unwrap();
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let repository_id = lease.metadata().repository_id.clone();
    drop(lease);
    manager
        .commit_repository_transaction(RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id,
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: author,
            reason: "an ordinary commit that checks no binding history".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: vec![RefMutation {
                name: RefName::branch(b"lineage-probe").unwrap(),
                expected: RefExpectation::MustNotExist,
                new_target: Some(RefTarget::symbolic(RefName::branch(b"main").unwrap())),
                policy: RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: None,
        })
        .expect("an ordinary commit lands");
    drop(manager);
    assert_eq!(
        kin_core::hydration_semantics::standing(&layout).label(),
        "current"
    );
    assert!(
        !workspace_lineage_checked(repo),
        "the ordinary commit was meant to end the lineage"
    );
}

/// A store whose every head and whose workspace already hold exactly this
/// build's derivation, and whose lineage something else ended, is checked by
/// the first daemon an ordinary command starts, before that daemon opens it,
/// and no head moves: the start records no change, so the store is never
/// ahead of a peer for a commit nobody made. The uncommitted edit stays
/// uncommitted work, the record is untouched, a reference answer certifies,
/// and a later start has nothing to do.
///
/// Falsify by leaving the daemon's start out: the lineage stays unproven.
/// Falsify the head rule by letting the start record a lineage-start change:
/// main moves.
#[test]
fn a_daemon_start_checks_a_store_whose_lineage_ended_without_moving_a_head() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("dirty");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let runtime = IsolatedDaemonRuntime::new(&repo);
    end_the_lineage_of_an_upgraded_store(&repo);
    let record = fs::read(layout.kindb_hydration_semantics_path()).unwrap();
    let head_before = main_head(&repo);

    // An ordinary command starts the daemon. Nothing here asks for an upgrade.
    succeed(&runtime, &repo, &["graph", "status"]);
    succeed(&runtime, &repo, &["daemon", "stop"]);

    assert!(
        workspace_lineage_checked(&repo),
        "the daemon's start left the workspace's binding history unproven; its log:\n{}",
        daemon_log_tail(&repo)
    );
    assert_eq!(main_head(&repo), head_before, "the start moved main");
    assert!(daemon_start_checkpoints(&repo).is_empty());
    assert_eq!(
        fs::read(layout.kindb_hydration_semantics_path()).unwrap(),
        record,
        "a re-qualification rewrote the hydration record"
    );
    let status = kin_status(&runtime, &repo);
    assert!(!status.contains("binding history: unchecked"), "{status}");

    // The uncommitted edit is still served as uncommitted work.
    let found: Value =
        serde_json::from_str(&succeed(&runtime, &repo, &["search", "sextuple", "--json"]))
            .expect("search emits JSON");
    assert!(
        found.as_array().expect("search rows").iter().any(|row| {
            row["name"] == "sextuple" && row["file"] == "web/lib.mjs" && row["line"] == 5
        }),
        "the uncommitted declaration must answer at its current line: {found}"
    );
    // The answer the lineage exists for certifies, through a daemon started by
    // the MCP server, which finds the lineage checked and records nothing.
    certified_references(&runtime, &repo, "double");
    succeed(&runtime, &repo, &["daemon", "stop"]);
    assert_eq!(main_head(&repo), head_before);
    assert!(daemon_start_checkpoints(&repo).is_empty());
    assert!(workspace_lineage_checked(&repo));
}

/// A store that reads current and serves state another build derived, as a
/// store an earlier release of the same replay semantics wrote does, is left
/// exactly where it is by a daemon's start: no head moves, nothing is
/// recorded, and the lineage stays unproven. `kin status` says so and names
/// `kin upgrade`, which then re-derives and checks it.
///
/// Falsify by letting the start re-derive differing state: main moves onto a
/// checkpoint.
#[test]
fn a_daemon_start_leaves_state_another_build_derived_to_kin_upgrade() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("dirty");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let runtime = IsolatedDaemonRuntime::new(&repo);
    kin_core::hydration_semantics::stamp_staged(&layout).expect("restamp the fixture store");
    assert!(!workspace_lineage_checked(&repo));
    let head_before = main_head(&repo);

    succeed(&runtime, &repo, &["graph", "status"]);
    succeed(&runtime, &repo, &["daemon", "stop"]);
    assert_eq!(main_head(&repo), head_before, "the start moved main");
    assert!(daemon_start_checkpoints(&repo).is_empty());
    assert!(!workspace_lineage_checked(&repo));
    assert!(
        daemon_log_tail(&repo).contains("moves no head"),
        "the start must say why it left the store; its log:\n{}",
        daemon_log_tail(&repo)
    );

    let status = kin_status(&runtime, &repo);
    assert!(
        status.contains("⚠ binding history: unchecked")
            && status.contains("Remedy: run `kin upgrade`"),
        "kin status must name the remedy for an unchecked store: {status}"
    );

    let report = json(&runtime, &repo, &["upgrade", "--json"]);
    assert_eq!(report["state"], "requalified", "{report}");
    assert_eq!(report["binding_history_checked"], true, "{report}");
    let status = kin_status(&runtime, &repo);
    assert!(!status.contains("binding history: unchecked"), "{status}");
}

/// The daemon-start entry point, called directly: it writes nothing on a store
/// whose semantics are behind, nothing on a store the re-qualification
/// protects, and nothing on a store whose lineage is already checked, and each
/// refusal says why so the daemon's log can name `kin upgrade`.
#[test]
fn a_daemon_start_writes_nothing_where_it_does_not_re_qualify() {
    use kin_cli::commands::upgrade::{
        requalify_at_daemon_start, upgrade_store, DaemonStartRequalification, UpgradeHooks,
        UpgradeState,
    };

    let root = tempdir().expect("temp root");
    unpack(root.path());
    let quiet = |_: &str| {};
    // Every open by this build records the history validation it checked the
    // store under, so each baseline is the store as an ordinary read left it.
    let settled_digest = |repo: &Path| {
        let layout = kin_core::KinLayout::new(repo.join(".kin"));
        drop(
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
                .unwrap()
                .open_manager_with_payload_stats()
                .unwrap(),
        );
        tree_digest(&repo.join(".kin"))
    };

    // Behind: the store keeps the remedy every surface names.
    let repo = root.path().join("clean");
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let before = settled_digest(&repo);
    let behind = requalify_at_daemon_start(&layout, &quiet);
    assert!(
        matches!(&behind, DaemonStartRequalification::NotAttempted(reason) if reason.contains("behind")),
        "{behind:?}"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "a daemon's start changed a store whose semantics are behind",
    );

    // Protected: a store holding a second workspace is one the plan refuses,
    // so the start refuses it from the envelope alone.
    let protected = root.path().join("dirty");
    let protected_layout = kin_core::KinLayout::new(protected.join(".kin"));
    add_a_second_workspace(&protected);
    kin_core::hydration_semantics::stamp_staged(&protected_layout)
        .expect("restamp the fixture store");
    let before = settled_digest(&protected);
    let refused = requalify_at_daemon_start(&protected_layout, &quiet);
    assert!(
        matches!(&refused, DaemonStartRequalification::NotAttempted(reason)
            if reason.contains("2 workspace(s)")),
        "{refused:?}"
    );
    assert_same_store(
        &before,
        &tree_digest(&protected.join(".kin")),
        "a daemon's start changed a store the re-qualification protects",
    );

    // Current, serving state another build derived: the start moves no head,
    // so it writes nothing and names the command that re-derives it.
    kin_core::hydration_semantics::stamp_staged(&layout).expect("restamp the fixture store");
    assert!(!workspace_lineage_checked(&repo));
    let before = settled_digest(&repo);
    let differs = requalify_at_daemon_start(&layout, &quiet);
    assert!(
        matches!(&differs, DaemonStartRequalification::Unfinished(reason)
            if reason.contains("moves no head") && reason.contains("kin upgrade")),
        "{differs:?}"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "a daemon's start changed a store serving state another build derived",
    );

    // Checked: the command re-qualifies the current store, and a start then
    // reads the envelope, finds the lineage and changes nothing.
    let author = kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>");
    let requalified = upgrade_store(&layout, author, &UpgradeHooks::default(), &quiet)
        .expect("the command re-qualifies the store");
    assert_eq!(requalified.state, UpgradeState::Requalified);
    assert_eq!(requalified.binding_history_checked, Some(true));
    let before = tree_digest(&repo.join(".kin"));
    let checked = requalify_at_daemon_start(&layout, &quiet);
    assert!(
        matches!(checked, DaemonStartRequalification::AlreadyChecked),
        "{checked:?}"
    );
    assert_same_store(
        &before,
        &tree_digest(&repo.join(".kin")),
        "a daemon's start changed a store whose lineage is checked",
    );
}

/// A daemon re-qualifies a store only while it holds the repository's runtime
/// authority, which one process holds at a time. While another process holds
/// it, as a daemon part way through a re-qualification or `kin upgrade` does,
/// no second start re-qualifies anything: the store keeps its generation, its
/// unproven lineage and every head. Once it is released, the next start does
/// the work, which shows the hold was the only thing in the way.
#[test]
fn no_daemon_start_re_qualifies_beside_a_held_runtime_authority() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    end_the_lineage_of_an_upgraded_store(&repo);
    let generation = authority_generation(&repo);
    let head = main_head(&repo);

    let held = kin_cli::daemon_client::acquire_repository_runtime_authority(&repo.join(".kin"))
        .expect("acquire the runtime authority")
        .expect("nothing else holds the runtime authority");
    // A daemon started directly, as a spawn would start it, cannot take the
    // authority, so it refuses to start and runs nothing.
    let refused = runtime
        .daemon_command()
        .args(["--port", "0", "--repo"])
        .arg(&repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .current_dir(&repo)
        .output()
        .expect("run the daemon");
    assert!(
        !refused.status.success(),
        "a daemon started beside a held runtime authority: stderr={}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(authority_generation(&repo), generation);
    assert_eq!(main_head(&repo), head);
    assert!(!workspace_lineage_checked(&repo));
    assert!(daemon_start_checkpoints(&repo).is_empty());

    drop(held);
    succeed(&runtime, &repo, &["graph", "status"]);
    succeed(&runtime, &repo, &["daemon", "stop"]);
    assert!(
        workspace_lineage_checked(&repo),
        "the start after the release must re-qualify the store; its log:\n{}",
        daemon_log_tail(&repo)
    );
    assert_eq!(main_head(&repo), head, "the start moved main");
}

/// Started the ordinary way, by a command that needs a daemon, on port 0, a
/// daemon that finds a store to re-qualify says so through the startup
/// progress a waiting client reads, before it publishes an endpoint or opens
/// any state, and finishes the work once nothing holds it back.
///
/// The hold is the repository authority lock, which the test takes before the
/// daemon starts and releases once the client has read the phase. The daemon's
/// check waits on it like any reader would. No clock decides anything.
///
/// Falsify by leaving the startup record out: the client reads only the
/// spawning phase until the daemon has opened.
#[test]
fn an_autostarted_daemon_reports_its_requalification_and_finishes_it() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let kin_root = repo.join(".kin");
    let layout = kin_core::KinLayout::new(kin_root.clone());
    let runtime = IsolatedDaemonRuntime::new(&repo);
    end_the_lineage_of_an_upgraded_store(&repo);
    let head = main_head(&repo);

    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
    let held = binding
        .freeze_existing_read_only(Duration::from_secs(10))
        .expect("hold the repository authority lock");

    let stdout_path = root.path().join("autostart.stdout");
    let stderr_path = root.path().join("autostart.stderr");
    let mut command = runtime
        .kin_command()
        .args(["graph", "status"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "180")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(&repo)
        .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
        .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
        .spawn_owned()
        .expect("spawn kin graph status");

    let deadline = Instant::now() + Duration::from_secs(120);
    let phase = loop {
        let phase = kin_cli::daemon_client::daemon_startup_progress(&kin_root).phase;
        if phase.contains("binding history") {
            break phase;
        }
        assert!(
            Instant::now() < deadline && command.try_wait().expect("poll the command").is_none(),
            "the start never reported its binding-history check: last phase {phase:?}, stderr={}",
            fs::read_to_string(&stderr_path).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        phase.contains("checking this store's binding history"),
        "{phase}"
    );
    assert!(
        !kin_root.join(kin_daemon_spawn::PORT_FILE_NAME).exists(),
        "no endpoint may be published before the check and its commit"
    );
    // Read through the hold itself: a second open would wait on the lock it
    // holds.
    let workspace = held.authority().metadata().workspaces[0].workspace_id;
    assert!(
        held.authority()
            .workspace_graph_snapshot(&workspace)
            .unwrap()
            .expect("the workspace has a committed graph")
            .verified_binding_history
            .is_none(),
        "nothing is committed while held"
    );

    drop(held);
    let deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        if let Some(status) = command.try_wait().expect("poll the command") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the command did not finish once the hold was released"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        status.success(),
        "kin graph status failed: stdout={} stderr={}",
        fs::read_to_string(&stdout_path).unwrap_or_default(),
        fs::read_to_string(&stderr_path).unwrap_or_default()
    );
    assert!(
        kin_cli::daemon_client::read_startup_requalification(&kin_root).is_none(),
        "the startup record ends with the start"
    );
    succeed(&runtime, &repo, &["daemon", "stop"]);
    assert!(
        workspace_lineage_checked(&repo),
        "the start must finish the re-qualification once released; its log:\n{}",
        daemon_log_tail(&repo)
    );
    assert_eq!(main_head(&repo), head, "the start moved main");
    assert!(daemon_start_checkpoints(&repo).is_empty());
}

/// Start a daemon directly on `repo` with its endpoint held unpublished, and
/// wait until the repository lock it holds and its own startup record name it.
/// With `gate`, it is also held before it opens or re-qualifies anything, for
/// as long as that file exists.
#[cfg(unix)]
fn spawn_starting_daemon(
    runtime: &IsolatedDaemonRuntime,
    repo: &Path,
    gate: Option<&Path>,
) -> common::RuntimeOwnedChild {
    let mut command = runtime.daemon_command();
    if let Some(gate) = gate {
        fs::write(gate, b"held").expect("arm the startup gate");
        command.env("KIN_DAEMON_TEST_STARTUP_GATE", gate);
    }
    let mut daemon = command
        .args(["--port", "0", "--repo"])
        .arg(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_TEST_STARTUP_HOLD_SECS", "300")
        .current_dir(repo)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn_owned()
        .expect("spawn a daemon");
    let kin_root = repo.join(".kin");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let kin_cli::daemon_client::StartingDaemonOwner::Starting(owner) =
            kin_cli::daemon_client::starting_daemon_owner(&kin_root)
        {
            if owner.identity().pid() == daemon.id() {
                return daemon;
            }
        }
        assert!(
            daemon.try_wait().expect("poll the daemon").is_none(),
            "the daemon exited before it held the repository; its log:\n{}",
            daemon_log_tail(repo)
        );
        assert!(
            Instant::now() < deadline,
            "the daemon never held the repository"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// `kin daemon stop --json` against a daemon that has published no endpoint,
/// which must name that daemon stopped and leave it gone.
#[cfg(unix)]
fn stop_starting_daemon(
    runtime: &IsolatedDaemonRuntime,
    repo: &Path,
    daemon: &mut common::RuntimeOwnedChild,
) {
    let report = json(runtime, repo, &["daemon", "stop", "--json"]);
    assert_eq!(report["all_stopped"], true, "{report}");
    assert_eq!(
        report["stopped"][0]["pid"].as_u64(),
        Some(u64::from(daemon.id())),
        "{report}"
    );
    assert_eq!(report["stopped"][0]["result"], "stopped", "{report}");
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("poll the daemon").is_none() {
        assert!(
            Instant::now() < deadline,
            "the stopped daemon is still running"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A stop that lands while a starting daemon re-qualifies its store, before
/// it opens state or publishes an endpoint, stops that daemon, and the store
/// then opens as either the authority it had or the one the re-qualification
/// committed, never anything between. The next start finishes the work.
///
/// The first stop lands while a gate this test controls holds the start before
/// the re-qualification begins, so it always lands before any write. The
/// second is not held and lands wherever the re-qualification has reached.
///
/// Falsify by resolving the stop from `daemon.pid` alone: it reports nothing
/// running and the daemon finishes the work the stop claimed to prevent.
#[cfg(unix)]
#[test]
fn a_stop_during_startup_requalification_leaves_the_old_or_the_committed_authority() {
    let root = tempdir().expect("temp root");
    unpack(root.path());
    let repo = root.path().join("clean");
    let kin_root = repo.join(".kin");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    end_the_lineage_of_an_upgraded_store(&repo);
    let generation = authority_generation(&repo);
    let head = main_head(&repo);
    assert!(!workspace_lineage_checked(&repo));

    let gate = root.path().join("gate");
    let mut daemon = spawn_starting_daemon(&runtime, &repo, Some(&gate));
    stop_starting_daemon(&runtime, &repo, &mut daemon);
    fs::remove_file(&gate).expect("disarm the startup gate");
    assert_eq!(authority_generation(&repo), generation);
    assert_eq!(main_head(&repo), head);
    assert!(!workspace_lineage_checked(&repo));

    let mut daemon = spawn_starting_daemon(&runtime, &repo, None);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut reported = false;
    loop {
        match kin_cli::daemon_client::read_startup_requalification(&kin_root) {
            Some(record) if record.requalifying => {
                eprintln!("stopping mid re-qualification at: {}", record.step);
                break;
            }
            Some(_) => reported = true,
            // Past the whole re-qualification before this poll saw it: the stop
            // then lands in the held endpoint window after the commit.
            None if reported => {
                eprintln!("the re-qualification finished before the stop");
                break;
            }
            None => {}
        }
        assert!(
            Instant::now() < deadline,
            "the start never reached its re-qualification"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    stop_starting_daemon(&runtime, &repo, &mut daemon);
    // No head moves either way: the re-qualification records no change.
    assert_eq!(main_head(&repo), head);
    if workspace_lineage_checked(&repo) {
        assert!(authority_generation(&repo) > generation);
    } else {
        assert_eq!(authority_generation(&repo), generation);
        assert_eq!(main_head(&repo), head);
    }

    succeed(&runtime, &repo, &["graph", "status"]);
    succeed(&runtime, &repo, &["daemon", "stop"]);
    assert!(
        workspace_lineage_checked(&repo),
        "the next start must finish the re-qualification; its log:\n{}",
        daemon_log_tail(&repo)
    );
}
