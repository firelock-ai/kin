// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin describe` and `kin call`: the routed MCP tool's words, run in a shell.
//!
//! The routed profiles serve one MCP tool, `kin`, and their instructions teach
//! its commands as `kin locate`, `kin source`, `kin describe` and `kin call`.
//! An agent that also has a shell types those words there. The CLI already had
//! `kin locate` and the other query commands, `kin source` is `kin graph
//! source`, and these two answer from the routed tool itself, so a shell and an
//! MCP client read one vocabulary out of one table.
//!
//! `kin describe` prints what the routed tool's `describe` answers, read from
//! [`kin_mcp::routed`] rather than from a copy of it. `kin call` sends the
//! routed tool's `call` through the server path `kin mcp start` answers it on,
//! [`kin_mcp::process_daemon_message`], against this repository's daemon: the
//! same name resolution, field checks, belt defaults, response budget, hints
//! and `_kin` envelope.
//!
//! Both answer as `agent-routed` does, writes included. A read-only MCP
//! profile limits what its one tool reaches; it does not make the machine
//! read-only, and a shell already writes through `kin commit` and the rest.
//! So a shell's `kin call` sends a write that `agent-routed-query` refuses
//! before anything runs, and `kin describe` lists that tool as a write.
//!
//! A few names mean something a shell runs another way, and `kin call`
//! refuses those by name, before anything is sent, with the spelling that
//! works: `kin_init` is `kin init`, the tool dispatchers are `kin describe` and
//! `kin call` themselves, a routed command's name is its CLI spelling or `kin
//! call` with the tool it runs, and a name nothing takes is sent nowhere.

use std::io::Read;

use anyhow::{Context, Result};
use kin_mcp::routed::{RoutedSurface, Routing};
use kin_mcp::{ContentBlock, ToolCallParams, ToolCallResult};
use serde_json::{json, Map, Value};

use crate::commands::mcp::McpToolProfile;

/// The profile a shell's `kin describe` and `kin call` answer as.
pub(crate) const SHELL_PROFILE: McpToolProfile = McpToolProfile::AgentRouted;

/// The routed surface [`SHELL_PROFILE`] serves.
pub(crate) fn shell_surface() -> RoutedSurface {
    SHELL_PROFILE
        .routed_surface()
        .expect("agent-routed serves a routed surface")
}

/// One answer from the routed tool: its text, and whether it is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub text: String,
    pub is_error: bool,
}

impl Answer {
    fn of(result: &ToolCallResult) -> Self {
        let text = result
            .content
            .iter()
            .map(|ContentBlock::Text { text }| text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        Self {
            text,
            is_error: result.is_error == Some(true),
        }
    }
}

/// `kin describe [command]`: what the routed tool's `describe` answers for
/// `command`, or with no command, every command and every other tool `kin
/// call` reaches.
///
/// Read from the routed tool on the surface a shell is served, so a command's
/// arguments, its example and the list of tools are the ones an MCP client
/// reads. A name nothing takes is refused the way the routed tool refuses it.
pub fn describe(command: Option<&str>) -> Answer {
    let args = match command {
        Some(command) => json!({ "command": command }),
        None => json!({}),
    };
    let mut params = routed_call(json!({"command": "describe", "args": args}));
    match kin_mcp::routed::route(&mut params, Some(shell_surface())) {
        Routing::Answer(result) => Answer::of(&result),
        // `describe` is answered by the routed tool itself and reads no graph,
        // so neither of these is reachable; saying so beats printing nothing.
        Routing::Dispatch | Routing::NotRouted => Answer {
            text: "describe was not answered by the routed kin tool".to_string(),
            is_error: true,
        },
    }
}

/// The routed tool called with `arguments`.
fn routed_call(arguments: Value) -> ToolCallParams {
    ToolCallParams {
        name: kin_mcp::routed::TOOL_NAME.to_string(),
        arguments: match arguments {
            Value::Object(fields) => fields.into_iter().collect(),
            _ => Default::default(),
        },
    }
}

/// Why `kin call` sends nothing for `name`, in a sentence that names what
/// runs instead in a shell, or `None` when the routed `call` takes it.
///
/// Names are read the way the routed tool reads them, so `kin-init` is
/// `kin_init` and `graph source` is the `source` command.
pub fn refusal_for(name: &str) -> Option<String> {
    let spelled = name.trim();
    if let Some(command) = kin_mcp::routed::command_named_by(spelled) {
        return Some(command_refusal(spelled, command));
    }
    let Some(tool) = kin_mcp::routed::tool_named_by(spelled) else {
        return Some(format!(
            "There is no Kin tool named '{spelled}'. `kin describe` lists every tool `kin call` \
             runs."
        ));
    };
    if tool == kin_mcp::repository_init::TOOL_NAME {
        return Some(format!(
            "{tool} sets up the folder an MCP client works in. In a shell, run `kin init` in that \
             folder, or `kin init <path>`."
        ));
    }
    if kin_mcp::routed::is_dispatcher(&tool) {
        return Some(format!(
            "{tool} finds and runs tools for an MCP client that lists only some of them. In a \
             shell, `kin describe` lists every tool and `kin call` runs any of them by name."
        ));
    }
    None
}

/// The refusal for a routed command's name: `kin call` runs tools, so it
/// names the command's CLI spelling and `kin call` with each tool it runs
/// that a shell's `kin call` runs too, which leaves `init` to `kin init`.
fn command_refusal(spelled: &str, command: &str) -> String {
    let row = kin_mcp::routed::command_table()
        .into_iter()
        .find(|row| row.command == command);
    let (cli, tools) = row.map(|row| (row.cli, row.tools)).unwrap_or_default();
    let lead = format!(
        "{spelled} is the kin tool's {command} command rather than a tool, and `kin call` runs a \
         tool by its registered name."
    );
    let calls: Vec<String> = tools
        .iter()
        .filter(|tool| refusal_for(tool).is_none())
        .map(|tool| format!("`kin call {tool}`"))
        .collect();
    if calls.is_empty() {
        return format!("{lead} In a shell it is `{cli}`.");
    }
    let calls = match calls.as_slice() {
        [only] => only.clone(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
        [] => String::new(),
    };
    let run = if cli.is_empty() {
        calls
    } else {
        format!("`{cli}`, or {calls}")
    };
    format!(
        "{lead} In a shell, run {run} with the same arguments; `kin describe {command}` gives \
         them."
    )
}

/// `kin call`'s arguments: one JSON object, read from stdin when given as
/// `-`, and the empty object when not given at all.
pub fn call_arguments(raw: Option<&str>, stdin: &mut dyn Read) -> Result<Map<String, Value>> {
    let text = match raw {
        None => return Ok(Map::new()),
        Some("-") => {
            let mut text = String::new();
            stdin
                .read_to_string(&mut text)
                .context("kin call could not read the tool's arguments from stdin")?;
            text
        }
        Some(text) => text.to_string(),
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(arguments)) => Ok(arguments),
        _ => anyhow::bail!(
            "kin call takes the tool's arguments as one JSON object, such as \
             '{{\"entity_id\":\"<entity id from kin locate>\"}}', or `-` to read that object \
             from stdin; `kin describe <tool>` gives the tool's fields"
        ),
    }
}

/// The `tools/call` request `kin call` sends: the routed tool's `call`, with
/// the tool and its arguments exactly as given.
pub fn call_request(tool: &str, arguments: Map<String, Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": kin_mcp::routed::TOOL_NAME,
            "arguments": {
                "command": "call",
                "args": {"tool": tool, "arguments": arguments},
            },
        },
    })
}

/// The server config a shell's call is answered under: the one `kin mcp
/// start` serves [`SHELL_PROFILE`] with, for a client working in this folder.
pub(crate) fn shell_config() -> kin_mcp::McpServerConfig {
    let mut config = crate::commands::mcp::served_config(SHELL_PROFILE);
    config.canonicalize = crate::commands::mcp::canonical_path;
    config.client_root = std::env::current_dir()
        .ok()
        .map(|dir| crate::commands::mcp::canonical_path(&dir));
    config
}

/// Answer one request through the server path `kin mcp start` answers it on.
pub(crate) async fn send(request: &Value, config: &kin_mcp::McpServerConfig) -> Result<Answer> {
    let response = kin_mcp::process_daemon_message(&request.to_string(), config)
        .await
        .context("the routed kin tool gave no answer")?;
    if let Some(error) = response.error {
        anyhow::bail!("the routed kin tool refused the call: {}", error.message);
    }
    let result: ToolCallResult = serde_json::from_value(response.result.unwrap_or_default())
        .context("the routed kin tool's answer is not a tool result")?;
    Ok(Answer::of(&result))
}

/// `kin call <tool> [arguments]`: run a registered tool through the routed
/// tool's `call`, against this repository's daemon.
///
/// A call the routed tool answers without the graph, one refused on its
/// fields, is answered here without resolving or starting a daemon, as `kin
/// mcp start` answers it. Every other call reaches the daemon the way `kin
/// graph source` does: `KIN_DAEMON_URL` when it is set, and otherwise the
/// daemon serving this repository, started when none is.
pub async fn call(tool: &str, arguments: Option<&str>) -> Result<Answer> {
    if let Some(refusal) = refusal_for(tool) {
        anyhow::bail!(refusal);
    }
    let arguments = call_arguments(arguments, &mut std::io::stdin().lock())?;
    let request = call_request(tool, arguments);
    let config = shell_config();
    if !kin_mcp::routed::answers_locally(&request, config.routed) {
        let layout = crate::commands::require_repository_layout()?;
        let url = crate::daemon_client::resolve_daemon_url(&layout)
            .await?
            .ok_or_else(|| crate::daemon_client::daemon_required_error("kin call", &layout))?;
        // The server path forwards to the daemon this names, as it does for
        // `kin mcp start`, and a daemon it revives joins supervisor routing.
        std::env::set_var("KIN_DAEMON_URL", &url);
        crate::daemon_client::install_spawn_registrar();
    }
    kin_mcp::first_contact::set_spelling(crate::commands::mcp::command_spelling());
    kin_mcp::session_exec::install_executor(crate::commands::agent_exec::executor());
    send(&request, &config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::test_env::EnvVarGuard;
    use kin_mcp::routed::{route, Routing};
    use kin_mcp::{ContentBlock, ToolCallParams, ToolCallResult};
    use serde_json::json;
    use serial_test::serial;
    use std::sync::{Arc, Mutex};

    /// What the routed tool itself answers to `describe` on `surface`.
    fn routed_describe(surface: RoutedSurface, command: Option<&str>) -> (String, bool) {
        let args = match command {
            Some(command) => json!({ "command": command }),
            None => json!({}),
        };
        let mut params: ToolCallParams = serde_json::from_value(json!({
            "name": kin_mcp::routed::TOOL_NAME,
            "arguments": {"command": "describe", "args": args},
        }))
        .expect("a tools/call params object");
        let Routing::Answer(result) = route(&mut params, Some(surface)) else {
            panic!("describe is answered by the routed tool");
        };
        let ContentBlock::Text { text } = &result.content[0];
        (text.clone(), result.is_error == Some(true))
    }

    /// `kin describe` prints exactly what the routed tool's `describe`
    /// answers on the surface a shell is served, from the one table both
    /// read, including the refusal for a name nothing takes.
    #[test]
    fn kin_describe_prints_what_the_routed_describe_answers() {
        for command in [
            None,
            Some("locate"),
            Some("source"),
            Some("mutate"),
            Some("call"),
            Some("graph_neighborhood"),
            Some("kin graph source"),
            Some("nope"),
        ] {
            let answer = describe(command);
            let (text, is_error) = routed_describe(RoutedSurface::WITH_WRITES, command);
            assert_eq!(answer.text, text, "{command:?}");
            assert_eq!(answer.is_error, is_error, "{command:?}");
        }
        assert!(describe(Some("nope")).is_error);
        // The words the routed instructions teach name the CLI's commands.
        let catalogue: Value = serde_json::from_str(&describe(None).text).expect("a catalogue");
        let cli_of = |command: &str| {
            catalogue["commands"]
                .as_array()
                .expect("commands")
                .iter()
                .find(|row| row["command"] == command)
                .map(|row| row["cli"].clone())
        };
        assert_eq!(cli_of("source"), Some(json!("kin source")));
        assert_eq!(cli_of("describe"), Some(json!("kin describe")));
        assert_eq!(cli_of("call"), Some(json!("kin call")));
    }

    /// What a shell does with a write, pinned. A read-only MCP profile limits
    /// what its one tool reaches; it does not make the machine read-only, and
    /// a shell already writes through `kin commit` and the rest. So `kin
    /// describe` and `kin call` answer as `agent-routed` does, writes
    /// included, and a write `agent-routed-query` refuses before anything
    /// runs is sent from a shell.
    #[test]
    fn a_shell_answers_as_agent_routed_writes_included() {
        assert_eq!(SHELL_PROFILE.token(), "agent-routed");
        assert_eq!(shell_surface(), RoutedSurface::WITH_WRITES);
        assert_eq!(SHELL_PROFILE.routed_surface(), Some(shell_surface()));
        let config = shell_config();
        assert_eq!(config.routed, Some(shell_surface()));
        assert!(config.agent_belt);

        let commit = call_request(
            "kin_transaction_commit",
            Map::from_iter([("transaction_id".to_string(), json!("t1"))]),
        );
        assert!(
            !kin_mcp::routed::answers_locally(&commit, Some(shell_surface())),
            "a shell sends the write: {commit}"
        );
        assert!(
            kin_mcp::routed::answers_locally(&commit, Some(RoutedSurface::READ_ONLY)),
            "agent-routed-query refuses the same call before anything runs"
        );

        let catalogue: Value = serde_json::from_str(&describe(None).text).expect("a catalogue");
        assert!(catalogue["other_tools"]
            .as_array()
            .expect("other_tools")
            .iter()
            .any(|row| row["tool"] == "kin_transaction_commit" && row["writes"] == true));
        for command in ["session", "mutate", "init"] {
            assert!(
                catalogue["commands"]
                    .as_array()
                    .expect("commands")
                    .iter()
                    .any(|row| row["command"] == command),
                "{command}: {catalogue}"
            );
        }
    }

    /// Names a shell runs another way are refused by name, before anything is
    /// sent, with the spelling that works in a shell. Every other name the
    /// routed `call` takes is sent as it is.
    #[test]
    fn kin_call_refuses_by_name_what_a_shell_runs_another_way() {
        for (name, says) in [
            ("kin_init", vec!["`kin init`"]),
            ("kin-init", vec!["`kin init`"]),
            ("kin_tool_search", vec!["`kin describe`", "`kin call`"]),
            ("kin_tool_call", vec!["`kin describe`", "`kin call`"]),
            (
                "locate",
                vec![
                    "`kin locate`",
                    "`kin call semantic_locate`",
                    "`kin describe locate`",
                ],
            ),
            (
                "search",
                vec!["`kin call semantic_search`", "`kin call lexical_lookup`"],
            ),
            (
                "session",
                vec!["`kin call kin_session_start`", "`kin describe session`"],
            ),
            (
                "graph source",
                vec!["`kin source`", "`kin call get_entity_source`"],
            ),
            ("describe", vec!["`kin describe`"]),
            ("init", vec!["`kin init`"]),
            ("nope", vec!["no Kin tool", "`kin describe`"]),
        ] {
            let refusal = refusal_for(name).unwrap_or_else(|| panic!("{name} was sent"));
            for phrase in says {
                assert!(refusal.contains(phrase), "{name}: {refusal}");
            }
            assert!(!refusal.contains('\u{2014}'), "{refusal}");
            // A refusal never offers a call a shell refuses in turn.
            for offered in refusal.split("`kin call ").skip(1) {
                let tool = offered.split('`').next().unwrap_or_default();
                assert_eq!(refusal_for(tool), None, "{name} offers {tool}: {refusal}");
            }
        }
        for name in [
            "graph_neighborhood",
            "graph-neighborhood",
            "get_entity_source",
            "trace-data-flow",
            "kin_mutate",
            "kin_session_start",
            "kin_transaction_commit",
        ] {
            assert_eq!(refusal_for(name), None, "{name}");
        }
    }

    /// The arguments are one JSON object, read from stdin for `-`, and none
    /// at all is the empty object. Anything else is refused with the shape
    /// that works.
    #[test]
    fn kin_call_takes_one_json_object_of_arguments() {
        let mut nothing = std::io::empty();
        assert_eq!(call_arguments(None, &mut nothing).unwrap(), Map::new());
        assert_eq!(
            call_arguments(Some(r#"{"entity_id":"e1","depth":2}"#), &mut nothing).unwrap(),
            Map::from_iter([
                ("entity_id".to_string(), json!("e1")),
                ("depth".to_string(), json!(2)),
            ])
        );
        let mut piped = std::io::Cursor::new(r#"{"session_id":"s1"}"#);
        assert_eq!(
            call_arguments(Some("-"), &mut piped).unwrap(),
            Map::from_iter([("session_id".to_string(), json!("s1"))])
        );
        for bad in ["[1]", "\"e1\"", "{", "7", "entity_id=e1"] {
            let refusal = call_arguments(Some(bad), &mut nothing)
                .expect_err(bad)
                .to_string();
            assert!(refusal.contains("one JSON object"), "{bad}: {refusal}");
            assert!(refusal.contains("`kin describe"), "{bad}: {refusal}");
        }
    }

    /// A stand-in daemon that answers `/mcp/tools/call` with `answer` and
    /// records each call it was sent. Every other route is a 404, which the
    /// server path reads as a daemon with nothing to add.
    async fn stand_in_daemon(answer: ToolCallResult) -> (String, Arc<Mutex<Vec<Value>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&calls);
        let app = axum::Router::new().route(
            "/mcp/tools/call",
            axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
                let recorded = Arc::clone(&recorded);
                let answer = answer.clone();
                async move {
                    recorded.lock().unwrap().push(body);
                    axum::Json(answer)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (url, calls)
    }

    /// `kin call` sends the routed `call` through the server path `kin mcp
    /// start` answers it on: the daemon is asked for exactly the named tool
    /// with the arguments given, and the answer is the routed answer, the
    /// tool's payload with its `_kin` envelope and its hints naming what runs
    /// in a shell. An error answer stays an error.
    #[tokio::test]
    #[serial]
    async fn kin_call_runs_the_named_tool_through_the_routed_call() {
        let _no_spawn = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let _session = EnvVarGuard::unset("KIN_SESSION_ID");
        let payload = json!({"entities": [], "note": "read one body with get_entity_source"});
        let (url, calls) = stand_in_daemon(ToolCallResult::text(payload.to_string())).await;
        let _daemon = EnvVarGuard::set("KIN_DAEMON_URL", &url);
        let config = shell_config();

        let request = call_request(
            "graph_neighborhood",
            Map::from_iter([
                ("entity_id".to_string(), json!("e1")),
                ("depth".to_string(), json!(2)),
            ]),
        );
        let answer = send(&request, &config).await.expect("an answer");
        let sent = calls.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0]["name"], "graph_neighborhood");
        assert_eq!(sent[0]["arguments"]["entity_id"], "e1");
        assert_eq!(sent[0]["arguments"]["depth"], 2);
        assert!(!answer.is_error, "{}", answer.text);
        let answered: Value = serde_json::from_str(&answer.text).expect("a JSON answer");
        assert_eq!(answered["note"], "read one body with kin source");
        assert!(answered.get(kin_mcp::ENVELOPE_KEY).is_some(), "{answered}");

        let (url, _) =
            stand_in_daemon(ToolCallResult::error("no entity exists with this ID")).await;
        let _daemon = EnvVarGuard::set("KIN_DAEMON_URL", &url);
        let answer = send(&request, &config).await.expect("an answer");
        assert!(answer.is_error, "{}", answer.text);
        assert!(
            answer.text.contains("no entity exists with this ID"),
            "{}",
            answer.text
        );
    }

    /// A call the routed tool refuses on its fields is answered without a
    /// daemon, the way `kin mcp start` answers it, and names the fields.
    #[tokio::test]
    #[serial]
    async fn a_call_refused_on_its_fields_needs_no_daemon() {
        let _daemon = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:9");
        let _no_spawn = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let request = call_request("graph_neighborhood", Map::new());
        assert!(kin_mcp::routed::answers_locally(
            &request,
            Some(shell_surface())
        ));
        let answer = send(&request, &shell_config()).await.expect("an answer");
        assert!(answer.is_error, "{}", answer.text);
        assert!(answer.text.contains("missing entity_id"), "{}", answer.text);
    }
}
