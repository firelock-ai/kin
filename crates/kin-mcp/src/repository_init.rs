// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin_init`: set a folder up as a Kin repository from inside an MCP client.
//!
//! A client installed from the MCP registry starts Kin through `npx` and puts
//! no `kin` on the user's PATH, so the first answer it got, "run `kin init .`",
//! named a command that user did not have. The MCP surface now carries the
//! command itself on the profiles that write, `agent-default` and `full` by
//! name and `agent-routed` as its `init` command, so an agent there can set the
//! repository up when its user asks. Setting a folder up is a write, so the
//! read-only profiles never serve it, and an answer there that finds no
//! repository names the `kin init .` command, spelled for the reader, instead.
//!
//! Only when asked. Initializing writes a `.kin` store into the folder and
//! reads its whole Git history, which on a large repository takes minutes, so
//! Kin never does it for a folder nobody named: not when a client opens a
//! workspace, and not when a graph call finds no repository. The tool is
//! annotated as a write, so a client that asks before a write asks here too.
//! `KIN_MCP_AUTO_INIT=1` on the npm wrapper stays the explicit opt-in for doing
//! it at launch.
//!
//! The work is done by the [`RepoInitializer`] the launcher hands the server:
//! it checks the folder and runs `kin init <dir> --json --no-enrich`, so this
//! crate touches no filesystem and starts no process of its own. Cross-file
//! enrichment is left to the daemon that serves the repository next, which
//! resumes it, so the call returns as soon as the graph exists. A call waits
//! [`INIT_WAIT`] for it, under the 60 s per-call timeout common clients use,
//! and a longer initialization keeps running behind the server and is reported
//! on the next call.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::first_contact::{kin_command, Spelling};
use crate::types::{ToolAnnotations, ToolCallResult, ToolDefinition};

/// The tool's registered name.
pub const TOOL_NAME: &str = "kin_init";

/// How long one call waits for an initialization before answering that it is
/// still running.
pub const INIT_WAIT: Duration = Duration::from_secs(40);

/// The registered description.
pub const DESCRIPTION: &str = "Set a folder up as a Kin repository, so Kin can answer about it. \
Call it when a Kin answer says the folder is not a Kin repository and the user wants Kin to \
serve it. With no path it sets up the client's workspace folder, or this server's working \
directory when the client names none. It runs `kin init` there: that writes a .kin store into \
the folder and reads the folder's Git history into a graph, so the folder must be a Git \
repository or empty. In a Git repository it also appends `/.kin/` to `.git/info/exclude`, Git's \
local ignore file that is never committed, unless a rule there already covers the store. It \
returns when the graph exists, or after about 40 seconds with the \
initialization still running; call it again to check on it. Cross-file enrichment continues in \
the background. A folder that already is a Kin repository is answered as one, and nothing is \
rewritten.";

/// The registered definition.
pub fn tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: TOOL_NAME.into(),
        description: DESCRIPTION.into(),
        annotations: ToolAnnotations {
            title: "Set up Kin".into(),
            read_only_hint: false,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The folder to set up, absolute or relative to the client's workspace folder. Defaults to that folder."
                }
            },
            "additionalProperties": false
        }),
    }
}

/// What the launcher hands the server to set up one folder.
pub type RepoInitializer =
    Arc<dyn Fn(PathBuf) -> Pin<Box<dyn Future<Output = InitOutcome> + Send>> + Send + Sync>;

/// What setting up one folder came to.
#[derive(Debug, Clone, PartialEq)]
pub enum InitOutcome {
    /// `kin init` built the graph; its `--json` report when it printed one.
    Initialized { report: Option<Value> },
    /// The folder already was a Kin repository, and nothing was run.
    AlreadyRepository,
    /// The folder must not be set up, and why, before anything ran.
    Refused(String),
    /// `kin init` ran and failed, in its own words.
    Failed(String),
}

impl InitOutcome {
    /// Whether the folder is a Kin repository now.
    pub fn is_repository(&self) -> bool {
        matches!(self, Self::Initialized { .. } | Self::AlreadyRepository)
    }
}

/// The folder a call names: `path` when given, resolved against the client's
/// folder when relative, and otherwise the client's folder itself.
pub fn target_dir(
    arguments: &std::collections::HashMap<String, Value>,
    client_root: Option<&Path>,
) -> Result<PathBuf, String> {
    let requested = match arguments.get("path") {
        None | Some(Value::Null) => None,
        Some(Value::String(path)) if !path.trim().is_empty() => Some(PathBuf::from(path.trim())),
        Some(_) => return Err("kin_init's path must be a folder's path, as a string.".into()),
    };
    match (requested, client_root) {
        (Some(path), _) if path.is_absolute() => Ok(path),
        (Some(path), Some(base)) => Ok(base.join(path)),
        (Some(_), None) => Err(
            "kin_init needs an absolute path here: this client named no workspace folder to \
             resolve a relative one against."
                .into(),
        ),
        (None, Some(base)) => Ok(base.to_path_buf()),
        (None, None) => Err(
            "kin_init needs a path: this client named no workspace folder, and this server has \
             no working directory to fall back to."
                .into(),
        ),
    }
}

/// An initialization running behind the server.
struct InFlight {
    dir: PathBuf,
    started: Instant,
    handle: tokio::task::JoinHandle<InitOutcome>,
}

/// Where an initialization this server started stands.
#[derive(Default)]
pub struct InitTracker {
    in_flight: Option<InFlight>,
}

/// What asking for an initialization came to.
#[derive(Debug)]
pub enum InitProgress {
    /// It finished inside the wait.
    Finished(InitOutcome),
    /// It is still running.
    Running { elapsed: Duration },
    /// Another folder's initialization is running, and one runs at a time.
    Busy { dir: PathBuf, elapsed: Duration },
}

impl InitTracker {
    /// The folder an initialization is running for, and for how long.
    pub fn running(&self) -> Option<(&Path, Duration)> {
        self.in_flight
            .as_ref()
            .map(|in_flight| (in_flight.dir.as_path(), in_flight.started.elapsed()))
    }

    /// Start setting up `dir`, or join the run already underway for it, and
    /// wait up to `wait` for it to finish.
    pub async fn start_or_join(
        &mut self,
        dir: PathBuf,
        initializer: &RepoInitializer,
        wait: Duration,
    ) -> InitProgress {
        if let Some(in_flight) = &self.in_flight {
            if in_flight.dir != dir {
                return InitProgress::Busy {
                    dir: in_flight.dir.clone(),
                    elapsed: in_flight.started.elapsed(),
                };
            }
        } else {
            self.in_flight = Some(InFlight {
                dir: dir.clone(),
                started: Instant::now(),
                handle: tokio::spawn(initializer(dir)),
            });
        }
        let in_flight = self
            .in_flight
            .as_mut()
            .expect("an initialization was just set");
        match tokio::time::timeout(wait, &mut in_flight.handle).await {
            Ok(joined) => {
                self.in_flight = None;
                InitProgress::Finished(joined.unwrap_or_else(|error| {
                    InitOutcome::Failed(format!("the initialization task stopped: {error}"))
                }))
            }
            Err(_) => InitProgress::Running {
                elapsed: in_flight.started.elapsed(),
            },
        }
    }

    /// Take the outcome of an initialization that finished behind the server
    /// since the last call, with the folder it was for.
    pub async fn take_finished(&mut self) -> Option<(PathBuf, InitOutcome)> {
        if !self
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight.handle.is_finished())
        {
            return None;
        }
        let in_flight = self.in_flight.take()?;
        let outcome = in_flight.handle.await.unwrap_or_else(|error| {
            InitOutcome::Failed(format!("the initialization task stopped: {error}"))
        });
        Some((in_flight.dir, outcome))
    }
}

/// The first question an answer suggests once a folder is a repository: the
/// one `kin init` and `kin setup` end on in a terminal, `kin refs` on a function
/// the reader knows, asked through the tool that answers it here. A routed
/// connection reads the tool as its `refs` command.
pub const FIRST_QUESTION: &str = "Ask what calls a function you know with find_references, \
and check the answer in the source.";

/// The answer to a finished initialization.
///
/// What happened rides `message`; what to do next rides `next_step`, the key a
/// routed connection presents in its own command names.
pub fn finished_answer(dir: &Path, outcome: &InitOutcome, spelling: Spelling) -> ToolCallResult {
    match outcome {
        InitOutcome::Initialized { report } => ToolCallResult::text(pretty(&json!({
            "folder": dir.display().to_string(),
            "state": "initialized",
            "message": format!("{} is a Kin repository now.", dir.display()),
            "next_step": FIRST_QUESTION,
            "note": "The next graph call is answered from it, and cross-file enrichment \
                     continues in the background.",
            "report": report,
        }))),
        InitOutcome::AlreadyRepository => ToolCallResult::text(pretty(&json!({
            "folder": dir.display().to_string(),
            "state": "already_a_repository",
            "message": format!(
                "{} already is a Kin repository, so nothing was changed.",
                dir.display()
            ),
            "next_step": FIRST_QUESTION,
        }))),
        InitOutcome::Refused(reason) => ToolCallResult::error(pretty(&json!({
            "folder": dir.display().to_string(),
            "state": "refused",
            "message": reason,
        }))),
        InitOutcome::Failed(output) => ToolCallResult::error(pretty(&json!({
            "folder": dir.display().to_string(),
            "state": "failed",
            "message": format!(
                "Kin could not set up {}. kin init said: {} Fix that and call kin_init again, or \
                 run {} in that folder to see the whole report.",
                dir.display(),
                output.trim(),
                kin_command("init .", spelling)
            ),
        }))),
    }
}

/// The answer while an initialization is still running.
pub fn running_answer(dir: &Path, elapsed: Duration) -> ToolCallResult {
    ToolCallResult::text(pretty(&json!({
        "folder": dir.display().to_string(),
        "state": "running",
        "message": format!(
            "Kin is still setting up {} after {} s. A large repository takes minutes.",
            dir.display(),
            elapsed.as_secs()
        ),
        "next_step": "Call kin_init again to check on it; graph calls answer once it finishes.",
    })))
}

/// The answer while another folder's initialization runs.
pub fn busy_answer(requested: &Path, running: &Path, elapsed: Duration) -> ToolCallResult {
    ToolCallResult::error(format!(
        "Kin is still setting up {} ({} s so far), and it sets up one folder at a time. Call \
         kin_init for {} again once that finishes.",
        running.display(),
        elapsed.as_secs(),
        requested.display()
    ))
}

/// The answer a graph call gets while an initialization this server started
/// is still running.
pub fn graph_call_while_initializing(tool: &str, dir: &Path, elapsed: Duration) -> ToolCallResult {
    ToolCallResult::error(format!(
        "kin-mcp cannot answer '{tool}' yet: Kin is still setting up {} ({} s so far), and there \
         is no graph to answer from until it finishes. Retry in a little while, or call kin_init \
         to check on it.",
        dir.display(),
        elapsed.as_secs()
    ))
}

/// The answer on a runtime that cannot set a folder up.
///
/// The command it hands over is spelled by [`kin_command`], so a reader whose
/// client started Kin through `npx`, with no `kin` on the PATH, gets the `npx`
/// form of this release rather than a `kin init` they cannot run.
pub fn unavailable_answer(spelling: Spelling) -> ToolCallResult {
    ToolCallResult::error(format!(
        "kin_init is answered by the Kin MCP server a client launches, which knows the client's \
         folder. This server was not given a way to set one up, so run {} in that folder \
         instead.",
        kin_command("init .", spelling)
    ))
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn args(path: Option<&str>) -> HashMap<String, Value> {
        path.map(|path| ("path".to_string(), json!(path)))
            .into_iter()
            .collect()
    }

    #[test]
    fn the_target_is_the_named_folder_or_the_client_folder() {
        let base = Path::new("/work/repo");
        assert_eq!(target_dir(&args(None), Some(base)).unwrap(), base);
        assert_eq!(
            target_dir(&args(Some("app")), Some(base)).unwrap(),
            base.join("app")
        );
        assert_eq!(
            target_dir(&args(Some("/elsewhere/app")), None).unwrap(),
            Path::new("/elsewhere/app")
        );
        assert!(target_dir(&args(Some("app")), None).is_err());
        assert!(target_dir(&args(None), None).is_err());
        let bad: HashMap<String, Value> = [("path".to_string(), json!(7))].into_iter().collect();
        assert!(target_dir(&bad, Some(base)).is_err());
    }

    #[tokio::test]
    async fn a_quick_initialization_finishes_inside_the_wait() {
        let initializer: RepoInitializer = Arc::new(|_dir| {
            Box::pin(async {
                InitOutcome::Initialized {
                    report: Some(json!({"ok": true})),
                }
            })
        });
        let mut tracker = InitTracker::default();
        match tracker
            .start_or_join(
                PathBuf::from("/work/a"),
                &initializer,
                Duration::from_secs(5),
            )
            .await
        {
            InitProgress::Finished(outcome) => assert!(outcome.is_repository()),
            other => panic!("{other:?}"),
        }
        assert!(tracker.running().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_initialization_keeps_running_and_is_reported_later() {
        let initializer: RepoInitializer = Arc::new(|_dir| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(120)).await;
                InitOutcome::Initialized { report: None }
            })
        });
        let mut tracker = InitTracker::default();
        let dir = PathBuf::from("/work/slow");
        assert!(matches!(
            tracker
                .start_or_join(dir.clone(), &initializer, Duration::from_secs(40))
                .await,
            InitProgress::Running { .. }
        ));
        assert_eq!(
            tracker.running().map(|(dir, _)| dir.to_path_buf()),
            Some(dir.clone())
        );
        // Another folder waits its turn.
        assert!(matches!(
            tracker
                .start_or_join(
                    PathBuf::from("/work/other"),
                    &initializer,
                    Duration::from_secs(1)
                )
                .await,
            InitProgress::Busy { .. }
        ));
        assert!(tracker.take_finished().await.is_none());
        tokio::time::sleep(Duration::from_secs(100)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let (finished, outcome) = tracker.take_finished().await.expect("it finished");
        assert_eq!(finished, dir);
        assert!(outcome.is_repository());
        assert!(tracker.running().is_none());
    }

    #[test]
    fn every_answer_names_a_next_step_that_works() {
        let dir = Path::new("/work/app");
        let failed = finished_answer(
            dir,
            &InitOutcome::Failed(
                "non-Git repository admission currently requires an empty directory".into(),
            ),
            Spelling::Npx,
        );
        assert_eq!(failed.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = &failed.content[0];
        assert!(text.contains("requires an empty directory"), "{text}");
        assert!(text.contains("npx -y @kinlab/kin@"), "{text}");
        let crate::types::ContentBlock::Text { text } =
            &running_answer(dir, Duration::from_secs(41)).content[0];
        let running: Value = serde_json::from_str(text).unwrap();
        assert!(
            running["message"].as_str().unwrap().contains("after 41 s"),
            "{text}"
        );
        assert!(
            running["next_step"]
                .as_str()
                .unwrap()
                .contains("Call kin_init again"),
            "{text}"
        );
        let crate::types::ContentBlock::Text { text } =
            &graph_call_while_initializing("semantic_locate", dir, Duration::from_secs(3)).content
                [0];
        assert!(text.contains("still setting up /work/app"), "{text}");
        assert!(!DESCRIPTION.contains('\u{2014}'));
    }

    /// A runtime that cannot set a folder up hands over a command the reader
    /// can run: the `npx` form where Kin came from the registry, since that
    /// reader has no `kin` on the PATH.
    #[test]
    fn the_unavailable_answer_names_a_command_the_reader_has() {
        let unavailable = unavailable_answer(Spelling::Npx);
        assert_eq!(unavailable.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = &unavailable.content[0];
        assert!(
            text.contains(&format!(
                "`npx -y @kinlab/kin@{} init .`",
                env!("CARGO_PKG_VERSION")
            )),
            "{text}"
        );
        assert!(!text.contains("`kin init"), "{text}");
        let crate::types::ContentBlock::Text { text } =
            &unavailable_answer(Spelling::Kin).content[0];
        assert!(text.contains("`kin init .`"), "{text}");
        assert!(!text.contains('\u{2014}'), "{text}");
    }
}
