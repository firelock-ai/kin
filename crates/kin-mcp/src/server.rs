// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use kin_model::graph::GraphStore;
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use crate::budget::ResponseBudget;
use crate::daemon_delegate;
use crate::envelope::{self, Envelope};
use crate::error::{McpError, Result};
use crate::handlers::{handle_tool_call, RequestRepositoryAuthority};
use crate::session::SessionRegistry;
use crate::startup_binding::{StartupBindingState, StartupDaemonBinding};
use crate::types::*;

/// MCP server configuration.
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    pub server_name: String,
    pub server_version: String,
    pub allowed_tools: Option<HashSet<String>>,
    pub session_authority_mode: SessionAuthorityMode,
    pub snapshot_path: Option<PathBuf>,
    /// Startup-pinned local authority for the explicit offline runtime.
    ///
    /// Product daemon mode dispatches inside the daemon and supplies its own
    /// retained binding; it never populates this stdio-side field.
    pub repository_authority: Option<RequestRepositoryAuthority>,
    /// This server is the curated `agent-default` belt.
    ///
    /// Two behaviours hang off it, and they are one concept: the belt serves the
    /// short descriptions and trimmed schemas rather than the registered long
    /// forms, and it asks `semantic_locate` for the compact response shape on
    /// behalf of the agents it serves.
    ///
    /// Separate from `allowed_tools` because three profiles filter and only one
    /// of them is this belt. `benchmark` and `context-bench` keep the long forms
    /// and the shared payload deliberately: their bytes are an input to a
    /// citable result, and a benchmark number must not move because a
    /// description was rewritten or a payload was narrowed.
    pub agent_belt: bool,
    /// The routed surface this connection serves, when it serves one.
    ///
    /// A routed connection lists the one tool [`crate::routed::TOOL_NAME`] and
    /// reaches every other tool through its commands; `allowed_tools` holds that
    /// one name, so a named tool called directly is refused with the command
    /// that runs it here.
    pub routed: Option<crate::routed::RoutedSurface>,
    /// Whether entity bodies are served with each line marked by its offset in
    /// the entity, as [`crate::entity_lines`] presents them.
    ///
    /// Set only for a profile with no Kin write path, and cleared for any
    /// client that asks for exact bodies when it connects, as `kin agent run`
    /// does. Everything that restates a body as the base of an edit is served
    /// its exact bytes.
    pub number_entity_lines: bool,
    /// Whether this connection's bytes are an input to a citable result.
    ///
    /// `benchmark` and `context-bench` are served the instructions a published
    /// number was measured under, byte for byte, for the same reason
    /// `agent_belt` leaves their descriptions and payloads alone.
    pub citable: bool,
    /// The folder the client works in: its first workspace root once it names
    /// one, and until then the launch directory the launcher records here.
    ///
    /// An answer from a repository that is not this folder says so, and
    /// `kin_init` sets this folder up when it is named nothing else.
    pub client_root: Option<PathBuf>,
    /// How a path is resolved before two are compared, supplied by the
    /// launcher. Resolving symlinks reads the filesystem, which this crate
    /// leaves to its launcher; the default compares paths as given.
    pub canonicalize: fn(&Path) -> PathBuf,
}

impl McpServerConfig {
    /// Serve this connection exact entity bodies, whatever its profile would
    /// present. Called when a client asks for them at `initialize`.
    pub fn serve_exact_entity_bodies(&mut self) {
        self.number_entity_lines = false;
        if let Some(surface) = self.routed.as_mut() {
            surface.numbered = false;
        }
    }

    /// Read what an `initialize` request asks of the connection.
    fn apply_client_capabilities(&mut self, initialize: &serde_json::Value) {
        if crate::entity_lines::client_wants_exact_bodies(initialize) {
            self.serve_exact_entity_bodies();
        }
    }

    /// Whether this connection serves `kin_init`: as the named tool on a
    /// profile that lists it, or as the routed `init` command where the routed
    /// tool carries writes. Setting a folder up creates a store and the
    /// repository's canonical state, so no read-only profile serves it, and a
    /// remedy there names the command a person runs instead.
    pub fn serves_init(&self) -> bool {
        match self.routed {
            Some(surface) => surface.writes,
            None => self
                .allowed_tools
                .as_ref()
                .is_none_or(|allowed| allowed.contains(crate::repository_init::TOOL_NAME)),
        }
    }
}

/// How the stdio server should present session authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthorityMode {
    /// The daemon must own session state. Local registry fallback is disabled.
    DaemonRequired,
    /// The local in-process registry is only a fallback for offline/test use.
    OfflineFallback,
}

impl SessionAuthorityMode {
    pub fn uses_daemon(self) -> bool {
        matches!(self, Self::DaemonRequired)
    }

    pub fn requires_daemon(self) -> bool {
        matches!(self, Self::DaemonRequired)
    }
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            server_name: "kin-mcp".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
            allowed_tools: None,
            session_authority_mode: SessionAuthorityMode::DaemonRequired,
            snapshot_path: None,
            repository_authority: None,
            agent_belt: false,
            routed: None,
            number_entity_lines: false,
            citable: false,
            client_root: None,
            canonicalize: Path::to_path_buf,
        }
    }
}

pub trait PersistableMcpStore: GraphStore {
    fn persist_primary_snapshot(&self, snapshot_path: Option<&Path>) -> Result<()> {
        let _ = snapshot_path;
        Ok(())
    }
}

impl PersistableMcpStore for kin_db::InMemoryGraph {
    fn persist_primary_snapshot(&self, snapshot_path: Option<&Path>) -> Result<()> {
        let Some(snapshot_path) = snapshot_path else {
            return Ok(());
        };
        self.flush_text_index().map_err(McpError::graph)?;
        let snapshot = self.to_snapshot();
        let text_index_path = snapshot_path
            .parent()
            .map(|parent| parent.join("text-index"))
            .ok_or_else(|| McpError::Other("snapshot path has no parent directory".into()))?;
        let manager = kin_db::SnapshotManager::new(snapshot_path.to_path_buf());
        let graph = kin_db::InMemoryGraph::from_snapshot_with_text_index(snapshot, text_index_path)
            .map_err(McpError::graph)?;
        manager.swap(graph);
        manager.save().map_err(McpError::graph)?;
        Ok(())
    }
}

/// Run the in-process MCP server over stdio (stdin/stdout).
///
/// This is the explicit offline/test runtime. Product `kin mcp start` uses
/// [`run_stdio_daemon`], which never receives a graph store and cannot fall
/// through to local graph handlers.
pub async fn run_stdio<G: PersistableMcpStore + 'static>(
    store: G,
    mut config: McpServerConfig,
) -> Result<()> {
    if !config.session_authority_mode.requires_daemon() && config.repository_authority.is_none() {
        config.repository_authority =
            crate::handlers::repository_authority::discover_for_process()?;
    }
    let sessions = SessionRegistry::new();
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut reader = reader;

    tracing::info!("kin-mcp stdio server starting");
    match config.session_authority_mode {
        SessionAuthorityMode::DaemonRequired => {
            tracing::info!(
                "kin-mcp session authority: daemon-required; local registry fallback is disabled"
            );
        }
        SessionAuthorityMode::OfflineFallback => {
            tracing::info!(
                "kin-mcp session authority: explicit offline test mode; local registry is authoritative for this run"
            );
        }
    }

    while let Some((message, framed)) = read_stdio_message(&mut reader).await? {
        if message.contains("\"initialize\"") {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&message) {
                if value.get("method").and_then(|method| method.as_str()) == Some("initialize") {
                    config.apply_client_capabilities(&value);
                }
            }
        }
        if let Some(response) = process_message(&message, &store, &config, &sessions).await {
            let response_json = serde_json::to_string(&response).map_err(McpError::Json)?;
            write_stdio_message(&mut stdout, &response_json, framed).await?;
        }
    }

    tracing::info!("kin-mcp stdio server shutting down");
    Ok(())
}

/// The repository this MCP process serves: its working directory and the URL of
/// the daemon that owns its graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundRepo {
    /// Repository working directory (the parent of its `.kin/`).
    pub root: PathBuf,
    /// Daemon endpoint serving that repository.
    pub daemon_url: String,
}

/// What the binder made of the MCP client's advertised workspace roots.
///
/// The two failure shapes are kept apart because they call for opposite
/// behavior. A root the server can see and identify as a Kin repository is
/// evidence about which codebase the client is asking about; a root the server
/// cannot resolve at all is evidence about nothing, because a containerised or
/// remote server reaches its repository over a boundary the client does not
/// share and the client's paths never exist in the server's namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceBinding {
    /// The process is bound to this repository, either freshly or because the
    /// roots still contain the repository it already served.
    Bound(BoundRepo),
    /// The roots name Kin repositories this server can see, and it is not
    /// serving any of them: either an operator pin refuses to follow the
    /// client, or the daemon for the repository the client moved to could not
    /// be resolved. The client really is looking at another codebase.
    OtherRepository(Vec<PathBuf>),
    /// None of the roots names a Kin repository this server can see. The client
    /// and the server describe the filesystem in different namespaces, so the
    /// roots say nothing about which repository this server should serve.
    Unresolvable,
}

/// Binds — or re-binds — the repo daemon from the MCP client's advertised
/// workspace roots.
///
/// Receives the filesystem paths of the client's roots and binds the daemon for
/// the first one that is a Kin repository (setting `KIN_DAEMON_URL` as a side
/// effect), reporting what it found as a [`WorkspaceBinding`]. Supplied by the
/// kin-cli MCP command; when the binder itself is `None`, roots binding is
/// disabled (the client cannot serve roots).
///
/// The binder is invoked for every `roots/list` response, not only the first:
/// an editor that moves its window to another folder announces the change, and
/// a server that keeps its original binding answers from a repository the user
/// has left. A [`WorkspaceBinding::OtherRepository`] return while a repository
/// is already bound is therefore meaningful — it tells the server to refuse tool
/// calls rather than serve them from the previous repository's graph.
pub type RepoBinder = Box<
    dyn Fn(Vec<PathBuf>) -> Pin<Box<dyn Future<Output = WorkspaceBinding> + Send>> + Send + Sync,
>;

/// The JSON-RPC id the server uses for its own `roots/list` request so it can
/// recognize the matching response coming back from the client.
const ROOTS_REQUEST_ID: &str = "kin-mcp-roots-list";

/// Run the daemon-required MCP server over stdio.
///
/// This mode is intentionally graphless: every `tools/call` request is
/// forwarded to the repo daemon, which executes against its live graph and
/// session coordinator. The stdio process only handles JSON-RPC framing,
/// initialization, tool listing, allow-list checks, and transport errors.
///
/// When no repository was bound at startup (no `--repo`/`KIN_MCP_REPO` and the
/// launch cwd is not inside a Kin repo — the common case for editors that spawn
/// MCP servers from `$HOME`) and the client advertises the MCP `roots`
/// capability, the server requests `roots/list` after initialization and binds
/// the daemon to the open workspace via `repo_binder`. That is what lets Cursor,
/// Windsurf, and other editors reach whatever repository the user has open
/// without a hardcoded path in the MCP config.
///
/// The client's workspace can move afterwards, so a `roots/list_changed`
/// notification re-requests roots whether or not a repository is bound, and the
/// binder decides: it re-binds the process to the repository the client is now
/// looking at, or reports that the roots name a different Kin repository it will
/// not follow, in which case every `tools/call` is refused with a structured
/// repo-mismatch error until a later roots change resolves it. A bound server
/// never keeps answering from a repository the client has left — a confident
/// answer about the wrong codebase is worse than an error.
///
/// Roots this server cannot resolve at all are the other case, and it is not a
/// workspace change. A server registered as `docker exec -w <repo> ... kin mcp
/// start`, or reached over any other boundary, is bound to a repository by its
/// own cwd or `--repo`/`KIN_MCP_REPO` while the client announces host paths that
/// never exist in the server's namespace. Those roots are evidence about
/// nothing, so a server holding its own binding keeps serving it and records the
/// disagreement at info instead of refusing every call for the life of the
/// process.
pub async fn run_stdio_daemon(
    config: McpServerConfig,
    repo_binder: Option<RepoBinder>,
    startup: Option<std::sync::Arc<StartupDaemonBinding>>,
    initializer: Option<crate::repository_init::RepoInitializer>,
) -> Result<()> {
    if !config.session_authority_mode.requires_daemon() {
        return Err(McpError::Other(
            "daemon stdio mode requires daemon session authority".to_string(),
        ));
    }

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);

    run_stdio_daemon_over(
        &mut reader,
        &mut stdout,
        config,
        repo_binder,
        bound_daemon_url_from_env(),
        startup,
        initializer,
    )
    .await
}

/// Transport-generic core of [`run_stdio_daemon`].
///
/// Split out so the binding lifecycle — the roots request, the response that
/// completes it, the re-request after a workspace change, and the refusal that
/// follows a change we cannot follow — is exercised over an in-memory transport
/// instead of only over the process's real stdin/stdout.
///
/// `bound_daemon_url` is the daemon this process was already bound to before the
/// loop started (from `--repo`/`KIN_MCP_REPO`/cwd), passed in rather than read
/// from the environment so the loop's binding decisions are a function of its
/// inputs.
async fn run_stdio_daemon_over<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut config: McpServerConfig,
    repo_binder: Option<RepoBinder>,
    bound_daemon_url: Option<String>,
    startup: Option<std::sync::Arc<StartupDaemonBinding>>,
    initializer: Option<crate::repository_init::RepoInitializer>,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tracing::info!("kin-mcp daemon-proxy stdio server starting");

    // MCP `roots` binding state. Before a repository is bound we reach out for
    // workspace roots as soon as the client says it can serve them; afterwards
    // only a roots *change* triggers another request. An editor may initialize
    // the shared MCP process before opening a workspace, so only suppress a
    // request while one is actually in flight.
    let mut client_supports_roots = false;
    let mut roots_request_state = WorkspaceRootsRequestState::default();
    let mut binding = RepoBindingState::started_with(bound_daemon_url);
    binding.init_served = config.serves_init();
    // A `kin_init` this server started, and the folder the client works in
    // before any roots arrive: the launch directory the launcher recorded.
    let mut init_tracker = crate::repository_init::InitTracker::default();
    let launch_root = config.client_root.clone();

    while let Some((message, framed)) = read_stdio_message(&mut *reader).await? {
        // The launcher's startup binding runs behind this loop so `initialize`
        // and `tools/list` are answered immediately. Once it settles with a
        // bound daemon, fold that into the roots-binding bookkeeping so a
        // later roots change compares against the repository actually served.
        if let Some(startup) = startup.as_ref() {
            if !binding.is_bound() {
                if let StartupBindingState::Bound(bound) = startup.snapshot() {
                    binding.bind(bound, BindingOrigin::Server);
                }
            }
        }

        // Peek at the raw JSON so we can distinguish the client's requests and
        // notifications from the `roots/list` response we may have sent: a
        // response carries no `method`, which the strongly-typed
        // `JsonRpcRequest` requires.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&message) {
            let method = value.get("method").and_then(|m| m.as_str());

            if method == Some("initialize") {
                client_supports_roots = value.pointer("/params/capabilities/roots").is_some();
                config.apply_client_capabilities(&value);
            }

            // Whether `--repo`/`KIN_MCP_REPO` pinned this server's repository.
            // Read per message rather than once: the startup binding settles
            // behind this loop, so the pin is not knowable when it starts.
            let repo_pinned = startup
                .as_ref()
                .is_some_and(|startup| startup.pinned_by_operator());

            // An initialization that finished behind the server since the last
            // message binds its repository before anything reads the binding.
            if let Some((dir, outcome)) = init_tracker.take_finished().await {
                if outcome.is_repository() {
                    adopt_initialized_repository(
                        dir,
                        &mut binding,
                        repo_binder.as_ref(),
                        startup.as_deref(),
                        repo_pinned,
                    )
                    .await;
                } else {
                    tracing::warn!(
                        dir = %dir.display(),
                        ?outcome,
                        "kin-mcp: a kin_init that ran past its call did not set the folder up"
                    );
                }
            }

            // `kin_init` is answered here, where the client's folder and the
            // binder are, and before anything waits on a daemon or refuses a
            // workspace it cannot bind: it is how a server with no repository
            // gets one.
            if method == Some("tools/call") {
                if let Some(call) = init_call(&value, &config) {
                    let response = answer_init_call(
                        call,
                        &config,
                        &mut init_tracker,
                        initializer.as_ref(),
                        &mut binding,
                        repo_binder.as_ref(),
                        startup.as_deref(),
                        repo_pinned,
                    )
                    .await;
                    if let Some(response) = response {
                        let response_json =
                            serde_json::to_string(&response).map_err(McpError::Json)?;
                        write_stdio_message(&mut *writer, &response_json, framed).await?;
                    }
                    continue;
                }
            }

            // A `tools/call` racing the launcher's startup binding gets a
            // bounded moment for a warm daemon to bind, then an honest
            // still-starting answer: never minutes of silence, and never a
            // remedy-flavored "no daemon" error while one is on its way up.
            //
            // The tool registry is exempt, because it reads no graph. Waiting on
            // the binding would answer "the daemon is still starting" to the one
            // question no daemon can answer better, and admitting a daemon spawn
            // for it would undo FIR-3099: an agent that asked only what tools
            // exist would open the store and schedule a full embedding pass.
            // A routed `describe`, or a routed call that will be refused, reads
            // no graph either.
            let call_reads_the_graph = value
                .pointer("/params/name")
                .and_then(|name| name.as_str())
                .map(crate::agent_belt::canonical_tool_name)
                != Some(crate::handlers::tool_search::TOOL_NAME)
                && !crate::routed::answers_locally(&value, config.routed);
            // While a `kin_init` this server started is still building the
            // graph, and nothing else is bound, there is no repository to
            // answer from yet and no daemon worth starting.
            if method == Some("tools/call") && call_reads_the_graph && !binding.is_bound() {
                if let Some((dir, elapsed)) = init_tracker.running() {
                    if let Some(response) = initializing_response(&value, dir, elapsed, &config) {
                        let response_json =
                            serde_json::to_string(&response).map_err(McpError::Json)?;
                        write_stdio_message(&mut *writer, &response_json, framed).await?;
                    }
                    continue;
                }
            }
            if method == Some("tools/call") && call_reads_the_graph {
                if let Some(startup) = startup.as_ref() {
                    // The first ask for a graph answer, and the only thing that
                    // admits starting a daemon (FIR-3099). Before this line
                    // every bind path attaches to a daemon that is already
                    // serving and starts none, so a session that never calls a
                    // tool never opens the store and never runs an embedding
                    // pass. Set before the wait, because the wait is what the
                    // launcher's binding task is sitting on.
                    // The bound this call gets, decided by whether it is the
                    // call that started the daemon. See
                    // `startup_bind_grace`.
                    let grace = startup_bind_grace(startup.admit_daemon_spawn());
                    if !startup.wait_until_settled(grace).await {
                        if let Some(response) = startup_pending_response(&value, startup, grace) {
                            let response_json =
                                serde_json::to_string(&response).map_err(McpError::Json)?;
                            write_stdio_message(&mut *writer, &response_json, framed).await?;
                        }
                        continue;
                    }
                    if !binding.is_bound() {
                        if let StartupBindingState::Bound(bound) = startup.snapshot() {
                            binding.bind(bound, BindingOrigin::Server);
                        }
                    }
                    // Roots the pre-call binder resolved to a Kin repository it
                    // was not yet allowed to start a daemon for. Put them
                    // through the binder again now that it is. This is the
                    // editor-launched-from-$HOME shape, where the client's roots
                    // are the only thing naming a repository and the launch
                    // directory settles unbound at once, so nothing was waited
                    // for above. After the settle, not before it, so a startup
                    // binding that is about to bind the same repository wins and
                    // no second daemon is raced for it.
                    if !binding.is_bound() {
                        let deferred = binding.deferred_roots();
                        if !deferred.is_empty() {
                            if let Some(binder) = repo_binder.as_ref() {
                                apply_workspace_roots(binder, deferred, &mut binding, repo_pinned)
                                    .await;
                            }
                        }
                    }
                }
            }

            // The client moved to a workspace we could not bind. Refuse every
            // tool call until the root becomes bindable: answering from the
            // repository the client left would return a confident, well-formed
            // result about the wrong codebase.
            //
            // The verdict is re-derived here rather than read out of the state
            // it was recorded in. It was computed once, when the roots changed,
            // and nothing about the announced root is fixed: `kin init` can run
            // there, a mount can appear, a container path can be made to exist.
            // A cached refusal outlives every one of those, so a server that
            // was right at roots-change time keeps refusing a workspace it
            // could now serve, and the only recovery is restarting the process.
            // Re-binding costs nothing that matters, because every call in this
            // state is being refused anyway.
            if method == Some("tools/call") && binding.is_mismatched() {
                if let Some(binder) = repo_binder.as_ref() {
                    let roots = binding.mismatched_roots();
                    if !roots.is_empty() {
                        apply_workspace_roots(binder, roots, &mut binding, repo_pinned).await;
                    }
                }
                if binding.is_mismatched() {
                    if let Some(response) = binding.repo_mismatch_response(&value) {
                        let response_json =
                            serde_json::to_string(&response).map_err(McpError::Json)?;
                        write_stdio_message(&mut *writer, &response_json, framed).await?;
                    }
                    continue;
                }
            }

            // Our own `roots/list` response returning from the client: bind the
            // daemon and swallow it (a response is never itself answered).
            if method.is_none()
                && value.get("id").and_then(|id| id.as_str()) == Some(ROOTS_REQUEST_ID)
            {
                roots_request_state.complete();
                let roots = parse_workspace_roots(&value);
                // The folder the client works in is its first root from here
                // on, which is what an answer from another repository is
                // compared to and what `kin_init` sets up by default.
                if !roots.is_empty() {
                    config.client_root = crate::first_contact::client_root(
                        &roots,
                        launch_root.as_deref(),
                        config.canonicalize,
                    );
                }
                if let Some(binder) = repo_binder.as_ref() {
                    apply_workspace_roots(binder, roots, &mut binding, repo_pinned).await;
                }
                continue;
            }

            // Ask the client for its workspace roots: while nothing is bound,
            // as soon as it finishes initializing or asks for the tool list
            // (retrying after an earlier empty response); and whenever it
            // reports a roots change, bound or not, because that is how an
            // editor announces that its window moved to another folder.
            if roots_request_state.begin_if_allowed(
                method,
                client_supports_roots,
                repo_binder.is_some(),
                binding.wants_workspace_roots(),
                Instant::now(),
            ) {
                let request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": ROOTS_REQUEST_ID,
                    "method": "roots/list",
                });
                let request_json = serde_json::to_string(&request).map_err(McpError::Json)?;
                write_stdio_message(&mut *writer, &request_json, framed).await?;
                // Fall through: `initialized` has no response, and `tools/list`
                // is still answered normally below.
            }
        }

        if let Some(mut response) = process_daemon_message(&message, &config).await {
            if is_tools_call(&message) {
                stamp_client_folder(&mut response, binding.repo_root.as_deref(), &config);
            }
            let response_json = serde_json::to_string(&response).map_err(McpError::Json)?;
            write_stdio_message(&mut *writer, &response_json, framed).await?;
        }
    }

    tracing::info!("kin-mcp daemon-proxy stdio server shutting down");
    Ok(())
}

/// Whether a raw message is a `tools/call` request.
fn is_tools_call(message: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(message)
        .ok()
        .and_then(|value| {
            value
                .get("method")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .as_deref()
        == Some("tools/call")
}

/// Make a tool answer on a connection whose client works in a folder other
/// than the repository this server is bound to say so, first.
///
/// An answer the daemon's health reached already carries `_kin.repository` and
/// the warning at the head of `_kin.advice`. Every other answer, a refusal, a
/// routed answer given here, a delegate error, gets both here, so no answer on
/// such a connection reads as if it came from the client's own folder. An
/// answer that is not JSON gets the warning as its first line. The same folder,
/// or no bound repository, leaves the answer as it is.
fn stamp_client_folder(
    response: &mut JsonRpcResponse,
    repo_root: Option<&Path>,
    config: &McpServerConfig,
) {
    let (Some(root), Some(client)) = (repo_root, config.client_root.as_deref()) else {
        return;
    };
    let identity =
        crate::first_contact::repository_identity(&(config.canonicalize)(root), Some(client));
    let Some(warning) = identity.warning.clone() else {
        return;
    };
    let Some(block) = response
        .result
        .as_mut()
        .and_then(|result| result.get_mut("content"))
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|content| content.first_mut())
    else {
        return;
    };
    let Some(text) = block.get("text").and_then(serde_json::Value::as_str) else {
        return;
    };
    let stamped = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(mut payload)) => {
            let key = crate::envelope::ENVELOPE_KEY;
            let mut kin = match payload.remove(key) {
                Some(serde_json::Value::Object(kin)) => kin,
                Some(_) => return,
                None => serde_json::Map::new(),
            };
            if kin
                .get("repository")
                .and_then(|repository| repository.get("warning"))
                .is_some()
            {
                return;
            }
            let advice = match kin.remove("advice") {
                Some(serde_json::Value::String(existing)) => format!("{warning} {existing}"),
                _ => warning,
            };
            kin.insert(
                "repository".to_string(),
                serde_json::to_value(&identity).unwrap_or_default(),
            );
            // Built in reading order, advice first and the envelope first,
            // whichever order the map keeps.
            let mut envelope = serde_json::Map::new();
            envelope.insert("advice".to_string(), serde_json::Value::String(advice));
            envelope.extend(kin);
            let mut ordered = serde_json::Map::new();
            ordered.insert(key.to_string(), serde_json::Value::Object(envelope));
            ordered.extend(payload);
            // Keep the wire format the answer already had: re-indenting a
            // compact answer would undo the call's `compact` choice after its
            // size was settled.
            match crate::budget::render_in_format_of(&serde_json::Value::Object(ordered), text) {
                Ok(text) => text,
                Err(_) => return,
            }
        }
        _ => format!("{warning}\n\n{text}"),
    };
    block["text"] = serde_json::Value::String(stamped);
}

/// Feed a `roots/list` response through the binder and record what it means for
/// this process: a fresh binding, an unchanged one, or a workspace the server
/// cannot follow.
async fn apply_workspace_roots(
    binder: &RepoBinder,
    roots: Vec<PathBuf>,
    binding: &mut RepoBindingState,
    repo_pinned: bool,
) {
    if roots.is_empty() {
        // No open folder is not the same as a different folder: there is no
        // other repository for the client's calls to be about, so an existing
        // binding is left alone rather than torn down.
        tracing::info!("kin-mcp: client returned no workspace roots; binding is unchanged");
        return;
    }

    let previous_url = binding.daemon_url.clone();
    match binder(roots.clone()).await {
        WorkspaceBinding::Bound(bound) => {
            if previous_url.as_deref() != Some(bound.daemon_url.as_str()) {
                // A different daemon serves this process now. Drop the revival
                // override, which pins delegate calls at a daemon this process
                // started for the repository it is leaving.
                daemon_delegate::clear_daemon_url_override();
                tracing::info!(
                    repo = %bound.root.display(),
                    daemon = %bound.daemon_url,
                    "kin-mcp: bound repo daemon from the client's workspace roots"
                );
            }
            binding.bind(bound, BindingOrigin::ClientRoots);
        }
        WorkspaceBinding::OtherRepository(repos) if binding.is_bound() => {
            tracing::warn!(
                roots = ?roots,
                repositories = ?repos,
                "kin-mcp: the client's workspace roots name a different Kin repository this server \
                 does not serve; refusing tool calls instead of answering from the bound repository"
            );
            binding.mark_mismatch(roots, repo_pinned);
        }
        // The client's roots resolve to nothing here. That is the shape of every
        // containerised or remote registration: the client names host paths and
        // the server lives in another namespace, so the roots carry no evidence
        // that the client left the repository this server was pinned to. A
        // server holding its own binding — its launch cwd, `--repo`, or
        // `KIN_MCP_REPO` — keeps serving it. A server whose only authority was a
        // previous roots answer has had that authority withdrawn, so it refuses.
        WorkspaceBinding::Unresolvable
            if binding.is_bound() && binding.origin == Some(BindingOrigin::ClientRoots) =>
        {
            tracing::warn!(
                roots = ?roots,
                "kin-mcp: the client's workspace roots changed to a workspace with no bindable Kin \
                 repository; refusing tool calls instead of answering from the previous repository"
            );
            binding.mark_mismatch(roots, repo_pinned);
        }
        WorkspaceBinding::Unresolvable if binding.is_bound() => {
            tracing::info!(
                roots = ?roots,
                repo = ?binding.repo_root,
                "kin-mcp: none of the client's workspace roots names a Kin repository this server \
                 can resolve; keeping the repository this server was started with"
            );
        }
        // Nothing is bound and the client named Kin repositories this server can
        // see. Before FIR-3099 that could only mean their daemons refused to
        // start, so there was nothing to retry. Now it is also what a bind that
        // is not yet allowed to start one looks like, so the roots are kept for
        // the first `tools/call` to put through the binder again.
        WorkspaceBinding::OtherRepository(repos) => {
            tracing::info!(
                repositories = ?repos,
                "kin-mcp: the client's workspace roots name a Kin repository with no daemon bound \
                 yet; the first tool call binds it"
            );
            binding.defer_roots(roots);
        }
        WorkspaceBinding::Unresolvable => {
            tracing::info!("kin-mcp: no Kin repository among the client's workspace roots");
        }
    }
}

/// A `tools/call` that is, or routes to, `kin_init` on this connection.
struct InitCall {
    id: Option<serde_json::Value>,
    /// The call as the named tool it stands for.
    params: ToolCallParams,
    /// Whether it came through the routed tool.
    routed: bool,
}

/// The `kin_init` call this request is, if it is one this connection serves.
fn init_call(request: &serde_json::Value, config: &McpServerConfig) -> Option<InitCall> {
    let id = request.get("id").cloned();
    let mut params: ToolCallParams = serde_json::from_value(request.get("params")?.clone()).ok()?;
    if config.routed.is_some() {
        if params.name != crate::routed::TOOL_NAME {
            return None;
        }
        let dispatched = matches!(
            crate::routed::route(&mut params, config.routed),
            crate::routed::Routing::Dispatch
        );
        return (dispatched && params.name == crate::repository_init::TOOL_NAME).then_some(
            InitCall {
                id,
                params,
                routed: true,
            },
        );
    }
    crate::agent_belt::canonicalize_tool_name(&mut params.name);
    let served = config
        .allowed_tools
        .as_ref()
        .is_none_or(|allowed| allowed.contains(crate::repository_init::TOOL_NAME));
    (params.name == crate::repository_init::TOOL_NAME && served).then_some(InitCall {
        id,
        params,
        routed: false,
    })
}

/// Answer one `kin_init` call: set the folder up, or report where that stands.
#[allow(clippy::too_many_arguments)]
async fn answer_init_call(
    call: InitCall,
    config: &McpServerConfig,
    tracker: &mut crate::repository_init::InitTracker,
    initializer: Option<&crate::repository_init::RepoInitializer>,
    binding: &mut RepoBindingState,
    binder: Option<&RepoBinder>,
    startup: Option<&StartupDaemonBinding>,
    repo_pinned: bool,
) -> Option<JsonRpcResponse> {
    use crate::repository_init::{
        busy_answer, finished_answer, running_answer, target_dir, unavailable_answer, InitProgress,
        INIT_WAIT,
    };
    let id = call.id.clone().filter(|id| !id.is_null())?;
    let result = match target_dir(&call.params.arguments, config.client_root.as_deref()) {
        Err(problem) => ToolCallResult::error(problem),
        Ok(dir) => {
            let dir = (config.canonicalize)(&dir);
            match initializer {
                None => unavailable_answer(crate::first_contact::Spelling::here()),
                Some(initializer) => match tracker
                    .start_or_join(dir.clone(), initializer, INIT_WAIT)
                    .await
                {
                    InitProgress::Finished(outcome) => {
                        if outcome.is_repository() {
                            adopt_initialized_repository(
                                dir.clone(),
                                binding,
                                binder,
                                startup,
                                repo_pinned,
                            )
                            .await;
                        }
                        finished_answer(&dir, &outcome, crate::first_contact::Spelling::here())
                    }
                    InitProgress::Running { elapsed } => running_answer(&dir, elapsed),
                    InitProgress::Busy {
                        dir: running,
                        elapsed,
                    } => busy_answer(&dir, &running, elapsed),
                },
            }
        }
    };
    let budget = ResponseBudget::from_arguments(&call.params.arguments);
    let enveloped = envelope::finalize_bounded(
        result,
        Envelope::daemon(),
        crate::repository_init::TOOL_NAME,
        &budget,
    );
    let mut response = JsonRpcResponse::success(
        Some(id),
        serde_json::to_value(&enveloped).unwrap_or_default(),
    );
    if call.routed {
        present_routed_hints(&mut response, &call.params);
    }
    Some(response)
}

/// Serve a folder `kin_init` just set up.
///
/// A server with nothing bound hands the folder to the next graph call, through
/// the path that already binds a repository the client named before a daemon
/// start was admitted, so this call answers as soon as the graph exists rather
/// than after a daemon has also started behind it. A server bound elsewhere,
/// the enclosing repository a nested folder was answered from, is moved to the
/// new repository now: the user asked for it. An operator pin is never
/// repointed by a setup call, and a server already bound to this folder has
/// nothing to do.
async fn adopt_initialized_repository(
    dir: PathBuf,
    binding: &mut RepoBindingState,
    binder: Option<&RepoBinder>,
    startup: Option<&StartupDaemonBinding>,
    repo_pinned: bool,
) {
    if repo_pinned || binding.repo_root.as_deref() == Some(dir.as_path()) {
        return;
    }
    if !binding.is_bound() {
        binding.defer_roots(vec![dir]);
        return;
    }
    if let Some(startup) = startup {
        startup.admit_daemon_spawn();
    }
    if let Some(binder) = binder {
        apply_workspace_roots(binder, vec![dir], binding, repo_pinned).await;
    }
}

/// The answer a graph call gets while a `kin_init` this server started is
/// still building the graph. `None` for a call with no id.
fn initializing_response(
    request: &serde_json::Value,
    dir: &Path,
    elapsed: Duration,
    config: &McpServerConfig,
) -> Option<JsonRpcResponse> {
    let id = request.get("id").filter(|id| !id.is_null())?.clone();
    let tool = request
        .pointer("/params/name")
        .and_then(|name| name.as_str())
        .unwrap_or("this tool");
    let result = crate::repository_init::graph_call_while_initializing(tool, dir, elapsed);
    let enveloped = envelope::finalize(result, Envelope::no_repository(), tool);
    let mut response = JsonRpcResponse::success(
        Some(id),
        serde_json::to_value(&enveloped).unwrap_or_default(),
    );
    if config.routed.is_some() && tool == crate::routed::TOOL_NAME {
        if let Ok(params) = serde_json::from_value::<ToolCallParams>(
            request.get("params").cloned().unwrap_or_default(),
        ) {
            present_routed_hints(&mut response, &params);
        }
    }
    Some(response)
}

/// The daemon bound before the stdio loop started (`KIN_DAEMON_URL` unset or
/// empty means nothing was bound).
fn bound_daemon_url_from_env() -> Option<String> {
    std::env::var("KIN_DAEMON_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Where a binding came from, which decides how much authority the client's
/// workspace roots carry over it.
///
/// A binding this server made for itself — its launch cwd, `--repo`, or
/// `KIN_MCP_REPO` — is an operator decision that survives roots it cannot
/// resolve. A binding that came from a previous `roots/list` answer exists only
/// because the client said so, so the client withdrawing it is decisive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingOrigin {
    /// Bound before or beside the stdio loop from this server's own inputs.
    Server,
    /// Bound from a `roots/list` answer.
    ClientRoots,
}

/// What the stdio loop knows about which repository it serves.
#[derive(Debug, Default)]
struct RepoBindingState {
    /// Daemon currently serving this process, if any.
    daemon_url: Option<String>,
    /// Repository that daemon serves. Unknown for a binding inherited from
    /// startup, which arrives as a URL with no accompanying root.
    repo_root: Option<PathBuf>,
    /// Where the current binding came from. `None` while nothing is bound.
    origin: Option<BindingOrigin>,
    /// Set when the client's workspace moved somewhere this server could not
    /// follow. Cleared by the next successful bind.
    mismatch: Option<WorkspaceMismatch>,
    /// Roots that named a Kin repository this server can see while nothing was
    /// bound. Kept so the first `tools/call` can put them through the binder
    /// again once starting a daemon is admitted. Cleared by the next successful
    /// bind.
    deferred_roots: Vec<PathBuf>,
    /// Whether this connection serves `kin_init`, so a refusal offers it only
    /// where a caller can call it.
    init_served: bool,
}

/// A workspace change the server could not follow: it is still bound to
/// `bound_repo`, while the client now reports `requested_roots`.
#[derive(Debug)]
struct WorkspaceMismatch {
    bound_repo: Option<PathBuf>,
    requested_roots: Vec<PathBuf>,
    /// Whether `--repo`/`KIN_MCP_REPO` pinned this server's repository, which
    /// decides which remedies the refusal is allowed to offer.
    repo_pinned: bool,
    /// Whether this connection serves `kin_init`.
    init_served: bool,
}

impl RepoBindingState {
    fn started_with(daemon_url: Option<String>) -> Self {
        Self {
            origin: daemon_url.is_some().then_some(BindingOrigin::Server),
            daemon_url,
            ..Self::default()
        }
    }

    fn is_bound(&self) -> bool {
        self.daemon_url.is_some()
    }

    /// Whether the server should still be reaching for workspace roots on the
    /// ordinary triggers. A refusing server counts as needing one: it is bound
    /// to a repository the client is not looking at, which is no more useful
    /// than being unbound, so it keeps trying to bind rather than waiting only
    /// for the client to announce another change.
    fn wants_workspace_roots(&self) -> bool {
        !self.is_bound() || self.is_mismatched()
    }

    fn is_mismatched(&self) -> bool {
        self.mismatch.is_some()
    }

    fn bind(&mut self, bound: BoundRepo, origin: BindingOrigin) {
        self.daemon_url = Some(bound.daemon_url);
        self.repo_root = Some(bound.root);
        self.origin = Some(origin);
        self.mismatch = None;
        self.deferred_roots.clear();
    }

    /// Remember roots that resolved to a Kin repository nothing is serving yet.
    fn defer_roots(&mut self, roots: Vec<PathBuf>) {
        self.deferred_roots = roots;
    }

    /// The roots waiting for a tool call to admit starting their daemon.
    ///
    /// Cloned rather than taken, so a call whose bind still fails leaves them
    /// for the next one. That costs a bind attempt per refused call, which is
    /// the same trade the mismatch retry above already makes and for the same
    /// reason: every call in this state is being refused anyway.
    fn deferred_roots(&self) -> Vec<PathBuf> {
        self.deferred_roots.clone()
    }

    fn mark_mismatch(&mut self, requested_roots: Vec<PathBuf>, repo_pinned: bool) {
        self.mismatch = Some(WorkspaceMismatch {
            bound_repo: self.repo_root.clone(),
            requested_roots,
            repo_pinned,
            init_served: self.init_served,
        });
    }

    /// The roots the client announced that this server could not bind.
    ///
    /// Empty when nothing is mismatched. Handed back so a later call can put
    /// the same roots through the binder again instead of trusting a verdict
    /// reached before anything on the host had a chance to change.
    fn mismatched_roots(&self) -> Vec<PathBuf> {
        self.mismatch
            .as_ref()
            .map(|mismatch| mismatch.requested_roots.clone())
            .unwrap_or_default()
    }

    /// Structured refusal for a `tools/call` that arrived while the client's
    /// workspace and this server's binding disagree. `None` for a malformed
    /// call with no id, which has no response channel — the caller still drops
    /// the call rather than forwarding it.
    fn repo_mismatch_response(&self, request: &serde_json::Value) -> Option<JsonRpcResponse> {
        let mismatch = self.mismatch.as_ref()?;
        let id = request.get("id").filter(|id| !id.is_null())?.clone();
        let tool = request
            .pointer("/params/name")
            .and_then(|name| name.as_str())
            .unwrap_or("this tool");
        let result = ToolCallResult::error(mismatch.message(tool));
        let enveloped = envelope::finalize(result, Envelope::workspace_mismatch(), tool);
        Some(JsonRpcResponse::success(
            Some(id),
            serde_json::to_value(&enveloped).unwrap_or_default(),
        ))
    }
}

impl WorkspaceMismatch {
    fn message(&self, tool: &str) -> String {
        let bound = match &self.bound_repo {
            Some(root) => root.display().to_string(),
            None => "the repository bound when this server started".to_string(),
        };
        let requested = self
            .requested_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "kin-mcp refuses '{tool}': the MCP client's workspace roots changed to [{requested}], \
             and none of them is a Kin repository this server can bind, so Kin is still bound to \
             {bound}. Answering would return a confident result about a repository you are no \
             longer looking at. {}",
            self.remedy()
        )
    }

    /// The fixes that actually apply to this server.
    ///
    /// A repo-bound server is not offered `kin init .`, and the omission is the
    /// point rather than brevity. `--repo`/`KIN_MCP_REPO` is how a server is
    /// registered against a repository it reaches over a boundary the client
    /// does not share: a docker-exec registration, a remote checkout. The path
    /// the client announces is then a HOST path this process may never be able
    /// to see, so running `kin init` there does not repair the mismatch. It
    /// creates a second, empty repository beside the real one and leaves the
    /// refusal exactly where it was.
    fn remedy(&self) -> String {
        if self.repo_pinned {
            "This server is pinned by --repo / KIN_MCP_REPO, so point the pin at the repository \
             you are working in and restart the MCP server, or open that repository's own path \
             in your client."
                .to_string()
        } else if self.init_served {
            format!(
                "Call kin_init to set the new workspace up, or run {} in it, or restart the MCP \
                 server from it (or with --repo <path> / KIN_MCP_REPO=<path>).",
                crate::first_contact::kin_command("init .", crate::first_contact::Spelling::here())
            )
        } else {
            format!(
                "Run {} in the new workspace, or restart the MCP server from it (or with --repo \
                 <path> / KIN_MCP_REPO=<path>).",
                crate::first_contact::kin_command("init .", crate::first_contact::Spelling::here())
            )
        }
    }
}

/// How long a `tools/call` waits for the launcher's startup daemon binding to
/// settle before answering that the daemon is still starting, once some earlier
/// call has already admitted the spawn.
///
/// A warm daemon binds in well under a second, so a call racing the bind gets
/// its real answer inside this window. A caller that reaches this bound has
/// already been told once, by the call that started the daemon, so repeating
/// the wait buys it nothing.
const TOOLS_CALL_STARTUP_BIND_GRACE: Duration = Duration::from_secs(10);

/// How long the FIRST graph-reading `tools/call` of a session waits.
///
/// That call is the one that admits the daemon spawn, so it is the only one
/// that can be waiting on a cold open rather than on a daemon somebody else
/// already paid for, and ten seconds is measurably short for it. Measured on
/// 2026-09-05 against kin `f6a29e329` on a 470 MiB store of 218 files: the
/// first call gave up at 10 s and the next one bound after 15.3 s, so the bind
/// wanted about 25 s and the session's first question failed anyway. The same
/// bound is what a call racing an in-flight admission needs: a five-line edit
/// on that store took the daemon 20 s to admit, and every `tools/call` during
/// that window read as still starting.
///
/// 45 s is that measurement with margin, and it stays under the 60 s per-call
/// timeout common MCP clients use, so a client times out on nothing this
/// process chose. It is a ceiling and not a delay: `wait_until_settled` returns
/// the instant the binding settles, so a warm session is exactly as fast as it
/// was. A cold flagship-scale start still takes minutes, no defensible grace
/// covers that, and the honest still-starting answer is still what it gets.
///
/// `kin setup`'s own MCP round trip is sized against this constant
/// (`kin_cli::commands::setup_verify`), because a client budget shorter than
/// this grace turns a still-starting answer into a killed process.
pub const FIRST_TOOLS_CALL_STARTUP_BIND_GRACE: Duration = Duration::from_secs(45);

/// The bound one `tools/call` gets to wait for the startup binding.
///
/// Pure, so the policy is provable without a daemon, a process or a clock.
const fn startup_bind_grace(first_graph_call: bool) -> Duration {
    if first_graph_call {
        FIRST_TOOLS_CALL_STARTUP_BIND_GRACE
    } else {
        TOOLS_CALL_STARTUP_BIND_GRACE
    }
}

/// Structured answer for a `tools/call` that arrived while the launcher's
/// startup binding is still pending. `None` for a malformed call with no id,
/// which has no response channel; the caller still drops the call rather than
/// forwarding it.
fn startup_pending_response(
    request: &serde_json::Value,
    startup: &StartupDaemonBinding,
    waited: Duration,
) -> Option<JsonRpcResponse> {
    let id = request.get("id").filter(|id| !id.is_null())?.clone();
    let tool = request
        .pointer("/params/name")
        .and_then(|name| name.as_str())
        .unwrap_or("this tool");
    let result = ToolCallResult::error(startup.starting_report(tool, waited));
    let enveloped = envelope::finalize(result, Envelope::daemon_unreachable(), tool);
    Some(JsonRpcResponse::success(
        Some(id),
        serde_json::to_value(&enveloped).unwrap_or_default(),
    ))
}

/// How long an unanswered `roots/list` suppresses another one. A client that
/// advertises the roots capability and then never answers would otherwise wedge
/// binding — and, after a workspace change, the refusal state — for the life of
/// the process.
const ROOTS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct WorkspaceRootsRequestState {
    in_flight_since: Option<Instant>,
}

impl WorkspaceRootsRequestState {
    fn complete(&mut self) {
        self.in_flight_since = None;
    }

    fn request_in_flight(&self, now: Instant) -> bool {
        self.in_flight_since
            .is_some_and(|started| now.saturating_duration_since(started) < ROOTS_REQUEST_TIMEOUT)
    }

    fn begin_if_allowed(
        &mut self,
        method: Option<&str>,
        client_supports_roots: bool,
        has_repo_binder: bool,
        wants_binding: bool,
        now: Instant,
    ) -> bool {
        let should_begin = should_request_workspace_roots(
            method,
            client_supports_roots,
            self.request_in_flight(now),
            has_repo_binder,
            wants_binding,
        );
        if should_begin {
            self.in_flight_since = Some(now);
        }
        should_begin
    }
}

/// Decide whether an inbound client message should trigger a workspace-roots
/// request. Kept separate from the stdio loop so the retry semantics remain
/// deterministic and testable without mutating process-global daemon state.
///
/// A roots *change* is honored whether or not a repository is bound: it is the
/// only signal an editor sends when its window moves to another folder, and
/// ignoring it once bound is what leaves the server answering from the previous
/// repository. The other triggers are gated on `wants_binding` — unbound, or
/// bound to a repository the client has left — so a settled session does not
/// re-ask on every `tools/list`, while a refusing one keeps trying.
fn should_request_workspace_roots(
    method: Option<&str>,
    client_supports_roots: bool,
    request_in_flight: bool,
    has_repo_binder: bool,
    wants_binding: bool,
) -> bool {
    if !client_supports_roots || request_in_flight || !has_repo_binder {
        return false;
    }
    match method {
        Some("notifications/roots/list_changed") => true,
        Some("initialized") | Some("notifications/initialized") | Some("tools/list") => {
            wants_binding
        }
        _ => false,
    }
}

/// Extract filesystem paths from an MCP `roots/list` response
/// (`result.roots[].uri`), accepting both `file://` URIs and bare paths.
fn parse_workspace_roots(value: &serde_json::Value) -> Vec<PathBuf> {
    value
        .pointer("/result/roots")
        .and_then(|roots| roots.as_array())
        .map(|roots| {
            roots
                .iter()
                .filter_map(|root| root.get("uri").and_then(|uri| uri.as_str()))
                .filter_map(root_uri_to_path)
                .collect()
        })
        .unwrap_or_default()
}

/// Convert an MCP root's `uri` into a filesystem path. Accepts spec-compliant
/// `file://` URIs (decoding `%XX` escapes) and the bare absolute path some
/// clients (e.g. Cursor) send instead. Returns `None` for remote/non-file URIs.
fn root_uri_to_path(uri: &str) -> Option<PathBuf> {
    if uri
        .get(.."file://".len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("file://"))
    {
        let rest = &uri["file://".len()..];

        // Empty authority: `file:///abs/path` or `file:///C:/Users/me/repo`.
        if rest.starts_with('/') {
            return Some(file_uri_path(percent_decode(rest)));
        }

        let slash = rest.find('/')?;
        let authority = &rest[..slash];
        let path = percent_decode(&rest[slash..]);

        // `localhost` is the local machine, so only its path component matters.
        if authority.eq_ignore_ascii_case("localhost") {
            return Some(file_uri_path(path));
        }

        // A few Windows clients emit the non-canonical but common
        // `file://C:/Users/...` spelling, treating the drive as an authority.
        if is_windows_drive_authority(authority) {
            return Some(PathBuf::from(format!("{authority}{path}")));
        }

        // A non-local file authority is a Windows UNC share. Do not reinterpret
        // it as a local POSIX path on Unix hosts.
        #[cfg(windows)]
        {
            return Some(PathBuf::from(format!(
                r"\\{authority}{}",
                path.replace('/', "\\")
            )));
        }
        #[cfg(not(windows))]
        {
            return None;
        }
    }
    // Some clients (Cursor) send a bare absolute path rather than a file URI.
    if uri.starts_with('/') || is_windows_drive_path(uri) || uri.starts_with(r"\\") {
        return Some(PathBuf::from(uri));
    }
    None
}

/// Normalize the path component of a file URI. RFC 8089 spells a Windows drive
/// URI as `file:///C:/...`; the leading slash is URI syntax, not part of the
/// native Windows path.
fn file_uri_path(path: String) -> PathBuf {
    if path.starts_with('/') && is_windows_drive_path(&path[1..]) {
        PathBuf::from(&path[1..])
    } else {
        PathBuf::from(path)
    }
}

fn is_windows_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn is_windows_drive_authority(authority: &str) -> bool {
    let bytes = authority.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Minimal percent-decoding for `file://` URI paths (handles `%20`, etc.).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(decoded) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                out.push(decoded);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn read_stdio_message<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(String, bool)>> {
    let mut first_line = String::new();
    loop {
        first_line.clear();
        let bytes = reader
            .read_line(&mut first_line)
            .await
            .map_err(McpError::Io)?;
        if bytes == 0 {
            return Ok(None);
        }
        if !first_line.trim().is_empty() {
            break;
        }
    }

    if let Some(content_length) = parse_content_length(&first_line) {
        let mut header_line = String::new();
        loop {
            header_line.clear();
            let bytes = reader
                .read_line(&mut header_line)
                .await
                .map_err(McpError::Io)?;
            if bytes == 0 {
                return Err(McpError::Protocol(
                    "unexpected EOF while reading MCP headers".into(),
                ));
            }
            if header_line == "\n" || header_line == "\r\n" {
                break;
            }
        }

        let mut payload = vec![0u8; content_length];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(McpError::Io)?;
        let message = String::from_utf8(payload)
            .map_err(|e| McpError::Protocol(format!("invalid UTF-8 payload: {e}")))?;
        return Ok(Some((message, true)));
    }

    Ok(Some((first_line.trim().to_string(), false)))
}

async fn write_stdio_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response_json: &str,
    framed: bool,
) -> Result<()> {
    if framed {
        let response_bytes = response_json.as_bytes();
        let header = format!("Content-Length: {}\r\n\r\n", response_bytes.len());
        writer
            .write_all(header.as_bytes())
            .await
            .map_err(McpError::Io)?;
        writer
            .write_all(response_bytes)
            .await
            .map_err(McpError::Io)?;
    } else {
        writer
            .write_all(response_json.as_bytes())
            .await
            .map_err(McpError::Io)?;
        writer.write_all(b"\n").await.map_err(McpError::Io)?;
    }
    writer.flush().await.map_err(McpError::Io)?;
    Ok(())
}

fn parse_content_length(line: &str) -> Option<usize> {
    let (name, value) = line.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("Content-Length") {
        return None;
    }
    value.trim().parse().ok()
}

/// Process a single JSON-RPC message and return a response.
pub async fn process_message<G: PersistableMcpStore>(
    message: &str,
    store: &G,
    config: &McpServerConfig,
    sessions: &SessionRegistry,
) -> Option<JsonRpcResponse> {
    let request: JsonRpcRequest = match serde_json::from_str(message) {
        Ok(req) => req,
        Err(e) => {
            return Some(JsonRpcResponse::error(
                None,
                -32700,
                format!("Parse error: {}", e),
            ));
        }
    };

    let id = request.id.clone();
    let is_notification = id.is_none();

    let response = match request.method.as_str() {
        "initialize" => Some(handle_initialize(id, &request.params, config)),
        "initialized" => None,
        "tools/list" => Some(handle_tools_list(id, config)),
        "tools/call" if config.session_authority_mode.requires_daemon() => {
            Some(handle_tools_call_daemon(id, &request.params, config).await)
        }
        "tools/call" => Some(handle_tools_call(id, &request.params, store, sessions, config).await),
        "ping" => Some(JsonRpcResponse::success(id, serde_json::json!({}))),
        _ => Some(JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", request.method),
        )),
    };

    if is_notification {
        None
    } else {
        response
    }
}

/// Process a single JSON-RPC message for daemon-backed product mode.
pub async fn process_daemon_message(
    message: &str,
    config: &McpServerConfig,
) -> Option<JsonRpcResponse> {
    let request: JsonRpcRequest = match serde_json::from_str(message) {
        Ok(req) => req,
        Err(e) => {
            return Some(JsonRpcResponse::error(
                None,
                -32700,
                format!("Parse error: {}", e),
            ));
        }
    };

    let id = request.id.clone();
    let is_notification = id.is_none();

    let response = match request.method.as_str() {
        "initialize" => Some(handle_initialize(id, &request.params, config)),
        "initialized" => None,
        "tools/list" => Some(handle_tools_list(id, config)),
        "tools/call" => Some(handle_tools_call_daemon(id, &request.params, config).await),
        "ping" => Some(JsonRpcResponse::success(id, serde_json::json!({}))),
        _ => Some(JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", request.method),
        )),
    };

    if is_notification {
        None
    } else {
        response
    }
}

/// The MCP protocol version this server supports.
const SUPPORTED_PROTOCOL_VERSION: &str = "2024-11-05";

/// The most bytes [`SERVER_INSTRUCTIONS`] may carry.
///
/// It is injected once per session and a client may spend it on the model's
/// context rather than on its own, so it is a budget rather than a page.
/// Grok delivers it as a 1,194-byte synthetic user message on turn one.
///
/// Held by the compile-time assertion below the string rather than by a test.
/// There is no state in which this crate should build with an instructions
/// string a client cannot afford to inject, and a test that fails after the
/// bytes are written is a slower way to learn the same thing.
pub(crate) const SERVER_INSTRUCTIONS_BUDGET: usize = 1_200;

/// Usage instructions returned at initialize time so a connecting agent knows
/// what this server is before its first tool call.
///
/// Written for the client shape where this string is ALL the model gets. A
/// client is free to hide the tool schemas: Grok never sends them, delivering
/// this string verbatim as a synthetic reminder on turn one and making the
/// model call its own `search_tool` with a query to learn any tool's name or
/// schema. Measured on 2026-09-15 with Kin attached beside Grok's own file and
/// shell tools, three local models made zero Kin calls across ten runs. The
/// string they read said "prefer semantic_locate" and "reach for grep only when
/// no graph-backed tool answers the question". Every one of the ten answered
/// from Grok's own file and shell tools instead, eight of them with grep, and
/// only three ever called `search_tool` at all.
///
/// So it names the tools a model reaches first by their exact registered names,
/// because a name a model has read is a name it can search for, and it tells a
/// model whose client lists tools by search to search for this server before
/// its first file read.
///
/// Since 2026-09-22 it is an operating procedure rather than a tool list: five
/// numbered steps, founder-approved, with the tool names adapted to the surface
/// a profile serves. A list of what each tool does left the choice to the
/// model, and in the corrected rerun pilot of 2026-09-22 the model explored
/// with shell commands only and never called a Kin tool. The procedure makes
/// the choice for it. The routed profiles' wording is
/// [`ROUTED_SERVER_INSTRUCTIONS`] and [`ROUTED_QUERY_SERVER_INSTRUCTIONS`], the
/// tool-search profile's is [`SEARCH_SERVER_INSTRUCTIONS`], and the citable
/// profiles keep [`LEGACY_SERVER_INSTRUCTIONS`]. `kin agent run` builds its
/// own prompt and never reads any of them.
pub(crate) const SERVER_INSTRUCTIONS: &str = "Kin answers questions about this repository from \
its semantic graph. Work in this order:
1. Find things with semantic_locate or semantic_search first. Do not grep or list files to \
explore.
2. Use find_references and get_context_pack when relationships or surrounding context are needed.
3. Read code with get_entity_source by entity id.
4. Use available verification tools only for builds and tests.
5. Read _kin.verdict first; inconclusive means the counts are a lower bound.
If your client does not show you these tools up front and you have to search for a tool, search \
for \"kin\" first, to discover the semantic tools; that is also how you reach any Kin tool it did \
not show you.";

/// [`SERVER_INSTRUCTIONS`] for `agent-search`, which serves a measured
/// always-on set and reaches the rest through `kin_tool_search` and
/// `kin_tool_call`. The same procedure, naming only tools that profile serves
/// and saying how the one it does not, `get_entity_source`, is reached.
pub(crate) const SEARCH_SERVER_INSTRUCTIONS: &str = "Kin answers questions about this \
repository from its semantic graph. Work in this order:
1. Find things with semantic_locate first. Do not grep or list files to explore.
2. Use get_context_pack and trace_data_flow when context or call flow is needed.
3. Read code by entity id with kin_tool_call, tool get_entity_source.
4. Use available verification tools only for builds and tests.
5. Read _kin.verdict first; inconclusive means the counts are a lower bound.
kin_tool_search finds every other read-only Kin tool, and kin_tool_call runs it. If your client \
does not show you these tools up front and you have to search for a tool, search for \"kin\" \
first, to discover the semantic tools.";

/// [`SERVER_INSTRUCTIONS`] for `agent-routed`, where every command is reached
/// through the one tool [`crate::routed::TOOL_NAME`]. The founder's wording,
/// verbatim: `kin locate` is that tool called with the `locate` command.
///
/// Its last sentence is true on this profile and on no named one: `describe`
/// lists every registered tool the commands do not name, and `call` runs it.
pub(crate) const ROUTED_SERVER_INSTRUCTIONS: &str = "Kin answers questions about this repository \
from its semantic graph, through one tool, kin, called with a command and its args. Work in this \
order:
1. Find things with kin locate or kin search first. Do not grep or list files to explore.
2. Use kin refs and kin context when relationships or surrounding context are needed.
3. Read code with kin source by entity id.
4. Use available verification tools only for builds and tests.
5. Read _kin.verdict first; inconclusive means the counts are a lower bound.
If your client does not show you the kin tool up front and you have to search for a tool, search \
for \"kin\" first, to discover the semantic tools. kin describe lists every other Kin tool, and kin \
call runs any of them.";

/// [`ROUTED_SERVER_INSTRUCTIONS`] for `agent-routed-query`, which serves the
/// same commands without a write path and reaches only read-only tools.
pub(crate) const ROUTED_QUERY_SERVER_INSTRUCTIONS: &str = "Kin answers questions about this \
repository from its semantic graph, through one tool, kin, called with a command and its args. \
Work in this order:
1. Find things with kin locate or kin search first. Do not grep or list files to explore.
2. Use kin refs and kin context when relationships or surrounding context are needed.
3. Read code with kin source by entity id.
4. Use available verification tools only for builds and tests.
5. Read _kin.verdict first; inconclusive means the counts are a lower bound.
If your client does not show you the kin tool up front and you have to search for a tool, search \
for \"kin\" first, to discover the semantic tools. kin describe lists every other read-only Kin \
tool, and kin call runs any of them.";

/// Historical instructions for the benchmark profiles, with retired file catalogs
/// removed from newly built servers. Earlier measurements remain bound to their
/// original binaries; changing this served surface requires a new measurement.
pub(crate) const LEGACY_SERVER_INSTRUCTIONS: &str = "Kin answers questions about this repository \
from a semantic graph. Use these tools instead of grep or file reads for questions about \
code and dependencies. Report missing semantic coverage as a gap.
If your client does not show you these tools up front and you have to search for a tool, search \
for \"kin\" first, to discover the semantic tools; that is also how you reach a tool this connection \
did not list.
semantic_locate: find code by describing what it does, when you do not know the name.
semantic_search: find declarations by exact name, kind or language.
get_context_pack: one token-bounded bundle of the code around an entity or a question.
find_references: who calls, imports or references one entity.
trace_data_flow: the ordered call chain out from one entity.
trace_path: how one entity reaches another.
impact_analysis: what a change to one entity could affect.
graph_neighborhood: dependencies and dependents of an entity.
Every answer carries a `_kin` envelope. Read `_kin.verdict` first: when its `state` is \
`inconclusive`, treat the counts as a lower bound and do not act on an absence in the answer.";

const _: () = assert!(
    SERVER_INSTRUCTIONS.len() <= SERVER_INSTRUCTIONS_BUDGET
        && SEARCH_SERVER_INSTRUCTIONS.len() <= SERVER_INSTRUCTIONS_BUDGET
        && ROUTED_SERVER_INSTRUCTIONS.len() <= SERVER_INSTRUCTIONS_BUDGET
        && ROUTED_QUERY_SERVER_INSTRUCTIONS.len() <= SERVER_INSTRUCTIONS_BUDGET
        && LEGACY_SERVER_INSTRUCTIONS.len() <= SERVER_INSTRUCTIONS_BUDGET,
    "an instructions string is over SERVER_INSTRUCTIONS_BUDGET: a client injects it once per \
     session, and on a client that hides tool schemas it is the whole surface the model reads"
);

/// The tools [`SERVER_INSTRUCTIONS`] sends a model to, in the order it does.
pub(crate) const NAMED_PROCEDURE_TOOLS: [&str; 5] = [
    "semantic_locate",
    "semantic_search",
    "find_references",
    "get_context_pack",
    "get_entity_source",
];

/// The instructions this connection's profile is served.
pub(crate) fn instructions_for(config: &McpServerConfig) -> &'static str {
    if config.citable {
        return LEGACY_SERVER_INSTRUCTIONS;
    }
    match config.routed {
        Some(surface) if surface.writes => ROUTED_SERVER_INSTRUCTIONS,
        Some(_) => ROUTED_QUERY_SERVER_INSTRUCTIONS,
        None => {
            let allowed = config.allowed_tools.as_ref();
            let serves_the_procedure = allowed.is_none_or(|allowed| {
                NAMED_PROCEDURE_TOOLS
                    .iter()
                    .all(|tool| allowed.contains(*tool))
            });
            if !serves_the_procedure && crate::tool_invocation::enabled(allowed) {
                SEARCH_SERVER_INSTRUCTIONS
            } else {
                SERVER_INSTRUCTIONS
            }
        }
    }
}

/// The tool listing this connection is served, exactly as `tools/list` writes
/// it: the routed tool on a routed connection, and otherwise the profile's
/// filtered, annotated and compacted list, with the source tools' description
/// saying so where bodies are numbered.
///
/// One function, so a test that measures the served bytes measures what the
/// server writes to the client rather than its own copy of the recipe.
pub fn served_tools_for(config: &McpServerConfig) -> ToolsListResult {
    if let Some(surface) = config.routed {
        return crate::routed::served_list(surface);
    }
    let mut tools =
        crate::tools::served_tools_list(config.allowed_tools.as_ref(), config.agent_belt);
    if config.number_entity_lines {
        crate::entity_lines::describe_numbered_bodies(&mut tools);
    }
    tools
}

/// Present one tool's result the way this connection is served it, before the
/// envelope is attached.
///
/// Today that is one thing: an entity's source body marked with each line's
/// offset in the entity, on a connection that numbers. A connection that can
/// write through Kin keeps the exact bytes, because it restates them, and so
/// does any client that asked for them, `kin agent run` among them; the
/// benchmark profiles keep their payload bytes because those are an input to a
/// citable result.
fn present_result(config: &McpServerConfig, tool: &str, result: &mut ToolCallResult) {
    if config.number_entity_lines && crate::entity_lines::numbers_this_tool(tool) {
        crate::entity_lines::number_entity_body(result);
    }
}

fn handle_initialize(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    // Check if the client requests a newer protocol version than we support.
    // We respond with our supported version and include a warning — we never
    // error, to remain forward-compatible.
    let client_version = params
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or(SUPPORTED_PROTOCOL_VERSION);

    let mut result = serde_json::to_value(&InitializeResult {
        protocol_version: SUPPORTED_PROTOCOL_VERSION.into(),
        capabilities: ServerCapabilities {
            tools: ToolsCapability {
                list_changed: false,
            },
        },
        server_info: ServerInfo {
            name: config.server_name.clone(),
            version: config.server_version.clone(),
        },
        instructions: Some(instructions_for(config).into()),
    })
    .unwrap_or_default();

    // Add kinVersion to serverInfo for Kin-aware clients.
    if let Some(info) = result.get_mut("serverInfo") {
        info["kinVersion"] = serde_json::json!(config.server_version);
    }

    // Warn if client requested a newer protocol version.
    if client_version != SUPPORTED_PROTOCOL_VERSION {
        result["_warning"] = serde_json::json!(format!(
            "client requested protocol version '{}', server supports '{}'; \
             falling back to server version",
            client_version, SUPPORTED_PROTOCOL_VERSION
        ));
    }

    JsonRpcResponse::success(id, result)
}

fn handle_tools_list(id: Option<serde_json::Value>, config: &McpServerConfig) -> JsonRpcResponse {
    let tools = served_tools_for(config);
    JsonRpcResponse::success(id, serde_json::to_value(&tools).unwrap_or_default())
}

async fn handle_tools_call<G: PersistableMcpStore>(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    store: &G,
    sessions: &SessionRegistry,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    let mut call_params: ToolCallParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(id, -32602, format!("Invalid params: {}", e));
        }
    };
    // A routed call becomes the named call it stands for before anything reads
    // its name, so everything below, the dispatcher and the envelope included,
    // treats it as that named call. `describe` and a call that did not validate
    // are answered here, through the same envelope.
    let routed_call = match crate::routed::route(&mut call_params, config.routed) {
        crate::routed::Routing::Answer(result) => {
            let budget = ResponseBudget::from_arguments(&call_params.arguments);
            return offline_envelope_success(id, result, crate::routed::TOOL_NAME, &budget);
        }
        crate::routed::Routing::Dispatch => true,
        crate::routed::Routing::NotRouted => false,
    };
    let mut response =
        dispatch_tools_call(id, &mut call_params, routed_call, store, sessions, config).await;
    if routed_call {
        present_routed_hints(&mut response, &call_params);
    }
    response
}

/// The offline route from a named call to its enveloped answer.
async fn dispatch_tools_call<G: PersistableMcpStore>(
    id: Option<serde_json::Value>,
    call_params: &mut ToolCallParams,
    routed_call: bool,
    store: &G,
    sessions: &SessionRegistry,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    // A routed connection's dispatcher is the routed tool, so the discovery
    // dispatcher is answered as the named call it is, with the refusal that
    // names the routed command.
    let discovered_call = if config.routed.is_some() {
        false
    } else {
        match crate::tool_invocation::expand(call_params, config.allowed_tools.as_ref()) {
            Ok(value) => value,
            Err(error) => return JsonRpcResponse::error(id, -32602, error.to_string()),
        }
    };
    // Resolve the served name to the registered one here, once, before anything
    // keyed on a tool name reads it: the profile filter below, the dispatcher,
    // the response-budget shape, the negative-evidence spec and the envelope.
    // `agent-default` served the declaration filter as `find_declarations` for
    // four landings, so that name is still accepted here; every profile now
    // advertises the registered name, and everything internal stays keyed on it.
    crate::agent_belt::canonicalize_tool_name(&mut call_params.name);
    // Refuse before forwarding too: an older daemon must not restore retired
    // file operations on an unfiltered connection.
    if let Some(message) = crate::tools::retired_file_operation(&call_params.name) {
        return JsonRpcResponse::error(id, -32602, message.into());
    }
    // The belt asks for the compact locate shape on its agents' behalf, only
    // when the caller named no surface. Applied here rather than in the daemon
    // because this is the one layer that knows which profile is being served.
    if config.agent_belt {
        crate::agent_belt::apply_belt_defaults(&call_params.name, &mut call_params.arguments);
    }
    let budget = ResponseBudget::from_arguments(&call_params.arguments);

    if let Some(allowed) = &config.allowed_tools {
        if !discovered_call && !routed_call && !allowed.contains(&call_params.name) {
            let error_result = not_enabled_refusal(config, &call_params.name);
            return offline_envelope_success(id, error_result, &call_params.name, &budget);
        }
    }

    // The "at least one of" rules the served schemas no longer carry: every
    // served schema is a plain object, because provider tool APIs drop a tool
    // whose schema opens with a combinator. Refused here, before anything
    // runs, with one call that works.
    if let Some(refusal) = crate::input_contract::refusal(&call_params.name, &call_params.arguments)
    {
        return offline_envelope_success(id, refusal, &call_params.name, &budget);
    }

    if call_params.name == crate::handlers::tool_search::TOOL_NAME {
        let result = crate::handlers::tool_search::handle_tool_search_with_profile(
            &call_params.arguments,
            config.allowed_tools.as_ref(),
        )
        .unwrap_or_else(|error| ToolCallResult::error(error.to_string()));
        return offline_envelope_success(id, result, &call_params.name, &budget);
    }

    // Nor a session workspace to run a command in. A command that would be
    // refused anywhere is still refused as it is on the daemon route.
    if call_params.name == crate::session_exec::TOOL_NAME {
        return offline_envelope_success(
            id,
            crate::session_exec::handle_with(
                &call_params.arguments,
                None,
                if routed_call {
                    crate::session_exec::CallForm::Routed
                } else {
                    crate::session_exec::CallForm::Named
                },
            )
            .await,
            &call_params.name,
            &budget,
        );
    }

    // This runtime serves a store, not a repository, so there is no folder here
    // for `kin_init` to set up.
    if call_params.name == crate::repository_init::TOOL_NAME {
        return offline_envelope_success(
            id,
            crate::repository_init::unavailable_answer(crate::first_contact::Spelling::here()),
            &call_params.name,
            &budget,
        );
    }

    let mut handler = std::pin::pin!(handle_tool_call(
        &call_params.name,
        &call_params.arguments,
        store,
        sessions,
        config.session_authority_mode,
        config.repository_authority.as_ref(),
        // No working copy on this route, and none is supposed to be here. It is
        // the explicit offline runtime, which serves a store rather than a
        // repository a daemon watches, and `kin mcp start` reaches the daemon
        // route instead (`session_authority_mode` is `DaemonRequired` there). A
        // probe built from this process's own working directory would be a
        // second, weaker guess at a repository this route never bound. So the
        // standing is `NotApplicable` rather than `Unchecked`: there is no disk
        // here that graph truth could be behind, which is a different fact from
        // a checkout nothing is watching.
        crate::working_copy::WorkingCopySurface::NotApplicable,
    ));
    let outcome = std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::future::Future::poll(handler.as_mut(), cx)
        })) {
            Ok(poll) => poll.map(Ok),
            Err(panic) => std::task::Poll::Ready(Err(panic)),
        }
    })
    .await;

    let call_result = match outcome {
        Ok(call_result) => call_result,
        Err(panic) => {
            let detail = panic
                .downcast_ref::<&str>()
                .map(|message| (*message).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "tool handler panicked".to_string());
            return JsonRpcResponse::error(
                id,
                -32603,
                format!(
                    "Internal error: tool '{}' panicked: {detail}",
                    call_params.name
                ),
            );
        }
    };

    match call_result {
        Ok(mut result) => {
            present_result(config, &call_params.name, &mut result);
            if tool_requires_persist(&call_params.name) {
                if let Err(error) = store.persist_primary_snapshot(config.snapshot_path.as_deref())
                {
                    let error_result = ToolCallResult::error(format!(
                        "tool succeeded but snapshot persistence failed: {error}"
                    ));
                    return offline_envelope_success(id, error_result, &call_params.name, &budget);
                }
            }
            offline_envelope_success(id, result, &call_params.name, &budget)
        }
        Err(e) => offline_envelope_success(
            id,
            ToolCallResult::error(e.to_string()),
            &call_params.name,
            &budget,
        ),
    }
}

/// The refusal a call to a tool this profile does not serve gets. On a routed
/// connection it names the routed command that runs the tool there.
fn not_enabled_refusal(config: &McpServerConfig, tool: &str) -> ToolCallResult {
    match config.routed {
        Some(surface) => crate::routed::refuse_named_call(tool, surface),
        None => ToolCallResult::error(format!("tool '{tool}' is not enabled in this MCP profile")),
    }
}

/// Present a routed call's finished answer with its hints naming the routed
/// commands that reach what they name, inside the budget the call was bounded
/// to. Authority and budget-cut disclosures stay exactly as the named answer
/// carries them. Only the existing final byte/token counters follow the new
/// spelling; a spelling that cannot fit keeps the original qualified answer.
fn present_routed_hints(response: &mut JsonRpcResponse, call_params: &ToolCallParams) {
    let Some(value) = response.result.as_ref() else {
        return;
    };
    let Ok(mut result) = serde_json::from_value::<ToolCallResult>(value.clone()) else {
        return;
    };
    let budget = ResponseBudget::from_arguments(&call_params.arguments);
    let original = result.clone();
    crate::routed::rewrite_hints(&mut result, budget.max_chars);
    for (block, original_block) in result.content.iter_mut().zip(&original.content) {
        let ContentBlock::Text { text } = block;
        let ContentBlock::Text {
            text: original_text,
        } = original_block;
        if text == original_text {
            continue;
        }
        // A soft-budget residual already discloses an over-budget answer.
        // Presentation must not silently change that standing fact or trim
        // the evidence which required it. Keep that answer intact.
        let fitted = (original_text.len() <= budget.max_chars)
            .then(|| fit_routed_hint_accounting(text, &call_params.name, &budget))
            .flatten();
        *text = fitted.unwrap_or_else(|| original_text.clone());
    }
    if let Ok(presented) = serde_json::to_value(&result) {
        response.result = Some(presented);
    }
}

/// Settle only already-present accounting after hint presentation. This is not
/// another envelope pass: no authority, verdict, absence, cuts or payload facts
/// are recomputed. The context limit is the payload's effective tier, which may
/// be higher than the caller's requested tier. Failure keeps the original text.
fn fit_routed_hint_accounting(text: &str, tool: &str, budget: &ResponseBudget) -> Option<String> {
    let Ok(mut payload) = serde_json::from_str::<serde_json::Value>(text) else {
        return (text.len() <= budget.max_chars).then(|| text.to_string());
    };
    let bytes_pointer = "/_kin/response/chars_after_budget";
    let carries_bytes = match payload.pointer(bytes_pointer) {
        Some(value) => {
            value.as_u64()?;
            true
        }
        None => false,
    };
    let context = matches!(tool, "get_context_pack" | "trace_computation");
    let token_limit = if context {
        match payload.get("token_budget") {
            Some(value) => Some(value.as_u64()?),
            None => None,
        }
    } else {
        None
    };
    let carries_tokens = context && payload.get("tokens_used").is_some();
    if carries_tokens {
        payload.get("tokens_used")?.as_u64()?;
        token_limit?;
    }
    let pretty = text.starts_with("{\n");
    for _ in 0..16 {
        let rendered = if pretty {
            serde_json::to_string_pretty(&payload).ok()?
        } else {
            serde_json::to_string(&payload).ok()?
        };
        let bytes = rendered.len() as u64;
        let tokens = kin_context::estimate_tokens(&rendered) as u64;
        let bytes_match = !carries_bytes || payload.pointer(bytes_pointer)?.as_u64() == Some(bytes);
        let tokens_match = !carries_tokens || payload.get("tokens_used")?.as_u64() == Some(tokens);
        if bytes_match && tokens_match {
            return (rendered.len() <= budget.max_chars
                && token_limit.is_none_or(|limit| tokens <= limit))
            .then_some(rendered);
        }
        if carries_bytes {
            *payload.pointer_mut(bytes_pointer)? = serde_json::json!(bytes);
        }
        if carries_tokens {
            *payload.get_mut("tokens_used")? = serde_json::json!(tokens);
        }
    }
    None
}

/// Attach the offline/in-process response envelope and wrap the result as a
/// JSON-RPC success. The in-process path is the explicit offline runtime, so the
/// envelope honestly flags `offline_fallback` (not daemon-owned truth). The tool
/// name lets `finalize` synthesize the confidence-qualified negative for empty
/// retrieval results on this path too.
fn offline_envelope_success(
    id: Option<serde_json::Value>,
    result: ToolCallResult,
    tool_name: &str,
    budget: &ResponseBudget,
) -> JsonRpcResponse {
    let enveloped = envelope::finalize_bounded(result, Envelope::offline(), tool_name, budget);
    JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default())
}

async fn handle_tools_call_daemon(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    let mut call_params: ToolCallParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(id, -32602, format!("Invalid params: {}", e));
        }
    };
    // A routed call becomes the named call it stands for before anything reads
    // its name, so it is forwarded to the daemon as that named call and the
    // daemon never learns a routed tool exists. `describe` and a call that did
    // not validate read no graph and are answered here, through the same
    // envelope the tool registry is.
    let routed_call = match crate::routed::route(&mut call_params, config.routed) {
        crate::routed::Routing::Answer(result) => {
            let budget = ResponseBudget::from_arguments(&call_params.arguments);
            let enveloped = envelope::finalize_bounded(
                result,
                Envelope::daemon(),
                crate::routed::TOOL_NAME,
                &budget,
            );
            return JsonRpcResponse::success(
                id,
                serde_json::to_value(&enveloped).unwrap_or_default(),
            );
        }
        crate::routed::Routing::Dispatch => true,
        crate::routed::Routing::NotRouted => false,
    };
    let mut response = forward_tools_call(id, &mut call_params, routed_call, config).await;
    if routed_call {
        present_routed_hints(&mut response, &call_params);
    }
    response
}

/// The daemon route from a named call to its enveloped answer.
async fn forward_tools_call(
    id: Option<serde_json::Value>,
    call_params: &mut ToolCallParams,
    routed_call: bool,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    // See `dispatch_tools_call`: on a routed connection the routed tool is the
    // dispatcher.
    let discovered_call = if config.routed.is_some() {
        false
    } else {
        match crate::tool_invocation::expand(call_params, config.allowed_tools.as_ref()) {
            Ok(value) => value,
            Err(error) => return JsonRpcResponse::error(id, -32602, error.to_string()),
        }
    };
    // Resolve the served name to the registered one here, once, before anything
    // keyed on a tool name reads it: the profile filter below, the dispatcher,
    // the response-budget shape, the negative-evidence spec and the envelope.
    // `agent-default` served the declaration filter as `find_declarations` for
    // four landings, so that name is still accepted here; every profile now
    // advertises the registered name, and everything internal stays keyed on it.
    crate::agent_belt::canonicalize_tool_name(&mut call_params.name);
    // Refuse before forwarding too: an older daemon must not restore retired
    // file operations on an unfiltered connection.
    if let Some(message) = crate::tools::retired_file_operation(&call_params.name) {
        return JsonRpcResponse::error(id, -32602, message.into());
    }
    // The belt asks for the compact locate shape on its agents' behalf, only
    // when the caller named no surface. Applied here rather than in the daemon
    // because this is the one layer that knows which profile is being served.
    if config.agent_belt {
        crate::agent_belt::apply_belt_defaults(&call_params.name, &mut call_params.arguments);
    }
    let budget = ResponseBudget::from_arguments(&call_params.arguments);

    if let Some(allowed) = &config.allowed_tools {
        if !discovered_call && !routed_call && !allowed.contains(&call_params.name) {
            let error_result = not_enabled_refusal(config, &call_params.name);
            let enveloped = envelope::finalize_bounded(
                error_result,
                Envelope::daemon(),
                &call_params.name,
                &budget,
            );
            return JsonRpcResponse::success(
                id,
                serde_json::to_value(&enveloped).unwrap_or_default(),
            );
        }
    }

    // See `dispatch_tools_call`: the rules the plain served schemas no longer
    // carry are refused here, before the daemon is asked anything. Not in the
    // handlers, which the daemon also calls with arguments it has rewritten.
    if let Some(refusal) = crate::input_contract::refusal(&call_params.name, &call_params.arguments)
    {
        let enveloped =
            envelope::finalize_bounded(refusal, Envelope::daemon(), &call_params.name, &budget);
        return JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default());
    }

    // The tool registry is answered here rather than forwarded. It is the
    // registry compiled into THIS binary, which is what `tools/list` on this
    // server is built from, so a daemon on a different build would hand an agent
    // a schema this server cannot dispatch. The answer reads no graph, so there
    // is nothing the daemon could add. The envelope is the daemon one because on
    // this route the SERVER is daemon-backed, which is what `runtime` reports;
    // `Envelope::daemon_unreachable` keeps the same value for the same reason.
    if call_params.name == crate::handlers::tool_search::TOOL_NAME {
        let result = crate::handlers::tool_search::handle_tool_search_with_profile(
            &call_params.arguments,
            config.allowed_tools.as_ref(),
        )
        .unwrap_or_else(|error| ToolCallResult::error(error.to_string()));
        let enveloped =
            envelope::finalize_bounded(result, Envelope::daemon(), &call_params.name, &budget);
        return JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default());
    }

    // `kin_init` is answered by the stdio loop, which holds the client's folder
    // and the binder. A call that reaches this handler another way has no
    // folder to set up, and is told where the command is answered.
    if call_params.name == crate::repository_init::TOOL_NAME {
        let enveloped = envelope::finalize_bounded(
            crate::repository_init::unavailable_answer(crate::first_contact::Spelling::here()),
            Envelope::daemon(),
            &call_params.name,
            &budget,
        );
        return JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default());
    }

    // A toolchain run is answered here, by the executor the launcher
    // installed: it materializes a session workspace through this daemon, runs
    // the command locally and hands the write-back to the daemon's reconcile
    // boundary. The daemon never runs a command itself.
    if call_params.name == crate::session_exec::TOOL_NAME {
        let form = if routed_call {
            crate::session_exec::CallForm::Routed
        } else {
            crate::session_exec::CallForm::Named
        };
        let result = crate::session_exec::handle(&call_params.arguments, form).await;
        let enveloped =
            envelope::finalize_bounded(result, Envelope::daemon(), &call_params.name, &budget);
        return JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default());
    }

    // The one-shot adapter preserves the existing unkeyed begin/commit path.
    // Keyed requests travel intact under a versioned internal name so an old
    // daemon refuses the durable contract before any transaction is started.
    if call_params.name == "kin_mutate" {
        let result = crate::handlers::sessions::mutate_through_daemon(&call_params.arguments)
            .await
            .unwrap_or_else(|error| ToolCallResult::error(error.to_string()));
        let enveloped =
            envelope::finalize_bounded(result, Envelope::daemon(), &call_params.name, &budget);
        return JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default());
    }

    // Graph status carries its own selected-graph coverage observation. Mark
    // the beginning before forwarding so a refusal published during the call
    // cannot be discharged by counters that may have preceded it.
    let graph_status_observation_started_at_unix =
        (call_params.name == "kin_graph_status").then(daemon_delegate::current_unix_seconds);
    let (mut result, mut base_env) =
        match daemon_delegate::forward_tool_call(&call_params.name, &call_params.arguments).await {
            Ok(Some(result)) => (result, Envelope::daemon()),
            // Which gap it was decides the envelope: a working directory that is no
            // repository has no daemon to be unreachable.
            Ok(None) => {
                daemon_delegate::daemon_unavailable_tool_result(
                    &call_params.name,
                    config.serves_init(),
                )
                .await
            }
            Err(error) => {
                let base = envelope_for_delegate_error(
                    &error,
                    daemon_delegate::recorded_daemon_kill().as_ref(),
                );
                (ToolCallResult::error(error), base)
            }
        };
    present_result(config, &call_params.name, &mut result);

    // Stamped on every answer, not only on the ones that failed. A suspended
    // sweep is a standing fact about what this store's graph can contain, so
    // the call it changes the reading of is the one that SUCCEEDS and returns
    // nothing: an agent certifying that absence needs to know the producer that
    // would have filled it is switched off.
    base_env = base_env.with_suspended_sweep(daemon_delegate::suspended_sweep().as_ref());
    // Stamped for the same reason and on the same calls. Work Kin declined
    // because the machine had no room is work no producer is doing, and the
    // answer it changes the reading of is the one that succeeds and returns
    // nothing. Generic tools reconcile an embedding refusal against the exact
    // selected-graph coverage returned by `/commands/resources`. Graph status
    // is handled below from the typed report it returns, so it never mixes two
    // independently sampled graph observations.
    if call_params.name != "kin_graph_status" {
        let pressure_refusal =
            daemon_delegate::outstanding_memory_pressure_refusal(&call_params.arguments).await;
        base_env = base_env.with_memory_pressure(pressure_refusal.as_ref());
    }
    // Stamped on every answer for the same reason, and it is the one of the
    // three that qualifies an answer which came back looking complete. A graph
    // short of its own last verified-good census returns rows that are all true
    // and a set that is not whole, and nothing in the payload can tell the two
    // apart.
    base_env = base_env.with_relation_census_loss(daemon_delegate::relation_census_hold().as_ref());
    // Stamped on every answer because a replay-version gap qualifies a graph
    // that otherwise looks complete. Historical deltas are not re-derived in
    // place, so the answer affected most is a successful absence whose missing
    // row may reflect replay semantics the store cannot show match this build.
    base_env = base_env.with_hydration_semantics_observation(
        daemon_delegate::hydration_semantics_standing().as_ref(),
    );
    // Stamped on every answer for the same reason as the three above, and it
    // qualifies the same kind of answer the census-loss flag does: one that came
    // back looking complete. A sweep that offered relations the graph does not
    // hold leaves an absence an agent may certify, and nothing in the payload
    // distinguishes it from an absence that is simply true.
    base_env = base_env.with_enrichment_shortfall(daemon_delegate::enrichment_shortfall().as_ref());

    // `kin_graph_status` already reports the exact graph view selected by the
    // daemon, including temporal-session scope. Generic `/health` is HEAD-only:
    // borrowing its entity count or generation here would mix two authorities
    // in one response. Build the standard `_kin` envelope from the report
    // itself and validate the fully annotated stdio payload instead.
    // Enrich the envelope with honest degraded/freshness signals from the daemon
    // `/health` body when the daemon is actually reachable. When it was already
    // determined unreachable, skip the probe — there is nothing to ask.
    //
    // Fetched before the graph-status branch below, not after it. That branch
    // used to return first and so never reached this probe at all, which took
    // the working-copy reading away from it along with the counts it is right to
    // refuse, and left it publishing "0 uncommitted" over a repository holding a
    // module the graph had never met (FIR-2820).
    let health = if base_env.degraded.daemon_unreachable == Some(true)
        || base_env.degraded.no_repository == Some(true)
    {
        None
    } else {
        daemon_delegate::fetch_health_snapshot().await
    };

    if call_params.name == "kin_graph_status" {
        // Two narrow lifts off the one health probe above, and nothing else
        // from it. Vector persistence is a property of this daemon's storage
        // backend rather than a HEAD graph observation, and the working-copy
        // reading is a fact about the disk rather than about the selected
        // graph; selected-graph finalization below still replaces every graph
        // field from the report itself.
        if let Some(health) = health.as_ref() {
            base_env = base_env.with_repository(
                health,
                config.client_root.as_deref(),
                config.canonicalize,
            );
            base_env = base_env.with_working_copy_health(health);
            // The third lift: which daemon answered, and how long it had been up.
            // A status read from a daemon that began serving a moment ago is the
            // answer most in need of saying so.
            base_env = base_env.with_answering_daemon(health);
            if let Some(unavailable) = health
                .get("embed_persistence_unavailable")
                .and_then(serde_json::Value::as_bool)
            {
                base_env = base_env.with_embed_persistence_unavailable(unavailable);
            }
        }
        let pressure_refusals = daemon_delegate::recorded_memory_pressure_refusals();
        let enveloped = finalize_daemon_graph_status(
            result,
            base_env,
            &pressure_refusals,
            graph_status_observation_started_at_unix
                .expect("graph status records its observation start before forwarding"),
        );
        return JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default());
    }

    if let Some(health) = health.as_ref() {
        base_env = base_env.with_health(health);
        base_env =
            base_env.with_repository(health, config.client_root.as_deref(), config.canonicalize);
    }

    let enveloped = envelope::finalize_bounded(result, base_env, &call_params.name, &budget);
    JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default())
}

/// The envelope for a delegate error, from the error itself.
///
/// A delegate error that ends with the daemon gone is exactly the condition
/// `daemon_unreachable` exists to state, and it was the one shape that never
/// set it: the flag was reserved for the case where no daemon endpoint was
/// resolved at all, so a session whose daemon was killed under it received an
/// empty `degraded` object, which a client cannot tell from a healthy answer
/// without parsing prose. Where the store has recorded why its daemons keep
/// dying, that is stamped beside it.
///
/// Every other delegate error is left alone. A live daemon rejecting a bad
/// argument has not become unreachable, and a store's kill history is not a
/// fact about that call.
fn envelope_for_delegate_error(
    error: &str,
    record: Option<&kin_daemon_spawn::DaemonKillRecord>,
) -> Envelope {
    if daemon_delegate::is_daemon_loss_error(error) {
        Envelope::daemon_unreachable().with_recorded_daemon_kill(record)
    } else {
        Envelope::daemon()
    }
}

fn finalize_daemon_graph_status(
    result: ToolCallResult,
    base_env: Envelope,
    pressure_refusals: &[kin_core::memory_pressure::PressureRefusal],
    observation_started_at_unix: u64,
) -> ToolCallResult {
    let unobserved_pressure_refusal = pressure_refusals.last();
    let mut report = match daemon_delegate::parse_graph_status_report(&result) {
        Ok(Some(report)) => report,
        Ok(None) => {
            return envelope::finalize(
                result,
                base_env.with_memory_pressure(unobserved_pressure_refusal),
                "kin_graph_status",
            );
        }
        Err(error) => {
            return envelope::finalize(
                ToolCallResult::error(error),
                base_env.with_memory_pressure(unobserved_pressure_refusal),
                "kin_graph_status",
            );
        }
    };

    let embedding_coverage = kin_core::memory_pressure::EmbeddingCoverage {
        pending: report.embeddings_pending,
        indexed: report.embeddings_indexed,
        total: report.embeddings_total,
    };
    let pressure_refusal = daemon_delegate::pressure_refusal_for_selected_graph(
        pressure_refusals,
        embedding_coverage,
        observation_started_at_unix,
    );

    let counts = (
        u64::try_from(report.entity_count),
        u64::try_from(report.embeddings_indexed),
        u64::try_from(report.embeddings_pending),
        u64::try_from(report.embeddings_total),
        u64::try_from(report.relation_count),
    );
    let (Ok(entity_count), Ok(indexed), Ok(pending), Ok(total), Ok(relation_count)) = counts else {
        return envelope::finalize(
            ToolCallResult::error(
                "daemon kin_graph_status counters do not fit the stdio response envelope",
            ),
            base_env.with_memory_pressure(pressure_refusal.as_ref()),
            "kin_graph_status",
        );
    };

    // A daemon owns the selected-graph report, but the stdio boundary owns
    // `_kin`. Rebuild the successful result from the strict typed report after
    // stripping any daemon-supplied envelope, so generic annotation cannot
    // preserve additive or unscoped metadata from a drifted daemon.
    report.response_envelope = None;
    let result = match serde_json::to_string_pretty(&report) {
        Ok(text) => ToolCallResult::text(text),
        Err(error) => {
            return envelope::finalize(
                ToolCallResult::error(format!(
                    "stdio kin_graph_status could not serialize the validated daemon report: \
                     {error}"
                )),
                base_env.with_memory_pressure(pressure_refusal.as_ref()),
                "kin_graph_status",
            );
        }
    };
    let mut selected_env = base_env
        .with_selected_graph_observation(
            envelope::DurabilityCounts {
                live_entities: entity_count,
                durable_entities: report.durable_entity_count,
                live_relations: Some(relation_count),
                durable_relations: report.durable_relation_count,
            },
            indexed,
            pending,
            total,
        )
        .with_memory_pressure(pressure_refusal.as_ref());
    if let Some(stale) = report.stale.as_ref() {
        selected_env = selected_env.with_selected_graph_staleness(
            stale.reason.as_str(),
            stale.settled_age_ms,
            stale.observed_authority_epoch,
            stale.live_attempts,
        );
    }
    let enveloped = envelope::finalize(result, selected_env, "kin_graph_status");
    if let Err(error) = daemon_delegate::parse_graph_status_report(&enveloped) {
        return envelope::finalize(
            ToolCallResult::error(format!(
                "stdio kin_graph_status contract validation failed after envelope annotation: \
                 {error}"
            )),
            Envelope::daemon(),
            "kin_graph_status",
        );
    }
    enveloped
}

fn tool_requires_persist(name: &str) -> bool {
    crate::handlers::review::is_review_mutation(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ENVELOPE_KEY, ENVELOPE_VERSION};
    use kin_db::InMemoryGraph;

    /// Run a `tools/call` through the real in-process chokepoint and return the
    /// parsed tool payload (the JSON inside the single text content block).
    async fn call_tool_payload(tool: &str, arguments: serde_json::Value) -> serde_json::Value {
        let mut config = McpServerConfig::default();
        config.session_authority_mode = SessionAuthorityMode::OfflineFallback;
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        })
        .to_string();
        let resp = process_message(&msg, &store, &config, &sessions)
            .await
            .expect("response");
        assert!(resp.error.is_none(), "transport error for {tool}");
        let result: ToolCallResult =
            serde_json::from_value(resp.result.expect("result")).expect("tool call result");
        let ContentBlock::Text { text } = result.content.first().expect("one content block");
        serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("envelope-annotated payload for {tool} is not JSON: {e}"))
    }

    /// Assert the offline envelope is present and well-formed on a payload.
    fn assert_offline_envelope(payload: &serde_json::Value, tool: &str) {
        let env = payload
            .get(ENVELOPE_KEY)
            .unwrap_or_else(|| panic!("tool {tool} response is missing the _kin envelope"));
        assert_eq!(
            env["envelope_version"], ENVELOPE_VERSION,
            "tool {tool} envelope version"
        );
        assert_eq!(
            env["runtime"], "offline-in-process",
            "tool {tool} runtime should report the in-process fallback"
        );
        // Honesty: the offline path flags itself as a non-daemon fallback.
        assert_eq!(env["degraded"]["offline_fallback"], true, "tool {tool}");
    }

    async fn offline_review_call(
        store: &InMemoryGraph,
        config: &McpServerConfig,
        tool: &str,
        arguments: serde_json::Value,
    ) -> ToolCallResult {
        let message = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        })
        .to_string();
        let response = process_message(&message, store, config, &SessionRegistry::new())
            .await
            .unwrap();
        assert!(response.error.is_none(), "{response:?}");
        serde_json::from_value(response.result.unwrap()).unwrap()
    }

    fn review_payload(result: &ToolCallResult) -> serde_json::Value {
        let ContentBlock::Text { text } = &result.content[0];
        serde_json::from_str(text).unwrap()
    }

    fn assigned_reviewers(store: &InMemoryGraph, review: &kin_model::ReviewId) -> Vec<String> {
        let mut names: Vec<_> = kin_review::assignments::current_assignments(store, review)
            .unwrap()
            .into_iter()
            .map(|assignment| assignment.reviewer.name)
            .collect();
        names.sort();
        names
    }

    /// A named call that breaks an "at least one of" rule the plain served
    /// schema no longer carries is refused by the server on both call routes,
    /// before anything runs: offline, and on the daemon route with no daemon
    /// to reach at all.
    #[tokio::test]
    async fn both_call_routes_refuse_a_call_missing_every_alternative() {
        let message = |tool: &str, arguments: serde_json::Value| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": tool, "arguments": arguments }
            })
            .to_string()
        };
        let refused_text = |response: JsonRpcResponse| -> serde_json::Value {
            assert!(response.error.is_none(), "{response:?}");
            let result: ToolCallResult = serde_json::from_value(response.result.unwrap()).unwrap();
            assert_eq!(result.is_error, Some(true), "{result:?}");
            let ContentBlock::Text { text } = &result.content[0];
            serde_json::from_str(text).unwrap()
        };
        let offline = McpServerConfig {
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            ..Default::default()
        };
        let daemon = McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(
                crate::tools::agent_default_tool_names(),
            )),
            agent_belt: true,
            ..Default::default()
        };
        let store = InMemoryGraph::new();
        for (tool, arguments, needs) in [
            (
                "semantic_locate",
                serde_json::json!({"limit": 3}),
                "query or cursor",
            ),
            (
                "get_context_pack",
                serde_json::json!({"depth": 1}),
                "entity_id or entities or question",
            ),
            (
                crate::handlers::lexical::TOOL_NAME,
                serde_json::json!({"kind": "function"}),
                "literal or cursor",
            ),
        ] {
            let answers = [
                refused_text(
                    process_message(
                        &message(tool, arguments.clone()),
                        &store,
                        &offline,
                        &SessionRegistry::new(),
                    )
                    .await
                    .unwrap(),
                ),
                refused_text(
                    process_daemon_message(&message(tool, arguments.clone()), &daemon)
                        .await
                        .unwrap(),
                ),
            ];
            for answer in answers {
                assert!(
                    answer["message"].as_str().unwrap().contains(needs),
                    "{tool}: {answer}"
                );
                assert_eq!(answer["example"]["name"], tool);
            }
        }
        // The review rules hold on the offline route, which serves them.
        for (tool, arguments) in [
            ("kin_review_create", serde_json::json!({"title": "t"})),
            (
                "kin_review_create",
                serde_json::json!({"title": "t", "base": "working-tree"}),
            ),
            (
                "kin_review_assign",
                serde_json::json!({"review_id": "r", "requested_reviewers": ["a"]}),
            ),
        ] {
            let answer = refused_text(
                process_message(
                    &message(tool, arguments.clone()),
                    &store,
                    &offline,
                    &SessionRegistry::new(),
                )
                .await
                .unwrap(),
            );
            assert_eq!(
                answer["error"], "missing_arguments",
                "{tool} {arguments}: {answer}"
            );
        }
    }

    #[tokio::test]
    async fn offline_review_unassign_survives_snapshot_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = dir.path().join("graph.kindb");
        let config = McpServerConfig {
            snapshot_path: Some(snapshot.clone()),
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            allowed_tools: None,
            ..Default::default()
        };
        let store = InMemoryGraph::new();
        let created = offline_review_call(
            &store,
            &config,
            "kin_review_create",
            // base and head as the handler would default them, which the
            // create call's "at least one of" rule asks the caller to name.
            serde_json::json!({"title":"Persist assignments", "base":"working-tree",
                "head":"working-tree", "reviewers":["Alice", "Bob"]}),
        )
        .await;
        assert_ne!(created.is_error, Some(true), "{created:?}");
        let review = kin_model::ReviewId(
            uuid::Uuid::parse_str(review_payload(&created)["review_id"].as_str().unwrap()).unwrap(),
        );
        let original = kin_db::SnapshotManager::open_without_text_index(&snapshot).unwrap();
        assert_eq!(
            assigned_reviewers(original.graph().as_ref(), &review),
            vec!["Alice", "Bob"]
        );
        drop(original);
        for _ in 0..2 {
            let result = offline_review_call(
                &store,
                &config,
                "kin_review_unassign",
                serde_json::json!({"review_id":review.to_string(), "reviewer":"Alice"}),
            )
            .await;
            assert_ne!(result.is_error, Some(true), "{result:?}");
            assert_eq!(review_payload(&result)["unassigned"], true);
            assert_eq!(assigned_reviewers(&store, &review), vec!["Bob"]);
            let reopened = kin_db::SnapshotManager::open_without_text_index(&snapshot).unwrap();
            assert_eq!(
                assigned_reviewers(reopened.graph().as_ref(), &review),
                vec!["Bob"],
                "a successful unassign must survive reopening the configured snapshot"
            );
        }
    }

    #[tokio::test]
    async fn offline_review_unassign_reports_snapshot_failure() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = dir.path().join("graph.kindb");
        let mut config = McpServerConfig {
            snapshot_path: Some(snapshot.clone()),
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            allowed_tools: None,
            ..Default::default()
        };
        let store = InMemoryGraph::new();
        let created = offline_review_call(
            &store,
            &config,
            "kin_review_create",
            serde_json::json!({"title":"Refuse false durable success", "base":"working-tree",
                "head":"working-tree", "reviewers":["Alice"]}),
        )
        .await;
        assert_ne!(created.is_error, Some(true), "{created:?}");
        let review = kin_model::ReviewId(
            uuid::Uuid::parse_str(review_payload(&created)["review_id"].as_str().unwrap()).unwrap(),
        );
        let blocked_parent = dir.path().join("not-a-directory");
        std::fs::write(&blocked_parent, b"owned fixture").unwrap();
        config.snapshot_path = Some(blocked_parent.join("graph.kindb"));
        let result = offline_review_call(
            &store,
            &config,
            "kin_review_unassign",
            serde_json::json!({"review_id":review.to_string(), "reviewer":"Alice"}),
        )
        .await;
        assert_eq!(result.is_error, Some(true), "{result:?}");
        assert!(review_payload(&result)["message"]
            .as_str()
            .unwrap()
            .contains("snapshot persistence failed"));
        // The existing offline contract applies in memory before persistence.
        // Failure must disclose this, not claim rollback or durable success.
        assert!(assigned_reviewers(&store, &review).is_empty());
        let reopened = kin_db::SnapshotManager::open_without_text_index(&snapshot).unwrap();
        assert_eq!(
            assigned_reviewers(reopened.graph().as_ref(), &review),
            vec!["Alice"]
        );
    }

    // ── D.8: every tool family carries the unified response envelope ──────────

    #[tokio::test]
    async fn envelope_present_on_entities_family() {
        // semantic_search returns an object payload; the envelope must ride
        // alongside the original `results` key without displacing it.
        let payload =
            call_tool_payload("semantic_search", serde_json::json!({ "query": "foo" })).await;
        assert_offline_envelope(&payload, "semantic_search");
        assert!(
            payload.get("results").is_some(),
            "semantic_search payload must keep its `results` key where agents expect it"
        );
    }

    #[tokio::test]
    async fn envelope_present_on_work_family() {
        let payload = call_tool_payload("kin_work_list", serde_json::json!({})).await;
        assert_offline_envelope(&payload, "kin_work_list");
    }

    #[tokio::test]
    async fn envelope_present_on_verification_family() {
        let payload = call_tool_payload("kin_coverage_summary", serde_json::json!({})).await;
        assert_offline_envelope(&payload, "kin_coverage_summary");
    }

    #[tokio::test]
    async fn envelope_present_on_error_results() {
        // semantic_locate errors offline (vector search needs the daemon). The
        // envelope must still be attached so degraded states are surfaced, and
        // the human message preserved alongside it.
        let payload = call_tool_payload(
            "semantic_locate",
            serde_json::json!({ "query": "where is auth handled" }),
        )
        .await;
        assert_offline_envelope(&payload, "semantic_locate");
        let message = payload["message"]
            .as_str()
            .expect("wrapped error message present");
        assert!(
            message.contains("requires the Kin daemon"),
            "original error message preserved, got: {message}"
        );
    }

    fn direct_graph_status_result_with_coverage(
        pending: usize,
        indexed: usize,
        total: usize,
    ) -> ToolCallResult {
        ToolCallResult::text(
            serde_json::json!({
                "schema": "kin.graph-status.v1",
                "view": "daemon_selected_graph",
                "scope": "temporal_session",
                "authority": "repo-daemon",
                "sampling": "point_in_time_selected_graph",
                "authority_epoch": 42,
                "entity_count": 2,
                "relation_count": 1,
                "embedding_source": "selected_graph",
                "embeddings_indexed": indexed,
                "embeddings_pending": pending,
                "embeddings_total": total,
                "completion_attested": false
            })
            .to_string(),
        )
    }

    fn direct_graph_status_result() -> ToolCallResult {
        direct_graph_status_result_with_coverage(1, 1, 2)
    }

    /// The same report with its graph emptied, the shape a daemon answers with in
    /// the moment after it begins serving and before its graph is loaded.
    fn direct_graph_status_result_with_entities(entity_count: u64) -> ToolCallResult {
        let result = direct_graph_status_result();
        let ContentBlock::Text { text } = result.content.first().expect("one content block");
        let mut report: serde_json::Value = serde_json::from_str(text).expect("report json");
        report["entity_count"] = serde_json::json!(entity_count);
        report["relation_count"] = serde_json::json!(0);
        ToolCallResult::text(report.to_string())
    }

    /// A status answer from a daemon whose graph holds nothing goes out as a
    /// graph gap with a verdict, and names the daemon that gave it, never as a
    /// bare zero.
    #[test]
    fn an_empty_selected_graph_goes_out_as_a_graph_gap_naming_its_daemon() {
        let health = serde_json::json!({
            "pid": 98031,
            "repo_root": "/work/umbrella",
            "repo_id": "local-4705badf13d922e2",
            "uptime_seconds": 1,
            "version": "0.7.9",
        });
        let base = Envelope::daemon()
            .with_working_copy_health(&health)
            .with_answering_daemon(&health);
        let enveloped =
            finalize_daemon_graph_status(direct_graph_status_result_with_entities(0), base, &[], 2);
        let report = daemon_delegate::parse_graph_status_report(&enveloped)
            .unwrap()
            .expect("successful stdio status report");
        let envelope = report
            .response_envelope
            .expect("stdio status carries the standard envelope");
        assert_eq!(envelope.graph_state.entity_count, Some(0));
        let verdict = envelope
            .verdict
            .expect("an empty graph must carry a verdict, never a bare zero");
        assert_eq!(
            verdict["inputs"]["graph_empty"], "inconclusive",
            "{verdict}"
        );
        assert!(
            verdict["limiting_factor"]
                .as_str()
                .is_some_and(|factor| factor.split("; ").any(|code| code == "graph_empty")),
            "the verdict must name the gap: {verdict}"
        );
        let daemon = envelope
            .answered_by
            .expect("the status answer names the daemon that gave it");
        assert_eq!(daemon.pid, 98031);
        assert_eq!(daemon.repo_id, "local-4705badf13d922e2");
        assert_eq!(daemon.repo_root, "/work/umbrella");
        assert_eq!(daemon.uptime_seconds, 1);

        // The control: a populated graph carries no graph gap.
        let populated = finalize_daemon_graph_status(
            direct_graph_status_result(),
            Envelope::daemon().with_answering_daemon(&health),
            &[],
            2,
        );
        let populated = daemon_delegate::parse_graph_status_report(&populated)
            .unwrap()
            .expect("successful stdio status report")
            .response_envelope
            .expect("stdio status carries the standard envelope");
        assert!(
            !serde_json::to_string(&populated)
                .unwrap()
                .contains("graph_empty"),
            "a populated graph is not a gap: {populated:?}"
        );
    }

    #[test]
    fn graph_status_stdio_envelope_is_derived_from_the_selected_graph() {
        // Even if a caller accidentally supplies a HEAD-derived base envelope,
        // finalization must replace every graph-specific field with the
        // temporal report's own observation.
        let head_health = serde_json::json!({
            "graph_entity_count": 999,
            "graph_generation": 77,
            "initialized": true,
            "graph_loaded": true,
            "reconciliation_status": "head-only",
            "embed_worker_failed": true,
            "embed_persistence_unavailable": true
        });
        let base = Envelope::daemon().with_health(&head_health);
        let enveloped = finalize_daemon_graph_status(direct_graph_status_result(), base, &[], 2);
        let report = daemon_delegate::parse_graph_status_report(&enveloped)
            .unwrap()
            .expect("successful stdio status report");
        let response_env = report
            .response_envelope
            .expect("stdio status carries the standard envelope");

        assert_eq!(
            report.scope,
            crate::handlers::entities::GraphStatusScope::TemporalSession
        );
        assert_eq!(report.entity_count, 2);
        assert_eq!(response_env.graph_state.entity_count, Some(2));
        assert!(response_env.graph_as_of.is_none());
        assert!(response_env.graph_state.loaded.is_none());
        assert!(response_env.graph_state.initialized.is_none());
        assert!(response_env.graph_state.reconciliation_status.is_none());
        assert!(response_env.degraded.embed_worker_failed.is_none());
        assert_eq!(
            response_env.degraded.embed_persistence_unavailable,
            Some(true),
            "an incomplete selected graph keeps the daemon storage blocker"
        );
        let coverage = response_env
            .semantic_coverage
            .expect("selected-graph embedding coverage");
        assert_eq!(coverage.indexed, 1);
        assert_eq!(coverage.pending, 1);
        assert_eq!(coverage.total, 2);
        assert!(!coverage.complete);
    }

    /// A replayed status sample must own the envelope's freshness reading.
    ///
    /// The first-contact run received counters from 359601 ms earlier beside
    /// `_kin.freshness.state=recorded` and `age_seconds=6`, because the latter
    /// came from HEAD admission health. A reader scanning the standard envelope
    /// therefore saw a fresh-looking status over an empty past graph.
    #[test]
    fn replayed_graph_status_marks_the_standard_envelope_stale() {
        let stale_result = ToolCallResult::text(
            serde_json::json!({
                "schema": "kin.graph-status.v1",
                "view": "daemon_selected_graph",
                "scope": "head",
                "authority": "repo-daemon",
                "sampling": "last_settled_selected_graph",
                "authority_epoch": 7,
                "entity_count": 0,
                "durable_entity_count": 0,
                "relation_count": 0,
                "embedding_source": "selected_graph",
                "embeddings_indexed": 0,
                "embeddings_pending": 0,
                "embeddings_total": 0,
                "completion_attested": false,
                "stale": {
                    "reason": "embedding_coverage_changing",
                    "settled_age_ms": 359601,
                    "observed_authority_epoch": 8,
                    "live_attempts": 3,
                    "note": "the live sample was abandoned while embedding coverage changed"
                }
            })
            .to_string(),
        );
        let admission_health = serde_json::json!({
            "reconcile": {
                "untracked_path_count": 0,
                "untracked_observed_age_seconds": 0,
                "last_admission_success_at": "2026-09-04T14:00:00Z",
                "last_admission_success_age_seconds": 6
            }
        });
        let enveloped = finalize_daemon_graph_status(
            stale_result,
            Envelope::daemon().with_working_copy_health(&admission_health),
            &[],
            2,
        );
        let report = daemon_delegate::parse_graph_status_report(&enveloped)
            .expect("the stdio contract validates")
            .expect("the status call succeeds");
        let freshness = serde_json::to_value(
            report
                .response_envelope
                .expect("stdio status carries an envelope")
                .freshness
                .expect("a replayed sample carries freshness"),
        )
        .unwrap();
        assert_eq!(freshness["state"], "stale");
        assert_eq!(freshness["basis"], "selected_graph_sample");
        assert_eq!(freshness["settled_age_ms"], 359601);
        assert_eq!(freshness["live_attempts"], 3);
        assert!(
            freshness.get("age_seconds").is_none(),
            "the unrelated six-second admission clock must not survive: {freshness}"
        );
    }

    #[test]
    fn graph_status_stdio_schema_rejects_a_mixed_head_envelope() {
        let enveloped =
            finalize_daemon_graph_status(direct_graph_status_result(), Envelope::daemon(), &[], 2);
        let ContentBlock::Text { text } = &enveloped.content[0];
        let mut payload: serde_json::Value = serde_json::from_str(text).unwrap();
        payload["_kin"]["graph_state"]["entity_count"] = serde_json::json!(999);
        payload["_kin"]["graph_as_of"] = serde_json::json!({ "generation": 77 });

        let error = serde_json::from_value::<crate::handlers::entities::GraphStatusReport>(payload)
            .expect_err("HEAD metadata must not validate beside a temporal selected graph");
        assert!(
            error.to_string().contains("_kin graph_as_of")
                || error.to_string().contains("_kin graph_state"),
            "{error}"
        );
    }

    #[test]
    fn graph_status_stdio_replaces_daemon_supplied_envelope_and_validates_coverage_note() {
        let enveloped =
            finalize_daemon_graph_status(direct_graph_status_result(), Envelope::daemon(), &[], 2);
        let ContentBlock::Text { text } = &enveloped.content[0];
        let mut payload: serde_json::Value = serde_json::from_str(text).unwrap();
        payload["_kin"]["graph_state"]["head_generation"] = serde_json::json!(77);

        let sanitized = finalize_daemon_graph_status(
            ToolCallResult::text(payload.to_string()),
            Envelope::daemon(),
            &[],
            2,
        );
        let ContentBlock::Text { text } = &sanitized.content[0];
        let sanitized_payload: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(
            sanitized_payload["_kin"]["graph_state"]
                .get("head_generation")
                .is_none(),
            "daemon-supplied additive envelope metadata must be stripped"
        );
        daemon_delegate::parse_graph_status_report(&sanitized)
            .expect("sanitized stdio report must validate")
            .expect("sanitized stdio report remains a success");

        // Envelope v2 sends no coverage sentence, so what the report validates is
        // the disclosure a reader acts on: `complete` has to agree with the
        // counters it is derived from.
        let mut disagreeing = sanitized_payload;
        disagreeing["_kin"]["semantic_coverage"]
            .as_object_mut()
            .unwrap()
            .insert("complete".to_string(), serde_json::json!(true));
        let error =
            serde_json::from_value::<crate::handlers::entities::GraphStatusReport>(disagreeing)
                .expect_err("incomplete coverage may not report itself complete");
        assert!(
            error
                .to_string()
                .contains("semantic_coverage disagrees with selected-graph status"),
            "{error}"
        );
    }

    fn response_pressure_refusal(work: &str) -> kin_core::memory_pressure::PressureRefusal {
        kin_core::memory_pressure::PressureRefusal {
            work: work.to_string(),
            level: "constrained".to_string(),
            reason: format!("{work} was refused"),
            at_unix: 1,
            from_budget: false,
        }
    }

    fn finalized_graph_status_with_pressure(
        work: &str,
        pending: usize,
        indexed: usize,
        total: usize,
    ) -> serde_json::Value {
        let refusal = response_pressure_refusal(work);
        // Production order: the typed report and durable refusal meet at the
        // graph-status finalizer. No second resources sample participates.
        let result = finalize_daemon_graph_status(
            direct_graph_status_result_with_coverage(pending, indexed, total),
            Envelope::daemon(),
            std::slice::from_ref(&refusal),
            2,
        );
        let ContentBlock::Text { text } = result.content.first().expect("one content block");
        serde_json::from_str(text).expect("annotated graph-status response")
    }

    #[test]
    fn graph_status_preserves_only_pressure_for_work_the_selected_graph_still_owes() {
        for (name, payload) in [
            (
                "incomplete selected embedding coverage",
                finalized_graph_status_with_pressure("embed-batch", 1, 8, 9),
            ),
            (
                "live embedding backlog",
                finalized_graph_status_with_pressure("embed-batch", 1, 9, 9),
            ),
            (
                "language-server work",
                finalized_graph_status_with_pressure("lsp-sweep", 0, 9, 9),
            ),
            (
                "future work",
                finalized_graph_status_with_pressure("future-heavy-work", 0, 9, 9),
            ),
        ] {
            assert_eq!(
                payload[ENVELOPE_KEY]["degraded"]["memory_pressure"],
                serde_json::json!(true),
                "{name} must survive selected-graph finalization: {payload}"
            );
        }

        let complete = finalized_graph_status_with_pressure("embed-batch", 0, 9, 9);
        assert!(
            complete[ENVELOPE_KEY]["degraded"]
                .get("memory_pressure")
                .is_none(),
            "exactly complete embedding coverage retires the response-level signal: {complete}"
        );
    }

    #[test]
    fn graph_status_qualifies_unavailable_persistence_by_selected_coverage() {
        let incomplete = finalize_daemon_graph_status(
            direct_graph_status_result_with_coverage(1, 8, 9),
            Envelope::daemon().with_embed_persistence_unavailable(true),
            &[],
            2,
        );
        let ContentBlock::Text { text } = incomplete.content.first().expect("one content block");
        let incomplete: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            incomplete[ENVELOPE_KEY]["degraded"]["embed_persistence_unavailable"],
            serde_json::json!(true),
            "incomplete selected coverage has no producer that can fill it"
        );

        let complete = finalize_daemon_graph_status(
            direct_graph_status_result_with_coverage(0, 9, 9),
            Envelope::daemon().with_embed_persistence_unavailable(true),
            &[],
            2,
        );
        let ContentBlock::Text { text } = complete.content.first().expect("one content block");
        let complete: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(
            complete[ENVELOPE_KEY]["degraded"]
                .get("embed_persistence_unavailable")
                .is_none(),
            "a fully covered selected graph has no embedding work for the unavailable producer"
        );
    }

    fn finalized_empty_locate_with_pressure(
        work: &str,
        embedding_coverage: Option<kin_core::memory_pressure::EmbeddingCoverage>,
    ) -> serde_json::Value {
        let refusal = daemon_delegate::pressure_refusal_for_coverage(
            response_pressure_refusal(work),
            embedding_coverage,
        );
        let env = Envelope::daemon()
            .with_selected_graph_observation(
                envelope::DurabilityCounts {
                    live_entities: 1,
                    durable_entities: Some(1),
                    live_relations: Some(0),
                    durable_relations: Some(0),
                },
                1,
                0,
                1,
            )
            .with_memory_pressure(refusal.as_ref());
        let result = envelope::finalize(
            ToolCallResult::text(
                serde_json::json!({
                    "query": "missing_authenticator",
                    "results": [],
                    "total_ranked": 0,
                })
                .to_string(),
            ),
            env,
            "semantic_locate",
        );
        let ContentBlock::Text { text } = result.content.first().expect("one content block");
        serde_json::from_str(text).expect("annotated locate response")
    }

    #[test]
    fn memory_pressure_qualifies_verdicts_only_for_outstanding_work() {
        let coverage = |pending, indexed, total| kin_core::memory_pressure::EmbeddingCoverage {
            pending,
            indexed,
            total,
        };
        let completed_embed =
            finalized_empty_locate_with_pressure("embed-batch", Some(coverage(0, 9, 9)));
        assert!(
            completed_embed[ENVELOPE_KEY]["degraded"]
                .get("memory_pressure")
                .is_none(),
            "completed embedding work must not leave a degradation: {completed_embed}"
        );
        assert!(!completed_embed["negative"]["degraded_signals"]
            .as_array()
            .expect("negative degradation labels")
            .iter()
            .any(|label| label.as_str() == Some("memory_pressure")));
        assert_eq!(
            completed_embed["negative"]["trust"], "authoritative",
            "whole coverage must not poison an otherwise exact semantic absence"
        );
        assert_eq!(
            completed_embed[ENVELOPE_KEY]["verdict"]["inputs"]["absence_gate"],
            "certified"
        );

        // An outstanding sweep stays visible on every answer and bounds only
        // the relation answers it feeds. This one ranks vectors over whole
        // embeddings, so it certifies and names the refusal it considered.
        let held_sweep = finalized_empty_locate_with_pressure("lsp-sweep", Some(coverage(0, 9, 9)));
        assert_eq!(
            held_sweep[ENVELOPE_KEY]["degraded"]["memory_pressure"], true,
            "a held sweep stays visible: {held_sweep}"
        );
        assert!(
            held_sweep["negative"]["degraded_signals"]
                .as_array()
                .expect("negative degradation labels")
                .iter()
                .any(|label| label.as_str() == Some("memory_pressure")),
            "a held sweep reaches the response-level negative: {held_sweep}"
        );
        assert_eq!(
            held_sweep["negative"]["trust"], "authoritative",
            "a held sweep does not bound a vector ranking: {held_sweep}"
        );
        assert!(
            held_sweep["negative"]["trust_reason"]
                .as_str()
                .unwrap_or_default()
                .contains(
                    "the disclosed signals [memory_pressure] were considered and are not \
                     load-bearing for this claim"
                ),
            "{held_sweep}"
        );
        assert_eq!(
            held_sweep[ENVELOPE_KEY]["verdict"]["inputs"]["absence_gate"],
            "certified"
        );

        for (work, observed) in [
            ("embed-batch", Some(coverage(1, 9, 9))),
            ("embed-batch", Some(coverage(0, 8, 9))),
            ("embed-batch", None),
            ("future-heavy-work", Some(coverage(0, 9, 9))),
        ] {
            let response = finalized_empty_locate_with_pressure(work, observed);
            assert_eq!(
                response[ENVELOPE_KEY]["degraded"]["memory_pressure"], true,
                "{work} with coverage {observed:?} stays visible: {response}"
            );
            assert!(
                response["negative"]["degraded_signals"]
                    .as_array()
                    .expect("negative degradation labels")
                    .iter()
                    .any(|label| label.as_str() == Some("memory_pressure")),
                "{work} must reach the response-level negative: {response}"
            );
            assert_eq!(response["negative"]["trust"], "inconclusive");
            assert_eq!(
                response[ENVELOPE_KEY]["verdict"]["inputs"]["absence_gate"],
                "inconclusive"
            );
        }
    }

    // ── Track C: confidence-qualified negatives ride the envelope through the
    //    real dispatch chokepoint, on the offline path, across tool groups. ──────

    /// Assert the additive `negative` contract is present and shaped, without
    /// disturbing the envelope or the original payload keys.
    fn assert_negative(payload: &serde_json::Value, tool: &str, kind: &str) -> serde_json::Value {
        assert_offline_envelope(payload, tool);
        let negative = payload
            .get("negative")
            .unwrap_or_else(|| panic!("tool {tool} empty result must carry a `negative` contract"));
        assert_eq!(negative["kind"], kind, "tool {tool} negative kind");
        // Offline is a fallback surface: absence is never authoritative here.
        assert_eq!(
            negative["safe_to_conclude_absent"], false,
            "tool {tool} offline absence must be inconclusive"
        );
        assert_eq!(negative["trust"], "inconclusive", "tool {tool}");
        assert!(
            negative["advice"].as_str().is_some_and(|a| !a.is_empty()),
            "tool {tool} negative must carry human advice"
        );
        negative.clone()
    }

    #[tokio::test]
    async fn negative_contract_on_empty_object_payload_search() {
        // Object payload: `negative` is added beside `_kin` and the untouched
        // `results` key.
        let payload = call_tool_payload(
            "semantic_search",
            serde_json::json!({ "query": "nonexistent" }),
        )
        .await;
        let negative = assert_negative(&payload, "semantic_search", "no_entity_match");
        assert_eq!(negative["result_count"], 0);
        assert_eq!(negative["interpretation"], "absent_as_indexed");
        // Back-compat: the original result collection still lives where agents
        // expect it, empty.
        assert_eq!(
            payload["results"].as_array().map(|a| a.len()),
            Some(0),
            "negative must not displace the original `results` key"
        );
    }

    #[tokio::test]
    async fn negative_contract_on_empty_bare_array_dead_code() {
        // Bare-array payload: the annotator wraps it under `result`; `negative`
        // rides alongside.
        let payload = call_tool_payload("dead_code", serde_json::json!({})).await;
        let negative = assert_negative(&payload, "dead_code", "no_dead_code");
        assert_eq!(negative["result_count"], 0);
        assert!(
            payload["result"].is_array(),
            "bare-array dead_code payload is wrapped under `result`"
        );
    }

    #[tokio::test]
    async fn no_negative_on_non_retrieval_tool() {
        // Work-graph listing is not a code-retrieval negative surface: an empty
        // work list must NOT be dressed up as a confidence-qualified absence.
        let payload = call_tool_payload("kin_work_list", serde_json::json!({})).await;
        assert_offline_envelope(&payload, "kin_work_list");
        assert!(
            payload.get("negative").is_none(),
            "non-retrieval tools must not carry a `negative` contract"
        );
    }

    #[test]
    fn default_config_requires_daemon_session_authority() {
        let config = McpServerConfig::default();
        assert_eq!(
            config.session_authority_mode,
            SessionAuthorityMode::DaemonRequired
        );
        assert!(config.session_authority_mode.requires_daemon());
    }

    #[tokio::test]
    async fn process_initialize() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());

        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "kin-mcp");
        // P2-2.3: kinVersion must be present in serverInfo
        assert!(result["serverInfo"]["kinVersion"].is_string());
        // The spec's instructions field must reach the wire with usable content.
        // What that content has to hold is asserted once, in
        // `agent_belt::tests::the_server_instructions_name_only_tools_the_profile_serves`,
        // against the served profiles. This asserts only that the string
        // survives the round trip, since a client that hides tool schemas has
        // nothing else to give the model.
        let instructions = result["instructions"].as_str().unwrap();
        assert_eq!(instructions, SERVER_INSTRUCTIONS);
        assert!(instructions.contains("semantic_locate"));
        // The one verdict has to be named on the wire, or an agent learns the
        // contract from whichever block it happens to read first.
        assert!(instructions.contains("_kin.verdict"));
    }

    #[tokio::test]
    async fn initialize_with_newer_protocol_version_includes_warning() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());

        let result = resp.result.unwrap();
        // Server falls back to its supported version
        assert_eq!(result["protocolVersion"], "2024-11-05");
        // Warning is present
        assert!(result["_warning"].is_string());
        assert!(result["_warning"].as_str().unwrap().contains("2099-01-01"));
    }

    #[tokio::test]
    async fn initialize_with_matching_protocol_version_no_warning() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        let result = resp.result.unwrap();
        assert!(result.get("_warning").is_none());
    }

    #[tokio::test]
    async fn process_tools_list() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());

        let tools = &resp.result.unwrap()["tools"];
        assert!(tools.is_array());
        let tools = tools.as_array().unwrap();
        assert!(!tools.is_empty());

        // The annotations have to survive the serving path, not just the
        // registry: a client reads them from this response and from nowhere
        // else.
        for tool in tools {
            assert!(
                tool["annotations"]["title"].is_string(),
                "{} reached the wire with no title",
                tool["name"]
            );
            assert!(tool["annotations"]["readOnlyHint"].is_boolean());
        }

        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "tools/list must serve a stable name order");
    }

    #[tokio::test]
    async fn process_tools_call_semantic_search() {
        let mut config = McpServerConfig::default();
        config.session_authority_mode = SessionAuthorityMode::OfflineFallback;
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"semantic_search","arguments":{"query":"foo"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn process_tools_call_semantic_locate_requires_daemon_offline() {
        // End-to-end dispatch check: semantic_locate must reach
        // handle_semantic_locate and report the daemon requirement rather than
        // silently degrading to a metadata filter when no daemon graph is
        // present.
        let mut config = McpServerConfig::default();
        config.session_authority_mode = SessionAuthorityMode::OfflineFallback;
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"semantic_locate","arguments":{"query":"where is auth handled"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.error.is_none());
        let result: ToolCallResult = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = match result.content.first().unwrap() {
            ContentBlock::Text { text } => text,
        };
        assert!(
            text.contains("requires the Kin daemon"),
            "expected daemon-required message, got: {text}"
        );
    }

    #[tokio::test]
    async fn daemon_required_tools_do_not_use_local_handlers() {
        // Bind this end-to-end dispatch test to a Kin repository explicitly.
        // Without `.kin`, the production delegate correctly reports the
        // distinct "not inside a kin repository" state before it can prove the
        // daemon-required branch this test is intended to lock down.
        //
        // The repository is private to this test, and the delegate is pointed
        // at it rather than at the process working directory. That directory is
        // shared by every test in this binary and the work handlers' tests move
        // it into repositories of their own, so a `.kin` made beside the crate
        // was sometimes looked for from another test's repository, or from one
        // already deleted, and this test read "not inside a kin repository".
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join(".kin")).unwrap();
        let _working_dir = crate::daemon_delegate::TestWorkingDir::enter(repo.path());
        let _daemon_url = kin_core::test_env::EnvVarGuard::unset("KIN_DAEMON_URL");
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"semantic_search","arguments":{"query":"foo"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.error.is_none());
        let result: ToolCallResult = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = match result.content.first().unwrap() {
            ContentBlock::Text { text } => text,
        };
        // A repository with no daemon serving it is one of the three
        // distinguished gaps, and it is the one this fixture builds. What the
        // test locks down is that dispatch never reaches a local handler.
        assert!(
            text.contains("no daemon is serving it"),
            "expected the repository-present, daemon-absent gap, got: {text}"
        );
    }

    #[tokio::test]
    async fn process_tools_call_register_session() {
        let mut config = McpServerConfig::default();
        config.session_authority_mode = SessionAuthorityMode::OfflineFallback;
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"register_session","arguments":{"assistant_name":"claude-code","session_id":"test-123"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert_eq!(sessions.count(), 1);
    }

    #[tokio::test]
    async fn process_daemon_message_handles_transport_methods_without_store() {
        let config = McpServerConfig::default();
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = process_daemon_message(msg, &config).await.unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn resource_uris_cannot_bypass_entity_only_source_tools() {
        let config = McpServerConfig::default();
        let init = handle_initialize(Some(serde_json::json!(1)), &serde_json::json!({}), &config);
        assert!(init.result.unwrap()["capabilities"]
            .get("resources")
            .is_none());
        for method in [
            "resources/list",
            "resources/templates/list",
            "resources/read",
        ] {
            for uri in ["file:///README.md", "kin://artifact/README.md"] {
                let request = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"uri":uri}}).to_string();
                for daemon in [false, true] {
                    let response = if daemon {
                        process_daemon_message(&request, &config).await
                    } else {
                        process_message(
                            &request,
                            &InMemoryGraph::default(),
                            &config,
                            &SessionRegistry::new(),
                        )
                        .await
                    }
                    .unwrap();
                    assert_eq!(response.error.unwrap().code, -32601);
                    assert!(response.result.is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn file_catalogs_are_absent_and_refused_on_every_profile_and_transport() {
        let mut configs = vec![
            McpServerConfig::default(),
            default_config(),
            query_config(),
            with_writes(),
            read_only(),
        ];
        for names in [
            crate::tools::agent_search_tool_names(),
            crate::tools::benchmark_tool_names(),
            crate::tools::context_bench_tool_names(),
        ] {
            configs.push(McpServerConfig {
                allowed_tools: Some(crate::tools::name_set(names)),
                ..Default::default()
            });
        }
        for retired in ["kin_artifact_list", "list_file_entities"] {
            for config in &configs {
                let listed = handle_tools_list(Some(serde_json::json!(1)), config);
                assert!(!serde_json::to_string(&listed.result)
                    .unwrap()
                    .contains(retired));
                for daemon in [false, true] {
                    for (name, args) in [
                        (retired, serde_json::json!({"path":"README.md"})),
                        (
                            "kin_tool_call",
                            serde_json::json!({"tool":retired,"arguments":{"path":"README.md"}}),
                        ),
                        (
                            "kin",
                            serde_json::json!({"command":retired,"args":{"path":"README.md"}}),
                        ),
                        (
                            "kin",
                            serde_json::json!({"command":format!("kin {retired}"),"args":{"path":"README.md"}}),
                        ),
                        (
                            "kin",
                            serde_json::json!({"command":"call","args":{"tool":retired,"arguments":{"path":"README.md"}}}),
                        ),
                    ] {
                        if name == "kin" && config.routed.is_none() {
                            continue;
                        }
                        let request = tools_call(name, args);
                        let response = if daemon {
                            process_daemon_message(&request, config).await
                        } else {
                            process_message(
                                &request,
                                &InMemoryGraph::default(),
                                config,
                                &SessionRegistry::new(),
                            )
                            .await
                        }
                        .unwrap();
                        assert!(
                            response.error.is_some()
                                || response
                                    .result
                                    .as_ref()
                                    .is_some_and(|r| r["isError"] == true),
                            "{retired} through {name}: {:?}",
                            response.result
                        );
                        // An unfiltered daemon connection must refuse locally, not
                        // contact an older daemon that still knows this operation.
                        if name == retired && config.allowed_tools.is_none() {
                            assert!(response
                                .error
                                .as_ref()
                                .unwrap()
                                .message
                                .contains("File catalogs are unavailable"));
                        }
                    }
                }
            }
            let discovery =
                crate::handlers::tool_search::handle_tool_search(&std::collections::HashMap::new())
                    .unwrap();
            assert!(!serde_json::to_string(&discovery).unwrap().contains(retired));
            assert!(!LEGACY_SERVER_INSTRUCTIONS.contains(retired));
        }
    }

    #[tokio::test]
    async fn whole_artifact_read_is_absent_and_refused_on_every_profile_and_transport() {
        let mut configs = vec![
            McpServerConfig::default(),
            default_config(),
            query_config(),
            with_writes(),
            read_only(),
        ];
        for names in [
            crate::tools::agent_search_tool_names(),
            crate::tools::benchmark_tool_names(),
            crate::tools::context_bench_tool_names(),
        ] {
            configs.push(McpServerConfig {
                allowed_tools: Some(crate::tools::name_set(names)),
                ..Default::default()
            });
        }
        for config in configs {
            let listed = handle_tools_list(Some(serde_json::json!(1)), &config);
            assert!(!serde_json::to_string(&listed.result)
                .unwrap()
                .contains("kin_artifact_read"));
            for daemon in [false, true] {
                for (name, args) in [
                    ("kin_artifact_read", serde_json::json!({"path":"README.md"})),
                    (
                        "kin_tool_call",
                        serde_json::json!({"tool":"kin_artifact_read","arguments":{"path":"README.md"}}),
                    ),
                    (
                        "kin",
                        serde_json::json!({"command":"read","args":{"path":"README.md"}}),
                    ),
                    (
                        "kin",
                        serde_json::json!({"command":"kin_artifact_read","args":{"path":"README.md"}}),
                    ),
                    (
                        "kin",
                        serde_json::json!({"command":"call","args":{"tool":"kin_artifact_read","arguments":{"path":"README.md"}}}),
                    ),
                ] {
                    // The routed tool is meaningful only on a routed profile.
                    if name == "kin" && config.routed.is_none() {
                        continue;
                    }
                    let request = tools_call(name, args);
                    let response = if daemon {
                        process_daemon_message(&request, &config).await
                    } else {
                        process_message(
                            &request,
                            &InMemoryGraph::default(),
                            &config,
                            &SessionRegistry::new(),
                        )
                        .await
                    }
                    .unwrap();
                    assert!(
                        response.error.is_some()
                            || response
                                .result
                                .as_ref()
                                .is_some_and(|r| r["isError"] == true),
                        "{name}: {:?}",
                        response.result
                    );
                }
            }
        }
        let discovery =
            crate::handlers::tool_search::handle_tool_search(&std::collections::HashMap::new())
                .unwrap();
        assert!(!serde_json::to_string(&discovery)
            .unwrap()
            .contains("kin_artifact_read"));
    }

    #[tokio::test]
    async fn discovery_reports_profile_eligibility_without_activating_tools() {
        for daemon_route in [false, true] {
            for filtered in [false, true] {
                let config = McpServerConfig {
                    allowed_tools: filtered
                        .then(|| crate::tools::name_set(crate::tools::agent_search_tool_names())),
                    agent_belt: filtered,
                    session_authority_mode: SessionAuthorityMode::OfflineFallback,
                    ..McpServerConfig::default()
                };
                let store = InMemoryGraph::default();
                let sessions = SessionRegistry::new();
                let before = handle_tools_list(Some(serde_json::json!(1)), &config);
                let listed = before.result.as_ref().unwrap()["tools"].as_array().unwrap();
                let search_description = listed
                    .iter()
                    .find(|tool| tool["name"] == "kin_tool_search")
                    .unwrap()["description"]
                    .as_str()
                    .unwrap();
                assert!(search_description.contains("Discovery does not"));
                assert!(!search_description.contains("callable definition"));
                for tool in listed {
                    assert!(!tool["description"]
                        .as_str()
                        .unwrap()
                        .contains("then call it on the next turn"));
                }
                let search = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kin_tool_search","arguments":{"need":"impact_analysis","limit":1}}}"#;
                let response = if daemon_route {
                    process_daemon_message(search, &config).await
                } else {
                    process_message(search, &store, &config, &sessions).await
                }
                .expect("search response");
                let result = response.result.expect("search result");
                let payload: serde_json::Value =
                    serde_json::from_str(result["content"][0]["text"].as_str().expect("JSON text"))
                        .unwrap();
                assert_eq!(payload["matches"][0]["name"], "impact_analysis");
                assert_eq!(
                    payload["invocation"]["profile_enabled"]["impact_analysis"],
                    !filtered
                );
                assert_eq!(payload["invocation"]["discovery_changes_profile"], false);
                assert_eq!(payload["invocation"]["normal_authorization_required"], true);
                let after = handle_tools_list(Some(serde_json::json!(3)), &config);
                assert_eq!(before.result, after.result);

                if filtered {
                    let invoke = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"impact_analysis","arguments":{}}}"#;
                    let response = if daemon_route {
                        process_daemon_message(invoke, &config).await
                    } else {
                        process_message(invoke, &store, &config, &sessions).await
                    }
                    .unwrap();
                    let result = response.result.unwrap();
                    assert_eq!(result["isError"], true);
                    assert!(result["content"][0]["text"]
                        .as_str()
                        .unwrap()
                        .contains("not enabled in this MCP profile"));
                }
            }
        }
    }

    #[tokio::test]
    async fn discovered_calls_reach_real_handlers_without_expanding_the_profile() {
        let config = McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(
                crate::tools::agent_search_tool_names(),
            )),
            agent_belt: true,
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            ..McpServerConfig::default()
        };
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        let bytes = b"fn dispatched_symbol() {}\n";
        let kin_index::IndexedAny::EntitySource(indexed) = kin_index::IndexPipeline::new()
            .index_any_content(
                &kin_model::FilePathId::new("src/lib.rs"),
                bytes,
                kin_blobs::digest(bytes),
            )
            .unwrap()
        else {
            panic!("source fixture");
        };
        for entity in indexed.entities {
            kin_model::EntityStore::upsert_entity(&store, &entity).unwrap();
        }
        store.flush_text_index().unwrap();
        let before = handle_tools_list(Some(serde_json::json!(1)), &config);
        let message = |name: &str, arguments: serde_json::Value| {
            serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":arguments}
        }).to_string()
        };
        let searched = process_message(
            &message(
                "kin_tool_search",
                serde_json::json!({"need":"semantic_search","limit":1}),
            ),
            &store,
            &config,
            &sessions,
        )
        .await
        .unwrap()
        .result
        .unwrap();
        let discovery: serde_json::Value =
            serde_json::from_str(searched["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(discovery["matches"][0]["name"], "semantic_search");
        assert_eq!(
            discovery["invocation"]["profile_enabled"]["semantic_search"],
            false
        );
        assert_eq!(
            discovery["invocation"]["callable_via_dispatcher"]["semantic_search"],
            true
        );
        let args = serde_json::json!({"query":"dispatched_symbol"});
        let refused = process_message(
            &message("semantic_search", args.clone()),
            &store,
            &config,
            &sessions,
        )
        .await
        .unwrap();
        assert_eq!(refused.result.unwrap()["isError"], true);
        let full = McpServerConfig {
            allowed_tools: None,
            ..config.clone()
        };
        let direct = process_message(
            &message("semantic_search", args.clone()),
            &store,
            &full,
            &sessions,
        )
        .await
        .unwrap();
        let wrapped = process_message(
            &message(
                "kin_tool_call",
                serde_json::json!({"tool":"semantic_search","arguments":args}),
            ),
            &store,
            &config,
            &sessions,
        )
        .await
        .unwrap();
        assert!(wrapped.error.is_none());
        let text = wrapped.result.as_ref().unwrap()["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            text.contains("dispatched_symbol") && text.contains("src/lib.rs"),
            "{text}"
        );
        assert_ne!(wrapped.result.as_ref().unwrap()["isError"], true);
        assert_eq!(
            direct.result, wrapped.result,
            "target answer, negative evidence and envelope must be unchanged"
        );
        assert_eq!(
            before.result,
            handle_tools_list(Some(serde_json::json!(3)), &config).result
        );
    }

    /// One guarded whole-entity update as `kin_mutate` takes it: the new body
    /// beside a well-formed `source_base`, whose entity id is the target.
    ///
    /// No route these tests drive compares a base with repository bytes, so a
    /// base that passes `EntitySourceBase::validate` is all they need. A body
    /// without one is refused as `source_base_required` before the behaviour
    /// these tests assert about could run.
    fn guarded_update_operation(body: &str) -> serde_json::Value {
        let base = crate::source_base::EntitySourceBase {
            schema: crate::source_base::SourceBaseSchema::V1,
            context: crate::source_base::SourceBaseContext {
                repository_id: "server-test".into(),
                workspace_id: uuid::Uuid::new_v4().to_string(),
                workspace_generation: 1,
                workspace_head_hash: "a".repeat(64),
                workspace_tree_hash: "b".repeat(64),
            },
            entity_id: kin_model::EntityId::new(),
            artifact_id: kin_model::ArtifactId::new(),
            source_blob_hash: "c".repeat(64),
            start_byte: 0,
            end_byte: 12,
            body_hash: "d".repeat(64),
        };
        serde_json::json!({
            "verb": "update",
            "target": base.entity_id.to_string(),
            "payload": { "EntitySourceBase": base },
            "body": body,
            "description": "edit",
        })
    }

    #[tokio::test]
    async fn discovered_calls_keep_profile_and_mutation_authority_refusals() {
        // An admissible mutation, so the refusals below are the profile's and
        // the session authority's rather than the operation's.
        let call = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"kin_tool_call","arguments":{"tool":"kin_mutate","arguments":{
                "operations":[guarded_update_operation("fn widget() {}")]
            }}
        }})
        .to_string();
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        for names in [
            crate::tools::agent_default_tool_names(),
            crate::tools::agent_query_tool_names(),
            crate::tools::context_bench_tool_names(),
        ] {
            let config = McpServerConfig {
                allowed_tools: Some(crate::tools::name_set(names)),
                session_authority_mode: SessionAuthorityMode::OfflineFallback,
                ..McpServerConfig::default()
            };
            for daemon in [false, true] {
                let response = if daemon {
                    process_daemon_message(&call, &config).await
                } else {
                    process_message(&call, &store, &config, &sessions).await
                }
                .unwrap();
                assert!(response.error.unwrap().message.contains("not enabled"));
            }
        }
        let config = McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(
                crate::tools::agent_search_tool_names(),
            )),
            agent_belt: true,
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            ..McpServerConfig::default()
        };
        for daemon in [false, true] {
            let response = if daemon {
                process_daemon_message(&call, &config).await
            } else {
                process_message(&call, &store, &config, &sessions).await
            }
            .unwrap();
            assert!(response.error.unwrap().message.contains("read-only"));
        }
        assert_eq!(sessions.count(), 0);
    }

    /// The tool registry is answered by this binary on the daemon route, from
    /// the definitions `tools/list` is built from.
    ///
    /// The daemon route forwards every name it does not special-case to the
    /// daemon's generic MCP endpoint. Forwarding this one would answer from
    /// whatever registry the daemon build carries, which is how an agent gets a
    /// schema for a tool this server cannot dispatch. There is no daemon in this
    /// test, so a forwarded call could not answer at all.
    #[tokio::test]
    async fn the_tool_registry_is_answered_locally_on_the_daemon_route() {
        let config = McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(
                crate::tools::agent_search_tool_names(),
            )),
            agent_belt: true,
            ..McpServerConfig::default()
        };

        let msg = format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"{}","arguments":{{"need":"impact_analysis"}}}}}}"#,
            crate::handlers::tool_search::TOOL_NAME
        );
        let resp = process_daemon_message(&msg, &config).await.unwrap();
        let result = resp.result.expect("the registry call is answered");
        assert_ne!(
            result.get("isError"),
            Some(&serde_json::json!(true)),
            "the registry call came back an error: {result:#?}"
        );
        let text = result["content"][0]["text"]
            .as_str()
            .expect("a text content block")
            .to_string();
        assert!(
            text.contains("impact_analysis"),
            "a withheld tool was not reachable through the served search: {text}"
        );

        // The control: a tool this profile does not serve is still refused, so
        // the short circuit above did not become a way around the profile.
        let refused = process_daemon_message(
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"impact_analysis","arguments":{}}}"#,
            &config,
        )
        .await
        .unwrap()
        .result
        .expect("a refusal is still a result frame");
        assert!(
            refused["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("not enabled in this MCP profile"),
            "the profile filter stopped refusing withheld tools: {refused:#?}"
        );
    }

    /// A mutation is expanded by this binary on the daemon route, not forwarded.
    ///
    /// This is the one that cost a debugging session. Everything the daemon
    /// route does not special-case is handed to the daemon under the name the
    /// caller used, and the daemon runs what arrives under
    /// `SessionAuthorityMode::OfflineFallback`, because inside the daemon its
    /// own registry IS the authority. A forwarded `kin_mutate` therefore reaches
    /// `handle_mutate` with `uses_daemon()` FALSE, takes the in-process branch,
    /// and is refused by a commit path that has no projection. The daemon routes
    /// exactly one name to its exact-commit path, `kin_transaction_commit`, so a
    /// one-shot under any other name never reaches it.
    ///
    /// There is no daemon in this test, which is what makes the two answers
    /// distinguishable: the local expansion refuses for its own missing
    /// `session_id` before it ever reaches the wire, and a call that did reach
    /// the wire comes back as the daemon being unavailable.
    #[tokio::test]
    async fn a_mutation_is_expanded_locally_on_the_daemon_route() {
        let config = McpServerConfig::default();
        // Guarded, so the expansion's check on the operations passes and the
        // only thing left for it to refuse is the missing session.
        let edit = guarded_update_operation("pub fn widget() {}");

        let unsessioned = process_daemon_message(
            &serde_json::json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{
                "name":"kin_mutate","arguments":{"operations":[edit]}
            }})
            .to_string(),
            &config,
        )
        .await
        .unwrap()
        .result
        .expect("the mutation call is answered");
        let text = unsessioned["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            text.contains("session_id") && text.contains("kin_session_start"),
            "a locally expanded mutate refuses for its own missing session before the wire; \
             a forwarded one could not have produced this: {text}"
        );

        // The discriminating half. With a session named, the expansion has
        // nothing left to refuse of its own and goes on to forward its begin.
        // Without this, the assertion above would pass just as well against an
        // expansion that refused everything.
        //
        // What the wire then says is deliberately not asserted. This test runs
        // wherever the checkout sits, and whether a daemon answers depends on
        // whether a store exists above that directory, which is a fact about the
        // machine rather than about this route. The assertion that carries the
        // guard is the one above: only a locally expanded mutate names
        // `kin_session_start`, and a forwarded one cannot, under any daemon.
        let sessioned = process_daemon_message(
            &serde_json::json!({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{
                "name":"kin_mutate","arguments":{
                    "session_id":"11111111-1111-4111-8111-111111111111",
                    "operations":[edit]
                }
            }})
            .to_string(),
            &config,
        )
        .await
        .unwrap()
        .result
        .expect("the mutation call is answered");
        let text = sessioned["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            !text.contains("kin_session_start"),
            "a named session was refused as missing: {text}"
        );
        assert!(
            !text.contains("source_base_required"),
            "the expansion refused the operations it should have forwarded: {text}"
        );
        assert_eq!(
            sessioned.get("isError"),
            Some(&serde_json::json!(true)),
            "a mutation with no daemon behind it still has to fail: {sessioned:#?}"
        );
    }

    #[tokio::test]
    async fn process_unknown_method() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":5,"method":"unknown/method","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn process_invalid_json() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let resp = process_message("not json", &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32700);
    }

    #[tokio::test]
    async fn process_ping() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":6,"method":"ping","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn process_initialized_notification_has_no_response() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions).await;
        assert!(resp.is_none());
    }

    #[test]
    fn parse_content_length_header() {
        assert_eq!(parse_content_length("Content-Length: 123\r\n"), Some(123));
        assert_eq!(parse_content_length("content-length: 7\n"), Some(7));
        assert_eq!(parse_content_length("X-Test: 1"), None);
        assert_eq!(parse_content_length("Content-Length: nope"), None);
    }

    #[test]
    fn root_uri_to_path_handles_file_uris_and_bare_paths() {
        assert_eq!(
            root_uri_to_path("file:///Users/me/proj"),
            Some(PathBuf::from("/Users/me/proj"))
        );
        // `file://host/path` drops the authority, leaving the absolute path.
        assert_eq!(
            root_uri_to_path("file://localhost/Users/me/proj"),
            Some(PathBuf::from("/Users/me/proj"))
        );
        // Percent-escaped characters (e.g. spaces) decode.
        assert_eq!(
            root_uri_to_path("file:///Users/me/My%20Repo"),
            Some(PathBuf::from("/Users/me/My Repo"))
        );
        // RFC 8089 Windows drive URIs drop the URI-only leading slash.
        assert_eq!(
            root_uri_to_path("file:///C:/Users/me/My%20Repo"),
            Some(PathBuf::from("C:/Users/me/My Repo"))
        );
        assert_eq!(
            root_uri_to_path("file://localhost/C:/Users/me/kin"),
            Some(PathBuf::from("C:/Users/me/kin"))
        );
        // Accept the non-canonical spelling emitted by some Windows clients.
        assert_eq!(
            root_uri_to_path("file://C:/Users/me/kin"),
            Some(PathBuf::from("C:/Users/me/kin"))
        );
        // Some clients (Cursor) send a bare absolute path, not a file:// URI.
        assert_eq!(
            root_uri_to_path("/Users/me/kin"),
            Some(PathBuf::from("/Users/me/kin"))
        );
        assert_eq!(
            root_uri_to_path(r"C:\Users\me\kin"),
            Some(PathBuf::from(r"C:\Users\me\kin"))
        );
        assert_eq!(
            root_uri_to_path("C:/Users/me/kin"),
            Some(PathBuf::from("C:/Users/me/kin"))
        );
        assert_eq!(root_uri_to_path("C:relative\\kin"), None);
        #[cfg(windows)]
        assert_eq!(
            root_uri_to_path("file://server/share/kin"),
            Some(PathBuf::from(r"\\server\share\kin"))
        );
        #[cfg(not(windows))]
        assert_eq!(root_uri_to_path("file://server/share/kin"), None);
        // Non-file schemes (e.g. remote workspaces) are skipped.
        assert_eq!(root_uri_to_path("vscode-remote://host/x"), None);
        assert_eq!(root_uri_to_path("https://example.com/x"), None);
    }

    #[test]
    fn parse_workspace_roots_extracts_local_paths() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": ROOTS_REQUEST_ID,
            "result": {
                "roots": [
                    {"uri": "file:///Users/me/kin", "name": "kin"},
                    {"uri": "vscode-remote://host/y"},
                    {"uri": "/Users/me/bare", "name": "bare"},
                    {"uri": "file:///Users/me/other"}
                ]
            }
        });
        assert_eq!(
            parse_workspace_roots(&response),
            vec![
                PathBuf::from("/Users/me/kin"),
                PathBuf::from("/Users/me/bare"),
                PathBuf::from("/Users/me/other"),
            ]
        );
        // A response carrying no roots yields an empty list, never a panic.
        assert!(parse_workspace_roots(&serde_json::json!({ "result": {} })).is_empty());
    }

    #[test]
    fn workspace_roots_retry_after_empty_response_or_root_change() {
        for method in [
            "initialized",
            "notifications/initialized",
            "notifications/roots/list_changed",
            "tools/list",
        ] {
            assert!(should_request_workspace_roots(
                Some(method),
                true,
                false,
                true,
                true,
            ));
        }
    }

    #[test]
    fn workspace_roots_request_stays_serialized() {
        assert!(!should_request_workspace_roots(
            Some("notifications/roots/list_changed"),
            true,
            true,
            true,
            true,
        ));
        assert!(!should_request_workspace_roots(
            Some("tools/list"),
            true,
            true,
            true,
            true,
        ));
    }

    #[test]
    fn workspace_roots_request_state_reopens_after_completion() {
        let now = Instant::now();
        let mut state = WorkspaceRootsRequestState::default();
        assert!(state.begin_if_allowed(Some("initialized"), true, true, true, now));
        assert!(!state.begin_if_allowed(
            Some("notifications/roots/list_changed"),
            true,
            true,
            true,
            now,
        ));

        state.complete();
        assert!(state.begin_if_allowed(
            Some("notifications/roots/list_changed"),
            true,
            true,
            true,
            now,
        ));
    }

    #[test]
    fn workspace_roots_request_retries_after_an_unanswered_request_times_out() {
        let start = Instant::now();
        let mut state = WorkspaceRootsRequestState::default();
        assert!(state.begin_if_allowed(Some("initialized"), true, true, true, start));

        // A client that advertises roots and never answers must not wedge
        // binding for the life of the process.
        let just_before = start + ROOTS_REQUEST_TIMEOUT - Duration::from_millis(1);
        assert!(!state.begin_if_allowed(Some("tools/list"), true, true, true, just_before));
        let after = start + ROOTS_REQUEST_TIMEOUT;
        assert!(state.begin_if_allowed(Some("tools/list"), true, true, true, after));
    }

    #[test]
    fn workspace_roots_request_requires_capability_binder_and_unbound_daemon() {
        let trigger = Some("tools/list");
        assert!(!should_request_workspace_roots(
            trigger, false, false, true, true,
        ));
        assert!(!should_request_workspace_roots(
            trigger, true, false, false, true,
        ));
        assert!(!should_request_workspace_roots(
            trigger, true, false, true, false,
        ));
        assert!(!should_request_workspace_roots(
            Some("tools/call"),
            true,
            false,
            true,
            true,
        ));
    }

    #[test]
    fn a_refusing_binding_still_wants_workspace_roots() {
        let mut binding = RepoBindingState::default();
        assert!(
            binding.wants_workspace_roots(),
            "unbound wants a repository"
        );

        binding.bind(
            bound_repo("/repo/a", "http://127.0.0.1:4111"),
            BindingOrigin::ClientRoots,
        );
        assert!(
            !binding.wants_workspace_roots(),
            "a settled binding must not re-ask on every trigger"
        );

        binding.mark_mismatch(vec![PathBuf::from("/elsewhere")], false);
        assert!(
            binding.wants_workspace_roots(),
            "bound to a repository the client left is no better than unbound"
        );

        binding.bind(
            bound_repo("/repo/b", "http://127.0.0.1:4222"),
            BindingOrigin::ClientRoots,
        );
        assert!(!binding.wants_workspace_roots());
        assert!(!binding.is_mismatched(), "binding again clears the refusal");
    }

    #[test]
    fn workspace_roots_change_is_honored_after_a_repository_is_already_bound() {
        // The defect this locks down: with a daemon already bound, the roots
        // change that an editor sends when its window moves to another folder
        // was dropped, leaving the server answering from the old repository.
        assert!(should_request_workspace_roots(
            Some("notifications/roots/list_changed"),
            true,
            false,
            true,
            false,
        ));
        // Everything else stays gated on an unbound daemon so a settled session
        // does not re-ask on every tools/list.
        assert!(!should_request_workspace_roots(
            Some("notifications/initialized"),
            true,
            false,
            true,
            false,
        ));
        // A roots change still needs a binder and the client capability, and
        // still never overlaps an in-flight request.
        assert!(!should_request_workspace_roots(
            Some("notifications/roots/list_changed"),
            true,
            true,
            true,
            false,
        ));
        assert!(!should_request_workspace_roots(
            Some("notifications/roots/list_changed"),
            true,
            false,
            false,
            false,
        ));
        assert!(!should_request_workspace_roots(
            Some("notifications/roots/list_changed"),
            false,
            false,
            true,
            false,
        ));
    }

    // ── Workspace-switch integration over the real stdio loop ──────────────

    /// Records every roots list the server hands the binder and replies with a
    /// scripted outcome per call, so a test can drive a bind and then a switch.
    struct ScriptedBinder {
        outcomes: std::sync::Mutex<std::collections::VecDeque<WorkspaceBinding>>,
        calls: std::sync::Arc<std::sync::Mutex<Vec<Vec<PathBuf>>>>,
    }

    impl ScriptedBinder {
        fn install(
            outcomes: Vec<WorkspaceBinding>,
        ) -> (
            RepoBinder,
            std::sync::Arc<std::sync::Mutex<Vec<Vec<PathBuf>>>>,
        ) {
            let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let scripted = std::sync::Arc::new(ScriptedBinder {
                outcomes: std::sync::Mutex::new(outcomes.into()),
                calls: std::sync::Arc::clone(&calls),
            });
            let binder: RepoBinder = Box::new(
                move |roots: Vec<PathBuf>| -> Pin<Box<dyn Future<Output = WorkspaceBinding> + Send>> {
                    let scripted = std::sync::Arc::clone(&scripted);
                    Box::pin(async move {
                        scripted.calls.lock().unwrap().push(roots);
                        scripted
                            .outcomes
                            .lock()
                            .unwrap()
                            .pop_front()
                            // A binder called more times than the script covers
                            // resolves nothing rather than binding something the
                            // test never named.
                            .unwrap_or(WorkspaceBinding::Unresolvable)
                    })
                },
            );
            (binder, calls)
        }
    }

    /// The binder outcome for a client that moved to a Kin repository this
    /// server does not serve.
    fn other_repository(root: &str) -> WorkspaceBinding {
        WorkspaceBinding::OtherRepository(vec![PathBuf::from(root)])
    }

    /// The binder outcome for a root this server cannot resolve at all: the
    /// container and remote shape, where the client's path does not exist in
    /// this process's namespace.
    fn unresolvable() -> WorkspaceBinding {
        WorkspaceBinding::Unresolvable
    }

    fn bound_repo(root: &str, daemon_url: &str) -> BoundRepo {
        BoundRepo {
            root: PathBuf::from(root),
            daemon_url: daemon_url.to_string(),
        }
    }

    /// Drive the daemon stdio loop over an in-memory transport with a scripted
    /// client session, and return every message the server wrote back.
    ///
    /// The config carries an empty tool allow-list so a `tools/call` that is
    /// *not* refused for a repo mismatch is answered locally by the allow-list
    /// branch. That keeps every assertion offline and deterministic: no test
    /// here ever reaches the daemon delegate, which on a machine with a live
    /// `KIN_DAEMON_URL` would open a connection and could spawn a daemon.
    /// FIR-3031, graded through the handler a client actually reaches rather
    /// than through the helper it calls.
    ///
    /// The helper has its own tests in `tools`. This one exists because a
    /// correct helper nobody calls is the same observable surface as no fix at
    /// all: deleting the call in `handle_tools_list` leaves every helper test
    /// green.
    #[test]
    fn tools_list_says_where_a_withheld_tool_is() {
        let config = McpServerConfig {
            allowed_tools: Some(
                crate::agent_default_tool_names()
                    .iter()
                    .map(|name| (*name).to_string())
                    .collect(),
            ),
            ..McpServerConfig::default()
        };
        let response = handle_tools_list(Some(serde_json::json!(1)), &config);
        let value = serde_json::to_value(&response).unwrap();
        let tools = value["result"]["tools"].as_array().expect("a tools array");
        assert_eq!(tools.len(), crate::agent_default_tool_names().len());

        let find_references = tools
            .iter()
            .find(|tool| tool["name"] == "find_references")
            .expect("find_references is served by the default profile");
        let description = find_references["description"].as_str().unwrap();
        assert!(
            description.contains("bulk_check_references"),
            "the batch advice survives: {description}"
        );
        assert!(
            description.contains("not served by this tool profile"),
            "and the served answer says the default profile withholds it: {description}"
        );

        // The control: the same handler with no profile filter must annotate
        // nothing, because nothing is withheld.
        let unfiltered = handle_tools_list(Some(serde_json::json!(2)), &McpServerConfig::default());
        let unfiltered = serde_json::to_value(&unfiltered).unwrap();
        for tool in unfiltered["result"]["tools"].as_array().unwrap() {
            assert!(
                !tool["description"]
                    .as_str()
                    .unwrap()
                    .contains("not served by this tool profile"),
                "an unfiltered surface withholds nothing: {}",
                tool["name"]
            );
        }
    }

    /// FIR-3099. The whole handshake, and a workspace-roots answer beside it,
    /// must leave the launcher's binding task still waiting: none of them is a
    /// caller asking Kin for a graph answer, and starting a daemon for one costs
    /// the store open and a full embedding pass.
    ///
    /// The roots answer is in the script on purpose. It is the second spawn
    /// door and the only one that fires when the server was launched outside a
    /// repository, so a fix that closed the startup binding alone would pass a
    /// version of this test that omitted it.
    #[tokio::test]
    async fn a_handshake_and_a_roots_answer_admit_no_daemon_spawn() {
        let startup = StartupDaemonBinding::new();
        let seen_roots = std::sync::Arc::new(std::sync::Mutex::new(Vec::<PathBuf>::new()));
        let recorder = std::sync::Arc::clone(&seen_roots);
        let binder: RepoBinder = Box::new(move |roots: Vec<PathBuf>| {
            let recorder = std::sync::Arc::clone(&recorder);
            Box::pin(async move {
                recorder.lock().unwrap().extend(roots);
                // What an attach-only bind reports for a repository this server
                // can see with no daemon serving it yet.
                WorkspaceBinding::OtherRepository(vec![PathBuf::from("/work/repo")])
            })
        });

        drive_daemon_loop_with_startup(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                roots_response(&["/work/repo"]),
            ],
            Some(binder),
            None,
            Some(std::sync::Arc::clone(&startup)),
        )
        .await;

        assert!(
            !startup.daemon_spawn_admitted(),
            "initialize, initialized, tools/list and a roots answer must not admit starting a \
             daemon: every one of them arrives before a caller has asked Kin anything"
        );
        assert!(
            !seen_roots.lock().unwrap().is_empty(),
            "the binder must still have been consulted, or this test would pass on a server \
             that ignores workspace roots entirely"
        );
    }

    /// The other direction, which is what keeps the test above from passing on
    /// a server that can never start a daemon at all.
    #[tokio::test]
    async fn the_first_tool_call_admits_the_daemon_spawn() {
        let startup = StartupDaemonBinding::new();
        startup.resolve_unbound("no repository at the launch directory");

        drive_daemon_loop_with_startup(
            &[
                initialize_with_roots_capability(),
                tool_call(3, "semantic_locate"),
            ],
            None,
            None,
            Some(std::sync::Arc::clone(&startup)),
        )
        .await;

        assert!(
            startup.daemon_spawn_admitted(),
            "a tools/call is a caller asking for a graph answer, and must admit the spawn the \
             answer needs"
        );
    }

    /// Roots a pre-call bind could not follow are kept, not discarded, so the
    /// first tool call binds the repository the client named instead of
    /// reporting no daemon for a repository Kin can see.
    #[tokio::test]
    async fn deferred_roots_are_rebound_on_the_first_tool_call() {
        let startup = StartupDaemonBinding::new();
        startup.resolve_unbound("no repository at the launch directory");
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&calls);
        let binder: RepoBinder = Box::new(move |_roots: Vec<PathBuf>| {
            let counter = std::sync::Arc::clone(&counter);
            Box::pin(async move {
                // First pass is the attach-only bind, which found no daemon.
                // Second pass runs with the spawn admitted and binds.
                if counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    WorkspaceBinding::OtherRepository(vec![PathBuf::from("/work/repo")])
                } else {
                    WorkspaceBinding::Bound(bound_repo("/work/repo", "http://127.0.0.1:4311"))
                }
            })
        });

        drive_daemon_loop_with_startup(
            &[
                initialize_with_roots_capability(),
                roots_response(&["/work/repo"]),
                tool_call(3, "semantic_locate"),
            ],
            Some(binder),
            None,
            Some(std::sync::Arc::clone(&startup)),
        )
        .await;

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the tool call must put the deferred roots through the binder again, now that \
             starting their daemon is admitted"
        );
    }

    async fn drive_daemon_loop(
        client_messages: &[serde_json::Value],
        repo_binder: Option<RepoBinder>,
        bound_daemon_url: Option<String>,
    ) -> Vec<serde_json::Value> {
        drive_daemon_loop_with_startup(client_messages, repo_binder, bound_daemon_url, None).await
    }

    async fn drive_daemon_loop_with_startup(
        client_messages: &[serde_json::Value],
        repo_binder: Option<RepoBinder>,
        bound_daemon_url: Option<String>,
        startup: Option<std::sync::Arc<StartupDaemonBinding>>,
    ) -> Vec<serde_json::Value> {
        let mut input = String::new();
        for message in client_messages {
            input.push_str(&message.to_string());
            input.push('\n');
        }
        let mut reader = BufReader::new(input.as_bytes());
        let mut written: Vec<u8> = Vec::new();
        let config = McpServerConfig {
            allowed_tools: Some(HashSet::new()),
            ..McpServerConfig::default()
        };

        run_stdio_daemon_over(
            &mut reader,
            &mut written,
            config,
            repo_binder,
            bound_daemon_url,
            startup,
            None,
        )
        .await
        .expect("stdio loop must drain the scripted client session");

        String::from_utf8(written)
            .expect("server output is UTF-8")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("server output is JSON-RPC"))
            .collect()
    }

    fn roots_response(roots: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": ROOTS_REQUEST_ID,
            "result": {
                "roots": roots
                    .iter()
                    .map(|root| serde_json::json!({ "uri": format!("file://{root}") }))
                    .collect::<Vec<_>>(),
            },
        })
    }

    fn initialize_with_roots_capability() -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "capabilities": { "roots": { "listChanged": true } } },
        })
    }

    fn tool_call(id: u32, name: &str) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": {} },
        })
    }

    fn roots_requests(responses: &[serde_json::Value]) -> Vec<&serde_json::Value> {
        responses
            .iter()
            .filter(|value| value.get("method").and_then(|m| m.as_str()) == Some("roots/list"))
            .collect()
    }

    /// The `_kin.degraded` object an answered tool call carries. Reads it out of
    /// the annotated content block rather than the transport frame, which is
    /// where an agent reads it.
    fn tool_error_degraded(response: &serde_json::Value) -> serde_json::Value {
        let text = tool_error_text(response);
        let payload: serde_json::Value =
            serde_json::from_str(&text).expect("an annotated tool result is JSON");
        payload
            .get(ENVELOPE_KEY)
            .and_then(|envelope| envelope.get("degraded"))
            .cloned()
            .unwrap_or_else(|| panic!("the response carries no _kin degraded object: {text}"))
    }

    fn tool_error_text(response: &serde_json::Value) -> String {
        let result: ToolCallResult =
            serde_json::from_value(response.get("result").cloned().expect("tool result"))
                .expect("tool result payload");
        assert_eq!(result.is_error, Some(true), "expected an error result");
        match result.content.first().expect("error content block") {
            ContentBlock::Text { text } => text.clone(),
        }
    }

    #[tokio::test]
    async fn roots_change_after_a_bind_rebinds_to_the_new_workspace() {
        let (binder, calls) = ScriptedBinder::install(vec![
            WorkspaceBinding::Bound(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            WorkspaceBinding::Bound(bound_repo("/repo/b", "http://127.0.0.1:4222")),
        ]);

        let responses = drive_daemon_loop(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                roots_response(&["/repo/a"]),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
                roots_response(&["/repo/b"]),
            ],
            Some(binder),
            None,
        )
        .await;

        // Two `roots/list` requests: the late bind, then the workspace switch.
        // On the pre-fix server the second never leaves the process.
        assert_eq!(
            roots_requests(&responses).len(),
            2,
            "a roots change after a successful bind must re-request roots: {responses:#?}"
        );
        let calls = calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                vec![PathBuf::from("/repo/a")],
                vec![PathBuf::from("/repo/b")]
            ],
            "the binder must be re-invoked with the client's new roots"
        );
    }

    #[tokio::test]
    async fn tool_calls_fail_loud_when_the_new_workspace_cannot_be_bound() {
        // Bind repo A from the client's own roots, then switch to a workspace
        // with no bindable Kin repo. A binding that exists only because the
        // client announced it does not survive the client withdrawing it, so
        // this server refuses rather than answering from the repository it was
        // sent to and then sent away from. The third outcome is the tool call's
        // own re-check, which must find the root still unbindable and leave the
        // refusal exactly as it was: re-checking changes when the verdict is
        // taken, never what it is.
        let (binder, calls) = ScriptedBinder::install(vec![
            WorkspaceBinding::Bound(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            unresolvable(),
            unresolvable(),
        ]);

        let responses = drive_daemon_loop(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                roots_response(&["/repo/a"]),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
                roots_response(&["/elsewhere/not-a-kin-repo"]),
                tool_call(7, "semantic_locate"),
            ],
            Some(binder),
            None,
        )
        .await;

        let answer = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(7))
            .expect("the tool call must be answered, not dropped");
        let text = tool_error_text(answer);
        assert!(
            text.contains("semantic_locate") && text.contains("/elsewhere/not-a-kin-repo"),
            "refusal must name the tool and the workspace the client moved to: {text}"
        );
        assert!(
            text.contains("/repo/a"),
            "refusal must name the repository still bound: {text}"
        );
        assert_eq!(
            calls.lock().unwrap().len(),
            3,
            "the tool call must re-check the root before refusing"
        );
    }

    /// The refusal was computed when the roots changed and then cached, so a
    /// root that became bindable afterwards kept being refused for the life of
    /// the process. The reported shape: a container registration whose
    /// announced host path was made to exist, with no way to restart the
    /// client's MCP server.
    #[tokio::test]
    async fn a_root_that_becomes_bindable_self_heals_on_the_next_tool_call() {
        let (binder, calls) = ScriptedBinder::install(vec![
            WorkspaceBinding::Bound(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            unresolvable(),
            WorkspaceBinding::Bound(bound_repo("/host/path", "http://127.0.0.1:4222")),
        ]);

        let responses = drive_daemon_loop(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                roots_response(&["/repo/a"]),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
                roots_response(&["/host/path"]),
                // No roots change and no restart in between: only the host
                // changed under a root the client already announced.
                tool_call(21, "semantic_locate"),
            ],
            Some(binder),
            None,
        )
        .await;

        let calls = calls.lock().unwrap().clone();
        assert_eq!(
            calls.len(),
            3,
            "the tool call must put the recorded roots through the binder again: {calls:?}"
        );
        assert_eq!(
            calls[2],
            vec![PathBuf::from("/host/path")],
            "the re-check must use the roots the client announced, not invent new ones"
        );

        let answer = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(21))
            .expect("the tool call must be answered");
        let text = tool_error_text(answer);
        assert!(
            text.contains("not enabled in this MCP profile"),
            "a root that became bindable must clear the refusal without a restart: {text}"
        );
    }

    /// Drive the loop with a repository bound at startup, then move the client
    /// to a second Kin repository this server does not serve, and return the
    /// refusal text.
    async fn pinned_workspace_refusal(repo_pinned: bool) -> String {
        let startup = StartupDaemonBinding::new();
        startup.resolve_bound(
            bound_repo("/repo/pinned", "http://127.0.0.1:4111"),
            repo_pinned,
        );
        // Twice: the roots change that records the mismatch, and the tool call's
        // own re-check.
        let (binder, _calls) = ScriptedBinder::install(vec![
            other_repository("/repo/second"),
            other_repository("/repo/second"),
        ]);

        let responses = drive_daemon_loop_with_startup(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                roots_response(&["/repo/second"]),
                tool_call(31, "semantic_locate"),
            ],
            Some(binder),
            None,
            Some(startup),
        )
        .await;

        let answer = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(31))
            .expect("the tool call must be answered");
        tool_error_text(answer)
    }

    /// `kin init .` is wrong advice for a repo-bound server, and wrong in the
    /// expensive direction: the repository the client moved to already exists,
    /// so following the hint writes a second store into it and still leaves the
    /// pinned server refusing.
    #[tokio::test]
    async fn a_repo_bound_refusal_does_not_suggest_kin_init() {
        let pinned = pinned_workspace_refusal(true).await;
        assert!(
            !pinned.contains("kin init"),
            "a repo-bound server must not send the user to create a second repository: {pinned}"
        );
        assert!(
            pinned.contains("--repo") && pinned.contains("KIN_MCP_REPO"),
            "the remedy that does apply must survive: {pinned}"
        );
        assert!(
            pinned.contains("semantic_locate") && pinned.contains("/repo/second"),
            "the refusal must still name the tool and the workspace: {pinned}"
        );

        // Falsification: an unpinned server reaches the same refusal by the
        // same path and still gets the suggestion, so the assertion above
        // describes the pin rather than a message that lost the text for
        // everyone.
        let unpinned = pinned_workspace_refusal(false).await;
        assert!(
            unpinned.contains("kin init"),
            "an unpinned server can genuinely init the workspace it is looking at: {unpinned}"
        );
    }

    /// Drive a server that bound its own repository before the loop started —
    /// the `docker exec -w <repo> ... kin mcp start` and plain per-repo
    /// registration shape — through a roots answer the binder reports as
    /// `resolution`, then two tool calls, and return their answers.
    async fn server_bound_run(
        resolution: WorkspaceBinding,
        root: &str,
    ) -> (serde_json::Value, serde_json::Value) {
        let startup = StartupDaemonBinding::new();
        // `pinned_by_operator: false` is the reported registration: the cwd of
        // the `docker exec` bound the repository, with no --repo/KIN_MCP_REPO.
        startup.resolve_bound(bound_repo("/work/express", "http://127.0.0.1:4111"), false);
        // Three: the roots answer, and each tool call's own re-check if the
        // first one recorded a mismatch.
        let (binder, _calls) =
            ScriptedBinder::install(vec![resolution.clone(), resolution.clone(), resolution]);

        let responses = drive_daemon_loop_with_startup(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                roots_response(&[root]),
                tool_call(41, "semantic_locate"),
                tool_call(42, "semantic_locate"),
            ],
            Some(binder),
            None,
            Some(startup),
        )
        .await;

        let answer_for = |id: u64| {
            responses
                .iter()
                .find(|value| value.get("id").and_then(|value| value.as_u64()) == Some(id))
                .unwrap_or_else(|| panic!("tool call {id} must be answered"))
                .clone()
        };
        (answer_for(41), answer_for(42))
    }

    /// The reported shape (FIR-2405): a server reached through `docker exec`
    /// serves `/work/express` while the client announces the host path
    /// `/private/tmp/.../work`, which never exists inside the container. That
    /// root is not evidence that the client left the repository this server was
    /// started for, so the server must keep answering. Before the fix exactly
    /// one call survived each respawn: the one that arrived before the roots
    /// answer did, after which every call was refused.
    #[tokio::test]
    async fn a_server_bound_repository_survives_roots_it_cannot_resolve() {
        let (first, second) =
            server_bound_run(unresolvable(), "/private/tmp/kin-dogfood/brown/work").await;

        for (id, answer) in [(41, &first), (42, &second)] {
            let text = tool_error_text(answer);
            assert!(
                !text.contains("kin-mcp refuses"),
                "call {id} must not be refused for a root this server cannot resolve: {text}"
            );
            assert!(
                text.contains("not enabled in this MCP profile"),
                "call {id} must reach ordinary handling: {text}"
            );
        }
    }

    /// Falsification of the test above, over the same helper: when the client's
    /// roots name a Kin repository this server can see and does not serve, the
    /// refusal is still owed. Answering would return a confident result about
    /// the wrong codebase, which is the failure the refusal exists to prevent.
    #[tokio::test]
    async fn a_server_bound_repository_still_refuses_a_second_kin_repository() {
        let (first, second) =
            server_bound_run(other_repository("/work/requests"), "/work/requests").await;

        for (id, answer) in [(41, &first), (42, &second)] {
            let text = tool_error_text(answer);
            assert!(
                text.contains("kin-mcp refuses") && text.contains("semantic_locate"),
                "call {id} must be refused and name the tool: {text}"
            );
            assert!(
                text.contains("/work/requests") && text.contains("/work/express"),
                "call {id} must name both the workspace and the bound repository: {text}"
            );
        }
    }

    /// The refusal reported a reachability problem it did not have: the bound
    /// daemon answered `/health` 200 throughout, so an agent reading
    /// `daemon_unreachable` went and checked a daemon that was fine.
    #[tokio::test]
    async fn a_workspace_refusal_is_not_stamped_daemon_unreachable() {
        let (refused, _) =
            server_bound_run(other_repository("/work/requests"), "/work/requests").await;
        let degraded = tool_error_degraded(&refused);

        assert_eq!(
            degraded.get("workspace_mismatch"),
            Some(&serde_json::Value::Bool(true)),
            "the refusal must carry its own degradation: {degraded}"
        );
        assert!(
            degraded.get("daemon_unreachable").is_none(),
            "a reachable daemon must not be reported unreachable: {degraded}"
        );

        // Falsification: the same assertion run against a server that keeps
        // serving proves the flag tracks the refusal rather than riding every
        // response out of this loop.
        let (served, _) = server_bound_run(unresolvable(), "/host/only/path").await;
        assert!(
            tool_error_degraded(&served)
                .get("workspace_mismatch")
                .is_none(),
            "a served call must carry no workspace mismatch"
        );
    }

    #[tokio::test]
    async fn a_bindable_workspace_switch_clears_an_earlier_refusal() {
        // A → unbindable workspace → B: the refusal must not outlive the switch
        // that resolves it.
        let (binder, _calls) = ScriptedBinder::install(vec![
            WorkspaceBinding::Bound(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            unresolvable(),
            WorkspaceBinding::Bound(bound_repo("/repo/b", "http://127.0.0.1:4222")),
        ]);

        let responses = drive_daemon_loop(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                roots_response(&["/repo/a"]),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
                roots_response(&["/elsewhere/not-a-kin-repo"]),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
                roots_response(&["/repo/b"]),
                tool_call(9, "semantic_locate"),
            ],
            Some(binder),
            None,
        )
        .await;

        let answer = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(9))
            .expect("the tool call must be answered");
        let text = tool_error_text(answer);
        assert!(
            text.contains("not enabled in this MCP profile"),
            "a successful re-bind must clear the refusal and let the call through: {text}"
        );
    }

    #[tokio::test]
    async fn a_refusing_server_keeps_trying_to_bind_on_ordinary_triggers() {
        // Bind A, switch to a workspace that cannot be bound, then send only a
        // plain `tools/list`. A refusing server is no more useful than an
        // unbound one, so it must reach for roots again instead of waiting for
        // the client to announce another change — and a bindable answer there
        // clears the refusal.
        let (binder, calls) = ScriptedBinder::install(vec![
            WorkspaceBinding::Bound(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            unresolvable(),
            WorkspaceBinding::Bound(bound_repo("/repo/b", "http://127.0.0.1:4222")),
        ]);

        let responses = drive_daemon_loop(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                roots_response(&["/repo/a"]),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
                roots_response(&["/elsewhere/not-a-kin-repo"]),
                serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                roots_response(&["/repo/b"]),
                tool_call(13, "semantic_locate"),
            ],
            Some(binder),
            None,
        )
        .await;

        assert_eq!(
            roots_requests(&responses).len(),
            3,
            "a refusing server must re-request roots on an ordinary trigger: {responses:#?}"
        );
        assert_eq!(
            calls.lock().unwrap().len(),
            3,
            "the third roots response must reach the binder"
        );
        let answer = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(13))
            .expect("the tool call must be answered");
        let text = tool_error_text(answer);
        assert!(
            text.contains("not enabled in this MCP profile"),
            "binding again must clear the refusal: {text}"
        );
    }

    #[tokio::test]
    async fn a_startup_bound_server_still_follows_a_workspace_switch() {
        // The reported shape: a repository bound before the loop starts (from
        // --repo/KIN_MCP_REPO/cwd) used to suppress roots handling entirely.
        let (binder, calls) = ScriptedBinder::install(vec![WorkspaceBinding::Bound(bound_repo(
            "/repo/b",
            "http://127.0.0.1:4222",
        ))]);

        let responses = drive_daemon_loop(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
                roots_response(&["/repo/b"]),
            ],
            Some(binder),
            Some("http://127.0.0.1:4111".to_string()),
        )
        .await;

        // `initialized` and `tools/list` must stay quiet for an already-bound
        // server; only the roots change reaches out.
        let requests = roots_requests(&responses);
        assert_eq!(
            requests.len(),
            1,
            "only the roots change may re-request roots once bound: {responses:#?}"
        );
        assert_eq!(
            calls.lock().unwrap().clone(),
            vec![vec![PathBuf::from("/repo/b")]],
            "the switch must reach the binder even though startup already bound a repo"
        );
    }

    #[tokio::test]
    async fn an_empty_roots_response_leaves_an_existing_binding_alone() {
        // No open folder is not a different folder: there is no other
        // repository the client's calls could be about, so a binding survives
        // and tool calls are not refused.
        let (binder, calls) = ScriptedBinder::install(vec![WorkspaceBinding::Bound(bound_repo(
            "/repo/a",
            "http://127.0.0.1:4111",
        ))]);

        let responses = drive_daemon_loop(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                roots_response(&["/repo/a"]),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
                roots_response(&[]),
                tool_call(11, "semantic_locate"),
            ],
            Some(binder),
            None,
        )
        .await;

        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "an empty roots list must not be handed to the binder"
        );
        let answer = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(11))
            .expect("the tool call must be answered");
        let text = tool_error_text(answer);
        assert!(
            text.contains("not enabled in this MCP profile"),
            "an empty roots list must not be treated as a workspace switch: {text}"
        );
    }

    /// The answer-early contract (FIR-2316): the handshake never waits on the
    /// daemon. With the startup binding pending forever (the shape of a cold
    /// flagship-scale daemon start), `initialize` and `tools/list` are still
    /// answered from this process.
    #[tokio::test]
    async fn initialize_and_tools_list_answer_while_the_startup_binding_is_pending() {
        let startup = StartupDaemonBinding::new();

        let responses = drive_daemon_loop_with_startup(
            &[
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            ],
            None,
            None,
            Some(startup),
        )
        .await;

        let initialize = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(1))
            .expect("initialize must be answered while the daemon binding is pending");
        assert!(
            initialize.pointer("/result/serverInfo/name").is_some(),
            "initialize must carry the ordinary result: {initialize:#?}"
        );
        let tools_list = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(2))
            .expect("tools/list must be answered while the daemon binding is pending");
        assert!(
            tools_list.pointer("/result/tools").is_some(),
            "tools/list must carry the ordinary result: {tools_list:#?}"
        );
    }

    /// A `tools/call` racing a binding that never settles gets the honest
    /// still-starting answer once the bounded grace elapses: not silence, and
    /// not the fall-through refusal this config would otherwise produce (the
    /// empty allow-list answers "not enabled in this MCP profile", so reaching
    /// that text would prove the guard never ran).
    #[tokio::test(start_paused = true)]
    async fn a_tool_call_during_a_pending_binding_answers_that_the_daemon_is_starting() {
        let startup = StartupDaemonBinding::new();

        let responses = drive_daemon_loop_with_startup(
            &[
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                tool_call(3, "kin_graph_status"),
            ],
            None,
            None,
            Some(startup),
        )
        .await;

        let answer = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(3))
            .expect("a tool call during startup binding must be answered, not dropped");
        let text = tool_error_text(answer);
        assert!(
            text.contains("still starting") && text.contains("kin_graph_status"),
            "the answer must say the daemon is starting and name the tool: {text}"
        );
        assert!(
            text.contains("retry"),
            "the remedy is retrying, not remediation: {text}"
        );
        assert!(
            !text.contains("not enabled in this MCP profile"),
            "the still-starting guard must answer before the fall-through path: {text}"
        );
    }

    /// Asking what tools exist neither waits for the daemon nor starts one.
    ///
    /// Two properties in one session, both of which the registry search would
    /// break if it were treated as an ordinary graph call. It must not be
    /// answered "the daemon is still starting", because no daemon can answer it
    /// better; and it must not admit a daemon spawn, because that is the
    /// FIR-3099 property that keeps a session which asked for no graph answer
    /// from opening the store and scheduling a full embedding pass.
    ///
    /// This config carries an empty allow-list, so a call that reaches ordinary
    /// handling answers "not enabled in this MCP profile". Reaching that text is
    /// what proves the exemption ran rather than the wait, and `kin_graph_status`
    /// beside it is the control that must still be told the daemon is starting.
    #[tokio::test(start_paused = true)]
    async fn the_tool_registry_neither_waits_for_the_daemon_nor_starts_one() {
        let startup = StartupDaemonBinding::new();

        let responses = drive_daemon_loop_with_startup(
            &[
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                tool_call(2, crate::handlers::tool_search::TOOL_NAME),
                tool_call(3, "kin_graph_status"),
            ],
            None,
            None,
            Some(std::sync::Arc::clone(&startup)),
        )
        .await;

        let search = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(2))
            .expect("the registry call must be answered, not dropped");
        let search_text = tool_error_text(search);
        assert!(
            !search_text.contains("still starting"),
            "the registry call waited on a daemon it does not read: {search_text}"
        );
        assert!(
            search_text.contains("not enabled in this MCP profile"),
            "the registry call did not reach ordinary handling, so the exemption is untested: \
             {search_text}"
        );

        let status = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(3))
            .expect("the control call must be answered");
        assert!(
            tool_error_text(status).contains("still starting"),
            "the control lost its still-starting answer, so this test would pass with the wait \
             removed for every tool: {}",
            tool_error_text(status)
        );

        // The spawn admission, on its own session, because the control call
        // above admits one by design and would mask this.
        let search_only = StartupDaemonBinding::new();
        drive_daemon_loop_with_startup(
            &[
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                tool_call(2, crate::handlers::tool_search::TOOL_NAME),
            ],
            None,
            None,
            Some(std::sync::Arc::clone(&search_only)),
        )
        .await;
        assert!(
            !search_only.daemon_spawn_admitted(),
            "asking what tools exist admitted a daemon spawn, which opens the store and \
             schedules an embedding pass for a session that asked for no graph answer"
        );

        // And the control for that half: a graph call in the same shape does
        // admit one, so the assertion above is about this tool rather than
        // about a path nothing reaches.
        let graph_call = StartupDaemonBinding::new();
        drive_daemon_loop_with_startup(
            &[
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                tool_call(2, "kin_graph_status"),
            ],
            None,
            None,
            Some(std::sync::Arc::clone(&graph_call)),
        )
        .await;
        assert!(
            graph_call.daemon_spawn_admitted(),
            "no tool admits a daemon spawn any more, so the exemption above proves nothing"
        );
    }

    /// Once the binding settles without a daemon, tool calls fall through to
    /// the ordinary handling instead of reporting a startup that is over.
    #[tokio::test]
    async fn a_tool_call_after_the_binding_settles_unbound_falls_through() {
        let startup = StartupDaemonBinding::new();
        startup.resolve_unbound("not a Kin repository");

        let responses = drive_daemon_loop_with_startup(
            &[
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                tool_call(4, "semantic_locate"),
            ],
            None,
            None,
            Some(startup),
        )
        .await;

        let answer = responses
            .iter()
            .find(|value| value.get("id").and_then(|id| id.as_u64()) == Some(4))
            .expect("the tool call must be answered");
        let text = tool_error_text(answer);
        assert!(
            !text.contains("still starting"),
            "a settled binding must not be reported as still starting: {text}"
        );
        assert!(
            text.contains("not enabled in this MCP profile"),
            "a settled-unbound binding falls through to the ordinary handling: {text}"
        );
    }

    /// A startup binding that settles bound folds into the roots bookkeeping:
    /// the server then behaves as bound, so it does not keep asking a
    /// roots-capable client for a workspace it already serves.
    #[tokio::test]
    async fn a_bound_startup_binding_folds_into_the_roots_bookkeeping() {
        let startup = StartupDaemonBinding::new();
        startup.resolve_bound(bound_repo("/repo/a", "http://127.0.0.1:4111"), false);
        let (binder, calls) = ScriptedBinder::install(vec![]);

        let responses = drive_daemon_loop_with_startup(
            &[
                initialize_with_roots_capability(),
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            ],
            Some(binder),
            None,
            Some(startup),
        )
        .await;

        assert!(
            roots_requests(&responses).is_empty(),
            "a server whose startup binding bound must not keep requesting workspace roots: \
             {responses:#?}"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "the binder must not run while the startup binding already bound"
        );
    }

    /// Every daemon-loss message the delegate mints must go out stamped unreachable.
    ///
    /// The endpoints were each guarded and the join between them was not. The delegate
    /// mints three messages for a daemon that stopped answering; the classifier keyed on
    /// one prefix; and the third, a connection that broke while it was carrying the
    /// request, went out with an empty `degraded` object, which a client reads as a live
    /// daemon. That shape is what an OOM kill mid-answer looks like from here and it is
    /// the first error a caller meets.
    ///
    /// So the cases are BUILT from the delegate's own constructors rather than written out
    /// again as strings. A fourth shape, or a reworded prefix, has to be handled here
    /// rather than merely matched, which is the whole difference between this test and two
    /// correct tests that jointly guard nothing.
    #[test]
    fn every_daemon_loss_message_the_delegate_mints_is_stamped_unreachable() {
        let record = kin_daemon_spawn::DaemonKillRecord {
            kills: 4,
            memory_kills: 4,
            first_unix: 4_320,
            last_unix: 4_800,
            last_pid: Some(41),
            last_cause: kin_daemon_spawn::DaemonKillCause::MemoryLimit {
                kernel_oom_kills: 1,
            },
            limit_bytes: Some(12 * 1024 * 1024 * 1024),
            last_rss_bytes: None,
        };
        for record in [None, Some(&record)] {
            let minted = [
                daemon_delegate::revival_failed_message(
                    "tool semantic_locate",
                    "http://127.0.0.1:42231",
                    "error sending request",
                    "daemon exited during startup with status signal: 9 (SIGKILL)",
                    record,
                ),
                daemon_delegate::revived_retry_failed_message(
                    "tool semantic_locate",
                    "http://127.0.0.1:42232",
                    "timed out",
                    record,
                ),
                daemon_delegate::transport_dropped_message(
                    "MCP tool call",
                    "error sending request for url (http://127.0.0.1:42231/mcp/tools/call)",
                    record,
                ),
            ];
            for message in minted {
                assert_eq!(
                    envelope_for_delegate_error(&message, record)
                        .degraded
                        .daemon_unreachable,
                    Some(true),
                    "a daemon-loss message went out reading as a live daemon: {message}"
                );
            }
        }

        // The control that has to stay silent. A live daemon refusing a call has not
        // become unreachable, and a flag set on everything says nothing.
        let ordinary = envelope_for_delegate_error("no entity named `HTTPAdapter.send`", None);
        assert_eq!(ordinary.degraded.daemon_unreachable, None);
    }

    /// The dead-daemon error is the shape that never set a degraded flag, and a
    /// client cannot tell an empty `degraded` object from a healthy answer
    /// without parsing prose. An ordinary tool error from a live daemon is left
    /// exactly as it was.
    #[test]
    fn a_dead_daemon_error_is_stamped_unreachable_and_an_ordinary_one_is_not() {
        let gone = envelope_for_delegate_error(
            "repo daemon exited; restart required: tool find_references: daemon at \
             http://127.0.0.1:32881 is not responding",
            None,
        );
        assert_eq!(gone.degraded.daemon_unreachable, Some(true));

        let ordinary = envelope_for_delegate_error("no entity named `HTTPAdapter.send`", None);
        assert_eq!(
            ordinary.degraded.daemon_unreachable, None,
            "a live daemon rejecting a call has not become unreachable"
        );
        assert_eq!(
            serde_json::to_value(&ordinary.degraded).unwrap(),
            serde_json::json!({}),
            "an ordinary tool error carries the same empty degraded object it always did"
        );
    }
    /// The bound one `tools/call` waits is decided by whether it is the call
    /// that started the daemon.
    ///
    /// The whole point of the fix is that the first ask is patient and the ones
    /// behind it are not, so both arms are asserted. Asserting only the long one
    /// would keep passing on the day every call got 45 s, which would put a
    /// three-quarter-minute stall in front of every repeat question about a
    /// daemon that is never coming up.
    #[test]
    fn only_the_call_that_starts_the_daemon_gets_the_long_wait() {
        assert_eq!(
            startup_bind_grace(true),
            FIRST_TOOLS_CALL_STARTUP_BIND_GRACE
        );
        assert_eq!(startup_bind_grace(false), TOOLS_CALL_STARTUP_BIND_GRACE);
        assert!(
            FIRST_TOOLS_CALL_STARTUP_BIND_GRACE > TOOLS_CALL_STARTUP_BIND_GRACE,
            "a first call that waited no longer than a repeat call is the defect this fixes"
        );
    }

    /// The first-call bound has to clear what a cold bind actually costs and
    /// stay under what an MCP client will wait.
    ///
    /// The lower bound is the measurement in the constant's own doc: a first
    /// call gave up at 10 s and the next one bound after 15.3 s, so anything at
    /// or under 25 s reproduces the gap. The upper bound is the 60 s per-call
    /// timeout common clients use, which this must never reach or the client
    /// times out instead of reading the report.
    #[test]
    fn the_first_call_bound_clears_the_measured_cold_bind_and_stays_under_a_client_timeout() {
        assert!(
            FIRST_TOOLS_CALL_STARTUP_BIND_GRACE > Duration::from_secs(25),
            "a bound at or under the measured 25 s cold bind fixes nothing"
        );
        assert!(
            FIRST_TOOLS_CALL_STARTUP_BIND_GRACE < Duration::from_secs(60),
            "a bound at a client's own per-call timeout hands the reader a timeout, not a report"
        );
    }

    /// A pending binding answers with the bound it waited, and the answer is
    /// still the structured still-starting result the callers key on.
    #[tokio::test]
    async fn a_first_call_that_outlasts_its_bound_reports_the_bound_it_waited() {
        let startup = StartupDaemonBinding::new();
        assert!(startup.admit_daemon_spawn());
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": "kin_graph_status", "arguments": {} },
        });
        let response =
            startup_pending_response(&request, &startup, FIRST_TOOLS_CALL_STARTUP_BIND_GRACE)
                .expect("a call carrying an id has a response channel");
        let rendered = serde_json::to_string(&response).expect("serialize");
        assert!(
            rendered.contains(&format!(
                "this call waited {}s",
                FIRST_TOOLS_CALL_STARTUP_BIND_GRACE.as_secs()
            )),
            "the report must name the bound this call actually waited: {rendered}"
        );
        assert!(
            rendered.contains("still starting") && rendered.contains("retry"),
            "the answer is still the honest still-starting report: {rendered}"
        );
    }

    // ── The routed profiles ─────────────────────────────────────────────────

    /// A routed profile's config, served the way `kin mcp start` serves it.
    fn routed_config(surface: crate::routed::RoutedSurface) -> McpServerConfig {
        McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(
                crate::tools::agent_routed_tool_names(),
            )),
            agent_belt: true,
            routed: Some(surface),
            number_entity_lines: surface.numbered,
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            ..McpServerConfig::default()
        }
    }

    fn with_writes() -> McpServerConfig {
        routed_config(crate::routed::RoutedSurface::WITH_WRITES)
    }

    fn read_only() -> McpServerConfig {
        routed_config(crate::routed::RoutedSurface::READ_ONLY)
    }

    /// The belt with its write half, which `agent-routed` must answer as.
    fn default_config() -> McpServerConfig {
        McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(
                crate::tools::agent_default_tool_names(),
            )),
            agent_belt: true,
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            ..McpServerConfig::default()
        }
    }

    /// The query belt, which `agent-routed-query` must answer as.
    fn query_config() -> McpServerConfig {
        McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(
                crate::tools::agent_query_tool_names(),
            )),
            agent_belt: true,
            number_entity_lines: true,
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            ..McpServerConfig::default()
        }
    }

    fn tools_call(name: &str, arguments: serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        })
        .to_string()
    }

    /// One change against `focal`'s history, with an id computed from its
    /// content, the shape the history handler's own tests build.
    fn history_change_for(
        parents: Vec<kin_model::SemanticChangeId>,
        deltas: Vec<kin_model::change::EntityDelta>,
        message: &str,
        second: usize,
    ) -> kin_model::change::SemanticChange {
        let root = parents.is_empty();
        let mut change = kin_model::change::SemanticChange {
            id: kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([0; 32])),
            origin: kin_model::change::ChangeOrigin::Native,
            parents,
            timestamp: serde_json::from_value(serde_json::json!(format!(
                "2026-09-22T21:{:02}:{:02}Z",
                second / 60,
                second % 60
            )))
            .unwrap(),
            author: kin_model::AuthorId::new("History parity"),
            message: message.into(),
            entity_deltas: deltas,
            relation_deltas: vec![],
            tree_deltas: vec![],
            admission_policy_delta: root.then(|| {
                kin_model::AdmissionPolicyDelta::initialize(
                    kin_model::SharedAdmissionPolicy::empty(0),
                )
            }),
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            external_reference_deltas: vec![],
            resolution_record_deltas: Vec::new(),
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        change
    }

    /// The bounded entity history answers through the routed tool exactly as
    /// the named `entity_history` tool answers on a profile that serves it:
    /// the same default page of 20 and ceiling of 100, the same
    /// `next_offset`, `change_count` and `latest_change_id`, the same
    /// `max_chars` trimming, and the same structured refusals when the
    /// metadata cannot fit. Reached through `call` and by the tool's own name,
    /// on both routed surfaces, byte for byte once the named answer's hints
    /// name the routed commands.
    #[tokio::test]
    async fn routed_entity_history_pages_and_bounds_like_the_named_tool() {
        use kin_model::change::EntityDelta;
        use kin_model::graph::ChangeStore;
        let (store, entities) = routed_fixture();
        let focal = entities
            .iter()
            .find(|entity| entity.name == "routed_helper")
            .expect("the fixture's helper")
            .clone();
        let bystander = entities
            .iter()
            .find(|entity| entity.name == "routed_caller")
            .expect("the fixture's caller")
            .clone();
        // 35 changes to the helper, with long messages so a budget has to trim.
        let mut parent = Vec::new();
        let mut previous = focal.clone();
        for n in 0..35 {
            let delta = if n == 0 {
                EntityDelta::Added { new: focal.clone() }
            } else {
                let mut revised = previous.clone();
                revised.signature = format!("fn routed_helper() -> u32 /* revision {n} */");
                let old = std::mem::replace(&mut previous, revised.clone());
                EntityDelta::Modified { old, new: revised }
            };
            let change = history_change_for(
                parent.clone(),
                vec![delta],
                &format!("{n}:{}", "界".repeat(150)),
                n,
            );
            store.create_change(&change).unwrap();
            parent = vec![change.id];
        }
        // The caller's history: one change whose ancestry is too long to
        // carry, and one whose metadata no page of max_chars 2,000 can hold.
        let fake_parent = |seed: usize| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(seed as u64).to_le_bytes());
            bytes[31] = 0x5a;
            kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes(bytes))
        };
        let caller_root = history_change_for(
            vec![],
            vec![EntityDelta::Added {
                new: bystander.clone(),
            }],
            "caller root",
            100,
        );
        store.create_change(&caller_root).unwrap();
        let mut revised = bystander.clone();
        revised.signature = "fn routed_caller() -> u32 /* merged */".into();
        let wide_merge = history_change_for(
            std::iter::once(caller_root.id)
                .chain((0..40).map(fake_parent))
                .collect(),
            vec![EntityDelta::Modified {
                old: bystander.clone(),
                new: revised.clone(),
            }],
            "a merge with forty parents",
            101,
        );
        store.create_change(&wide_merge).unwrap();

        let focal_id = focal.id.to_string();
        let caller_id = bystander.id.to_string();
        let named = McpServerConfig {
            allowed_tools: None,
            agent_belt: true,
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
            ..McpServerConfig::default()
        };
        let cases: Vec<serde_json::Value> = vec![
            serde_json::json!({"entity_id": focal_id}),
            serde_json::json!({"entity_id": focal_id, "offset": 20, "limit": 10}),
            serde_json::json!({"entity_id": focal_id, "limit": 100}),
            serde_json::json!({"entity_id": focal_id, "offset": 30}),
            serde_json::json!({"entity_id": focal_id, "max_chars": 8000}),
            serde_json::json!({"entity_id": caller_id, "max_chars": 2000}),
            serde_json::json!({"entity_id": caller_id}),
        ];
        let mut seen_codes = Vec::new();
        let mut seen_next = Vec::new();
        for arguments in &cases {
            let sessions = SessionRegistry::new();
            let named_answer = process_message(
                &tools_call("entity_history", arguments.clone()),
                &store,
                &named,
                &sessions,
            )
            .await
            .expect("a named response");
            let named_answer = presented_as_routed(named_answer, "entity_history", arguments);
            for surface in [with_writes(), read_only()] {
                for routed_args in [
                    serde_json::json!({"command": "call", "args": {"tool": "entity_history", "arguments": arguments}}),
                    serde_json::json!({"command": "entity_history", "args": arguments}),
                ] {
                    let routed_answer = process_message(
                        &tools_call(crate::routed::TOOL_NAME, routed_args.clone()),
                        &store,
                        &surface,
                        &sessions,
                    )
                    .await
                    .expect("a routed response");
                    assert_eq!(
                        serde_json::to_string(&routed_answer.result).unwrap(),
                        serde_json::to_string(&named_answer.result).unwrap(),
                        "{routed_args} on {:?} answered differently from entity_history",
                        surface.routed
                    );
                }
            }
            let text = named_answer.result.as_ref().unwrap()["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string();
            let payload: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            if arguments.get("entity_id") == Some(&serde_json::json!(focal_id))
                && arguments.get("max_chars").is_none()
            {
                let rows = payload["result"].as_array().expect("a real history page");
                let offset = arguments["offset"].as_u64().unwrap_or(0);
                let limit = arguments["limit"].as_u64().unwrap_or(20);
                let returned = rows.len() as u64;
                assert!(returned > 0 && returned <= limit && offset + returned <= 35);
                assert_eq!(payload["returned"], rows.len());
                assert_eq!(
                    payload["next_offset"],
                    if offset + returned < 35 {
                        serde_json::json!(offset + returned)
                    } else {
                        serde_json::Value::Null
                    }
                );
                if limit == 100 {
                    assert!(returned < 35, "the ceiling case must exercise a budget cut");
                }
                assert!(
                    rows.iter().all(|row| row.get("detail_summary").is_none()),
                    "tail rows must be withheld before retained focal details"
                );
            }
            if let Some(code) = payload
                .pointer("/error/code")
                .or_else(|| payload.pointer("/_kin/error/code"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    [
                        "history_metadata_exceeds_budget",
                        "history_ancestry_exceeds_limit",
                    ]
                    .into_iter()
                    .find(|code| text.contains(code))
                    .map(str::to_string)
                })
            {
                seen_codes.push(code);
            }
            if arguments.get("entity_id") == Some(&serde_json::json!(focal_id))
                && arguments.get("max_chars").is_none()
            {
                seen_next.push((
                    arguments.clone(),
                    payload["limit"].clone(),
                    payload["returned"].clone(),
                    payload["next_offset"].clone(),
                    payload["change_count"].clone(),
                    payload["latest_change_id"].is_string(),
                ));
            }
        }
        // The controls: the pages are the bounded ones, and the refusal was
        // reached, so the comparison covered it. The ceiling page gives up tail
        // rows to preserve retained detail. Its size is budget-dependent;
        // next_offset must follow the rows actually returned on both routes.
        let returned = |case: usize| seen_next[case].2.as_u64().expect("returned row count");
        let page = |case: usize, limit: u64, returned: u64, next: serde_json::Value| {
            (
                cases[case].clone(),
                serde_json::json!(limit),
                serde_json::json!(returned),
                next,
                serde_json::json!(35),
                true,
            )
        };
        assert_eq!(
            seen_next,
            vec![
                page(0, 20, returned(0), serde_json::json!(returned(0))),
                page(1, 10, returned(1), serde_json::json!(20 + returned(1))),
                page(2, 100, returned(2), serde_json::json!(returned(2))),
                page(3, 20, 5, serde_json::Value::Null),
            ],
        );
        assert!(
            seen_codes.contains(&"history_metadata_exceeds_budget".to_string()),
            "{seen_codes:?}"
        );

        // Outside the schema's bounds, or the wrong type, both routes refuse,
        // and in the same sentence: the router before dispatch, the named
        // handler itself. Neither clamps.
        for (field, value, sentence) in [
            (
                "limit",
                serde_json::json!(500),
                "entity_history: limit must be at most 100.",
            ),
            (
                "limit",
                serde_json::json!(0),
                "entity_history: limit must be at least 1.",
            ),
            (
                "limit",
                serde_json::json!("ten"),
                "entity_history: limit must be an integer.",
            ),
            (
                "max_chars",
                serde_json::json!(1999),
                "entity_history: max_chars must be at least 2000.",
            ),
            (
                "max_chars",
                serde_json::json!(60001),
                "entity_history: max_chars must be at most 60000.",
            ),
            (
                "offset",
                serde_json::json!(-1),
                "entity_history: offset must be at least 0.",
            ),
        ] {
            let mut arguments = serde_json::json!({"entity_id": focal_id});
            arguments[field] = value.clone();
            let named_answer = process_message(
                &tools_call("entity_history", arguments.clone()),
                &store,
                &named,
                &SessionRegistry::new(),
            )
            .await
            .expect("a named response");
            let named_text = serde_json::to_string(&named_answer.result).unwrap();
            assert_eq!(
                named_answer.result.as_ref().unwrap()["isError"],
                true,
                "{field} {value}: {named_text}"
            );
            assert!(
                named_text.contains(sentence),
                "named {field} {value}: {named_text}"
            );
            for surface in [with_writes(), read_only()] {
                let routed_answer = process_message(
                    &tools_call(
                        crate::routed::TOOL_NAME,
                        serde_json::json!({"command": "call", "args": {"tool": "entity_history", "arguments": arguments}}),
                    ),
                    &store,
                    &surface,
                    &SessionRegistry::new(),
                )
                .await
                .expect("a routed response");
                let routed_text = serde_json::to_string(&routed_answer.result).unwrap();
                assert_eq!(
                    routed_answer.result.as_ref().unwrap()["isError"],
                    true,
                    "{field} {value}: {routed_text}"
                );
                assert!(
                    routed_text.contains(sentence),
                    "routed {field} {value}: {routed_text}"
                );
            }
        }
    }

    /// A store holding one small Rust file whose second function calls its
    /// first, so a reference, a chain and a route all have something to find.
    fn routed_fixture() -> (InMemoryGraph, Vec<kin_model::Entity>) {
        let store = InMemoryGraph::default();
        let bytes = b"fn routed_helper() -> u32 {\n    7\n}\n\nfn routed_caller() -> u32 {\n    routed_helper() + 1\n}\n";
        let kin_index::IndexedAny::EntitySource(indexed) = kin_index::IndexPipeline::new()
            .index_any_content(
                &kin_model::FilePathId::new("src/routed.rs"),
                bytes,
                kin_blobs::digest(bytes),
            )
            .unwrap()
        else {
            panic!("source fixture");
        };
        for entity in &indexed.entities {
            kin_model::EntityStore::upsert_entity(&store, entity).unwrap();
        }
        for relation in &indexed.relations {
            kin_model::EntityStore::upsert_relation(&store, relation).unwrap();
        }
        store.flush_text_index().unwrap();
        (store, indexed.entities)
    }

    /// `text` with every UUID replaced by one placeholder.
    fn mask_uuids(text: &str) -> String {
        let bytes = text.as_bytes();
        let shape = |at: usize| {
            at + 36 <= bytes.len()
                && bytes[at..at + 36].iter().enumerate().all(|(index, byte)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        *byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit()
                    }
                })
        };
        let mut out = String::with_capacity(text.len());
        let mut index = 0;
        while index < bytes.len() {
            if shape(index) {
                out.push_str("<uuid>");
                index += 36;
            } else {
                let character = text[index..].chars().next().unwrap();
                out.push(character);
                index += character.len_utf8();
            }
        }
        out
    }

    /// The named answer as a routed connection presents it: the same bytes
    /// with its hints naming the routed commands.
    fn presented_as_routed(
        mut response: JsonRpcResponse,
        tool: &str,
        arguments: &serde_json::Value,
    ) -> JsonRpcResponse {
        let params: ToolCallParams =
            serde_json::from_value(serde_json::json!({"name": tool, "arguments": arguments}))
                .unwrap();
        present_routed_hints(&mut response, &params);
        response
    }

    fn finalized_hint_context(
        tool: &str,
        arguments: &serde_json::Value,
        hint: &str,
        body: &str,
    ) -> JsonRpcResponse {
        let params: ToolCallParams = serde_json::from_value(serde_json::json!({
            "name": tool, "arguments": arguments
        }))
        .unwrap();
        let payload = serde_json::json!({
            "token_budget": 8000, "tokens_used": 0,
            "focal_entity": {"id": "focal", "name": "focal", "body": body, "body_complete": true},
            "dependencies": [{"id": "dependency", "name": "dependency", "body_unavailable": hint}],
            "dependents": [],
            "degradations": [{"reason": "references_are_incomplete"}]
        });
        let result = envelope::finalize_bounded(
            ToolCallResult::text(payload.to_string()),
            Envelope::daemon(),
            tool,
            &ResponseBudget::from_arguments(&params.arguments),
        );
        assert_ne!(result.is_error, Some(true));
        JsonRpcResponse::success(
            Some(serde_json::json!(1)),
            serde_json::to_value(result).unwrap(),
        )
    }

    fn presented_text(response: &JsonRpcResponse) -> &str {
        response.result.as_ref().unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
    }

    /// Exercise the supported final presentation boundary after real envelope
    /// qualification, including shortening, lengthening and equal-byte hints.
    #[test]
    fn routed_hint_accounting_matches_final_context_wire_without_changing_facts() {
        let body = "fn café() {\r\n    execute();\r\n}";
        let hints = [
            (
                "no source body was read for this row: it was not priced by this request's source projection; read it with get_entity_source",
                "no source body was read for this row: it was not priced by this request's source projection; read it with kin source",
            ),
            ("use graph_neighborhood", "use kin call graph_neighborhood"),
            ("use trace_data_flow", "use kin trace-data-flow"),
            ("use kin_graph_status", "use kin graph status"),
        ];
        for tool in ["get_context_pack", "trace_computation"] {
            for compact in [true, false] {
                let args = serde_json::json!({"compact": compact, "max_chars": 60000});
                for (hint, routed_hint) in hints {
                    let before = finalized_hint_context(tool, &args, hint, body);
                    let mut expected: serde_json::Value =
                        serde_json::from_str(presented_text(&before)).unwrap();
                    let after = presented_as_routed(before, tool, &args);
                    let text = presented_text(&after);
                    let actual: serde_json::Value = serde_json::from_str(text).unwrap();
                    assert_eq!(actual["dependencies"][0]["body_unavailable"], routed_hint);
                    assert_eq!(actual["_kin"]["response"]["chars_after_budget"], text.len());
                    assert_eq!(actual["tokens_used"], kin_context::estimate_tokens(text));
                    assert_eq!(text.contains('\n'), !compact);
                    assert!(text.len() <= 60000);
                    assert!(kin_context::estimate_tokens(text) <= 8000);
                    // Every fact, source byte, standing limitation, negative and
                    // authority field stays equal. Only these three values vary.
                    expected["dependencies"][0]["body_unavailable"] =
                        serde_json::json!(routed_hint);
                    expected["_kin"]["response"]["chars_after_budget"] =
                        serde_json::json!(text.len());
                    expected["tokens_used"] = serde_json::json!(kin_context::estimate_tokens(text));
                    assert_eq!(actual, expected, "{tool}, compact={compact}, {hint}");
                }
            }
        }
    }

    /// A routed spelling can be shorter in bytes and still require more of the
    /// context token estimate. It must not escape the effective context tier.
    #[test]
    fn routed_hint_accounting_keeps_original_at_effective_token_limit() {
        let args = serde_json::json!({"token_budget": 4000, "max_chars": 60000});
        for tool in ["get_context_pack", "trace_computation"] {
            let mut words = 5000;
            let mut at_limit = None;
            for _ in 0..8 {
                let body = "word ".repeat(words);
                let before = finalized_hint_context(tool, &args, "use get_entity_source", &body);
                let text = presented_text(&before);
                let payload: serde_json::Value = serde_json::from_str(text).unwrap();
                assert_eq!(payload["focal_entity"]["body"], body);
                let tokens = kin_context::estimate_tokens(text);
                assert!(tokens <= 8000);
                if tokens == 8000 {
                    at_limit = Some(before);
                    break;
                }
                words += ((8000 - tokens) * 7 / 8).max(1);
            }
            let before = at_limit.expect("the real finalizer reaches the effective token ceiling");
            // The same payload with room still takes the routed spelling even
            // though its effective tier exceeds the caller's requested tier.
            let roomy = finalized_hint_context(
                tool,
                &args,
                "use get_entity_source",
                &"word ".repeat(words - 100),
            );
            assert!(kin_context::estimate_tokens(presented_text(&roomy)) > 4000);
            let roomy_after = presented_as_routed(roomy, tool, &args);
            let payload: serde_json::Value =
                serde_json::from_str(presented_text(&roomy_after)).unwrap();
            assert_eq!(
                payload["dependencies"][0]["body_unavailable"],
                "use kin source"
            );
            let original = before.result.clone();
            let after = presented_as_routed(before, tool, &args);
            assert_eq!(after.result, original, "the named spelling fits exactly");
            assert_eq!(kin_context::estimate_tokens(presented_text(&after)), 8000);
        }
    }

    /// Recounting the final byte counter itself can add a digit. The old hint
    /// byte guard alone admitted this rewrite with stale four-digit accounting.
    #[test]
    fn routed_hint_accounting_checks_ceiling_after_counter_growth() {
        let args = serde_json::json!({"max_chars": 10000});
        let mut padding = 6000;
        let mut exact = None;
        for _ in 0..8 {
            let body = "x".repeat(padding);
            let before =
                finalized_hint_context("get_context_pack", &args, "use graph_neighborhood", &body);
            let text = presented_text(&before);
            let payload: serde_json::Value = serde_json::from_str(text).unwrap();
            assert_eq!(payload["focal_entity"]["body"], body);
            if text.len() == 9991 {
                exact = Some(before);
                break;
            }
            padding = padding
                .checked_add_signed(9991 - text.len() as isize)
                .unwrap();
        }
        let before = exact.expect("the finalized fixture is nine bytes below its ceiling");
        let original = before.result.clone();
        let after = presented_as_routed(before, "get_context_pack", &args);
        assert_eq!(after.result, original);
        assert_eq!(presented_text(&after).len(), 9991);
    }

    #[test]
    fn routed_hint_accounting_preserves_existing_soft_budget_residual() {
        let args = serde_json::json!({"max_chars": 2000});
        let params: ToolCallParams = serde_json::from_value(serde_json::json!({
            "name": "find_references", "arguments": args
        }))
        .unwrap();
        let result = envelope::finalize_bounded(
            ToolCallResult::text(
                serde_json::json!({
                    "references": [], "total": 0, "observation": "x".repeat(4000),
                    "hint": "use get_entity_source"
                })
                .to_string(),
            ),
            Envelope::daemon(),
            "find_references",
            &ResponseBudget::from_arguments(&params.arguments),
        );
        let before = JsonRpcResponse::success(
            Some(serde_json::json!(1)),
            serde_json::to_value(result).unwrap(),
        );
        assert!(presented_text(&before).len() > 2000);
        assert!(presented_text(&before).contains("response_over_budget"));
        let original = before.result.clone();
        let after = presented_as_routed(before, "find_references", &args);
        assert_eq!(after.result, original);
    }

    /// `graph source` and `kin graph source`, the CLI's spellings, answer a
    /// routed call byte for byte as `source` does on both routed profiles:
    /// payload, `_kin` envelope and any refusal. The Kin block `kin setup`
    /// writes for a routed client names source that way, so the same words
    /// run through the routed tool and in a shell.
    #[tokio::test]
    async fn graph_source_answers_exactly_as_source_does() {
        async fn answer(
            store: &InMemoryGraph,
            config: &McpServerConfig,
            command: &str,
            entity_id: &str,
        ) -> serde_json::Value {
            let request = tools_call(
                crate::routed::TOOL_NAME,
                serde_json::json!({"command": command, "args": {"entity_id": entity_id}}),
            );
            let response = process_message(&request, store, config, &SessionRegistry::new())
                .await
                .expect("a routed response");
            assert!(response.error.is_none(), "{command} was a transport error");
            response.result.expect("a result")
        }

        let (store, entities) = routed_fixture();
        let helper = entities
            .iter()
            .find(|entity| entity.name == "routed_helper")
            .expect("the fixture has routed_helper")
            .id
            .to_string();
        for config in [with_writes(), read_only()] {
            let source = answer(&store, &config, "source", &helper).await;
            let text = source["content"][0]["text"].as_str().expect("a text block");
            let payload: serde_json::Value =
                serde_json::from_str(text).expect("an enveloped payload is JSON");
            assert!(payload.get(ENVELOPE_KEY).is_some(), "{payload}");
            assert!(
                payload.get("example").is_none(),
                "source stopped at the router: {payload}"
            );
            for spelling in ["graph source", "kin graph source"] {
                assert_eq!(
                    answer(&store, &config, spelling, &helper).await,
                    source,
                    "{spelling} on {:?}",
                    config.routed
                );
            }
        }
    }

    /// Every routed command answers with exactly what its named tool answers
    /// on the named profile it stands in for, for the same arguments: payload,
    /// negative evidence and `_kin` envelope, byte for byte once the named
    /// answer's hints name the routed commands, including where the named tool
    /// itself refuses. `agent-routed` answers as `agent-default`, writes
    /// included, and `agent-routed-query` as `agent-query`.
    #[tokio::test]
    async fn each_routed_command_returns_its_named_tool_payload() {
        let (store, entities) = routed_fixture();
        let id_of = |name: &str| {
            entities
                .iter()
                .find(|entity| entity.name == name)
                .unwrap_or_else(|| panic!("the fixture has no {name}"))
                .id
                .to_string()
        };
        let (helper, caller) = (id_of("routed_helper"), id_of("routed_caller"));
        let reads: Vec<(serde_json::Value, &str, serde_json::Value)> = vec![
            (
                serde_json::json!({"command": "locate", "args": {"query": "routed helper"}}),
                "semantic_locate",
                serde_json::json!({"query": "routed helper"}),
            ),
            (
                serde_json::json!({"command": "search", "args": {"query": "routed_helper"}}),
                "semantic_search",
                serde_json::json!({"query": "routed_helper"}),
            ),
            (
                serde_json::json!({"command": "search", "args": {"literal": "routed_helper()"}}),
                "lexical_lookup",
                serde_json::json!({"literal": "routed_helper()"}),
            ),
            (
                serde_json::json!({"command": "context", "args": {"entity_id": caller}}),
                "get_context_pack",
                serde_json::json!({"entity_id": caller}),
            ),
            (
                serde_json::json!({"command": "refs", "args": {"entity_id": helper}}),
                "find_references",
                serde_json::json!({"entity_id": helper}),
            ),
            (
                serde_json::json!({"command": "trace", "args": {"focal": caller}}),
                "trace_data_flow",
                serde_json::json!({"focal": caller}),
            ),
            (
                serde_json::json!({"command": "path", "args": {"from": caller, "to": helper}}),
                "trace_path",
                serde_json::json!({"from": caller, "to": helper}),
            ),
            (
                serde_json::json!({"command": "impact", "args": {"entity_ids": [helper]}}),
                "impact_analysis",
                serde_json::json!({"entity_ids": [helper]}),
            ),
            (
                serde_json::json!({"command": "source", "args": {"entity_id": helper}}),
                "get_entity_source",
                serde_json::json!({"entity_id": helper}),
            ),
            (
                serde_json::json!({"command": "status"}),
                "kin_graph_status",
                serde_json::json!({}),
            ),
            (
                serde_json::json!({"command": "call", "args": {"tool": "graph_neighborhood", "arguments": {"entity_id": helper}}}),
                "graph_neighborhood",
                serde_json::json!({"entity_id": helper}),
            ),
            (
                serde_json::json!({"command": "graph_neighborhood", "args": {"entity_id": helper}}),
                "graph_neighborhood",
                serde_json::json!({"entity_id": helper}),
            ),
        ];
        // A mutate the handler refuses before it changes anything, so both
        // calls meet the same store: kin_mutate's own refusal, the same way
        // whichever name reached it. The update names an entity the store does
        // not hold and carries its source base, so it passes the semantic check
        // and opens a transaction before the in-process commit refuses its body.
        let edit = guarded_update_operation("fn x() {}");
        let writes: Vec<(serde_json::Value, &str, serde_json::Value)> = vec![(
            serde_json::json!({"command": "mutate", "args": {"operations": [edit]}}),
            "kin_mutate",
            serde_json::json!({"operations": [edit]}),
        )];
        let mut answered: Vec<&str> = Vec::new();
        let cases = reads
            .iter()
            .map(|case| (case, true))
            .chain(writes.iter().map(|case| (case, false)));
        for ((routed_args, tool, named_args), read) in cases {
            let pairs: Vec<(McpServerConfig, McpServerConfig)> = if read {
                vec![
                    (with_writes(), default_config()),
                    (read_only(), query_config()),
                ]
            } else {
                vec![(with_writes(), default_config())]
            };
            for (routed, named) in pairs {
                let sessions = SessionRegistry::new();
                let routed_answer = process_message(
                    &tools_call(crate::routed::TOOL_NAME, routed_args.clone()),
                    &store,
                    &routed,
                    &sessions,
                )
                .await
                .expect("a routed response");
                let named_answer = process_message(
                    &tools_call(tool, named_args.clone()),
                    &store,
                    &named,
                    &sessions,
                )
                .await
                .expect("a named response");
                assert!(
                    routed_answer.error.is_none(),
                    "{routed_args} was a transport error"
                );
                let named_answer = presented_as_routed(named_answer, tool, named_args);
                // A write opens its own transaction, so the two answers carry
                // different transaction ids and nothing else.
                let comparable = |result: &Option<serde_json::Value>| {
                    let mut result = result.clone();
                    // Independent traversals record their own duration. Normalize
                    // only the measured elapsed_ms, never semantic payload data.
                    if let Some(contents) = result
                        .as_mut()
                        .and_then(|v| v.get_mut("content"))
                        .and_then(serde_json::Value::as_array_mut)
                    {
                        for block in contents {
                            if let Some(text) =
                                block.get("text").and_then(serde_json::Value::as_str)
                            {
                                if let Ok(mut payload) =
                                    serde_json::from_str::<serde_json::Value>(text)
                                {
                                    if let Some(explored) = payload
                                        .get_mut("explored")
                                        .and_then(serde_json::Value::as_array_mut)
                                    {
                                        for row in explored {
                                            if row.get("elapsed_ms").is_some() {
                                                row["elapsed_ms"] = serde_json::json!(0);
                                            }
                                        }
                                    }
                                    block["text"] =
                                        serde_json::json!(serde_json::to_string(&payload).unwrap());
                                }
                            }
                        }
                    }
                    let text = serde_json::to_string(&result).unwrap();
                    if read {
                        text
                    } else {
                        mask_uuids(&text)
                    }
                };
                assert_eq!(
                    comparable(&routed_answer.result),
                    comparable(&named_answer.result),
                    "{routed_args} on {:?} answered differently from {tool}",
                    routed.routed
                );
                let result = routed_answer.result.expect("a result");
                let text = result["content"][0]["text"].as_str().expect("a text block");
                let payload: serde_json::Value =
                    serde_json::from_str(text).expect("an enveloped payload is JSON");
                assert!(
                    payload.get(ENVELOPE_KEY).is_some(),
                    "{routed_args} came back without the envelope: {payload}"
                );
                if result.get("isError") != Some(&serde_json::json!(true)) {
                    if routed.routed.is_some_and(|surface| surface.writes) {
                        answered.push(tool);
                    }
                    continue;
                }
                // The in-process route has no daemon and no pinned repository
                // authority, so some tools refuse here. Their refusal has to be
                // the HANDLER's own, which proves the routed call reached the
                // handler rather than stopping at the router.
                assert!(
                    payload.get("example").is_none(),
                    "{tool} came back with the router's refusal: {payload}"
                );
            }
        }
        // The control: the graph-only tools answer for real here, so the
        // comparison covers real payloads and not only matching refusals.
        answered.sort_unstable();
        assert!(
            answered.len() >= 5
                && [
                    "impact_analysis",
                    "semantic_search",
                    "trace_data_flow",
                    "trace_path"
                ]
                .iter()
                .all(|tool| answered.contains(tool)),
            "the commands that answer in-process moved: {answered:?}"
        );
    }

    /// A write on the read-only routed surface is refused before anything
    /// runs, and the refusal names the profile that carries it.
    #[tokio::test]
    async fn the_read_only_routed_surface_refuses_every_write() {
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        for arguments in [
            serde_json::json!({"command": "mutate", "args": {"operations": []}}),
            serde_json::json!({"command": "session", "args": {"vendor": "v", "client_name": "c", "cwd": "/"}}),
            serde_json::json!({"command": "kin_mutate", "args": {"operations": []}}),
            serde_json::json!({"command": "call", "args": {"tool": "kin_transaction_begin", "arguments": {}}}),
        ] {
            let result = process_message(
                &tools_call(crate::routed::TOOL_NAME, arguments.clone()),
                &store,
                &read_only(),
                &sessions,
            )
            .await
            .unwrap()
            .result
            .unwrap();
            assert_eq!(result["isError"], true, "{arguments}");
            let payload: serde_json::Value =
                serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
            let message = payload["message"].as_str().unwrap();
            assert!(
                message.contains("read-only agent-routed-query")
                    && message.contains("agent-routed profile carries"),
                "{arguments}: {message}"
            );
            assert!(payload.get(ENVELOPE_KEY).is_some());
        }
        assert!(
            sessions.list_agent_sessions().is_empty(),
            "a refused write still opened a session"
        );
        // Named directly, the write tool is refused the same way.
        let direct = process_message(
            &tools_call("kin_mutate", serde_json::json!({"operations": []})),
            &store,
            &read_only(),
            &sessions,
        )
        .await
        .unwrap()
        .result
        .unwrap();
        assert!(direct["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("agent-routed profile carries"));
    }

    /// `describe` and a refusal are answered by this server, with the
    /// envelope, on both routes, and the daemon route needs no daemon for
    /// either because neither reads a graph.
    #[tokio::test]
    async fn routed_describe_and_refusals_carry_the_envelope_on_both_routes() {
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        for surface in [
            crate::routed::RoutedSurface::WITH_WRITES,
            crate::routed::RoutedSurface::READ_ONLY,
        ] {
            let offline = routed_config(surface);
            let mut daemon_config = routed_config(surface);
            daemon_config.session_authority_mode = SessionAuthorityMode::DaemonRequired;
            for (arguments, is_error) in [
                (
                    serde_json::json!({"command": "describe", "args": {"command": "search"}}),
                    false,
                ),
                (serde_json::json!({"command": "describe"}), false),
                (
                    serde_json::json!({"command": "locate", "args": {"q": "retries"}}),
                    true,
                ),
            ] {
                let message = tools_call(crate::routed::TOOL_NAME, arguments.clone());
                for response in [
                    process_message(&message, &store, &offline, &sessions).await,
                    process_daemon_message(&message, &daemon_config).await,
                ] {
                    let result = response.expect("a response").result.expect("a result");
                    assert_eq!(
                        result.get("isError") == Some(&serde_json::json!(true)),
                        is_error,
                        "{arguments}: {result}"
                    );
                    let payload: serde_json::Value =
                        serde_json::from_str(result["content"][0]["text"].as_str().unwrap())
                            .unwrap();
                    assert!(payload.get(ENVELOPE_KEY).is_some(), "{payload}");
                    if is_error {
                        let message = payload["message"].as_str().expect("a refusal says why");
                        assert!(message.contains("query (string)"), "{message}");
                        assert_eq!(payload["example"]["command"], "locate");
                    } else if arguments.get("args").is_some() {
                        assert_eq!(payload["variants"].as_array().map(Vec::len), Some(2));
                    } else {
                        assert!(payload["other_tools"]
                            .as_array()
                            .is_some_and(|rows| !rows.is_empty()));
                    }
                }
            }
            // The control: a named tool the routed profile does not serve is
            // still refused, so routing did not become a way around the
            // profile, and the refusal names the command that runs it here.
            let refused = process_message(
                &tools_call("semantic_locate", serde_json::json!({"query": "x"})),
                &store,
                &offline,
                &sessions,
            )
            .await
            .unwrap()
            .result
            .unwrap();
            let text = refused["content"][0]["text"].as_str().unwrap();
            assert!(text.contains("not enabled in this MCP profile"), "{text}");
            assert!(text.contains("command locate"), "{text}");
        }
    }

    /// Initialize serves the operating procedure worded for the surface the
    /// profile serves.
    #[tokio::test]
    async fn initialize_serves_the_procedure_for_the_profile() {
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        let message = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        for (config, expected, names) in [
            (with_writes(), ROUTED_SERVER_INSTRUCTIONS, "kin locate"),
            (read_only(), ROUTED_QUERY_SERVER_INSTRUCTIONS, "kin locate"),
            (query_config(), SERVER_INSTRUCTIONS, "semantic_locate"),
            (default_config(), SERVER_INSTRUCTIONS, "semantic_locate"),
            (
                McpServerConfig::default(),
                SERVER_INSTRUCTIONS,
                "semantic_locate",
            ),
        ] {
            let result = process_message(message, &store, &config, &sessions)
                .await
                .unwrap()
                .result
                .unwrap();
            let instructions = result["instructions"].as_str().unwrap();
            assert_eq!(instructions, expected);
            assert!(instructions.contains(names));
            for step in ["1. ", "2. ", "3. ", "4. ", "5. "] {
                assert!(
                    instructions.contains(&format!("\n{step}")),
                    "{step}: {instructions}"
                );
            }
        }
    }

    /// Each profile's `tools/list` is what its surface says: one routed tool on
    /// the routed profiles, read-only on the read-only one, and the source
    /// tool described the way the connection serves bodies.
    #[tokio::test]
    async fn each_profile_lists_what_its_surface_serves() {
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let listed = |config: McpServerConfig| {
            let store = &store;
            let sessions = &sessions;
            async move {
                process_message(list, store, &config, sessions)
                    .await
                    .unwrap()
                    .result
                    .unwrap()["tools"]
                    .as_array()
                    .unwrap()
                    .clone()
            }
        };
        let routed = listed(with_writes()).await;
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0]["name"], crate::routed::TOOL_NAME);
        assert_eq!(routed[0]["annotations"]["readOnlyHint"], false);
        let commands = routed[0]["inputSchema"]["properties"]["command"]["enum"].clone();
        assert!(commands
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("mutate")));

        let query_routed = listed(read_only()).await;
        assert_eq!(query_routed.len(), 1);
        assert_eq!(query_routed[0]["annotations"]["readOnlyHint"], true);
        let commands = query_routed[0]["inputSchema"]["properties"]["command"]["enum"].clone();
        assert!(!commands
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("mutate")));
        assert!(query_routed[0]["description"]
            .as_str()
            .unwrap()
            .contains("+N offsets"));

        let source = |tools: &[serde_json::Value]| {
            tools
                .iter()
                .find(|tool| tool["name"] == "get_entity_source")
                .map(|tool| tool["description"].as_str().unwrap().to_string())
                .unwrap()
        };
        assert_eq!(
            source(&listed(query_config()).await),
            crate::entity_lines::NUMBERED_SOURCE_DESCRIPTION
        );
        assert_ne!(
            source(&listed(default_config()).await),
            crate::entity_lines::NUMBERED_SOURCE_DESCRIPTION
        );
    }

    async fn drive_daemon_loop_with_initializer(
        client_messages: &[serde_json::Value],
        config: McpServerConfig,
        initializer: Option<crate::repository_init::RepoInitializer>,
    ) -> Vec<serde_json::Value> {
        let mut input = String::new();
        for message in client_messages {
            input.push_str(&message.to_string());
            input.push('\n');
        }
        let mut reader = BufReader::new(input.as_bytes());
        let mut written: Vec<u8> = Vec::new();
        run_stdio_daemon_over(
            &mut reader,
            &mut written,
            config,
            None,
            None,
            None,
            initializer,
        )
        .await
        .expect("stdio loop must drain the scripted client session");
        String::from_utf8(written)
            .expect("server output is UTF-8")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("server output is JSON-RPC"))
            .collect()
    }

    /// `kin_init` is answered by the stdio loop on the profiles that write,
    /// named and routed, with the folder the client works in as its default,
    /// and it runs only the initializer the launcher handed over. Setting a
    /// folder up is a write: every read-only profile refuses it by every name
    /// it could be reached by, and the initializer never runs for one.
    #[tokio::test]
    async fn kin_init_is_served_only_where_kin_writes() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<PathBuf>::new()));
        let recorder = std::sync::Arc::clone(&seen);
        let initializer: crate::repository_init::RepoInitializer =
            std::sync::Arc::new(move |dir: PathBuf| {
                recorder.lock().unwrap().push(dir);
                Box::pin(async {
                    crate::repository_init::InitOutcome::Initialized {
                        report: Some(serde_json::json!({"initialized": true})),
                    }
                })
            });
        let call = |id: u32, name: &str, arguments: serde_json::Value| {
            serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                               "params": {"name": name, "arguments": arguments}})
        };
        let payload = |response: &serde_json::Value| -> serde_json::Value {
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap()
        };
        let text = |response: &serde_json::Value| -> String {
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        };
        let with_folder = |mut config: McpServerConfig| {
            config.session_authority_mode = SessionAuthorityMode::DaemonRequired;
            config.client_root = Some(PathBuf::from("/work/app"));
            config
        };

        assert!(default_config().serves_init());
        assert!(with_writes().serves_init());
        assert!(
            McpServerConfig::default().serves_init(),
            "full serves every tool"
        );
        let named = drive_daemon_loop_with_initializer(
            &[
                call(1, "kin_init", serde_json::json!({})),
                call(2, "kin_init", serde_json::json!({"path": "sub"})),
            ],
            with_folder(default_config()),
            Some(initializer.clone()),
        )
        .await;
        assert_eq!(payload(&named[0])["state"], "initialized", "{}", named[0]);
        assert_eq!(payload(&named[0])["folder"], "/work/app");
        assert!(payload(&named[0])["next_step"]
            .as_str()
            .unwrap()
            .contains("find_references"));
        assert!(payload(&named[0]).get(ENVELOPE_KEY).is_some());
        assert_eq!(payload(&named[1])["folder"], "/work/app/sub");

        let routed = drive_daemon_loop_with_initializer(
            &[call(
                3,
                crate::routed::TOOL_NAME,
                serde_json::json!({"command": "init"}),
            )],
            with_folder(with_writes()),
            Some(initializer.clone()),
        )
        .await;
        let answer = payload(&routed[0]);
        assert_eq!(answer["state"], "initialized", "{answer}");
        assert!(
            answer["next_step"].as_str().unwrap().contains("kin refs"),
            "a routed connection is told its own command: {answer}"
        );
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![
                PathBuf::from("/work/app"),
                PathBuf::from("/work/app/sub"),
                PathBuf::from("/work/app"),
            ]
        );

        // No initializer: the call is answered, and says where it is answered.
        let without = drive_daemon_loop_with_initializer(
            &[call(4, "kin_init", serde_json::json!({}))],
            with_folder(default_config()),
            None,
        )
        .await;
        assert_eq!(without[0]["result"]["isError"], true);

        // Every read-only profile, and the citable ones, refuse it.
        let search = McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(
                crate::tools::agent_search_tool_names(),
            )),
            agent_belt: true,
            ..McpServerConfig::default()
        };
        let citable = |names: &[&str]| McpServerConfig {
            allowed_tools: Some(crate::tools::name_set(names)),
            citable: true,
            ..McpServerConfig::default()
        };
        let refusals: Vec<(&str, McpServerConfig, serde_json::Value, &str)> = vec![
            (
                "agent-query",
                query_config(),
                call(5, "kin_init", serde_json::json!({})),
                "not enabled in this MCP profile",
            ),
            (
                "agent-search",
                search.clone(),
                call(6, "kin_init", serde_json::json!({})),
                "not enabled in this MCP profile",
            ),
            (
                "agent-search through its dispatcher",
                search,
                call(
                    7,
                    "kin_tool_call",
                    serde_json::json!({"tool": "kin_init", "arguments": {}}),
                ),
                "kin_tool_call is read-only",
            ),
            (
                "benchmark",
                citable(crate::tools::benchmark_tool_names()),
                call(8, "kin_init", serde_json::json!({})),
                "not enabled in this MCP profile",
            ),
            (
                "context-bench",
                citable(crate::tools::context_bench_tool_names()),
                call(9, "kin_init", serde_json::json!({})),
                "not enabled in this MCP profile",
            ),
            (
                "agent-routed-query init",
                read_only(),
                call(
                    10,
                    crate::routed::TOOL_NAME,
                    serde_json::json!({"command": "init"}),
                ),
                "The agent-routed profile carries Kin's writes.",
            ),
            (
                "agent-routed-query by the tool's name",
                read_only(),
                call(
                    11,
                    crate::routed::TOOL_NAME,
                    serde_json::json!({"command": "kin_init"}),
                ),
                "The agent-routed profile carries Kin's writes.",
            ),
            (
                "agent-routed-query through call",
                read_only(),
                call(
                    12,
                    crate::routed::TOOL_NAME,
                    serde_json::json!({"command": "call", "args": {"tool": "kin_init", "arguments": {}}}),
                ),
                "The agent-routed profile carries Kin's writes.",
            ),
            (
                "agent-routed-query named",
                read_only(),
                call(13, "kin_init", serde_json::json!({})),
                "kin_init",
            ),
        ];
        for (label, config, request, expected) in refusals {
            assert!(!config.serves_init(), "{label}");
            let answered = drive_daemon_loop_with_initializer(
                &[request],
                with_folder(config),
                Some(initializer.clone()),
            )
            .await;
            // Refused as a tool error, or, where a dispatcher rejects the
            // arguments before any tool runs, as a JSON-RPC error.
            let refusal = match answered[0].get("error") {
                Some(error) => error.to_string(),
                None => {
                    assert_eq!(
                        answered[0]["result"]["isError"], true,
                        "{label}: {}",
                        answered[0]
                    );
                    text(&answered[0])
                }
            };
            assert!(refusal.contains(expected), "{label}: {}", answered[0]);
        }
        assert_eq!(
            seen.lock().unwrap().len(),
            3,
            "no read-only or citable profile ran the initializer"
        );
    }

    /// The listing each profile serves carries `kin_init`, or the routed
    /// `init` command, only where the profile writes.
    #[test]
    fn only_the_profiles_that_write_list_kin_init() {
        let listed = |config: &McpServerConfig| -> Vec<String> {
            served_tools_for(config)
                .tools
                .iter()
                .map(|tool| tool.name.clone())
                .collect()
        };
        assert!(listed(&default_config()).contains(&"kin_init".to_string()));
        assert!(listed(&McpServerConfig::default()).contains(&"kin_init".to_string()));
        for (label, config) in [
            ("agent-query", query_config()),
            (
                "agent-search",
                McpServerConfig {
                    allowed_tools: Some(crate::tools::name_set(
                        crate::tools::agent_search_tool_names(),
                    )),
                    ..McpServerConfig::default()
                },
            ),
            (
                "benchmark",
                McpServerConfig {
                    allowed_tools: Some(crate::tools::name_set(
                        crate::tools::benchmark_tool_names(),
                    )),
                    ..McpServerConfig::default()
                },
            ),
            (
                "context-bench",
                McpServerConfig {
                    allowed_tools: Some(crate::tools::name_set(
                        crate::tools::context_bench_tool_names(),
                    )),
                    ..McpServerConfig::default()
                },
            ),
        ] {
            assert!(
                !listed(&config).contains(&"kin_init".to_string()),
                "{label}"
            );
            assert!(!config.serves_init(), "{label}");
        }
        let routed_enum = |config: &McpServerConfig| -> Vec<String> {
            served_tools_for(config).tools[0].input_schema["properties"]["command"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect()
        };
        assert!(routed_enum(&with_writes()).contains(&"init".to_string()));
        assert!(!routed_enum(&read_only()).contains(&"init".to_string()));
        assert!(
            !served_tools_for(&with_writes()).tools[0]
                .annotations
                .read_only_hint
        );
        assert!(
            served_tools_for(&read_only()).tools[0]
                .annotations
                .read_only_hint
        );
    }

    /// Every answer on a connection whose client works in a folder inside the
    /// bound repository leads with which repository answered, whatever
    /// produced it; an answer from the client's own folder is left as it is.
    #[test]
    fn every_answer_for_a_nested_folder_leads_with_the_repository_that_answered() {
        let answer = |text: &str| {
            JsonRpcResponse::success(
                Some(serde_json::json!(1)),
                serde_json::json!({"content": [{"type": "text", "text": text}]}),
            )
        };
        let text_of = |response: &JsonRpcResponse| -> String {
            response.result.as_ref().unwrap()["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let nested = McpServerConfig {
            client_root: Some(PathBuf::from("/work/repo/app")),
            ..McpServerConfig::default()
        };
        let root = Path::new("/work/repo");

        // A routed refusal answered here, with an envelope and no repository,
        // in each wire format. The stamp keeps the format the answer already
        // had, and the warning leads the envelope in both.
        let refusal = serde_json::json!({"_kin": {"envelope_version": 2}, "message": "no"});
        let pretty = serde_json::to_string_pretty(&refusal).unwrap();
        let mut refused = answer(&pretty);
        stamp_client_folder(&mut refused, Some(root), &nested);
        let text = text_of(&refused);
        let first = text.lines().nth(2).unwrap().trim_start();
        assert!(first.starts_with("\"advice\": \"This answer comes from the Kin repository at /work/repo, not from /work/repo/app"), "{text}");
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["_kin"]["repository"]["root"], "/work/repo");
        assert_eq!(value["_kin"]["repository"]["client_root"], "/work/repo/app");
        assert_eq!(value["message"], "no");
        let mut compact = answer(&refusal.to_string());
        stamp_client_folder(&mut compact, Some(root), &nested);
        let compact_text = text_of(&compact);
        assert!(!compact_text.contains('\n'), "{compact_text}");
        assert!(compact_text.starts_with("{\"_kin\":{\"advice\":\"This answer comes from the Kin repository at /work/repo, not from /work/repo/app"), "{compact_text}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&compact_text).unwrap(),
            value
        );

        // An answer with advice of its own keeps it, after the warning.
        let mut advised = answer(r#"{"_kin": {"advice": "Missing: Go references."}, "hits": []}"#);
        stamp_client_folder(&mut advised, Some(root), &nested);
        let value: serde_json::Value = serde_json::from_str(&text_of(&advised)).unwrap();
        let advice = value["_kin"]["advice"].as_str().unwrap();
        assert!(
            advice.starts_with("This answer comes from")
                && advice.ends_with("Missing: Go references."),
            "{advice}"
        );

        // An answer the daemon's health already stamped is not stamped twice.
        let health = serde_json::json!({"repo_root": "/work/repo"});
        let stamped_env = crate::envelope::Envelope::daemon().with_repository(
            &health,
            Some(Path::new("/work/repo/app")),
            Path::to_path_buf,
        );
        let finalized = crate::envelope::finalize(
            ToolCallResult::text(serde_json::json!({"references": []}).to_string()),
            stamped_env,
            "find_references",
        );
        let mut from_health = JsonRpcResponse::success(
            Some(serde_json::json!(1)),
            serde_json::to_value(&finalized).unwrap(),
        );
        let before = text_of(&from_health);
        stamp_client_folder(&mut from_health, Some(root), &nested);
        assert_eq!(text_of(&from_health), before);
        let health_value: serde_json::Value = serde_json::from_str(&before).unwrap();
        assert_eq!(
            health_value["_kin"]["advice"]
                .as_str()
                .unwrap()
                .matches("This answer comes from")
                .count(),
            1,
            "{before}"
        );

        // Plain text gets the warning as its first line.
        let mut plain = answer("tool 'x' is not enabled in this MCP profile");
        stamp_client_folder(&mut plain, Some(root), &nested);
        assert!(
            text_of(&plain).starts_with("This answer comes from the Kin repository at /work/repo")
        );

        // The client's own folder, or no bound repository: nothing changes.
        let own = McpServerConfig {
            client_root: Some(PathBuf::from("/work/repo")),
            ..McpServerConfig::default()
        };
        let mut same = answer(r#"{"message": "ok"}"#);
        stamp_client_folder(&mut same, Some(root), &own);
        assert_eq!(text_of(&same), r#"{"message": "ok"}"#);
        let mut unbound = answer(r#"{"message": "ok"}"#);
        stamp_client_folder(&mut unbound, None, &nested);
        assert_eq!(text_of(&unbound), r#"{"message": "ok"}"#);
    }

    async fn drive_daemon_loop_with_config(
        client_messages: &[serde_json::Value],
        config: McpServerConfig,
    ) -> Vec<serde_json::Value> {
        drive_daemon_loop_with_initializer(client_messages, config, None).await
    }

    /// A client that asks for exact entity bodies when it connects, as `kin
    /// agent run` does, is served them on a profile that would otherwise
    /// number, and its listing says so; a client that does not ask is served
    /// the numbered form.
    #[tokio::test]
    async fn a_client_that_asks_for_exact_bodies_is_served_them() {
        let initialize = |capabilities: serde_json::Value| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": capabilities,
                           "clientInfo": {"name": "kin-agent", "version": "0"}},
            })
        };
        let list = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        let exact = serde_json::json!({"experimental": {"kin": {"exactEntityBodies": true}}});
        let mut daemon_query = query_config();
        daemon_query.session_authority_mode = SessionAuthorityMode::DaemonRequired;
        let mut daemon_routed = read_only();
        daemon_routed.session_authority_mode = SessionAuthorityMode::DaemonRequired;
        for (capabilities, numbered) in [(serde_json::json!({}), true), (exact, false)] {
            let responses = drive_daemon_loop_with_config(
                &[initialize(capabilities.clone()), list.clone()],
                daemon_query.clone(),
            )
            .await;
            let tools = responses[1]["result"]["tools"].as_array().unwrap();
            let source = tools
                .iter()
                .find(|tool| tool["name"] == "get_entity_source")
                .unwrap();
            assert_eq!(
                source["description"] == crate::entity_lines::NUMBERED_SOURCE_DESCRIPTION,
                numbered,
                "{capabilities}"
            );
            let responses = drive_daemon_loop_with_config(
                &[initialize(capabilities.clone()), list.clone()],
                daemon_routed.clone(),
            )
            .await;
            let description = responses[1]["result"]["tools"][0]["description"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(
                description.contains("+N offsets"),
                numbered,
                "{description}"
            );
        }
        let mut config = query_config();
        config.serve_exact_entity_bodies();
        assert!(!config.number_entity_lines);
        let mut routed = read_only();
        routed.serve_exact_entity_bodies();
        assert!(!routed.number_entity_lines && !routed.routed.unwrap().numbered);
    }

    /// A routed dispatch's hints name the spellings that reach each tool
    /// through the routed tool and in a shell, and its `_kin` envelope is
    /// exactly the named answer's. The session command has no CLI spelling,
    /// so its tool is named with `kin call`.
    #[tokio::test]
    async fn a_routed_answer_names_routed_commands_in_its_hints() {
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        // Guarded, so the refusal whose hints are under test is the missing
        // session's and not the operation's.
        let arguments = serde_json::json!({
            "operations": [guarded_update_operation("pub fn value() {}")]
        });
        let named = process_message(
            &tools_call("kin_mutate", arguments.clone()),
            &store,
            &McpServerConfig {
                session_authority_mode: SessionAuthorityMode::DaemonRequired,
                ..default_config()
            },
            &sessions,
        )
        .await
        .unwrap()
        .result
        .unwrap();
        let mut daemon_routed = with_writes();
        daemon_routed.session_authority_mode = SessionAuthorityMode::DaemonRequired;
        let routed = process_daemon_message(
            &tools_call(
                crate::routed::TOOL_NAME,
                serde_json::json!({"command": "mutate", "args": arguments}),
            ),
            &daemon_routed,
        )
        .await
        .unwrap()
        .result
        .unwrap();
        let text = |result: &serde_json::Value| {
            serde_json::from_str::<serde_json::Value>(
                result["content"][0]["text"].as_str().unwrap(),
            )
            .unwrap()
        };
        let (named_payload, routed_payload) = (text(&named), text(&routed));
        let named_message = named_payload["message"].as_str().unwrap();
        let routed_message = routed_payload["message"].as_str().unwrap();
        assert!(
            named_message.contains("kin_session_start"),
            "{named_message}"
        );
        assert_eq!(
            routed_message,
            named_message.replace("kin_session_start", "kin call kin_session_start"),
            "{routed_message}"
        );
        assert_eq!(routed_payload[ENVELOPE_KEY], named_payload[ENVELOPE_KEY]);
    }

    /// An entity's body is marked with each line's offset where the
    /// connection numbers, and served exactly everywhere else: a profile that
    /// can write through Kin, the full surface, the citable benchmark
    /// profiles, and a client that asked. A whole-file read is never numbered.
    #[test]
    fn entity_bodies_are_numbered_only_where_the_connection_numbers() {
        let record = serde_json::json!({
            "id": "e1", "file_path": "src/lib.rs", "start_line": 40, "end_line": 42,
            "body": "fn a() {\n    b();\n}",
        });
        let read = serde_json::json!({"path_label": "src/lib.rs", "text_utf8": "fn a() {\n}\n"});
        let presented = |config: &McpServerConfig, tool: &str, payload: &serde_json::Value| {
            let mut result = ToolCallResult::text(payload.to_string());
            present_result(config, tool, &mut result);
            let crate::types::ContentBlock::Text { text } = &result.content[0];
            serde_json::from_str::<serde_json::Value>(text).unwrap()
        };
        let named = |names: Option<&[&str]>, belt: bool| McpServerConfig {
            allowed_tools: names.map(crate::tools::name_set),
            agent_belt: belt,
            ..McpServerConfig::default()
        };
        let search = McpServerConfig {
            number_entity_lines: true,
            ..named(Some(crate::tools::agent_search_tool_names()), true)
        };
        for config in [read_only(), query_config(), search] {
            for tool in ["get_entity_source", "get_entity_body"] {
                let numbered = presented(&config, tool, &record);
                assert_eq!(numbered["body"], "+0\tfn a() {\n+1\t    b();\n+2\t}");
                assert_eq!(
                    numbered[crate::entity_lines::NUMBERING_KEY],
                    crate::entity_lines::NUMBERING_NOTE
                );
                assert_eq!(numbered["start_line"], 40, "the file location moved");
                assert_eq!(numbered["end_line"], 42, "the file location moved");
            }
            assert_eq!(presented(&config, "unregistered_tool", &read), read);
        }
        let mut asked = query_config();
        asked.serve_exact_entity_bodies();
        for config in [
            with_writes(),
            default_config(),
            named(Some(crate::tools::agent_default_tool_names()), true),
            named(None, false),
            named(Some(crate::tools::benchmark_tool_names()), false),
            named(Some(crate::tools::context_bench_tool_names()), false),
            asked,
        ] {
            assert_eq!(presented(&config, "get_entity_source", &record), record);
        }
    }
}
