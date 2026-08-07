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

use crate::daemon_delegate;
use crate::envelope::{self, Envelope};
use crate::error::{McpError, Result};
use crate::handlers::{handle_tool_call, RequestRepositoryAuthority};
use crate::session::SessionRegistry;
use crate::tools::tool_definitions;
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

/// Binds — or re-binds — the repo daemon from the MCP client's advertised
/// workspace roots.
///
/// Receives the filesystem paths of the client's roots, binds the daemon for the
/// first one that is a Kin repository (setting `KIN_DAEMON_URL` as a side
/// effect), and returns the bound repository — or `None` if none of the roots is
/// a Kin repository whose daemon can be resolved. Supplied by the kin-cli MCP
/// command; when `None`, roots binding is disabled (the client cannot serve
/// roots).
///
/// The binder is invoked for every `roots/list` response, not only the first:
/// an editor that moves its window to another folder announces the change, and
/// a server that keeps its original binding answers from a repository the user
/// has left. A `None` return while a repository is already bound is therefore
/// meaningful — it tells the server to refuse tool calls rather than serve them
/// from the previous repository's graph.
pub type RepoBinder = Box<
    dyn Fn(Vec<PathBuf>) -> Pin<Box<dyn Future<Output = Option<BoundRepo>> + Send>> + Send + Sync,
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
/// looking at, or reports that it cannot, in which case every `tools/call` is
/// refused with a structured repo-mismatch error until a later roots change
/// resolves it. A bound server never keeps answering from a repository the
/// client has left — a confident answer about the wrong codebase is worse than
/// an error.
pub async fn run_stdio_daemon(
    config: McpServerConfig,
    repo_binder: Option<RepoBinder>,
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
    config: McpServerConfig,
    repo_binder: Option<RepoBinder>,
    bound_daemon_url: Option<String>,
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

    while let Some((message, framed)) = read_stdio_message(&mut *reader).await? {
        // Peek at the raw JSON so we can distinguish the client's requests and
        // notifications from the `roots/list` response we may have sent: a
        // response carries no `method`, which the strongly-typed
        // `JsonRpcRequest` requires.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&message) {
            let method = value.get("method").and_then(|m| m.as_str());

            if method == Some("initialize") {
                client_supports_roots = value.pointer("/params/capabilities/roots").is_some();
            }

            // The client moved to a workspace we could not bind. Refuse every
            // tool call until a later roots change lands on a Kin repository:
            // answering from the repository the client left would return a
            // confident, well-formed result about the wrong codebase.
            if method == Some("tools/call") && binding.is_mismatched() {
                if let Some(response) = binding.repo_mismatch_response(&value) {
                    let response_json = serde_json::to_string(&response).map_err(McpError::Json)?;
                    write_stdio_message(&mut *writer, &response_json, framed).await?;
                }
                continue;
            }

            // Our own `roots/list` response returning from the client: bind the
            // daemon and swallow it (a response is never itself answered).
            if method.is_none()
                && value.get("id").and_then(|id| id.as_str()) == Some(ROOTS_REQUEST_ID)
            {
                roots_request_state.complete();
                if let Some(binder) = repo_binder.as_ref() {
                    apply_workspace_roots(binder, parse_workspace_roots(&value), &mut binding)
                        .await;
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

        if let Some(response) = process_daemon_message(&message, &config).await {
            let response_json = serde_json::to_string(&response).map_err(McpError::Json)?;
            write_stdio_message(&mut *writer, &response_json, framed).await?;
        }
    }

    tracing::info!("kin-mcp daemon-proxy stdio server shutting down");
    Ok(())
}

/// Feed a `roots/list` response through the binder and record what it means for
/// this process: a fresh binding, an unchanged one, or a workspace the server
/// cannot follow.
async fn apply_workspace_roots(
    binder: &RepoBinder,
    roots: Vec<PathBuf>,
    binding: &mut RepoBindingState,
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
        Some(bound) => {
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
            binding.bind(bound);
        }
        None if binding.is_bound() => {
            tracing::warn!(
                roots = ?roots,
                "kin-mcp: the client's workspace roots changed to a workspace with no bindable Kin \
                 repository; refusing tool calls instead of answering from the previous repository"
            );
            binding.mark_mismatch(roots);
        }
        None => {
            tracing::info!("kin-mcp: no Kin repository among the client's workspace roots");
        }
    }
}

/// The daemon bound before the stdio loop started (`KIN_DAEMON_URL` unset or
/// empty means nothing was bound).
fn bound_daemon_url_from_env() -> Option<String> {
    std::env::var("KIN_DAEMON_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// What the stdio loop knows about which repository it serves.
#[derive(Debug, Default)]
struct RepoBindingState {
    /// Daemon currently serving this process, if any.
    daemon_url: Option<String>,
    /// Repository that daemon serves. Unknown for a binding inherited from
    /// startup, which arrives as a URL with no accompanying root.
    repo_root: Option<PathBuf>,
    /// Set when the client's workspace moved somewhere this server could not
    /// follow. Cleared by the next successful bind.
    mismatch: Option<WorkspaceMismatch>,
}

/// A workspace change the server could not follow: it is still bound to
/// `bound_repo`, while the client now reports `requested_roots`.
#[derive(Debug)]
struct WorkspaceMismatch {
    bound_repo: Option<PathBuf>,
    requested_roots: Vec<PathBuf>,
}

impl RepoBindingState {
    fn started_with(daemon_url: Option<String>) -> Self {
        Self {
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

    fn bind(&mut self, bound: BoundRepo) {
        self.daemon_url = Some(bound.daemon_url);
        self.repo_root = Some(bound.root);
        self.mismatch = None;
    }

    fn mark_mismatch(&mut self, requested_roots: Vec<PathBuf>) {
        self.mismatch = Some(WorkspaceMismatch {
            bound_repo: self.repo_root.clone(),
            requested_roots,
        });
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
        let enveloped = envelope::finalize(result, Envelope::daemon_unreachable(), tool);
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
             longer looking at. Run `kin init .` in the new workspace, or restart the MCP server \
             from it (or with --repo <path> / KIN_MCP_REPO=<path>)."
        )
    }
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
    let mut tools = tool_definitions();
    if let Some(allowed) = &config.allowed_tools {
        tools.tools.retain(|tool| allowed.contains(&tool.name));
    }
    JsonRpcResponse::success(id, serde_json::to_value(&tools).unwrap_or_default())
}

async fn handle_tools_call<G: PersistableMcpStore>(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    store: &G,
    sessions: &SessionRegistry,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    let call_params: ToolCallParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(id, -32602, format!("Invalid params: {}", e));
        }
    };

    if let Some(allowed) = &config.allowed_tools {
        if !allowed.contains(&call_params.name) {
            let error_result = ToolCallResult::error(format!(
                "tool '{}' is not enabled in this MCP profile",
                call_params.name
            ));
            return offline_envelope_success(id, error_result, &call_params.name);
        }
    }

    let mut handler = std::pin::pin!(handle_tool_call(
        &call_params.name,
        &call_params.arguments,
        store,
        sessions,
        config.session_authority_mode,
        config.repository_authority.as_ref(),
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
        Ok(result) => {
            if tool_requires_persist(&call_params.name) {
                if let Err(error) = store.persist_primary_snapshot(config.snapshot_path.as_deref())
                {
                    let error_result = ToolCallResult::error(format!(
                        "tool succeeded but snapshot persistence failed: {error}"
                    ));
                    return offline_envelope_success(id, error_result, &call_params.name);
                }
            }
            offline_envelope_success(id, result, &call_params.name)
        }
        Err(e) => {
            offline_envelope_success(id, ToolCallResult::error(e.to_string()), &call_params.name)
        }
    }
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
) -> JsonRpcResponse {
    let enveloped = envelope::finalize(result, Envelope::offline(), tool_name);
    JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default())
}

async fn handle_tools_call_daemon(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    let call_params: ToolCallParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(id, -32602, format!("Invalid params: {}", e));
        }
    };

    if let Some(allowed) = &config.allowed_tools {
        if !allowed.contains(&call_params.name) {
            let error_result = ToolCallResult::error(format!(
                "tool '{}' is not enabled in this MCP profile",
                call_params.name
            ));
            let enveloped = envelope::finalize(error_result, Envelope::daemon(), &call_params.name);
            return JsonRpcResponse::success(
                id,
                serde_json::to_value(&enveloped).unwrap_or_default(),
            );
        }
    }

    let (result, mut base_env) =
        match daemon_delegate::forward_tool_call(&call_params.name, &call_params.arguments).await {
            Ok(Some(result)) => (result, Envelope::daemon()),
            Ok(None) => (
                daemon_delegate::daemon_unavailable_tool_result(&call_params.name),
                Envelope::daemon_unreachable(),
            ),
            Err(error) => (ToolCallResult::error(error), Envelope::daemon()),
        };

    // `kin_graph_status` already reports the exact graph view selected by the
    // daemon, including temporal-session scope. Generic `/health` is HEAD-only:
    // borrowing its entity count or generation here would mix two authorities
    // in one response. Build the standard `_kin` envelope from the report
    // itself and validate the fully annotated stdio payload instead.
    if call_params.name == "kin_graph_status" {
        let enveloped = finalize_daemon_graph_status(result, base_env);
        return JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default());
    }

    // Enrich the envelope with honest degraded/freshness signals from the daemon
    // `/health` body when the daemon is actually reachable. When it was already
    // determined unreachable, skip the probe — there is nothing to ask.
    if base_env.degraded.daemon_unreachable != Some(true) {
        if let Some(health) = daemon_delegate::fetch_health_snapshot().await {
            base_env = base_env.with_health(&health);
        }
    }

    let enveloped = envelope::finalize(result, base_env, &call_params.name);
    JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default())
}

fn finalize_daemon_graph_status(result: ToolCallResult, base_env: Envelope) -> ToolCallResult {
    let mut report = match daemon_delegate::parse_graph_status_report(&result) {
        Ok(Some(report)) => report,
        Ok(None) => return envelope::finalize(result, base_env, "kin_graph_status"),
        Err(error) => {
            return envelope::finalize(ToolCallResult::error(error), base_env, "kin_graph_status");
        }
    };

    let counts = (
        u64::try_from(report.entity_count),
        u64::try_from(report.embeddings_indexed),
        u64::try_from(report.embeddings_pending),
        u64::try_from(report.embeddings_total),
    );
    let (Ok(entity_count), Ok(indexed), Ok(pending), Ok(total)) = counts else {
        return envelope::finalize(
            ToolCallResult::error(
                "daemon kin_graph_status counters do not fit the stdio response envelope",
            ),
            base_env,
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
                base_env,
                "kin_graph_status",
            );
        }
    };
    let selected_env =
        base_env.with_selected_graph_observation(entity_count, indexed, pending, total);
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
    matches!(
        name,
        "kin_review_create"
            | "kin_review_decide"
            | "kin_review_note_add"
            | "kin_review_discuss"
            | "kin_review_discuss_reply"
            | "kin_review_discuss_resolve"
            | "kin_review_assign"
            | "kin_review_remove_reviewer"
    )
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

    fn direct_graph_status_result() -> ToolCallResult {
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
                "embeddings_indexed": 1,
                "embeddings_pending": 1,
                "embeddings_total": 2,
                "completion_attested": false
            })
            .to_string(),
        )
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
            "embed_worker_failed": true
        });
        let base = Envelope::daemon().with_health(&head_health);
        let enveloped = finalize_daemon_graph_status(direct_graph_status_result(), base);
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
        let coverage = response_env
            .semantic_coverage
            .expect("selected-graph embedding coverage");
        assert_eq!(coverage.indexed, 1);
        assert_eq!(coverage.pending, 1);
        assert_eq!(coverage.total, 2);
        assert!(!coverage.complete);
    }

    #[test]
    fn graph_status_stdio_schema_rejects_a_mixed_head_envelope() {
        let enveloped =
            finalize_daemon_graph_status(direct_graph_status_result(), Envelope::daemon());
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
            finalize_daemon_graph_status(direct_graph_status_result(), Envelope::daemon());
        let ContentBlock::Text { text } = &enveloped.content[0];
        let mut payload: serde_json::Value = serde_json::from_str(text).unwrap();
        payload["_kin"]["graph_state"]["head_generation"] = serde_json::json!(77);

        let sanitized = finalize_daemon_graph_status(
            ToolCallResult::text(payload.to_string()),
            Envelope::daemon(),
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

        let mut missing_note = sanitized_payload;
        missing_note["_kin"]["semantic_coverage"]
            .as_object_mut()
            .unwrap()
            .remove("note");
        let error =
            serde_json::from_value::<crate::handlers::entities::GraphStatusReport>(missing_note)
                .expect_err("incomplete coverage must carry its selected-graph note");
        assert!(
            error
                .to_string()
                .contains("note must be present exactly when coverage is incomplete"),
            "{error}"
        );
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
        assert!(!tools.as_array().unwrap().is_empty());
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
        struct RemoveCreatedKinDir(Option<std::path::PathBuf>);

        impl Drop for RemoveCreatedKinDir {
            fn drop(&mut self) {
                if let Some(path) = self.0.take() {
                    let _ = std::fs::remove_dir(path);
                }
            }
        }

        // Bind this end-to-end dispatch test to a Kin repository explicitly.
        // Without `.kin`, the production delegate correctly reports the
        // distinct "not inside a kin repository" state before it can prove the
        // daemon-required branch this test is intended to lock down.
        let kin_dir = std::env::current_dir().unwrap().join(".kin");
        let remove_kin_dir = match std::fs::create_dir(&kin_dir) {
            Ok(()) => RemoveCreatedKinDir(Some(kin_dir)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && kin_dir.is_dir() => {
                RemoveCreatedKinDir(None)
            }
            Err(error) => panic!("failed to establish Kin repo fixture: {error}"),
        };
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
        assert!(text.contains("Kin daemon is required"));
        drop(remove_kin_dir);
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

        binding.bind(bound_repo("/repo/a", "http://127.0.0.1:4111"));
        assert!(
            !binding.wants_workspace_roots(),
            "a settled binding must not re-ask on every trigger"
        );

        binding.mark_mismatch(vec![PathBuf::from("/elsewhere")]);
        assert!(
            binding.wants_workspace_roots(),
            "bound to a repository the client left is no better than unbound"
        );

        binding.bind(bound_repo("/repo/b", "http://127.0.0.1:4222"));
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
        outcomes: std::sync::Mutex<std::collections::VecDeque<Option<BoundRepo>>>,
        calls: std::sync::Arc<std::sync::Mutex<Vec<Vec<PathBuf>>>>,
    }

    impl ScriptedBinder {
        fn install(
            outcomes: Vec<Option<BoundRepo>>,
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
                move |roots: Vec<PathBuf>| -> Pin<Box<dyn Future<Output = Option<BoundRepo>> + Send>> {
                    let scripted = std::sync::Arc::clone(&scripted);
                    Box::pin(async move {
                        scripted.calls.lock().unwrap().push(roots);
                        let next = scripted.outcomes.lock().unwrap().pop_front();
                        next.flatten()
                    })
                },
            );
            (binder, calls)
        }
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
    async fn drive_daemon_loop(
        client_messages: &[serde_json::Value],
        repo_binder: Option<RepoBinder>,
        bound_daemon_url: Option<String>,
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
            Some(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            Some(bound_repo("/repo/b", "http://127.0.0.1:4222")),
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
        // Bind repo A, then switch to a workspace with no bindable Kin repo.
        let (binder, _calls) = ScriptedBinder::install(vec![
            Some(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            None,
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
    }

    #[tokio::test]
    async fn a_bindable_workspace_switch_clears_an_earlier_refusal() {
        // A → unbindable workspace → B: the refusal must not outlive the switch
        // that resolves it.
        let (binder, _calls) = ScriptedBinder::install(vec![
            Some(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            None,
            Some(bound_repo("/repo/b", "http://127.0.0.1:4222")),
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
            Some(bound_repo("/repo/a", "http://127.0.0.1:4111")),
            None,
            Some(bound_repo("/repo/b", "http://127.0.0.1:4222")),
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
        let (binder, calls) =
            ScriptedBinder::install(vec![Some(bound_repo("/repo/b", "http://127.0.0.1:4222"))]);

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
        let (binder, calls) =
            ScriptedBinder::install(vec![Some(bound_repo("/repo/a", "http://127.0.0.1:4111"))]);

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
}
