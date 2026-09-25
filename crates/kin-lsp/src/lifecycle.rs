// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP server lifecycle management — start, initialize, shutdown.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kin_model::LanguageId;
use tokio::io::AsyncReadExt;
use tokio::process::{ChildStderr, Command};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info};

use crate::client::JsonRpcClient;
use crate::error::{LspError, Result};
use crate::protocol::{self, InitializeParams, InitializeResult};
use crate::registry::{
    BinaryFinder, ProviderGap, ProviderGapReason, ProviderProbe, ProviderRegistry,
    SystemBinaryFinder,
};
use crate::server_process::ServerProcess;

pub use crate::server_process::TERMINATION_GRACE;

/// How much of a server's stderr is retained. Bounded because a chatty server
/// would otherwise grow this without limit for the life of the process, and
/// the last words are the ones that explain a death.
const STDERR_TAIL_CAP: usize = 8 * 1024;

/// A running LSP server with an initialized JSON-RPC client.
///
/// On Unix the server runs as the leader of its own process group, and every
/// way of letting go of it ends that group, with everything the server started:
/// [`LspServer::shutdown`], a drop, and the death of the process holding it.
pub struct LspServer {
    pub client: JsonRpcClient,
    pub capabilities: protocol::ServerCapabilities,
    process: ServerProcess,
    stderr_tail: StderrTail,
}

/// What a server that stopped answering left behind.
///
/// A server that dies after its handshake has no JSON-RPC reply left to
/// explain itself in. Its exit and its stderr are all there is, and a Go
/// runtime that cannot start a thread, a process killed for memory, and a
/// crash on one file look identical from the protocol side: every request
/// fails with the same "server shutdown unexpectedly".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerDeparture {
    /// How the process ended, as a clause a reason can carry, or `None` when
    /// it had not exited by the time this was read.
    pub exit: Option<String>,
    /// The last of what it wrote to stderr, trimmed. Empty when it wrote
    /// nothing.
    pub stderr: String,
}

impl ServerDeparture {
    /// One clause for a reason a reader sees, keeping at most the last
    /// `max_stderr` bytes of stderr, which are the ones that explain a death.
    pub fn describe(&self, max_stderr: usize) -> String {
        let exit = self
            .exit
            .clone()
            .unwrap_or_else(|| "its process had not exited".to_string());
        if self.stderr.is_empty() {
            return format!("{exit}, and it wrote nothing to stderr");
        }
        let tail = last_bytes(&self.stderr, max_stderr);
        let cut = if tail.len() < self.stderr.len() {
            "..."
        } else {
            ""
        };
        format!("{exit}; its last stderr: {cut}{tail}")
    }
}

/// The last `max` bytes of `text`, moved forward to a character boundary.
fn last_bytes(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

fn describe_exit(status: std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("it exited with code {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("it was killed by signal {signal}");
        }
    }
    format!("it ended with {status}")
}

/// How long a failure path waits for a dying server's stderr to be drained.
///
/// The write that fails and the read that captures the server's words happen on
/// different tasks, so at the instant a broken pipe surfaces the drain may not
/// have run at all. Without this wait the words are there and simply not
/// collected yet, and the failure reports that the server said nothing. Paid
/// only on a failure path, never on a healthy start.
const STDERR_SETTLE: Duration = Duration::from_millis(250);

/// A server's stderr tail, plus a signal for when the stream reached EOF.
struct StderrTail {
    buffer: Arc<Mutex<Vec<u8>>>,
    drained: Arc<Notify>,
}

/// Drain a server's stderr into a bounded tail buffer.
///
/// Draining is not optional once stderr is piped: an undrained pipe fills its
/// kernel buffer and then blocks the server on its next write, which would turn
/// a diagnostic into a hang.
fn drain_stderr(stderr: ChildStderr) -> StderrTail {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let drained = Arc::new(Notify::new());
    let sink = Arc::clone(&buffer);
    let done = Arc::clone(&drained);
    tokio::spawn(async move {
        let mut stderr = stderr;
        let mut chunk = [0u8; 1024];
        loop {
            match stderr.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let mut held = sink.lock().await;
                    held.extend_from_slice(&chunk[..read]);
                    let overflow = held.len().saturating_sub(STDERR_TAIL_CAP);
                    if overflow > 0 {
                        held.drain(..overflow);
                    }
                }
            }
        }
        // `notify_one` stores a permit when nobody is waiting yet, so a drain
        // that finishes before the failure path asks is not a lost wakeup.
        done.notify_one();
    });
    StderrTail { buffer, drained }
}

/// Attach the server's own last words to a failure, when it left any.
///
/// A server that answers over JSON-RPC explains itself through the error it
/// returns. One that dies before it can frame a reply explains itself only on
/// stderr, and that is the case this exists for.
async fn with_stderr(reason: LspError, tail: &StderrTail) -> LspError {
    // Wait, briefly, for the stream to reach EOF. A server that has already
    // exited hits EOF at once; a server still running never does, which is what
    // the bound is for.
    let _ = tokio::time::timeout(STDERR_SETTLE, tail.drained.notified()).await;
    let captured = tail.buffer.lock().await;
    if captured.is_empty() {
        return reason;
    }
    LspError::ServerFailedWithStderr {
        reason: reason.to_string(),
        stderr: String::from_utf8_lossy(&captured).trim().to_string(),
    }
}

fn require_utf16(capabilities: &protocol::ServerCapabilities) -> Result<()> {
    match capabilities.position_encoding.as_deref() {
        None | Some("utf-16") => Ok(()),
        Some(other) => Err(LspError::InitializeFailed(format!(
            "unsupported position encoding {other}; Kin requested utf-16"
        ))),
    }
}

impl LspServer {
    /// Start an LSP server process and perform the initialize handshake.
    pub async fn start(
        command: &str,
        args: &[&str],
        workspace_root: &Path,
        initialization_options: Option<serde_json::Value>,
    ) -> Result<Self> {
        info!(command, ?args, "starting LSP server");

        let mut invocation = Command::new(command);
        invocation.args(args);
        let mut process = ServerProcess::spawn(invocation)
            .map_err(|e| LspError::ServerStartFailed(format!("{}: {}", command, e)))?;

        let (stdin, stdout, stderr) = process.take_stdio();
        let stdin = stdin
            .ok_or_else(|| LspError::ServerStartFailed("failed to capture stdin".to_string()))?;
        let stdout = stdout
            .ok_or_else(|| LspError::ServerStartFailed("failed to capture stdout".to_string()))?;
        let stderr = stderr
            .ok_or_else(|| LspError::ServerStartFailed("failed to capture stderr".to_string()))?;
        let stderr_tail = drain_stderr(stderr);

        let client = JsonRpcClient::new(stdin, stdout);

        // Perform LSP initialize handshake.
        let init_params = InitializeParams::for_workspace(workspace_root, initialization_options);

        let handshake = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client.request("initialize", &init_params),
        )
        .await;

        let result = match handshake {
            Err(_) => return Err(with_stderr(LspError::Timeout, &stderr_tail).await),
            Ok(Err(error)) => {
                return Err(with_stderr(
                    LspError::InitializeFailed(error.to_string()),
                    &stderr_tail,
                )
                .await)
            }
            Ok(Ok(result)) => result,
        };

        let init_result: InitializeResult = serde_json::from_value(result)
            .map_err(|error| LspError::InitializeFailed(error.to_string()))?;
        require_utf16(&init_result.capabilities)?;

        // Send `initialized` notification.
        client.notify("initialized", serde_json::json!({})).await?;

        debug!(
            call_hierarchy = init_result.capabilities.call_hierarchy_provider.is_some(),
            definition = init_result.capabilities.definition_provider.is_some(),
            references = init_result.capabilities.references_provider.is_some(),
            type_hierarchy = init_result.capabilities.type_hierarchy_provider.is_some(),
            type_definition = init_result.capabilities.type_definition_provider.is_some(),
            "server initialized"
        );

        Ok(Self {
            client,
            capabilities: init_result.capabilities,
            process,
            stderr_tail,
        })
    }

    /// What this server has written to stderr so far, bounded to its last
    /// bytes. Empty when it has written nothing.
    pub async fn stderr_tail(&self) -> String {
        let captured = self.stderr_tail.buffer.lock().await;
        String::from_utf8_lossy(&captured).trim().to_string()
    }

    /// Whether the connection to this server is gone. See
    /// [`JsonRpcClient::is_disconnected`].
    pub fn is_disconnected(&self) -> bool {
        self.client.is_disconnected()
    }

    /// What this server left behind: its exit, once its process has ended,
    /// and the last of its stderr.
    ///
    /// Meant for a server that [`Self::is_disconnected`]. Its stdout closing
    /// and its process being reaped are separate events, and its stderr is
    /// drained on a task of its own, so each is given a short bound to catch
    /// up rather than read as absent the instant the connection drops.
    pub async fn departure(&mut self) -> ServerDeparture {
        let _ = tokio::time::timeout(STDERR_SETTLE, self.stderr_tail.drained.notified()).await;
        let deadline = tokio::time::Instant::now() + STDERR_SETTLE;
        let exit = loop {
            if let Some(status) = self.process.exit_status() {
                break Some(describe_exit(status));
            }
            if tokio::time::Instant::now() >= deadline {
                break None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        ServerDeparture {
            exit,
            stderr: self.stderr_tail().await,
        }
    }

    /// End a server that can no longer answer, with every process it
    /// started, without the shutdown request.
    ///
    /// [`Self::shutdown`] asks first, and on a connection whose reader has
    /// already stopped that request waits out its whole reply budget for an
    /// answer that cannot come.
    pub async fn abandon(self) {
        self.process.terminate().await;
    }

    /// A server whose process accepts input and answers nothing.
    ///
    /// For tests that assert on what this crate SENDS. The document lifecycle
    /// the enrichment join needs is notifications, which expect no reply, so a
    /// process that swallows them exercises the real code path without needing
    /// a language server installed on the machine running the suite.
    #[cfg(test)]
    pub(crate) fn offline_for_tests() -> Self {
        let mut process =
            ServerProcess::spawn(Command::new("cat")).expect("spawn a process that accepts input");
        let (stdin, stdout, stderr) = process.take_stdio();
        Self {
            client: JsonRpcClient::new(
                stdin.expect("captured stdin"),
                stdout.expect("captured stdout"),
            ),
            capabilities: protocol::ServerCapabilities::default(),
            process,
            stderr_tail: drain_stderr(stderr.expect("captured stderr")),
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted_for_tests(script: &str, responses: serde_json::Value) -> Self {
        let mut invocation = Command::new("python3");
        invocation
            .args(["-u", "-c", script])
            .env("KIN_LSP_TEST_RESPONSES", responses.to_string());
        let mut process =
            ServerProcess::spawn(invocation).expect("spawn the scripted JSON-RPC peer");
        let (stdin, stdout, stderr) = process.take_stdio();
        Self {
            client: JsonRpcClient::new(
                stdin.expect("captured stdin"),
                stdout.expect("captured stdout"),
            ),
            capabilities: serde_json::from_value(serde_json::json!({
                "callHierarchyProvider": true,
                "typeHierarchyProvider": true,
                "typeDefinitionProvider": true,
                "definitionProvider": true,
                "referencesProvider": true,
                "implementationProvider": true,
            }))
            .unwrap(),
            process,
            stderr_tail: drain_stderr(stderr.expect("captured stderr")),
        }
    }

    /// Ask the server to shut down and exit, then end its process group:
    /// SIGTERM to the server and everything it started, and SIGKILL to
    /// whatever is left after [`TERMINATION_GRACE`].
    ///
    /// `exit` is a request the server honours for itself at best. What it
    /// started is left to notice on its own, and tsserver processes have
    /// outlived their typescript-language-server by 20 to 40 minutes.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self
            .client
            .request("shutdown", serde_json::json!(null))
            .await;
        let _ = self.client.notify("exit", serde_json::json!(null)).await;
        self.process.terminate().await;
        Ok(())
    }

    /// Check if the server supports call hierarchy.
    pub fn has_call_hierarchy(&self) -> bool {
        matches!(
            self.capabilities.call_hierarchy_provider.as_ref(),
            Some(serde_json::Value::Bool(true) | serde_json::Value::Object(_))
        )
    }

    /// Check if the server supports go-to-definition.
    pub fn has_definition(&self) -> bool {
        matches!(
            self.capabilities.definition_provider.as_ref(),
            Some(serde_json::Value::Bool(true) | serde_json::Value::Object(_))
        )
    }

    /// Check if the server supports find references.
    pub fn has_references(&self) -> bool {
        matches!(
            self.capabilities.references_provider.as_ref(),
            Some(serde_json::Value::Bool(true) | serde_json::Value::Object(_))
        )
    }

    /// Check if the server supports type hierarchy.
    pub fn has_type_hierarchy(&self) -> bool {
        matches!(
            self.capabilities.type_hierarchy_provider.as_ref(),
            Some(serde_json::Value::Bool(true) | serde_json::Value::Object(_))
        )
    }

    /// Check if the server supports go-to-type-definition.
    pub fn has_type_definition(&self) -> bool {
        matches!(
            self.capabilities.type_definition_provider.as_ref(),
            Some(serde_json::Value::Bool(true) | serde_json::Value::Object(_))
        )
    }

    /// Check if the server supports go-to-implementation.
    pub fn has_implementation(&self) -> bool {
        matches!(
            self.capabilities.implementation_provider.as_ref(),
            Some(serde_json::Value::Bool(true) | serde_json::Value::Object(_))
        )
    }

    /// The capabilities this live server reported during the initialize
    /// handshake, expressed in the registry's capability vocabulary. This is the
    /// source of truth for what actually ran and feeds the enrichment proof.
    pub fn probed_capabilities(
        &self,
    ) -> std::collections::BTreeSet<crate::registry::LspCapability> {
        use crate::registry::LspCapability;
        let mut caps = std::collections::BTreeSet::new();
        if self.has_definition() {
            caps.insert(LspCapability::Definition);
        }
        if self.has_type_definition() {
            caps.insert(LspCapability::TypeDefinition);
        }
        if self.has_references() {
            caps.insert(LspCapability::References);
        }
        if self.has_call_hierarchy() {
            caps.insert(LspCapability::CallHierarchy);
        }
        if self.has_type_hierarchy() {
            caps.insert(LspCapability::TypeHierarchy);
        }
        caps
    }
}

/// How long a readiness probe waits for a server to complete the handshake.
///
/// Deliberately far below the 30 s ceiling [`LspServer::start`] allows an
/// enrichment run. A probe answers an operator or a startup path, and a
/// surface that blocks for half a minute to render one status row has traded
/// one bad answer for a worse experience.
pub const READINESS_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Ask whether a language is actually served on this host, and answer with one
/// of three states rather than two.
///
/// `Ok` is usable: the server resolved, completed the initialize handshake, and
/// reported the capabilities in the returned [`ProviderProbe`]. `Err` is a
/// [`ProviderGap`] whose reason separates the two ways a language can fail to
/// be served: no binary at all, versus a binary that is present and refuses to
/// initialize. Those need different repairs, which is why the caller is given
/// the distinction instead of a boolean.
///
/// This exists because a binary on `PATH` is not a working language server.
/// Resolution alone answered the weaker question, and a host whose server was
/// installed but unusable was reported as served by every surface that asked.
///
/// It spawns a process, so it belongs to lifecycle paths that may spawn
/// (daemon start, install verification, a diagnostic command) and never to a
/// query path.
pub async fn probe_readiness(
    registry: &ProviderRegistry,
    language: LanguageId,
    workspace_root: &Path,
    initialization_options: Option<serde_json::Value>,
) -> std::result::Result<ProviderProbe, ProviderGap> {
    probe_readiness_with(
        registry,
        language,
        workspace_root,
        initialization_options,
        &SystemBinaryFinder,
    )
    .await
}

/// [`probe_readiness`] with an injected [`BinaryFinder`], so the three states
/// can be exercised against fixture servers instead of whatever the host
/// happens to have installed.
pub async fn probe_readiness_with(
    registry: &ProviderRegistry,
    language: LanguageId,
    workspace_root: &Path,
    initialization_options: Option<serde_json::Value>,
    finder: &dyn BinaryFinder,
) -> std::result::Result<ProviderProbe, ProviderGap> {
    let resolved = registry.resolve_with(language, finder)?;
    let command = resolved.command.display().to_string();
    let args: Vec<&str> = resolved.args.iter().map(String::as_str).collect();

    let started = tokio::time::timeout(
        READINESS_PROBE_TIMEOUT,
        LspServer::start(&command, &args, workspace_root, initialization_options),
    )
    .await;

    let unusable = |message: String| ProviderGap {
        language,
        reason: ProviderGapReason::ServerUnusable { message },
        tried: vec![resolved.id.clone()],
    };

    match started {
        Err(_) => Err(unusable(format!(
            "did not complete the initialize handshake within {}s",
            READINESS_PROBE_TIMEOUT.as_secs()
        ))),
        Ok(Err(error)) => Err(unusable(error.to_string())),
        Ok(Ok(server)) => {
            let probed_capabilities = server.probed_capabilities();
            // Dropped rather than shut down politely: a drop ends the server's
            // whole process group at once, and a probe has no session worth
            // closing.
            drop(server);
            Ok(ProviderProbe {
                resolved,
                probed_capabilities,
            })
        }
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use crate::registry::LspCapability;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn start_sends_the_selected_workspace_folder_on_the_wire() {
        let peer = format!(
            "import os\nos.environ['KIN_LSP_TEST_RESPONSES'] = '{{\"initialize\": {{\"result\": {{\"capabilities\": {{\"definitionProvider\": true}}}}}}}}'\n{}",
            include_str!("enrichment_test_peer.py")
        );
        let root = std::env::temp_dir().join("kin workspace with spaces");
        let options = serde_json::json!({"diagnosticMode": "off"});
        let server = LspServer::start(
            "python3",
            &["-u", "-c", &peer],
            &root,
            Some(options.clone()),
        )
        .await
        .expect("fixture initializes through the production lifecycle");
        let seen = server
            .client
            .request("test/seen", serde_json::Value::Null)
            .await
            .unwrap();
        let initialize = seen
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["method"] == "initialize")
            .expect("actual initialize request was captured");
        let uri = protocol::path_to_uri(&root);
        assert_eq!(initialize["params"]["rootUri"], uri);
        assert_eq!(
            initialize["params"]["workspaceFolders"],
            serde_json::json!([{"uri": uri, "name": "kin workspace with spaces"}])
        );
        assert_eq!(initialize["params"]["initializationOptions"], options);
        server.shutdown().await.unwrap();
    }

    /// Fixture servers, so the three readiness states are exercised against
    /// processes this test owns rather than whatever the host has installed.
    ///
    /// A test that has to break the machine it runs on to prove a failure state
    /// cannot run in CI and will not be re-run by anyone. These do the same job
    /// deterministically on every platform this crate builds for.
    fn fixture(body: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "kin-lsp-readiness-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let path = dir.join("fixture-server");
        let mut file = std::fs::File::create(&path).expect("fixture file");
        file.write_all(body.as_bytes()).expect("fixture body");
        drop(file);
        let mut perms = std::fs::metadata(&path)
            .expect("fixture metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("fixture executable");
        path
    }

    /// A server that completes the handshake and reports the providers Kin
    /// uses.
    ///
    /// It reads the request before answering, and stays alive afterwards,
    /// because a real server does both. A fixture that answers into a pipe
    /// before the client has finished writing to it, or that exits while the
    /// client is still writing, makes the client fail with a broken pipe and
    /// tests the harness rather than the code.
    fn usable_server() -> PathBuf {
        fixture(
            r#"#!/bin/sh
read -r _ 2>/dev/null
BODY='{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"definitionProvider":true,"referencesProvider":true,"typeDefinitionProvider":true,"callHierarchyProvider":true}}}'
printf 'Content-Length: %d\r\n\r\n%s' "${#BODY}" "$BODY"
sleep 30
"#,
        )
    }

    /// A server that starts and refuses to initialize, the shape
    /// `typescript-language-server` takes when its tsserver is missing.
    ///
    /// The refusal under test is the JSON-RPC error, not the exit that follows
    /// it in the real server. Exiting the instant the reply is written raced
    /// the client's own write on Linux and produced a broken pipe instead of
    /// the refusal, so this stays alive and lets the probe's drop end it, the
    /// `sleep` along with the shell.
    fn unusable_server() -> PathBuf {
        fixture(
            r#"#!/bin/sh
read -r _ 2>/dev/null
BODY='{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Could not find a valid TypeScript installation. Exiting."}}'
printf 'Content-Length: %d\r\n\r\n%s' "${#BODY}" "$BODY"
sleep 30
"#,
        )
    }

    /// A server that says why it is dying on stderr and then dies, framing no
    /// reply at all. The only class where stderr is the sole explanation.
    fn server_that_dies_talking_to_stderr() -> PathBuf {
        fixture(
            r#"#!/bin/sh
echo 'fatal: libfoo.so.1: cannot open shared object file' >&2
exit 127
"#,
        )
    }

    /// A finder that resolves every binary to one fixture, so the registry's
    /// resolution succeeds and the handshake is what decides the outcome.
    struct FixtureFinder(Option<PathBuf>);

    impl BinaryFinder for FixtureFinder {
        fn find_on_path(&self, _binary: &str) -> Option<PathBuf> {
            self.0.as_ref().map(|_| PathBuf::from("/bin/sh"))
        }
        fn probe_version(&self, _path: &Path) -> Option<String> {
            Some("fixture".to_string())
        }
    }

    async fn probe(finder: &FixtureFinder) -> std::result::Result<ProviderProbe, ProviderGap> {
        // Execute the installed interpreter, which reads the fixture as data.
        // Executing a freshly written script itself can fail with ETXTBSY on Linux.
        let registry = if let Some(script) = &finder.0 {
            ProviderRegistry::from_config(&crate::registry::RegistryConfig {
                providers: vec![crate::registry::ProviderOverride {
                    language: "typescript".into(),
                    provider: "typescript-language-server".into(),
                    binaries: Vec::new(),
                    args: Some(vec![script.display().to_string()]),
                }],
                ..Default::default()
            })
            .unwrap()
        } else {
            ProviderRegistry::with_defaults()
        };
        probe_readiness_with(
            &registry,
            LanguageId::TypeScript,
            Path::new("/tmp"),
            None,
            finder,
        )
        .await
    }

    #[tokio::test]
    async fn a_server_that_completes_the_handshake_is_usable_and_reports_its_providers() {
        let probed = probe(&FixtureFinder(Some(usable_server())))
            .await
            .expect("a server that answers initialize is usable");
        assert_eq!(
            probed.resolved.command,
            PathBuf::from("/bin/sh"),
            "fixture source is read by the installed interpreter, never executed directly"
        );
        for capability in [
            LspCapability::Definition,
            LspCapability::References,
            LspCapability::TypeDefinition,
            LspCapability::CallHierarchy,
        ] {
            assert!(
                probed.serves(capability),
                "the fixture reported {capability:?} and the probe lost it"
            );
        }
    }

    /// The state this whole probe exists for, and the one binary presence
    /// cannot see.
    #[tokio::test]
    async fn a_present_server_that_refuses_to_initialize_is_a_gap_carrying_its_own_message() {
        let gap = probe(&FixtureFinder(Some(unusable_server())))
            .await
            .expect_err("a server that refuses initialize is not usable");
        match &gap.reason {
            ProviderGapReason::ServerUnusable { message } => assert!(
                message.contains("Could not find a valid TypeScript installation"),
                "the gap must carry the server's own words, got: {message}"
            ),
            other => panic!(
                "a present-but-unusable server must not be reported as {other:?}; \
                 collapsing it into an absence loses the only repair an operator can act on"
            ),
        }
    }

    /// The third state, kept distinct from the second on purpose.
    #[tokio::test]
    async fn a_missing_binary_is_a_different_gap_than_an_unusable_server() {
        let gap = probe(&FixtureFinder(None))
            .await
            .expect_err("no binary means no server");
        assert_eq!(
            gap.reason,
            ProviderGapReason::NoBinaryOnPath,
            "an absent binary and an unusable server need different repairs"
        );
    }

    /// The drain is a different task from the write that fails, so at the
    /// instant a failure surfaces the words may exist and simply not be
    /// collected yet.
    ///
    /// This is not hypothetical timing worry. The first version of this code
    /// read the buffer immediately, passed on macOS, and failed on Linux CI
    /// with "IO error: Broken pipe" and an empty tail, because there the
    /// initialize write hit the dead process before the drain task had run at
    /// all. Platform timing decided whether the feature worked, which is the
    /// same as it not working. This models the losing order directly so the
    /// answer no longer depends on which machine asks.
    #[tokio::test]
    async fn a_tail_still_being_drained_is_waited_for_rather_than_read_as_silence() {
        let tail = StderrTail {
            buffer: Arc::new(Mutex::new(Vec::new())),
            drained: Arc::new(Notify::new()),
        };
        let buffer = Arc::clone(&tail.buffer);
        let drained = Arc::clone(&tail.drained);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            buffer
                .lock()
                .await
                .extend_from_slice(b"fatal: the reason it died");
            drained.notify_one();
        });

        let attached = with_stderr(LspError::ServerDied, &tail).await;
        let rendered = attached.to_string();
        assert!(
            rendered.contains("fatal: the reason it died"),
            "the server's words arrived after the failure and were read as silence: {rendered}"
        );
    }

    /// FIR-2514: a server with nothing to say over JSON-RPC still says it on
    /// stderr, and that is the only place it can.
    #[tokio::test]
    async fn a_server_that_dies_before_replying_keeps_its_last_words() {
        let gap = probe(&FixtureFinder(Some(server_that_dies_talking_to_stderr())))
            .await
            .expect_err("a server that exits 127 is not usable");
        let reason = gap.reason.to_string();
        assert!(
            reason.contains("cannot open shared object file"),
            "the server's stderr is the only explanation it gave, and it was dropped: {reason}"
        );
    }

    /// A server that finishes the handshake and then exits on its own, having
    /// said why on stderr, the way a Go server that cannot start another
    /// thread does partway through loading packages.
    ///
    /// It stays up long enough for the `initialized` notification to be
    /// written, so the handshake is not what fails.
    fn server_that_exits_after_the_handshake() -> PathBuf {
        fixture(
            r#"#!/bin/sh
read -r _ 2>/dev/null
BODY='{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"definitionProvider":true}}}'
printf 'Content-Length: %d\r\n\r\n%s' "${#BODY}" "$BODY"
sleep 2
echo 'fatal error: runtime: failed to create new OS thread' >&2
exit 2
"#,
        )
    }

    async fn start(program: PathBuf) -> LspServer {
        LspServer::start(
            program.to_str().expect("fixture path is UTF-8"),
            &[],
            &std::env::temp_dir(),
            None,
        )
        .await
        .expect("the fixture completes the handshake")
    }

    /// A server that dies mid-session reads as disconnected, and what it left
    /// behind is kept: the exit and its own last words. Before this, a caller
    /// had only "server shutdown unexpectedly" on every request, for any cause.
    #[tokio::test]
    async fn a_server_that_exits_mid_session_is_disconnected_and_keeps_its_last_words() {
        let mut server = start(server_that_exits_after_the_handshake()).await;
        assert!(
            !server.is_disconnected(),
            "a server that has just answered the handshake is connected"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !server.is_disconnected() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a server whose process exited must read as disconnected"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let departure = server.departure().await;
        assert_eq!(
            departure.exit.as_deref(),
            Some("it exited with code 2"),
            "{departure:?}"
        );
        assert!(
            departure.stderr.contains("failed to create new OS thread"),
            "the server's stderr is the only account of why it exited: {departure:?}"
        );
        let described = departure.describe(4096);
        assert!(
            described.contains("it exited with code 2")
                && described.contains("failed to create new OS thread"),
            "{described}"
        );
        server.abandon().await;
    }

    /// Whether `pid` is a child of this process that has exited and has not
    /// been reaped. Asked with `WNOWAIT`, so asking reaps nothing.
    fn exited_and_unreaped(pid: libc::pid_t) -> bool {
        // SAFETY: `info` is zeroed, the call writes only into it, and WNOWAIT
        // leaves the child waitable.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: waitid filled a child-status siginfo, which sets si_pid.
        let reported = unsafe { info.si_pid() };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let reported = info.si_pid;
        result == 0 && reported == pid
    }

    /// Reading how a dead server ended leaves its leader unreaped, so the
    /// group's id stays reserved until the stop has signalled it.
    ///
    /// The leader's pid is the group's id, and an id is free to be handed out
    /// again once its group is empty. A leader that died alone and was reaped
    /// to read its status leaves an empty group, and the SIGTERM the stop sends
    /// next would go to whichever new process was given that id. Kept unreaped,
    /// the leader holds the id until the stop reaps it after signalling.
    #[tokio::test]
    async fn a_departure_leaves_the_dead_leader_unreaped_until_the_stop() {
        let mut server = start(server_that_exits_after_the_handshake()).await;
        let leader = server.process.leader_pid();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !server.is_disconnected() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a server whose process exited must read as disconnected"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let departure = server.departure().await;
        assert_eq!(
            departure.exit.as_deref(),
            Some("it exited with code 2"),
            "{departure:?}"
        );
        assert!(
            exited_and_unreaped(leader),
            "reading the exit reaped the leader, which frees the group's id before the stop \
             signals it"
        );
        server.abandon().await;
        assert!(
            !exited_and_unreaped(leader),
            "the stop reaps the leader once it has signalled the group"
        );
    }

    /// The control: a server that is still running is connected and has no
    /// exit to report, so the check cannot pass by calling everything dead.
    #[tokio::test]
    async fn a_running_server_is_connected_and_has_no_exit_to_report() {
        let mut server = start(usable_server()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!server.is_disconnected(), "a running server is connected");
        let departure = server.departure().await;
        assert_eq!(departure.exit, None, "{departure:?}");
        server.abandon().await;
    }

    /// A long stderr is cut to its last bytes, on a character boundary, and
    /// says it was cut.
    #[test]
    fn a_departure_keeps_the_end_of_a_long_stderr() {
        let departure = ServerDeparture {
            exit: Some("it exited with code 2".to_string()),
            stderr: format!("{}é the last line", "x".repeat(100)),
        };
        let described = departure.describe(16);
        assert!(
            described.starts_with("it exited with code 2; its last stderr: ..."),
            "{described}"
        );
        assert!(
            described.ends_with("é the last line") || described.ends_with(" the last line"),
            "{described}"
        );
        assert!(!described.contains("xxxx"), "{described}");
        let quiet = ServerDeparture {
            exit: None,
            stderr: String::new(),
        };
        assert_eq!(
            quiet.describe(16),
            "its process had not exited, and it wrote nothing to stderr"
        );
    }
}
