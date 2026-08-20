// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP server lifecycle management — start, initialize, shutdown.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use kin_model::LanguageId;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, Command};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info};

use crate::client::JsonRpcClient;
use crate::error::{LspError, Result};
use crate::protocol::{self, InitializeParams, InitializeResult};
use crate::registry::{
    BinaryFinder, ProviderGap, ProviderGapReason, ProviderProbe, ProviderRegistry,
    SystemBinaryFinder,
};

/// How much of a server's stderr is retained. Bounded because a chatty server
/// would otherwise grow this without limit for the life of the process, and
/// the last words are the ones that explain a death.
const STDERR_TAIL_CAP: usize = 8 * 1024;

/// A running LSP server with an initialized JSON-RPC client.
pub struct LspServer {
    pub client: JsonRpcClient,
    pub capabilities: protocol::ServerCapabilities,
    child: Child,
    stderr_tail: StderrTail,
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

impl LspServer {
    /// Start an LSP server process and perform the initialize handshake.
    pub async fn start(
        command: &str,
        args: &[&str],
        workspace_root: &Path,
        initialization_options: Option<serde_json::Value>,
    ) -> Result<Self> {
        info!(command, ?args, "starting LSP server");

        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| LspError::ServerStartFailed(format!("{}: {}", command, e)))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| LspError::ServerStartFailed("failed to capture stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| LspError::ServerStartFailed("failed to capture stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| LspError::ServerStartFailed("failed to capture stderr".to_string()))?;
        let stderr_tail = drain_stderr(stderr);

        let client = JsonRpcClient::new(stdin, stdout);

        // Perform LSP initialize handshake.
        let init_params = InitializeParams {
            process_id: Some(std::process::id()),
            root_uri: Some(protocol::path_to_uri(workspace_root)),
            capabilities: protocol::kin_capabilities(),
            initialization_options,
        };

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

        let init_result: InitializeResult =
            serde_json::from_value(result).unwrap_or(InitializeResult {
                capabilities: protocol::ServerCapabilities::default(),
            });

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
            child,
            stderr_tail,
        })
    }

    /// What this server has written to stderr so far, bounded to its last
    /// bytes. Empty when it has written nothing.
    pub async fn stderr_tail(&self) -> String {
        let captured = self.stderr_tail.buffer.lock().await;
        String::from_utf8_lossy(&captured).trim().to_string()
    }

    /// A server whose process accepts input and answers nothing.
    ///
    /// For tests that assert on what this crate SENDS. The document lifecycle
    /// the enrichment join needs is notifications, which expect no reply, so a
    /// process that swallows them exercises the real code path without needing
    /// a language server installed on the machine running the suite.
    #[cfg(test)]
    pub(crate) fn offline_for_tests() -> Self {
        let mut child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn a process that accepts input");
        let stdin = child.stdin.take().expect("captured stdin");
        let stdout = child.stdout.take().expect("captured stdout");
        let stderr = child.stderr.take().expect("captured stderr");
        Self {
            client: JsonRpcClient::new(stdin, stdout),
            capabilities: protocol::ServerCapabilities::default(),
            child,
            stderr_tail: drain_stderr(stderr),
        }
    }

    /// Send shutdown request and exit notification.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self
            .client
            .request("shutdown", serde_json::json!(null))
            .await;
        let _ = self.client.notify("exit", serde_json::json!(null)).await;
        // Child is killed on drop via kill_on_drop(true).
        drop(self.child);
        Ok(())
    }

    /// Check if the server supports call hierarchy.
    pub fn has_call_hierarchy(&self) -> bool {
        self.capabilities.call_hierarchy_provider.is_some()
    }

    /// Check if the server supports go-to-definition.
    pub fn has_definition(&self) -> bool {
        self.capabilities.definition_provider.is_some()
    }

    /// Check if the server supports find references.
    pub fn has_references(&self) -> bool {
        self.capabilities.references_provider.is_some()
    }

    /// Check if the server supports type hierarchy.
    pub fn has_type_hierarchy(&self) -> bool {
        self.capabilities.type_hierarchy_provider.is_some()
    }

    /// Check if the server supports go-to-type-definition.
    pub fn has_type_definition(&self) -> bool {
        self.capabilities.type_definition_provider.is_some()
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
            // Dropped rather than shut down politely: `kill_on_drop` ends the
            // process at once, and a probe has no session worth closing.
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
    /// the refusal, so this stays alive and lets the probe's `kill_on_drop`
    /// end it.
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
            self.0.clone()
        }
        fn probe_version(&self, _path: &Path) -> Option<String> {
            Some("fixture".to_string())
        }
    }

    async fn probe(finder: &FixtureFinder) -> std::result::Result<ProviderProbe, ProviderGap> {
        probe_readiness_with(
            &ProviderRegistry::with_defaults(),
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
}
