// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! HTTP transport for kin-remote sync protocol.
//!
//! Provides `HttpDeltaPuller` and `HttpMutationPusher` implementations that
//! communicate with a KinLab server over REST endpoints:
//!
//! - `GET  {base_url}/api/sync/delta?entity_id={id}` — pull a single entity delta
//! - `GET  {base_url}/api/sync/delta?since={iso8601}` — pull deltas since timestamp
//! - `POST {base_url}/api/sync/push` — push local mutations

use crate::delta_pull::{DeltaPuller, PullError};
use crate::mutation_push::{MutationPushError, MutationPusher};
use crate::sync_types::{LocalMutation, PushResult, SemanticDelta};
use chrono::{DateTime, Utc};
use std::time::Duration;
use tracing::{debug, warn};
use ureq::Agent;

/// Require TLS for credentials except on literal loopback development endpoints.
/// Validation does not rewrite the URL used to key saved credentials.
pub fn validate_credential_url(raw: &str) -> Result<(), &'static str> {
    let url = url::Url::parse(raw).map_err(|_| "invalid credential endpoint URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
    {
        return Err("credential endpoint must not contain userinfo, a query, or a fragment");
    }
    match url.scheme() {
        "https" => Ok(()),
        "http"
            if matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
                || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback()) =>
        {
            Ok(())
        }
        _ => Err("credential endpoint requires HTTPS or a literal loopback HTTP address"),
    }
}

#[cfg(test)]
mod credential_url_tests {
    use super::validate_credential_url;

    #[test]
    fn credential_urls_require_tls_except_loopback() {
        for raw in [
            "https://example.com",
            "https://example.com/prefix/",
            "http://127.0.0.1:4219",
            "http://127.42.0.2",
            "http://[::1]:4219",
        ] {
            assert!(validate_credential_url(raw).is_ok(), "{raw}");
        }
        for raw in [
            "http://example.com",
            "http://localhost",
            "http://127.0.0.1.example.com",
            "http://[::ffff:127.0.0.1]",
            "http://0.0.0.0",
            "http://192.168.1.1",
            "ftp://127.0.0.1",
            "file:///tmp/a",
            "https://user:password@example.com",
            "https://example.com?x=y",
            "https://example.com#fragment",
            "not a URL",
        ] {
            assert!(validate_credential_url(raw).is_err(), "{raw}");
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the HTTP transport layer.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Base URL of the KinLab server (e.g. `https://kinlab.example.com`).
    pub base_url: String,
    /// Optional bearer token for authentication.
    pub auth_token: Option<String>,
    /// Request timeout in seconds (default: 30).
    pub timeout_secs: u64,
}

impl HttpConfig {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            auth_token: None,
            timeout_secs: 30,
        }
    }

    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    fn build_agent(&self) -> Agent {
        Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(self.timeout_secs)))
            .max_redirects(0)
            .build()
            .into()
    }
}

// ---------------------------------------------------------------------------
// HttpDeltaPuller
// ---------------------------------------------------------------------------

/// Pulls semantic deltas from a KinLab server over HTTP.
pub struct HttpDeltaPuller {
    config: HttpConfig,
    agent: Agent,
}

impl HttpDeltaPuller {
    pub fn new(config: HttpConfig) -> Self {
        let agent = config.build_agent();
        Self { config, agent }
    }
}

impl std::fmt::Debug for HttpDeltaPuller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDeltaPuller")
            .field("base_url", &self.config.base_url)
            .finish()
    }
}

fn is_connectivity_error(err: &ureq::Error) -> bool {
    match err {
        ureq::Error::Timeout(_) | ureq::Error::ConnectionFailed | ureq::Error::HostNotFound => true,
        ureq::Error::Io(io_err) => matches!(
            io_err.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::TimedOut
        ),
        _ => false,
    }
}

fn map_ureq_error_to_pull(err: ureq::Error) -> PullError {
    if let ureq::Error::StatusCode(404) = &err {
        return PullError::EntityNotFound("remote returned 404".to_owned());
    }
    if is_connectivity_error(&err) {
        return PullError::RemoteUnavailable(format!("{err}"));
    }
    PullError::Protocol(format!("HTTP error: {err}"))
}

fn map_ureq_error_to_push(err: ureq::Error) -> MutationPushError {
    if is_connectivity_error(&err) {
        return MutationPushError::RemoteUnavailable(format!("{err}"));
    }
    MutationPushError::Protocol(format!("HTTP error: {err}"))
}

impl DeltaPuller for HttpDeltaPuller {
    fn pull_delta(&self, entity_id: &str) -> Result<SemanticDelta, PullError> {
        validate_credential_url(&self.config.base_url)
            .map_err(|message| PullError::Protocol(message.to_string()))?;
        let url = format!(
            "{}/api/sync/delta?entity_id={}",
            self.config.base_url,
            urlencoded(entity_id)
        );
        debug!(entity_id, url = %url, "pulling delta");

        let mut request = self.agent.get(&url);
        if let Some(ref token) = self.config.auth_token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }

        let response = request.call().map_err(map_ureq_error_to_pull)?;
        let body = response
            .into_body()
            .read_to_string()
            .map_err(|e| PullError::Protocol(format!("failed to read response body: {e}")))?;

        let delta: SemanticDelta = serde_json::from_str(&body)
            .map_err(|e| PullError::Protocol(format!("failed to deserialize delta: {e}")))?;

        Ok(delta)
    }

    fn pull_deltas_since(&self, since: DateTime<Utc>) -> Result<Vec<SemanticDelta>, PullError> {
        validate_credential_url(&self.config.base_url)
            .map_err(|message| PullError::Protocol(message.to_string()))?;
        let url = format!(
            "{}/api/sync/delta?since={}",
            self.config.base_url,
            urlencoded(&since.to_rfc3339())
        );
        debug!(since = %since, url = %url, "pulling deltas since");

        let mut request = self.agent.get(&url);
        if let Some(ref token) = self.config.auth_token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }

        let response = request.call().map_err(map_ureq_error_to_pull)?;
        let body = response
            .into_body()
            .read_to_string()
            .map_err(|e| PullError::Protocol(format!("failed to read response body: {e}")))?;

        let deltas: Vec<SemanticDelta> = serde_json::from_str(&body)
            .map_err(|e| PullError::Protocol(format!("failed to deserialize deltas: {e}")))?;

        Ok(deltas)
    }
}

// ---------------------------------------------------------------------------
// HttpMutationPusher
// ---------------------------------------------------------------------------

/// Pushes local mutations to a KinLab server over HTTP.
pub struct HttpMutationPusher {
    config: HttpConfig,
    agent: Agent,
}

impl HttpMutationPusher {
    pub fn new(config: HttpConfig) -> Self {
        let agent = config.build_agent();
        Self { config, agent }
    }
}

impl std::fmt::Debug for HttpMutationPusher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpMutationPusher")
            .field("base_url", &self.config.base_url)
            .finish()
    }
}

impl MutationPusher for HttpMutationPusher {
    fn push_mutations(&self, mutations: &[LocalMutation]) -> Result<PushResult, MutationPushError> {
        validate_credential_url(&self.config.base_url)
            .map_err(|message| MutationPushError::Protocol(message.to_string()))?;
        let url = format!("{}/api/sync/push", self.config.base_url);
        debug!(count = mutations.len(), url = %url, "pushing mutations");

        let body = serde_json::to_string(mutations).map_err(|e| {
            MutationPushError::Protocol(format!("failed to serialize mutations: {e}"))
        })?;

        let mut request = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json");
        if let Some(ref token) = self.config.auth_token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }

        let response = request
            .send(body.as_bytes())
            .map_err(map_ureq_error_to_push)?;

        let resp_body = response.into_body().read_to_string().map_err(|e| {
            MutationPushError::Protocol(format!("failed to read response body: {e}"))
        })?;

        let result: PushResult = serde_json::from_str(&resp_body).map_err(|e| {
            MutationPushError::Protocol(format!("failed to deserialize push result: {e}"))
        })?;

        match &result {
            PushResult::Accepted { accepted_count, .. } => {
                debug!(accepted_count, "push accepted");
            }
            PushResult::Conflict { conflicts, .. } => {
                warn!(conflict_count = conflicts.len(), "push returned conflicts");
            }
            PushResult::Rejected { reason } => {
                warn!(reason, "push rejected");
            }
        }

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal percent-encoding for URL query parameters and path segments.
pub(crate) fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX_UPPER[(b >> 4) as usize]));
                out.push(char::from(HEX_UPPER[(b & 0x0f) as usize]));
            }
        }
    }
    out
}

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn serve_once(response: String) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "no fixture request");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            // A socket accepted from a non-blocking listener inherits O_NONBLOCK on
            // macOS and BSD, where on Linux it does not, and a read timeout does not
            // apply to a non-blocking socket. Without this the read below returns
            // WouldBlock the moment a client has not written its request yet, and
            // this thread panics: measured on this fixture at twelve failures in two
            // hundred runs, every one of them on WouldBlock.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8(request).unwrap()
        });
        (url, thread)
    }

    /// A client whose request lands after the server's first read is still served.
    ///
    /// The fixture binds a non-blocking listener so its accept loop can give up
    /// rather than hang. On macOS and BSD the socket `accept` returns inherits that
    /// flag and on Linux it does not, and `set_read_timeout` does nothing to a
    /// non-blocking socket, so the server's first `read_exact` answered WouldBlock
    /// whenever the client had not written yet and the fixture thread panicked. That
    /// is the macOS shard's own failure on kin#1742's landing, and it measured here
    /// at twelve failures in two hundred runs before the fix, all twelve on
    /// WouldBlock.
    ///
    /// The delay is the subject rather than a wait for a race to settle: it puts the
    /// client's bytes strictly after the server's first read, which is the ordering
    /// the kernel failed on. On Linux this passes either way, so the macOS shards are
    /// what grade it.
    #[test]
    fn a_client_whose_request_lands_after_the_first_read_is_still_served() {
        use std::io::{Read, Write};
        let (url, server) = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
        );
        let mut client = std::net::TcpStream::connect(url.trim_start_matches("http://")).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: fixture\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let request = server
            .join()
            .expect("the fixture server must survive a client that writes after it reads");
        assert!(request.starts_with("GET / HTTP/1.1"), "{request}");
    }

    #[test]
    fn sync_credentials_refuse_insecure_endpoints_before_network() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://localhost:{}", listener.local_addr().unwrap().port());
        let config = HttpConfig::new(url)
            .with_auth("fixture-token")
            .with_timeout(1);
        let puller = HttpDeltaPuller::new(config.clone());
        assert!(
            matches!(puller.pull_delta("entity:1"), Err(PullError::Protocol(message)) if message.contains("requires HTTPS"))
        );
        assert!(
            matches!(puller.pull_deltas_since(Utc::now()), Err(PullError::Protocol(message)) if message.contains("requires HTTPS"))
        );
        let pusher = HttpMutationPusher::new(config);
        assert!(
            matches!(pusher.push_mutations(&[]), Err(MutationPushError::Protocol(message)) if message.contains("requires HTTPS"))
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn sync_credentials_allow_literal_loopback_and_refuse_redirects() {
        let delta = serde_json::json!({"entity_id":"entity:1","before_hash":null,"after_hash":"hash","change_set":[],"timestamp":"2026-09-08T00:00:00Z","actor_id":"fixture"});
        let bodies = [
            delta.to_string(),
            format!("[{delta}]"),
            r#"{"Accepted":{"accepted_count":0,"new_remote_head":"hash"}}"#.to_owned(),
        ];
        for (operation, body) in bodies.into_iter().enumerate() {
            for redirect in [false, true] {
                let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                target.set_nonblocking(true).unwrap();
                let response = if redirect {
                    format!("HTTP/1.1 302 Found\r\nLocation: http://{}/redirect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target.local_addr().unwrap())
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let (url, server) = serve_once(response);
                let config = HttpConfig::new(url)
                    .with_auth("fixture-token")
                    .with_timeout(1);
                let success = match operation {
                    0 => HttpDeltaPuller::new(config).pull_delta("entity:1").is_ok(),
                    1 => HttpDeltaPuller::new(config)
                        .pull_deltas_since(Utc::now())
                        .is_ok(),
                    _ => HttpMutationPusher::new(config).push_mutations(&[]).is_ok(),
                };
                let request = server.join().unwrap();
                assert!(request
                    .to_lowercase()
                    .contains("authorization: bearer fixture-token"));
                assert_eq!(
                    success, !redirect,
                    "operation={operation} redirect={redirect}"
                );
                assert_eq!(
                    target.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
        }
    }

    #[test]
    fn http_config_builder() {
        let config = HttpConfig::new("https://kinlab.example.com")
            .with_auth("test-token-123")
            .with_timeout(60);

        assert_eq!(config.base_url, "https://kinlab.example.com");
        assert_eq!(config.auth_token.as_deref(), Some("test-token-123"));
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn http_config_defaults() {
        let config = HttpConfig::new("http://localhost:4010");

        assert_eq!(config.base_url, "http://localhost:4010");
        assert!(config.auth_token.is_none());
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn urlencoded_leaves_unreserved_chars() {
        assert_eq!(urlencoded("hello-world_123"), "hello-world_123");
    }

    #[test]
    fn urlencoded_encodes_special_chars() {
        assert_eq!(urlencoded("entity:1"), "entity%3A1");
        assert_eq!(urlencoded("a b"), "a%20b");
        assert_eq!(urlencoded("foo/bar"), "foo%2Fbar");
    }

    #[test]
    fn urlencoded_encodes_rfc3339_timestamp() {
        // The colons and plus in timestamps must be encoded
        let ts = "2026-03-25T10:30:00+00:00";
        let encoded = urlencoded(ts);
        assert!(encoded.contains("%3A")); // colons encoded
        assert!(!encoded.contains(':')); // no raw colons
    }

    #[test]
    fn http_delta_puller_debug() {
        let config = HttpConfig::new("https://kinlab.example.com");
        let puller = HttpDeltaPuller::new(config);
        let debug = format!("{:?}", puller);
        assert!(debug.contains("kinlab.example.com"));
    }

    #[test]
    fn http_mutation_pusher_debug() {
        let config = HttpConfig::new("https://kinlab.example.com");
        let pusher = HttpMutationPusher::new(config);
        let debug = format!("{:?}", pusher);
        assert!(debug.contains("kinlab.example.com"));
    }

    #[test]
    fn pull_delta_connection_refused() {
        // Connect to a port that (almost certainly) has nothing listening.
        let config = HttpConfig::new("http://127.0.0.1:19999").with_timeout(2);
        let puller = HttpDeltaPuller::new(config);

        let err = puller.pull_delta("entity:1").unwrap_err();
        match err {
            PullError::RemoteUnavailable(_) => {} // expected
            other => panic!("expected RemoteUnavailable, got: {other}"),
        }
    }

    #[test]
    fn push_mutations_connection_refused() {
        let config = HttpConfig::new("http://127.0.0.1:19999").with_timeout(2);
        let pusher = HttpMutationPusher::new(config);

        let mutation = LocalMutation {
            entity_id: "entity:1".to_owned(),
            mutation_id: uuid::Uuid::new_v4(),
            change_set: vec![],
            base_hash: None,
            new_hash: Some("hash-new".to_owned()),
            timestamp: chrono::Utc::now(),
        };

        let err = pusher.push_mutations(&[mutation]).unwrap_err();
        match err {
            MutationPushError::RemoteUnavailable(_) => {} // expected
            other => panic!("expected RemoteUnavailable, got: {other}"),
        }
    }

    #[test]
    fn map_ureq_error_handles_timeout() {
        // Verify the error mapping functions produce the right variants
        let timeout_err = ureq::Error::Timeout(ureq::Timeout::Global);
        match map_ureq_error_to_pull(timeout_err) {
            PullError::RemoteUnavailable(msg) => assert!(msg.contains("timeout"), "msg: {msg}"),
            other => panic!("expected RemoteUnavailable, got: {other}"),
        }

        let timeout_err = ureq::Error::Timeout(ureq::Timeout::Global);
        match map_ureq_error_to_push(timeout_err) {
            MutationPushError::RemoteUnavailable(msg) => {
                assert!(msg.contains("timeout"), "msg: {msg}")
            }
            other => panic!("expected RemoteUnavailable, got: {other}"),
        }
    }
}
