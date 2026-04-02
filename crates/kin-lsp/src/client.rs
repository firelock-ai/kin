// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Generic JSON-RPC 2.0 client over stdio transport.
//!
//! Communicates with LSP servers via stdin/stdout using the LSP base protocol:
//! `Content-Length: N\r\n\r\n{json body}`.

use std::sync::atomic::{AtomicI64, Ordering};

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::ChildStdin;
use tokio::sync::Mutex;
use tracing::debug;

use crate::error::{LspError, Result};

/// A JSON-RPC 2.0 client that speaks LSP base protocol over stdio.
pub struct JsonRpcClient {
    stdin: Mutex<ChildStdin>,
    /// Buffered reader for stdout — reads Content-Length delimited messages.
    stdout: Mutex<BufReader<tokio::process::ChildStdout>>,
    next_id: AtomicI64,
}

impl JsonRpcClient {
    pub fn new(stdin: ChildStdin, stdout: tokio::process::ChildStdout) -> Self {
        Self {
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: AtomicI64::new(1),
        }
    }

    /// Send a request and wait for the response.
    pub async fn request<P: Serialize>(
        &self,
        method: &str,
        params: P,
    ) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        self.send_message(&request).await?;

        // Read responses until we get one matching our ID.
        // LSP servers send notifications interleaved with responses.
        // Timeout after 10s total to prevent blocking on notification floods.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(LspError::Timeout);
            }
            let msg = match tokio::time::timeout(remaining, self.read_message()).await {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(LspError::Timeout),
            };
            if let Some(msg_id) = msg.get("id") {
                if msg_id.as_i64() == Some(id) {
                    if let Some(error) = msg.get("error") {
                        return Err(LspError::JsonRpc(error.to_string()));
                    }
                    return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                }
            }
            // Not our response — notification or someone else's response. Skip.
        }
    }

    /// Drain pending notifications from the server's stdout.
    /// Call this after didOpen or other operations that trigger notification floods.
    /// Reads messages until a 500ms gap with no new messages.
    pub async fn drain_notifications(&self) {
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                self.read_message(),
            )
            .await
            {
                Ok(Ok(msg)) => {
                    // Notification — discard and keep reading.
                    if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
                        debug!(method, "drained notification");
                    }
                }
                _ => break, // Timeout or error — done draining.
            }
        }
    }

    /// Send multiple requests concurrently and collect all responses.
    /// Returns results in the same order as the input methods/params.
    pub async fn request_batch<P: Serialize + Clone>(
        &self,
        requests: &[(&str, P)],
    ) -> Vec<Result<Value>> {
        // Send all requests first (assign sequential IDs).
        let mut ids = Vec::with_capacity(requests.len());
        for (method, params) in requests {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            });
            if let Err(e) = self.send_message(&request).await {
                ids.push((id, Some(Err(e))));
                continue;
            }
            ids.push((id, None));
        }

        // Read all responses, matching by ID.
        let mut results: std::collections::HashMap<i64, Result<Value>> =
            std::collections::HashMap::new();
        let expected = ids.iter().filter(|(_, err)| err.is_none()).count();

        for _ in 0..expected {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.read_message(),
            )
            .await
            {
                Ok(Ok(msg)) => {
                    if let Some(msg_id) = msg.get("id").and_then(|v| v.as_i64()) {
                        if msg.get("error").is_some() {
                            results.insert(
                                msg_id,
                                Err(LspError::JsonRpc(msg["error"].to_string())),
                            );
                        } else {
                            results.insert(
                                msg_id,
                                Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                            );
                        }
                    }
                    // Skip notifications (no id field).
                }
                Ok(Err(_)) => break, // Server died
                Err(_) => break,     // Timeout
            }
        }

        // Return results in original order.
        ids.into_iter()
            .map(|(id, send_err)| {
                if let Some(err) = send_err {
                    err
                } else {
                    results.remove(&id).unwrap_or(Err(LspError::Timeout))
                }
            })
            .collect()
    }

    /// Send a notification (no response expected).
    pub async fn notify<P: Serialize>(&self, method: &str, params: P) -> Result<()> {
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.send_message(&notification).await
    }

    /// Send a raw JSON-RPC message with Content-Length header.
    async fn send_message(&self, message: &Value) -> Result<()> {
        let body = serde_json::to_string(message)?;
        let header = format!("Content-Length: {}\r\n\r\n", body.len());

        let mut stdin = self.stdin.lock().await;
        stdin.write_all(header.as_bytes()).await?;
        stdin.write_all(body.as_bytes()).await?;
        stdin.flush().await?;

        debug!(method = message.get("method").and_then(|m| m.as_str()).unwrap_or("response"), "sent message");
        Ok(())
    }

    /// Read one JSON-RPC message from stdout (Content-Length delimited).
    async fn read_message(&self) -> Result<Value> {
        let mut stdout = self.stdout.lock().await;

        // Read headers until blank line.
        let mut content_length: Option<usize> = None;
        let mut header_line = String::new();
        loop {
            header_line.clear();
            let bytes_read = stdout.read_line(&mut header_line).await?;
            if bytes_read == 0 {
                return Err(LspError::ServerDied);
            }
            let trimmed = header_line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some(len_str) = trimmed.strip_prefix("Content-Length: ") {
                content_length = len_str.parse().ok();
            }
        }

        let length = content_length.ok_or_else(|| {
            LspError::Protocol("missing Content-Length header".to_string())
        })?;

        // Read exactly `length` bytes of body.
        let mut body = vec![0u8; length];
        tokio::io::AsyncReadExt::read_exact(&mut *stdout, &mut body).await?;

        let value: Value = serde_json::from_slice(&body)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_rpc_request_format() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        });
        let body = serde_json::to_string(&request).unwrap();
        assert!(body.contains("\"jsonrpc\":\"2.0\""));
        assert!(body.contains("\"method\":\"initialize\""));
    }
}
