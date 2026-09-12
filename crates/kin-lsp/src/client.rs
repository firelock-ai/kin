// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! JSON-RPC 2.0 client over stdio with background reader.
//!
//! Architecture: a dedicated tokio task owns the BufReader<ChildStdout>
//! and reads all messages. Responses are dispatched by ID via oneshot
//! channels. Notifications are discarded. No mutex on the read path.
//!
//! A FIFO writer owns stdin. Normal writes retain one shared permit until
//! flushed, including after caller cancellation. Document cleanup can queue
//! synchronously on Drop, before the next pass opens the same document.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::ChildStdin;
use tokio::sync::{mpsc, oneshot, Mutex, OwnedSemaphorePermit, Semaphore};
use tracing::debug;

use crate::error::{LspError, Result};

/// Pending response waiters, keyed by request ID.
/// The background reader removes entries and fires the oneshot.
type WaiterMap = Arc<Mutex<HashMap<i64, oneshot::Sender<Result<Value>>>>>;

enum Outbound {
    Message {
        body: String,
        ack: oneshot::Sender<Result<()>>,
        _permit: OwnedSemaphorePermit,
    },
    CloseDocuments {
        uris: Vec<String>,
        ack: Option<oneshot::Sender<Result<()>>>,
    },
}

#[cfg(test)]
type AckPause = Arc<std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>>;

/// A JSON-RPC 2.0 client with FIFO writes and async response dispatch.
pub struct JsonRpcClient {
    writer: mpsc::Sender<Outbound>,
    write_slot: Arc<Semaphore>,
    failed: Arc<AtomicBool>,
    writer_handle: tokio::task::JoinHandle<()>,
    #[cfg(test)]
    ack_pause: AckPause,
    waiters: WaiterMap,
    next_id: AtomicI64,
    /// Handle to the background reader task (kept alive with the client).
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl JsonRpcClient {
    pub fn new(mut stdin: ChildStdin, stdout: tokio::process::ChildStdout) -> Self {
        let waiters: WaiterMap = Arc::new(Mutex::new(HashMap::new()));
        let reader_waiters = Arc::clone(&waiters);
        // Only one normal frame can be pending. The bounded queue also admits
        // small cleanup batches when an in-flight write's caller is cancelled.
        let (writer, mut outgoing) = mpsc::channel::<Outbound>(64);
        let write_slot = Arc::new(Semaphore::new(1));
        let failed = Arc::new(AtomicBool::new(false));
        let writer_failed = Arc::clone(&failed);
        let writer_waiters = Arc::clone(&waiters);
        #[cfg(test)]
        let ack_pause: AckPause = Arc::new(std::sync::Mutex::new(None));
        #[cfg(test)]
        let writer_pause = Arc::clone(&ack_pause);
        let writer_handle = tokio::spawn(async move {
            while let Some(message) = outgoing.recv().await {
                if writer_failed.load(Ordering::Acquire) {
                    break;
                }
                let result = match &message {
                    Outbound::Message { body, .. } => write_frame(&mut stdin, body).await,
                    Outbound::CloseDocuments { uris, .. } => {
                        let mut result = Ok(());
                        for uri in uris {
                            let body = serde_json::json!({
                                "jsonrpc": "2.0", "method": "textDocument/didClose",
                                "params": { "textDocument": { "uri": uri } },
                            })
                            .to_string();
                            if let Err(error) = write_frame(&mut stdin, &body).await {
                                result = Err(error);
                                break;
                            }
                        }
                        result
                    }
                };
                #[cfg(test)]
                {
                    let pause = writer_pause.lock().unwrap().take();
                    if let Some((entered, resume)) = pause {
                        entered.notify_one();
                        resume.notified().await;
                    }
                }
                if result.is_err() {
                    writer_failed.store(true, Ordering::Release);
                    fail_waiters(&writer_waiters).await;
                }
                let failed = result.is_err();
                match message {
                    Outbound::Message { ack, .. } => {
                        let _ = ack.send(result);
                    }
                    Outbound::CloseDocuments { ack: Some(ack), .. } => {
                        let _ = ack.send(result);
                    }
                    Outbound::CloseDocuments { ack: None, .. } => {}
                }
                if failed {
                    break;
                }
            }
        });

        // Spawn background reader — owns stdout exclusively, no mutex on reads.
        let reader_handle = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_one_message(&mut reader).await {
                    Ok(msg) => {
                        // Response (has "id") → dispatch to waiter.
                        if let Some(id) = msg.get("id").and_then(|v| v.as_i64()) {
                            let mut map = reader_waiters.lock().await;
                            if let Some(tx) = map.remove(&id) {
                                let result = if let Some(error) = msg.get("error") {
                                    Err(LspError::JsonRpc(error.to_string()))
                                } else {
                                    Ok(msg.get("result").cloned().unwrap_or(Value::Null))
                                };
                                let _ = tx.send(result); // Receiver may have dropped (timeout)
                            }
                        }
                        // Notification (no "id") → drop silently.
                    }
                    Err(_) => {
                        // Server closed stdout or parse error — wake all waiters with error.
                        let mut map = reader_waiters.lock().await;
                        for (_, tx) in map.drain() {
                            let _ = tx.send(Err(LspError::ServerDied));
                        }
                        break;
                    }
                }
            }
        });

        Self {
            writer,
            write_slot,
            failed,
            writer_handle,
            #[cfg(test)]
            ack_pause,
            waiters,
            next_id: AtomicI64::new(1),
            _reader_handle: reader_handle,
        }
    }

    /// Send a request and wait for the response (with 10s timeout).
    pub async fn request<P: Serialize>(&self, method: &str, params: P) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Register waiter BEFORE sending (no race with the reader).
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().await.insert(id, tx);

        // Send the request.
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        if let Err(e) = self.send_message(&request).await {
            self.waiters.lock().await.remove(&id);
            return Err(e);
        }

        // Wait for the background reader to dispatch our response.
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(LspError::ServerDied), // Sender dropped (reader died)
            Err(_) => {
                // Timeout — clean up the waiter.
                self.waiters.lock().await.remove(&id);
                Err(LspError::Timeout)
            }
        }
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

    /// Synchronously queue all owned-document closes. Waiting for the returned
    /// acknowledgment is optional; enqueue order survives caller cancellation.
    pub(crate) fn close_documents(
        &self,
        uris: Vec<String>,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        if self.failed.load(Ordering::Acquire) {
            return Err(LspError::ServerDied);
        }
        let (ack, done) = oneshot::channel();
        let message = Outbound::CloseDocuments {
            uris,
            ack: Some(ack),
        };
        if self.writer.try_send(message).is_err() {
            self.fail_writer();
            return Err(LspError::ServerDied);
        }
        Ok(done)
    }

    fn fail_writer(&self) {
        if !self.failed.swap(true, Ordering::AcqRel) {
            self.writer_handle.abort();
            let waiters = Arc::clone(&self.waiters);
            tokio::spawn(async move {
                fail_waiters(&waiters).await;
            });
        }
    }

    #[cfg(test)]
    pub(crate) fn pause_next_write_ack(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *self.ack_pause.lock().unwrap() = Some((entered.clone(), resume.clone()));
        (entered, resume)
    }

    /// Send one frame. The writer owns the permit, so dropping this future
    /// cannot admit another document body while the first is blocked on IO.
    async fn send_message(&self, message: &Value) -> Result<()> {
        let permit = self
            .write_slot
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| LspError::ServerDied)?;
        if self.failed.load(Ordering::Acquire) {
            return Err(LspError::ServerDied);
        }
        let body = serde_json::to_string(message)?;
        let (ack, done) = oneshot::channel();
        if self
            .writer
            .try_send(Outbound::Message {
                body,
                ack,
                _permit: permit,
            })
            .is_err()
        {
            self.fail_writer();
            return Err(LspError::ServerDied);
        }
        done.await.map_err(|_| LspError::ServerDied)??;
        debug!(
            method = message
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("response"),
            "sent message"
        );
        Ok(())
    }
}

async fn fail_waiters(waiters: &WaiterMap) {
    for (_, waiter) in waiters.lock().await.drain() {
        let _ = waiter.send(Err(LspError::ServerDied));
    }
}

async fn write_frame(stdin: &mut ChildStdin, body: &str) -> Result<()> {
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin.write_all(header.as_bytes()).await?;
    stdin.write_all(body.as_bytes()).await?;
    stdin.flush().await?;
    Ok(())
}

/// Read one JSON-RPC message from a BufReader (Content-Length delimited).
/// This is a free function — no &self, no mutex. Called only by the reader task.
async fn read_one_message(
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> std::result::Result<Value, LspError> {
    // Read headers until blank line.
    let mut content_length: Option<usize> = None;
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let bytes_read = reader.read_line(&mut header_line).await?;
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

    let length = content_length
        .ok_or_else(|| LspError::Protocol("missing Content-Length header".to_string()))?;

    // Read exactly `length` bytes of body.
    let mut body = vec![0u8; length];
    tokio::io::AsyncReadExt::read_exact(reader, &mut body).await?;

    let value: Value = serde_json::from_slice(&body)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
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
