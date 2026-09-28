// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(feature = "gcs")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kin_daemon::publication_lease::{
    ObjectStorePublicationControlStore, PublicationControlRecord, PublicationControlStore,
};
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::{ClientOptions, RetryConfig};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

/// A real HTTP/1 GCS object response. Keep-alive is essential here: the
/// in-memory object store and a server that closes every response cannot
/// expose a connection whose original executor has stopped driving it.
struct ControlServer {
    url: String,
    stop: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl ControlServer {
    fn start(body: Vec<u8>, keep_alive: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_stop = Arc::clone(&stop);
        let server_connections = Arc::clone(&connections);
        let server_requests = Arc::clone(&requests);
        let worker = std::thread::spawn(move || {
            let mut clients = Vec::new();
            while !server_stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(client) => client,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("loopback accept: {error}"),
                };
                server_connections.fetch_add(1, Ordering::SeqCst);
                let stop = Arc::clone(&server_stop);
                let requests = Arc::clone(&server_requests);
                let body = body.clone();
                clients.push(std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(50)))
                        .unwrap();
                    stream.set_write_timeout(Some(REQUEST_TIMEOUT)).unwrap();
                    let mut pending = Vec::new();
                    while !stop.load(Ordering::SeqCst) {
                        let mut chunk = [0; 1024];
                        match stream.read(&mut chunk) {
                            Ok(0) => return,
                            Ok(count) => pending.extend_from_slice(&chunk[..count]),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                continue;
                            }
                            Err(_) => return,
                        }
                        assert!(pending.len() < 16 * 1024, "bounded request headers");
                        let Some(end) = pending.windows(4).position(|part| part == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let head = String::from_utf8(pending.drain(..end + 4).collect()).unwrap();
                        requests
                            .lock()
                            .unwrap()
                            .push(head.lines().next().unwrap().to_string());
                        let connection = if keep_alive { "keep-alive" } else { "close" };
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nETag: \"fixture\"\r\nx-goog-generation: 1\r\nLast-Modified: Sun, 27 Sep 2026 00:00:00 GMT\r\nConnection: {connection}\r\n\r\n",
                            body.len()
                        );
                        if stream.write_all(head.as_bytes()).is_err()
                            || stream.write_all(&body).is_err()
                            || stream.flush().is_err()
                        {
                            return;
                        }
                        if !keep_alive {
                            return;
                        }
                    }
                }));
            }
            for client in clients {
                client.join().unwrap();
            }
        });
        Self {
            url,
            stop,
            connections,
            requests,
            worker: Some(worker),
        }
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn publication_control_reads_cross_from_sync_to_async_with_keep_alive() {
    // This is transport coverage, not live cloud or reader-admission proof.
    let record: PublicationControlRecord = serde_json::from_value(serde_json::json!({
        "schema": "kin.publication-control.v2",
        "scope": "gcs://fixture-bucket/fixture",
        "revision": 7,
        "last_fence": 3,
        "repositories": ["fixture"],
        "reader": {
            "identity": "fixture-reader",
            "min_snapshot_schema": 1,
            "max_snapshot_schema": 28,
            "admitted_at": "2026-09-27T00:00:00Z",
            "expires_at": "2026-09-28T00:00:00Z"
        },
        "last_authority_fenced_at": null,
        "last_authority_fence": [],
        "active_lease": null,
        "last_completed_lease": null
    }))
    .unwrap();

    // Close is the control: it exercises the same payload and executor
    // transition while removing only reuse of an existing connection.
    for keep_alive in [false, true] {
        let server = ControlServer::start(serde_json::to_vec(&record).unwrap(), keep_alive);
        let client = GoogleCloudStorageBuilder::new()
            .with_bucket_name("fixture-bucket")
            .with_base_url(&server.url)
            .with_skip_signature(true)
            .with_client_options(
                ClientOptions::new()
                    .with_allow_http(true)
                    .with_http1_only()
                    .with_timeout(REQUEST_TIMEOUT)
                    .with_connect_timeout(REQUEST_TIMEOUT),
            )
            .with_retry(RetryConfig {
                max_retries: 0,
                retry_timeout: REQUEST_TIMEOUT,
                ..Default::default()
            })
            .build()
            .unwrap();
        let store = ObjectStorePublicationControlStore::new(Arc::new(client), "fixture");
        assert!(tokio::runtime::Handle::try_current().is_err());
        // The HTTP client races checking a pooled connection out against
        // dialling a new one, so a warm read can open a second connection
        // while the first is still on its way back to the pool. What this
        // fixture must establish is that some warm read reused a connection
        // with keep-alive on, and that none ever did with it off, so it reads
        // until reuse shows, within a bound.
        let mut warm_reads = 0;
        loop {
            let loaded = store.load().expect("synchronous control read").unwrap();
            assert_eq!(loaded.record, record);
            assert_eq!(loaded.version.version.as_deref(), Some("1"));
            warm_reads += 1;
            let connections = server.connections.load(Ordering::SeqCst);
            if !keep_alive {
                assert_eq!(
                    connections, warm_reads,
                    "closed connections are never reused"
                );
                if warm_reads == 2 {
                    break;
                }
            } else if warm_reads >= 2 && connections < warm_reads {
                break;
            }
            assert!(
                warm_reads < 8,
                "the warm reads must establish that this fixture reuses its connection \
                 (keep_alive={keep_alive}, connections={connections}, reads={warm_reads})"
            );
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async { store.load() });
        let requests = server.requests.lock().unwrap().clone();
        let loaded = result.unwrap_or_else(|error| {
            panic!(
                "sync-to-async control read failed (keep_alive={keep_alive}, connections={}, requests={requests:?}): {error}",
                server.connections.load(Ordering::SeqCst)
            )
        });
        assert_eq!(loaded.unwrap().record, record);
        assert_eq!(
            requests.len(),
            warm_reads + 1,
            "no retries or silently skipped reads"
        );
        assert!(requests.iter().all(|line| {
            line == "GET /fixture%2Dbucket/fixture%2F%2Ekin%2Dgraph%2Dpublication%2Dcontrol%2Ejson HTTP/1.1"
        }));
    }
}
